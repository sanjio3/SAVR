"""A1 规则扫描。

注入类（SQLi / 命令注入 / XSS / SSRF / 反序列化 等）：由 CodeQL 做数据流分析，
``A1CodeQLSemanticAgent`` 做 AI 语义整合。自写 yaml 正则引擎（原 A1RuleAgent）已删除，
**不再作为注入类的兜底**——CodeQL 不可用或未开启 ``a1_use_codeql`` 时，注入类不出结果。

业务逻辑类（越权 / 状态机 / 计算逻辑 / 认证会话 / 滥用 DoS）：由
``A1BusinessLogicAIAgent`` 做 AI 语义识别（主链路），自写启发式分析器仅作离线兜底；
CodeQL 仅提供辅助结构验证。详见 analyze_business_logic。
"""
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.agents.a1_bola_analyzer import analyze_sources as _analyze_bola
from src.agents.a1_codeql_adapter import CodeQLAdapter
from src.agents.a1_codeql_semantic_agent import A1CodeQLSemanticAgent
from src.agents.a1_injection_heuristic import analyze_files as _heuristic_injection
from src.agents.a1_injection_heuristic import analyze_content as _analyze_content_registry
from src.core.models import ScanResult, Vulnerability
from src.pipeline.a1.manifest import A1_MANIFEST
from src.pipeline.stage_contract import StageService

# 由 src.core.config_registry 统一读取。self.config 中的 a1_use_codeql / codeql.bin_path
# 作为显式覆盖（编排层下发的运行时决策），未给出时回退到配置文件。
try:
    from src.core import config_registry as _cfg
except Exception:  # pragma: no cover
    _cfg = None

logger = logging.getLogger(__name__)

# 能被 CodeQL / Maven / Gradle / npm / go / pip 识别为「项目根」的构建文件
_BUILD_FILE_MARKERS = (
    "pom.xml", "build.gradle", "build.gradle.kts", "package.json",
    "go.mod", "requirements.txt", "setup.py", "pyproject.toml",
    "composer.json", "Gemfile", "Cargo.toml", "Makefile",
)


_LANG_BY_EXT = {
    ".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".go": "go", ".php": "php",
    ".rb": "ruby", ".cs": "csharp", ".kt": "kotlin", ".scala": "scala",
    ".cpp": "cpp", ".cc": "cpp", ".c": "cpp", ".h": "cpp",
}


def _hypo_to_vulnerability(h: Dict[str, Any]) -> Vulnerability:
    """把业务逻辑/BOLA 假说（dict）规整为 A1 的 Vulnerability，并入 A1 findings。

    同时兼容两种输出形状：
    - A1BusinessLogicAIAgent（LLM 主链路）：file/line/category/vuln_type/family/
      target_endpoint/http_method/vulnerable_param/confidence/evidence。
    - a1_bola_analyzer（离线兜底）：vuln_type/family/entry_point(``path:line``)/param/
      data_access_sink/required_control_point/confidence/evidence。
    """
    h = h or {}
    file = str(h.get("file") or "")
    line = h.get("line")
    if line is None and h.get("entry_point"):
        ep = str(h["entry_point"])
        if ":" in ep:
            fpart, _, lpart = ep.rpartition(":")
            if not file:
                file = fpart
            try:
                line = int(lpart)
            except (TypeError, ValueError):
                line = None

    category = str(h.get("category") or h.get("vuln_type") or "")
    vuln_type = str(h.get("vuln_type") or category.upper() or "BUSINESS_LOGIC")
    family = str(h.get("family") or "business-logic")
    confidence = str(h.get("confidence") or "medium").lower()
    severity = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}.get(confidence, "medium")
    endpoint = str(h.get("target_endpoint") or h.get("entry_point") or "")
    param = str(h.get("vulnerable_param") or h.get("param") or "")
    description = str(h.get("evidence") or h.get("required_control_point") or "")
    sink = str(h.get("data_access_sink") or h.get("required_control_point") or "")

    v = Vulnerability(
        type=vuln_type,
        severity=severity,
        line=line,
        description=description,
        fix="补充控制点校验（归属/角色/状态/边界/限流，视类别而定）",
        file=file,
        entry_point=endpoint,
        sink=sink,
        source="a1",
        confidence=confidence,
        detection_method=h.get("detection_method") or "rule",
        rule_name=h.get("rule_name") or category,
    )
    # 业务逻辑语义（类别/参数/端点/家族）随 a1_evidence 携带，供 findings 持久化与 A2 证据基础复用；
    # 不污染 inject 类 a1_evidence 的既有键（entry_candidates 等），A2 路由/参数解析只读 exploit_spec.entry。
    setattr(v, "a1_evidence", {
        "business_logic": True,
        "category": category,
        "family": family,
        "target_endpoint": endpoint,
        "http_method": str(h.get("http_method") or ""),
        "vulnerable_param": param,
    })
    # 什么都不写 —— 只有 bind_static_routes 命中的才会被塞一个「仅 entry 的裸 spec」，经
    # normalize_exploit_spec 补全后 payload.payload_family 恒为空。后果：登记层
    # （trigger_spec_registry:620）读不到族名只好回落 _norm_family，D1 也就拿不到族化的重放路由；
    # 同时 prerequisites.victim_resource_id 恒空，BOLA/IDOR 重放目标缺失。
    # 这里在生产者处一次性写全：规范业务族落进 payload.payload_family，差分族补 victim 哨兵。
    try:
        from src.core.exploit_spec import (
            canonical_business_logic_family,
            DIFFERENTIAL_PROOF_FAMILIES,
            empty_exploit_spec,
        )
        _canon = canonical_business_logic_family(family) or canonical_business_logic_family(category)
        if _canon:
            spec = getattr(v, "exploit_spec", None)
            # Vulnerability 默认已带 empty_exploit_spec（非 None 但全空），故不能只在「无 spec」时
            # 补 entry —— 必须按字段判空补位，否则 entry.route 永远写不进去。
            if not isinstance(spec, dict) or not spec:
                spec = empty_exploit_spec()
                v.exploit_spec = spec
            # 只写 HTTP 路由形态的端点：离线 BOLA 分析器的 entry_point 形如
            # ``OrderService.java:118``（源码定位），写进 entry.route 会被登记层
            # 判为 route_is_source_path 整条丢弃，也会污染 D2 构造请求。
            _route = endpoint if str(endpoint or "").lstrip().startswith("/") else ""
            _entry = spec.setdefault("entry", {})
            if _route and not _SOURCE_PATH_ENDPOINT_RE.search(_route) and not str(_entry.get("route") or "").strip():
                _entry["route"] = _route
                _entry["method"] = str(h.get("http_method") or "")
            spec.setdefault("payload", {})["payload_family"] = _canon
            if _canon in DIFFERENTIAL_PROOF_FAMILIES:
                # 哨兵由 D1 replay_* 从账户池解析真实受害者 id（与 A2 主路径同口径）
                spec.setdefault("prerequisites", {})
                if not spec["prerequisites"].get("victim_resource_id"):
                    spec["prerequisites"]["victim_resource_id"] = "VICTIM_FROM_POOL"
    except Exception as _e:  # 生产者补全失败不得影响 finding 产出
        logger.debug("[A1] 业务族 exploit_spec 补全失败（%s）：%s", getattr(v, "file", ""), _e)
    return v


def _hypo_to_candidate(h: Dict[str, Any]) -> Dict[str, Any]:
    """把业务逻辑/BOLA 假说转成 a1_evidence_index 的 business_logic_candidates 条目，供 A2 证据基础。"""
    h = h or {}
    file = str(h.get("file") or "")
    line = h.get("line")
    if line is None and h.get("entry_point"):
        ep = str(h["entry_point"])
        if ":" in ep:
            _, _, lpart = ep.rpartition(":")
            try:
                line = int(lpart)
            except (TypeError, ValueError):
                line = None
    return {
        "category": str(h.get("category") or h.get("vuln_type") or ""),
        "vuln_type": str(h.get("vuln_type") or (h.get("category") or "").upper() or "BUSINESS_LOGIC"),
        "family": str(h.get("family") or "business-logic"),
        "route": str(h.get("target_endpoint") or h.get("entry_point") or ""),
        "method": str(h.get("http_method") or ""),
        "param": str(h.get("vulnerable_param") or h.get("param") or ""),
        "file": file,
        "line": line,
        "confidence": str(h.get("confidence") or "medium").lower(),
        "evidence": str(h.get("evidence") or h.get("required_control_point") or "")[:300],
    }


# 「源码路径当 HTTP 端点」的形态：``xxx.java:118``（离线 BOLA 分析器 entry_point 的默认形状）。
# 命中即说明该字段承载的是代码定位而非 HTTP 路由，不能进 a1_evidence.target_endpoint。
_SOURCE_PATH_ENDPOINT_RE = re.compile(r"\.(java|kt|py|go|js|ts|rb|php|cs|scala)\s*:\s*\d+\s*$", re.I)


def _dedup_hypos(hypos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """业务族三路假说去重（保留首次出现的那条）。

    LLM 链路（A1BusinessLogicAIAgent）、BOLA 离线兜底（a1_bola_analyzer）、结构特征
    确定性检测（a1_business_structure_analyzer）会对同一个漏洞各产出一条假说；不去重
    会让 findings 计数虚高，也会让同一路由的 trigger_spec 被重复登记。

    去重键按优先级：
    - 有源码定位 → ``(归一化文件, 行号, 规范族, 参数名)``。三路对同一 handler 定位到的
      行号一致（都是方法声明行），因此能正确合并；族不同（如同一方法的 IDOR 与金额篡改）
      或参数不同则不合并。
    - 无源码定位 → 退化为 ``(路由, 规范族, 参数名)``。
    """
    from src.core.exploit_spec import canonical_business_logic_family
    from src.core.path_norm import normalize_path_key

    seen = set()
    out: List[Dict[str, Any]] = []
    for h in hypos or []:
        h = h or {}
        family = canonical_business_logic_family(str(h.get("family") or h.get("vuln_type") or ""))
        param = str(h.get("vulnerable_param") or h.get("param") or "").strip().lower()

        file = str(h.get("file") or "")
        line = h.get("line")
        if line is None and h.get("entry_point"):
            ep = str(h["entry_point"])
            if ":" in ep:
                fpart, _, lpart = ep.rpartition(":")
                if not file:
                    file = fpart
                try:
                    line = int(lpart)
                except (TypeError, ValueError):
                    line = None
        if file:
            key = (normalize_path_key(file), line, family, param)
        else:
            route = str(h.get("target_endpoint") or h.get("route") or h.get("entry_point") or "")
            key = (route.strip().lower(), None, family, param)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


class A1PipelineService(StageService):
    stage_name = "a1"

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        # 配置统一：codeql bin_path 优先 self.config，否则 config/codeql.yaml(+环境变量)。
        _codeql_bin = (self.config.get("codeql") or {}).get("bin_path") or (
            _cfg.codeql_bin_path() if _cfg else None)
        self._codeql = CodeQLAdapter(codeql_bin=_codeql_bin)
        self._semantic = A1CodeQLSemanticAgent(self.config)

    def _codeql_enabled(self) -> bool:
        """是否启用 CodeQL 数据流通道。

        优先级：self.config.a1_use_codeql（编排层运行时决策）> config/codeql.yaml enabled。
        """
        _v = self.config.get("a1_use_codeql")
        if _v is not None:
            return bool(_v)
        return bool(_cfg.codeql_enabled(default=True)) if _cfg else True
        # 工厂产出语义整合 agent（兼容 StageService.create）；scan_files 直接走项目级 CodeQL。
        super().__init__(manifest=A1_MANIFEST, factory=lambda: self._semantic)

    # ---------------- 注入类：CodeQL 数据流 + AI 语义整合 ----------------
    def scan_files(self, files: List[Dict], code_root: Optional[str] = None) -> List[ScanResult]:
        """注入类主链路：CodeQL 扫描（优先扫原始项目根）→ AI 语义整合；CodeQL 不可用 /
        构建失败 / 空结果时，回退确定性轻量 sink 兜底（a1_injection_heuristic）。

        返回每文件一个 ScanResult（保持历史「每文件一个」契约）。同时记录 ``_last_scan_meta``
        供报告区分引擎（codeql / heuristic-fallback / heuristic-only / none）与 CodeQL 状态，
        消除「构建失败」与「确实无漏洞」的状态歧义。
        """
        self._last_scan_meta = {"engine": "none", "codeql_status": "unavailable", "heuristic_used": False}
        if not files:
            return []

        # M12：语言从「一个」改成「一组」。一个工作区可以同时是 Java + 前端（java 源码
        # 里带 static 前端资源的靶场很常见），只按单一语言建库会把另一语言的库整个漏掉
        # （表现为该语言零告警，被误读成「无漏洞」）。
        languages = self._detect_languages(files)
        self._last_scan_meta["languages"] = list(languages)
        results: List[ScanResult] = []
        codeql_enabled = self._codeql_enabled()

        # ---- CodeQL 通道（数据流 + AI 语义整合）：按检测到的语言各建一个库 ----
        codeql_results: List[ScanResult] = []
        if codeql_enabled and self._codeql.is_available():
            per_lang: Dict[str, str] = {}
            for lang in languages:
                got = self._scan_language(files, lang, per_lang, code_root)
                if got:
                    codeql_results.extend(got)
                per_lang[lang] = "ok" if got else ("empty" if not per_lang.get(lang) else "empty")
            self._last_scan_meta["codeql_status"] = (
                "ok" if codeql_results else "build_failed_or_empty")
            self._last_scan_meta["codeql_languages"] = per_lang
            if not codeql_results:
                # 否则「构建失败」被误读成「确实无漏洞」，TP/FP 口径失去可信基础。
                logger.error(
                    "[A1][codeql] CodeQL 已启用但零结果（build_failed_or_empty，languages=%s）→ "
                    "降级 heuristic；**本次结果为启发式规则匹配，非语义数据流分析**", per_lang)

        # 原逻辑「CodeQL 有结果就整段跳过 heuristic」会在 CodeQL 覆盖不满时静默丢掉
        # crypto/weakrand/securecookie/trustbound 等五类保底召回（占 benchmark 样本 41.5%）。
        # 现改为两通道都跑，结果取并集：重叠命中按 (type, sink, 行±3) 去重，保留 CodeQL 条目
        # （其数据流证据更强），heuristic 独苗照常并入（source 已自带 a1-injection-heuristic 打标）。
        heur_vulns = _heuristic_injection(files)

        if codeql_results and heur_vulns:
            results, heur_added = self._merge_heuristic_into_codeql(codeql_results, heur_vulns)
            self._last_scan_meta["heuristic_used"] = True
            self._last_scan_meta["heuristic_merged_count"] = heur_added
            self._last_scan_meta["engine"] = "codeql+heuristic"
        elif codeql_results:
            results = codeql_results
            self._last_scan_meta["engine"] = "codeql"
        else:
            results = self._bucket_vulns(heur_vulns)
            self._last_scan_meta["heuristic_used"] = bool(heur_vulns)
            _codeql_ready = bool(codeql_enabled and self._codeql.is_available())
            self._last_scan_meta["engine"] = (
                "heuristic-fallback" if _codeql_ready else "heuristic-only"
            )
            # 默认禁用 CodeQL 时也必须告警一次，让人知道本次是规则匹配而非跨过程数据流。
            if not _codeql_ready:
                logger.warning(
                    "[A1][codeql] CodeQL 未启用（a1_use_codeql=%s, available=%s）→ 本次为 "
                    "heuristic-only 模式；**结果为启发式规则匹配，非跨过程语义分析**",
                    codeql_enabled, self._codeql.is_available())

        # CodeQL 主链路成功时，确定性 heuristic 兜底被整段跳过（上方 if not results 分支不进），
        # 而 curated skill（如 CVE-2022-22978 这类配置型/模式型漏洞）CodeQL 默认查询集不覆盖，
        # 会被静默漏检。故无论 CodeQL 是否启用/成功，active skill 规则都须独立扫描并并入结果，
        # 使这些手工校验过的规则始终是 A1 的「保底召回」。仅并入 active skill（staging 不参与运行时）。
        skill_vulns = self._scan_active_skill_rules(files)
        if skill_vulns:
            results = self._merge_skill_vulns(results, skill_vulns)
            self._last_scan_meta["skill_channel_used"] = True
            self._last_scan_meta["skill_channel_count"] = len(skill_vulns)

        # （PreparedStatement 绑定 / ESAPI 编码 / SecureRandom / SHA-256+ / 双 Cookie 属性等）
        # 的 finding 在 A1 出口直接抑制，不再流向 A2/候选/确认链路。fail-open：无证据不抑制。
        try:
            from src.core.safe_patterns import build_file_index, filter_scan_results
            # 不解析成绝对路径则窗口读不到 → 抑制规则静默失效。
            results, suppressed = filter_scan_results(results, file_index=build_file_index(files))
            if suppressed:
                self._last_scan_meta["safe_pattern_suppressed"] = len(suppressed)
                self._last_scan_meta["safe_pattern_rules"] = sorted({s["rule"] for s in suppressed})
                logger.info("[A1] 安全实现负向模式抑制 %d 条 finding（规则=%s）",
                            len(suppressed), self._last_scan_meta["safe_pattern_rules"])
        except Exception as _e:
            logger.warning("[A1] 安全实现负向模式执行失败（不阻断，保留原结果）：%s", _e)

        # 补齐：输入文件但本阶段未产出告警的，仍返回空 ScanResult，保持「每文件一个」契约
        produced = {r.file for r in results}
        for f in files:
            if f.get("path") not in produced:
                results.append(ScanResult(file=f.get("path", ""), vulnerabilities=[], agent="a1"))
        return results

    @staticmethod
    def _bucket_vulns(vulns: List[Vulnerability]) -> List[ScanResult]:
        """把扁平 Vulnerability 列表按 file 归并到每文件一个 ScanResult（agent=a1）。"""
        by_file: Dict[str, List[Vulnerability]] = {}
        order: List[str] = []
        for v in vulns:
            key = v.file or ""
            if key not in by_file:
                by_file[key] = []
                order.append(key)
            by_file[key].append(v)
        return [ScanResult(file=f, vulnerabilities=vs, agent="a1") for f, vs in by_file.items()]

    @staticmethod
    def _scan_active_skill_rules(files: List[Dict]) -> List[Vulnerability]:
        """强制互补通道——只跑 active Skill 规则表达式（rule_expression）。

        与 CodeQL / 全量 heuristic 兜底解耦：即便后者已产出结果，curated skill 仍须独立扫描，
        避免配置型/模式型漏洞（如 CVE-2022-22978）被漏检。失败 fail-open，绝不阻断主扫描。
        """
        out: List[Vulnerability] = []
        for f in files or []:
            try:
                content = f.get("content") or ""
                if not content:
                    continue
                lang = f.get("language") or _LANG_BY_EXT.get(
                    Path(f.get("path", "")).suffix.lower()
                ) or "java"
                out.extend(_analyze_content_registry(
                    f.get("path", ""), content, lang=lang, registry_only=True,
                ))
            except Exception as _e:
                logger.warning("[A1] active skill 通道扫描 %s 失败（跳过）：%s",
                               f.get("path"), _e)
                continue
        return out

    @staticmethod
    def _merge_heuristic_into_codeql(
        codeql_results: List[ScanResult], heur_vulns: List[Vulnerability],
    ) -> Tuple[List[ScanResult], int]:
        """启发式 finding 并入 CodeQL 结果，返回 (合并结果, heuristic 新增条数)。

        去重键为 (type, sink, 行±3)：CodeQL 行号是数据流终点行、heuristic 是正则
        命中行，同一条命中常差 1~2 行；沿用精确等值会重复计数推高宽松 FPR（门禁
        判据红线 ≤5pp），故行差 ≤3 视为同一命中，保留证据更强的 CodeQL 条目。
        heuristic 独苗照常并入（source=a1-injection-heuristic，对账可区分通道）。
        """
        by_file: Dict[str, ScanResult] = {r.file: r for r in codeql_results}
        added = 0
        # 原因：两个引擎的 `type` 根本不是一套命名——CodeQL 出 `cross-site scripting` /
        # `template-injection`，启发式出 `xss` / `ssti`，`type` 不等 ⇒ 去重失效
        # （本轮实测：同 (文件,行) 多条的组 49 个，其中 28 组族名不同，
        #   SSTI.java:37 一行报出 `template-injection`/`template injection`/`ssti` 三条）。
        # `sink` 也不再参与比较：CodeQL 的 sink 是 rule_id（`java/xss`），
        # 启发式的是 API 名，两者永远不相等，要求相等等于永远不去重。
        try:
            from src.core.normalize import normalize_family as _nf
        except Exception:  # pragma: no cover
            _nf = lambda x: str(x or "").strip().lower()  # noqa: E731

        def _cfam(x) -> str:
            raw = str(getattr(x, "type", "") or "")
            return _nf(raw) or raw.strip().lower()

        def _sink_compatible(a, b) -> bool:
            """两个 sink 是否可比。

            CodeQL 的 `sink` 是 rule_id（`java/xss`），启发式的是 API 名（`getWriter`），
            两者永远不相等 ⇒ 直接要求相等等于永远不去重。
            但也不能无条件忽略：同一族同一行上的**两个真实 sink**（`Statement.execute`
            vs `Files.write`）是不同漏洞，必须保留。
            折中：**带 `/` 的（rule_id 形态）视为通配**，其余按字符串相等比较。
            """
            sa = str(getattr(a, "sink", "") or "")
            sb = str(getattr(b, "sink", "") or "")
            if not sa or not sb:
                return True
            if sa == sb:
                return True
            return ("/" in sa) != ("/" in sb)

        for v in heur_vulns:
            f = getattr(v, "file", "") or ""
            sr = by_file.get(f)
            if sr is None:
                sr = ScanResult(file=f, vulnerabilities=[], agent="a1")
                by_file[f] = sr
                codeql_results.append(sr)
            _vfam = _cfam(v)
            dup = any(
                _cfam(x) == _vfam
                and abs((x.line or 0) - (v.line or 0)) <= 3
                and _sink_compatible(x, v)
                for x in sr.vulnerabilities
            )
            if not dup:
                sr.vulnerabilities.append(v)
                added += 1
        return codeql_results, added

    @staticmethod
    def _merge_skill_vulns(
        results: List[ScanResult], skill_vulns: List[Vulnerability],
    ) -> List[ScanResult]:
        """把 curated skill 产出的 finding 按 (file,line,type,sink) 去重并入已有 ScanResult。

        同文件已有 ScanResult 则追加，否则新建；保持「每文件一个」契约，不重复计已存在的命中。
        """
        by_file: Dict[str, ScanResult] = {r.file: r for r in results}
        for v in skill_vulns:
            f = getattr(v, "file", "") or ""
            sr = by_file.get(f)
            if sr is None:
                sr = ScanResult(file=f, vulnerabilities=[], agent="a1")
                by_file[f] = sr
                results.append(sr)
            seen = {(x.line, x.type, x.sink) for x in sr.vulnerabilities}
            if (v.line, v.type, v.sink) not in seen:
                sr.vulnerabilities.append(v)
        return results

    @staticmethod
    def _resolve_project_root(files: List[Dict], code_root: Optional[str] = None) -> Optional[str]:
        """从文件列表定位「原始项目根」：取公共目录，向上回溯直到命中构建文件标记。

        命中则返回该根目录（CodeQL 可在此构建数据库）；未命中则回退公共目录本身。

        ``code_root`` 拼成绝对路径，否则 CodeQL create_database 在错误目录执行。
        """
        paths = [f.get("path") for f in files if f.get("path")]
        if not paths:
            return None

        def _abs(p):
            pp = Path(str(p).replace("\\", "/"))
            if pp.is_absolute():
                return pp
            if code_root:
                return Path(code_root) / pp
            return pp

        abs_paths = [_abs(p) for p in paths]
        try:
            common = Path(os.path.commonpath([str(p) for p in abs_paths]))
        except ValueError:
            return None
        if not common.is_dir():
            common = common.parent
        # 向上回溯至多 6 层寻找构建文件
        cur = common
        for _ in range(10):
            if any((cur / marker).exists() for marker in _BUILD_FILE_MARKERS):
                return str(cur)
            parent = cur.parent
            if parent == cur:
                break
            cur = parent
        # 未命中构建文件：回退公共目录（至少保留目录结构）
        return str(common)

    @staticmethod
    def _detect_languages(files: List[Dict]) -> List[str]:
        """识别工作区里出现的**全部**语言（M12，多语言 CodeQL 架构的地基）。

        返回按文件数从多到少排序的语言列表（同数按注册表序，保证可复现）。
        空输入退回 ["python"] —— 与改版前的退化值一致，避免下游拿到空列表炸掉。
        """
        exts: Dict[str, int] = {}
        for f in files or []:
            lang = str(f.get("language") or "").lower()
            if lang in set(_LANG_BY_EXT.values()):
                exts[lang] = exts.get(lang, 0) + 1
                continue
            ext = Path(str(f.get("path") or "")).suffix.lower()
            if ext in _LANG_BY_EXT:
                lang = _LANG_BY_EXT[ext]
                exts[lang] = exts.get(lang, 0) + 1
        if not exts:
            return ["python"]
        # 注册表顺序兜底稳定排序（两个语言文件数相同时取注册表先出现的那个）
        ordered = [k for k in dict.fromkeys(_LANG_BY_EXT.values()) if k in exts]
        ordered.sort(key=lambda k: -exts[k])
        return ordered

    @classmethod
    def _detect_language(cls, files: List[Dict]) -> str:
        """单语言退化视图（保留历史调用点）。"""
        langs = cls._detect_languages(files)
        return langs[0] if langs else "python"

    def _scan_language(self, files: List[Dict], language: str,
                       per_lang: Dict[str, str], code_root: Optional[str] = None) -> List[ScanResult]:
        """对单个语言跑一次 CodeQL（原始项目根优先，失败/空结果则列文件建临时工程）。

        ``per_lang`` 用来记录每个语言的收尾状态（ok / empty / build_failed），
        使 A1 能区分「这个语言真没告警」与「这个语言的库没建起来」——
        两者混在一起就会把构建失败读成无漏洞。
        """
        got: List[ScanResult] = []
        # 优先对「原始项目根」跑 CodeQL（保留 pom/build 与目录结构，避免临时工程路径错位）
        root = self._resolve_project_root(files, code_root)
        if root:
            got = self._semantic.scan_project(root, language=language)
        if not got:
            # 兜底：列文件重建临时工程（适用于无构建文件的纯语言，如单文件 python/go）
            #
            # 临时工程没有 pom.xml，`mvn -B compile` 必然失败，而失败信息会覆盖掉
            # 真实原因（本轮实测：真实根上 create 成功、analyze 未跑，
            # 却只看到临时工程里 "mvn compile failed"，排查方向被带偏）。
            # 判据：根目录有 pom.xml / build.gradle 就跳过临时兜底。
            _has_build = bool(root) and any(
                os.path.isfile(os.path.join(root, n))
                for n in ("pom.xml", "build.gradle", "build.gradle.kts"))
            if _has_build:
                logger.warning(
                    "[A1][codeql] %s 有构建文件但 CodeQL 无产出，跳过临时工程兜底"
                    "（临时工程无 pom，mvn 必失败，只会掩盖真实原因）；reason=%s",
                    language, str(getattr(self._semantic, "_last_codeql_reason", ""))[:300])
            else:
                tmp = Path(tempfile.mkdtemp(prefix="a1-codeql-"))
                try:
                    self._write_temp_project(files, tmp)
                    got = self._semantic.scan_project(str(tmp), language=language)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
        per_lang[language] = "ok" if got else "empty"
        if not got:
            # 「是构建失败、分析失败，还是真的没告警」。
            try:
                _reason = str(getattr(self._semantic, "_last_codeql_reason", "") or "")
                _status = str(getattr(self._semantic, "_last_codeql_status", "") or "")
                if _reason or _status:
                    self._last_scan_meta["codeql_reason"] = (_reason or _status)[:400]
                    self._last_scan_meta["codeql_reason_lang"] = language
            except Exception:
                pass
        return got

    @staticmethod
    def _write_temp_project(files: List[Dict], tmp: Path) -> None:
        for f in files:
            rel = f.get("path") or "source.txt"
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(f.get("content", "") or "", encoding="utf-8", errors="ignore")

    def codeql_status(self) -> Dict[str, object]:
        """A1 外接 CodeQL 能力状态（供编排/报告展示）。

        新增 ``last_scan_meta``：暴露最近一次 scan_files 实际使用的引擎与 CodeQL 状态，
        使报告能区分「codeql 扫描成功 / codeql 构建失败→轻量兜底 / codeql 禁用→仅轻量兜底」，
        避免「构建失败」被误读为「无漏洞」。
        """
        available = self._codeql.is_available()
        meta = getattr(self, "_last_scan_meta", None) or {"engine": "none", "codeql_status": "unavailable", "heuristic_used": False}
        # 静态路由前置绑定指标随状态一起暴露，便于前端/报告看到"多少条 finding 已静态拿到真实路由"。
        route_bind = getattr(self, "_last_route_bind_meta", None)
        if route_bind:
            meta = dict(meta)
            meta["route_bind"] = route_bind
        return {
            "available": available,
            "version": self._codeql.version() if available else "",
            "enabled": self._codeql_enabled(),
            # 注入类轻量兜底：CodeQL 不可用/构建失败时仍能检出明显 sink，不再以 0 结果误判安全
            "fallback": "injection-heuristic",
            "injection_engine": "codeql+ai-semantic",
            "last_scan_meta": meta,
        }

    def scan_project_with_codeql(self, project_path: str, language: str = "python") -> Dict[str, object]:
        """A1 外接 CodeQL 扫描入口。返回带 status 字段的结果（build_failed 等清晰可辨）。

        CodeQL 构建失败 / 空结果时，附加 ``heuristic_alerts``（轻量 sink 兜底），
        供调用方在不依赖 Maven/CodeQL 的情况下仍能见到明显 sink。
        """
        if not self._codeql_enabled():
            return {"available": False, "status": "disabled", "alerts": [], "reason": "a1_use_codeql disabled"}
        result = self._codeql.scan(project_path, language=language)
        # 构建失败或 0 告警时附轻量兜底，避免「未扫描」被当作「无漏洞」
        if result.get("status") in ("build_failed", "analyze_failed", "no_vuln", "unavailable"):
            try:
                from src.agents.a1_injection_heuristic import scan_path as _heuristic_scan_path
                heur = _heuristic_scan_path(project_path, language)
                result["heuristic_alerts"] = [
                    {"file": v.file, "line": v.line, "type": v.type, "severity": v.severity, "sink": v.sink}
                    for v in heur
                ]
            except Exception:
                result["heuristic_alerts"] = []
        return result

    # ---------------- 业务逻辑类：AI Agent 语义识别（主链路） ----------------
    def analyze_bola(self, files: List[Dict]) -> List[Dict[str, object]]:
        """BOLA 业务逻辑策略分析：源文件 → BOLA 假说（family=IDOR，便于 vuln_hash 对齐）。"""
        return _analyze_bola(files)

    def analyze_business_logic(self, files: List[Dict]) -> List[Dict[str, object]]:
        """ 业务逻辑策略分析（全类目）：AI Agent 语义识别为主链路。

        主链路 = ``A1BusinessLogicAIAgent``（LLM 语义识别）；无 LLM 时降级为自写启发式分析器
        （离线兜底，非主链路）。CodeQL 在该链路中仅做辅助结构验证。
        """
        from src.agents.a1_business_logic_ai_agent import A1BusinessLogicAIAgent
        return A1BusinessLogicAIAgent(self.config).analyze_sources(files)

    def analyze_business_structure(self, files: List[Dict]) -> List[Dict[str, object]]:
        """业务族「结构特征」**确定性**检测（不调 LLM）。

        这是消除「业务逻辑类 findings 只能靠 LLM 产出」单点故障的关键一环：
        ``analyze_business_logic`` 走 LLM、``analyze_business_structure`` 走纯静态规则
        。LLM 整体不可用时，业务族仍有一批确定性候选产出。

        开关：``a1_business_structure``（默认开；关掉即退回纯 LLM 口径，便于 A/B 对照）。
        """
        if not self.config.get("a1_business_structure", True):
            return []
        from src.agents.a1_business_structure_analyzer import analyze_files as _analyze_structure
        return _analyze_structure(files)

    # ---------------- 业务逻辑类并入 A1 findings，为 A2 提供证据基础 ----------------
    def merge_business_logic_findings(
        self, a1_results: List[ScanResult], files: List[Dict]
    ) -> List[ScanResult]:
        """把 analyze_business_logic（AI 主链路）+ analyze_bola（越权离线兜底）的假说并入
        A1 findings（每文件一个 ScanResult），并把这些假说作为 business_logic_candidates 挂到
        ScanResult.evidence，使其经 _build_a1_evidence_index → a1_evidence_index 注入 A2 LLM prompt，
        形成 A2 的证据基础（让 A2 的越权/状态机/计算逻辑等假说有 A1 静态线索可交叉印证）。

        best-effort：任一分析器失败都不阻断注入类结果返回。
        """
        try:
            bl_hypos = self.analyze_business_logic(files) or []
        except Exception as _e:
            logger.warning("[A1] 业务逻辑 AI 分析失败（回退空，不影响注入类）：%s", _e)
            bl_hypos = []
        try:
            bola_hypos = self.analyze_bola(files) or []
        except Exception as _e:
            logger.warning("[A1] BOLA 分析失败（回退空，不影响注入类）：%s", _e)
            bola_hypos = []
        try:
            struct_hypos = self.analyze_business_structure(files) or []
        except Exception as _e:
            logger.warning("[A1] 业务族结构特征检测失败（回退空，不影响注入类）：%s", _e)
            struct_hypos = []

        # LLM 链路 / BOLA 离线兜底 / 结构特征确定性检测三路合并后按
        # 「路由 + 规范族 + 参数」去重，避免同一漏洞被三路各记一条导致 findings 虚高。
        hypos: List[Dict[str, Any]] = _dedup_hypos(
            list(bl_hypos) + list(bola_hypos) + list(struct_hypos)
        )
        if not hypos:
            return a1_results

        # 按文件归并：复用既有 ScanResult（追加 vuln + 扩展 evidence），或新建。
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for h in hypos:
            f = str(h.get("file") or "")
            if not f and h.get("entry_point"):
                f = str(h["entry_point"]).rsplit(":", 1)[0]
            by_file.setdefault(f, []).append(h)

        results_map = {r.file: r for r in a1_results}
        new_results = list(a1_results)
        added = 0
        for f, hs in by_file.items():
            vulns = [_hypo_to_vulnerability(h) for h in hs]
            candidates = [_hypo_to_candidate(h) for h in hs]
            added += len(vulns)
            if f in results_map:
                sr = results_map[f]
                sr.vulnerabilities.extend(vulns)
                sr.evidence.setdefault("business_logic_candidates", []).extend(candidates)
            else:
                new_results.append(ScanResult(
                    file=f, vulnerabilities=vulns, agent="a1",
                    evidence={"business_logic_candidates": candidates},
                ))
        logger.info("[A1] 业务逻辑类并入 A1 findings：%d 条假说（BOLA/越权/状态机/计算逻辑/认证会话/滥用DoS）", added)
        return new_results

    def bind_static_routes(
        self, a1_results: List[ScanResult], files: List[Dict]
    ) -> List[ScanResult]:
        """用静态解析出的 Spring 路由，给每条 A1 finding 前置绑定真实 HTTP 入口。

        此前路由只能靠 A2 LLM 在语义分析时"顺便"猜，代价是：LLM 一挂业务族 findings
        直接归零；LLM 敷衍输出 "/"、" /admin/"、"/admin/," 这类残缺路由写进
        exploit_spec 后 D2 构造请求必失败，整批 findings 被丢弃。路由其实是**源码里的
        确定性事实**（@RestController/@Controller + 类级 @RequestMapping + 方法级
        @*Mapping），不该交给 LLM 猜。

        落地方式（不新开通道，沿用既有单一真相源）：
        - 写 ``v.a1_evidence.target_endpoint`` / ``http_method``：这两个字段是
          ``resolve_endpoint_full`` 的一等候选（候选 ⑤ + Tier 3.5 兜底），因此 A2 阶段
          的通道 A/B 两处投影会自动得到同一条路由，不会漂移。
        - 写 ``v.exploit_spec.entry.route/method``：只在原本为空时填，使即便 A2 整个
          阶段失败，finding 也已携带可达入口（消除"A2 一挂业务族全消失"的前置条件）。
        - 未命中静态路由的标 ``route_status='static-failed'``，留给 A2 LLM 推断，
          并且**绝不**回填任何猜测值（宁缺毋滥）。

        best-effort：任何异常都不影响既有 A1 结果返回。
        """
        try:
            from src.core.route_resolver import build_route_index, resolve_route_for_finding
        except Exception as _e:  # 模块缺失不应拖垮 A1
            logger.warning("[A1] 静态路由模块不可用（跳过前置绑定）：%s", _e)
            return a1_results

        try:
            index = build_route_index(files)
        except Exception as _e:
            logger.warning("[A1] 静态路由索引构建失败（跳过前置绑定）：%s", _e)
            return a1_results

        if not index:
            self._last_route_bind_meta = {"routes": 0, "bound": 0, "failed": 0, "skipped": 0}
            return a1_results

        bound = 0
        failed = 0
        skipped = 0
        for sr in a1_results or []:
            for v in getattr(sr, "vulnerabilities", None) or []:
                if not getattr(v, "file", ""):
                    skipped += 1
                    continue
                hit = None
                try:
                    hit = resolve_route_for_finding(
                        index, file=v.file, line=getattr(v, "line", None)
                    )
                except Exception as _e:
                    logger.debug("[A1] 静态路由绑定异常（%s）：%s", v.file, _e)
                    hit = None

                ev = getattr(v, "a1_evidence", None)
                if not isinstance(ev, dict):
                    ev = {}
                    setattr(v, "a1_evidence", ev)

                if not hit:
                    failed += 1
                    ev["route_status"] = "static-failed"
                    # 顺手清掉「源码路径当路由」的污染：离线 BOLA 分析器的 entry_point 形如
                    # ``.../OrderService.java:118``，会被 _hypo_to_vulnerability 一并写进
                    # a1_evidence.target_endpoint。该字段是 resolve_endpoint_full 的一等候选，
                    # target_endpoint 就是 orderservice.java:118/131）。entry_point 本身
                    # （代码定位语义）保持不变，只清 HTTP 端点字段。
                    if _SOURCE_PATH_ENDPOINT_RE.search(str(ev.get("target_endpoint") or "")):
                        ev["target_endpoint"] = ""
                        ev["route_status"] = "static-failed-source-path-cleared"
                    continue

                bound += 1
                ev["route_status"] = "static"
                ev["target_endpoint"] = hit["route"]
                ev["http_method"] = hit["method"]
                ev["static_route_params"] = hit["params"]
                ev["route_handler"] = hit["qualified_name"]
                if hit.get("view_template"):
                    ev["view_template"] = hit["view_template"]
                # 参数名：仅在尚无参数名、且该路由只有唯一候选入参时补位，绝不猜多参场景
                if not str(ev.get("vulnerable_param") or "").strip():
                    cands = [p for p in hit["params"] if p.get("name")]
                    if len(cands) == 1:
                        ev["vulnerable_param"] = cands[0]["name"]

                # exploit_spec.entry：只在为空时填（A2 的 _pre_resolve_a2_endpoints 会用同一
                # 真相源覆写，结果一致；此处填是为了 A2 整体失败时 finding 仍带可达入口）
                try:
                    spec = getattr(v, "exploit_spec", None)
                    if not isinstance(spec, dict) or not spec:
                        # 经 normalize_exploit_spec 补全后所有语义字段为空，且掩盖了「该 finding
                        # 从未经过 A2 造弹」这一事实，是  payload_family 大面积为空的成因之一。
                        try:
                            from src.core.exploit_spec import empty_exploit_spec as _empty_spec
                            spec = _empty_spec()
                        except Exception:
                            spec = {}
                        v.exploit_spec = spec
                    entry = spec.setdefault("entry", {})
                    if not str(entry.get("route") or "").strip():
                        entry["route"] = hit["route"]
                        entry["method"] = hit["method"]
                        entry["resolved_by"] = "a1-static-route"
                    # 入口已被静态证明为真实 HTTP 入口
                    v.has_http_entry = True
                except Exception as _e:
                    logger.debug("[A1] exploit_spec 回填失败（%s）：%s", v.file, _e)

        self._last_route_bind_meta = {
            "routes": len(index),
            "bound": bound,
            "failed": failed,
            "skipped": skipped,
        }
        logger.info(
            "[A1] 静态路由前置绑定：索引 %d 条路由，绑定成功 %d 条，未命中 %d 条，无文件 %d 条",
            len(index), bound, failed, skipped,
        )
        return a1_results

    # ---------------- 模板层 XSS：跨文件确定性关联（块4 #17/#18）----------------
    def merge_template_xss_findings(
        self, a1_results: List[ScanResult], files: List[Dict]
    ) -> List[ScanResult]:
        """把模板层 XSS（th:utext 跨文件关联）假说并入 A1 findings（注入族，非业务逻）。

        xss 属注入族（exploit_spec._INJECTION_FAMILIES），故并入时 **不** 标 business_logic=True，
        走注入族链路（A2 绑定 entry.route → D2 验证）。产物为确定性检出，不依赖 A2 LLM 发现。

        best-effort：异常绝不影响注入类 / 业务逻类结果返回。
        """
        try:
            from src.agents.a1_template_xss_analyzer import analyze_files as _analyze_xss
            xss_hypos = _analyze_xss(files) or []
        except Exception as _e:
            logger.warning("[A1] 模板层 XSS 分析失败（回退空，不影响其它结果）：%s", _e)
            return a1_results
        if not xss_hypos:
            return a1_results

        # 按 Controller 文件归并（entry_point 即 控制器文件:行号）
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for h in xss_hypos:
            f = str(h.get("entry_point") or "").rsplit(":", 1)[0]
            by_file.setdefault(f, []).append(h)

        results_map = {r.file: r for r in a1_results}
        new_results = list(a1_results)
        added = 0
        for f, hs in by_file.items():
            vulns = [_xss_to_vulnerability(h) for h in hs]
            added += len(vulns)
            if f in results_map:
                results_map[f].vulnerabilities.extend(vulns)
            else:
                new_results.append(ScanResult(file=f, vulnerabilities=vulns, agent="a1"))
        logger.info("[A1] 模板层 XSS 并入 A1 findings：%d 条（reflected/stored，注入族）", added)
        return new_results


def _xss_to_vulnerability(h: Dict[str, Any]) -> "Vulnerability":
    """模板层 XSS 假说 → Vulnerability（注入族口径，entry_point 承载真实路由供 A2 绑定）。"""
    from src.core.models import Vulnerability, rule_hit_label

    h = h or {}
    ep = str(h.get("entry_point") or "")
    # entry_point 形如 "控制器文件:行号"；路由单独存于 target_endpoint。A2 消费 vuln.entry_point
    # 推导路由，故此处把真实 HTTP 路由写入 entry_point（与 vertical_privesc 等假说口径一致）。
    route = str(h.get("target_endpoint") or "")
    method = str(h.get("http_method") or "GET")
    param = str(h.get("vulnerable_param") or "")
    subtype = str(h.get("subtype") or "reflected")
    tpl_sink = str(h.get("template_sink") or "")
    wep = str(h.get("write_endpoint") or "")
    confidence = str(h.get("confidence") or "high").lower()
    severity = "high" if confidence == "high" else "medium"
    line = None
    if ":" in ep:
        try:
            line = int(ep.rsplit(":", 1)[-1])
        except (TypeError, ValueError):
            line = None
    display_type = "Reflected XSS" if subtype == "reflected" else "Stored XSS"
    v = Vulnerability(
        type=display_type,
        severity=severity,
        line=line,
        description=str(h.get("evidence") or ""),
        fix="对模板输出做 HTML 转义（改用 th:text，或对 th:utext 内容先做 HTML 实体编码），并对用户输入做输入校验/白名单。",
        file=ep.rsplit(":", 1)[0] if ":" in ep else "",
        entry_point=route,  # A2 路由绑定关键字段
        sink=f"template:{tpl_sink} th:utext",
        has_http_entry=True,
        verdict="待分析",
        source="a1-template-xss",
        confidence=confidence,
        detection_method="rule",
        rule_name=rule_hit_label(display_type, "xss", "th:utext"),
    )
    setattr(v, "a1_evidence", {
        "business_logic": False,
        "category": "xss",
        "family": "xss",
        "subtype": subtype,
        "target_endpoint": route,
        "http_method": method,
        "vulnerable_param": param,
        "template_sink": tpl_sink,
        "write_endpoint": wep,
        "entry_method": method,
    })
    return v
