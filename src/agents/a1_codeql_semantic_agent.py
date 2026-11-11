"""A1 注入类：CodeQL 数据流 + AI 语义整合（替代自写 yaml 正则引擎）。

重构前 A1 注入类由 ``A1RuleAgent``（src/agents/a1_intelligent_agent.py，自写 yaml 正则引擎）
产出告警。该引擎泛化差、跨语言弱、逼近不了真实漏洞，已按架构决议删除。

新主链路（注入类）：
1. ``CodeQLAdapter`` 做数据流分析，产出 SARIF 告警（参数从哪个入口、到哪个危险 sink、
   有没有经过校验/净化）。CodeQL 不可用或 ``a1_use_codeql`` 未开启时不产出注入类结果，
   **不再回退自写正则引擎**（原 yaml 引擎已删除）。
2. 本模块 ``A1CodeQLSemanticAgent`` 对 CodeQL 告警做「AI 语义整合」：去重、裁剪明显误报、
   标注业务上下文（是否 HTTP 入口可触发等），统一映射为平台 ``Vulnerability`` 模型。

AI 语义整合通过 ``src.core.model_gateway.ModelGateway`` 完成：配置真实 LLM provider 时，
由 LLM 对告警做语义研判；未配置（离线）时降级为确定性映射（rule_id → 漏洞族），
保证平台在无网络/无密钥环境下仍可运行与测试。
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents.a1_codeql_adapter import CodeQLAdapter
from src.core.model_gateway import gateway_from_config, resolve_llm_config

logger = logging.getLogger(__name__)
from src.core.models import ScanResult, Vulnerability, rule_hit_label

# CodeQL rule-id 子串 → 平台漏洞族/类型 的确定性映射（离线兜底用）
_RULE_FAMILY_MAP = (
    # ---- SAVR 自定义查询（tools/codeql-queries）优先登记 ----
    ("sastai/java/weak-hash-algorithm", "Weak Hash Algorithm", "hash"),
    ("sastai/java/sql-injection-extended", "SQL Injection", "sql-injection"),
    ("sastai/java/command-injection-extended", "Command Injection", "command-execution"),
    ("sastai/java/path-injection-extended", "Path Injection", "path-traversal"),
    ("sastai/java/format-string-controlled", "Format String Controlled", "log-injection"),
    # ---- 官方 java-queries 中 Benchmark 五族对应的既有查询 ----
    ("weak-cryptographic-algorithm", "Insecure Crypto Algorithm", "crypto"),
    ("insecure-randomness", "Insecure Randomness", "weakrand"),
    ("insecure-cookie", "Insecure Cookie", "securecookie"),
    ("sensitive-cookie-not-httponly", "Sensitive Cookie Not HttpOnly", "securecookie"),
    ("trust-boundary-violation", "Trust Boundary Violation", "trustbound"),
    ("sql-injection", "SQL Injection", "sql-injection"),
    ("command-line-injection", "Command Injection", "command-execution"),
    ("code-injection", "Code Injection", "code-injection"),
    ("expression-injection", "Expression Injection", "expression-injection"),
    ("path-injection", "Path Injection", "path-traversal"),
    ("path-traversal", "Path Traversal", "path-traversal"),
    ("ldap-injection", "LDAP Injection", "ldap-injection"),
    ("xpath-injection", "XPath Injection", "xpath-injection"),
    ("header-injection", "Header Injection", "header-injection"),
    ("xss", "Cross-Site Scripting", "xss"),
    ("cross-site-scripting", "Cross-Site Scripting", "xss"),
    ("server-side-request-forgery", "SSRF", "ssrf"),
    ("ssrf", "SSRF", "ssrf"),
    ("unsafe-deserialization", "Insecure Deserialization", "deserialization"),
    ("deserialization", "Insecure Deserialization", "deserialization"),
    ("url-redirection", "Open Redirect", "open-redirect"),
    ("log-injection", "Log Injection", "log-injection"),
    ("xxe", "XXE", "xxe"),
    ("xml-external-entity", "XXE", "xxe"),
    ("no-sql-injection", "NoSQL Injection", "nosql-injection"),
    ("template-injection", "Template Injection", "template-injection"),
    ("ldap", "LDAP Injection", "ldap-injection"),
)


def _map_rule_to_family(rule_id: str, message: str) -> str:
    """CodeQL rule_id → 平台族（canonical snake_case）。

    未命中才走下面的子串表；再未命中返回 `unmapped`（不再猜显示名）。
    原因：族名不认识 ⇒ D2 没有证明模板 ⇒ spec 结构性停在 unconfirmed
    。
    """
    # 空 rule_id 不是「未登记的 CodeQL 规则」，是**根本没有规则**（LLM 研判残项）。
    # 若也返回 unmapped，会污染族空间并冒充映射缺口。
    # 约定：空 rule_id → 返回空串，由调用方决定丢弃或另给族。
    if not str(rule_id or "").strip():
        return ""
    try:
        from src.core.family_map import UNMAPPED, canonical_from_rule
        fam, _reason = canonical_from_rule(rule_id)
        if fam and fam != UNMAPPED:
            return fam
    except Exception:
        pass
    text = (rule_id or "") + " " + (message or "")
    low = text.lower()
    for needle, vtype, family in _RULE_FAMILY_MAP:
        if needle in low:
            return family.replace("-", "_")
    try:
        from src.core.family_map import UNMAPPED
        return UNMAPPED
    except Exception:
        return "code_injection"


def _map_rule_to_type(rule_id: str, message: str) -> str:
    """漏洞类型名。与 `_map_rule_to_family` 同源，保证 type 与 family 不再分叉。

    历史坑：这里原来的兜底是 ``tail.replace("-", " ").title``，
    于是 `java/log-injection` 变成 `Log Injection` 并作为 type 落库，
    再流到 `trigger_specs.family`，下游族路由全空。
    """
    return _map_rule_to_family(rule_id, message)


class A1CodeQLSemanticAgent:
    """CodeQL 告警 → 平台 Vulnerability 的语义整合层（AI 主链路 / 离线兜底）。"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        # resolve_llm_config：保证局部投影配置也能拿到 llm 段（详见该函数注释）
        self.gateway = gateway_from_config(resolve_llm_config(self.config))
        self._codeql = CodeQLAdapter(codeql_bin=self.config.get("codeql", {}).get("bin_path"))
        # 而 create_database 其实返回了具体错误（构建命令 stderr / finalize 失败原因），
        # 全被这一层丢掉了 ⇒ 每轮都在猜「是查询包不行还是构建不行」。
        self._last_codeql_reason = ""
        self._last_codeql_status = ""

    # ---- 主入口：项目级 CodeQL 扫描 + 语义整合 ----
    def scan_project(self, project_path: str, language: str = "python") -> List[ScanResult]:
        """整项目 CodeQL 扫描并整合为 ScanResult 列表（每文件一个）。

        注入类主链路；CodeQL 不可用或未开启时返回空结果（无自写正则兜底）。

        ④ A1/CodeQL→A2 稳定输入（Step1+Step2 上游）：每个 Vulnerability 附带 ``a1_evidence``
        （rule_id/message/severity/file/line + entry_candidates/source_candidates/sink_candidates），
        并把按文件聚合后的 a1_evidence 挂到 ``ScanResult.evidence`` 上，供
        ``benchmark_cli._build_a1_evidence_index`` 抽成 ``a1_evidence_index`` 注入 A2 LLM prompt
        （Step3），并在 auto_register_from_a2 时持久化进 ``findings.a1_evidence``（Step2 落库）。
        """
        if not self.config.get("a1_use_codeql") or not self._codeql.is_available():
            return []
        result = self._codeql.scan(project_path, language=language)
        if not result.get("available") or not result.get("alerts"):
            # 保留失败原因：build_failed / analyze_failed / no_vuln 三者的处置完全不同，
            # 丢掉 reason 就只能看到「零结果」。
            try:
                self._last_codeql_status = str(result.get("status") or "")
                _r = str(result.get("reason") or "")
                if _r:
                    # 追加而不是覆盖：一轮里可能先对真实根跑、再对临时工程兜底，
                    # 覆盖会让「真实根为什么失败」永远看不到（本轮踩过）。
                    self._last_codeql_reason = (
                        (self._last_codeql_reason + " | " + _r)[-900:]
                        if self._last_codeql_reason else _r[:900])
            except Exception:
                pass
            return []
        vulns = self.integrate(result["alerts"], {"project_path": project_path, "language": language})
        scan_results = self._bucket_by_file(vulns, project_path)
        # ④：把每个 ScanResult 的 a1_evidence 挂到 .evidence，激活 A1→A2 证据索引链路
        for sr in scan_results:
            sr.evidence = self._merge_a1_evidence(
                [getattr(v, "a1_evidence", {}) for v in sr.vulnerabilities]
            )
        return scan_results

    # ---- A1 证据构造：CodeQL 告警 → a1_evidence（④ Step1 上游数据）----
    def _alert_to_evidence(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """把一条 CodeQL 告警转成 a1_evidence 字典。

        从 relatedLocations 抽取污点源/汇（CodeQL 数据流查询会在 relatedLocations 里给出
        source/sink 节点），供 A2 prompt 注入真实调用入口与污点源候选。
        """
        rels = alert.get("related_locations") or []
        source_candidates: List[Dict[str, Any]] = []
        sink_candidates: List[Dict[str, Any]] = []
        for r in rels:
            kind = (r.get("kind") or "").lower()
            note = r.get("message", "") or ""
            loc = {"file": r.get("file", ""), "line": r.get("line", 0), "note": note}
            low = note.lower()
            if kind == "source" or "source" in low or "tainted" in low:
                source_candidates.append(loc)
            elif kind == "sink" or "sink" in low:
                sink_candidates.append(loc)
        # 主告警位置（sink）始终作为 sink 候选
        sink_candidates.append({
            "file": alert.get("file", ""),
            "line": alert.get("line", 0),
            "note": alert.get("rule_id", ""),
        })
        # 把「像 HTTP 入口」的源（请求参数/用户输入）视为 entry 候选，供 A2 入口定位
        entry_candidates = [
            s for s in source_candidates
            if any(k in (s.get("note", "").lower()) for k in
                    ("request", "parameter", "http", "user input", "userinput", "query", "header"))
        ]
        return {
            "rule_id": alert.get("rule_id", ""),
            "message": alert.get("message", ""),
            "severity": alert.get("severity", ""),
            "file": alert.get("file", ""),
            "line": alert.get("line", 0),
            "entry_candidates": entry_candidates,
            "source_candidates": source_candidates,
            "sink_candidates": sink_candidates,
        }

    @staticmethod
    def _merge_a1_evidence(items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """聚合同一文件的多个 Vulnerability 的 a1_evidence，供 ScanResult.evidence 使用。"""
        merged: Dict[str, Any] = {
            "entry_candidates": [], "source_candidates": [], "sink_candidates": [],
            "rule_id": "", "message": "", "severity": "", "file": "", "line": 0,
        }
        for it in items or []:
            if not it:
                continue
            for key in ("entry_candidates", "source_candidates", "sink_candidates"):
                merged[key].extend(list(it.get(key, []) or []))
            for key in ("rule_id", "message", "severity", "file"):
                if not merged[key] and it.get(key):
                    merged[key] = it[key]
            if not merged["line"] and it.get("line"):
                merged["line"] = it["line"]
        return merged

    # ---- 语义整合：告警列表 → Vulnerability 列表 ----
    def integrate(self, alerts: List[Dict[str, Any]], ctx: Dict[str, Any]) -> List[Vulnerability]:
        """对 CodeQL 告警做语义整合。

        - 在线（配置了 LLM）：交给 LLM 做去重/误报裁剪/业务上下文标注；
        - 离线：确定性映射（rule_id → 漏洞族/类型），并做同文件同规则去重。

        到确定性映射——否则 4452 条 CodeQL 告警被整批丢弃，A1 永久 fallback heuristic。
        """
        if self.gateway.is_offline:
            return self._offline_map(alerts, ctx)
        try:
            triaged = self._llm_triage(alerts, ctx)
            if triaged:
                return triaged
        except Exception:
            # AI 研判失败 → 降级确定性映射，平台不硬停
            pass
        return self._offline_map(alerts, ctx)

    def _offline_map(self, alerts: List[Dict[str, Any]], ctx: Dict[str, Any]) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        seen = set()
        for a in alerts or []:
            rule_id = a.get("rule_id", "")
            message = a.get("message", "")
            family = _map_rule_to_family(rule_id, message)
            vtype = _map_rule_to_type(rule_id, message)
            file = a.get("file", "")
            line = a.get("line") or 0
            sev = (a.get("severity") or "warning").lower()
            severity = "HIGH" if sev in ("error", "high") else ("MEDIUM" if sev == "warning" else "LOW")
            dedup = (file, line, rule_id, vtype)
            if dedup in seen:
                continue
            seen.add(dedup)
            v = Vulnerability(
                type=vtype,
                severity=severity,
                line=line,
                description=message or f"CodeQL alert {rule_id}",
                file=file,
                sink=rule_id,
                source="a1-codeql",
                has_http_entry=False,
                confidence="medium",
                verdict="待分析",
            )
            # A1 是规则模式命中，不走污点流四维度评判：标记 detection_method + 中文规则名
            v.detection_method = "rule"
            v.rule_name = rule_hit_label(vtype, family, rule_id)
            # ④ Step1：把 CodeQL 告警挂为 a1_evidence（供 A2 prompt 注入 + findings 持久化）
            setattr(v, "a1_evidence", self._alert_to_evidence(a))
            out.append(v)
        return out

    def _llm_triage(self, alerts: List[Dict[str, Any]], ctx: Dict[str, Any]) -> List[Vulnerability]:
        prompt = (
            "你是 SAST 语义整合引擎。下方是一组 CodeQL 静态扫描告警（JSON 数组）。\n"
            "请对每个告警给出研判：是否真实漏洞（true_positive / false_positive）、"
            "漏洞族 family（sql-injection/command-execution/xss/ssrf/deserialization/path-traversal 等）、"
            "是否 HTTP 入口可触发（http_entry: true/false）。\n"
            "仅返回 JSON 数组，元素字段：rule_id, file, line, family, type, severity(HIGH/MEDIUM/LOW), "
            "verdict(true_positive/false_positive), http_entry(bool), reason。不要输出解释文字。\n\n"
            f"ALERTS:\n{json.dumps(alerts, ensure_ascii=False)[:6000]}"
        )
        resp = self.gateway.complete(purpose="a1-codeql-semantic-triage", prompt=prompt, context=ctx)
        parsed = self._parse_llm_json(resp.text)
        out: List[Vulnerability] = []
        _dropped_no_type = 0
        # LLM 经常把 rule_id 漏掉（只回 file/line），于是族判定拿不到规则身份，
        # 落库成 `unmapped`。
        # 修法：按 (file, line) 回填原始告警的 rule_id —— 告警本来就在手上，不该丢。
        _by_pos: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for _a in alerts or []:
            _k = (str(_a.get("file") or ""), int(_a.get("line") or 0))
            _by_pos.setdefault(_k, []).append(_a)
        _recovered = 0
        for item in parsed or []:
            if str(item.get("verdict", "")).lower() == "false_positive":
                continue
            # 回填 rule_id：LLM 漏字段时按 (file, line) 找原始告警（多命中取第一条未用过的）
            if not str(item.get("rule_id") or "").strip():
                _cands = _by_pos.get((str(item.get("file") or ""), int(item.get("line") or 0))) or []
                if _cands:
                    _src = _cands.pop(0)  # 取走，避免同一告警被多个残项重复认领
                    item = dict(item)
                    item["rule_id"] = str(_src.get("rule_id") or "")
                    item.setdefault("message", _src.get("message") or "")
                    _recovered += 1
            # 族/类型三级回退：LLM 给的 family → LLM 给的 type → rule_id 映射表。
            # 三者全空说明这条研判项没带任何漏洞身份（只有 file/line），
            # 落库只会变成一条 `unmapped` 噪声。
            _fam = (str(item.get("family") or "").strip()
                    or str(item.get("type") or "").strip()
                    or _map_rule_to_type(item.get("rule_id", ""), ""))
            if not _fam:
                _dropped_no_type += 1
                continue
            v = Vulnerability(
                type=_fam,
                severity=str(item.get("severity") or "MEDIUM").upper(),
                line=item.get("line") or 0,
                description=item.get("reason") or item.get("rule_id") or "",
                file=item.get("file", ""),
                sink=item.get("rule_id", ""),
                source="a1-codeql-ai",
                has_http_entry=bool(item.get("http_entry")),
                confidence="high" if str(item.get("verdict", "")).lower() == "true_positive" else "medium",
                verdict="待分析",
            )
            # A1 是规则模式命中，不走污点流四维度评判：标记 detection_method + 中文规则名
            v.detection_method = "rule"
            v.rule_name = rule_hit_label(
                _fam,
                item.get("family"),
                item.get("rule_id"),
            )
            # ④ Step1：把 LLM 研判对应的 CodeQL 告警（含 rule_id/file/line）挂为 a1_evidence
            setattr(v, "a1_evidence", self._alert_to_evidence(item))
            out.append(v)
        if _recovered:
            logger.info("[A1][codeql] LLM 漏 rule_id 的研判项，已按 (file,line) 回填 %d 条", _recovered)
        if _dropped_no_type:
            logger.warning(
                "[A1][codeql] LLM 研判有 %d 项既无 rule_id 也无法按位置回填，已丢弃（不落 unmapped 噪声）",
                _dropped_no_type)
        return out

    @staticmethod
    def _parse_llm_json(text: str) -> List[Dict[str, Any]]:
        if not text:
            return []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
        # 容忍 ```json ... ``` 包裹
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(0))
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
        return []

    @staticmethod
    def _bucket_by_file(vulns: List[Vulnerability], project_path: str) -> List[ScanResult]:
        """把扁平 Vulnerability 列表按 file 归并到每文件一个 ScanResult。"""
        by_file: Dict[str, List[Vulnerability]] = {}
        order: List[str] = []
        for v in vulns:
            key = v.file or ""
            if key not in by_file:
                by_file[key] = []
                order.append(key)
            by_file[key].append(v)
        return [ScanResult(file=f, vulnerabilities=vs, agent="a1") for f, vs in by_file.items()]
