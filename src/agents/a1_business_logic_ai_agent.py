"""A1 业务逻辑漏洞：AI Agent 语义识别为主链路（替代自写正则 analyzer 作为主力）。

重构前业务逻辑漏洞由 6 个自写启发式 analyzer（a1_*_analyzer.py）直接产出假说，作为主链路。
该路线泛化差、依赖正则/关键字、逼近不了真实业务语义。按架构决议：

- **主链路**：``A1BusinessLogicAIAgent`` 用 LLM 做语义识别——理解「敏感操作 + 缺失控制点」
  （归属校验/角色校验/状态守卫/边界校验/限流）的业务模式，产出带 category 的假说。
- **离线兜底（非主链路）**：当未配置 LLM（ModelGateway 离线）时，降级调用 6 个自写启发式
  analyzer。这些 analyzer 明确标注 ``IS_PRIMARY_PATH = False``，仅作为无 LLM 时的低成本启发式，
  不在主链路中。
- **CodeQL 辅助结构验证**：当本机 CodeQL CLI 可用时，对假说做辅助校验——确认敏感参数是否
  经过 ownership / 权限校验函数（结构层面），结果写入每条假说的 ``codeql_structural_checked``。

所有假说统一含 ``category`` 标签（bola / vertical_privesc / cross_module_privesc /
state_machine / calculation_logic / auth_session / abuse_dos），便于下游 D1 重放验证与
``vuln_hash`` 聚类去重（见 src/core/vuln_hash.py:cluster_business_logic_hypotheses）。
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from src.agents.a1_abuse_dos_analyzer import analyze_sources as _analyze_abuse
from src.agents.a1_auth_session_analyzer import analyze_sources as _analyze_auth
from src.agents.a1_bola_analyzer import analyze_sources as _analyze_bola
from src.agents.a1_calculation_logic_analyzer import analyze_sources as _analyze_calculation
from src.agents.a1_codeql_adapter import CodeQLAdapter
from src.agents.a1_race_analyzer import analyze_sources as _analyze_race
from src.agents.a1_state_machine_analyzer import analyze_sources as _analyze_state_machine
from src.agents.a1_vertical_privesc_analyzer import analyze_sources as _analyze_vertical
from src.core.model_gateway import ModelGateway, gateway_from_config, resolve_llm_config
from src.core.models import rule_hit_label

ALL_CATEGORIES = (
    "bola", "vertical_privesc", "cross_module_privesc", "state_machine",
    "calculation_logic", "auth_session", "abuse_dos", "race",
)

_CATEGORY_DESC = {
    "bola": "水平越权（IDOR）：敏感资源操作缺失归属校验",
    "vertical_privesc": "垂直越权：高权限操作缺失角色/权限校验",
    "cross_module_privesc": "跨模块/跨业务越权：跨服务调用缺失 scope/tenant 隔离",
    "state_machine": "状态机/流程控制：状态转换操作缺失当前状态前置校验",
    "calculation_logic": "计算与交易逻辑：客户端参数参与金额/数量运算缺失服务端边界校验",
    "auth_session": "认证与会话：验证码回显/无校验环节/重置 Token 未绑定用户/未授权接口/弱 JWT/签名绕过",
    "abuse_dos": "滥用与资源消耗：通知/批量查询/退款操作缺失频率限制或幂等控制",
    "race": "并发竞争：读-判-写三段非原子，无行锁/条件更新导致超卖/超发/双重消费",
}


class A1BusinessLogicAIAgent:
    """业务逻辑漏洞 AI 语义识别（主链路）。"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        # resolve_llm_config：保证局部投影配置也能拿到 llm 段（详见该函数注释）
        self.gateway = gateway_from_config(resolve_llm_config(self.config))
        self._codeql = CodeQLAdapter(codeql_bin=self.config.get("codeql", {}).get("bin_path"))

    def analyze_sources(self, files: List[Dict[str, Any]], categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """源文件 → 业务逻辑漏洞假说（AI 主链路 / 离线启发式兜底）。"""
        cats = set(categories or ALL_CATEGORIES)
        if self.gateway.is_offline:
            # 离线兜底：自写启发式 analyzer（非主链路）
            return self._offline_heuristic(files, cats)
        try:
            hypos = self._llm_analyze(files, cats)
        except Exception:
            return self._offline_heuristic(files, cats)
        # 主链路确定性兜底（backstop）：即便 LLM 在线，也用静态业务逻分析器补刀，
        # 防止 LLM 漏检各业务族（典型：race/state_machine/calculation_logic/auth_session/
        # abuse_dos 在纯 LLM 主链路下长期 0 命中）。各静态分析器自带 HTTP 路由抽取，
        # 产出的 target_endpoint 可被 trigger_spec 路由门禁直接消费，避免假说因无路由被漏斗丢弃。
        # 仅保留带真实路由的假说（无路由的业务假说无法落 trigger_spec，留着只会成为漏斗噪声）。
        _backstop_calls = []
        if {"bola"} & cats:
            _backstop_calls.append(_analyze_bola)
        if {"vertical_privesc", "cross_module_privesc"} & cats:
            _backstop_calls.append(_analyze_vertical)
        if {"state_machine"} & cats:
            _backstop_calls.append(_analyze_state_machine)
        if {"calculation_logic"} & cats:
            _backstop_calls.append(_analyze_calculation)
        if {"auth_session"} & cats:
            _backstop_calls.append(_analyze_auth)
        if {"abuse_dos"} & cats:
            _backstop_calls.append(_analyze_abuse)
        if {"race"} & cats:
            _backstop_calls.append(_analyze_race)
        for _fn in _backstop_calls:
            try:
                for h in _fn(files):
                    if h.get("category") not in cats:
                        continue
                    if not h.get("target_endpoint"):
                        continue
                    if self._dup_hypo(hypos, h):
                        continue
                    h["source"] = "a1-business-logic-static-backstop"
                    h["detection_method"] = "rule"
                    h["rule_name"] = rule_hit_label(h.get("vuln_type", ""), h.get("family", ""), "")
                    hypos.append(h)
            except Exception as _e:  # 静态 backstop 异常绝不影响 LLM 主链路已产出的假说
                logger.warning("[A1] 静态 backstop 异常（已忽略，不丢弃 LLM 假说）：%s", _e)
        return hypos

    @staticmethod
    def _dup_hypo(hypos: List[Dict[str, Any]], cand: Dict[str, Any]) -> bool:
        """避免静态 backstop 与 LLM 主链路对同一 (行号, 类别) 重复产出假说。"""
        cl = cand.get("category")
        cf = (cand.get("function") or "").lower()
        ce = cand.get("entry_point") or ""
        m = re.search(r":(\d+)$", ce)
        cline = int(m.group(1)) if m else None
        for h in hypos:
            if h.get("category") != cl:
                continue
            hl = h.get("line") or 0
            if cline is not None and hl and cline == hl and (not cf or cf == (h.get("function") or "").lower()):
                return True
        return False

    # ---- 主链路：LLM 语义识别 ----
    def _llm_analyze(self, files: List[Dict[str, Any]], cats: set) -> List[Dict[str, Any]]:
        catalog = {c: _CATEGORY_DESC[c] for c in cats}
        prompt = (
            "你是业务逻辑漏洞分析专家。给定若干源文件，识别其中的业务逻辑漏洞假说。\n"
            "关注的类别与语义：\n"
            + "\n".join(f"- {c}: {d}" for c, d in catalog.items())
            + "\n\n对每一个疑似点，输出 JSON 数组，元素字段：\n"
            "  file(相对路径), line(int), category(上述类别之一), vuln_type(大写短标识),\n"
            "  family(如 IDOR/privesc/state-machine/business-logic/auth-session/abuse-dos),\n"
            "  target_endpoint(可选, 如 /api/...), http_method(可选), vulnerable_param(可选),\n"
            "  language, confidence(high/medium/low), evidence(一句话命中依据)。\n"
            "只返回 JSON 数组，不要解释。\n\n"
            "FILES:\n"
            + self._format_files(files)[:8000]
        )
        ctx = {"categories": sorted(cats), "file_count": len(files)}
        resp = self.gateway.complete(purpose="business-logic-analysis", prompt=prompt, context=ctx)
        hypos = self._parse_llm_json(resp.text, cats)
        # CodeQL 辅助结构验证（参数是否经过 ownership/权限校验函数）
        if self._codeql.is_available():
            self._aux_codeql_structural_verify(hypos, files)
        for h in hypos:
            h.setdefault("source", "a1-business-logic-ai")
            h["detection_method"] = "rule"
            h["rule_name"] = rule_hit_label(
                h.get("vuln_type", ""), h.get("family", ""), ""
            )
        return hypos

    # ---- 离线兜底（非主链路）：自写启发式 analyzer ----
    def _offline_heuristic(self, files: List[Dict[str, Any]], cats: set) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if "bola" in cats:
            out += [dict(h, category="bola") for h in _analyze_bola(files)]
        if {"vertical_privesc", "cross_module_privesc"} & cats:
            for h in _analyze_vertical(files):
                if h.get("category") in cats:
                    out.append(h)
        if "state_machine" in cats:
            out += _analyze_state_machine(files)
        if "calculation_logic" in cats:
            out += _analyze_calculation(files)
        if "auth_session" in cats:
            out += _analyze_auth(files)
        if "abuse_dos" in cats:
            out += _analyze_abuse(files)
        if "race" in cats:
            out += _analyze_race(files)
        for h in out:
            h.setdefault("source", "offline-heuristic-fallback")
        return out

    # ---- CodeQL 辅助结构验证（可选，best-effort）----
    def _aux_codeql_structural_verify(self, hypos: List[Dict[str, Any]], files: List[Dict[str, Any]]) -> None:
        """当 CodeQL 可用时，对假说做辅助结构验证：敏感参数是否经过 ownership/权限校验。

        实现策略：写入临时项目 → CodeQL 扫描 → 检查假说文件附近是否存在
        ``missing-permission-check`` 类告警（rule_id 含 permission/authz/unauthorized 等）。
        命中则说明「存在校验」，将假说 ``codeql_structural_checked`` 置为 ``has_check``；
        否则置为 ``no_check_evidence``。best-effort：任何异常直接跳过，不阻断主链路。
        """
        try:
            import shutil
            import tempfile
            from pathlib import Path
            tmp = Path(tempfile.mkdtemp(prefix="bl-codeql-"))
            for f in files:
                rel = f.get("path") or "source.txt"
                dst = tmp / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(f.get("content", "") or "", encoding="utf-8", errors="ignore")
            result = self._codeql.scan(str(tmp), language="python")
            shutil.rmtree(tmp, ignore_errors=True)
            alerts = result.get("alerts") or []
            checked_files = {
                (a.get("file", ""), str(a.get("line", "")))
                for a in alerts
                if any(k in (a.get("rule_id", "") + a.get("message", "")).lower()
                       for k in ("permission", "authz", "unauthor", "access-control", "missing-check"))
            }
            for h in hypos:
                key = (h.get("file", ""), str(h.get("line", "")))
                h["codeql_structural_checked"] = "has_check" if key in checked_files else "no_check_evidence"
        except Exception:
            for h in hypos:
                h.setdefault("codeql_structural_checked", "skipped")

    @staticmethod
    def _format_files(files: List[Dict[str, Any]]) -> str:
        chunks = []
        for f in files:
            chunks.append(f"### {f.get('path', '')}\n```\n{(f.get('content', '') or '')[:1500]}\n```")
        return "\n\n".join(chunks)

    @staticmethod
    def _parse_llm_json(text: str, cats: set) -> List[Dict[str, Any]]:
        if not text:
            return []
        raw = None
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            import re
            m = re.search(r"\[.*\]", text, re.DOTALL)
            if m:
                try:
                    raw = json.loads(m.group(0))
                except json.JSONDecodeError:
                    raw = None
        if not isinstance(raw, list):
            return []
        out: List[Dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            cat = (item.get("category") or "").lower()
            if cat not in ALL_CATEGORIES:
                continue
            if cats and cat not in cats:
                continue
            out.append({
                "file": item.get("file", ""),
                "line": item.get("line") or 0,
                "category": cat,
                "vuln_type": item.get("vuln_type") or cat.upper(),
                "family": item.get("family") or "business-logic",
                "target_endpoint": item.get("target_endpoint", ""),
                "http_method": item.get("http_method", ""),
                "vulnerable_param": item.get("vulnerable_param", ""),
                "language": item.get("language", ""),
                "confidence": item.get("confidence", "medium"),
                "evidence": item.get("evidence", ""),
            })
        return out
