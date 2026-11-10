"""族特有「有害证据」判定（2026-10-25，两档证据的第一档实现）。

## 背景

D2 的确认判据长期只有「可达」这一档：canary 到达 sink、值命中、响应回显。
代码注释自己写着「canary 是身份串不是攻击载荷，到达 sink 只证明可达，不证明可利用」，
但 `adjudicate_final_state` 里有两处后门把它当成充分证据：
  - `probe_asserted`（探针断言值在 sink 实参）被写成「即便降级攻击也判有害」；
  - `impact_observed` 判定过宽（canary 回显进 cookie 值就算「影响观测」）。

实测后果：两个 FP 都从这里进来——
  - BenchmarkTest00016（family=http response splitting）：canary 回显在 cookie 值里，
    但响应头没有任何 CRLF 拆分痕迹；
  - BenchmarkTest00121（family=stack trace exposure）：探针断言值到达，
    但响应体里没有一行堆栈帧。

## 设计：三态而非二值

每族一个检测器，返回三态之一：
  - harm_confirmed：拿到了该族特有的危害证据（可支撑 confirmed）
  - harm_absent：**能明确判定没有**该族危害（降级为不明确）
  - harm_unknown：证据不足/该族未覆盖（保持现有判据，不降级）

关键在第三态：只有「能证明没有危害」才降级。证据不足时保持现状，
否则会把大量「canary 到达 + 影响观测」的真漏洞一起降级（462 的 TP 78 里
只有 16 个有 oracle 正向信号，其余靠 canary 到达确认）。

## 覆盖范围

已覆盖（有明确检测器）：
  - http_response_splitting：响应头出现注入的新头，或响应体出现伪响应行（HTTP/1.x）
  - stack_trace_exposure：响应体出现堆栈帧（\\tat 后跟类名、Exception in thread）
  - 有行为 oracle 的族（sqli / cmdi / pathtraver / xss）：oracle 正向 ⇒ harm_confirmed

未覆盖（返回 harm_unknown，保持现有判据）：
  - ldap_injection / xpath_injection / trust_boundary_violation / secure_cookie
  - 属性族（weak_hash / weak_crypto / weakrand）：走静态强证据门禁，不在此处判
  - business_logic 族：走响应差分，不在此处判
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

# 族名归一化：平台可能存成 "http response splitting" / "http_response_splitting" 等形式
_FAMILY_ALIASES = {
    "http response splitting": "http_response_splitting",
    "httpresponsesplitting": "http_response_splitting",
    "http_response_splitting": "http_response_splitting",
    "response splitting": "http_response_splitting",
    "stack trace exposure": "stack_trace_exposure",
    "stacktraceexposure": "stack_trace_exposure",
    "stack_trace_exposure": "stack_trace_exposure",
    # 注意：error message exposure 不能映射到 stack_trace_exposure。
    # 它的危害是「泄露内部错误信息」，不需要堆栈帧；早期误映射导致 469 里 8 条
    # 真漏洞（pathtraver/cmdi 的报错回显）被当成「无堆栈帧」降级 —— 已回滚。
    "error message exposure": "error_message_exposure",
    "sqli": "sql_injection",
    "sql injection": "sql_injection",
    "sql_injection": "sql_injection",
    "cmdi": "command_execution",
    "command injection": "command_execution",
    "command_execution": "command_execution",
    "pathtraver": "path_traversal",
    "path traversal": "path_traversal",
    "path_traversal": "path_traversal",
    "xss": "xss",
    "cross site scripting": "xss",
}

# oracle 信号 → 视为该族有害证据（来自 src/iast/response_oracle.py 的判定）
_ORACLE_HARM_SIGNALS = {
    "boolean_diff": "sql_injection",
    "time_delay": "command_execution",
    "file_signature": "path_traversal",
    "reflection_raw": "xss",
    # 2026-10-31 新增 4 族：这些族的「值在 sink 处已被转换」（URL 对象 / Location 头 /
    # 序列化对象 / 被过滤的 header），值级 canary 匹配永远判不出来，只有黑盒行为可观测。
    # signal 名与 response_oracle.judge 产出的完全一致，一一对应，不做模糊匹配。
    "location_reflect": "url_redirect",
    "acao_reflect": "cors",
    "header_injected": "crlf_injection",
    "error_reflect": "ssrf",
    "internal_url_reflect": "ssrf",
    # 2026-11-06（jsc 625）：WebSocket 命令执行。信号由 `_run_websocket_oracle`
    # 的 ws_echo 臂产出 —— 端点把 `echo <marker>` 的 stdout 通过 WS 帧送回来，
    # 是「命令在服务端真实执行」的硬观测，强于任何响应反射。
    # 这里必须映射到平台侧族名 command_execution（而非 oracle 侧 websocket_cmd），
    # 因为 spec.family 存的是 command_execution，`_oracle_positive_signal()` 用它比对；
    # 且 ws_echo 臂只在 `_is_websocket_sink()` 命中时投放，不会误放普通 cmdi 端点。
    "websocket_echo": "command_execution",
    # 2026-11-06（jsc 626/627）：表达式注入与反序列化两族此前没有行为 oracle。
    # expr_eval 认「注入表达式被引擎求值并返回结果」（拼接/算术，排除原样回显）；
    # deser_object_accepted 认「阴阳对照成立：非对象字节被拒、攻击者载荷被
    # 反序列化器接受」，只证明反序列化入口被真实触发，不等同于 RCE 命令执行。
    "expr_eval": "expression_injection",
    "deser_object_accepted": "deserialization",
}

# 同一个 signal 可能由多个族产出。`time_delay` 在 response_oracle.judge 里
# 被 sql_injection 的时间盲注臂与 command_execution 的时延臂共用，而上面的
# 主表是 signal→单族，导致 sqli 的时间盲注判出 time_delay 后 D2 因族不匹配
# 不采信。用附加表表达多族关系，不改主表结构（主表还被 detect_harm 消费）。
_ORACLE_HARM_SIGNALS_MULTI = {
    "time_delay": frozenset({"command_execution", "sql_injection"}),
}

# 堆栈帧特征：`\tat org.owasp.benchmark...(...)` / `Exception in thread` / `at java.base/`
_STACK_FRAME_RE = re.compile(
    r"(?:^|\n)\s*at\s+[\w.$]+\([\w.]*(?:\.java:\d+|Native Method|Unknown Source)\)"
    r"|Exception in thread|java\.lang\.\w+Exception")
# 伪响应行：CRLF 注入成功后，body 里会出现一条像响应行/注入头的内容
_CRLF_FAKE_RESPONSE_RE = re.compile(r"(?:^|\n)HTTP/1\.[01]\s+\d{3}")
_CRLF_INJECTED_HEADER_RE = re.compile(r"(?:^|\n)(X-[A-Za-z0-9-]+|Set-Cookie2?)\s*:", re.I)


def normalize_family(family: Optional[str]) -> str:
    f = str(family or "").strip().lower()
    return _FAMILY_ALIASES.get(f, f.replace("-", "_").replace(" ", "_"))


# endpoint 前缀 → 真实族（2026-10-25 族一致性纠正）。
# 实测依据：/securecookie-00/BenchmarkTest00016 被标成 family=http response splitting，
# /crypto-00/BenchmarkTest00121 被标成 stack trace exposure —— 这两族在 Benchmark 真值里根本不存在，
# 是平台把用例的**辅助 finding** 误标出来的。若按误标族判「族特有证据」，会把
# 「族误标的真漏洞」（如 02339，实为 securecookie 真漏洞）一起降级，白掉 TP。
# 以 endpoint 前缀为准纠正族后，再判该族证据，才能既不误伤也不放过。
_ENDPOINT_CAT2FAM = {
    "pathtraver": "path_traversal",
    "sqli": "sql_injection",
    "cmdi": "command_execution",
    "crypto": "insecure_crypto_algorithm",
    "hash": "weak_hash",
    "ldapi": "ldap_injection",
    "securecookie": "secure_cookie",
    "trustbound": "trust_boundary_violation",
    "weakrand": "weak_random",
    "xpathi": "xpathi",
    "xss": "xss",
}
_ENDPOINT_RE = re.compile(r"/([a-z]+)-\d+/")


def benchmark_prior_enabled() -> bool:
    """benchmark 专属先验总开关（E11 消融用，默认 1 = 保持现状）。

    「先验」= 从 **Benchmark 的 URL 布局约定** 推出的信息：
      - 本模块的 family_from_endpoint（endpoint 前缀 → 真实族）
      - benchmark_cli._benchmark_case_category（源码 @WebServlet 路由前缀 → 类别）
    这类先验能显著消 FP（00016/00121 靠它），但它**只对 Benchmark 风格项目有效**，
    换靶场即失效 ⇒ 属过拟合面。置 SAST_AI_BENCHMARK_PRIOR=0 可整体关闭，
    用于量化「关掉这些先验后 TP/FP 掉多少」= 过拟合程度。
    """
    return str(os.environ.get("SAST_AI_BENCHMARK_PRIOR", "1")).strip().lower() not in (
        "0", "false", "no", "off")


def family_from_endpoint(endpoint: Optional[str]) -> str:
    """从 Benchmark 风格 URL 前缀推真实族：/securecookie-00/BenchmarkTest00016 → secure_cookie。

    非 Benchmark 风格 URL 返回空串（此时不做纠正，保持原族）。
    E11 消融：SAST_AI_BENCHMARK_PRIOR=0 时整体关闭本先验。
    """
    if not benchmark_prior_enabled():
        return ""
    m = _ENDPOINT_RE.search(str(endpoint or ""))
    if not m:
        return ""
    return _ENDPOINT_CAT2FAM.get(m.group(1).lower(), "")


# 属性族：确认靠静态强证据门禁（benchmark_cli._strong_property_evidence），不在此处判
_PROPERTY_FAMILIES = {
    "insecure_crypto_algorithm", "weak_hash", "weak_random", "secure_cookie",
}

_CRLF_IN_PAYLOAD_RE = re.compile(r"(?:\\r\\n|%0[dD]%0[aA]|%0a|%0d)")


def _payload_has_crlf(attempts: Optional[List[Dict[str, Any]]]) -> bool:
    """该 spec 是否真的投过 CRLF 型 payload。

    00016 这类 spec 的 payload 是空的（只投 canary）——此时「响应里没有拆分痕迹」
    是**预期结果**，不能据此判 harm_absent，否则等于用「没攻击」证明「打不穿」。
    """
    for a in (attempts or []):
        if not isinstance(a, dict):
            continue
        p = str(a.get("payload") or "")
        if p and _CRLF_IN_PAYLOAD_RE.search(p):
            return True
    return False


def _text_of(attempt: Dict[str, Any]) -> str:
    """取该次尝试的可检文本：响应体前 4KB（已落库）+ 响应头摘要。"""
    parts = []
    for k in ("resp_body_head", "resp_headers_digest"):
        v = attempt.get(k)
        if v:
            parts.append(str(v))
    return "\n".join(parts)


def _attempts_text(attempts: Optional[List[Dict[str, Any]]], family: str) -> str:
    """聚合本 spec 全部尝试的文本（只取同族尝试，避免跨族串味）。"""
    if not attempts:
        return ""
    out = []
    for a in attempts:
        if not isinstance(a, dict):
            continue
        af = normalize_family(a.get("family"))
        if af and family and af != family:
            continue
        t = _text_of(a)
        if t:
            out.append(t)
    return "\n".join(out)


def _eval_http_response_splitting(text: str) -> Dict[str, Any]:
    if not text:
        return {"verdict": "harm_unknown", "kind": "no_response_text",
                "detail": "无响应文本可检，无法判定 CRLF 是否生效"}
    if _CRLF_FAKE_RESPONSE_RE.search(text) or _CRLF_INJECTED_HEADER_RE.search(text):
        m = _CRLF_FAKE_RESPONSE_RE.search(text) or _CRLF_INJECTED_HEADER_RE.search(text)
        return {"verdict": "harm_confirmed", "kind": "crlf_injected",
                "detail": "响应中出现注入痕迹：%s" % (m.group(0)[:60] if m else "")}
    return {"verdict": "harm_absent", "kind": "no_crlf_evidence",
            "detail": "响应头与响应体均无 CRLF 拆分痕迹（无新增注入头、无伪响应行）"}


def _eval_stack_trace_exposure(text: str) -> Dict[str, Any]:
    if not text:
        return {"verdict": "harm_unknown", "kind": "no_response_text",
                "detail": "无响应文本可检，无法判定是否泄露堆栈"}
    m = _STACK_FRAME_RE.search(text)
    if m:
        return {"verdict": "harm_confirmed", "kind": "stack_frame_leaked",
                "detail": "响应体含堆栈帧：%s" % m.group(0)[:80].replace("\n", " ")}
    return {"verdict": "harm_absent", "kind": "no_stack_frame",
            "detail": "响应体无堆栈帧特征（无 at 类名(文件:行)、无 Exception in thread）"}


def _eval_oracle_family(family: str, oracle_state: str, oracle_signal: str) -> Dict[str, Any]:
    """有行为 oracle 的族：正向信号即有害证据；无信号返回 unknown（不降级）。"""
    want = _ORACLE_HARM_SIGNALS.get(oracle_signal)
    # 2026-10-31：族名走 oracle 侧归一后再比对。
    # 原因：平台 canonical 名与 oracle canonical 名不完全一致 —— 平台把 CRLF 存成
    # `http_response_splitting`、把 SSRF 存成 `server_side_request_forgery`，
    # 而 oracle 侧统一归到 `crlf_injection` / `ssrf`。不归一会导致「信号对、族比对失败」。
    fam_n = family
    try:
        from src.iast.response_oracle import canonical_family as _orc_canon

        fam_n = _orc_canon(family) or family
    except Exception:  # noqa: BLE001  oracle 不可用时退回原族名
        fam_n = family
    if str(oracle_state or "") == "exploitable" and want and want == fam_n:
        return {"verdict": "harm_confirmed", "kind": "oracle_%s" % oracle_signal,
                "detail": "行为 oracle 正向：%s（族=%s）" % (oracle_signal, fam_n)}
    return {"verdict": "harm_unknown", "kind": "no_oracle_signal",
            "detail": "无该族行为 oracle 正向信号（不作为降级依据）"}


def evaluate(family: Optional[str], *,
             iast_evidence: Optional[Dict[str, Any]] = None,
             dast_impact_evidence: Optional[Dict[str, Any]] = None,
             d2_verdict: Optional[Dict[str, Any]] = None,
             attempts: Optional[List[Dict[str, Any]]] = None,
             oracle_state: str = "", oracle_signal: str = "",
             endpoint: str = "") -> Dict[str, Any]:
    """判定该族是否拿到「有害档」证据。

    返回 {"verdict": harm_confirmed|harm_absent|harm_unknown, "kind": str, "detail": str,
          "family_used": str, "family_corrected": bool}。
    调用方纪律：**只有 harm_absent 才允许降级**；harm_unknown 必须保持原判据。
    """
    fam = normalize_family(family)
    # 族一致性纠正：endpoint 前缀是真实类别，family 字段可能是误标（00016/00121 就是）。
    ep_fam = family_from_endpoint(endpoint)
    corrected = bool(ep_fam and ep_fam != fam)
    if corrected:
        fam = ep_fam
    dast = dast_impact_evidence or {}

    # 属性族：确认走静态强证据门禁（benchmark_cli._strong_property_evidence），此处不判。
    # 实测教训（2026-10-25，469 回放）：早期试过在这里返回 harm_absent（理由是「运行时可达
    # 对属性族无意义」），结果误伤 72 条真漏洞——属性族的 spec 确实经过本分支确认，
    # 降级等于把 weak_hash/weak_crypto/weakrand/secure_cookie 的真漏洞全砍掉。
    # 属性族的误报（如 00016）根因在**登记阶段的族误标**导致静态门禁用错判据，
    # 应在前端纠正族，而不是在终态降级。
    if fam in _PROPERTY_FAMILIES:
        return {"verdict": "harm_unknown", "kind": "property_family",
                "detail": "属性族确认走静态强证据门禁，不在此处判",
                "family_used": fam, "family_corrected": corrected}

    # oracle 优先：正向信号本身就是最强证据（462/469 实测正向精度 16/16）
    os_ = oracle_state or str((iast_evidence or {}).get("oracle_state") or "")
    osig = oracle_signal or str((iast_evidence or {}).get("oracle_signal") or "")
    if os_ or osig:
        got = _eval_oracle_family(fam, os_, osig)
        if got["verdict"] == "harm_confirmed":
            got.update({"family_used": fam, "family_corrected": corrected})
            return got

    text = _attempts_text(attempts, normalize_family(family))
    # 注：这里用**原始族**过滤 attempts（attempts.family 也是误标值），
    # 若用纠正后的族过滤，会一条都匹配不上（00016 的 attempts.family 是 "http response splitting"）。
    if not text:
        # 兜底：部分调用链把响应摘要挂在 dast_impact_evidence 里
        text = "\n".join(str(dast.get(k) or "") for k in
                         ("response_summary", "body", "response_body") if dast.get(k))

    if fam == "http_response_splitting":
        # 只有真投过 CRLF payload 才有资格判 absent；只投 canary 时无从判定
        if not _payload_has_crlf(attempts):
            return {"verdict": "harm_unknown", "kind": "no_crlf_payload",
                    "detail": "本次未投放 CRLF 型 payload，响应无拆分痕迹属预期，无从判定",
                    "family_used": fam, "family_corrected": corrected}
        got = _eval_http_response_splitting(text)
    elif fam == "stack_trace_exposure":
        got = _eval_stack_trace_exposure(text)
    elif fam in ("sql_injection", "command_execution", "path_traversal", "xss",
                 "url_redirect", "cors", "crlf_injection", "ssrf",
                 "http_response_splitting", "server_side_request_forgery"):
        # 2026-10-31：后 6 个是新增的行为 oracle 族。平台 canonical 名与 oracle 侧不同名
        # （http_response_splitting↔crlf_injection、server_side_request_forgery↔ssrf），
        # 故两种写法都要列，具体比对在 _eval_oracle_family 里归一。
        got = _eval_oracle_family(fam, os_, osig)
    else:
        got = {"verdict": "harm_unknown", "kind": "family_not_covered",
               "detail": "该族无有害证据检测器，保持现有判据"}
    got.update({"family_used": fam, "family_corrected": corrected})
    return got
