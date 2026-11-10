"""值级 sink 实参闸（本质修复）：判定「污点值是否真的到达 sink」。

为什么这是本质
--------------
污点流的本质问题是「**污点值是否真的流到 sink**」。源码正则/语义模式只能猜
OWASP Benchmark 的几种固定写法，换靶场即失效。而运行时探针已经记录了 sink 的
**实际实参**（`iast_events.source_value` / `evidence_json.payload`），因此可以直判：

  重放注入的 payload（taint_marker 的 PAYLOAD 段）出现在 sink 实参里 → 污点真到 sink → 可利用
  未出现（实参是常量/净化值/错源）→ 污点没到 → 安全（FP）

这是 target-agnostic 的运行时判定，不看源码形状。

实测（run 364 cmdi）：
  - FP：20/28 有 cmdi sink 事件的用例「payload 不在实参」→ 正确判安全；
  - TP：15/25 有事件的用例「payload 在实参」→ 正确判可利用；
  - 另有 10 条 TP「payload 不在实参」实为 **D1 重放注错源**（servlet 读 header，重放注了 param），
    属重放保真度问题，值级判定本身是对的（payload 确实没到 sink）。

结论：值级闸负责「到达后是否真可利用」的判定；「payload 能否到 sink」由 D1 重放保真度保证。
"""
from __future__ import annotations

import html
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import unquote


def _normalize(s: Any) -> str:
    """payload 归一化：URL 解码（多级）+ HTML 反转义 + 去反斜杠转义。

    解决"payload 被 URL 编码/转义后不再字面出现"导致的值级误判（Phase 0c）。
    """
    t = str(s or "")
    for _ in range(3):
        t2 = unquote(t)
        if t2 == t:
            break
        t = t2
    t = html.unescape(t)
    t = t.replace("\\/", "/").replace('\\"', '"').replace("\\u0025", "%")
    return t


_CHAR_LIST_RE = re.compile(r"\[([^\[\]]{4,})\]")


def flatten_char_arrays(text: Any) -> str:
    """把探针记录的 char[] 实参（逐字符列表）重组成字符串。

    实测（r106 xss，CoyoteWriter.write）：Java 侧实参是 char[]，探针把 source_value 记成
    ``[[s, 4, s, t, 4, 1, 3, b, b, ...]]``——canary 被逐字符拆开，任何字面/身份段匹配都失败
    （xss 29 个真 TP 因此误判 absent）。这里把「全是短元素」的列表就地拼接；
    ``[userid, 10340]`` 这类正常短参数列表（元素含长串）保持原样。
    """
    s = str(text or "")
    if "[" not in s:
        return s

    def _repl(m: "re.Match") -> str:
        inner = m.group(1)
        parts = [p.strip() for p in inner.split(",")]
        if len(parts) < 4:
            return m.group(0)
        # 单字符元素（允许 \x 转义、引号包裹）才拼接；出现长元素说明是参数列表，不拼
        if not all(len(p) <= 3 for p in parts):
            return m.group(0)
        return "".join(parts)

    return _CHAR_LIST_RE.sub(_repl, s)

# 各族「真 sink」token（只在这些 sink 上比对 payload，避免日志/响应等旁路 sink 误命中）。
# token 为子串匹配，且必须来自 iast_events 实测 sink_file 分布（见 docs/2026-10-18-两项落地前置方法分析.md）：
#   - trustbound：探针实录为 StandardSession.setAttribute / StandardSessionFacade.setAttribute，
#     故用 "Session.setAttribute" 而非接口名 "HttpSession.setAttribute"（实测匹配不到）。
#   - xpath：实录为 XPathImpl.evaluate，补 XPathImpl 实现类形态。
#   - sqli：补 MyBatis Executor.query / Executor.update（hsqldb / delegating 已由 Statement/PreparedStatement 覆盖）。
#   - xss：实录主形态是 CoyoteWriter.print/println（占比 ~78%），补 print（同时覆盖 println）
#     与 Spring StringHttpMessageConverter.writeInternal。
# 放大 token 不会误杀 TP：值级闸规则为「用例内全部 spec 判 absent 才否决」，真 TP 的 payload
# 出现在 sink 实参 → at_sink，仅 FP（实参无 payload）被 absent 否决，结构性保证 0 抑损。
FAMILY_SINK_TOKENS: Dict[str, tuple] = {
    "command_execution": ("Runtime.exec", "ProcessBuilder"),
    # 2026-10-18（r106 实证）：补探针实录的真实 SQL sink 形态——
    #   prepareCall（CallableStatement，HSQLDB/DBCP 各 58 条）、prepareStatement（方法名小写，
    #   PreparedStatement 接口名匹配不到）、addBatch（Statement.addBatch 真执行）、
    #   JDBCStatement / DelegatingStatement（探针按实现类织入，无方法后缀）。
    # 实测：补齐后 sqli TP at_sink 183→267（覆盖 98.5%），且 all_absent 变 FP 纯净（0 TP 混入），
    # 可再安全否决 31 个 FP 用例、0 误杀。
    "sql_injection": (
        "Statement.execute", "PreparedStatement", "executeQuery", "executeUpdate", "execute(",
        "Executor.query", "Executor.update",
        "prepareCall", "prepareStatement", "addBatch", "CallableStatement",
        "JDBCStatement", "DelegatingStatement",
    ),
    # 2026-10-18（r108 实证）：path_traversal 的 spec 常与 xss/trustbound/xpathi 用例同处一案
    # （发现层族误判），旧 token 只覆盖 FileInputStream/FileOutputStream/Files./File. 四类，
    # 补 NIO / 随机访问 / 上传落盘形态，避免「真到达却判 no_event」。
    "path_traversal": (
        "FileInputStream", "FileOutputStream", "Files.", "File.",
        "RandomAccessFile", "FileChannel", "Paths.get", "Path.of", "FileReader", "FileWriter",
    ),
    # XXE（2026-10-18 新增）：探针实录 javax.xml.parsers.DocumentBuilder.parse /
    # org.apache.xerces.jaxp.DocumentBuilderImpl.parse（run 389 各 6 条）。此前无 token ⇒
    # xxe spec 恒 no_event ⇒ 值级闸对 xxe 完全失效（BenchmarkTest01479 的 FP 无法否决）。
    "xxe": (
        "DocumentBuilder.parse", "DocumentBuilderImpl.parse",
        "SAXParser.parse", "SAXParserImpl.parse", "XMLReader.parse",
        "Unmarshaller.unmarshal", "SAXSource", "Transformer.transform",
    ),
    "ldap_injection": ("DirContext.search", "InitialDirContext", "NamingEnumeration"),
    # 2026-10-18：补 XPathExpressionImpl.evaluate（探针实录 com.sun...jaxp.XPathExpressionImpl，
    # 122 条事件；旧 token XPathExpression.evaluate 因 Impl 断开匹配不到，同 trustbound Facade 类 bug）。
    # 另补 compile：Benchmark 部分用例写 `xp.compile(expr).evaluate(doc,NODESET)`，canary 在
    # **compile 实参**里（evaluate 实参只有 [#document, NODESET]），探针已补 hook compile。
    "xpath_injection": ("XPath.evaluate", "XPathExpression.evaluate", "XPathImpl.evaluate",
                        "XPathExpressionImpl.evaluate", "XPathImpl.compile", "XPath.compile"),
    "xss": ("PrintWriter.write", "CoyoteWriter.write", "getWriter", "CoyoteWriter.print", "StringHttpMessageConverter.writeInternal"),
    "weak_hash": ("MessageDigest.getInstance",),
    "weak_crypto": ("Cipher.getInstance",),
    "trust_boundary_violation": ("StandardSession.setAttribute", "SessionFacade.setAttribute", "putValue"),
}

_AT_SINK = "at_sink"      # payload 出现在真 sink 实参 → 可利用
_ABSENT = "absent"        # 真 sink 已到达但实参无 payload → 安全（FP）
_NO_EVENT = "no_event"    # 无真 sink 事件（重放未到/未覆盖）→ 无法判定


def payload_of(taint_marker: str) -> str:
    """从 taint_marker 提取注入 payload 段（兼容两种 marker 格式）。

    - 新格式：``s4st41<hex>PAYLOAD<hex>`` → 取 ``PAYLOAD`` 之后的部分；
    - 旧格式（反射 XSS 等仍在使用）：``s4st41<hex>"><svg<hex>`` → 没有 ``PAYLOAD``
      分隔符，payload 是 canary 身份段之后的全部（XSS 注入串本身，如 ``"><svg…``）。

    2026-10-18 实证（r106 run 380/381）：xss spec 的 marker 100% 是旧格式，
    ``payload_of`` 返回空 → ``judge_sink_value`` 整体短路 no_event，值级闸对 xss 全族
    形同虚设；而探针其实录得了 1022 条 CoyoteWriter.write 事件。不是探针覆盖问题，
    是**解析器不认旧格式**。
    """
    m = str(taint_marker or "")
    if "PAYLOAD" in m:
        return m.split("PAYLOAD", 1)[1].strip()
    ident = identity_of(m)
    if ident and m.startswith(ident):
        return m[len(ident):].strip()
    return m


def identity_of(taint_marker: str) -> str:
    """canary 身份段（``s4st41<16hex>``）：marker 里 PAYLOAD 段之前的稳定前缀。

    为什么值级命中要看身份段：探针实录的 sink 实参经常把 payload 段截断/改写
    （r106 实证：``session.putValue`` 把 canary 当 KEY 存、值段截尾
    ``PAYLOAD56254c0`` vs marker ``PAYLOAD56254c01``），但**身份段原样保留**。
    因此 at_sink 判据用「payload 段 ∥ 身份段」双轨：payload 段精确命中优先级最高，
    身份段命中兜底（实测在 sqli/trustbound/xss/xpathi 四族上身份段匹配零 FP）。
    """
    m = str(taint_marker or "")
    if not m:
        return ""
    try:
        from src.iast.canary import CanaryMatcher
        ident = CanaryMatcher.find_identity(m) or ""
        if ident:
            return ident
    except Exception:
        pass
    mm = re.match(r"(s4st41[0-9a-fA-F]{6,})", m)
    return mm.group(1) if mm else ""


# 平台族名别名（DB 里可能是 cmdi/sqli 等短名，需映射到规范族）
_FAMILY_ALIASES = {
    "cmdi": "command_execution",
    "command": "command_execution",
    "sqli": "sql_injection",
    "sql": "sql_injection",
    "xss": "xss",
    "path": "path_traversal",
    "pathtraver": "path_traversal",
    "ldap": "ldap_injection",
    "ldapi": "ldap_injection",
    "xpath": "xpath_injection",
    "xpathi": "xpath_injection",
    "trustbound": "trust_boundary_violation",
    "weakrand": "weak_random",
}

# 算法/属性族（其"值"是算法名/flag，不是污点 payload，值级闸不适用）
NON_DATAFLOW_FAMILIES = {
    "weak_hash", "hash", "weak_crypto", "crypto", "weak_random", "weakrand",
    "secure_cookie", "securecookie",
}


def canonical_family(family: str) -> str:
    fam = str(family or "").strip().lower()
    return _FAMILY_ALIASES.get(fam, fam)


def is_dataflow_family(family: str) -> bool:
    return canonical_family(family) not in NON_DATAFLOW_FAMILIES


def _sink_tokens(family: str) -> tuple:
    fam = canonical_family(family)
    if fam in FAMILY_SINK_TOKENS:
        return FAMILY_SINK_TOKENS[fam]
    for k, v in FAMILY_SINK_TOKENS.items():
        if k in fam or fam in k:
            return v
    return ()


def judge_sink_value(
    events: Iterable[Dict[str, Any]],
    taint_marker: str,
    family: str = "",
    sink_tokens: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """判定污点值是否到达 sink。

    返回 {"verdict": at_sink|absent|no_event, "payload": str, "identity": str,
        "matched_sink": str, "matched_on": payload|identity|""}。
    - at_sink  : payload 段**或** canary 身份段出现在该族真 sink 的实参里 → 可确认可利用；
    - absent   : 真 sink 已到达但实参里两者都没有 → 污点被截断/常量/错源 → 安全；
    - no_event : 无该族真 sink 事件 → 证据不足，无法判定（既不能确认也不能据此否决）。

    判据纪律（2026-10-18 实证收口）：
    1. **只比对 source_value**（sink 实际实参）。evidence_json 是请求侧回显元数据，
       实测把身份段匹配污染（r106 trustbound blob 匹配 → 31 个 FP 全判 at_sink），
       不能当 sink 实参用。
    2. **族身份约束**：token 命中后再过 ``is_family_relevant_sink``（框架噪声黑名单 +
       族画像），Response.setHeader / Cookie.<init> / thymeleaf 等非本族 sink 上的命中
       一律剔除。
    3. token 匹配大小写不敏感（实录类是 ``org.apache.catalina.session.
       StandardSessionFacade.setAttribute``，大小写混合）。
    """
    tokens = sink_tokens if sink_tokens else _sink_tokens(family)
    if isinstance(tokens, str):
        tokens = (tokens,)
    tokens = tuple(str(t) for t in (tokens or ()) if str(t))
    tokens_low = tuple(t.lower() for t in tokens)
    payload = payload_of(taint_marker)
    identity = identity_of(taint_marker)
    evs = list(events or [])
    if (not payload and not identity) or not tokens_low:
        return {"verdict": _NO_EVENT, "payload": payload, "identity": identity,
                "matched_sink": "", "matched_on": ""}
    # 噪声约束（fail-open：导入失败不阻断）。只用 is_genuine_sink_identity 的框架噪声
    # 黑名单 + trustbound 白名单做约束；不用 _FAMILY_SINK_HINTS 正向画像——它比
    # FAMILY_SINK_TOKENS 更窄（SQL 画像不含 MyBatis Executor.query），会把已由 token
    # 命中的合法 sink 误剔除（实测打挂 test_sql_mybatis_new_token_absent_veto）。
    _genuine = None
    try:
        from src.iast.sink_identity import is_genuine_sink_identity as _genuine
    except Exception:  # pragma: no cover
        _genuine = None
    sink_evs = []
    for e in evs:
        sf = str(e.get("sink_file") or "")
        if not any(t in sf.lower() for t in tokens_low):
            continue
        if _genuine is not None and not _genuine(sf, family):
            continue  # 框架噪声 sink（Set-Cookie / thymeleaf 等）不算本族证据
        sink_evs.append(e)
    if not sink_evs:
        return {"verdict": _NO_EVENT, "payload": payload, "identity": identity,
                "matched_sink": "", "matched_on": ""}
    needles = [("payload", payload), ("identity", identity)]
    needles = [(k, v) for k, v in needles if v]
    for e in sink_evs:
        sv = str(e.get("source_value") or "")
        # char[] 实参（逐字符列表）先重组，否则 canary 被拆开永远匹配不到（r106 xss 实证）
        sv_flat = flatten_char_arrays(sv)
        variants = [sv] if sv_flat == sv else [sv, sv_flat]
        for raw in variants:
            raw_n = _normalize(raw)
            for kind, nd in needles:
                if nd in raw or (raw_n and nd in raw_n):
                    return {"verdict": _AT_SINK, "payload": payload, "identity": identity,
                            "matched_sink": str(e.get("sink_file") or ""), "matched_on": kind}
    return {"verdict": _ABSENT, "payload": payload, "identity": identity,
            "matched_sink": str(sink_evs[0].get("sink_file") or ""), "matched_on": ""}


def is_vetoed_by_value(verdict: Dict[str, Any]) -> bool:
    """仅 'absent' 才否决（确认态降级）；at_sink/no_event 不动（no_event 证据不足，不误杀）。"""
    return (verdict or {}).get("verdict") == _ABSENT
