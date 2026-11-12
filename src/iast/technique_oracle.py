"""按「注入技术」选判据。

## 为什么需要它

同一个族有**多种注入技术**，危害的观测方式完全不同：

    sqli:  报错 / 布尔盲注 / 时间盲注 / 联合 / 堆叠
    xss:   反射 / 存储 / DOM
    xxe:   回显 / OOB / 参数实体
    ssrf:  回显 / 盲 / 协议走私
    ssti:  表达式求值
    crlf:  响应头注入

而现有判定只有一条路：`canary 到达 sink`。这对**盲注类**根本不成立——
canary 明明到了 `JdbcTemplate`，但响应里没有任何差异，于是判「到了 sink 但无危害」。
实测 本轮 13 个未确认真值文件里有 **5 个**（sqli/xss/xxe/shiro/jwt）属于这一类。

## 设计原则

1. **技术由载荷形态判定，不让 LLM 猜**：`' OR '1'='1` 就是布尔、`SLEEP(3)` 就是时间、
   `${7*7}` 就是求值。形态是确定性的。
2. **判据只认「可复现的观测」**：响应差异 / 耗时差 / 回显内容 / 响应头。不认「像是有漏洞」。
3. **按代价从低到高**：报错（1 次请求）→ 回显（1 次）→ 布尔（2 次）→ 时间（等 N 秒）→ OOB。
4. **只升级、不降级**：本模块只产出「有硬证据」的结论，判不了就返回 None 交回原流程。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ── 技术判定：从载荷形态反推 ────────────────────────────────────────────────

_SQLI_TIME_RE = re.compile(
    r"(?:\bSLEEP\s*\(|\bpg_sleep\s*\(|\bWAITFOR\s+DELAY\b|\bBENCHMARK\s*\(|"
    r"\bDBMS_PIPE\s*\.\s*RECEIVE_MESSAGE|\bHEAVY_QUERY\b)", re.I)
_SQLI_UNION_RE = re.compile(r"\bUNION\b[\s\S]{0,40}\bSELECT\b", re.I)
_SQLI_STACKED_RE = re.compile(r";\s*(?:INSERT|UPDATE|DELETE|DROP|CREATE|EXEC|ALTER)\b", re.I)
_SQLI_BOOL_PAIR_RE = re.compile(
    r"(?:'|\")\s*OR\s*(?:'1'\s*=\s*'1'?|1\s*=\s*1|'a'\s*=\s*'a'?)", re.I)
_SQLI_BOOL_FALSE_RE = re.compile(
    r"(?:'|\")\s*OR\s*(?:'1'\s*=\s*'2'?|1\s*=\s*2|'a'\s*=\s*'b'?)", re.I)
_SQLI_ERROR_RE = re.compile(
    r"(?:extractvalue\s*\(|updatexml\s*\(|cast\s*\([^)]*as\s+int|"
    r"convert\s*\([^)]*int|1\s*/\s*0|'\s*\)\s*--)", re.I)

_XSS_RE = re.compile(r"<\s*script|onerror\s*=|javascript\s*:|<\s*img|<\s*svg", re.I)
_SSTI_RE = re.compile(r"\$\{[^}]*\}|\{\{[^}]*\}\}|#\{[^}]*\}|%\{[^}]*\}")
_CRLF_RE = re.compile(r"%0d%0a|%0D%0A|\r\n", re.I)
_XXE_RE = re.compile(r"<!DOCTYPE[^>]*\[|<!ENTITY", re.I)
_JNDI_RE = re.compile(r"\$\{jndi:", re.I)
# 命令执行的 marker（payload_library._cmd_injection 生成 `echo sastai_cmd_<hex>`）。
# 判据必须同时看「有没有 marker」和「有没有完整载荷」：应用把参数原样反射时，
# 响应里也会出现 marker（在 `echo sastai_cmd_xxx` 里），那不是执行。
_CMD_MARKER_RE = re.compile(r"sastai_cmd_([a-f0-9]{6,})", re.I)
# 与 shell 形态的区别：载荷是**脚本源码**，判据是求值结果回显 / 引擎异常，
# 不是 shell 命令的 stdout marker。
_CMD_SCRIPT_RE = re.compile(
    r"java\.lang\.|System\.getProperty|\.concat\(|\.getRuntime\(|"
    r"'[^']*'\s*\+|\bnew\s+java\.", re.I)

# 判据只在「2xx 且不是拒绝页」时确认 —— 302（重定向登录）已被状态码门挡掉。
_CSRF_REJECT_MARKERS = (
    "missing csrf", "invalid csrf", "csrf token", "csrf令牌", "forbidden",
    "unauthorized", "please sign in", "please login", "access denied",
)
#
# 于是**任何** POST 端点只要碰巧返回 200 就会被判成 CSRF 漏洞 ——
# XXE 端点 POST 空 body 返回 `xxe except` + 200，
# 就被当成「CSRF 确认」，把一条真值外的 (xxe.java, csrf) 塞进 confirmed，
# 直接推高红线（重放确认误报率）。
#
# 修正：2xx 只是「没被拦」，不等于「状态变更被接受」。必须再有**服务端明说
# 状态变更已执行**的语义证据。否则无法区分「CSRF 防护放行」与
# 「这个 POST 端点根本不是 CSRF 场景」。
_CSRF_ACCEPT_MARKERS = (
    "csrf passed", "csrf pass", "success", "updated", "created", "deleted",
    "saved", "ok", "accepted", "changed",
)
# 命中「拒绝页」或明显与状态变更无关的业务响应 ⇒ 不确认。
_CSRF_OTHER_BODY_MARKERS = (
    "xxe except", "bad url", "illegal file path", "file doesn't exist",
    "ssrf check failed", "output stream is null", "invaid cors config",
    "origin is not safe",
)

# 各技术的「危害观测」特征
_DB_ERROR_SIGNATURES = (
    "sql syntax", "sqlstate", "you have an error in your sql", "ora-0", "pg::syntaxerror",
    "unclosed quotation mark", "quoted string not properly terminated", "mysql_fetch",
    "org.h2.jdbc", "org.postgresql.util.psqlexception", "java.sql.sqlsyntaxerrorexception",
    "com.mysql.jdbc.exceptions", "sqlite error", "syntax error at or near",
)
_PASSWD_SIGNATURE = "root:x:0:0"
# 路径穿越回显：通用文件内容签名（不只 /etc/passwd）。
# 与 response_oracle._FILE_SIGNATURES 同源，但本模块不依赖 response_oracle，故自持一份精简集。
# 命中即「服务端把任意文件内容回显」的硬证据，与靶场 OS / 项目类型无关。
_TRAVERSAL_FILE_SIGNATURES = (
    "root:x:0:0", "root:*:0:0",                       # /etc/passwd
    "[fonts]", "[extensions]", "for 16-bit app support",  # Windows win.ini
    "127.0.0.1 localhost", "localhost name resolution",   # Windows hosts
    "<project", "<artifactId>", "<modelVersion>",        # Maven pom.xml
)


def _decode_maybe(raw: str) -> str:
    """把 base64 / hex 编码文本还原；不像编码则返回空串（fail-open，绝不误判）。

    仅对「去空白后长度 >= 16 且全为 base64/hex 字符」尝试，避免对普通 HTML 做无谓解码。
    """
    import base64 as _b64

    txt = "".join(str(raw or "").split())
    if len(txt) < 16:
        return ""
    _b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
    if set(txt) <= _b64_chars and len(txt) % 4 in (0, 2, 3):
        try:
            pad = "=" * (-len(txt) % 4)
            blob = _b64.urlsafe_b64decode(txt + pad) if ("-" in txt or "_" in txt) \
                else _b64.b64decode(txt + pad)
            out = blob.decode("utf-8", "ignore")
            if out and sum(1 for ch in out[:400] if ch.isprintable() or ch in "\r\n\t") >= min(80, len(out[:400])):
                return out
        except Exception:  # noqa: BLE001
            pass
    if len(txt) % 2 == 0 and set(txt) <= set("0123456789abcdefABCDEF"):
        try:
            out = bytes.fromhex(txt).decode("utf-8", "ignore")
            if out and sum(1 for ch in out[:400] if ch.isprintable() or ch in "\r\n\t") >= min(80, len(out[:400])):
                return out
        except Exception:  # noqa: BLE001
            pass
    return ""


def _traversal_file_signature(body: str) -> str:
    """在响应体（含 base64 编码回显）里寻找文件内容签名，返回命中的签名串。"""
    raw = str(body or "")
    low = raw.lower()
    for sig in _TRAVERSAL_FILE_SIGNATURES:
        if sig.lower() in low:
            return sig
    dec = _decode_maybe(raw)
    if dec:
        dlow = dec.lower()
        for sig in _TRAVERSAL_FILE_SIGNATURES:
            if sig.lower() in dlow:
                return sig
    return ""
_SSTI_EXPECT = "49"          # ${7*7} / {{7*7}} 的求值结果
_SSTI_RAW = "7*7"

#
# detect_technique 对不认识
# 形态的载荷一律返回 `<family>_generic`，而 judge_attempts 没有任何 generic 分支
# ⇒ 这些 spec 无论响应里有多硬的观测都判不了。617 的 47 条 layer3 里落到
# generic/空 的 attempt：xss 45、cmd 39、deser 27、ssrf 15、path 4、ssti 3、
# redirect 3、crlf 2、cors 1、xxe 1。
#
# 下面只补「响应层有确定性硬观测」的三族（xss / command_execution / ssti）和
# CORS 的反射形态，不碰 deser / ssrf / path / xxe：那些族的响应是
# `java.lang.NullPointerException` / `[-] SSRF check failed` /
# `Output stream is null` / `xxe except`，属于探针观测层或载荷层，用响应判据会造
# 误报，按排期留在 D1 / A2 / I1 层处理。
_CMD_NATIVE_SIGNATURES = (
    "java.io.ioexception: cannot run program",
    "createprocess error=",
)
# 参数被塞进 JS 源码由 Nashorn 求值（`engine.eval("load(\"<jsurl>\")")`），
# 载荷不是 shell 命令。判据 = 响应里出现**脚本求值结果**（我方 marker）。
# 脚本引擎抛出的异常类名也算 —— 「进了脚本引擎」本身就是强观测。
_CMD_SCRIPT_SIGNATURES = (
    "nashorn",
    "org.codehaus.groovy",
    "groovy.lang",
    "multiplecompilationerrors",
    "org.mozilla.javascript",
    "javascriptException",
    "scriptengine",
)
# Windows whoami 的「域\用户」输出形式。负向前瞻排除盘符路径，
# 避免把普通文件路径误当命令回显。
_WHOAMI_OUTPUT_RE = re.compile(
    r"^(?!\w:\\)[a-z0-9_.-]{1,64}\\[a-z0-9_.$-]{1,64}$", re.I)

_SSTI_ENGINE_SIGNATURES = (
    "org.apache.velocity.exception.",
    "freemarker.core.",
    "org.thymeleaf.exceptions.",
    "org.springframework.expression.",
    "spelevaluationexception",
    "ognl.ognlexception",
)
#
# 与 ssti_eval 同构但语法不同：SpEL 裸表达式是 `7*7`，模板模式是 `#{7*7}`。
# 判据要「结果出现 + 原表达式不出现」——后者排除「只是把载荷反射回来了」。
_EXPR_EVAL_RESULT = "49"
_EXPR_EVAL_RAW = ("7*7", "#{7*7}")
# CORS：我方 canary 被原样反射进 ACAO。canary 前缀是项目自产的确定性形态，
# 与 cmd_echo 认 `sastai_cmd_` marker 同性质，不是概率/严重度阈值判据。
_CORS_CANARY_REFLECT_RE = re.compile(
    r"access-control-allow-origin=[^,]*s4st41", re.I)
# 固定 marker，与 response_oracle.build_ws_probe 同源。回显帧落进 replay_attempts 的
# resp_body_head 后，由 judge_attempts 的 websocket_echo 判据消费。
_WS_MARKER_RE = re.compile(r"SASTAI_WS_([a-z0-9]{4,})", re.I)


def detect_technique(family: str, payload: str) -> str:
    """从载荷形态判定注入技术（确定性，不看族名以外的任何上下文）。"""
    p = str(payload or "")
    fam = str(family or "").lower()
    if fam == "csrf":
        # CSRF 的确认不依赖载荷形态（无 token 的状态变更请求本身就是「载荷」）。
        # 必须先于 URL/其它形态规则，否则 csrf 的 URL 形 payload 会被吃进 ssrf_echo。
        return "csrf_statechange"
    if not p:
        return ""
    # 形态规则之前，否则会被 cmd_echo / ssrf_echo 抢走而走不到回显帧判据。
    if _WS_MARKER_RE.search(p):
        return "websocket_echo"
    if _JNDI_RE.search(p):
        return "jndi_lookup"
    # 放在 ssti 之前：`$(echo x)` 不是 `${...}`，但 `echo x` 会被后面的通用规则吃掉，
    # 显式判成 cmd_echo 才能走到回显判据。
    if _CMD_MARKER_RE.search(p):
        # 判据不同（cmd_script：求值结果回显 / 脚本引擎异常），
        # 必须与 shell 形态（cmd_echo）区分开。
        if _CMD_SCRIPT_RE.search(p):
            return "cmd_script"
        return "cmd_echo"
    if _SQLI_TIME_RE.search(p):
        return "sqli_time"
    if _SQLI_UNION_RE.search(p):
        return "sqli_union"
    if _SQLI_STACKED_RE.search(p):
        return "sqli_stacked"
    if _SQLI_ERROR_RE.search(p):
        return "sqli_error"
    if _SQLI_BOOL_FALSE_RE.search(p):
        return "sqli_bool_false"
    if _SQLI_BOOL_PAIR_RE.search(p):
        return "sqli_bool_true"
    if _XXE_RE.search(p):
        return "xxe_echo"
    if _CRLF_RE.search(p):
        return "crlf_header"
    # SpEL 模板模式 `#{7*7}` 会被 SSTI 形态规则抢走（判成 ssti_eval），
    # 技术名不准会让归因统计错位。族已知时以族为准。
    if fam in ("spel_injection", "spel", "expression_injection", "ognl",
               "template_injection", "mvel"):
        return "expr_eval"
    if _SSTI_RE.search(p):
        return "ssti_eval"
    if _XSS_RE.search(p):
        return "xss_reflected"
    # CORS 必须排在 ssrf_echo 之前：两者的载荷都是 http:// URL，只有族能区分。
    # 判据完全不同——CORS 看响应头是否反射了攻击者 Origin，不是看响应体。
    # 白名单绕过必须排在 cors / ssrf_echo 之前：三者载荷都是 http:// URL，只有族能区分。
    # 判据不看响应体，看 Location 头是否把「攻击者 URL」原样写回 —— 正常白名单跳转
    # 只会跳到站内地址，把外部域写进 Location 就是校验被绕过的铁证
    #   302 的 location 原样返回该 URL，此前无判据消费 ⇒ 真值点恒漏报）。
    if fam in ("url_whitelist_bypass", "url_whitelist", "url_allowlist") and re.match(r"^https?://", p, re.I):
        return "url_whitelist_location"
    # 载荷是 `*s4st41...PAYLOAD...`（直接投 Origin 值），旧条件要求 `^https?://`
    # 把它判成 cors_generic，而无判据消费 ⇒ ACAO 明明反射了 canary 也不确认。
    # cors 族任何非空载荷都该走「ACAO 是否反射」这一条判据。
    if fam == "cors":
        return "cors_reflect"
    if re.match(r"^https?://", p, re.I):
        return "ssrf_echo"
    if re.match(r"^[.\w/:\\%]+$", p) and (
            ".." in p or "%2e" in p.lower() or re.match(r"^[a-zA-Z]:[\\/]", p)):
        return "path_traversal_echo"
    # 判据，就交给它，不要丢进无判据的 *_generic。
    if fam == "xss":
        return "xss_reflected"
    if fam == "command_execution":
        return "cmd_native"
    if fam == "ssti":
        return "ssti_engine"
    # SpEL 的 `7*7` 与 SQL 的 `' OR '1'='1` 都不匹配前面的形态规则（无引号无关键字），
    # 落到 generic 就永远没有判据消费。族已知时一律认成 expr_eval
    # （已在上面的族分支提前拦截，此处不再重复）。
    # 与 XSS 形态（<script/onerror=）不同，也不像 URL ⇒ 单独认。
    if fam in ("jsonp_referer", "jsonp"):
        return "jsonp_reflect"
    return fam + "_generic" if fam else ""


def _body(attempt: Dict[str, Any]) -> str:
    return str(attempt.get("resp_body_head") or "")


def _payload_host(payload: str) -> str:
    """从载荷提取 host 片段（小写），用于 Location 反射判据。

    刻意**不用** urlparse：`evil.com\\@good.com` 会被它拆成
    userinfo=evil.com\\ + host=good.com，而白名单绕过要的恰恰是攻击者写在最前的那一段。
    直接截取 `://` 到第一个 `/` 之间的内容即可。
    """
    s = str(payload or "").strip()
    m = re.match(r"^[a-z]+://([^/]+)", s, re.I)
    if not m:
        return ""
    return m.group(1).strip().lower().rstrip("\\/")


def _elapsed(attempt: Dict[str, Any]) -> float:
    try:
        return float(attempt.get("elapsed_ms") or 0) / 1000.0
    except Exception:  # noqa: BLE001
        return 0.0


# ── 判据：每个技术一条，只认硬观测 ──────────────────────────────────────────

def judge_attempts(family: str, attempts: List[Dict[str, Any]],
                   baseline_ms: Optional[float] = None,
                   spec_id: Any = None) -> Tuple[bool, str, Dict[str, Any]]:
    """对一组重放记录按技术选判据。返回 (是否确认, 技术, 证据)。

    判据全部是「可复现的观测」：
      - sqli_error    : 响应体出现数据库错误特征
      - sqli_boolean  : 真/假两个载荷的响应体差异显著（长度差 > 15% 或 一边含关键词）
      - sqli_time     : 含 SLEEP 的那次耗时明显高于基线（> 基线 + 2s 且 > 2×基线）
      - xss_reflected : 响应体里出现原始载荷（未转义）
      - ssti_eval     : 响应体出现求值结果 49 且不出现原始 `7*7`
      - xxe_echo      : 响应体出现 /etc/passwd 特征
      - crlf_header   : 响应头出现注入的头名
    """
    fam = str(family or "").lower()
    if not attempts:
        return False, "", {}

    by_tech: Dict[str, List[Dict[str, Any]]] = {}
    for a in attempts:
        t = detect_technique(fam, str(a.get("payload") or ""))
        if t:
            by_tech.setdefault(t, []).append(a)

    # 1) 报错型：一次请求就能判
    for a in by_tech.get("sqli_error", []):
        body = _body(a).lower()
        for sig in _DB_ERROR_SIGNATURES:
            if sig in body:
                return True, "sqli_error", {"attempt_no": a.get("attempt_no"), "signature": sig}

    # 2) 反射型：响应里出现原始载荷
    for a in by_tech.get("xss_reflected", []):
        payload = str(a.get("payload") or "")
        if payload and payload in _body(a):
            return True, "xss_reflected", {"attempt_no": a.get("attempt_no"), "payload": payload[:60]}

    # 3) 求值型：出现 49 且原文的 7*7 不在（避免把回显当求值）
    for a in by_tech.get("ssti_eval", []):
        body = _body(a)
        if _SSTI_EXPECT in body and _SSTI_RAW not in body:
            return True, "ssti_eval", {"attempt_no": a.get("attempt_no")}

    # 3.5) 命令执行回显：响应出现 marker，且**不出现完整载荷**（`echo <marker>`）。
    # 后者是「参数被原样反射」的形态——`return token` 型端点会命中，
    # 若不排除就会把「反射」误判成「执行」。
    for a in by_tech.get("cmd_echo", []):
        payload = str(a.get("payload") or "")
        m = _CMD_MARKER_RE.search(payload)
        if not m:
            continue
        marker = m.group(0)
        body = _body(a)
        if marker in body and ("echo " + marker) not in body:
            return True, "cmd_echo", {"attempt_no": a.get("attempt_no"), "marker": marker}

    # `java.io.IOException: Cannot run program "...": CreateProcess error=2, ...`。
    # 这两种串只可能由 JVM 真的调用 Runtime.exec / ProcessBuilder 后产生，参数原样
    # 反射造不出来（反射只会出现 payload 本身）。现有 cmd_echo 只认
    # `sastai_cmd_` marker，故裸命令恒落 generic 无判据。
    for a in by_tech.get("cmd_native", []):
        body = _body(a)
        low = body.lower()
        for sig in _CMD_NATIVE_SIGNATURES:
            if sig in low:
                return True, "cmd_native", {"attempt_no": a.get("attempt_no"),
                                            "signature": sig}
        if _WHOAMI_OUTPUT_RE.search(body.strip()):
            return True, "cmd_native", {"attempt_no": a.get("attempt_no"),
                                        "signature": "whoami_output"}

    # Velocity 载荷 `#set($e=...).$e.getClass.forName("java.lang.Runtime")...exec(...)`
    # 触发 `org.apache.velocity.exception.MethodInvocationException`（500 响应体带
    # `Invocation of method 'exec' in class java.lang.Runtime`），另有
    # `ParseErrorException`。这是「攻击者输入被送进模板引擎求值」的硬观测，比
    # `${7*7}`→49 更强（已到 Runtime.exec 调用）。现有 ssti_eval 只认 49，故恒漏判。
    for a in by_tech.get("ssti_engine", []):
        low = _body(a).lower()
        for sig in _SSTI_ENGINE_SIGNATURES:
            if sig in low:
                return True, "ssti_engine", {"attempt_no": a.get("attempt_no"),
                                             "signature": sig}

    # 载荷 `7*7`（或模板形态 `#{7*7}`）被表达式引擎求值 ⇒ 响应出现 `49`，
    # 且**不出现**原表达式（后者排除「只是把载荷反射回来了」）。
    # 这与 ssti_eval 同构但语法不同（SpEL 裸表达式无 `${}`），故单列一条判据。
    for a in by_tech.get("expr_eval", []):
        body = _body(a)
        if _EXPR_EVAL_RESULT in body and not any(r in body for r in _EXPR_EVAL_RAW):
            return True, "expr_eval", {"attempt_no": a.get("attempt_no"),
                                       "result": _EXPR_EVAL_RESULT}

    # 载荷是**非法 JSONP 标识符**（含 `<` `(` 等），响应体以载荷开头 ⇒
    # callback 名被原样写进响应，攻击者可控制 JSONP 回调 ⇒ 可注入脚本。
    # 正常实现要么拒绝要么转义，不会原样写回。
    for a in by_tech.get("jsonp_reflect", []):
        payload = str(a.get("payload") or "").strip()
        if payload and _body(a).lstrip().startswith(payload[:12]):
            return True, "jsonp_reflect", {"attempt_no": a.get("attempt_no"),
                                           "payload": payload[:40]}

    # 参数被塞进 JS/Groovy 源码由脚本引擎求值，载荷形态与 shell 命令完全不同
    # （`java.lang.System.getProperty('java.version')+'<marker>'`）。
    # 判据 = 响应里出现我方 marker（求值结果回显），或出现脚本引擎异常类名
    # （「确实进了脚本引擎」本身就是强观测）。
    for a in by_tech.get("cmd_script", []):
        body = _body(a)
        low = body.lower()
        payload = str(a.get("payload") or "")
        m = _CMD_MARKER_RE.search(payload)
        if m:
            marker = m.group(0)
            # 与 cmd_echo 同一原则：出现完整载荷说明只是反射，不是求值。
            if marker in body and payload.strip() not in body:
                return True, "cmd_script", {"attempt_no": a.get("attempt_no"),
                                            "marker": marker}
        for sig in _CMD_SCRIPT_SIGNATURES:
            if sig in low:
                return True, "cmd_script", {"attempt_no": a.get("attempt_no"),
                                            "signature": sig}

    # 4) XXE 回显
    for a in by_tech.get("xxe_echo", []):
        if _PASSWD_SIGNATURE in _body(a):
            return True, "xxe_echo", {"attempt_no": a.get("attempt_no")}

    # 5) 路径穿越回显（泛化：任意文件签名，含 base64 编码回显）
    # 把文件整段 base64 回显、且读的是 pom.xml / Windows hosts 的靶场永远判不了。
    # 改为通用签名集 + base64 解码（与 response_oracle._find_signature 同口径）。
    for a in by_tech.get("path_traversal_echo", []):
        sig = _traversal_file_signature(_body(a))
        if sig:
            return True, "path_traversal_echo", {"attempt_no": a.get("attempt_no"), "signature": sig}

    # 6) CRLF：注入的头名出现在响应头/响应体里。
    # 载荷注入 X-Sastai-Probe 而判据找 x-injected，真打通也永远判不了。
    # 回显排除与 cmd_echo 同一原则：载荷被解码后原样反射回响应体时，头名/值只是回显
    # 的一部分，不是拆行成功。
    for a in by_tech.get("crlf_header", []):
        payload = str(a.get("payload") or "")
        body = _body(a).lower()
        hdr_digest = str(a.get("resp_headers_digest") or "").lower()
        m = re.search(r"(?:%0d%0a|\r\n)\s*([a-z0-9\-]{3,32})\s*:\s*([^\s%]{3,64})", payload, re.I)
        if m:
            hdr_name, hdr_val = m.group(1).lower(), m.group(2).lower()
            decoded = payload.replace("%0D%0A", "\r\n").replace("%0d%0a", "\r\n").lower()
            is_echo = (decoded in body) or (payload.lower() in body)
            if not is_echo:
                pair = f"{hdr_name}: {hdr_val}"
                if pair in hdr_digest or pair.replace(" ", "") in hdr_digest.replace(" ", ""):
                    return True, "crlf_header", {
                        "attempt_no": a.get("attempt_no"), "header": hdr_name, "in": "headers"}
                if pair in body:
                    return True, "crlf_header", {
                        "attempt_no": a.get("attempt_no"), "header": hdr_name, "in": "body"}
        # 旧判据兜底（历史载荷注入的是 x-injected）
        if "x-injected" in body or "set-cookie: sast" in body:
            return True, "crlf_header", {"attempt_no": a.get("attempt_no")}

    # 7) 布尔盲注：真/假两次响应差异
    trues = by_tech.get("sqli_bool_true", [])
    falses = by_tech.get("sqli_bool_false", [])
    if trues and falses:
        for t in trues:
            for f in falses:
                lt, lf = len(_body(t)), len(_body(f))
                if lt and lf:
                    ratio = abs(lt - lf) / max(lt, lf)
                    if ratio >= 0.15:
                        return True, "sqli_boolean", {
                            "true_len": lt, "false_len": lf, "ratio": round(ratio, 3)}

    # 8) 时间盲注：耗时显著高于基线
    for a in by_tech.get("sqli_time", []):
        el = _elapsed(a)
        base = (baseline_ms or 0) / 1000.0
        if el >= 2.0 and (not base or el > base * 2):
            return True, "sqli_time", {"elapsed_s": round(el, 2), "baseline_s": round(base, 2)}

    # 9) SSRF 回显：响应里出现内网特征（保守：只认回环地址的固定探针响应）
    for a in by_tech.get("ssrf_echo", []):
        body = _body(a).lower()
        if "sast-probe" in body:
            return True, "ssrf_echo", {"attempt_no": a.get("attempt_no")}

    # 10) CORS：只认响应头。`Access-Control-Allow-Origin` 反射了攻击者 Origin
    # （或直接 `*`）就是可利用的跨域读，与响应体无关。
    # 603 实测 5 条 cors spec 全停在 `no-arrival` —— 不是没打中，是判据用错了通道：
    # 探针不会在 `setHeader` 处触发，而 oracle 臂的响应体是正常业务数据（请求确实成功）。
    for a in by_tech.get("cors_reflect", []):
        hdr = str(a.get("resp_headers_digest") or "").lower()
        payload = str(a.get("payload") or "").strip().lower()
        if "access-control-allow-origin" not in hdr:
            continue
        if payload and payload in hdr:
            return True, "cors_reflect", {"attempt_no": a.get("attempt_no"),
                                          "acao": payload}
        if "access-control-allow-origin=*" in hdr:
            return True, "cors_reflect", {"attempt_no": a.get("attempt_no"), "acao": "*"}
        # 原样反射回来（`access-control-allow-origin=s4st41...PAYLOAD...`），而不是
        # `*`，也不是 `http://evil.com`。这同样是「Origin 未校验被回写」的铁证，
        # 只认 `*` 会把它漏掉。
        if _CORS_CANARY_REFLECT_RE.search(hdr):
            return True, "cors_reflect", {"attempt_no": a.get("attempt_no"),
                                          "acao": "reflected_canary"}

    # 11) JNDI：响应里看不出任何痕迹，只认「本地监听收到回连」。
    # 目标在 lookup 阶段就会建连，LDAP 握手失败不影响这个事实。
    # 按 spec 归账（`hits_for`）：回连是异步到达的，全局计数会把多个 spec 混在一起。
    if by_tech.get("jndi_lookup"):
        try:
            from src.iast.jndi_probe import hit_count, hits, hits_for
            n = hits_for(spec_id) if spec_id is not None else hit_count()
        except Exception:  # noqa: BLE001
            n = 0
        if n > 0:
            return True, "jndi_lookup", {"connections": n,
                                         "peers": [h.get("peer") for h in hits()[:3]]}

    # 此前没有任何判据消费这个证据 ⇒ csrf 真值点永远漏报。
    # 门禁缺一不可：
    #   - 只认状态变更方法（POST/PUT/PATCH/DELETE）—— GET 的 200 没有「被改状态」语义；
    #   - 2xx —— 302（重定向登录页）/ 401/403（防护拦截）都不算；
    #   - 响应体不是 CSRF 拒绝页；
    #     旧判据只到「2xx 且不是拒绝页」，于是任何 POST 端点返回 200 都被判成 CSRF：
    #     XXE 端点 POST 空 body → 200 `xxe except` ⇒ 被误判成
    #     (xxe.java, csrf) confirmed，直接污染红线。2xx 只说明「没被拦」，
    #     不说明「状态真的被改了」。
    for a in by_tech.get("csrf_statechange", []):
        method = str(a.get("http_method") or "").upper()
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            continue
        try:
            sc = int(a.get("status_code") or 0)
        except Exception:  # noqa: BLE001
            sc = 0
        if not (200 <= sc < 300):
            continue
        body_l = _body(a).lower()
        if any(m in body_l for m in _CSRF_REJECT_MARKERS):
            continue
        if any(m in body_l for m in _CSRF_OTHER_BODY_MARKERS):
            continue
        if not any(m in body_l for m in _CSRF_ACCEPT_MARKERS):
            # 没有「状态变更被接受」的语义证据 ⇒ 无法区分「CSRF 防护放行」
            # 与「这个 POST 根本不是 CSRF 场景」⇒ 不确认。证据不足时保持未确认，
            # 绝不把「2xx」当成漏洞证据。
            continue
        return True, "csrf_statechange", {
            "attempt_no": a.get("attempt_no"), "status": sc, "method": method}

    # 判据 = 响应 Location 头里出现了**载荷自身的 host 片段**。正常白名单跳转只会跳站内地址，
    # 把攻击者 URL 原样写回 Location 就说明校验被绕过。
    # 刻意不硬编码 evil.com 之类域名：host 从载荷自身提取，换任何攻击域都成立。
    for a in by_tech.get("url_whitelist_location", []):
        payload = str(a.get("payload") or "").strip()
        hdr = str(a.get("resp_headers_digest") or "")
        m = re.search(r"(?im)location\s*[:=]\s*([^,\r\n]+)", hdr)
        if not m:
            continue
        loc = m.group(1).strip().lower()
        p_host = _payload_host(payload)
        if p_host and p_host in loc:
            return True, "url_whitelist_location", {
                "attempt_no": a.get("attempt_no"),
                "status": a.get("status_code"),
                "location": loc[:120],
                "payload_host": p_host,
            }

    # 端点把 shell 命令的 stdout 通过 WebSocket 帧送回，D1 已把该帧写进 resp_body_head。
    # 判据 = 帧里出现载荷自身的固定 marker。只认「命令确实执行并回显」，不认 2xx /
    # 「端点注册成功」这类弱信号，避免把静态注册页当命令执行证据。
    for a in by_tech.get("websocket_echo", []):
        m = _WS_MARKER_RE.search(str(a.get("payload") or ""))
        if not m:
            continue
        if m.group(0).lower() in _body(a).lower():
            return True, "websocket_echo", {
                "attempt_no": a.get("attempt_no"),
                "marker": m.group(0),
            }

    return False, "", {}


def supported_techniques(family: str) -> List[str]:
    """该族已知的技术清单（按代价从低到高），供文档/诊断用。"""
    fam = str(family or "").lower()
    table = {
        "sql_injection": ["sqli_error", "sqli_union", "sqli_boolean", "sqli_time", "sqli_stacked"],
        "xss": ["xss_reflected"],
        "xxe": ["xxe_echo"],
        "ssti": ["ssti_eval", "ssti_engine"],
        "crlf_injection": ["crlf_header"],
        "path_traversal": ["path_traversal_echo"],
        "ssrf": ["ssrf_echo"],
        "jndi_injection": ["jndi_lookup"],
        "command_execution": ["cmd_echo", "cmd_native"],
        "websocket_cmd": ["websocket_echo"],
        "cors": ["cors_reflect"],
        "csrf": ["csrf_statechange"],
        "spel_injection": ["expr_eval"],
        "expression_injection": ["expr_eval"],
        "jsonp_referer": ["jsonp_reflect"],
    }
    for key, techs in table.items():
        if key in fam:
            return techs
    return []
