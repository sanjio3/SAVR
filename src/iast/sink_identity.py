"""sink 身份校验（④ 关联 / ingest 层）。

背景（§14.2 缺口）：``is_sink_reached(state)`` 只判 canary 状态字符串，不校验「到达的到底是不是
该族真实危险函数」。结果 canary 随请求流经框架基础设施（响应写入 / 序列化 / 模板渲染）时被织到这些
噪声 sink 上，``correlation.confirmed_runtime`` 与 D2 ``sink_reached`` 据此误背书，把「污点流过
Response.setHeader」当成「漏洞可利用」。

两侧命名空间不可直接比：
- ``iast_events.sink_file`` = JVM 类名.方法（如 ``java.nio.file.Files.newOutputStream``）；
- ``trigger_specs.expected_sink_file`` = 源码路径（如 ``src\\main\\java\\...\\Rce.java``）。
故本模块只做「sink 身份是否属于框架噪声」的黑名单判定，不逐族维护「真 sink 白名单」——避免
RandomAccessFile 这类「对 path-traversal 是真 sink、对其他族是噪声」的跨族误杀。

设计收口（2026-09-23，实证 50 族 / 14918 条关联事件）：
- 极窄噪声黑名单：仅纯响应写入 / 序列化框架类 + thymeleaf（这些 sink 在任何请求里都会被织到）。
- XSS / SSTI 例外：响应写入 / 模板渲染本身就是这两族的 sink，噪声黑名单不适用。
- 零误杀：未知 sink 类（含空 sink_file）→ 视为真实（fail-open），绝不误杀真漏洞。
"""

from typing import Dict, Tuple

from src.iast.canary import is_sink_reached

# 框架基础设施 sink：任何把污点数据流经响应写入 / 序列化 / 模板渲染的请求都会被织到，与具体漏洞无关。
# 这些 sink 上观察到的「canary 抵达」不构成该族的真实漏洞证据。
# 绝不包含文件 IO（``java.io.RandomAccessFile`` 等——对 path-traversal 是真 sink，误入黑名单会误杀真漏洞）。
SINK_NOISE_BLACKLIST = frozenset(
    {
        "org.springframework.http.converter.StringHttpMessageConverter.writeInternal",
        "org.apache.catalina.connector.Response.setHeader",
        "org.apache.catalina.connector.Response.addHeader",
        "org.apache.catalina.connector.ResponseFacade.setHeader",
        "org.apache.catalina.connector.ResponseFacade.addHeader",
        "javax.servlet.http.HttpServletResponseWrapper.setHeader",
        "javax.servlet.http.HttpServletResponseWrapper.addHeader",
        "org.springframework.security.web.util.OnCommittedResponseWrapper.addHeader",
        "org.thymeleaf.TemplateEngine.process",
        "org.thymeleaf.standard.expression.StandardExpressionParser.parseExpression",
    }
)

# ─────────────────────────────────────────────────────────────────────────────
# Cookie 构造/属性 sink 的适用范围（2026-10-30）
#
# 探针在每个 doGet 里都会织一个 Cookie（只处理硬编码 "color"），它的
# `javax.servlet.http.Cookie.<init>` / `setSecure` / `setHttpOnly` 会以
# `sink-reached-probe` 落库。这个 sink 只对 **secure_cookie** 族有意义；
# 对其它族它是纯噪声，却因为不在 SINK_NOISE_BLACKLIST 里被 fail-open 放行：
#   - 00969（cmdi/safe）：11 条事件**全部**是 Cookie.<init>，没有任何 ProcessBuilder；
#   - 01841（pathtraver/safe）：12 条事件全部是 Cookie.<init>，没有任何文件 IO。
# 两者因此被确认成 confirmed_exploitable ⇒ Benchmark 误报。
# 修法：非 cookie 族遇到 Cookie 构造类 sink 一律判非真（放在响应写入族放行之前，
# 否则 xss 族会被 is_response_writer_family 提前放行）。
# 零误杀验证（case 级，17 族全部已确认 spec）：丢 TP = 0，消 FP = 2（00969 / 01841）。
# ─────────────────────────────────────────────────────────────────────────────
_COOKIE_SINK_TOKENS = (
    "cookie.<init>",
    "cookie.setsecure",
    "cookie.sethttponly",
    "javax.servlet.http.cookie",
)


def _is_cookie_sink(sink_file: str) -> bool:
    s = (sink_file or "").strip().lower()
    return bool(s) and any(t in s for t in _COOKIE_SINK_TOKENS)


def _is_cookie_family(family: str) -> bool:
    return "cookie" in (family or "").strip().lower()


# ─────────────────────────────────────────────────────────────────────────────
# 会话属性写入 sink 的适用范围（2026-10-30）
#
# 同一个 case 常同时挂着 xss / sqli 的候选 spec，而它们的 canary 与 trustbound spec 共用。
# 于是 session `setAttribute` / `putValue` 事件会被当成 sql_injection 的「到达」，
# dry-run 实测 31 条 sql_injection spec 落在 putValue 上 ⇒ 凭空确认出跨族 FP。
#
# 会话写入只对 trust_boundary_violation 族有意义；对其它族一律非真。
# 这条必须放在共享判据里（而不是某个调用方），否则「主路径」与「迟到补捞」口径会漂移：
# 本轮实测，补捞侧多查一道族画像闸，把 6 个 path_traversal TP（02197/02378/02463/
# 02556/02559/02569）挡在外面 —— 它们的到达 sink 是响应写入，而主路径是认的。
# ─────────────────────────────────────────────────────────────────────────────
_SESSION_WRITE_TOKENS = (
    "setattribute",
    "putvalue",
    "standardsession",
    "sessionfacade",
    "httpsession",
)


def _is_session_write_sink(sink_file: str) -> bool:
    s = (sink_file or "").strip().lower()
    return bool(s) and any(t in s for t in _SESSION_WRITE_TOKENS)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP 基础设施写入 sink（2026-11-03，jsc-leakfix-r17 实测）
#
# ``StringHttpMessageConverter.writeInternal``（REST 序列化器）与
# ``Response.setHeader/addHeader``（响应头写入）是**所有请求**的必经之路：
#   - websocket 部署异常串经过 writeInternal 返回，曾被当成 xss 值级命中
#     （jsc 607 实测 2 条 confirmed_exploitable 全是这类噪声）；
#   - log4j 端点的 `return token` 回显经过 writeInternal / setHeader，
#     同样被误判 xss。
# 对响应写入族（xss/ssti）它们同样不是「页面上下文 sink」——模板引擎
# （thymeleaf/freemarker/velocity 的 process）才是，那几个类**不**在本组，
# 继续放行（ssti 的真 sink 就是 TemplateEngine.process）。
# ─────────────────────────────────────────────────────────────────────────────
_HTTP_INFRA_NOISE_TOKENS = (
    "messageconverter",                       # StringHttpMessageConverter 等 REST 序列化器
    "response.setheader", "response.addheader",
    "responsefacade.setheader", "responsefacade.addheader",
    "responsewrapper.setheader", "responsewrapper.addheader",
    "oncommittedresponsewrapper",
)


def _is_http_infra_noise(sink_file: str) -> bool:
    s = (sink_file or "").strip().lower()
    return bool(s) and any(t in s for t in _HTTP_INFRA_NOISE_TOKENS)


# ─────────────────────────────────────────────────────────────────────────────
# 无数据流 sink 的族（2026-11-03）
#
# csrf / cors 是「路由级配置属性」：危害不在任何一行代码的运行时参数上，而在
# 「这个端点缺不缺防护」。探针在任何真实 sink（XML 解析器 / 反序列化器 / 命令
# 执行器）上看到的值级命中，都**不能**为这两个族背书——jsc 607 实测 4 条 csrf
# spec 全是被 xxe/xstream 端点的探针事件跨族确认的（值级真命中、族完全错）。
# 这两族的确认只允许两条路：technique/差分 oracle（响应证据）或静态规则升级
# （framework: 前缀）。sink_file 为空时 fail-open（无信息不误杀）。
# ─────────────────────────────────────────────────────────────────────────────
_NO_DATAFLOW_SINK_FAMILIES = ("csrf", "cors")


def _is_no_dataflow_family(family: str) -> bool:
    f = (family or "").strip().lower().replace("-", "_").replace(" ", "_")
    return any(f == x or f.startswith(x + "_") or x in f for x in _NO_DATAFLOW_SINK_FAMILIES)

# ─────────────────────────────────────────────────────────────────────────────
# 信任边界（trustbound / trust_boundary_violation）真 sink 正向白名单
#
# 信任边界族的真漏洞证据**唯一**是「会话属性写入」：HttpSession.setAttribute / putValue
# （探针侧落地为 StandardSession / StandardSessionFacade.setAttribute|putValue）。
# 其余 sink 一律不是该族证据：
#   - doGet 里的 Cookie 构造（Cookie.<init> / setSecure / setHttpOnly）是探针故意织的
#     「假 sink」（只处理硬编码 "color" cookie），与信任边界无关；
#   - Response.addHeader / setHeader 回写的 Set-Cookie / Accept-Ranges 是框架噪声
#     （task-4 实测 7 条 confirmed 全是这类噪声，source_value 里根本没有 canary）。
# 故对信任边界族不能走 fail-open（否则 Cookie / Set-Cookie 噪声会被当真确认），必须正向
# 白名单：只有会话属性写入算真 sink。本组 tokens 同时服务于 is_genuine_sink_identity
# （网关身份）与 is_family_relevant_sink（值级身份）。
# ─────────────────────────────────────────────────────────────────────────────
_TRUSTBOUND_GENUINE_TOKENS = (
    "setattribute", "putvalue",
    "standardsession", "sessionfacade", "httpsession",
)

def _is_trustbound_family(family: str) -> bool:
    """该族是否为信任边界（trustbound / trust_boundary_violation 等同义写法）。"""
    f = (family or "").lower().replace("-", "_").replace(" ", "_")
    return "trustbound" in f or "trust_boundary" in f

# 这些族里「响应写入 / 模板渲染」本身就是 sink（XSS / SSTI），噪声黑名单不适用。
# 用子串匹配覆盖命名变体（java_reflected_xss / java_thymeleaf_ssti / template_injection / ssti 等）。
_RESPONSE_WRITER_FAMILY_HINTS = (
    "xss",
    "ssti",
    "模板注入",
    "thymeleaf",
    "freemarker",
    "velocity",
    "jinja",
    "template",
)


def is_response_writer_family(family: str) -> bool:
    """该族是否以响应写入 / 模板渲染为 sink（XSS / SSTI 类）。"""
    f = (family or "").lower()
    return any(hint in f for hint in _RESPONSE_WRITER_FAMILY_HINTS)


# ─────────────────────────────────────────────────────────────────────────────
# 族相关 sink 画像（2026-10-10 落地，值级判据专用）
#
# 起因：值级比对（我方投放数据是否真的出现在 sink 实参值里）如果只看「有没有命中」，
# 会被**非本族**的 sink 污染 —— 实测 run 251 的 129 条值级命中里有 28 条落在
# javax.servlet.http.Cookie.<init>：那只是请求把自己的 cookie 原值建对象（canary 就在名字旁边），
# 与任何注入族都无关。同理 SQL _safe 版的回显、路径 עם常量也不该被当成链路证据。
#
# 所以值级证据必须附带「这个 sink 是本族的 sink」这一条身份约束，否则等于换了个更响亮的噪声。
#
# 收口原则：
#   - 只做**宽松子串**画像 + fail-open：未登记族 / 空 sink_file 一律视为相关，
#     宁可漏判也不跨族背书（本通道只做正向加证，跨族误判也不会误杀真漏洞）。
#   - 刻意不写成「必须完全等于某类名」的白名单：JDK 版本换一下 throwable 之类命名变体
#     一出现，整族就失效，而 fail-open 的宽松子串不会因为命名差异突然静默失灵。
# ─────────────────────────────────────────────────────────────────────────────
_FAMILY_SINK_HINTS: Dict[str, Tuple[str, ...]] = {
    # 键 = family 子串（归一化后小写），按顺序第一条命中的为准
    "sql": ("jdbc", "statement.execute", "preparedstatement", "preparecall", "preparestatement",
            "createstatement", "createquery", "createNativeQuery".lower(), "jdbctemplate",
            "namedparameterjdbctemplate", "dbcp", "hikari", "sqldialect"),
    "command": ("runtime.exec", "processbuilder", "process.start", "commons.exec", "executor.exec"),
    "xpath": ("xpath", "xpathfactory", "xpathexpression"),
    "xxe": ("documentbuilder", "saxparser", "xmlreader", "unmarshaller", "xstream", "saxbuilder"),
    # path 必须排在 xpath 之后：'path' 是 'xpathi' 的子串，顺序反了会把 XPath 注入族的
    # 证据按「路径穿越」画像判掉（xpathi 全族值级命中静默归零）。
    "path": ("fileinputstream", "fileoutputstream", "randomaccessfile",
             "files.new", "files.read", "files.write", "file.", "fileutils", "pathto"),
    "ldap": ("dircontext", "initialdircontext", "ldap", "namingenumeration", "ldapcontext"),
    # 2026-10-12（r80 实证）：Tomcat 的真实反射入口是 CoyoteWriter（response.getWriter() 的
    # 实际返回类型），且它**覆写了** write/print/println/format 等（ByteBuddy 按类织入，钩父类
    # PrintWriter 对 Tomcat 响应体零命中）。旧 tokens 只覆盖到 CoyoteWriter.write（因字符串里
    # 恰好含 "writer.write"），而最常用的 print/println/format 会被判「非本族 sink」剔除。
    # 这也是 xss 值级通道长期只出零星几条的隐形原因。补 coyotewriter 兜住该类的全部覆写形态。
    "xss": ("printwriter", "printstream", "servletoutputstream", "outputstream.write",
            "writer.write", "response.getwriter", "response.getoutputstream",
            "coyotewriter", "writer.print", "writer.println", "writer.printf",
            "writer.format", "writer.append"),
    "weakrand": ("random.next", "random.int", "random.long", "math.random", "util.random"),
    "securecookie": ("cookie.setsecure", "cookie.sethttponly", "cookie.<init>", "servlet.http.cookie"),
    "crypto": ("cipher.getinstance", "cipher.init", "keygenerator"),
    "hash": ("messagedigest.getinstance", "messagedigest.update", "digestutils", "stringutils.getmd5"),
    "deserialization": ("objectinputstream", "readobject", "resolveClass".lower(), "xstream.fromxml",
                        "readvalue", "readValue".lower(),
                        # 2026-11-03（jsc 607）：fastjson/jackson 的事件 sink 是 JSON 解析器自身，
                        # 不带 objectinputstream 字样——画像缺这几条会让 gate-B 的族相关性闸
                        # 把 fastjson 真值点的迟到证据挡在外面（fail-closed 反向误杀）。
                        "fastjson", "parseobject", "json.parse", "defaultjsonparser",
                        "jackson", "objectmapper", "fromxml"),
    # 2026-11-03（jsc 607）：log4j/JNDI 的事件 sink 落在 JndiManager/JndiLookup/
    # Interpolator.lookup 上，与 ldap 无字面交集；无画像时 gate-B 走 fail-open，
    # 有画像就必须把这些真 sink 覆盖进来，否则 jndi 真值点会被反向误杀。
    "jndi": ("jndi", "initialcontext", "naming.lookup", "jndimanager", "jndilookup",
             "interpolator", "ldap", "rmi"),
    # 镜像包里的ognl/spel；注意把它放在最后，避免吃掉 sql / command 的前缀匹配
    "expression": ("expressionparser", "spel", "ognl", "scriptengine.eval", "templateengine.process"),
}

# SecureRandom 陷阱（2026-10-09 实证）：java.security.SecureRandom extends java.util.Random 且
# 不覆写 nextXxx，java.util.Random 上的 hook 会把强随机源误抓成弱随机。值级证据里同样要排除，
# 否则「弱随机」族的值级命中会从 SecureRandom 上取证，方向性错误。
_SECURE_RANDOM_EXCLUDE = "securerandom"


def family_sink_tokens(family: str) -> Tuple[str, ...]:
    """取该族的 sink 画像（无任何登记 → 返回空元组，交由调用方 fail-open）。"""
    f = (family or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not f:
        return ()
    if _is_trustbound_family(family):
        # 信任边界真 sink 唯一是会话属性写入，值级比对同样据此收口。
        return _TRUSTBOUND_GENUINE_TOKENS
    for key, tokens in _FAMILY_SINK_HINTS.items():
        if key in f:
            return tokens
        # 同义族名（pathtraver / path_traversal / file_read）
        if key == "path" and ("traver" in f or "file_" in f or "fileinclude" in f):
            return tokens
        if key == "command" and ("cmdi" in f or "rce" in f or "code_injection" in f):
            return tokens
    return ()


def is_family_relevant_sink(sink_file: str, family: str) -> bool:
    """该 sink 是否属于本族的 sink 画像（fail-open）。

    用途是给**值级判据**加身份约束：只有「我方投放数据真的出现在 sink 实参值里，
    且这个 sink 属于本族」才算数，避免用响应回显、cookie 自身构造、常量路径等
    非本族 sink 上的 sub 串命中冒充数据流证据。
    """
    sf = (sink_file or "").strip().lower()
    if not sf:
        return True          # 无 sink 信息 → fail-open
    if not is_genuine_sink_identity(sink_file, family):
        return False         # 框架噪声 sink
    tokens = family_sink_tokens(family)
    if not tokens:
        return True          # 未登记族（业务逻辑 / 未知族）→ fail-open
    if "random" in tokens and _SECURE_RANDOM_EXCLUDE in sf:
        return False
    return any(t in sf for t in tokens)


def is_genuine_sink_identity(sink_file: str, family: str) -> bool:
    """校验「到达的 sink」是否为该族真实危险函数。

    零误杀原则：未知 sink 类（含空 sink_file）→ 视为真实（fail-open），绝不误杀真漏洞；
    仅显式框架噪声 sink 或非本族真 sink 才判非真。

    信任边界特例：该族真 sink 唯一是会话属性写入（setAttribute / putValue），必须正向白名单，
    避免 Cookie 假 sink / Set-Cookie 框架噪声被当作真确认（task-4 实测 7 条 confirmed 全是噪声）。

    Cookie 特例（2026-10-30）：见 ``_COOKIE_SINK_TOKENS`` 注释。Cookie 构造/属性 sink
    只对 secure_cookie 族有意义，对其它族一律非真 —— 这条必须放在响应写入族放行之前，
    否则 xss 族会先被 ``is_response_writer_family`` 提前放行。

    csrf/cors 特例（2026-11-03）：两族是路由级配置属性，没有任何运行时数据流 sink；
    任何非空 sink_file 上的探针/值级命中都不能为其背书（jsc 607：4 条 csrf spec 被
    xxe/xstream 端点的解析器 sink 跨族确认）。确认只能走 oracle 或静态规则升级。

    HTTP 基础设施写入特例（2026-11-03）：对响应写入族，``writeInternal``（REST 序列化器）
    与 ``setHeader/addHeader``（响应头）是所有请求的必经之路，不是页面上下文 sink ——
    必须放在写入族放行之前判掉（jsc 607：websocket 异常串/log4j 回显被误确认 xss）。
    """
    sf = (sink_file or "").strip()
    if _is_no_dataflow_family(family) and sf:
        # csrf/cors 无数据流 sink：任何具体 sink 上的证据都不算数
        return False
    if _is_cookie_sink(sf) and not _is_cookie_family(family):
        return False
    if _is_session_write_sink(sf) and not _is_trustbound_family(family):
        # 会话属性写入只对信任边界族有意义（见 _SESSION_WRITE_TOKENS 注释）。
        return False
    if is_response_writer_family(family):
        # 响应写入 / 模板渲染即真 sink —— 但 REST 序列化器 / 响应头写入是
        # 所有请求的必经之路，对写入族同样是噪声，先于放行判掉。
        if _is_http_infra_noise(sf):
            return False
        return True
    if sf in SINK_NOISE_BLACKLIST:
        return False
    if _is_trustbound_family(family):
        # 正向白名单：只有会话属性写入算信任边界真 sink；Cookie 构造 / 其他一律非真。
        if not sf:
            return True  # 无 sink 信息 → 保守 fail-open，不误杀
        return any(tok in sf.lower() for tok in _TRUSTBOUND_GENUINE_TOKENS)
    return True


def is_sink_reached_genuine(state: str, sink_file: str, family: str) -> bool:
    """综合判据：状态为 sink-reached 且 sink 身份为该族真实 sink。"""
    if not is_sink_reached(state):
        return False
    return is_genuine_sink_identity(sink_file, family)


def iast_evidence_sink_reached_genuine(iast_evidence: dict, family: str) -> bool:
    """从聚合后的 iast_evidence（含 reached_sink_files / matched_sink_file）判断是否真·sink 到达。

    fail-open：当聚合证据里没有任何 sink_file 信息（如迟到证据补捞只升级了 state 而未回填
    sink_file）时，视为真实，避免误杀真实到达。
    """
    if not iast_evidence:
        return False
    state = str(iast_evidence.get("state", "") or "")
    if not is_sink_reached(state):
        return False
    sink_files = list(iast_evidence.get("reached_sink_files") or [])
    if not sink_files:
        sink_files = [iast_evidence.get("matched_sink_file") or ""]
    genuine_files = [sf for sf in sink_files if sf]
    if not genuine_files:
        # 无 sink_file 信息 → fail-open 视为真实（避免误杀迟到升级）
        return True
    return any(is_genuine_sink_identity(sf, family) for sf in genuine_files)
