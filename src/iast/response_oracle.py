"""族级行为 oracle：只看 HTTP 响应/时序，判断「注入是否真的产生了效果」。

## 为什么需要它（治本，而非治标）

平台此前的「确认」严重依赖自家 IAST 探针能看到 sink 实参。两个结构性缺陷：
  1. **换靶场即失效**：真实客户目标没有我们的探针，判据全部落空；
  2. **对象型 sink 永远看不见**：`new FileInputStream(file)` / `MessageDigest.getInstance(alg)`
     的实参是对象/数组，探针拿不到字符串。

本模块换判据：**判「有没有产生效果」，而不是判「sink 里有没有 payload」**。
响应体差异 / 时延差 / 文件内容签名 / 反射，全部是黑盒可观测量，与探针无关。
IAST 从此降级为「放大器」：有探针时提升置信度，没探针时 oracle 独立定案。

## 三个层次

- `build_probes`：按族生成探测臂（纯数据，不发请求）；
- `evaluate_passive`：对**已经发过**的响应做零成本判定（xss 反射 / 路径穿越文件签名）；
- `judge`：把多臂观测聚合成 `exploitable / not_exploitable / inconclusive`。

## 纪律

- 只判「本族 + 本通道」；通道不适用（path/multipart）或观测缺失 ⇒ `inconclusive`，
  **绝不**把「没打通」当成「不存在」——那正是历史上 FP/FN 互生的根源。
- `exploitable` 需要正向信号（差异/时延/签名/反射）；`not_exploitable` 只在
  「各臂都有响应且无任何正向信号」时给出，且置信度显著低于正向判定。
"""
from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional

# 支持 oracle 的族（canonical 名）
#
# 真实项目里大量漏洞的「值在 sink 处已被转换」——SSRF 变成 URL 对象、重定向变成
# Location 头、CORS 变成响应头回显、CRLF 被拼进 header。这类用「canary 原文匹配」
# 永远判不出来，只能用**黑盒可观测行为**判：看响应头有没有回显、看有没有注入成功。
# 新增的 4 族探测方式全部是通用的（不依赖任何靶场的命名/路径约定）。
ORACLE_FAMILIES = (
    "sql_injection", "command_execution", "path_traversal", "xss",
    "url_redirect", "cors", "crlf_injection", "ssrf",
    # 命令 stdout 走 WebSocket 帧、不进 HTTP 响应体，必须单独归一走两步投递。
    "websocket_cmd",
    # canonical_family 返回空串会导致族 oracle 早退，build_probes 产出 0 条探测臂。
    # 这两族的判据都是黑盒可观测量（表达式求值结果回显、反序列化阴阳对照），
    # 不依赖探针插桩，也不依赖任何靶场的路径/参数命名。
    "expression_injection",
    "deserialization",
)

_ALIASES = {
    "sql_injection": "sql_injection",
    "sqli": "sql_injection",
    "sql": "sql_injection",
    "command_execution": "command_execution",
    "command_injection": "command_execution",
    "cmdi": "command_execution",
    "command": "command_execution",
    "rce": "command_execution",
    "code_injection": "command_execution",
    "path_traversal": "path_traversal",
    "pathtraver": "path_traversal",
    "path": "path_traversal",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "url_redirect": "url_redirect",
    "open_redirect": "url_redirect",
    "open-redirect": "url_redirect",
    "unvalidated_redirect": "url_redirect",
    "urlredirect": "url_redirect",
    # 未登记 ⇒ canonical_family 返回空串 ⇒ _run_family_oracle 早退，该族
    # 族级探测臂根本不投，
    # 而 technique_oracle.url_whitelist_location 判据一直在等 Location 证据。
    # 语义与 url_redirect 同源（把外部 URL 投进去看 Location 是否回显），
    # 复用已验证的 redirect 探测臂即可。判据只看「Location 是否反射载荷 host」，
    # 端点不 sendRedirect 时无 Location ⇒ 不确认，fail-safe 不造误报。
    "url_whitelist_bypass": "url_redirect",
    "url_whitelist": "url_redirect",
    "url_allowlist": "url_redirect",
    "url_bypass": "url_redirect",
    "cors": "cors",
    "cors_misconfiguration": "cors",
    "cors_misconfig": "cors",
    "crlf_injection": "crlf_injection",
    "crlf": "crlf_injection",
    "http_response_splitting": "crlf_injection",
    "header_injection": "crlf_injection",
    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    # 普通 cmdi 端点仍走 delay 臂；族提升由 D1 在 spec 指向 WebSocket sink 时显式完成。
    "websocket_cmd": "websocket_cmd",
    "websocketscmdendpoint": "websocket_cmd",
    "websocket_cmd_endpoint": "websocket_cmd",
    "websocket_command_execution": "websocket_cmd",
    # 反序列化（Java 原生 / XStream / 文本型链）。刻意只收「引擎执行用户串」
    # 与「把用户字节喂给反序列化器」两类语义，不把 jndi_injection 等误收进来。
    "expression_injection": "expression_injection",
    "expr_injection": "expression_injection",
    "expression": "expression_injection",
    "qlexpress": "expression_injection",
    "spel": "expression_injection",
    "deserialization": "deserialization",
    "insecure_deserialization": "deserialization",
    "unsafe_deserialization": "deserialization",
    "java_deserialization": "deserialization",
    "xstream": "deserialization",
    "xstreamrce": "deserialization",
}

# 判定阈值
SIMILAR_THRESHOLD = 0.98      # 剥值归一后相似度低于此 ⇒ 判定「响应有实质差异」
LEN_DELTA_RATIO = 0.05        # 长度差超过 5% 也算实质差异
LEN_DELTA_ABS = 40            # 且至少 40 字符，避免小响应抖动
DELAY_THRESHOLD_MS = 2000.0   # 时延差 ≥ 2s 判命令执行（探针命令固定 sleep 4s）

# 外部域名用 RFC2606 保留域（example.com 的子域），保证「不可能真的被访问成功」，
# 因此只要它出现在响应头里，就一定是应用把用户输入原样回显了 —— 这是通用判据，
# 与任何靶场的路径/参数命名无关。
_ORACLE_EXTERNAL_HOST = "sastai-oracle.example.com"
_ORACLE_EXTERNAL_URL = "http://" + _ORACLE_EXTERNAL_HOST + "/"
# SSRF 探测：指向必然连不通的本机端口（1 号端口无服务），看错误是否被回显。
# 用本机而不是外部域名，是为了不依赖出网、且不会触发真实外连。
_ORACLE_SSRF_URL = "http://127.0.0.1:1/sastai-oracle"
# CRLF 探测：注入后应多出一个自定义响应头
_ORACLE_CRLF_HEADER = "X-Sastai-Probe"
_ORACLE_CRLF_PAYLOAD = "sastai1%0d%0a" + _ORACLE_CRLF_HEADER + ":%201"
# SSRF 错误回显特征（通用：连接被拒/解析失败/超时都算「真的发起了连接」）
_SSRF_ERROR_HINTS = (
    "connection refused", "connect failed", "connection reset",
    "unknown host", "no route to host", "connect timed out", "read timed out",
    "sockettimeoutexception", "connectexception", "unknownhostexception",
    "拒绝", "连接失败", "无法连接", "未知主机",
)

# `/websocket/cmd?path=<ws_path>` 动态注册一个 WebSocket 端点，随后连上该端点发一条消息，
# 端点把消息当 shell 命令执行并把 stdout 通过 WebSocket 帧回显。这类端点有两个结构性差异：
#   1. 命令注入参数根本不在 HTTP 层（param_name 为空是合理的），D1 的 no_param 守门会误杀；
#   2. stdout 不进 HTTP 响应体，现有 cmd_echo / cmd_native 判据永远读不到证据。
# 故单独归一为 websocket_cmd 族，走「HTTP 注册 + WebSocket 收发」两步 + 回显帧判据。
_WS_MARKER_RE = re.compile(r"SASTAI_WS_([a-z0-9]{4,})", re.I)
_WS_ENDPOINT_PREFIX = "/sastai_ws_"


def build_ws_probe(token: Any = "") -> Dict[str, str]:
    """构造 WebSocket 命令执行探测的两步材料（纯函数、确定性）。

    token 由调用方给（通常用 spec.id），保证同一 spec 复用同一端点路径、不同 spec 不冲突。
    marker 是**无害命令的固定输出**：`echo SASTAI_WS_<token>` 在 cmd.exe / bash 下都只会把
    该字符串打到 stdout，不读文件、不改状态、不外连；端点把 stdout 通过帧送回来，帧里出现
    marker 即证明「命令在服务端真实执行」——这是与探针无关的硬观测。
    """
    t = re.sub(r"[^a-z0-9]", "", str(token or "").lower())[:12] or "probe1"
    marker = "SASTAI_WS_" + t
    return {
        "marker": marker,
        "ws_path": _WS_ENDPOINT_PREFIX + t,
        "command": "echo " + marker,
        "register_param": "path",
    }


def canonical_family(family: Any) -> str:
    """把平台里的各种族写法归一；不支持的族返回空串。"""
    key = str(family or "").strip().lower()
    return _ALIASES.get(key, "")


def oracle_families_from_env(default: str = ",".join(ORACLE_FAMILIES)) -> List[str]:
    """从 `SAST_AI_ORACLE_FAMILIES` 读取启用族（逗号分隔，允许别名）。"""
    import os

    raw = os.environ.get("SAST_AI_ORACLE_FAMILIES", default)
    out: List[str] = []
    for part in str(raw or "").split(","):
        fam = canonical_family(part)
        if fam and fam not in out:
            out.append(fam)
    return out


def oracle_enabled() -> bool:
    """总开关。默认开启：只增加观测，不改任何判定（写库列 oracle_state 供离线复核）。"""
    import os

    return str(os.environ.get("SAST_AI_ORACLE", "1")).strip().lower() not in ("0", "false", "off", "no")


@dataclass(frozen=True)
class Probe:
    """一条探测臂。`channel=name` 表示把 payload 投在**参数名**上（名注入型 servlet），
    `channel=header` 表示投在固定请求头（Referer/UA 这类通用反射入口）。"""

    arm: str          # benign / bool_true / bool_false / delay / file / reflect
    payload: str
    channel: str = "value"   # value | name | header
    note: str = ""


@dataclass
class ArmResult:
    arm: str
    payload: str
    status: Optional[int] = None
    body: str = ""
    elapsed_ms: float = 0.0
    error: str = ""
    note: str = ""
    # 全在响应头里（Location 回显、ACAO 回显、注入的自定义头），不看头就判不了。
    headers: Dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str:
        """大小写不敏感取响应头（HTTP 头名不区分大小写）。"""
        target = str(name or "").strip().lower()
        for k, v in (self.headers or {}).items():
            if str(k).strip().lower() == target:
                return str(v or "")
        return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arm": self.arm,
            "payload": self.payload,
            "status": self.status,
            "body_len": len(self.body or ""),
            "elapsed_ms": round(float(self.elapsed_ms or 0.0), 1),
            "error": self.error,
            "note": self.note,
            "headers": {k: v for k, v in (self.headers or {}).items()
                        if str(k).lower() in ("location", "access-control-allow-origin",
                                              "access-control-allow-credentials")},
        }


# ─────────────────────────── 探测臂构造 ───────────────────────────

_SQLI_TRUE_QUOTE = "' OR '1'='1"
_SQLI_FALSE_QUOTE = "' OR '1'='2"
_SQLI_TRUE_NUM = "1 OR 1=1"
_SQLI_FALSE_NUM = "1 AND 1=2"

# 路径穿越候选阶梯：从近到远。
#
# 探测 payload 打进去会把这个 web.xml **截断成 0 字节** ⇒ 靶场下次重启时
# `SAXParseException: Premature end of file`，Context[/benchmark] 启动失败。
# 实测：471 跑到 23:43 时 web.xml 被清零，整轮扫完后靶场再也起不来。
#
# 修法：改用**专用签名文件**（由 launcher 创建并置只读），探测它可以读、但不能被写坏；
# 即使被写坏也只影响 oracle 自身，不会破坏靶场。
_PATH_CANDIDATES = (
    # 曾经放在 WEB-INF/ 下并置只读，结果是：Windows 只读文件让 Tomcat 的
    # ExpandWar.deleteDir 删不掉目录 ⇒ `ContextConfig.beforeStart 上下文[/benchmark]
    # 的异常修复 docBase` ⇒ 上下文起不来。
    # 移到 TOMCAT 根（webapps 同级）后：不在解包目录内，重解包不碰它；
    # 路径基准：TESTFILES_DIR = user.dir(=tomcat/bin) + testfiles/ ⇒ ../../ 即 tomcat 根。
    ("../../oracle-sig.txt", "oracle_sig"),
    # Spring Boot 这类以 `java -jar` 启动的目标没有 testfiles 目录，
    # `oracle-sig.txt` 必然不存在 ⇒ 所有穿越臂都返回「文件不存在」，误判成「没打通」。
    # 实测该靶场 /vul 端点响应 `File doesn't exist or is not a file.`，即端点无防护、
    # 只是我们的 payload 指向了不存在的文件。
    # 改用**项目自身必然存在的构建/配置文件**，并且**两种基准都试**：
    #   - 不带 ../：进程 cwd 就是项目根（`java -jar target/x.jar` 且 shell 在项目根时）
    #   - 带 ../：进程 cwd 在 target/ 或 bin/ 下
    # 与具体靶场无关 —— 任何 Maven/Gradle/npm 项目都至少命中一条。
    ("pom.xml", "pom_xml"),
    ("build.gradle", "gradle_build"),
    ("package.json", "npm_package"),
    ("../pom.xml", "pom_xml"),
    ("../../pom.xml", "pom_xml"),
    ("../../../pom.xml", "pom_xml"),
    ("../build.gradle", "gradle_build"),
    ("../../build.gradle", "gradle_build"),
    ("../package.json", "npm_package"),
    # 系统文件（Linux / Windows 双份；靶场 OS 未知，两种都要试）
    ("../../../../../../etc/passwd", "passwd"),
    ("../../../../../../../../etc/passwd", "passwd"),
    ("../../../../../../../../Windows/win.ini", "win_ini"),
    ("..\\..\\..\\..\\..\\..\\Windows\\win.ini", "win_ini"),
    # 取决于看门狗被拉起时的目录，相对候选（pom.xml / ../../../etc/passwd）经常
    # 解析不到文件 ⇒ oracle 臂全返回 "File doesn't exist"。绝对路径经
    # `Paths.get` 直接解析、不受 cwd 影响，且 C: 系统盘上 `hosts` 必然存在，
    # 故能稳定读到内容并触发 base64 签名确认。用正斜杠（Java 在 Windows 下接受）。
    ("C:/Windows/System32/drivers/etc/hosts", "win_hosts"),
    ("C:/Windows/win.ini", "win_ini"),
)

_FILE_SIGNATURES = {
    # 专用签名文件的内容标记（launcher 负责创建）
    "oracle_sig": ("SAST_ORACLE_SIG_V1",),
    # 保留：历史 arm 可能仍带这个 note（测试与回放数据），签名照旧识别
    "web_xml": ("<web-app", "</web-app>"),
    "passwd": ("root:x:0:0", "root:*:0:0"),
    "win_ini": ("[fonts]", "[extensions]", "for 16-bit app support"),
    "win_hosts": ("127.0.0.1 localhost", "localhost name resolution", "# localhost name resolution"),
    "pom_xml": ("<project", "<artifactId>", "<modelVersion>"),
    "gradle_build": ("plugins {", "dependencies {", "repositories {"),
    "npm_package": ('"name"', '"version"', '"dependencies"'),
}

_XSS_PROBE = "<sastxss1>"
# 反射型 XSS 的通用兜底入口（很多实现直接回显 Referer / UA）
_XSS_EXTRA_HEADERS = ("Referer", "User-Agent")

# 命令执行：两条通道各一发。`&` 用于「命令拼接」型（echo <param>），
# `FOO=` 用于「环境变量」型（Runtime.exec(args, {param}) + .bat 里 %FOO% 被当命令执行）。
_CMDI_DELAY = (
    ("& ping -n 5 127.0.0.1", "cmd_append"),
    ("FOO=ping -n 5 127.0.0.1", "env_assign"),
)

#
# 为什么必须有它：sql_injection 的探测臂此前只有「布尔真假对」+「阴性对照」，
# judge 也只有布尔差分一条判据。但真实靶场里布尔对**结构上无法产生差异**的场景很常见：
#   - 报错被吞：端点 catch(SQLException){log} 后返回空串，布尔对都是空响应；
# 这三类下 judge 只能落到 boolean_same（inconclusive），sqki 恒漏报。
#
# 时间盲注是唯一不依赖「响应内容」的可观测量：payload 里带 SLEEP(3)，
# 目标若把它拼进 SQL 并执行，该次请求就会比基线慢 ≥2s。这与 command_execution
# 已有的 delay 臂 + time_delay 判据**完全同构**，直接复用（不是新判定口径）。
#
# 纪律：
#   - 无破坏性：只有 SLEEP/pg_sleep/WAITFOR，不投 UNION 全列枚举 / DROP / 堆叠写；
#   - fail-safe：不延时、请求失败、5xx 一律不确认（judge 里逐条守住）；
#   - 多方言各一发，但都用 3s，判据只看「最大延时 - 基线」，与方言无关；
#   - 探测臂落在 replay_attempts（attempt_no 100+，带 elapsed_ms），
#     technique_oracle postpass 的 sqli_time 判据会独立再确认一次，形成双保险。
_SQLI_DELAY = (
    ("' OR SLEEP(3)-- ", "sqli_sleep_mysql_quote"),
    ("1 OR SLEEP(3)-- ", "sqli_sleep_mysql_numeric"),
    ("' OR pg_sleep(3)-- ", "sqli_sleep_pg_quote"),
    ("'; WAITFOR DELAY '0:0:3'-- ", "sqli_sleep_mssql"),
)

#
# 共同约束：这两族的端点都把**整个请求体**当输入（QLExpress.vuln1 用
# WebUtils.getRequestBody(req) 读表达式，XStreamRce.parseXml 用同一个工具读 XML），
# 不是「从某个具名字段取值」。所以探测臂必须走 D1 的 raw-body 通道，不能包成
# {"_body": "..."} 的 JSON 对象 —— 那样两端都只会解析失败。
#
# 表达式臂的判据是「求值结果」而不是「原样回显」：拼接臂期望 SASTAI_<token>
# （原文里带引号和 + 号，回显不会长这样），算术臂期望 777。安全端点若只是把
# 输入当字符串回显，两个期望值都不会出现，判据自然不确认。
_EXPR_BENIGN = '"SASTAI_BENIGN"'
_EXPR_ARITH = "111 * 7"
_EXPR_ARITH_EXPECT = "777"

# 反序列化臂走阴阳对照：阴臂投一个确定不是序列化对象/XML 的串，阳臂投主载荷
# （D1 传到 build_probes 的 primary_value，即 ysoserial gadget 或文本型链）以及
#   /xstream                    合法对象 XML → 200 "xstream"；垃圾串 → 500 StreamException
#   /deserialize/rememberMe/vuln  gadget → 200 "Are u ok?"；AAAA → 500
#   /shiro/deserialize           AES 包装弹 → 200；AAAA → 200 "decrypt error"
# 判据要求「阴臂明确失败 + 阳臂 2xx 且响应实质不同」，只证明攻击者可控字节
# 被目标反序列化器完整解析（反序列化入口被真实触发），**不等于** RCE 命令执行。
_DESER_INVALID_PREFIX = "SASTAI_NOT_AN_OBJECT_"
_DESER_VALID_XML = "<java.lang.String>SASTAI_ORACLE</java.lang.String>"
_DESER_ERROR_HINTS = (
    "streamexception", "streamcorruptedexception", "invalidclassexception",
    "objectinputstream", "readobject", "decrypt error", "rememberme cookie",
    "cannot be cast", "deserializ", "xstream", "serialization",
    # catch 异常后 return e.toString，HTTP status 仍是 200。只看 status>=400
    # 会把「阴臂明确解析失败」误判成「阴臂也被接受」→ negative_control_accepted，
    # 把 626 已确认的 Fastjson.java 冲成 unconfirmed。异常文本本身就是失败证据。
    "jsonexception", "syntax error", "parseobject", "jackson",
    "unexpected token", "not a json", "json parse", "qlcompile",
)


def _sqli_quote_context(payload: str) -> str:
    """从 A2 的 payload 猜注入上下文：quote（字符串拼接）/ numeric（数值位）。"""
    p = str(payload or "")
    if "'" in p or '"' in p:
        return "quote"
    if re.match(r"^\s*-?\d+\s*$", p) or re.match(r"^\s*\d+\s*(OR|AND|UNION|\|\||--)", p, re.I):
        return "numeric"
    return "quote"


def build_probes(family: Any, *, payload: str = "", servlet_name: str = "",
                 probe_token: Any = "",
                 channels: Iterable[str] = ("value", "name")) -> List[Probe]:
    """按族构造探测臂。`payload` 用于推断注入上下文（sqli 引号/数值）。

    为什么要两条通道：Benchmark 有大量 servlet 取的是「参数名」而非「参数值」
    （值 == servlet 名时，把该参数的**名字**当 param），例如 cmdi-01441 / xss-00544。
    名通道对「取值」型 servlet 无害（多出的参数被忽略），故两通道都投，命中即短路。
    """
    fam = canonical_family(family)
    chans = [c for c in channels if c in ("value", "name")]
    if not chans:
        chans = ["value"]
    name_ok = bool(servlet_name) and "name" in chans
    out: List[Probe] = []

    if fam == "websocket_cmd":
        wp = build_ws_probe(probe_token or servlet_name or "probe1")
        return [Probe("ws_echo", wp["command"],
                      note="ws_echo:" + wp["ws_path"] + ":" + wp["marker"])]

    if fam == "sql_injection":
        ctx = _sqli_quote_context(payload)
        if ctx == "numeric":
            val = [Probe("benign", "1", note="numeric_control"),
                   Probe("bool_true", _SQLI_TRUE_NUM, note="numeric_true"),
                   Probe("bool_false", _SQLI_FALSE_NUM, note="numeric_false")]
            nam = [Probe("bool_true", _SQLI_TRUE_NUM, channel="name", note="numeric_true@name"),
                   Probe("bool_false", _SQLI_FALSE_NUM, channel="name", note="numeric_false@name")]
        else:
            val = [Probe("benign", "sastai1", note="string_control"),
                   Probe("bool_true", _SQLI_TRUE_QUOTE, note="quote_true"),
                   Probe("bool_false", _SQLI_FALSE_QUOTE, note="quote_false")]
            nam = [Probe("bool_true", _SQLI_TRUE_QUOTE, channel="name", note="quote_true@name"),
                   Probe("bool_false", _SQLI_FALSE_QUOTE, channel="name", note="quote_false@name")]
        out = val + (nam if name_ok else [])
        # 放在布尔臂之后：judge 先看便宜的布尔差分，无差异才看延时（代价从低到高）。
        for pl, tag in _SQLI_DELAY:
            out.append(Probe("delay", pl, note=tag))
        return out

    if fam == "command_execution":
        out = [Probe("benign", "sastai1", note="control")]
        for pl, tag in _CMDI_DELAY:
            out.append(Probe("delay", pl, note=tag))
        if name_ok:
            for pl, tag in _CMDI_DELAY:
                out.append(Probe("delay", pl, channel="name", note=tag + "@name"))
        return out

    if fam == "path_traversal":
        out = [Probe("file", p, note=tag) for p, tag in _PATH_CANDIDATES]
        if name_ok:
            out += [Probe("file", p, channel="name", note=tag + "@name") for p, tag in _PATH_CANDIDATES]
        return out

    if fam == "xss":
        out = [Probe("reflect", _XSS_PROBE, channel="value", note="value_channel")]
        if name_ok:
            # 名注入型：参数名就是 payload，值填 servlet 名（servlet 按「值==自己名字」挑参数）。
            out.append(Probe("reflect", _XSS_PROBE, channel="name", note="name_channel"))
        # 反射型 XSS 的经典入口不止「声明的那一个参数」：Referer / User-Agent 常被直接回显。
        # 登记成了 servlet 名 ⇒ 只投声明通道永远打不中。这两条是通用兜底，不是靶场特判。
        for hdr in _XSS_EXTRA_HEADERS:
            out.append(Probe("reflect", _XSS_PROBE, channel="header", note="hdr:" + hdr))
        return out


    if fam == "url_redirect":
        # 注入一个不可能被真实访问的保留域名，看它是否出现在 Location 里。
        # 通用性：任何「把用户输入直接拼进跳转目标」的实现都会中；有白名单校验的实现不会。
        out = [Probe("redirect", _ORACLE_EXTERNAL_URL, note="external_host")]
        # 「解析歧义型绕过弹」可能正好通过白名单并被原样写进 Location。只投保留域
        # 会让这类端点恒为 no_location，等于拿不到它本可提供的正向证据。
        # 再投一发主载荷做对照：保留域不跳 + 主载荷跳 ⇒ 白名单被绕过，判据可判定。
        _pv = str(payload or "").strip()
        if _pv and _pv != _ORACLE_EXTERNAL_URL and len(_pv) >= 8:
            out.append(Probe("redirect", _pv, note="primary_payload"))
        if name_ok:
            out.append(Probe("redirect", _ORACLE_EXTERNAL_URL, channel="name",
                             note="external_host@name"))
        return out

    if fam == "cors":
        # 用 Origin 头投递：CORS 配置错误的表现是「把请求 Origin 原样回显到
        # Access-Control-Allow-Origin」，与参数名无关，故只投 header 通道。
        out = [Probe("cors", _ORACLE_EXTERNAL_URL.rstrip("/"), channel="header",
                     note="hdr:Origin")]
        return out

    if fam == "crlf_injection":
        # 注入 %0d%0a 让响应多出一个自定义头；能出现就说明 CR/LF 没被过滤。
        out = [Probe("crlf", _ORACLE_CRLF_PAYLOAD, note="header_inject")]
        if name_ok:
            out.append(Probe("crlf", _ORACLE_CRLF_PAYLOAD, channel="name",
                             note="header_inject@name"))
        return out

    if fam == "ssrf":
        # 指向必然连不通的本机端口：连接错误被回显 = 服务端真的替我们发起了请求。
        # 不依赖出网、不触发真实外连，且「错误回显」是通用可观测量。
        out = [Probe("ssrf", _ORACLE_SSRF_URL, note="loopback_unreachable")]
        if name_ok:
            out.append(Probe("ssrf", _ORACLE_SSRF_URL, channel="name",
                             note="loopback_unreachable@name"))
        return out

    if fam == "expression_injection":
        # 只看「求值」，不看「回显」：benign 是一条合法常量表达式做基线，
        # 两条 expr_eval 分别看字符串拼接与算术是否真的被引擎执行。
        t = re.sub(r"[^a-z0-9]", "", str(probe_token or "").lower())[:12] or "probe1"
        return [
            Probe("benign", _EXPR_BENIGN, note="expr_const"),
            Probe("expr_eval", '"SASTAI_" + "%s"' % t, note="expr_concat:" + t),
            Probe("expr_eval", _EXPR_ARITH, note="expr_arith"),
        ]

    if fam == "deserialization":
        t = re.sub(r"[^a-z0-9]", "", str(probe_token or "").lower())[:12] or "probe1"
        out = [Probe("deser_invalid", _DESER_INVALID_PREFIX + t,
                     note="negative_control")]
        pv = str(payload or "").strip()
        if pv and len(pv) >= 8 and pv != out[0].payload:
            out.append(Probe("deser_valid", pv, note="primary_payload"))
        out.append(Probe("deser_valid", _DESER_VALID_XML, note="xstream_object_xml"))
        return out

    return []


# ─────────────────────────── 响应归一与比较 ───────────────────────────

def _payload_forms(value: str) -> List[str]:
    """payload 在响应里可能出现的形态：原文 / URL 编码 / HTML 转义 / 双重。"""
    v = str(value or "")
    if not v:
        return []
    forms = {
        v,
        urllib.parse.quote(v, safe=""),
        urllib.parse.quote_plus(v, safe=""),
        html.escape(v),
        v.replace("'", "&#39;").replace('"', "&quot;"),
        v.replace("'", "&#x27;").replace('"', "&#34;"),
        urllib.parse.unquote(v),
    }
    return [f for f in forms if f]


def normalize_body(body: str, strip_values: Iterable[str] = ()) -> str:
    """把响应体归一：解 HTML 实体 → 解 URL 编码 → 剥掉我们自己投的值 → 折叠空白。

    剥值是关键：Benchmark 一类目标会把「含 payload 的 SQL 原文」回显进响应，
    不剥就会把「payload 文本不同」误当成「响应不同」→ 布尔对恒判差异 → 全量误报。
    """
    text = html.unescape(str(body or ""))
    try:
        text = urllib.parse.unquote(text)
    except Exception:
        pass
    for val in strip_values:
        for form in _payload_forms(val):
            text = text.replace(form, "\u00abP\u00bb")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def similarity(a: str, b: str) -> float:
    """归一后文本相似度（0~1）。空串对空串算 1.0。"""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:6000], b[:6000]).ratio()


def bodies_differ(a: str, b: str) -> bool:
    """两个已归一响应是否「有实质差异」（不是 payload 文本差异，值已剥除）。"""
    if abs(len(a) - len(b)) > max(LEN_DELTA_ABS, LEN_DELTA_RATIO * max(len(a), len(b))):
        return True
    return similarity(a, b) < SIMILAR_THRESHOLD


def _find_signature(body: str, tag: str) -> str:
    # 目标可能把文件内容做 HTML 转义再回显（例如 `&lt;Server`），
    # 必须先解实体再匹配签名，否则永远读不到原始标签。
    raw = html.unescape(str(body or ""))
    low = raw.lower()
    for sig in _FILE_SIGNATURES.get(tag, ()):  # type: ignore[arg-type]
        if sig.lower() in low:
            return sig
    # 目标可能把整个文件以 base64 回显，此时直接匹配 `<project` 永远失败，
    # 于是「明明读到了文件」却被判成没读到。
    # 这不是靶场特例：base64/hex 回显在真实系统里很常见（下载接口、图片转 base64 等）。
    # 故对「看起来像编码」的响应再做一次解码匹配，且只在长度合理时尝试（避免大响应卡住）。
    dec = _try_decode_text(raw)
    if dec:
        dlow = html.unescape(dec).lower()
        for sig in _FILE_SIGNATURES.get(tag, ()):  # type: ignore[arg-type]
            if sig.lower() in dlow:
                return sig
    return ""


def _try_decode_text(raw: str) -> str:
    """把 base64 / hex 编码的响应体还原成文本；不像编码则返回空串。

    只在「去空白后长度 ≥ 16 且全为 base64/hex 字符」时尝试，避免对普通 HTML 做无谓解码。
    失败一律返回空串（fail-open：解不出来就按原文判，绝不因此误判）。
    """
    import base64

    txt = "".join(str(raw or "").split())
    if len(txt) < 16:
        return ""
    # base64：字母数字 + / + = （URL-safe 变体用 - 和 _）
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
    if set(txt) <= b64_chars and len(txt) % 4 in (0, 2, 3):
        try:
            pad = "=" * (-len(txt) % 4)
            blob = base64.urlsafe_b64decode(txt + pad) if ("-" in txt or "_" in txt) \
                else base64.b64decode(txt + pad)
            out = blob.decode("utf-8", "ignore")
            # 解出来得是可读文本才采信（二进制内容不算）
            if out and sum(1 for ch in out[:400] if ch.isprintable() or ch in "\r\n\t") >= min(200, len(out[:400])):
                return out
        except Exception:  # noqa: BLE001
            pass
    # hex：纯 0-9a-f，偶数长度
    if len(txt) % 2 == 0 and set(txt) <= set("0123456789abcdefABCDEF"):
        try:
            out = bytes.fromhex(txt).decode("utf-8", "ignore")
            if out and sum(1 for ch in out[:400] if ch.isprintable() or ch in "\r\n\t") >= min(200, len(out[:400])):
                return out
        except Exception:  # noqa: BLE001
            pass
    return ""


_COOKIE_ILLEGAL = set(' \t",;\\')


def encode_cookie_value(value: str) -> str:
    """cookie 值里的空格/引号/逗号/分号会被 Tomcat 整条丢弃（实测：带空格的 payload ⇒
    servlet 读到 noCookieValueSupplied）。目标侧普遍会 URLDecoder.decode，故按需百分号编码。
    仅对**含非法字符**的值编码，纯 `bar'--` 之类保持原样，避免改变既有基线行为。
    """
    v = str(value or "")
    if not v:
        return v
    if any(ch in _COOKIE_ILLEGAL for ch in v) or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in v):
        return urllib.parse.quote(v, safe="")
    return v


def _raw_reflection(body: str, payload: str) -> bool:
    """payload 原样（未转义）出现在响应里。"""
    if not payload:
        return False
    return payload in (body or "")


def _escaped_reflection(body: str, payload: str) -> bool:
    esc = html.escape(payload)
    return bool(esc and esc != payload and esc in (body or ""))


# ─────────────────────────── 被动判定（零请求） ───────────────────────────

def evaluate_passive(family: Any, payload: str, body: str) -> Dict[str, Any]:
    """对已发出的响应做零成本判定（xss 反射 / pathtraver 文件签名 / sqli 报错）。

    只作为**加分项**：命中即 `exploitable`（正向信号足够强），未命中一律 `inconclusive`
    （不能因为主载荷没回显就否定，可能只是通道/形状不对）。
    """
    fam = canonical_family(family)
    body = str(body or "")
    if fam == "xss":
        if _raw_reflection(body, payload):
            return {"verdict": "exploitable", "signal": "reflection_raw", "confidence": 0.85,
                    "reason": "payload 原样出现在响应体（未转义）"}
        if _escaped_reflection(body, payload):
            return {"verdict": "not_exploitable", "signal": "reflection_escaped", "confidence": 0.6,
                    "reason": "payload 被 HTML 转义后回显"}
        return {"verdict": "inconclusive", "signal": "no_reflection", "confidence": 0.0,
                "reason": "响应体未见 payload（可能不反射）"}
    if fam == "path_traversal":
        low = body.lower()
        for tag, sigs in _FILE_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in low:
                    return {"verdict": "exploitable", "signal": "file_signature", "confidence": 0.9,
                            "reason": "响应体出现文件内容签名 %r（%s）" % (sig, tag)}
        return {"verdict": "inconclusive", "signal": "no_file_signature", "confidence": 0.0,
                "reason": "响应体未见已知文件签名"}
    return {"verdict": "inconclusive", "signal": "unsupported", "confidence": 0.0, "reason": ""}


# ─────────────────────────── 多臂聚合判定 ───────────────────────────

def _by_arm(arms: List[ArmResult]) -> Dict[str, List[ArmResult]]:
    out: Dict[str, List[ArmResult]] = {}
    for a in arms:
        out.setdefault(a.arm, []).append(a)
    return out


def _ok(a: ArmResult) -> bool:
    return bool(a) and not a.error and a.status is not None


def _pairs_by_channel(arms: List[ArmResult]) -> List[Dict[str, ArmResult]]:
    """按通道（value / name）把臂配对。通道信息编码在 note 的 `@name` 后缀里。"""
    buckets: Dict[str, Dict[str, ArmResult]] = {}
    for a in arms or []:
        ch = "name" if str(a.note or "").endswith("@name") else "value"
        bucket = buckets.setdefault(ch, {})
        # 同名臂保留第一个成功的（短路后不会重复）
        bucket.setdefault(a.arm, a)
    return [buckets[k] for k in ("value", "name") if k in buckets]


def _time_delay_reason(arms: List[ArmResult], baseline_ms: float = 0.0) -> str:
    """时间盲注正向信号：某条 delay 臂比基线慢 ≥ DELAY_THRESHOLD_MS 且非 5xx。

    与 command_execution 分支的 time_delay 判据逐条等价（同一阈值、同一基线取法），
    抽出供 sql_injection 复用；cmdi 既有代码不动，避免回归。返回空串表示无信号。
    基线优先用外部传入（主重放耗时），否则用同组 benign 臂，都没有则按 0 比。
    """
    delays = [a for a in (arms or []) if a.arm == "delay" and _ok(a)]
    if not delays:
        return ""
    base_ms = float(baseline_ms or 0.0)
    if not base_ms:
        benigns = [a for a in (arms or []) if a.arm == "benign" and _ok(a)]
        if benigns:
            base_ms = float(benigns[0].elapsed_ms or 0.0)
    best = max(delays, key=lambda a: float(a.elapsed_ms or 0.0))
    delta = float(best.elapsed_ms or 0.0) - base_ms
    if delta >= DELAY_THRESHOLD_MS and best.status is not None and int(best.status) < 500:
        return ("时延臂比基线慢 %.0fms（%s, %.0fms vs %.0fms）"
                % (delta, best.note, best.elapsed_ms, base_ms))
    return ""


def judge(family: Any, arms: List[ArmResult], baseline_ms: float = 0.0) -> Dict[str, Any]:
    """把多臂观测聚合成结论。

      - `exploitable` 只由**正向信号**触发（布尔差异 / 时延 / 文件签名 / 原样反射）；
      - `not_exploitable` 只在**主动净化证据**下给出（payload 被转义回显）；
      - 其余一律 `inconclusive` —— 「没打通」不等于「不存在」，黑盒没有否定证据的能力。
    """
    fam = canonical_family(family)
    base = {
        "family": fam,
        "verdict": "inconclusive",
        "signal": "",
        "confidence": 0.0,
        "reason": "",
        "arms": [a.to_dict() for a in (arms or [])],
    }

    if fam == "websocket_cmd":
        ws_arms = [a for a in (arms or []) if a.arm == "ws_echo" and _ok(a)]
        if not ws_arms:
            base["reason"] = "WebSocket 回显臂观测缺失（端点注册失败 / 连接超时 / 未收到帧）"
            return base
        for a in ws_arms:
            m = _WS_MARKER_RE.search(str(a.payload or ""))
            if m and m.group(0).lower() in str(a.body or "").lower():
                base.update(verdict="exploitable", signal="websocket_echo", confidence=0.90,
                            reason="WebSocket 帧回显了命令输出 %r —— 命令在服务端真实执行"
                                   % m.group(0))
                return base
        base.update(signal="no_ws_echo",
                    reason="WebSocket 帧未回显命令输出（命令未执行 / 端点不可用），保持未确认")
        return base

    if fam == "expression_injection":
        evals = [a for a in (arms or []) if a.arm == "expr_eval" and _ok(a)]
        if not evals:
            base["reason"] = "表达式求值臂观测缺失（请求失败 / 端点不可达）"
            return base
        for a in evals:
            note = str(a.note or "")
            if note.startswith("expr_concat:"):
                expect = "SASTAI_" + note.split(":", 1)[1]
            elif note == "expr_arith":
                expect = _EXPR_ARITH_EXPECT
            else:
                continue
            raw = str(a.body or "")
            # 原样回显不算求值：注入串里带引号 / + / *，回显型实现会整串带回来。
            if str(a.payload or "").strip() and str(a.payload).strip() in raw:
                continue
            body = normalize_body(raw, [str(a.payload or "")])
            if (expect and int(a.status or 0) < 400
                    and expect.lower() in body.lower()):
                base.update(verdict="exploitable", signal="expr_eval", confidence=0.90,
                            reason="表达式引擎返回了注入表达式的求值结果 %r（status=%s，非原样回显）"
                                   % (expect, a.status))
                return base
        base.update(signal="no_expr_eval",
                    reason="%d 条求值臂均未返回期望的拼接/算术结果" % len(evals))
        return base

    if fam == "deserialization":
        neg = [a for a in (arms or []) if a.arm == "deser_invalid" and _ok(a)]
        pos = [a for a in (arms or []) if a.arm == "deser_valid" and _ok(a)]
        if not neg or not pos:
            base["reason"] = "反序列化阴阳对照臂观测缺失（请求失败 / 端点不可达）"
            return base
        neg_bad = []
        for a in neg:
            txt = (str(a.body or "") + " " + str(a.status or "")).lower()
            if int(a.status or 0) >= 400 or any(h in txt for h in _DESER_ERROR_HINTS):
                neg_bad.append(a)
        if not neg_bad:
            base.update(signal="negative_control_accepted",
                        reason="阴臂（确定不是序列化对象的字节）也被正常接受，"
                               "无法区分目标是否真的做了反序列化")
            return base
        for a in pos:
            st = int(a.status or 0)
            if st == 0 or st >= 400:
                continue
            left = normalize_body(str(a.body or ""), [str(a.payload or "")])
            right = normalize_body(str(neg_bad[0].body or ""),
                                   [str(neg_bad[0].payload or "")])
            if bodies_differ(left, right):
                base.update(verdict="exploitable", signal="deser_object_accepted",
                            confidence=0.85,
                            reason="阴阳对照成立：非对象字节被拒（status=%s），"
                                   "攻击者可控载荷被反序列化器接受（status=%s，响应实质不同）；"
                                   "证明反序列化入口被真实触发，不等同于 RCE 命令执行"
                                   % (neg_bad[0].status, a.status))
                return base
        base.update(signal="no_deser_diff",
                    reason="阴臂失败但阳臂未表现出实质差异，保持未确认")
        return base

    if fam == "sql_injection":
        # 空库 / 报错被吞 / 302 统一重定向时布尔对必然一致，只有它能定案。
        # 无 delay 臂（历史数据 / 内嵌库无 sleep）时本段自动跳过，完全回落到
        # 原布尔判据，对既有用例零回归。
        _delay = _time_delay_reason(arms, baseline_ms)
        if _delay:
            base.update(verdict="exploitable", signal="time_delay", confidence=0.85,
                        reason=_delay)
            return base
        tried = 0
        for pair in _pairs_by_channel(arms):
            true_arm, false_arm, benign = pair.get("bool_true"), pair.get("bool_false"), pair.get("benign")
            if not (_ok(true_arm) and _ok(false_arm)):  # type: ignore[arg-type]
                continue
            tried += 1
            strip = [true_arm.payload, false_arm.payload,  # type: ignore[union-attr]
                     benign.payload if benign else ""]
            t = normalize_body(true_arm.body, strip)      # type: ignore[union-attr]
            f = normalize_body(false_arm.body, strip)     # type: ignore[union-attr]
            if bodies_differ(t, f):
                base.update(verdict="exploitable", signal="boolean_diff", confidence=0.9,
                            reason="布尔对响应实质不同（剥值后 sim=%.3f, len %d vs %d）"
                                   % (similarity(t, f), len(t), len(f)))
                return base
            # 布尔对一致，但与阴性对照不同 ⇒ 疑似「语法报错型」（INSERT/UPDATE 场景常见）。
            # 只记录不确认：安全实现也可能拒绝非法字符并回不同错误页。
            if _ok(benign) and benign is not None:  # type: ignore[arg-type]
                b = normalize_body(benign.body, strip)  # type: ignore[union-attr]
                if bodies_differ(b, t) and not bodies_differ(t, f):
                    base.update(signal="error_diff_only", confidence=0.3,
                                reason="布尔对一致但与无害对照不同——疑似语法报错型（不确认）")
                    return base
        if not tried:
            base["reason"] = "布尔对观测缺失（请求失败）"
        elif not base["reason"]:
            base.update(signal="boolean_same", reason="布尔对响应一致——未见布尔差异（写入型语句不适用）")
        return base

    if fam == "command_execution":
        delays = [a for a in (arms or []) if a.arm == "delay" and _ok(a)]
        if not delays:
            base["reason"] = "时延臂观测缺失（请求失败）"
            return base
        base_ms = float(baseline_ms or 0.0)
        if not base_ms:
            benigns = [a for a in (arms or []) if a.arm == "benign" and _ok(a)]
            if benigns:
                base_ms = float(benigns[0].elapsed_ms or 0.0)
        best = max(delays, key=lambda a: float(a.elapsed_ms or 0.0))
        delta = float(best.elapsed_ms or 0.0) - base_ms
        if delta >= DELAY_THRESHOLD_MS and best.status is not None and int(best.status) < 500:
            base.update(verdict="exploitable", signal="time_delay", confidence=0.85,
                        reason="时延臂比基线慢 %.0fms（%s, %.0fms vs %.0fms）"
                               % (delta, best.note, best.elapsed_ms, base_ms))
            return base
        base.update(signal="no_delay",
                    reason="%d 个时延臂均未超阈值（max delta %.0fms）" % (len(delays), delta))
        return base

    if fam == "path_traversal":
        files = [a for a in (arms or []) if a.arm == "file" and _ok(a)]
        if not files:
            base["reason"] = "文件臂观测缺失（请求失败）"
            return base
        for a in files:
            sig = _find_signature(a.body, a.note)
            if sig:
                base.update(verdict="exploitable", signal="file_signature", confidence=0.92,
                            reason="payload=%r 读到文件内容签名 %r" % (a.payload, sig))
                return base
        base.update(signal="no_file_signature",
                    reason="%d 个穿越候选均未读到文件内容签名" % len(files))
        return base

    if fam == "xss":
        reflects = [a for a in (arms or []) if a.arm == "reflect" and _ok(a)]
        if not reflects:
            base["reason"] = "反射臂观测缺失（请求失败）"
            return base
        for a in reflects:
            if _raw_reflection(a.body, a.payload):
                base.update(verdict="exploitable", signal="reflection_raw", confidence=0.9,
                            reason="payload 原样出现在响应体（%s，未转义）" % a.note)
                return base
        if any(_escaped_reflection(a.body, a.payload) for a in reflects):
            base.update(verdict="not_exploitable", signal="reflection_escaped", confidence=0.65,
                        reason="payload 被 HTML 转义后回显（主动净化证据）")
            return base
        base.update(signal="no_reflection", reason="响应体未见 payload（不反射）")
        return base


    if fam == "url_redirect":
        arms_r = [a for a in (arms or []) if a.arm == "redirect" and _ok(a)]
        if not arms_r:
            base["reason"] = "跳转臂观测缺失（请求失败）"
            return base
        for a in arms_r:
            loc = a.header("Location")
            if not loc:
                continue
            # 白名单绕过型端点把**注入的绕过 URL 原样**写进 Location（例如
            # `http://evil.com\@www.joychou.org/a.html`），这同样是「用户输入直达
            # 跳转目标」的硬证据，却因不含保留域名被判 location_constrained 而漏掉。
            # 现增加「本次探测臂注入值被原样回显」这一条，要求注入值长度 >= 8，
            # 固定跳转/登录页不可能包含我方投放的完整 URL，不引入误报。
            _inj = str(getattr(a, "payload", "") or "").strip()
            _hit = _ORACLE_EXTERNAL_HOST in loc.lower() or (
                len(_inj) >= 8 and (_inj in loc or _inj.lower() in loc.lower()))
            if _hit:
                base.update(verdict="exploitable", signal="location_reflect", confidence=0.9,
                            reason="Location 头回显注入的跳转目标（status=%s, loc=%r）"
                                   % (a.status, loc[:120]))
                return base
        # 有 Location 但不含外部域名 ⇒ 应用做了跳转但目标被约束（可能是白名单）。
        # 黑盒无法断言「一定不可绕过」，故不判 not_exploitable，只记信号。
        if any(a.header("Location") for a in arms_r):
            base.update(signal="location_constrained",
                        reason="有 Location 但未回显外部域名（疑似白名单/固定跳转）")
            return base
        base.update(signal="no_location", reason="响应无 Location 头（非跳转响应）")
        return base

    if fam == "cors":
        arms_c = [a for a in (arms or []) if a.arm == "cors" and _ok(a)]
        if not arms_c:
            base["reason"] = "CORS 臂观测缺失（请求失败）"
            return base
        for a in arms_c:
            acao = a.header("Access-Control-Allow-Origin")
            if _ORACLE_EXTERNAL_HOST in acao.lower():
                acac = a.header("Access-Control-Allow-Credentials").lower()
                base.update(verdict="exploitable", signal="acao_reflect", confidence=0.9,
                            reason="Access-Control-Allow-Origin 回显外部 Origin（%r, credentials=%s）"
                                   % (acao[:80], acac or "未设置"))
                return base
            if acao.strip() == "*":
                # 通配符是配置宽松，但浏览器禁止其携带凭据，危害低于「回显任意 Origin」。
                # 按「宁可 inconclusive 不可误判」的纪律，只记信号不确认。
                base.update(signal="acao_wildcard",
                            reason="ACAO 为通配符 *（未回显具体 Origin，危害有限）")
                return base
        base.update(signal="no_acao", reason="响应未回显 Access-Control-Allow-Origin")
        return base

    if fam == "crlf_injection":
        arms_l = [a for a in (arms or []) if a.arm == "crlf" and _ok(a)]
        if not arms_l:
            base["reason"] = "CRLF 臂观测缺失（请求失败）"
            return base
        for a in arms_l:
            if a.header(_ORACLE_CRLF_HEADER):
                base.update(verdict="exploitable", signal="header_injected", confidence=0.92,
                            reason="响应头出现注入的 %s（CR/LF 未被过滤）" % _ORACLE_CRLF_HEADER)
                return base
        base.update(signal="no_injected_header",
                    reason="%d 个注入臂均未产生 %s 响应头（CR/LF 被过滤或未到达 header 写入）"
                           % (len(arms_l), _ORACLE_CRLF_HEADER))
        return base

    if fam == "ssrf":
        arms_s = [a for a in (arms or []) if a.arm == "ssrf" and _ok(a)]
        if not arms_s:
            base["reason"] = "SSRF 臂观测缺失（请求失败）"
            return base
        for a in arms_s:
            low = (a.body or "").lower()
            hit = next((h for h in _SSRF_ERROR_HINTS if h in low), "")
            if hit:
                base.update(verdict="exploitable", signal="error_reflect", confidence=0.85,
                            reason="服务端替我们发起了请求，连接错误被回显（命中 %r）" % hit)
                return base
            # 响应体直接回显了内网地址本身，也说明输入进了 URL 并被执行
            if "127.0.0.1:1" in low or "127.0.0.1:1" in (a.header("Location") or ""):
                base.update(verdict="exploitable", signal="internal_url_reflect", confidence=0.8,
                            reason="响应回显了注入的内网地址（说明输入进入了 URL 执行路径）")
                return base
        base.update(signal="no_ssrf_effect",
                    reason="%d 个 SSRF 臂均未见连接错误/内网地址回显（可能被白名单或协议校验拦住）"
                           % len(arms_s))
        return base

    base["reason"] = "不支持的族"
    return base


def summarize(verdict: Dict[str, Any]) -> str:
    """一行摘要，供日志/报告使用。"""
    return "[oracle:%s] %s/%s %s" % (
        verdict.get("family") or "?",
        verdict.get("verdict") or "?",
        verdict.get("signal") or "-",
        (verdict.get("reason") or "")[:120],
    )
