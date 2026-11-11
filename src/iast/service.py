"""I1 listener 服务层：会话注册 + workspace 绑定 + 事件摄取（token 鉴权 / 去重 / canary 匹配）。

依据：3.9 / 3.15 / 3.16 / 3.19。
- workspace 主键 = code_path（target_path），1:N session（一个仓库多 appName/微服务）。
- 注册颁发 probe_token；摄取端点要求 X-Iast-Token 匹配。
- 摄取幂等去重 + 依事件携带的 canary 跑三态匹配，标记 canary_match / canary_state。
"""
import hashlib
import logging
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.core.exploit_spec import canonical_family
from src.core.identity_marker import filter_identity_markers
from src.iast.canary import CanaryMatcher, CanaryStates, is_sink_reached
from src.iast.ingest_metrics import INGEST_METRICS
from src.iast.version_contract import validate_version_contract
from src.infrastructure.db import Database

logger = logging.getLogger(__name__)

# item 4 方向 3：SQLite 单写者约束下，所有 iast_events 刷盘必须串行。该锁与 IastService 实例
# 生命周期解耦（模块级单例），使并发 ingest_events 调用合流为批量刷盘，不会并发写库。
# 方向 2 的「背压」也由此实现：锁竞争 + 同步 flush 使 HTTP 处理线程在后端跟不上时自然阻塞
# （探针侧 POST 变慢），而非丢弃事件——宁可变慢不丢。
_INGEST_FLUSH_LOCK = threading.Lock()


def _is_value_evidence(rec: Dict[str, Any]) -> bool:
    """该事件是否为「值级证据」——平台 canary 身份段真实出现在 sink 实参文本里。

    canary 为空时退化为常量；对「多 servlet 共用同一 sink 名、sink_line 恒 0」的族（如
    trustbound 的 HttpSession.setAttribute），漏洞 sink 事件会与框架样板写入同键而被挤掉。
    这类事件是攻击者数据确证穿透到 sink 实参的直接证据，价值最高，一律免去重。

    fail-open：解析异常返回 False（仍按原键去重），不改变既有语义。
    """
    try:
        payload = str(rec.get("source_value") or "")
        if not payload:
            return False
        return bool(CanaryMatcher.find_identity(payload))
    except Exception:  # noqa: BLE001 - 判据异常不得影响摄取
        return False

# 代码根目录解析结果观测表：task_id -> code_root。
# —— 拿不到就意味着抑制恒为 0。用全局而非实例属性，是因为 IastService 可能多实例。
_CODE_ROOT_STATS: Dict[Any, str] = {}

# 取值的依据见 IastService._resolve_event_task_id 的 docstring —— 身份段含 run nonce、
# 同一身份段在一次扫描内不会改属，故正结果 TTL 可较长；负结果可能只是「spec 尚未登记」，
# 必须短 TTL；workspace 级回退快照含运行时间窗与活跃会话，随时间变化，用最短 TTL。
_OWNERSHIP_IDENT_TTL = 60.0
_OWNERSHIP_NEG_TTL = 2.0
_OWNERSHIP_WORKSPACE_TTL = 5.0
# 容量上限：键为真实 canary 身份段（每 spec 一个），跨多轮任务会累积。
# 超限整表清空（而非 LRU）——重建代价只是一次 DB 查询，逻辑更简单、无额外簿记开销。
_OWNERSHIP_CACHE_MAX = 4096
# 探针批量 flush 的迟到事件」被时间窗错归到后启动 task / 归 NULL 的问题。配合分片真串行（排空等待）
# 使用：排空期内无下一 task 在跑，312 的迟到事件落进 312 的延长窗 → 正确归 312，不被 313 抢。
_ATTR_GRACE_SECONDS = 300.0

# item 4 方向 1：iast_events 批量落库 INSERT 模板（executemany 单事务复用）
_IAST_EVENT_INSERT_SQL = """INSERT INTO iast_events
       (session_id, workspace_id, task_id, app_name, agent_id, event_type, vuln_type, trace_id, canary, canary_match, canary_state, sink_reached, sink_file, sink_line, sink_method, source_name, source_type, source_value, principal, severity, stack_trace, taint_path_json, evidence_json, correlated_finding_id, correlated_instance_id, ingested_at, ingest_bucket)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)"""


def _now() -> str:
    return datetime.utcnow().isoformat()


def _canary_hash(canary: str) -> str:
    return hashlib.sha256(canary.encode("utf-8")).hexdigest()[:16]


def _parse_dt(value: Optional[str]) -> Optional[float]:
    """把 scan_tasks / iast_events 里的时间戳（ISO，可能带 'T' 或空格分隔、可选小数秒）解析为 POSIX 秒。

    用 time.mktime + 本地时间元组：本项目 ingestion 全部走 _now（datetime.utcnow.isoformat，
    即 UTC 字面量），而 scan_tasks.started_at/finished_at 由后端以本地/UTC 混合写入，
    统一按「无时区本地解析」处理即可满足「落窗比较」的相对一致性需求（只比较先后，不比较绝对时区）。
    解析失败返回 None。
    """
    if not value:
        return None
    s = str(value).strip().replace("T", " ").replace("Z", "")
    # 去掉小数秒
    if "." in s:
        s = s.split(".")[0]
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return None


# JDK sink 类方法签名前缀 -> 规范漏洞家族（模块级，供 IastService.correlate_sink_events_to_findings 使用）。
# 仅收录「真实污点传播漏洞 sink」；框架渲染类（org.thymeleaf / org.apache.velocity 的
# TemplateEngine.process / parseExpression 等）在每次页面渲染都会触发，属噪声，不入库归因。
# 家族名必须与 src/core/exploit_spec.canonical_family 的归并结果一致（如 SQL 注入、xxe）。
_SINK_SIGNATURE_TO_FAMILY: List[Tuple[str, str]] = [
    ("java.lang.ProcessBuilder", "command_execution"),
    ("java.lang.Runtime", "command_execution"),
    ("java.lang.ProcessImpl", "command_execution"),
    ("com.mysql.cj.jdbc", "SQL 注入"),
    ("com.mysql.jdbc", "SQL 注入"),
    ("org.apache.ibatis.executor", "SQL 注入"),
    ("org.springframework.jdbc", "SQL 注入"),
    ("org.apache.xerces", "xxe"),
    ("org.xml.sax", "xxe"),
    ("javax.xml.parsers", "xxe"),
    ("com.fasterxml.jackson.databind.ObjectMapper", "deserialization"),
    ("com.alibaba.fastjson.JSON", "deserialization"),
    ("java.io.ObjectInputStream", "deserialization"),
    ("org.springframework.expression", "spel_injection"),
    ("org.springframework.http.converter.StringHttpMessageConverter", "xss"),
    ("java.io.RandomAccessFile", "path_traversal"),
    ("java.io.FileInputStream", "path_traversal"),
    ("java.io.FileOutputStream", "path_traversal"),
    ("java.nio.file", "path_traversal"),
    ("java.net.HttpURLConnection", "ssrf"),
    ("java.net.URL", "ssrf"),
    ("org.apache.http", "ssrf"),
]


def _sink_signature_to_family(sink_file: str) -> str:
    """由 JDK sink 签名（iast_events.sink_file，形如 java.lang.ProcessBuilder.start）推断规范漏洞家族。

    返回 canonical_family 字符串；无法归类时返回 ''。
    """
    sf = (sink_file or "").strip()
    if not sf:
        return ""
    for prefix, fam in _SINK_SIGNATURE_TO_FAMILY:
        # 用 prefix + '.' 防 java.lang.Runtime 误匹配 java.lang.RuntimeException 一类。
        if sf == prefix or sf.startswith(prefix + "."):
            return fam
    return ""


class IastService:
    def __init__(self, db: Optional[Database] = None):
        if db is None:
            import tempfile
            from pathlib import Path
            tmp = Path(tempfile.gettempdir()) / f"savr_iast_{int(time.time() * 1000000)}.db"
            db = Database(str(tmp))
        self.db = db
        # _ident_owner：(workspace_id, canary 身份段) -> (过期时刻, task_id 或 None)
        # _ws_owner：workspace_id -> (过期时刻, {task_ids, windows, active})
        # 实例级缓存即可生效：API 侧 IastService 由容器单例持有（src/api/dependencies.py）。
        self._ident_owner: Dict[Tuple[int, str], Tuple[float, Optional[int]]] = {}
        self._ws_owner: Dict[int, Tuple[float, Dict[str, Any]]] = {}

    # ---------- workspace 绑定（3.9 / 3.19） ----------
    @staticmethod
    def _norm_path(p: str) -> str:
        """路径归一化：统一分隔符、去尾斜杠、忽略大小写（Windows 上不区分大小写）。

        为什么必须归一化再比：workspace 里的 target_path 是建档时写进去的（常带正斜杠，
        如 `D:/Users/...`），而探针/Java 侧上报的几乎必然是平台原生分隔符（`D:\\Users\\...`）。
        「code_path 与该 workspace_id 已绑定到其他路径」，表现为靶场起不来且错误信息
        指向"重绑"这种完全无关的方向，极难自查。启动脚本侧一直自己做这个归一化，
        service 层漏了 —— 现统一到这里，两边不再各写一套。
        """
        return (p or "").replace("\\", "/").rstrip("/").lower()

    def _resolve_workspace(self, code_path: str, explicit_workspace_id: Optional[int]) -> Dict[str, Any]:
        norm_in = self._norm_path(code_path)
        if explicit_workspace_id is not None:
            row = self.db.execute("SELECT id, target_path FROM workspaces WHERE id = ?", (explicit_workspace_id,), fetchone=True)
            if not row:
                raise ValueError(f"workspace_id={explicit_workspace_id} 不存在")
            if norm_in and row["target_path"] and self._norm_path(row["target_path"]) != norm_in:
                # 静默搬家会破坏资产绑定历史，拒绝
                raise ValueError(
                    f"code_path 与该 workspace_id 已绑定到其他路径，拒绝跨 workspace 重绑"
                    f"（workspace {explicit_workspace_id}={row['target_path']!r} vs 入参 {code_path!r}）"
                )
            return {"id": row["id"], "new": False}
        if norm_in:
            # 注意 fetchall=True 是**必填**：项目的 Database.execute 把 fetchone/fetchall
            # 做成了 keyword-only 参数，不传时返回 None，.fetchall 会 AttributeError。
            for r in self.db.execute("SELECT id, target_path FROM workspaces", fetchall=True):
                if self._norm_path(r["target_path"]) == norm_in:
                    return {"id": r["id"], "new": False}
        # 自动建 workspace（名默认取 code_path 末段）
        name = (code_path or "iast-ws").rstrip("/").rstrip("\\").split("/")[-1].split("\\")[-1] or "iast-ws"
        self.db.execute(
            "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) VALUES (?, ?, '', '{}', ?, ?)",
            (name, code_path or "", _now(), _now()),
        )
        wid = int(self.db.execute("SELECT id FROM workspaces ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
        return {"id": wid, "new": True}

    # ---------- 会话注册 ----------
    def register_session(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target_url = payload.get("target_url", "")
        code_path = payload.get("code_path", "")
        app_name = payload.get("app_name", "")
        agent_id = payload.get("agent_id", "")
        if not (target_url and app_name and agent_id):
            raise ValueError("target_url / app_name / agent_id 必填")
        #  版本钉死：探针在注册（即启动）时上报自身 jar 版本，平台侧钉死 SAST 分析代码版本，
        # 注册即校验对齐，结果写入 version_status（mismatch 将被 A0 门禁硬阻断发流量）。
        probe_version = (payload.get("probe_version", "") or "").strip()
        contract = validate_version_contract(probe_version)
        version_status = contract.status
        sast_code_version = contract.sast_code_version
        ws = self._resolve_workspace(code_path, payload.get("workspace_id"))
        workspace_id = ws["id"]
        settings = dict(payload.get("settings", {}) or {})
        probe_packages = (payload.get("probe_packages", "") or "").strip()
        if probe_packages:
            settings["probe_packages"] = probe_packages
        # 方案 4：挂载命令所用 JDK 路径，按被扫描项目变化；存于 settings 透传给前端生成挂载命令。
        java_path = (payload.get("java_path", "") or "").strip()
        if java_path:
            settings["java_path"] = java_path
        settings_json = Database.dumps(settings)
        server_port = int(payload.get("server_port") or 8899)
        probe_token = secrets.token_urlsafe(24)
        now = _now()
        existing = self.db.execute(
            "SELECT id, probe_token FROM iast_sessions WHERE workspace_id = ? AND app_name = ? AND agent_id = ?",
            (workspace_id, app_name, agent_id), fetchone=True,
        )
        if existing:
            # 同 code_path + appName 再注册 = 新部署，原地更新（保留原 token 不失效）
            self.db.execute(
                """UPDATE iast_sessions
                   SET target_url = ?, code_path = ?, settings_json = ?, status = 'unknown',
                       probe_version = ?, sast_code_version = ?, version_status = ?, server_port = ?, updated_at = ?
                   WHERE id = ?""",
                (target_url, code_path, settings_json, probe_version, sast_code_version, version_status, server_port, now, existing["id"]),
            )
            token = existing["probe_token"]
            sid = int(existing["id"])
        else:
            self.db.execute(
                """INSERT INTO iast_sessions
                   (workspace_id, app_name, agent_id, target_url, code_path, probe_mode, status, last_heartbeat_at, registered_at, updated_at, settings_json, probe_token, probe_version, sast_code_version, version_status, server_port)
                   VALUES (?, ?, ?, ?, ?, ?, 'unknown', '', ?, ?, ?, ?, ?, ?, ?, ?)""",
                (workspace_id, app_name, agent_id, target_url, code_path, payload.get("probe_mode", "iast"), now, now, settings_json, probe_token, probe_version, sast_code_version, version_status, server_port),
            )
            sid = int(self.db.execute("SELECT id FROM iast_sessions ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
            token = probe_token
        row = self.db.execute("SELECT * FROM iast_sessions WHERE id = ?", (sid,), fetchone=True)
        return self._session_to_dict(row, token)

    def _session_to_dict(self, row, token: str) -> Dict[str, Any]:
        settings = Database.loads(row["settings_json"]) if "settings_json" in row.keys() else {}
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "app_name": row["app_name"],
            "agent_id": row["agent_id"],
            "target_url": row["target_url"],
            "code_path": row["code_path"],
            "probe_mode": row["probe_mode"],
            "probe_packages": settings.get("probe_packages", "") if isinstance(settings, dict) else "",
            "server_port": int(row["server_port"]) if "server_port" in row.keys() and row["server_port"] else 8899,
            "status": row["status"],
            "agent_phase": (row["agent_phase"] if "agent_phase" in row.keys() and row["agent_phase"] else "unknown"),
            "java_path": (settings.get("java_path", "") if isinstance(settings, dict) else ""),
            "probe_version": row["probe_version"],
            "sast_code_version": row["sast_code_version"],
            "version_status": row["version_status"],
            "last_heartbeat_at": (row["last_heartbeat_at"] if "last_heartbeat_at" in row.keys() else "") or "",
            "probe_token": token,
            "registered_at": row["registered_at"],
        }

    def update_heartbeat(self, session_id: int, token: str, agent_phase: Optional[str] = None) -> Dict[str, Any]:
        """/ 探针心跳上报：写 last_heartbeat_at，供 A0 心跳新鲜判断直接判在线。

        方案 3：agent_phase 非空时一并写入（WARMING_UP 预热中 / READY 已就绪）。
        """
        row = self.db.execute("SELECT * FROM iast_sessions WHERE id = ?", (session_id,), fetchone=True)
        if not row:
            raise ValueError(f"iast_session {session_id} 不存在")
        if token and row["probe_token"] != token:
            raise ValueError("probe_token 不匹配")
        now = _now()
        # 心跳到达即代表探针在线，同步把 status 翻为 ready，避免前端在两次 A0 检查之间一直显示 unready。
        if agent_phase:
            self.db.execute(
                "UPDATE iast_sessions SET last_heartbeat_at = ?, updated_at = ?, agent_phase = ?, status = ? WHERE id = ?",
                (now, now, agent_phase, "ready", session_id),
            )
        else:
            self.db.execute(
                "UPDATE iast_sessions SET last_heartbeat_at = ?, updated_at = ?, status = ? WHERE id = ?",
                (now, now, "ready", session_id),
            )
        updated = self.db.execute("SELECT * FROM iast_sessions WHERE id = ?", (session_id,), fetchone=True)
        return self._session_to_dict(updated, row["probe_token"])

    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM iast_sessions WHERE id = ?", (session_id,), fetchone=True)
        return dict(row) if row else None

    def list_sessions(self, workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        if workspace_id is not None:
            rows = self.db.execute("SELECT * FROM iast_sessions WHERE workspace_id = ? ORDER BY id DESC", (workspace_id,), fetchall=True)
        else:
            rows = self.db.execute("SELECT * FROM iast_sessions ORDER BY id DESC", fetchall=True)
        return [dict(r) for r in rows]

    def authenticate(self, app_name: str, agent_id: str, token: str) -> Optional[Dict[str, Any]]:
        row = self.db.execute(
            "SELECT * FROM iast_sessions WHERE app_name = ? AND agent_id = ? AND probe_token = ?",
            (app_name, agent_id, token), fetchone=True,
        )
        return dict(row) if row else None

    def authenticate_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """探针兼容桥鉴权：仅凭 probe_token 反查会话（探针心跳/事件只带 X-Agent-Token，无 session id）。"""
        if not token:
            return None
        row = self.db.execute(
            "SELECT * FROM iast_sessions WHERE probe_token = ?",
            (token,), fetchone=True,
        )
        return dict(row) if row else None

    def update_heartbeat_by_token(self, token: str, agent_phase: Optional[str] = None) -> Dict[str, Any]:
        session = self.authenticate_by_token(token)
        if not session:
            raise ValueError("probe_token 不匹配")
        return self.update_heartbeat(session["id"], token, agent_phase)

    # ---------- TriggerSpec 登记（A2 产出，供匹配） ----------

    # 代码根目录缓存：task_id -> root。生产调用点不传 code_root，只能从任务的
    # options_json 反推；每个任务只查一次库。
    _CODE_ROOT_CACHE: Dict[Any, str] = {}

    def _task_code_root(self, task_id: Any) -> str:
        """解析任务的代码根目录（带缓存）。

        背景见 src/core/safe_verdict.root_from_shard_file 的注释：scan_tasks
        里既没有 target 也没有 code_root，只有 shard_file 可反推。解析不出就返回
        空串，调用方 fail-open（不抑制），绝不因解析失败挡住登记。
        """
        if task_id is None:
            return ""
        key = str(task_id)
        cached = self._CODE_ROOT_CACHE.get(key)
        if cached is not None:
            return cached
        root = ""
        try:
            from src.core.safe_verdict import root_from_options_json as _root_of

            # Database.execute 的 fetch 参数是 **keyword-only**：写成
            # execute(sql, p).fetchone 会拿到 None 再 AttributeError。
            # 这个坑在 src/core/dast_config_check.py:38 的注释里记过一次，
            # 这里又踩了一次——代价是 root 恒为空、抑制静默归零，而日志只有一句
            # 被 fail-open 吞掉的 warning。
            row = self.db.execute(
                "SELECT options_json FROM scan_tasks WHERE id = ?", (task_id,),
                fetchone=True,
            )
            if row is not None:
                opts = row["options_json"] if isinstance(row, dict) else row[0]
                root = _root_of(str(opts or "")) or ""
        except Exception as _exc:
            logger.warning("[trigger_spec] 代码根目录解析失败（按无根目录处理，不抑制）：%s", _exc)
            root = ""
        if len(self._CODE_ROOT_CACHE) > 512:
            self._CODE_ROOT_CACHE.clear()
        self._CODE_ROOT_CACHE[key] = root
        return root

    def register_trigger_spec(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        now = _now()
        # victim_identifiers：已知受害者标识（username/email/user_id 等），用于 D1 双账号差分重放时
        # 判定「攻击者取回了受害者的数据」。登记阶段优先取 A2 prerequisites.victim_identifiers，
        # 缺则取账户发现产物里的 victim 账户已知属性（见 trigger_spec_registry）。存为 JSON 字符串。
        # 故统一经 src/core/identity_marker 强度判定过滤，杜绝假确认。
        _vi = payload.get("victim_identifiers")
        if isinstance(_vi, (list, tuple)):
            vi_json = Database.dumps(filter_identity_markers(_vi))
        elif isinstance(_vi, str) and _vi.strip():
            vi_json = _vi
        else:
            vi_json = "[]"
        # P0-2 收敛（单真相源）：category 与 business_logic_category 必须一致。
        # 两条注册路径在此汇合——① auto_register_from_a2 已两列同值传入；② 前端经 REST
        # POST /api/iast/trigger-specs 注册时只填 business_logic_category（或两列填成不同业务族，
        # 如 cat='bola' bl='calculation_logic'），导致历史 9~18 条分歧 spec。此处统一收敛：
        # business_logic_category 归一为规范业务族后作为权威，两列都取该值；技术族（非业务族）
        # 归一为空时回退以 category 对齐，保证两列恒相等、杜绝列分歧。
        _bl = str(payload.get("business_logic_category") or "").strip()
        _cat = str(payload.get("category") or "").strip()
        if _bl or _cat:
            try:
                from src.iast.trigger_spec_registry import _normalize_business_logic_category as _norm_bl
            except Exception:
                _norm_bl = None
            _nbl = _norm_bl(_bl) if _norm_bl else _bl
            if _nbl:
                _cat = _nbl
                _bl = _nbl
            elif _cat:
                _bl = _cat
            elif _bl:
                _cat = _bl
            payload["category"] = _cat
            payload["business_logic_category"] = _bl
        # 沿路径/候选文件抓守卫（跨文件、按行为判定，不看名字）→ 抽 FilterSpec → 回填 raw，
        # 落库即成 trigger_specs.raw_json.filter_spec，供 D1 净化感知造弹与升变体消费。
        # fail-open：挖掘失败不影响登记。开关 SAST_AI_SANITIZER_MINER=0 可关闭。
        try:
            from src.core.sanitizer_miner import attach_filter_spec as _attach_fs
            _fs_meta = _attach_fs(payload, code_root=payload.get("code_root"), db=self.db)
            if _fs_meta and _fs_meta.get("filter_spec"):
                logger.info(
                    "[trigger_spec] 净化器约束已回填：family=%s endpoint=%s guards=%s kind=%s",
                    payload.get("family", ""), payload.get("target_endpoint", ""),
                    _fs_meta.get("guards"), _fs_meta.get("filter_spec"))
        except Exception as _fs_exc:
            logger.warning("[trigger_spec] 净化器挖掘失败（不影响登记）：%s", _fs_exc)

        #
        # 为什么放在这里：这是 spec 落库的**唯一咽喉点**（A2 自动登记与前端 REST
        # 两条注册路径在此汇合）。原先 safe_patterns 的抑制只接在 A1 出口
        # （src/pipeline/a1/service.py:303），而 A2 独立判定后直接走到这里落库，
        # 完全绕过了抑制 —— 规则表在、接线在，唯独作用域不覆盖 A2。
        # 且上一轮承诺的「getter 白名单 +5.9pt」落空成 +0.0pt。
        #
        # 用例级否决（方案 2）：本条被判安全时，还要看**同一 endpoint 同族**的
        # 其他 spec 是否也都安全；只要有一条不安全，就保留本条（保守，宁可多报不漏报）。
        # （一条 source=a2、一条 source=unknown 且 a21 候选分 0）正是这个场景。
        _suppressed = 0
        _suppress_rule = ""
        _conf_boost = 0.0
        _pos_rule = ""
        _cap_family = ""
        try:
            from src.core.safe_verdict import judge_spec as _judge_spec

            # 不解析的后果是 expected_sink_file（相对路径）拼不出绝对路径 → 类级窗口为空
            # 根目录算出来的，不是生产路径算出来的，两者不能混为一谈。
            _code_root = str(payload.get("code_root") or "").strip()
            if not _code_root and payload.get("task_id") is not None:
                _code_root = self._task_code_root(payload.get("task_id"))
            if _code_root:
                _CODE_ROOT_STATS[payload.get("task_id")] = _code_root
            _v = _judge_spec(
                family=str(payload.get("family") or ""),
                sink_file=str(payload.get("expected_sink_file") or ""),
                sink_line=(payload.get("expected_sink_line") or None),
                snippet=str((payload.get("raw") or {}).get("code_snippet") or ""),
                code_root=_code_root,
            )
            if _v.get("suppressed"):
                _suppressed = 1
                _suppress_rule = str(_v.get("rule") or "")
                # 同一个 keyword-only 坑（见上面 _task_code_root 的注释）：
                # 这里原来是 .fetchall，抛 AttributeError 后被外层 except 吞掉，
                # 于是 _suppressed 保持 1 —— 用例级否决（方案 2）**从未真正生效过**。
                # 修好之后否决才真的会起作用，抑制数会下降，这是预期内的。
                _peer = self.db.execute(
                    "SELECT suppressed_by_safe_verdict FROM trigger_specs "
                    "WHERE task_id IS ? AND family = ? AND target_endpoint = ?",
                    (payload.get("task_id"), canonical_family(payload.get("family", "")),
                     payload.get("target_endpoint", "")),
                    fetchall=True,
                ) or []
                if any(not int((r["suppressed_by_safe_verdict"] or 0)) for r in _peer):
                    # 同族同端点存在未被抑制的 spec → 用例级否决不成立，保留本条
                    _suppressed = 0
                    _suppress_rule = ""
            _conf_boost = float(_v.get("confidence_boost") or 0.0)
            _pos_rule = str(_v.get("positive_rule") or "")
            _cap_family = str(_v.get("capability_family") or "")
        except Exception as _sv_exc:
            # fail-open：裁决异常一律不抑制、不加分，绝不因裁决器故障挡住登记
            logger.warning("[trigger_spec] 安全裁决异常（不影响登记，放行）：%s", _sv_exc)
        if _suppressed:
            logger.info(
                "[trigger_spec] 安全实现抑制：family=%s endpoint=%s rule=%s",
                payload.get("family", ""), payload.get("target_endpoint", ""), _suppress_rule)
        # 为什么改：闭环二次回灌原先 DELETE 整表再 INSERT，spec id 全变 ⇒ replay_attempts.spec_id
        # 49% 变孤儿，verification_status 也被清空 ⇒ 必须整轮重放。
        # 现在的语义：
        #   * 已存在 → UPDATE 只改「触发相关 + 元数据」字段，**保留 id / verification_status /
        #     iast_state / business_logic_confirmed**（上轮结论不丢、attempt 归因不断）；
        #   * 触发字段（endpoint/param/location/method/payloads）真变了 → 只把这一条的状态置空；
        #   * 不存在 → INSERT。
        _values = {
            "workspace_id": payload.get("workspace_id"),
            "session_id": payload.get("session_id"),
            "task_id": payload.get("task_id"),
            "finding_id": payload.get("finding_id"),
            "vulnerability_hash_v2": payload.get("vulnerability_hash_v2", ""),
            "family": canonical_family(payload.get("family", "")),
            "target_endpoint": payload.get("target_endpoint", ""),
            "http_method": payload.get("http_method", "GET"),
            "param_name": payload.get("param_name", ""),
            "param_name_source": payload.get("param_name_source", "unknown"),
            "param_location": payload.get("param_location", "query"),
            "content_type": payload.get("content_type", ""),
            "principal": payload.get("principal", ""),
            "taint_marker": payload.get("taint_marker", ""),
            "expected_sink_file": payload.get("expected_sink_file", ""),
            "expected_sink_line": payload.get("expected_sink_line", 0),
            "representative_request_params_json": Database.dumps(payload.get("representative_request_params", [])),
            "raw_json": Database.dumps(payload.get("raw", {})),
            "poc_chain_json": Database.dumps(payload.get("poc_chain", [])),
            "category": payload.get("category", ""),
            "business_logic_category": payload.get("business_logic_category", ""),
            "attack_payloads_json": Database.dumps(payload.get("attack_payloads", [])),
            "accounts_json": Database.dumps(payload.get("accounts", [])),
            "victim_resource_id": payload.get("victim_resource_id", ""),
            "victim_identifiers": vi_json,
            "auth_binding_json": Database.dumps(payload.get("auth_binding", {})),
            "replayable": payload.get("replayable", 1),
            "business_logic_confirmed": payload.get("business_logic_confirmed", 0),
            "verification_status": payload.get("verification_status", ""),
            "iast_state": payload.get("iast_state", ""),
            "created_at": now,
            "suppressed_by_safe_verdict": _suppressed,
            "suppress_rule": _suppress_rule,
            "confidence_boost": _conf_boost,
            "positive_evidence_rule": _pos_rule,
            "capability_family": _cap_family,
            "filter_spec_json": Database.dumps(payload.get("filter_spec") or {}),
            "bypass_state": str(payload.get("bypass_state") or ""),
            "bypass_reason": str(payload.get("bypass_reason") or "")[:500],
        }
        _tid = payload.get("task_id")
        _vhash = payload.get("vulnerability_hash_v2", "")
        _existing = None
        try:
            _existing = self.db.execute(
                "SELECT id, target_endpoint, param_name, param_location, http_method, "
                "attack_payloads_json, taint_marker FROM trigger_specs "
                "WHERE task_id IS ? AND vulnerability_hash_v2 = ?", (_tid, _vhash), fetchone=True)
        except Exception:
            _existing = None
        if _existing:
            _ex = dict(_existing)
            _trig = any(
                str(_values.get(k) or "") != str(_ex.get(k) or "")
                for k in ("target_endpoint", "param_name", "param_location",
                          "http_method", "attack_payloads_json")
            )
            _skip = {"task_id", "vulnerability_hash_v2", "created_at", "finding_id",
                     "workspace_id", "business_logic_confirmed",
                     "verification_status", "iast_state"}
            _cols = [c for c in _values if c not in _skip]
            if not _trig:
                # 触发条件没变：连 taint_marker 都不动，保证历史 IAST 事件仍能按 marker 归因
                _cols = [c for c in _cols if c != "taint_marker"]
            _sql = "UPDATE trigger_specs SET " + ", ".join("%s=?" % c for c in _cols) + " WHERE id=?"
            self.db.execute(_sql, tuple(_values[c] for c in _cols) + (_ex["id"],))
            if _trig:
                # 只重置这一条：触发条件变了，旧确认态对新请求不再成立
                self.db.execute(
                    "UPDATE trigger_specs SET verification_status='', iast_state='' WHERE id=?",
                    (_ex["id"],))
                logger.info("[trigger_spec] upsert 触发条件变更，重置确认态：spec=%s", _ex["id"])
            sid = int(_ex["id"])
        else:
            _cols = list(_values)
            self.db.execute(
                "INSERT INTO trigger_specs (%s) VALUES (%s)" % (
                    ",".join(_cols), ",".join("?" * len(_cols))),
                tuple(_values[c] for c in _cols),
            )
            _row = self.db.execute(
                "SELECT id FROM trigger_specs WHERE task_id IS ? AND vulnerability_hash_v2=?"
                " ORDER BY id DESC LIMIT 1",
                (_tid, _vhash), fetchone=True)
            sid = int((_row or {"id": 0})["id"])
        row = self.db.execute("SELECT * FROM trigger_specs WHERE id = ?", (sid,), fetchone=True)
        return dict(row)

    def update_trigger_spec_victim_identifiers(self, spec_id: int, identifiers: Any,
                                               victim_resource_id: Optional[str] = None) -> None:
        """D1 运行时 bootstrap 出 victim 账户的已知属性后，把 username/email/user_id 回填进
        victim_identifiers，使差分重放的「泄露判定」可生效，并供报告/回归消费。best-effort。

        而非残留 VICTIM_FROM_POOL 字面量），使 data_leak 腿拿到真实 victim 资源 id。
        """
        try:
            if isinstance(identifiers, (list, tuple)):
                vi_json = Database.dumps(list(identifiers))
            elif isinstance(identifiers, str) and identifiers.strip():
                vi_json = identifiers
            else:
                vi_json = None
            if vi_json is None and not victim_resource_id:
                return
            cols: List[str] = []
            params: List[Any] = []
            if vi_json is not None:
                cols.append("victim_identifiers = ?")
                params.append(vi_json)
            if victim_resource_id:
                cols.append("victim_resource_id = ?")
                params.append(str(victim_resource_id))
            params.append(int(spec_id))
            self.db.execute(
                "UPDATE trigger_specs SET %s WHERE id = ?" % ", ".join(cols),
                params,
            )
        except Exception as _e:  # fail-open：回填失败不影响主流程
            logger.warning("[IastService] 回填 victim 标识失败（忽略）：%s", _e)

    def list_trigger_specs(
        self,
        workspace_id: Optional[int] = None,
        task_id: Optional[int] = None,
        session_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """读回已登记的 TriggerSpec（A2 的 poc 假说），供攻击计划阶段投影 / D1 重放消费。"""
        clauses: List[str] = []
        params: List[Any] = []
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        # 必须排除被 safe_verdict 判为安全实现的 spec，否则用户看到的仍是未过滤的 FP。
        clauses.append("COALESCE(suppressed_by_safe_verdict, 0) = 0")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.execute(
            "SELECT * FROM trigger_specs" + where + " ORDER BY id ASC", params, fetchall=True
        )
        return [dict(r) for r in rows]

    def query_events_by_canary(self, task_id: Optional[int], identity: str) -> List[Dict[str, Any]]:
        """按 canary 身份段（s4st41<16hex>）反查本 task 的 IAST 事件，供攻击计划回填运行时命中态。"""
        if not identity:
            return []
        rows = self.db.execute(
            "SELECT id, event_type, canary, canary_state, canary_match, sink_file, sink_line, vuln_type, severity "
            "FROM iast_events WHERE task_id = ? AND canary LIKE ?",
            (task_id, f"%{identity}%"), fetchall=True,
        )
        return [dict(r) for r in rows]

    # ---------- 事件摄取（3.15） + item 4 吞吐优化（批处理写库 / 合流 / 去重批量化 / 背压 / 指标） ----------
    def ingest_events(self, app_name: str, agent_id: str, token: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """ 探针批量事件摄取。

        item 4 吞吐优化：把「解析」与「落库」解耦，同一批事件合流为一次去重查询 + 一次
        executemany 单事务，事务数从「每条 1 个」降到「每批 1 个」（方向 1 / 3 / 4）。

        对外契约不变：同步返回，落库完成后才返回；重复事件静默丢弃但仍计入 accepted；
        仅在整行都写不进去（session/workspace 级外键）时才计 rejected。
        """
        session = self.authenticate(app_name, agent_id, token)
        if not session:
            INGEST_METRICS.record_received(len(events))
            INGEST_METRICS.record_rejected(len(events))
            return {"accepted": 0, "rejected": len(events), "session_id": None,
                    "errors": [f"鉴权失败：app_name={app_name} agent_id={agent_id} 的 token 不匹配"]}
        session_id = session["id"]
        workspace_id = session["workspace_id"]
        INGEST_METRICS.record_received(len(events))

        # 计时必须覆盖「解析 + 落库」全过程：解析阶段（任务归属查询）实测占端到端 98.7%，
        # 只计刷盘会得到虚高的排空速率。
        # time.time 在 Windows 上粒度约 15.6ms，小批次（数十条以内）会被整段测成 0.0ms，
        # 只是换了个触发路径（连接复用后小批次的真实耗时首次落到了时钟粒度以下）。
        # perf_counter 是高分辨率单调时钟，不受系统时间回拨影响。
        _t0 = time.perf_counter()

        # 1) 解析（含 canary 三态、任务归属解析），在刷盘锁外执行
        prepared: List[Dict[str, Any]] = []
        rejected = 0
        errors: List[str] = []
        for ev in events:
            try:
                rec = self._prepare_event(session_id, workspace_id, app_name, agent_id, ev)
            except Exception as _e:  # noqa: BLE001 - 单事件解析失败不得拖垮整批
                rejected += 1
                errors.append(f"事件解析失败：{_e}")
                continue
            if rec is None:
                rejected += 1
                continue
            prepared.append(rec)

        # 2) 落库：SQLite 单写者约束下串行刷盘。方向 2 的「背压」由此实现——
        #    积压时处理线程在此阻塞（探针侧 POST 随之变慢），而非丢弃事件：宁可变慢不丢。
        with _INGEST_FLUSH_LOCK:
            written, failed = self._flush_events_batch(session_id, workspace_id, prepared)
        INGEST_METRICS.record_flush(len(prepared), written, (time.perf_counter() - _t0) * 1000.0)

        accepted = len(prepared) - failed
        rejected += failed
        if failed:
            errors.append(f"{failed} 条事件因 session/workspace 级外键约束写入失败")
        INGEST_METRICS.record_accepted(accepted)
        INGEST_METRICS.record_rejected(rejected)
        return {"accepted": accepted, "rejected": rejected, "session_id": session_id, "errors": errors}

    def _prepare_event(self, session_id: int, workspace_id: int, app_name: str, agent_id: str,
                       ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """把探针事件解析为待落库记录：字段归一 + canary 三态 + 任务归属 + FK 预降级。

        不含任何写库动作——把「解析」与「落库」解耦（方向 3），使整批事件能合流为一次批量写。
        """
        event_type = ev.get("eventType", "sink_call")
        vuln_type = ev.get("vulnType", "")
        trace_id = ev.get("traceId", "")
        canary = ev.get("canary", "")
        sink = ev.get("sink", {}) or {}
        sink_file = str(sink.get("file", ""))
        sink_line = int(sink.get("line", 0) or 0)
        sink_method = str(sink.get("method", ""))
        source = ev.get("source", {}) or {}
        principal = ev.get("principal", "")
        severity = ev.get("severity", "INFO")
        stack_trace = ev.get("stackTrace", "")
        evidence = ev.get("evidence", {}) or {}
        if not isinstance(evidence, dict):
            evidence = {}
        # v2 证据分层：把 agent_bridge 透传的 L3 语义字段并入 evidence（JSON 落库），
        # 保证 compute_value_hit / d2_facade 从 DB 回读事件时仍能读到消毒器/异常/插桩台账。
        # 同时兜底从 ev["context"] 直接取（探针直连旧端点时 context 未被展平的情况）。
        for _k in ("sink_sanitizer", "sink_outcome", "sink_exception_class", "sink_exception_msg", "hook_inventory"):
            _v = ev.get(_k)
            if _v in (None, ""):
                _ctx = ev.get("context")
                if isinstance(_ctx, dict):
                    _v = _ctx.get(_k)
            if _v not in (None, ""):
                evidence[_k] = _v
        taint_path = ev.get("taintPath", "") or ""
        ingested_at = _now()
        # 幂等去重时间窗（3.15）。ingest_bucket 为整数（time_bucket），避免 SQLite 解析 ISO 时间失败。
        ingest_bucket = int(time.time()) // 10

        # canary 三态匹配
        canary_match = 0
        canary_state = ""
        # 优先信任探针断言：canary 走 X-SASTAI-Trace 头（方案B 双通道），不进 payload，后端
        # CanaryMatcher 子串匹配会因缺 metacharacter 而失准，故以探针断言为准；探针未断言时退回旧逻辑。
        incoming_canary_state = (ev.get("canaryState") or ev.get("canary_state") or "")
        #  探针侧「本请求已观测到 canary」轻量事件：消解 no-arrival 歧义
        # （探针确认 canary 抵达了请求边界但未达 sink = "arrived"，区别于 sink_call 的 sink-reached/arrival-sanitized）。
        if event_type == "canary_observed" and canary:
            canary_state = CanaryStates.ARRIVED
            canary_match = 1
        elif canary:
            if incoming_canary_state:
                canary_state = incoming_canary_state
                canary_match = 0 if incoming_canary_state == CanaryStates.NO_ARRIVAL else 1
            else:
                sample = " ".join(str(x) for x in (evidence, source.get("value", ""), stack_trace) if x)
                state = CanaryMatcher(canary).match(sample)
                canary_state = state
                if state != CanaryStates.NO_ARRIVAL:
                    canary_match = 1

        #  事件归属：探针上报只有 workspace/app/agent，没有 task_id；按 canary 身份段
        # 反查 trigger_specs取得 task_id，使 I1/I2 能按 task 聚合。
        # 若查不到（如人工流量/旧数据），task_id 保持 NULL，仍可按 workspace 级回退查询。
        event_task_id = self._resolve_event_task_id(workspace_id, canary, trace_id, event_time=ingested_at)
        # INSERT 失败（HTTP 500），导致探针证据被静默丢弃、D1→IAST→D2 闭环断裂、D2 永远确认不出。
        # task_id 按设计本就可空/best-effort，
        # 因此解析到无效/过期 task_id 时直接降级为 NULL，绝不因归属解析失误而丢证据。
        if event_task_id is not None:
            _trow = self.db.execute(
                "SELECT 1 FROM scan_tasks WHERE id = ? LIMIT 1", (event_task_id,), fetchone=True
            )
            if not _trow:
                logger.warning(
                    "[IAST] 事件解析到的 task_id=%s 在 scan_tasks 中不存在，降级为 NULL（避免 FK 失败丢证据）",
                    event_task_id,
                )
                event_task_id = None

        return {
            "event_type": event_type, "vuln_type": vuln_type, "trace_id": trace_id, "canary": canary,
            "canary_match": canary_match, "canary_state": canary_state,
            "sink_file": sink_file, "sink_line": sink_line, "sink_method": sink_method,
            "source_name": str(source.get("name", "")), "source_type": str(source.get("type", "")),
            "source_value": str(source.get("value", "")),
            "principal": principal, "severity": severity, "stack_trace": stack_trace,
            "evidence": evidence, "taint_path": taint_path,
            "ingested_at": ingested_at, "ingest_bucket": ingest_bucket,
            "event_task_id": event_task_id,
            "sink_reached_val": 1 if is_sink_reached(canary_state) else 0,
            "app_name": app_name, "agent_id": agent_id,
        }

    @staticmethod
    def _event_insert_params(session_id: int, workspace_id: int, rec: Dict[str, Any],
                             null_task: bool = False) -> Tuple[Any, ...]:
        """构造 iast_events 单行 INSERT 参数。null_task=True 用于外键失败后的降级重试。"""
        task_id = None if null_task else rec["event_task_id"]
        return (
            session_id, workspace_id, task_id, rec["app_name"], rec["agent_id"], rec["event_type"],
            rec["vuln_type"], rec["trace_id"], rec["canary"], rec["canary_match"], rec["canary_state"],
            rec["sink_reached_val"], rec["sink_file"], rec["sink_line"], rec["sink_method"],
            rec["source_name"], rec["source_type"], rec["source_value"],
            rec["principal"], rec["severity"], rec["stack_trace"],
            (rec["taint_path"] if rec["taint_path"] else "{}"),
            Database.dumps(rec["evidence"]), rec["ingested_at"], rec["ingest_bucket"],
        )

    def _flush_events_batch(self, session_id: int, workspace_id: int,
                            prepared: List[Dict[str, Any]]) -> Tuple[int, int]:
        """把已解析记录攒批落库。返回 (written, failed)。

        方向 1：全部非重复行一次 executemany，单事务提交（fsync / 锁开销从「每事件」降为「每批」）。
        方向 4：去重从逐条 SELECT 改为「一次 SELECT 拉回本时间窗已存在键」，批内再用 set 折叠。
        调用方须持有 _INGEST_FLUSH_LOCK（SQLite 单写者，避免并发写库）。
        """
        if not prepared:
            return 0, 0
        INGEST_METRICS.record_pending(len(prepared))
        # 同一次调用共享去重时间窗（原语义：10s 窗内同键幂等）
        bucket = prepared[0]["ingest_bucket"]
        existing_rows = self.db.execute(
            "SELECT event_type, sink_file, sink_line, canary FROM iast_events "
            "WHERE session_id = ? AND ingest_bucket = ?",
            (session_id, bucket), fetchall=True,
        ) or []
        existing_keys = {
            (str(r["event_type"]), str(r["sink_file"] or ""), int(r["sink_line"] or 0), r["canary"])
            for r in existing_rows
        }
        to_insert: List[Dict[str, Any]] = []
        seen_in_batch = set()
        dup_count = 0
        exempt_count = 0
        for rec in prepared:
            # 去重键 (event_type, sink_file, sink_line, canary) 在 canary 为空时退化为常量。
            # 对「多个 servlet 共用同一 sink 名、sink_line 恒 0」的族（如 trustbound 的
            # HttpSession.setAttribute），漏洞 sink 事件会与框架样板写入同键，同一 10s 桶内
            # 命中并上报（payload 含 canary），库内该 canary 却零事件；后端 received=26651 而
            # written=4193，84% 被去重丢弃。
            # 故：payload（source_value）里含平台 canary 身份段的事件 = 最高价值的值级证据，
            # 一律不参与去重；其余（框架噪声）仍按原键折叠，维持 D2 洪峰期控量。
            if _is_value_evidence(rec):
                to_insert.append(rec)
                exempt_count += 1
                continue
            key = (rec["event_type"], rec["sink_file"], rec["sink_line"], rec["canary"])
            if key in existing_keys or key in seen_in_batch:
                dup_count += 1  # 重复事件静默丢弃（仍计入 accepted，与原语义一致）
                continue
            seen_in_batch.add(key)
            to_insert.append(rec)
        INGEST_METRICS.record_dup_skipped(dup_count)
        if exempt_count:
            logger.info("[IAST] 值级证据免去重 %d 条（本批 %d 条，去重跳过 %d 条）",
                        exempt_count, len(prepared), dup_count)
        if not to_insert:
            INGEST_METRICS.record_pending(0)
            return 0, 0

        params = [self._event_insert_params(session_id, workspace_id, rec) for rec in to_insert]
        written_recs: List[Dict[str, Any]] = []
        failed = 0
        try:
            self.db.executemany(_IAST_EVENT_INSERT_SQL, params)
            written_recs = to_insert
        except sqlite3.IntegrityError as _fk_err:
            # 安全网：批量写遇外键约束时逐行降级 task_id=NULL 重试，保留「绝不因 FK 丢证据」兜底。
            logger.warning("[IAST] 批量写 iast_events 触发外键约束，逐行降级 task_id=NULL 重试：%s", _fk_err)
            for rec in to_insert:
                try:
                    self.db.execute(
                        _IAST_EVENT_INSERT_SQL,
                        self._event_insert_params(session_id, workspace_id, rec, null_task=True),
                    )
                    written_recs.append(rec)
                except sqlite3.IntegrityError as _fk_err2:
                    logger.error(
                        "[IAST] iast_events 降级 task_id=NULL 后仍外键约束（session/workspace 级），丢弃事件：%s",
                        _fk_err2,
                    )
                    failed += 1
        INGEST_METRICS.record_written(len(written_recs))
        if written_recs:
            self._apply_side_effects(session_id, workspace_id, written_recs)
        INGEST_METRICS.record_pending(0)
        return len(written_recs), failed

    def _apply_side_effects(self, session_id: int, workspace_id: int, recs: List[Dict[str, Any]]) -> None:
        """/ 实例合并 +  回填触发（均为 best-effort，不阻断摄取）。

        与原实现语义一致，仅把「逐事件的实例表查询 / 写」改为批量：一次 SELECT 拉回已存在的
        vhash，再批量 UPDATE / INSERT；回填触发改为一次 SELECT 取回本批各 canary 的最新事件 id。
        """
        sink_recs = [
            r for r in recs
            if r["canary"] and r["canary_state"] in (CanaryStates.SINK_REACHED, CanaryStates.SINK_REACHED_PROBE)
        ]
        if sink_recs:
            # 收口：事件侧 canary 只有 22 字符身份段，spec 侧 taint_marker 是「身份段+元字符段」，
            # 历史实现 `taint_marker = canary` 全等比较恒 0 命中 → IAST 确认态从未回写实例表。
            # 改用身份段前缀匹配（与 orchestrator / correlation / blackboard 同一口径）。
            vmap: Dict[str, Tuple[str, str]] = {}  # vhash -> (family, severity)
            for rec in sink_recs:
                _ident = CanaryMatcher.find_identity(rec["canary"]) or rec["canary"]
                spec_row = self.db.execute(
                    "SELECT vulnerability_hash_v2, family FROM trigger_specs "
                    "WHERE taint_marker = ? OR taint_marker LIKE ? LIMIT 1",
                    (rec["canary"], f"{_ident}%"), fetchone=True,
                )
                if spec_row and spec_row.get("vulnerability_hash_v2"):
                    vhash = spec_row["vulnerability_hash_v2"]
                    family = spec_row["family"] or rec["vuln_type"] or "unknown"
                    vmap.setdefault(vhash, (family, rec["severity"] or "MEDIUM"))
            if vmap:
                vhashes = list(vmap.keys())
                _ph = ",".join("?" * len(vhashes))
                existing_rows = self.db.execute(
                    f"SELECT id, vulnerability_hash_v2 FROM vulnerability_instances "
                    f"WHERE workspace_id = ? AND vulnerability_hash_v2 IN ({_ph})",
                    [workspace_id, *vhashes], fetchall=True,
                ) or []
                existing_by_vhash = {r["vulnerability_hash_v2"]: int(r["id"]) for r in existing_rows}
                now = _now()
                upd_params: List[Tuple[Any, ...]] = []
                ins_params: List[Tuple[Any, ...]] = []
                for vhash, (family, severity) in vmap.items():
                    _ex_id = existing_by_vhash.get(vhash)
                    if _ex_id is not None:
                        upd_params.append((now, _ex_id))
                    else:
                        ins_params.append(
                            (workspace_id, vhash, family, severity or "MEDIUM",
                             f"IAST confirmed: {family}", now, now)
                        )
                if upd_params:
                    self.db.executemany(
                        "UPDATE vulnerability_instances SET status = 'confirmed_runtime', updated_at = ? WHERE id = ?",
                        upd_params,
                    )
                if ins_params:
                    self.db.executemany(
                        """INSERT INTO vulnerability_instances
                           (workspace_id, vulnerability_hash_v2, family, severity, title, status, source, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, 'confirmed_runtime', 'iast', ?, ?)""",
                        ins_params,
                    )
        #  回填触发点：落库后反查 provisional 事务，命中则触发重裁（best-effort，绝不阻断摄取）。
        try:
            from src.iast.orchestrator import notify_backfill

            canary_recs = [r for r in recs if r["canary"]]
            if canary_recs:
                bucket = canary_recs[0]["ingest_bucket"]
                rows = self.db.execute(
                    "SELECT id, canary FROM iast_events WHERE session_id = ? AND ingest_bucket = ? "
                    "ORDER BY id DESC",
                    (session_id, bucket), fetchall=True,
                ) or []
                # 每个 canary 取最新一条（等价于原逐事件的 ORDER BY id DESC LIMIT 1）
                latest_id: Dict[str, int] = {}
                for row in rows:
                    latest_id.setdefault(str(row["canary"]), int(row["id"]))
                for rec in canary_recs:
                    eid = latest_id.get(rec["canary"])
                    if eid is not None:
                        notify_backfill(rec["canary"], rec["canary_state"], eid)
        except Exception:
            pass

    def mark_exploit_confirmed(self, workspace_id: int, vulnerability_hash_v2: str) -> int:
        """Point5 语义分级：D2 harmful 裁决确认「可观测危害」时，把对应 vulnerability_instances
        的 exploit_confirmed 置 1（与 status='confirmed_runtime' 的「污点抵达 sink」并存）。返回受影响行数。

        confirmed_runtime 只证「污点传播到了 sink」，不等于「可利用」；exploit_confirmed 才是 D2 在
        结果点核实到的真实危害。两栏分离，前端据此分「潜在命中(taint reached)」与「真命中(exploited)」。
        """
        if not vulnerability_hash_v2:
            return 0
        try:
            self.db.execute(
                "UPDATE vulnerability_instances SET exploit_confirmed = 1 "
                "WHERE workspace_id = ? AND vulnerability_hash_v2 = ?",
                (workspace_id, vulnerability_hash_v2),
            )
            row = self.db.execute(
                "SELECT COUNT(*) AS c FROM vulnerability_instances "
                "WHERE workspace_id = ? AND vulnerability_hash_v2 = ? AND exploit_confirmed = 1",
                (workspace_id, vulnerability_hash_v2), fetchone=True,
            )
            return int((row or {}).get("c", 0) or 0)
        except Exception as exc:
            logger.warning("[IastService] mark_exploit_confirmed 失败（不影响重放）：%s", exc)
            return 0

    def _resolve_event_task_id(self, workspace_id: int, canary: str, trace_id: str, event_time: Optional[str] = None) -> Optional[int]:
        """按 canary 身份段反查 trigger_specs，取得事件归属的 task_id。

        归属优先级（从高到低）：
        1) canary 身份段命中 trigger_specs.taint_marker → 该 spec 的 task_id（最精确）。
        2) 单 task 回退：workspace 仅单一 task 登记过 trigger_specs → 无身份段事件也归属该 task。
        3) ③ 选项A：活跃扫描会话 current_task_id 已标记 → 归属该活跃 task。
        4) 时间窗回退：多 task 共存、无身份段、无活跃会话时，
           按事件 ingested_at 落入哪个 task 的运行时间窗（scan_tasks.started_at~finished_at）
           归属该 task；重叠窗取「最晚启动」的 task（后启动的扫描通常是当前关注的）。
           这解决了 ws 内多 task 并发/历史共存时，运行期 sink 事件被结构性归 NULL
           （iast_events.task_id=NULL 占比过高，I1/I2 按 task 聚合永远看不到数据）的问题。
           时间窗外的事件（早于任何 task 启动 / 落在窗间空隙）→ 不臆测，保持 NULL。

        解析阶段占 98.7%）。缓存口径与退出条件：
          - 身份段 → task_id 缓存 60s：身份段含 run nonce、全局唯一，同一身份段在一次扫描内
            不会改属（闭环二次回灌即便 DELETE+INSERT，task_id 也不变）。命中即为权威归属。
          - 身份段查不到缓存 2s：负结果可能是「spec 尚未登记」，短 TTL 避免错过刚登记的 spec。
          - workspace 级回退快照缓存 5s：task 集合 / 运行时间窗 / 活跃会话三者合为一次快照，
            行为与逐次查库完全等价（时间窗比较改为在快照上做内存比较），但把 N+2 次查询降到 1 次。
        """
        _now_ts = time.time()
        if not canary:
            # trace_id 有时也携带 canary 身份段，作为降级
            canary = trace_id or ""
        ident = CanaryMatcher.find_identity(canary)
        if ident:
            _ck = (workspace_id, ident)
            _hit = self._ident_owner.get(_ck)
            if _hit is not None and _hit[0] > _now_ts:
                if _hit[1] is not None:
                    return _hit[1]
                # 负结果已过期 → 落到下面重查
            else:
                # 用前缀匹配：taint_marker = identity + metacharacter，探针事件里的 canary 可能是
                # 完整 canary 或仅身份段（被截断/编码后）。LIKE identity% 可覆盖两者。
                row = self.db.execute(
                    "SELECT task_id FROM trigger_specs WHERE workspace_id = ? AND taint_marker LIKE ? ORDER BY id DESC LIMIT 1",
                    (workspace_id, f"{ident}%"), fetchone=True,
                )
                _owner = row.get("task_id") if row else None
                if len(self._ident_owner) >= _OWNERSHIP_CACHE_MAX:
                    self._ident_owner.clear()
                self._ident_owner[_ck] = (
                    _now_ts + (_OWNERSHIP_IDENT_TTL if _owner is not None else _OWNERSHIP_NEG_TTL),
                    _owner,
                )
                if _owner is not None:
                    return _owner

        # 回退：workspace 级快照（task 集合 + 运行时间窗 + 活跃扫描会话），5s 内复用。
        snap = self._workspace_owner_snapshot(workspace_id, _now_ts)
        task_ids = snap["task_ids"]
        if not task_ids:
            # ③ 选项A：活跃扫描会话归属。多 task 共存且无 canary 身份段时，归属当前活跃扫描 task，
            # 避免窗口内无身份段事件（普通 SINK_HIT 实时流量常为空）被静默归 NULL（结构性丢数据）。
            # 由 verify 在 run_transaction 窗口起止处标记/清除 iast_sessions.current_task_id。
            return snap["active"]
        if len(task_ids) == 1:
            # 单 task 回退：未携带 canary 的运行期 sink 事件归属该 task，
            # 使 I1 监听 / I2 裁决能按 task 聚合。
            return task_ids[0]
        # （XSS 的元字符 canary 被应用 HTML 编码后，探针记录的身份段恒为空）会被时间窗错归到
        # 后启动的 task（重叠窗取最晚启动），导致先启动的 task 事件归零。修复：空 canary 事件
        # 优先归当前活跃重放 task（current_task_id，即 verify 在重放窗标记的活动会话），它是
        # 此刻谁在重放最精确的信号；仅当无活跃会话时才退到时间窗。
        # 注意 find_identity 对无身份段输入返回 ""（空串）而非 None，故用 not ident 兼顾二者。
        if not ident and snap["active"] is not None:
            return snap["active"]
        # 多 task：时间窗回退（在快照上做内存比较，不再逐 task 查库）。
        if event_time:
            et = _parse_dt(event_time)
            if et is not None:
                candidates = []
                for start, finish, tid in snap["windows"]:
                    # finished_at 为 NULL 表示仍在运行 → 窗延伸到当下；已结束 task 的窗向后延伸
                    # 312 的 late flush 曾归 NULL / 错归 313）。配合分片真串行排空，312 的迟到事件
                    # 落进 312 的延长窗 → 正确归 312，不被后启动的 task 抢。
                    end = (_now_ts if finish is None else finish + _ATTR_GRACE_SECONDS)
                    if start <= et <= end:
                        candidates.append((start, tid))
                if candidates:
                    # 重叠窗取最晚启动的 task（最新关注对象）
                    candidates.sort(key=lambda x: x[0], reverse=True)
                    return candidates[0][1]
        # ③ 选项A：活跃扫描会话归属（event_time 无窗匹配时再兜底）。
        return snap["active"]

    def _workspace_owner_snapshot(self, workspace_id: int, now_ts: Optional[float] = None) -> Dict[str, Any]:
        """构造（并缓存 5s）本 workspace 的归属回退数据：登记过 spec 的 task、各 task 运行时间窗、活跃会话。

        与逐次查库等价，只是把「DISTINCT task_ids + 每 task 一次窗口查询 + 活跃会话查询」
        合并为一次快照，供同一批/相邻批事件复用。
        """
        now_ts = time.time() if now_ts is None else now_ts
        _hit = self._ws_owner.get(workspace_id)
        if _hit is not None and _hit[0] > now_ts:
            return _hit[1]

        distinct = self.db.execute(
            "SELECT DISTINCT task_id FROM trigger_specs WHERE workspace_id = ? AND task_id IS NOT NULL",
            (workspace_id,), fetchall=True,
        ) or []
        task_ids = [int(r["task_id"]) for r in distinct if r.get("task_id") is not None]
        windows: List[Tuple[float, Optional[float], int]] = []
        for tid in task_ids:
            win = self.db.execute(
                "SELECT started_at, finished_at FROM scan_tasks WHERE id = ?",
                (tid,), fetchone=True,
            )
            if not win:
                continue
            s = _parse_dt(win.get("started_at") or "")
            if s is None:
                continue  # 无起始时间无法定窗，跳过（避免臆测）
            f = _parse_dt(win.get("finished_at") or "")
            windows.append((s, f, tid))
        active_row = self.db.execute(
            "SELECT current_task_id FROM iast_sessions WHERE workspace_id = ? AND current_task_id IS NOT NULL LIMIT 1",
            (workspace_id,), fetchone=True,
        )
        active = active_row.get("current_task_id") if active_row else None
        snap = {"task_ids": task_ids, "windows": windows, "active": active}
        if len(self._ws_owner) >= _OWNERSHIP_CACHE_MAX:
            self._ws_owner.clear()
        self._ws_owner[workspace_id] = (now_ts + _OWNERSHIP_WORKSPACE_TTL, snap)
        return snap


    # ---------- I1 监听器摘要（按 task 聚合 IAST 运行时事件） ----------
    def summarize_task_events(self, task_id: int) -> Dict[str, Any]:
        """返回本 task 的 IAST 运行时事件摘要，供 I1 监听器面板展示。"""
        rows = self.db.execute(
            "SELECT event_type, canary_state, sink_method, sink_file, canary "
            "FROM iast_events WHERE task_id = ?",
            (task_id,), fetchall=True,
        ) or []
        rows = [dict(r) for r in rows]
        total = len(rows)
        sink_hits = [r for r in rows if str(r.get("event_type") or "").upper() in ("SINK_HIT", "SINK_CALL")]
        by_state: Dict[str, int] = {}
        for r in rows:
            st = r.get("canary_state") or "none"
            by_state[st] = by_state.get(st, 0) + 1
        canary_arrivals = sum(
            1 for r in rows
            if str(r.get("canary_state") or "") in ("arrived", "arrival-sanitized", "sink-reached", "sink-reached-probe")
        )
        sink_methods = sorted({
            str(r.get("sink_method") or r.get("sink_file") or "")
            for r in sink_hits
            if (r.get("sink_method") or r.get("sink_file"))
        })
        ws_row = self.db.execute("SELECT workspace_id FROM scan_tasks WHERE id = ?", (task_id,), fetchone=True)
        workspace_id = ws_row["workspace_id"] if ws_row else None
        sess = []
        if workspace_id is not None:
            sess = [dict(r) for r in (self.db.execute(
                "SELECT id, app_name, agent_id, target_url, status, last_heartbeat_at "
                "FROM iast_sessions WHERE workspace_id = ?",
                (workspace_id,), fetchall=True,
            ) or [])]
        return {
            "task_id": task_id,
            "total_events": total,
            "sink_hit_events": len(sink_hits),
            "canary_arrivals": canary_arrivals,
            "by_state": by_state,
            "distinct_sink_count": len(sink_methods),
            "sink_methods_sample": sink_methods[:10],
            "sessions": sess,
        }

    # ---------- A0 环境识别 ----------
    def check_environment_readiness(
        self,
        target_url: str,
        app_name: str,
        agent_id: str,
        *,
        config: Any = None,
        http_probe: Any = None,
    ) -> Dict[str, Any]:
        """按  四步法确认目标可达 + 探针在线 + 绑定一致。

        结论回写 iast_sessions.status（ready / unready），供预处理阶段与 D1 复探复用。
        返回 EnvironmentReadiness.to_dict。
        """
        from src.iast.env_readiness import check_environment_readiness, wake_probe

        readiness = check_environment_readiness(
            self.db, target_url, app_name, agent_id, config=config, http_probe=http_probe
        )
        # 探针静默但进程活着 ⇒ 判活失败。此处主动探活一次再判，避免：
        #   - A0 门禁把整轮扫描挡死；
        #   - D2 每事务复探判 not ready ⇒ 该批 spec 全落 invalidated。
        # 判据本身不放松：敲完门仍不 ready 就照原样返回 not ready。
        if not readiness.is_ready():
            try:
                if wake_probe(target_url):
                    readiness = check_environment_readiness(
                        self.db, target_url, app_name, agent_id,
                        config=config, http_probe=http_probe,
                    )
                    logger.info(
                        "[env-readiness] 主动探活后重判 %s/%s：ready=%s（%s）",
                        app_name, agent_id, readiness.is_ready(),
                        (readiness.detail or {}).get("probe_liveness"),
                    )
            except Exception as _we:  # noqa: BLE001  探活失败不影响原判据
                logger.debug("[env-readiness] 主动探活异常（按原判据）：%s", _we)
        # 回写会话状态（best-effort，绝不阻断调用方）
        try:
            status = "ready" if readiness.is_ready() else "unready"
            self.db.execute(
                "UPDATE iast_sessions SET status = ? WHERE app_name = ? AND agent_id = ?",
                (status, app_name, agent_id),
            )
        except Exception:
            pass
        return readiness.to_dict()

    def poll_events_by_canary(
        self,
        canary: str,
        since_id: int = 0,
        limit: int = 50,
        app_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """供编排器按 canary 精确轮询 IAST 事件窗口。返回 id + canary_state。

         事件隔离：可选 app_name / agent_id / trace_id 形参，提供时 AND 进 WHERE，
        强制 agentId / appName / traceId 关联，避免共用同一运行实例的多次扫描事件混流与状态污染
        （一次扫描的数据污染另一次）。不提供则退化为纯 canary 匹配（向后兼容）。
        """
        sql = """SELECT id, canary_state, canary, sink_method, sink_file, sink_line,
                        source_value, stack_trace, taint_path_json, event_type
                 FROM iast_events
                 WHERE canary = ? AND id > ?"""
        params: List[Any] = [canary, int(since_id)]
        if app_name is not None:
            sql += " AND app_name = ?"
            params.append(app_name)
        if agent_id is not None:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        if trace_id is not None:
            sql += " AND trace_id = ?"
            params.append(trace_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(int(limit))
        rows = self.db.execute(sql, params, fetchall=True)
        return [dict(r) for r in (rows or [])]

    def poll_authz_blindspots(
        self,
        canary: str,
        app_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """任务4 IAST 校验函数 hook：按 canary 拉取探针观测到的「授权盲点」事件。

        探针 AuthzDecisionAdvice 在字节码层 hook Spring Security 的
        AccessDecisionManager.decide（所有方法/URL 级安全决策的唯一漏斗点）。请求退出时若
        「访问了域对象但没有任何对象级(ownership)授权决策」→ SecurityAgent.reportBolaSuspect
        发 event_type='BOLA_SUSPECT'（category=bola），并把本请求的平台 canary 身份段回带进
        payload → 落 source_value。

        这是把 BOLA 从「响应差分」（只证结果泄露）升级为「授权 hook 语义确认」（探针在鉴权
        函数处证明未做对象级归属校验，机制级证据）的运行时凭据。仅返回与本次攻击 canary
        关联的盲点事件；source_value 内含被越权访问的对象清单。
        """
        if not canary:
            return []
        # iast_events.canary 列只存平台 canary 身份段（s4st41<16hex>，22 字符）；而调用方传入的
        # 是完整 taint_marker（身份段 + 元字符段）。必须先归一为身份段再比对，否则恒 0 命中。
        from src.iast.canary import CanaryMatcher
        identity = CanaryMatcher.find_identity(canary) or canary
        sql = """SELECT id, event_type, principal, source_value, sink_method, sink_file, stack_trace, canary
                 FROM iast_events
                 WHERE canary = ? AND UPPER(event_type) IN ('BOLA_SUSPECT', 'AUTHZ_BLINDSPOT')"""
        params: List[Any] = [identity]
        if app_name is not None:
            sql += " AND app_name = ?"
            params.append(app_name)
        if agent_id is not None:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(int(limit))
        rows = self.db.execute(sql, params, fetchall=True)
        return [dict(r) for r in (rows or [])]

    def correlate_bola_suspect_to_findings(self, task_id: int) -> Dict[str, Any]:
        """任务4 回填：把探针发射的 BOLA_SUSPECT 事件按 canary 身份段反查 trigger_specs.taint_marker，
        归属到对应 finding，写入 iast_events.correlated_finding_id 与 findings.raw_json.iast_evidence。

        探针异步 flush，重放期 poll_authz_blindspots 可能因窗口不足错过事件；此法作为扫描后兜底，
        保证业务型越权（BOLA/IDOR）的运行时证据落到 finding 裁决层，而非停留在 iast_events 游离态。
        """
        if not task_id:
            return {"error": "task_id required"}
        from src.iast.canary import CanaryMatcher
        import json as _json
        rows = self.db.execute(
            """SELECT id, canary FROM iast_events
               WHERE task_id=? AND UPPER(event_type)='BOLA_SUSPECT' AND canary IS NOT NULL""",
            (task_id,), fetchall=True)
        rows = [dict(r) for r in (rows or [])]
        if not rows:
            return {"events": 0, "correlated": 0, "findings_updated": 0, "per_finding": {}}
        specs = self.db.execute(
            """SELECT taint_marker, finding_id FROM trigger_specs
               WHERE task_id=? AND taint_marker IS NOT NULL AND finding_id IS NOT NULL""",
            (task_id,), fetchall=True)
        specs = [dict(r) for r in (specs or [])]
        canary2fid: Dict[str, int] = {}
        for s in specs:
            tm = s.get("taint_marker")
            fid = s.get("finding_id")
            ident = CanaryMatcher.find_identity(tm) if tm else None
            if ident and fid is not None:
                canary2fid[ident[:22]] = int(fid)
        per_finding: Dict[int, List[int]] = {}
        updated_events = 0
        for r in rows:
            eid = r.get("id")
            canary = r.get("canary")
            ident = CanaryMatcher.find_identity(canary) or (canary or "")[:22]
            key = ident[:22]
            fid = canary2fid.get(key)
            if fid:
                self.db.execute(
                    "UPDATE iast_events SET correlated_finding_id=? WHERE id=? AND (correlated_finding_id IS NULL OR correlated_finding_id<>?)",
                    (fid, eid, fid))
                updated_events += 1
                per_finding.setdefault(fid, []).append(eid)
        findings_updated = 0
        for fid, eids in per_finding.items():
            frow = self.db.execute("SELECT raw_json FROM findings WHERE id=?", (fid,), fetchall=True)
            if not frow:
                continue
            raw = frow[0]["raw_json"] if isinstance(frow[0], dict) else frow[0][0]
            try:
                dj = _json.loads(raw)
            except Exception:
                continue
            ie = dj.get("iast_evidence") or {}
            # 绝对值写入（非累加），保证重复运行幂等、不虚增计数
            ie["authz_event_count"] = len(eids)
            ie["iast_authz_confirmed"] = True
            ie["iast_reached"] = True
            ie["iast_event_count"] = len(eids)
            etypes = ie.get("iast_event_types") or []
            if "BOLA_SUSPECT" not in etypes:
                etypes.append("BOLA_SUSPECT")
            ie["iast_event_types"] = etypes
            dj["iast_evidence"] = ie
            dj["bola_correlated_event_ids"] = eids
            self.db.execute("UPDATE findings SET raw_json=? WHERE id=?",
                           (_json.dumps(dj, ensure_ascii=False), fid))
            findings_updated += 1
        return {
            "events": len(rows),
            "correlated": updated_events,
            "findings_updated": findings_updated,
            "per_finding": {str(k): len(v) for k, v in per_finding.items()},
        }

    def correlate_sink_events_to_findings(self, task_id: int) -> Dict[str, Any]:
        """任务通用回填：把探针发射的 SINK_HIT / TAINT_FLOW 事件按 canary 身份段反查 trigger_specs.taint_marker，
        归属到对应 finding，写入 iast_events.correlated_finding_id，打通确认层闭环。

        旧实现 correlate_bola_suspect_to_findings 仅处理 BOLA_SUSPECT 事件，注入型家族（命令执行 / SSRF /
        XXE / SQLi / SpEL / 路径穿越 / XSS 等）的运行时 sink 证据（SINK_HIT）从未被归因，导致
        correlated_finding_id 全局恒为 0、确认层闭环断在「探针 → finding」这一段（#3 根因之一）。
        本方法补齐该缺口，并叠加 endpoint+family 兜底锚定（spec.finding_id 多为 NULL、spec.vuln_hash
        与 findings 不匹配时仍能落位）。幂等、fail-open。
        """
        if not task_id:
            return {"error": "task_id required"}
        import json as _json
        # 放宽查询：不再硬过滤 canary IS NOT NULL。
        # canary 为空），但 sink_file（JDK 类方法签名，如 java.lang.ProcessBuilder.start）稳定存在，是可靠的
        # 家族级归因信号。多取 sink_file/sink_method/sink_line/vuln_type 供 Phase B 使用。
        rows = self.db.execute(
            """SELECT id, canary, event_type, sink_file, sink_method, sink_line, vuln_type
               FROM iast_events
               WHERE task_id=? AND UPPER(event_type) IN ('SINK_HIT','TAINT_FLOW')""",
            (task_id,), fetchall=True)
        rows = [dict(r) for r in (rows or [])]
        if not rows:
            return {"events": 0, "correlated": 0, "findings_updated": 0, "per_finding": {}}

        # canary 身份(22) -> trigger_spec
        specs = self.db.execute(
            """SELECT taint_marker, target_endpoint, family, vulnerability_hash_v2, finding_id
               FROM trigger_specs WHERE task_id=? AND taint_marker IS NOT NULL""",
            (task_id,), fetchall=True)
        spec_by_ident: Dict[str, Dict[str, Any]] = {}
        for s in (specs or []):
            tm = s.get("taint_marker")
            ident = CanaryMatcher.find_identity(tm) if tm else ""
            if ident:
                spec_by_ident[ident[:22]] = s

        # (canonical_family, endpoint) -> finding_id 兜底锚定（Phase A 端点级精确）
        fbs = self.db.execute(
            "SELECT id, finding_type, raw_json FROM findings WHERE task_id=?", (task_id,), fetchall=True)
        ep_fam_to_fid: Dict[Tuple[str, str], int] = {}
        # canonical_family -> [finding_id...]（Phase B 家族级归因，排除 SCA 噪声族）
        fam_fids: Dict[str, List[int]] = {}
        for f in (fbs or []):
            fid = f.get("id")
            ft = f.get("finding_type") or ""
            cf = canonical_family(ft)
            if cf in ("sca",):
                continue
            if cf not in fam_fids:
                fam_fids[cf] = []
            fam_fids[cf].append(int(fid))
            raw = f.get("raw_json")
            try:
                dj = _json.loads(raw) if isinstance(raw, (str, bytes)) else (raw or {})
            except Exception:
                dj = {}
            es = (dj.get("exploit_spec") or {}) if isinstance(dj, dict) else {}
            ent = (es.get("entry") or {}) if isinstance(es, dict) else {}
            route = (ent.get("route") or (dj.get("trigger_spec_detail") or {}).get("endpoint") or "")
            key = (cf, (route or "").lower())
            if key not in ep_fam_to_fid:
                ep_fam_to_fid[key] = fid

        per_finding: Dict[int, List[int]] = {}
        updated_events = 0
        family_linked_events = 0
        for r in rows:
            eid = r.get("id")
            canary = r.get("canary")
            ident = CanaryMatcher.find_identity(canary) or ""
            spec = spec_by_ident.get(ident[:22])
            fid = None
            if spec:
                fid = spec.get("finding_id")
                if fid is None and spec.get("vulnerability_hash_v2"):
                    m = self.db.execute(
                        "SELECT id FROM findings WHERE task_id=? AND vulnerability_hash_v2=?",
                        (task_id, spec["vulnerability_hash_v2"]), fetchall=True)
                    if m:
                        fid = m[0]["id"]
                if fid is None and spec.get("target_endpoint"):
                    fk = (canonical_family(spec.get("family") or ""), (spec["target_endpoint"] or "").lower())
                    fid = ep_fam_to_fid.get(fk)
            if fid:
                self.db.execute(
                    "UPDATE iast_events SET correlated_finding_id=? WHERE id=? AND (correlated_finding_id IS NULL OR correlated_finding_id<>?)",
                    (fid, eid, fid))
                updated_events += 1
                per_finding.setdefault(int(fid), []).append(eid)
                continue
            # Phase B（SINK_HIT 专属）：canary 不可归因时，按 JDK sink 签名家族级回填。
            # 精度说明：SINK_HIT 事件不含请求端点，无法精确到单条 finding；探针自主污点追踪下
            # sink_file（JDK 类方法签名）是可靠的「家族」信号。因此回填到同家族全部应用层 finding——
            # 这是家族级确认（命中该族 sink 即证该族可利用），非单实例精确归因。单实例精确需探针在
            # SINK_HIT 上回带端点/canary（独立探针 R&D 项）。仅用家族级匹配避免跨族过归因。
            if (r.get("event_type") or "").upper() == "SINK_HIT":
                fam = _sink_signature_to_family(r.get("sink_file") or "")
                if fam and fam in fam_fids:
                    linked_any = False
                    for tfid in fam_fids[fam]:
                        self.db.execute(
                            "UPDATE iast_events SET correlated_finding_id=? WHERE id=? AND (correlated_finding_id IS NULL OR correlated_finding_id<>?)",
                            (tfid, eid, tfid))
                        linked_any = True
                        per_finding.setdefault(int(tfid), []).append(eid)
                    if linked_any:
                        updated_events += 1
                        family_linked_events += 1
        return {
            "events": len(rows),
            "correlated": updated_events,
            "family_linked": family_linked_events,
            "findings_updated": len(per_finding),
            "per_finding": {str(k): len(v) for k, v in per_finding.items()},
        }
