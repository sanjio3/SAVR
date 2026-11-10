"""知识条目（黑板阶段二）：环境事实 / 靶场档案 / 已知坑的一等公民化。

设计目标（round-10-blackboard-plan.md 阶段二）：
- 把"频繁开新 session 不掉信息"从早期设计笔记迁移为机器可读、阶段必读的 DB 真相源。
- 条目形状：{workspace_id, kind, key, value_json, source, confidence, ttl, status, first_seen_at, last_seen_at, superseded_by}
- kind 枚举：target_profile / env_fact / pitfall / family_alias / verified_conclusion
- workspace_id=0 表示全局知识（跨 session 可用，不绑具体工作区）。

铁律：只灌已实测确认过的硬事实；错误事实比没事实更糟，故种子函数全部取自真实事故与靶场实测，
不臆造。
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

KIND_TARGET_PROFILE = "target_profile"
KIND_ENV_FACT = "env_fact"
KIND_PITFALL = "pitfall"
KIND_FAMILY_ALIAS = "family_alias"
KIND_VERIFIED_CONCLUSION = "verified_conclusion"

_KINDS = {
    KIND_TARGET_PROFILE,
    KIND_ENV_FACT,
    KIND_PITFALL,
    KIND_FAMILY_ALIAS,
    KIND_VERIFIED_CONCLUSION,
}

# 阶段必读映射（read_for_stage 用）
_STAGE_KINDS = {
    "a0": [KIND_TARGET_PROFILE, KIND_PITFALL],
    "a2": [KIND_FAMILY_ALIAS],
    "d1": [KIND_PITFALL],
}


def _now() -> str:
    return datetime.utcnow().isoformat()


def upsert(
    db,
    workspace_id: int,
    kind: str,
    key: str,
    value: Any,
    *,
    source: str = "",
    confidence: str = "medium",
    ttl: str = "",
    status: str = "active",
) -> bool:
    """写入/更新一条知识条目；同 (workspace_id, kind, key) 存在则更新 last_seen_at 与值。"""
    if kind not in _KINDS:
        logger.warning("[knowledge] 未知 kind=%s，归入 verified_conclusion", kind)
        kind = KIND_VERIFIED_CONCLUSION
    now = _now()
    try:
        db.execute(
            """
            INSERT INTO knowledge_entries
            (workspace_id, kind, key, value_json, source, confidence, ttl, status, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, kind, key) DO UPDATE SET
                value_json=excluded.value_json,
                source=excluded.source,
                confidence=excluded.confidence,
                ttl=excluded.ttl,
                status=excluded.status,
                last_seen_at=excluded.last_seen_at
            """,
            (workspace_id, kind, key, json.dumps(value, ensure_ascii=False),
             source, confidence, ttl, status, now, now),
        )
        return True
    except Exception as _e:
        logger.warning("[knowledge] upsert 失败 kind=%s key=%s：%s", kind, key, _e)
        return False


def get(db, workspace_id: int, kind: str, key: str) -> Optional[Dict[str, Any]]:
    row = db.execute(
        "SELECT * FROM knowledge_entries WHERE workspace_id=? AND kind=? AND key=?",
        (workspace_id, kind, key), fetchone=True,
    )
    return dict(row) if row else None


def get_by_kind(db, workspace_id: int, kind: str) -> List[Dict[str, Any]]:
    rows = db.execute(
        "SELECT * FROM knowledge_entries WHERE workspace_id=? AND kind=? ORDER BY key",
        (workspace_id, kind), fetchall=True,
    ) or []
    return [dict(r) for r in rows]


def load_knowledge(db, workspace_id: int, kinds: Optional[List[str]] = None) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """读某 workspace 的知识条目，返回 {kind: {key: rec}}，rec 含解析后的 value 字段。

    kinds 为 None 时读全部 kind。不过滤 ttl（首期 ttl 留空，所有条目常驻）。
    """
    sql = "SELECT * FROM knowledge_entries WHERE workspace_id=?"
    args: List[Any] = [workspace_id]
    if kinds:
        ph = ",".join("?" * len(kinds))
        sql += f" AND kind IN ({ph})"
        args += list(kinds)
    sql += " ORDER BY kind, key"
    try:
        rows = db.execute(sql, tuple(args), fetchall=True) or []
    except Exception as _e:
        logger.warning("[knowledge] load_knowledge 失败：%s", _e)
        return {}
    out: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for r in rows:
        rec = dict(r)
        try:
            rec["value"] = json.loads(rec.get("value_json") or "{}")
        except Exception:
            rec["value"] = {}
        out.setdefault(rec["kind"], {})[rec["key"]] = rec
    return out


def read_for_stage(workspace_id: Optional[int], stage: str, db=None) -> Dict[str, Any]:
    """best-effort：为某阶段读取"必读"知识并记日志，返回条目（不抛异常、不阻断扫描）。

    合并逻辑：先读具体 workspace_id，再读全局 workspace_id=0，后者作为跨 session 兜底。
    仅日志化消费（digest），不改变任何阶段行为；真正"跳过重复重放"等动作属预读接线，不在此处。
    """
    kinds = _STAGE_KINDS.get(stage)
    if not kinds:
        return {}
    if workspace_id is None and stage == "a0":
        # A0 无 workspace 时仍读全局知识
        workspace_ids = [0]
    elif workspace_id is None:
        workspace_ids = [0]
    else:
        workspace_ids = [workspace_id, 0] if workspace_id != 0 else [0]

    if db is None:
        try:
            from src.infrastructure.db import Database
            db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        except Exception as _e:
            logger.warning("[knowledge] 阶段 %s 无法获取 DB，跳过必读：%s", stage, _e)
            return {}

    merged: Dict[str, Any] = {}
    try:
        for wid in workspace_ids:
            data = load_knowledge(db, wid, kinds)
            for kind, keys in data.items():
                for k, rec in keys.items():
                    # 具体 workspace 优先；全局仅在缺失时兜底
                    if k not in merged.get(kind, {}):
                        merged.setdefault(kind, {})[k] = rec
    except Exception as _e:
        logger.warning("[knowledge] 阶段 %s 必读加载失败（不阻断）：%s", stage, _e)
        return {}

    digest = {kind: sorted(keys.keys()) for kind, keys in merged.items()}
    if digest:
        logger.info("[knowledge] 阶段 %s 必读知识已载入：%s", stage, digest)
    return merged


# ---------------------------------------------------------------------------
# 种子数据（仅已实测确认过的硬事实；workspace_id=0 全局常驻）
# ---------------------------------------------------------------------------
def seed_target_mall_knowledge(db, workspace_id: int = 0) -> int:
    """灌入 target-mall / SAVR 平台的已实测硬事实（约 18 条）。

    全部来自真实事故与靶场实测，不臆造。返回成功写入条数。
    """
    n = 0
    S = "verified-2026-09"

    # ---- target_profile：靶场档案 ----
    n += upsert(db, workspace_id, KIND_TARGET_PROFILE, "target-mall", {
        "target": "target-mall",
        "db_type": "H2",
        "db_mode": "file",
        "self_heal": "schema_repair 仅在启动时跑一次",
        "auth": "CurrentUser.of / MyBatis",
        "port": 8092,
        "framework": "SpringBoot + MyBatis",
    }, source=S, confidence="high")

    # ---- env_fact：环境事实 ----
    n += upsert(db, workspace_id, KIND_ENV_FACT, "target-mall-port", {
        "port": 8092,
        "watchdog": "launch_target_mall.py",
        "process": "java -jar target-mall",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_ENV_FACT, "venv-shim-double-stack", {
        "fact": "单 .venv 解释器被 shim 包装时会呈现假双栈（8000 起不来 / 8092 / 5200 正常）",
        "cause": "托管运行时后台任务外壳重拉子进程",
        "fix": "命名互斥体单实例守卫 + task_runner 钉死 VENV_PY 到 .venv/Scripts/python.exe",
    }, source=S, confidence="high")
    # 不再把本机绝对路径灌进知识库。路径由部署方通过
    # SAST_AI_PROBE_JAR 提供，种子里只保留可移植的相对默认值。
    n += upsert(db, workspace_id, KIND_ENV_FACT, "probe-jar", {
        "path": os.environ.get("SAST_AI_PROBE_JAR", "probe-java/target/sec-probe.jar"),
        "env_var": "SAST_AI_PROBE_JAR",
        "redeploy": "杀靶场子 java，由对应看门狗自愈重建",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_ENV_FACT, "git-bash-taskkill", {
        "fact": "Git Bash 下 taskkill /PID 被路径转换改 //PID 静默失败",
        "fix": "MSYS_NO_PATHCONV=1 taskkill /PID <pid> /F",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_ENV_FACT, "netstat-encoding", {
        "fact": "netstat 输出是 GBK，Python 读需 gbk 解码",
        "avoid": "wmic 已禁用，勿用",
    }, source=S, confidence="medium")
    n += upsert(db, workspace_id, KIND_ENV_FACT, "curl-body", {
        "fact": "Git Bash 内联 curl -d '{json}' 被转义破坏 → 400 error parsing body",
        "fix": "写 json 到文件后 --data-binary @file",
    }, source=S, confidence="high")

    # ---- pitfall：已知坑 ----
    n += upsert(db, workspace_id, KIND_PITFALL, "h2-file-drop-persists", {
        "fact": "H2 是文件库，DROP 会持久化；扫描前必须验 /products 返回 200",
        "symptom": "/products 500 → 文件库被 DROP 打死",
        "fix": "重启 target-mall 让 schema_repair 自愈（仅启动时跑）",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_PITFALL, "mybatis-currentuser-hook-miss", {
        "fact": "target-mall 用 MyBatis + CurrentUser.of，原 CrudRepository 钩子永不命中",
        "bola_suspect": 0,
        "fix": "ExecutorQueryAdvice + CurrentUserAdvice + recordObjectAccess 去重",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_PITFALL, "adaptive-concurrency-H2", {
        "fact": "H2 内存库并发重放下丢表 → 500，把靶场不健康误判为漏洞无证据",
        "fix": "自适应并发闸门（初始4/最大12）+ 熔断自动复位",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_PITFALL, "prompt-format-forbidden", {
        "fact": "prompt 模板禁裸 str.format()，一律走 src/agents/prompt_render.py 的 render_prompt()",
        "cause": "audit_prompts.yaml 字面路由 /order/{id} 触发 KeyError 被 A2 analyze() 吞掉 → 60/60 全挂、业务逻辑 findings 归零",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_PITFALL, "stable-vuln-key", {
        "fact": "stable_vuln_key 是路由无关判据；跨阶段按文件路径做 key 走 src/core/path_norm.py match_path_key",
        "cause": "A1 产绝对路径、A2 产相对路径，直接 .get 恒 miss → per-file 证据从没喂进 LLM",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_PITFALL, "reconcile-no-cross-round-accumulate", {
        "fact": "对账口径必须单轮，禁跨轮累加（同一漏洞重复计数陷阱）",
        "example": "task7+8+9 累加成 35 confirmed，去重后仅 20，单轮实际 13",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_PITFALL, "judge-by-findings-not-spec-count", {
        "fact": "判召回率看 entry.route 填充率，不看 trigger_specs 确认数",
        "cause": "落在 config/filter/schema.sql 的 findings 无路由 100% 丢弃",
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_PITFALL, "recall-funnel-a2-unique-source", {
        "fact": "A2 是业务逻辑类 findings 唯一来源，A1 规则引擎只产技术族",
        "a2_down": "垂直越权/竞态/重放/jwt 类全部消失，只剩注入类",
    }, source=S, confidence="high")

    # ---- family_alias：族别名映射（中文族名 → canonical token） ----
    n += upsert(db, workspace_id, KIND_FAMILY_ALIAS, "vertical_privesc", {
        "canonical": "vertical_privesc",
        "zh": "垂直越权",
        "alias": ["垂直越权", "Vertical Privilege Escalation", "VERTICAL_PRIVESC"],
    }, source=S, confidence="high")
    n += upsert(db, workspace_id, KIND_FAMILY_ALIAS, "bola", {
        "canonical": "bola",
        "zh": "水平越权 / IDOR",
        "alias": ["BOLA", "水平越权", "IDOR", "越权"],
    }, source=S, confidence="high")

    # ---- verified_conclusion：已验证结论（带 run 出处语义） ----
    n += upsert(db, workspace_id, KIND_VERIFIED_CONCLUSION, "template-xss-target-mall-3-sinks", {
        "fact": "target-mall 真实 3 个 XSS sink：/products reflected、/product/{id} stored via /comment、/profile stored via /profile/update",
        "method": "Thymeleaf th:utext 非转义 + model.addAttribute 回显",
        "detector": "src/agents/a1_template_xss_analyzer.py + src/core/template_taint.py",
    }, source=S, confidence="high")

    return n
