"""黑板（单一真相源）与轮次体系。

  导致同一 task 被多轮覆写成混合库，单轮归因做不到（task-3：漏斗读数 47→25 自相矛盾）。
- 此前「展示计数」各处自存快照（scan_progress / summary_json / results 各一份），与 DB 实表
  长期漂移，只能靠 事后对账补丁续命。

本模块提供唯一真相源：
- scan_runs：每轮不可变运行记录（含代码版本指纹，杜绝「旧 backend 跑旧代码」假阳性）。
- vuln_blackboard：以 vulnerability_instances 的 vuln_hash 为锚，按 (workspace, vhash, run)
  钉住 detect/confirm/运行时证据 三态 + 证据指针。

铁律：所有展示计数一律从 vuln_blackboard 派生，禁止各处自存快照。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 代码版本指纹取样文件：这些文件的 mtime 变化即代表「跑的可能不是我以为的代码」。
_FINGERPRINT_FILES = (
    "src/iast/trigger_spec_registry.py",
    "src/core/vuln_hash.py",
    "src/core/param_resolver.py",
    "src/core/exploit_spec.py",
    "src/agents/a2_intelligent_agent.py",
    "src/agents/a1_injection_heuristic.py",
    "src/cli/benchmark_cli.py",
    "src/agents/d2_facade.py",
)

# 运行时「canary 到达 sink」的证据态（探针写入 iast_events.canary_state）。
# 单一真相源在 src/iast/canary.py（含探针显式断言 sink-reached-probe），此处重导出。
from src.iast.canary import SINK_REACHED_STATES, canary_key, is_sink_reached  # noqa: F401


def _now() -> str:
    return datetime.utcnow().isoformat()


def compute_code_fingerprint(project_root: Optional[str] = None) -> Dict[str, Any]:
    """计算代码版本指纹：git revision（可得时）+ 关键文件 mtime 摘要。

    用于写进 scan_runs.code_fingerprint，使每轮扫描可追溯「当时跑的是哪份代码」，
    杜绝「marker 说新代码已加载、实际 backend 跑旧代码」这类假阳性。
    """
    root = project_root or os.getcwd()
    git_rev = ""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root, capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            git_rev = (out.stdout or "").strip()
    except Exception:
        git_rev = ""

    parts: List[str] = []
    key_files: List[Dict[str, Any]] = []
    for rel in _FINGERPRINT_FILES:
        p = os.path.join(root, rel)
        try:
            mt = os.path.getmtime(p)
        except OSError:
            mt = 0.0
        key_files.append({"file": rel, "mtime": mt})
        parts.append(f"{rel}:{int(mt)}")

    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return {
        "fingerprint": digest,
        "git_revision": git_rev,
        "key_files": key_files,
    }


# ---------------------------------------------------------------------------
# 轮次（scan_runs）
# ---------------------------------------------------------------------------
def start_run(
    db,
    workspace_id: int,
    task_id: int,
    round_no: int = 0,
    options: Optional[Dict[str, Any]] = None,
    project_root: Optional[str] = None,
) -> Optional[int]:
    """开启一轮扫描，写不可变 run 记录并回写 scan_tasks.run_id。

    返回 run_id；失败返回 None（不阻断扫描）。
    """
    try:
        fp = compute_code_fingerprint(project_root)
        now = _now()
        db.execute(
            """
            INSERT INTO scan_runs
            (workspace_id, task_id, round_no, code_fingerprint, git_revision,
             key_files_json, backend_pid, options_json, metrics_json, status,
             started_at, finished_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_id, task_id, int(round_no or 0),
                fp["fingerprint"], fp["git_revision"],
                json.dumps(fp["key_files"], ensure_ascii=False),
                os.getpid(),
                json.dumps(options or {}, ensure_ascii=False),
                "{}", "running", now, "", now,
            ),
        )
        row = db.execute(
            "SELECT id FROM scan_runs WHERE task_id=? ORDER BY id DESC LIMIT 1",
            (task_id,), fetchone=True,
        )
        run_id = int(row["id"]) if row else None
        if run_id:
            try:
                db.execute("UPDATE scan_tasks SET run_id=? WHERE id=?", (run_id, task_id))
            except Exception as _e:
                logger.warning("[blackboard] 回写 scan_tasks.run_id 失败：%s", _e)
        logger.info(
            "[blackboard] run 开启 run_id=%s task=%s round=%s fingerprint=%s git=%s",
            run_id, task_id, round_no, fp["fingerprint"], fp["git_revision"] or "-",
        )
        return run_id
    except Exception as _e:
        logger.warning("[blackboard] start_run 失败（不阻断扫描）：%s", _e)
        return None


def finish_run(db, run_id: Optional[int], status: str = "completed",
               metrics: Optional[Dict[str, Any]] = None) -> None:
    """结束一轮：写终态与指标。run 记录此后视为不可变（不再 UPDATE 业务字段）。"""
    if not run_id:
        return
    try:
        db.execute(
            "UPDATE scan_runs SET status=?, finished_at=?, metrics_json=? WHERE id=?",
            (status, _now(), json.dumps(metrics or {}, ensure_ascii=False), run_id),
        )
    except Exception as _e:
        logger.warning("[blackboard] finish_run 失败：%s", _e)


def close_open_runs(db, task_id: int, status: str = "failed") -> int:
    """闭合该 task 下所有未收口的 run（孤儿轮次 / 陈旧记录根治）。

    finish_run 只按单个 run_id 收口，而 scan_runs 可能对同一 task 留多条 running 记录
    永远停在 running —— 这就是「scan_runs 陈旧记录」的来源。此处按 task 批量闭合
    所有 finished_at 为空的 run，返回闭合条数。fail-open，失败只告警。
    """
    try:
        rows = db.execute(
            "SELECT id FROM scan_runs WHERE task_id=? AND (finished_at IS NULL OR finished_at='')",
            (task_id,), fetchall=True,
        )
    except Exception as _e:
        logger.warning("[blackboard] close_open_runs 查询失败：%s", _e)
        return 0
    closed = 0
    for r in rows or []:
        try:
            finish_run(db, int(r["id"]), status=status)
            closed += 1
        except Exception as _e:
            logger.warning("[blackboard] close_open_runs 闭合 run=%s 失败：%s", r.get("id"), _e)
    return closed


def resolve_run_id(db, task_id: int) -> Optional[int]:
    """取 task 所属 run_id；缺失则回退 scan_tasks.run_id。"""
    try:
        row = db.execute(
            "SELECT id FROM scan_runs WHERE task_id=? ORDER BY id DESC LIMIT 1", (task_id,),
            fetchone=True,
        )
        if row:
            return int(row["id"])
    except Exception:
        pass
    try:
        row = db.execute("SELECT run_id FROM scan_tasks WHERE id=?", (task_id,), fetchone=True)
        if row and row["run_id"]:
            return int(row["run_id"])
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 黑板同步（唯一真相源）
# ---------------------------------------------------------------------------
def sync_blackboard(db, task_id: int, run_id: Optional[int] = None,
                    workspace_id: Optional[int] = None) -> int:
    """从 findings / trigger_specs / iast_events 派生本轮黑板行。

    - detect_state：findings 或 trigger_specs 命中 → detected
    - confirm_state：该 vhash 的 D2 验证进入确认态（verification_status ∈
      confirmed_exploitable/exploitable）或 IAST canary 运行时到达 sink（iast_state ∈
      SINK_REACHED_STATES）才计为 confirmed；仅「存在 spec（待重放假说）」不算确认。
    - sink_reached：存在 iast_events，其 canary 匹配该 spec 的 taint_marker
      且 canary_state ∈ SINK_REACHED_STATES → 1
    返回写入/更新的行数。
    """
    run_id = run_id or resolve_run_id(db, task_id)
    if run_id is None:
        logger.warning("[blackboard] task=%s 无 run_id，跳过黑板同步", task_id)
        return 0
    try:
        row = db.execute("SELECT workspace_id FROM scan_tasks WHERE id=?", (task_id,), fetchone=True)
        workspace_id = int(workspace_id or (row["workspace_id"] if row else 0))
    except Exception:
        workspace_id = int(workspace_id or 0)

    # 1) 收集本轮 findings 的 vhash → 代表 finding_id
    findings: Dict[str, int] = {}
    try:
        for r in db.execute(
            "SELECT id, vulnerability_hash_v2 FROM findings WHERE task_id=? AND id NOT IN (SELECT finding_id FROM trigger_specs WHERE COALESCE(suppressed_by_safe_verdict, 0) = 1 AND finding_id > 0)", (task_id,), fetchall=True
        ) or []:
            vh = r["vulnerability_hash_v2"]
            if vh:
                findings.setdefault(vh, int(r["id"]))
    except Exception as _e:
        logger.warning("[blackboard] 读取 findings 失败：%s", _e)

    # 2) 收集本轮 trigger_specs
    specs: Dict[str, Dict[str, Any]] = {}
    try:
        for r in db.execute(
            "SELECT id, vulnerability_hash_v2, family, target_endpoint, http_method,"
            " verification_status, iast_state, taint_marker FROM trigger_specs WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict, 0) = 0",
            (task_id,), fetchall=True,
        ) or []:
            vh = r["vulnerability_hash_v2"]
            if vh:
                specs[vh] = dict(r)
    except Exception as _e:
        logger.warning("[blackboard] 读取 trigger_specs 失败：%s", _e)

    # 3) canary → 是否到达 sink（本轮 IAST 事件）
    reached_canaries = set()
    try:
        for r in db.execute(
            "SELECT canary, canary_state FROM iast_events WHERE task_id=?", (task_id,), fetchall=True
        ) or []:
            st = (r["canary_state"] or "").strip().lower()
            if is_sink_reached(st) and r["canary"]:
                # 归一为身份段：事件侧只有 22 字符身份段，spec 侧是「身份段+元字符段」完整串。
                reached_canaries.add(canary_key(r["canary"]))
    except Exception as _e:
        logger.warning("[blackboard] 读取 iast_events 失败：%s", _e)

    # 4) vulnerability_instances 指针（跨 task 全局去重锚点）
    inst_by_vh: Dict[str, int] = {}
    try:
        for r in db.execute(
            "SELECT id, vulnerability_hash_v2 FROM vulnerability_instances WHERE workspace_id=?",
            (workspace_id,), fetchall=True,
        ) or []:
            inst_by_vh[r["vulnerability_hash_v2"]] = int(r["id"])
    except Exception:
        pass

    # 5) 清理孤儿黑板行：本 (task, run) 下、vhash 既不在 findings 也不在 specs 的残留行。
    #    成因：auto_register 写入 spec 后，后续 consolidation/去重删除了该 spec，但黑板行
    #    仍保留 confirm_state='confirmed'，导致「黑板 confirmed」虚高。
    #    黑板是单真相源，必须随 findings/specs 实时收敛，禁止残留孤儿行。
    valid_vh = set(findings) | set(specs)
    if valid_vh:
        try:
            ph = ",".join("?" * len(valid_vh))
            db.execute(
                f"DELETE FROM vuln_blackboard WHERE task_id=? AND run_id=? "
                f"AND vulnerability_hash_v2 NOT IN ({ph})",
                (task_id, int(run_id), *valid_vh),
            )
        except Exception as _e:
            logger.warning("[blackboard] 清理孤儿黑板行失败（不阻断）：%s", _e)

    writer = f"task:{task_id}/run:{int(run_id)}/pid:{os.getpid()}"
    n = 0
    n_sink = 0
    for vh in valid_vh:
        spec = specs.get(vh) or {}
        taint = spec.get("taint_marker") or ""
        # 两侧都归一为身份段再比对（历史实现用完整 taint_marker 全等 22 字符事件 canary，恒 0 命中）
        sink_reached = 1 if (taint and canary_key(taint) in reached_canaries) else 0
        detect_state = "detected" if (vh in findings or vh in specs) else "undetected"
        # trigger_spec 只是 A2 的待重放假说（候选攻击面），不等于已确认可利用；
        # 只有 D2 验证为可利用或 IAST 运行时真正到达 sink 才算 confirmed。
        verif = (spec.get("verification_status") or "").strip().lower()
        iast_st = (spec.get("iast_state") or "").strip().lower()
        confirm_state = "confirmed" if _is_confirmed(verif, iast_st) else "unconfirmed"
        desired = {
            "family": spec.get("family") or "",
            "detect_state": detect_state,
            "confirm_state": confirm_state,
            "sink_reached": sink_reached,
            "verification_status": spec.get("verification_status") or "",
            "iast_state": spec.get("iast_state") or "",
            "finding_id": findings.get(vh),
            "trigger_spec_id": spec.get("id"),
            "iast_event_id": None,
            "instance_id": inst_by_vh.get(vh),
            "target_endpoint": spec.get("target_endpoint") or "",
            "http_method": spec.get("http_method") or "",
        }
        try:
            # 阶段三：乐观锁合并写入（并发安全），每次写入落 audit。
            write_blackboard_row(db, workspace_id, vh, int(run_id), task_id, desired, writer)
            n += 1
            n_sink += sink_reached
        except Exception as _e:
            logger.warning("[blackboard] 写黑板行失败 vhash=%s：%s", vh[:12], _e)
    logger.info("[blackboard] task=%s run=%s 黑板同步 %d 行（sink_reached=%d，到达 sink 的 canary %d 个）",
                task_id, run_id, n, n_sink, len(reached_canaries))
    return n


# ---------------------------------------------------------------------------
# 阶段三：并发读改写合并（乐观锁 + 按字段合并 + 审计）
# ---------------------------------------------------------------------------
# 黑板行「状态列」集合：合并时只动这些列，不动 id/version/时间戳等元数据。
_BLACKBOARD_STATE_COLS = (
    "family", "detect_state", "confirm_state", "sink_reached", "verification_status",
    "iast_state", "finding_id", "trigger_spec_id", "iast_event_id", "instance_id",
    "target_endpoint", "http_method",
)
# 乐观锁重试上限：正常竞争几次内即可收敛；超过即视为异常（绝不静默丢写）。
_MAX_OPTIMISTIC_RETRIES = 64


def _coalesce_desired(desired: Dict[str, Any]) -> Dict[str, Any]:
    """把调用方给的 desired 收拢成标准状态列集合，填补缺省值。"""
    return {
        "family": desired.get("family") or "",
        "detect_state": desired.get("detect_state") or "undetected",
        "confirm_state": desired.get("confirm_state") or "unconfirmed",
        "sink_reached": int(desired.get("sink_reached") or 0),
        "verification_status": desired.get("verification_status") or "",
        "iast_state": desired.get("iast_state") or "",
        "finding_id": desired.get("finding_id"),
        "trigger_spec_id": desired.get("trigger_spec_id"),
        "iast_event_id": desired.get("iast_event_id"),
        "instance_id": desired.get("instance_id"),
        "target_endpoint": desired.get("target_endpoint") or "",
        "http_method": desired.get("http_method") or "",
    }


def _merge_blackboard_state(current: Dict[str, Any], desired: Dict[str, Any]):
    """按合并语义算 merged，返回 (merged, changed)。

    合并规则（round-10-blackboard-plan.md 阶段三）：
    - detect_state / confirm_state：单调升级，永不降级（防并发回写冲掉已确认态）。
    - sink_reached：取 OR（任一到达即为 1）。
    - verification_status：强者胜（rank 高者覆盖）。
    - 其余列（family/iast_state/target_endpoint/http_method/各指针）：取非空，desired 优先。

    内部先对 desired 做 _coalesce_desired，确保任何调用方（含单测）传入 partial 也不会 KeyError。
    """
    desired = _coalesce_desired(desired)
    merged = dict(current)
    changed = False

    nd = _stronger(_DETECT_RANK, current.get("detect_state") or "undetected", desired["detect_state"])
    if nd != current.get("detect_state"):
        merged["detect_state"] = nd
        changed = True

    nc = _stronger(_CONFIRM_RANK, current.get("confirm_state") or "unconfirmed", desired["confirm_state"])
    if nc != current.get("confirm_state"):
        merged["confirm_state"] = nc
        changed = True

    if int(desired.get("sink_reached") or 0) and not int(current.get("sink_reached") or 0):
        merged["sink_reached"] = 1
        changed = True

    nv = _stronger(_VERIF_RANK, current.get("verification_status") or "", desired["verification_status"])
    if nv != current.get("verification_status"):
        merged["verification_status"] = nv
        changed = True

    for k in ("family", "iast_state", "target_endpoint", "http_method"):
        dv = desired.get(k) or ""
        if dv and dv != current.get(k):
            merged[k] = dv
            changed = True

    for k in ("finding_id", "trigger_spec_id", "iast_event_id", "instance_id"):
        dv = desired.get(k)
        cv = current.get(k)
        if dv and (cv in (None, 0, "", 0)):
            merged[k] = dv
            changed = True

    return merged, changed


def _state_snapshot(row: Any) -> Dict[str, Any]:
    """从整行/desired 中提取状态列快照，用于审计 before/after_json。"""
    if not isinstance(row, dict):
        return {}
    return {k: row.get(k) for k in _BLACKBOARD_STATE_COLS}


def _audit_blackboard_write(db, workspace_id, vhash, run_id, task_id, op, v_before, v_after,
                            before, after, writer, blackboard_id=None) -> None:
    """写一条黑板审计记录（best-effort，不阻断主流程）。"""
    try:
        db.execute(
            """
            INSERT INTO blackboard_entries_audit
            (workspace_id, vulnerability_hash_v2, run_id, task_id, blackboard_id, op,
             version_before, version_after, before_json, after_json, writer, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, vhash, int(run_id), int(task_id), blackboard_id, op,
             int(v_before), int(v_after),
             json.dumps(_state_snapshot(before), ensure_ascii=False),
             json.dumps(_state_snapshot(after), ensure_ascii=False),
             writer, _now()),
        )
    except Exception as _e:
        logger.warning("[blackboard] 写审计失败（不阻断）：%s", _e)


def write_blackboard_row(db, workspace_id: int, vhash: str, run_id: int, task_id: int,
                         desired: Dict[str, Any], writer: str) -> str:
    """并发安全的黑板行写入：乐观锁 + 按字段合并 + 审计落库。

    流程：
    - 读 current → 按 _merge_blackboard_state 算 merged；
    - 无变化：op=noop（仍记一条审计，version 不变）；
    - 有变化：UPDATE ... WHERE id=? AND version=?，影响行数 0 即被人抢先写过
      → 重读重算重试（最多 _MAX_OPTIMISTIC_RETRIES 次）；
    - 首行不存在：INSERT（op=insert），遇 UNIQUE 冲突说明并发已插入 → 下一轮读后合并。
    返回 op 字符串（insert/merge/noop）。乐观锁耗尽则抛 RuntimeError。
    """
    desired = _coalesce_desired(desired)
    now = _now()
    for _attempt in range(_MAX_OPTIMISTIC_RETRIES):
        cur = db.execute(
            "SELECT * FROM vuln_blackboard WHERE workspace_id=? AND vulnerability_hash_v2=? AND run_id=?",
            (workspace_id, vhash, int(run_id)), fetchone=True,
        )
        if cur is None:
            # 首行：尝试插入
            try:
                db.execute(
                    """
                    INSERT INTO vuln_blackboard
                    (workspace_id, vulnerability_hash_v2, run_id, task_id, family,
                     detect_state, confirm_state, sink_reached, verification_status, iast_state,
                     finding_id, trigger_spec_id, iast_event_id, instance_id,
                     target_endpoint, http_method, version, last_writer, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (workspace_id, vhash, int(run_id), int(task_id),
                     desired["family"], desired["detect_state"], desired["confirm_state"],
                     desired["sink_reached"], desired["verification_status"], desired["iast_state"],
                     desired["finding_id"], desired["trigger_spec_id"], desired["iast_event_id"],
                     desired["instance_id"], desired["target_endpoint"], desired["http_method"],
                     0, writer, now, now),
                )
                _audit_blackboard_write(db, workspace_id, vhash, run_id, task_id, "insert",
                                        0, 0, {}, desired, writer)
                return "insert"
            except sqlite3.IntegrityError:
                # 并发插入竞争失败，别人已插入；下一轮读后合并
                continue

        merged, changed = _merge_blackboard_state(cur, desired)
        if not changed:
            _audit_blackboard_write(db, workspace_id, vhash, run_id, task_id, "noop",
                                   cur["version"], cur["version"], cur, cur, writer,
                                   blackboard_id=cur.get("id"))
            return "noop"

        n = db.execute(
            """
            UPDATE vuln_blackboard
            SET family=?, detect_state=?, confirm_state=?, sink_reached=?,
                verification_status=?, iast_state=?, finding_id=?, trigger_spec_id=?,
                iast_event_id=?, instance_id=?, target_endpoint=?, http_method=?,
                version=version+1, last_writer=?, updated_at=?
            WHERE id=? AND version=?
            """,
            (merged["family"], merged["detect_state"], merged["confirm_state"], merged["sink_reached"],
             merged["verification_status"], merged["iast_state"], merged["finding_id"],
             merged["trigger_spec_id"], merged["iast_event_id"], merged["instance_id"],
             merged["target_endpoint"], merged["http_method"],
             writer, now, cur["id"], cur["version"]),
            return_rowcount=True,
        )
        if int(n or 0) >= 1:
            _audit_blackboard_write(db, workspace_id, vhash, run_id, task_id, "merge",
                                   cur["version"], cur["version"] + 1, cur, merged, writer,
                                   blackboard_id=cur.get("id"))
            return "merge"
        # 乐观锁失败：重读重算重试
    raise RuntimeError(
        f"blackboard 乐观锁重试耗尽 ws={workspace_id} vhash={str(vhash)[:12]} run={run_id} "
        f"task={task_id}（疑似持续高并发写冲突，请排查写入方）"
    )


def repair_summary_snapshot(db, task_id: int, run_id: Optional[int] = None) -> Dict[str, Any]:
    """把 scan_tasks.summary_json 里自存的展示快照对齐到黑板真值（铁律：展示计数从黑板派生）。

    成因：summary_json.stage_results.a2_poc.registered_trigger_specs 是扫描期写入的快照，
    与后续 DB 实表/黑板长期漂移，导致前端展示虚高。
    此处不删快照机制，仅在 --sync 后把快照值改写为当前真值，使展示与黑板一致。
    返回被改写的字段。
    """
    run_id = run_id or resolve_run_id(db, task_id)
    derived = derive_counts(db, task_id, run_id)
    try:
        row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=?", (task_id,), fetchone=True)
        if not row:
            return {}
        summary = json.loads(row["summary_json"] or "{}")
    except Exception:
        return {}
    changed = {}
    try:
        sr = summary.setdefault("stage_results", {})
        a2 = sr.setdefault("a2_poc", {})
        old = a2.get("registered_trigger_specs")
        new = derived["confirmed"]
        if old != new:
            a2["registered_trigger_specs"] = new
            changed["a2_poc.registered_trigger_specs"] = {"from": old, "to": new}
        # D2 阶段计数也对齐黑板派生（true 口径）
        d2 = sr.setdefault("d2", {})
        for key in ("confirmed_exploitable", "sink_reached", "verified"):
            cur = d2.get(key)
            val = derived.get(key) if key != "confirmed_exploitable" else derived.get("verified")
            if cur != val:
                d2[key] = val
                changed[f"d2.{key}"] = {"from": cur, "to": val}
        # 黑板计数对齐（铁律：前端展示从黑板派生，必须覆盖 summary 快照，
        # 杜绝 detected==confirmed 漂移 / 孤儿行虚高）。derive_counts 已是当前真值。
        bb = sr.get("blackboard")
        if isinstance(bb, dict):
            if bb.get("counts") != derived:
                bb["counts"] = derived
                changed["blackboard.counts"] = {"from": bb.get("counts"), "to": derived}
        elif bb is None:
            sr["blackboard"] = {"counts": derived}
            changed["blackboard.counts"] = {"from": None, "to": derived}
        db.execute(
            "UPDATE scan_tasks SET summary_json=? WHERE id=?",
            (json.dumps(summary, ensure_ascii=False), task_id),
        )
    except Exception as _e:
        logger.warning("[blackboard] repair_summary_snapshot 失败（不阻断）：%s", _e)
        return {}
    return changed


def derive_counts(db, task_id: int, run_id: Optional[int] = None) -> Dict[str, int]:
    """从黑板派生展示计数（唯一真相源）。禁止各处自存快照。

    - confirmed：D2 验证可利用 或 IAST sink 到达（强证据档）；
    - suspicious：已检出但未达确认判据（弱证据档 = detected - confirmed），
      含 verification_status=provisional / no_evidence / 未知族等；
    - provisional：verification_status=provisional 的行数（suspicious 的子集信号）。
    """
    run_id = run_id or resolve_run_id(db, task_id)
    out = {
        "run_id": run_id or 0,
        "blackboard_rows": 0,
        "detected": 0,
        "confirmed": 0,
        "sink_reached": 0,
        "verified": 0,
        "suspicious": 0,
        "provisional": 0,
    }
    if not run_id:
        return out
    try:
        row = db.execute(
            """
            SELECT COUNT(*) AS n,
                   SUM(CASE WHEN detect_state='detected' THEN 1 ELSE 0 END) AS detected,
                   SUM(CASE WHEN confirm_state='confirmed' THEN 1 ELSE 0 END) AS confirmed,
                   SUM(CASE WHEN sink_reached=1 THEN 1 ELSE 0 END) AS sink_reached,
                   SUM(CASE WHEN verification_status IN ('confirmed_exploitable','exploitable') THEN 1 ELSE 0 END) AS verified,
                   SUM(CASE WHEN verification_status='provisional' THEN 1 ELSE 0 END) AS provisional
            FROM vuln_blackboard WHERE task_id=? AND run_id=?
            """,
            (task_id, run_id), fetchone=True,
        )
        if row:
            detected = int(row["detected"] or 0)
            confirmed = int(row["confirmed"] or 0)
            out.update({
                "blackboard_rows": int(row["n"] or 0),
                "detected": detected,
                "confirmed": confirmed,
                "sink_reached": int(row["sink_reached"] or 0),
                "verified": int(row["verified"] or 0),
                "suspicious": max(0, detected - confirmed),
                "provisional": int(row["provisional"] or 0),
            })
    except Exception as _e:
        logger.warning("[blackboard] derive_counts 失败：%s", _e)
    return out


# ---------------------------------------------------------------------------
# 阶段一：跨 run 最强态 load（让黑板事前可读，而非仅事后对账）
# ---------------------------------------------------------------------------
# detect_state / confirm_state 单调升级序；verification_status 强者胜序。
_DETECT_RANK = {"undetected": 0, "detected": 1}
_CONFIRM_RANK = {"unconfirmed": 0, "confirmed": 1}
_VERIF_RANK = {"": 0, "no_evidence": 0, "invalidated": 0, "provisional": 1, "exploitable": 2, "confirmed": 3, "confirmed_exploitable": 3,
                "confirmed_code_property": 3}
# 见 src/iast/target_epoch.py）。rank 取 0：它既不是确认也不是否证，绝不能压过任何真实
# 结论（跨 run 合并仍保留历史 run 的最强态）。


def _stronger(rank_map: Dict[str, int], a: str, b: str) -> str:
    return a if rank_map.get(a, 0) >= rank_map.get(b, 0) else b


def _is_confirmed(verification_status: str, iast_state: str) -> bool:
    """F4 修复：黑板 confirm_state 的唯一权威来源（确认判据）。

    只有满足以下任一才计为 confirmed：
    - D2 验证进入确认态：verification_status ∈ {confirmed_exploitable, exploitable}
    - IAST 运行时证据：iast_state 含 sink-reached（canary 真正到达 sink）
    仅「存在 trigger_spec（待重放假说）」不算确认——这是旧实现的 bug 根源
    （把候选攻击面直接当已确认，导致 detected==confirmed 无任何区分力）。
    """
    vs = (verification_status or "").strip().lower()
    if vs in ("confirmed_exploitable", "exploitable"):
        return True
    return is_sink_reached((iast_state or "").strip().lower())


def load(db, workspace_id: int, vhash_set) -> Dict[str, Dict[str, Any]]:
    """跨**所有历史 run** 取每 vhash 的「最强态」。

    合并规则（来自 round-10-blackboard-plan.md 阶段一）：
    - detect_state / confirm_state：单调升级（detected > undetected；confirmed > unconfirmed），永不降级。
    - sink_reached：取 OR，任一 run 到达即为 1。
    - verification_status：强者胜（confirmed_exploitable == confirmed > exploitable > provisional > no_evidence）。

    返回 dict：{vhash: {detect_state, confirm_state, sink_reached, verification_status,
    iast_state, family, run_ids:[...]}}。
    仅含 vhash_set 中确实存在于黑板的历史 vhash；集合外的 vhash 绝不出现（缺失即无历史经验）。

    注意：本函数只读、不改库，也不影响任何阶段行为；真正「跳过重复重放」等接线属于阶段三前的
    预读动作，不在本函数职责内（避免改变基线行为）。
    """
    if not vhash_set:
        return {}
    vhash_list = [str(v) for v in vhash_set if v]
    if not vhash_list:
        return {}
    ph = ",".join("?" * len(vhash_list))
    try:
        rows = db.execute(
            """
            SELECT vulnerability_hash_v2, detect_state, confirm_state, sink_reached,
                   verification_status, iast_state, family, run_id
            FROM vuln_blackboard
            WHERE workspace_id=? AND vulnerability_hash_v2 IN (%s)
            """ % ph,
            (workspace_id, *vhash_list), fetchall=True,
        ) or []
    except Exception as _e:
        logger.warning("[blackboard] load 失败（返回空）：%s", _e)
        return {}

    merged: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        vh = r["vulnerability_hash_v2"]
        cur = merged.setdefault(vh, {
            "detect_state": "undetected",
            "confirm_state": "unconfirmed",
            "sink_reached": 0,
            "verification_status": "no_evidence",
            "iast_state": "",
            "family": "",
            "run_ids": [],
        })
        cur["run_ids"].append(int(r["run_id"]) if r["run_id"] else 0)
        cur["detect_state"] = _stronger(_DETECT_RANK, cur["detect_state"], r["detect_state"] or "undetected")
        cur["confirm_state"] = _stronger(_CONFIRM_RANK, cur["confirm_state"], r["confirm_state"] or "unconfirmed")
        # sink_reached 取 OR
        if r["sink_reached"]:
            cur["sink_reached"] = 1
        # verification_status 强者胜
        cur["verification_status"] = _stronger(
            _VERIF_RANK, cur["verification_status"], r["verification_status"] or "no_evidence"
        )
        if r["iast_state"]:
            cur["iast_state"] = r["iast_state"]
        if r["family"]:
            cur["family"] = r["family"]
    return merged


# ---------------------------------------------------------------------------
# 一致性自检
# ---------------------------------------------------------------------------
def consistency_check(db, task_id: int, run_id: Optional[int] = None, auto_fix: bool = True) -> Dict[str, Any]:
    """每轮结束的一致性自检：DB 实表 vs 黑板派生 vs 前端展示快照。

    三者必须一致；不一致直接以 alerts 报出（不再靠事后 reconcile 补丁）。

    自愈（auto_fix=True，默认）：黑板是「单一真相源」，其派生计数必须实时反映当前
    DB 实表（findings / trigger_specs / iast_events）状态。spec 会在落库后被
    reconcile_orphan_specs / second_pass 等路径裁剪或回灌，若黑板未随之重算就会残留
    对齐前端快照，使自检结果恒为「当前真相」而非「某次同步时的快照」。
    auto_fix=False 时退化为纯校验（不改库），供需要区分「漂移」与「真不一致」的场景。
    """
    run_id = run_id or resolve_run_id(db, task_id)
    if auto_fix and run_id is not None:
        try:
            sync_blackboard(db, task_id, run_id)
            repair_summary_snapshot(db, task_id, run_id)
        except Exception as _e:
            logger.warning("[blackboard] 一致性自检自愈（重算黑板/对齐快照）失败（不阻断）：%s", _e)
    alerts: List[str] = []
    result: Dict[str, Any] = {"task_id": task_id, "run_id": run_id, "alerts": alerts}

    def _scalar(sql: str, args: tuple) -> int:
        try:
            r = db.execute(sql, args, fetchone=True)
            return int(list(r.values())[0]) if r else 0
        except Exception:
            return -1

    db_specs = _scalar("SELECT COUNT(*) FROM trigger_specs WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict, 0) = 0", (task_id,))
    db_confirmed_spec_vh = _scalar(
        "SELECT COUNT(DISTINCT vulnerability_hash_v2) FROM trigger_specs WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict, 0) = 0 "
        "AND (verification_status IN ('confirmed_exploitable','exploitable') "
        "OR iast_state LIKE '%sink-reached%')", (task_id,))
    db_findings = _scalar("SELECT COUNT(*) FROM findings WHERE task_id=? AND id NOT IN (SELECT finding_id FROM trigger_specs WHERE COALESCE(suppressed_by_safe_verdict, 0) = 1 AND finding_id > 0)", (task_id,))
    derived = derive_counts(db, task_id, run_id)

    # 前端展示：summary_json 里的 stage_results 快照（a2_poc.registered_trigger_specs 等）
    snap_specs = None
    try:
        row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=?", (task_id,), fetchone=True)
        if row:
            summary = json.loads(row["summary_json"] or "{}")
            snap = ((summary.get("stage_results") or {}).get("a2_poc") or {})
            snap_specs = snap.get("registered_trigger_specs")
    except Exception:
        snap_specs = None

    result.update({
        "db_trigger_specs": db_specs,
        "db_confirmed_spec_vhashes": db_confirmed_spec_vh,
        "db_findings": db_findings,
        "blackboard": derived,
        "snapshot_registered": snap_specs,
    })

    # （旧实现 confirmed==spec 数导致 detected==confirmed 无区分力）。
    if db_confirmed_spec_vh >= 0 and derived["confirmed"] >= 0 and db_confirmed_spec_vh != derived["confirmed"]:
        alerts.append(
            f"真实确认 spec vhash({db_confirmed_spec_vh}) != 黑板 confirmed({derived['confirmed']})："
            "黑板 confirm_state 未对齐 D2/IAST 确认判据（可先 --sync 再校验）"
        )
    if derived["confirmed"] > derived["detected"]:
        alerts.append(
            f"黑板 confirmed({derived['confirmed']}) > detected({derived['detected']})：漏斗倒置，"
            "confirm_state 计算错误（疑似孤儿行未清理）"
        )
    if derived["sink_reached"] > derived["confirmed"]:
        alerts.append(
            f"黑板 sink_reached({derived['sink_reached']}) > confirmed({derived['confirmed']})：漏斗倒置"
        )
    if snap_specs is not None and derived["confirmed"] >= 0 and int(snap_specs) != derived["confirmed"]:
        alerts.append(
            f"前端快照 registered({snap_specs}) != 黑板 confirmed({derived['confirmed']})：展示计数应从黑板派生"
        )
    if db_specs > 0 and derived["sink_reached"] == 0:
        alerts.append(
            f"本轮 spec 共 {db_specs} 条但 sink_reached=0：canary 未到达 sink，"
            "D2 确认数将被判定侧锁死（优先排查探针/重放侧）"
        )
    result["ok"] = not alerts
    if alerts:
        logger.warning("[blackboard] 一致性自检 task=%s 发现 %d 处不一致：%s", task_id, len(alerts), alerts)
    return result
