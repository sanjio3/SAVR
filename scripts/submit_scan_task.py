"""幂等地提交扫描任务（REST POST /api/scan-tasks）。

调用方误以为请求失败于是重发，结果同一批任务被建了两遍（同一 name 出现两组重复任务）。
两组任务并发打同一靶机，d2 阶段从 10~20 分钟拖到近两小时，基线样本被污染。

本脚本的幂等约定：
  1. 提交前先查 scan_tasks 里是否已存在同名任务；
  2. 若同名任务处于非终态（pending/queued/running），直接复用，不重复创建；
  3. 若同名任务已终态（completed/failed），默认仍复用（视为同一轮），除非 --force-new；
  4. 只有在真正 POST 成功、拿到 id 之后才打印结果——避免"响应已生效但后续代码报错"导致的重复提交。

用法：
    python scripts/submit_scan_task.py --dry-run --name X      # 只打印将要提交的内容
"""
import argparse
import json
import os
import sqlite3
import sys
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:8000/api/scan-tasks"
DB = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
TERMINAL = ("completed", "failed")
NON_TERMINAL = ("pending", "queued", "running")

# 有 created_at 的表必须带时间截止（created_at < now）防误杀本轮新行；
# sca_components 无 created_at 列，只能在「提交前」这一时点整按 task_id 清（此刻不可能有本轮新行）。
_RESIDUE_TABLES = [
    ("trigger_specs", True),
    ("model_runs", True),
    ("hypotheses", True),
    ("vuln_blackboard", True),
    ("blackboard_audit", True),
    ("scan_task_events", True),
    ("scan_runs", True),
    ("iast_events", True),
    ("sca_components", False),
    ("sca_scans", True),
]


def _table_has_column(con, table: str, column: str) -> bool:
    cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    return column in cols


def _next_task_id(con) -> int:
    """预测下一次 INSERT 会拿到的 task id：优先 sqlite_sequence（AUTOINCREMENT），回落 MAX(id)+1。"""
    try:
        row = con.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='scan_tasks'").fetchone()
        if row and row[0]:
            return int(row[0]) + 1
    except Exception:
        pass
    row = con.execute("SELECT COALESCE(MAX(id),0)+1 FROM scan_tasks").fetchone()
    return int(row[0]) if row else 1


def preflight_stale_task_id(db_path: str, backup_dir: str = "") -> dict:
    """提交前预检：预测的下一个 task_id 在子表里若有残留行（scan_tasks 已无对应任务），
    按时间截止清理并隔离备份。返回 {task_id, cleaned: {table: n}, skipped, backup}。

    安全闸：
    1. scan_tasks 里若仍存在该 id 的行（并发提交竞态）→ 跳过清理，只报警；
    2. 有 created_at 的表一律 DELETE ... AND created_at < now（UTC）；
    3. 删除前行集写入隔离备份 JSON（quarantine）。
    """
    import datetime
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        next_id = _next_task_id(con)
        out = {"task_id": next_id, "cleaned": {}, "skipped": "", "backup": ""}
        exists = con.execute("SELECT 1 FROM scan_tasks WHERE id=?", (next_id,)).fetchone()
        if exists:
            out["skipped"] = f"scan_tasks 已存在 id={next_id} 的行（竞态或非自增），跳过清理"
            return out
        now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        residue = {}
        for table, has_ts in _RESIDUE_TABLES:
            try:
                if not _table_has_column(con, table, "task_id"):
                    continue
                ts_col = has_ts and _table_has_column(con, table, "created_at")
                cond = "task_id=? AND created_at < ?" if ts_col else "task_id=?"
                params = (next_id, now_utc) if ts_col else (next_id,)
                n = con.execute(f"SELECT COUNT(*) FROM {table} WHERE {cond}", params).fetchone()[0]
                if n:
                    residue[table] = (n, ts_col, params)
            except Exception as e:
                print(f"[preflight] 检查 {table} 失败（跳过）：{e}", file=sys.stderr)
        if not residue:
            return out
        total = sum(n for n, _, _ in residue.values())
        print(f"[preflight] 发现 task_id={next_id} 残留行 {total} 条（scan_tasks 无对应任务），"
              f"隔离备份后按时间截止清理…")
        if backup_dir:
            bdir = Path(backup_dir)
            bdir.mkdir(parents=True, exist_ok=True)
            backup = {"task_id": next_id, "captured_at_utc": now_utc, "tables": {}}
            for table, (n, ts_col, params) in residue.items():
                cond = "task_id=? AND created_at < ?" if ts_col else "task_id=?"
                rows = con.execute(f"SELECT * FROM {table} WHERE {cond}", params).fetchall()
                backup["tables"][table] = [dict(r) for r in rows]
            bpath = bdir / f"stale_taskid_{next_id}_{datetime.datetime.utcnow():%Y%m%d_%H%M%S}.json"
            bpath.write_text(json.dumps(backup, ensure_ascii=False, default=str), encoding="utf-8")
            out["backup"] = str(bpath)
            print(f"[preflight] 隔离备份：{bpath}")
        for table, (n, ts_col, params) in residue.items():
            cond = "task_id=? AND created_at < ?" if ts_col else "task_id=?"
            con.execute(f"DELETE FROM {table} WHERE {cond}", params)
        con.commit()
        out["cleaned"] = {t: n for t, (n, _, _) in residue.items()}
        print(f"[preflight] 清理完成：{out['cleaned']}")
        return out
    finally:
        con.close()


def canonical_payload(name: str, workspace_id: int = 1, idor_app_id: str = "") -> dict:
    """构造一次扫描任务的默认提交参数。"""
    return {
        "workspace_id": workspace_id,
        "name": name,
        "enable_a1": True,
        "enable_a2": True,
        "enable_verification": True,
        "enable_sca": True,
        "enable_ai_review": True,
        "enable_idor": True,
        "idor_app_id": idor_app_id,
        "enable_entry_discovery": True,
        "scan_mode": "filter_first",
        "model_profile": "default",
        "prompt_version": "terminal-first-v1",
        "sca_tool": "auto",
        "sca_severity_threshold": "LOW",
        "sca_ignore_unfixed": False,
        "output_format": "both",
        "approval_mode": "off",
        "tool_allowlist": [],
    }


def find_existing(name: str):
    try:
        con = sqlite3.connect(DB)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, name, status, phase FROM scan_tasks WHERE name=? ORDER BY id", (name,)
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception as e:  # 库不可读时不阻断提交，退回"未发现"
        print(f"[warn] 查询既有任务失败（按未发现处理）：{e}", file=sys.stderr)
        return []


def post(payload: dict, timeout: int = 30) -> dict:
    """POST 并**立即**返回解析后的响应；任何解析/后续处理都在拿到 id 之后进行。"""
    req = urllib.request.Request(
        API, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    global DB
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="任务名（幂等键）")
    ap.add_argument("--force-new", action="store_true",
                    help="同名任务即使存在也强制新建（会产生并行任务，慎用）")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--db", default=DB)
    ap.add_argument("--workspace-id", type=int, default=1,
                    help="工作区 id（在 SAVR 中注册的工作区）")
    ap.add_argument("--idor-app-id", default="",
                    help="IDOR 应用标识（可选，须与 workspace_id 对应）")
    ap.add_argument("--no-verification", action="store_true",
                    help="关闭 D2 动态验证（无运行实例时使用）")
    ap.add_argument("--no-sca", action="store_true",
                    help="关闭 SCA")
    ap.add_argument("--no-idor", action="store_true",
                    help="关闭 IDOR（无鉴权面时使用）")
    ap.add_argument("--shard", default="",
                    help="分片清单 JSON 路径；不传即全量扫描")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="跳过提交前 task_id 残留预检")
    ap.add_argument("--preflight-backup-dir", default=".SAVR/quarantine",
                    help="残留行隔离备份目录")
    ap.add_argument("--env", action="append", default=[],
                    help="任务级环境开关（可多次）：KEY=VALUE。写入 options_json.run_env，"
                         "由 scan_task_runner 启动时注入子进程")
    args = ap.parse_args()

    DB = args.db
    # A dry run writes nothing, so the stale-task-id preflight (which may also
    # move rows into a backup) must not run for it.
    if not args.skip_preflight and not args.dry_run:
        try:
            preflight_stale_task_id(DB, args.preflight_backup_dir)
        except Exception as e:
            print(f"[preflight] 预检失败（不阻断提交，可人工排查）：{e}", file=sys.stderr)
    payload = canonical_payload(args.name, args.workspace_id, args.idor_app_id)
    # 任务级环境开关由 --env 显式提供，不预置任何目标相关的默认值。
    _run_env = {}
    for _kv in (args.env or []):
        if "=" in _kv:
            _k, _v = _kv.split("=", 1)
            _run_env[_k.strip()] = _v.strip()
        else:
            print("[warn] --env 需要 KEY=VALUE 形式，忽略：%r" % _kv)
    payload["run_env"] = _run_env
    if args.no_verification:
        payload["enable_verification"] = False
    if args.no_sca:
        payload["enable_sca"] = False
    if args.no_idor:
        payload["enable_idor"] = False
    if args.shard:
        payload["shard_file"] = str(args.shard).strip()
        if not os.path.isfile(payload["shard_file"]):
            print(f"[shard] 分片清单不存在：{payload['shard_file']}", file=sys.stderr)
            return 2

    if args.dry_run:
        print("[dry-run] 将提交：")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if not args.force_new:
        existing = find_existing(args.name)
        live = [e for e in existing if e["status"] in NON_TERMINAL]
        if live:
            print(f"[idempotent] 同名任务已在运行，复用不重复提交："
                  f"task_id={live[0]['id']} status={live[0]['status']}")
            return 0
        if existing:
            print(f"[idempotent] 同名任务已存在且已终态，复用："
                  f"task_id={existing[0]['id']} status={existing[0]['status']}"
                  f"（如需重跑加 --force-new）")
            return 0

    # 关键：先拿到响应，再打印。绝不在拿到 id 前做可能抛异常的操作。
    resp = post(payload)
    task_id = resp.get("id")
    print(f"created task_id={task_id} status={resp.get('status')} "
          f"phase={resp.get('phase')} name={resp.get('name')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
