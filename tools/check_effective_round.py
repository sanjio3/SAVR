"""按 Gate 0「有效轮硬条件」判定一轮扫描能不能计入验收。

背景（docs/gate0_release_criteria.md G0-1）：A2 若因 LLM 不可用丢了文件，四档会
表现为「掉点」，很容易被误读成泛化退化。因此任一 round 必须先过有效轮判据，
再看红线 / 重放 / gap。判据是 fail-closed 的：字段缺失也判无效。

判据（全部满足才算有效）：
  1. task status == completed；
  2. stage_results.a2.contract 存在，且含 transport 与 file_failures；
  3. transport.exhausted == 0；
  4. transport.generation_timeouts == 0；
  5. transport.circuit_broken == 0；
  6. file_failures.failed_files == 0；
  7. transport.truncated 字段存在（可观测性要求，不要求为 0）；
  8. 重放层环境一致（见下）。

重放层环境一致性（2026-11-08，本轮复盘）：640 的 A2 contract 与
637 / 639 逐字节一致，但扫描中途 8080 被另一个 Spring Boot 实例接管，
393 条请求落到异构 404 错误体（epoch + iso 两种格式），IAST 事件 -21%，
最终 ssrf.java/ssrf 少 2 条 oracle:error_reflect 确认、重放掉 1 点。只查
A2 contract 会把被污染轮判成有效，进而把环境干扰误读成稳定性退化。
硬条件：404 率 <= 10%、404 端点 <= 4 个、Spring 错误体格式 <= 1 种、
IAST 事件 > 0、认证态请求占比 >= 90%。阈值由 634/635/637/638/639 实测
（404 1.8~2.2%，2~3 端点，单一 epoch，认证 99.5%）与 640（18.3%，20 端点，
epoch+iso）分离得出；盲化轮 638 同样通过，不需要单独豁免。

`truncated` 只作为 warning，不否决轮次。原因：它表示某次调用被 num_predict
硬闸截断，但解析层仍可能保留可用结果；准确性底线由「文件是否丢失 /
调用是否失败」承担。本轮实测截断落在 ClassDataLoader.java，该文件在
之前一直被 180s 超时静默丢弃，而 634 在完全失去它的情况下仍达到
红线 0/62、重放 24/24。带 warning 的轮次必须在对账文档里逐个列出被截断
文件、是否为真值点、是否影响四档分母。

用法：
  python tools/check_effective_round.py --task-id 636
  python tools/check_effective_round.py --task-id 640 --json
  python tools/check_effective_round.py --progress path/to/scan_progress.json --json
  python tools/check_effective_round.py --task-id 631 --no-replay-env  # 仅历史对照

退出码：0 = 有效；2 = 无效（含不可验证）；3 = 读取/参数错误。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "app.db")

# Gate 0 有效轮硬条件：这些键必须为 0
ZERO_MAX_KEYS = ("exhausted", "generation_timeouts", "circuit_broken")
# 必须存在但允许非零：可观测性要求，非零只产生 warning
REQUIRED_OBSERVABILITY_KEYS = ("truncated",)

# 重放层环境一致性阈值（实测分离依据见模块注释）
# 2026-11-08（L2 本轮）：404 率在不同靶场**不可比**，必须按 workspace 分档。
# jsc 的路由是 /sqli、/xss 这类单段语义路由，404 率天然低（1.8~2.2%）；
# RuoYi 是多段业务路由，且 A2 会从工具类的方法名脑补出不存在的路由
# （exportExcel / loadYaml / address / upload / nameUUIDFromBytes），
# 645 实测 1043 次重放里 138 次 404 全部落在 5 个「应用里根本没有」的路由上，
# 0 次触及 6 条真值点。把 jsc 的 10% 直接套过来只会量出「路由推断质量」，
# 不是这个检查要抓的「靶场身份变了」。
# 负控：640（jsc 上的抢占轮）在新分档下仍然 INVALID —— ratio 18.3% > 10%、
# endpoints 20 > 4、error_body_shapes 2 > 1，三条同时命中。
REPLAY_PROFILES = {
    4: {"name": "jsc", "max_not_found_ratio": 0.10, "max_not_found_endpoints": 4},
    8: {"name": "ruoyi", "max_not_found_ratio": 0.20, "max_not_found_endpoints": 8},
}
REPLAY_DEFAULT_PROFILE = {"name": "default", "max_not_found_ratio": 0.10,
                          "max_not_found_endpoints": 4}
REPLAY_MAX_ERROR_BODY_SHAPES = 1
REPLAY_MIN_AUTHENTICATED_RATIO = 0.90


def replay_profile(workspace_id) -> dict:
    """按 workspace 取重放层阈值；未登记的目标用默认（jsc 档），fail-closed。"""
    try:
        return REPLAY_PROFILES.get(int(workspace_id), REPLAY_DEFAULT_PROFILE)
    except (TypeError, ValueError):
        return REPLAY_DEFAULT_PROFILE


def _json_loads(raw, default=None):
    if not raw:
        return {} if default is None else default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {} if default is None else default


def _contract_from_db(task_id: int, db_path: str = DB) -> dict:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute(
            "SELECT id, name, status, phase, error_message, summary_json, output_dir "
            "FROM scan_tasks WHERE id=?", (task_id,)).fetchone()
    finally:
        con.close()
    if not row:
        raise ValueError("task_id=%d 不存在" % task_id)
    d = dict(row)
    summary = _json_loads(d.get("summary_json"))
    contract = ((summary.get("stage_results") or {}).get("a2") or {}).get("contract") or {}
    out_dir = os.path.join(ROOT, str(d.get("output_dir") or "").replace("\\", os.sep))
    # summary_json 是终态权威；未落库时退回 scan_progress.json（运行中/异常收尾的轮次）
    if not contract and os.path.isfile(os.path.join(out_dir, "scan_progress.json")):
        with open(os.path.join(out_dir, "scan_progress.json"), encoding="utf-8") as fh:
            prog = json.load(fh)
        contract = ((prog.get("stage_results") or {}).get("a2") or {}).get("contract") or {}
    d["contract"] = contract
    d.pop("summary_json", None)
    return d


def _contract_from_progress(path: str) -> dict:
    if not os.path.isfile(path):
        raise ValueError("进度文件不存在：%s" % path)
    with open(path, encoding="utf-8") as fh:
        prog = json.load(fh)
    return {
        "id": os.path.basename(os.path.dirname(path)),
        "name": os.path.basename(os.path.dirname(path)),
        "status": "unknown",
        "phase": "",
        "error_message": "",
        "contract": ((prog.get("stage_results") or {}).get("a2") or {}).get("contract") or {},
    }


def _error_body_shape(body: str) -> str:
    """识别 Spring Boot 404 错误体代际：epoch 数字时间戳 vs ISO 8601。

    同一轮同时出现两种代际，说明 8080 上不止一个应用实例在应答（本轮
    的 epoch 35 条来自 java-sec-code，iso 393 条来自中途抢占端口的另一实例）。
    """
    b = body or ""
    if '"timestamp":"' in b:
        return "iso"
    if '"timestamp":' in b:
        tail = b.split('"timestamp":', 1)[1] or " "
        if re.match(r"\s*\d", tail):
            return "epoch"
    return "other"


def replay_env_stats(db_path: str, task_id: int) -> dict:
    """从 replay_attempts / iast_events 抽取重放层靶场指纹；fail-closed。"""
    if not os.path.isfile(db_path):
        return {"available": False, "reason": "db missing: %s" % db_path}
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        names = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "replay_attempts" not in names:
            return {"available": False, "reason": "replay_attempts table missing"}
        rows = con.execute(
            "SELECT status_code, target_endpoint, resp_body_head, action_json "
            "FROM replay_attempts WHERE task_id=?", (task_id,)).fetchall()
        if not rows:
            return {"available": False, "reason": "no replay_attempts for task %d" % task_id}
        not_found = [r for r in rows if r["status_code"] == 404]
        shapes = sorted({_error_body_shape(r["resp_body_head"]) for r in not_found}
                        - {"other"})
        auth_ok = 0
        for r in rows:
            try:
                state = json.loads(r["action_json"] or "{}").get("auth_state")
                if state in ("authenticated", "reauthed"):
                    auth_ok += 1
            except (TypeError, ValueError):
                pass
        iast = 0
        if "iast_events" in names:
            iast = con.execute(
                "SELECT count(*) FROM iast_events WHERE task_id=?",
                (task_id,)).fetchone()[0]
        workspace_id = None
        if "scan_tasks" in names:
            row = con.execute(
                "SELECT workspace_id FROM scan_tasks WHERE id=?", (task_id,)).fetchone()
            workspace_id = row[0] if row else None
        ep_counts: dict = {}
        for r in not_found:
            ep = r["target_endpoint"]
            ep_counts[ep] = ep_counts.get(ep, 0) + 1
        top_eps = sorted(ep_counts.items(), key=lambda kv: -kv[1])[:5]
        return {
            "available": True,
            "workspace_id": workspace_id,
            "attempts": len(rows),
            "not_found": len(not_found),
            "not_found_ratio": round(len(not_found) / len(rows), 4),
            "not_found_endpoints": len(ep_counts),
            "not_found_endpoint_top": top_eps,
            "error_body_shapes": shapes,
            "other_error_bodies": sum(
                1 for r in not_found if _error_body_shape(r["resp_body_head"]) == "other"),
            "iast_events": iast,
            "authenticated_ratio": round(auth_ok / len(rows), 4),
        }
    finally:
        con.close()


def evaluate(info: dict) -> dict:
    """返回判定结果；fail-closed：任何字段缺失都算不可验证。"""
    checks = []
    status = str(info.get("status") or "")
    checks.append({
        "name": "task_completed",
        "ok": status == "completed",
        "detail": "status=%s" % (status or "?"),
    })

    contract = info.get("contract") or {}
    transport = contract.get("transport")
    failures = contract.get("file_failures")
    has_payload = isinstance(transport, dict) and isinstance(failures, dict)
    checks.append({
        "name": "a2_contract_has_transport_and_file_failures",
        "ok": has_payload,
        "detail": ("contract 存在" if contract else "contract 缺失") +
                  ("；transport/file_failures 齐备" if has_payload
                   else "；缺 transport 或 file_failures（修复前轮次不可验证）"),
    })

    transport = transport if isinstance(transport, dict) else {}
    failures = failures if isinstance(failures, dict) else {}
    for key in ZERO_MAX_KEYS:
        val = transport.get(key)
        checks.append({
            "name": "transport.%s == 0" % key,
            "ok": isinstance(val, (int, float)) and val == 0,
            "detail": "实测 %s" % ("缺失" if val is None else val),
        })
    warnings = []
    for key in REQUIRED_OBSERVABILITY_KEYS:
        val = transport.get(key)
        present = isinstance(val, (int, float))
        checks.append({
            "name": "transport.%s present (observability)" % key,
            "ok": present,
            "detail": "实测 %s" % ("缺失" if val is None else val),
        })
        if present and val > 0:
            warnings.append(
                "transport.%s=%d：本轮有调用被生成硬闸截断，对账文档须逐个列出"
                "被截断文件、是否为真值点、是否影响四档分母" % (key, val))
    failed_files = failures.get("failed_files")
    checks.append({
        "name": "file_failures.failed_files == 0",
        "ok": isinstance(failed_files, (int, float)) and failed_files == 0,
        "detail": "实测 %s" % ("缺失" if failed_files is None else failed_files),
    })

    # info 带 replay_env 才检查（--progress / 历史对照可显式豁免），
    # CLI 的 --task-id 路径必须提供，缺失或不可读同样 fail-closed。
    replay_env = info.get("replay_env")
    if replay_env is not None:
        re_ = replay_env if isinstance(replay_env, dict) else {}
        checks.append({
            "name": "replay_env.available",
            "ok": re_.get("available") is True,
            "detail": re_.get("reason") or ("attempts=%s" % re_.get("attempts", "?")),
        })
        prof = replay_profile(re_.get("workspace_id"))
        info["replay_profile"] = prof
        max_ratio = prof["max_not_found_ratio"]
        max_eps = prof["max_not_found_endpoints"]
        ratio = re_.get("not_found_ratio")
        checks.append({
            "name": "replay_env.not_found_ratio <= %.2f [%s]" % (max_ratio, prof["name"]),
            "ok": isinstance(ratio, (int, float)) and ratio <= max_ratio,
            "detail": "实测 %s" % ("缺失" if ratio is None else "%.1f%%" % (100 * ratio)),
        })
        eps = re_.get("not_found_endpoints")
        checks.append({
            "name": "replay_env.not_found_endpoints <= %d [%s]" % (max_eps, prof["name"]),
            "ok": isinstance(eps, int) and eps <= max_eps,
            "detail": "实测 %s%s" % ("缺失" if eps is None else eps,
                                     "" if not re_.get("not_found_endpoint_top") else
                                     " " + ", ".join("%s×%d" % (str(k).rsplit("/", 1)[-1], v)
                                                     for k, v in re_["not_found_endpoint_top"][:3])),
        })
        shapes = re_.get("error_body_shapes")
        checks.append({
            "name": "replay_env.error_body_shapes <= %d" % REPLAY_MAX_ERROR_BODY_SHAPES,
            "ok": isinstance(shapes, list) and len(shapes) <= REPLAY_MAX_ERROR_BODY_SHAPES,
            "detail": "实测 %s" % (shapes if isinstance(shapes, list) else "缺失"),
        })
        iast = re_.get("iast_events")
        checks.append({
            "name": "replay_env.iast_events > 0",
            "ok": isinstance(iast, int) and iast > 0,
            "detail": "实测 %s" % ("缺失" if iast is None else iast),
        })
        ar = re_.get("authenticated_ratio")
        checks.append({
            "name": "replay_env.authenticated_ratio >= %.2f" % REPLAY_MIN_AUTHENTICATED_RATIO,
            "ok": isinstance(ar, (int, float)) and ar >= REPLAY_MIN_AUTHENTICATED_RATIO,
            "detail": "实测 %s" % ("缺失" if ar is None else "%.1f%%" % (100 * ar)),
        })

    valid = all(c["ok"] for c in checks)
    return {
        "task_id": info.get("id"),
        "name": info.get("name"),
        "status": status,
        "error_message": info.get("error_message") or "",
        "effective": valid,
        "verdict": "EFFECTIVE" if valid else "INVALID",
        "warnings": warnings if valid else [],
        "checks": checks,
        "failed_checks": [c["name"] for c in checks if not c["ok"]],
        "contract": contract,
        "replay_env": replay_env,
        "replay_profile": info.get("replay_profile") or {},
        "check_replay_env": replay_env is not None,
        "replay_env_exempt": bool(info.get("replay_env_exempt")),
    }


def render(result: dict) -> str:
    lines = [
        "有效轮判定（Gate 0 G0-1 硬条件）",
        "  task %s  %s" % (result.get("task_id"), result.get("name") or ""),
        "  status: %s" % result.get("status"),
        "  结论: %s" % result["verdict"],
        "",
    ]
    for c in result["checks"]:
        lines.append("  [%s] %-52s %s" % ("OK" if c["ok"] else "NG", c["name"], c["detail"]))
    if result["error_message"]:
        lines += ["", "  task error_message: %s" % result["error_message"][:300]]
    re_ = result.get("replay_env") or {}
    if re_:
        if re_.get("available"):
            prof = result.get("replay_profile") or {}
            lines += ["", "  重放层环境指纹（#541）：404 %d/%d (%.1f%%)，%d 个端点，错误体 %s，"
                      "IAST %d，认证态 %.1f%%  [口径 %s]" % (
                          re_["not_found"], re_["attempts"],
                          100 * re_["not_found_ratio"], re_["not_found_endpoints"],
                          "+".join(re_["error_body_shapes"]) or "none",
                          re_["iast_events"], 100 * re_["authenticated_ratio"],
                          prof.get("name", "?"))]
            if re_.get("not_found_endpoint_top"):
                lines.append("    404 端点 top：%s" % ", ".join(
                    "%s×%d" % (k, v) for k, v in re_["not_found_endpoint_top"][:5]))
        else:
            lines += ["", "  重放层环境指纹（#541）：不可验证 - %s" % re_.get("reason")]
    elif result.get("replay_env_exempt"):
        lines += ["", "  [EXEMPT] 重放层环境检查已豁免，仅可用于历史对照，不得计入 Gate 0。"]
    for w in result.get("warnings") or []:
        lines += ["", "  [WARN] %s" % w]
    if not result["effective"]:
        lines += ["", "  -> 本轮不得计入 G0-2 / G0-3 验收；排查 A2 / Ollama / GPU / 靶场端口占用后重跑。"]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Gate 0 有效轮判定")
    ap.add_argument("--task-id", type=int, default=0)
    ap.add_argument("--progress", default="", help="直接读 scan_progress.json（不查库）")
    ap.add_argument("--db", default=DB, help="结果库路径（默认 data/app.db）")
    ap.add_argument("--no-replay-env", action="store_true",
                    help="跳过重放层环境检查；仅历史对照，不得用于 Gate 0 新轮次")
    ap.add_argument("--json", action="store_true", help="输出 JSON 而非文本")
    args = ap.parse_args(argv)

    if not args.task_id and not args.progress:
        ap.error("必须给 --task-id 或 --progress")
    try:
        info = (_contract_from_db(args.task_id, args.db) if args.task_id
                else _contract_from_progress(args.progress))
        if args.task_id:
            if args.no_replay_env:
                info["replay_env_exempt"] = True
            else:
                info["replay_env"] = replay_env_stats(args.db, args.task_id)
    except Exception as exc:  # noqa: BLE001
        print("[check-effective-round] 读取失败：%s" % exc, file=sys.stderr)
        return 3

    result = evaluate(info)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render(result))
    return 0 if result["effective"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
