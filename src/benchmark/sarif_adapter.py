"""SARIF 导出适配器（P-F 后半 · ①接线）。

把 `trigger_specs` 行转成 `src/benchmark/sarif_exporter.to_sarif` 需要的 vuln dict 形状，
供 benchmark_cli 的 reporting 阶段（写出 MD/JSON 后追加写 report.sarif.json）和
tools/_wb_* 脚本独立调用。

关键映射：
  verification_status -> verification_state
      confirmed_exploitable / confirmed_code_property / confirmed_sink_control -> "confirmed"
      其余（no_evidence / sink_reached / unconfirmed / no-iast-evidence ...）原样透传
  sarif_exporter.to_sarif 在 include_unconfirmed=False 时只导出 verification_state=="confirmed"。

纯函数 + 一个 sqlite 便利加载器，无重依赖（只依赖 stdlib 与 sarif_exporter）。
"""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

# 与 tools/gate_quality_redline.py 口径一致的确认态
CONFIRMED_STATES = ("confirmed_exploitable", "confirmed_code_property", "confirmed_sink_control")

# family -> 默认严重度（raw_json 里没有 severity 时兜底）
_FAMILY_SEV = {
    "sqli": "high", "sql_injection": "high", "sql 注入": "high", "xss": "high",
    "cmdi": "high", "command_execution": "high", "pathtraver": "high",
    "path_traversal": "high", "ldapi": "high", "ldap_injection": "high",
    "xpathi": "high", "xpath_injection": "high", "ssrf": "high",
    "trustbound": "high", "trust_boundary_violation": "high", "xxe": "high",
    "deserialization": "high", "jndi_injection": "high", "crlf_injection": "high",
    "hash": "medium", "weak_hash": "medium", "weakrand": "medium",
    "weak_random": "medium", "crypto": "medium", "securecookie": "medium",
    "csrf": "medium", "open_redirect": "medium", "idor": "medium",
    "file_upload": "medium",
}


def _jload(s: Any) -> Optional[dict]:
    if not s:
        return None
    if isinstance(s, dict):
        return s
    if isinstance(s, str):
        try:
            v = json.loads(s)
            return v if isinstance(v, dict) else None
        except Exception:
            return None
    return None


def _severity_of(spec: Dict[str, Any]) -> str:
    raw = _jload(spec.get("raw_json")) or {}
    sev = (raw.get("severity") or "").strip().lower()
    if sev in ("critical", "high", "medium", "low", "info", "informational"):
        return sev
    fam = str(spec.get("family") or "").strip().lower().replace(" ", "_")
    return _FAMILY_SEV.get(fam, "medium")


def _description_of(spec: Dict[str, Any]) -> str:
    raw = _jload(spec.get("raw_json")) or {}
    desc = raw.get("description") or raw.get("display_title") or ""
    if desc:
        return str(desc)
    fam = str(spec.get("family") or "").strip().lower().replace(" ", "_")
    ep = str(spec.get("target_endpoint") or "")
    return f"OWASP Benchmark {ep} ({fam})"


def _verification_state_of(status: str) -> str:
    return "confirmed" if (status or "") in CONFIRMED_STATES else (status or "")


def spec_to_vuln(spec: Dict[str, Any]) -> Dict[str, Any]:
    """单行 trigger_specs(dict) -> sarif_exporter 的 vuln dict。"""
    status = str(spec.get("verification_status") or "")
    raw = _jload(spec.get("raw_json")) or {}
    line = spec.get("expected_sink_line") or raw.get("line") or 1
    try:
        line = int(line)
    except Exception:
        line = 1
    return {
        "display_family": str(spec.get("family") or "").strip().lower().replace(" ", "_"),
        "family": str(spec.get("family") or ""),
        "severity": _severity_of(spec),
        "description": _description_of(spec),
        "file": str(spec.get("expected_sink_file") or ""),
        "line": line,
        "vulnerability_hash_v2": str(spec.get("vulnerability_hash_v2") or ""),
        "verification_state": _verification_state_of(status),
        # 透传原始态，便于下游审计
        "verification_status": status,
        "target_endpoint": str(spec.get("target_endpoint") or ""),
    }


def specs_to_vulns(specs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [spec_to_vuln(s) for s in specs if isinstance(s, dict)]


_SPEC_COLS = (
    "id, family, target_endpoint, verification_status, vulnerability_hash_v2, "
    "expected_sink_file, expected_sink_line, raw_json, capability_family"
)


def load_task_vulns_sqlite(db_path: str, task_id: int,
                           only_confirmed: bool = False) -> List[Dict[str, Any]]:
    """从 SQLite 直接加载某任务的 trigger_specs 转成 vuln dict 列表。

    only_confirmed=True 时只取确认态（CI 只报确认项的用法）。
    """
    con = sqlite3.connect(db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        if only_confirmed:
            q = f"SELECT {_SPEC_COLS} FROM trigger_specs WHERE task_id=? AND verification_status IN ({','.join('?'*len(CONFIRMED_STATES))})"
            rows = con.execute(q, [task_id, *CONFIRMED_STATES]).fetchall()
        else:
            rows = con.execute(
                f"SELECT {_SPEC_COLS} FROM trigger_specs WHERE task_id=?", (task_id,)
            ).fetchall()
        return [spec_to_vuln(dict(r)) for r in rows]
    finally:
        con.close()


def export_task_sarif(db_path: str, task_id: int, out_path: str,
                      include_unconfirmed: bool = False) -> str:
    """一次性：加载 + 写 SARIF 到 out_path，返回路径。"""
    from src.benchmark import sarif_exporter
    vulns = load_task_vulns_sqlite(db_path, task_id, only_confirmed=not include_unconfirmed)
    return sarif_exporter.write_sarif(out_path, vulns, include_unconfirmed=include_unconfirmed)


if __name__ == "__main__":
    import sys
    _db = os.environ.get("SAST_AI_DB_PATH",
                         os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "app.db"))
    _tid = int(sys.argv[1]) if len(sys.argv) > 1 else 361
    _out = sys.argv[2] if len(sys.argv) > 2 else f"data/baselines/task{_tid}.sarif.json"
    _p = export_task_sarif(_db, _tid, _out, include_unconfirmed=False)
    print("wrote", _p)
