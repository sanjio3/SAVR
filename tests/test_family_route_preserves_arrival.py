"""族路由 post-pass **不得覆盖到达证据**（2026-10-04，L3 指标假退化回归锁）。

事故链（run 112 实测）：
  1. weak_random 路由修复落地后，该族 16 条 spec 全部从 `confirmed_exploitable` 改判为
     `confirmed_code_property`（14 条）/ `unconfirmed`（2 条）——**这是正确的**。
  2. 但 post-pass 的写回语句无条件写 `iast_state = f"family-route:{status}"`，
     把这 16 条原本的 `sink-reached-probe` 全部盖掉。
  3. L3 运行时到达指标正是按 `iast_state='sink-reached-probe'` 统计的
     ⇒ run 112 的 L3 从 67.9% 掉到 52.8%，而**真实到达一条都没少**（纯标签假退化）。
     逐族到达数实测：weak_random 16→0、command_execution 33→28、其余 8 族逐位不变。

修法：写回时若当前 `iast_state` 属于到达态集合，则**只更新 `verification_status`**，
不动 `iast_state`；非到达态仍写 `family-route:*` 标记（保留归因线索）。

本文件锁三件事：
  ① 到达态 + 状态改判 → iast_state 保持原值；
  ② 非到达态 + 状态改判 → 仍写 family-route 标记（不得把这条能力一起删掉）；
  ③ 判定结果与当前状态相同 → 一行都不许写（既有的防无意义写回保护不能退化）。
"""
import sqlite3

from src.cli.benchmark_cli import _apply_family_route_postpass


class _FakeDB:
    """最小 sdb 替身：execute(sql, params, fetchall=True) -> List[dict]（与真后处理同接口）。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def execute(self, sql, params=(), fetchall=False):
        cur = self.conn.execute(sql, tuple(params))
        rows = [dict(r) for r in cur.fetchall()]
        self.conn.commit()
        return rows if fetchall else rows


def _make_db(rows):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INT, family TEXT,"
        " taint_marker TEXT, session_id INT, verification_status TEXT, iast_state TEXT)")
    conn.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY, task_id INT, canary TEXT,"
        " sink_file TEXT, source_value TEXT, evidence_json TEXT, canary_state TEXT)")
    for r in rows:
        conn.execute(
            "INSERT INTO trigger_specs (id, task_id, family, taint_marker, session_id,"
            " verification_status, iast_state) VALUES (?,?,?,?,?,?,?)", r)
    return _FakeDB(conn)


def _read(db, sid):
    r = db.conn.execute("SELECT verification_status, iast_state FROM trigger_specs WHERE id=?",
                        (sid,)).fetchone()
    return r["verification_status"], r["iast_state"]


def test_arrived_state_is_preserved_when_status_changes():
    """① 到达态 + 改判 ⇒ iast_state 原样保留，只改 verification_status。"""
    ident = "s4st41" + "a" * 16
    db = _make_db([(1, 7, "weak_random", ident, 1, "confirmed_exploitable", "sink-reached-probe")])
    # 造一条专属随机源事件，让 apply_family_route 有依据判成 code_property
    db.execute("INSERT INTO iast_events (task_id, canary, sink_file, source_value)"
               " VALUES (7, ?, 'java.util.Random.nextInt', '')", (ident,))
    n = _apply_family_route_postpass(7, db)
    vs, iast = _read(db, 1)
    assert n == 1, f"应当改判 1 条，实际 {n}"
    assert vs == "confirmed_code_property", f"应改判为 code_property，实际 {vs}"
    assert iast == "sink-reached-probe", (
        f"到达证据被覆盖了！iast_state={iast} —— L3 指标会因此凭空掉（2026-10-04 事故）")


def test_non_arrived_state_still_gets_route_marker():
    """② 非到达态仍写 family-route 标记（归因线索能力不得一起删掉）。"""
    ident = "s4st41" + "b" * 16
    db = _make_db([(2, 7, "weak_random", ident, 1, "confirmed_exploitable", "no-arrival")])
    db.execute("INSERT INTO iast_events (task_id, canary, sink_file, source_value)"
               " VALUES (7, ?, 'java.util.Random.nextInt', '')", (ident,))
    _apply_family_route_postpass(7, db)
    vs, iast = _read(db, 2)
    assert vs == "confirmed_code_property", f"实际 {vs}"
    assert iast == "family-route:confirmed_code_property", f"非到达态应写路由标记，实际 {iast}"


def test_unchanged_verdict_writes_nothing():
    """③ 判定结果 == 当前状态 ⇒ 一行都不写（保护 no-arrival / safe-pattern-veto 诊断态）。"""
    ident = "s4st41" + "c" * 16
    db = _make_db([(3, 7, "sqli", ident, 1, "unconfirmed", "no-arrival")])
    n = _apply_family_route_postpass(7, db)
    vs, iast = _read(db, 3)
    assert n == 0, f"数据流族不该被改写，实际改了 {n} 条"
    assert iast == "no-arrival", f"诊断态被覆盖：{iast}"
