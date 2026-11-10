"""d2_facade.recover_late_arrival 的回归锁（2026-10-11 第六节落地）。

事故背景（必须记住，否则下面几条锁会被当成"过度设计"删掉）：
orchestrator 采集窗口硬上限 900s 锚定 created_at，探针事件是批量 flush 落库的，
整批事件往往在窗口关闭之后才落库 —— 写路径（benchmark_cli / d2_facade 边扫边定稿）
据此把本应 confirmed 的 spec 写成 no-arrival，而 I1 读路径（correlation）无窗口、
全量重算能把 732 条真 TP 救回。这是"同一批数据、写路径 0 / 读路径 732"的反差根因。

收口：在 run_d2_verify 终态 return 前，注入一次 recover_late_arrival（post-scan 迟到回收），
用全量 iast_events 重算 arrival + value_hit（gate B：到达真实 sink 且 source_value 比对命中）。

本文件锁的是 recover_late_arrival 自身的四条铁律，先说结论再上锁：
    1. gate B 正召回：unconfirmed spec + 真实 sink 到达 + source_value 含完整 canary → 升级。
    2. 零 FP：噪声 sink / 值级未命中（source_value 不含完整 canary）/ 无事件 → 绝不误升。
    3. 单调不降级：已是 confirmed_* 的 spec 被跳过，回收失败/重跑绝不把它打回 no_evidence。
    4. 幂等：对同一 task 跑两次，第二次升级数为 0（第一次已把真 TP 全收口）。

外加一条真实世界锁：ldapi/trustbound/xpathi/xss 这类"族专属 sink 未把 canary 落进可读
source_value"的 spec，gate B 必须判 value_hit=0 → 不误升（与 r77 实测 4 族 0 救回一致，
它们的救回要靠 sink 覆盖率补强，不是窗口修复能解）。
"""
from __future__ import annotations

import pytest

from src.agents.d2_facade import recover_late_arrival


# ── canary 构造（与 CanaryFactory 同形，避免测试依赖 A2 运行时）─────────────────
_ID = "s4st41" + "a" * 16                      # 身份段：s4st41 + 16 hex
_CM_MARKER = _ID + "$(id)" + "c" * 8           # cmdi 完整 taint_marker（身份段+元字符段）
_LD_MARKER = _ID + "../" + "d" * 8             # path-traversal 完整 taint_marker


class _FakeDB:
    """最小 Database 包装仿真：只实现 recover_late_arrival 用到的三条 SQL。"""

    def __init__(self, specs, events):
        self.specs = [dict(s) for s in specs]
        self.events = [dict(e) for e in events]
        self.updates = []

    def execute(self, sql, params=None, fetchall=False, fetchone=False):
        s = (sql or "").strip()
        up = s.upper()
        if up.startswith("SELECT") and "FROM trigger_specs" in s:
            if fetchall:
                return [dict(sp) for sp in self.specs]
            return dict(self.specs[0]) if self.specs else None
        if up.startswith("SELECT") and "FROM iast_events" in s:
            if fetchall:
                return [dict(e) for e in self.events]
            return dict(self.events[0]) if self.events else None
        if up.startswith("UPDATE"):
            # 两种写法：
            #   UPDATE ... SET verification_status=?, iast_state=?, raw_json=? WHERE id=?  (确认升级, 4 参)
            #   UPDATE ... SET verification_status=?, iast_state=? WHERE id=?               (arrival 回填, 3 参)
            if len(params) == 4:
                vs, iast_state, _raw_json, sid = params
            else:
                vs, iast_state, sid = params
            for sp in self.specs:
                if sp["id"] == sid:
                    sp["verification_status"] = vs
                    sp["iast_state"] = iast_state
                    self.updates.append(sid)
                    break
            return None
        return [] if fetchall else None


def _cmdi_spec(sid, status="no_evidence"):
    return {
        "id": sid,
        "taint_marker": _CM_MARKER,
        "family": "command-execution",
        "capability_family": "cmdi",
        "target_endpoint": "/rce",
        "verification_status": status,
        "iast_state": "no-arrival",
    }


def _cmdi_event(sid_value, sink_file="java.lang.Runtime.exec", source_value=None,
                canary_state="sink-reached-probe"):
    return {
        "canary": _ID,
        "canary_state": canary_state,
        "sink_file": sink_file,
        "source_value": source_value if source_value is not None else f"[cmd.exe, /c, echo {_CM_MARKER}]",
    }


# ── 锁 1：gate B 正召回 ────────────────────────────────────────────────────────
def test_gate_b_upgrades_genuine_cmdi_tp():
    """unconfirmed cmdi spec + 真实 sink 到达 + source_value 含完整 canary → 升级为 confirmed_exploitable。"""
    specs = [_cmdi_spec(1, status="no_evidence")]
    events = [_cmdi_event(_CM_MARKER)]
    db = _FakeDB(specs, events)

    upgraded, stats = recover_late_arrival(db, task_id=1, dry_run=False)

    assert upgraded == [1], "真实 cmdi TP 应被 gate B 救回"
    assert stats["considered"] == 1
    assert stats["upgraded"] == 1
    assert db.specs[0]["verification_status"] == "confirmed_exploitable"
    assert db.specs[0]["iast_state"] == "sink-reached-probe"


# ── 锁 2a：零 FP —— 噪声 sink（响应写入）即便值级命中也不升 ──────────────────────
def test_zero_fp_noise_sink_not_upgraded():
    """cmdi 完整 canary 落在 setHeader（框架噪声 sink）→ is_genuine_sink_identity 判非真 → 不升。"""
    specs = [_cmdi_spec(2, status="no_evidence")]
    # 噪声 sink：source_value 里仍含完整 canary，但 sink_file 在 SINK_NOISE_BLACKLIST
    events = [_cmdi_event(_CM_MARKER, sink_file="org.apache.catalina.connector.Response.setHeader")]
    db = _FakeDB(specs, events)

    upgraded, _ = recover_late_arrival(db, task_id=2, dry_run=False)

    assert upgraded == [], "噪声 sink 上的值级命中不得冒充真实 cmdi 到达"
    assert db.specs[0]["verification_status"] == "no_evidence", "绝不降级也绝不误升"


# ── 锁 2b：零 FP —— 值级未命中（source_value 不含完整 canary）────────────────────
def test_zero_fp_value_miss_not_upgraded():
    """source_value 只含身份段、不含完整 canary → compute_value_hit 判 miss → 不升确认。
    （2026-10-11 起：到达真 sink 但值级 miss 的 spec 只被**回填 arrival 态**，绝不升确认。）"""
    specs = [_cmdi_spec(3, status="no_evidence")]
    # 真实 cmdi sink，但 source_value 仅仅是命令实参里出现了身份段，元字符段被截断/变形
    events = [_cmdi_event(_CM_MARKER,
                          sink_file="java.lang.Runtime.exec",
                          source_value=f"[cmd.exe, /c, echo {_ID}]")]
    db = _FakeDB(specs, events)

    upgraded, stats = recover_late_arrival(db, task_id=3, dry_run=False)

    assert upgraded == [], "值级比对未命中完整 canary 不得升确认（这是 4 族 value_hit=0 的同一判据）"
    assert db.specs[0]["verification_status"] == "sink_reached", "但应回填到达态"
    assert db.specs[0]["iast_state"] == "sink-reached-probe"
    assert stats["arrivals_backfilled"] == 1


# ── 锁 2c：零 FP —— 无事件 / 状态非到达 ────────────────────────────────────────
def test_zero_fp_no_event_or_non_arrival():
    """spec 完全无对应事件，或事件状态是 no-arrival → 不升。"""
    specs = [_cmdi_spec(4, status="no_evidence")]
    db_empty = _FakeDB(specs, [])
    up1, _ = recover_late_arrival(db_empty, task_id=4, dry_run=False)
    assert up1 == [], "无事件不得升级"

    db_na = _FakeDB(specs, [_cmdi_event(_CM_MARKER, canary_state="no-arrival")])
    up2, _ = recover_late_arrival(db_na, task_id=4, dry_run=False)
    assert up2 == [], "事件状态非到达不得升级"


# ── 锁 2d：真实世界 —— value_hit=0 族（ldapi，source_value 无完整 canary）不误升 ──
def test_value_hit_zero_family_ldapi_not_upgraded():
    """ldapi spec：事件到达真实 ldap sink，但 source_value 只含身份段、不含完整 canary，
    且**无 evidence_json** → gate B 必须不误升（须走 sink 覆盖率 / evidence 扩展）。"""
    marker = _LD_MARKER
    ident = "s4st41" + "a" * 16
    specs = [{
        "id": 5,
        "taint_marker": marker,
        "family": "ldap-injection",
        "capability_family": "ldapi",
        "target_endpoint": "/ldap",
        "verification_status": "no_evidence",
        "iast_state": "no-arrival",
    }]
    # 真实 ldap sink，但查询串里只出现了身份段（LDAP 查询表达式未承载完整 canary），无 evidence_json
    events = [{
        "canary": ident,
        "canary_state": "sink-reached-probe",
        "sink_file": "javax.naming.directory.InitialDirContext.search",
        "source_value": f"ldap://host:389/dc=example?uid={ident}",
    }]
    db = _FakeDB(specs, events)

    upgraded, _ = recover_late_arrival(db, task_id=5, dry_run=False)

    assert upgraded == [], "ldap 无 evidence_json 时不得误升"


# ── 锁 2e：ldap 经 evidence_json.payload 含完整 canary → 可救回（r77 实测 +79 TP / 0 FP）──
def test_ldap_recoverable_via_evidence_json():
    """ldap spec：探针把完整 canary 落在 evidence_json.payload（过滤器串），source_value 只含身份段。
    仅 ldap/xpath 两族扩展比对 evidence_json → 必须升级；且零 FP（canary 在真实 search 过滤串里）。"""
    marker = _LD_MARKER
    ident = "s4st41" + "a" * 16
    specs = [{
        "id": 10,
        "taint_marker": marker,
        "family": "ldap-injection",
        "capability_family": "ldapi",
        "target_endpoint": "/ldap",
        "verification_status": "no_evidence",
        "iast_state": "no-arrival",
    }]
    filter_str = f"(&(objectclass=person)(uid={marker}))"
    events = [{
        "canary": ident,
        "canary_state": "sink-reached-probe",
        "sink_file": "javax.naming.directory.InitialDirContext.search",
        "source_value": f"ldap://host:389/dc=example?uid={ident}",  # 仅身份段
        "evidence_json": __import__("json").dumps({"payload": filter_str, "context": {}}),
    }]
    db = _FakeDB(specs, events)

    upgraded, _ = recover_late_arrival(db, task_id=10, dry_run=False)

    assert upgraded == [10], "ldap 经 evidence_json.payload 含完整 canary 必须可救回"
    assert db.specs[0]["verification_status"] == "confirmed_exploitable"


# ── 锁 2f：非 ldap/xpath 族不得因 evidence_json 误升（守住 r75 SQL 的 10 FP 教训）──
def test_non_ldap_family_ignores_evidence_json():
    """cmdi spec 即便 evidence_json 里含完整 canary，也只认 source_value（不开全局 evidence 比对），
    避免重演 r75 SQL 开 evidence 混进 10 FP 的事故。"""
    marker = _CM_MARKER
    ident = "s4st41" + "a" * 16
    specs = [_cmdi_spec(11, status="no_evidence")]
    # 真实 cmdi sink，source_value 只含身份段（值级 miss），但 evidence_json 里塞了完整 canary
    events = [{
        "canary": ident,
        "canary_state": "sink-reached-probe",
        "sink_file": "java.lang.Runtime.exec",
        "source_value": f"[cmd.exe, /c, echo {ident}]",
        "evidence_json": __import__("json").dumps({"payload": f"echo {marker}"}),
    }]
    db = _FakeDB(specs, events)

    upgraded, _ = recover_late_arrival(db, task_id=11, dry_run=False)

    assert upgraded == [], "非 ldap/xpath 族不得比对 evidence_json（守住 SQL 10 FP 教训）"


# ── 锁 3：单调不降级 —— 已 confirmed 的 spec 被跳过 ─────────────────────────────
def test_no_downgrade_of_confirmed_specs():
    """已是 confirmed_exploitable 的 spec：回收不得改它，也不得把它计入 upgraded。"""
    specs = [_cmdi_spec(6, status="confirmed_exploitable")]
    events = [_cmdi_event(_CM_MARKER)]
    db = _FakeDB(specs, events)

    upgraded, stats = recover_late_arrival(db, task_id=6, dry_run=False)

    assert upgraded == [], "已确认 spec 必须被跳过（单调，不重算）"
    assert stats["considered"] == 0, "confirmed 不计入 considered"
    assert db.specs[0]["verification_status"] == "confirmed_exploitable", "绝不降级"
    assert db.specs[0]["iast_state"] == "no-arrival", "已确认态原样保留"


# ── 锁 4：幂等 —— 跑两次，第二次升级数为 0 ─────────────────────────────────────
def test_idempotent_double_run():
    """同一 task 连续跑两次：第一次收口真 TP，第二次升级数为 0。"""
    specs = [_cmdi_spec(7, status="no_evidence")]
    events = [_cmdi_event(_CM_MARKER)]
    db = _FakeDB(specs, events)

    up1, _ = recover_late_arrival(db, task_id=7, dry_run=False)
    assert up1 == [7], "第一次应升级真 TP"

    up2, stats2 = recover_late_arrival(db, task_id=7, dry_run=False)
    assert up2 == [], "第二次幂等：已 confirmed 不再升级"
    assert stats2["considered"] == 0, "第二次无未确认 spec 可考量"


# ── 锁 5：only_unconfirmed 过滤语义 ─────────────────────────────────────────────
def test_only_unconfirmed_skips_sink_reached_intermediate():
    """only_unconfirmed=True 时，处于中间态（sink_reached，非 no_evidence/unconfirmed）的
    spec 不应被回收重算（避免与主线确认闸门抢活）；默认（False）则仍按全体未确认处理。"""
    # sink_reached 中间态 spec（已抵达、未证实利用），有真实事件
    specs = [{
        "id": 8,
        "taint_marker": _CM_MARKER,
        "family": "command-execution",
        "capability_family": "cmdi",
        "target_endpoint": "/rce",
        "verification_status": "sink_reached",
        "iast_state": "sink-reached-probe",
    }]
    events = [_cmdi_event(_CM_MARKER)]
    db = _FakeDB(specs, events)

    up_filtered, _ = recover_late_arrival(db, task_id=8, dry_run=False, only_unconfirmed=True)
    assert up_filtered == [], "only_unconfirmed 必须跳过 sink_reached 中间态"

    up_all, _ = recover_late_arrival(db, task_id=8, dry_run=False, only_unconfirmed=False)
    assert up_all == [8], "默认模式按全体未确认处理，真 TP 仍应升级"


# ── 锁 6：dry_run 不写库 ────────────────────────────────────────────────────────
def test_dry_run_does_not_mutate_db():
    """dry_run=True 只返回待升级清单，不写 trigger_specs。"""
    specs = [_cmdi_spec(9, status="no_evidence")]
    events = [_cmdi_event(_CM_MARKER)]
    db = _FakeDB(specs, events)

    upgraded, _ = recover_late_arrival(db, task_id=9, dry_run=True)

    assert upgraded == [9], "dry_run 仍要返回待升级清单"
    assert db.specs[0]["verification_status"] == "no_evidence", "dry_run 不得写库"
    assert db.updates == [], "dry_run 不得产生任何 UPDATE"


# ══════════════════════════════════════════════════════════════════════════════
# 锁 7（2026-10-11 新增）：迟到 arrival 回填
#
# 事故背景：D2 采集窗内探针批量 flush 迟到，运行期把 spec 判成 no-arrival。
# r77 实测 306/307 有 112+137 个 spec 在 iast_events 里存在真 sink 的 sink-reached
# 事件，却从未被登记为到达 —— L3 到达层与 I2/family-route 消费全部失真。
# 回填铁律：只补到达态（sink_reached + iast_state），**绝不升 confirmed**；单调；幂等。
# ══════════════════════════════════════════════════════════════════════════════

def test_arrival_backfilled_when_window_missed():
    """真 sink 到达但值级无命中 → 回填到达态（sink_reached），不升确认。"""
    specs = [_cmdi_spec(20, status="no_evidence")]
    # 真 cmdi sink，canary 仅身份段（值级必然 miss），但到达态成立
    events = [_cmdi_event(_CM_MARKER, sink_file="java.lang.Runtime.exec",
                          source_value=f"[cmd.exe, /c, echo {_ID}]",
                          canary_state="sink-reached-probe")]
    db = _FakeDB(specs, events)

    upgraded, stats = recover_late_arrival(db, task_id=20, dry_run=False)

    assert upgraded == [], "回填不得升确认"
    assert stats["arrivals_backfilled"] == 1
    assert db.specs[0]["verification_status"] == "sink_reached"
    assert db.specs[0]["iast_state"] == "sink-reached-probe"


def test_arrival_backfill_is_monotonic_and_idempotent():
    """已是到达态的 spec 不回退、不重复写；第二次跑回填数为 0。"""
    specs = [_cmdi_spec(21, status="sink_reached")]
    specs[0]["iast_state"] = "sink-reached-probe"
    events = [_cmdi_event(_CM_MARKER, sink_file="java.lang.Runtime.exec",
                          source_value=f"[cmd.exe, /c, echo {_ID}]")]
    db = _FakeDB(specs, events)

    _, stats = recover_late_arrival(db, task_id=21, dry_run=False)

    assert stats["arrivals_backfilled"] == 0, "已在到达态 → 幂等不重写"
    assert db.specs[0]["iast_state"] == "sink-reached-probe", "绝不降级"


def test_arrival_backfill_requires_genuine_sink():
    """噪声 sink（setHeader）的 sink-reached 事件不得回填到达态（防 L3 到达层被噪声灌水）。"""
    specs = [_cmdi_spec(22, status="no_evidence")]
    events = [_cmdi_event(_CM_MARKER,
                          sink_file="org.apache.catalina.connector.Response.setHeader",
                          source_value=f"[X-XSS-Protection, {_ID}]")]
    db = _FakeDB(specs, events)

    _, stats = recover_late_arrival(db, task_id=22, dry_run=False)

    assert stats["arrivals_backfilled"] == 0, "噪声 sink 不构成到达"
    assert db.specs[0]["verification_status"] == "no_evidence"


def test_confirm_wins_over_arrival_backfill():
    """值级命中时走确认路径（confirmed_exploitable），不回填为 sink_reached。"""
    specs = [_cmdi_spec(23, status="no_evidence")]
    events = [_cmdi_event(_CM_MARKER)]  # source_value 含完整 marker → 值级命中
    db = _FakeDB(specs, events)

    upgraded, stats = recover_late_arrival(db, task_id=23, dry_run=False)

    assert upgraded == [23]
    assert stats["arrivals_backfilled"] == 0, "确认路径优先，不再计回填"
    assert db.specs[0]["verification_status"] == "confirmed_exploitable"


def test_arrival_backfill_dry_run_no_write():
    """dry_run 下回填只计数不写库。"""
    specs = [_cmdi_spec(24, status="no_evidence")]
    events = [_cmdi_event(_CM_MARKER, sink_file="java.lang.Runtime.exec",
                          source_value=f"[cmd.exe, /c, echo {_ID}]")]
    db = _FakeDB(specs, events)

    _, stats = recover_late_arrival(db, task_id=24, dry_run=True)

    assert stats["arrivals_backfilled"] == 1, "dry_run 仍要给出回填计数"
    assert db.updates == [], "dry_run 不得写库"
    assert db.specs[0]["verification_status"] == "no_evidence"
