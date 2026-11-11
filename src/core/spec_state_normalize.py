#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""spec 状态口径归一。

## 解决什么问题

本轮的 `deserialization` 全族 12 条 spec 一次重放都没有，却全部被记成
`iast_state = 'no-arrival'`（语义是「打了但没到 sink」），于是 D2 记 `true_miss`，

实际原因是 D1 的这句日志：

    [D1.replay] GET /classloader 无可用载荷且无净化器约束 → 标记 degraded_no_synthesis
                （不投假弹；family=deserialization）

即 **A2 造不出该族的攻击载荷 → D1 拒绝投假弹 → 不发请求 → 没有事件 → 记成 no-arrival**。

「没弹可投」和「打了没到」在能力评估里含义完全相反：
前者是 payload 合成能力缺口，后者是重放/路由/判据问题。混在一起就无法归因。

## 判据（三条同时成立，全是确定性观测）

1. `iast_state == 'no-arrival'`
2. 该 spec 在 `replay_attempts` 里**没有任何记录**
3. `attack_payloads_json` 为空

三条同时成立才判 `payload_unavailable`。

为什么必须带第 3 条：OWASP 上大量 spec 的 `attack_payloads_json` 也是空的，
但 D1 用净化感知合成（`sanitizer_aware`）照样发出去了，有 attempt 记录。
**只有「既没有弹、又没发出去」才是 payload 缺口**；有弹却没发出去是另一种故障，
必须留在 `no-arrival` 里等人查，不能被这里顺手抹平。

## 边界

- 只改 `iast_state` / `failure_attribution` / `failure_attribution_reason` 三个字段
- **不动 `verification_status`**（不把任何东西升成 confirmed，也不降级）
- 幂等：已经是 `payload_unavailable` 的不会再被处理
- 可 dry-run
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

STATE_PAYLOAD_UNAVAILABLE = "payload_unavailable"
ATTR_NO_PAYLOAD = "no_payload_synthesized"


def normalize_payload_unavailable(db: Any, task_id: Optional[int], dry_run: bool = False) -> Dict[str, int]:
    """把「没弹可投」从「打了没到」里分出来。返回统计。

    参数 ``db`` 需要支持 ``execute`` / ``commit``（sqlite3.Connection 或平台的包装）。
    """
    if task_id is None:
        return {"scanned": 0, "marked": 0}

    def _all(sql: str, params):
        """兼容两种句柄：平台 Database（execute(..., fetchall=True)）与裸 sqlite3。"""
        if hasattr(db, "connect"):  # 平台包装
            return list(db.execute(sql, list(params), fetchall=True) or [])
        return list(db.execute(sql, tuple(params)))

    def _cell(row, idx: int, name: str):
        """兼容 sqlite3.Row（按键）与 tuple（按位）。"""
        try:
            return row[name]
        except Exception:
            return row[idx]

    def _run(sql: str, params):
        if hasattr(db, "connect"):
            db.execute(sql, list(params))
        else:
            db.execute(sql, tuple(params))

    rows = _all(
        "SELECT id AS sid, family AS fam, attack_payloads_json AS ap, "
        "iast_state AS st, failure_attribution AS fa "
        "FROM trigger_specs WHERE task_id = ? AND iast_state = 'no-arrival'",
        (int(task_id),),
    )
    if not rows:
        return {"scanned": 0, "marked": 0}

    replayed = {
        int(_cell(r, 0, "spec_id")) for r in _all(
            "SELECT DISTINCT spec_id AS spec_id FROM replay_attempts WHERE task_id = ?",
            (int(task_id),),
        ) if r and _cell(r, 0, "spec_id") is not None
    }

    marked = []
    for row in rows:
        sid = int(_cell(row, 0, "sid"))
        if sid in replayed:
            continue  # 发过请求 → 不是 payload 缺口，留在 no-arrival 等查
        try:
            payloads = json.loads(_cell(row, 2, "ap") or "[]")
        except Exception:
            payloads = []
        if payloads:
            continue  # 有弹却没发 → 另一种故障，不归到这里
        marked.append((sid, str(_cell(row, 1, "fam") or "")))

    if marked and not dry_run:
        for sid, _fam in marked:
            _run(
                "UPDATE trigger_specs SET iast_state = ?, failure_attribution = ?, "
                "failure_attribution_reason = ? WHERE id = ?",
                (
                    STATE_PAYLOAD_UNAVAILABLE,
                    ATTR_NO_PAYLOAD,
                    "D1 degraded_no_synthesis：A2 未产出该族攻击载荷，D1 拒绝投假弹，"
                    "本次未发出请求（不是 no-arrival）",
                    sid,
                ),
            )
        if not hasattr(db, "connect"):
            try:
                db.commit()
            except Exception:
                pass

    if marked:
        fams: Dict[str, int] = {}
        for _sid, fam in marked:
            fams[fam] = fams.get(fam, 0) + 1
        logger.info(
            "[spec-normalize] task=%s 把 %d 条「无弹可投」从 no-arrival 里分出%s：%s",
            task_id, len(marked), "（dry-run）" if dry_run else "", fams,
        )
    return {"scanned": len(rows), "marked": len(marked)}


# ── 族能力分类（语义分类，与任何靶场无关）─────────────────────────────────
#
# 为什么不用 `exploit_spec._INJECTION_FAMILIES` 直接判定：那三个集合是**代码路由用的**，
# 既漏（crlf_injection / ssti / url_redirect 都不在里面，但它们明明能靠重放确认），
# 又多（file-upload 在里面，但确认它靠的是落盘行为不是 payload 注入）。
# 这里按「该族的危害能不能靠投放载荷、观测影响来证明」重新分类，作为度量口径的唯一真相源。

# 可重放证明：把载荷投进去，能观测到危害（注入生效 / 文件被读 / 请求被引到别处 / 模板被渲染）。
REPLAY_PROVABLE = frozenset({
    "sql_injection", "command_execution", "xss", "ssrf", "path_traversal", "xxe",
    "deserialization", "expression_injection", "spel", "spel_injection",
    "template_injection", "ssti", "jndi_injection", "ldap_injection",
    "xpathi", "xpath_injection", "nosql_injection", "ognl",
    "crlf_injection", "url_redirect", "url_whitelist_bypass", "jsonp_referer",
    "file_upload", "open_redirect", "code_injection",
    # 这三个也能靠重放证明，别误归到属性族：
    #   cors     —— 带 Origin 打一发，看 ACAO 是否回显；
    #   csrf     —— 不带 token 打一发，看状态是否真的被改；
    #   auth_bypass / authentication_session —— 不带凭据打一发，看是否 200。
    "cors", "csrf", "auth_bypass", "authentication_session",
})

# 属性 / 配置族：危害是「某个开关没开 / 某个头没设 / 某个算法太弱」，
# 与有没有把载荷送进 sink 无关 ⇒ 只能靠静态证据，不能进动态分母。
PROPERTY_ONLY = frozenset({
    # 这些的「危害」是某个属性不对，没有「投一个载荷进去」的语义：
    #   secure_cookie   —— Cookie 有没有 setSecure/HttpOnly；
    #   weak_crypto/hash/random —— 用了什么算法；
    #   information_exposure / log_injection —— 有没有把敏感值写进响应/日志；
    #   trust_boundary_violation / config_security / clickjacking —— 配置项。
    "secure_cookie", "securecookie",
    "weak_crypto", "weak_hash", "weak_random", "crypto", "weakrand", "hash",
    "information_exposure", "information-disclosure", "log_injection", "log_disclosure",
    "auth_session", "broken_access_control",
    "trust_boundary_violation", "config_security", "clickjacking",
    "unmapped", "unknown", "",
})

# 无 HTTP 入口：连「打一发」的前提都不成立（例如 RMI 服务在 main 里）。
NO_HTTP_ENTRY = frozenset({"rmi"})


def classify_dynamic(family: str) -> str:
    """返回 ``replay`` / ``property`` / ``no_entry`` / ``other``。"""
    try:
        from src.core.normalize import normalize_family
        fam = str(normalize_family(family) or "").strip().lower()
    except Exception:
        fam = str(family or "").strip().lower()
    if fam in REPLAY_PROVABLE:
        return "replay"
    if fam in NO_HTTP_ENTRY:
        return "no_entry"
    if fam in PROPERTY_ONLY:
        return "property"
    return "other"


def is_dynamic_eligible(family: str) -> bool:
    """该族是否应计入「动态确认」分母。

    只有 `replay` 类计入。属性族、无 HTTP 入口族、以及未知族都不计入——
    它们进分母只会让动态数字系统性偏低，那是度量错误，不是能力不足。
    """
    return classify_dynamic(family) == "replay"


#
# 为什么必须做：本轮实测 36 条「到了 sink 但未确认」里，**14 条一次重放都没有**
# （`replay_attempts` 零行）。其中 7 条连该文件在本任务内都**没有任何 iast_event**，
# 却标着 `sink-reached` —— 状态凭空产生。这不是判据问题，是**口径污染**：
# 它让「到了 sink 判不出」这个归因失真，也让后续所有按 sink 状态做的分析都建立在假数据上。
#
# 判据（两条同时成立才降级，全部是确定性观测）：
#   1. `iast_state` 属于 sink-reached* 家族
#   2. 该 spec 在 `replay_attempts` 里没有任何记录
#   3. 该 spec 的 sink 文件在本任务 `iast_events` 里没有任何事件（sink_file / stack_trace 都不命中）
#
# 只降级到 `no-arrival` 并标 `sink_state_without_evidence`，**不动 verification_status**
# —— 已经确认过的（哪怕确认得可疑）留给 D2 判据那一步去处理，这里只修观测口径。

STATE_SINK_WITHOUT_EVIDENCE = "sink_state_without_evidence"


def reconcile_sink_state_without_evidence(db: Any, task_id: Optional[int],
                                          dry_run: bool = False) -> Dict[str, Any]:
    """把「没有重放、也没有任何探针事件」的 sink-reached 状态降级为 no-arrival。"""
    if task_id is None:
        return {"scanned": 0, "downgraded": 0, "files": []}

    def _all(sql: str, params):
        if hasattr(db, "connect"):
            return list(db.execute(sql, list(params), fetchall=True) or [])
        return list(db.execute(sql, tuple(params)))

    def _cell(row, idx: int, name: str):
        try:
            return row[name]
        except Exception:
            return row[idx]

    def _run(sql: str, params):
        if hasattr(db, "connect"):
            db.execute(sql, list(params))
        else:
            db.execute(sql, tuple(params))

    rows = _all(
        "SELECT id AS sid, family AS fam, expected_sink_file AS sf, "
        "expected_sink_line AS sl FROM trigger_specs "
        "WHERE task_id = ? AND iast_state LIKE 'sink-reached%'",
        (int(task_id),),
    )
    if not rows:
        return {"scanned": 0, "downgraded": 0, "files": []}

    replayed = {int(_cell(r, 0, "spec_id")) for r in _all(
        "SELECT DISTINCT spec_id AS spec_id FROM replay_attempts WHERE task_id = ?",
        (int(task_id),)) if r and _cell(r, 0, "spec_id") is not None}

    # 本任务内所有事件的可搜索文本（sink_file + stack_trace，统一小写正斜杠）。
    # 注意：stack_trace 里出现的是**类名**（形如 `at com.example.web.Foo.sink(Foo.java:12)`），
    # 不是文件名，所以不能只按「basename 相等」匹配 —— 要按「类名子串」匹配。
    haystack: List[str] = []
    for r in _all("SELECT sink_file AS f, stack_trace AS s FROM iast_events WHERE task_id = ?",
                  (int(task_id),)):
        _t = (str(_cell(r, 0, "f") or "") + " " + str(_cell(r, 1, "s") or "")).replace("\\", "/").lower()
        if _t.strip():
            haystack.append(_t)

    downgraded = []
    for row in rows:
        sid = int(_cell(row, 0, "sid"))
        if sid in replayed:
            continue
        _base = str(_cell(row, 2, "sf") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        if not _base:
            continue
        _stem = _base[:-5] if _base.endswith(".java") else _base
        if any((_base in h) or (_stem and _stem in h) for h in haystack):
            continue  # 该文件/类确实有探针事件，状态有据，不动
        downgraded.append(sid)

    if downgraded and not dry_run:
        for sid in downgraded:
            _run("UPDATE trigger_specs SET iast_state='no-arrival', failure_attribution=?, "
                 "failure_attribution_reason=? WHERE id=?",
                 (STATE_SINK_WITHOUT_EVIDENCE,
                  "既无重放记录、也无任何探针事件，sink-reached 状态无证据支撑，"
                  "按观测口径降级为 no-arrival（不是判据结论）", sid))
        if not hasattr(db, "connect"):
            try:
                db.commit()
            except Exception:
                pass

    if downgraded:
        logger.info("[spec-normalize] task=%s 降级无证据的 sink-reached %d 条%s",
                    task_id, len(downgraded), "（dry-run）" if dry_run else "")
    return {"scanned": len(rows), "downgraded": len(downgraded), "files": downgraded}
