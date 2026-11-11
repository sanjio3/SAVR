"""DAST 配置自检闸门。

要抓的是两类「配置看着有、实际跑不出判据」的洞：
    1. **base_url 为空**：D1/D2 的所有重放都发不出去，表现为一整轮 no-arrival，
       而报告上看不出是「没配地址」还是「漏洞不存在」——后者会被当成永久非漏洞，
       直接污染确认口径的分母。
    2. **双账号是同一主体**：越权类（BOLA/垂直越权）的判据是「攻击者身份读到了受害者
       的数据」。两个账号 subject 相同时，攻击者用自己的身份读自己的数据就能通过判据，
       产出的是**假确认**。这是比缺配置更危险的一类：它不是让结论缺失，而是让结论错误。

设计取舍（为什么是「显式告警」而不是「拒绝提交」）：
    - 拒绝提交会挡住「先扫静态、运行时后配」的正常用法（OWASP/benchmark 类靶场
      本来就常先做静态分析）。
    - 但这两类问题**必须在提交时就让人看见**，不能等扫完 40 分钟看一堆 no_evidence
      才发现是配置没填。
    所以：产出结构化告警 + 事件 + 日志，任务照常提交，但告警随任务一起留痕，
    对账时能区分「靶场没配」与「真没打中」。

M11 同时把 workspace-5/6 的配置补齐（base_url 与双账号），补的值一律来自
真实登录/真实端口登记，**绝不伪造 cookie**。
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SEV_BLOCKING = "blocking"     # 运行时验证必然跑不出判据（缺地址）
SEV_FALSE_CONFIRM = "false_confirm"   # 会产出假确认（双账号同主体）


def _app_row(db: Any, app_id: str) -> Optional[Dict[str, Any]]:
    if db is None or not app_id:
        return None
    # Database.execute 的 fetchone 是关键字参数（src/infrastructure/db.py），
    # 写成 db.execute(sql, p).fetchall 会在真实库上拿空并被 except 吞掉 —— 已踩过。
    try:
        row = db.execute(
            "SELECT app_id, app_name, base_url, auth_type, role_boundaries_json "
            "FROM dast_apps WHERE app_id = ?", (str(app_id),), fetchone=True)
    except Exception:
        return None
    return dict(row) if row else None


def _accounts(db: Any, app_id: str) -> List[Dict[str, Any]]:
    if db is None or not app_id:
        return []
    try:
        rows = db.execute(
            "SELECT account_id, role, subject, tenant, auth_cookies_json, auth_headers_json "
            "FROM dast_accounts WHERE app_id = ? ORDER BY id", (str(app_id),), fetchall=True)
    except Exception:
        return []
    return [dict(r) for r in (rows or [])]


def _ws_settings(db: Any, workspace_id: Any) -> Dict[str, Any]:
    """读 workspace 侧设置在**本 app 之上**。

    重放真正用的是 workspace.settings_json.service_url（见 workspace_runtime），
    dast_apps.base_url 只是 DAST 应用登记。两者都可能有值且一致，但只查前者
    会漏报「workspace 配了、DAST 应用登记漏填」，只查后者会误报「没配地址」。
    所以 base_url 的判定取**生效值**：dast_apps 优先，空则回退 workspace 设置。
    """
    if db is None or workspace_id in (None, ""):
        return {}
    try:
        row = db.execute(
            "SELECT settings_json FROM workspaces WHERE id = ?",
            (workspace_id,), fetchone=True)
    except Exception:
        return {}
    if not row:
        return {}
    # sqlite3 返回元组、DB 层封装可能返回 dict；两种都要吃得下。
    raw = row[0] if isinstance(row, (tuple, list)) else (row.get("settings_json") or "")
    try:
        obj = json.loads(raw) if raw else {}
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _effective_base_url(app: Dict[str, Any], ws: Dict[str, Any]) -> str:
    for v in (app.get("base_url"),
              (ws or {}).get("service_url"),
              (ws or {}).get("target_url")):
        if v and str(v).strip():
            return str(v).strip()
    return ""


def _subject_of(acc: Dict[str, Any]) -> str:
    """账号主体标识：subject 优先，缺失退回 account_id。

    subject 是平台约定的「这个身份到底是谁」（用户 id / 租户+用户名），
    account_id 只是登录名——两个不同登录名可能映射到同一个 subject
    （比如同一人的两个入口），那照样是假确认。
    """
    return str(acc.get("subject") or acc.get("account_id") or "").strip()


def check_dast_config(db: Any, app_id: str, workspace_id: Any = None,
                      enable_verification: bool = True) -> Dict[str, Any]:
    """检查单个 DAST app 的配置完备性。返回 {ok, warnings:[...], summary}。

    ok=False 表示**至少有一条 blocking/严重告警**，调用方应显著提示；
    但本函数自身不做任何拦截决策（那是调用方与用户的决定）。
    """
    warnings: List[Dict[str, Any]] = []
    ws = _ws_settings(db, workspace_id) if workspace_id is not None else {}
    app = _app_row(db, app_id)
    if app is None:
        # workspace.settings_json.service_url（见 _ws_settings docstring）；此前在
        # app_not_found 分支短路返回「重放将无目标可打」，从未检查 workspace 生效地址，
        # 导致 OWASP 分片跑批每片都背一条
        # blocking 假告警。现在：workspace 配了生效地址 → 降级为 info（走 workspace 配置）；
        # 真没配 → 维持原 blocking。
        ws_url = _effective_base_url({}, ws)
        if ws_url:
            return {
                "ok": True, "app_id": app_id, "workspace_id": workspace_id,
                "base_url": ws_url,
                "warnings": [{
                    "code": "app_not_found_ws_fallback",
                    "severity": "info",
                    "message": (f"DAST app {app_id!r} 未登记，但 workspace 配置了生效地址 "
                                f"{ws_url} —— 重放按 workspace 配置打靶"),
                    "fix": "",
                }],
                "summary": {"app_found": False, "base_url_ok": True, "accounts": 0,
                            "ws_fallback": True, "has_false_confirm_risk": False},
            }
        warnings.append({
            "code": "app_not_found",
            "severity": SEV_BLOCKING,
            "message": f"DAST app {app_id!r} 在 dast_apps 里不存在，重放将无目标可打",
            "fix": "先在 DAST 应用配置里创建该 app 并填 base_url",
        })
        return {"ok": False, "app_id": app_id, "warnings": warnings,
                "summary": {"app_found": False, "accounts": 0}}

    base_url = _effective_base_url(app, ws)
    if not base_url:
        warnings.append({
            "code": "base_url_empty",
            "severity": SEV_BLOCKING,
            "message": (f"DAST app {app_id!r} 的 base_url 为空 —— D1/D2 的重放全部发不出去，"
                        "本轮运行时族会整片 no-arrival，且报告无法区分「没配地址」与「无漏洞」"),
            "fix": f"把 {app_id} 的 base_url 填成靶场实际监听地址（如 http://127.0.0.1:8080）",
        })
    elif not base_url.startswith(("http://", "https://")):
        warnings.append({
            "code": "base_url_malformed",
            "severity": SEV_BLOCKING,
            "message": f"DAST app {app_id!r} 的 base_url {base_url!r} 缺 http(s):// 前缀",
            "fix": "补全协议前缀",
        })

    accounts = _accounts(db, app_id)

    # 判据不看「role 列里写了什么」，而看「这一组账号是不是同一个主体」。
    # 踩过的坑：workspace-4 的 role 列装的是**权限角色**（user/admin），
    # attacker/victim 只存在于 account_id —— 按 role 标签分组会取空，
    # 于是双账号同主体的假确认风险被整个漏掉。
    # 所以这里直接按 subject 分组：≥2 个账号同主体即判风险，
    # 越权判据一定会被自己的数据满足。
    if enable_verification and len(accounts) >= 2:
        by_subject: Dict[str, List[Dict[str, Any]]] = {}
        for a in accounts:
            by_subject.setdefault(_subject_of(a), []).append(a)
        dup = [subj for subj, grp in by_subject.items()
               if subj and len(grp) >= 2]
        if dup:
            subj = sorted(dup)[0]
            grp = by_subject[subj]
            names = "、".join(str(a.get("account_id") or "?") for a in grp)
            same_seen = len({str(a.get("auth_cookies_json") or "")
                             for a in grp}) == 1
            warnings.append({
                "code": "dual_account_same_subject",
                "severity": SEV_FALSE_CONFIRM,
                "message": (f"DAST app {app_id!r} 的账号 {names} 是**同一主体**"
                            f"（subject={subj!r}）—— 越权判据会被自己的数据满足，"
                            "产出的是假确认（比缺配置更危险：结论错而不是结论缺）"
                            + ("；且两者的凭据串完全相同，等于同一个会话被登记了两次"
                               if same_seen else "")),
                "fix": "补一个真正不同的受害者账号，并把 subject 登记成不同的用户标识"
                       "（需要真实登录取会话，不要复制粘贴现有 cookie）",
            })
    # 有角色标签但缺凭据 → 运行时会以未认证身份打，判据必然不成立
    for a in accounts:
        cookies = str(a.get("auth_cookies_json") or "").strip()
        headers = str(a.get("auth_headers_json") or "").strip()
        if cookies in ("", "{}") and headers in ("", "{}"):
            warnings.append({
                "code": "account_without_credential",
                "severity": SEV_BLOCKING,
                "message": (f"DAST app {app_id!r} 的账号 {a.get('account_id')!r} "
                            "没有登记任何 cookie / header —— 重放会以未认证身份打，越权类判据不成立"),
                "fix": "真实登录一次并把会话 cookie/header 登记进来（不要伪造）",
            })

    sev = {w["severity"] for w in warnings}
    return {
        "ok": not warnings,
        "app_id": app_id,
        "workspace_id": workspace_id,
        "base_url": base_url,
        "warnings": warnings,
        "summary": {
            "app_found": True,
            "base_url_ok": bool(base_url),
            "accounts": len(accounts),
            "roles": sorted({str(a.get("role") or "") for a in accounts} |
                            {str(a.get("account_id") or "") for a in accounts}),
            "has_false_confirm_risk": SEV_FALSE_CONFIRM in sev,
        },
    }


def check_task_dast_config(db: Any, workspace_id: Any, app_id: str = "",
                           enable_verification: bool = True) -> Dict[str, Any]:
    """提交任务时调用：确定该查哪个 app（显式 idor_app_id 优先，否则 workspace-N）后自检。

    未开运行时验证（enable_verification=False）且没显式指定 app 时不做检查——
    纯静态扫描不该被 DAST 配置问题拦住。
    """
    resolved = str(app_id or "").strip() or ("workspace-%s" % workspace_id)
    if not enable_verification and not app_id:
        return {"ok": True, "skipped": True, "app_id": resolved, "warnings": [],
                "reason": "未启用运行时验证，跳过 DAST 配置自检"}
    res = check_dast_config(db, resolved, workspace_id, enable_verification)
    if res["ok"]:
        return res
    logger.warning(
        "[dast-config-check] workspace-%s 的 app %s 配置不完备：%s",
        workspace_id, resolved,
        "；".join("[%s] %s" % (w["code"], w["message"]) for w in res["warnings"]))
    return res
