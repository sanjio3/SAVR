"""round_report.py — 结构化「R报告器」数据接口。

替代原先的 Markdown 报告文件展示：直接把 R13 target-mall 对账 / 三层泄漏诊断 /
运行时证据以结构化 JSON 返回给前端，由 RoundReporter.vue 做标签栏分页渲染。

路由：
    GET /api/round-report/{task_id}                完整报告
        ?baseline=<id>                            附带基线对比块
        ?summary_only=1                           仅返回 summary + config（跨轮对比用）
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api/round-report", tags=["round-report"])

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[3]

# env_premise 判定三态（真值两层）。本地常量而非 import，避免 FastAPI 路由模块
# 在导入期就硬依赖 core 层（上面的 _env_premise_check 是惰性 import + fail-open）。
SATISFIED = "satisfied"
UNSATISFIED = "unsatisfied"
UNKNOWN = "unknown"


def _resolve_db() -> str:
    """与后端其余模块一致：SAST_AI_DB_PATH 环境变量优先，默认 data/app.db（相对项目根）。"""
    raw = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
    p = Path(raw)
    if not p.is_absolute():
        p = PROJECT_ROOT / raw
    return str(p)


# (编号, 类型, 期望路由子串, 期望族 token(小写), 技术/业务, 环境前提 env_premise)
# 与 scripts/reconcile_target_mall_v2.py 保持一致，确保 DETECT/CONFIRM 口径不变。
#
# env_premise（2026-10-03 M1 真值两层）：本条目「在运行时打通」所需的环境前提。
#   {}  = 无前提（L_code == L_exploit，代码缺陷即可利用，不依赖中间件/DB/出网）。
#   可机检 = {"事实名": [允许取值]}，事实名见 src/core/env_premise.KNOWN_FACT_KEYS，
#            由 runtime_facts.collect_facts() 提供；事实缺失时 fail-open（不缩小分母）。
#   仅声明 = {"_note": "..."}：已知存在环境依赖但阈值未实测，不伪造版本号，同样 fail-open。
# 用途：L_exploit（可利用层）分母只数前提满足的条目，把「环境打不通」从「检测漏检」
#       里摘出去（记 env_unsupported，见 src/core/failure_attribution.py）。
# 注意：这是 **target-mall** 的真值表（包名 com.sanjio.mall；/seckill、/coupon、/wallet、/order/buy…）。
# java-sec-code 任务绝不可套用本表（路由零重合），见下方 JAVA_SEC_CODE + _golden_for_task。
# env_premise 一律 {}：target-mall 是自建 SpringBoot 靶场，35 条真值均为「代码缺陷即
# 可利用」，无已证实的中间件/JDK/DB 版本门槛。此处不臆造前提 —— 一旦某条被打不通，
# 它属于 true_miss / pipeline_gap，不是 env_unsupported（见 failure_attribution）。
VULNS = [
    (1, "SQL注入", ["/login"], ["sql"], "tech", {}),
    (2, "SQL注入", ["/products?keyword"], ["sql"], "tech", {}),
    (3, "SQL注入", ["/api/products/sort"], ["sql"], "tech", {}),
    (4, "SQL注入", ["/api/products/by-category"], ["sql"], "tech", {}),
    (5, "SQL注入", ["/admin/report"], ["sql"], "tech", {}),
    (6, "命令注入", ["/admin/ping"], ["command"], "tech", {}),
    (7, "SpEL注入", ["/api/coupon/preview"], ["spel"], "tech", {}),
    (8, "SSTI", ["/marketing/preview"], ["ssti", "模板"], "tech", {}),
    (9, "反序列化", ["/profile/import"], ["deserial", "反序列化"], "tech", {}),
    (10, "SSRF", ["/profile/avatar-from-url"], ["ssrf"], "tech", {}),
    (11, "SSRF", ["/admin/fetch"], ["ssrf"], "tech", {}),
    (12, "SSRF(存储)", ["/ticket"], ["ssrf"], "tech", {}),
    (13, "路径穿越(读)", ["/order/invoice"], ["path", "路径"], "tech", {}),
    (14, "路径穿越(写)+上传", ["/upload"], ["path", "路径", "upload"], "tech", {}),
    (15, "XXE", ["/order/import-xml"], ["xxe"], "tech", {}),
    (16, "存储型XSS", ["/comment"], ["xss"], "tech", {}),
    (17, "反射型XSS", ["/products?keyword"], ["xss"], "tech", {}),
    (18, "存储型XSS(签名)", ["/profile"], ["xss"], "tech", {}),
    (19, "水平越权IDOR", ["/order/", "/profile?", "/cart/remove", "/comment/delete"], ["bola", "idor"], "biz", {}),
    (20, "水平越权·地址", ["/address"], ["bola", "idor"], "biz", {}),
    (21, "垂直越权(JWT)", ["/admin/"], ["vertical", "jwt"], "biz", {}),
    (22, "垂直越权·删用户", ["/ops/user/delete"], ["vertical"], "biz", {}),
    (23, "垂直越权·审单", ["/ops/order/review"], ["vertical"], "biz", {}),
    (24, "越权改密", ["/profile/password"], ["idor", "auth", "password"], "biz", {}),
    (25, "批量赋值提权", ["/profile/update"], ["calculation", "批量赋值"], "biz", {}),
    (26, "秒杀超卖", ["/seckill"], ["race"], "biz", {}),
    (27, "优惠券超发", ["/coupon/claim"], ["race"], "biz", {}),
    (28, "提现竞态", ["/wallet/withdraw"], ["race"], "biz", {}),
    (29, "转账重复", ["/wallet/transfer"], ["race"], "biz", {}),
    (30, "支付金额篡改", ["/order/buy", "/order/checkout", "/pay"], ["calculation"], "biz", {}),
    (31, "优惠券叠加", ["/order/buy", "coupon"], ["calculation"], "biz", {}),
    (32, "状态机跳步", ["/ship"], ["state_machine"], "biz", {}),
    (33, "退款滥用", ["/refund"], ["abuse_dos"], "biz", {}),
    (34, "回调签名伪造", ["/payment/callback", "/payment/sign"], ["signature", "auth"], "biz", {}),
    (35, "未授权接口泄露", ["/api/internal/"], ["unauthorized", "未授权"], "biz", {}),
]

# 残缺路由：A2 解析器会拒收，此处用于统计「被丢弃」比例（空串单独算「无路由」）。
BOGUS_ROUTES = {"/", "/admin", "/admin/", "/admin/,", "/,", "/admin/, "}

# ---------------------------------------------------------------------------
# java-sec-code 黄金集（2026-09-20 建立，2026-09-20 二次对齐 README）
# ---------------------------------------------------------------------------
# 背景：上面 VULNS 是 target-mall 的真值表；旧版对 java-sec-code 任务也套用它 → 路由完全不重合
# → 即便已检出也无法「确认」（实测 run 22 只有 2/35 命中，其中 1 条还是 /login 巧合）。
# java-sec-code 是纯技术漏洞教学靶场（**无任何业务逻辑/竞态/状态机漏洞**），故另立本表，
# 按工作区名选择。每项：(编号, 类型, 期望路由片段, 期望族 token(小写), "tech", 环境前提)；
# 路由/族片段均为**子串**匹配（与 _spec_match 一致：target_endpoint 含任一路由片段且 family 含任一 token）。
#
# 本表**逐条镜像 README_zh.md 的「漏洞代码」清单（29 类，README 原始顺序、原始命名）**，
# 目的就是让「README 的每一行是否跑通」可被逐条对账。因此：
#   - 不收录 README 未列出的类（靶场另有 Cookies / GetRequestURI / Dotall / WebSockets 等，
#     属靶场超出 README 的部分，不计入本基准）；
#   - 不臆造 README 没有的类（初版曾误加「Jackson 反序列化」，靶场无独立入口，已删）；
#   - 「Java RMI」无 HTTP 入口（RMI/Server.java 是独立 main() 进程），routes 留空，
#     由 _build 判为非运行时适用、不计入可重放分母（避免制造永久假漏检）。
# env_premise 说明（真值两层）：下表多数条目为 {}（代码缺陷即可利用）。已证实的
# 环境依赖用 {"_note": ...} 声明但**不伪造阈值** —— 阈值需 M2 采到 mw_version/db_type/
# egress 后实测确定，届时把 note 换成可机检的 {"事实名": [取值]} 即可自动生效。
JAVA_SEC_CODE = [
    (1, "Actuators to RCE", ["appinfo", "actuator", "/trace", "/env", "/beans"], ["information", "actuator"], "tech", {}),
    (2, "CommandInject", ["codeinject", "jscmd", "yarm", "groovy"], ["command"], "tech", {}),
    (3, "CORS", ["cors"], ["cors"], "tech", {}),
    # CRLF：可利用性受中间件响应头 sanitize 约束（Tomcat 高版本会净化注入的 CRLF，
    # 使响应头分裂打不出来）。这是**运行时事实**，不是判据错配 —— 代码缺陷仍在
    # （L_code 层 TP），只是当前中间件下打不通（L_exploit 层打不通 ⇒ env_unsupported）。
    # 阈值（哪个版本起净化）未实测，故只声明不机检；M2 采到 mw_type/mw_version 后转键。
    (4, "CRLF Injection", ["crlf"], ["crlf", "header"], "tech",
     {"_note": "可利用性受中间件响应头 sanitize 约束（Tomcat 高版本净化 CRLF）；阈值未实测，M2 采到 mw_version 后转可机检"}),
    # ②（2026-09-20）：把 cors 纳入 CSRF 黄金 tokens 与 routes。靶场 CSRF 弱点
    # （form POST 缺 token）经 A1/A2 检出后，spec 的 family 实测被归为 cors（如 /cors 端点，
    # finding 9345→spec family=cors、target_endpoint=/cors），仅用 ["csrf"] 会让该 spec 永远对不上
    # CSRF 黄金项（family 不含 csrf 且路由 /cors 不含子串 csrf）→ 显示未入环。cors 与 CSRF 在靶场
    # 同源（同一套「状态变更端点缺 CSRF 校验」弱点），同时把 cors 加进 tokens 与 routes，
    # 即让现有 /cors spec 对账入环，不依赖伪造任何新数据。
    (5, "CSRF", ["csrf", "cors"], ["csrf", "cors"], "tech", {}),
    (6, "CVE-2022-22978", ["auth_bypass", "cve-2022-22978", "broken_access_control", "regexmatchers"], ["/black_path%0a/xx", "black_path"], "tech", {}),
    (7, "Deserialize", ["rememberme", "/deserialize"], ["deserial"], "tech", {}),
    (8, "Fastjson", ["fastjson"], ["deserial"], "tech", {}),
    (9, "File Upload", ["/file/upload", "/upload", "/file/any"], ["path", "upload"], "tech", {}),
    (10, "IP Forge", ["/ip/noproxy", "/ip/proxy"], ["ip", "path", "information"], "tech", {}),
    # Java RMI：无 HTTP 入口（独立 main()），routes 空 → 结构上不可运行时重放
    (11, "Java RMI", [], ["rmi"], "no_http", {"_note": "无 HTTP 入口（独立 main 进程），结构上不可运行时重放"}),
    (12, "JSONP", ["jsonp"], ["jsonp", "csrf"], "tech", {}),
    # Log4j：JNDI 远程 codebase 加载受 JDK 版本约束（8u191 / 11.0.1 起 trustURLCodebase
    # 默认关闭）。跨主版本的阈值不是线性可比的（8u191 与 11.0.1 是两条独立分支），
    # 用单一区间表达会误判，故此处只声明；M2 后按 jdk_version 分支表转可机检。
    # 注意：即便 codebase 被禁，JNDI **查询**本身仍会发出（DNS/LDAP 带外可观测），
    # 所以本条在 L_code 层恒为 TP，L_exploit 层才受此前提约束。
    (13, "Log4j", ["log4j"], ["jndi"], "tech",
     {"_note": "JNDI 远程 codebase 加载受 JDK 版本约束（8u191/11.0.1 起 trustURLCodebase 默认关闭）；跨主版本非线性，M2 后转可机检"}),
    (14, "ooxmlXXE", ["ooxml"], ["xxe"], "tech", {}),
    (15, "PathTraversal", ["path_traversal"], ["path"], "tech", {}),
    (16, "QLExpress", ["qlexpress", "vuln1"], ["qlexpress", "code"], "tech", {}),
    (17, "RCE", ["/rce"], ["command", "code"], "tech", {}),
    (18, "Shiro", ["shiro"], ["deserial"], "tech", {}),
    (19, "SpEL", ["spel"], ["spel"], "tech", {}),
    # SQL 注入：时间盲注/报错注入的可行性受数据库方言约束（MySQL/PostgreSQL/MSSQL 的
    # sleep 函数与报错函数互不相同）。代码缺陷（拼接）本身与方言无关 ⇒ L_code 层恒 TP；
    # 但「用哪条弹药能打通」是环境事实，M6 会按 db_type 收窄弹药，避免三方言穷举超预算。
    (20, "SQL Injection", ["jdbc", "mybatis", "sqli", "postgresql", "db2"], ["sql"], "tech",
     {"_note": "注入可证性受数据库方言约束（sleep/报错函数各异）；M6 按 db_type 收窄弹药，不穷举三方言"}),
    (21, "SSRF", ["ssrf", "openstream", "urlconnection", "httpclient", "resttemplate", "dnsrebind",
                  "hutool", "exclued", "ioutils", "jsoup", "imageio", "proxy"], ["ssrf"], "tech",
     {"_note": "带外证明力通道需靶场可出网（egress）+ OOB 域名已配；两者未到位前只能靠响应差分/时延"}),
    (22, "SSTI", ["ssti", "velocity"], ["template"], "tech", {}),
    (23, "URL Redirect", ["urlredirect"], ["redirect"], "tech", {}),
    (24, "URL whitelist Bypass", ["url_bypass", "/url/"], ["url", "whitelist"], "tech", {}),
    (25, "xlsxStreamerXXE", ["xlsx"], ["xxe"], "tech",
     {"_note": "XXE 带外/文件读取可证性受 XML 解析器配置（外部实体是否禁用）约束；该配置需投弹实测（依赖 OOB），域名未到位前 fail-open"}),
    (26, "XSS", ["/xss"], ["xss"], "tech",
     {"_note": "反射型/DOM 型回显取证在无 JS 引擎时够不着（DOM XSS 明确降级为静态提示，不参与确认口径）"}),
    (27, "XStream", ["xstream"], ["deserial"], "tech", {}),
    (28, "XXE", ["/xxe", "xmlreader", "documenthelper", "documentbuilder"], ["xxe"], "tech",
     {"_note": "XXE 带外/文件读取可证性受 XML 解析器配置（外部实体是否禁用）约束；该配置需投弹实测（依赖 OOB），域名未到位前 fail-open"}),
    (29, "JWT", ["/jwt"], ["jwt", "auth"], "tech", {}),
]

# 靶场 → 黄金集。按工作区名（workspaces.name）子串选择。
GOLDEN_SETS = {
    "java-sec-code": JAVA_SEC_CODE,
    "target-mall": VULNS,
}


def _golden_for_task(cur, task_id: int):
    """按任务所属工作区名选择黄金集，返回 (golden_list, target_name)。

    未识别靶场返回空表（不套用任何真值表，避免把别的靶场基准当本靶场基准、读出假「未达成」）。
    """
    name = ""
    try:
        cur.execute(
            "SELECT w.name FROM scan_tasks t LEFT JOIN workspaces w ON t.workspace_id=w.id WHERE t.id=?",
            (task_id,),
        )
        row = cur.fetchone()
        if row:
            name = str(row[0] or "")
    except Exception:
        name = ""
    low = name.lower()
    for key, golden in GOLDEN_SETS.items():
        if key in low:
            return golden, key
    return [], (name or "unknown")


def _env_premise_check(env_premise, facts):
    """判定黄金条目的环境前提；任何异常一律 fail-open（返回 unknown，不缩小分母）。"""
    try:
        from src.core.env_premise import check_premise
        return check_premise(env_premise, facts)
    except Exception:
        return UNKNOWN, "premise_check_error(fail-open)"


def _env_premise_desc(env_premise) -> str:
    try:
        from src.core.env_premise import describe
        return describe(env_premise)
    except Exception:
        return ""


def _tok(s: str) -> str:
    return (s or "").lower()


def _extract_route(d: dict) -> str:
    """从 finding raw_json 抽取真实 HTTP 路由。

    路由实际绑在 exploit_spec.entry.route / trigger_spec_detail.endpoint，
    而非顶层 entry_route（多数 finding 该字段为空但已成功转 trigger_spec）。
    """
    rt = ""
    es = d.get("exploit_spec")
    if isinstance(es, str):
        try:
            es = json.loads(es)
        except Exception:
            es = {}
    if isinstance(es, dict):
        e = es.get("entry") or {}
        if isinstance(e, dict):
            rt = (e.get("route") or "").strip()
    if not rt:
        tsd = d.get("trigger_spec_detail")
        if isinstance(tsd, str) and tsd.strip():
            try:
                import re
                m = re.search(r"endpoint'\s*:\s*'([^']*)'", tsd)
                if m:
                    rt = m.group(1).strip()
            except Exception:
                pass
    if not rt:
        rt = (d.get("entry_route") or "").strip()
    return rt


def _route_hit(route: str, blob: str) -> bool:
    """route 是否命中 finding 文本。短 ASCII route（<=4）走词边界，避免 rce/sql 等误中子串
    （如 resources 含 rce）；其余（含中文、长 route）沿用子串匹配。"""
    rr = _tok(route).strip("/").strip()
    if not rr:
        return False
    if len(rr) <= 4 and rr.isalnum():
        return bool(re.search(r"(?<![a-z0-9])" + re.escape(rr) + r"(?![a-z0-9])", blob))
    return rr in blob


def _finding_match(tokens, routes, finds):
    """finding 是否命中某黄金项。

    2026-09-21：除 tokens 外，把黄金项的 routes 也纳入匹配源。原因——部分黄金项（如
    CVE-2022-22978）的 tokens 是攻击 payload 串（black_path、/black_path%0a/xx），这些串
    只存在于触发请求里、根本不在 finding 字段中，导致只用 tokens 匹配时该黄金项永远
    detect=False（实测 run 25 即此）。而 routes（cve-2022-22978 / regexmatchers /
    auth_bypass 等）恰是 finding 的 type/display_family/file_path/sink 会带的锚点，
    纳入后可正确判检出。短 route 走词边界、长 route 走子串，控制误召回。
    """
    for ft, src, rj, fp in finds:
        blob = _tok(ft) + " " + _tok(src) + " " + _tok(fp)
        try:
            d = json.loads(rj) if rj else {}
            blob += " " + _tok(d.get("sink", "")) + " " + _tok(d.get("entry_point", ""))
            # display_family / display_title 是 SCA 与语义发现都有的稳定展示字段，纳入可提升召回
            blob += " " + _tok(d.get("display_family", "")) + " " + _tok(d.get("display_title", ""))
        except Exception:
            pass
        if any(t in blob for t in tokens):
            return True
        if any(_route_hit(r, blob) for r in (routes or [])):
            return True
    return False


# 运行时观测态强弱：同族多候选 spec 择优时用（越高越强）
_SPEC_IAST_RANK = {
    "sink-reached": 3, "sink-reached-probe": 3,
    "iast-reached": 2, "iast-authz-confirmed": 2,
    "business-logic-confirmed": 2, "business-side-effect-confirmed": 2,
    "arrival-sanitized": 1,
    "no-iast-evidence": 0,
    "no-arrival": -1,
    # 下面两态（2026-09-22 新增）**不是**「探针没命中」，必须排在 no-arrival 之后，
    # 保证「有注入点、投放了、但 canary 没到」的 spec 优先被取中（那条信息量更大）。
    "no-injectable-param": -2,
    "no-iast-sink": -2,
}
_SPEC_VS_RANK = {
    "confirmed_exploitable": 3, "exploitable": 3, "confirmed_sink_control": 2,
    # 2026-10-07（方案①）：「已确认抵达危险函数，但未证实利用成功」。
    # 排位依据：证据强度低于 confirmed_exploitable（它只有探针断言，没有带外/回显/
    # 结果点等独立可利用性证据），但高于 unconfirmed —— 抵达本身是**已观测到的**事实，
    # 不是推测，故给 1.5（用 ×2 避免浮点：unconfirmed=2, 本项=3, confirmed=6）。
    "sink_reached": 1.5,
    "unconfirmed": 1, "no_evidence": 0, "invalidated": -1,
}

# 「IAST 语义下无 sink 可断言」的黄金项 —— 按靶场真值表逐条论证，不是配置开关。
# 这些类的弱点形态是「安全控制缺失」（absence of control），不存在承载不可信数据的危险函数，
# IAST 无论怎么重放都不会有 sink 事件。它和「探针没命中」是**两回事**，混在一起会把口径问题
# 读成探针缺陷（run 31 的 #5 即被读成 no-arrival）。判定它们需要 DAST 侧断言
# （对比「带控制 / 不带控制」两次响应的差异），不属 IAST 通道能覆盖的范围。
_GOLDEN_NO_IAST_SINK = {
    # java-sec-code：README_zh.md 把 CSRF 直接指向 security/WebSecurityConfig.java（配置文件本身），
    # controller/CSRF.java 只有 GET /csrf/（返回视图）与 POST /csrf/post（返回字符串），
    # 二者均无危险函数；弱点在配置层（application.properties: joychou.security.csrf.enabled=false）。
    "CSRF": (
        "CSRF 是配置级控制缺失（WebSecurityConfig + csrf.enabled=false），"
        "controller/CSRF.java 无危险函数可供 IAST 断言；需 DAST 侧对比（带/不带 token 的响应差异）。"
    ),
}


def _spec_injectable(s: dict) -> bool:
    """spec 是否具备可投放 canary 的注入点。

    判据（任一成立即可）：``param_name`` 非空，或 ``representative_request_params`` 里至少有一个
    具名参数。两者都空意味着 D1 的 ``_inject`` 会因「无参数名」直接 return —— canary 从未发出去，
    此时读出来的 no-arrival 是**投放侧缺口**，不是探针未命中。
    """
    if str(s.get("param_name") or "").strip():
        return True
    try:
        rep = json.loads(s.get("representative_request_params_json") or "[]")
    except Exception:
        rep = []
    if not isinstance(rep, list):
        return False
    for rp in rep:
        if isinstance(rp, dict) and str(rp.get("name") or rp.get("param_name") or "").strip():
            return True
    return False


def _spec_match(tokens, routes, specs):
    """返回 (endpoint, verification_status, iast_state, family, spec_id, candidates, injectable) 或 None。

    2026-09-22 改动：同一黄金项常会匹配到**多条**同族 spec —— A2 闭环重跑会为同一端点
    再生成 spec（实测 run 31 的 /log4j 有 8636/8637、/spel/vuln1 有 8649/8793）。
    旧实现按 trigger_specs 行序返回**第一条**，会把「有 canary 抵达证据的那条」丢掉，
    读成假的 no-arrival（run 31 的 #13 Log4j、#19 SpEL 即此：被取中的那条 0 事件，
    另一条分别有 10 条 / 3 条 sink-reached-probe）。现改为在全部候选中按
    「运行时观测态 + 裁决态」择优，并把候选数一并返回，使报告能显式标注「多候选择优」。

    同日第二改：把「无注入点」的 spec 从 no-arrival 里分出来，单列 ``no-injectable-param``。
    """
    best = None
    best_key = None
    best_spec = None
    n = 0
    for s in specs:
        fam = s.get("family") or ""
        if not any(t in _tok(fam) for t in tokens):
            continue
        ep = s.get("target_endpoint") or ""
        if not any(r.lower() in (ep or "").lower() for r in routes):
            continue
        n += 1
        state = str(s.get("iast_state") or "").strip()
        rank = _SPEC_IAST_RANK.get(state, 0)
        # 无注入点且未抵达 → 降级到 -2，让「投放过但没到」的 spec 优先（信息量更大）
        if rank <= -1 and not _spec_injectable(s):
            rank = -2
        key = (rank, _SPEC_VS_RANK.get(str(s.get("verification_status") or "").strip(), 0))
        if best_key is None or key > best_key:
            best_key = key
            best = (ep, s.get("verification_status"), s.get("iast_state"), fam, s.get("id"))
            best_spec = s
    if best is None:
        return None
    state = str(best[2] or "").strip()
    injectable = _spec_injectable(best_spec) if best_spec else False
    # 只有「本来就读成 no-arrival 且 spec 根本没有注入点」才改判，别把真实抵达态盖掉
    if state == "no-arrival" and not injectable:
        best = (best[0], best[1], "no-injectable-param", best[3], best[4])
    return best + (n, injectable)


def _config_snapshot() -> dict:
    cfg_path = PROJECT_ROOT / "config.yaml"
    try:
        import yaml
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        api = cfg.get("api", {}) or {}
        a2 = (cfg.get("agents", {}) or {}).get("a2", {}) or {}
        llm = cfg.get("llm", {}) or {}
        return {
            "provider": api.get("provider"),
            "model": api.get("model"),
            "a2_max_workers": a2.get("max_workers"),
            "a2_llm_concurrency": a2.get("llm_concurrency"),
            "llm_provider": llm.get("provider"),
            "llm_model": llm.get("model"),
        }
    except Exception as e:  # config 读取失败不影响核心对账
        return {"error": str(e)}


def _three_layer(cur, tid: int) -> dict:
    # 门禁1 ap_route_gate
    cur.execute("SELECT id, source, raw_json FROM findings WHERE task_id=?", (tid,))
    rows = cur.fetchall()
    total = len(rows)
    with_route = bogus = no_route = spec_ok = 0
    for fid, src, rj in rows:
        try:
            d = json.loads(rj) if rj else {}
        except Exception:
            d = {}
        rt = _extract_route(d)
        if rt in BOGUS_ROUTES:
            bogus += 1
        elif rt:
            with_route += 1
        else:
            no_route += 1
        if str(d.get("trigger_spec_provided", "")).strip().lower() in ("true", "1"):
            spec_ok += 1
    ap_route = dict(total=total, with_route=with_route, no_route=no_route, bogus=bogus, spec_ok=spec_ok)

    # 门禁2 d1_env_blocked
    cur.execute(
        "SELECT COUNT(*), "
        "SUM(CASE WHEN target_endpoint IS NOT NULL AND target_endpoint<>'' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN business_logic_category IS NOT NULL AND business_logic_category<>'' THEN 1 ELSE 0 END) "
        "FROM trigger_specs WHERE task_id=?", (tid,))
    tot, with_ep, biz = cur.fetchone()
    tot = tot or 0
    with_ep = with_ep or 0
    biz = biz or 0
    cur.execute(
        "SELECT COUNT(*), "
        "SUM(CASE WHEN canary_match=1 THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN LOWER(canary_state) IN ('sink-reached','sink-reached-probe') THEN 1 ELSE 0 END) "
        "FROM iast_events WHERE task_id=?", (tid,))
    ev_tot, ev_match, ev_sink = cur.fetchone()
    ev_tot = ev_tot or 0
    ev_match = ev_match or 0
    ev_sink = ev_sink or 0
    d1 = dict(specs=tot, with_ep=with_ep, biz=biz, ev_tot=ev_tot, ev_match=ev_match, ev_sink=ev_sink)

    # 门禁3 d2_judge / blackboard 硬门禁
    cur.execute(
        "SELECT COUNT(*), "
        "SUM(CASE WHEN detect_state='detected' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN confirm_state='confirmed' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN sink_reached=1 THEN 1 ELSE 0 END) "
        "FROM vuln_blackboard WHERE task_id=?", (tid,))
    bb_tot, det, conf, sink = cur.fetchone()
    bb_tot = bb_tot or 0
    det = det or 0
    conf = conf or 0
    sink = sink or 0
    cur.execute(
        "SELECT verification_status, COUNT(*) FROM vuln_blackboard "
        "WHERE task_id=? GROUP BY verification_status ORDER BY 2 DESC", (tid,))
    verification = {str(k): v for k, v in cur.fetchall()}
    cur.execute(
        "SELECT iast_state, COUNT(*) FROM vuln_blackboard "
        "WHERE task_id=? GROUP BY iast_state ORDER BY 2 DESC", (tid,))
    iast_state_dist = {str(k): v for k, v in cur.fetchall()}
    # 闭环分层口径（2026-09-20）：
    # - spec_backed：有 TriggerSpec 的行（真正进入 D1 重放 / D2 验证链），等价 confirm_state='confirmed'。
    # - detect_only：只有 finding、从未生成 TriggerSpec 的行（停在「已检出」，从未入环）——
    #   它们是黑板大头（实测 run 22 为 489 行），旧版把它们混进闭环分母，把闭环率算成 73/562 的假象。
    # - verified：verification_status ∈ (confirmed_exploitable, exploitable)，即真正被判定可利用。
    #   §2026-09-22 拆分：verification_status 是 **DAST/AI 轴**的裁决（d2_judge.judge_verification
    #   里 `"verification_status": legacy.get(...)`，与 IAST 轴完全独立），而 iast_state 是运行时
    #   观测轴。两轴结论可以不一致 —— 实测 run 31 有 42 行 verification_status=confirmed_exploitable
    #   但 iast_state=no-arrival。把它们混算成同一个 verified 就是「d2_verified 虚高」的直接来源
    #   （那个 42 的存在意味着一部分「已验证」其实没有任何运行时抵达证据）。
    #   故拆成两档**并列输出**（保留原 verified 不动，历史对账口径仍可比）：
    #     verified_iast_backed：verification_status 确认 **且** iast_state 观测到抵达 —— 真·运行时可利用
    #     verified_dast_only  ：仅 DAST/AI 轴判定可利用、IAST 无证据 —— 须单独复核，不得当运行时命中数用
    # D4（2026-10-10，与 summary 同源）：下方 `verified` 与 summary 的 canonical confirmed_count
    # 必须同源——两者都取「verification_status ∈ (confirmed_exploitable, exploitable)」这一**同一权威定义**
    # （summary 侧为 _d2m['verified_count'] = total_vulnerabilities，本函数侧为下方 GROUP BY 同义计数）。
    # 禁止在此处另起一套口径（如只数 confirmed_exploitable 或混入 iast_state 过滤），否则两份报告对同一
    # 任务报出不同「已确认」数，对账无法交叉验证。iast 支持度细分由 verified_iast_backed 单独并列承担。
    _CONFIRMED_STATUS_SET = ("confirmed_exploitable", "exploitable")
    verified = sum(int(verification.get(s, 0)) for s in _CONFIRMED_STATUS_SET)
    cur.execute(
        "SELECT COUNT(*) FROM vuln_blackboard WHERE task_id=? "
        "AND verification_status IN ('confirmed_exploitable','exploitable') "
        "AND LOWER(COALESCE(iast_state,'')) IN ("
        "'sink-reached','sink-reached-probe','iast-reached','iast-authz-confirmed',"
        "'business-logic-confirmed','business-side-effect-confirmed')",
        (tid,))
    verified_iast_backed = int((cur.fetchone() or [0])[0] or 0)
    verified_dast_only = max(0, verified - verified_iast_backed)
    # Q1：spec 层「确认」与运行时层「sink 身份」冲突计数。此前两层打架（spec 标
    # confirmed_exploitable 而运行时判噪声 sink）不可见，只能靠人工比对；这里显式统计，
    # 让对账能直接看到 Q1 修复前后的落差。口径：confirmed spec 中，其 canary 关联到的
    # 全部 iast_events 落点皆为框架噪声 sink 的行数。fail-open：查不到事件不计入。
    sink_identity_conflict = 0
    try:
        from src.iast.canary import CanaryMatcher as _Q1CM
        from src.iast.sink_identity import is_genuine_sink_identity as _Q1Genuine
        cur.execute(
            "SELECT s.family, s.raw_json, s.taint_marker FROM trigger_specs s "
            "WHERE s.task_id=? AND s.verification_status IN ('confirmed_exploitable','exploitable')",
            (tid,))
        for _fam, _rj, _mk_col in cur.fetchall():
            try:
                _d = json.loads(_rj or "{}") or {}
            except Exception:
                _d = {}
            # canary 标识三处来源：spec.taint_marker 列（权威）→ raw_json.taint_marker
            # → raw_json.d2_evidence.taint_marker。缺列兜底会让本统计静默漏数。
            _id = _Q1CM.find_identity(str(_mk_col or ""))
            if not _id:
                _id = _Q1CM.find_identity(str(_d.get("taint_marker") or ""))
            if not _id:
                _id = _Q1CM.find_identity(
                    str((_d.get("d2_evidence") or {}).get("taint_marker") or ""))
            if not _id:
                continue
            cur.execute(
                "SELECT sink_file FROM iast_events WHERE task_id=? AND canary LIKE ?",
                (tid, "%" + _id + "%"))
            _sfs = [str(r[0] or "") for r in cur.fetchall() if r and r[0]]
            if _sfs and not any(_Q1Genuine(x, str(_fam or "")) for x in _sfs):
                sink_identity_conflict += 1
    except Exception as _q1_e:
        logger.debug("[round_report] sink 身份冲突统计跳过：%s", _q1_e)
    spec_backed = conf
    detect_only = max(0, bb_tot - conf)

    # 「仅检出」再按根因细分（2026-09-20）——detect_only 是个误导性大数（实测 run 22 为 489），
    # 若当成同一类「验证缺口」会导出完全错误的结论。四类：
    #   sca          组件/依赖 CVE：无 HTTP 入口、无运行时语义，结构上不可能进 D1/D2（非缺陷，应标 not_applicable）
    #   no_route     语义发现但没有入口路由：绝大多数是「同一漏洞在 sink 行的重复报点」（入口行那条已入环）
    #   dup_route    有入口路由、且该路由已有 TriggerSpec：同一漏洞的重复报点（非缺口）
    #   unbound_route 有入口路由、但该路由没有任何 TriggerSpec：**真缺口**（路由绑定丢失，须补齐）
    # 计数口径 = 无 spec 的黑板行（与 detect_only 同源，故四类之和 == detect_only）。
    def _norm_ep(p: str) -> str:
        p = (p or "").strip().lower()
        p = re.sub(r"\{[^}]*\}", "{}", p)
        return p.rstrip("/") or "/"

    cur.execute("SELECT target_endpoint FROM trigger_specs WHERE task_id=?", (tid,))
    spec_eps = {_norm_ep(r[0]) for r in cur.fetchall() if r[0]}
    cur.execute(
        "SELECT b.finding_id, f.source, f.raw_json FROM vuln_blackboard b "
        "JOIN findings f ON f.task_id=b.task_id AND f.id=b.finding_id "
        "WHERE b.task_id=? AND b.trigger_spec_id IS NULL",
        (tid,))
    d_only = dict(sca=0, no_route=0, dup_route=0, unbound_route=0)
    for _fid, _src, _rj in cur.fetchall():
        if _tok(_src) == "sca":
            d_only["sca"] += 1
            continue
        try:
            _d = json.loads(_rj) if _rj else {}
        except Exception:
            _d = {}
        _m = re.search(r"(/[A-Za-z0-9_\-/{}.]*)", str(_d.get("entry_point") or ""))
        _path = _m.group(1) if _m else ""
        if not _path:
            d_only["no_route"] += 1
        elif _norm_ep(_path) in spec_eps:
            d_only["dup_route"] += 1
        else:
            d_only["unbound_route"] += 1

    # 注意：这里**不再输出** `confirmed` 键。黑板的 confirm_state 语义是「存在 TriggerSpec」，
    # 而非「运行时已验证」（blackboard.py 第 276 行 `"confirmed" if spec else "unconfirmed"`），
    # 直接以 confirmed 命名会让调用方读成「确认漏洞数」（实测 run 2273 vs 真 verified 63；
    # run 2369 vs 17）。统一改名 spec_backed，运行时确认数用 verified。
    d2 = dict(rows=bb_tot, detected=det, sink=sink,
              verification=verification, iast_state=iast_state_dist,
              spec_backed=spec_backed, verified=verified, detect_only=detect_only,
              verified_iast_backed=verified_iast_backed, verified_dast_only=verified_dast_only,
              sink_identity_conflict=sink_identity_conflict,
              detect_only_breakdown=d_only)

    return dict(ap_route=ap_route, d1=d1, d2=d2)


def _attribution_stats(specs, golden, facts) -> dict:
    """未确认 spec 的四值判责统计（2026-10-03 M1）。

    优先采信 D2 已落库的 ``failure_attribution`` 列（那条是运行时真实判定）；列为空时
    （旧任务 / D2 尚未接线）就地按同一套规则补算，使历史任务也能读出归因分布。
    """
    try:
        from src.core import failure_attribution as fa
        from src.core.env_premise import UNSATISFIED
    except Exception:
        return {"counts": {}, "rows": [], "source": "unavailable"}

    # 族 → 环境前提：从黄金集条目的 tokens 反查（黄金条目按族 token 匹配 spec）
    premise_by_family = {}
    try:
        for entry in golden or []:
            if len(entry) < 6:
                continue
            _premise = entry[5]
            if not _premise:
                continue
            for t in (entry[3] or []):
                premise_by_family.setdefault(str(t).lower(), _premise)
    except Exception:
        premise_by_family = {}

    counts = {c: 0 for c in fa.ALL_CLASSES}
    from_db = 0
    computed = 0
    rows = []
    for s in specs or []:
        stored = str(s.get("failure_attribution") or "").strip()
        if stored in fa.ALL_CLASSES:
            cls = stored
            reason = str(s.get("failure_attribution_reason") or "")
            from_db += 1
        else:
            fam = str(s.get("family") or "").strip().lower()
            cls, reason = fa.classify(s, facts, premise_by_family.get(fam))
            if cls:
                computed += 1
        if not cls:
            continue
        counts[cls] = counts.get(cls, 0) + 1
        rows.append({
            "id": s.get("id"),
            "family": s.get("family"),
            "endpoint": s.get("target_endpoint"),
            "class": cls,
            "reason": reason,
        })
    rows.sort(key=lambda r: (r["class"], str(r.get("family") or "")))
    return {
        "counts": counts,
        "unconfirmed_total": sum(counts.values()),
        "from_db": from_db,
        "computed": computed,
        # 只留前 200 条明细，避免大任务的报告体把前端打爆
        "rows": rows[:200],
        "source": "db+computed",
    }


def _build(task_id: int, include_baseline: bool, baseline_id: int | None, summary_only: bool) -> dict:
    db = _resolve_db()
    if not os.path.exists(db):
        raise HTTPException(status_code=404, detail=f"DB not found: {db}")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # ORDER BY id：多候选择优在「同分」时需要确定顺序，避免报告随 SQLite 扫描序抖动。
    # 2026-09-22 增选 param_name / representative_request_params_json：用来判 spec 有没有注入点
    # （无注入点 ⇒ canary 从未投放 ⇒ 不该读成 no-arrival）。
    # 2026-10-03 M1：多选 raw_json / accounts_json / victim_resource_id / failure_attribution
    # —— 前三者是「差分族缺输入」这类 pipeline_gap 的判据，第四者是 D2 落库的判责结果
    # （列缺失时这里会抛错，故用 try 回落最小列集，绝不让报告整体 500）。
    try:
        cur.execute(
            "SELECT id, family, target_endpoint, verification_status, iast_state, business_logic_category, "
            "param_name, representative_request_params_json, raw_json, accounts_json, victim_resource_id, "
            "failure_attribution, failure_attribution_reason "
            "FROM trigger_specs WHERE task_id=? ORDER BY id", (task_id,))
        specs = [dict(r) for r in cur.fetchall()]
    except Exception:
        cur.execute(
            "SELECT id, family, target_endpoint, verification_status, iast_state, business_logic_category, "
            "param_name, representative_request_params_json "
            "FROM trigger_specs WHERE task_id=? ORDER BY id", (task_id,))
        specs = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT finding_type, source, raw_json, file_path FROM findings WHERE task_id=?", (task_id,))
    finds = [(r["finding_type"], r["source"], r["raw_json"], r["file_path"]) for r in cur.fetchall()]

    sca_count = sum(1 for _ in finds if _tok(_[1]) == "sca")
    semantic_findings = len(finds) - sca_count

    # 按靶场选择黄金集（java-sec-code / target-mall → 各自真值表；未识别靶场为空表）
    golden, golden_target = _golden_for_task(cur, task_id)

    # 真值两层（2026-10-03 M1）：环境事实用于判定「该条目在当前靶场到底能不能打通」。
    # 事实缺失时 env_premise 一律 fail-open，故本轮未配事实也不会静默缩小分母。
    # 传入 target_path 才会做依赖/配置解析（pom/gradle/application.*）—— 这是 M2 采
    # db_type/mw_version 的路子；不给就只剩 jdk 与环境变量登记，同样 fail-open。
    try:
        from src.core.runtime_facts import collect_facts
        cur.execute("SELECT w.target_path FROM scan_tasks t LEFT JOIN workspaces w ON t.workspace_id=w.id WHERE t.id=?", (task_id,))
        _tp_row = cur.fetchone()
        _tp = (_tp_row[0] if _tp_row else "") or ""
        _facts = collect_facts(_tp)
    except Exception:
        _facts = {}

    reconcile = []
    detected = confirmed = 0
    golden_applicable = 0        # 有 HTTP 入口、可运行时重放的基准条数（闭环分母）
    golden_not_applicable = []   # 结构上不可运行时重放的基准（如 Java RMI），单列不计分母
    golden_state_dist: dict = {}  # 基准层 iast_state 分布（把 no-arrival 与另外两态分开计数）
    golden_env_unsupported = []  # L_code 有、L_exploit 因环境不支持剔除的条目
    golden_env_unverified = []   # 前提不可机检（fail-open 留在分母），需 M2 采事实后收敛
    # 可利用层口径：只数「前提满足」的条目（见 env_premise.is_exploit_layer）
    golden_exploit_total = 0
    exploit_detected = exploit_confirmed = 0
    for vid, vtype, routes, tokens, kind, env_premise in golden:
        applicable = bool(routes)
        if not applicable:
            golden_not_applicable.append(vtype)
            reconcile.append({
                "id": vid, "type": vtype, "kind": kind, "routes": routes, "tokens": tokens,
                "applicable": False, "detect": None, "confirm": None,
                "spec_endpoint": None, "spec_family": None, "finding_family": None,
                "verification_status": None, "iast_state": None,
                "env_premise": env_premise,
                "env_premise_desc": _env_premise_desc(env_premise),
                "env_premise_state": "not_applicable",
            })
            continue
        golden_applicable += 1
        sm = _spec_match(tokens, routes, specs)
        fm = _finding_match(tokens, routes, finds)
        is_conf = sm is not None
        is_det = is_conf or fm
        _state = (sm[2] if sm else None) or ""
        _injectable = bool(sm[6]) if sm else False
        # 「IAST 语义下无 sink」的类单独标注：它既不是探针漏命中，也不是 spec 缺注入点。
        # 只在确实没有抵达证据时才改写，免得把将来真的抵达了的结果盖掉。
        if vtype in _GOLDEN_NO_IAST_SINK and _state in ("", "no-arrival", "no-injectable-param"):
            _state = "no-iast-sink"
        if _state:
            golden_state_dist[_state] = golden_state_dist.get(_state, 0) + 1
        if is_conf:
            confirmed += 1
        if is_det:
            detected += 1
        # 两层口径：只有前提「明确不满足」才从 L_exploit 分母剔除；
        # unknown（事实未采到 / 前提仅声明）fail-open 留在分母并计入 unverified 清单。
        _p_state, _p_reason = _env_premise_check(env_premise, _facts)
        if _p_state == UNSATISFIED:
            golden_env_unsupported.append(vtype)
        else:
            golden_exploit_total += 1
            if is_conf:
                exploit_confirmed += 1
            if is_det:
                exploit_detected += 1
            if _p_state == UNKNOWN:
                golden_env_unverified.append(vtype)
        reconcile.append({
            "id": vid,
            "type": vtype,
            "kind": kind,
            "routes": routes,
            "tokens": tokens,
            "applicable": True,
            "detect": is_det,
            "confirm": is_conf,
            # 真值两层：同一条目在 L_code / L_exploit 两层可能不同
            "exploit_layer": _p_state != UNSATISFIED,
            "env_premise": env_premise,
            "env_premise_desc": _env_premise_desc(env_premise),
            "env_premise_state": _p_state,
            "env_premise_reason": _p_reason,
            "spec_endpoint": sm[0] if sm else None,
            "spec_family": sm[3] if sm else None,
            "finding_family": None,  # 仅命中 finding 未命中 spec 时的辅助信息，暂留
            "verification_status": sm[1] if sm else None,
            "iast_state": _state or None,
            # §2026-09-22：暴露「取中的是哪条 spec、共有几条候选」，让「多候选择优」
            # 与「借别的族的 spec 入环」（如 CSRF 借 CORS，见 JAVA_SEC_CODE #5 注释）
            # 都能被一眼看出，而不是读成一个看似纯粹的数字。
            "spec_id": sm[4] if sm else None,
            "spec_candidates": sm[5] if sm else 0,
            # spec 是否具备可投放 canary 的注入点：False 时上面的 iast_state 会被读成
            # no-injectable-param（投放侧缺口），不能当成探针漏命中。
            "spec_injectable": _injectable,
            # 该基准是否在 IAST 语义下结构性地没有 sink 可断言（见 _GOLDEN_NO_IAST_SINK）
            "iast_inapplicable": vtype in _GOLDEN_NO_IAST_SINK,
        })
        if vtype in _GOLDEN_NO_IAST_SINK:
            reconcile[-1]["iast_inapplicable_reason"] = _GOLDEN_NO_IAST_SINK[vtype]

    # blackboard（按族聚合，用于运行时证据面板）
    try:
        cur.execute(
            "SELECT family, COUNT(*) FROM vuln_blackboard WHERE task_id=? GROUP BY family ORDER BY 2 DESC",
            (task_id,))
        bb_by_family = {str(k): v for k, v in cur.fetchall()}
    except Exception:
        bb_by_family = {}

    tl = _three_layer(cur, task_id)

    # 失败归因（2026-10-03 M1）：把「未确认」按责任归属劈成四类。
    # 优先读 D2 落库的 failure_attribution 列；列为空（旧任务 / D2 未接线）时就地补算，
    # 保证历史任务也能读出归因分布。
    attribution = _attribution_stats(specs, golden, _facts)
    con.close()

    # 闭环分母 = 有 HTTP 入口、可运行时重放的基准条数（Java RMI 这类无入口项不计入，单列）
    golden_total = golden_applicable
    summary = {
        # ---- 真值两层（L_code / L_exploit）----
        # L_code：代码缺陷层，静态侧能看到的东西，不受运行时环境约束（== golden_total）。
        # L_exploit：可利用层，只有环境前提满足的条目才计入（前提明确不满足者剔除）。
        # 差集 env_unsupported **不是检测失败**，是环境打不通 —— 旧口径把它算进漏检，
        # 制造出永远修不好的「假漏检」（如 Tomcat 高版本 sanitize 掉 CRLF）。
        "golden_code_total": golden_total,
        "golden_exploit_total": golden_exploit_total,
        "golden_env_unsupported": golden_env_unsupported,
        "golden_env_unverified": golden_env_unverified,
        "exploit_detected": exploit_detected,
        "exploit_confirmed": exploit_confirmed,
        "exploit_detect_rate": round(exploit_detected / golden_exploit_total, 4) if golden_exploit_total else 0.0,
        "exploit_confirm_rate": round(exploit_confirmed / golden_exploit_total, 4) if golden_exploit_total else 0.0,
        "sca_findings": sca_count,
        "semantic_findings": semantic_findings,
        "specs_total": len(specs),
        "findings_total": len(finds),
        "golden_target": golden_target,
        "golden_total": golden_total,
        "golden_not_applicable": golden_not_applicable,
        # 2026-09-22：基准层 iast_state 分布。把「探针没命中」(no-arrival) 与
        # 「spec 无注入点」(no-injectable-param)、「该类 IAST 无 sink 可断言」(no-iast-sink) 分开计数，
        # 三者是不同性质的缺口，混在一起会把口径问题读成探针缺陷。
        "golden_state_dist": golden_state_dist,
        "detected": detected,
        "confirmed": confirmed,
        # 注意：detected/confirmed 是**基准层**口径 ——
        #   detected = 基准类是否被检出（命中 finding 或 spec）
        #   confirmed = 基准类是否匹配到 TriggerSpec（即「已入环」），**不是**「运行时已验证」。
        # 运行时确认请看 three_layer.d2.verified。
        "detect_rate": round(detected / golden_total, 4) if golden_total else 0.0,
        "confirm_rate": round(confirmed / golden_total, 4) if golden_total else 0.0,
        "blackboard": {
            "rows": tl["d2"]["rows"],
            "detected": tl["d2"]["detected"],
            "spec_backed": tl["d2"]["spec_backed"],
            "verified": tl["d2"]["verified"],
            "sink": tl["d2"]["sink"],
        },
        "iast_events": {
            "total": tl["d1"]["ev_tot"],
            "canary_match": tl["d1"]["ev_match"],
            "sink_reached": tl["d1"]["ev_sink"],
        },
        "three_layer": tl,
        "blackboard_by_family": bb_by_family,
        # 失败归因：未确认的四值判责分布（env/probe/pipeline/true_miss）。
        # 看**归因分布**而不是看未确认总数，才能判断一次改动到底修了哪一类。
        "failure_attribution": attribution,
    }

    if summary_only:
        return {
            "task_id": task_id,
            "generated_at": int(time.time()),
            "config": _config_snapshot(),
            "summary": summary,
            "reconcile_counts": {"detected": detected, "confirmed": confirmed, "total": golden_total},
        }

    out = {
        "task_id": task_id,
        "generated_at": int(time.time()),
        "config": _config_snapshot(),
        "golden_target": golden_target,
        "golden_total": golden_total,
        "summary": summary,
        "reconcile": reconcile,
    }
    if include_baseline and baseline_id is not None:
        try:
            out["baseline"] = _build(baseline_id, include_baseline=False, baseline_id=None, summary_only=False)
        except Exception:
            out["baseline"] = None
    return out


@router.get("/{task_id}")
def get_round_report(
    task_id: int,
    baseline: int | None = Query(default=None, description="基线 task-id，附带对比块"),
    summary_only: bool = Query(default=False, description="仅返回 summary + config（跨轮对比用）"),
):
    return _build(task_id, include_baseline=True, baseline_id=baseline, summary_only=summary_only)
