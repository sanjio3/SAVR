"""滥用与资源消耗 静态分析（重构文档 §2.2 业务逻辑策略分析）。

核心本质：接口缺乏频率限制或资源消耗控制，被攻击者用于恶意消耗资源或骚扰他人。

两类场景：
1. 短信/邮件/通知轰炸：发送验证码/通知接口无 IP/手机号/时间间隔限制
2. 接口滥用/爬虫防护缺失：核心数据查询接口无 Token 校验、无请求频率限制、无数据混淆

识别「通知发送 / 批量数据查询导出」类操作（sendSms/sendEmail/export/search/list/...），
若方法体内未见频率限制/节流注解或逻辑（@RateLimit/bucket4j/redis incr/锁/频率控制等）
即构成滥用 DoS 假说（ABUSE_DOS）。

**定位：离线兜底（非主链路）。** 业务逻辑漏洞的主链路是 ``A1BusinessLogicAIAgent``（LLM 语义识别，
见 src/agents/a1_business_logic_ai_agent.py）。本分析器仅在未配置 LLM（ModelGateway 离线）时
作为低成本启发式被调用，不在主链路中。CodeQL 在主链路中承担辅助结构验证（发送/查询接口是否有限流）。

均为 SAST 种子：产出假说交 D1 操作器做高频重放验证（无 429 即疑似无限流），不追求 IAST 自主发现。
"""
# 业务逻辑漏洞主链路为 A1BusinessLogicAIAgent（LLM 语义识别）；本模块仅作离线兜底。
IS_PRIMARY_PATH = False

import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents._bl_common import extract_functions, has_token, safe_text, scan_spring_endpoints

# 退款滥用控制点 token（出现任一即视为有退款次数/额度/状态校验）
_REFUND_CONTROL: Tuple[str, ...] = (
    "alreadyrefunded", "refundcount", "refundtimes", "maxrefund", "refundstatus",
    "canrefund", "if (amount", "if(amount", "@idempotent", "idempotent", "refunded",
    "status ==", "status.equals", "once", "refundonce", "refundlimit", "refunddedup",
)

# 通知发送 / 批量数据查询导出 类操作
_NOTIFY_BULK_OP = re.compile(
    r"(?i)\b("
    r"sendsms|sendemail|sendmail|sendnotification|pushmessage|pushnotify|notify|"
    r"export|exportall|exportusers|download|downloadfile|"
    r"search|list|query|getlist|getpage|page|bulkquery|scrape|crawl|"
    r"getalldata|fetchall|dump"
    r")\b"
)
# 频率限制/节流 token（出现任一即视为有限流）
_RATE_LIMIT: Tuple[str, ...] = (
    "@ratelimit", "@throttle", "@ratelimiter", "ratelimit", "rate_limit", "ratelimiter",
    "rateLimiter", "throttle", "limiter", "bucket4j", "guava", "sentinel", "hystrix",
    "slidingwindow", "sliding window", "attempt limit", "lock", "lockout",
    "frequencycontrol", "frequency_control", "frequencyControl", "redis incr", "incr(",
    "per minute", "per second", "perminute", "persecond", "60 second", "seconds interval",
    "@sentinels", "flowcontrol", "flow control", "circuitbreaker", "leakybucket", "tokenbucket",
)


def analyze_file(path: str, content: str, lang: Optional[str] = None) -> List[Dict[str, Any]]:
    """单文件分析：返回 滥用 DoS 假说列表（含 通知/批量查询无频控 与 退款滥用 #33）。"""
    content = safe_text(content)
    if lang is None:
        lang = (path.rsplit(".", 1)[-1] if "." in path else "").lower()
    hypotheses: List[Dict[str, Any]] = []

    # ---- 路由感知补扫：退款滥用（#33）----
    for route, http_method, blk, mname, line_idx in scan_spring_endpoints(content):
        if not route:
            continue
        if re.search(r"^/order/[^/]+/refund$", route, re.IGNORECASE) or mname == "refund":
            low = blk.lower()
            if not has_token(low, _REFUND_CONTROL):
                hypotheses.append({
                    "vuln_type": "ABUSE_DOS",
                    "category": "abuse_dos",
                    "family": "abuse-dos",
                    "sub_type": "refund_abuse",
                    "entry_point": f"{path}:{line_idx}",
                    "target_endpoint": route,
                    "http_method": http_method,
                    "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
                    "required_control_point": "退款须校验额度/次数/订单状态：单笔订单仅可退一次、退款金额不超过实付、已退款订单不可再退，并加幂等防重放",
                    "confidence": "medium",
                    "evidence": f"端点({route}) 退款逻辑未校验退款额度/次数/订单状态，存在重复退款滥用风险",
                })
                continue

    # ---- 原有：通知发送 / 批量查询导出 无频率限制 ----
    for fn in extract_functions(content, lang):
        if not _NOTIFY_BULK_OP.search(fn["name"]):
            continue
        if has_token(fn["body"], _RATE_LIMIT):
            continue  # 有限流，不构成假说
        hypotheses.append({
            "vuln_type": "ABUSE_DOS",
            "category": "abuse_dos",
            "family": "abuse-dos",
            "entry_point": f"{path}:{fn['start']}",
            "function": fn["name"],
            "required_control_point": "频率限制/资源控制：发送类与批量查询类接口须加 @RateLimit/令牌桶/滑动窗口，并限制单 IP/账号频次",
            "confidence": "medium",
            "evidence": "通知发送/批量查询导出类操作 且 方法体内未见频率限制/节流校验",
        })
    return hypotheses


def analyze_sources(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量分析（与 A1 scan_files 输入形状对齐：[{path, content, language?}]）。"""
    out: List[Dict[str, Any]] = []
    for f in files or []:
        path = f.get("path") or f.get("file_path") or ""
        content = f.get("content") or f.get("source") or ""
        lang = f.get("language") or f.get("lang")
        out.extend(analyze_file(path, content, lang))
    return out
