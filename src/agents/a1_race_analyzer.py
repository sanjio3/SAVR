"""并发竞争（Race Condition）静态分析。

核心本质：读-判-写三段非原子，无行锁 / 条件扣减 / 原子更新，高并发下被重复消费或超卖。

识别「读-判-写」非原子模式：
- 读：findById / getBalance / getStock / countClaim / select ... 取当前值
- 判：if (balance < amount) / stock < qty / countClaim > 0 等比较
- 写：updateBalance / decreaseStock / insertClaim / subtract / add 回写
且方法体**缺少**原子/锁/条件更新保护（@Transactional / synchronized / SELECT ... FOR UPDATE /
``UPDATE ... SET x = x - n WHERE x >= n`` / ReentrantLock / 乐观锁 CAS / redis incr）。

典型靶场端点：/seckill（超卖）、/coupon/claim（限领超发）、/wallet/withdraw（余额双重消费）、
/wallet/transfer（转账重复消费）。

均为 SAST 种子：产出假说交 D1 操作器做并发重放验证（并发发出数十请求观察超卖/超发/透支），
不追求 IAST 自主发现。

**定位：离线兜底（非主链路）。** 业务逻辑漏洞主链路为 ``A1BusinessLogicAIAgent``（LLM 语义识别）。
本分析器作为低成本启发式，在在线主链路中也作为确定性 backstop 调用（避免 LLM 漏检竞态类）。
"""
# 业务逻辑漏洞主链路为 A1BusinessLogicAIAgent（LLM 语义识别）；本模块同时作为在线 backstop。
IS_PRIMARY_PATH = False

import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents._bl_common import has_token, safe_text, scan_spring_endpoints

# 竞态类端点（函数名命中即视为读-判-写候选）。仅保留精确竞态动词，避免 pay/order/submit/book 等
# 宽泛词误伤支付/下单/提交等非竞态端点。
_RACE_OP = re.compile(
    r"(?i)(?<!\w)("
    r"seckill|withdraw|transfer|claim|redeem|lock|unlock|acquire|consume|"
    r"draw|grab|snatch|reserve|occupy|deduct|charge|deposit"
    r")\b"
)
# 读操作（取当前值）
_READ_OP = re.compile(
    r"(?i)("
    r"findbyid|findone|getbyid|getbalance|getstock|countclaim|count|select|"
    r"query|load|getquantity|getamount|getcount|findbysubject|"
    r"selectforupdate|queryforupdate"
    r")"
)
# 写操作（回写）
_WRITE_OP = re.compile(
    r"(?i)("
    r"updatebalance|decreaseStock|decreasestock|increase|insertclaim|insert|update|"
    r"setbalance|setstock|add|subtract|delete|save|persist|merge|"
    r"updatequantity|deduct|charge|deposit"
    r")"
)
# 判断/比较（读后做阈值判断）
_CHECK_OP = re.compile(r"(?i)(compareto|[<>]=?|==|equals|if\s*\()")
# 原子/锁/条件更新保护（出现任一即视为已做并发防护）
_ATOMIC_GUARD: Tuple[str, ...] = (
    "@transactional", "synchronized", "for update", "forupdate",
    "where x >=", "where balance >=", "where stock >=", "where count >=",
    "set x = x", "set balance = balance", "set stock = stock",
    "reentrantlock", "stampedlock", "readwritelock", "lock(", "redis incr",
    "atomic", "cas", "compareandset", "optimistic", "version", "@version",
    "redislock", "redisson", "setnx", "lua script", "increment",
)


def analyze_file(path: str, content: str, lang: Optional[str] = None) -> List[Dict[str, Any]]:
    """单文件分析：返回 并发竞争 假说列表（带 HTTP 路由）。"""
    content = safe_text(content)
    hypotheses: List[Dict[str, Any]] = []
    for route, http_method, blk, mname, line_idx in scan_spring_endpoints(content):
        if not route:
            continue
        if not _RACE_OP.search(mname):
            continue
        low = blk.lower()
        has_read = bool(_READ_OP.search(low))
        has_write = bool(_WRITE_OP.search(low))
        has_check = bool(_CHECK_OP.search(low))
        if not (has_read and has_write and has_check):
            continue
        if has_token(low, _ATOMIC_GUARD):
            continue  # 已有原子/锁/条件更新保护，不构成假说
        hypotheses.append({
            "vuln_type": "RACE_CONDITION",
            "category": "race",
            "family": "race",
            "entry_point": f"{path}:{line_idx}",
            "target_endpoint": route,
            "http_method": http_method,
            "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
            "required_control_point": "并发安全：读-判-写须原子化——使用 @Transactional + 数据库行锁(SELECT ... FOR UPDATE) 或条件更新(UPDATE ... SET x=x-n WHERE x>=n)，或对额度/库存加分布式锁与幂等约束",
            "confidence": "medium",
            "evidence": f"端点({route}) 读-判-写三段非原子（先查余额/库存/已领，再判断，后回写），未见 @Transactional/行锁/条件扣减等并发防护，存在超卖/超发/双重消费风险",
        })
    return hypotheses


def analyze_sources(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量分析（与 A1 scan_files 输入形状对齐：[{path, content, language?}]）。"""
    out: List[Dict[str, Any]] = []
    for f in files or []:
        path = f.get("path") or f.get("file_path") or ""
        content = f.get("content") or f.get("source") or ""
        lang = f.get("language") or f.get("lang")
        try:
            out.extend(analyze_file(path, content, lang))
        except Exception as _e:
            import logging
            logging.getLogger(__name__).warning("[race] analyze_file skipped %s: %s", path, _e)
    return out
