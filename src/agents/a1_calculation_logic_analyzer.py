"""计算与交易逻辑 静态分析（重构文档 §2.2 业务逻辑策略分析）。

核心本质：后端对关键数值（金额、数量、比例、运费）缺乏严格的边界校验和合理性检查。

识别「客户端可控参数直接参与金额/数量运算」且「服务端未做边界校验」：
- 客户端输入入口：@RequestParam / @RequestBody / request.getParameter / body.get / params.get 等
- 运算对象：price/total/amount/quantity/discount/freight/fee/balance/cost 等
- 运算符号：* + - / multiply add subtract divide BigDecimal Math.
- 缺失服务端校验：无 @Min/@Max/@DecimalMin/@Positive、无 if(qty>0)、无 Math.abs/clamp/rangeCheck 等

含两类场景：
- 金额/数量篡改（负数或极值）：quantity=-10 使总价变负，充值整数溢出，浮点精度薅羊毛
- 优惠叠加/门槛绕过：改数量使总价跌破满减门槛，运费字段改负数

均为 SAST 种子：产出假说交 D1 操作器做负数/极值变异重放验证，不追求 IAST 自主发现。

**定位：离线兜底（非主链路）。** 业务逻辑漏洞主链路为 ``A1BusinessLogicAIAgent``（LLM 语义识别）。
本分析器仅在未配置 LLM 时作为低成本启发式被调用，不在主链路中；CodeQL 在主链路承担辅助
结构验证（数值参数是否经过服务端边界校验函数）。
"""
# 业务逻辑漏洞主链路为 A1BusinessLogicAIAgent（LLM 语义识别）；本模块仅作离线兜底。
IS_PRIMARY_PATH = False

import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents._bl_common import extract_functions, has_token, safe_text, scan_spring_endpoints

# 客户端可控输入入口
_CLIENT_INPUT = re.compile(
    r"(?i)("
    r"request\.getparameter|request\.getparameter\w*|"
    r"@requestparam|@requestbody|requestbody|"
    r"body\[\s*[\"']|body\.get\(|params\.get\(|form\.get\(|"
    r"query\.get\(|req\.json|request\.json|payload\.get\(|dto\.get\(|"
    r"@pathvariable|getquery\w*\(|getparam\w*\(|getbody\w*\(|"
    r"request\.get\w*\(|ctx\.get\w*\(|input\.\w+"
    r")"
)
# 金额/数量字段
_MONEY_FIELD = re.compile(
    r"(?i)\b(price|total|totalfee|totalamount|amount|quantity|qty|count|"
    r"discount|freight|fee|balance|cost|subtotal|coupon|reduce|payable)\b"
)
# 运算符号/对象
_ARITH = re.compile(r"(?i)([\*/+\-]=|\b(multiply|add|subtract|divide|scale|round)\b|BigDecimal|Math\.)")
# 服务端边界校验 token（出现任一即视为有校验）
_SERVER_VALIDATION: Tuple[str, ...] = (
    "@min", "@max", "@decimalmin", "@decimalmax", "@positive", "@negative",
    "@range", "math.abs", "validatemoney", "validateamount", "validateprice",
    "checkamount", "checkrange", "validaterange", "assertpositive", "assertnonnegative",
    "signum", "clamp", "rangecheck", "numberformat", "validator",
    "if (quantity", "if(quantity", "if (qty", "if(qty", "if (amount", "if(amount",
    ">= 0", "<= 0", "> 0", "< 0", ">=0", "<=0", ">0", "<0",
    "quantity > 0", "quantity<0", "amount < 0", "total < 0", "qty <= 0",
)

# 并发 / 竞态类端点（claim/redeem/lock/acquire/consume 等）：其「金额/数量运算」通常是优惠券
# 并发领取的竞态条件，不属于「计算逻辑篡改」，归 RACE 类。改进清单 P1#2：仅按端点命名排除
# （精确匹配 camelCase 复合名 claimCoupon 等），避免因 @Transactional / synchronized 等通用
# 写法把正常 checkout 计算逻辑也误排除。
_RACE_OP = re.compile(
    r"(?i)(?<!\w)(claim|redeem|lock|unlock|acquire|consume|draw|grab|snatch|reserve|occupy)"
)

# 4.2 优惠叠加 / 门槛绕过：优惠/折扣的「叠加/合并/组合」操作，且门槛或总价取自客户端、服务端未重算。
_DISCOUNT_STACK_OP = re.compile(
    r"(?i)(applycoupon|addcoupon|stackcoupon|usecoupon|redemptioncoupon|combinepromo|"
    r"mergepromo|mergediscount|stackdiscount|couponstack|accumulatecoupon)"
)
# 服务端对门槛/总价做了重算或重校验 -> 不构成 4.2 假说。
# 注意：has_token() 对「小写后的方法体」做大小写敏感的字串匹配，故此处 token 必须全小写。
_THRESHOLD_REVALIDATE: Tuple[str, ...] = (
    "recompute", "recalcu", "recount", "revalid", "recalculate", "recomputethreshold",
    "verifythreshold", "checkthreshold", "validatethreshold", "recounttotal", "recalculatetotal",
)

# 控制器层路由感知补扫：客户端可控金额/数量/优惠参数直接采信、无服务端重算/边界校验。
_PAYMENT_ROUTE_RE = re.compile(
    r"^/order/(buy|checkout)$|^/order/[^/]+/(pay|paynow)$", re.IGNORECASE
)
_MONEY_PARAM_RE = re.compile(
    r"\b(amount|payamount|price|total|totalamount|quantity|qty|coupon|balance|discount|freight|fee|cost)\b",
    re.IGNORECASE,
)
# 服务端对金额做了重算/边界校验 -> 不构成金额篡改假说（须全小写，与 has_token 一致）
_AMOUNT_REVALIDATE: Tuple[str, ...] = (
    "recompute", "recalcu", "recount", "revalid", "recalculate", "verifyamount",
    "checkamount", "validateamount", "math.max", "clamp", "@decimalmin", "@positive",
    "@min", "max(0", "bigdecimal.zero", "signum", "rangecheck", ">= 0", "<= 0", "> 0",
    "< 0", ">=0", "<=0", ">0", "<0", "if (amount", "if(amount", "if (qty", "if(qty",
)
# 批量赋值（Mass Assignment）：BeanWrapper / setPropertyValue 把外部 Map 灌进实体且无字段白名单。
_MASS_ASSIGN_SINK = re.compile(r"(?i)(beanwrapper|setpropertyvalue|copyProperties|populate\s*\()")
_FIELD_WHITELIST = ("setallowedfields", "allowedfields", "whitelist", "fieldwhitelist", "permit")


def analyze_file(path: str, content: str, lang: Optional[str] = None) -> List[Dict[str, Any]]:
    """单文件分析：返回 计算/交易逻辑篡改 假说列表（含 4.1 数量篡改 / 4.2 优惠叠加 / 控制器层
    金额篡改·优惠叠加 / 批量赋值 Mass Assignment），均带 HTTP 路由以便落 trigger_spec。"""
    content = safe_text(content)
    if lang is None:
        lang = (path.rsplit(".", 1)[-1] if "." in path else "").lower()
    hypotheses: List[Dict[str, Any]] = []

    # ---- 控制器层路由感知补扫（直接抽取真实 HTTP 路由，避免假说因无路由被漏斗丢弃）----
    for route, http_method, blk, mname, line_idx in scan_spring_endpoints(content):
        if not route:
            continue
        low = blk.lower()
        sig = blk[:blk.index("{")] if "{" in blk else blk
        # 批量赋值：BeanWrapper/setPropertyValue 把外部 Map 灌入实体且无字段白名单
        if _MASS_ASSIGN_SINK.search(low) and not has_token(low, _FIELD_WHITELIST):
            hypotheses.append({
                "vuln_type": "CALCULATION_LOGIC",
                "category": "calculation_logic",
                "subtype": "mass_assignment",
                "family": "business-logic",
                "entry_point": f"{path}:{line_idx}",
                "target_endpoint": route,
                "http_method": http_method,
                "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
                "required_control_point": "对外部传入对象做字段白名单/类型校验（BeanWrapper.setAllowedFields），禁止整体 setPropertyValue 把 role/isVip/balance 等敏感字段灌入实体",
                "confidence": "high",
                "evidence": f"端点({route}) 用 BeanWrapper/setPropertyValue 把请求参数无差别写入实体且无字段白名单，存在批量赋值提权",
            })
            continue
        # 金额/优惠篡改：下单·支付类路由直接采信客户端 amount/coupon 且无服务端重算
        if _PAYMENT_ROUTE_RE.search(route):
            has_money = bool(_MONEY_PARAM_RE.search(sig)) or bool(_MONEY_PARAM_RE.search(low))
            if not has_money:
                continue
            if "coupon" in low and not has_token(low, _THRESHOLD_REVALIDATE):
                hypotheses.append({
                    "vuln_type": "CALCULATION_LOGIC",
                    "category": "calculation_logic",
                    "subtype": "discount_stacking_threshold_bypass",
                    "family": "business-logic",
                    "entry_point": f"{path}:{line_idx}",
                    "target_endpoint": route,
                    "http_method": http_method,
                    "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
                    "required_control_point": "服务端按购物车明细重算总价与满减门槛，禁止信任客户端自报的 coupon/threshold，单笔订单优惠需做幂等/上限约束",
                    "confidence": "medium",
                    "evidence": f"端点({route}) 直接采信客户端 coupon 并参与金额运算，未见服务端重算门槛/总价（优惠叠加/金额为负风险）",
                })
            elif not has_token(low, _AMOUNT_REVALIDATE):
                hypotheses.append({
                    "vuln_type": "CALCULATION_LOGIC",
                    "category": "calculation_logic",
                    "subtype": "amount_tampering",
                    "family": "business-logic",
                    "entry_point": f"{path}:{line_idx}",
                    "target_endpoint": route,
                    "http_method": http_method,
                    "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
                    "required_control_point": "服务端按商品定价重算金额，禁止信任客户端传入的 amount/payAmount，并对数值做非负/范围校验",
                    "confidence": "medium",
                    "evidence": f"端点({route}) 直接采信客户端 amount/payAmount 作为支付金额，未见服务端重算/边界校验（金额篡改风险）",
                })

    # ---- 服务/其它层 4.1/4.2 通用判定 ----
    # R24-E：原实现「凡方法体含 @XMapping 一律跳过」是过度抑制 —— 它把**路由补扫覆盖不到的
    # 控制器端点**（如 `/checkout`、`/api/order/checkout/coupons` 这类不匹配 _PAYMENT_ROUTE_RE
    # 的映射）也一并跳过，导致通用 4.1/4.2 分支对控制器层完全失效（test_41_generic_still_detected
    # 恒 0 命中）。改为**按方法名去重**：只有「路由补扫已经为该方法产出假说」时才跳过，
    # 既恢复通用分支对控制器端点的覆盖，又不产生同一方法的两条重复假说。
    _route_covered = {str(h.get("function") or "") for h in hypotheses}
    for fn in extract_functions(content, lang):
        if re.search(r"@(Get|Post|Put|Delete|Patch|Request)Mapping", fn["body"]) and fn["name"] in _route_covered:
            continue
        body = fn["body"]
        low_body = body.lower()
        # 并发/竞态端点不归入计算逻辑篡改（属 RACE 类），降低误报（改进清单 P1#2）
        if _RACE_OP.search(fn["name"]):
            continue

        # ---- 4.2 优惠叠加 / 门槛绕过（优先判定，避免与 4.1 重复计）----
        if _DISCOUNT_STACK_OP.search(fn["name"]):
            if _CLIENT_INPUT.search(body) and not has_token(low_body, _THRESHOLD_REVALIDATE):
                hypotheses.append({
                    "vuln_type": "CALCULATION_LOGIC",
                    "category": "calculation_logic",
                    "subtype": "discount_stacking_threshold_bypass",
                    "family": "business-logic",
                    "entry_point": f"{path}:{fn['start']}",
                    "function": fn["name"],
                    "required_control_point": "优惠叠加/门槛绕过防护：服务端按购物车明细重算总价与满减门槛，禁止信任客户端自报的 total/threshold，且单笔订单优惠需做幂等/上限约束",
                    "confidence": "medium",
                    "evidence": "优惠/折扣叠加操作读取客户端传入的 total/threshold 并直接累加优惠，未见服务端重算门槛/总价",
                })
            continue

        # ---- 4.1 金额/数量篡改（负数或极值）----
        if not (_CLIENT_INPUT.search(body) and _MONEY_FIELD.search(body) and _ARITH.search(body)):
            continue
        if has_token(low_body, _SERVER_VALIDATION):
            continue
        hypotheses.append({
            "vuln_type": "CALCULATION_LOGIC",
            "category": "calculation_logic",
            "family": "business-logic",
            "entry_point": f"{path}:{fn['start']}",
            "function": fn["name"],
            "required_control_point": "服务端边界校验：对 quantity/price/amount/discount/freight 做非负/范围/合理性校验（@DecimalMin/@Positive/clamp/rangeCheck）",
            "confidence": "medium",
            "evidence": "客户端可控参数直接参与金额/数量运算 且 方法体内未见服务端边界校验",
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
