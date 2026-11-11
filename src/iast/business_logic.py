"""业务逻辑漏洞 全类目编排。

此前 bola_race 仅落地 BOLA/RACE 两类；现已扩充为九大类全覆盖（依据 many_md/业务逻辑漏洞.MD）：
- bola            水平越权（IDOR）—— 已由 a1_bola_analyzer 覆盖
- vertical_privesc   垂直越权（低权限执行高权限操作）
- cross_module_privesc 跨模块/跨业务越权（Token scope/tenant 隔离缺失）
- state_machine      状态机/流程控制（跳跃/回退/闭环破坏）
- calculation_logic  计算与交易逻辑（金额/数量/优惠篡改）
- auth_session       认证与会话（验证码/密码重置缺陷）
- abuse_dos          滥用与资源消耗（轰炸/爬虫无限流）
- race               竞态条件（并发重复提交/非幂等写）
- signature_bypass   签名/JWT 绕过（alg:none / RS→HS 密钥混淆 / 空签名 / 弱密钥爆破，最正确最慢）

统一模式（与 BOLA/RACE 一致）：主链路 = ``A1BusinessLogicAIAgent``（LLM 语义识别）产出假说，
未配置 LLM 时降级为自写启发式分析器（a1_*_analyzer，仅离线兜底、IS_PRIMARY_PATH=False）；
→ D1 操作器做运行时重放验证（replay_*）。IAST 探针侧相关钩子属 Java 探针扩展（手册 3.11），不在
Python 侧实现，本模块只编排 Python 侧链路。

为兼容既有 bola_race 路由/端点，保留 bola_race_status/analyze_bola/verify_bola/verify_race
四个函数（行为与原 bola_race 模块一致）。
"""
import logging
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 若两条 spec 同时验证同一个用户，后取的快照可能已是「被前一条改过」的脏基线，
# 回滚就会把脏状态写回并固化 —— 比不验证更糟。故可回滚验证整段串行执行。
_RESTORE_LOCK = threading.Lock()

from src.agents.a1_bola_analyzer import analyze_sources as _analyze_bola
from src.application.d1_service import D1Service

ALL_CATEGORIES = (
    "bola", "vertical_privesc", "cross_module_privesc", "state_machine", "race",
    "calculation_logic", "auth_session", "abuse_dos", "signature_bypass",
)


def business_logic_status() -> Dict[str, Any]:
    """真实能力状态（取代占位）：九大类全覆盖。"""
    cats = {
        "bola": {
            "supported": True,
            "sast": "a1_bola_analyzer：识别敏感操作(按id取对象)+缺失归属校验",
            "verify": "D1 多身份重放(BOLA)：攻击者取受害者资源 id，命中受害者标识即 confirmed",
            "family": "IDOR",
        },
        "vertical_privesc": {
            "supported": True,
            "sast": "a1_vertical_privesc_analyzer：识别高权限操作+缺失角色/权限校验",
            "verify": "D1 replay_vertical：低权限身份直呼高权限端点被接受即 confirmed",
            "family": "vertical_privesc",
        },
        "cross_module_privesc": {
            "supported": True,
            "sast": "a1_vertical_privesc_analyzer：识别跨模块服务调用+缺失 scope/tenant 校验",
            "verify": "D1 replay_cross_module：跨域 Token 命中另一子系统内部端点被接受即 confirmed",
            "family": "cross_module_privesc",
        },
        "state_machine": {
            "supported": True,
            "sast": "a1_state_machine_analyzer：识别状态转换操作+缺失当前状态前置校验",
            "verify": "D1 replay_state_machine：非法/逆向状态下调用转换操作被接受即 confirmed",
            "family": "state-machine",
        },
        "calculation_logic": {
            "supported": True,
            "sast": "a1_calculation_logic_analyzer：识别客户端参数参与金额运算+缺失服务端边界校验",
            "verify": "D1 replay_calculation：负数/极值变异被接受且出现负数金额即 confirmed",
            "family": "business-logic",
        },
        "auth_session": {
            "supported": True,
            "sast": "a1_auth_session_analyzer：识别验证码回显/无校验环节/重置 Token 未绑定用户",
            "verify": "D1 replay_auth_session：受害者标识+复用凭证重置成功即 confirmed",
            "family": "auth-session",
        },
        "abuse_dos": {
            "supported": True,
            "sast": "a1_abuse_dos_analyzer：识别通知/批量查询操作+缺失频率限制",
            "verify": "D1 replay_abuse_dos：高频重放全成功且无 429/403 即 confirmed（缺失限流）",
            "family": "abuse-dos",
        },
        "race": {
            "supported": True,
            "sast": "并发分析：识别非幂等写操作+缺失分布式锁/版本号/事务隔离",
            "verify": "D1 replay_race：并发重复提交被接受且产生重复副作用（重复扣款/重复订单）即 confirmed",
            "family": "race-condition",
        },
        "signature_bypass": {
            "supported": True,
            "sast": "a1_auth_session_analyzer：识别签名/JWT 校验缺失或弱密钥（RS→HS 密钥混淆、alg:none、弱密钥）",
            "verify": "D1 replay_signature_bypass：系统性尝试 alg:none/密钥混淆/空签名/弱密钥爆破，任一变体被接受即 confirmed（最正确最慢）",
            "family": "auth-session",
        },
    }
    return {
        "status": "delivered",
        "delivered": True,
        "categories": cats,
        "design_notes": [
            "SAST-seeded：所有假说由 SAST 业务逻辑策略分析产出，D1 只做运行时影响验证",
            "九大类与 many_md/业务逻辑漏洞.MD 一一对应，分类标签即文档核心类别",
            "互补于注入类（CodeQL/内置规则）：本路径专攻业务逻辑语义，不依赖污点/签名",
        ],
    }


def analyze(files: List[Dict[str, Any]], categories: Optional[List[str]] = None,
            config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """源文件 → 业务逻辑漏洞假说（可指定 categories 子集；缺省全类目）。

    主链路 = ``A1BusinessLogicAIAgent``（AI 语义识别）；未配置 LLM 时降级为自写启发式
    analyzer（离线兜底）。CodeQL 在该链路中仅做辅助结构验证。

    config 携带 LLM/CodeQL 配置时，主链路走真实 GLM 语义识别（离线兜底仍可用）。

    输入形状：[{path, content, language?}]。返回假说列表，每项含 category / vuln_type / family。
    """
    from src.agents.a1_business_logic_ai_agent import A1BusinessLogicAIAgent
    return A1BusinessLogicAIAgent(config).analyze_sources(files, categories=categories)


def verify(category: str, trigger_spec: Dict[str, Any], target: Dict[str, Any],
           accounts: Any = None, concurrency: int = 5,
           gateway: Any = None, db: Any = None) -> Dict[str, Any]:
    """D1 运行时重放验证分发：category → 对应 replay_* 方法。

    gateway（ModelGateway）可选：传入且在线时，D1 重放判定可叠加 AI 语义复核（best-effort，
    失败回退启发式）；不传则纯确定性重放（与既有测试行为一致）。

    db（Database）可选但**必须传**：不传时 D1Service 会退化为临时库（D1Service.__init__
    的 tempfile 兜底），导致 replay_* 内的回填（victim_identifiers / accounts_json）写进
    临时库、永不落 data/app.db —— 生产端表现为 victim_identifiers 两轮全空。
    调用方（d2_facade._verify_business_logic / D1Service._replay_business_logic）均应传真实 db。
    """
    # 避免每个 replay_* 各自漏判。absent_id = 资源 id 换哨兵后照常投放（零持久化变更）；
    # skip = 凭据/金额/批量赋值类无法中和 → 整条不执行，如实标 skipped，绝不伪造证据。
    from src.iast.attack_context import neutralize_destructive_spec
    trigger_spec, _guard = neutralize_destructive_spec(trigger_spec)
    if _guard.get("action") == "skip":
        return {
            "confirmed": False, "verdict": "skipped_destructive_guard",
            "skipped": True, "status_code": 0, "response_summary": "",
            "request_state": "skipped", "reason": _guard.get("reason", ""),
            "destructive_guard": _guard,
        }

    svc = D1Service(db=db, gateway=gateway)
    cat = (category or "").lower()
    _ep = str((trigger_spec or {}).get("target_endpoint") or "").lower()
    def _finish(res: Any) -> Any:
        """把破坏性闸门记录挂在结果上（absent_id 生效时），供呈现层与报告如实说明。"""
        if isinstance(res, dict) and _guard:
            res.setdefault("destructive_guard", _guard)
        return res

    def _dispatch() -> Dict[str, Any]:
        """按 category 分发到对应 replay_*（供可回滚包装复用，保证不论哪条通道都受回滚保护）。"""
        if "/payment/callback" in _ep:
            return svc.replay_callback_signature_forgery(trigger_spec, target, accounts=accounts)
        if cat == "bola":
            return svc.replay_bola(trigger_spec, target, accounts=accounts)
        if cat == "race":
            return svc.replay_race(trigger_spec, target, concurrency=concurrency, accounts=accounts)
        if cat in ("vertical", "vertical_privesc"):
            return svc.replay_vertical(trigger_spec, target, accounts=accounts)
        if cat in ("cross_module", "cross_module_privesc", "cross_business"):
            return svc.replay_cross_module(trigger_spec, target, accounts=accounts)
        if cat in ("state_machine", "statemachine"):
            return svc.replay_state_machine(trigger_spec, target, accounts=accounts)
        if cat in ("calculation", "calculation_logic"):
            return svc.replay_calculation(trigger_spec, target, accounts=accounts)
        if cat in ("auth_session", "auth", "captcha", "password_reset"):
            return svc.replay_auth_session(trigger_spec, target, accounts=accounts)
        if cat in ("abuse_dos", "abuse", "dos"):
            return svc.replay_abuse_dos(trigger_spec, target, concurrency=concurrency, accounts=accounts)
        if cat in ("signature_bypass", "signature", "jwt_forgery", "jwt", "alg_none"):
            return svc.replay_signature_bypass(trigger_spec, target, accounts=accounts)
        raise ValueError(f"unknown business-logic category: {category}")

    # 契约：无基线不投放；投放后无条件回滚并复读；回滚失败一律改判 failure，绝不留持久变更换确认。
    if _guard.get("action") == "restore_after":
        with _RESTORE_LOCK:
            # 回滚目标必须等于实际被打到的资源：这里与 replay_* 走同一条 B 门禁解析，避免两边各解一套。
            # 解析失败不阻断 —— restorable_profile 取不到基线会自己放弃投放。
            try:
                _vres = svc._resolve_victim_identity(target, trigger_spec, accounts) or {}
                _rid = str(_vres.get("victim_resource_id") or "").strip()
            except Exception as _exc:  # noqa: BLE001
                logger.warning("[R26.restore] victim 解析失败，回滚退用账户自带 id：%s", _exc)
                _rid = ""
            if _rid:
                trigger_spec = dict(trigger_spec or {})
                trigger_spec["victim_resource_id"] = _rid
            with svc.restorable_profile(target, accounts, trigger_spec) as st:
                if not st.get("baseline"):
                    res: Dict[str, Any] = {
                        "confirmed": False, "verdict": "no_restore_baseline", "status_code": 0,
                        "response_summary": "", "request_state": "skipped",
                        "reason": "未取得可回滚基线（rid=%s），按 restore_after 契约不投放" % (st.get("rid") or "-"),
                    }
                else:
                    res = _dispatch()
        if not isinstance(res, dict):
            res = {"confirmed": False, "verdict": "non_dict_result"}
        res["restore"] = {"attempted": bool(st.get("baseline")),
                          "ok": st.get("restored"), "note": st.get("note") or "",
                          "rid": st.get("rid") or ""}
        if st.get("restored") is False:
            res["confirmed"] = False
            res["verdict"] = "restore_failed"
            res["reason"] = ("回滚失败，按 failure 处理（不留持久变更优先于取证）：%s"
                             % (st.get("note") or ""))
            logger.error("[R26.restore] verify 回滚失败，判据作废：rid=%s", st.get("rid"))
        return _finish(res)

    return _finish(_dispatch())


# ---------------- 向后兼容 bola_race 模块（行为与原模块一致）----------------
def bola_race_status() -> Dict[str, Any]:
    st = business_logic_status()
    return {
        "status": "delivered",
        "delivered": True,
        "bola": st["categories"]["bola"],
        "race": st["categories"]["race"],
        "design_notes": st["design_notes"],
    }


def analyze_bola(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return _analyze_bola(files)


def verify_bola(trigger_spec: Dict[str, Any], target: Dict[str, Any],
                accounts: Any = None, db: Any = None) -> Dict[str, Any]:
    return D1Service(db=db).replay_bola(trigger_spec, target, accounts=accounts)


def verify_race(trigger_spec: Dict[str, Any], target: Dict[str, Any],
                concurrency: int = 5, accounts: Any = None, db: Any = None) -> Dict[str, Any]:
    return D1Service(db=db).replay_race(trigger_spec, target, concurrency=concurrency, accounts=accounts)
