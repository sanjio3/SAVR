"""M14：受害者可观测状态查询（state_query）—— 协议、解析、写端点推导。

为什么单独立模块：业务逻辑族（race / state_machine / calculation_logic）的确认判据
是「投攻击前后，受害者可观测状态发生非自身操作导致的异常变化」。这条判据要的只是
「去哪儿读、读哪些字段」，与具体哪个重放原语（replay_race / replay_state_machine /
replay_calculation）无关。把协议收在 core，D1 三个原语都吃同一份。

## 一、字段协议（唯一口径）

`state_query` 只有两种合法形状，其它一律判 None（宁可不差分，也不猜）：

  str   —— GET 该端点，响应整个 JSON 当快照。
  dict  —— {"endpoint": str, "method": "GET"?, "json_paths": [..]?, "text_paths": [..]?}
             endpoint   读端点路径（必填）
             method     默认 GET
             json_paths 点分路径，从 JSON 响应里逐层取值（["data.balance"]）
             text_paths 正则串，从**非 JSON** 文本响应里 $\\1$ 式抓取
                        （例：[r'"balance":\\s*"([^"]+)"']）
             两者都不给 → 整个 JSON 作快照（str 形状等价）

非 JSON 响应**必须显式给 json_paths/text_paths** 才采信。不给就返回 None：
整段正文做差分会被时间戳、CSRF token、随机数噪声淹没，那是制造假确认，
不是度量。宁可报「证据缺失」，不许伪造。

## 二、配置位置（优先级从高到低）

  1. spec["raw_json"]["exploit_spec"]["state_query"]  按条最准（历史遗留，`_dig` 穿透）
  2. spec["state_query"]                              按条（spec 顶层）
  3. target["state_query"]                            按靶场（dast_apps / workspace 设置）
  4. read_endpoint                                    两步重放三级定位产出的读端点
                                                      （它就是状态读端点，最省一次请求）
  5. derived                                          由写端点启发式推导 + 真实请求验证
  6. none                                             None（调用方降级为并发计数等弱信号）

## 三、derived 的纪律（本模块最要紧的一条）

推导只负责**出候选**，不负责**下结论**。候选必须被一次真实 GET（200 + 可解析）
验证过才算数；验证不了就是 None，调用方降级。推导永远不会凭路径形状断言
「这个端点能读回状态」——路径长得像，不代表 401、404 或者根本不做权限校验。

代价纪律：derived 候选的验证请求算在 5 次重放预算内，默认最多探 2 个候选。
"""

from typing import Any, Dict, List, Optional, Tuple

# derived 时候选验证的请求次数上限（含首个命中），其余原语可按需覆盖。
DEFAULT_DERIVED_CANDIDATE_BUDGET = 2

# 写端点末尾的常见动词：看到它，说明最后一段是「动作」不是「资源」，读状态得往上退。
_STATE_VERB_SUFFIXES = frozenset({
    "delete", "remove", "refund", "update", "create", "add", "submit",
    "approve", "cancel", "publish", "withdraw", "transfer", "pay",
    "recharge", "review", "claim", "consume", "deduct", "revoke", "reset",
})

# 动词后缀 → 可能的读端点兄弟段。只在「上溯一层」时按序追加。
_STATE_SIBLING_HINTS = {
    "withdraw": ("balance", "wallet", "account"),
    "transfer": ("balance", "wallet", "account"),
    "refund": ("order", "orders", "balance"),
    "pay": ("order", "orders", "balance"),
    "recharge": ("balance", "wallet", "account"),
    "deduct": ("balance", "wallet"),
    "consume": ("balance", "wallet"),
    "claim": ("order", "orders", "coupon", "coupons"),
    "review": ("order", "orders"),
    "update": (),
    "create": (),
    "add": (),
    "submit": (),
    "approve": (),
    "cancel": (),
    "publish": (),
    "revoke": (),
    "reset": (),
    "delete": (),
    "remove": (),
}

# 读端点段名 → 同前缀兄弟。命中则把兄弟追加在父路径下（/wallet → /wallet/balance）。
_READ_TAIL_HINTS = {
    "withdraw": ("balance", "wallet"),
    "transfer": ("balance", "wallet"),
    "refund": ("balance",),
    "pay": ("balance",),
}

# 通用读尾。只在父路径**不含路径参数**时追加 —— /order/{id}/list 这种组合几乎必 404，
# 白占预算（derived 时候选验证只给 2 次）。
_COMMON_READ_TAILS = ("list", "detail", "info", "me", "status", "orders")


def _dig(obj: Any, *path: str) -> Any:
    """穿透 JSON 字符串 / dict 的逐层取值（与 d1_service._dig 同语义，不共享避免循环依赖）。"""
    cur = obj
    for key in path:
        if cur is None:
            return None
        if isinstance(cur, str):
            try:
                import json
                cur = json.loads(cur)
            except Exception:
                return None
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def normalize_state_query(value: Any) -> Optional[Dict[str, Any]]:
    """把任意来源的 state_query 归一成 {endpoint, method, json_paths, text_paths}；不合法返回 None。"""
    if isinstance(value, str):
        value = value.strip().lstrip("/")
        if not value or value.startswith("{"):
            return None
        return {"endpoint": value, "method": "GET", "json_paths": [], "text_paths": []}
    if not isinstance(value, dict):
        return None
    ep = str(value.get("endpoint") or value.get("url") or "").strip()
    if not ep:
        return None
    return {
        "endpoint": ep.lstrip("/"),
        "method": str(value.get("method") or "GET").upper() or "GET",
        "json_paths": list(value.get("json_paths") or value.get("fields") or []),
        "text_paths": list(value.get("text_paths") or value.get("regexes") or []),
    }


def derive_state_query_candidates(write_route: str, limit: int = 4) -> List[str]:
    """由写端点路径启发式推导读端点候选（纯函数、零 I/O、不判成败）。

    顺序是**按命中概率排的，不是按路径形状排的** —— derived 时候选验证只有 2 次预算，
    排第三的候选等于不存在（真实库实测：/wallet/withdraw 的 /wallet/balance 原本排第三，
    预算内只探到 /wallet 和几乎必 404 的 /balance）。

      1) 同前缀换尾（/wallet/withdraw → /wallet/balance）  最准，只在末段非参数时做
      2) 父路径（/order/{id}/refund → /order/{id}）
      3) 动词兄弟（/ops/user/delete → /ops、/user/balance …）
      4) 父路径 + 通用读尾（list/detail/info/me/status/orders）
      5) 写端点自身（GET 兜底：很多「读状态」就是同一个资源）

    父路径含 {…} 路径参数时跳过「换尾」与「父+读尾」：/order/{id}/list 这类组合
    几乎必 404，白占预算。去重保序，最多 limit 个。
    """
    segs = [s for s in str(write_route or "").split("/") if s]
    if not segs:
        return []
    parent = "/".join(segs[:-1])
    last = str(segs[-1]).lower()
    has_param = ("{" in parent) or ("{" in last)
    out: List[str] = []

    def _add(path: str) -> None:
        path = ("/" + path.strip("/")).rstrip("/")
        if path and path != "/" and path not in out:
            out.append(path)

    is_verb = last in _STATE_VERB_SUFFIXES

    # 1) 同前缀换尾（仅父路径无参数时）
    if not has_param:
        for tail in _READ_TAIL_HINTS.get(last, ()):
            segs[-1] = tail
            _add("/".join(segs))
    # 2) 父路径
    if parent:
        _add(parent)
    # 3) 动词兄弟 + 上溯
    if is_verb:
        grand = "/".join(segs[:-2])
        if grand:
            _add(grand)
        for sib in _STATE_SIBLING_HINTS.get(last, ()):
            _add(f"{grand}/{sib}" if grand else sib)
            if parent:
                _add(f"{parent}/{sib}")
    # 4) 父路径 + 通用读尾（同样跳过参数路径）
    if parent and not has_param:
        for tail in _COMMON_READ_TAILS:
            _add(f"{parent}/{tail}")
    # 5) 自身兜底
    _add("/".join(segs))
    return out[:limit]


def resolve_state_query(spec: Optional[Dict] = None, target: Optional[Dict] = None,
                        read_endpoint: Any = None, derive: bool = True
                        ) -> Tuple[Optional[Dict[str, Any]], str]:
    """四级优先级解析 + 可选推导。返回 (cfg, source)。

    source ∈ {spec, target, spec_raw_json, read_endpoint, derived, none}
    —— 调用方要把 source 写进结果：对账时得能说清这条状态差分是哪一级给的。
    """
    spec = dict(spec or {})
    target = dict(target or {})

    raw = spec.get("state_query")
    source = "spec"
    if not raw:
        raw = target.get("state_query")
        source = "target"
    if not raw:
        raw = _dig(spec.get("raw_json"), "exploit_spec", "state_query")
        if raw:
            source = "spec_raw_json"
    if not raw and read_endpoint:
        raw = read_endpoint
        source = "read_endpoint"

    cfg = normalize_state_query(raw)
    if cfg:
        return cfg, source

    if derive:
        route = str(spec.get("target_endpoint") or "")
        if route:
            cands = derive_state_query_candidates(route)
            if cands:
                return ({"endpoint": cands[0], "method": "GET",
                         "json_paths": None, "text_paths": None,
                         "candidates": cands}, "derived")
    return None, "none"


def _as_json_obj(data: Any) -> Optional[Any]:
    """把「已解析对象 / JSON 文本」统一成对象。文本解析失败返回 None（不猜）。"""
    if isinstance(data, (dict, list)):
        return data
    if isinstance(data, str):
        try:
            import json
            parsed = json.loads(data)
            return parsed if isinstance(parsed, (dict, list)) else None
        except Exception:
            return None
    return None


def extract_state_fields(data: Any, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """从一次响应体里按 cfg 抠状态字段。抠不出（形状不符/无 paths）返回 None —— 不伪造。

    入参既可是 resp.json 的对象，也可是 resp.text。
    """
    if not isinstance(cfg, dict):
        return None
    paths = list(cfg.get("json_paths") or [])
    text_paths = list(cfg.get("text_paths") or [])
    if paths:
        obj = _as_json_obj(data)
        if obj is None:
            return None
        return {p: _dig(obj, *str(p).split(".")) for p in paths}
    if text_paths:
        if not isinstance(data, str):
            # 对象形状不给 text_paths 用：拿不到原文，抠不出来就 None。
            return None
        import re
        out: Dict[str, Any] = {}
        for pat in text_paths:
            try:
                m = re.search(str(pat), data)
            except re.error:
                return None
            if not m:
                continue
            out[f"text:{pat}"] = m.group(1) if m.groups() else m.group(0)
        return out if out else None
    obj = _as_json_obj(data)
    return obj if isinstance(obj, dict) else None


def state_query_applicable(cfg: Optional[Dict[str, Any]]) -> bool:
    """cfg 是否可用于快照：有 endpoint 且（有 paths 或形状可整取）。"""
    if not isinstance(cfg, dict) or not str(cfg.get("endpoint") or "").strip():
        return False
    return True
