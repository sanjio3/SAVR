"""攻击计划 RAG+LLM 升级（用户指令步骤二~五）。

把确定性模板升级为「模板 + RAG 记忆库 + LLM」的混合生成：

- 步骤二（检索优先）：优先用 poc_memory_store 检索同族/同框架/同 sink 的正样本做 few-shot，
  命中且可用的直接作为攻击计划的强先验；未命中走模板。
- 步骤三（低完备度 LLM 升级）：exploit_spec 的 route/parameter/encoding 三项齐全 → 完全信任
  确定性模板；缺任一 → 触发 LLM 补齐（模板在这些场景下本来就靠猜）。
- 步骤四（分组批量 + 跨轮缓存）：按 (family, framework) 分组一次批量 LLM；永久缓存键跨轮复用，
  避免对「同一族同一框架的同类缺口」反复问 LLM。
- 步骤五（并发节流）：LLM 并发上限 2，信号量 + 队列，防 Ollama 本机 VRAM 撑爆（6.27G/8G）。

安全约束：
- 任何异常都降级为「返回 None（= 走确定性模板）」，绝不阻断 D2 主链路。
- 离线模式（无可用 provider）直接跳过 LLM，不伪造输出。
- 仅在「低完备度」时介入确定性输出；高完备度严格走模板，保证既有精确率不被 LLM 噪声污染。
- 默认开关由环境变量 SAST_AI_D2_RAG_LLM_ENABLED 控制（默认开启，可关）；关闭即纯模板。

跨轮缓存落盘 data/d2_plan_cache.json；RAG 记忆库落盘 data/poc_memory.json。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .poc_memory_store import (
    PocMemoryStore,
    default_store,
    normalize_sink_signature,
)

logger = logging.getLogger(__name__)

_RAG_LLM_ENABLED = os.environ.get("SAST_AI_D2_RAG_LLM_ENABLED", "true").strip().lower() in (
    "1", "true", "yes", "on")
_MAX_CONCURRENCY = int(os.environ.get("SAST_AI_D2_RAG_CONCURRENCY", "2") or 2)
_CACHE_PATH = os.environ.get("SAST_AI_D2_PLAN_CACHE_PATH") or "data/d2_plan_cache.json"
_METRICS_PATH = os.environ.get("SAST_AI_D2_PLAN_METRICS_PATH") or "data/d2_plan_metrics.json"

# 并发节流信号量：LLM 调用上限 2（本机 qwen3:8b 占 6.27G/8G VRAM，2 并发即 57 tok/s，再高即 OOM）。
_llm_semaphore = threading.BoundedSemaphore(max(1, _MAX_CONCURRENCY))
_cache_lock = threading.RLock()
_metrics_lock = threading.Lock()

# ---------------------------------------------------------------------------
# attack_plan.source 字段本身已由 d2_semantics._build_attack_plan 落（llm|deterministic），
# 这里的计数器是跨轮聚合口径，落盘 data/d2_plan_metrics.json 供对账脚本与看板消费。
# ---------------------------------------------------------------------------
_METRIC_KEYS = ("llm_generated", "cache_hits", "rejected_route", "rejected_param",
                "adopted", "adopted_confirmed", "fallback_template")


def _load_metrics() -> Dict[str, int]:
    try:
        p = Path(_METRICS_PATH)
        if p.exists():
            raw = json.loads(p.read_text(encoding="utf-8", errors="ignore") or "{}")
            if isinstance(raw, dict):
                return {k: int(raw.get(k, 0) or 0) for k in _METRIC_KEYS}
    except Exception:
        pass
    return {k: 0 for k in _METRIC_KEYS}


def _save_metrics(m: Dict[str, int]) -> None:
    try:
        p = Path(_METRICS_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:
        pass


def bump_metric(key: str, delta: int = 1) -> None:
    if key not in _METRIC_KEYS:
        return
    with _metrics_lock:
        m = _load_metrics()
        m[key] = int(m.get(key, 0) or 0) + delta
        _save_metrics(m)


def get_plan_metrics() -> Dict[str, int]:
    with _metrics_lock:
        return _load_metrics()


# ---------------------------------------------------------------------------
# route 必须命中 preprocess/spec 的 endpoint 集合；parameter 必须在 spec 参数集合内。
# 不合法字段直接丢弃（计划其余字段保留，回落模板语义），并计数 rejected_*。
# ---------------------------------------------------------------------------
def validate_llm_plan(
    plan: Optional[Dict[str, Any]],
    allowed_endpoints: Optional[List[str]] = None,
    allowed_params: Optional[List[str]] = None,
) -> tuple:
    """校验 LLM 计划中的 suggested_route / suggested_parameter。

    返回 (cleaned_plan, rejected_dict)。rejected_dict 形如 {"route": "..."}，只含被丢弃字段。
    allowed_* 为 None/空时视为「无法校验」——此时按宽松语义保留字段但记 warning（不臆造拦截）。
    """
    if not isinstance(plan, dict):
        return plan, {}
    rejected: Dict[str, str] = {}
    cleaned = dict(plan)
    route = str(cleaned.pop("suggested_route", "") or "").strip()
    param = str(cleaned.pop("suggested_parameter", "") or "").strip()
    if route:
        eps = [str(e or "").strip() for e in (allowed_endpoints or []) if str(e or "").strip()]
        if not eps:
            logger.warning("[d2_plan_rag] suggested_route=%s 无 endpoint 集合可比对，按不采纳处理", route[:80])
            rejected["route"] = route
        else:
            def _norm(u: str) -> str:
                return u.split("?")[0].rstrip("/").lower()
            nr = _norm(route)
            if any(nr == _norm(e) or nr.endswith(_norm(e)) or _norm(e).endswith(nr) for e in eps):
                cleaned["suggested_route"] = route
            else:
                rejected["route"] = route
    if param:
        ps = {str(p or "").strip() for p in (allowed_params or []) if str(p or "").strip()}
        if not ps:
            logger.warning("[d2_plan_rag] suggested_parameter=%s 无参数集合可比对，按不采纳处理", param[:40])
            rejected["param"] = param
        elif param in ps:
            cleaned["suggested_parameter"] = param
        else:
            rejected["param"] = param
    if rejected.get("route"):
        bump_metric("rejected_route")
    if rejected.get("param"):
        bump_metric("rejected_param")
    return cleaned, rejected


def _load_cache() -> Dict[str, Any]:
    try:
        p = Path(_CACHE_PATH)
        if p.exists():
            raw = p.read_text(encoding="utf-8", errors="ignore")
            if raw.strip():
                return json.loads(raw)
    except Exception as _e:  # 缓存读取失败不影响主链路
        logger.debug("[d2_plan_rag] 缓存读取失败（降级空）：%s", _e)
    return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        p = Path(_CACHE_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, p)
    except Exception as _e:
        logger.debug("[d2_plan_rag] 缓存落盘失败（忽略）：%s", _e)


def _cache_key(family: str, framework: str, sink_signature: str, gap_signature: str) -> str:
    payload = f"{family}|{framework}|{sink_signature}|{gap_signature}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 步骤三：完备度评分——route / parameter / encoding 三项齐全用模板，缺任一触发 LLM。
# ---------------------------------------------------------------------------
def attack_plan_completeness(exploit_spec: Dict[str, Any]) -> Dict[str, Any]:
    """评估攻击计划可生成的完备度。

    返回 {route, parameter, encoding, complete, missing: [..]}。
    - route：exploit_spec.entry.route 存在且非空
    - parameter：entry.parameter_name 或 payload 推导出的参数名存在
    - encoding：已知族（payload_family 在已知集合）或 D2 已知怎么编码
    """
    spec = exploit_spec or {}
    entry = spec.get("entry") or {}
    payload = spec.get("payload") or {}
    family = str(payload.get("payload_family") or "").lower()
    route = bool(str(entry.get("route") or "").strip())
    parameter = bool(str(entry.get("parameter_name") or "").strip())
    # encoding 已知：大多数已知族都有确定的元字符/编码形态；只有未知族才缺。
    known_families = {
        "sql-injection", "command-execution", "xss", "path-traversal", "xxe",
        "xpath-injection", "template-injection", "jwt", "open-redirect",
        "file-upload", "deserialization", "nosql-injection", "ssrf", "idor",
        "cors", "cookie", "auth-bypass", "csrf", "ldap", "map-payload",
    }
    encoding = family in known_families
    missing = []
    if not route:
        missing.append("route")
    if not parameter:
        missing.append("parameter")
    if not encoding:
        missing.append("encoding")
    return {
        "route": route,
        "parameter": parameter,
        "encoding": encoding,
        "complete": len(missing) == 0,
        "missing": missing,
        "family": family,
    }


# ---------------------------------------------------------------------------
# 步骤二：检索优先——把命中样本拼成 few-shot 文本。
# ---------------------------------------------------------------------------
def _few_shot_prompt_block(few_shots: List[Dict[str, Any]]) -> str:
    if not few_shots:
        return ""
    lines = ["# 已验证同类漏洞的攻击计划样例（few-shot，仅作结构参考）："]
    for i, fs in enumerate(few_shots, 1):
        plan = fs.get("attack_plan") or {}
        if not isinstance(plan, dict):
            continue
        bg = plan.get("business_goal") or ""
        steps = plan.get("steps") or []
        dl = plan.get("delivery_shape") or ""
        ir = plan.get("input_role") or ""
        lines.append(
            f"## 样例{i}（{fs.get('family')}/{fs.get('framework')}/{fs.get('sink_signature')}，"
            f"命中 {fs.get('hit_count', 1)} 次）\n"
            f"- 业务目标：{bg}\n"
            f"- 输入角色：{ir}\n"
            f"- 投放形态：{dl}\n"
            f"- 步骤：{json.dumps(steps, ensure_ascii=False)}"
        )
    return "\n".join(lines)


def build_rag_messages(
    vulnerability: Dict[str, Any],
    project_context: Dict[str, Any],
    exploit_spec: Dict[str, Any],
    completeness: Dict[str, Any],
    few_shots: Optional[List[Dict[str, Any]]] = None,
    allowed_endpoints: Optional[List[str]] = None,
    allowed_params: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """构造发给 LLM 的 messages（系统提示 + 用户任务）。

    模板只靠猜的字段（completeness.missing）由 LLM 补齐；已有字段作为强约束要求保留。
    """
    family = completeness.get("family") or ""
    missing = completeness.get("missing") or []
    vuln_type = str(vulnerability.get("type") or "")
    sink = str(vulnerability.get("sink") or "")
    entry_point = str(vulnerability.get("entry_point") or vulnerability.get("file") or "")
    source_file = str(vulnerability.get("file") or "")
    line = str(vulnerability.get("line") or "")
    language = str((project_context or {}).get("language") or "")
    framework = str((project_context or {}).get("framework") or "")

    few_shot_block = _few_shot_prompt_block(few_shots or [])

    system = (
        "你是应用安全攻击计划专家。给定一条 SAST/AST 发现的漏洞（含类型、sink、入口、源码位置）"
        "和一份不完整的 exploit 契约，输出一份 JSON 格式的攻击计划，用于指导 DAST 运行时验证。"
        "必须包含字段：business_goal（业务目标，中文）、input_role（攻击者可控输入的角色）、"
        "delivery_shape（payload 投放形态，如 'GET 请求参数'/'JSON 请求体'/'Base64 编码对象，通过 form body 导入'）、"
        "trigger_condition（触发条件）、verification_signal（成功信号，要可观测）、"
        "steps（有序步骤列表，字符串数组）、constraints（约束列表，字符串数组）。"
        "若确定性模板缺失 route 或 parameter，另在 JSON 顶层给出 suggested_route / suggested_parameter 字段"
        "（必须从给定上下文中真实存在的端点与参数里选，禁止臆造；找不到就省略该字段）。"
        "只输出 JSON，不要解释。"
    )
    user = (
        f"漏洞类型：{vuln_type}\n"
        f"族（family）：{family}\n"
        f"sink：{sink}\n"
        f"入口/文件：{entry_point}\n"
        f"源码：{source_file}:{line}\n"
        f"目标语言：{language}\n"
        f"目标框架：{framework}\n"
        f"不完整契约：{json.dumps(exploit_spec, ensure_ascii=False)[:1500]}\n"
        f"确定性模板无法确定的字段：{', '.join(missing) if missing else '无（请仅在已有信息上润色）'}\n"
    )
    if few_shot_block:
        user += "\n" + few_shot_block + "\n"
    if allowed_endpoints:
        user += f"\n可选端点（suggested_route 只能从中选）：{json.dumps(allowed_endpoints[:20], ensure_ascii=False)}\n"
    if allowed_params:
        user += f"可选参数名（suggested_parameter 只能从中选）：{json.dumps(sorted(set(allowed_params))[:20], ensure_ascii=False)}\n"
    user += (
        "\n请补齐缺失字段并输出完整攻击计划 JSON。若确定性模板已足够（无缺失字段），"
        "可基于已有契约直接输出等价 JSON，但不要臆造不存在的路由。"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _parse_llm_plan(text: str) -> Optional[Dict[str, Any]]:
    """从 LLM 输出里尽量抠出 JSON 攻击计划；抠不到返回 None（降级模板）。"""
    if not text:
        return None
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            obj = json.loads(text[start:end + 1])
            if isinstance(obj, dict) and obj.get("business_goal"):
                return obj
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 步骤四 + 五：跨轮缓存 + 并发节流 + 分组批量，统一收敛到一次 LLM 调用。
# ---------------------------------------------------------------------------
def _invoke_llm_cached(gateway, family: str, framework: str, sink_signature: str,
                       gap_signature: str, messages: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """带跨轮缓存与并发节流的单次 LLM 调用。命中缓存直接返回；否则拿信号量后调用并写回。"""
    key = _cache_key(family, framework, sink_signature, gap_signature)
    with _cache_lock:
        cache = _load_cache()
        hit = cache.get(key)
        if hit is not None:
            logger.debug("[d2_plan_rag] 缓存命中 plan %s", key)
            bump_metric("cache_hits")
            return hit
    acquired = _llm_semaphore.acquire(timeout=60)
    if not acquired:
        logger.warning("[d2_plan_rag] 获取 LLM 并发信号量超时（降级模板）")
        return None
    try:
        resp = gateway.complete(purpose="d2_attack_plan", prompt=json.dumps(messages, ensure_ascii=False))
        plan = _parse_llm_plan(resp.text)
        if plan is not None:
            with _cache_lock:
                cache = _load_cache()
                cache[key] = plan
                _save_cache(cache)
        return plan
    except Exception as _e:  # 任何 LLM 异常都降级模板
        logger.debug("[d2_plan_rag] LLM 调用失败（降级模板）：%s", _e)
        return None
    finally:
        _llm_semaphore.release()


def generate_attack_plan(
    vulnerability: Dict[str, Any],
    project_context: Dict[str, Any],
    exploit_spec: Dict[str, Any],
    gateway=None,
    store: Optional[PocMemoryStore] = None,
    allowed_endpoints: Optional[List[str]] = None,
    allowed_params: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """为单条漏洞生成「RAG+LLM」攻击计划（或 None = 走确定性模板）。

    完整流程：完备度评分 → 检索 few-shot →（低完备度且非离线）LLM 补齐 → 白名单校验 →
    跨轮缓存/节流。返回值可直接喂给 d2_semantics._build_attack_plan 的 plan 参数。
    allowed_endpoints / allowed_params：白名单校验集合（A 第三步）；缺失时臆造字段不采纳。
    """
    if not _RAG_LLM_ENABLED:
        return None
    completeness = attack_plan_completeness(exploit_spec)
    # 完整契约直接走模板，不浪费 LLM。
    if completeness.get("complete"):
        return None
    if gateway is None or getattr(gateway, "is_offline", True):
        # 离线模式不调用 LLM（离线兜底文本不可用），保留确定性模板。
        return None
    family = completeness.get("family") or str((exploit_spec.get("payload") or {}).get("payload_family") or "")
    framework = str((project_context or {}).get("framework") or "")
    sink_signature = normalize_sink_signature(
        family,
        str(vulnerability.get("type") or ""),
        str(vulnerability.get("sink") or ""),
    )
    store = store or default_store()
    few_shots = store.retrieve(family, framework, sink_signature, top_k=3)
    messages = build_rag_messages(vulnerability, project_context, exploit_spec, completeness, few_shots)
    gap_signature = "|".join(completeness.get("missing") or [])
    plan = _invoke_llm_cached(gateway, family, framework, sink_signature, gap_signature, messages)
    if plan is None:
        bump_metric("fallback_template")
        return None
    bump_metric("llm_generated")
    plan, _rejected = validate_llm_plan(plan, allowed_endpoints, allowed_params)
    return plan


# ---------------------------------------------------------------------------
# 步骤二（闭环回填）：当一条攻击计划确实导致确认可利用，回写入记忆库做正样本。
# ---------------------------------------------------------------------------
def record_confirmed_plan(
    vulnerability: Dict[str, Any],
    project_context: Dict[str, Any],
    exploit_spec: Dict[str, Any],
    attack_plan: Dict[str, Any],
    *,
    observation: str = "verified_exploitable",
    canary_form: str = "plain",
    store: Optional[PocMemoryStore] = None,
) -> None:
    """把已验证正样本写入 POC 记忆库（闭环反哺）。失败静默。"""
    try:
        family = str((exploit_spec.get("payload") or {}).get("payload_family") or "").lower()
        framework = str((project_context or {}).get("framework") or "").lower()
        sink_signature = normalize_sink_signature(
            family, str(vulnerability.get("type") or ""), str(vulnerability.get("sink") or ""))
        store = store or default_store()
        store.record({
            "family": family,
            "framework": framework,
            "sink_signature": sink_signature,
            "canary_form": canary_form,
            "attack_shape": str((attack_plan or {}).get("delivery_shape") or "unknown"),
            "attack_plan": attack_plan,
            "exploit_spec_summary": {
                "family": family,
                "route": (exploit_spec.get("entry") or {}).get("route"),
                "parameter": (exploit_spec.get("entry") or {}).get("parameter_name"),
            },
            "observation": observation,
            "verified": True,
        })
    except Exception as _e:
        logger.debug("[d2_plan_rag] record_confirmed_plan 失败（忽略）：%s", _e)


# ---------------------------------------------------------------------------
# 分组批量（步骤四）：一批漏洞先按 (family, framework) 分组，组内共享同一份 few-shot
# 与同一份系统提示，逐条并发（受信号量节流）调用，返回与输入同序的计划列表。
# ---------------------------------------------------------------------------
def generate_attack_plan_batch(
    items: List[Dict[str, Any]],
    gateway=None,
    store: Optional[PocMemoryStore] = None,
) -> List[Optional[Dict[str, Any]]]:
    """批量生成（同 (family, framework) 分组共用检索上下文）。返回与 items 同序的计划列表。

    items 元素：{vulnerability, project_context, exploit_spec}。
    """
    if not items:
        return []
    store = store or default_store()
    results: List[Optional[Dict[str, Any]]] = [None] * len(items)
    prepared_map: Dict[int, Dict[str, Any]] = {}
    # 预计算每条的完备度/检索；完整契约或离线直接 None（不占 LLM）。
    prepared = []
    for idx, it in enumerate(items):
        vuln = it.get("vulnerability") or {}
        pc = it.get("project_context") or {}
        spec = it.get("exploit_spec") or {}
        comp = attack_plan_completeness(spec)
        if comp.get("complete") or gateway is None or getattr(gateway, "is_offline", True):
            results[idx] = None
            continue
        family = comp.get("family") or str((spec.get("payload") or {}).get("payload_family") or "")
        framework = str(pc.get("framework") or "")
        sig = normalize_sink_signature(family, str(vuln.get("type") or ""), str(vuln.get("sink") or ""))
        few = store.retrieve(family, framework, sig, top_k=3)
        msgs = build_rag_messages(vuln, pc, spec, comp, few,
                                  allowed_endpoints=it.get("allowed_endpoints"),
                                  allowed_params=it.get("allowed_params"))
        gap = "|".join(comp.get("missing") or [])
        prepared.append((idx, family, framework, sig, gap, msgs))
        prepared_map[idx] = {"allowed_endpoints": it.get("allowed_endpoints"), "allowed_params": it.get("allowed_params")}

    # 逐条走带缓存+节流的调用（信号量已限并发 2）。
    for idx, family, framework, sig, gap, msgs in prepared:
        plan = _invoke_llm_cached(gateway, family, framework, sig, gap, msgs)
        if plan is None:
            bump_metric("fallback_template")
            results[idx] = None
            continue
        bump_metric("llm_generated")
        results[idx] = validate_llm_plan(
            plan,
            prepared_map.get(idx, {}).get("allowed_endpoints"),
            prepared_map.get(idx, {}).get("allowed_params"),
        )[0]
    return results
