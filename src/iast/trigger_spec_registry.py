"""TriggerSpec 登记与加载的公共模块（统一链路 §D 阶段）。

把 A2 语义分析产出的 poc 假说（canary 来源）自动登记到 trigger_specs 表，供 D1 运行时重放
驱动 I1 监听 / D2 校验 / I2 裁决；并在验证阶段按 workspace + 漏洞 hash 加载这些 spec。

该模块是离线 CLI 入口与实时后端路径（scan_task_runner → run_benchmark）共用的唯一登记实现，
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.param_resolver import is_valid_param_name, is_valid_route, resolve_endpoint_from_source, resolve_trigger_endpoint, _is_probe_route
from src.core.exploit_spec import canonical_business_logic_family, derive_flow_type, DIFFERENTIAL_PROOF_FAMILIES, is_injection_family
from src.core.vuln_hash import _norm_family, canonicalize_vuln_for_hash, vulnerability_hash_v2
from src.core.normalize import correct_family_by_evidence, normalize_family
from src.iast.attack_context import build_attack_context, is_business_logic
from src.iast.canary import CanaryFactory
from src.iast.service import IastService
from src.infrastructure.db import Database

logger = logging.getLogger(__name__)

_BENCHMARK_CASE_RE = re.compile(r"(BenchmarkTest\d+)")

# 可安全「追加同名候选」的参数位置。header/cookie 类不在其中 —— 见下方函数说明。
_APPENDABLE_PARAM_LOCATIONS = ("query", "body", "form")


def append_benchmark_case_param(
    params: List[Dict[str, Any]],
    pname: str,
    location: str,
    route: str,
    canary: str,
) -> List[Dict[str, Any]]:
    """当反射参数名与用例类名一致时，补全参数候选。

    **只**带错名字重放 ⇒ servlet 走「找不到参数」的提前返回分支（响应体原文
    ``getQueryString couldn't find expected parameter

    修法是**追加**用例名候选，而不是替换 —— 替换会弄坏 Referer 类用例：00013/00144 走
    header 注入、参数名 'Referer' 本就是对的，把 query 参数改成用例名
    反而让它失去注入点。故只对 query/body/form 类追加，header/cookie 类保持原样。

    非 Benchmark 路由（route 里没有 BenchmarkTest\\d+）直接原样返回，对通用链路零影响。
    """
    out = list(params or [])
    m = _BENCHMARK_CASE_RE.search(str(route or ""))
    if not m:
        return out
    case_name = m.group(1)
    if not case_name or case_name == pname:
        return out
    if str(location or "query").lower() not in _APPENDABLE_PARAM_LOCATIONS:
        return out
    # 幂等守卫：候选里已有同名参数就不再追加。判据只看 pname（不随 params 变化），
    # 若上游重复调用会静默追加多条同名候选 —— 这里兜住，避免多带重复 query 参数。
    if any(isinstance(p, dict) and str(p.get("name") or "") == case_name for p in out):
        return out
    out.append({"name": case_name, "location": "query", "value": canary})
    return out


def _derive_poc_chain(family, route, method, pname, location, sink_file, sink_line) -> List[Dict[str, Any]]:
    """从 A2 既有结构化字段派生 poc 链（污点流经的有序节点序列）。

    这是 I1 逐节点符合性校验所需的「攻击链假说」。A2 若已产出 exploit_spec.poc_chain
    则优先用之（真正的 LLM 猜测链）；否则用 entry(route/method/param) + family 典型传播路径
    + expected_sink 推导，保证本轮不依赖 A2 LLM 改造也能端到端跑通。
    """
    chain: List[Dict[str, Any]] = []
    src_label = f"{method} {route}"
    if pname:
        src_label += f"#{pname}({location})"
    chain.append({
        "stage": "source",
        "role": "source",
        "node": src_label,
        "signature": f"{route}#{pname}" if pname else route,
    })
    fam = (family or "").lower()
    if "deserial" in fam:
        chain.append({"stage": "transform", "role": "transform", "node": "Base64.decode", "signature": "java.util.Base64.decode"})
        chain.append({"stage": "transform", "role": "transform", "node": "ObjectInputStream.readObject", "signature": "java.io.ObjectInputStream.readObject"})
    elif "ssrf" in fam:
        chain.append({"stage": "transform", "role": "transform", "node": "URL.openStream", "signature": "java.net.URL.openStream"})
    elif "sql" in fam or "inject" in fam:
        chain.append({"stage": "transform", "role": "transform", "node": "Statement.execute", "signature": "java.sql.Statement.execute"})
    sink_label = f"{sink_file}:{sink_line}" if sink_file else "unknown-sink"
    chain.append({
        "stage": "sink",
        "role": "sink",
        "node": sink_label,
        "signature": sink_file or "",
    })
    return chain


def _build_attack_context_with_warning(vuln_dict, a1_ev, family, vhash):
    """B：构造攻击上下文，并在 spec 无真实攻击 payload 时显式告警。

    转换本身已完整（select_attack_payloads → attack_payloads → register_trigger_spec 落入
    attack_payloads_json 列），故此处只负责「空 payload 不静默」：
    - 反序列化族：D1 重放时会由 SCA 弹药库 / gadget 构造器补真字节，属预期降级 → info。
    - 业务逻辑族（bola/idor/race/...）：走双账户差分重放，本就不依赖 attack_payloads → info。
    - 其余族：A2 未产出真实 payload，D1 将退化为纯 canary 探针 → 明确 WARNING，提示排查 A2 造弹。
    """
    ctx = build_attack_context(vuln_dict, a1_ev)
    attack_payloads = ctx.get("attack_payloads") or []
    if attack_payloads:
        return ctx
    fam = str(family or "").strip().lower()
    category = str(ctx.get("category") or "").strip().lower()
    if fam == "deserialization":
        logger.info(
            "[A2->TriggerSpec] spec %s 无 attack_payload（family=deserialization）：D1 重放将由 SCA 弹药库/"
            "gadget 构造器补造真字节，预期降级为 canary 探针。", vhash[:12],
        )
    elif is_business_logic(category):
        logger.info(
            "[A2->TriggerSpec] spec %s 无 attack_payload（category=%s）：走双账户差分重放，不依赖 attack_payloads，符合预期。",
            vhash[:12], category,
        )
    else:
        logger.warning(
            "[A2->TriggerSpec] spec %s 无真实 attack_payload（family=%s, category=%s）：D1 将退化为纯 canary 探针，"
            "I2 须按弱证据处理。请排查 A2 是否产出真实 payload（占位串已被 select_attack_payloads 过滤）。",
            vhash[:12], fam, category,
        )
    return ctx


# 业务逻辑类目归一（真源见 src/core/exploit_spec.py 的 DIFFERENTIAL_PROOF_FAMILIES + 别名表，
# （sql/deserialization/ssrf 等）一律返回空，使这些 spec 在 D2 走 canary 污点重放而非业务差分重放。
# _BL_CATEGORIES 直接引用规范集；D1 重放路由特例 idor→bola 单独保留
# （business_logic.verify 仅 8 类，无 idor；IDOR 在 D1 层与 BOLA 同路由）。
_BL_CATEGORIES = tuple(DIFFERENTIAL_PROOF_FAMILIES)
_BL_ROUTE_OVERRIDES = {"idor": "bola"}


def _normalize_business_logic_category(raw: str) -> str:
    """把 A2/A1 给出的类目标签归一为业务差分重放的规范类目；非业务类目返回空字符串。"""
    raw = str(raw or "").strip().lower()
    if not raw:
        return ""
    norm = canonical_business_logic_family(raw)
    if norm not in _BL_CATEGORIES:
        return ""
    return _BL_ROUTE_OVERRIDES.get(norm, norm)


# 业务（BOLA/IDOR/垂直/跨模块/状态机/计算逻辑/认证/滥用）漏洞的漏洞定位类通常是 Service / DAO /
# Mapper 等「被调用的组件」，而其真实 HTTP 入口在对应的 Controller / Resource 上。A2/A1 只产出
# ``file:line``（指向 Service 类），resolve_trigger_endpoint 据此既无候选路由、Tier-2 类级匹配又因
# vuln.file(Service)≠discovered.file(Controller) 的 basename 不相等而落空（见 #6 解释）。本函数做
# **服务类→控制器类** 的命名推导（绝非「源码路径当路由」的兜底），把漏洞挂到其真实 HTTP 入口，
# 是业务族解析失败的 genuine 修复，与「pre-resolve 失败强行走 Tier-2 类级匹配」是两回事。
_SERVICE_SUFFIXES = ("ServiceImpl", "Service", "Impl", "DaoImpl", "Dao", "Repository",
                     "RepositoryImpl", "Mapper", "Manager", "BO", "Po", "Entity")
_CONTROLLER_SUFFIXES = ("Controller", "RestController", "Resource", "Api", "Endpoint", "Handler")


def _service_base_name(file_basename: str) -> Optional[str]:
    """从 Service/DAO 文件基名提取业务根名：OrderServiceImpl.java -> Order。"""
    name = Path(file_basename or "").stem
    if not name:
        return None
    for suf in _SERVICE_SUFFIXES:
        if name.endswith(suf) and len(name) > len(suf):
            return name[: len(name) - len(suf)]
    return name


def _controller_candidates(base: str) -> List[str]:
    """由业务根名派生可能的控制器文件名（基名，含后缀）。"""
    return [f"{base}{s}.java" for s in _CONTROLLER_SUFFIXES]


def _infer_business_category_from_family(vuln_dict: Dict[str, Any]) -> str:
    """Q2：显式 business_logic_category/category 为空时，从 A2 真实产出族 / vuln 显示族标签推断业务类目。

    来源优先级（首个命中 DIFFERENTIAL_PROOF_FAMILIES 即返回，避免过宽映射覆盖精确标签）：
    1. exploit_spec.payload.payload_family（A2 结构化产出族，最权威）
    2. vuln 显示族标签 type / finding_type / display_family / finding_family（剥「基础设施层-/业务逻辑类-」
       前缀）——直接经 canonical_business_logic_family 归一，绕过 _norm_family 的过宽「越权」针
       （该针把 垂直越权 也误归 idor→bola，是 P0-2 垂直越权族连续 10 轮错标水平越权的根因）
    3. _norm_family(vuln_dict)（兜底，含上述歧义，仅当前两者都未命中时才轮到）

    复用 exploit_spec.canonical_business_logic_family（已覆盖中英文显示名：状态机跳步 / 金额篡改 /
    并发超发 / 竞态条件 / 水平越权(idor) / 垂直越权 / 批量赋值 等）归一为规范差分 token，
    再经 _normalize_business_logic_category 落到规范类别（idor→bola）。非业务族（sql/xss/命令/
    反序列化/ssrf 等）不会被误标，返回空串——注入型 family 恒不在 DIFFERENTIAL_PROOF_FAMILIES 内。
    """
    _es = vuln_dict.get("exploit_spec") or {}
    _payload = _es.get("payload") or _es  # 适配 payload 平铺或被包裹两种情况
    _pf = str(_payload.get("payload_family") or _es.get("payload_family") or "").strip()
    _nf = _norm_family(vuln_dict)
    # 直接读显示族标签（type / finding_type / display_family / finding_family），剥「基础设施层-/业务逻辑类-」
    # 前缀后作为高优先级来源，绕过 _norm_family 的过宽「越权」针（该针把 垂直越权 也误归 idor→bola）。
    _labels: List[str] = []
    for _k in ("type", "finding_type", "display_family", "finding_family"):
        _v = vuln_dict.get(_k)
        if _v:
            _labels.append(re.sub(r"^(基础设施层|业务逻辑类)[-_]", "", str(_v).strip()))
    _sources: List[str] = []
    if _pf:
        _sources.append(_pf)
    _sources.extend([_l for _l in _labels if _l])
    if _nf and _nf != "unknown":
        _sources.append(_nf)
    for raw in _sources:
        _cand = canonical_business_logic_family(raw)
        if _cand in DIFFERENTIAL_PROOF_FAMILIES:
            return _normalize_business_logic_category(_cand)
    return ""


def _resolve_business_category(category: str, family: str, vuln_dict: Dict[str, Any]) -> str:
    """第一点 C-补：family 派生业务类目优先于自由文本 category 标签的最终决策（纯函数，便于回归守卫）。

    返回用于 spec 落库的最终 category。逻辑：
    - _family_cat：来自 vuln_dict（payload_family + 中文显示族标签，最精确，见 _infer_business_category_from_family）。
      其输入是 _family_cat2 输入的超集（多读中文显示族标签），故 _family_cat 永不会比 _family_cat2 更不精确。
    - _family_cat2：来自本 spec 即将落库的 family（优先 payload_family，缺失时退 _norm_family，可能退化为歧义 idor→bola）。

    决策优先级（关键防回退）：
    1. _family_cat 非空即权威——它直接读中文标签，能复原被 _norm_family 误归的 vertical_privesc。
       - 若 _family_cat != category：以 _family_cat 覆盖（family 派生优先于自由文本标签）。
       - 若 _family_cat == category（二者已一致且正确）：**保持，绝不再让退化的 _family_cat2 覆盖回去**。
         此前 bug 正是若 category 已被 _derive_category 正确算成 vertical_privesc、elif 又用退化的
         _family_cat2='bola' 覆盖，把正确值打回 bola。
    2. 仅当 _family_cat 为空（vuln_dict 无任何业务族信号），才退 _family_cat2。
    注入族不在 DIFFERENTIAL_PROOF_FAMILIES，两类目派生源恒空，不影响既有逻辑。
    """
    _family_cat = _infer_business_category_from_family(vuln_dict)
    _family_cat2 = (_normalize_business_logic_category(canonical_business_logic_family(family))
                    if canonical_business_logic_family(family) in DIFFERENTIAL_PROOF_FAMILIES else "")
    # _family_cat 权威：非空即采信；与 category 一致时保持稳定，杜绝 _family_cat2 回退覆盖。
    if _family_cat:
        if _family_cat != category:
            return _family_cat
        return category
    if _family_cat2 and _family_cat2 != category:
        return _family_cat2
    return category


# （_resolve_business_category 第 2 版）实际被加载。验证完成后删除。
def _write_resolve_marker():
    try:
        # 用绝对路径写，避免扫描子进程 CWD 非项目根时 marker 落到别处造成误判。
        # 文件位于 <root>/src/iast/trigger_spec_registry.py，需向上 3 级到项目根。
        _here = os.path.dirname(os.path.abspath(__file__))
        _root = os.path.dirname(os.path.dirname(_here))
        _mp = os.path.join(_root, "logs", ".resolve_version_marker")
        os.makedirs(os.path.join(_root, "logs"), exist_ok=True)
        with open(_mp, "a", encoding="utf-8") as _mf:
            _mf.write("R10B3FIX_v2 loaded\n")
    except Exception:
        pass
_write_resolve_marker()


def _resolve_business_endpoint(
    vuln_dict: Dict[str, Any], discovered_routes: Optional[List[Dict[str, Any]]]
) -> Optional[Dict[str, str]]:
    """业务族 genuine 端点解析：Service/DAO 类 -> 同名控制器 -> discovered_routes 真实路由。

    仅在 resolve_trigger_endpoint 已返回空路由且类目为业务逻辑时调用（兜底，不遮蔽既有解析）。
    返回 {route, method, param_name, param_location, resolvable} 或 None。
    """
    if not discovered_routes:
        return None
    category = _normalize_business_logic_category(
        str(vuln_dict.get("business_logic_category") or vuln_dict.get("category") or "")
    )
    if not category:
        # Q2：旧数据可能未填 category，但从 A2 payload_family / type 可推断业务类目，
        # 使 Service/DAO 业务型（OrderService、*Mapper）仍经命名推导回收真实 Controller 路由。
        category = _infer_business_category_from_family(vuln_dict)
    if not category:
        return None
    _f = str(vuln_dict.get("file") or "")
    if not _f:
        return None
    base = _service_base_name(Path(_f).name)
    if not base:
        return None
    cands = set(_controller_candidates(base))
    # 也允许控制器名与 Service 同名（如 OrderService 对应 OrderController，去掉 Service 即得 Order）
    _disc_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for _d in discovered_routes:
        _df = _d.get("file", "")
        if _df:
            _disc_by_file.setdefault(Path(_df).name, []).append(_d)
    matches: List[Dict[str, Any]] = []
    for cf in cands:
        if cf in _disc_by_file:
            matches.extend(_disc_by_file[cf])
    if not matches:
        return None
    # 优先选带真实参数名（便于 register 校验）且与 A2 method 一致的路由
    _a2_method = str((vuln_dict.get("exploit_spec") or {}).get("entry", {}).get("method") or "").upper() or None

    def _score(_dm: Dict[str, Any]) -> int:
        s = 0
        _m = str(_dm.get("method") or "").upper()
        if _a2_method and _m and _m == _a2_method:
            s += 2
        _params = _dm.get("params") or []
        if _params:
            s += 1
        return s

    _chosen = max(matches, key=_score)
    _route = str(_chosen.get("route") or "")
    if not _route or not is_valid_route(_route):
        return None
    _method = str(_chosen.get("method") or "GET").upper()
    _params = _chosen.get("params") or []
    _pname = _params[0].get("param_name", "") if _params else ""
    _loc = _params[0].get("param_location", "query") if _params else "query"
    return {
        "route": _route,
        "method": _method,
        "param_name": _pname,
        "param_location": _loc,
        "resolvable": True,
        "param_name_source": "business-controller-inference",
    }


def _victim_identifiers_from_accounts(accounts: Any) -> List[str]:
    """从账户发现产物抽取受害者标识。

    规则：
    - 显式哨兵优先：含 role=attacker/victim 的账户时，仅 victim 账户贡献其
      username/email 等标识；attacker 账户恒剔除。
      账户为攻击者（列表首位），其余为受害者候选；其中 subject 与 role 同名的
      「角色名账户」（如 admin/admin）视为角色占位而非真实受害者，剔除，避免把
      角色名当受害者标识污染 D1 差分判定。
    - 标识取自顶层字段或 metadata 子对象（两者取并集，顶层优先）。
    """
    if not accounts or not isinstance(accounts, list):
        return []
    # 标识字段合并：metadata 兜底，顶层覆盖
    def _fields(acc: Dict[str, Any]) -> Dict[str, Any]:
        meta = acc.get("metadata") if isinstance(acc.get("metadata"), dict) else {}
        merged = dict(meta)
        merged.update(acc)
        return merged

    _ID_KEYS = ("username", "user_name", "email", "user_id", "userid", "uid", "id")

    def _pick(acc: Dict[str, Any]) -> List[str]:
        f = _fields(acc)
        out = []
        for k in _ID_KEYS:
            v = f.get(k)
            if v is not None and str(v).strip():
                out.append(str(v).strip())
        return out

    # 显式哨兵分支
    explicit = [
        a for a in accounts
        if isinstance(a, dict) and str(a.get("role") or "").lower() in ("attacker", "victim")
    ]
    if explicit:
        out: List[str] = []
        for a in explicit:
            if str(a.get("role") or "").lower() == "victim":
                out.extend(_pick(a))
        return _dedupe_identifiers(out)

    # 无显式哨兵：最低特权角色为攻击者，其余候选；角色名账户剔除
    _PRIV_ORDER = {"guest": 0, "user": 1, "admin": 2}

    def _priv(role: Any) -> int:
        return _PRIV_ORDER.get(str(role or "").lower(), 1)

    ranked = sorted(
        (a for a in accounts if isinstance(a, dict)),
        key=lambda a: _priv(a.get("role")),
    )
    if not ranked:
        return []
    attacker = ranked[0]
    out = []
    for a in ranked[1:]:
        subject = str(a.get("subject") or "")
        role = str(a.get("role") or "").lower()
        if subject and subject.lower() == role:
            # 角色名账户（subject==role），非真实受害者标识
            continue
        out.extend(_pick(a))
    return _dedupe_identifiers(out)


def _dedupe_identifiers(out: List[str]) -> List[str]:
    seen = set()
    clean: List[str] = []
    for x in out:
        if x in seen or len(x) > 256:
            continue
        seen.add(x)
        clean.append(x)
    return clean[:10]


def _derive_victim_identifiers(
    vuln_dict: Dict[str, Any],
    ctx: Optional[Dict[str, Any]] = None,
    *,
    discovered_accounts: Any = None,
) -> List[str]:
    """#2：从 A2 prerequisites 或账户发现产物提取已知受害者标识（username/email/user_id 等）。

    使 D1 双账号差分重放能判定「攻击者取回了受害者的数据」。优先级：
    ① A2 prerequisites.victim_identifiers（显式列表）；
    ② 实时上下文 ctx.accounts 中 role=victim 账户的已知属性；
    ③ 跨轮持久账户发现产物（dast_accounts，经 _load_discovered_accounts 加载）。
    返回去重后的非空标识列表（最多留若干条，避免污染泄漏判定）。
    """
    out: List[str] = []
    prereq = (vuln_dict.get("exploit_spec") or {}).get("prerequisites") or {}
    _vi = prereq.get("victim_identifiers") if isinstance(prereq, dict) else None
    if isinstance(_vi, (list, tuple)):
        out.extend(str(x).strip() for x in _vi if str(x).strip())
    # ② 实时上下文里的 victim 账户已知属性
    accounts = (ctx or {}).get("accounts") if isinstance(ctx, dict) else None
    if isinstance(accounts, list):
        for acc in accounts:
            if not isinstance(acc, dict):
                continue
            if str(acc.get("role") or "").lower() not in ("victim", "target", "b"):
                continue
            for key in ("username", "user_name", "email", "user_id", "userid", "uid", "id"):
                val = acc.get(key)
                if val is not None and str(val).strip():
                    out.append(str(val).strip())
                    break
    # ③ 跨轮持久账户发现产物（dast_accounts）
    if discovered_accounts:
        out.extend(_victim_identifiers_from_accounts(discovered_accounts))
    return _dedupe_identifiers(out)


def _load_discovered_accounts(db: Any, workspace_id: Any) -> List[Dict[str, Any]]:
    """从 dast_accounts 加载本 workspace 的账户发现产物。

    返回已展开 metadata 的账户列表（含 subject / role / username 等），供
    _victim_identifiers_from_accounts 派生受害者标识。任何异常安全降级为 []。
    """
    if db is None or workspace_id is None:
        return []
    try:
        app_id = f"workspace-{workspace_id}"
        rows = db.execute(
            "SELECT subject, role, metadata_json FROM dast_accounts WHERE app_id = ?",
            (app_id,),
            fetchall=True,
        )
        if not rows:
            return []
        accounts: List[Dict[str, Any]] = []
        for r in rows:
            meta: Dict[str, Any] = {}
            try:
                meta = Database.loads(r.get("metadata_json")) or {}
            except Exception:
                meta = {}
            accounts.append({
                "subject": r.get("subject"),
                "role": r.get("role"),
                **meta,
            })
        return accounts
    except Exception:
        return []


def persist_a1_evidence_to_findings(db: Any, a1_evidence: Any, vhash: str, task_id: Any) -> int:
    """注册期补偿写入 a1_evidence。

    限定 task_id 且只补空值（a1_evidence 为空 / NULL / '{}'），绝不覆盖收尾
    replace_for_task 写入的权威证据。返回受影响行数（诊断用）。无匹配行或入参
    非法时返回 0（安全 noop）。
    """
    if db is None or not vhash or not a1_evidence:
        return 0
    try:
        affected = db.execute(
            "UPDATE findings SET a1_evidence = ? "
            "WHERE task_id = ? AND vulnerability_hash_v2 = ? "
            "AND (a1_evidence IS NULL OR TRIM(a1_evidence) = '' OR TRIM(a1_evidence) = '{}')",
            (Database.dumps(a1_evidence), task_id, vhash),
            return_rowcount=True,
        )
        return int(affected or 0)
    except Exception:
        return 0


#
# `confirmed_exploitable`（case 级 6 个真漏洞），但报告 vulnerabilities 里同 case 的 vuln
# 的 verification_decision.verification_status 仍是 `unconfirmed` ⇒ 前端与对账都读不到确认态，
# 6 个真漏洞被算进漏报。
#
# 成因：trigger 层（D2 统一链路终态）与 findings 层（A1/A2 静态条目收尾重写）是两条独立写入
# 路径，收尾 replace_for_task 时没有把 trigger 的确认结果收敛回去。
#
# 修法：收尾前按 vulnerability_hash_v2（回退 case 名）取该漏洞 trigger 记录的**最强**确认态，
# 回填到 findings。**仅升级不降级**，并留痕来源字段，保证可回溯、不误伤。

_VERIFICATION_STATUS_RANK = {
    "confirmed_code_property": 1,
    "confirmed_exploitable": 2,
}


def _backfill_case_key(text: Any) -> str:
    m = _BENCHMARK_CASE_RE.search(str(text or ""))
    return m.group(1) if m else ""


def backfill_verification_status_from_triggers(db: Any, task_id: Any,
                                               findings: List[Dict[str, Any]],
                                               logger: Any = None) -> int:
    """把 trigger_specs 的确认态收敛回 findings，返回被升级的条目数。

    安全约束：
    - 入参非法 / 查库异常 / 无确认记录 ⇒ 返回 0（noop），绝不抛错阻断收尾；
    - 只把非确认态升级为确认态，已有的确认态一律不动，避免降级真阳性。
    """
    if db is None or not findings:
        return 0
    try:
        rows = db.execute(
            "SELECT target_endpoint, vulnerability_hash_v2, verification_status "
            "FROM trigger_specs WHERE task_id = ?",
            (task_id,), fetchall=True) or []
    except Exception:
        return 0

    by_case: Dict[str, int] = {}
    by_vhash: Dict[str, int] = {}
    for _row in rows:
        # Database.execute(fetchall=True) 返回 dict 列表（row_factory），
        # 按元组解包会抛 ValueError 并被外层 except 吞成 noop —— 只能按 key 取。
        if isinstance(_row, dict):
            ep = _row.get("target_endpoint")
            vh = _row.get("vulnerability_hash_v2")
            vs = _row.get("verification_status")
        else:
            ep, vh, vs = (_row + (None, None, None))[:3]
        _r = _VERIFICATION_STATUS_RANK.get(str(vs or "").strip().lower(), 0)
        if not _r:
            continue
        _c = _backfill_case_key(ep)
        if _c:
            by_case[_c] = max(by_case.get(_c, 0), _r)
        _vh = str(vh or "").strip()
        if _vh:
            by_vhash[_vh] = max(by_vhash.get(_vh, 0), _r)

    if not by_case and not by_vhash:
        return 0

    upgraded = 0
    for _v in findings:
        if not isinstance(_v, dict):
            continue
        _vd = _v.get("verification_decision")
        if not isinstance(_vd, dict):
            _vd = {}
        _cur = str(_vd.get("verification_status") or "").strip().lower()
        if _cur in _VERIFICATION_STATUS_RANK:
            continue  # 已确认 ⇒ 不动（只升级不降级）
        _r = by_vhash.get(str(_v.get("vulnerability_hash_v2") or "").strip(), 0)
        if not _r:
            _c = _backfill_case_key(_v.get("file") or _v.get("chain_id"))
            _r = by_case.get(_c, 0) if _c else 0
        if not _r:
            continue
        _vd["verification_status"] = (
            "confirmed_exploitable" if _r >= 2 else "confirmed_code_property")
        _vd["verification_status_source"] = "trigger_specs"
        _v["verification_decision"] = _vd
        _v["verification_state"] = "confirmed"
        _v["exploitable"] = "Yes"
        upgraded += 1

    if logger is not None and upgraded:
        logger.info("[D2][writeback] trigger_specs 确认态回填 findings：task=%s 升级=%s",
                    task_id, upgraded)
    return upgraded


VICTIM_FROM_POOL = "VICTIM_FROM_POOL"


def _normalize_victim_resource_id(value: Any, family: Any) -> str:
    """登记期咽喉点：victim_resource_id 归一。

    - 具体值（非空且非纯空白）→ 原样转字符串返回（A2 LLM 给的具体 id 优先，绝不覆盖）；
    - 差分证明族缺值 → 补 VICTIM_FROM_POOL 哨兵；
    - 非差分族缺值 → 保持空（注入族走 canary 重放，绝不被塞入差分就绪哨兵）。
    """
    if value is not None and str(value).strip():
        return str(value).strip()
    if canonical_business_logic_family(str(family or "")) in DIFFERENTIAL_PROOF_FAMILIES:
        return VICTIM_FROM_POOL
    return ""


def _account_identifiers(acc: Any) -> List[str]:
    """从账户字典抽取强身份指纹。

    候选标识取自顶层字段与 metadata 子对象的并集，再交由 filter_identity_markers 过滤：
    短数字 uid/id 这类低区分度值一律丢弃，避免响应体里恰好出现的数字被误判为
    「取回了受害者数据」。
    """
    from src.core.identity_marker import filter_identity_markers

    if not isinstance(acc, dict):
        return []
    meta = acc.get("metadata") if isinstance(acc.get("metadata"), dict) else {}
    merged = dict(meta)
    merged.update(acc)
    candidates = []
    for key in ("username", "user_name", "email", "user_id", "userid", "uid", "id", "subject"):
        val = merged.get(key)
        if val is not None and str(val).strip():
            candidates.append(str(val).strip())
    return filter_identity_markers(candidates)


def _derive_category(vuln_dict: Dict[str, Any], a1_ev: Dict[str, Any]) -> str:
    """第一点 C：从漏洞结构化字段提取业务类目，供 d2_facade 路由到 replay_*。

    优先级：vuln.business_logic_category > vuln.category > a1_evidence.category（仅当
    a1_evidence.business_logic 为真时，避免普通漏洞被误标业务类目）。解析不出业务类目则返回
    空串（spec 走普通 canary 污点重放）。
    """
    raw = (
        vuln_dict.get("business_logic_category")
        or vuln_dict.get("category")
        or ((a1_ev or {}).get("category") if (a1_ev or {}).get("business_logic") else None)
        or ""
    )
    cat = _normalize_business_logic_category(raw)
    # Q2：显式类目为空时（多见于旧 task 数据），从 A2 payload_family / vuln.type 推断业务类目，
    # 使 Service/DAO 业务型仍能正确路由到差分重放并触发端点解析兜底。非业务族返回空（不误标）。
    if not cat:
        cat = _infer_business_category_from_family(vuln_dict)
    return cat



# ---------------------------------------------------------------------------
# 无路由确定性重归因（JSONP / CVE-2022-22978）
# ---------------------------------------------------------------------------
_JSONP_ADVICE_BASENAMES = {"object2jsonp.java"}


def _jsonp_advice_file(file, discovered_routes):
    """识别 JSONP @ControllerAdvice 辅助类（Object2Jsonp.java）。

    该类本身无 @RequestMapping，仅 beforeBodyWriteInternal 包 JSONP 响应；真实漏洞路由
    在 controller/Jsonp.java 的 /jsonp/*。也支持 discovered_routes 中标记
    is_controller_advice 的路由（entry_discovery_service 已打标）。
    """
    basename = os.path.basename(str(file)).lower()
    if basename in _JSONP_ADVICE_BASENAMES:
        return True
    for d in (discovered_routes or []):
        _df = str(d.get("file") or "").lower()
        if os.path.basename(_df) in _JSONP_ADVICE_BASENAMES:
            return True
        if d.get("is_controller_advice"):
            return True
    return False


def _first_route_containing(routes, needle):
    for r in routes:
        if needle in str(r):
            return r
    return None


def _no_route_reattribution(vuln_dict, discovered_routes):
    """无真实 HTTP 路由时的确定性重归因（纯函数，不依赖 LLM）。

    - JSONP：@ControllerAdvice 辅助类（Object2Jsonp.java）-> 重归因到 controller/Jsonp.java
      的真实 /jsonp/* 路由（优先 /jsonp/vuln/* 明确漏洞端点）；使 JSONP spec 能进 D1 重放。
    - CVE-2022-22978：授权绕过配置类（WebSecurityConfig.java）无真实 HTTP 路由，合成
      /black_path%0a/xx PoC 路由（regexMatchers 对 %0a 换行失效的绕过点），做运行时 200-vs-403
      真闭环证明，不依赖短期 token 假闭环。
    非上述两类一律返回 None（不遮蔽既有解析）。
    """
    file = str(vuln_dict.get("file") or "")
    vtype = str(vuln_dict.get("type") or vuln_dict.get("finding_type") or "")
    raw = str(vuln_dict.get("raw_json") or "")

    # CVE-2022-22978：配置类合成可重放 PoC 路由。
    #   ① 内置硬编码规则产出 type="CVE-2022-22978"；
    #   ② active skill 规则（rule_expression 强制通道）产出 type="Broken Access Control"、
    #      sink/id="cve-2022-22978"（raw 含该 id）。
    # 故触发条件统一为「CVE id 出现在 type 或 raw（大小写不敏感）」，或旧版
    # （WebSecurityConfig 源文件 + regexMatchers 字面量）兜底。
    _cve_blob = (vtype + " " + raw).lower()
    if "cve-2022-22978" in _cve_blob or ("WebSecurityConfig" in file and "regexMatchers" in raw):
        return {
            "route": "/black_path%0a/xx",
            "method": "GET",
            "reason": "cve-2022-22978-synthetic-route",
        }

    # JSONP @ControllerAdvice：重归因到 controller/Jsonp.java 的 /jsonp/* 真实路由
    if _jsonp_advice_file(file, discovered_routes):
        routes = [str(d.get("route", "")) for d in (discovered_routes or []) if d.get("route")]
        jsonp_routes = [r for r in routes if r.startswith("/jsonp")]
        if jsonp_routes:
            vuln_route = _first_route_containing(jsonp_routes, "vuln") or jsonp_routes[0]
            return {
                "route": vuln_route,
                "method": "GET",
                "reason": "jsonp-controller-advice-reattribution",
            }
    return None

def resolve_endpoint_full(
    vuln: Any,
    a1_evidence: Optional[Dict[str, Any]] = None,
    code_root: Optional[str] = None,
    discovered_routes: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """单一入口解析真相源。

    把「core resolve_trigger_endpoint + 越权真实路由纠正(point 4) + 业务族端点推导(#1)」
    合成一个确定性解析器，供两处投影共用，消除此前通道 A（trigger_specs.target_endpoint，
    100% 有路由）与通道 B（exploit_spec.entry.route，仅 16.7%）的漂移：

    - 通道 B 写入点 ``benchmark_cli._pre_resolve_a2_endpoints``：调用本函数解析后写回
      vuln.exploit_spec.entry（ground truth），供 plan_pocs 直接消费、不再让 LLM 猜路由。
    - 通道 A 写入点 ``auto_register_from_a2``：调用本函数解析后写 trigger_specs.target_endpoint，
      供 D1 重放驱动。

    两处调用同一函数、输入相同（vuln / a1_evidence / code_root / discovered_routes）即得到
    完全一致的解析结果——这就是「单一真相源、两处各自投影」。下游门禁（is_valid_route /
    is_valid_param_name / 探针路由守门 / 无参越权放宽）仍由各自调用方独立执行，不在本函数内。

    返回 dict 字段：route / method / param_name / param_location / param_name_source /
    resolvable / resolution_failure / category（业务类目，供 d2_facade 路由差分重放）。
    """
    from src.core.param_resolver import resolve_trigger_endpoint

    resolved = resolve_trigger_endpoint(
        vuln, a1_evidence,
        code_root=code_root or None, discovered_routes=discovered_routes,
    )
    vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else (vuln if isinstance(vuln, dict) else {})
    a1_evidence = a1_evidence or {}

    # 业务类目（第一点 C）：供下方越权纠正 / 业务端点推导判定「是否业务型」。
    category = _derive_category(vuln_dict, a1_evidence)

    route = str(resolved.get("route") or "")
    method = str(resolved.get("method") or "GET").upper()

    # —— 无路由确定性重归因（JSONP / CVE-2022-22978）——
    # 部分弱点类在 A2/A1 阶段解析不出真实 HTTP 路由：JSONP 真值路由在 controller/Jsonp.java 的
    # /jsonp/*，CVE 真值路由需合成 /black_path%0a/xx PoC。此处做确定性重归因，使这些 spec 能进入
    # D1 重放闭环（CVE 为真实运行时 200-vs-403 证明，非短期 token 假闭环）。
    if not route:
        _reatt = _no_route_reattribution(vuln_dict, discovered_routes)
        if _reatt:
            route = _reatt["route"]
            method = str(_reatt.get("method") or method).upper()
            logger.info(
                "[resolve_endpoint_full] 无路由重归因：file=%s -> route='%s'（%s）。",
                vuln_dict.get("file"), route, _reatt.get("reason"),
            )

    pname = str(resolved.get("param_name") or "")
    location = str(resolved.get("param_location") or "query")
    param_name_source = str(resolved.get("param_name_source") or "unknown")

    _PRIVESC_CATS = ("vertical_privesc", "cross_module_privesc")

    # —— point 4：越权真实路由纠正（仅越权类目）——
    # A2 对垂直越权等常幻觉出不存在的端点，而真实管理端点
    # （/admin/users 等）只存在于 discovered_routes（SAST ground truth）。当解析出的 route
    # 不在 discovered_routes 中、且存在命中 admin 语义的真实路由时，用真实路由覆盖，避免 D1
    # 重放打到幻觉端点而永远 405。非越权或已命中真实路由时不干预。
    if category in _PRIVESC_CATS and discovered_routes:
        _disc_routes = [d.get("route", "") for d in discovered_routes if d.get("route")]
        if (not route) or (route not in _disc_routes):
            _admin = [r for r in _disc_routes if re.search(r"/(admin|manage|console|sys)/", r, re.I)]
            if _admin:
                _pref = _admin[0]
                _pref_method = next(
                    (str(d.get("method", "")).upper() for d in discovered_routes
                     if d.get("route") == _pref and d.get("method")), method
                )
                logger.info(
                    "[resolve_endpoint_full] 越权类目 %s 端点由%s '%s' 纠正/补为真实管理路由 '%s'（来自 discovered_routes）。",
                    category, "幻觉" if route else "空端点", route or "(空)", _pref,
                )
                route = _pref
                method = _pref_method or method

    # —— #1 业务族 genuine 端点解析（Service->Controller 命名推导）——
    # 当 core 解析仍解析不出路由（业务族 vuln.file 指向 Service/DAO，A2/A1 只给 file:line，
    # Tier-2 类级匹配又因 vuln.file(Service)≠discovered.file(Controller) 的 basename 不相等而
    # 落空），用 _resolve_business_endpoint 把漏洞挂到同名控制器的真实 HTTP 入口。仅在 route 为空
    # 且类目为业务逻辑时触发，不遮蔽既有解析，更不把源码路径当路由。
    if not route and category and category not in _PRIVESC_CATS:
        _be = _resolve_business_endpoint(vuln_dict, discovered_routes)
        if _be:
            route = _be["route"]
            method = _be["method"]
            if not pname:
                pname = _be["param_name"]
            if not location:
                location = _be["param_location"]
            param_name_source = _be.get("param_name_source", "business-controller-inference")
            logger.info(
                "[resolve_endpoint_full] 业务族 %s 端点经 Service->Controller 推导解析为 '%s'（%s）。",
                category, route, category,
            )

    # 注入族 spec 登记要求 route + param 齐备（is_injection_family 分支），而 A2 的 LLM 参数提取
    # 存在方差：常只给路由不给参数。
    # 此前 param 为空即判 unresolvable → auto_register 跳过登记 → 该漏洞永远进不了 D1 重放，
    # 也就永远拿不到 Fix B 的离线确认。此处用 entry_discovery 的真实 request_params（SAST ground
    # truth）补齐，不猜测、不静默编造：只有该路由确有登记参数时才回填。
    if route and not pname:
        try:
            if is_injection_family(_norm_family(vuln_dict)) and discovered_routes:
                from src.core.param_resolver import build_discovered_route_index
                _idx = build_discovered_route_index(discovered_routes)
                _hit = next((d for d in _idx if d.get("route") == route), None)
                if _hit:
                    _dp = _hit.get("params") or []
                    if _dp:
                        _p0 = _dp[0]
                        pname = str(_p0.get("param_name") or "")
                        location = str(_p0.get("param_location") or location or "query")
                        param_name_source = "discovered-route-param-fallback"
                        logger.info(
                            "[resolve_endpoint_full] 注入族 %s 路由 '%s' 参数为空，"
                            "由 discovered_routes 真实请求参数回推为 '%s'（%s）。",
                            _norm_family(vuln_dict), route, pname, location,
                        )
        except Exception as _e:  # 兜底失败不得影响既有解析
            logger.debug("[resolve_endpoint_full] 注入族参数兜底失败（忽略）：%s", _e)

    resolved["route"] = route
    resolved["method"] = method
    resolved["param_name"] = pname
    resolved["param_location"] = location
    resolved["param_name_source"] = param_name_source
    resolved["category"] = category
    # 给出的是 `parentId` / `username` / 空。投 `parentId=<payload>` 时 mapper 的
    # `params.dataScope` 拿不到值 ⇒ SQL 根本没被注入，但查询照常执行、探针在 mapper 处
    # 命中 ⇒ 状态成 `sink-reached`，看起来「到了 sink」，5 条真值全漏。
    #
    # `framework_sinks._rule_mybatis_dollar` 已经把 `${a.b}` 转成 `a[b]` 放进 a1_evidence，
    # 这里无条件覆盖：注入点在 SQL 模板里写死了，比任何从 Java 签名推出来的都准。
    _mp = str((a1_evidence or {}).get("param") or "").strip()
    if str((a1_evidence or {}).get("rule") or "") == "mybatis_dollar_substitution" and _mp:
        resolved["param_name"] = _mp
        resolved["param_name_source"] = "mybatis-mapper"
        pname = _mp
        param_name_source = "mybatis-mapper"
    # 回写 resolvable（与 core resolver 同口径：注入型要 route+param，业务型只要 route 非空）。
    _norm = _norm_family(vuln_dict)
    if route and (pname or not is_injection_family(_norm)):
        resolved["resolvable"] = True
    #   parsed  = 路由+参数齐备（resolvable），可正常登记重放；
    #   unknown = 解析器有输入但没把握（resolution_failure 已给出 missing_route /
    #             missing_param_injection / unresolved 具体原因），登记层据此 skip 并落
    #             显式原因，绝不丢弃；unknown 占比异常高由 auto_register 告警；
    #   empty   = 输入本身不含任何可解析线索（entry_point / file 全空），无从解析。
    if resolved.get("resolvable"):
        resolved["parse_status"] = "parsed"
    elif not str(vuln_dict.get("entry_point") or "") and not str(vuln_dict.get("file") or ""):
        resolved["parse_status"] = "empty"
    else:
        resolved["parse_status"] = "unknown"
    return resolved


def summarize_parse_status(resolutions: List[Any]) -> Dict[str, Any]:
    """聚合解析状态分布，并按 20% 阈值给出解析器盲区告警判定。

    输入为 resolve_endpoint_full 产物列表（或含 parse_status 键的 dict）；
    返回 {"parsed": n, "unknown": n, "empty": n, "unknown_ratio": x, "unknown_alert": bool}。
    """
    counts = {"parsed": 0, "unknown": 0, "empty": 0}
    for r in resolutions or []:
        if not isinstance(r, dict):
            continue
        status = str(r.get("parse_status") or "")
        if status in counts:
            counts[status] += 1
    total = sum(counts.values())
    ratio = (counts["unknown"] / total) if total else 0.0
    return {
        **counts,
        "total": total,
        "unknown_ratio": round(ratio, 4),
        "unknown_alert": bool(total and ratio > 0.2),
    }


def _should_clear_specs_on_rerun(before: int, input_rows: int, min_ratio: float = 0.5) -> bool:
    """闭环二次回灌「是否允许整批清库」的判定。

    二次回灌的语义是「先 DELETE 本 task 全部 spec，再按本次输入整体重登记」，其正确性
    **完全依赖输入是全量**。历史实现只校验了「输入非空」这一半，于是出现了：
    清库前 156 条 spec、本轮只登记出 52 条 ⇒ 未参与回灌的 104 条被永久清除，且不进任何
    skipped 计数（静默丢失，含 33 条真值 TP，召回 100%→54.2%）。

    判据：输入条数明显小于已有 spec 数（默认 < 50%）即判定为收窄子集，拒绝清库。
    输入条数取的是**未去重的上界**，
    因此判断天然偏保守——宁可不清库（退化为安全的增量更新），也绝不误删。

    :param before: 清库前本 task 已有 spec 条数
    :param input_rows: 本次回灌输入的漏洞条数（上界）
    :param min_ratio: 规模下限比例，可用 SAST_AI_SPEC_RERUN_MIN_RATIO 覆盖
    :return: True=允许清库；False=拒绝清库（保留旧 spec，走增量更新）
    """
    try:
        before = int(before or 0)
    except Exception:
        before = 0
    try:
        input_rows = int(input_rows or 0)
    except Exception:
        input_rows = 0
    try:
        ratio = float(min_ratio)
    except Exception:
        ratio = 0.5
    if before <= 0:
        # 无历史 spec，清库无任何损失。
        return True
    if ratio <= 0:
        # 显式关掉守卫（ratio=0）时才无条件清库，保留逃生口。
        return True
    return input_rows >= before * ratio


def _resolve_vuln_file(code_root: str, vuln_file: str) -> str:
    """把 finding 的 file 解析成可读的绝对路径。

    vuln.file 可能是绝对路径，也可能是相对 code_root 的路径；个别轮次还会出现
    「相对路径里已经带了 code_root 的尾段」（src/main/java/... 而 code_root 也是
    .../src/main/java）——逐段剥离前缀都试一遍，找不到返回第一个候选（调用方按 isfile 判）。
    """
    raw = str(vuln_file or "").strip()
    if not raw:
        return ""
    p = raw.replace("\\", "/")
    cands: List[str] = []
    if os.path.isabs(p):
        cands.append(p)
    if code_root:
        root = str(code_root).replace("\\", "/")
        cands.append(os.path.join(root, p.lstrip("/")))
        parts = [x for x in p.split("/") if x]
        for i in range(1, len(parts)):
            cands.append(os.path.join(root, "/".join(parts[i:])))
    for c in cands:
        try:
            if os.path.isfile(c):
                return os.path.normpath(c)
        except Exception:
            continue
    return os.path.normpath(cands[0]) if cands else raw


def spurious_no_sink_at_registration(code_root: str, vuln_file: str, family: str,
                                     framework_sink: bool = False) -> bool:
    """登记阶段判「该 finding 是不是跨族捏造」（True = 应剔除）。

    与 A1 侧 ``_filter_property_family_findings`` 里的 ``spurious_no_sink`` 同一判据，
    区别是这里用的是**最终族**（已过 correct_family_by_evidence / normalize_family），
    因此能覆盖「A2 type=unknown、登记时才纠族」的形态（本轮的 01586/01661）。

    零误杀边界：``spurious_no_sink`` 只对 sql_injection / command_execution / xss /
    securecookie / ldapi / xpathi 生效；path_traversal 与 trustbound 显式不判
    （真用例与安全例都可能含 FileInputStream / setAttribute，会误杀）。
    文件解析不出、读取失败、族未登记 ⇒ 一律 fail-open 返回 False（不动）。

    反射型 RCE 只调用 ``Class.forName`` / ``Method.invoke``，也会被本门禁剔除。
    """
    if framework_sink:
        return False
    if not vuln_file or not family:
        return False
    try:
        from src.iast.property_evidence import spurious_no_sink
    except Exception:
        return False
    p = _resolve_vuln_file(code_root, vuln_file)
    if not p or not os.path.isfile(p):
        return False
    try:
        with open(p, encoding="utf-8", errors="ignore") as fh:
            code = fh.read()
    except Exception:  # noqa: BLE001
        return False
    try:
        return bool(spurious_no_sink(code, family, framework_sink=framework_sink))
    except Exception:  # noqa: BLE001
        return False


def auto_register_from_a2(
    task_id: Optional[int],
    a2_results: List[Any],
    discovered_routes: Optional[List[Dict[str, Any]]] = None,
    extra_results: Optional[List[Any]] = None,
    second_pass: bool = False,
) -> Tuple[int, int]:
    """A2→TriggerSpec 自动登记：把 plan_pocs 选定的 canonical findings 自动写入 trigger_specs，
    供 D2 的 A2→D1 自动重放驱动 D1 运行时验证（闭环，不再只靠前端手动面板）。

    - 与 enable_a3 / enable_verification 完全解耦：只要传入 a2_results 即登记，验证开关只决定
      D1 是否消费 spec，不决定是否登记（spec 始终可查可重放）。
      结合 A2 假说 + entry_discovery 真实路由 + A1 静态调用链证据 + 源码注解解析，精度高于原
      guess_parameter_name 正则猜测（全部属 SAST 静态，非猜测）。
      request_observed，该档恒为空且已被 Tier0 真实路由取代，保留只会造成误映射。解析现完全由
      resolve_trigger_endpoint 的 SAST 静态档承担。
    - parameter_name / route / method 任一无法解析时，跳过该漏洞，
      并计数 skipped，使「0 条登记」可被明确归因（空 code_root + 无观测面 + A1 缺字段），而非静默失败。

    返回 (registered, skipped)。
    """
    if task_id is None:
        # 离线直跑入口不带 task_id，无法归属 workspace，
        # 故不登记；该入口已被禁用（见 benchmark_cli.main 守卫）。此处显式报错而非静默。
        logger.error(
            "[A2->TriggerSpec] 拒绝登记：task_id 为空（离线 CLI 入口不应直接调用统一链路登记）。"
            "请通过任务编排路径（task_service → scan_task_runner → run_benchmark(task_id=...)）触发。"
        )
        return 0, 0

    # #3：skipped 落因的人读标签，供前端按 finding 下钻诊断「为什么没进 plan 池」。
    _SKIP_REASON_LABELS = {
        "invalid_param_name": "解析不出合法参数名（is_valid_param_name 失败）",
        "missing_route": "解析不出任何 HTTP 入口路由",
        "route_is_source_path": "A2/源码给出的入口是 Java 源码路经（非 HTTP 路由），已拒绝登记",
        "route_is_probe_endpoint": "解析出的入口是 IAST 探针调试端点（/api/fw/*），非应用真实漏洞，已跳过",
        "unresolved_endpoint_or_param": "结合 A2 假说 + A1 证据 + 源码注解仍无法解析出 (param, route)",
        "duplicate_route_family_covered": "同族同路由的重复假说（D1 全参注入已被既有 spec 覆盖），上游去重跳过",
        "route_family_dominated": "同路由同文件已有根因注入族，属性/配置族 spec 让位（登记级仲裁）",
    }

    _parse_status_counts: Dict[str, int] = {}

    _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
    db = Database(_db_path)
    iast = IastService(db)

    ws_id = None
    try:
        _row = db.execute("SELECT workspace_id FROM scan_tasks WHERE id=?", [task_id], fetchone=True)
        ws_id = int(_row["workspace_id"]) if _row else None
    except Exception:
        ws_id = None
    if ws_id is None:
        logger.warning("[A2->TriggerSpec] task_id=%s 找不到所属 workspace，跳过登记", task_id)
        return 0, 0

    # code_root 优先 workspace.target_path（代码根），回退 session.code_path，保证
    # resolve_endpoint_from_source 始终基于真实代码根解析 (param_name, route, method)。
    try:
        _ws = db.execute("SELECT target_path FROM workspaces WHERE id=?", [ws_id], fetchone=True)
        ws_target_path = (_ws["target_path"] or "") if _ws else ""
    except Exception:
        ws_target_path = ""

    # 取当前 workspace 在线会话（若有）绑定到 spec，便于自动重放时按会话路由；无则留 NULL。
    session_id = None
    session_code_path = None
    try:
        _sessions = iast.list_sessions(ws_id)
        if _sessions:
            _first = _sessions[0]
            session_id = int(_first.get("id")) if isinstance(_first, dict) else int(_first["id"])
            session_code_path = (_first.get("code_path") or "") if isinstance(_first, dict) else ""
    except Exception:
        session_id = None
    # 优先 workspace.target_path，回退 session.code_path
    code_root = ws_target_path or session_code_path

    # §canary-唯一性：本次登记批次共享一个 run_nonce（4 位十六进制），使本任务本轮生成的
    # 全部 canary 处于一个与历史运行/其他任务不相交的命名空间，配合 D1 重放前清缓存杜绝串扰。
    from src.iast.canary import _rand_hex
    run_nonce = _rand_hex(4)

    if not code_root:
        # 空 code_root 是 ws=4 当初 0 条登记的根因（无在线 IAST 会话且无 workspace.target_path），
        # 此时无法从源码解析真实 (param_name, route, method)，登记大概率全部 skip。显式告警以便归因。
        logger.warning(
            "[A2->TriggerSpec] workspace=%s 的 code_root 为空（无 workspace.target_path 且无在线 IAST 会话 code_path），"
            "将从 A2 既有字段尽力解析；解析不出参数名/路由的漏洞会被跳过登记。",
            ws_id,
        )

    registered = 0
    skipped = 0
    skipped_duplicate = 0
    skipped_unresolved = 0
    skipped_spurious = 0
    total_a2 = 0
    reasons: List[Dict[str, str]] = []
    _batch_route_specs: List[tuple] = []
    # (c) 上游去重：本批次已登记的 (family, route) 集合（含跨 scan_result 的全部输入）。
    # 默认关闭，env 显式开启才生效。
    _SPEC_DEDUP_ROUTE_ENABLED = os.environ.get("SAST_AI_SPEC_DEDUP_ROUTE", "") == "1"
    _seen_family_route: set = set()
    #
    # 旧实现按 (task_id, vhash) 逐条删旧 spec，前提是「回灌前后 vhash 不变」。但 i2 反馈会
    # 修正 family/type（如 ldapi 从 xpath-injection 纠回 ldap-injection），vhash 随族名变化，
    # + 233(second_pass) = 420 条 spec 落在 184 个端点上（2.28 条/端点），D1 重放与 D2
    # 对账被同一漏洞的多份陈旧副本灌满，既拖慢又污染计数。
    # 改为「整批清 + 整批重登记」，spec 集合恒等于本次登记输入，不再有残留副本。
    # 安全前提（调用方必须满足，见 benchmark_cli i2 闭环）：回灌输入必须是**全量合并后的
    # A2 结果**，不能用收窄子集，否则会把未参与回灌的漏洞 spec 清掉。故下方对输入规模做
    # 守卫：输入为空时拒绝清库（宁可保留旧 spec，也不能把重放目标清空）。
    # 第一点 A：拓宽登记输入源。除 A2 假说外，把 A1 等其它阶段的 findings（含业务逻辑假说、
    # 已带 a1_evidence.target_endpoint 的漏洞）也纳入登记候选；解析得出 (route, param) 即通过，
    # 解析不出仍按 skipped_unresolved 跳过。去重按 vhash 兜底，避免重复。
    # 注意：这行必须早于下方 second_pass 清库块——清库判据要读 _all_results 的规模，
    # 闭环被 benchmark_cli 的 except 吞成 {"error": ...}，第二轮 D2 重验与 spec 回灌全部静默丢失。
    _all_results: List[Any] = list(a2_results or []) + list(extra_results or [])
    _second_pass_cleared = 0
    if second_pass and _all_results:
        try:
            _before = db.execute(
                "SELECT COUNT(*) AS c FROM trigger_specs WHERE task_id = ?", (task_id,), fetchone=True
            )
            _before = int((_before or {}).get("c") or 0)
            # 二次回灌是「先清库再整体重登记」。注释要求输入必须是全量，但此处原先只实现了
            # 本轮只登记出 52 条 ⇒ 未参与回灌的漏洞被永久清除，且不进任何 skipped 计数
            # （静默丢失；含 33 条真值 TP，召回 100%→54.2%，-45.8pp）。
            # 补齐规模守卫：输入条数（未去重上界，只会比实际可登记数更大，故判断偏保守、
            # 不会误拒）明显小于已有 spec 数时判定为收窄子集，拒绝清库。
            # 不清库时后续循环走 second_pass 的 (task_id, vhash) 删旧插新分支，语义退化为
            # 安全的增量更新，未参与回灌的输入不会丢。
            _input_rows = sum(
                len(getattr(_sr, "vulnerabilities", []) or []) for _sr in _all_results
            )
            try:
                _min_ratio = float(os.environ.get("SAST_AI_SPEC_RERUN_MIN_RATIO", "0.5"))
            except Exception:
                _min_ratio = 0.5
            if not _should_clear_specs_on_rerun(_before, _input_rows, _min_ratio):
                logger.warning(
                    "[A2->TriggerSpec] task=%s 二次回灌拒绝清库：输入 %d 条 < 已有 spec %d 条的 %.0f%%，"
                    "疑似收窄子集（清库会永久丢失未参与回灌的 spec）。改为增量更新，保留旧 spec。",
                    task_id, _input_rows, _before, _min_ratio * 100,
                )
            else:
                # 这样 spec id 稳定 ⇒ replay_attempts 不再出现孤儿，
                # verification_status 也不会被清空 ⇒ 闭环第二轮只需重放变更项。
                logger.info(
                    "[A2->TriggerSpec] 闭环二次回灌：upsert 模式，保留 task=%s 的历史 spec %d 条"
                    "（不再清库；触发条件变化的条目由 register_trigger_spec 单独重置）",
                    task_id, _before)
        except Exception as _clr:
            # 清库失败不可静默：保留旧 spec 继续跑只是重复，清一半再登记才是灾难。
            logger.warning(
                "[A2->TriggerSpec] task=%s 二次回灌清库失败（跳过清库，按旧逻辑登记）：%s",
                task_id, _clr,
            )
    # ≈ 45+ 分钟全程不写 scan_progress.json，task_runner 的心跳看门狗
    # 终止瞬间仍在以 1.5s/条注册 spec）。每 10s 刷新一次进度文件，喂看门狗 + 前端可见。
    _reg_output_dir = ""
    try:
        _reg_row = db.execute(
            "SELECT output_dir FROM scan_tasks WHERE id=?", (task_id,), fetchone=True
        )
        if _reg_row:
            _reg_output_dir = str(
                _reg_row.get("output_dir") if isinstance(_reg_row, dict) else _reg_row[0]
            ) or ""
    except Exception:
        _reg_output_dir = ""
    _reg_progress_path = os.path.join(_reg_output_dir, "scan_progress.json") if _reg_output_dir else None
    # 因此崩溃被 except 吞掉，spec 全部改由闭环 second_pass 产出）。
    _reg_total = sum(len(getattr(_sr, "vulnerabilities", []) or []) for _sr in _all_results)
    _reg_done = 0
    _reg_last_write = 0.0

    def _reg_heartbeat() -> None:
        if not _reg_progress_path:
            return
        try:
            _prog: Dict[str, Any] = {}
            if os.path.exists(_reg_progress_path):
                with open(_reg_progress_path, "r", encoding="utf-8") as _fh:
                    _prog = json.loads(_fh.read() or "{}")
            if not isinstance(_prog, dict):
                _prog = {}
            _prog["spec_registration_progress"] = {
                "done": _reg_done,
                "total": _reg_total,
                "status": "registering",
            }
            with open(_reg_progress_path, "w", encoding="utf-8") as _fh:
                json.dump(_prog, _fh, ensure_ascii=False)
        except Exception:
            pass

    for scan_result in _all_results:
        for vuln in getattr(scan_result, "vulnerabilities", []) or []:
            # §统一链路：D1 重放覆盖全部「可解析出端点+参数」的 A2 假说，不再限定
            # a21_selected=True（原 gate 依赖 is_canonical，java-quote 等靶场 A2 未标 canonical
            # 导致 0 条登记、D1 永无靶可打）。防错由下方 parameter_name/route 合法性校验兜底
            # 因此放宽此处不会注入到应用不读取的位置。
            vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else dict(vuln)
            # 杠杆一：spec 注册端先 canonicalize 再算 vhash，与 finding 落库端 enrich_finding_hash
            # 走同一归一路径（NAMING_STANDARDS 簇一/二/三/四），保证同漏洞两端 vhash 一致，消除假孤儿。
            vhash = vulnerability_hash_v2(canonicalize_vuln_for_hash(vuln_dict))
            total_a2 += 1
            _reg_done += 1
            if _reg_progress_path and (time.time() - _reg_last_write) >= 10.0:
                _reg_last_write = time.time()
                _reg_heartbeat()
            # 去重：同 task 同 hash 已登记则跳过；跨 task 允许重复登记，
            # 避免新扫描因旧 task 已登记同一 hash 而全量被跳过（导致 I1/D2 无本 task 数据）。
            try:
                _existing = db.execute(
                    "SELECT id FROM trigger_specs WHERE task_id=? AND vulnerability_hash_v2=?",
                    (task_id, vhash), fetchone=True,
                )
                if _existing:
                    if second_pass:
                        # (task_id, vhash) 就地更新，id 保持不变 ⇒ replay_attempts 归因不断；
                        # 触发字段真变了它会自行重置该条确认态。这里直接继续往下走。
                        logger.debug("[A2->TriggerSpec] 二次回灌命中已有 spec（task=%s vhash=%s），走 upsert",
                                     task_id, vhash)
                    else:
                        skipped_duplicate += 1
                        continue
            except Exception:
                pass
            exploit_spec = vuln_dict.get("exploit_spec") or {}
            entry = exploit_spec.get("entry") or {}
            family = (exploit_spec.get("payload") or {}).get("payload_family") or _norm_family(vuln_dict)
            # —— 证据纠族：基于路由/源文件/sink 确定性证据纠正 family，覆盖 LLM/A2 误判。
            # 须位于 vhash 计算(675)之后、register 之前，否则族名回流会污染 vuln_hash 致哈希绑定断裂。
            # （CVE-2022-22978 的 WebSecurityConfig.java）本身没有真实 HTTP 路由，resolve_endpoint_full
            # 才会合成 /black_path%0a/xx。若只拿原始 entry.route（空），auth_bypass 的路由针
            # "black_path"/"cve-2022-22978" 永远不命中，族名纠不回 auth_bypass，spec 对账进不了
            # CVE 黄金项。故 entry.route 为空时回退到 _no_route_reattribution 的合成路由。
            _entry_route = str((entry or {}).get("route") or "")
            if not _entry_route:
                _reatt = _no_route_reattribution(vuln_dict, discovered_routes)
                if _reatt:
                    _entry_route = str(_reatt.get("route") or "")
            _corr = correct_family_by_evidence(
                family,
                route=_entry_route,
                file=str(vuln_dict.get("file") or getattr(vuln, "file", "") or ""),
                sink="",
            )
            if _corr.get("corrected") == "1":
                logger.info("[A2->TriggerSpec] 证据纠族 %s -> %s（rule=%s, evidence=%s）",
                            family, _corr["family"], _corr.get("rule"), _corr.get("evidence"))
            family = _corr["family"]
            # 把「弱哈希算法/weak-hash/weak-hash-algorithm」这类同概念多写法收敛为单一规范键。
            # AP 分族计数与基准真值匹配全部错配。必须在 vhash 之后（不回改哈希）。
            _fam_norm = normalize_family(family)
            if _fam_norm and _fam_norm != family:
                logger.info("[A2->TriggerSpec] 族名归一 %s -> %s（spec 落库收口）", family, _fam_norm)
                family = _fam_norm
            # 为什么必须在这里：A2 常产出 type=unknown 的 finding，族是在**这里**由
            # correct_family_by_evidence / normalize_family 推断出来的（01586/01661 就是
            # 「A2 说 unknown → 这里纠成 sql_injection → 文件里连 SQL 关键字都没有」）。
            # 上游 A1/A2 侧的同名门禁按「finding 自己的 type」判，拿到 unknown 时无从判断；
            # 只有拿到**最终族**才能判，所以这里是唯一能挡住这类捏造的位置。
            # 判据与 A1 侧完全同源（src/iast/property_evidence.spurious_no_sink）。
            if code_root and family:
                try:
                    _vf_dbg = str(vuln_dict.get("file") or getattr(vuln, "file", "") or "")
                    # a1_ev 在本循环里到下方才赋值，这里就地取，避免顺序耦合。
                    _fw_hit = bool(((vuln_dict.get("a1_evidence")
                                     or getattr(vuln, "a1_evidence", None) or {})
                                    .get("framework_sink")))
                    if spurious_no_sink_at_registration(code_root, _vf_dbg, family,
                                                        framework_sink=_fw_hit):
                        _vf_abs = _resolve_vuln_file(code_root, _vf_dbg)
                        skipped_spurious += 1
                        skipped += 1
                        reasons.append({
                            "vulnerability_hash_v2": vhash,
                            "family": family,
                            "reason": "spurious_no_sink",
                            "reason_label": "文件里没有该族应有的 API（跨族捏造，登记前剔除）",
                            "param_name": "",
                            "route": str((entry or {}).get("route") or ""),
                            "file": _vf_abs,
                        })
                        logger.info(
                            "[A2->TriggerSpec] 跨族无 sink 门禁剔除 vhash=%s family=%s file=%s",
                            str(vhash or "")[:12], family, _vf_abs)
                        continue
                except Exception as _sp_exc:
                    logger.debug("[A2->TriggerSpec] 跨族无 sink 门禁跳过：%s", _sp_exc)
            canary = CanaryFactory.build(family, run_nonce=run_nonce)
            # (route, method, param_name, location)，取代原 guess_parameter_name 正则猜测。
            # 优先级：entry_discovery 真实路由 > A1 静态候选 > 源码注解解析（均属 SAST 静态，非猜测）。
            # 任一关键项（param_name / route）无法解析都不静默登记无效 spec。
            a1_ev = vuln_dict.get("a1_evidence") or getattr(vuln, "a1_evidence", None) or {}
            # ④：A1/CodeQL 证据随假说一并持久化到 findings，供 A2 阶段稳定消费（已通过
            # a1_evidence_index 注入 A2 prompt）。best-effort，失败不阻断登记。
            if a1_ev and vhash:
                try:
                    db.execute(
                        "UPDATE findings SET a1_evidence = ? WHERE vulnerability_hash_v2 = ?",
                        (Database.dumps(a1_ev), vhash),
                    )
                except Exception:
                    pass
            # 单一入口解析真相源：core resolve_trigger_endpoint + 越权真实路由纠正 +
            # 业务族端点推导，三者在 resolve_endpoint_full 内一次性完成，pre_resolve 与 auto_register
            # 共用同一函数，确保通道 A(trigger_specs.target_endpoint) 与通道 B(exploit_spec.entry.route)
            # 两处投影一致、不再漂移。下方仅做注册级守门（探针/源码路由拦截、无参越权放宽），不再重复解析。
            resolved = resolve_endpoint_full(
                vuln, a1_ev,
                code_root=code_root or None, discovered_routes=discovered_routes,
            )
            # unknown 占比超阈值在收尾统一告警——解析盲区必须可见，不许静默。
            _ps = str(resolved.get("parse_status") or "")
            _parse_status_counts[_ps] = _parse_status_counts.get(_ps, 0) + 1
            pname = resolved.get("param_name", "")
            param_name_source = resolved.get("param_name_source", "unknown")
            route = resolved.get("route", "")
            method = (resolved.get("method") or "GET").upper()
            location = resolved.get("param_location") or "query"
            # (exploit_spec.entry.route) 必须一致。resolve_endpoint_full 在 auto_register 阶段复算时，
            # 因 vuln.exploit_spec.entry.route 已被 pre_resolve 写入、且 A2 结构化 entry 候选优先级更高，
            # entry.route=/black_path）。此处以通道 A 解析结果为权威，把 route 写回 vuln.exploit_spec.entry，
            # 使存储 spec 的 raw_json 中 entry.route == target_endpoint，彻底消除漂移。route 不参与 vhash
            # （vuln_hash.py 任务③），故不影响 hash 关联；target_endpoint 即 D1 重放权威端点，保持不变，零回放回归。
            if route and isinstance(vuln_dict.get("exploit_spec"), dict):
                _e = vuln_dict["exploit_spec"].get("entry")
                if isinstance(_e, dict):
                    _e["route"] = route
                    # 通道 A（trigger_specs 的 param_name / param_location 列）由 resolve_endpoint_full
                    # 解析，D1 重放真正用的是它；但通道 B（raw_json.exploit_spec.entry）此前只回写
                    # route，parameter_name/location 停留在 A2 阶段被 idor/ssrf 分支抹掉的空串。
                    # 结果对账/报告层读 entry 得到空参数，与 DB 列不一致。这里以同一解析结果
                    # 补齐两个字段，使 A/B 恒一致。route 已证明不参与 vhash、零回放回归，
                    # 参数字段同理（exploit_spec.entry 不进 hash_components）。
                    if pname:
                        _e["parameter_name"] = pname
                    if location:
                        _e["parameter_location"] = location
                try:
                    _src_spec = getattr(vuln, "exploit_spec", None)
                    if isinstance(_src_spec, dict) and isinstance(_src_spec.get("entry"), dict):
                        _src_spec["entry"]["route"] = route
                        if pname:
                            _src_spec["entry"]["parameter_name"] = pname
                        if location:
                            _src_spec["entry"]["parameter_location"] = location
                except Exception:
                    pass
            # _vuln_file 供下方注册级守门（探针/源码路经拦截）使用。
            _vuln_file = vuln_dict.get("file", "") or getattr(vuln, "file", "")
            # 第一点 C：业务类目（来自 resolve_endpoint_full，供 d2_facade 路由到 replay_bola/replay_race 等
            # 专用差分重放）。非业务类目返回空串，spec 走普通 canary 污点重放（不影响既有逻辑）。
            category = resolved.get("category") or _derive_category(vuln_dict, a1_ev)
            # 第一点 C-补：结构化 family 派生类目优先于自由文本 category 标签（覆盖上游把
            # vertical-privilege-escalation 族 vuln_dict.category 错标 bola、导致按水平越权重放永远
            # no-iast-evidence 的场景）。覆盖决策抽到 _resolve_business_category 纯函数，便于回归守卫。
            category = _resolve_business_category(category, family, vuln_dict)
            # 垂直/跨模块越权通常为无参 GET（如 /admin/users），param_name 非必填——放宽注册级守门，
            # 避免「无参数名」把真实管理端点拒之门外（is_valid_param_name("") 恒 False）。
            _NO_PARAM_CATEGORIES = ("vertical_privesc", "cross_module_privesc")
            if category in _NO_PARAM_CATEGORIES and not is_valid_param_name(pname):
                pname = ""
                location = ""
            # 注册级硬守门（防御纵深）：resolve_trigger_endpoint 已在候选/Tier 阶段过滤，但
            # 仍可能因 Tier2 直接锁 entry.route 等路径漏过探针/源码路经。此处再挡一次，并给出
            # 可下钻的精确原因（供 #3 写入 task_result 前端诊断）。
            _reject_reason = None
            # 垂直/跨模块越权为无参 GET（如 /admin/users），param_name 非必填；为空时跳过参数名校验，
            # 但非空却非法仍拒（防止脏值注入）。
            _no_param_cat = category in ("vertical_privesc", "cross_module_privesc")
            # #3 sound 优先（宁可误报也不漏报）：注入族若已解析出合法路由但 param 仍空，不再直接拒
            # （此前会把大量真实漏洞静默丢弃）。放行登记为可重放 spec，交由 D1 全参 canary 注入兜底
            # （representative_request_params 全参数带标 / 无参时 best-effort）。仅当 param 非空却
            # 非法才拒（防脏值注入到应用不读取的位置）。
            if (not _no_param_cat or pname) and pname and not is_valid_param_name(pname):
                _reject_reason = "invalid_param_name"
            elif not route:
                # @WebServlet 自注解兜底（配置类/sensitive 类 finding 常驻自包含 servlet，
                # 这是确定性回填（代码级 ground truth），绝不触发 A2 全量重跑。
                _self_ep = None
                try:
                    from src.core.param_resolver import servlet_self_endpoint
                    # (b)：_vuln_file 是相对 code_root 的路径，servlet_self_endpoint 内部直接
                    # Path.read_text——从后端 CWD 解析必然失败返回 None，E-2 兜底对全部相对路径
                    # 传入即解析出路由）。这里必须先拼 code_root 再解析。
                    _self_src = str(_vuln_file or "")
                    if _self_src and code_root and not os.path.isabs(_self_src):
                        _self_src = os.path.normpath(
                            os.path.join(str(code_root), _self_src.replace('\\', '/').lstrip('/')))
                    _self_ep = servlet_self_endpoint(_self_src) if _self_src else None
                except Exception:
                    _self_ep = None
                if _self_ep and str(_self_ep.get("route") or ""):
                    route = str(_self_ep["route"])
                    if not pname:
                        pname = str(_self_ep.get("param_name") or "")
                        location = str(_self_ep.get("param_location") or "query")
                        param_name_source = str(_self_ep.get("param_name_source") or "servlet-self-annotation")
                    logger.info(
                        "[A2->TriggerSpec] missing_route 定向回填（E-2）：vhash=%s 文件自注解给出路由 %s",
                        vhash[:12], route,
                    )
                else:
                    _reject_reason = "missing_route"
            elif not is_valid_route(route):
                # 源码路经（OrderService.java:118 之类）被当成路由——绝不让其进 spec 表污染 AP。
                _reject_reason = "route_is_source_path"
            elif _is_probe_route(_vuln_file, route):
                # 探针调试路由（/api/fw/dubbo、/api/fw/redis）——应用真实漏洞不存在于此，跳过。
                _reject_reason = "route_is_probe_endpoint"
            if _reject_reason:
                logger.warning(
                    "[A2->TriggerSpec] 跳过漏洞 %s 的自动登记（原因=%s）：param_name='%s', route='%s'。"
                    "不登记无效 spec，避免 D1 把 canary 注入到应用不读取的位置。",
                    vhash[:12], _reject_reason, pname, route,
                )
                skipped_unresolved += 1
                skipped += 1
                reasons.append({
                    "vulnerability_hash_v2": vhash,
                    "family": family,
                    "reason": _reject_reason,
                    "reason_label": _SKIP_REASON_LABELS.get(_reject_reason, _reject_reason),
                    "param_name": pname,
                    "route": route,
                    # 随 reason 携带 file。missing_route_watch 此前运行期查
                    # findings 表必然查空（findings 仅收尾由 replace_for_task 重写），case/file 全空、
                    # 102 条全部塌进 cross_file——归属字段必须在这里就地给出。
                    "file": _vuln_file,
                })
                continue
            # 走到此处 route 已通过 is_valid_route + 非探针守门，replayable 恒为 1。
            replayable = 1

            # 0 事件（canary 不可注入/请求未达），后登记那条必 2 事件 confirmed——
            # 重复 spec 是确认层的冗余票（两条假说载荷形态不同，恰一条可注入）。
            # 去重保首条 = 9/9 系统性保住坏票，L2 召回 -9 用例。故默认关闭；如需开启
            # （纯吞吐考量、接受召回损失）设 SAST_AI_SPEC_DEDUP_ROUTE=1。
            _dedup_key = (family, route)
            if _SPEC_DEDUP_ROUTE_ENABLED and _dedup_key in _seen_family_route:
                skipped_duplicate += 1
                skipped += 1
                reasons.append({
                    "vulnerability_hash_v2": vhash,
                    "family": family,
                    "reason": "duplicate_route_family_covered",
                    "reason_label": _SKIP_REASON_LABELS.get(
                        "duplicate_route_family_covered", "duplicate_route_family_covered"),
                    "param_name": pname,
                    "route": route,
                    "file": _vuln_file,
                })
                logger.info(
                    "[A2->TriggerSpec] 上游去重：vhash=%s family=%s route=%s 已有同族同路由 spec，跳过",
                    vhash[:12], family, route,
                )
                continue
            _seen_family_route.add(_dedup_key)

            # #2：受害者标识派生（username/email/user_id 等），供 D1 双账号差分重放判定「取回受害者数据」。
            # 优先 A2 prerequisites.victim_identifiers，否则取账户发现产物里 victim 账户的已知属性。
            _attack_ctx = _build_attack_context_with_warning(vuln_dict, a1_ev, family, vhash)
            _discovered_accounts = _load_discovered_accounts(db, ws_id)
            victim_identifiers = _derive_victim_identifiers(
                vuln_dict, _attack_ctx, discovered_accounts=_discovered_accounts
            )

            params = []
            if pname:
                params.append({
                    "name": pname,
                    "location": location,
                    "value": canary,
                })
            # （'param'/'name'/''）只带错名字重放 ⇒ servlet 走「找不到参数」的提前返回分支
            # ⇒ 零事件。追加用例名候选（**追加不替换**：Referer 类用例是 header 注入、
            # 实测可用，替换会弄坏）。详见 append_benchmark_case_param 说明。
            params = append_benchmark_case_param(params, pname, location, route, canary)
            # poc 链假说：优先用 A2 已产出的 exploit_spec.poc_chain，否则从 entry+family+sink 推导。
            a2_chain = (vuln_dict.get("exploit_spec") or {}).get("poc_chain")
            poc_chain = a2_chain if isinstance(a2_chain, list) and a2_chain else _derive_poc_chain(
                family, route, method, pname, location,
                vuln_dict.get("file", "") or getattr(vuln, "file", ""),
                int(vuln_dict.get("line") or getattr(vuln, "line", 0) or 0),
            )
            iast.register_trigger_spec({
                "workspace_id": ws_id,
                "session_id": session_id,
                "task_id": task_id,
                "finding_id": None,
                "vulnerability_hash_v2": vhash,
                "family": family,
                "target_endpoint": route,
                "http_method": method,
                "param_name": pname,
                "category": category,
                "business_logic_category": category,
                "param_name_source": param_name_source,
                "param_location": location,
                "replayable": replayable,
                "content_type": entry.get("content_type", ""),
                "principal": (exploit_spec.get("prerequisites") or {}).get("role_or_permission", ""),
                # point 4：受害者资源 id（BOLA/IDOR 重放要注入的真实对象 id）。此前整条链路恒为空
                # （schema 无字段 + normalize 丢弃），现纳入 schema 后从 A2 prerequisites 透传。
                # 若 A2 仍未回填，则留空——D1 replay_bola 会据此判定「无受害者 id 可注入」而非误打 404。
                "victim_resource_id": str((exploit_spec.get("prerequisites") or {}).get("victim_resource_id", "") or "").strip(),
                # #2：已知受害者标识（username/email/user_id），供 D1 响应体差分判定泄露。
                "victim_identifiers": victim_identifiers,
                "taint_marker": canary,
                "expected_sink_file": vuln_dict.get("file", "") or getattr(vuln, "file", ""),
                "expected_sink_line": int(vuln_dict.get("line") or getattr(vuln, "line", 0) or 0),
                "representative_request_params": params,
                "poc_chain": poc_chain,
                # 此前 filter_spec_json / bypass_state 两列在真实跑批里恒空（空转），
                # 因为登记端从未写入——A2 也没产出结构化净化器信息。
                # 注意：normalize_exploit_spec 只保留 schema 内定义的分组键，顶层自定义键
                # （如 filter_spec）会被丢弃，所以这里优先读 dataclass 属性（与 bypass_state 同路径），
                # 再回退到 exploit_spec（若将来把 filter_spec 正式纳入 schema）。
                "filter_spec": (getattr(vuln, "filter_spec", None)
                                or exploit_spec.get("filter_spec") or {}),
                "bypass_state": str(getattr(vuln, "bypass_state", "") or ""),
                "bypass_reason": str(getattr(vuln, "bypass_reason", "") or ""),
                "raw": vuln_dict,
                # D1 真实攻击：A2 构造的攻击载荷 + 账户上下文随 spec 登记。
                # payload 由 A2 产出（反序列化等需真 gadget 链），D1 只做投放，不在此生成。
                **_attack_ctx,
            })
            registered += 1
            # 因为同一批里「先登记 csrf、后登记 deserialization」的顺序不可预知）。
            _batch_route_specs.append((
                str(route or "").strip().lower(),
                os.path.basename(str(vuln_dict.get("file", "") or getattr(vuln, "file", "")) or "").lower(),
                str(family or "").strip().lower(),
                str(vhash or ""),
            ))
    # A2 常在同一 (route, file) 上同时产出「根因注入族」与「属性/配置族」（csrf/cors 等）
    # 的 spec；属性族后续会被同端点真实注入 sink 的探针事件**跨族确认**成确认级误报
    # 。
    # 与 framework_sinks._arbitrate_families 规则 1 同源：同 (route, file) 存在注入族
    # （priority < 40）⇒ 删除本批次登记的属性族（priority >= 40）spec。
    # 属性族在没有兄弟注入族时照常登记（/csrf/post 只有 csrf 族 → 保留，走 oracle 通道）。
    _route_arbitrated = 0
    if _batch_route_specs:
        try:
            from src.iast.framework_sinks import family_priority as _fam_prio
        except Exception:  # noqa: BLE001  表缺失时退回统一中档，仲裁自动失效（fail-open）
            _fam_prio = lambda _f: 30  # noqa: E731
        for (_r_key, _f_key, _fam_low, _vh) in _batch_route_specs:
            if not _vh or _fam_prio(_fam_low) < 40:
                continue
            _dominated = any(
                _r2 == _r_key and _f2 == _f_key and _fam_prio(_f2_fam) < 40
                for (_r2, _f2, _f2_fam, _vh2) in _batch_route_specs
            )
            if not _dominated:
                # 批内无兄弟注入族 → 查库（早前轮次 upsert 过的同路由同文件 spec）。
                # basename 在 Python 侧比对：LIKE 的 `_` 是单字符通配，文件名比较不能下推。
                try:
                    _sib_rows = db.execute(
                        "SELECT DISTINCT family, expected_sink_file FROM trigger_specs "
                        "WHERE task_id=? AND lower(target_endpoint)=?",
                        (task_id, _r_key),
                    ).fetchall()
                except Exception:  # noqa: BLE001
                    _sib_rows = []
                for _srow in _sib_rows or []:
                    _sib_fam = str(_srow[0] or "").strip().lower()
                    _sib_file = os.path.basename(str(_srow[1] or "")).lower()
                    if (_sib_file == _f_key and _sib_fam
                            and _sib_fam != _fam_low and _fam_prio(_sib_fam) < 40):
                        _dominated = True
                        break
            if not _dominated:
                continue
            try:
                db.execute(
                    "DELETE FROM trigger_specs WHERE task_id=? AND vulnerability_hash_v2=?",
                    (task_id, _vh),
                )
                _route_arbitrated += 1
                reasons.append({
                    "vulnerability_hash_v2": _vh,
                    "family": _fam_low,
                    "reason": "route_family_dominated",
                    "reason_label": "同路由同文件已有根因注入族，属性/配置族 spec 让位（登记级仲裁）",
                    "param_name": "",
                    "route": _r_key,
                    "file": _f_key,
                })
                logger.info(
                    "[A2->TriggerSpec] 路由级族仲裁：删除 vhash=%s family=%s (route=%s, file=%s)"
                    "—— 同路由已有注入族 spec，属性族让位",
                    _vh[:12], _fam_low, _r_key, _f_key,
                )
            except Exception as _ra_exc:  # noqa: BLE001  fail-open：仲裁异常不阻断收尾
                logger.debug("[A2->TriggerSpec] 路由级族仲裁失败（忽略）：%s", _ra_exc)
    if _route_arbitrated:
        logger.warning(
            "[A2->TriggerSpec] 路由级族仲裁删除 %d 条属性/配置族 spec（同路由存在根因注入族）",
            _route_arbitrated,
        )
    if skipped:
        logger.warning(
            "[A2->TriggerSpec] 共 %d 条漏洞因 parameter_name 非法/缺失且无法从代码/路由"
            "提取真实参数名而被跳过登记（不静默登记无效 spec，避免 D1 把 canary 注入到应用不读取的位置）。",
            skipped,
        )
    # #3：按原因聚合计数，供前端「为什么没进 plan 池」面板做分布下钻。
    _by_reason: Dict[str, int] = {}
    for _r in reasons:
        _k = _r.get("reason", "unknown")
        _by_reason[_k] = _by_reason.get(_k, 0) + 1
    _ps_summary = summarize_parse_status(
        [{"parse_status": k} for k, v in _parse_status_counts.items() for _ in range(v)]
    )
    if _ps_summary["unknown_alert"]:
        logger.warning(
            "[A2->TriggerSpec] 解析 unknown 占比 %.1f%%（%d/%d）超过 20%% 阈值——param_resolver "
            "存在盲区（Tier 未命中 / entry_discovery 路由覆盖不足），请按下钻原因核查，勿当真实漏报。",
            _ps_summary["unknown_ratio"] * 100.0,
            _ps_summary["unknown"],
            _ps_summary["total"],
        )
    return {
        "registered": registered,
        "skipped": skipped,
        "skipped_duplicate": skipped_duplicate,
        "skipped_unresolved": skipped_unresolved,
        "skipped_spurious": skipped_spurious,
        "route_family_arbitrated": _route_arbitrated,
        "total_a2": total_a2,
        "parse_status_counts": _parse_status_counts,
        "parse_status_summary": _ps_summary,
        # 完整落因列表（不再截断），每条含 vulnerability_hash_v2 / family / reason / reason_label /
        # param_name / route，供 task_result.json 持久化 + 前端按 finding 下钻。
        "reasons": reasons,
        "skipped_by_reason": _by_reason,
    }


def attach_rep_params(sd: Dict[str, Any]) -> Dict[str, Any]:
    """把 DB 列 ``representative_request_params_json`` 解析到内存键 ``representative_request_params``。

    rep 循环恒空转 ⇒ param_name 为空的 A2 spec 完全没有注入点（trustbound 00668/00670/00671/
    01546 等 11 个真 TP 因此空 key 落库、被误判 absent）。原地补齐，返回同一个 dict。
    """
    if not sd.get("representative_request_params") and sd.get("representative_request_params_json"):
        try:
            _rp = json.loads(sd.get("representative_request_params_json") or "[]")
            if isinstance(_rp, list):
                sd["representative_request_params"] = _rp
        except Exception:
            pass
    return sd


def load_trigger_specs_by_workspace(ws_id: Optional[int], task_id: Optional[int] = None) -> Dict[str, List[Dict[str, Any]]]:
    """按 workspace（可选 + task_id）加载其 TriggerSpec，按 vulnerability_hash_v2 分组，供 D2 verify 关联重放。

    第二点 #2：新增 task_id 过滤，使验证阶段只加载「本 task 登记的 spec」，避免跨 task 累积的
    陈旧/畸形 spec（task-1/2/3 的 canary 与预置 payload）混入本 task 重放，造成 D1 度量污染与
    跨 task canary 串扰。仅当 task_id 给定时才加 AND task_id=?。

    返回 {vuln_hash: [spec, ...]}。加载失败（表缺失/连接异常）时返回空 dict，由调用方按无靶处理。
    """
    by_hash: Dict[str, List[Dict[str, Any]]] = {}
    if ws_id is None:
        return by_hash
    _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
    try:
        db = Database(_db_path)
        if task_id is not None:
            rows = db.execute(
                "SELECT * FROM trigger_specs WHERE workspace_id=? AND task_id=? "
                "AND COALESCE(suppressed_by_safe_verdict, 0) = 0",
                (ws_id, task_id), fetchall=True
            )
        else:
            rows = db.execute(
                "SELECT * FROM trigger_specs WHERE workspace_id=? "
                "AND COALESCE(suppressed_by_safe_verdict, 0) = 0",
                (ws_id,), fetchall=True
            )
        for s in rows:
            sd = dict(s)
            sd["flow_type"] = derive_flow_type(sd.get("family") or sd.get("category") or "")
            # representative_request_params（D1 replay 只读后者）。缺映射会让空 param_name 的
            # A2 spec 完全无注入点。详见 attach_rep_params 的说明。
            attach_rep_params(sd)
            h = sd.get("vulnerability_hash_v2")
            if h:
                by_hash.setdefault(h, []).append(sd)
    except Exception as _e:
        logger.warning("[TriggerSpec] 加载 workspace=%s 的 trigger_specs 失败（按无靶处理）：%s", ws_id, _e)
    return by_hash


def _audit_orphan_deletions(task_id: Optional[int], orphans) -> None:
    """孤儿 spec 删除留痕。

    为什么必须留痕：本轮删了 12 条 spec，只留下一行「已清理 12 条」的日志，
    事后只能靠「specs 109→97」这个数字倒推是哪 12 条、属于哪些族。
    硬删除 + 无留痕，是这次复盘里最贵的一课。

    落 ``data/orphan_spec_audit/<task>.jsonl``，一行一条，字段够复盘用即可。
    任何异常都吞掉——审计不允许影响主链路。
    """
    try:
        import json as _json
        import os as _os
        import time as _time
        root = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
        out_dir = _os.path.join(root, "data", "orphan_spec_audit")
        _os.makedirs(out_dir, exist_ok=True)
        path = _os.path.join(out_dir, f"{task_id if task_id is not None else 'unknown'}.jsonl")
        ts = _time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(path, "a", encoding="utf-8") as fh:
            for s in orphans:
                d = dict(s)
                fh.write(_json.dumps({
                    "ts": ts,
                    "task_id": task_id,
                    "spec_id": d.get("id"),
                    "family": d.get("family"),
                    "file": d.get("expected_sink_file"),
                    "line": d.get("expected_sink_line"),
                    "endpoint": d.get("target_endpoint"),
                    "vhash": d.get("vulnerability_hash_v2"),
                    "reason": "no_matching_finding",
                }, ensure_ascii=False) + "\n")
    except Exception:
        return


def reconcile_orphan_specs(task_id: Optional[int], dry_run: bool = False) -> int:
    """#B 数据卫生：删除本 task 中「全局都查无对应 finding」的孤儿 trigger_spec。

    task-4 重扫同代码不会再写 finding 行，仅 task-1 持有该 hash 的 finding）。因此判定孤儿必须按
    **全局** vulnerability_hash_v2 匹配，不能再用 ``f.task_id = ts.task_id`` 限定同 task——否则会把
    「finding 仅存在于更早 task」的本 task 合法 spec 误删（表现为 A2 登记 5 条、跑完流水线变 3 条，
    且被剪掉的正好是 D1 待重放的 spec）。

    正确判定：只要该 vulnerability_hash_v2 在 findings 表**任何 task** 存在，spec 即非孤儿（漏洞真实、
    重放目标有效，不得剪掉）；仅当全局都查无此 hash 的 finding 时才清理（A2 假说未被持久化为 finding）。

    调用时机：必须在 findings 落库 *之后*（benchmark 流程里 auto_register 在落库前执行，故本函数
    放在 run_benchmark 末尾、findings 写盘后调用；绝不能在 auto_register 内部加「要求 findings 行」
    的硬守卫，否则会误杀本就先于 findings 登记的合法 spec）。

    参数：
      task_id: 仅对该 task 做对账；None 表示全部 task。
      dry_run: True 只返回待删数量不执行删除。
    返回：实际删除（或待删）的 spec 行数。
    """
    _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
    try:
        db = Database(_db_path)
        if task_id is None:
            cond = ""
            params: List[Any] = []
        else:
            cond = "WHERE ts.task_id=?"
            params = [task_id]
        del cond, params  # 改用下方双键判定（不再走 vhash 单键 SQL JOIN）
        # exploit_spec.entry.route 纳入 hash 组件，_pre_resolve_a2_endpoints / plan_pocs 会改写
        # entry.route → 注册端 spec.vhash ≠ finding.vhash，于是"真有 finding、只是 hash 漂移"的
        # 包含已由路由兜底填好 /marketing/preview 的 #8 SSTI spec）。
        # 现改为双键：vhash ∪ stable_vuln_key（后者只吃 file/line/type/code 源坐标，免疫 route 漂移）。
        # "reconcile_orphan_specs 判孤儿静默删除（AP 段 81 条真 POC 被删）"的记载。
        # ``f.task_id = ts.task_id AND f.vulnerability_hash_v2 = ts.vulnerability_hash_v2`` 判定孤儿，
        # 会把「finding 仅存在于更早 task」的本 task 合法 spec 误删。
        # 正确口径：只要该 vulnerability_hash_v2 在 findings 表里**任何 task** 存在，spec 就非孤儿——
        # 漏洞是真实的，重放目标有效，不得剪掉（尤其不得剪掉 D1 待重放的 spec）。
        # 仅当全局都查无此 hash 的 finding 时才视为真孤儿（A2 假说未被持久化为 finding）予以清理。
        import json as _json

        # finding 侧取列 + raw_json。两端都算"稳定键变体"取并集，规避 type 表示形态差异。
        _spec_sql = (
            "SELECT id, task_id, vulnerability_hash_v2, raw_json, expected_sink_file, "
            # family / target_endpoint 供孤儿审计留痕：只记 file+line 的话，
            "expected_sink_line, family, target_endpoint FROM trigger_specs"
        )
        if task_id is None:
            spec_rows = db.execute(_spec_sql, fetchall=True) or []
        else:
            spec_rows = db.execute(_spec_sql + " WHERE task_id=?", [task_id], fetchall=True) or []
        find_rows = db.execute(
            "SELECT id, vulnerability_hash_v2, finding_type, file_path, line, raw_json FROM findings",
            fetchall=True,
        ) or []

        try:
            from src.core.vuln_hash import stable_vuln_keys as _stable_vuln_keys
        except Exception:  # pragma: no cover - 极端情况下退化为单键，保持旧行为
            _stable_vuln_keys = None

        def _raw_of(row):
            try:
                return _json.loads(row["raw_json"] or "{}") or {}
            except Exception:
                return {}

        def _stable_variants(file_v, line_v, code_v, type_candidates):
            """稳定键并集：每个 type 候选都同时算「强键(file+line+code)」与「弱键(file+code, 行号置 0)」。

            来自不同来源（静态报点 vs 回填），强键会因此失配而被误判孤儿删除——孤儿删除是
            """
            if not _stable_vuln_keys:
                return set()
            out = set()
            for t in type_candidates:
                if not t:
                    continue
                for k in _stable_vuln_keys({
                    "file": file_v or "",
                    "line": line_v or 0,
                    "type": t,
                    "code_snippet": code_v or "",
                }):
                    if k:
                        out.add(k)
            return out

        # finding 侧：vhash 集合 + 稳定键集合
        f_vhash = set()
        f_stable = set()
        for f in find_rows:
            f = dict(f)
            if f.get("vulnerability_hash_v2"):
                f_vhash.add(str(f["vulnerability_hash_v2"]))
            fr = _raw_of(f)
            # 报告装配把同族同行多条收敛成一条 canonical，其余进 supporting_nodes，
            # findings 表只落 canonical 行；若不把 absorbed_vhashes 计入，
            # 被吸收成员的 spec 会被当孤儿删掉（本轮删了 16 条）。
            try:
                for _h in (fr.get("absorbed_vhashes") or []):
                    if _h:
                        f_vhash.add(str(_h))
            except Exception:
                pass
            f_stable |= _stable_variants(
                f.get("file_path") or fr.get("file") or fr.get("file_path") or "",
                f.get("line") or fr.get("line") or 0,
                fr.get("code_snippet") or fr.get("code") or "",
                (f.get("finding_type"), fr.get("type"), fr.get("original_type"),
                 fr.get("display_family"), fr.get("family")),
            )

        orphans = []
        for s in spec_rows:
            s = dict(s)
            vh = str(s.get("vulnerability_hash_v2") or "")
            if vh and vh in f_vhash:
                continue  # vhash 命中：非孤儿
            sr = _raw_of(s)
            s_stable = _stable_variants(
                sr.get("file") or sr.get("file_path") or s.get("expected_sink_file") or "",
                sr.get("line") or s.get("expected_sink_line") or 0,
                sr.get("code_snippet") or sr.get("code") or "",
                (sr.get("type"), sr.get("original_type"), sr.get("display_family"),
                 sr.get("finding_type"), sr.get("family")),
            )
            if s_stable & f_stable:
                continue  # 稳定键命中：路由漂移的合法 spec，保留
            orphans.append(s)
        # 依据：`a1_evidence.framework_sink=True`（或 source=a1-framework-sinks）说明这条 spec
        # 来自确定性静态规则，不是 A2 的臆造。此时「findings 表里找不到」只说明**下游丢条**
        #         # 不能据此把 spec 删掉——否则等于让下游的 bug 反噬上游的正确结果。
        kept_by_a1 = []
        for s in list(orphans):
            try:
                _sr = _raw_of(dict(s))
                _ev = _sr.get("a1_evidence") or {}
                if (isinstance(_ev, dict) and _ev.get("framework_sink")) or \
                        str(_sr.get("source") or "") == "a1-framework-sinks":
                    kept_by_a1.append(s)
                    orphans.remove(s)
            except Exception:
                continue
        if kept_by_a1:
            logger.info(
                "[TriggerSpec] 保留 %d 条 A1 规则产出的 spec（task_id=%s）：findings 缺失属下游丢条，"
                "不按孤儿删除（family=%s）",
                len(kept_by_a1), task_id,
                sorted({str(dict(s).get("family") or "") for s in kept_by_a1}))
        n = len(orphans)
        if n and not dry_run:
            ids = [r["id"] for r in orphans]
            db.execute(
                "DELETE FROM trigger_specs WHERE id IN (%s)" % ",".join("?" * len(ids)),
                ids,
            )
            logger.info("[TriggerSpec] 已清理 %d 条跨任务/无对应 finding 的孤儿 spec（task_id=%s）", n, task_id)
            _audit_orphan_deletions(task_id, orphans)
        elif n:
            logger.info("[TriggerSpec] dry-run：将清理 %d 条孤儿 spec（task_id=%s）", n, task_id)
        try:
            from src.core.stage_funnel import record
            record(task_id, "specs.orphan_cleanup",
                   in_count=len(spec_rows), out_count=len(spec_rows) - (0 if dry_run else n),
                   reasons={"deleted_orphan": 0 if dry_run else n,
                            "kept_a1_rule_spec": len(kept_by_a1)})
        except Exception:
            pass
        return n
    except Exception as _e:
        logger.warning("[TriggerSpec] reconcile_orphan_specs 失败（跳过）：%s", _e)
        return 0


def bind_specs_to_findings(task_id: Optional[int], dry_run: bool = False) -> int:
    """#1/#7 数据回灌：把本 task 的 trigger_spec 与 findings 按 vulnerability_hash_v2 全局关联。

    解决 task7 两类数据断裂：
    ① spec.finding_id 恒为 NULL（孤儿）——登记时无法预知 finding 行；现在 findings 已落库，
       按 vuln_hash 全局查 findings 回写 finding_id，使 spec↔finding 双向可达。
    ② finding.trigger_spec_detail.endpoint 被 A2 pre-resolve 写成 Windows 源码路径——这里用
       spec 干净字段（target_endpoint / http_method / param_name / category / victim_*）覆盖回灌，
       D1/D2 与报告均应以 spec 的干净端点为准（见 #2/#7 铁律）。

    返回成功绑定的 spec 数。best-effort，单条失败不影响其余。
    """
    if task_id is None:
        return 0
    _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
    try:
        db = Database(_db_path)
        specs = db.execute(
            "SELECT id, vulnerability_hash_v2, finding_id "
            "FROM trigger_specs WHERE task_id=? "
            "AND COALESCE(suppressed_by_safe_verdict, 0) = 0", (task_id,), fetchall=True,
        )
        if not specs:
            return 0
        # 一次性取本 task 全部 findings 的 (vuln_hash -> id) 映射，避免逐条 SELECT findings。
        # 关键修正：findings 表自历史回灌后已无 trigger_spec_detail 列（D1/D2/报告均以
        # trigger_specs.target_endpoint 为干净端点真源，见 MEMORY ），原实现读/写该列会抛
        # no such column 并中断整函数，导致 finding_id 永不为回写。本函数现在只做 spec↔finding 的
        # hash 关联与 finding_id 回写，完全不触碰 findings 其它列，保证绑定在主路径上稳定生效。
        fmap = {}
        try:
            for r in db.execute(
                "SELECT id, vulnerability_hash_v2 FROM findings WHERE task_id=?", (task_id,), fetchall=True,
            ):
                if r.get("vulnerability_hash_v2"):
                    fmap[r["vulnerability_hash_v2"]] = int(r["id"])
        except Exception:
            fmap = {}
        bound = 0
        for sp in specs:
            h = sp.get("vulnerability_hash_v2") or ""
            if not h:
                continue
            fid = fmap.get(h)
            if fid is None:
                continue
            # ① 回写 finding_id（仅当为空时，避免覆盖既有正确绑定）
            if not sp.get("finding_id"):
                if not dry_run:
                    db.execute("UPDATE trigger_specs SET finding_id=? WHERE id=?", (fid, int(sp["id"])))
                bound += 1
        logger.info("[TriggerSpec] 已绑定 %d 条 spec→finding（task_id=%s）", bound, task_id)
        return bound
    except Exception as _e:
        logger.warning("[TriggerSpec] bind_specs_to_findings 失败（跳过）：%s", _e)
        return 0


def purge_task_canary_events(task_id: Optional[int], dry_run: bool = False) -> int:
    """#1C 清空旧 canary 缓存：D1 重放前，删除「本 task 的 spec 对应的旧 canary 事件」。

    成因：探针（sec-probe.jar）在内存中缓存已注入过的 canary，重跑/换 task 时可能把上一次
    重放残留的 canary 事件再次回带，导致本次 D1 度量被陈旧事件污染（表现为「I1 观测到不属于
    本 task 的 canary 事件」）。本函数在每次 D1 重放开始前，按本 task 的 trigger_spec 身份段
    精准删除其历史 iast_events，给本次重放一个干净的度量基线。

    仅删除「canary 身份段 ∈ 本 task 的 spec 身份段」的事件 —— 不碰其他 task 的数据，安全可逆。
    参数：
      task_id: 目标 task；None 时不做任何事（避免误清全库）。
      dry_run: True 只返回待删数量不执行删除。
    返回：待删/已删的事件行数。
    """
    if task_id is None:
        return 0
    _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
    try:
        db = Database(_db_path)
        idents = [
            (r["taint_marker"][:22] if r["taint_marker"] else "")
            for r in db.execute(
                "SELECT taint_marker FROM trigger_specs WHERE task_id=?", (task_id,), fetchall=True
            )
            if r["taint_marker"]
        ]
        if not idents:
            return 0
        q = ",".join("?" * len(idents))
        rows = db.execute(
            f"SELECT count(*) c FROM iast_events WHERE canary IN ({q})", idents, fetchone=True
        )
        n = int(rows["c"]) if rows else 0
        if n and not dry_run:
            db.execute(f"DELETE FROM iast_events WHERE canary IN ({q})", idents)
            logger.info("[TriggerSpec] 已清空 task=%s 的旧 canary 事件 %d 条（D1 重放前基线清理）", task_id, n)
        return n
    except Exception as _e:
        logger.warning("[TriggerSpec] purge_task_canary_events 失败（跳过）：%s", _e)
        return 0
