import hashlib
import json
import re
from typing import Any, Dict, List


def _norm_text(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


# 短 ASCII token 必须按「词」匹配（两侧不得紧邻 [a-z0-9]），否则会被常见英文单词 / 路径的
# 子串误命中：resources→rce、mysql→sql、classpath→path、executor(MyBatis)→exec、
# escalation→sca。
#  实测事故：模板层 XSS 的 sink 为 src/main/resources/templates/*.html，
# 其中 "resources" 含子串 "rce"，而 command-execution 规则排在 xss 之前 → 每轮 3 条
# 模板 XSS + 1 条模板注入被错归 command-execution（spec 仍登记且仍 confirmed，但按
# 命令注入判据验证、族计数错位）。
_WORD_ONLY_NEEDLES = frozenset({
    "idor", "ssrf", "rce", "exec", "sql", "sqli", "path", "xss", "sca", "cve", "osv",
})
_WORD_RE_CACHE: Dict[str, Any] = {}


def _needle_hit(needle: str, text: str) -> bool:
    """needle 命中判定：短 ASCII token 走词边界，其余（含中文与长 token）沿用子串匹配。"""
    if needle not in _WORD_ONLY_NEEDLES:
        return needle in text
    pattern = _WORD_RE_CACHE.get(needle)
    if pattern is None:
        pattern = re.compile(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])")
        _WORD_RE_CACHE[needle] = pattern
    return bool(pattern.search(text))


def _norm_family(item: Dict[str, Any]) -> str:
    text = " ".join(
        _norm_text(item.get(key))
        for key in ("type", "display_family", "original_type", "finding_type", "description", "sink")
    )
    mapping = (
        (("idor", "ownership", "tenant", "resource_id", "越权"), "idor"),
        (("ssrf",), "ssrf"),
        (("command", "rce", "exec", "命令"), "command-execution"),
        (("sql", "sqli"), "sql-injection"),
        # 导致 /ldapi-00/ 端点落库为 xpathi 而与 GT(ldapi) 错配。这里以 LDAP 信号（描述/类型含
        # "ldap"）确定性收敛到 ldap_injection（normalize 层 alias→ldapi），与 A2/D2 LDAP 主链路一致。
        # 不入 "目录"（目录遍历描述也含"目录"），避免 path-traversal 被误并。
        (("ldap", "ldapi"), "ldap_injection"),
        # XPath 全称是 XML Path Language，它的 type/description 里天然含「路径」
        #         # 而下方 path-traversal 的中文针是纯子串匹配、没有词边界 ⇒ xpath 用例会先被
        # 用例 rule_name 是对的（XPath注入）但 type/finding_family 全被写成 路径穿越/
        # path_traversal，导致 path_traversal 成为全量第一大族（107 条）跨族无差别搭售。
        # 注意 xpath 针不能进 _WORD_ONLY_NEEDLES：要能命中 "javax.xml.xpath" 里的 xpath
        # （其左侧字符是 x，词边界会把它挡掉）。
        (("xpath", "xpathi", "xpath-injection"), "xpath-injection"),
        # 中文针不再用裸「路径」（同上，会被 XML 路径误中），收紧为路径穿越语义的整词。
        # "路径拼接" 覆盖 A1 「文件路径拼接」规则的 sink 文案，"目录遍历" 覆盖常见中文族名。
        (("path", "traversal", "路径穿越", "路径遍历", "路径拼接", "目录遍历"), "path-traversal"),
        (("xss",), "xss"),
        (("upload", "上传"), "file-upload"),
        (("deserial", "反序列化"), "deserialization"),
        (("sca",), "sca"),
    )
    for needles, family in mapping:
        if any(_needle_hit(needle, text) for needle in needles):
            return family
    # "cve"/"osv" 不代表依赖漏洞 —— 很多代码级配置/逻辑漏洞的标识本身就是 CVE 编号
    # （如 CVE-2022-22978 = Spring regexMatchers 授权绕过，属 broken_access_control）。
    # 旧实现把任何含 "cve" 的文本一律归 sca，导致：
    #   ① 族计数错位（CVE 授权绕过被计入 sca 依赖漏洞）；
    #   ② hash 走 SCA 分支且组件字段全空 → 退化成常量 hash（哈希塌缩，详见 hash_components）。
    # 现在只有「确有依赖组件信息」（component/version/vulnerability_id/ecosystem 之一）时
    # 才归 sca；否则归其真实类型（如 cve-2022-22978 / broken_access_control）。
    if _needle_hit("cve", text) or _needle_hit("osv", text):
        sca = item.get("sca") if isinstance(item.get("sca"), dict) else {}
        has_dep = any(
            _norm_text(sca.get(k) or item.get(k))
            for k in ("component_name", "component_version", "vulnerability_id", "ecosystem")
        )
        if has_dep:
            return "sca"
    return _norm_text(item.get("type") or item.get("finding_type") or "unknown") or "unknown"


def _stable_code_block(value: Any) -> str:
    code = str(value or "")
    code = re.sub(r"//.*|#.*", "", code)
    code = re.sub(r"\s+", "", code)
    if len(code) > 900:
        code = code[:450] + code[-450:]
    return hashlib.sha256(code.encode("utf-8", errors="ignore")).hexdigest()[:16] if code else ""


def _anchor(value: Any) -> str:
    text = _norm_text(value)
    text = re.sub(r"\b\d+\b", "<n>", text)
    return text[:160]


def hash_components(item: Dict[str, Any]) -> Dict[str, str]:
    family = _norm_family(item)
    file_path = _norm_text(item.get("file") or item.get("file_path"))
    file_tail = "/".join(part for part in file_path.split("/")[-3:] if part)
    source = _anchor(item.get("entry_point") or item.get("source") or item.get("trigger_route"))
    sink = _anchor(item.get("sink") or item.get("sink_anchor") or item.get("d2_status"))
    route = _anchor(item.get("entry_route") or item.get("trigger_route") or item.get("endpoint"))
    code_hash = _stable_code_block(item.get("code_snippet") or item.get("code") or item.get("snippet"))
    sca = item.get("sca") if isinstance(item.get("sca"), dict) else {}
    if family == "sca" or sca:
        sca_components = {
            "family": "sca",
            "component": _norm_text(sca.get("component_name") or item.get("component_name")),
            "version": _norm_text(sca.get("component_version") or item.get("component_version")),
            "vulnerability_id": _norm_text(sca.get("vulnerability_id") or item.get("vulnerability_id") or item.get("id")),
            "ecosystem": _norm_text(sca.get("ecosystem") or item.get("ecosystem")),
        }
        # SCA 分支。若 component/version/vulnerability_id/ecosystem 全空，返回该字典会塌缩为
        # 常量 {"family":"sca","component":"","version":"","vulnerability_id":"","ecosystem":""}，
        # f74c4bf23d66d43c9700833f 被信息泄露(Index.java)、XXE(XXE.java)、CVE 授权绕过
        # (WebSecurityConfig.java)、CORS(/cors) 四种互不相关的漏洞共用 —— 黑板按 hash 合并，
        # CVE finding 因此「继承」了 /cors 的 confirmed_exploitable/sink-reached-probe，
        # 验证态误挂、跨任务污染。
        # 现在无 SCA 内容时回落到常规组件（含 file_tail/route/code_block），使代码级 CVE 等
        # 获得唯一且稳定的 hash；真实依赖漏洞（有组件字段）仍走 SCA 分支，去重语义不变。
        if any(sca_components[k] for k in ("component", "version", "vulnerability_id", "ecosystem")):
            return sca_components
        # 无 SCA 内容 -> 落到下方常规组件；family 仍按 _norm_family 结果（代码级 CVE 已不再归 sca）。
    return {
        "family": family,
        "file_tail": file_tail,
        "source": source,
        "sink": sink,
        "route": route,
        "code_block": code_hash,
        # category 维度：业务逻辑漏洞（bola/vertical_privesc/...）即使同 endpoint 也不同类，
        # 必须显式进 hash，避免被 _norm_family 统一掉进 idor 而含糊合并（架构决议 §去重）。
        # 缺省 "" 对注入类无影响，向后兼容。
        "category": _norm_text(item.get("category")),
    }


def vulnerability_hash_v2(item: Dict[str, Any]) -> str:
    components = hash_components(item)
    payload = json.dumps(components, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# 背景：hash 的 source 组件语义是「代码定位（文件:行）」，canonicalize 的取值链为
#   entry_point -> source -> trigger_route
# 而 A1 静态通道把「检测器身份」写进了 source（a1_injection_heuristic.py 的
# `source="a1-injection-heuristic"`，另有 'a1' / 'a2' 两种取值）。于是同一条漏洞：
#   spec 侧（raw A2 dict，带 source）  -> source 组件 = 'a1-injection-heuristic'
#   finding 侧（report_manager dict，无 source 字段） -> source 组件 = ''
# 两侧 vhash 分叉，spec 与 finding 永远关联不上（假孤儿），对账层读不到该漏洞的 spec。
# spec（2dc234cb30e2a13491a464e5）逐组件比对，唯一差异就是这个 source 字段。
# 修法：source 只在「确为定位形态」（含路径分隔符 / 行号冒号 / 源码扩展名结尾）时才采信；
# 检测器身份串不计入。entry_point / trigger_route 两档不受影响。
#   finding 侧 hash 变化 0 条；spec 侧变化 57 条；两侧同 hash 交集群 43 -> 93。
# ---------------------------------------------------------------------------
_CODE_LOCATION_RE = re.compile(r"[:/\\]|\.[A-Za-z][A-Za-z0-9]{0,7}$")


def _looks_like_code_location(value: Any) -> bool:
    """判断取值是否为「代码定位」形态（如 OrderService.java:118、src/main/java/X.java）。

    非定位形态（检测器身份 a1-injection-heuristic / a1 / a2、纯类型名）一律返回 False。
    """
    return bool(_CODE_LOCATION_RE.search(str(value or "").strip()))


def canonicalize_vuln_for_hash(vuln: Any) -> Dict[str, Any]:
    """把 A2 ``vuln.to_dict`` 与 report_manager finding dict 的字段变体统一归一为
    ``hash_components`` 期望的规范键集，确保同一漏洞（无论来自哪个阶段、字段名如何变体）
    的 ``vulnerability_hash_v2`` 完全一致 —— 这是「假孤儿误删」的根因修复。

    - 族名 / category 经 ``canonical_business_logic_family`` 归一（DIFFERENTIAL_PROOF_FAMILIES 单一真相源，簇一）；
    - 端点字段统一填充 ``entry_route``/``trigger_route``/``endpoint``/``target_endpoint``/``route`` 全部视图，
      使 hash_components 的别名读取得到同一解析结果（簇三）；
    - 受害者资源 id 唯一字段 ``victim_resource_id``（簇二）；
    - canary 完整值字段 ``taint_marker``（≡ ``iast_events.canary``，簇四）不参与 hash（vhash 描述的是漏洞身份、
      与每轮 canary 无关），此处仅作规范名对齐、不落入 components。

    返回仅含 hash 相关规范键的 dict，供 ``vulnerability_hash_v2`` 直接消费。
    """
    # 惰性导入避免潜在循环依赖（exploit_spec 被 core 包大量模块引用）。
    from src.core.exploit_spec import (
        canonical_business_logic_family,
        canonical_exposure_family,
    )

    def _canon_family(raw: str) -> str:
        # 族名单一真相源：先过业务差分族归一，再过暴露/配置族归一（与 derive_flow_type /
        # is_business_logic_family / is_exposure_family 同一真源，NAMING_STANDARDS 簇一/三）。
        # 非业务非暴露的注入型族（sql/xss/ssrf…）两函数均 passthrough，结果不变。
        return canonical_exposure_family(canonical_business_logic_family(raw))

    if hasattr(vuln, "to_dict"):
        _src = vuln.to_dict()
    elif not isinstance(vuln, dict):
        return {}
    else:
        _src = vuln

    def _pick(*keys, default: str = "") -> Any:
        for k in keys:
            v = _src.get(k)
            if v not in (None, "", [], {}):
                return v
        return default

    # 族名单一真相源归一（NAMING_STANDARDS 簇一/三）
    # 关键：必须优先 original_type。report_manager 在落库前把 original_type 强制回填为「原始 A2 type」，
    # 而 finding 侧的 type 已被改写为 display_title、display_family 由 report_manager 自己的归一器算出——
    # 两者可能和系统 canonical_business_logic_family 不完全一致。优先吃 original_type 可保证 spec 侧
    # （raw A2，无 original_type 字段→回退到 type）与 finding 侧（original_type==原始 A2 type）读到
    # 完全同一个族源，消除「family 漂移」导致的假孤儿误删（AP 段 81 条真 POC 被删的根因之一）。
    raw_family = _pick(
        "original_type", "family", "type", "vuln_type",
        "payload_family", "display_family", "finding_family",
    )
    norm_family = _canon_family(raw_family) if raw_family else ""
    # category 仅从 category / business_logic_category 字段归一（业务型子类目必须显式进 hash，
    # 避免同端点不同类目被含糊合并）。注意：不得回退到 raw_family —— 注入/暴露类漏洞的 category 恒为空，
    # 回退会把 family 注入 category 组件，破坏既有 finding vhash 的向后兼容性（129/200 回归根因）。
    norm_category = _canon_family(_pick("category", "business_logic_category"))

    file_v = _norm_text(_pick("file", "file_path"))
    # 代码定位（文件:行）。source 档加「定位形态」守卫，避免 A1 的检测器身份串
    # （'a1-injection-heuristic'/'a1'/'a2'）被当作定位吃进 hash，导致 spec 侧与 finding 侧
    # vhash 分叉（假孤儿，详见 _looks_like_code_location 上方说明）。
    _ep_v = _pick("entry_point")
    _src_v = _pick("source")
    _tg_v = _pick("trigger_route")
    entry_v = _ep_v or (_src_v if _looks_like_code_location(_src_v) else "") or _tg_v
    # 历史教训（两次）：route 一旦进 hash，会因「通道 A(target_endpoint) 与 通道 B(exploit_spec.entry.route)
    # 漂移」「entry.route 被 plan_pocs 改写致 runtime_vhash ≠ stored_vhash、D2 回写落空」反复制造
    # 「假孤儿误删 81 条真 POC」与「trigger_spec verification_status 永空」（见本文件 stable_vuln_key
    # 即本就未进 hash；此前 _pick("target_endpoint","endpoint","route","http_path", _es_route) 把
    # _es_route 当位置参数误传（等价于 _src.get("/cors") 恒 None），使 exploit_spec.entry.route 永不
    # 生效——这是 latent 陷阱：一旦有人「修正」该 bug 把 _es_route 当 default 传入，route 即进 hash、
    # 全线回归。此处显式归零并删除死代码，使「route 永不进入 hash」成为确定行为。
    # 真实路由只走 trigger_specs.target_endpoint（通道 A，D1 重放权威）/ exploit_spec.entry.route（通道 B），
    # 二者由 auto_register_from_a2 写回收口为一致，不参与身份 hash。
    route_v = ""
    # sink：严禁把 d2_status 当作 sink 吃进 hash。d2_status 是 D2 验证态（plan_ready/unverified/
    # sink_reached 等），仅存在于 finding 侧（report/D2 注入），raw A2 spec 侧无此字段——把它放进
    # sink 别名链会造成「finding 侧 sink=plan_ready、spec 侧 sink=''」的永久失配，进而被
    # reconcile_orphan_specs 判孤儿静默删除（AP 段 81 条真 POC 被删的主根因）。改为只吃真实 sink 名。
    sink_v = _pick("sink", "sink_anchor")
    code_v = _pick("code_snippet", "code", "snippet")
    description_v = _src.get("description") or ""

    # SCA：优先内嵌 sca 子 dict；否则从顶层 component_* 字段重建，兼容两种 finding 形态
    _raw_sca = _src.get("sca")
    if isinstance(_raw_sca, dict):
        sca_v = _raw_sca
    elif _pick("component_name", "component"):
        sca_v = {
            "component_name": _norm_text(_pick("component_name", "component")),
            "component_version": _norm_text(_pick("component_version", "version")),
            "vulnerability_id": _norm_text(_pick("vulnerability_id", "id", "cve_id")),
            "ecosystem": _norm_text(_pick("ecosystem")),
        }
    else:
        sca_v = {}

    return {
        # 族名 + 展示 + category（全归一，避免注入/业务/暴露三类字段形态漂移）
        "family": norm_family,
        "type": norm_family,
        "display_family": norm_family,
        "payload_family": norm_family,
        "finding_family": norm_family,
        "original_type": norm_family,
        "category": norm_category,
        "business_logic_category": norm_category,
        "description": description_v,
        # 文件（双键一致）
        "file": file_v,
        "file_path": file_v,
        # 代码定位（单键一致）
        "entry_point": entry_v,
        "source": entry_v,
        # HTTP 路径（多视图一致）
        "entry_route": route_v,
        "trigger_route": route_v,
        "target_endpoint": route_v,
        "endpoint": route_v,
        "route": route_v,
        "http_path": route_v,
        # sink
        "sink": sink_v,
        "sink_anchor": sink_v,
        "d2_status": sink_v,
        # 代码块
        "code_snippet": code_v,
        "code": code_v,
        "snippet": code_v,
        # SCA
        "sca": sca_v,
        "component_name": sca_v.get("component_name", "") if sca_v else _pick("component_name"),
        "component_version": sca_v.get("component_version", "") if sca_v else _pick("component_version"),
        "vulnerability_id": sca_v.get("vulnerability_id", "") if sca_v else _pick("vulnerability_id", "id"),
        "ecosystem": sca_v.get("ecosystem", "") if sca_v else _pick("ecosystem"),
        # 受害者资源 id（唯一规范名，NAMING_STANDARDS 簇二）
        "victim_resource_id": _pick("victim_resource_id"),
    }


def stable_vuln_key(vuln: Any, line_agnostic: bool = False) -> str:
    """Route-漂移免疫、且表示形态无关的稳定关联键（D2 关联键加固）。

    ``line_agnostic=True`` 时算「行号无关弱键」（把 ``l`` 固定为 0 再哈希）。

    「行号来源的任何变化」敏感——只要将来有一侧改成从别处取行号（例如从 IAST 事件回填真实
    sink 行、或从 A0 静态路由表回填），两端立刻算出不同的键，D2 关联会**成批**失配，
    而症状只是「验证数突然下降」，极难反查（记忆里已有一条同类问题：报点行漂移）。
    弱键让「行号一致时走强键、行号漂移时走弱键兜底」成为可能，不会因行号变化直接丢关联。

    弱键只应在**强键未命中时**作为兜底使用：它把同文件同类型但不同行的漏洞也可能并到一起，
    单独使用会放大误归因面。

    见 canonicalize_vuln_for_hash 任务③修复）——但历史上 route 进 hash 曾因 entry.route 被
    ``_pre_resolve_a2_endpoints`` / plan_pocs 改写而漂移，导致 runtime_vhash ≠ stored_vhash、Phase2 写回落空。
    本函数仍坚持 route 完全不参与，作为 D2 关联键的纵深免疫：即便未来路由口径再变动，D2 关联不受影响。

    本函数**不复用 canonicalize_vuln_for_hash**：canonicalize 会吃 original_type/category/sink/entry_point
    等字段，而 spec 的 raw_json 是**完整** vuln 字典、run_d2_verify 产出的 vuln_payload 是**精简子集**
    （缺 category/original_type 等），两端喂入 canonicalize 会归一出不同 key，反而匹配失败。

    故关联键只依赖两端**必然相等、且不受 plan_pocs 篡改**的源坐标字段：
      - file_tail（路径末 3 段，归一化，抗绝对/相对路径差异）
      - line（源码行号，plan_pocs 不动）
      - type（漏洞类型，canonicalize 前的原始 type/finding_type，raw_json 与 vuln_payload 同源）
      - code_block（code_snippet 归一哈希；code_snippet 是源码快照，plan_pocs 不改写）
    auto_register 在 plan_pocs 之后执行，故 raw_json 与 vuln_payload 都反映 post-plan_pocs 状态，上述字段两端
    恒等。route 完全不参与，彻底免疫 entry.route 漂移；也不吃 original_type/category 等表示形态敏感字段，
    彻底规避「完整 dict vs 精简 dict」的归一错位。

    参数：vuln 对象（有 to_dict）或 dict。
    返回：24 位 hex 稳定关联键；输入非法时返回 ""。
    """
    try:
        if hasattr(vuln, "to_dict"):
            src = vuln.to_dict()
        elif isinstance(vuln, dict):
            src = vuln
        else:
            return ""

        def _pick(*keys, default=""):
            for k in keys:
                v = src.get(k)
                if v not in (None, "", [], {}):
                    return v
            return default

        file_v = _norm_text(_pick("file", "file_path"))
        file_tail = "/".join(p for p in file_v.split("/")[-3:] if p)
        type_v = _norm_text(_pick("type", "original_type", "family", "vuln_type", "finding_type", "display_family"))
        line_v = "0" if line_agnostic else str(_pick("line", default=0) or 0)
        code_v = _stable_code_block(_pick("code_snippet", "code", "snippet"))
        payload = json.dumps(
            {"ft": file_tail, "t": type_v, "l": line_v, "c": code_v},
            sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    except Exception:
        return ""


def stable_vuln_keys(vuln: Any) -> List[str]:
    """返回稳定关联键的「强键 + 弱键」有序列表（供并集反查）。

    顺序恒为 [强键(file+line+type+code), 弱键(file+type+code，行号置 0)]；
    调用方应先按强键查，未命中再按弱键兜底。任一键算不出时省略（不返回空串）。
    """
    out: List[str] = []
    for _flag in (False, True):
        try:
            k = stable_vuln_key(vuln, line_agnostic=_flag)
        except Exception:
            k = ""
        if k and k not in out:
            out.append(k)
    return out


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 为什么需要第二把键：vulnerability_hash_v2 是**精确身份键**，组件里含 source/sink/
# code_block/category，任何一个字段的形态漂移（行号变动、代码片段截断、A2 改写描述）
# 都会让同一处漏洞跨轮算出不同 hash。用它当**对账分母**会让分母随生成噪声抖动 ——
# 上一轮 199 条、这一轮 203 条，数字动了但没人知道是能力变了还是措辞变了。
#
# 聚合键只保留「人眼认定同一处漏洞」所必需的三要素：
#     family（哪一类） + file_tail（哪个文件） + route（哪个入口）
# 不含行号、不含代码片段、不含 sink 文本 ⇒ 抗行漂移、抗描述改写、抗 A2 措辞抖动。
# 代价：同一文件同一入口的两个不同参数点会被并成一条 —— 这正是「对账分母」想要的
# 语义（数的是「几处漏洞」，不是「几条 finding」）。
#
# 双键分工（勿混用）：
#     aggregate_stable_key  → 对账分母 / 跨轮对比 / 黄金集匹配（稳定性优先）
#     vulnerability_hash_v2 → spec↔finding 追踪 / 去重落库 / D2 关联（精确性优先）
#
# 进入身份 hash）。聚合键**必须**吃真实路由，故此处从原始 item 直读，绝不过
# canonicalize——否则 route 恒空，聚合键退化成 family+file_tail 两要素。
def aggregate_components(item: Any) -> Dict[str, str]:
    """稳定聚合键的三个组件：family / file_tail / route。"""
    src = item.to_dict() if hasattr(item, "to_dict") else (item if isinstance(item, dict) else {})

    def _pick(*keys, default: str = "") -> Any:
        for k in keys:
            v = src.get(k)
            if v not in (None, "", [], {}):
                return v
        return default

    file_path = _norm_text(_pick("file", "file_path"))
    file_tail = "/".join(p for p in file_path.split("/")[-3:] if p)
    route = _anchor(
        _pick("target_endpoint", "entry_route", "trigger_route", "endpoint", "route", "http_path")
    )
    # 族名走 _norm_family 的别名归一（与 hash_components 同一真源），否则 spec 侧的
    # family 列与 finding 侧的 type/finding_type 列会算出不同聚合键、对不上账。
    # 注意 _norm_family 不读 "family" 键，故此处显式把取值放进 "type" 再喂进去。
    raw_family = _pick("family", "type", "original_type", "finding_type", "display_family", "category")
    return {
        "family": _norm_family({"type": raw_family}),
        "file_tail": file_tail,
        "route": route,
    }


def aggregate_stable_key(item: Any) -> str:
    """稳定聚合键（对账分母用）：sha256(family + file_tail + route)[:24]。

    输入非法或三要素全空时返回 ""（调用方应跳过，不要拿空串当分组键 —— 那会把
    所有残缺 finding 并成一大坨）。
    """
    try:
        comp = aggregate_components(item)
    except Exception:
        return ""
    # 至少要能定位到「哪个文件」或「哪个入口」，否则这条 finding 连人都认不出是啥，
    # 算出来的键只会把所有残缺记录并成一大坨（family 缺省会归一成 "unknown"，不能用它判空）。
    if not (comp.get("file_tail") or comp.get("route")):
        return ""
    payload = json.dumps(comp, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def enrich_finding_hash(item: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(item)
    # 归一 hash 输入，消除 A2 vuln.to_dict 与 report_manager finding dict 字段形态差异
    # （杠杆一：同一漏洞在 spec 注册端与 finding 落库端产出一致 vhash，根治假孤儿误删）。
    canonical = canonicalize_vuln_for_hash(enriched)
    components = hash_components(canonical)
    enriched.setdefault("vulnerability_hash_v1", enriched.get("chain_id") or enriched.get("canonical_group_key") or "")
    enriched["vulnerability_hash_v2"] = vulnerability_hash_v2(canonical)
    enriched["hash_components"] = components
    enriched["hash_confidence"] = "high" if components.get("code_block") or components.get("vulnerability_id") else "medium"
    # 聚合键从**原始** item 算（需吃真实路由），不走 canonicalize（它会把 route 归零）。
    _agg = aggregate_stable_key(enriched)
    if _agg:
        enriched["aggregate_stable_key"] = _agg
        enriched["aggregate_components"] = aggregate_components(enriched)
    return enriched


def enrich_findings(items: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    return [enrich_finding_hash(item) for item in items]


# ---------------------------------------------------------------------------
# 业务逻辑漏洞 跨 stage 聚类去重
# ---------------------------------------------------------------------------
def business_logic_group_key(item: Dict[str, Any], app: str = "") -> str:
    """跨 stage 聚类 key：同一 ``(app, file, route, method, vulnerable_param, category)`` 归并。

    用于把 A1 多个 analyzer / A2 语义分析 / D1 重放确认 / IAST 观测 对同一业务逻辑点的
    重复命中合并为一条「证据」，但 ``category`` 显式参与 key，保证 BOLA 与垂直越权等同
    endpoint 不同类目不会被含糊并成一条（类型可区分）。
    """
    file_path = _norm_text(item.get("file") or item.get("file_path"))
    route = _anchor(
        item.get("target_endpoint") or item.get("entry_route")
        or item.get("trigger_route") or item.get("endpoint")
    )
    method = _norm_text(item.get("http_method") or item.get("method"))
    param = _anchor(item.get("vulnerable_param") or item.get("param"))
    category = _norm_text(item.get("category"))
    raw = json.dumps(
        {
            "app": _norm_text(app),
            "file": file_path,
            "route": route,
            "method": method,
            "param": param,
            "category": category,
        },
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def cluster_business_logic_hypotheses(hypos: List[Dict[str, Any]], app: str = "") -> List[Dict[str, Any]]:
    """把跨 analyzer / 跨 stage 的业务逻辑假说聚类为单条「待验证」证据。

    - 同 ``(app, file, route, method, vulnerable_param, category)`` 的假说合并为一条，
      保留 ``category`` / ``vuln_types`` / ``evidence`` / ``sources`` 列表（类型可区分）。
    - 若任一成员 ``status=confirmed`` 或 ``source`` 以 ``d1`` 开头，则升级为 ``confirmed``。
    - IAST 观测（``source`` 以 ``iast`` 开头）只追加 evidence，不单独成簇。

    返回顺序与首次出现顺序一致。
    """
    groups: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for h in hypos or []:
        if not isinstance(h, dict):
            continue
        key = business_logic_group_key(h, app=app)
        if key not in groups:
            groups[key] = {
                "app": app,
                "file": h.get("file") or h.get("file_path") or "",
                "target_endpoint": (
                    h.get("target_endpoint") or h.get("entry_route")
                    or h.get("endpoint") or ""
                ),
                "http_method": h.get("http_method") or h.get("method") or "",
                "vulnerable_param": h.get("vulnerable_param") or h.get("param") or "",
                "category": h.get("category") or "",
                "vuln_types": [],
                "evidence": [],
                "sources": [],
                "status": "pending_verification",
            }
            order.append(key)
        g = groups[key]
        vt = h.get("vuln_type")
        if vt and vt not in g["vuln_types"]:
            g["vuln_types"].append(vt)
        ev = h.get("evidence")
        if ev and ev not in g["evidence"]:
            g["evidence"].append(ev)
        src = h.get("source") or "unknown"
        if src not in g["sources"]:
            g["sources"].append(src)
        hstatus = str(h.get("status") or "")
        if hstatus == "confirmed" or src.startswith("d1"):
            g["status"] = "confirmed"
    return [groups[k] for k in order]
