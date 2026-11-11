"""BOLA 业务逻辑策略分析。

职责：识别「敏感操作 + 应有控制点缺失」——即某 handler 用外部传入的实体 id 直接做数据访问
（repository.findById / ORM get / SQL WHERE id= / Mongo find_one(_id)），但方法体内未做归属校验
（不比对当前主体与资源 owner、无 @PreAuthorize / hasPermission / checkOwnership 等）。

**定位：离线兜底（非主链路）。** 业务逻辑漏洞的主链路是 ``A1BusinessLogicAIAgent``（LLM 语义识别，
见 src/agents/a1_business_logic_ai_agent.py）。本分析器仅在未配置 LLM（ModelGateway 离线）时
作为低成本启发式被调用，不在主链路中。CodeQL 在主链路中承担辅助结构验证（参数是否经过
ownership 校验函数）。

BOLA 家族映射对齐 SAST 的 IDOR（BOLA→IDOR 以便 vulnerability_hash_v2 对齐）。
"""
# 业务逻辑漏洞主链路为 A1BusinessLogicAIAgent（LLM 语义识别）；本模块仅作离线兜底。
IS_PRIMARY_PATH = False

import re
from typing import Any, Dict, List, Optional

# 数据访问「按 id 取对象」sink（敏感操作）。命中即代表"用外部 id 直查对象"。
_DATA_ACCESS_PATTERNS = [
    re.compile(
        r"""(?ix)
        (?:\w+\.)?
        (?:repository|repo|dao|mapper|entitymanager|em|session|db|collection|\w+dao|\w+\.objects)
        \s*\.\s*
        (?:findbyid|findby|findone|find|getbyid|getby|get|load|query|find_one|findonebyid|findbyuuid)
        \s*\([^)]*\)""",
    ),
    re.compile(r"""(?ix)(?:select|delete|update)\s+.+\bwhere\b\s+.{0,80}?\bid\b\s*=\s*:?\s*\S+"""),
    re.compile(r"""(?ix)(?:mongo|collection|db)\.find_one\s*\(\s*\{[^}]*['"]?_?id['"]?\s*:\s*[^}]+\}"""),
]

# 方法体内出现以下任一 token 即视为"有控制点"，不构成 BOLA 假说。
_OWNERSHIP_TOKENS = (
    "getcurrentuser", "getprincipal", "getauthentication", "securityutils",
    "haspermission", "preauthorize", "postauthorize", "checkownership",
    "isowner", "owns", "verifyaccess", "assertcanaccess", "accesscontrol",
    "ownerid", "owner_id", "owner ==", "owner.equals", "currentuser",
    "authentication", "authorized", "acl", "rbac", "getloggedinuser",
)

_ID_PARAM_RE = re.compile(r"(?i)\b(\w*id\w*)\b")

# 状态机 / 流程类端点（cancel/ship/refund/complete/process/submit/approve/transition 等）：
# 其「按 id 取对象」通常是状态流转前置查询，而非越权读取他人资源，不构成 BOLA。
# ：排除这类端点，降低 BOLA 在状态机端点上的误报。
# 注：用首部负 lookbehind 匹配 camelCase 复合名（cancelOrder / shipOrder），不加尾部 \b 以免漏配。
_STATE_MACHINE_OP = re.compile(
    r"(?i)(?<!\w)("
    r"cancel|ship|refund|complete|process|submit|approve|reject|confirm|"
    r"transition|updatestatus|setstatus|changestatus|close|finish|revoke|"
    r"activate|deactivate|lock|unlock|advance|step|next|mark\w*|"
    r"updateorder|orderstatus|handle\w*"
    r")"
)

# 业务逻辑离线兜底（除 BOLA/IDOR 外，覆盖非 ORM 形态的「设计层」漏洞）：
#  - 不安全对象存储 / Mass Assignment：外部传入的 Map/Object/DTO 被无校验地 putAll/put/copyProperties
#    进内部可变状态（如 java-quote 的 importConfig(Map) -> userConfig.putAll）。
#  - 敏感对象暴露：getter 直接返回内部可变容器/对象引用（如 getQuoteCache -> quoteCache 含 processor 对象）。
# 这些在 java-quote 这类内存态靶场里是主要业务逻辑缺陷，ORM/SQL sink 启发式抓不到，故离线补位。
_MASS_ASSIGN_SINK = re.compile(
    r"""(?ix)
    (?:\w+\.)?(?:putall|addall|setall|merge|copyProperties|copyPropertiesTo|populate|updateAll)
    \s*\([^)]*\)"""
)
_MAP_PARAM_RE = re.compile(r"(?i)\b(map|dict|properties|object|dto|config|payload|params?|body|jsonnode|hashmap|hashtable|jsonobject)\b")
_SENSITIVE_EXPOSE_RE = re.compile(
    r"(?i)return\s+(?:quoteCache|userConfig|cache|store|registry|context|session|state|config)\b"
)
_SENSITIVE_FIELD_DECL = re.compile(
    r"""(?i)(private|protected|public)?\s+(?:final\s+)?(map|hashmap|hashtable|properties|object|concurrenthashmap)\b"""
)


def _is_getter(name: str) -> bool:
    return bool(re.match(r"(?i)^(get|fetch|load|export|dump|serialize|toMap|asMap)\w*$", name))


def _extract_functions(content: str, lang: str) -> List[Dict[str, Any]]:
    """按语言抽取函数/方法块（启发式，够 analyzer 用）。返回 [{name, params, body, start}]。"""
    funcs: List[Dict[str, Any]] = []
    lines = content.splitlines()
    lang = (lang or "").lower()

    if lang in ("py", "python"):
        for i, line in enumerate(lines):
            m = re.match(r"^(\s*)def\s+(\w+)\s*\((.*?)\)\s*:", line)
            if not m:
                continue
            indent = len(m.group(1))
            body: List[str] = []
            for j in range(i + 1, len(lines)):
                cur = lines[j]
                if cur.strip() == "" or (len(cur) - len(cur.lstrip())) > indent:
                    body.append(cur)
                else:
                    break
            funcs.append({"name": m.group(2), "params": m.group(3), "body": "\n".join(body), "start": i + 1})
        return funcs

    # java / js / ts / php / go：括号匹配
    for i, line in enumerate(lines):
        m = re.search(r"\b(\w+)\s*\(([^)]*)\)\s*\{", line)
        if not m or line.strip().startswith(("if", "for", "while", "switch", "catch", "do", "else")):
            continue
        depth = 0
        started = False
        body: List[str] = []
        for j in range(i, len(lines)):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            body.append(lines[j])
            if started and depth == 0:
                break
        funcs.append({"name": m.group(1), "params": m.group(2), "body": "\n".join(body), "start": i + 1})
    return funcs


def _has_ownership_check(body: str) -> bool:
    low = body.lower()
    return any(tok in low for tok in _OWNERSHIP_TOKENS)


def _find_id_param(params: str) -> Optional[str]:
    m = _ID_PARAM_RE.search(params or "")
    return m.group(1) if m else None


def _sink_has_id_arg(sink_text: str) -> bool:
    """sink 调用的实参里含 id 字样（如 findById(orderId)）。"""
    return bool(_ID_PARAM_RE.search(sink_text))


def analyze_file(path: str, content: str, lang: Optional[str] = None) -> List[Dict[str, Any]]:
    """单文件分析：返回业务逻辑假说（BOLA/IDOR + 不安全对象存储/Mass Assignment + 敏感对象暴露）。"""
    if lang is None:
        lang = (path.rsplit(".", 1)[-1] if "." in path else "").lower()
    hypotheses: List[Dict[str, Any]] = []
    for fn in _extract_functions(content, lang):
        # 状态机 / 流程类端点：按 id 取对象多为状态流转前置，不构成 BOLA 假说
        if _STATE_MACHINE_OP.search(fn["name"]):
            continue
        # ---- BOLA / IDOR：按 id 取对象 + 缺失归属校验（ORM/SQL 形态）----
        for pat in _DATA_ACCESS_PATTERNS:
            m = pat.search(fn["body"])
            if not m:
                continue
            sink_text = m.group(0)
            # 有归属校验则不构成 BOLA
            if _has_ownership_check(fn["body"]):
                break
            id_param = _find_id_param(fn["params"])
            # 需要能定位到"外部传入的 id"（签名 id 参数 或 sink 实参含 id），降低误报
            if not id_param and not _sink_has_id_arg(sink_text):
                break
            hypotheses.append({
                "vuln_type": "BOLA",
                "family": "IDOR",  # BOLA→IDOR 以便 vuln_hash 对齐
                "entry_point": f"{path}:{fn['start']}",
                "function": fn["name"],
                "param": id_param or "<id-arg>",
                "data_access_sink": sink_text[:200],
                "required_control_point": "归属校验：比对当前主体与资源 owner（hasPermission/@PreAuthorize/checkOwnership/owner==currentUser）",
                "confidence": "medium",
                "evidence": "敏感操作(按id取对象) 且 方法体内未见归属/授权校验",
            })
            break

        # ---- 不安全对象存储 / Mass Assignment：外部 Map/Object 被无校验地并入内部可变状态 ----
        if _MAP_PARAM_RE.search(fn["params"] or "") and _MASS_ASSIGN_SINK.search(fn["body"]):
            if not _has_ownership_check(fn["body"]):
                hypotheses.append({
                    "vuln_type": "MASS_ASSIGNMENT",
                    "family": "mass-assignment",
                    "category": "不安全对象存储",
                    "entry_point": f"{path}:{fn['start']}",
                    "function": fn["name"],
                    "param": _find_id_param(fn["params"]) or "<map-arg>",
                    "data_access_sink": _MASS_ASSIGN_SINK.search(fn["body"]).group(0)[:200],
                    "required_control_point": "对外部传入对象做字段白名单/类型校验，禁止整体 putAll 进内部状态",
                    "confidence": "medium",
                    "evidence": "方法接收外部 Map/对象并整体 putAll/put 进内部可变状态，缺字段校验",
                })

        # ---- 敏感对象暴露：getter 直接返回内部可变容器/对象引用 ----
        if _is_getter(fn["name"]) and _SENSITIVE_EXPOSE_RE.search(fn["body"]):
            hypotheses.append({
                "vuln_type": "SENSITIVE_EXPOSURE",
                "family": "sensitive-exposure",
                "category": "信息泄露",
                "entry_point": f"{path}:{fn['start']}",
                "function": fn["name"],
                "param": "",
                "data_access_sink": fn["name"],
                "required_control_point": "返回内部状态的不可变拷贝/投影，避免泄露内部对象引用（含可用作 gadget 的 processor 等）",
                "confidence": "medium",
                "evidence": "getter 直接返回内部可变容器/对象引用（可能含可被利用的内部对象）",
            })
    return hypotheses


def analyze_sources(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量分析（与 A1 scan_files 的输入形状对齐：[{path, content, language?}]）。"""
    out: List[Dict[str, Any]] = []
    for f in files or []:
        path = f.get("path") or f.get("file_path") or ""
        content = f.get("content") or f.get("source") or ""
        lang = f.get("language") or f.get("lang")
        out.extend(analyze_file(path, content, lang))
    return out
