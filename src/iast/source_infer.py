"""源码驱动的注入点推导（阶段 1.1：重放智能化）。

背景（r109 逐案取证）
--------------------
把 1833 条 spec 按证据链分桶后，125 条（6.8%）落在 S2 —— canary **送达到了应用**
（有探针事件）但**没到该族 sink**。逐案比对「spec 记录的注入点」与「servlet 源码真实的
取源表达式」，发现两类系统性错配：

1. **源位置错**：spec 记 query，servlet 实际读 header / cookie（A2 默认猜 query）；
2. **源藏在 helper 类**：servlet 里根本没有 getParameter/getHeader 字样，取源转发到
   `org.owasp.benchmark.helpers.SeparateClassRequest.getTheParameter(...)` 之类的工具类
   （如 BenchmarkTest00996/00100 那段 cookie 源）。只在 servlet 本文件里做正则匹配会
   「无显式取源」而误判为无法判定，而这批恰好是 r109 里 9 个「弱证据 TP」的主体。

本模块只读源码、确定性推导（与 `src/core/source_location.py` 同一风格，不调 LLM），
输出**全部**候选注入点（而不是单个 location），供 D1 在 spec 覆盖不到时补投。

设计约束
--------
- 只做「补投」：spec 已覆盖的 (name, location) 不重复注入，主注入路径行为不变；
- 名注入源（读参数/头的**名字**）不在此模块产出 —— 那条路径由 `detect_name_source`
  + D1 的 Fix C 独占，避免两个机制同时抢请求；
- 所有产出都带 `evidence`（命中的源码片段）与 `confidence`，可审计、可回退。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from src.core.source_location import strip_java_comments

VALID_LOCATIONS = {"query", "header", "cookie", "body", "path"}

# 参数名合法性（与 D1 的 is_valid_param_name 保守一致：字母数字与少量分隔符）
_VALID_PARAM_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")


@dataclass(frozen=True)
class InjectionPoint:
    """一个候选注入点。"""

    name: str            # 参数名（body 源可能为空串）
    location: str        # query / header / cookie / body / path
    kind: str = "value"  # value=把值注到这里；name=把名字注到这里（本模块不产出）
    evidence: str = ""   # 命中的源码片段（审计用）
    confidence: float = 0.5

    def as_tuple(self) -> Tuple[str, str]:
        return (self.name, self.location)


# ---------------------------------------------------------------- 源码抽取

def _read_code(path: Optional[str] = None, code: Optional[str] = None,
               code_root: Optional[str] = None) -> Optional[str]:
    if code is not None:
        return strip_java_comments(code)
    if not path:
        return None
    real = resolve_source_path(path, code_root)
    if not real:
        return None
    try:
        with open(real, encoding="utf-8", errors="replace") as fh:
            return strip_java_comments(fh.read())
    except Exception:
        return None


def _points_from_code(code: str, case_name: Optional[str] = None) -> List[InjectionPoint]:
    out: List[InjectionPoint] = []
    esc = re.escape(case_name) if case_name else None

    def add(name: str, loc: str, ev: str, conf: float, kind: str = "value") -> None:
        name = (name or "").strip()
        if loc not in VALID_LOCATIONS:
            return
        if kind == "value" and name and not _VALID_PARAM_NAME.match(name):
            return  # 非法参数名（含逗号/引号/类型签名）不作为注入点
        out.append(InjectionPoint(name=name, location=loc, kind=kind,
                                  evidence=ev[:160], confidence=conf))

    # ① header：getHeader("X") / getHeaders("X")
    for m in re.finditer(r'getHeaders?\s*\(\s*"([^"]{1,80})"', code):
        add(m.group(1), "header", m.group(0), 0.95)
    for m in re.finditer(r"getHeader\s*\(\s*([A-Za-z_][A-Za-z0-9_]{0,60})\s*\)", code):
        add(m.group(1), "header", m.group(0), 0.6)

    # ② query：getParameter("X") / getParameterValues("X") / getParameterMap()
    for m in re.finditer(r'getParameter(?:Values|Map)?\s*\(\s*"([^"]{1,80})"', code):
        add(m.group(1), "query", m.group(0), 0.95)
    for m in re.finditer(r"getParameter\s*\(\s*([A-Za-z_][A-Za-z0-9_]{0,60})\s*\)", code):
        add(m.group(1), "query", m.group(0), 0.6)
    if esc and re.search(rf'getParameter\s*\(\s*"{esc}"', code):
        add(esc, "query", f'getParameter("{esc}")', 0.99)

    # ③ cookie：getCookies() + getName().equals("X")
    cookies_block = bool(re.search(r"getCookies\s*\(", code))
    if cookies_block:
        for m in re.finditer(r'getName\s*\(\s*\)\s*\.equals\s*\(\s*"([^"]{1,80})"', code):
            add(m.group(1), "cookie", m.group(0), 0.95)
        # cookie 名来自变量/无字面量时，用「servlet 自己种的 cookie 名」作候选
        for m in re.finditer(r'new\s+[\w.]*Cookie\s*\(\s*"([^"]{1,80})"', code):
            add(m.group(1), "cookie", m.group(0), 0.8)
        # 兜底：没有任何可辨名字时用用例名（Benchmark 的惯例是 cookie 名=用例名）
        if cookies_block and not any(p.location == "cookie" for p in out) and case_name:
            add(case_name, "cookie", "getCookies() + 无字面量名", 0.5)

    # ④ body：getInputStream() / getReader()
    if re.search(r"getInputStream\s*\(|getReader\s*\(", code):
        add("", "body", "getInputStream/getReader", 0.85)

    # ⑤ path：@PathParam 语义无法从 servlet 看出，此处不产出（交由 spec 自己声明）
    return out


def _helper_points(code: str, project_root: Optional[str],
                   case_name: Optional[str], _depth: int = 0) -> List[InjectionPoint]:
    """跟随 helper 类的取源调用，解决「servlet 本文件无显式取源」的错配。"""
    if _depth >= 2 or not project_root or not os.path.isdir(project_root):
        return []
    out: List[InjectionPoint] = []
    # 形如 helpers.SeparateClassRequest.getTheParameter(request, "x")
    for m in re.finditer(r"\b([A-Z]\w{2,60})\.([a-z]\w{2,60})\s*\(", code):
        cls, meth = m.group(1), m.group(2)
        hf = _find_helper_file(project_root, cls)
        if not hf:
            continue
        hcode = _read_code(path=hf)
        if not hcode:
            continue
        sig = re.search(rf"(?:public|protected|static)[^\n=]*\b{re.escape(meth)}\s*\(([^)]{{0,200}})\)",
                        hcode)
        args = m.group(0)
        # helper 方法体里的取源表达式同样计入
        pts = _points_from_code(hcode, case_name)
        for p in pts:
            p2 = InjectionPoint(name=p.name, location=p.location, kind=p.kind,
                                evidence=f"{cls}.{meth} → {p.evidence}",
                                confidence=round(p.confidence * 0.9, 3))
            out.append(p2)
        # 字面量实参（如 getTheParameter(request, "BenchmarkTest00996"）本身就是参数名
        for lit in re.finditer(rf"{re.escape(cls)}\.{re.escape(meth)}\s*\([^)]*?\"([^\"]{{1,80}})\"", args):
            if any(p.location == "query" for p in pts) or not pts:
                out.append(InjectionPoint(name=lit.group(1), location="query",
                                          evidence=f"{cls}.{meth}(\"{lit.group(1)}\")",
                                          confidence=0.85))
        _ = sig
    return out


def _find_helper_file(project_root: str, class_name: str) -> Optional[str]:
    """在 project_root 下按类名找唯一 .java 源码文件（helpers/ 优先）。"""
    hits: List[str] = []
    for base in ("src/main/java", "src", "."):
        root = os.path.join(project_root, base)
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            if os.path.basename(dp) in ("target", "node_modules", ".git"):
                continue
            if class_name + ".java" in fn:
                hits.append(os.path.join(dp, class_name + ".java"))
        if hits:
            break
    return hits[0] if len(hits) == 1 else None


# ---------------------------------------------------------------- 对外接口

def extract_injection_points(
    path: Optional[str] = None,
    code: Optional[str] = None,
    case_name: Optional[str] = None,
    project_root: Optional[str] = None,
) -> List[InjectionPoint]:
    """从 servlet 源码（必要时跟随 helper 类）推导全部候选注入点。

    返回按 (confidence desc, location, name) 排序、去重后的列表；可能为空（无法判定）。
    """
    src = _read_code(path=path, code=code, code_root=project_root)
    if src is None:
        return []
    name = case_name
    if not name and path:
        base = os.path.basename(path)
        name = base[:-5] if base.endswith(".java") else base
    pts = _points_from_code(src, name)
    if not any(p.location in ("query", "header", "cookie") for p in pts):
        pts.extend(_helper_points(src, project_root, name))
    # 去重（同 name+location+kind 取最高置信）
    best: Dict[Tuple[str, str, str], InjectionPoint] = {}
    for p in pts:
        k = (p.name, p.location, p.kind)
        if k not in best or p.confidence > best[k].confidence:
            best[k] = p
    return sorted(best.values(), key=lambda p: (-p.confidence, p.location, p.name))


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_RESOLVE_CACHE: Dict[str, Optional[str]] = {}
_BASENAME_INDEX: Dict[str, Dict[str, str]] = {}
_DISCOVERED_ROOTS: Optional[List[str]] = None


def _basename_index(root: str) -> Dict[str, str]:
    """源码根下 basename → 绝对路径的索引（每个根只 walk 一次，结果缓存）。

    只索引 ``<root>/src/main/java`` 下的 .java，用于解析「裸文件名」形态的
    ``expected_sink_file``（A2 偶发只落文件名，见 resolve_source_path 注释）。
    同 basename 冲突时保留首个（Benchmark 用例类名全局唯一，实际不会冲突）。
    """
    cached = _BASENAME_INDEX.get(root)
    if cached is not None:
        return cached
    idx: Dict[str, str] = {}
    base = os.path.join(root, "src", "main", "java")
    if os.path.isdir(base):
        for dirpath, _dirnames, filenames in os.walk(base):
            for fn in filenames:
                if fn.endswith(".java"):
                    idx.setdefault(fn, os.path.join(dirpath, fn))
    _BASENAME_INDEX[root] = idx
    return idx


def _norm(p: str) -> str:
    return str(p or "").replace("\\", "/").strip()


def _candidate_roots(explicit: Optional[str] = None) -> List[str]:
    """候选代码根（按优先级）：显式 code_root > spec/target 携带 > env > 有界发现。"""
    roots: List[str] = []
    if explicit:
        roots.append(_norm(explicit))
    env = _norm(os.environ.get("SAST_AI_SOURCE_ROOTS") or "")
    if env:
        roots.extend(_norm(x) for x in env.split(os.pathsep) if _norm(x))
    roots.extend(_discover_roots())
    out: List[str] = []
    for r in roots:
        if r and r not in out and os.path.isdir(r):
            out.append(r)
    return out


def _discover_roots() -> List[str]:
    """有界发现「含 src/main/java 的 OWASP 源码根」，结果缓存。

    背景：trigger_specs.expected_sink_file 存的是**相对路径**
    （``src/main/java/org/owasp/benchmark/testcode/X.java``），而真实源码在工作区的
    ``target_path``（workspaces 表，runtime 才知道）。不解析 ⇒ 读不到源码 ⇒
    注入点推导与方法回退全部静默失效（r110 实测：9 个弱证据 TP 无一改善）。
    """
    global _DISCOVERED_ROOTS
    if _DISCOVERED_ROOTS is not None:
        return _DISCOVERED_ROOTS
    found: List[str] = []
    seeds = [
        os.path.join(_REPO_ROOT, "..", "owasp-code", "BenchmarkJava-master"),
        os.path.join(_REPO_ROOT, "data", "samples", "test-project"),
        os.path.join(_REPO_ROOT, "..", "benchmark-sample-200"),
    ]
    # 上级目录里的 OWAMP 源码树（一层，bounded）
    try:
        parent = os.path.dirname(_REPO_ROOT)
        for name in sorted(os.listdir(parent))[:40]:
            d = os.path.join(parent, name)
            if os.path.isdir(d) and os.path.isdir(os.path.join(d, "src", "main", "java")):
                seeds.append(d)
    except Exception:
        pass
    # 本仓 data/workspaces/* 下带源码的工作区（bounded）
    ws = os.path.join(_REPO_ROOT, "data", "workspaces")
    if os.path.isdir(ws):
        try:
            for name in sorted(os.listdir(ws))[:30]:
                d = os.path.join(ws, name)
                if os.path.isdir(os.path.join(d, "src", "main", "java")):
                    seeds.append(d)
        except Exception:
            pass
    for d in seeds:
        nd = os.path.normpath(_norm(d))
        if nd not in found and os.path.isdir(os.path.join(nd, "src", "main", "java")):
            found.append(nd)
    _DISCOVERED_ROOTS = found
    return found


def resolve_source_path(rel_path: Optional[str], code_root: Optional[str] = None) -> Optional[str]:
    """把 spec 的相对/绝对 sink 路径解析成真实可读的源码文件。

    依次尝试：绝对路径原样 → 各候选根下按原样拼接 → 逐级剥掉前导分量再拼
    （与 benchmark_cli._resolve_source_path 同一策略）。命中即缓存。
    """
    raw = _norm(rel_path)
    if not raw:
        return None
    if raw in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[raw]
    hit: Optional[str] = None
    if os.path.isabs(raw) and os.path.isfile(raw):
        hit = raw
    else:
        from pathlib import Path as _Path
        parts = _Path(raw).parts
        for root in _candidate_roots(code_root):
            cands = [os.path.join(root, raw)]
            for i in range(1, len(parts)):
                cands.append(os.path.join(root, _Path(*parts[i:])))
            for cand in cands:
                try:
                    if os.path.isfile(cand):
                        hit = cand
                        break
                except OSError:
                    continue
            if hit:
                break
        # 2026-10-19（r111 weakrand 实证）：A2 有时只落**裸文件名**
        # （expected_sink_file="BenchmarkTest00094.java"，无任何目录分量），
        # 上面的拼接全部落空 ⇒ 静态安全实现判据读不到源码。用一次性
        # basename 索引（每个源码根只 walk 一次，结果缓存）兜底。
        if not hit and "/" not in raw:
            for root in _candidate_roots(code_root):
                hit = _basename_index(root).get(raw)
                if hit:
                    break
    _RESOLVE_CACHE[raw] = hit
    return hit


def project_root_from_source(path: Optional[str]) -> Optional[str]:
    """由 servlet 源码绝对路径反推工程根（含 ``src/main/java`` 的那一级）。

    helper 类查找需要工程根；spec 的 ``expected_sink_file`` 通常是
    ``<root>/src/main/java/org/owasp/benchmark/testcode/BenchmarkTestNNNNN.java``。
    """
    p = str(path or "").replace("\\", "/")
    i = p.find("/src/main/java/")
    return p[:i] if i > 0 else None


def derive_extra_injections(
    spec: Dict[str, Any],
    project_root: Optional[str] = None,
) -> List[Tuple[str, str]]:
    """相对 spec 已声明的注入点，给出**待补投**的 (name, location) 列表。

    只返回 kind == "value" 的点（名注入由 detect_name_source 独占路径）；
    spec 已覆盖的 (name, location) 会被剔除，保证主注入行为不变。
    """
    if not isinstance(spec, dict):
        return []
    code_root = project_root
    src_path = spec.get("expected_sink_file") or spec.get("sink_file") or ""
    for _k in ("code_root", "target_path", "project_root", "source_root", "workspace_root"):
        _v = str(spec.get(_k) or "").strip()
        if _v:
            code_root = code_root or _v
            break
    real_src = resolve_source_path(src_path, code_root)
    if real_src:
        src_path = real_src
    case_name = None
    for key in ("target_endpoint", "expected_sink_file", "sink_file"):
        m = re.search(r"BenchmarkTest\d+", str(spec.get(key) or ""))
        if m:
            case_name = m.group(0)
            break
    pts = extract_injection_points(path=src_path or None, case_name=case_name,
                                   project_root=project_root)
    if not pts:
        return []
    declared = []
    for loc in ("query", "header", "cookie", "body", "multipart", "form", "path"):
        nm = str(spec.get("param_name") or "")
        declared.append((nm, loc))
    have_loc = str(spec.get("param_location") or "").lower()
    if have_loc:
        declared.append((str(spec.get("param_name") or ""), have_loc))
    extra: List[Tuple[str, str]] = []
    for p in pts:
        if p.kind != "value" or p.location not in VALID_LOCATIONS:
            continue
        if (p.name, p.location) in declared:
            continue
        # 同一位置已有 spec 声明时不再补同名点，避免无谓注入
        if any(nm == p.name and p.location in ("query", "header", "cookie") for nm, _ in declared):
            continue
        extra.append((p.name, p.location))
    return extra


# ---------------------------------------------------------------- 方法回退（1.2）

# sink 语义提示：命中即认为该 doXxx 方法体内「可能到达漏洞族 sink」
_SINK_HINTS = (
    "prepareCall", "prepareStatement", "createStatement", ".execute",
    "getSession", "setAttribute", "putValue", ".evaluate", ".compile(",
    "NamingEnumeration", "DirContext", "Runtime", "ProcessBuilder",
    "FileInputStream", "MessageDigest", "Cipher", "Transformer",
)

_DO_METHOD_RE = re.compile(
    r"public\s+void\s+do(Get|Post|Put|Delete|Head|Patch)\s*\([^)]*\)\s*(?:throws[^\{]*)?\{")
_METHOD_ALIAS = {"Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE",
                 "Head": "HEAD", "Patch": "PATCH"}


def method_bodies(code: str) -> Dict[str, str]:
    """剥出 servlet 各 doXxx 方法体（按方法名聚合）。"""
    code = strip_java_comments(code or "")
    out: Dict[str, str] = {}
    for m in _DO_METHOD_RE.finditer(code):
        meth = _METHOD_ALIAS.get(m.group(1), m.group(1).upper())
        i = m.end() - 1
        depth, j = 0, i
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out[meth] = out.get(meth, "") + code[i:j]
    return out


def sink_bearing_methods(code: str) -> List[str]:
    """源码里「方法体含 sink 语义」的 doXxx 列表。"""
    return [m for m, body in method_bodies(code).items()
            if any(h in body for h in _SINK_HINTS)]


def derive_method_augmentations(spec: Dict[str, Any],
                                project_root: Optional[str] = None,
                                code: Optional[str] = None) -> List[str]:
    """spec 声明的 http_method 不含 sink，而另一个 doXxx 含 sink → 返回应补投的方法。

    r109 逐案取证：**395 条 spec（21.5%）属方法错配** —— 典型如 BenchmarkTest00996
    把读 cookie + prepareCall 全放在 doPost，而 spec 记 GET；D1 只发 GET → servlet 只种
    cookie 就转发，sink 永不执行，表现为 S2（到应用未到族 sink）。该类用例占 9 个
    「弱证据 TP」的全部。

    只返回**源码能证明 sink 所在**的方法，避免无依据地换方法（幂等/副作用风险）。
    """
    if not isinstance(spec, dict):
        return []
    code_root = project_root
    src_path = spec.get("expected_sink_file") or spec.get("sink_file") or ""
    for _k in ("code_root", "target_path", "project_root", "source_root", "workspace_root"):
        _v = str(spec.get(_k) or "").strip()
        if _v:
            code_root = code_root or _v
            break
    if code is None:
        code = _read_code(path=src_path or None, code_root=code_root)
    if not code:
        return []
    declared = str(spec.get("http_method") or "GET").strip().upper() or "GET"
    sm = sink_bearing_methods(code)
    if not sm or declared in sm:
        return []
    return [m for m in sm if m != declared]
