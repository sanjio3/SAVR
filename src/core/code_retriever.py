"""A2 符号检索增强（RAG）retriever。

在 plan_pocs 的 LLM 调用之前，为单个漏洞取出跨文件代码切片（调用方文件、
带类级 @RequestMapping 的 controller 文件、sink 定义文件），注入 prompt，
使 LLM 对动态/反射/SAST 断链点也能正确推断路由与 poc_chain。

设计原则：
- 仅读取（只读文件系统 + code_index），不修改任何数据。
- 任何异常都降级为空串，绝不阻断 plan_pocs 主链路。
- 切片总长度受 max_chars 限制，避免撑爆 prompt。
- 受 ``a2_analyzer.config.enable_rag``（默认 true）+ 环境变量
  ``SASTAI_A2_ENABLE_RAG`` 控制；``code_root`` 缺失时直接返回空。
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 常见 sink 关键词 → 检索词（用于在代码库里定位 sink 定义/调用点）。
_SINK_KEYWORDS: Dict[str, List[str]] = {
    "command-execution": ["Runtime.getRuntime().exec", "ProcessBuilder", "getRuntime().exec", ".exec("],
    "sql-injection": ["createQuery", "executeQuery", "Statement.execute", "JdbcTemplate", "createNativeQuery"],
    "template-injection": ["SpelExpressionParser", "getValue(", "TemplateEngine.process", "FreeMarker", "Velocity"],
    "deserialization": ["readObject", "ObjectInputStream", "SerializationUtils", "fromXML"],
    "path-traversal": ["new File(", "FileInputStream", "Paths.get(", "getCanonicalPath"],
    "ssrf": ["new URL(", "HttpClient", "RestTemplate", "OkHttpClient", "HttpURLConnection"],
    "xss": ["getWriter().print", "response.getWriter", "ModelAndView.addObject"],
    "xxe": ["DocumentBuilder", "SAXParser", "XMLInputFactory", "TransformerFactory"],
}


def rag_enabled() -> bool:
    """RAG 开关：环境变量优先，回退 agent_skills.yaml 的 a2_analyzer.config.enable_rag（默认 true）。"""
    env = os.environ.get("SASTAI_A2_ENABLE_RAG")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "on")
    try:
        import yaml

        p = Path(__file__).resolve().parent.parent / "config" / "agent_skills.yaml"
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return bool(((data.get("a2_analyzer", {}) or {}).get("config", {}) or {}).get("enable_rag", True))
    except Exception:
        pass
    return True


def _vuln_route(vuln: Any) -> str:
    """从 vuln 的 exploit_spec.entry / entry_point 抽取已解析/假说的 route。"""
    try:
        spec = getattr(vuln, "exploit_spec", None) or {}
        if isinstance(spec, dict):
            entry = spec.get("entry") or {}
            r = entry.get("route") or entry.get("trigger_route")
            if r:
                return str(r).strip()
        ep = str(getattr(vuln, "entry_point", "") or "")
        m = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", ep)
        if m:
            return m.group(2).strip()
    except Exception:
        pass
    return ""


def _vuln_sink_keywords(vuln: Any) -> List[str]:
    vtype = str(getattr(vuln, "type", "") or "").lower()
    fam = ""
    try:
        spec = getattr(vuln, "exploit_spec", None) or {}
        fam = str((spec.get("payload") or {}).get("payload_family", "") or "").lower()
    except Exception:
        pass
    kws: List[str] = []
    for key, words in _SINK_KEYWORDS.items():
        if key in vtype or key in fam:
            kws.extend(words)
    for token in re.findall(r"[A-Za-z][A-Za-z.]+", vtype):
        if token.lower() in ("exec", "spel", "ognl", "readobject"):
            kws.append(token)
    seen = set()
    out = []
    for w in kws:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def _resolve_caller_files(code_root: str, vuln: Any) -> List[str]:
    """从 vuln.callers 解析出候选源文件路径（相对 code_root 或 glob 模式）。"""
    callers = getattr(vuln, "callers", None)
    if isinstance(callers, str):
        callers = [callers]
    if not isinstance(callers, (list, tuple)):
        return []
    files: List[str] = []
    for c in callers[:5]:
        c = str(c or "").strip()
        if not c:
            continue
        if ".java" in c or ".kt" in c or ".py" in c or ".go" in c:
            files.append(c.split(":")[0])
            continue
        cls = re.sub(r"\(.*?\)", "", c).split(".")[-2] if "." in c else c
        if cls:
            for ext in (".java", ".kt", ".py"):
                files.append(f"**/{cls}{ext}")
    return list(dict.fromkeys(files))


def _read_window(path: Path, around_line: int = 0, before: int = 25, after: int = 35) -> Optional[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return None
    if not lines:
        return None
    if around_line and 1 <= around_line <= len(lines):
        lo = max(0, around_line - before)
        hi = min(len(lines), around_line + after)
        window = lines[lo:hi]
        header = f"# {path.name} (lines {lo+1}-{hi})"
        return header + "\n" + "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(window))
    window = lines[:80]
    return f"# {path.name} (head)\n" + "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(window))


def _find_controller_file(code_root: str, route: str, code_index: Optional[Dict] = None) -> Optional[Path]:
    """定位声明了该 route 的 controller 源文件。优先用 code_index，回退文件系统 grep。"""
    route_norm = route.strip().lstrip("/")
    if not route_norm:
        return None
    if code_index:
        try:
            funcs = code_index.get("functions") or {}
            for fv in funcs.values():
                fv = fv if isinstance(fv, dict) else {}
                if fv.get("http_entry") and route_norm in str(fv.get("route") or fv.get("http_path") or ""):
                    fp = fv.get("file")
                    if fp:
                        cand = Path(code_root) / fp
                        if cand.exists():
                            return cand
        except Exception:
            pass
    try:
        root = Path(code_root)
        pat = re.compile(re.escape(route_norm))
        for p in root.rglob("*.java"):
            try:
                if pat.search(p.read_text(encoding="utf-8", errors="ignore")):
                    return p
            except Exception:
                continue
    except Exception:
        pass
    return None


def _grep_sink_file(code_root: str, keywords: List[str]) -> Optional[Path]:
    if not keywords:
        return None
    try:
        root = Path(code_root)
        best: Optional[Path] = None
        best_score = 0
        for p in root.rglob("*.java"):
            if "test" in str(p).lower():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            score = sum(text.count(k) for k in keywords)
            if score > best_score:
                best_score = score
                best = p
        if best_score > 0:
            return best
    except Exception:
        pass
    return None


def retrieve_rag_context(
    vuln: Any,
    code_root: Optional[str],
    code_index: Optional[Dict] = None,
    max_chars: int = 5500,
) -> str:
    """为单漏洞检索跨文件代码切片（RAG）。失败返回空串（不阻断主链路）。"""
    if not code_root or not rag_enabled():
        return ""
    try:
        root = Path(code_root)
        if not root.exists():
            return ""
        chunks: List[str] = []
        seen_files: set = set()

        def _add(path: Optional[Path], around: int = 0) -> None:
            if not path or not path.exists():
                return
            key = str(path)
            if key in seen_files:
                return
            seen_files.add(key)
            w = _read_window(path, around)
            if w:
                chunks.append(w)

        # 1) 漏洞所在文件（sink 文件）窗口
        vf = getattr(vuln, "file", "") or ""
        if vf:
            cvf = root / vf
            if not cvf.exists():
                cvf = root / vf.replace("\\", "/")
            try:
                ln = int(getattr(vuln, "line", 0) or 0)
            except Exception:
                ln = 0
            _add(cvf, ln)

        # 2) controller 文件（含 route 声明）
        route = _vuln_route(vuln)
        if route:
            _add(_find_controller_file(code_root, route, code_index))

        # 3) caller 文件
        for cf_rel in _resolve_caller_files(code_root, vuln):
            if cf_rel.startswith("**/"):
                try:
                    for p in root.glob(cf_rel):
                        _add(p)
                        break
                except Exception:
                    pass
            else:
                cp = root / cf_rel
                if not cp.exists():
                    cp = root / cf_rel.replace("\\", "/")
                _add(cp)

        # 4) sink 定义文件
        _add(_grep_sink_file(code_root, _vuln_sink_keywords(vuln)))

        out = "\n\n".join(chunks)
        if len(out) > max_chars:
            out = out[:max_chars] + "\n...[RAG context truncated]"
        return out
    except Exception as _e:  # RAG 是增强项，任何异常都不应阻断 plan_pocs
        logger.debug("[code_retriever] RAG 检索失败（降级为空）：%s", _e)
        return ""
