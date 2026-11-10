import ast
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

import yaml

from src.infrastructure.repositories import EntryAssetRepository

_RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "entrypoint_rules.yaml"

# Builtin fallback used when the yaml config is missing/unreadable. Mirrors the
# historical inline regex list so behaviour is identical without the file.
_DEFAULT_RULES: List[Dict[str, Any]] = [
    {"entry_type": "web_route", "pattern": r"@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(([^)]*)\)", "confidence": "high"},
    {"entry_type": "web_route", "pattern": r"@(app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)", "confidence": "high"},
    {"entry_type": "web_route", "pattern": r"@(app)\.(route)\s*\(\s*['\"]([^'\"]+)", "confidence": "high"},
    {"entry_type": "mq_consumer", "pattern": r"@(KafkaListener|RabbitListener|JmsListener)\s*\(([^)]*)\)", "confidence": "high"},
    {"entry_type": "scheduled_job", "pattern": r"@(Scheduled|Cron)\s*\(([^)]*)\)", "confidence": "medium"},
    {"entry_type": "mcp_tool", "pattern": r"@(Tool|McpTool)|registerTool\s*\(", "confidence": "medium"},
    {"entry_type": "rpc_method", "pattern": r"@(GrpcService|DubboService|FeignClient|RpcService)\b", "confidence": "medium"},
]

# HTTP verb attribute names that indicate a route decorator on any object
# (``@app.route`` but also ``@bp.route``, ``@blueprint.get`` etc).
_AST_ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch", "options", "head"}
_AST_ROUTE_CALLS = {"add_url_rule", "add_route", "register_rest_route"}


def _load_rules(path: Path = _RULES_PATH) -> List[Dict[str, Any]]:
    if not path.exists():
        return list(_DEFAULT_RULES)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return list(_DEFAULT_RULES)
    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list) or not rules:
        return list(_DEFAULT_RULES)
    return rules


class EntryDiscoveryService:
    def __init__(
        self,
        entry_repository: Optional[EntryAssetRepository] = None,
        *,
        rules_path: Optional[str] = None,
    ):
        self.entry_repository = entry_repository
        rules = _load_rules(Path(rules_path)) if rules_path else _load_rules()
        self._compiled: List[Tuple[str, Pattern[str], str]] = []
        for rule in rules:
            entry_type = str(rule.get("entry_type") or "").strip()
            pattern = rule.get("pattern")
            if not entry_type or not pattern:
                continue
            flags = 0 if "i" not in {f.lower() for f in (rule.get("flags") or ["i"])} else re.I
            try:
                compiled = re.compile(pattern, flags)
            except re.error:
                continue
            confidence = str(rule.get("confidence") or "medium").strip() or "medium"
            self._compiled.append((entry_type, compiled, confidence))

    def discover(self, project_path: str, framework: str = "") -> Dict[str, Any]:
        """发现入口点。framework 由 R0 技术栈识别提供（§8.4 第2点框架特化），
        非空时在结果中回带，供 A0 编排与下游做框架感知决策。"""
        root = Path(project_path)
        entries: List[Dict[str, Any]] = []
        if not root.exists():
            return {"status": "error", "message": f"Path does not exist: {project_path}", "entries": []}
        for path in root.rglob("*"):
            # §7（2026-09-24）：.codeql-db 内含 CodeQL 建库复制的源码副本，会把同一 servlet
            # 路由登记两遍（实测 208→416）。对 D2 无正确性影响但污染入口计数，与
            # file_inventory.DEFAULT_SKIP_PREFIXES 同口径排除。
            #
            # 2026-11-04：改为**前缀匹配** `.codeql-db*`。jsc 源码根下曾残留 5 个半成品库
            # （`.codeql-db.partial2..5`），精确匹配排不掉 → 同一份源码被登记 5 遍，
            # 入口数从 780 膨胀到数千。
            if not path.is_file() or any(
                part in {".git", "node_modules", "target", "__pycache__", ".venv", ".codeqldb"}
                or part.startswith(".codeql-db")
                for part in path.parts
            ):
                continue
            if path.suffix.lower() not in {".java", ".py", ".js", ".ts", ".tsx", ".jsx"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            file_entries = self._discover_file(rel, content)
            if path.suffix.lower() == ".py":
                file_entries.extend(self._discover_python_ast(rel, content, file_entries))
            for e in file_entries:
                if e.get("entry_type") == "web_route":
                    params = self._extract_request_params(rel, content, e)
                    e["request_params"] = params
                    e.setdefault("metadata", {})["request_params"] = params
            entries.extend(file_entries)
        return {
            "status": "completed",
            "entry_count": len(entries),
            "entries": entries,
            "rule_candidates": self._rule_candidates(entries),
            "framework": framework,  # §8.4 框架特化上下文
        }


    def discover_and_persist(
        self, project_path: str, workspace_id: Optional[int] = None, task_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Discover entries and persist them (and rule candidates) as durable assets."""
        result = self.discover(project_path)
        if result.get("status") != "completed" or self.entry_repository is None:
            return result
        persisted_entries = [
            self.entry_repository.upsert_entry(workspace_id, task_id, entry)
            for entry in result["entries"]
        ]
        persisted_rules = [
            self.entry_repository.upsert_rule_candidate(workspace_id, candidate)
            for candidate in result["rule_candidates"]
        ]
        result["persisted_entry_count"] = len(persisted_entries)
        result["persisted_rule_count"] = len(persisted_rules)
        return result

    @staticmethod
    def _entry_hash(entry_type: str, rel: str, signature: str) -> str:
        payload = f"{entry_type}|{rel}|{signature}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:24]

    @staticmethod
    def _rule_hash(entry_type: str, signature: str) -> str:
        payload = f"{entry_type}|{signature}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:24]

    @staticmethod
    def _class_request_mapping_bases(lines: List[str]) -> Dict[int, str]:
        """收集类级 ``@RequestMapping`` 前缀路径：class_decl_line(1-based) -> base_path。

        Spring 控制器常把公共前缀写在类级 ``@RequestMapping("/api/admin")`` 上，方法级
        ``@GetMapping("/users")`` 只写相对路径。若只识别方法级路径，discovered_routes 里
        就只有 ``/users`` 而缺 ``/api/admin/users``，导致 /admin/users 这类管理端点永远
        进不了 discovered_routes（task7 实测：entry_discovery 根本没发现 /admin/users），进而
        A2 幻觉端点无法被 ground truth 纠正、BOLA/垂直越权的类级前缀路由整条丢失。
        """
        bases: Dict[int, str] = {}
        for i, ln in enumerate(lines, start=1):
            if "@RequestMapping" not in ln:
                continue
            window = "\n".join(lines[i - 1: min(i + 6, len(lines))])
            pm = re.search(r'["\']([^"\']+)["\']', window)
            if not pm:
                continue
            bp = pm.group(1).strip()
            cm = re.search(r'\bclass\s+(\w+)', window)
            if not cm:
                continue
            cname = cm.group(1)
            for j in range(i - 1, min(i + 6, len(lines))):
                if re.search(r'\bclass\s+' + re.escape(cname) + r'\b', lines[j]):
                    bases[j + 1] = bp  # 1-based class decl line
                    break
        return bases

    @staticmethod
    def _prefix_route(base: str, route: str) -> str:
        base = (base or "").strip().rstrip("/")
        route = (route or "").strip()
        if not base:
            return route
        if not route:
            return base
        if route.startswith(base):
            return route
        if route.startswith("/"):
            return base + route
        return base + "/" + route

    @staticmethod
    def _rewrite_signature_prefix(signature: str, combined: str) -> str:
        """把映射注解里的首个引号路径替换为拼接后的完整路径（保留其余内容）。"""
        return re.sub(r'(["\'])([^"\']*)(["\'])',
                      lambda m: m.group(1) + combined + m.group(3), signature, count=1)

    def _discover_file(self, rel: str, content: str) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        lines = content.splitlines()
        bases = self._class_request_mapping_bases(lines)
        _base_paths = set(bases.values())
        # （2026-09-20）：识别 @ControllerAdvice / @RestControllerAdvice 类。这类 advice 类
        # （如 JSONP 的 Object2Jsonp）本身不含真实业务路由，只是对控制器响应的统一包装
        # （beforeBodyWrite）。其内若恰有 @GetMapping 等注解，照常登记为 web_route，但打标
        # is_controller_advice=True，供下游（trigger_spec_registry 的 JSONP 重归因）把它识别为
        # 「辅助上下文」而非漏洞真实归属文件——真实 HTTP 端点须回到对应 controller。
        _is_advice = bool(re.search(r"@(Rest)?ControllerAdvice\b", content))
        for idx, line in enumerate(lines, start=1):
            for entry_type, pattern, confidence in self._compiled:
                match = pattern.search(line)
                if not match:
                    continue
                signature = line.strip()[:220]
                # ① 类级前缀拼接：把类级 @RequestMapping 前缀补到方法级相对路径前，
                # 使 discovered_routes 携带完整 HTTP 路由（/api/admin/users 而非 /users）。
                is_class_level = False
                if entry_type == "web_route":
                    route_m = re.search(r'["\']([^"\']+)["\']', signature)
                    if route_m:
                        # 类级 @RequestMapping 会被误当完整端点登记（仅作 base path，
                        # 自身不可调用）。若其路径等于某控制器类级 base path 且紧邻类声明，
                        # 标记为类级，在路由索引层剔除，避免被当作真实端点回写/重放。
                        if route_m.group(1) in _base_paths and re.search(
                            r"\b(class|interface|enum)\b",
                            "\n".join(lines[max(0, idx - 2): idx + 2]),
                        ):
                            is_class_level = True
                        base = ""
                        for cl in sorted(bases.keys()):
                            if cl == idx:
                                continue  # 跳过类自身的 @RequestMapping，避免自我拼接
                            if cl <= idx and bases[cl]:
                                base = bases[cl]
                            elif cl > idx:
                                break
                        if base:
                            combined = self._prefix_route(base, route_m.group(1))
                            if combined != route_m.group(1):
                                signature = self._rewrite_signature_prefix(signature, combined)
                entry: Dict[str, Any] = {
                    "entry_type": entry_type,
                    "file": rel,
                    "line": idx,
                    "signature": signature,
                    "confidence": confidence,
                    "source": "regex-entry-discovery",
                    "entry_hash": self._entry_hash(entry_type, rel, signature),
                }
                if _is_advice:
                    # advice 类的路由是「辅助上下文」，标记后下游可据此把漏洞归属回真实 controller。
                    entry["is_controller_advice"] = True
                    entry.setdefault("metadata", {})["is_controller_advice"] = True
                if is_class_level:
                    entry["is_class_level"] = True
                    entry.setdefault("metadata", {})["is_class_level"] = True
                entries.append(entry)
        return entries

    def _discover_python_ast(
        self, rel: str, content: str, existing: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """AST-based Python route discovery.

        Catches route registrations the line-regex misses: blueprint decorators
        (``@bp.route`` / ``@blueprint.get``), and imperative registration such as
        ``app.add_url_rule(...)``. AST evidence is high-confidence.
        """
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        seen_lines = {(e.get("entry_type"), e.get("line")) for e in existing}
        found: List[Dict[str, Any]] = []

        def _add(entry_type: str, lineno: int, signature: str) -> None:
            key = (entry_type, lineno)
            if key in seen_lines:
                return
            seen_lines.add(key)
            sig = signature.strip()[:220]
            found.append({
                "entry_type": entry_type,
                "file": rel,
                "line": lineno,
                "signature": sig,
                "confidence": "high",
                "source": "ast-entry-discovery",
                "entry_hash": self._entry_hash(entry_type, rel, sig),
            })

        for node in ast.walk(tree):
            # Decorator routes: @<obj>.route / @<obj>.get / ... on any object.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for deco in node.decorator_list:
                    call = deco if isinstance(deco, ast.Call) else None
                    target = call.func if call else deco
                    if isinstance(target, ast.Attribute) and target.attr.lower() in _AST_ROUTE_ATTRS:
                        _add("web_route", getattr(deco, "lineno", node.lineno), self._unparse(deco))
            # Imperative registration: app.add_url_rule('/x', ...), register_rest_route(...).
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Attribute):
                    name = func.attr
                elif isinstance(func, ast.Name):
                    name = func.id
                if name in _AST_ROUTE_CALLS:
                    _add("web_route", node.lineno, self._unparse(node))
        return found

    @staticmethod
    def _entry_window(content: str, line: int, before: int = 1, after: int = 40) -> str:
        lines = content.splitlines()
        start = max(0, line - 1 - before)
        end = min(len(lines), line - 1 + after)
        return "\n".join(lines[start:end])

    def _extract_request_params(self, rel: str, content: str, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """§7.13/§3.8 入口参数采集：为 web_route 产出 representative_request_params
        （param_name + param_location + content_type），供 4.7.2 multi-match 全参数带标一次回放。
        覆盖 Flask/Spring 路径参数与方法参数注解（@PathVariable/@RequestParam/@RequestBody）。"""
        if entry.get("entry_type") != "web_route":
            return []
        sig = entry.get("signature", "")
        window = self._entry_window(content, int(entry.get("line") or 1))
        params: List[Dict[str, Any]] = []
        seen = set()

        def add(name: str, location: str, content_type: str = "") -> None:
            name = (name or "").strip().strip("\"'")
            if not name or name in seen:
                return
            seen.add(name)
            params.append({"param_name": name, "param_location": location, "content_type": content_type})

        # 路径参数：Flask <conv:name> / <name>，Spring {name}
        for m in re.finditer(r"<(?:[a-zA-Z_]+:)?([a-zA-Z_][a-zA-Z0-9_]*)>", sig):
            add(m.group(1), "path")
        for m in re.finditer(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", sig):
            add(m.group(1), "path")
        # Java 注解：@PathVariable / @RequestParam / @RequestHeader / @CookieValue（接受单/双引号）
        for m in re.finditer(r"@(PathVariable|RequestParam|RequestHeader|CookieValue)\s*(?:\(\s*(?:[\"']([^\"']+)[\"']|value\s*=\s*[\"']([^\"']+)[\"']|name\s*=\s*[\"']([^\"']+)[\"'])\s*\))?", window):
            anno = m.group(1)
            name = m.group(2) or m.group(3) or m.group(4)
            if "PathVariable" in anno:
                loc = "path"
            elif "Header" in anno:
                loc = "header"
            elif "Cookie" in anno:
                loc = "cookie"
            else:
                loc = "query"
            if name:
                add(name, loc)
        # Spring consumes → content_type（仅标注，不新增参数）
        m_cons = re.search(r'consumes\s*=\s*\{?\s*"([^"]+)"', window)
        consumes = m_cons.group(1) if m_cons else ""
        if "@RequestBody" in window:
            # 标记最近的 @RequestParam/@PathVariable 之外，body 参数通常无显式名；
            # 退化为一个 body 占位参数，供 multi-match 仍可带标。
            add("_body", "body", consumes or "application/json")
        if rel.endswith(".py"):
            mdef = re.search(r"def\s+\w+\s*\((.*?)\)\s*:", window)
            if mdef:
                for raw in mdef.group(1).split(","):
                    a = raw.strip().split(":")[0].split("=")[0].strip()
                    if a and a not in ("self", "cls", "request", "*args", "**kwargs"):
                        add(a, "query")
            for m in re.finditer(r"request\.(?:args|form|values)\.get\(\s*['\"]([^'\"]+)['\"]", window):
                add(m.group(1), "query")
        return params

    @staticmethod
    def _unparse(node: ast.AST) -> str:
        try:
            return ast.unparse(node)  # type: ignore[attr-defined]
        except Exception:
            return getattr(node, "attr", "") or type(node).__name__

    def _rule_candidates(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        candidates = []
        for entry in entries:
            key = (entry.get("entry_type"), entry.get("signature"))
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "entry_type": entry.get("entry_type"),
                "pattern": entry.get("signature"),
                "status": "candidate",
                "confidence": entry.get("confidence", "medium"),
                "rule_hash": self._rule_hash(str(entry.get("entry_type")), str(entry.get("signature"))),
            })
        return candidates[:100]
