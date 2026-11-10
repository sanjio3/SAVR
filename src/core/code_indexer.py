"""
Lightweight code indexer used by preprocessing and cross-file reachability checks.
"""

import json
import logging
import os
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    name: str
    file: str
    line: int
    return_type: str = ""
    parameters: str = ""
    # 结构化形参（2026-11-02）：`[{"annotations": [...], "type": "MultipartFile", "name": "file"}]`。
    # 为什么要它：`parameters` 是给人看的字符串，下游要判断「这个参数是文件、是字节流、
    # 还是普通字符串」才能决定**编码方式**（multipart / 二进制 / json / query）。
    # 只靠名字猜不出来（`file` 可能是 String，`data` 可能是 MultipartFile），必须看类型。
    params_typed: List[Dict] = field(default_factory=list)
    is_static: bool = False
    is_public: bool = False
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    http_entry: Optional[str] = None


@dataclass
class ClassInfo:
    name: str
    file: str
    line: int
    methods: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)


class CodeIndexer:
    def __init__(self):
        self.functions: Dict[str, FunctionInfo] = {}
        self.classes: Dict[str, ClassInfo] = {}
        self.files: Dict[str, Dict] = {}
        self._file_contents: Dict[str, str] = {}
        self._current_file = ""
        self._current_class = ""

    def index_project(self, files: List[Dict]) -> Dict:
        logger.info("Indexing %s files...", len(files))
        for file_info in files:
            rel_path = file_info.get("rel_path", "")
            content = file_info.get("content", "")
            language = file_info.get("language", "java")
            if not content:
                continue
            self._index_file(rel_path, content, language)

        self._build_call_relations()
        result = {
            "functions": {key: asdict(value) for key, value in self.functions.items()},
            "classes": {key: asdict(value) for key, value in self.classes.items()},
            "files": self.files,
            "stats": {
                "total_functions": len(self.functions),
                "total_classes": len(self.classes),
                "total_files": len(self.files),
                "http_entries": sum(1 for item in self.functions.values() if item.http_entry),
            },
        }
        logger.info(
            "Indexed: %s functions, %s classes, %s HTTP entries",
            result["stats"]["total_functions"],
            result["stats"]["total_classes"],
            result["stats"]["http_entries"],
        )
        return result

    def _index_file(self, rel_path: str, content: str, language: str):
        self._current_file = rel_path
        self._file_contents[rel_path] = content
        self.files[rel_path] = {"language": language, "functions": [], "classes": []}
        lines = content.split("\n")
        if language in {"java", "kotlin", "scala"}:
            self._index_java_file(lines)
        elif language == "python":
            self._index_python_file(lines)
        elif language in {"javascript", "typescript"}:
            self._index_js_file(lines)
        elif language == "php":
            self._index_php_file(lines)

    @staticmethod
    def _extract_java_mapping_path(annotation_line: str) -> str:
        line = str(annotation_line or "")
        for pattern in (
            r"@\w+Mapping\s*\(\s*(?:value|path)\s*=\s*\{\s*\"([^\"]+)\"",
            r"@\w+Mapping\s*\(\s*(?:value|path)\s*=\s*\"([^\"]+)\"",
            r"@\w+Mapping\s*\(\s*\{\s*\"([^\"]+)\"",
            r"@\w+Mapping\s*\(\s*\"([^\"]+)\"",
        ):
            match = re.search(pattern, line, re.I)
            if match:
                return str(match.group(1) or "").strip()
        return ""

    @staticmethod
    def _extract_java_mapping_method(annotation_line: str) -> str:
        line = str(annotation_line or "")
        direct = re.search(r"@(Get|Post|Put|Delete|Patch)Mapping", line, re.I)
        if direct:
            return str(direct.group(1) or "").upper()
        request = re.search(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH)", line, re.I)
        if request:
            return str(request.group(1) or "").upper()
        return "GET" if "@RequestMapping" in line else ""

    # Servlet 入口方法 → HTTP 方法（service 同时处理 GET/POST，此处记 GET 供展示/可达性判断）
    _SERVLET_ENTRY_METHODS = {
        "service": "GET",
        "doGet": "GET",
        "doPost": "POST",
        "doPut": "PUT",
        "doDelete": "DELETE",
    }

    @staticmethod
    def _extract_servlet_route(annotation_line: str) -> str:
        """从 @WebServlet 注解提取路由。

        覆盖形态（OWASP Benchmark 全量 205 类实测为 value= 单值）：
        @WebServlet("/x") / @WebServlet(value = "/x") / @WebServlet(urlPatterns = "/x")
        以及 value/urlPatterns 数组 { "/a", "/b" } 取第一个。
        """
        line = str(annotation_line or "")
        if "@WebServlet" not in line:
            return ""
        for key in ("urlPatterns", "value"):
            m = re.search(key + r"\s*=\s*\{?\s*\"([^\"]+)\"", line)
            if m:
                return str(m.group(1) or "").strip()
        m = re.search(r'@WebServlet\s*\(\s*"([^"]+)"\s*\)', line)
        if m:
            return str(m.group(1) or "").strip()
        return ""

    @staticmethod
    def _extract_filter_route(annotation_line: str) -> str:
        """从 @WebFilter 注解提取路由（形态同 @WebServlet：urlPatterns/value/裸串/数组）。"""
        line = str(annotation_line or "")
        if "@WebFilter" not in line:
            return ""
        for key in ("urlPatterns", "value"):
            m = re.search(key + r"\s*=\s*\{?\s*\"([^\"]+)\"", line)
            if m:
                return str(m.group(1) or "").strip()
        m = re.search(r'@WebFilter\s*\(\s*"([^"]+)"\s*\)', line)
        if m:
            return str(m.group(1) or "").strip()
        return ""

    @staticmethod
    def _join_routes(base_route: str, method_route: str) -> str:
        base = str(base_route or "").strip().strip("/")
        sub = str(method_route or "").strip().strip("/")
        if base and sub:
            return f"/{base}/{sub}"
        if base:
            return f"/{base}"
        if sub:
            return f"/{sub}"
        return ""

    @staticmethod
    def _balanced_params(text: str, open_idx: int) -> str:
        """从 `(` 起做括号配平，返回形参原文（不含两端括号）；配不平返回空串。"""
        if open_idx < 0 or open_idx >= len(text) or text[open_idx] != "(":
            return ""
        depth = 0
        for i in range(open_idx, len(text)):
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[open_idx + 1:i]
        return ""

    @staticmethod
    def _split_top_level(params: str) -> List[str]:
        """按顶层逗号切形参（保护 `<>`、`[]`、`()` 内的逗号）。"""
        out: List[str] = []
        depth = 0
        cur: List[str] = []
        for ch in params or "":
            if ch in "(<[{":
                depth += 1
            elif ch in ")>]}":
                depth -= 1
            if ch == "," and depth == 0:
                out.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        if cur:
            out.append("".join(cur))
        return [p.strip() for p in out if p.strip()]

    @classmethod
    def _parse_typed_params(cls, params: str) -> List[Dict]:
        """形参原文 → `[{"annotations": [...], "type": "...", "name": "..."}]`。

        下游靠 `type` 决定**编码方式**：`MultipartFile` 必须 multipart、
        `byte[]` 必须二进制体、`String` 走 query/form。名字猜不出来（`file` 也可能是 String）。
        """
        result: List[Dict] = []
        ann_re = r"@[\w.]+(?:\s*\([^)]*\))?"
        for part in cls._split_top_level(params or ""):
            anns = re.findall(ann_re, part)
            rest = re.sub(ann_re, " ", part)
            rest = re.sub(r"\bfinal\b", " ", rest).strip()
            toks = [t for t in rest.replace("...", "[]").split() if t]
            if not toks:
                continue
            if len(toks) == 1:
                typ, name = toks[0], ""
            else:
                typ, name = toks[-2], toks[-1]
            result.append({"annotations": anns, "type": typ, "name": name})
        return result

    def _index_java_file(self, lines: List[str]):
        # 2026-11-02：**锚定行首**。原正则 `(public\s+)?class\s+(\w+)` 用 search 匹配，
        # 注释里出现 "Check deserialize class using black list" 就会被当成类声明
        # （class=using）⇒ current_class 被改写、类级注解标志被清掉 ⇒ 后续方法全丢入口。
        # 实测 Deserialize.java 因此掉了 2 个入口。锚定 + 允许前置修饰符才可靠。
        class_pattern = re.compile(
            r"^\s*(?:(?:public|protected|private|abstract|final|static)\s+)*class\s+(\w+)")
        method_pattern = re.compile(
            r"(public|private|protected)\s+(static\s+)?([\w<>\[\],?]+)\s+(\w+)\s*\(([^)]*)\)"
        )
        pending_annotations: List[str] = []
        current_class = ""
        class_base_route = ""
        current_class_is_servlet = False
        # 2026-11-02：类级注解决定「这个类到底有没有 HTTP 入口」。
        # 此前 http_entry 只判 `http_route and visibility=='public'`，于是任何类里带
        # @RequestMapping 的方法都被当成入口 —— 实测 `ClassDataLoader` 类上没有 @Controller，
        # Spring 从不注册该路由，D1 打过去 404/115B，白打一条。
        current_class_is_controller = False
        # 2026-11-02：`@WebFilter` + `doFilter` 是**真实的 HTTP 入口**（每个匹配请求都过它），
        # 但此前完全没建模 ⇒ 过滤器里的 sink 拿不到入口、param 推断恒失败
        # （实测 `@WebFilter(urlPatterns="/x")` 的 `doFilter` 里 `request.getHeader("Origin")`
        # 能确定性推断出 Origin，却因「所在方法不是入口」被丢弃）。
        current_class_is_filter = False

        for index, line in enumerate(lines):
            line_num = index + 1
            stripped = line.strip()
            if (not stripped or stripped.startswith("//") or stripped.startswith("/*")
                    or stripped.startswith("*")):
                continue
            if stripped.startswith("@"):
                pending_annotations.append(stripped)
                continue

            class_match = class_pattern.search(line)
            if class_match:
                current_class = class_match.group(1)
                self._current_class = current_class
                current_class_is_servlet = False
                current_class_is_controller = False
                current_class_is_filter = False
                class_info = ClassInfo(name=current_class, file=self._current_file, line=line_num)
                class_base_route = ""
                if any(annotation.startswith("@RestController") or annotation.startswith("@Controller") for annotation in pending_annotations):
                    class_info.annotations.append("controller")
                    current_class_is_controller = True
                for annotation in pending_annotations:
                    if "@RequestMapping" in annotation:
                        class_base_route = self._extract_java_mapping_path(annotation)
                    if "@WebServlet" in annotation:
                        # P0-1（2026-09-25）：把 benchmark 评分侧的 Servlet 入口解析接入通用
                        # 入口发现——此前 code_indexer 只认 Spring 注解，纯 Servlet 工程
                        # （OWASP Benchmark 205 个 @WebServlet 类）索引出 0 个 HTTP 入口，
                        # 导致下游 entry_candidates 空、252/253 候选 no_trigger_spec。
                        class_info.annotations.append("servlet")
                        servlet_route = self._extract_servlet_route(annotation)
                        if servlet_route:
                            class_base_route = servlet_route
                            current_class_is_servlet = True
                    if "@WebFilter" in annotation:
                        filter_route = self._extract_filter_route(annotation)
                        # 只认**具体路由**：`@WebFilter("/*")` 这类通配符路由不是可重放的
                        # 端点（拿 `/*` 去发请求没有意义），保持「不入入口」的历史口径。
                        if filter_route and "*" not in filter_route:
                            class_info.annotations.append("filter")
                            class_base_route = filter_route
                            current_class_is_filter = True
                self.classes[current_class] = class_info
                self.files[self._current_file]["classes"].append(current_class)
                pending_annotations = []
                continue

            # 形参可能跨行，且注解里本身带括号（`@RequestParam("file") MultipartFile file`）。
            # 单行正则 + `([^)]*)` 会在注解的 `)` 处截断 ⇒ 类型丢失（实测被截成
            # `@RequestParam("file"`），下游就无从判断该用 multipart 还是 query。
            # 改为「窗口内匹配 + 括号配平取形参」。
            _window = "\n".join(lines[index: min(len(lines), index + 6)])
            method_match = method_pattern.search(_window)
            if not method_match:
                pending_annotations = []
                continue
            # 2026-11-02 实杀：窗口匹配会把**同一个方法声明**在后续每一行都重复命中
            # （窗口覆盖 6 行、逐行前进），而 `line_num` 记的是「窗口起始行」而不是
            # 「声明所在行」⇒ 行号错、同方法被索引 5~6 次。以前靠「同名 key 覆盖」把
            # 重复吃掉（于是行号恒等于最后一个窗口的起始行，也是错的）；
            # 加了重载后缀后重复就暴露成 6 个 http_entries。
            # 正解：算**声明真实行号**，并据此去重。
            _decl_line = line_num + _window[: method_match.start()].count("\n")
            # 只在「声明确实行在当前行」时才建条目：
            # 否则窗口在声明之前的若干行就会先命中，那时类级注解/入口标志还没就位
            # （实测 Servlet 的 doPost 因此丢了 http_entry），而且会重复建条目。
            # 这里 continue 但**不清空** pending_annotations —— 方法注解在声明上一行，
            # 必须留到声明行才消费。
            if _decl_line != line_num:
                continue
            _open_idx = _window.find("(", method_match.start())
            params_raw = self._balanced_params(_window, _open_idx)

            visibility = method_match.group(1)
            is_static = bool(method_match.group(2))
            return_type = method_match.group(3) or "void"
            method_name = method_match.group(4)
            if method_name == current_class:
                pending_annotations = []
                continue

            http_method = ""
            http_route = ""
            servlet_entry = None
            if current_class_is_servlet and method_name in self._SERVLET_ENTRY_METHODS:
                # Servlet 入口：路由在类级 @WebServlet，挂到 doGet/doPost 等入口方法；
                # protected/public 的 HttpServlet override 都算（Benchmark 实测为 public）。
                if class_base_route:
                    servlet_entry = f"{self._SERVLET_ENTRY_METHODS[method_name]} {class_base_route}"
            elif current_class_is_filter and method_name == "doFilter":
                # Filter 入口：路由在类级 @WebFilter，方法恒为 doFilter，HTTP 方法不限（记 ANY）。
                if class_base_route:
                    servlet_entry = f"ANY {class_base_route}"
            else:
                for annotation in pending_annotations:
                    parsed_method = self._extract_java_mapping_method(annotation)
                    parsed_path = self._extract_java_mapping_path(annotation)
                    if parsed_method or parsed_path or "@RequestMapping" in annotation:
                        http_method = parsed_method or http_method or "GET"
                        http_route = self._join_routes(class_base_route, parsed_path)
                        break

            func_key = f"{self._current_file}:{method_name}"
            # 同一行会被「窗口匹配」重复命中多次（`_window` 覆盖 6 行，逐行前进）——
            # 以前靠「同名覆盖」把重复吃掉，加了重载后缀后重复就会累积
            # （实测 Servlet 用例的 http_entries 从 2 变 6）。这里按 (名, 行) 先去重。
            if any((v.name == method_name and v.line == _decl_line)
                   for v in self.functions.values()
                   if getattr(v, "file", None) == self._current_file):
                pending_annotations = []
                continue
            # 2026-11-02 实杀：**重载方法会互相覆盖**。key 只有「文件:方法名」，
            # 同名重载后一个直接顶掉前一个 ⇒ 前一个的定义、行号、callers 全部丢失。
            # 实测 RuoYi 的 `JobInvokeUtil` 有两个 `invokeMethod`（`invokeMethod(SysJob)` 在 L23、
            # `invokeMethod(Object,String,List)` 在 L49），索引里只剩 L49 那个 ⇒
            # sink 在第 37 行（`Class.forName(beanName)`）时找不到所属函数 ⇒ 路由反查失败
            # ⇒ 真值表里唯一一条 in_scope 的 command_execution 一条候选都产不出。
            # 修法：重载按出现顺序加 `#2`/`#3` 后缀，**首个保留原名**（callers 仍按原名连边）。
            if func_key in self.functions:
                _n = 2
                while f"{func_key}#{_n}" in self.functions:
                    _n += 1
                func_key = f"{func_key}#{_n}"
            func_info = FunctionInfo(
                name=method_name,
                file=self._current_file,
                line=_decl_line,
                return_type=return_type,
                parameters=params_raw,
                params_typed=self._parse_typed_params(params_raw),
                is_static=is_static,
                is_public=(visibility == "public"),
                http_entry=(
                    servlet_entry
                    or (f"{http_method} {http_route}"
                        if (http_route and visibility == "public"
                            and (current_class_is_controller or current_class_is_servlet))
                        else None)
                ),
            )
            self.functions[func_key] = func_info
            self.files[self._current_file]["functions"].append(method_name)
            if current_class and current_class in self.classes:
                self.classes[current_class].methods.append(method_name)
            pending_annotations = []

    def _index_python_file(self, lines: List[str]):
        for index, line in enumerate(lines):
            line_num = index + 1
            if line.strip().startswith("#"):
                continue
            class_match = re.search(r"class\s+(\w+)", line)
            if class_match:
                class_name = class_match.group(1)
                self._current_class = class_name
                self.classes[class_name] = ClassInfo(name=class_name, file=self._current_file, line=line_num)
                self.files[self._current_file]["classes"].append(class_name)
                continue
            func_match = re.search(r"def\s+(\w+)\s*\(", line)
            if not func_match:
                continue
            func_name = func_match.group(1)
            func_key = f"{self._current_file}:{func_name}"
            func_info = FunctionInfo(name=func_name, file=self._current_file, line=line_num, is_public=True)
            self.functions[func_key] = func_info
            self.files[self._current_file]["functions"].append(func_name)

    def _index_js_file(self, lines: List[str]):
        route_pattern = re.compile(
            r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*(?:"([^"]+)"|\'([^\']+)\')',
            re.I,
        )
        for index, line in enumerate(lines):
            line_num = index + 1
            if line.strip().startswith("//"):
                continue
            route_match = route_pattern.search(line)
            if route_match:
                method = str(route_match.group(1) or "").upper()
                route = route_match.group(2) or route_match.group(3) or "/"
                synthetic_name = f"route_{method.lower()}_{route.strip('/').replace('/', '_').replace('-', '_') or 'root'}_{line_num}"
                func_key = f"{self._current_file}:{synthetic_name}"
                self.functions[func_key] = FunctionInfo(
                    name=synthetic_name,
                    file=self._current_file,
                    line=line_num,
                    is_public=True,
                    http_entry=f"{method} {route}",
                )
                self.files[self._current_file]["functions"].append(synthetic_name)
            func_match = re.search(r"function\s+(\w+)\s*\(", line)
            if not func_match:
                continue
            func_name = func_match.group(1)
            func_key = f"{self._current_file}:{func_name}"
            self.functions[func_key] = FunctionInfo(name=func_name, file=self._current_file, line=line_num, is_public=True)
            self.files[self._current_file]["functions"].append(func_name)

    def _index_php_file(self, lines: List[str]):
        full_text = "\n".join(lines)
        property_values: Dict[str, str] = {}
        route_facade = re.compile(r"Route::(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
        rest_route_start = re.compile(
            r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^,]+)\s*,\s*\[(.*?)\]\s*\)",
            re.I | re.S,
        )
        endpoint_property = re.compile(r"(?:public|protected|private)\s+\$([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]+)['\"]\s*;")
        method_pattern = re.compile(r"['\"]methods['\"]\s*=>\s*['\"]([A-Z,|]+)['\"]", re.I)

        for index, line in enumerate(lines):
            line_num = index + 1
            if line.strip().startswith("//"):
                continue

            property_match = endpoint_property.search(line)
            if property_match:
                property_values[property_match.group(1)] = property_match.group(2)

            route_match = route_facade.search(line)
            if route_match:
                method = str(route_match.group(1) or "").upper()
                route = str(route_match.group(2) or "").strip()
                synthetic_name = f"route_{method.lower()}_{route.strip('/').replace('/', '_').replace('-', '_') or 'root'}_{line_num}"
                func_key = f"{self._current_file}:{synthetic_name}"
                self.functions[func_key] = FunctionInfo(
                    name=synthetic_name,
                    file=self._current_file,
                    line=line_num,
                    is_public=True,
                    http_entry=f"{method} /{route.lstrip('/')}",
                )
                self.files[self._current_file]["functions"].append(synthetic_name)
                continue

        for match in re.finditer(rest_route_start, full_text):
            namespace = str(match.group(1) or "").strip().strip("/")
            endpoint_expr = str(match.group(2) or "").strip()
            route_config = str(match.group(3) or "")
            endpoint_name = endpoint_expr.strip("'\"")
            if endpoint_expr.startswith("$this->"):
                endpoint_name = property_values.get(endpoint_expr.split("->", 1)[1].strip(), endpoint_name)

            method_match = method_pattern.search(route_config)
            method = str(method_match.group(1) or "GET").split('|')[0].split(',')[0].upper() if method_match else "GET"
            route = "/" + "/".join(part for part in ("wp-json", namespace, str(endpoint_name).strip().strip("/")) if part)
            line_num = full_text[:match.start()].count("\n") + 1
            synthetic_name = f"rest_{method.lower()}_{str(endpoint_name).strip('/').replace('/', '_').replace('-', '_') or 'root'}_{line_num}"
            func_key = f"{self._current_file}:{synthetic_name}"
            self.functions[func_key] = FunctionInfo(
                name=synthetic_name,
                file=self._current_file,
                line=line_num,
                is_public=True,
                http_entry=f"{method} {route}",
            )
            self.files[self._current_file]["functions"].append(synthetic_name)

    # 单函数 callees/callers 列表长度上限（防御性封顶）。背景（2026-10-17 事故）：
    # 原实现按裸方法名解析 callee，Java servlet 的 doGet 普遍调用 doPost(...)，
    # 于是每个 doGet 链到索引内**全部** 2740 个同名 doPost，调用图二次方爆炸，
    # code_index.json 膨胀到 1.9GB；runner 加载后系统内存耗尽，a2_poc 阶段
    # 新建线程失败（can't start new thread），半全量扫描 run 362 崩死。
    _MAX_RELATIONS = 200

    def _declared_type(self, file_path: str, var_name: str) -> str:
        """同文件里 var_name 的声明类型（字段/局部变量），推断不到返回空串。

        只做「Type var;」这一确定形态；泛型/链式声明宁可返回空（交给唯一名回退），
        绝不猜——猜错类型会连错边，比漏边更糟。
        """
        content = self._file_contents.get(file_path, "") or ""
        if not content or not var_name:
            return ""
        m = re.search(
            r"\b([A-Z][\w$]*)\s+" + re.escape(var_name) + r"\s*(?:[;=,)]|$)",
            content, re.M,
        )
        return m.group(1) if m else ""

    def _build_call_relations(self):
        functions_by_name: Dict[str, List[str]] = defaultdict(list)
        for func_key, func_info in self.functions.items():
            functions_by_name[func_info.name].append(func_key)

        # 文件 -> 主类名（Java/PHP 类名与文件名一致），供「Class.method()」类限定解析
        file_class: Dict[str, str] = {}
        for cls_name, cls_info in self.classes.items():
            file_class.setdefault(cls_info.file, cls_name)

        # 调用点正则：可选 this./self. 前缀 + 可选接收者 + 方法名 + 左括号。
        # 接收者区分：None（裸调用/this/self）→ 只连本文件同名函数；
        # 大写开头（类名）→ 只连该类所在文件；小写开头（变量）→ 静态类型未知，不连
        # （宁可漏边，也绝不造「一个 doGet 连全部 doPost」的爆炸边）。
        call_re = re.compile(r"\b(?:(?:this|self)\.)?(?:([A-Za-z_$][\w$]*)\.)?([A-Za-z_$][\w$]*)\s*\(")

        for file_path, file_info in self.files.items():
            content = self._file_contents.get(file_path, "")
            if not content:
                continue
            lines = content.split("\n")
            function_lines = []
            for func_name in file_info.get("functions", []):
                func_key = f"{file_path}:{func_name}"
                func_info = self.functions.get(func_key)
                if func_info:
                    function_lines.append((func_info.line, func_key, func_info))
            function_lines.sort()

            for idx, (start_line, func_key, func_info) in enumerate(function_lines):
                end_line = function_lines[idx + 1][0] - 1 if idx + 1 < len(function_lines) else len(lines)
                body = "\n".join(lines[max(0, start_line - 1):end_line])
                # 一遍扫描函数体，收集全部调用点（避免原实现「每个候选名 × 每个函数体」的
                # 二次正则开销），再按类限定规则解析目标。
                for m in call_re.finditer(body):
                    qualifier, cand = m.group(1), m.group(2)
                    # 2026-11-02 修：原先无条件跳过「同名调用」，把**跨类同名调用**也跳了。
                    # 实测 `SSRF.request()` 里调 `HttpUtils.request(url)`，因为两者都叫
                    # `request` 被跳过 ⇒ `HttpUtils.java:request` 的 callers 恒为空 ⇒
                    # 工具类 sink 的参数回溯全部断链（param 空 32 条卡在这）。
                    # 只有「裸调用且同名」（即真的自递归）才该跳过。
                    if cand == func_info.name and qualifier is None:
                        continue
                    target_keys = functions_by_name.get(cand)
                    if not target_keys:
                        continue
                    if qualifier is None:
                        targets = [k for k in target_keys if k.startswith(file_path + ":")]
                    elif qualifier[:1].isupper():
                        targets = [k for k in target_keys if file_class.get(k.split(":", 1)[0]) == qualifier]
                    else:
                        # 变量接收者：先按同文件里的字段/局部变量声明推断静态类型；
                        # 推断不到时，**仅当该方法名在全项目唯一**才连（唯一 ⇒ 不可能造
                        # 「一个 doGet 连全部 doPost」的爆炸边）。反编译产物常缺字段声明
                        # （r111 回归：GatewayController.evaluationService.evaluate(rule)）。
                        targets = []
                        _vtype = self._declared_type(file_path, qualifier)
                        if _vtype:
                            targets = [k for k in target_keys
                                       if file_class.get(k.split(":", 1)[0]) == _vtype]
                        if not targets and len(target_keys) == 1:
                            targets = target_keys
                    for target_key in targets:
                        if target_key == func_key:
                            continue
                        if target_key not in func_info.callees:
                            if len(func_info.callees) >= self._MAX_RELATIONS:
                                break
                            func_info.callees.append(target_key)
                        target_info = self.functions.get(target_key)
                        if target_info and func_key not in target_info.callers:
                            if len(target_info.callers) < self._MAX_RELATIONS:
                                target_info.callers.append(func_key)

    def save_index(self, index: Dict, path: str):
        # 紧凑序列化（2026-10-17）：原 indent=2 在边爆炸场景下把 1.9GB 写到磁盘；
        # 调用图修复后本应是小文件，紧凑格式作为纵深防御再降一个量级。
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(index, handle, ensure_ascii=False, separators=(",", ":"))
        logger.info("Index saved to %s", path)

    def load_index(self, path: str) -> Optional[Dict]:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as handle:
            index = json.load(handle)
        logger.info("Index loaded from %s", path)
        return index

    def find_call_chain(self, target_function: str, index: Dict) -> Dict:
        result = {"has_caller": False, "http_entry": None, "callers": [], "verdict": "❌ 假漏洞-无调用点"}
        functions = index.get("functions", {})
        matched_func = None
        for func_key, func_info in functions.items():
            if target_function.lower() in func_key.lower() or str(func_info.get("name", "")).lower() == target_function.lower():
                matched_func = func_info
                break
        if not matched_func:
            return result
        if matched_func.get("http_entry"):
            result["has_caller"] = True
            result["http_entry"] = matched_func["http_entry"]
            result["verdict"] = "✅ 真漏洞-HTTP入口可触发"
            return result
        if matched_func.get("callers"):
            result["has_caller"] = True
            result["callers"] = matched_func["callers"]
            result["verdict"] = "✅ 真漏洞-有调用点"
        return result


def create_incremental_index(files: List[Dict], old_index: Dict = None) -> Dict:
    indexer = CodeIndexer()
    new_index = indexer.index_project(files)
    if old_index:
        new_index["functions"].update(old_index.get("functions", {}))
        new_index["classes"].update(old_index.get("classes", {}))
        new_index["files"].update(old_index.get("files", {}))
    return new_index
