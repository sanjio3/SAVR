"""
API 端点自动发现器
从代码中自动提取 API 端点信息
"""
import re
import logging
from typing import List, Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class EndpointDiscoverer:
    """自动发现 API 端点"""

    JAVA_INPUT_ANNOTATIONS = {'RequestParam', 'PathVariable', 'RequestBody'}

    @staticmethod
    def _join_url_paths(base_path: str, sub_path: str) -> str:
        parts = []
        for part in (base_path or "", sub_path or ""):
            cleaned = str(part).strip().strip("/")
            if cleaned:
                parts.append(cleaned)
        return "/" + "/".join(parts) if parts else "/"

    @staticmethod
    def _split_top_level(text: str, delimiter: str = ',') -> List[str]:
        items = []
        current = []
        angle_depth = 0
        paren_depth = 0
        brace_depth = 0
        bracket_depth = 0
        in_string: Optional[str] = None
        escaped = False

        for char in text:
            if in_string:
                current.append(char)
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == in_string:
                    in_string = None
                continue

            if char in {'"', "'"}:
                in_string = char
                current.append(char)
                continue

            if char == '<':
                angle_depth += 1
            elif char == '>':
                angle_depth = max(0, angle_depth - 1)
            elif char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth = max(0, paren_depth - 1)
            elif char == '{':
                brace_depth += 1
            elif char == '}':
                brace_depth = max(0, brace_depth - 1)
            elif char == '[':
                bracket_depth += 1
            elif char == ']':
                bracket_depth = max(0, bracket_depth - 1)

            if (
                char == delimiter
                and angle_depth == 0
                and paren_depth == 0
                and brace_depth == 0
                and bracket_depth == 0
            ):
                item = "".join(current).strip()
                if item:
                    items.append(item)
                current = []
                continue

            current.append(char)

        tail = "".join(current).strip()
        if tail:
            items.append(tail)
        return items

    @staticmethod
    def _extract_annotation_blocks(segment: str) -> Tuple[List[Tuple[str, str]], str]:
        annotations: List[Tuple[str, str]] = []
        idx = 0
        length = len(segment)

        while idx < length:
            while idx < length and segment[idx].isspace():
                idx += 1
            if idx >= length or segment[idx] != '@':
                break

            idx += 1
            start = idx
            while idx < length and (segment[idx].isalnum() or segment[idx] in '._$'):
                idx += 1
            annotation_name = segment[start:idx].split('.')[-1]

            while idx < length and segment[idx].isspace():
                idx += 1

            raw_args = ""
            if idx < length and segment[idx] == '(':
                depth = 1
                idx += 1
                arg_start = idx
                in_string: Optional[str] = None
                escaped = False
                while idx < length and depth > 0:
                    char = segment[idx]
                    if in_string:
                        if escaped:
                            escaped = False
                        elif char == '\\':
                            escaped = True
                        elif char == in_string:
                            in_string = None
                    else:
                        if char in {'"', "'"}:
                            in_string = char
                        elif char == '(':
                            depth += 1
                        elif char == ')':
                            depth -= 1
                            if depth == 0:
                                raw_args = segment[arg_start:idx]
                                idx += 1
                                break
                    idx += 1

            annotations.append((annotation_name, raw_args))

        return annotations, segment[idx:].strip()

    @classmethod
    def _extract_named_annotation_value(cls, raw_args: str) -> Optional[str]:
        raw_args = (raw_args or "").strip()
        if not raw_args:
            return None

        for pattern in (
            r'\b(?:value|name|path)\s*=\s*"([^"]+)"',
            r"\b(?:value|name|path)\s*=\s*'([^']+)'",
        ):
            match = re.search(pattern, raw_args)
            if match:
                return match.group(1)

        top_level_parts = cls._split_top_level(raw_args)
        if top_level_parts and '=' not in top_level_parts[0]:
            literal = top_level_parts[0].strip()
            if (literal.startswith('"') and literal.endswith('"')) or (
                literal.startswith("'") and literal.endswith("'")
            ):
                return literal[1:-1]
        return None

    @staticmethod
    def _clean_java_param_declaration(remainder: str) -> str:
        cleaned = re.sub(r'\bfinal\s+', '', remainder)
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned.strip()

    # Java Spring 注解模式
    SPRING_PATTERNS = {
        'mapping_annotations': [
            r'@RequestMapping\s*\(\s*"([^"]+)"',
            r'@RequestMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@RequestMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
            r'@GetMapping\s*\(\s*"([^"]+)"',
            r'@GetMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@GetMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
            r'@PostMapping\s*\(\s*"([^"]+)"',
            r'@PostMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@PostMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
            r'@PutMapping\s*\(\s*"([^"]+)"',
            r'@PutMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@PutMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
            r'@DeleteMapping\s*\(\s*"([^"]+)"',
            r'@DeleteMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@DeleteMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
            r'@PatchMapping\s*\(\s*"([^"]+)"',
            r'@PatchMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@PatchMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
            r'@RequestParam\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@PathVariable\s*\([^)]*value\s*=\s*"([^"]+)"',
        ],
        'method': [
            r'@(?:Get|Post|Put|Delete|Patch|RequestMapping)',
        ],
        'class_mapping': [
            r'@RequestMapping\s*\(\s*"([^"]+)"',
            r'@RequestMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@RequestMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
        ]
    }

    # Python Flask/Django 模式
    FLASK_PATTERNS = {
        'route': [
            r"@app\.route\s*\(['\"]([^'\"]+)['\"]",
            r"@route\s*\(['\"]([^'\"]+)['\"]",
        ],
        'method': [
            r"methods\s*=\s*\[['\"]([^'\"]+)['\"]",
        ]
    }

    # FastAPI 模式
    FASTAPI_PATTERNS = {
        'route': [
            r"@app\.(get|post|put|delete|patch|options|head)\s*\(['\"]([^'\"]+)['\"]",
            r"@router\.(get|post|put|delete|patch)\s*\(['\"]([^'\"]+)['\"]",
            r"@app\.api_route\s*\(['\"]([^'\"]+)['\"]",
        ],
        'method': [
            r"methods\s*=\s*\[([^\]]+)\]",
        ]
    }

    # Django 模式
    DJANGO_PATTERNS = {
        'url': [
            r"path\s*\(['\"]([^'\"]+)['\"]",
            r"re_path\s*\(\s*r?['\"]([^'\"]+)['\"]",
            r"url\s*\(\s*r?['\"]([^'\"]+)['\"]",
        ],
        'view': [
            r"class\s+(\w+View)\s*\(",
            r"def\s+(\w+)\s*\(\s*request",
        ]
    }

    # Node.js Express 模式
    EXPRESS_PATTERNS = {
        'route': [
            r"app\.(get|post|put|delete|patch|options|head)\s*\(\s*['\"]([^'\"]+)['\"]",
            r"router\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
            r"app\.(get|post|put|delete|patch)\s*\(\s*[`]",
        ],
    }

    PHP_PATTERNS = {
        'rest_route': r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^,]+)\s*,\s*\[(.*?)\]\s*\)",
        'route_facade': r"Route::(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
        'endpoint_property': r"(?:public|protected|private)\s+\$([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]+)['\"]\s*;",
        'methods': r"['\"]methods['\"]\s*=>\s*['\"]([A-Z,|]+)['\"]",
    }

    # Spring WebFlux 模式
    SPRING_WEBFLUX_PATTERNS = {
        'mapping_annotations': [
            r'@GetMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@PostMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@PutMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@DeleteMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
            r'@RequestMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
        ],
    }

    # JAX-RS 模式 (Java)
    JAXRS_PATTERNS = {
        'mapping_annotations': [
            r'@Path\s*\(\s*"([^"]+)"\s*\)',
            r'@GET\s*\(\s*\)',
            r'@POST\s*\(\s*\)',
            r'@PUT\s*\(\s*\)',
            r'@DELETE\s*\(\s*\)',
            r'@PathParam\s*\(\s*"([^"]+)"\s*\)',
            r'@QueryParam\s*\(\s*"([^"]+)"\s*\)',
            r'@FormParam\s*\(\s*"([^"]+)"\s*\)',
        ],
    }

    def __init__(self):
        self.endpoints = []
        self.class_mappings = []

    def discover_from_file(self, content: str, filename: str, rel_path: str) -> List[Dict]:
        """
        从单个文件发现端点

        Returns:
            List of dicts with 'path', 'method', 'params', 'vuln_types' keys
        """
        discovered = []
        ext = Path(rel_path or filename).suffix.lower()

        # 根据语言和框架选择发现策略
        if ext in ['.java', '.kt', '.scala']:
            # 检测 Spring WebFlux
            if 'webflux' in content.lower() or 'reactor' in content.lower():
                discovered = self._discover_spring_webflux(content, rel_path)
            # 检测 JAX-RS
            elif 'javax.ws.rs' in content or 'jakarta.ws.rs' in content:
                discovered = self._discover_jaxrs_endpoints(content, rel_path)
            else:
                discovered = self._discover_java_endpoints(content, rel_path)
        elif ext in ['.py']:
            # 检测 FastAPI
            if 'fastapi' in content.lower() or 'APIRouter' in content:
                discovered = self._discover_fastapi_endpoints(content, rel_path)
            # 检测 Django
            elif 'django' in content.lower() or 'path(' in content or 're_path(' in content:
                discovered = self._discover_django_endpoints(content, rel_path)
            else:
                discovered = self._discover_python_endpoints(content, rel_path)
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            discovered = self._discover_nodejs_endpoints(content, rel_path)
        elif ext in ['.php']:
            discovered = self._discover_php_endpoints(content, rel_path)

        logger.info(f"Discovered {len(discovered)} endpoints from {filename}")
        return discovered

    def _discover_java_endpoints(self, content: str, rel_path: str) -> List[Dict]:
        """发现 Java Spring 端点"""
        endpoints = []

        # 查找方法级别的映射
        lines = content.split('\n')
        current_class = ""
        pending_method_type: Optional[str] = None
        pending_method_path = ""
        method_signature_pattern = re.compile(
            r'^\s*(?:public|protected|private)\s+(?:static\s+)?(?:[\w<>\[\],?]+\s+)+(\w+)\s*\('
        )

        for i, line in enumerate(lines):
            stripped = line.strip()

            # 检查类映射
            for pattern in self.SPRING_PATTERNS['class_mapping']:
                match = re.search(pattern, line)
                if match:
                    current_class = match.group(1)
                    break

            method_type = pending_method_type or "GET"
            path = ""
            mapping_found = False

            # 确定 HTTP 方法
            if '@GetMapping' in stripped:
                method_type = "GET"
                mapping_found = True
            elif '@PostMapping' in stripped:
                method_type = "POST"
                mapping_found = True
            elif '@PutMapping' in stripped:
                method_type = "PUT"
                mapping_found = True
            elif '@DeleteMapping' in stripped:
                method_type = "DELETE"
                mapping_found = True
            elif '@PatchMapping' in stripped:
                method_type = "PATCH"
                mapping_found = True
            elif '@RequestMapping' in stripped:
                # 提取方法类型
                method_match = re.search(r'method\s*=\s*RequestMethod\.(\w+)', line)
                if method_match:
                    method_type = method_match.group(1)
                mapping_found = True

            # 提取路径
            for pattern in self.SPRING_PATTERNS['mapping_annotations']:
                match = re.search(pattern, line)
                if match:
                    path = match.group(1)
                    break

            if mapping_found:
                is_class_level_request_mapping = (
                    '@RequestMapping' in stripped
                    and any(token in "".join(lines[i:i + 3]) for token in (' class ', 'class ', 'interface ', 'enum '))
                )
                if is_class_level_request_mapping:
                    pending_method_type = None
                    pending_method_path = ""
                    continue

                pending_method_type = method_type
                pending_method_path = path
                continue

            if pending_method_type and method_signature_pattern.search(stripped):
                full_path = self._join_url_paths(current_class, pending_method_path)
                params = self._extract_java_params(lines, i)
                endpoints.append({
                    'path': full_path,
                    'method': pending_method_type,
                    'params': params,
                    'file': rel_path,
                    'line': i + 1,
                    'vuln_types': self._infer_vuln_types(full_path, params, content)
                })
                pending_method_type = None
                pending_method_path = ""

        return endpoints

    def _extract_java_params(self, lines: List[str], start_line: int) -> List[Dict]:
        """提取 Java 方法参数"""
        params = []
        signature_parts = []
        paren_depth = 0
        saw_open_paren = False

        for i in range(start_line, min(start_line + 12, len(lines))):
            line = lines[i].strip()
            if not line:
                continue
            signature_parts.append(line)
            paren_depth += line.count('(') - line.count(')')
            if '(' in line:
                saw_open_paren = True
            if saw_open_paren and paren_depth <= 0:
                break

        signature = " ".join(signature_parts)
        match = re.search(r'\((.*)\)', signature)
        if not match:
            return params

        params_block = match.group(1).strip()
        if not params_block:
            return params

        param_segments = self._split_top_level(params_block)

        for segment in param_segments:
            annotations, remainder = self._extract_annotation_blocks(segment)
            input_annotation = next(
                ((name, raw_args) for name, raw_args in annotations if name in self.JAVA_INPUT_ANNOTATIONS),
                None,
            )
            if not input_annotation:
                continue

            annotation, raw_args = input_annotation
            cleaned = self._clean_java_param_declaration(remainder)
            if not cleaned:
                continue

            pieces = cleaned.rsplit(' ', 1)
            if len(pieces) < 2:
                continue

            param_name = pieces[-1]
            param_type = pieces[0].strip()
            param = {
                'name': param_name,
                'type': param_type,
                'annotation': annotation,
            }
            source_name = self._extract_named_annotation_value(raw_args)
            if source_name:
                param['source_name'] = source_name
            params.append(param)

        return params

    def _discover_python_endpoints(self, content: str, rel_path: str) -> List[Dict]:
        """发现 Python Flask/Django 端点"""
        endpoints = []

        for pattern in self.FLASK_PATTERNS['route']:
            matches = re.finditer(pattern, content)
            for match in matches:
                path = match.group(1)

                # 查找对应的方法
                method = "GET"
                lines = content.split('\n')
                line_num = content[:match.start()].count('\n')

                # 查找附近的 methods 定义
                for i in range(max(0, line_num - 3), min(len(lines), line_num + 3)):
                    method_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", lines[i])
                    if method_match:
                        methods_str = method_match.group(1)
                        methods = re.findall(r"['\"](\w+)['\"]", methods_str)
                        if methods:
                            method = methods[0].upper()
                        break

                # 推断漏洞类型
                vuln_types = self._infer_vuln_types(path, [], content)

                endpoints.append({
                    'path': path,
                    'method': method,
                    'params': [],
                    'file': rel_path,
                    'line': line_num + 1,
                    'vuln_types': vuln_types
                })

        return endpoints

    def _discover_nodejs_endpoints(self, content: str, rel_path: str) -> List[Dict]:
        """发现 Node.js Express 端点"""
        endpoints = []

        for pattern in self.EXPRESS_PATTERNS['route']:
            matches = re.finditer(pattern, content)
            for match in matches:
                method = match.group(1).upper()
                path = match.group(2) if match.lastindex >= 2 else "/"

                # 推断漏洞类型
                vuln_types = self._infer_vuln_types(path, [], content)

                line_num = content[:match.start()].count('\n')

                endpoints.append({
                    'path': path,
                    'method': method,
                    'params': [],
                    'file': rel_path,
                    'line': line_num + 1,
                    'vuln_types': vuln_types
                })

        return endpoints

    def _discover_php_endpoints(self, content: str, rel_path: str) -> List[Dict]:
        """发现 PHP / WordPress / custom Route facade 端点"""
        endpoints = []
        property_values = {
            name: value
            for name, value in re.findall(self.PHP_PATTERNS['endpoint_property'], content)
        }

        route_facade = re.finditer(self.PHP_PATTERNS['route_facade'], content, re.I)
        for match in route_facade:
            method = str(match.group(1) or "").upper()
            path = str(match.group(2) or "").strip()
            line_num = content[:match.start()].count('\n') + 1
            endpoints.append({
                'path': f"/{path.lstrip('/')}",
                'method': method,
                'params': [],
                'file': rel_path,
                'line': line_num,
                'vuln_types': self._infer_vuln_types(path, [], content),
                'framework': 'php-route-facade',
            })

        for match in re.finditer(self.PHP_PATTERNS['rest_route'], content, re.I | re.S):
            namespace = str(match.group(1) or "").strip().strip("/")
            endpoint_expr = str(match.group(2) or "").strip()
            route_config = str(match.group(3) or "")
            line_num = content[:match.start()].count('\n') + 1

            if endpoint_expr.startswith("$this->"):
                endpoint_name = endpoint_expr.split("->", 1)[1].strip()
                endpoint_name = property_values.get(endpoint_name, endpoint_name)
            else:
                endpoint_name = endpoint_expr.strip("'\"")
            endpoint_name = str(endpoint_name or "").strip().strip("/")

            method_match = re.search(self.PHP_PATTERNS['methods'], route_config, re.I)
            method = str(method_match.group(1) or "GET").split('|')[0].split(',')[0].upper() if method_match else "GET"
            path = "/" + "/".join(part for part in ("wp-json", namespace, endpoint_name) if part)
            endpoints.append({
                'path': path,
                'method': method,
                'params': [],
                'file': rel_path,
                'line': line_num,
                'vuln_types': self._infer_vuln_types(path, [], content),
                'framework': 'wordpress-rest',
            })

        return endpoints

    def _discover_fastapi_endpoints(self, content: str, rel_path: str) -> List[Dict]:
        """发现 FastAPI 端点"""
        endpoints = []

        for pattern in self.FASTAPI_PATTERNS['route']:
            matches = re.finditer(pattern, content)
            for match in matches:
                method = match.group(1).upper()
                path = match.group(2) if match.lastindex >= 2 else "/"

                # 查找附近的参数定义
                params = self._extract_fastapi_params(content, match.start())

                line_num = content[:match.start()].count('\n')
                vuln_types = self._infer_vuln_types(path, params, content)

                endpoints.append({
                    'path': path,
                    'method': method,
                    'params': params,
                    'file': rel_path,
                    'line': line_num + 1,
                    'vuln_types': vuln_types,
                    'framework': 'fastapi'
                })

        return endpoints

    def _extract_fastapi_params(self, content: str, position: int) -> List[Dict]:
        """从 FastAPI 端点提取参数"""
        params = []

        # 查找函数定义
        text_after = content[position:position+500]

        # 匹配函数参数: def endpoint(param: type = ...):
        param_match = re.search(r'def\s+\w+\s*\((.*?)\):', text_after)
        if param_match:
            param_str = param_match.group(1)
            # 匹配每个参数
            for p in param_str.split(','):
                p = p.strip()
                if p and p != 'request':
                    # 提取参数名
                    name_match = re.match(r'(\w+)', p)
                    if name_match:
                        param_name = name_match.group(1)
                        param_type = 'any'

                        # 提取类型注解
                        if ':' in p:
                            type_part = p.split(':')[1].split('=')[0].strip()
                            param_type = type_part

                        # 检查默认值
                        has_default = '=' in p

                        params.append({
                            'name': param_name,
                            'type': param_type,
                            'required': not has_default,
                            'in': 'path' if '{' in p else 'query'
                        })

        return params

    def _discover_django_endpoints(self, content: str, rel_path: str) -> List[Dict]:
        """发现 Django 端点"""
        endpoints = []

        # 查找 url 模式
        for pattern in self.DJANGO_PATTERNS['url']:
            matches = re.finditer(pattern, content)
            for match in matches:
                path = match.group(1)

                # 替换 Django URL 模式为实际路径
                path = re.sub(r'<(\w+):(\w+)>', r'{\2}', path)  # <app:name> -> {name}
                path = re.sub(r'<(\w+)>', r'{\1}', path)  # <name> -> {name}
                path = re.sub(r'(\w+)/', r'\1/', path)  # 保持普通路径

                line_num = content[:match.start()].count('\n')

                # 查找对应的视图
                view_func = self._find_django_view(content, line_num)

                # 推断方法
                method = self._infer_django_method(content, line_num)

                vuln_types = self._infer_vuln_types(path, [], content)

                endpoints.append({
                    'path': '/' + path.lstrip('/'),
                    'method': method,
                    'params': [],
                    'file': rel_path,
                    'line': line_num + 1,
                    'vuln_types': vuln_types,
                    'view': view_func,
                    'framework': 'django'
                })

        return endpoints

    def _find_django_view(self, content: str, line_num: int) -> Optional[str]:
        """查找 Django 视图函数"""
        lines = content.split('\n')
        start = max(0, line_num - 10)
        end = min(len(lines), line_num + 5)

        for i in range(start, end):
            line = lines[i]
            # 匹配 url(..., views.xxx)
            view_match = re.search(r'views\.(\w+)', line)
            if view_match:
                return view_match.group(1)
            # 匹配类视图
            class_match = re.search(r'\.(\w+View)\.', line)
            if class_match:
                return class_match.group(1)

        return None

    def _infer_django_method(self, content: str, line_num: int) -> str:
        """推断 Django HTTP 方法"""
        lines = content.split('\n')
        start = max(0, line_num - 5)
        end = min(len(lines), line_num + 5)

        for i in range(start, end):
            line = lines[i].lower()
            if '.get(' in line or 'get_queryset' in line:
                return 'GET'
            if '.post(' in line:
                return 'POST'
            if '.put(' in line:
                return 'PUT'
            if '.delete(' in line:
                return 'DELETE'

        return 'GET'  # 默认

    def _discover_spring_webflux(self, content: str, rel_path: str) -> List[Dict]:
        """发现 Spring WebFlux 端点"""
        # 与 Java Spring 类似，但使用 Flux/Mono
        return self._discover_java_endpoints(content, rel_path)

    def _discover_jaxrs_endpoints(self, content: str, rel_path: str) -> List[Dict]:
        """发现 JAX-RS 端点"""
        endpoints = []

        lines = content.split('\n')
        current_class_path = ""
        current_method_path = ""

        for i, line in enumerate(lines):
            # 提取类级别 @Path
            class_path_match = re.search(r'@Path\s*\(\s*"([^"]+)"\s*\)', line)
            if class_path_match:
                current_class_path = class_path_match.group(1)

            # 提取方法级别 @Path
            method_path_match = re.search(r'@Path\s*\(\s*"([^"]+)"\s*\)', line)
            if method_path_match:
                current_method_path = method_path_match.group(1)

            # 确定 HTTP 方法
            method = "GET"
            if '@GET' in line:
                method = "GET"
            elif '@POST' in line:
                method = "POST"
            elif '@PUT' in line:
                method = "PUT"
            elif '@DELETE' in line:
                method = "DELETE"

            # 如果有 @Path 或 HTTP 方法注解，提取完整路径
            if '@GET' in line or '@POST' in line or '@PUT' in line or '@DELETE' in line or method_path_match:
                full_path = (current_class_path + current_method_path).replace("//", "/")

                # 提取参数
                params = self._extract_jaxrs_params(lines, i)

                vuln_types = self._infer_vuln_types(full_path, params, content)

                endpoints.append({
                    'path': full_path,
                    'method': method,
                    'params': params,
                    'file': rel_path,
                    'line': i + 1,
                    'vuln_types': vuln_types,
                    'framework': 'jaxrs'
                })

        return endpoints

    def _extract_jaxrs_params(self, lines: List[str], start_line: int) -> List[Dict]:
        """提取 JAX-RS 方法参数"""
        params = []

        for i in range(start_line, min(start_line + 10, len(lines))):
            line = lines[i]

            # 匹配参数注解
            for annotation, param_type in [
                ('@PathParam', 'path'),
                ('@QueryParam', 'query'),
                ('@FormParam', 'form'),
                ('@HeaderParam', 'header'),
                ('@CookieParam', 'cookie'),
                ('@MatrixParam', 'matrix'),
                ('@Body', 'body')
            ]:
                match = re.search(rf'{annotation}\s*\(\s*"([^"]+)"\s*\)\s+(\w+)\s+(\w+)', line)
                if match:
                    params.append({
                        'name': match.group(2),
                        'type': match.group(3),
                        'annotation': annotation,
                        'in': param_type
                    })

        return params

    def extract_actual_params(self, content: str, method_line: int) -> List[Dict]:
        """
        从方法签名和注解中提取真实参数

        Args:
            content: 文件内容
            method_line: 方法所在行号

        Returns:
            参数列表
        """
        lines = content.split('\n')
        method_line = max(0, method_line - 1)  # 转换为0索引

        # 查找方法签名
        for i in range(method_line, min(method_line + 5, len(lines))):
            line = lines[i]

            # Java 方法参数
            if '@' not in line and '(' in line and ')' in line:
                param_match = re.search(r'\((.*?)\)', line)
                if param_match:
                    param_str = param_match.group(1)
                    if param_str.strip():
                        return self._extract_java_params(lines, i)

        return []

    def _infer_vuln_types(self, path: str, params: List[Dict], content: str) -> List[str]:
        """根据路径和参数推断可能的漏洞类型"""
        vuln_types = []
        path_lower = path.lower()
        content_lower = content.lower()

        # SQL 注入
        if any(kw in path_lower for kw in ['query', 'search', 'user', 'id', 'sql', 'db']):
            vuln_types.append('sql_injection')

        # XSS
        if any(kw in path_lower for kw in ['html', 'render', 'view', 'display', 'show', 'echo']):
            vuln_types.append('xss')

        # 命令注入
        if any(kw in path_lower for kw in ['exec', 'shell', 'cmd', 'command', 'system', 'process']):
            vuln_types.append('command_injection')

        # SSRF
        if any(kw in path_lower for kw in ['fetch', 'url', 'proxy', 'redirect', 'load', 'request']):
            vuln_types.append('ssrf')

        # 文件操作
        if any(kw in path_lower for kw in ['file', 'path', 'upload', 'download', 'read', 'write']):
            vuln_types.append('path_traversal')

        # XML 处理
        if any(kw in path_lower for kw in ['xml', 'parse']):
            vuln_types.append('xxe')

        # 反序列化
        if any(kw in path_lower for kw in ['serialize', 'deserialize', 'object', 'decode']):
            vuln_types.append('deserialization')

        # 重定向
        if any(kw in path_lower for kw in ['redirect', 'next', 'url', 'return', 'callback']):
            vuln_types.append('url_redirect')

        # 检查代码中的敏感操作
        if 'executequery' in content_lower or 'statement' in content_lower:
            if 'sql_injection' not in vuln_types:
                vuln_types.append('sql_injection')

        if 'runtime.exec' in content_lower or 'processbuilder' in content_lower:
            if 'command_injection' not in vuln_types:
                vuln_types.append('command_injection')

        if 'urlconnection' in content_lower or 'httprequest' in content_lower:
            if 'ssrf' not in vuln_types:
                vuln_types.append('ssrf')

        return vuln_types

    def match_endpoints_for_vulnerability(self, vuln_type: str, file_path: str,
                                          discovered_endpoints: List[Dict]) -> List[Dict]:
        """为漏洞匹配对应的测试端点"""
        matched = []

        for endpoint in discovered_endpoints:
            # 文件匹配
            if endpoint.get('file') != file_path:
                continue

            # 漏洞类型匹配
            if vuln_type.lower() in [v.lower() for v in endpoint.get('vuln_types', [])]:
                matched.append(endpoint)

        # 如果没有精确匹配，尝试模糊匹配
        if not matched:
            for endpoint in discovered_endpoints:
                if endpoint.get('file') == file_path:
                    matched.append(endpoint)

        return matched


def extract_endpoints_from_files(files: List[Dict]) -> Dict[str, List[Dict]]:
    """
    从文件列表中提取所有端点

    Returns:
        Dict mapping file paths to lists of endpoints
    """
    discoverer = EndpointDiscoverer()
    all_endpoints = {}

    for file_info in files:
        rel_path = file_info.get('rel_path', '')
        content = file_info.get('content', '')
        name = file_info.get('name', '') or Path(rel_path).name

        if content:
            endpoints = discoverer.discover_from_file(content, name, rel_path)
            if endpoints:
                all_endpoints[rel_path] = endpoints

    logger.info(f"Total endpoints discovered: {sum(len(e) for e in all_endpoints.values())}")
    return all_endpoints
