"""
R0 Recon Agent - 信息收集
负责扫描项目结构，识别框架/库/API，提取攻击面
"""
import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
import logging

from ..core.file_inventory import load_skip_dirs, should_skip_dir

logger = logging.getLogger(__name__)


@dataclass
class ProjectInfo:
    """项目信息"""
    name: str = ""
    path: str = ""
    language: str = ""
    framework: str = ""
    build_tool: str = ""

    # 项目结构
    source_dirs: List[str] = field(default_factory=list)
    test_dirs: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)

    # 依赖信息
    dependencies: Dict[str, str] = field(default_factory=dict)
    dependency_files: List[str] = field(default_factory=list)

    # 入口点
    http_routes: List[Dict] = field(default_factory=list)
    entry_points: List[Dict] = field(default_factory=list)

    # 项目文件清单
    files: List[str] = field(default_factory=list)

    # 数据流
    user_inputs: List[Dict] = field(default_factory=list)
    db_queries: List[Dict] = field(default_factory=list)
    external_calls: List[Dict] = field(default_factory=list)

    # 安全配置
    security_configs: Dict = field(default_factory=dict)

    def to_dict(self):
        return {
            'name': self.name,
            'path': self.path,
            'language': self.language,
            'framework': self.framework,
            'build_tool': self.build_tool,
            'source_dirs': self.source_dirs,
            'test_dirs': self.test_dirs,
            'config_files': self.config_files,
            'dependencies': self.dependencies,
            'dependency_files': self.dependency_files,
            'http_routes': self.http_routes,
            'entry_points': self.entry_points,
            'user_inputs': self.user_inputs,
            'db_queries': self.db_queries,
            'external_calls': self.external_calls,
            'security_configs': self.security_configs
        }


class R0ReconAgent:
    """R0 Recon 信息收集 Agent"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.project_info = ProjectInfo(path=str(project_path))
        self.project_info.name = self.project_path.name
        self.skip_dirs = load_skip_dirs()

    def _walk_project(self):
        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not should_skip_dir(d, self.skip_dirs)]
            yield root, dirs, files

    def scan(self) -> ProjectInfo:
        """执行完整的信息收集"""
        logger.info(f"Starting R0 Recon scan: {self.project_path}")

        # 1. 项目结构扫描
        self._scan_project_structure()

        # 2. 技术栈识别
        self._detect_tech_stack()

        # 3. 依赖分析
        self._analyze_dependencies()

        # 4. 入口点提取
        self._extract_entry_points()

        # 5. 数据流分析
        self._analyze_data_flow()

        # 6. 安全配置分析
        self._analyze_security_configs()

        logger.info(f"R0 Recon completed: {len(self.project_info.http_routes)} routes, "
                   f"{len(self.project_info.dependencies)} deps")
        return self.project_info

    def _scan_project_structure(self):
        """扫描项目结构"""
        source_dirs = []
        test_dirs = []
        config_files = []

        # 常见源代码目录
        source_patterns = ['src', 'source', 'app', 'sourcecode', 'src/main/java', 'src/main/python']

        for root, dirs, files in self._walk_project():
            # 跳过隐藏目录和生成目录
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'target', 'dist', 'build', '__pycache__', 'venv', 'env']]

            rel_path = os.path.relpath(root, self.project_path)

            # 检测源代码目录
            for pattern in source_patterns:
                if pattern in rel_path:
                    source_dirs.append(rel_path)
                    break

            # 检测测试目录
            if 'test' in rel_path.lower() or 'spec' in rel_path.lower():
                test_dirs.append(rel_path)

            # 收集配置文件
            for f in files:
                if f in ['pom.xml', 'build.gradle', 'requirements.txt', 'package.json',
                         'Dockerfile', 'docker-compose.yml', 'application.properties',
                         'application.yml', 'web.config', '.htaccess', 'settings.py',
                         'config.py', 'app.yaml', 'gunicorn.conf.py']:
                    config_files.append(os.path.join(rel_path, f))

        self.project_info.source_dirs = list(set(source_dirs))
        self.project_info.test_dirs = list(set(test_dirs))
        self.project_info.config_files = config_files

    def _detect_tech_stack(self):
        """识别技术栈"""
        path = self.project_path

        # 检测语言
        if (path / 'pom.xml').exists() or (path / 'build.gradle').exists():
            self.project_info.language = 'java'
            self.project_info.build_tool = 'maven' if (path / 'pom.xml').exists() else 'gradle'
        elif (path / 'requirements.txt').exists() or (path / 'setup.py').exists():
            self.project_info.language = 'python'
        elif (path / 'package.json').exists():
            self.project_info.language = 'javascript'
        elif (path / 'go.mod').exists():
            self.project_info.language = 'go'

        # 检测框架
        if self._contains_file('spring', ['pom.xml', 'build.gradle']):
            self.project_info.framework = 'spring'
        elif self._contains_file('django', ['requirements.txt', 'settings.py']):
            self.project_info.framework = 'django'
        elif self._contains_file('flask', ['requirements.txt', 'app.py']):
            self.project_info.framework = 'flask'
        elif self._contains_file('express', ['package.json']):
            self.project_info.framework = 'express'

    def _contains_file(self, keyword: str, filenames: List[str]) -> bool:
        """检查指定文件中是否存在关键字"""
        for root, dirs, files in self._walk_project():
            for f in files:
                if not any(f == fn or f.endswith(fn) for fn in filenames):
                    continue
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                        if keyword.lower() in file.read().lower():
                            return True
                except OSError:
                    continue
        return False

    def _analyze_dependencies(self):
        """分析依赖"""
        deps = {}
        dep_files = []

        # Maven
        pom = self.project_path / 'pom.xml'
        if pom.exists():
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(pom)
                root = tree.getroot()
                ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
                for dep in root.findall('.//m:dependency', ns):
                    art = dep.find('m:artifactId', ns)
                    ver = dep.find('m:version', ns)
                    if art is not None:
                        deps[art.text] = ver.text if ver is not None else 'unknown'
                dep_files.append('pom.xml')
            except:
                pass

        # Python
        req = self.project_path / 'requirements.txt'
        if req.exists():
            try:
                with open(req, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '==' in line:
                                name, ver = line.split('==')
                                deps[name.strip()] = ver.strip()
                            else:
                                deps[line] = 'latest'
                dep_files.append('requirements.txt')
            except:
                pass

        # JavaScript
        pkg = self.project_path / 'package.json'
        if pkg.exists():
            try:
                with open(pkg, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    deps.update(data.get('dependencies', {}))
                    deps.update(data.get('devDependencies', {}))
                dep_files.append('package.json')
            except:
                pass

        self.project_info.dependencies = deps
        self.project_info.dependency_files = dep_files

    def _extract_entry_points(self):
        """提取入口点"""
        http_routes = []
        entry_points = []

        # Java Spring 路由
        self._extract_java_routes(http_routes, entry_points)

        # Python Flask/Django 路由
        self._extract_python_routes(http_routes, entry_points)

        # JavaScript Express 路由
        self._extract_js_routes(http_routes, entry_points)

        self.project_info.http_routes = http_routes
        self.project_info.entry_points = entry_points

    def _extract_java_routes(self, http_routes: List, entry_points: List):
        """提取Java Spring路由"""
        annotations = ['@RequestMapping', '@PostMapping', '@GetMapping',
                     '@PutMapping', '@DeleteMapping', '@PatchMapping']

        for root, dirs, files in self._walk_project():
            dirs[:] = [d for d in dirs if d not in ['target', 'test', 'node_modules']]

            for f in files:
                if not f.endswith('.java'):
                    continue

                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r', encoding='utf-8') as file:
                        content = file.read()
                        lines = content.split('\n')

                        for i, line in enumerate(lines, 1):
                            for ann in annotations:
                                if ann in line:
                                    # 提取路由路径
                                    path_match = re.search(r'\(\s*["\']([^"\']+)["\']\s*\)', line)
                                    path = path_match.group(1) if path_match else '/'

                                    # 提取HTTP方法
                                    method = 'GET'
                                    if 'PostMapping' in ann:
                                        method = 'POST'
                                    elif 'GetMapping' in ann:
                                        method = 'GET'
                                    elif 'PutMapping' in ann:
                                        method = 'PUT'
                                    elif 'DeleteMapping' in ann:
                                        method = 'DELETE'

                                    http_routes.append({
                                        'file': os.path.relpath(filepath, self.project_path),
                                        'line': i,
                                        'path': path,
                                        'method': method,
                                        'annotation': ann
                                    })
                except:
                    pass

    def _extract_python_routes(self, http_routes: List, entry_points: List):
        """提取Python Flask/Django路由"""
        for root, dirs, files in self._walk_project():
            dirs[:] = [d for d in dirs if d not in ['venv', 'env', '__pycache__', '.git']]

            for f in files:
                if not f.endswith('.py'):
                    continue

                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r', encoding='utf-8') as file:
                        content = file.read()
                        lines = content.split('\n')

                        # Flask路由
                        flask_pattern = r'@app\.route\(["\']([^"\']+)["\']'

                        for i, line in enumerate(lines, 1):
                            match = re.search(flask_pattern, line)
                            if match:
                                path = match.group(1)
                                http_routes.append({
                                    'file': os.path.relpath(filepath, self.project_path),
                                    'line': i,
                                    'path': path,
                                    'method': 'GET',
                                    'framework': 'flask'
                                })

                            # Django路由
                            if 'path(' in line or 're_path(' in line:
                                entry_points.append({
                                    'file': os.path.relpath(filepath, self.project_path),
                                    'line': i,
                                    'code': line.strip()
                                })
                except:
                    pass

    def _extract_js_routes(self, http_routes: List, entry_points: List):
        """提取JavaScript Express路由"""
        for root, dirs, files in self._walk_project():
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'dist']]

            for f in files:
                if not f.endswith('.js'):
                    continue

                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r', encoding='utf-8') as file:
                        content = file.read()
                        lines = content.split('\n')

                        express_patterns = [
                            r'app\.(get|post|put|delete|patch)\((["\'])([^"\']+)\2',
                            r'router\.(get|post|put|delete|patch)\((["\'])([^"\']+)\2'
                        ]

                        for i, line in enumerate(lines, 1):
                            for pattern in express_patterns:
                                match = re.search(pattern, line)
                                if match:
                                    method = match.group(1).upper()
                                    path = match.group(3)
                                    http_routes.append({
                                        'file': os.path.relpath(filepath, self.project_path),
                                        'line': i,
                                        'path': path,
                                        'method': method,
                                        'framework': 'express'
                                    })
                except:
                    pass

    def _analyze_data_flow(self):
        """分析数据流"""
        user_inputs = []
        db_queries = []
        external_calls = []

        # 扫描所有源代码文件
        for root, dirs, files in self._walk_project():
            dirs[:] = [d for d in dirs if d not in ['test', 'venv', 'node_modules', 'target']]

            for f in files:
                if not (f.endswith('.java') or f.endswith('.py') or f.endswith('.js')):
                    continue

                filepath = os.path.join(root, f)
                rel_path = os.path.relpath(filepath, self.project_path)

                try:
                    with open(filepath, 'r', encoding='utf-8') as file:
                        content = file.read()
                        lines = content.split('\n')

                        for i, line in enumerate(lines, 1):
                            # 用户输入点
                            if any(kw in line for kw in ['request.getParameter', 'request.getHeader',
                                                          '@RequestParam', '@RequestBody',
                                                          'request.args.get', 'request.form.get']):
                                user_inputs.append({
                                    'file': rel_path,
                                    'line': i,
                                    'code': line.strip(),
                                    'type': 'http_input'
                                })

                            # 数据库查询
                            if any(kw in line for kw in ['executeQuery', 'createStatement',
                                                          'PreparedStatement', 'cursor.execute',
                                                          'Model.objects', 'db.execute']):
                                db_queries.append({
                                    'file': rel_path,
                                    'line': i,
                                    'code': line.strip(),
                                    'type': 'db_query'
                                })

                            # 外部调用
                            if any(kw in line for kw in ['HttpURLConnection', 'URLConnection',
                                                          'requests.get', 'requests.post',
                                                          'fetch(', 'axios.', 'openConnection']):
                                external_calls.append({
                                    'file': rel_path,
                                    'line': i,
                                    'code': line.strip(),
                                    'type': 'external_call'
                                })
                except:
                    pass

        self.project_info.user_inputs = user_inputs
        self.project_info.db_queries = db_queries
        self.project_info.external_calls = external_calls

    def _analyze_security_configs(self):
        """分析安全配置"""
        configs = {}

        # 检查常见配置文件
        config_files = {
            'application.properties': self._parse_properties,
            'application.yml': self._parse_yaml,
            'application.yaml': self._parse_yaml,
            'security.yml': self._parse_yaml,
            'applicationContext.xml': self._parse_xml
        }

        for root, dirs, files in self._walk_project():
            for f in files:
                if f in config_files:
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as file:
                            content = file.read()
                            parse_func = config_files[f]
                            parsed = parse_func(content)
                            configs[f] = parsed
                    except:
                        pass

        self.project_info.security_configs = configs

    def _parse_properties(self, content: str) -> Dict:
        """解析properties文件"""
        result = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                result[k.strip()] = v.strip()
        return result

    def _parse_yaml(self, content: str) -> Dict:
        """解析YAML文件"""
        try:
            return yaml.safe_load(content) or {}
        except:
            return {}

    def _parse_xml(self, content: str) -> Dict:
        """解析XML文件"""
        try:
            import xml.etree.ElementTree as ET
            return {'xml_parsed': True}
        except:
            return {}

    def get_summary(self) -> Dict:
        """获取信息收集摘要"""
        return {
            'project_name': self.project_info.name,
            'language': self.project_info.language,
            'framework': self.project_info.framework,
            'source_dirs_count': len(self.project_info.source_dirs),
            'dependencies_count': len(self.project_info.dependencies),
            'http_routes_count': len(self.project_info.http_routes),
            'entry_points_count': len(self.project_info.entry_points),
            'user_inputs_count': len(self.project_info.user_inputs),
            'security_configs_count': len(self.project_info.security_configs)
        }
