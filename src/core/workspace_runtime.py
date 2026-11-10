"""
Per-workspace runtime overrides（靶场专属路由 / 标记 / 镜像 / 探针类名 / JDK 路径 / 端点表）。

背景：扫描引擎长期被两个互斥靶场（java-quote、target-mall）的硬编码对照表污染——
java-quote 的 /debug/import、/api/quote/random、setQuoteCache 标记散落在 report_manager /
a2 / d2 / endpoints.yaml；target-mall 的 sink→路由兜底表散落在 param_resolver。新靶场接入时
若继续往核心塞对照表，会系统性污染其他靶场。

本模块是唯一的收口点：所有「靶场专属」值都从这里读。默认值 = 历史上硬编码的并集（保证不配置时
行为与旧代码完全一致）；每个 workspace 可在 settings.workspace_runtime_config 里覆盖自己的值，
从而把污染从「核心代码」移到「workspace 配置」。扫描子进程启动时由 scan_task_runner 从
workspace.settings 装载一次（见 set_runtime）。

设计约束：
- 不依赖任何 workspace 对象，纯模块级单例，便于纯函数（param_resolver / gadget_builder）直接读。
- 路径归一化（canonical_group_key 去绝对前缀）依赖 code_root，由 set_runtime(code_root=...) 注入。
"""
import os
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 默认值 = 历史上硬编码的并集（保证未配置 workspace 时行为不变）；
# 其中本机绝对路径类配置已改为环境变量驱动，见下方 jdk_candidates 注释
# ---------------------------------------------------------------------------
_DEFAULT_DESERIALIZATION_MARKERS = [
    'objectinputstream', 'readobject', 'setquotecache', 'cacheprocessor', 'debugcontroller',
    '/debug/import', '/api/quote/random', 'process(userconfig)',
    'importconfig', 'processor.process', 'transformer', 'transformedmap', 'commons-collections',
]

# REANCHOR_PATTERNS['deserialization'] 的原始默认值（a2_intelligent_agent.py:34-48）
_DEFAULT_REANCHOR_DESERIALIZATION = [
    (r'\breadObject\s*\(', 12),
    (r'\bObjectInputStream\b', 11),
    (r'\bXMLDecoder\b', 11),
    (r'\.transform\s*\(', 10),
    (r'\.put\s*\(', 9),
    (r'\bputAll\s*\(', 9),
    (r'process\s*\(\s*userConfig\s*\)', 10),
    (r'setQuoteCache\s*\(', 8),
    (r'\bTransformedMap\b', 9),
    (r'\bTransformer\b', 8),
    (r'\bcommons-collections\b', 7),
    (r'applyTransformer\s*\(', 6),
    (r'decoratedMap', 6),
]

_DEFAULTS: Dict[str, Any] = {
    # —— 反序列化链（java-quote 专属，但作为默认兜底）——
    "deserialization_chain": {
        "markers": list(_DEFAULT_DESERIALIZATION_MARKERS),
        "reanchor_patterns": list(_DEFAULT_REANCHOR_DESERIALIZATION),
        "entry_route": "/debug/import",
        "trigger_route": "/api/quote/random",
        "import_path": "/debug/import",
        "trigger_path": "/api/quote/random",
        "probe_path": "/api/quote/random",
        "image": "java-quote-ctf:latest",
        "chain_id_prefix": "deserialization:project_chain",
    },
    # —— sink 文件 → 真实业务入口（target-mall 专属，但作为默认兜底）——
    "sink_file_route_overrides": {
        "DeserializeUtil": [
            {"route": "/profile/import", "method": "POST", "param": "data", "location": "body"},
        ],
        "XmlImporter": [
            {"route": "/order/import-xml", "method": "POST", "param": "xml", "location": "body"},
        ],
        "HttpFetcher": [
            {"route": "/profile/avatar-from-url", "method": "POST", "param": "url", "location": "query"},
            {"route": "/admin/fetch", "method": "POST", "param": "url", "location": "query"},
        ],
        "UserMapper": [
            {"route": "/login", "method": "POST", "param": "username", "location": "body"},
        ],
        "ProductMapper": [
            {"route": "/products", "method": "GET", "param": "keyword", "location": "query"},
            {"route": "/api/products/sort", "method": "GET", "param": "sort", "location": "query"},
            {"route": "/api/products/by-category", "method": "GET", "param": "category", "location": "query"},
        ],
        "CouponMapper": [
            {"route": "/coupons", "method": "GET", "param": "keyword", "location": "query"},
        ],
        "JdbcReportDao": [
            {"route": "/admin/report", "method": "GET", "param": "status", "location": "query"},
            {"route": "/api/products/by-category", "method": "GET", "param": "category", "location": "query"},
        ],
        "CmdUtil": [
            {"route": "/admin/ping", "method": "GET", "param": "host", "location": "query"},
        ],
        "ProductController": [
            {"route": "/products", "method": "GET", "param": "keyword", "location": "query"},
            {"route": "/api/products/sort", "method": "GET", "param": "sort", "location": "query"},
            {"route": "/api/products/by-category", "method": "GET", "param": "category", "location": "query"},
        ],
        "HomeController": [
            {"route": "/login", "method": "POST", "param": "username", "location": "body"},
        ],
    },
    # —— sink 族 → 真实业务入口（target-mall 专属，作为默认兜底）——
    "sink_family_route_overrides": {
        "deserialization": [
            {"route": "/profile/import", "method": "POST", "param": "data", "location": "body"},
        ],
        "xxe": [
            {"route": "/order/import-xml", "method": "POST", "param": "xml", "location": "body"},
        ],
        "ssrf": [
            {"route": "/profile/avatar-from-url", "method": "POST", "param": "url", "location": "query"},
            {"route": "/admin/fetch", "method": "GET", "param": "url", "location": "query"},
        ],
        "command-execution": [
            {"route": "/admin/ping", "method": "GET", "param": "host", "location": "query"},
        ],
        "path-traversal": [
            {"route": "/order/invoice", "method": "GET", "param": "id", "location": "query"},
        ],
    },
    # —— 探针噪声过滤（target-mall 专属 FrameworkProbeController）——
    "probe_class_names": ["FrameworkProbeController", "ProbeController", "sec-probe", "fw/"],
    "probe_controller_markers": [
        "FrameworkProbeController", "ProbeController", "HealthProbeController",
        "DebugController", "FrameworkDebugController",
    ],
    "probe_route_prefixes": ["/api/fw/", "/fw/", "/actuator/", "/probe/"],
    # —— 反序列化验证镜像 / 镜像别名 / 优先级（java-quote 专属，作为默认兜底）——
    "images": ["java-quote-ctf:latest", "sast-target:latest"],
    "image_alias": {
        "ctf-java-quote": ["java-quote-ctf:latest", "sast-target:latest"],
        "java-quote": ["java-quote-ctf:latest", "sast-target:latest"],
        "python": ["python:latest", "sast-target:latest"],
    },
    "image_priority": {
        "java-quote-ctf:latest": 0,
        "sast-target:latest": 1,
        "test-java:latest": 2,
    },
    # —— gadget 构造用 JDK 根 ——
    # 2026-11-06 开源 P0：本机绝对路径不再进仓库。由 SAST_AI_JDK_CANDIDATES
    # （os.pathsep 分隔）或 workspace 的 workspace_runtime_config 提供；未配置时为空，
    # 由 a1_codeql_adapter 的跨平台 JDK 扫描兜底。
    "jdk_candidates": [p for p in os.environ.get(
        "SAST_AI_JDK_CANDIDATES", "").split(os.pathsep) if p],
    # —— 可选：覆盖 endpoints.yaml 的端点（per-workspace）——
    "endpoints": None,
}


# ---------------------------------------------------------------------------
# 模块级单例状态
# ---------------------------------------------------------------------------
_current: Dict[str, Any] = dict(_DEFAULTS)
_code_root: Optional[str] = None


def set_runtime(cfg: Optional[Dict[str, Any]] = None, code_root: Optional[str] = None) -> None:
    """装载某 workspace 的运行时配置。

    cfg 来自 workspace.settings['workspace_runtime_config']（自由 JSON，键同 _DEFAULTS）。
    未提供的键保留默认；code_root 用于 canonical_group_key 路径归一化。
    """
    global _current, _code_root
    _current = dict(_DEFAULTS)
    if isinstance(cfg, dict):
        for key, val in cfg.items():
            if val is None:
                continue
            if isinstance(val, dict) and isinstance(_current.get(key), dict):
                merged = dict(_current[key])
                merged.update(val)
                _current[key] = merged
            else:
                _current[key] = val
    if code_root:
        _code_root = str(code_root)


def reset_runtime() -> None:
    """恢复默认（测试 / 无 workspace 上下文时使用）。"""
    global _current, _code_root
    _current = dict(_DEFAULTS)
    _code_root = None


def raw() -> Dict[str, Any]:
    return _current


def get(key: str, default: Any = None) -> Any:
    return _current.get(key, default)


# —— 语义化访问器（站点按需调用，避免散落 dict 取值）——
def deserialization_chain() -> Dict[str, Any]:
    return _current.get("deserialization_chain", {})


def sink_file_route_overrides() -> Dict[str, Any]:
    return _current.get("sink_file_route_overrides", {})


def sink_family_route_overrides() -> Dict[str, Any]:
    return _current.get("sink_family_route_overrides", {})


def probe_class_names() -> List[str]:
    return list(_current.get("probe_class_names", []))


def probe_controller_markers() -> List[str]:
    return list(_current.get("probe_controller_markers", []))


def probe_route_prefixes() -> List[str]:
    return list(_current.get("probe_route_prefixes", []))


def images() -> List[str]:
    return list(_current.get("images", []))


def image_alias() -> Dict[str, List[str]]:
    return _current.get("image_alias", {})


def image_priority() -> Dict[str, int]:
    return _current.get("image_priority", {})


def jdk_candidates() -> List[str]:
    return list(_current.get("jdk_candidates", []))


def endpoints_override() -> Optional[Dict[str, Any]]:
    return _current.get("endpoints")


def normalize_group_key_path(file: str) -> str:
    """canonical_group_key 路径归一化（第 8 类）：去掉 workspace 绝对前缀，避免换机/换工作区失配。

    若 file 是绝对路径且位于 code_root 下，返回相对 code_root 的路径；否则原样返回。
    """
    if not file or not _code_root:
        return file
    import os
    f = str(file)
    root = _code_root.rstrip("/\\")
    # Windows / POSIX 路径分隔符统一比较
    norm_f = f.replace("\\", "/")
    norm_root = root.replace("\\", "/").rstrip("/")
    if norm_f.startswith(norm_root + "/") or norm_f == norm_root:
        rel = os.path.relpath(f, root)
        return rel.replace("\\", "/")
    return f
