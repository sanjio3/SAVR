"""IAST 模块 Pydantic 模型：会话注册、事件摄取信封、TriggerSpec 投影。

字段依据：3.8.1 TriggerSpec 字段表、3.10 前端表单、3.15 摄取端点契约。
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---- 会话注册（3.10 / 3.19）----
class IastSessionRegister(BaseModel):
    target_url: str
    code_path: str = ""
    app_name: str
    agent_id: str
    workspace_id: Optional[int] = None  # 显式绑定；缺省按 code_path 主键自动建
    probe_mode: str = "iast"
    probe_packages: str = "com.example"
    server_port: int = 8899  # 目标项目监听端口，挂载命令据此生成 -Dserver.port
    java_path: str = ""  # 方案 4：挂载命令所用 JDK 的 java 可执行文件路径
    settings: Dict[str, Any] = Field(default_factory=dict)  # {phase2_enabled, whitelist, flush_period_sec}


class IastSessionResponse(BaseModel):
    id: int
    workspace_id: int
    app_name: str
    agent_id: str
    target_url: str
    code_path: str
    probe_mode: str
    probe_packages: str = ""
    server_port: int = 8899
    status: str
    agent_phase: str = "unknown"  # 方案 3：探针阶段 WARMING_UP / READY
    java_path: str = ""  # 方案 4：挂载命令所用 JDK 的 java 可执行文件路径
    last_heartbeat_at: str = ""
    probe_token: str  # 仅注册时返回一次
    registered_at: str


# ---- 事件摄取信封（3.15）----
class IastEventItem(BaseModel):
    eventType: str = "sink_call"  # sink_call | canary_observed
    vulnType: str = ""
    traceId: str = ""
    canary: str = ""
    sink: Dict[str, Any] = Field(default_factory=dict)  # {file, line, method}
    source: Dict[str, Any] = Field(default_factory=dict)  # {name, type, value}
    principal: str = ""
    severity: str = "INFO"
    stackTrace: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    # 注：原 request_observed 事件的 route/method/params 字段随 iast_request_params 表


class IastEventIngest(BaseModel):
    agentId: str
    appName: str
    environment: Optional[Dict[str, Any]] = None
    events: List[IastEventItem] = Field(default_factory=list)


class IastEventIngestResponse(BaseModel):
    accepted: int
    rejected: int
    session_id: Optional[int] = None
    errors: List[str] = Field(default_factory=list)


# ---- TriggerSpec 投影（3.8.1，A2 产出，I1 匹配用）----
class TriggerSpecRegister(BaseModel):
    workspace_id: int
    session_id: int
    task_id: Optional[int] = None
    finding_id: Optional[int] = None
    vulnerability_hash_v2: str = ""
    family: str = ""
    target_endpoint: str = ""
    http_method: str = "GET"
    param_name: str = ""
    param_location: str = "query"  # query | header | cookie | body | path
    content_type: str = ""
    principal: str = ""
    taint_marker: str = ""  # 即 canary
    expected_sink_file: str = ""
    expected_sink_line: int = 0
    representative_request_params: List[Dict[str, Any]] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)


class TriggerSpecResponse(BaseModel):
    id: int
    vulnerability_hash_v2: str
    family: str
    taint_marker: str
    target_endpoint: str
    created_at: str
