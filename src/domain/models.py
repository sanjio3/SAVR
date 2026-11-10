from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SUSPENDED = "suspended"


@dataclass
class Workspace:
    id: Optional[int]
    name: str
    target_path: str
    description: str = ""
    settings: Dict[str, Any] = field(default_factory=dict)
    archived: bool = False
    slug: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanTask:
    id: Optional[int]
    workspace_id: int
    name: str
    status: TaskStatus = TaskStatus.PENDING
    phase: str = "pending"
    output_dir: str = ""
    options: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: str = ""
    finished_at: str = ""


@dataclass
class TaskEvent:
    id: Optional[int]
    task_id: int
    event_type: str
    payload: Dict[str, Any]
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ReportRecord:
    id: Optional[int]
    task_id: int
    workspace_id: int
    report_type: str
    file_path: str
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class FindingRecord:
    id: Optional[int]
    task_id: int
    workspace_id: int
    finding_type: str
    severity: str
    file_path: str
    line: int
    title: str
    raw: Dict[str, Any]
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # 2026-09-15 item 3：SCA 命名空间从 finding_type 剥离。组件名/编号拆到独立列，
    # finding_type 仅留族名 "sca"。老行（迁移前）这两列默认空串，读路径须容错缺列。
    sca_component: str = ""
    sca_advisory_id: str = ""
