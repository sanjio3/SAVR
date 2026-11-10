"""
IAST 路径上的目标描述符。

重构文档 3.4：EnvPrep / A2.9 与 PreparedRuntime(Docker 模型) 已整体退役（本平台不再准备或执行运行时）。
取而代之的是 ExternalTarget —— 仅描述一个「外部常驻、用户自挂探针」的目标，SAVR 拿到即视为可用，
登记后即可驱动 DAST 发触发请求、接收 IAST 事件。不再有任何「准备 / 就绪」状态机。
"""
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ExternalTarget:
    service_url: str = ""
    app_name: str = ""
    agent_id: str = ""
    probe_mode: str = "monitor"  # 固定 monitor-only，探针只观测不阻断
    auth_context: Dict[str, Any] = field(default_factory=dict)
    code_path: str = ""
    # Point3 auth bootstrap：业务逻辑差分重放所需的登录配置与预置账户。
    # login 由 workspace / external_target 提供（平台不内置任何凭据）；bootstrap_accounts
    # 据此真登录取 token。accounts 为已解析好的 attacker/victim（优先于 login）。
    login: Dict[str, Any] = field(default_factory=dict)
    accounts: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_registered(self) -> bool:
        return bool(self.service_url and self.app_name and self.agent_id)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_external_target(target: Optional[Dict[str, Any]]) -> ExternalTarget:
    if isinstance(target, ExternalTarget):
        return target
    payload = dict(target or {})
    # 2026-11-02：`auth` 与 `login` 是同一件事的两种写法（workspace settings 新写法用
    # `auth`，早期注册器用 `login`）。这里只认 `login`，导致 `auth` 写法在归一化时被丢掉
    # ⇒ D1 判定「没配登录」⇒ 重放全程未认证。实测 本轮（若依）：523 条重放里 476 条 302，
    # 105 条 vertical_privesc 全部 no-iast-evidence。故 `login` 为空时用 `auth` 顶上。
    _login = dict(payload.get("login", {}) or {})
    if not _login and isinstance(payload.get("auth"), dict):
        _login = dict(payload["auth"])
    return ExternalTarget(
        service_url=str(payload.get("service_url", "") or ""),
        app_name=str(payload.get("app_name", "") or ""),
        agent_id=str(payload.get("agent_id", "") or ""),
        probe_mode=str(payload.get("probe_mode", "monitor") or "monitor"),
        auth_context=dict(payload.get("auth_context", {}) or {}),
        code_path=str(payload.get("code_path", "") or ""),
        login=_login,
        accounts=dict(payload.get("accounts", {}) or {}),
    )
