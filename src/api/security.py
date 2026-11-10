"""API authentication, RBAC, and audit logging.

Design goals:
* **Safe by default for local/dev and tests**: when ``SAST_AI_AUTH_ENABLED`` is not
  truthy, every request is treated as the built-in ``admin`` principal, so existing
  behaviour and tests are unchanged.
* **Production-ready when enabled**: set ``SAST_AI_AUTH_ENABLED=1`` and provide API
  keys via ``SAST_AI_API_KEYS`` (JSON mapping ``{"<key>": "<role>"}``). Requests must
  then present ``X-API-Key`` or ``Authorization: Bearer <key>``. Roles gate endpoints
  through :func:`require_role`.
* **Auditable**: :class:`AuditMiddleware` appends every mutating request to ``audit_log``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Optional

from fastapi import Depends, Header, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

ROLE_ADMIN = "admin"
ROLE_REVIEWER = "reviewer"
ROLE_VIEWER = "viewer"
_ROLE_RANK = {ROLE_VIEWER: 1, ROLE_REVIEWER: 2, ROLE_ADMIN: 3}


@dataclass
class Principal:
    actor: str
    role: str


def _auth_enabled() -> bool:
    return os.environ.get("SAST_AI_AUTH_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def _api_keys() -> Dict[str, str]:
    raw = os.environ.get("SAST_AI_API_KEYS", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return {str(key): str(role) for key, role in data.items()} if isinstance(data, dict) else {}


def _extract_key(x_api_key: Optional[str], authorization: Optional[str]) -> str:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def current_principal(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> Principal:
    if not _auth_enabled():
        return Principal(actor="local", role=ROLE_ADMIN)
    key = _extract_key(x_api_key, authorization)
    role = _api_keys().get(key, "")
    if not role:
        raise HTTPException(status_code=401, detail="missing or invalid API key")
    return Principal(actor=key[:8] + "...", role=role)


def require_role(minimum: str):
    """Return a dependency enforcing that the principal's role rank >= ``minimum``."""
    required_rank = _ROLE_RANK.get(minimum, 3)

    def _dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if _ROLE_RANK.get(principal.role, 0) < required_rank:
            raise HTTPException(status_code=403, detail=f"role '{minimum}' or higher required")
        return principal

    return _dependency


class AuditMiddleware(BaseHTTPMiddleware):
    """Append mutating requests to the audit log (best-effort, never blocks the response)."""

    _MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(self, app, audit_repository_provider):
        super().__init__(app)
        self._provider = audit_repository_provider

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.method in self._MUTATING:
            try:
                principal = current_principal(
                    request.headers.get("x-api-key"), request.headers.get("authorization")
                )
                actor, role = principal.actor, principal.role
            except HTTPException:
                actor, role = "anonymous", ""
            try:
                self._provider().add(
                    actor=actor, role=role, action="http_request", method=request.method,
                    path=request.url.path, status_code=response.status_code,
                )
            except Exception:  # pragma: no cover - audit must never break the request
                pass
        return response
