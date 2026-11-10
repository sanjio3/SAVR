"""§4.2 环境契约（一）：版本钉死 + 启动时校验。

背景（重构文档 4.2）：
探针挂载的 jar 版本须与 SAST 分析代码版本对齐，否则 sink 行号/文件对不上
（Ctrl.java:42 指向错误位置）。因此须「版本钉死 + 启动时校验」：
- 平台侧钉死一个 SAST 分析代码版本（PINNED_SAST_CODE_VERSION）；
- 探针在注册会话（即探针启动）时上报自身 jar 版本（probe_version）；
- 注册即校验二者是否一致，结果写入 iast_sessions.version_status；
- A0 环境门禁读取 version_status，mismatch 时硬阻断 D1 发流量（否则 canary
  sink 行号错位，整条链负向结论不可信）。

校验三态：
- matched：probe_version 与钉死版本一致；
- mismatch：二者均非空且不一致（硬阻断）；
- unverified：探针未上报版本或平台未钉版本（软放行，仅记录，不阻断）。
"""
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def _pinned_sast_code_version() -> str:
    """钉死的 SAST 分析代码版本。

    优先级：环境变量 SAST_CODE_VERSION > 配置 iast.sast_code_version > 默认空（未钉死）。
    未钉死（空）时，validate_version_contract 对该维度软放行（unverified），
    绝不因平台自身未配置而误阻断真实流量。
    """
    env = os.environ.get("SAST_CODE_VERSION", "").strip()
    if env:
        return env
    try:
        from src.core.config import config as _cfg

        cfg_val = _cfg.get("iast.sast_code_version", "")
        if cfg_val:
            return str(cfg_val)
    except Exception:
        pass
    return ""


# 默认钉死版本（生产应通过环境变量覆盖此值）
DEFAULT_PINNED_SAST_CODE_VERSION = ""


VERSION_STATUS_MATCHED = "matched"
VERSION_STATUS_MISMATCH = "mismatch"
VERSION_STATUS_UNVERIFIED = "unverified"
VERSION_STATUS_UNKNOWN = "unknown"


@dataclass
class VersionContract:
    probe_version: str = ""
    sast_code_version: str = ""
    matched: bool = False
    status: str = VERSION_STATUS_UNKNOWN
    detail: Dict[str, Any] = field(default_factory=dict)

    def block_reason(self) -> str:
        if self.status == VERSION_STATUS_MISMATCH:
            return (
                f"探针版本与 SAST 分析代码版本不一致（probe={self.probe_version or '<空>'} "
                f"vs sast={self.sast_code_version or '<未钉死>'}），sink 行号/文件可能错位，"
                f"已阻断发流量（§4.2 版本钉死）"
            )
        if self.status == VERSION_STATUS_UNVERIFIED:
            return "探针未上报版本或平台未钉版本，无法校验对齐（软放行，建议补钉）"
        return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe_version": self.probe_version,
            "sast_code_version": self.sast_code_version,
            "matched": self.matched,
            "status": self.status,
            "detail": self.detail,
            "block_reason": self.block_reason(),
        }


def validate_version_contract(
    probe_version: str,
    sast_code_version: Optional[str] = None,
) -> VersionContract:
    """校验探针版本与钉死 SAST 版本是否对齐。

    - 平台未钉版本（sast_code_version 空）：status=unverified，软放行；
    - 探针未上报（probe_version 空）：status=unverified，软放行；
    - 二者均非空且相等：status=matched；
    - 二者均非空且不等：status=mismatch（硬阻断）。
    """
    if sast_code_version is None:
        sast_code_version = _pinned_sast_code_version()
    probe_version = (probe_version or "").strip()
    sast_code_version = (sast_code_version or "").strip()

    if not sast_code_version or not probe_version:
        return VersionContract(
            probe_version=probe_version,
            sast_code_version=sast_code_version,
            matched=False,
            status=VERSION_STATUS_UNVERIFIED,
            detail={"reason": "缺失任一侧版本，无法对齐校验"},
        )
    if probe_version == sast_code_version:
        return VersionContract(
            probe_version=probe_version,
            sast_code_version=sast_code_version,
            matched=True,
            status=VERSION_STATUS_MATCHED,
            detail={"reason": "探针版本与钉死 SAST 版本一致"},
        )
    return VersionContract(
        probe_version=probe_version,
        sast_code_version=sast_code_version,
        matched=False,
        status=VERSION_STATUS_MISMATCH,
        detail={"reason": "探针版本与钉死 SAST 版本不一致"},
    )
