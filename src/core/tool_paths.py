from pathlib import Path
from typing import List, Optional
import os
import shutil


def get_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def get_external_tools_dir() -> Optional[Path]:
    """外部工具目录：第三方二进制不入库。

    通过 ``SAST_AI_TOOLS_DIR`` 指定；未设置返回 None。
    解析顺序见 ``candidate_tool_paths``：外部目录优先，仓库内路径保留兼容。
    """
    raw = (os.environ.get("SAST_AI_TOOLS_DIR") or "").strip()
    return Path(raw) if raw else None


def get_d2_resources_dir() -> Path:
    return get_repo_root() / "src" / "pipeline" / "d2" / "resources"


def get_tools_dir() -> Path:
    return get_d2_resources_dir() / "tools"


def get_skills_dir() -> Path:
    """Agent 本地知识文档目录（SKILL.md/references/scripts），**不是**运行时检测 Skill。

    运行时检测能力的 Skill（规则表达式 + 提示词片段，带 status/golden/gate）在
    ``get_rules_dir``（src/config/rules/*.yaml），由 core/rule_registry 消费。
    两者概念不同，勿混用。本函数保留供未来 Agent 知识加载使用（当前无调用方）。
    """
    return get_repo_root() / "src" / "agents" / "resources" / "skills"


def get_rules_dir() -> Path:
    """运行时检测 Skill（规则单元）目录：src/config/rules/*.yaml，由 rule_registry 消费。"""
    return get_repo_root() / "src" / "config" / "rules"


def get_exploits_dir() -> Path:
    return get_tools_dir() / "exploits"


def get_java_tools_dir() -> Path:
    return get_tools_dir() / "java"


def get_runtime_config_dir() -> Path:
    return get_repo_root() / "src" / "config" / "runtime"


def candidate_tool_paths(filename: str) -> List[Path]:
    repo_root = get_repo_root()
    tools_dir = get_tools_dir()
    candidates: List[Path] = []
    # 外部工具目录优先（开源场景：第三方二进制不入库，由 scripts/fetch_tools.py 下载）
    external = get_external_tools_dir()
    if external is not None:
        candidates.append(external / filename)
    candidates.extend([
        repo_root / filename,
        tools_dir / filename,
        repo_root / "lib" / filename,
    ])
    return candidates


def find_existing_tool(*filenames: str) -> Optional[Path]:
    for filename in filenames:
        for candidate in candidate_tool_paths(filename):
            if candidate.exists():
                return candidate
    return None


def find_ysoserial_jar() -> Optional[Path]:
    return find_existing_tool("ysoserial-all.jar", "ysoserial.jar")


def find_codeql() -> Optional[Path]:
    """Locate the CodeQL CLI without any machine-specific configuration.

    Search order: ``SAST_AI_TOOLS_DIR/codeql``, then ``tools/codeql`` inside the
    repository (where ``scripts/fetch_tools.py --only codeql`` unpacks the
    bundle), then ``PATH``. An explicit ``CODEQL_BIN`` is handled by
    ``src.core.config_registry`` before this function is reached, so a stale
    environment value can never shadow a working install here.

    Returns None when nothing is found; callers must degrade explicitly and
    record the reason rather than silently producing an empty report.
    """
    exe_names = ("codeql.exe", "codeql")
    roots: List[Path] = []
    external = get_external_tools_dir()
    if external is not None:
        roots.append(external / "codeql")
    roots.append(get_repo_root() / "tools" / "codeql")
    for root in roots:
        for name in exe_names:
            candidate = root / name
            if candidate.is_file():
                return candidate
        # Some bundles keep an extra nesting level: codeql/codeql/codeql.
        for name in exe_names:
            nested = root / "codeql" / name
            if nested.is_file():
                return nested
    found = shutil.which("codeql")
    return Path(found) if found else None


def find_java_decompiler_jar(extra_search_dirs: Optional[List[Path]] = None) -> Optional[Path]:
    candidates = ["cfr-0.152.jar", "cfr.jar"]
    search_dirs = [Path(path) for path in (extra_search_dirs or []) if path]
    for directory in search_dirs:
        for name in candidates:
            candidate = directory / name
            if candidate.exists():
                return candidate
    return find_existing_tool(*candidates)


# --- 黑盒工具（nuclei / ffuf / feroxbuster）---
# **当前无任何调用方**，仅保留待后续复用（用户决定何时接入、接哪个阶段）。
# 复用时的硬约束（沿用原 ED 阶段的边界要求）：
#   * **禁止用于 D1**：D1 只按 A2 攻击计划（trigger_spec）严格执行重放，不得自行 fuzz、
#     不得自行变异参数。
#   * 工具未安装时返回 None，调用方须按 skipped 处理，不得阻断流水线。


def find_nuclei() -> Optional[Path]:
    """基于模板的漏洞扫描器（CVE/误配置/技术指纹）。返回 nuclei.exe 路径，未安装返回 None。

    当前无调用方，保留待后续复用。"""
    return find_existing_tool("nuclei.exe", "nuclei")


def find_ffuf() -> Optional[Path]:
    """Web 模糊测试（目录/路由/参数发现）。返回 ffuf.exe 路径，未安装则返回 None。

    当前无调用方，保留待后续复用。"""
    return find_existing_tool("ffuf.exe", "ffuf")


def find_feroxbuster() -> Optional[Path]:
    """内容/目录发现（递归爆破）。返回 feroxbuster.exe 路径，未安装则返回 None。

    当前无调用方，保留待后续复用。"""
    return find_existing_tool("feroxbuster.exe", "feroxbuster")
