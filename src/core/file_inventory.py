"""
Shared file inventory and ignore rules for scan/recon stages.
"""
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set
import os

from .config import config


DEFAULT_SKIP_DIRS: Set[str] = {
    "test",
    "tests",
    "__test__",
    "pytest",
    "target",
    "build",
    "dist",
    "out",
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "bower_components",
    "vendor",
    ".idea",
    ".vscode",
    ".eclipse",
    "venv",
    ".venv",
    "env",
    ".env",
    "min",
    "minified",
    "assets",
    "docs",
    "doc",
    "examples",
    "sample",
    "__pycache__",
    "output",
    "data/samples",
    ".d2-runtime",
    ".docker-local",
    ".codex-docker",
}

DEFAULT_SKIP_PREFIXES: Sequence[str] = (
    ".d2-",
    # CodeQL 建库目录（.codeql-db）。建库时 CodeQL 会把源码复制一份进数据库目录，
    # 若不排除，第二次扫描会把这份副本当成源码再扫一遍——实测 OWASP Benchmark 重扫时
    # SQL 注入 17→34、XXE 8→16、命令注入 8→16 全部精确翻倍，对账结果完全失真。
    ".codeql",
)

DEFAULT_SKIP_FILE_NAMES: Set[str] = {
    "payload.b64",
    "payload.base64",
    "payload.bin",
    "payload.ser",
    "payload.txt",
    "payload2.b64",
    "payload2.base64",
    "payload3.txt",
    "payload_cc1.b64",
    "payload_cc2.b64",
    "payload_cc3.ser",
    "poc.b64",
    "poc.ser",
    "cmd_payload.txt",
}

DEFAULT_SKIP_SUFFIXES: Sequence[str] = (
    ".pyc",
    ".class",
    ".jar",
)


def load_skip_dirs(extra_skip_dirs: Optional[Iterable[str]] = None) -> Set[str]:
    configured = config.get("scan.skip_dirs", []) or []
    values = {str(item).strip() for item in configured if str(item).strip()}
    values.update(DEFAULT_SKIP_DIRS)
    if extra_skip_dirs:
        values.update({str(item).strip() for item in extra_skip_dirs if str(item).strip()})
    return values


def should_skip_dir(name: str, skip_dirs: Optional[Set[str]] = None) -> bool:
    skip_dirs = skip_dirs or load_skip_dirs()
    if name in skip_dirs:
        return True
    return any(name.startswith(prefix) for prefix in DEFAULT_SKIP_PREFIXES)


def should_skip_file(path: Path) -> bool:
    name = path.name
    if name in DEFAULT_SKIP_FILE_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in DEFAULT_SKIP_SUFFIXES)


def iter_files(
    target_path: Path,
    extensions: Optional[Set[str]] = None,
    skip_dirs: Optional[Set[str]] = None,
) -> Iterator[Path]:
    effective_skip_dirs = skip_dirs or load_skip_dirs()
    for root, dirs, filenames in os.walk(target_path):
        skipped_here = [d for d in dirs if should_skip_dir(d, effective_skip_dirs)]
        dirs[:] = [d for d in dirs if d not in skipped_here]
        for filename in filenames:
            filepath = Path(root) / filename
            if should_skip_file(filepath):
                continue
            if extensions and filepath.suffix.lower() not in extensions:
                continue
            yield filepath


def summarize_tree(
    target_path: Path,
    extensions: Optional[Set[str]] = None,
    skip_dirs: Optional[Set[str]] = None,
) -> Dict[str, List[str]]:
    files = []
    for filepath in iter_files(target_path, extensions=extensions, skip_dirs=skip_dirs):
        try:
            files.append(str(filepath.relative_to(target_path)))
        except ValueError:
            files.append(str(filepath))
    return {"files": files}
