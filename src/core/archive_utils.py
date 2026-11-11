"""
Archive helpers for uploaded workspaces and benchmark source preparation.
"""

import logging
import subprocess
import shutil
import tarfile
from pathlib import Path
from typing import List
import zipfile

try:
    import py7zr  # type: ignore
except Exception:  # pragma: no cover - optional dependency for local installs
    py7zr = None


logger = logging.getLogger(__name__)

SOURCE_FILE_EXTENSIONS = {
    ".java", ".kt", ".scala",
    ".py",
    ".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue",
    ".php", ".phtml",
    ".go",
    ".c", ".cc", ".cpp", ".h", ".hpp",
}

ARCHIVE_SUFFIXES = (
    ".zip",
    ".7z",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".gz",
)

NESTED_SOURCE_ARCHIVE_HINTS = (
    "src",
    "source",
    "project",
    "app",
    "code",
)


def _is_safe_member_path(member_name: str) -> bool:
    member_path = Path(member_name)
    return not member_path.is_absolute() and ".." not in member_path.parts


def _archive_stem(path: Path) -> str:
    name = path.name
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if name.lower().endswith(suffix):
            return name[:-len(suffix)]
    return path.stem


def is_7z_archive(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(6) == b"7z\xbc\xaf'\x1c"
    except Exception:
        return False


def is_archive_file(path: Path) -> bool:
    if not path.is_file():
        return False
    lowered = path.name.lower()
    if lowered.endswith(ARCHIVE_SUFFIXES):
        return True
    return is_7z_archive(path)


def contains_supported_source_files(root: Path) -> bool:
    for candidate in root.rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() in SOURCE_FILE_EXTENSIONS:
            return True
    return False


def extract_archive(archive_path: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    if is_7z_archive(archive_path):
        if py7zr is None:
            seven_zip = shutil.which("7z") or shutil.which("7za") or _find_windows_7z()
            if not seven_zip:
                raise RuntimeError("py7zr or 7z.exe is required to extract 7z archives")
            result = subprocess.run(
                [seven_zip, "x", str(archive_path), f"-o{destination_dir}", "-y"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=180,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "7z extraction failed")
            return destination_dir
        with py7zr.SevenZipFile(archive_path, mode="r") as archive:
            archive.extractall(path=destination_dir)
        return destination_dir

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if not _is_safe_member_path(member.filename):
                    raise ValueError(f"Unsafe archive entry detected: {member.filename}")
            archive.extractall(destination_dir)
        return destination_dir

    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as archive:
            for member in archive.getmembers():
                if not _is_safe_member_path(member.name):
                    raise ValueError(f"Unsafe archive entry detected: {member.name}")
            archive.extractall(destination_dir)
        return destination_dir

    raise ValueError(f"Unsupported archive format: {archive_path}")


def detect_project_root(extracted_dir: Path) -> Path:
    entries = [item for item in extracted_dir.iterdir() if item.name not in {"__MACOSX"}]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted_dir


def expand_nested_source_archives(root: Path, *, max_passes: int = 3) -> List[Path]:
    expanded: List[Path] = []
    for _ in range(max_passes):
        if contains_supported_source_files(root):
            break

        archive_candidates = [
            candidate
            for candidate in root.rglob("*")
            if is_archive_file(candidate)
        ]
        if not archive_candidates:
            break

        archive_candidates.sort(
            key=lambda item: (
                0 if any(hint in item.name.lower() for hint in NESTED_SOURCE_ARCHIVE_HINTS) else 1,
                len(item.parts),
                item.name.lower(),
            )
        )

        extracted_this_pass = False
        for archive_path in archive_candidates:
            destination = archive_path.parent / _archive_stem(archive_path)
            if destination.exists() and contains_supported_source_files(destination):
                expanded.append(destination)
                extracted_this_pass = True
                continue
            try:
                if destination.exists():
                    shutil.rmtree(destination)
                extract_archive(archive_path, destination)
                expanded.append(destination)
                extracted_this_pass = True
            except Exception as exc:
                logger.warning("Failed to expand nested archive %s: %s", archive_path, exc)
        if not extracted_this_pass:
            break
    return expanded


def _find_windows_7z() -> str:
    candidates = [
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
        Path(r"C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience\7z.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return ""
