"""Generate and verify unified-diff patch drafts.

Replaces the previous TODO stub with a real, well-formed unified diff. When the
target file is available inside a git working tree, the draft is validated with
``git apply --check`` and ``applies_cleanly`` reflects the real result. Otherwise
the draft is returned as advisory with ``applies_cleanly=False`` and an honest reason.

The generated change is intentionally conservative: it inserts a guard/marker
comment near the vulnerable line so a human owner can complete the fix. Automatic
semantic mutation of source is deliberately out of scope.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional

_COMMENT_PREFIX = {
    ".py": "#", ".rb": "#", ".sh": "#", ".yaml": "#", ".yml": "#",
    ".java": "//", ".js": "//", ".ts": "//", ".tsx": "//", ".jsx": "//",
    ".go": "//", ".c": "//", ".cpp": "//", ".cs": "//", ".php": "//",
}


def _comment_for(path: str) -> str:
    return _COMMENT_PREFIX.get(Path(path).suffix.lower(), "#")


def _resolve(file_path: str, root: Optional[str]) -> Optional[Path]:
    if not file_path:
        return None
    candidate = Path(file_path)
    if candidate.is_absolute() and candidate.is_file():
        return candidate
    if root:
        joined = Path(root) / file_path
        if joined.is_file():
            return joined
    return candidate if candidate.is_file() else None


def _git_root(path: Path) -> Optional[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    top = result.stdout.strip()
    return Path(top) if top else None


def _git_apply_check(git_root: Path, diff_text: str) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False, encoding="utf-8", newline="\n") as handle:
        handle.write(diff_text)
        patch_path = handle.name
    try:
        result = subprocess.run(
            ["git", "-C", str(git_root), "apply", "--check", patch_path],
            capture_output=True, text=True, timeout=15,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        try:
            Path(patch_path).unlink()
        except OSError:
            pass


def build_patch_draft(
    file_path: str,
    line: int,
    strategy: str,
    *,
    root: Optional[str] = None,
) -> Dict[str, object]:
    """Build a unified-diff patch draft, verifying it against git when possible."""
    rel = (file_path or "target-file").replace("\\", "/")
    comment = _comment_for(rel)
    guard = f"{comment} SAST-AI guard: {strategy}".rstrip()

    resolved = _resolve(file_path, root)
    if resolved is None:
        diff = "\n".join([
            f"--- a/{rel}",
            f"+++ b/{rel}",
            "@@ -1,1 +1,2 @@",
            f"+{guard}",
        ]) + "\n"
        return {
            "diff": diff,
            "applies_cleanly": False,
            "verified": False,
            "reason": "Target file not available in a git working tree; draft is advisory only.",
        }

    text = resolved.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    total = len(lines)
    # Insert the guard immediately before the vulnerable line (1-based), clamped.
    insert_at = max(1, min(int(line or 1), total)) if total else 1
    ctx_before = lines[insert_at - 1] if total else ""
    git_root = _git_root(resolved)
    diff_rel = rel
    if git_root is not None:
        try:
            diff_rel = str(resolved.resolve().relative_to(git_root.resolve())).replace("\\", "/")
        except ValueError:
            diff_rel = rel
    # Hunk: 1 context line (original) -> guard + same context line (2 lines added region).
    hunk_header = f"@@ -{insert_at},1 +{insert_at},2 @@"
    diff = "\n".join([
        f"--- a/{diff_rel}",
        f"+++ b/{diff_rel}",
        hunk_header,
        f"+{guard}",
        f" {ctx_before}",
    ]) + "\n"

    applies_cleanly = False
    verified = False
    reason = "Draft generated; git working tree not detected for verification."
    if git_root is not None:
        verified = True
        applies_cleanly = _git_apply_check(git_root, diff)
        reason = (
            "Verified with `git apply --check`."
            if applies_cleanly
            else "`git apply --check` rejected the draft; manual adjustment required."
        )
    return {
        "diff": diff,
        "applies_cleanly": applies_cleanly,
        "verified": verified,
        "reason": reason,
    }
