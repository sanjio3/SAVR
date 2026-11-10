import subprocess
from pathlib import Path

import pytest

from src.core.patcher import build_patch_draft


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def _has_git() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def test_advisory_draft_without_git_tree(tmp_path: Path):
    # Non-existent file -> advisory-only draft, not verified.
    result = build_patch_draft(str(tmp_path / "missing.py"), 3, "sanitize input")
    assert result["applies_cleanly"] is False
    assert result["verified"] is False
    assert "--- a/" in result["diff"]
    assert "SAST-AI guard: sanitize input" in result["diff"]


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_verified_draft_applies_cleanly_in_git_tree(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "tester")
    target = root / "app.py"
    target.write_text(
        "\n".join(["def handler(req):", "    q = req.args['q']", "    run(q)", ""]),
        encoding="utf-8",
    )
    _git(root, "add", "app.py")
    _git(root, "commit", "-m", "init")

    result = build_patch_draft(str(target), line=3, strategy="validate query")
    assert result["verified"] is True
    assert result["applies_cleanly"] is True
    assert "@@ -3,1 +3,2 @@" in result["diff"]

    # The produced diff must actually apply against the working tree.
    patch = root / "draft.patch"
    patch.write_text(result["diff"], encoding="utf-8", newline="\n")
    proc = subprocess.run(
        ["git", "-C", str(root), "apply", "--check", str(patch)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
