"""G1: git-diff targeted retest (第四版 §2.13).

Builds a real temporary git repo with a vulnerable commit and, on separate
branches, a "no fix" change and a real parameterized-query fix. Asserts the
git_diff retest strategy reaches opposite conclusions and drives the lifecycle.
"""

import subprocess
from pathlib import Path

import pytest

from src.application.retest_service import RetestService
from src.core import git_diff, lifecycle
from src.infrastructure.db import Database
from src.infrastructure.repositories import FindingRepository


def _run(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _run(repo, "init", "-q")
    _run(repo, "config", "user.email", "test@example.com")
    _run(repo, "config", "user.name", "tester")
    _run(repo, "config", "commit.gpgsign", "false")


def _write(repo: Path, rel: str, content: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


VULN = (
    "def get_user(cursor, user_id):\n"
    '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    "    return cursor.fetchone()\n"
)
FIXED = (
    "def get_user(cursor, user_id):\n"
    '    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
    "    return cursor.fetchone()\n"
)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "proj"
    _init_repo(repo)
    _write(repo, "app/dao.py", VULN)
    _write(repo, "README.md", "v1\n")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-q", "-m", "base: vulnerable")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    # Branch that does NOT touch the vulnerable file.
    _run(repo, "checkout", "-q", "-b", "nofix")
    _write(repo, "README.md", "v2 unrelated\n")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-q", "-m", "nofix: docs only")

    # Branch that applies a real parameterized-query fix.
    _run(repo, "checkout", "-q", base)
    _run(repo, "checkout", "-q", "-b", "realfix")
    _write(repo, "app/dao.py", FIXED)
    _run(repo, "add", "-A")
    _run(repo, "commit", "-q", "-m", "fix: parameterize query")
    return repo


def _seed_finding(db: Database, repo: Path) -> str:
    now = "2026-01-01T00:00:00"
    db.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", str(repo), "", "{}", now, now),
    )
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (1, "task", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )
    repo_obj = FindingRepository(db)
    repo_obj.replace_for_task(1, 1, [{
        "type": "SQL Injection",
        "display_family": "sql-injection",
        "file": "app/dao.py",
        "line": 2,
        "sink": "cursor.execute",
        "entry_point": "GET /users",
        "exploitable": True,
        "project_path": str(repo),
    }])
    return repo_obj.list(workspace_id=1, task_id=1)[0].raw["vulnerability_hash_v2"]


def test_analyze_diff_detects_and_rejects_fix():
    assert git_diff.analyze_diff("", "sql-injection")["result"] == git_diff.NOT_FIXED
    diff = "--- a/x\n+++ b/x\n-cursor.execute(sql + user_id)\n+cursor.execute(sql, (user_id,))\n"
    assert git_diff.analyze_diff(diff, "sql-injection", sink="cursor.execute")["result"] == git_diff.FIXED


def test_git_diff_retest_reaches_opposite_conclusions(tmp_path: Path, repo: Path):
    db = Database(str(tmp_path / "app.db"))
    vuln_hash = _seed_finding(db, repo)
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "nofix~1"], capture_output=True, text=True).stdout.strip()

    service = RetestService(db)

    nofix = service.retest(1, vuln_hash, strategy="git_diff", base_ref=base, patch_ref="nofix", repo_path=str(repo))
    assert nofix["retest"]["result"] == "still_vulnerable"
    assert nofix["retest"]["strategy"] == "git_diff"
    assert nofix["instance"]["status"] in {lifecycle.CONFIRMED, lifecycle.REOPENED}

    fixed = service.retest(1, vuln_hash, strategy="git_diff", base_ref=base, patch_ref="realfix", repo_path=str(repo))
    assert fixed["retest"]["result"] == "fixed"
    assert fixed["instance"]["status"] == lifecycle.FIXED
    assert "app/dao.py" in fixed["retest"]["evidence"]["diff"]
    assert fixed["retest"]["evidence"]["fix_signals"]


def test_git_diff_retest_requires_refs(tmp_path: Path, repo: Path):
    db = Database(str(tmp_path / "app.db"))
    vuln_hash = _seed_finding(db, repo)
    service = RetestService(db)
    result = service.retest(1, vuln_hash, strategy="git_diff", repo_path=str(repo))
    assert result["retest"]["result"] == "inconclusive"
    assert result["retest"]["evidence"]["strategy_available"] is False
