"""Git-diff targeted retest (第一版  / 第四版 G1).

Given a vulnerability's ``base_ref`` (the version where it was found) and a
``patch_ref`` (a candidate fix), this module extracts *only* the diff of the
files on that vulnerability's chain and decides whether the fix broke the
source->sink path -- **without re-running a full scan**.

Judgement is layered, mirroring the acceptance criteria of :

* **Code layer** – does the diff of the affected files introduce a filter /
  sanitizer / authorization check (or remove the vulnerable sink)?  We match the
  ``accept`` / ``reject`` keyword families used elsewhere in the review pipeline.
* **Dynamic layer** (optional) – a caller may supply a ``dynamic_recheck``
  callback (e.g. the D2 PoC or an IDOR replay) whose boolean result ("still
  exploitable") overrides an ambiguous code-layer verdict.
* **Evidence layer** – the returned dict always carries the diff text and the
  human-readable reasons behind the verdict.

Results use the retest vocabulary ``fixed`` / ``not_fixed`` / ``uncertain``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Result vocabulary (kept independent from the lifecycle module).
FIXED = "fixed"
NOT_FIXED = "not_fixed"
UNCERTAIN = "uncertain"

# Generic tokens that signal a defensive change was introduced in the diff.
_GENERIC_FIX_KEYWORDS = [
    "validate", "validator", "validation", "sanitize", "sanitizer", "sanitiz",
    "escape", "allowlist", "whitelist", "permission", "authorize",
    "authorization", "owner", "tenant", "forbidden", "guard", "filter",
    "check_access", "assert", "raise permission",
]

# Family-specific fix signals. Keys align with ``display_family`` used across the
# review/standards pipeline.
_FAMILY_FIX_KEYWORDS: Dict[str, List[str]] = {
    "sql-injection": [
        "parameter", "parameterized", "prepared", "placeholder", "%s", " ? ",
        "(?", ",?", "bindparam", "sqlalchemy", "execute(", "escape_string",
    ],
    "idor": [
        "owner", "tenant", "permission", "current_user", "authorize", "acl",
        "forbidden", "403", "is_owner", "check_access",
    ],
    "ssrf": [
        "allowlist", "whitelist", "scheme", "urlparse", "is_private",
        "block", "deny", "ip_address", "hostname",
    ],
    "command-execution": [
        "shlex", "quote", "shell=false", "subprocess.run", "args=[",
        "allowlist", "no shell",
    ],
    "path-traversal": [
        "realpath", "abspath", "basename", "normpath", "startswith",
        "safe_join", "commonpath",
    ],
    "xss": ["escape", "markupsafe", "bleach", "encode", "sanitize", "quote"],
}


def _git(repo_path: str, *args: str) -> str:
    """Run a git command inside ``repo_path`` and return stdout (empty on error)."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout or ""


def is_git_repo(repo_path: str) -> bool:
    return bool(_git(repo_path, "rev-parse", "--is-inside-work-tree").strip())


def run_git_diff(
    repo_path: str,
    base_ref: str,
    patch_ref: str,
    files: Optional[List[str]] = None,
) -> str:
    """Return the ``git diff base..patch`` restricted to ``files`` (all if empty)."""
    args = ["diff", f"{base_ref}..{patch_ref}"]
    clean_files = [f for f in (files or []) if f]
    if clean_files:
        args.append("--")
        args.extend(clean_files)
    return _git(repo_path, *args)


def _added_removed(diff_text: str) -> Dict[str, List[str]]:
    added: List[str] = []
    removed: List[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    return {"added": added, "removed": removed}


def _match_keywords(lines: List[str], keywords: List[str]) -> List[str]:
    joined = "\n".join(lines).lower()
    return [kw for kw in keywords if kw.strip() and kw.lower() in joined]


def analyze_diff(diff_text: str, family: str, sink: str = "") -> Dict[str, Any]:
    """Code-layer analysis of a diff for a single vulnerability family.

    Returns a dict with ``result`` (fixed/not_fixed/uncertain), ``fix_signals``,
    ``sink_removed`` and human-readable ``reasons``.
    """
    family = str(family or "unknown").strip().lower()
    reasons: List[str] = []

    if not diff_text.strip():
        return {
            "result": NOT_FIXED,
            "fix_signals": [],
            "sink_removed": False,
            "reasons": ["affected files unchanged between base and patch (no fix applied)"],
        }

    parts = _added_removed(diff_text)
    keywords = list(_GENERIC_FIX_KEYWORDS) + _FAMILY_FIX_KEYWORDS.get(family, [])
    fix_signals = sorted(set(_match_keywords(parts["added"], keywords)))

    sink = str(sink or "").strip()
    sink_removed = False
    if sink:
        sink_token = sink.split("(")[0].strip().lower()
        removed_join = "\n".join(parts["removed"]).lower()
        added_join = "\n".join(parts["added"]).lower()
        sink_removed = bool(sink_token) and sink_token in removed_join and sink_token not in added_join

    if fix_signals:
        reasons.append("fix signals added in diff: " + ", ".join(fix_signals))
    if sink_removed:
        reasons.append(f"vulnerable sink '{sink}' removed on the fix branch")

    if fix_signals or sink_removed:
        result = FIXED
    else:
        result = UNCERTAIN
        reasons.append("diff touches affected files but no clear filter/authz/sink change detected")

    return {
        "result": result,
        "fix_signals": fix_signals,
        "sink_removed": sink_removed,
        "reasons": reasons,
    }


def affected_files_for_finding(finding: Dict[str, Any]) -> List[str]:
    """Collect the files on the vulnerability chain from a finding record."""
    files: List[str] = []

    def _add(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in files:
            files.append(text)

    _add(finding.get("file") or finding.get("file_path"))
    for key in ("call_chain", "data_flow", "chain", "anchors"):
        chain = finding.get(key)
        if isinstance(chain, list):
            for node in chain:
                if isinstance(node, dict):
                    _add(node.get("file") or node.get("file_path"))
                elif isinstance(node, str):
                    _add(node)
    for extra in finding.get("related_files", []) or []:
        _add(extra)
    return files


def targeted_retest(
    repo_path: str,
    base_ref: str,
    patch_ref: str,
    finding: Dict[str, Any],
    family: str = "",
    dynamic_recheck: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Full G1 flow: pull the chain-scoped diff, judge it, attach evidence.

    ``dynamic_recheck`` (optional) returns True if the PoC still succeeds; a True
    result forces ``not_fixed`` regardless of the code-layer verdict, and a False
    result can promote an ``uncertain`` code verdict to ``fixed``.
    """
    family = str(family or finding.get("display_family") or finding.get("type") or "unknown").lower()
    sink = str(finding.get("sink") or "")
    files = affected_files_for_finding(finding)

    if not is_git_repo(repo_path):
        return {
            "result": UNCERTAIN,
            "strategy_available": False,
            "reasons": [f"'{repo_path}' is not a git work tree"],
            "diff": "",
            "affected_files": files,
        }

    diff_text = run_git_diff(repo_path, base_ref, patch_ref, files)
    analysis = analyze_diff(diff_text, family, sink)
    result = analysis["result"]
    reasons = list(analysis["reasons"])

    dynamic_result: Optional[bool] = None
    if dynamic_recheck is not None:
        try:
            dynamic_result = bool(dynamic_recheck())
        except Exception as exc:  # dynamic layer is best-effort
            reasons.append(f"dynamic recheck errored: {exc}")
            dynamic_result = None
        if dynamic_result is True:
            result = NOT_FIXED
            reasons.append("dynamic recheck: PoC still succeeds")
        elif dynamic_result is False:
            reasons.append("dynamic recheck: PoC no longer succeeds")
            if result == UNCERTAIN:
                result = FIXED

    return {
        "result": result,
        "strategy_available": True,
        "base_ref": base_ref,
        "patch_ref": patch_ref,
        "affected_files": files,
        "fix_signals": analysis["fix_signals"],
        "sink_removed": analysis["sink_removed"],
        "dynamic_recheck": dynamic_result,
        "diff": diff_text,
        "reasons": reasons,
        "detail": "; ".join(reasons),
    }
