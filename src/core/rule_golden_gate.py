"""Skill（规则单元）golden 回归门禁。

背景：``src/config/rules/*.yaml`` 里每个 skill 都声明了 ``golden`` 正/负样本与

  - ``grep -rn "min_recall" src/ scripts/ tests/`` → 零命中；
  - ``rule_feedback_service`` 走的是另一套东西（taint rule 的 source/sink/sanitizer →
    ``generated_rules.yaml`` → DB 里的 evaluation golden set），与 skill 的 ``golden`` 无关。

结果是「提 active 前须跑 golden 回归」只能人肉目测，出不了证据。本模块把该门禁做成
**可执行、可复现、可出证据**的检查：读取 skill 的 ``golden.corpus``（**真实靶场文件引用**，
不是构造样本），用 skill 自己的 ``rule_expression`` 实跑一遍，产出 recall 与误报情况，
并按 ``gate.min_recall`` 判定是否达成。

真值来源是靶场真实源码（项目铁律：全真实数据，禁伪造样本）。语料文件不存在时判
``skipped`` 而非 ``failed``，以免在没摆靶场的机器上把单测卡死。

只用标准库。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.rule_registry import RuleSkill, load_rules, reload_rules
from src.core.tool_paths import get_repo_root

DEFAULT_CORPUS_ROOT = get_repo_root().parent


def default_corpus_root() -> Path:
    """语料根目录默认值：SAVR 仓库的父目录（靶场与其同级）。"""
    return DEFAULT_CORPUS_ROOT


def _hit_lines(expr: str, content: str) -> Optional[List[int]]:
    """用 skill 的 rule_expression 扫 content，返回命中的 1-based 行号；表达式非法返回 None。"""
    try:
        pat = re.compile(expr)
    except re.error:
        return None
    return [content[: m.start()].count("\n") + 1 for m in pat.finditer(content)]


def evaluate_skill(skill: RuleSkill, *, corpus_root: Optional[Path] = None) -> Dict[str, Any]:
    """对单个 skill 跑 golden 回归，返回结构化结果（不抛异常）。

    返回字段：
      - ``status``: ``passed`` / ``failed`` / ``skipped`` / ``no_corpus`` / ``bad_expression``
      - ``recall``: 命中样本数 / 应命中样本数（无样本时为 0.0）
      - ``min_recall``: 来自 ``gate.min_recall``（默认 1.0）
      - ``must_hit`` / ``must_not_hit``: 逐条明细（含命中行号，作为证据）
      - ``missing``: 缺失的语料文件（相对 corpus_root）
    """
    corpus_root = Path(corpus_root) if corpus_root else default_corpus_root()
    golden = skill.golden or {}
    corpus = golden.get("corpus") or {}
    min_recall = float((skill.gate or {}).get("min_recall", 1.0) or 1.0)
    out: Dict[str, Any] = {
        "id": skill.id,
        "status": skill.status,
        "is_active": skill.is_active,
        "expression": skill.rule_expression,
        "min_recall": min_recall,
        "recall": 0.0,
        "must_hit": [],
        "must_not_hit": [],
        "missing": [],
    }

    must_hit: List[Dict[str, Any]] = list(corpus.get("must_hit") or [])
    must_not_hit: List[Dict[str, Any]] = list(corpus.get("must_not_hit") or [])
    if not must_hit and not must_not_hit:
        out["status"] = "no_corpus"
        return out
    if not skill.rule_expression:
        # 无表达式的 skill（如纯提示词 skill）无可回归对象，按无样本处理。
        out["status"] = "no_corpus"
        return out

    cache: Dict[str, Optional[str]] = {}

    def _read(entry: Dict[str, Any]) -> Optional[str]:
        rel = str(Path(str(entry.get("repo") or "")) / str(entry.get("file") or ""))
        if rel not in cache:
            path = corpus_root / rel
            try:
                cache[rel] = path.read_text(encoding="utf-8") if path.exists() else None
            except Exception:
                cache[rel] = None
        return cache[rel]

    had_bad_expr = False
    total = 0
    matched = 0

    for entry in must_hit:
        rel = str(Path(str(entry.get("repo") or "")) / str(entry.get("file") or ""))
        content = _read(entry)
        item = {"target": rel, "expected_lines": list(entry.get("lines") or [])}
        if content is None:
            out["missing"].append(rel)
            item["result"] = "missing"
        else:
            lines = _hit_lines(skill.rule_expression, content)
            if lines is None:
                had_bad_expr = True
                item["result"] = "bad_expression"
            else:
                item["hit_lines"] = lines
                expected = set(item["expected_lines"])
                ok = bool(expected.issubset(set(lines))) if expected else bool(lines)
                item["result"] = "hit" if ok else "miss"
                total += 1
                matched += 1 if ok else 0
        out["must_hit"].append(item)

    negative_violations = 0
    for entry in must_not_hit:
        rel = str(Path(str(entry.get("repo") or "")) / str(entry.get("file") or ""))
        content = _read(entry)
        item = {"target": rel}
        if content is None:
            out["missing"].append(rel)
            item["result"] = "missing"
        else:
            lines = _hit_lines(skill.rule_expression, content)
            if lines is None:
                had_bad_expr = True
                item["result"] = "bad_expression"
            else:
                item["hit_lines"] = lines
                item["result"] = "clean" if not lines else "violation"
                if lines:
                    negative_violations += 1
        out["must_not_hit"].append(item)

    if had_bad_expr:
        out["status"] = "bad_expression"
        return out
    if total == 0 and negative_violations == 0 and out["missing"]:
        # 样本文件全缺，无从回归
        out["status"] = "skipped"
        return out

    out["recall"] = round(matched / total, 4) if total else 0.0
    out["negative_violations"] = negative_violations
    passed = (out["recall"] >= min_recall - 1e-9) and negative_violations == 0
    out["status"] = "passed" if passed else "failed"
    return out


def evaluate_rules(
    *,
    skill_ids: Optional[List[str]] = None,
    corpus_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """对（指定的）全部 skill 跑 golden 回归，返回汇总结果。"""
    skills = load_rules()
    selected = (
        {sid: skills[sid] for sid in skill_ids if sid in skills}
        if skill_ids
        else dict(skills)
    )
    results = [evaluate_skill(sk, corpus_root=corpus_root) for sk in selected.values()]
    graded = [r for r in results if r["status"] in ("passed", "failed")]
    return {
        "corpus_root": str(Path(corpus_root) if corpus_root else default_corpus_root()),
        "results": results,
        "graded": len(graded),
        "passed": sum(1 for r in graded if r["status"] == "passed"),
        "failed": sum(1 for r in graded if r["status"] == "failed"),
        "skipped": sum(1 for r in results if r["status"] in ("skipped", "no_corpus")),
        "ok": all(r["status"] != "failed" for r in results),
    }


def _item_bounds(lines: List[str], skill_id: str) -> Optional[Tuple[int, int]]:
    """定位 ``skills:`` 列表中某个 skill 的文本区间 ``[start, end)``。

    必须兼容两种 YAML 写法：

      - 手写风格（本项目规则文件）：``- id: cve-2022-22978`` —— 列表标记与 id 同行；
      - ``yaml.safe_dump`` 默认输出：按键名**排序**，id 常不在首位，
        形如 ``- family: auth_bypass`` / 下一行 ``  id: xxx`` —— 列表标记在别的键上。

    只认第一条 ``id: <skill_id>``，再从该行向上找「缩进更浅的列表项起始行」作为区间起点。
    """
    id_pat = re.compile(r"^(\s*)(-\s*)?id:\s*" + re.escape(skill_id) + r"\s*$")
    id_line: Optional[int] = None
    for i, ln in enumerate(lines):
        if id_pat.match(ln.rstrip("\r\n")):
            id_line = i
            break
    if id_line is None:
        return None

    stripped = lines[id_line].rstrip("\r\n")
    m = re.match(r"^(\s*)(-\s*)?id:", stripped)
    if m is None:
        return None
    indent, inline_marker = m.group(1), bool(m.group(2))

    if inline_marker:
        item_indent, start = indent, id_line
    else:
        item_indent, start = None, None
        for j in range(id_line - 1, -1, -1):
            mm = re.match(r"^(\s*)-\s+\S", lines[j].rstrip("\r\n"))
            if mm and len(mm.group(1)) < len(indent):
                item_indent, start = mm.group(1), j
                break
        if start is None:
            return None

    end = len(lines)
    next_pat = re.compile(r"^" + re.escape(item_indent) + r"-\s+\S")
    for j in range(start + 1, len(lines)):
        if next_pat.match(lines[j].rstrip("\r\n")):
            end = j
            break
    return start, end


def _rewrite_status(source_path: str, skill_id: str, new_status: str) -> bool:
    """在 yaml 中**定点改写**指定 skill 的 ``status`` 行（保留整份文件注释）。

    做法：先用 ``_item_bounds`` 框出该 skill 的文本区间，只替换区间内第一条 ``status:`` 行的值。
    刻意不用 yaml round-trip，因为规则文件里有大量说明注释，``safe_dump`` 会把它们全部丢掉。
    """
    path = Path(source_path)
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    bounds = _item_bounds(lines, skill_id)
    if bounds is None:
        return False
    start, end = bounds
    st_pat = re.compile(r"^(\s*status:\s*)([^\s#]+)(.*)$")
    for k in range(start, end):
        m = st_pat.match(lines[k].rstrip("\r\n"))
        if m:
            eol = "\r\n" if lines[k].endswith("\r\n") else "\n"
            lines[k] = f"{m.group(1)}{new_status}{m.group(3)}{eol}"
            path.write_text("".join(lines), encoding="utf-8")
            return True
    return False


def promote_skill(
    skill_id: str,
    *,
    corpus_root: Optional[Path] = None,
    confirm: bool = False,
    reload: bool = True,
) -> Dict[str, Any]:
    """把 skill 从 ``staging`` 提升为 ``active``，**只在 golden 门禁通过且显式人工确认时**执行。

    项目铁律：未在目标上做过 golden 回归的规则不得置为 active，且提级须人工确认。
    故本函数是两道闸门串联：①门禁必须 ``passed``；②必须显式传 ``confirm=True``。
    任一不满足即拒绝（不改动任何文件），并回传门禁证据。

    返回 ``{ok, changed, reason, gate?, source_path?}``。
    """
    skills = load_rules()
    sk = skills.get(skill_id)
    if sk is None:
        return {"ok": False, "changed": False, "reason": f"skill not found: {skill_id}"}
    if sk.is_active:
        return {"ok": True, "changed": False, "reason": "already active"}

    gate = evaluate_skill(sk, corpus_root=corpus_root)
    if gate.get("status") != "passed":
        return {"ok": False, "changed": False,
                "reason": f"golden gate not passed: {gate.get('status')}", "gate": gate}
    if not confirm:
        return {"ok": False, "changed": False,
                "reason": "human confirmation required (confirm=True)", "gate": gate}
    if not sk.source_path:
        return {"ok": False, "changed": False, "reason": "source_path unknown", "gate": gate}
    if not _rewrite_status(sk.source_path, skill_id, "active"):
        return {"ok": False, "changed": False,
                "reason": "status line not found in source file", "gate": gate}
    if reload:
        reload_rules()
    return {"ok": True, "changed": True, "reason": "promoted",
            "gate": gate, "source_path": sk.source_path}


def format_report(report: Dict[str, Any]) -> str:
    """把汇总结果渲染成纯文本报告（供 CLI / 日志输出）。"""
    lines = [f"corpus_root = {report['corpus_root']}",
             f"graded={report['graded']} passed={report['passed']} "
             f"failed={report['failed']} skipped={report['skipped']}",
             ""]
    for r in report["results"]:
        lines.append(f"[{r['status'].upper()}] {r['id']}")
        lines.append(f"    expr: {r['expression'] or '(none)'}")
        lines.append(f"    recall: {r.get('recall', 0.0)} (min_recall={r.get('min_recall', 1.0)})")
        for it in r.get("must_hit") or []:
            lines.append(
                f"    must_hit {it['target']}: {it['result']}"
                f" expected={it.get('expected_lines')} hits={it.get('hit_lines')}"
            )
        for it in r.get("must_not_hit") or []:
            lines.append(
                f"    must_not_hit {it['target']}: {it['result']} hits={it.get('hit_lines')}"
            )
        if r.get("missing"):
            lines.append(f"    missing: {r['missing']}")
    return "\n".join(lines)
