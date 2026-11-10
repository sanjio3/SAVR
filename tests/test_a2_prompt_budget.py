# -*- coding: utf-8 -*-
"""回归锁：A2 prompt 必须落在 num_ctx 预算内。

2026-11-08 L2实测：`_user_prompt` 把整份源码拼进去、没有 token 预算，
Ollama 在 `num_ctx=8192` 下超限直接 400：

    request (9486 tokens) exceeds the available context size (8192 tokens)

26KB 的 HTML 就 9,486 token（HTML/JS/SQL 的 token 密度远高于 Java），于是 10 个大
文件在调用前失败、被记成 `file_failures`，看起来像「LLM 不可用」。

锁定五条不变量：
  A. 预算 7000，高于 jsc 全量最大 6,361 ⇒ jsc 的 prompt 逐字节不变；
  B. 预算内 `analyze()` 不裁剪、不改 prompt、不计数；
  C. 超预算按疑点行开窗，保留该行、带省略标记、估算 token 落回预算；
  D. 裁剪只发生在 prompt 层，不改 temperature / seed / num_ctx / num_predict；
  E. `_est_tokens` 必须是 len//3（两端都偏保守）。
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.agents import a2_integrated_analyst as A  # noqa: E402


def _findings(line=0):
    return [{"line": line, "family": "xss", "note": "可疑 sink"}]


def _dummy_llm(captured):
    def _call(msgs):
        captured.append(msgs)
        return "[]"
    return _call


def _trimmed_count() -> int:
    return int(A._CONTRACT_STATS.get("code_trimmed") or 0)


# ── A/E. 常量与估算 ────────────────────────────────────────────────────────

def test_prompt_budget_default_is_7000(monkeypatch):
    monkeypatch.delenv("SAST_AI_A2_PROMPT_TOKENS", raising=False)
    assert A.prompt_token_budget() == 7000


def test_prompt_budget_env_semantics(monkeypatch):
    """`_env_float` 的语义：区间内生效，越界/非法回默认（不是夹到边界）。"""
    monkeypatch.setenv("SAST_AI_A2_PROMPT_TOKENS", "5000")
    assert A.prompt_token_budget() == 5000
    monkeypatch.setenv("SAST_AI_A2_PROMPT_TOKENS", "100")
    assert A.prompt_token_budget() == 7000
    monkeypatch.setenv("SAST_AI_A2_PROMPT_TOKENS", "not-a-number")
    assert A.prompt_token_budget() == 7000


def test_est_tokens_is_len_div_3():
    assert A._est_tokens("") == 0
    assert A._est_tokens("a" * 3000) == 1000


# ── C. 裁剪函数的行为 ──────────────────────────────────────────────────────

def test_code_within_budget_is_returned_verbatim():
    code = "\n".join("line %d" % i for i in range(50))
    assert A._trim_code_to_budget(code, _findings(10), 10 ** 6) == code


def test_finding_line_survives_trimming():
    lines = ["noise %d" % i for i in range(4000)]
    lines[2500] = "HERE_IS_THE_SINK(x)"
    code = "\n".join(lines)
    out = A._trim_code_to_budget(code, _findings(2501), 4000)
    assert "HERE_IS_THE_SINK(x)" in out
    assert "省略" in out
    assert len(out) < len(code)


def test_head_is_always_kept():
    lines = ["head_marker"] + ["noise %d" % i for i in range(4000)]
    out = A._trim_code_to_budget("\n".join(lines), _findings(0), 3000)
    assert out.startswith("head_marker")


def test_trimmed_output_respects_budget():
    code = "\n".join("x" * 100 for _ in range(3000))
    budget = 5000
    out = A._trim_code_to_budget(code, _findings(1500), budget)
    assert len(out) <= budget + 200      # 省略标记本身有几十字节余量


# ── B. 预算内 analyze() 不动 prompt ────────────────────────────────────────

def test_analyze_within_budget_keeps_prompt_byte_identical(monkeypatch):
    monkeypatch.setenv("SAST_AI_A2_PROMPT_TOKENS", "7000")
    code = "public class A { void f(String s) { sink(s); } }"
    expected = A._user_prompt(code, "A.java", _findings(1))
    captured = []
    before = _trimmed_count()
    A.IntegratedAnalyst(llm_call=_dummy_llm(captured)).analyze(
        code, "A.java", _findings(1))
    assert captured, "LLM 未被调用"
    assert captured[0][-1]["content"] == expected
    assert _trimmed_count() == before, "预算内不应触发裁剪"


# ── D. 超预算才裁剪，且只动 prompt ─────────────────────────────────────────

def test_analyze_over_budget_trims_prompt(monkeypatch):
    monkeypatch.setenv("SAST_AI_A2_PROMPT_TOKENS", "2000")
    # HTML 风格：短 token、高密度标点，估算最坏情况
    code = "\n".join('<div class="c%d"><span>%d</span></div>' % (i, i)
                     for i in range(1500))
    findings = _findings(1000)
    original = A._user_prompt(code, "page.html", findings)
    captured = []
    before = _trimmed_count()
    A.IntegratedAnalyst(llm_call=_dummy_llm(captured)).analyze(
        code, "page.html", findings)

    sent = captured[0][-1]["content"]
    assert sent != original
    assert "省略" in sent
    total = A._est_tokens(captured[0][0]["content"]) + A._est_tokens(sent)
    assert total <= 2000, "裁剪后仍超预算：%d" % total
    assert _trimmed_count() == before + 1


def test_contract_stats_exposes_code_trimmed():
    """裁剪次数必须可观测；它不是硬条件，但不能悄悄发生。"""
    assert "code_trimmed" in A.contract_stats()


def test_trim_does_not_change_sampling_params():
    """裁剪只影响 prompt 文本，请求体其余参数必须保持默认。"""
    import inspect
    src = inspect.getsource(A.ollama_chat)
    assert '"num_ctx": 8192' in src
    assert "llm_num_predict_default()" in src
    assert 'SAST_AI_LLM_TEMPERATURE", "0"' in src


# ── A. jsc 全量文件在预算内（不需要重跑 L1/L3 的确定性依据）────────────────

def _jsc_root() -> str:
    """jsc 原靶场根目录：从本机 DB 的 workspace 4 读，避免在测试里写死绝对路径。"""
    db = os.path.join(ROOT, "data", "app.db")
    if not os.path.isfile(db):
        return ""
    try:
        import sqlite3
        con = sqlite3.connect("file:%s?mode=ro" % db.replace("\\", "/"), uri=True)
        row = con.execute("SELECT target_path FROM workspaces WHERE id=4").fetchone()
        con.close()
        root = (row[0] if row and row[0] else "") or ""
        return root if os.path.isdir(root) else ""
    except Exception:  # noqa: BLE001
        return ""


@pytest.mark.skipif(not _jsc_root(), reason="本机未注册 jsc 原靶场（workspace 4）")
def test_jsc_prompts_all_fit_default_budget():
    root = _jsc_root()
    worst = (0, "")
    for dp, _dn, fn in os.walk(root):
        if any(x in dp for x in (".git", "target", ".codeql-db")):
            continue
        for f in fn:
            if not f.endswith((".java", ".jsp", ".js", ".html", ".xml")):
                continue
            try:
                code = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            prompt = A._user_prompt(code, f, _findings(0))
            est = A._est_tokens(A.SYSTEM) + A._est_tokens(prompt)
            if est > worst[0]:
                worst = (est, f)
    assert worst[0] <= A.prompt_token_budget(), \
        "jsc 出现超预算文件（会改变历史读数）：%s est=%d" % (worst[1], worst[0])
