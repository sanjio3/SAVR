"""M10 SSTI 按引擎分桶 + 求值对测试（2026-10-03）。

核心主张：
  1. 求值对按引擎分桶 —— 同一组表达式打所有引擎会同时漏报（语法不匹配）与
     误报（别的表达式碰巧算出 49）。
  2. 引擎由 A1 从 import / class 路径**静态**识别，不需要 LLM。
  3. 每桶给多组求值对（首选 + 备选），因为各引擎版本对同一语法支持有差异
     （Velocity 老版本 ${7*7} 不求值）。命中任一即确证。
  4. 识别不出引擎时走跨引擎兜底，但 engine_identified=False，不冒充已识别。
  5. 判定三态：evaluated（可利用）/ literal（模板没求值 = 真阴性）/ absent（证据缺失）。
"""
from src.core import ssti_engines as se
from src.core.result_point import evaluate_result_point, judge_ssti


def test_registry_covers_seven_engines():
    assert set(se.ENGINE_REGISTRY) == {
        "velocity", "freemarker", "thymeleaf", "pebble", "spel", "ognl", "mvel"}


def test_detect_engines_from_imports_statically():
    assert se.detect_engines(
        [{"path": "T.java", "content": "import org.thymeleaf.spring5.SpringTemplateEngine;"}]
    ) == ["thymeleaf"]
    got = se.detect_engines([{"path": "V.java", "content":
                              "import org.apache.velocity.app.VelocityEngine;"
                              "import freemarker.template.Configuration;"}])
    assert set(got) == {"velocity", "freemarker"}


def test_detect_engines_returns_empty_when_none():
    assert se.detect_engines([{"path": "X.java", "content": "class A {}"}]) == []


def test_engine_family_names_bucket():
    assert se.engine_family("velocity") == "ssti_velocity"
    assert se.engine_family("thymeleaf") == "ssti_thymeleaf"
    assert se.engine_family("unknown-thing") == "ssti"


def test_each_bucket_has_distinct_eval_pairs():
    """各桶求值对不能是同一组（那分桶就没意义了）。"""
    pairs = {name: [p for p, _ in se.eval_pairs_for(name)] for name in se.ENGINE_REGISTRY}
    assert pairs["thymeleaf"] != pairs["freemarker"]
    assert pairs["pebble"] != pairs["ognl"]
    # 关键差异：OGNL 用 %{}，Pebble 用 {{ }}，Thymeleaf 用 ${} 或 *{}
    assert any("%{" in p for p in pairs["ognl"])
    assert any("{{" in p for p in pairs["pebble"])
    assert any("${" in p for p in pairs["thymeleaf"])


def test_bucket_gives_multiple_pairs_for_version_drift():
    """Velocity 老版本 ${7*7} 可能不求值 → 必须并列备选（#set 形态）。"""
    pairs = [p for p, _ in se.eval_pairs_for("velocity")]
    assert any(p.startswith("#set") for p in pairs)


def test_judge_evaluated_vs_literal_vs_absent():
    assert se.judge("value=49", "${7*7}", "49") == se.SSTI_EVALUATED
    assert se.judge("value=${7*7}", "${7*7}", "49") == se.SSTI_LITERAL
    assert se.judge("nothing here", "${7*7}", "49") == se.SSTI_ABSENT


def test_judge_by_engine_uses_bucket_syntax():
    res = se.judge_by_engine("<b>49</b>", ["ognl"])
    assert res["state"] == se.SSTI_EVALUATED
    assert res["engine"] == "ognl" and res["engine_identified"] is True
    assert "%{7*7}" == res["payload"]


def test_literal_is_true_negative_not_exploitable():
    res = se.judge_by_engine("<b>${7*7}</b>", ["thymeleaf"])
    assert res["state"] == se.SSTI_LITERAL


def test_unidentified_engine_fallback_is_flagged():
    """识别不出引擎时跨引擎兜底能命中，但必须标 engine_identified=False。"""
    res = se.judge_by_engine("<b>49</b>", [])
    assert res["state"] == se.SSTI_EVALUATED
    assert res["engine_identified"] is False
    assert res["engine"] == ""


def test_judge_ssti_end_to_end_by_engine():
    """result_point 接入：按桶派发，命中即 confirmed_exploitable。"""
    dast = {"body": "<div>49</div>", "attack_payload_used": ""}
    r = judge_ssti(dast, ["thymeleaf"])
    assert r["matched"] is True and r["state"] == "evaluated"
    assert r["suggested_status"] == "confirmed_exploitable"


def test_judge_ssti_literal_suggests_filtered():
    dast = {"body": "<div>${7*7}</div>", "attack_payload_used": ""}
    r = judge_ssti(dast, ["thymeleaf"])
    assert r["matched"] is False
    assert r["suggested_status"] == "filtered_not_exploitable"


def test_evaluate_result_point_reads_engines_from_dast():
    dast = {"body": "<div>49</div>", "ssti_engines": ["pebble"]}
    r = evaluate_result_point("ssti", dast)
    assert r["matched"] is True
    assert r["ssti_engine"] == "pebble"


def test_absent_suggests_two_step_replay():
    """没观测到求值对 → 不是无害，是「没看到」，指引去两步重放。"""
    r = evaluate_result_point("ssti", {"body": "clean page"})
    assert r["definitive"] is False
    assert r["next_action"] == "two_step_replay"
