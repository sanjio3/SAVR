"""Harness 改造各新层（§4 + 1.2 P0/P1）的回归测试（2026-09-19）。

覆盖：模型能力画像、输出契约、并发闸门、prompt 缓存、提示词注册表、Skill 规则注册表、工具层硬化。
全部为纯逻辑 / 单测，不触网、不依赖真实 LLM。缓存相关只测指纹确定性与 fail-open 分支。
"""
import os
import unittest
from pathlib import Path

from src.core import model_capabilities as mc
from src.core import llm_output as lo
from src.core import llm_gate as lg
from src.core import llm_cache as lc
from src.core import prompt_registry as pr
from src.core import rule_registry as rr
from src.core import rule_golden_gate as rgg
from src.agents import a2_tools


class TestModelCapabilities(unittest.TestCase):
    def test_resolve_builtin_local_small(self):
        p = mc.resolve_profile(model="qwen3:14b", provider="qwen")
        self.assertEqual(p.tier, "local")
        # 2026-09-19：1 -> 2。本地 provider 免鉴权/无配额/不计费，重试只耗时不放大量请求；
        # 且接本地时 api.fallback_provider 通常置空，同 provider 重试是唯一容错手段。
        self.assertEqual(p.max_attempts, 2)
        self.assertEqual(p.recommended_concurrency, 2)
        self.assertLessEqual(p.context_window, 8192)
        self.assertFalse(p.use_thinking)

    def test_resolve_unknown_falls_back(self):
        p = mc.resolve_profile(model="does-not-exist-xyz", provider="")
        self.assertEqual(p.context_window, mc.SAFE_FALLBACK.context_window)
        self.assertFalse(p.supports_tools)

    def test_clamp_max_tokens(self):
        p = mc.resolve_profile(model="qwen3:14b")
        self.assertEqual(mc.clamp_max_tokens(p, 99999), p.max_output_tokens)
        self.assertEqual(mc.clamp_max_tokens(p, 100), 100)

    def test_input_budget_positive(self):
        p = mc.resolve_profile(model="qwen3:14b")
        self.assertGreater(mc.input_budget(p), 0)
        self.assertLess(mc.input_budget(p), p.context_window)


class TestLLMOutput(unittest.TestCase):
    def test_parse_clean_object(self):
        data, diag = lo.parse_llm_json('{"a": 1, "b": [1,2]}')
        self.assertTrue(diag.ok)
        self.assertEqual(data, {"a": 1, "b": [1, 2]})

    def test_parse_fenced(self):
        text = '```json\n{"x": 42}\n```'
        data, diag = lo.parse_llm_json(text)
        self.assertTrue(diag.ok)
        self.assertEqual(data, {"x": 42})

    def test_parse_truncated_repairs(self):
        # 被 max_tokens 截断的对象，finish_reason="length" -> 尝试截断修复
        truncated = '{"vulnerabilities": [{"type": "SQL注入", "line": 12'
        data, diag = lo.parse_llm_json(truncated, finish_reason="length")
        # 契约：截断时走 repair/salvage 降级链；无论成功与否都给出诊断信号，绝不静默
        self.assertTrue(diag.truncated)
        self.assertTrue(diag.repaired or diag.ok or diag.strategy in ("repaired", "array-salvage"))

    def test_parse_array_salvage(self):
        half = '[{"id": 1}, {"id": 2'
        data, diag = lo.parse_llm_json(half)
        # 半截数组：至少要救回已闭合的元素（返回首个完整对象或已闭合元素列表），不整段丢弃
        if isinstance(data, list):
            self.assertGreaterEqual(len(data), 1)
        else:
            self.assertIsInstance(data, dict)
            self.assertEqual(data.get("id"), 1)
        self.assertTrue(diag.ok)

    def test_parse_garbage_never_raises(self):
        # 契约：失败返回 data=None（不是 []，避免与「模型判定无问题」混淆）
        data, diag = lo.parse_llm_json("完全不是 JSON 的乱码文本")
        self.assertFalse(diag.ok)
        self.assertIsNone(data)

    def test_is_truncated(self):
        self.assertTrue(lo.is_truncated("length", ""))
        self.assertFalse(lo.is_truncated("stop", ""))


class TestLLMGate(unittest.TestCase):
    def _restore(self):
        lg.configure_gate(width=8)

    def test_singleton_and_acquire(self):
        g = lg.get_gate()
        self.assertIs(g, lg.get_gate())
        with g.acquire(timeout=2) as admitted:
            self.assertTrue(admitted)

    def test_timeout_returns_false(self):
        g = lg.get_gate()
        lg.configure_gate(width=1)
        # 占用唯一许可，再在子线程请求应超时返回 False（不抛异常）
        import threading
        lg.configure_gate(width=1)
        with g.acquire(timeout=2):
            ev = {}
            def worker():
                with g.acquire(timeout=0.2) as a:
                    ev["admitted"] = a
            t = threading.Thread(target=worker)
            t.start()
            t.join(3)
        self.assertFalse(ev.get("admitted", True))
        self._restore()

    def test_stats(self):
        s = lg.gate_stats()
        self.assertIn("in_flight", s)


class TestLLMCache(unittest.TestCase):
    def test_build_cache_key_deterministic_and_sensitive(self):
        base = dict(provider="x", model="m", messages=[{"role": "user", "content": "hi"}],
                    temperature=0.0, max_tokens=100, prompt_version="v1")
        k1 = lc.build_cache_key(**base)
        k2 = lc.build_cache_key(**base)
        self.assertEqual(k1, k2)
        k3 = lc.build_cache_key(**{**base, "messages": [{"role": "user", "content": "bye"}]})
        self.assertNotEqual(k1, k3)
        k4 = lc.build_cache_key(**{**base, "prompt_version": "v2"})
        self.assertNotEqual(k1, k4)

    def test_disabled_get_returns_none(self):
        old = os.environ.get("SAST_AI_LLM_CACHE")
        os.environ["SAST_AI_LLM_CACHE"] = "0"
        try:
            self.assertIsNone(lc.get("anything"))
        finally:
            if old is None:
                os.environ.pop("SAST_AI_LLM_CACHE", None)
            else:
                os.environ["SAST_AI_LLM_CACHE"] = old

    def test_put_empty_text_noop(self):
        # 空响应不缓存：函数应在触库前返回（无 DB/无异常）
        try:
            lc.put("somekey", text="   ")
        except Exception as exc:  # pragma: no cover
            self.fail(f"put(empty) 不应抛异常：{exc}")


class TestPromptRegistry(unittest.TestCase):
    def test_registry_loads_and_resolves(self):
        reg = pr.get_registry()
        names = reg._entries.keys()
        self.assertIn("audit_file", names)
        self.assertIn("sql_injection", names)  # 此前 dead 的族模板已进注册表
        text, meta = pr.get_prompt_template("audit_file")
        self.assertGreater(len(text), 100)
        self.assertEqual(meta["version"], "terminal-first-v1")
        self.assertTrue(meta["hash"])

    def test_hash_changes_with_content(self):
        h1 = pr.compute_prompt_hash("n", "v", "abc")
        h2 = pr.compute_prompt_hash("n", "v", "abcd")
        self.assertNotEqual(h1, h2)
        h3 = pr.compute_prompt_hash("n", "v2", "abc")
        self.assertNotEqual(h1, h3)

    def test_hierarchical_fallback_default(self):
        reg = pr.get_registry()
        pe = reg.get("audit_file", family="nonexistent-family")
        self.assertIsNotNone(pe)
        self.assertEqual(pe.name, "audit_file")

    def test_version_selects_template(self):
        """version 真正驱动模板选择：同名两版本返回不同正文（§4.1 修复，2026-09-20）。"""
        import os as _os
        import tempfile
        import yaml as _yaml
        reg_spec = {
            "prompts": {
                "_vtest": {
                    "default": "v1",
                    "versions": [
                        {"version": "v1", "file": "audit_prompts.yaml", "key": "audit_file"},
                        {"version": "v2", "file": "audit_prompts.yaml", "key": "audit_batch"},
                    ],
                }
            }
        }
        with tempfile.TemporaryDirectory() as d:
            p = _os.path.join(d, "registry.yaml")
            with open(p, "w", encoding="utf-8") as f:
                _yaml.safe_dump(reg_spec, f, allow_unicode=True)
            reg = pr.PromptRegistry(p)
        t_default = reg.get("_vtest")
        t_v1 = reg.get("_vtest", version="v1")
        t_v2 = reg.get("_vtest", version="v2")
        self.assertIsNotNone(t_default)
        self.assertIsNotNone(t_v2)
        self.assertEqual(t_default.text, t_v1.text)      # 未指定 → default(v1)
        self.assertNotEqual(t_v1.text, t_v2.text)        # 指定 v2 → 选到不同正文
        self.assertEqual(t_v2.version, "v2")

    def test_load_prompts_dict_version_fallback(self):
        """load_prompts_dict 按 version 选；显式 version / 未命中版本均不报错。"""
        base = pr.load_prompts_dict()
        explicit = pr.load_prompts_dict(version="terminal-first-v1")
        self.assertEqual(base.get("audit_file"), explicit.get("audit_file"))
        # 不存在的版本 → 回退 default，仍能取到正文（分级回退）
        fallback = pr.load_prompts_dict(version="no-such-version")
        self.assertEqual(base.get("audit_file"), fallback.get("audit_file"))
        self.assertTrue(fallback.get("audit_file"))

    def test_default_resolution_matches_legacy_flatten(self):
        """回归护栏（2026-09-20）：`load_prompts_dict()` 在默认配置下必须与「旧摊平行为」等价。

        旧实现把 `all()` 里每个版本的正文按加载顺序写进 `out[name]`（后来者覆盖），
        调用方从不传版本 → `prompt_version` 只进 metadata、从不驱动模板选择。
        新实现改为逐名 `registry.get(name, version=...)`。**风险点**在于：若某个模板有多个版本，
        且它的 `default` 不是「加载顺序最后一条」，默认路径下的正文就会与旧行为不同 ——
        那等于悄悄改了 A2 提示词，会污染所有后续扫描的可比性（且极难察觉）。

        本用例把这份等价性钉死；将来新增多版本模板时若破坏等价性，这里会先红。
        """
        reg = pr.get_registry()
        legacy = {}
        for pe in reg.all():          # all() 的迭代顺序 = 加载顺序，后来者覆盖前者
            legacy[pe.name] = pe.text
        # 两条路径都要等价：①不传版本；②真实扫描实际传的版本（submit_scan_task.py 的
        # canonical payload 里 prompt_version='terminal-first-v1'，run 20/21 options 实测一致）。
        for ver in (None, "terminal-first-v1"):
            current = {k: v for k, v in pr.load_prompts_dict(version=ver).items() if "." not in k}
            tag = "version=None" if ver is None else f"version={ver}"
            self.assertEqual(set(legacy), set(current), f"{tag} 下模板名集合发生变化")
            mismatched = [n for n in legacy if legacy[n] != current.get(n)]
            self.assertEqual(mismatched, [],
                             f"{tag} 下正文与旧行为不一致：{mismatched}")

    def test_each_prompt_name_resolves_to_its_declared_default(self):
        """默认路径必须落在注册表声明的 default 版本上（而非「字典序最大」兜底）。"""
        reg = pr.get_registry()
        versions = {k: v for k, v in pr.load_prompts_dict().items() if k.endswith(".version")}
        for name in reg.names():
            declared = reg.default_version(name)
            resolved = versions.get(f"{name}.version")
            self.assertTrue(declared, f"{name} 未声明 default")
            self.assertEqual(resolved, declared, f"{name} 默认解析到 {resolved}，声明的是 {declared}")


class TestRuleRegistry(unittest.TestCase):
    def test_loads_real_skill(self):
        rules = rr.load_rules()
        self.assertIn("cve-2022-22978", rules)
        sk = rules["cve-2022-22978"]
        self.assertEqual(sk.family, "auth_bypass")
        self.assertTrue(sk.rule_expression)
        self.assertTrue(sk.prompt_fragment)
        self.assertTrue(sk.source_path, "必须记录来源文件，提级时定点回写要用")
        # 状态断言写成「契约」而不是「当前值」：is_active 必须与 status 自洽。
        # （2026-09-20 提级后本规则为 active；旧写法 assertFalse(is_active) 把可变生命周期
        #   当成常量断言，一提级就红。这类断言属于测错了对象。）
        self.assertEqual(sk.is_active, sk.status.strip().lower() == "active")

    def test_consumption_matches_active_status(self):
        """不变量：**只有** active 的 skill 会被 A1/A2 消费（与当前是否已提级无关）。"""
        ids_expr = {e["id"] for e in rr.get_rule_expressions()}
        for sid, sk in rr.load_rules().items():
            if sk.is_active and sk.rule_expression:
                self.assertIn(sid, ids_expr, f"{sid} 已 active 却未进入 A1 规则表达式列表")
            else:
                self.assertNotIn(sid, ids_expr, f"{sid} 未 active（或无表达式）却进入了 A1 列表")
        active_with_fragment = [
            sk for sk in rr.load_rules().values()
            if sk.is_active and sk.prompt_fragment
            and (not sk.languages or "java" in sk.languages)
        ]
        hints = rr.build_skill_hints(language="java")
        self.assertEqual(bool(hints), bool(active_with_fragment),
                         "build_skill_hints 的产出与 active skill 的存在性不一致")

    def test_active_rule_flows_to_a1_and_a2(self):
        # 临时把样板提升为 active，验证「A1 静态通道 + A2 提示词通道」两条消费路径都通
        sk = rr._REGISTRY["cve-2022-22978"]
        old = sk.status
        try:
            sk.status = "active"
            exprs = rr.get_rule_expressions()
            self.assertTrue(any(e["id"] == "cve-2022-22978" for e in exprs))
            self.assertIn("auth_bypass", rr.build_skill_hints(language="java"))
            # A1 消费：analyze_content 合并 active 规则表达式后应命中
            from src.agents.a1_injection_heuristic import analyze_content
            code = ('http.authorizeRequests()'
                    '  .requestMatchers(new RegexRequestMatcher(".*", "/x")).antMatchers("/admin")')
            vulns = analyze_content("SecConfig.java", code, lang="java")
            self.assertTrue(any((v.sink or "") == "cve-2022-22978" for v in vulns),
                            f"active skill 未进入 A1 结果：{[ (v.sink, v.type) for v in vulns ]}")
        finally:
            sk.status = old

    def test_a1_ignores_samples_matching_no_rule_expression(self):
        """精确路径匹配器不属本规则族，不应命中（与规则是否 active 无关）。"""
        from src.agents.a1_injection_heuristic import analyze_content
        code = '.requestMatchers("/admin/**").hasRole("ADMIN")'
        vulns = analyze_content("SecConfig.java", code, lang="java")
        self.assertFalse(any((v.sink or "") == "cve-2022-22978" for v in vulns))

    # --- 2026-09-20 形态修正的锁定测试 -------------------------------------------------
    # 背景：初版 rule_expression 只认字面量 RegexRequestMatcher，但靶场真实落点是
    # Spring Security DSL 形态 regexMatchers(...)，导致规则提 active 也永不命中。
    # 以下三条把「覆盖两种同族形态、不误伤精确匹配器、命中靶场真实文件」锁死。

    def test_cve_rule_expression_covers_both_real_forms(self):
        import re
        expr = rr.load_rules()["cve-2022-22978"].rule_expression
        pat = re.compile(expr)  # 非法正则直接抛错，等价于锁定可编译性
        dsl = '.regexMatchers("/black_path.*").denyAll()'
        self.assertTrue(pat.search(dsl), f"表达式未覆盖 DSL 形态：{expr}")
        literal = 'new RegexRequestMatcher("/black_path.*", null, true)'
        self.assertTrue(pat.search(literal), f"表达式未覆盖字面量形态：{expr}")

    def test_cve_rule_expression_ignores_precise_matchers_and_imports(self):
        import re
        expr = rr.load_rules()["cve-2022-22978"].rule_expression
        pat = re.compile(expr)
        # 负样本：Spring Security 6 的 requestMatchers 精确路径匹配不属该 CVE 范畴
        self.assertFalse(pat.search('.requestMatchers("/admin/**").hasRole("ADMIN")'))
        # import 语句无左括号，不应被当成命中
        self.assertFalse(pat.search(
            'import org.springframework.security.web.util.matcher.RegexRequestMatcher;'))

    def test_cve_rule_hits_real_target_file(self):
        import re
        expr = rr.load_rules()["cve-2022-22978"].rule_expression
        pat = re.compile(expr)
        sdl_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        tgt = os.path.join(sdl_root, "java-sec-code", "src", "main", "java",
                           "org", "joychou", "security", "WebSecurityConfig.java")
        if not os.path.exists(tgt):
            self.skipTest("靶场源码不存在，跳过真实文件命中校验")
        with open(tgt, encoding="utf-8") as fh:
            content = fh.read()
        lines = content.splitlines()
        hits = [content[:m.start()].count("\n") + 1 for m in pat.finditer(content)]
        self.assertTrue(hits, "规则表达式未命中靶场真实漏洞文件")
        for ln in hits:
            self.assertIn("regexMatchers", lines[ln - 1],
                          f"第 {ln} 行命中但非 regexMatchers 落点：{lines[ln - 1]!r}")

    def test_a1_consumes_cve_rule_for_dsl_form_when_active(self):
        rr.load_rules()  # 先触发加载，保证 _REGISTRY 已就绪（用例按字母序可能先于其他用例）
        sk = rr._REGISTRY["cve-2022-22978"]
        old = sk.status
        try:
            sk.status = "active"
            from src.agents.a1_injection_heuristic import analyze_content
            code = ('http.authorizeRequests()\n'
                    '        .regexMatchers("/black_path.*").denyAll()\n'
                    '        .anyRequest().authenticated();\n')
            vulns = analyze_content("WebSecurityConfig.java", code, lang="java")
            self.assertTrue(any((v.sink or "") == "cve-2022-22978" for v in vulns),
                            f"DSL 形态未被 A1 检出：{[(v.sink, v.type) for v in vulns]}")
        finally:
            sk.status = old


class TestRuleGoldenGate(unittest.TestCase):
    """skill golden 回归门禁 + 提级双闸门（2026-09-20）。

    背景：golden / gate.min_recall 此前零代码消费者，「跑 golden 回归」只能人肉目测。
    本组测试锁定门禁真的可执行、可拒绝、成功提级可复现，且拒绝时绝不改文件。

    **隔离设计**：提级会改写真实规则文件的 status。若直接拿线上那条规则做测试，
    断言「提级后仍是 staging」就等于把可变生命周期当成常量 —— 一提级测试就红
    （2026-09-20 实际踩到，5 条测试同时红）。故本组在 setUp 里把 `rule_registry`
    的规则目录指向临时目录，用一条**状态完全由测试掌控**的同构 skill 来验机制。
    """

    SKILL_ID = "tmp-golden-gate"

    def setUp(self):
        import shutil
        import tempfile
        import yaml as _yaml
        self._orig_dir = rr._RULES_DIR
        self._tmp = tempfile.mkdtemp(prefix="rules-gate-")
        spec = {"skills": [{
            "id": self.SKILL_ID,
            "version": 1,
            "status": "staging",
            "family": "auth_bypass",
            "languages": ["java"],
            "payload": {
                "vuln_type": "Broken Access Control",
                "severity": "HIGH",
                "rule_expression": r"(?i)(?:regexMatchers|RegexRequestMatcher)\s*\(",
                "prompt_fragment": "测试用片段",
            },
            "golden": {"corpus": {
                "must_hit": [{"repo": "java-sec-code",
                              "file": "src/main/java/org/joychou/security/WebSecurityConfig.java",
                              "lines": [79]}],
                "must_not_hit": [{"repo": "target-mall",
                                  "file": "src/main/java/com/sanjio/mall/config/SecurityConfig.java"}],
            }},
            "gate": {"min_recall": 1.0},
        }]}
        with open(os.path.join(self._tmp, "tmp_gate.yaml"), "w", encoding="utf-8") as fh:
            _yaml.safe_dump(spec, fh, allow_unicode=True)
        rr._RULES_DIR = Path(self._tmp)   # 模块内是 Path，必须是 Path 才能做 `/` 拼接
        rr.reload_rules()

    def tearDown(self):
        import shutil
        rr._RULES_DIR = self._orig_dir
        rr.reload_rules()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _corpus(self):
        root = rgg.default_corpus_root()
        tgt = root / "java-sec-code" / "src" / "main" / "java" / "org" / "joychou" / "security" / "WebSecurityConfig.java"
        return root, tgt

    def test_gate_passes_on_real_corpus(self):
        root, tgt = self._corpus()
        if not tgt.exists():
            self.skipTest("靶场源码不存在，跳过 golden 门禁校验")
        sk = rr.load_rules()[self.SKILL_ID]
        res = rgg.evaluate_skill(sk, corpus_root=root)
        self.assertEqual(res["status"], "passed")
        self.assertEqual(res["recall"], 1.0)
        self.assertEqual(res["negative_violations"], 0)
        # 证据：命中行必须落在声明的期望行上
        self.assertEqual(res["must_hit"][0]["hit_lines"], [79])

    def test_gate_skips_when_corpus_missing(self):
        import tempfile
        sk = rr.load_rules()[self.SKILL_ID]
        with tempfile.TemporaryDirectory() as d:
            res = rgg.evaluate_skill(sk, corpus_root=d)
        # 语料缺失判 skipped（不阻塞无靶场的机器），且不得判 passed
        self.assertEqual(res["status"], "skipped")
        self.assertTrue(res["missing"])

    def test_promote_requires_human_confirmation(self):
        root, tgt = self._corpus()
        if not tgt.exists():
            self.skipTest("靶场源码不存在，跳过 golden 门禁校验")
        sk = rr.load_rules()[self.SKILL_ID]
        before = os.path.getmtime(sk.source_path)
        res = rgg.promote_skill(self.SKILL_ID, corpus_root=root, confirm=False)
        self.assertFalse(res["ok"])
        self.assertIn("confirmation", res["reason"])
        self.assertEqual(os.path.getmtime(sk.source_path), before, "拒绝提级时不得改动规则文件")
        self.assertEqual(rr.load_rules()[self.SKILL_ID].status, "staging")

    def test_promote_refuses_when_gate_not_passed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            res = rgg.promote_skill(self.SKILL_ID, corpus_root=d, confirm=True)
        self.assertFalse(res["ok"])
        self.assertIn("gate not passed", res["reason"])
        self.assertEqual(rr.load_rules()[self.SKILL_ID].status, "staging")

    def test_promote_success_activates_and_is_idempotent(self):
        """成功路径：门禁 passed + confirm=True → 真正置为 active 并刷新注册表。"""
        root, tgt = self._corpus()
        if not tgt.exists():
            self.skipTest("靶场源码不存在，跳过提级成功路径校验")
        res = rgg.promote_skill(self.SKILL_ID, corpus_root=root, confirm=True)
        self.assertTrue(res["ok"], res.get("reason"))
        self.assertTrue(res["changed"])
        self.assertEqual(rr.load_rules()[self.SKILL_ID].status, "active")
        self.assertTrue(rr.load_rules()[self.SKILL_ID].is_active)
        # 已 active 再提一次：不报错、不改动
        again = rgg.promote_skill(self.SKILL_ID, corpus_root=root, confirm=True)
        self.assertTrue(again["ok"])
        self.assertFalse(again["changed"])

    def test_rewrite_status_is_surgical_and_keeps_comments(self):
        import tempfile
        src = (
            "# 顶部说明注释，必须保留\n"
            "skills:\n"
            "  - id: alpha\n"
            "    version: 1\n"
            "    status: staging\n"
            "    family: a\n"
            "  - id: beta\n"
            "    version: 1\n"
            "    status: staging    # 行尾注释也要保留\n"
            "    family: b\n"
        )
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules.yaml")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(src)
            self.assertTrue(rgg._rewrite_status(p, "beta", "active"))
            with open(p, encoding="utf-8") as fh:
                out = fh.read()
        self.assertIn("# 顶部说明注释，必须保留", out)
        self.assertIn("# 行尾注释也要保留", out)
        self.assertIn("  - id: alpha\n    version: 1\n    status: staging", out)
        self.assertIn("    status: active    # 行尾注释也要保留", out)

    def test_rewrite_status_handles_id_not_first_key(self):
        """id 不在列表项首键时也要能定位并改写。

        yaml.safe_dump 默认按**键名排序**输出，id 常不在首位（形如 `- family: a` 下接
        `  id: alpha`），此时「`- id:` 同行」的朴素实现会找不到目标 —— 实测踩到过。
        """
        import tempfile
        import yaml as _yaml
        doc = {"skills": [
            {"family": "a", "id": "alpha", "status": "staging", "version": 1},
            {"family": "b", "id": "beta", "status": "staging", "version": 1},
        ]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules.yaml")
            with open(p, "w", encoding="utf-8") as fh:
                _yaml.safe_dump(doc, fh, allow_unicode=True)   # 默认 sort_keys=True
            with open(p, encoding="utf-8") as fh:
                before = fh.read()
            self.assertTrue(rgg._rewrite_status(p, "beta", "active"))
            with open(p, encoding="utf-8") as fh:
                after = fh.read()
        self.assertNotEqual(before, after)
        statuses = {s["id"]: s["status"] for s in _yaml.safe_load(after)["skills"]}
        self.assertEqual(statuses, {"alpha": "staging", "beta": "active"},
                         "只应改写目标 skill 的 status")


class TestScanDiffGate(unittest.TestCase):
    """扫描结果差分门禁（D2 差分）—— 2026-09-20。

    锁定三件事：①守卫指标跌破基线必须判回归；②两任务模型画像不一致时必须显式
    指出「不可归因」而不是给出错误结论；③缺 final_report_summary 时不得静默通过。
    """

    _SCHEMA = (
        "CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY, status TEXT, workspace_id INTEGER,"
        " summary_json TEXT)",
        "CREATE TABLE model_runs (id INTEGER PRIMARY KEY, model TEXT, metadata_json TEXT,"
        " task_id INTEGER)",
    )

    def _mkdb(self, tmpdir, tasks, runs):
        """tasks: {id: {status, summary, workspace}}；runs: {task_id: [(model, provider), ...]}"""
        import json as _json
        import sqlite3 as _sq
        p = os.path.join(tmpdir, "t.db")
        con = _sq.connect(p)
        for ddl in self._SCHEMA:
            con.execute(ddl)
        for tid, spec in tasks.items():
            con.execute(
                "INSERT INTO scan_tasks (id, status, workspace_id, summary_json) VALUES (?,?,?,?)",
                (tid, spec.get("status", "completed"), spec.get("workspace", 4),
                 _json.dumps({"final_report_summary": spec.get("summary", {})})),
            )
        rid = 0
        for tid, pairs in runs.items():
            for model, provider in pairs:
                rid += 1
                con.execute(
                    "INSERT INTO model_runs (id, model, metadata_json, task_id) VALUES (?,?,?,?)",
                    (rid, model, _json.dumps({"provider": provider}), tid),
                )
        con.commit()
        con.close()
        return p

    def test_passes_when_guards_hold_and_model_mix_matches(self):
        import tempfile
        from src.core import scan_diff_gate as sdg
        base = {"d2_verified_count": 50, "chain_proven_count": 55, "a1_count": 103}
        cand = {"d2_verified_count": 50, "chain_proven_count": 56, "a1_count": 104}
        with tempfile.TemporaryDirectory() as d:
            db = self._mkdb(d, {1: {"summary": base}, 2: {"summary": cand}},
                            {1: [("qwen3:8b", "ollama")], 2: [("qwen3:8b", "ollama")]})
            res = sdg.evaluate_diff_gate(1, 2, db_path=db)
        self.assertTrue(res["ok"], res.get("reason"))
        self.assertEqual(res["comparability"]["status"], "ok")
        self.assertEqual(res["diff"]["numeric"]["chain_proven_count"]["delta"], 1)

    def test_fails_on_guard_regression(self):
        import tempfile
        from src.core import scan_diff_gate as sdg
        base = {"d2_verified_count": 50, "chain_proven_count": 55}
        cand = {"d2_verified_count": 49, "chain_proven_count": 55}
        with tempfile.TemporaryDirectory() as d:
            db = self._mkdb(d, {1: {"summary": base}, 2: {"summary": cand}},
                            {1: [("qwen3:8b", "ollama")], 2: [("qwen3:8b", "ollama")]})
            res = sdg.evaluate_diff_gate(1, 2, db_path=db)
        self.assertFalse(res["ok"])
        self.assertIn("d2_verified_count", [r["metric"] for r in res["regressions"]])

    def test_flags_incomparable_model_mix(self):
        import tempfile
        from src.core import scan_diff_gate as sdg
        same = {"d2_verified_count": 50, "chain_proven_count": 55}
        with tempfile.TemporaryDirectory() as d:
            db = self._mkdb(d, {1: {"summary": same}, 2: {"summary": same}},
                            {1: [("qwen3:8b", "ollama")], 2: [("glm-4-plus", "zhipu")]})
            res = sdg.evaluate_diff_gate(1, 2, db_path=db)
        # 指标全等，但模型画像不同 -> 结论不可归因，必须判不通过
        self.assertFalse(res["ok"])
        self.assertEqual(res["comparability"]["status"], "mismatch")
        self.assertIn("不可归因", res["reason"])

    def test_missing_summary_does_not_pass_silently(self):
        import tempfile
        from src.core import scan_diff_gate as sdg
        with tempfile.TemporaryDirectory() as d:
            db = self._mkdb(d, {1: {"summary": {"d2_verified_count": 50}},
                                2: {"summary": {}}},
                            {1: [], 2: []})
            res = sdg.evaluate_diff_gate(1, 2, db_path=db)
        self.assertFalse(res["ok"])
        self.assertIn("final_report_summary", res["reason"])

    def test_unknown_task_raises(self):
        import tempfile
        from src.core import scan_diff_gate as sdg
        with tempfile.TemporaryDirectory() as d:
            db = self._mkdb(d, {}, {})
            with self.assertRaises(ValueError):
                sdg.collect_metrics(999, db_path=db)

    def test_collect_metrics_extracts_declared_fields(self):
        import tempfile
        from src.core import scan_diff_gate as sdg
        with tempfile.TemporaryDirectory() as d:
            db = self._mkdb(d, {7: {"summary": {"sca_count": 348, "a2_count": 116,
                                               "by_severity": {"HIGH": 243}}}},
                            {7: [("qwen3:8b", "ollama")]})
            m = sdg.collect_metrics(7, db_path=db)
        self.assertEqual(m["sca_count"], 348)
        self.assertEqual(m["a2_count"], 116)
        self.assertEqual(m["by_severity"]["HIGH"], 243)
        self.assertEqual(m["d2_verified_count"], 0)  # 未声明的数值指标补 0，保证形状稳定
        self.assertEqual(m["model_mix"]["providers"], {"ollama": 1})


class TestAgenticTools(unittest.TestCase):
    def setUp(self):
        a2_tools.reset_tool_stats()

    def test_unknown_tool_is_safe(self):
        res = a2_tools.execute_tool("nope")
        self.assertFalse(res.get("ok"))

    def test_existing_tool_records_stats(self):
        a2_tools.execute_tool("read_file", {"path": "no-such-file-xyz"})
        stats = a2_tools.tool_stats()
        self.assertIn("read_file", stats)
        self.assertEqual(stats["read_file"]["calls"], 1)

    def test_tool_timeout_is_caught(self):
        # 注入一个会 hang 的工具，验证超时返回 ok=False 不卡死
        import time as _t
        a2_tools._EXECUTORS["_slow_test"] = lambda a: (_t.sleep(30) or {"ok": True})
        try:
            res = a2_tools.execute_tool("_slow_test", {}, timeout=0.2)
            self.assertFalse(res.get("ok"))
            self.assertTrue(res.get("timed_out"))
        finally:
            a2_tools._EXECUTORS.pop("_slow_test", None)


class TestAgenticBudget(unittest.TestCase):
    def test_tool_budget_tiers(self):
        from src.agents import a2_agentic as ag
        # 本地小模型：受限上下文 -> 收紧到 <=2000
        self.assertLessEqual(ag._tool_result_budget_chars("qwen3:14b"), 2000)
        # 云端大模型（tier=large）-> 放宽到 4000
        self.assertEqual(ag._tool_result_budget_chars("claude-3-5-sonnet-20241022"), 4000)
        self.assertEqual(ag._tool_result_budget_chars("glm-4-plus"), 4000)
        # 未知模型 -> 保守（<=2000）
        self.assertLessEqual(ag._tool_result_budget_chars("does-not-exist-xyz"), 2000)

    def test_trim_history(self):
        from src.agents import a2_agentic as ag
        msgs = [{"role": "user", "content": "t"}] + \
               [{"role": "assistant", "content": "a"}, {"role": "user", "content": "u"}] * 5
        self.assertEqual(len(ag._trim_history(msgs, 3)), 7)  # 1 + 2*3
        self.assertEqual(ag._trim_history(msgs, 0), msgs)     # keep_rounds<=0 不裁


if __name__ == "__main__":
    unittest.main()
