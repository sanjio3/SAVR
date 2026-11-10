"""族名漂移修复的回归守卫（2026-09-20）。

背景（run 22 实测，全部为真实数据）：
    family 来源 `payload_family or _norm_family(vuln_dict)` 的两个上游都会错，且归一表
    救不了「概念判错」：
      - /urlRedirect/setHeader    finding.type 已是正确的 url_redirect，却被 A2 的
                                  payload_family=ssrf 覆盖（优先级更高）→ spec.family=ssrf
      - /crlf/safecode            type 判成「注入类-命令注入」→ command_execution
      - /url/vuln/url_bypass      type 判成 path_traversal
    后果：基准对账 `_spec_match` 要求族 token 命中，这三类因族名不符被判「未入环」，
    导出「跑不通」的假象（实际 spec 已存在且已 sink-reached-probe）。

本文件锁定 `src.core.normalize.correct_family_by_evidence` 的行为与安全边界。
"""
import pytest

from src.core.normalize import correct_family_by_evidence, normalize_family

# ---- run 22 的真实三元组（route / file / sink 均取自 findings 表，非构造） ----
CASE_URL_REDIRECT = dict(
    family="ssrf",
    route="/urlRedirect/setHeader",
    file="src/main/java/org/joychou/controller/URLRedirect.java",
    sink="",
)
CASE_CRLF = dict(
    family="command_execution",
    route="/crlf/safecode",
    file="src/main/java/org/joychou/controller/CRLFInjection.java",
    sink="",
)
CASE_URL_WHITELIST = dict(
    family="path_traversal",
    route="/url/vuln/url_bypass",
    file="src/main/java/org/joychou/controller/URLWhiteList.java",
    sink="",
)


class TestRealDriftCases:
    def test_url_redirect_not_overwritten_by_payload_family(self):
        """payload_family=ssrf 覆盖了正确的 type=url_redirect —— 证据层必须纠正回来。"""
        r = correct_family_by_evidence(**CASE_URL_REDIRECT)
        assert r["family"] == "url_redirect"
        assert r["original"] == "ssrf"
        assert r["corrected"] == "1"
        assert r["rule"] == "url_redirect"
        assert "urlredirect" in r["evidence"]

    def test_crlf_misjudged_as_command_execution(self):
        r = correct_family_by_evidence(**CASE_CRLF)
        assert r["family"] == "crlf_injection"
        assert r["original"] == "command_execution"
        assert r["corrected"] == "1"

    def test_url_whitelist_misjudged_as_path_traversal(self):
        r = correct_family_by_evidence(**CASE_URL_WHITELIST)
        assert r["family"] == "url_whitelist_bypass"
        assert r["original"] == "path_traversal"
        assert r["corrected"] == "1"

    @pytest.mark.parametrize(
        "case,tokens",
        [
            (CASE_URL_REDIRECT, ("redirect",)),
            (CASE_CRLF, ("crlf", "header")),
            (CASE_URL_WHITELIST, ("url", "whitelist")),
        ],
    )
    def test_corrected_family_satisfies_golden_tokens(self, case, tokens):
        """纠正后的族名必须能命中 JAVA_SEC_CODE 的族 token —— 否则基准仍判「未入环」。

        这是本次修复的目的本身：`round_report._spec_match` 要求 **族 token 命中 且 路由命中**。
        """
        fam = correct_family_by_evidence(**case)["family"]
        assert any(t in fam for t in tokens), f"{fam} 未命中任何 token {tokens}"


class TestSafetyBoundaries:
    def test_evidence_agrees_with_llm_records_rule_without_correction(self):
        """证据与 LLM 判断一致时不得记成「纠正」（否则制造无意义 diff）。"""
        r = correct_family_by_evidence(
            "ssrf", route="/ssrf/urlConnection/vuln",
            file="src/main/java/org/joychou/controller/SSRF.java",
        )
        assert r["family"] == "ssrf"
        assert r["corrected"] == "0"
        assert r["rule"] == "ssrf"
        assert r["evidence"]

    def test_no_evidence_never_invents_a_family(self):
        r = correct_family_by_evidence("sql_injection", route="/login", file="LoginController.java")
        assert r["family"] == "sql_injection"
        assert r["corrected"] == "0"
        assert r["rule"] == ""

    def test_empty_family_returns_empty(self):
        r = correct_family_by_evidence("", route="/anything", file="Anything.java")
        assert r["family"] == "" and r["original"] == "" and r["corrected"] == "0"

    def test_file_evidence_requires_bound_route(self):
        """未绑定入口的 finding 只靠文件名不得改族。

        反例来源：URLRedirect.java:88 是 safe 方法里的 `response.getWriter().write("url forbidden")`，
        被 A2 判成 xss。它没有 route，此时若仅凭文件名把族改成 url_redirect，就会把一个
        「同文件里的另一类漏洞」也一起改写 —— 所以文件名只作为有入口时的补充证据。
        """
        r = correct_family_by_evidence("xss", route="", file="URLRedirect.java")
        assert r["family"] == "xss"
        assert r["corrected"] == "0"

    def test_url_redirect_rule_does_not_steal_xss_sink(self):
        """可覆盖集合刻意不含 xss：同一文件里 getWriter 直出确实更像 XSS，不抢 LLM 的判断。"""
        r = correct_family_by_evidence(
            "xss", route="/urlRedirect/sendRedirect/sec", file="URLRedirect.java",
            sink="response.getWriter 直出",
        )
        assert r["family"] == "xss"
        assert r["corrected"] == "0"

    def test_generic_token_url_does_not_trigger_whitelist_rule(self):
        """`url` 是泛词，不得单独触发白名单绕过（针必须是 url_bypass/urlwhitelist）。"""
        r = correct_family_by_evidence(
            "ssrf", route="/ssrf/urlConnection/vuln", file="SSRF.java",
        )
        assert r["family"] == "ssrf"

    def test_allow_file_without_route_fixes_crlf(self):
        """findings 落库场景常无 route：开启开关后，文件专用针（crlf）可独立纠族。

        真实数据（run 27 finding 11035）：CRLFInjection.java 被上游判成 command_execution。
        """
        r = correct_family_by_evidence(
            "command_execution", route="", file="CRLFInjection.java",
            allow_file_without_route=True,
        )
        assert r["family"] == "crlf_injection"
        assert r["corrected"] == "1"
        assert r["evidence"].startswith("file~crlf")

    def test_allow_file_without_route_still_protects_xss(self):
        """开关开启也不得抢走 xss —— url_redirect 的可覆盖集合不含 xss（同 test_url_redirect_*）。"""
        r = correct_family_by_evidence(
            "xss", route="", file="URLRedirect.java", allow_file_without_route=True,
        )
        assert r["family"] == "xss"
        assert r["corrected"] == "0"

    def test_allow_file_without_route_fixes_url_whitelist(self):
        """url_whitelist_bypass 现已授予 file_dedicated（2026-09-22 修正）。

        真实数据（run 38 findings 16739/16802/16894/16895/16896/16897）：URLWhiteList.java
        的 6 条 finding 在落库侧被判成 path_traversal，而 findings 常无 route —— 此前
        「不授予 file_dedicated」使它们永远纠不回来，族名误归因「本体」在 findings 侧未修。
        现在移除 xss、授予文件针独立生效后，无 route 也能纠正。
        """
        r = correct_family_by_evidence(
            "path_traversal", route="", file="URLWhiteList.java",
            allow_file_without_route=True,
        )
        assert r["family"] == "url_whitelist_bypass"
        assert r["corrected"] == "1"
        assert r["evidence"].startswith("file~urlwhitelist")
        # 有 route 时该规则照常生效。
        r2 = correct_family_by_evidence(
            "path_traversal", route="/url/vuln/url_bypass", file="URLWhiteList.java",
        )
        assert r2["family"] == "url_whitelist_bypass"

    def test_url_whitelist_rule_does_not_steal_xss(self):
        """可覆盖集合不含 xss：URLWhiteList.java:138/140 的反射 XSS（run 38 finding
        16926/16927）即便文件针独立生效也抢不走 —— 这是授予 file_dedicated 的前提。"""
        r = correct_family_by_evidence(
            "xss", route="", file="URLWhiteList.java", allow_file_without_route=True,
        )
        assert r["family"] == "xss"
        assert r["corrected"] == "0"

    def test_allow_file_without_route_still_respects_ungranted_rules(self):
        """未授予 file_dedicated 的规则即便开开关也不得凭文件改族（以 sql_injection 的
        /jdbc 针为例：它只认 route，文件名里带 jdbc 也不生效）。"""
        r = correct_family_by_evidence(
            "generic", route="", file="JdbcController.java",
            allow_file_without_route=True,
        )
        assert r["family"] == "generic"
        assert r["corrected"] == "0"

    def test_placeholder_family_is_overridable_by_jsonp_evidence(self):
        """占位族名 none 不携带概念信息：/jsonp 路由命中即纠正为 jsonp_referer。

        真实数据（run 27 spec 7475）：route=/jsonp、family="none"，因 none 不在
        jsonp_referer 的可覆盖集合内而卡死在 none，黄金集对账无法按族名入环。
        """
        r = correct_family_by_evidence("none", route="/jsonp", file="WebConfig.java")
        assert r["family"] == "jsonp_referer"
        assert r["corrected"] == "1"
        assert r["evidence"].startswith("route~jsonp")

    def test_placeholder_family_does_not_bypass_evidence_requirement(self):
        """占位族名只在**确有证据命中**时才被纠正，无证据不得臆造族名。"""
        r = correct_family_by_evidence("none", route="/some/other", file="Foo.java")
        assert r["family"] == "none"
        assert r["corrected"] == "0"

    def test_real_family_still_guarded_by_overrideable_set(self):
        """真实族名（xss）不受占位规则影响：仍须落在可覆盖集合内才允许纠正。"""
        r = correct_family_by_evidence("xss", route="/jsonp", file="WebConfig.java")
        # jsonp_referer 的可覆盖集合含 xss → 仍按集合规则纠正（行为不变）。
        assert r["family"] == "jsonp_referer"
        r2 = correct_family_by_evidence("xss", route="/urlRedirect/x", file="URLRedirect.java")
        # url_redirect 的可覆盖集合不含 xss → 不纠正（安全边界未被占位规则削弱）。
        assert r2["family"] == "xss"

    def test_default_call_site_behaviour_unchanged(self):
        """缺省不开启开关 → 与历史行为一致（spec 侧口径不变），无回归。"""
        r = correct_family_by_evidence("command_execution", route="", file="CRLFInjection.java")
        assert r["family"] == "command_execution"
        assert r["corrected"] == "0"

    def test_sink_api_evidence_only_for_unique_apis(self):
        """sendRedirect 是 url_redirect 唯一诊断 API；即便 route 缺失也允许单凭它纠正。"""
        r = correct_family_by_evidence("ssrf", route="", file="SomeController.java",
                                       sink="response.sendRedirect")
        assert r["family"] == "url_redirect"
        assert r["corrected"] == "1"
        assert r["evidence"].startswith("sink~sendredirect")

    def test_overrideable_set_does_not_widen_beyond_listed_families(self):
        """未落入可覆盖集合时一律不动 —— 这是防止「把正确族名改窄」的唯一屏障。

        实测教训：早期把多数规则设成无条件覆盖，结果 /shiro/deserialize、/fastjson/deserialize、
        /xstream 的 family=deserialization 被改窄成 shiro/fastjson/xstream，而基准的族 token
        恰恰是粗粒度的 deserial，直接丢 5 类。此处以 /xstream 场景锁定。
        """
        for fam in ("deserialization", "template-injection", "jndi_injection"):
            pass
        r = correct_family_by_evidence("deserialization", route="/xstream", file="XStreamRce.java")
        assert r["family"] == "deserialization" and r["corrected"] == "0"

    def test_no_rule_uses_unconditional_override(self):
        """结构守卫：规则表里不得再出现「可覆盖集合 = None」（无条件覆盖）。"""
        from src.core.normalize import _EVIDENCE_FAMILY_RULES
        bad = [r[0] for r in _EVIDENCE_FAMILY_RULES if r[3] is None]
        assert not bad, f"以下规则是无条件覆盖，必须显式给出可覆盖集合：{bad}"

    def test_needles_do_not_cross_match_across_families(self):
        """针不得跨族子串误命中。

        实测教训：早期针 "xstream" 会命中 **xlsxstreamerxxe.java**（子串），把 XXE 改成 XStream。
        """
        r = correct_family_by_evidence(
            "xxe", route="/xlsx-streamer/readxlsx",
            file="src/main/java/org/joychou/controller/othervulns/xlsxStreamerXXE.java",
        )
        assert r["family"] == "xxe", "xlsxStreamerXXE 是 XXE，不得被 xstream 针抢走"

    def test_pure_function_does_not_mutate_inputs(self):
        case = dict(CASE_CRLF)
        correct_family_by_evidence(**case)
        assert case == CASE_CRLF


class TestNormalizeTableCoverage:
    """这四类此前在 `_FAMILY_KEYWORDS` 里**完全没有条目**，A2 写什么就原样返回。"""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CRLF Injection", "crlf_injection"),
            ("crlf", "crlf_injection"),
            ("URL whitelist Bypass", "url_whitelist_bypass"),
            # JWT 弱密钥按平台既有设计属**暴露轴** weak-crypto（不是业务族 auth_session）：
            # exploit_spec._EXPOSURE_FAMILY_ALIASES 里 "jwt-硬编码或弱密钥" -> "weak-crypto"。
            # 裸 "jwt" 针会把它抢成业务轴（flow_type 由 exposure 变 business_logic），故刻意不登记。
            ("JWT硬编码或弱密钥", "weak_crypto"),
            ("broken access control", "broken_access_control"),
            ("越权改密/账号接管", "bola"),
            ("url_redirect", "url_redirect"),
        ],
    )
    def test_new_keywords_canonicalize(self, raw, expected):
        assert normalize_family(raw) == expected

    def test_bare_jwt_needle_must_not_hijack_business_labels(self):
        """业务族表已把 jwt 系标签归到 auth_session，技术族表不得用裸针抢走它们。"""
        for raw in ("JWT安全漏洞", "jwt伪造/权限提升", "jwt-验证逻辑缺陷-(alg:none)"):
            assert normalize_family(raw) == "auth_session", raw

    def test_existing_families_not_regressed(self):
        for raw, expected in (
            ("sql injection", "sql_injection"),
            ("SSRF", "ssrf"),
            ("命令执行", "command_execution"),
            ("路径穿越", "path_traversal"),
            ("反序列化", "deserialization"),
            ("跨站脚本", "xss"),
            ("越权改密/账号接管", "bola"),
            ("垂直越权", "vertical_privesc"),
            ("水平越权(idor)", "bola"),
            ("竞态条件", "race"),
        ):
            assert normalize_family(raw) == expected, raw

    def test_exposure_axis_is_preserved(self):
        """漂移修复不得把暴露轴的东西挪到别的轴（derive_flow_type 是前端标签与重放器选择依据）。"""
        from src.core.exploit_spec import derive_flow_type
        for raw in ("JWT硬编码或弱密钥", "弱密码存储"):
            assert derive_flow_type(normalize_family(raw)) == "exposure", raw


class TestRegistryWiring:
    def test_registry_imports_the_corrector(self):
        """接线守卫：纠正函数必须真被登记路径引用（防止只写函数不接线）。"""
        import src.iast.trigger_spec_registry as m
        assert hasattr(m, "correct_family_by_evidence")

    def test_correction_happens_after_vhash_and_before_register(self):
        """顺序守卫：纠正必须位于 vhash 计算之后、register_trigger_spec 之前。

        否则族名会回流进 `_canon_family` → vuln_hash 变号 → spec 与 finding 的哈希绑定断裂。
        """
        import inspect
        import src.iast.trigger_spec_registry as m
        src = inspect.getsource(m)
        i_hash = src.index("vulnerability_hash_v2(canonicalize_vuln_for_hash(")
        i_fix = src.index("correct_family_by_evidence(")
        i_reg = src.index("iast.register_trigger_spec({")
        assert i_hash < i_fix < i_reg
