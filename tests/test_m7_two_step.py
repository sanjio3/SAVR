"""M7 两步重放（存储型写→读配对）测试（2026-10-03）。

覆盖三段：
    ① src/core/replay_plan.py —— 数据结构、自限标记、回显三态、标记反查
    ② A1 读端点静态定位 —— 与写端点判定对称
    ③ echo_marker 证据通道 —— 三态落到 D2 仲裁的正确结论
        （raw 可利用 / escaped 真阴性且 definitive / absent 证据缺失非无害）
"""
import json

from src.core import evidence_channels as _ec
from src.core import replay_plan as _rp


# ── ① replay_plan 核心 ────────────────────────────────────────────────────
def test_marker_is_unique_and_parseable():
    a = _rp.make_self_limiting_marker()
    b = _rp.make_self_limiting_marker()
    assert a != b
    assert _rp.is_marker(a)
    assert not _rp.is_marker("hello world")
    # 标记可拆出短 id 段（实体化/拆散场景用）
    assert _rp.marker_id(a) == a.split("-", 1)[1]
    assert _rp.marker_id("plain") == "plain"


def test_echo_three_states():
    mk = _rp.make_self_limiting_marker()
    # raw：原样出现（可利用）
    assert _rp.classify_echo("<div>%s</div>" % mk, mk) == _rp.ECHO_RAW
    # escaped：整串被实体化包裹（到 sink 但被转义 → 真阴性）
    assert _rp.classify_echo("<div>&lt;%s&gt;</div>" % mk, mk) == _rp.ECHO_ESCAPED
    # absent：没出现
    assert _rp.classify_echo("<div>hello</div>", mk) == _rp.ECHO_ABSENT


def test_echo_raw_when_entity_elsewhere_in_body():
    """正文别处有 `&lt;` 但标记原样输出 —— 必须判 raw，判 escaped 就是漏报。

    这条是实测踩出来的坑（3 字符/8 字符窗口把正文别处的实体化痕迹算进来了），
    模板没转义的场景（th:utext 原样吐 payload）正好落在这里。
    """
    mk = _rp.make_self_limiting_marker()
    assert _rp.classify_echo("a &lt; b " + mk, mk) == _rp.ECHO_RAW
    assert _rp.classify_echo("a &lt; b &gt; " + mk + " &lt; b &gt;", mk) == _rp.ECHO_RAW


def test_echo_raw_when_raw_angle_brackets():
    """`<marker>` 是原字符尖括号包裹 = th:utext 原样输出（可利用），不是转义。"""
    mk = _rp.make_self_limiting_marker()
    assert _rp.classify_echo("<" + mk + ">", mk) == _rp.ECHO_RAW


def test_echo_escaped_when_right_side_amp():
    mk = _rp.make_self_limiting_marker()
    assert _rp.classify_echo("x" + mk + "&amp;", mk) == _rp.ECHO_ESCAPED
    assert _rp.classify_echo("&lt;" + mk, mk) == _rp.ECHO_ESCAPED


def test_build_plan_and_roundtrip_through_raw_json():
    mk = _rp.make_self_limiting_marker()
    plan = _rp.build_replay_plan("comment/add", "POST", "content", "comment/list",
                                 "static", mk)
    assert plan["version"] == _rp.REPLAY_PLAN_VERSION
    assert [s["role"] for s in plan["steps"]] == ["write", "read"]
    # 每步都要自解释：端点/方法/参数/抽取规则都在 raw_json 里，不改表结构
    write_step = plan["steps"][0]
    assert write_step["endpoint"] == "comment/add" and write_step["method"] == "POST"
    assert write_step["param"] == "content" and write_step["value"] == mk
    assert plan["steps"][1]["extract"]["needle"] == mk
    # 挂进 raw_json 再读回，字段不丢
    spec = {"raw_json": json.dumps({"replay_plan": plan})}
    back = _rp.plan_from_spec(spec)
    assert back["marker"] == mk
    assert back["read_endpoint"] == {"endpoint": "comment/list", "source": "static"}


def test_read_endpoint_normalized_from_str():
    """上游可能只塞 str 形态的 read_endpoint，读回来必须归一成 dict（单一形状）。"""
    mk = _rp.make_self_limiting_marker()
    plan = {"version": 1, "enabled": True, "stored_field": "c", "marker": mk,
            "steps": [], "read_endpoint": "comment/list"}
    spec = {"raw_json": json.dumps(plan)}
    back = _rp.plan_from_spec(spec)
    assert back["read_endpoint"] == {"endpoint": "comment/list", "source": "static"}


def test_plan_from_spec_falls_back_to_top_level_fields():
    mk = _rp.make_self_limiting_marker()
    spec = {"raw_json": json.dumps({
        "write_endpoint": "comment/add", "read_endpoint": "comment/list",
        "stored_field": "content", "read_endpoint_source": "static", "marker": mk}),
    }
    back = _rp.plan_from_spec(spec)
    assert back["steps"][0]["endpoint"] == "comment/add"
    assert back["read_endpoint"]["endpoint"] == "comment/list"


def test_scan_read_candidates_finds_the_hit_and_stops():
    mk = _rp.make_self_limiting_marker()
    calls = []

    def fetch(route):
        calls.append(route)
        if route == "comment/list":
            return 200, "<html>%s</html>" % mk
        return 200, "<html>nothing</html>"

    res = _rp.scan_read_candidates(["comment/add", "comment/list", "comment/other"],
                                   mk, fetch, limit=12)
    assert res["state"] == _rp.ECHO_RAW
    assert res["endpoint"] == "comment/list" and res["source"] == "probe_scan"
    # 命中即停，不把候选表扫完（省预算）
    assert calls == ["comment/add", "comment/list"]


def test_scan_read_candidates_absent_when_no_hit():
    mk = _rp.make_self_limiting_marker()
    res = _rp.scan_read_candidates(["a", "b"], mk, lambda r: (200, "clean"), limit=2)
    assert res["state"] == _rp.ECHO_ABSENT
    assert res["endpoint"] == "" and res["exhausted"] is True


def test_scan_read_candidates_respects_limit():
    mk = _rp.make_self_limiting_marker()
    seen = []

    def fetch(route):
        seen.append(route)
        return 200, "clean"

    _rp.scan_read_candidates(["r%d" % i for i in range(50)], mk, fetch, limit=5)
    assert len(seen) == 5


def test_match_read_endpoint_prefers_same_path_get():
    """同路径 GET 是最便宜的一级（零额外请求），优先于全表按字段匹配。"""
    eps = [{"route": "/comment", "method": "GET", "fields": {"body"}, "source": "model"},
           {"route": "/all", "method": "GET", "fields": {"content"}, "source": "model"}]
    # 写 /comment → 读 /comment（同路径命中，不碰字段匹配）
    route, how = _rp.match_read_endpoint(eps, "content", write_route="/comment")
    assert route == "/comment" and how == "same_path_get"
    # 写 /other（表里没有对应的 GET）→ 退化到按字段匹配
    route2, how2 = _rp.match_read_endpoint(eps, "content", write_route="/other")
    assert route2 == "/all" and how2 == "model_field"


def test_collect_read_endpoints_requires_db_read_signal():
    """读端点必须同时满足「GET + 库读信号 + 带出字段」，否则 /login 这类页面会被全算进来。"""
    files = [{"path": "A.java", "language": "java", "content": """
    @GetMapping("/login")
    public String login(String user) { return "login"; }

    @GetMapping("/comment/list")
    public String list(Model m) {
        mapper.selectList(null);
        m.addAttribute("content", x);
        return "list";
    }
    """}]
    eps = _rp.collect_read_endpoints(files, fields=["content"])
    assert "/login" not in [e["route"] for e in eps]
    assert "/comment/list" in [e["route"] for e in eps]


# ── ② A1 读端点静态定位（写接口判定的对称面）──────────────────────────────
def test_a1_analyzer_emits_read_endpoint_for_stored_xss():
    from src.agents.a1_template_xss_analyzer import analyze_files
    files = [
        {"path": "WebController.java", "language": "java", "content": """
        @PostMapping("/comment/add")
        public String add(@RequestParam String signature) {
            mapper.insert(signature); return "ok";
        }
        @GetMapping("/comment")
        public String show(Model model) {
            mapper.selectById(1);
            model.addAttribute("content", o);
            return "detail";
        }
        """},
        # 模板路径必须落在 Thymeleaf 前缀下（classpath:/templates/ + .html），
        # 否则 view_name_to_template_rel 解析不到，存储型假说直接不产出。
        {"path": "templates/detail.html", "language": "template", "content": """
        <div th:utext="${content.signature}"></div>
        """},
    ]
    hypos = analyze_files(files)
    stored = [h for h in hypos if h.get("subtype") == "stored"]
    assert stored, "存储型 XSS 假说没出（模板 sink 与 model key 关联失败）"
    for h in stored:
        assert h.get("write_endpoint"), "写端点不能为空"
        assert h.get("read_endpoint"), "M7：静态侧必须给出读端点，否则两级兜底全白搭"
        assert h.get("read_endpoint_source") == "static"


# ── ③ echo_marker 证据通道 ────────────────────────────────────────────────
def _dast(two_step):
    return {"two_step": two_step}


def _ts(state, endpoint="/comment", source="static"):
    return {"enabled": True, "marker": "sastai-0123456789abcdef",
            "read": {"endpoint": endpoint, "status_code": 200, "state": state},
            "read_endpoint_source": source, "steps_executed": 1}


def test_echo_marker_channel_registered_with_strength_three():
    assert _ec.CHANNEL_STRENGTH["echo_marker"] == 3
    # 同证明力排在 result_point_diff 之前（跨请求回显比同请求回显更硬）
    assert _ec._CHANNEL_PRIORITY["echo_marker"] < _ec._CHANNEL_PRIORITY["result_point_diff"]
    assert _ec.CHANNEL_REPLAY_COST["echo_marker"] == 2   # 写 1 + 读 1，固有开销压不掉


def test_echo_marker_raw_is_confirmable():
    verdict = _ec.verify_with_channels("xss", {}, _dast(_ts("raw")))
    assert verdict["primary_channel"] == "echo_marker"
    assert verdict["harmful"] is True and verdict["sink_reached"] is True
    assert verdict["evidence_strength"] == 3
    assert verdict["echo_state"] == "raw"


def test_echo_marker_escaped_is_true_negative_not_evidence_absence():
    """到 sink 但被转义 = 真阴性，且是**确证**的无害（definitive），不是没证据。

    与 M5 结果点比对同一条纪律：结果点被转义不能抬成可利用，也不能掉成 no_evidence。
    """
    verdict = _ec.verify_with_channels("xss", {}, _dast(_ts("escaped")))
    assert verdict["primary_channel"] == "echo_marker"
    assert verdict["harmful"] is False
    assert verdict["sink_reached"] is True
    assert verdict["echo_state"] == "escaped"


def test_echo_marker_absent_is_evidence_gap_not_harmless():
    verdict = _ec.verify_with_channels("xss", {}, _dast(_ts("absent")))
    echo = [o for o in verdict.get("evidence_channels", [])
            if o["channel"] == "echo_marker"][0]
    assert echo["definitive"] is False
    assert not verdict["harmful"]
    assert "证据缺失" in echo["reason"]


def test_echo_marker_absent_when_two_step_disabled():
    """没配两步重放的 spec 不进这条通道（反射型不该白花 2 次预算）。"""
    assert _ec._echo_marker_ready({})[0] is False
    assert _ec._echo_marker_ready({"two_step": {"enabled": False}})[0] is False


def test_echo_marker_applicable_only_when_read_endpoint_exists():
    """通道适用性由 replay_plan 决定，不由族名硬塞。"""
    plan = {"read_endpoint": {"endpoint": "/comment", "source": "static"}}
    ok, why = _ec._echo_marker_ready({"two_step": {"plan": plan}})
    assert ok and "static" in why
    ok2, why2 = _ec._echo_marker_ready({})
    assert not ok2 and "none" in why2


def test_echo_marker_beats_lower_strength_channels():
    """不短路仲裁：回显（3）必须压过探针断言（2）。"""
    iast = {"state": "sink-reached-probe"}
    dast = _dast(_ts("raw"))
    verdict = _ec.verify_with_channels("xss", iast, dast)
    assert verdict["primary_channel"] == "echo_marker"


def test_two_step_step_skipped_when_main_replay_is_write_endpoint():
    """主重放端点就是写端点时不重复投发（省 1 次预算）。"""
    plan = _rp.build_replay_plan("comment/add", "POST", "content", "comment",
                                 "static", _rp.make_self_limiting_marker())
    spec = {"target_endpoint": "comment/add", "http_method": "POST",
            "raw_json": json.dumps({"replay_plan": plan})}
    assert _rp.plan_from_spec(spec)["read_endpoint"]["endpoint"] == "comment"
