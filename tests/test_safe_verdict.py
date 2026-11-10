"""r58 精确率整改（方案 1/2/3/4/5）的回归锁定。

锁住的每一条都是本轮真实踩过的坑，删掉任何一条都会让修复静默失效：

1. 弱随机用 SecureRandom ⇒ 必须抑制（safe_patterns 原规则只认 SecureRandom，
   漏了 ThreadLocalRandom/UUID/Mac，226 个 FP 只剔到 46）；
2. 常量返回的 helper ⇒ 必须抑制；但**透传 request 的 helper 不许抑制**
   （那是真外部源，误杀直接掉召回）。判据必须走「解析被调方法体」的通用机制，
   不能按方法名硬编码；
3. Math.random / 裸 new Random() ⇒ deny 生效，不许抑制（真实项目里
   「既有强随机又用 Math.random」仍应报）；
4. 类级窗口而不是 ±15 行：OWASP 的 sink 行常落在 doGet 的委托行上
   （`doPost(request, response);`），方法级窗口会取到空壳 doGet 而一条不命中；
5. 裁决器任何异常都必须 fail-open（不抑制），绝不能因裁决故障挡住 spec 登记；
6. flow_complete 曾恒为 False：根因是 _sink_present 只看 vuln.sink（常空），
   不看平台已经记好的 vuln.file + vuln.line。
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.core.safe_verdict import judge_spec  # noqa: E402
from src.core.const_prop import list_index_value_is_literal  # noqa: E402
from src.core.proof_obligations import _sink_present  # noqa: E402

SECURE = """
public class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("p");
        int v = new SecureRandom().nextInt(100);
        response.getWriter().println(v);
    }
}
"""

THREAD_LOCAL = SECURE.replace("new SecureRandom()", "ThreadLocalRandom.current()")
UUID_RNG = SECURE.replace("new SecureRandom()", "UUID.randomUUID()")
MATH_RANDOM = SECURE.replace("new SecureRandom()", "Math.random()")
BARE_RANDOM = SECURE.replace("new SecureRandom()", "new Random()")

# 常量返回 helper：类名/方法名都是**随便起的**，证明判据走的是机制不是硬编码
HELPER_CONST_SRC = """
public class PlaceholderHelper {
    private String prefix = "x";
    public String getPlaceholder(String p) {
        return "bar";
    }
}
"""

HELPER_PASSTHROUGH_SRC = """
public class PlaceholderHelper {
    private HttpServletRequest request;
    public PlaceholderHelper(HttpServletRequest request) { this.request = request; }
    public String getPlaceholder(String p) {
        return request.getParameter(p);
    }
}
"""

SAFE_HELPER = """
public class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        PlaceholderHelper scr = new PlaceholderHelper(request);
        String param = scr.getPlaceholder("T");
        String sql = "SELECT * FROM t WHERE a = '" + param + "'";
        stmt.executeQuery(sql);
    }
}
"""

# 透传 request 的版本（同一个方法名，只有方法体不同）—— 必须**不许**抑制
REAL_EXTERNAL = SAFE_HELPER

LIST_SAFE = """
public class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String bar = "alsosafe";
        List<String> valuesList = new ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(request.getParameter("p"));
        valuesList.add("moresafe");
        valuesList.remove(0);
        bar = valuesList.get(1);
        response.getWriter().println(bar);
    }
}
"""


def _mk(src: str, tmp_path: str, family: str = "weak_random"):
    p = os.path.join(tmp_path, "T.java")
    with open(p, "w", encoding="utf-8") as f:
        f.write(src)
    return p, family


def _mk_pair(main_src: str, helper_src: str, tmp_path: str):
    """写两个文件并把它俩所在目录当 code_root（跨文件解析需要）。"""
    with open(os.path.join(tmp_path, "T.java"), "w", encoding="utf-8") as f:
        f.write(main_src)
    with open(os.path.join(tmp_path, "PlaceholderHelper.java"), "w", encoding="utf-8") as f:
        f.write(helper_src)
    return os.path.join(tmp_path, "T.java")


def test_secure_random_suppressed():
    p, fam = _mk(SECURE, ROOT, "weak_random")
    r = judge_spec(family=fam, sink_file=p, sink_line=4)
    assert r["suppressed"] is True, r
    assert r["rule"] == "strong_rng_only", r


def test_thread_local_random_and_uuid_also_suppressed():
    """safe_patterns 原规则只认 SecureRandom，漏了这两类（226 FP 只剔到 46 的根因）。"""
    for src, label in ((THREAD_LOCAL, "ThreadLocalRandom"), (UUID_RNG, "UUID.randomUUID")):
        p, fam = _mk(src, ROOT, "weak_random")
        r = judge_spec(family=fam, sink_file=p, sink_line=4)
        assert r["suppressed"] is True, f"{label} 未被抑制: {r}"


def test_math_random_denied():
    p, fam = _mk(MATH_RANDOM, ROOT, "weak_random")
    assert judge_spec(family=fam, sink_file=p, sink_line=4)["suppressed"] is False


def test_bare_random_denied():
    p, fam = _mk(BARE_RANDOM, ROOT, "weak_random")
    assert judge_spec(family=fam, sink_file=p, sink_line=4)["suppressed"] is False


def test_constant_returning_helper_suppressed(tmp_path):
    """被调方法的每个 return 都是字面量 ⇒ 该调用值是常量 ⇒ 抑制。

    类名 / 方法名都是随手起的，判据不能依赖名字（原来靠 `\\.getTheValue\\(` 硬编码，
    换个项目必然零命中 —— 见 safe_verdict._EXTRA_RULES 上方的注释）。
    """
    p = _mk_pair(SAFE_HELPER, HELPER_CONST_SRC, str(tmp_path))
    r = judge_spec(family="sql_injection", sink_file=p, sink_line=5, code_root=str(tmp_path))
    assert r["suppressed"] is True, r
    assert r["rule"] == "untaint_constant_call", r


def test_passthrough_helper_not_suppressed(tmp_path):
    """方法体是 `return request.getParameter(p);` —— 透传外部输入，抑制它 = 误杀真漏洞。

    这一条同时锁住「同名方法、不同方法体必须区分」：类名方法名与上一个用例完全一样，
    只有方法体不同，结果必须相反。名字白名单做不到这一点，机制才能。
    """
    p = _mk_pair(REAL_EXTERNAL, HELPER_PASSTHROUGH_SRC, str(tmp_path))
    assert judge_spec(family="sql_injection", sink_file=p, sink_line=5,
                      code_root=str(tmp_path))["suppressed"] is False


def test_untaint_only_applies_to_input_driven_families(tmp_path):
    """「值不可控 ⇒ 安全」只对注入类成立。weak_hash 用 MD5 哈希常量仍然是漏洞。

    r60 实测：不区分族语义直接放开会误杀 44 个 TP（TPR 降 3.11pp，超 3pp 门限）。
    """
    p = _mk_pair(SAFE_HELPER, HELPER_CONST_SRC, str(tmp_path))
    assert judge_spec(family="weak_hash", sink_file=p, sink_line=5,
                      code_root=str(tmp_path))["suppressed"] is False


def test_constant_call_requires_no_external_input(tmp_path):
    """类里只要有一处读外部输入，类级窗口就推不出「值都是常量」⇒ 不抑制。"""
    src = SAFE_HELPER.replace(
        'String param = scr.getPlaceholder("T");',
        'String param = scr.getPlaceholder("T") + request.getParameter("q");')
    p = _mk_pair(src, HELPER_CONST_SRC, str(tmp_path))
    assert judge_spec(family="sql_injection", sink_file=p, sink_line=5,
                      code_root=str(tmp_path))["suppressed"] is False


def test_literal_list_index_suppressed(tmp_path):
    """列表索引偏移：get(1) 实际取到 "moresafe"，不是 param。"""
    p, _fam = _mk(LIST_SAFE, str(tmp_path), "xss")
    r = judge_spec(family="xss", sink_file=p, sink_line=10, code_root=str(tmp_path))
    assert r["suppressed"] is True, r
    assert r["rule"] == "untaint_literal_index", r


def test_sink_line_on_delegate_call_still_suppressed():
    """类级窗口的意义：sink 行落在 doGet 委托行上（真实 OWASP 的写法）也要能判。"""
    p, fam = _mk(SECURE, ROOT, "weak_random")
    r = judge_spec(family=fam, sink_file=p, sink_line=2)
    assert r["suppressed"] is True, r


def test_fail_open_on_unreadable_file():
    r = judge_spec(family="weak_random", sink_file="/nonexistent/xx.java", sink_line=10)
    assert r["suppressed"] is False
    assert r["confidence_boost"] == 0.0


def test_positive_evidence_gives_confidence_boost_without_suppressing():
    src = SECURE.replace("new SecureRandom()", 'new Random().nextInt(100) + MD5')
    src = src.replace("import", "import java.security.MessageDigest; // import", 1)
    p, fam = _mk(src, ROOT, "weak_hash")
    r = judge_spec(family=fam, sink_file=p, sink_line=4)
    assert r["suppressed"] is False
    assert r["confidence_boost"] > 0.0, r
    assert r["positive_rule"] == "weak_digest_used", r


def test_list_index_value_is_literal():
    """benchmark 安全变体：add("safe") / add(param) / add("moresafe") / remove(0) / get(1)"""
    src = """
    List<String> valuesList = new ArrayList<String>();
    valuesList.add("safe");
    valuesList.add(param);
    valuesList.add("moresafe");
    valuesList.remove(0);
    bar = valuesList.get(1);
    """
    ok, val = list_index_value_is_literal(src)
    assert ok is True and val == "moresafe", (ok, val)


def test_list_index_unknown_is_not_literal():
    """get 取到变量 ⇒ 不可确定 ⇒ 不判安全（宁可漏抑制不误杀）。"""
    src = """
    List<String> v = new ArrayList<String>();
    v.add("safe");
    v.add(param);
    v.remove(0);
    x = v.get(0);
    """
    assert list_index_value_is_literal(src)[0] is False


def test_sink_present_fallback_uses_file_and_line():
    """flow_complete 曾恒 False 的根因：平台记了 file+line，但 vuln.sink 是空串。"""

    class V:
        sink = ""
        file = "src/main/java/T.java"
        line = 28

    assert _sink_present(V(), None) is True

    class VEmpty:
        sink = ""
        file = ""
        line = 0

    assert _sink_present(VEmpty(), None) is False
    assert _sink_present(VEmpty(), {"poc_chain": [{"stage": "sink"}]}) is True
