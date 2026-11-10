"""A1「文件读写 sink」污点门控：跨文件包装传播路径必须同样受门控。

2026-10-04 由 OWASP 靶场对账发现（详见 改进清单.md 2026-10-04 第一节）：
`src/agents/a1_injection_heuristic.py:150` 的注释声称「本规则补上文件读写构造，并走污点门控
避免无差别报」，但实测 cmdi 用例上大量 `Utils.printOSCommandResults(...) → 文件读写 sink`
是无差别命中。两处根因：

1. 门控只写在「直接规则命中」循环里（`analyze_content` 的 `if sink in _TAINT_GATED_SINKS`），
   而 `build_sink_wrappers` → `_wrapper_call_hits` 的**跨文件包装传播**路径完全不过门控。
2. 传播时 sink 名被装饰成 `call + " → " + info["sink"]`，门控按 sink 名**精确字符串**匹配，
   带前缀的名字永远匹配不上 `_TAINT_GATED_SINKS` 里的裸名 ⇒ 即使补判断也会静默 no-op。

本文件锁定**目标语义**（红灯）：路径穿越的成立要件是「**目标路径**由外部输入决定」，
而不是「调用点传了脏数据」。据此：

- 包装方法内部把路径写死（哪怕拼接了方法自己的参数）而调用方只传内容 → 不得报；
- 包装方法的 sink 路径表达式引用了「调用点传入污点表达式」的那个形参 → 应报；
- 直接命中仍旧只看 sink 实参是否带污点（不得回归）；
- 非门控族（SSRF 等）的传播行为不得因本次修复而改变（不得回归掉召回）。

测试用的三个包装方法刻意对应 OWASP Benchmark 的真实形态：
`Utils.printOSCommandResults` 是基准自带的写文件工具（路径写死、内容由调用方给），
它在每个 cmdi 用例里都被调用 ⇒ 就是那批无差别命中的来源。
"""
from src.agents import a1_injection_heuristic as H

UTILS = """package org.owasp.benchmark.utils;

import java.io.FileOutputStream;

public class Utils {
    public static final String TESTFILES_DIR = "C:/benchmark/";

    // ① 基准自带的写文件工具：目标路径由「方法自己的参数」拼出，调用方只提供内容。
    public static void printOSCommandResults(String cmdOut, int fileNum) throws Exception {
        FileOutputStream fos = new FileOutputStream(TESTFILES_DIR + "cmd" + fileNum);
        fos.write(cmdOut.getBytes());
        fos.close();
    }

    // ② 真·路径穿越包装：sink 的路径形参直接就是调用方传入的那个值。
    public static void writeUserFile(String path, byte[] content) throws Exception {
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(content);
        fos.close();
    }

    // ③ 非门控族（SSRF）：传播行为不得受本次修复影响。
    public static void fetch(String url) throws Exception {
        java.net.URL u = new java.net.URL(url);
        u.openConnection().getInputStream();
    }
}
"""

# 调用 ①：实参带污点，但传的是「内容」，路径仍由方法内写死 ⇒ 不得报路径穿越
CALLER_STATIC_PATH = """package org.owasp.benchmark.test;

import org.owasp.benchmark.utils.Utils;

public class BenchmarkTest00123 {
    public void doPost(javax.servlet.http.HttpServletRequest request,
                       javax.servlet.http.HttpServletResponse response) throws Exception {
        String cmd = request.getParameter("cmd");
        Utils.printOSCommandResults(cmd, 1);
    }
}
"""

# 调用 ②：形参 path 被赋的正是污点 ⇒ 路径可被外部控制 ⇒ 应报
CALLER_TAINTED_PATH = """package org.owasp.benchmark.test;

import org.owasp.benchmark.utils.Utils;

public class BenchmarkTest00201 {
    public void doPost(javax.servlet.http.HttpServletRequest request,
                       javax.servlet.http.HttpServletResponse response) throws Exception {
        String p = request.getParameter("path");
        Utils.writeUserFile(p, "x".getBytes());
    }
}
"""

# 直接命中：sink 实参带污点才报
DIRECT_HIT = """package org.owasp.benchmark.test;

public class BenchmarkTest00300 {
    public void doPost(javax.servlet.http.HttpServletRequest request,
                       javax.servlet.http.HttpServletResponse response) throws Exception {
        String f = request.getParameter("file");
        new java.io.FileOutputStream(f).write(1);
    }
    public void doGet(javax.servlet.http.HttpServletRequest request,
                      javax.servlet.http.HttpServletResponse response) throws Exception {
        new java.io.FileOutputStream("/tmp/static-name").write(1);
    }
}
"""

# 非门控族：SSRF 包装调用必须照旧传播
CALLER_SSRF = """package org.owasp.benchmark.test;

import org.owasp.benchmark.utils.Utils;

public class BenchmarkTest00401 {
    public void doPost(javax.servlet.http.HttpServletRequest request,
                       javax.servlet.http.HttpServletResponse response) throws Exception {
        String u = request.getParameter("url");
        Utils.fetch(u);
    }
}
"""


def _f(path, content):
    return {"path": path, "content": content, "language": "java"}


def _analyze(*pairs):
    files = [_f(f"/src/{name}", body) for name, body in pairs]
    return H.analyze_files(files)


def _file_sinks(vulns, path_suffix):
    """挑出指定文件里、族为 path-traversal（type=Path Traversal）的条目 sink 列表。"""
    return [v.sink for v in vulns
            if v.file.endswith(path_suffix) and v.type == "Path Traversal"]


def test_wrapper_with_static_path_is_not_propagated():
    """① 包装方法内部写死路径、调用方只传内容 ⇒ 不得报路径穿越（当前会报，红灯）。"""
    vulns = _analyze(("Utils.java", UTILS),
                     ("BenchmarkTest00123.java", CALLER_STATIC_PATH))
    sinks = _file_sinks(vulns, "BenchmarkTest00123.java")
    assert not sinks, f"目标路径不可控，不该报路径穿越，实际报了：{sinks}"


def test_wrapper_path_param_fed_by_tainted_arg_is_propagated():
    """② 包装方法的 sink 路径形参被喂了污点 ⇒ 应报（红/绿都应成立，防修复过头）。"""
    vulns = _analyze(("Utils.java", UTILS),
                     ("BenchmarkTest00201.java", CALLER_TAINTED_PATH))
    sinks = _file_sinks(vulns, "BenchmarkTest00201.java")
    assert sinks, "路径由污点决定却没报，修复过头了（漏报真漏洞）"


def test_direct_hit_still_gated_by_taint():
    """③ 直接命中：带污点报、纯静态不报（原门控行为不得回归）。"""
    vulns = _analyze(("BenchmarkTest00300.java", DIRECT_HIT))
    lines = [v.line for v in vulns
             if v.file.endswith("BenchmarkTest00300.java") and v.type == "Path Traversal"]
    assert len(lines) == 1, f"应恰好报 1 条（带污点那条），实际 {lines}"
    # 带污点的是 doPost（第一个方法，行号更小）
    assert lines[0] < 20, f"报出来的应是 doPost 里的污点写入，实际行号 {lines[0]}"


def test_non_gated_family_propagation_unchanged():
    """④ 非门控族（SSRF）传播行为不受影响（不得为了降文件族误报而砍掉其它族）。"""
    vulns = _analyze(("Utils.java", UTILS),
                     ("BenchmarkTest00401.java", CALLER_SSRF))
    ssrf = [v.sink for v in vulns
            if v.file.endswith("BenchmarkTest00401.java") and v.type == "SSRF"]
    assert ssrf, "SSRF 包装传播被误伤，召回会掉"
