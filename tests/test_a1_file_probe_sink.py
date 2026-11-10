"""回归锁：A1 路径穿越的「文件元数据探测」sink（2026-10-07 新增）。

## 为什么补这条

`a1_injection_heuristic` 原有的路径穿越 sink 只认「真正读文件」的动作
（`new FileInputStream` / `Files.readAllBytes` / `readFile`），漏掉了 OWASP 里
整整一类形态：**`new File(路径)` 之后不做任何 I/O，只做元数据探测**。

    java.io.File fileTarget = new java.io.File(bar);   // bar ← 用户输入
    if (fileTarget.exists()) { ... }                   // 只探测存在性

r63-verify 实测：pathtraver-1 的 10 个静态漏检
（00011/00061/00215/00359/00452/00697/00698/01156/01231/01232）**全部**是这个形态；
对照已检出的 00001/00002 走 FileInputStream/FileOutputStream，被旧规则命中。

⇒ 漏检根因是 **sink 侧覆盖缺口**，不是源侧（`getParameter`/`getHeader`/`getCookies`
早已在 `_SOURCE_RE` 里，实测 10 个漏检中 6 个用的是 `getParameter`）。

## 为什么必须带「被消费」条件

真实项目里 `new File("config.properties")` 遍地都是，光构造不消费不算漏洞。
故规则要求 600 字符窗口内出现消费动作（exists/isFile/canRead/getCanonicalPath…）。
OWASP 真实写法固定是「构造 → 消费」紧邻（00011: L54 构造、L64 消费）。

## 实测口径（离线双向验证，2740 用例）
    规则独有命中：新增 TP 60 / 新增 FP 47
    其中平台**早已检出**（不增误报）：TP 50 / FP 37
    ⇒ 真正新增召回 10、真正新增误报 10
    新增的 10 个误报是「污点确实流到 new File 但真值标 FP」，属 safe-verdict
    的清理范畴（该方向已验证不可靠，见记忆 2026-10-07 第十一节），非本规则缺陷。
"""
import re

import pytest

from src.agents.a1_injection_heuristic import _RULES


def _rule(name: str):
    """从 _RULES 里按 label 取规则（表结构是 Dict[lang, List[五元组]]，规则挂在 "java" 组）。"""
    for group in _RULES.values():
        for rx, _vuln, _fam, _sev, label in group:
            if label == name:
                return rx
    raise AssertionError("找不到 sink 规则：%s" % name)


FILE_PROBE = _rule("file metadata probe")
FILE_READ = _rule("file read")


class TestFileProbeRuleShape:
    def test_rule_exists_and_is_path_traversal(self):
        for group in _RULES.values():
            for _rx, _vuln, fam, sev, label in group:
                if label == "file metadata probe":
                    assert fam == "path-traversal"
                    assert sev == "MEDIUM"
                    return
        raise AssertionError("未登记 file metadata probe 规则")

    def test_construct_only_is_not_flagged(self):
        """只构造不消费 ⇒ 不命中（防真实项目 `new File("config.properties")` 误报）。"""
        src = 'File f = new File("config.properties");'
        assert not FILE_PROBE.search(src)

    def test_construct_then_exists_is_flagged(self):
        assert FILE_PROBE.search('File f = new File(p);\nif (f.exists()) {}')

    def test_double_arg_constructor_is_flagged(self):
        """00011 真实形态：new File(基址, 相对路径) 双参。"""
        assert FILE_PROBE.search('File f = new File("/base", p);\nf.isDirectory();')

    @pytest.mark.parametrize("consumer", [
        "exists", "isFile", "isDirectory", "canRead", "canWrite",
        "length", "delete", "renameTo", "getCanonicalPath",
        "getAbsolutePath", "toPath", "list", "listFiles",
    ])
    def test_all_consumer_variants(self, consumer):
        assert FILE_PROBE.search("File f = new File(p);\nf.%s();" % consumer), consumer

    def test_cross_line_within_window(self):
        """构造与消费可隔若干行（OWASP 中间常夹 try/catch）。"""
        body = "File f = new File(p);\n" + "\n".join(["// filler"] * 20) + "\nf.exists();"
        assert FILE_PROBE.search(body)

    def test_far_apart_not_flagged(self):
        """超出窗口不命中 —— 防止把文件别处的消费当成本条的证据。"""
        body = "File f = new File(p);\n" + ("x" * 900) + "\nf.exists();"
        assert not FILE_PROBE.search(body)

    def test_no_interference_with_file_read_rule(self):
        """两条规则并存：真读文件的用例两条都命中（重复覆盖由去重键处理）。"""
        src = 'fis = new FileInputStream(new File(p));\nf.exists();'
        assert FILE_READ.search(src)
        assert FILE_PROBE.search(src)


class TestRealOwaspcases:
    """用真实 OWASP 用例源码锁定行为（不硬编码判定，只确认形态命中）。"""

    CASES_TP = [
        ("BenchmarkTest00011", "new File(param,\"/Test.txt\") + .exists()"),
        ("BenchmarkTest00359", "new File(bar) + .exists()"),
        ("BenchmarkTest00697", "new File(bar)"),
    ]

    def _read(self, name):
        import os
        root = os.environ.get(
            "SAST_AI_OWASP_SRC",
            r"<sdl-root>/owasp-code\BenchmarkJava-master"
            r"\src\main\java\org\owasp\benchmark\testcode")
        path = os.path.join(root, name + ".java")
        if not os.path.isfile(path):
            pytest.skip("OWASP 源码不在本机：%s" % path)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    @pytest.mark.parametrize("name,desc", CASES_TP)
    def test_real_missed_case_now_matched(self, name, desc):
        assert FILE_PROBE.search(self._read(name)), "%s 未被新规则命中（%s）" % (name, desc)
