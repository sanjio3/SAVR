"""normalize_type 归并回归测试（2026-09-14）。

背景：task 7 final_report 的 by_type 把同一族裂成多个标签（前缀、括号、大小写、
分隔符差异），根因是 normalize_type 旧实现只做精确别名查表 + 原样放行。
本测试用 task 7 实测标签集合，断言「同一族的标签归并后只出现一个」。

判定口径：每个分组内的标签集合经 normalize_type 后必须收敛为单一族名。
例外：通用 RCE（远程代码执行）与 RMI-RCE（rmi远程代码执行）按语义不强并
（模块注释明确「仅收录同一概念的多种写法，不做跨概念合并」），故不列入本测试。
"""
import pytest

from src.core.normalize import _FAMILY_KEYWORDS, normalize_type, strip_family_prefix


CONVERGENCE_GROUPS = {
    "xxe": ["xxe", "xxe (xml external entity)"],
    "ssrf": ["ssrf", "基础设施层-ssrf", "infrastructure layer - ssrf"],
    "url redirect": ["url重定向", "url redirect", "基础设施层-url重定向"],
    "idor": [
        "cors - insecure direct object reference (idor)",
        "idor",
        "infrastructure layer - insecure direct object reference (idor)",
    ],
    "file-upload": ["文件上传", "文件上传-文件类型限制绕过", "文件上传-文件内容检查不足"],
    "log-disclosure": ["日志泄露", "基础设施层-日志泄露", "基础设施层-日志记录敏感信息"],
    "insecure-configuration": [
        "基础设施层-安全配置",
        "基础设施层-安全配置不当",
        "基础设施层-安全配置错误",
        "基础设施层-不安全的域名配置",
        "基础设施层-xml解析器安全配置",
    ],
    "jsonp-referer": [
        "基础设施层-jsonp referer校验不安全",
        "基础设施层-jsonp referer 安全问题",
        "基础设施层-referer 安全问题",
    ],
    "rmi": ["rmi远程代码执行", "基础设施层-远程方法调用"],
    "ssti": ["ssti (server-side template injection)", "ssti", "服务端模板注入"],
}


def test_same_family_variants_converge():
    failures = {}
    for family, labels in CONVERGENCE_GROUPS.items():
        outputs = {label: normalize_type(label) for label in labels}
        uniq = set(outputs.values())
        if len(uniq) != 1:
            failures[family] = outputs
    assert not failures, f"以下族的标签未收敛：{failures}"


def test_strip_family_prefix():
    assert strip_family_prefix("基础设施层-ssrf") == "ssrf"
    assert strip_family_prefix("业务逻辑类-并发竞争") == "并发竞争"
    assert strip_family_prefix("infrastructure layer - ssrf") == "ssrf"
    assert strip_family_prefix("  ssrf  ") == "ssrf"
    assert strip_family_prefix("") == ""


def test_unknown_label_passthrough():
    # 未登记的标签仍原样返回，不臆造族名
    assert normalize_type("某个从未登记的新族") == "某个从未登记的新族"
    assert normalize_type("") == ""
    assert normalize_type(None) == ""


def test_command_execution_family_converges():
    """command 族的全部写法必须收敛为一个规范族名。

    2026-09-14 审计发现本文件对 command 关键字的覆盖数为 0，导致三个缺陷漏网：
    'Command Injection' 原样返回（既没小写也没去空格）、'command_injection' 与
    'command-execution' 三者互不相等。后果是同一处代码只因写法不同就裂成多个族。
    注意：通用 RCE（远程代码执行）与 RMI-RCE 按语义不合并，故不列入本组。
    """
    labels = ("command-execution", "command_injection", "Command Injection",
              "command execution", "命令注入", "命令执行", "os command")
    outputs = {label: normalize_type(label) for label in labels}
    assert len(set(outputs.values())) == 1, f"command 族未收敛：{outputs}"
    assert set(outputs.values()) == {"command_execution"}


def test_canonical_family_separator_is_uniform():
    """规范族名的分隔符必须只有一种（item 2 已统一为下划线，2026-09-15 落地）。

    三种分隔符并存时，任何按字符串相等比较的场合（去重键、对账匹配、前端筛选）
    都可能漏配。现 _FAMILY_KEYWORDS 全部规范名仅用下划线，本用例从 xfail 转正。
    """
    separators = set()
    for canon, _ in _FAMILY_KEYWORDS:
        if " " in canon:
            separators.add("space")
        if "-" in canon:
            separators.add("hyphen")
        if "_" in canon:
            separators.add("underscore")
    assert len(separators) <= 1, f"规范族名分隔符混用：{separators}"
    assert separators == {"underscore"}, f"规范族名分隔符应为下划线：{separators}"
