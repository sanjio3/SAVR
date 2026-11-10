"""SCA + 代码可达性双条件判定测试（2026-08-29）。

核心原则：宁可漏选（D1 老实降级），不可误选（拿不存在的 gadget 去打会把有效验证污染成假阴性）。
本文件用真实临时文件锁死四种判定组合，以及两条容易出错的细节：
版本匹配（1.2.3 vs 1.2.3.RELEASE / 3.1 vs 3.1.0）与依赖目录排除（target 下的 readObject 不算入口）。
"""
import pytest

from src.iast.reachability import (
    find_dependency_declaration,
    find_usage_entries,
    judge_reachability,
    resolve_declared_dependencies,
    version_matches,
)


@pytest.fixture
def maven_project(tmp_path):
    """带 commons-collections 3.1 的 Maven 项目骨架。"""
    (tmp_path / "pom.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.1</version>
    </dependency>
    <dependency>
      <groupId>com.alibaba</groupId>
      <artifactId>fastjson</artifactId>
      <version>1.2.24</version>
    </dependency>
  </dependencies>
</project>
""",
        encoding="utf-8",
    )
    return tmp_path


# --------------------------------------------------------------------------- 版本匹配


@pytest.mark.parametrize("declared,detected,expected", [
    ("3.1", "3.1", True),
    ("3.1", "3.1.0", True),          # 短版本按 0 补齐
    ("1.2.24", "1.2.24", True),
    ("1.2.3", "1.2.3.RELEASE", True),  # qualifier 不参与比较
    ("3.1", "3.2.1", False),
    ("1.2.24", "1.2.83", False),
    ("", "3.1", True),               # 声明没写版本 → 按 name 放行
    ("${cc.version}", "3.1", True),  # Maven 属性占位符无法解析 → 放行
    ("3.1", "", True),               # SCA 没检出版本 → 放行
])
def test_version_matches(declared, detected, expected):
    assert version_matches(declared, detected) is expected


# --------------------------------------------------------------------------- 构建文件解析


def test_parse_maven_dependencies(maven_project):
    deps = resolve_declared_dependencies(str(maven_project))
    names = {d["name"] for d in deps}
    assert "commons-collections:commons-collections" in names
    assert "com.alibaba:fastjson" in names


def test_declared_dependency_found_by_full_and_short_name(maven_project):
    """groupId:artifactId 与仅 artifactId 两种写法都要能命中。"""
    full = find_dependency_declaration({"name": "commons-collections:commons-collections",
                                        "version": "3.1"}, str(maven_project))
    assert full is not None
    assert full["version"] == "3.1"

    short = find_dependency_declaration({"name": "commons-collections",
                                         "version": "3.1"}, str(maven_project))
    assert short is not None


def test_declared_dependency_version_mismatch_is_rejected(maven_project):
    """SCA 检出 3.2.2 但构建文件声明 3.1 → 版本不符，不算 classpath 命中。"""
    hit = find_dependency_declaration({"name": "commons-collections:commons-collections",
                                       "version": "3.2.2"}, str(maven_project))
    assert hit is None


def test_missing_code_root_yields_no_dependencies():
    assert resolve_declared_dependencies(None) == []
    assert resolve_declared_dependencies("/nonexistent/path/xyz") == []


def test_parse_gradle_dependencies(tmp_path):
    (tmp_path / "build.gradle").write_text(
        """
dependencies {
    implementation 'commons-collections:commons-collections:3.1'
    implementation "com.alibaba:fastjson:1.2.24"
}
""",
        encoding="utf-8",
    )
    deps = resolve_declared_dependencies(str(tmp_path))
    names = {d["name"] for d in deps}
    assert "commons-collections:commons-collections" in names
    assert "com.alibaba:fastjson" in names


def test_parse_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "django==3.2.0\n# comment\nrequests>=2.0\n",
        encoding="utf-8",
    )
    deps = resolve_declared_dependencies(str(tmp_path))
    names = {d["name"] for d in deps}
    assert "django" in names
    assert "requests" in names


# --------------------------------------------------------------------------- 利用入口扫描


def test_find_usage_entries_detects_read_object(tmp_path):
    (tmp_path / "Demo.java").write_text(
        "ObjectInputStream ois = new ObjectInputStream(in);\nObject o = ois.readObject();\n",
        encoding="utf-8",
    )
    hits = find_usage_entries("deserialization", str(tmp_path))
    assert hits
    assert any("readObject" in h["snippet"] for h in hits)


def test_find_usage_entries_detects_fastjson(tmp_path):
    (tmp_path / "Api.java").write_text('Object o = JSON.parseObject(input);\n', encoding="utf-8")
    hits = find_usage_entries("deserialization", str(tmp_path))
    assert any("parseObject" in h["snippet"] for h in hits)


def test_dependency_dirs_are_not_counted_as_entries(tmp_path):
    """target/ 与 node_modules/ 下的 readObject 不是本项目入口，必须排除，否则可达性永远为真。"""
    (tmp_path / "target").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "target" / "Generated.java").write_text("ois.readObject();\n", encoding="utf-8")
    (tmp_path / "node_modules" / "lib.java").write_text("ois.readObject();\n", encoding="utf-8")
    hits = find_usage_entries("deserialization", str(tmp_path))
    assert hits == []


def test_unknown_family_has_no_entry_requirement(tmp_path):
    assert find_usage_entries("sqli", str(tmp_path)) == []


# --------------------------------------------------------------------------- 四种判定组合


def test_reachable_when_classpath_and_entry_both_hit(maven_project):
    src = maven_project / "src"
    src.mkdir()
    (src / "Deser.java").write_text(
        "ObjectInputStream ois = new ObjectInputStream(in); Object o = ois.readObject();",
        encoding="utf-8",
    )
    r = judge_reachability({"name": "commons-collections:commons-collections", "version": "3.1"},
                           family="deserialization", code_root=str(maven_project))
    assert r["reachable"] is True
    assert r["classpath_hit"] is True
    assert r["entry_hit"] is True
    assert r["confidence"] == "high"


def test_unreachable_when_classpath_but_no_entry(maven_project):
    """库在 classpath 上但代码里没有反序列化调用点 → 打了也走不到 sink，不许选弹。"""
    r = judge_reachability({"name": "commons-collections:commons-collections", "version": "3.1"},
                           family="deserialization", code_root=str(maven_project))
    assert r["reachable"] is False
    assert r["classpath_hit"] is True
    assert r["entry_hit"] is False
    assert "利用入口" in r["reason"]


def test_unreachable_when_entry_but_no_classpath(tmp_path):
    """代码在反序列化，但 SCA 报的库不在声明里（传递依赖/版本不符）→ gadget 必然打空。"""
    (tmp_path / "Deser.java").write_text("ois.readObject();\n", encoding="utf-8")
    r = judge_reachability({"name": "commons-collections:commons-collections", "version": "3.1"},
                           family="deserialization", code_root=str(tmp_path))
    assert r["reachable"] is False
    assert r["classpath_hit"] is False
    assert r["entry_hit"] is True
    assert "未在构建文件里显式声明" in r["reason"]


def test_unreachable_when_neither_hit(tmp_path):
    r = judge_reachability({"name": "some-lib:some-lib", "version": "1.0"},
                           family="deserialization", code_root=str(tmp_path))
    assert r["reachable"] is False
    assert r["classpath_hit"] is False
    assert r["entry_hit"] is False
    assert r["confidence"] == "low"


def test_text_family_bypasses_gate_without_false_negative():
    """文本型族不依赖库 gadget，必须放行 —— 对它设门控会制造假阴性。"""
    r = judge_reachability({"name": "nothing:nothing", "version": "1.0"},
                           family="sqli", code_root=None)
    assert r["reachable"] is True
    assert "不启用" in r["reason"]


def test_empty_code_root_reports_unreachable_not_error(tmp_path):
    """code_root 为空时必须明确判不可达并说明原因，不能抛异常也不能静默放行。"""
    r = judge_reachability({"name": "commons-collections:commons-collections", "version": "3.1"},
                           family="deserialization", code_root=None)
    assert r["reachable"] is False
    assert "code_root 为空" in r["reason"]


def test_empty_component_is_unreachable(maven_project):
    r = judge_reachability({}, family="deserialization", code_root=str(maven_project))
    assert r["reachable"] is False


# ── 缓存与遍历剪枝守卫（2026-11-01）───────────────────────────────────────────
#
# 事故背景：judge_reachability 是**逐 SCA 组件**调用的（一次造弹 90+ 个组件），
# 而 find_usage_entries 每次都要把整个源码树读一遍 ⇒ 单条 deserialization spec
# 在 sca_forge_attack_payloads 里卡 5 分钟以上，17 条 spec 把 D2 批墙钟(600s)与
# 单条墙钟(300s)全部吃光，整批降级、一条请求都没发出去（本轮的 17 条
# deser spec 零 attempt 的真因）。下面三条锁死修复。


def test_source_iter_prunes_skip_dirs(tmp_path):
    """target/、node_modules/ 必须在目录层剪枝，不能走进去再过滤。

    走进去再过滤会让 rglob 把大目录里所有文件 stat 一遍（java-sec-code 实测 3.3s/次）。
    """
    from src.iast.reachability import _iter_source_files

    src = tmp_path / "src"
    src.mkdir()
    (src / "App.java").write_text("class App {}", encoding="utf-8")
    for d in ("target", "node_modules", ".git"):
        sub = tmp_path / d
        sub.mkdir()
        (sub / "Ignored.java").write_text("class Ignored {}", encoding="utf-8")

    names = {p.name for p in _iter_source_files(tmp_path)}
    assert "App.java" in names
    assert "Ignored.java" not in names


def test_usage_entries_is_cached(tmp_path, monkeypatch):
    """同一 (family, code_root) 的第二次调用必须命中缓存，不再读文件。

    判据不是「更快」（时间断言会 flaky），而是「读文件次数为 0」。
    """
    from src.iast import reachability as rz

    (tmp_path / "App.java").write_text("x.readObject(in);", encoding="utf-8")
    rz.clear_reachability_cache()
    first = rz.find_usage_entries("deserialization", str(tmp_path))
    assert first, "临时项目里应有 readObject 入口"

    reads = {"n": 0}
    real_read = type(tmp_path / "App.java").read_text

    def _counting_read(self, *a, **kw):
        reads["n"] += 1
        return real_read(self, *a, **kw)

    monkeypatch.setattr(type(tmp_path / "App.java"), "read_text", _counting_read)
    second = rz.find_usage_entries("deserialization", str(tmp_path))
    assert second == first
    assert reads["n"] == 0, "命中缓存时不应再读源码文件"


def test_cache_invalidated_when_source_changes(tmp_path):
    """源码变了（指纹变化）必须重算，不能返回旧结论。"""
    from src.iast import reachability as rz

    f = tmp_path / "App.java"
    f.write_text("class App {}", encoding="utf-8")
    rz.clear_reachability_cache()
    assert rz.find_usage_entries("deserialization", str(tmp_path)) == []

    # 指纹带 5s TTL，测试里直接清掉指纹缓存以模拟「TTL 已过」
    f.write_text("x.readObject(in);", encoding="utf-8")
    rz._FP_CACHE.clear()
    hits = rz.find_usage_entries("deserialization", str(tmp_path))
    assert hits, "源码新增 readObject 后必须重算并命中"


# ── 缓存与遍历剪枝守卫（2026-11-01）───────────────────────────────────────────
#
# 事故背景：judge_reachability 是**逐 SCA 组件**调用的（一次造弹 90+ 个组件），
# 而 find_usage_entries 每次都要把整个源码树读一遍 ⇒ 单条 deserialization spec
# 在 sca_forge_attack_payloads 里卡 5 分钟以上，17 条 spec 把 D2 批墙钟(600s)与
# 单条墙钟(300s)全部吃光，整批降级、一条请求都没发出去（本轮的 17 条
# deser spec 零 attempt 的真因）。下面三条锁死修复。


def test_source_iter_prunes_skip_dirs(tmp_path):
    """target/、node_modules/ 必须在目录层剪枝，不能走进去再过滤。

    走进去再过滤会让 rglob 把大目录里所有文件 stat 一遍（java-sec-code 实测 3.3s/次）。
    """
    from src.iast.reachability import _iter_source_files

    src = tmp_path / "src"
    src.mkdir()
    (src / "App.java").write_text("class App {}", encoding="utf-8")
    for d in ("target", "node_modules", ".git"):
        sub = tmp_path / d
        sub.mkdir()
        (sub / "Ignored.java").write_text("class Ignored {}", encoding="utf-8")

    names = {p.name for p in _iter_source_files(tmp_path)}
    assert "App.java" in names
    assert "Ignored.java" not in names


def test_usage_entries_is_cached(tmp_path, monkeypatch):
    """同一 (family, code_root) 的第二次调用必须命中缓存，不再读文件。

    判据不是「更快」（时间断言会 flaky），而是「读文件次数为 0」。
    """
    from src.iast import reachability as rz

    (tmp_path / "App.java").write_text("x.readObject(in);", encoding="utf-8")
    rz.clear_reachability_cache()
    first = rz.find_usage_entries("deserialization", str(tmp_path))
    assert first, "临时项目里应有 readObject 入口"

    reads = {"n": 0}
    real_read = type(tmp_path / "App.java").read_text

    def _counting_read(self, *a, **kw):
        reads["n"] += 1
        return real_read(self, *a, **kw)

    monkeypatch.setattr(type(tmp_path / "App.java"), "read_text", _counting_read)
    second = rz.find_usage_entries("deserialization", str(tmp_path))
    assert second == first
    assert reads["n"] == 0, "命中缓存时不应再读源码文件"


def test_cache_invalidated_when_source_changes(tmp_path):
    """源码变了（指纹变化）必须重算，不能返回旧结论。"""
    from src.iast import reachability as rz

    f = tmp_path / "App.java"
    f.write_text("class App {}", encoding="utf-8")
    rz.clear_reachability_cache()
    assert rz.find_usage_entries("deserialization", str(tmp_path)) == []

    # 指纹带 5s TTL，测试里直接清掉指纹缓存以模拟「TTL 已过」
    f.write_text("x.readObject(in);", encoding="utf-8")
    rz._FP_CACHE.clear()
    hits = rz.find_usage_entries("deserialization", str(tmp_path))
    assert hits, "源码新增 readObject 后必须重算并命中"


# ── 指纹 TTL 必须大于「算一次指纹的代价」（2026-11-02）─────────────────────────
#
# 事故：`_FP_TTL_S = 5.0` 是写死的。java-sec-code（87 文件）算一次指纹 1.66s，5s TTL 够用；
# 但 OWASP 全集（2843 文件）算一次要 **11.3s** —— TTL 比计算本身还短 ⇒ **缓存永远失效**，
# 每调一次就重扫整棵源码树。实测 本轮因此卡在注册后的后处理 30 分钟：
# 0 次重放、0 个探针事件，进程系统 CPU 时间 1877s（全在 stat 上）。
#
# 锁两件事：
#   1. 默认 TTL 不是「小常数」，而是自适应且下限 ≥ 300s；
#   2. 短时间内的多次调用不得重复遍历源码树（判据是遍历次数，不是时间断言）。

def test_fingerprint_ttl_is_not_shorter_than_measurement(tmp_path, monkeypatch):
    from src.iast import reachability as rz

    (tmp_path / "A.java").write_text("class A {}", encoding="utf-8")
    rz.clear_reachability_cache()
    assert rz._FP_MIN_TTL_S >= 300.0, "TTL 下限必须远大于一次遍历的代价"

    calls = {"n": 0}
    real = rz._iter_source_files

    def _counting(root):
        calls["n"] += 1
        return real(root)

    monkeypatch.setattr(rz, "_iter_source_files", _counting)
    rz.code_root_fingerprint(str(tmp_path))
    first = calls["n"]
    assert first >= 1
    # 模拟「已经过了 60 秒」（远超旧 TTL 5s，但远低于新下限）。
    # 必须先存下原函数：rz.time 就是全局 time 模块，直接 lambda 里再调 time.time() 会递归。
    import time as _time_mod
    _orig_time = _time_mod.time
    monkeypatch.setattr(_time_mod, "time", lambda: _orig_time() + 60)
    rz.code_root_fingerprint(str(tmp_path))
    assert calls["n"] == first, "TTL 内不得重新遍历源码树"


# ── 两步桥：写入口 → 存储 → 调度器执行（2026-11-02）──────────────────────────
#
# 事故：RuoYi 的 `JobInvokeUtil.invokeMethod` 由 Quartz **异步**调用，
# 静态调用图里没有 HTTP 入口 ⇒ 真值表里唯一一条 in_scope 的 command_execution
# （/monitor/job/add + /monitor/job/run）一条候选都产不出。
#
# 修法：从 sink 读的字段（`sysJob.getInvokeTarget()`）反查「谁把用户输入写进这个实体」：
#   策略1 setter 有显式调用点 → 用它的 caller；
#   策略2 setter 由框架（Jackson）运行时调 → 按**实体类型**找接收该类型的写入口。
# 策略2 必须按「写」优先：同一实体有 list/export/add/run 一堆入口，
# 取第一个会拿到只读接口（实测先取到 `/monitor/job/list`）。

def _two_step_project(tmp_path):
    (tmp_path / "JobInvokeUtil.java").write_text('''package d;
public class JobInvokeUtil {
    public static void invokeMethod(SysJob sysJob) throws Exception {
        String invokeTarget = sysJob.getInvokeTarget();
        Class.forName(invokeTarget).newInstance();
    }
}''', encoding="utf-8")
    (tmp_path / "SysJobController.java").write_text('''package d;
@RestController
@RequestMapping("/monitor/job")
public class SysJobController {
    @PostMapping("/list")
    public Object list(SysJob job) { return null; }
    @PostMapping("/add")
    public Object addSave(@RequestBody SysJob job) { return null; }
    @PostMapping("/run")
    public Object run(SysJob job) { return null; }
}''', encoding="utf-8")
    return tmp_path


def test_two_step_bridge_prefers_write_endpoint(tmp_path):
    from src.core.callgraph_route import route_via_writer, clear_cache

    root = _two_step_project(tmp_path)
    clear_cache()
    r = route_via_writer(str(root), "JobInvokeUtil.java", 4)
    assert r["route"] == "/monitor/job/add", r
    assert "getInvokeTarget" in r["bridge"], r


def test_two_step_bridge_empty_when_no_entity_param(tmp_path):
    """没有实体形参 ⇒ 不该硬猜一个路由出来。"""
    from src.core.callgraph_route import route_via_writer, clear_cache

    (tmp_path / "U.java").write_text('''package d;
public class U {
    public void f(String s) { Class.forName(s); }
}''', encoding="utf-8")
    clear_cache()
    assert route_via_writer(str(tmp_path), "U.java", 3)["route"] == ""
