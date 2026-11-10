"""M12 JS 静态扫描架构准备测试（2026-10-03）。

只做架构准备、不做能力验收（四个靶场零前端 JS，OWASP Benchmark 也没有前端真值）。
要钉住的三件事：
  1. 语言识别从「一个」改成「一组」，多语言工作区不会被只按主语言建库而漏掉另一种语言；
  2. 每种语言各建一个 CodeQL 库（默认库路径按语言分开），否则第二种语言直接覆盖第一种；
  3. 自定义查询按语言取包 —— 没有该语言包时返回空，**绝不回退 Java 包**
     （Java 查询 import java.qll，套到 javascript 库上 analyze 会失败，
      而 A1 会把 analyze 失败记账成「无漏洞」，属于静默丢召回）。
"""
from pathlib import Path

from src.agents.a1_codeql_adapter import CodeQLAdapter
from src.pipeline.a1.service import A1PipelineService
from src.core.models import ScanResult


def test_detect_languages_returns_all_present_languages():
    files = [{"path": "a.java"}, {"path": "b.java"}, {"path": "c.js"},
             {"path": "d.ts"}, {"path": "e.py"}]
    langs = A1PipelineService._detect_languages(files)
    # .ts/.js 都映射到 javascript，只应按扩展名算一个 javascript
    assert set(langs) == {"java", "javascript", "python"}
    assert langs[0] == "java"   # java 2 个 > javascript 2 个不成立 → 两者同数时按注册表序 java 在前


def test_ordered_by_file_count_desc():
    files = [{"path": "a.js"}, {"path": "b.js"}, {"path": "c.js"}, {"path": "d.java"}]
    assert A1PipelineService._detect_languages(files) == ["javascript", "java"]


def test_single_language_still_works():
    assert A1PipelineService._detect_languages([{"path": "a.java"}]) == ["java"]
    assert A1PipelineService._detect_languages([{"path": "a.py"}]) == ["python"]


def test_empty_files_degrades_to_python():
    assert A1PipelineService._detect_languages([]) == ["python"]


def test_language_field_is_honored_and_normalized():
    """显式 language 字段优先，大小写归一化。"""
    assert A1PipelineService._detect_languages([{"language": "JAVA", "path": "x"}]) == ["java"]
    assert A1PipelineService._detect_languages([{"language": "javascript", "path": "x"}]) == ["javascript"]


def test_detect_language_single_view_back_compat():
    assert A1PipelineService._detect_language([{"path": "a.py"}, {"path": "b.java"}]) == "python"


def test_default_db_path_is_per_language():
    """多语言工作区各语言一个库：共用 .codeql-db 会让后者覆盖前者。"""
    root = Path("/proj")                      # 跨 Windows/POSIX 都用 Path 拼，避免分隔符差异
    assert CodeQLAdapter.default_db_path(str(root), "java") == str(root / ".codeql-db")
    assert CodeQLAdapter.default_db_path(str(root), "javascript") == str(root / ".codeql-db-javascript")
    assert CodeQLAdapter.default_db_path(str(root), "python") == str(root / ".codeql-db-python")
    paths = {CodeQLAdapter.default_db_path(str(root), lg)
             for lg in ("java", "javascript", "python")}
    assert len(paths) == 3


def test_custom_queries_are_language_scoped():
    java_q = CodeQLAdapter.custom_queries("java")
    assert java_q, "Java 包必须还在（回归保护）"
    # javascript 包还没写 → 空列表，且**不能**偷偷回退 Java 包
    assert CodeQLAdapter.custom_queries("javascript") == []


def test_custom_queries_loads_language_specific_pack_when_present(tmp_path, monkeypatch):
    pack = tmp_path / "codeql-queries" / "javascript" / "src"
    pack.mkdir(parents=True)
    (pack / "JsSinks.ql").write_text("// placeholder\n", encoding="utf-8")
    monkeypatch.setattr(CodeQLAdapter, "_CUSTOM_PACK_ROOT", str(tmp_path / "codeql-queries"))
    got = CodeQLAdapter.custom_queries("javascript")
    assert [Path(p).name for p in got] == ["JsSinks.ql"]
    # 同一次改动下 Java 包不受影响（仍然拿到真实 Java 查询，且不含 JS 那个占位）
    java_q = [Path(p).name for p in CodeQLAdapter.custom_queries("java")]
    assert "JsSinks.ql" not in java_q
    assert len(java_q) >= 4


def test_normalize_suite_for_javascript():
    """JS 官方套件名必须带语言前缀，否则 CLI 当 pack 名解析并报 pack not found。"""
    assert CodeQLAdapter._normalize_suite("security-extended", "javascript") == "javascript-security-extended"
    assert CodeQLAdapter._normalize_suite("javascript-security-extended", "javascript") == "javascript-security-extended"


def test_scan_files_runs_codeql_for_every_detected_language():
    """发现两种语言时，CodeQL 必须按语言各跑一次（不是只跑主语言）。"""

    class _FakeSemantic:
        def __init__(self):
            self.calls = []

        def scan_project(self, project_path, language="python"):
            self.calls.append(language)
            return []

    class _FakeAdapter:
        @staticmethod
        def is_available():
            return True

    svc = A1PipelineService.__new__(A1PipelineService)
    svc._semantic = _FakeSemantic()
    svc._codeql = _FakeAdapter()
    svc.config = {"a1_use_codeql": True}
    svc._last_scan_meta = {}
    svc._last_route_bind_meta = None

    files = [{"path": "a.java", "content": "x"},
             {"path": "b.js", "content": "y"},
             {"path": "c.py", "content": "z"}]
    svc._resolve_project_root = lambda _f, _cr=None: "/tmp/proj"
    svc._write_temp_project = lambda _f, _t: None
    svc._merge_heuristic_into_codeql = lambda c, h: (c, 0)
    svc._merge_skill_vulns = lambda r, s: r
    svc._bucket_vulns = lambda v: []
    svc._scan_active_skill_rules = lambda f: []

    svc.scan_files(files)
    # 每个语言至少跑一次（库为空时会再走一次「列文件建临时工程」兜底，故按去重断言）
    assert sorted(set(svc._semantic.calls)) == ["java", "javascript", "python"]
    assert sorted(svc._last_scan_meta["languages"]) == ["java", "javascript", "python"]


def test_codeql_language_status_recorded_per_language():
    """每个语言要有独立状态：区分「这个语言没告警」与「这个语言库没建起来」。"""

    class _FakeSemantic:
        def scan_project(self, project_path, language="python"):
            # java 库建不起来，javascript/python 有结果
            return [] if language == "java" else [ScanResult(file="b.js")]

    class _FakeAdapter:
        @staticmethod
        def is_available():
            return True

    svc = A1PipelineService.__new__(A1PipelineService)
    svc._semantic = _FakeSemantic()
    svc._codeql = _FakeAdapter()
    svc.config = {"a1_use_codeql": True}
    svc._last_scan_meta = {}
    svc._last_route_bind_meta = None
    svc._resolve_project_root = lambda _f, _cr=None: "/tmp/proj"
    svc._write_temp_project = lambda _f, _t: None
    svc._merge_heuristic_into_codeql = lambda c, h: (c, 0)
    svc._merge_skill_vulns = lambda r, s: r
    svc._bucket_vulns = lambda v: []
    svc._scan_active_skill_rules = lambda f: []

    svc.scan_files([{"path": "a.java", "content": "x"}, {"path": "b.js", "content": "y"}])
    status = svc._last_scan_meta.get("codeql_languages") or {}
    assert status.get("java") == "empty"
    assert status.get("javascript") == "ok"
