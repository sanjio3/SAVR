"""A1 外接 CodeQL 适配层（ / 「A1 规则扫描 → 外接工具（如 CodeQL）」能力改造）。

A1 的静态模式匹配目标从内置正则/规则引擎改为外接 CodeQL 工具。本模块提供适配层：
- 检测本机 codeql CLI 是否可用；
- 可用时提供 database create / database analyze（SARIF）调用骨架；
- 不可用时 is_available=False，由 A1PipelineService 回退内置规则引擎（不阻断扫描）。

注意：CodeQL 对 Java 项目需要编译数据库（codeql database create --language=java 需 Maven/Gradle
构建环境），Python/JS 可自动提取。实际调用依赖本机 CodeQL CLI + 查询库（qlpack），本适配层
只做能力检测与调用骨架，完整扫描在无 CLI 时回退内置规则。
"""
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# config/codeql.yaml，由 src.core.config_registry 统一读取（环境变量 > yaml > 代码默认）。
# 套件名硬编码等。配置模块极特殊不可用时退回历史 env/默认值，绝不抛异常中断扫描。
try:
    from src.core import config_registry as _cfg
except Exception:  # pragma: no cover - src.core 不可用时退回历史默认
    _cfg = None


def _cfg_codeql_enabled(default: bool = True) -> bool:
    if _cfg is not None:
        return _cfg.codeql_enabled(default=default)
    return default and str(os.environ.get("SAST_AI_DISABLE_CODEQL", "")).strip().lower() not in (
        "1", "true", "yes", "on")


def _cfg_codeql_bin(default: Optional[str] = None) -> Optional[str]:
    if _cfg is not None:
        return _cfg.codeql_bin_path(default=default)
    return os.environ.get("CODEQL_BIN") or default


def _cfg_codeql_threads(default: int = 2) -> int:
    if _cfg is not None:
        return _cfg.codeql_threads(default=default)
    try:
        return int(os.environ.get("CODEQL_THREADS") or default)
    except (TypeError, ValueError):
        return default


def _cfg_codeql_ram(default: int = 4096) -> int:
    if _cfg is not None:
        return _cfg.codeql_ram_mb(default=default)
    raw = os.environ.get("CODEQL_RAM_MB")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _cfg_codeql_suite(default: str = "java-security-extended") -> str:
    if _cfg is not None:
        return _cfg.codeql_suite(default=default)
    return os.environ.get("CODEQL_SUITE") or default


def _cfg_codeql_timeout(kind: str, default: int) -> int:
    if _cfg is not None:
        return _cfg.codeql_timeout(kind, default)
    return default


logger = logging.getLogger(__name__)


# 背景：CodeQL 对 Java 项目要跑 ``mvn -B compile``。子进程若**继承后端进程的 JAVA_HOME**
# （本机是 jdk-21），而项目声明 JDK8 且用老版本 Lombok，编译直接崩：
#   NoSuchFieldError: Class com.sun.tools.javac.tree.JCTree$JCImport does not have
#   member field 'com.sun.tools.javac.tree.JCTree qualid'
# ⇒ 空库 ⇒ codeql_status=build_failed_or_empty ⇒ 降级启发式（A1 主力整条失效）。
#
#   JAVA_HOME=jdk-21  → mvn -B compile 失败（上面的 NoSuchFieldError）
#   JAVA_HOME=jdk65   → BUILD SUCCESS（4.7s）
# engine=codeql+heuristic / codeql_status=ok 一直正常——**同一套代码，只因项目形态不同而一个通一个不通**。
#
# 结论：构建子进程的 JAVA_HOME 必须**按项目声明**决定，不能继承。这也正是「真实业务项目
# 普遍是 Maven/Gradle + 老 JDK + Lombok」时 A1 全线退化的根因。

# 部署方可通过 SAST_AI_JDK_ROOT 追加自己的 JDK 根目录。
_JDK_ROOTS = tuple(p for p in (
    os.environ.get("SAST_AI_JDK_ROOT", ""),
    r"C:/Program Files/Java",
    r"C:/Program Files/Eclipse Adoptium",
    os.path.expanduser("~/.jdks"),
) if p)
_JDK_SCAN_CACHE: Optional[List[tuple]] = None


def _major_of(version: str) -> int:
    """把 ``JAVA_VERSION`` 字符串归一成主版本号：'1.8.0_65'→8，'11.0.25'→11，'21.0.7'→21。"""
    v = str(version or "").strip().strip('"').split("_")[0]
    if v.startswith("1."):
        v = v[2:]
    try:
        return int(v.split(".")[0])
    except (TypeError, ValueError):
        return 0


def _scan_jdks() -> List[tuple]:
    """扫本地 JDK，返回 ``[(major, path)]``（按 major 升序，去重）。

    版本判定读 JDK 根目录的 ``release`` 文件（``JAVA_VERSION="1.8.0_65"``），
    比跑 ``java -version`` 快且不依赖 PATH；读不到就退回目录名里的数字。
    """
    global _JDK_SCAN_CACHE
    if _JDK_SCAN_CACHE is not None:
        return _JDK_SCAN_CACHE
    found: Dict[int, str] = {}
    for root in _JDK_ROOTS:
        try:
            if not root or not os.path.isdir(root):
                continue
            for name in sorted(os.listdir(root)):
                path = os.path.normpath(os.path.join(root, name))
                if not os.path.isfile(os.path.join(path, "bin", "javac.exe")):
                    continue
                major = 0
                rel = os.path.join(path, "release")
                if os.path.isfile(rel):
                    try:
                        with open(rel, "r", encoding="utf-8", errors="ignore") as fh:
                            for line in fh:
                                if line.startswith("JAVA_VERSION="):
                                    major = _major_of(line.split("=", 1)[1])
                                    break
                    except Exception:
                        major = 0
                if not major:
                    digits = "".join(ch for ch in name if ch.isdigit())
                    major = _major_of(digits[:2]) if digits else 0
                if major and major not in found:
                    found[major] = path
        except Exception:
            continue
    _JDK_SCAN_CACHE = sorted(found.items())
    return _JDK_SCAN_CACHE


_POM_JAVA_PATTERNS = (
    r"<java\.version>\s*([^<\s]+)\s*</java\.version>",
    r"<maven\.compiler\.release>\s*([^<\s]+)\s*</maven\.compiler\.release>",
    r"<maven\.compiler\.source>\s*([^<\s]+)\s*</maven\.compiler\.source>",
    r"<maven\.compiler\.target>\s*([^<\s]+)\s*</maven\.compiler\.target>",
)
_GRADLE_JAVA_PATTERNS = (
    r"sourceCompatibility\s*=\s*['\"]?(?:JavaVersion\.VERSION_)?([0-9._]+)",
    r"JavaLanguageVersion\.of\(\s*([0-9]+)\s*\)",
)


def _project_java_major(project_path: str) -> int:
    """从 pom.xml / build.gradle 读项目声明的 Java 主版本；读不到返回 0。

    只读**项目根**的构建文件：多模块项目里子模块的声明不决定构建 JDK，
    根 pom 的 ``maven.compiler.*`` 才是 mvn 实际用的。
    """
    if not project_path or not os.path.isdir(project_path):
        return 0
    pom = os.path.join(project_path, "pom.xml")
    if os.path.isfile(pom):
        try:
            import re as _re
            with open(pom, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read(200000)
            for pat in _POM_JAVA_PATTERNS:
                m = _re.search(pat, txt)
                if m:
                    major = _major_of(m.group(1))
                    if major:
                        return major
        except Exception:
            pass
    for gname in ("build.gradle", "build.gradle.kts"):
        gp = os.path.join(project_path, gname)
        if not os.path.isfile(gp):
            continue
        try:
            import re as _re
            with open(gp, "r", encoding="utf-8", errors="ignore") as fh:
                txt = fh.read(200000)
            for pat in _GRADLE_JAVA_PATTERNS:
                m = _re.search(pat, txt)
                if m:
                    major = _major_of(m.group(1))
                    if major:
                        return major
        except Exception:
            pass
    return 0


def resolve_build_java_home(project_path: str) -> str:
    """按项目声明挑构建 JDK，返回 JAVA_HOME 路径；无法决定时返回空串（保持继承）。

    优先级：``SAST_AI_JAVA_HOME``（显式覆盖）> 项目声明的主版本匹配 > 空（不干预）。
    刻意**不做**「找不到就用默认 JDK」的兜底：错配的 JDK 会把「构建失败」伪装成
    「项目有问题」，而保持继承至少能让调用方看到真实报错。
    """
    override = os.environ.get("SAST_AI_JAVA_HOME", "").strip()
    if override and os.path.isdir(override):
        return override
    major = _project_java_major(project_path)
    if not major:
        return ""
    for m, path in _scan_jdks():
        if m == major:
            return path
    return ""


def _env_with_mvn_shim(project_path: Optional[str] = None) -> Dict[str, str]:
    """返回注入 Maven shim 的子进程环境变量（shim 目录置于 PATH 最前）。

    ``project_path`` 非空时额外按项目声明钉死 ``JAVA_HOME``（见上方「构建 JDK 绑定」）。
    钉不住时保持继承并在日志里明说，避免再次出现「以为是查询包不行」的错归因。
    """
    env = dict(os.environ)
    shim = CodeQLAdapter._MVN_SHIM_DIR
    existing = env.get("PATH", "")
    if shim not in existing.split(os.pathsep):
        env["PATH"] = shim + os.pathsep + existing
    # 原实现把 override 检查关在 ``if project_path:`` 里 —— CodeQL 的 prepared 扫描根
    # （无 pom，甚至传 None）场景下，覆盖被静默忽略，构建回退到继承的 jdk-21，
    # 撞老 Lombok 编译失败 → java 级 empty → 整轮降级启发式（A1 276→133）。
    _override = str(env.get("SAST_AI_JAVA_HOME", "") or "").strip()
    if _override and os.path.isdir(_override):
        env["JAVA_HOME"] = _override
        _jbin = os.path.join(_override, "bin")
        if _jbin not in env.get("PATH", "").split(os.pathsep):
            env["PATH"] = _jbin + os.pathsep + env.get("PATH", "")
        logger.info("[codeql] 构建 JDK 由 SAST_AI_JAVA_HOME 显式覆盖：%s（project_path=%s）",
                    _override, project_path or "(空)")
    elif project_path:
        major = _project_java_major(project_path)
        jh = resolve_build_java_home(project_path)
        if jh:
            env["JAVA_HOME"] = jh
            jbin = os.path.join(jh, "bin")
            if jbin not in env.get("PATH", "").split(os.pathsep):
                env["PATH"] = jbin + os.pathsep + env.get("PATH", "")
            logger.info("[codeql] 构建 JDK 已绑定：%s（项目声明 %s）", jh, major or "?")
        else:
            logger.warning(
                "[codeql] 未能按项目声明绑定构建 JDK（项目声明=%s，本地可用=%s）→ "
                "沿用继承的 JAVA_HOME=%s；若项目是老 JDK + Lombok，构建很可能失败并降级启发式",
                major or "未声明", [m for m, _ in _scan_jdks()], env.get("JAVA_HOME", "(空)"))
    else:
        logger.warning(
            "[codeql] 未收到 project_path 且未设 SAST_AI_JAVA_HOME → 沿用继承的 JAVA_HOME=%s；"
            "老 JDK + Lombok 项目构建可能失败并降级启发式", env.get("JAVA_HOME", "(空)"))
    return env


class CodeQLAdapter:
    """CodeQL 外接工具适配器。"""

    # 项目内固化的可用 Maven shim（改进清单 P0#1）：直启 java + classworlds，绕过本机损坏的 mvn。
    # CodeQL 对 Java 项目需 autobuild（mvn compile），构建时把此目录置于 PATH 最前，
    # 使 codeql 子进程解析到的 mvn 即为此可用 shim。
    _MVN_SHIM_DIR = str(Path(__file__).resolve().parent.parent.parent / "tools" / "mvn_shim")

    # SAVR 自定义 CodeQL 查询目录（tools/codeql-queries/src/*.ql）—— 当前是 Java 包
    _CUSTOM_QUERY_DIR = str(Path(__file__).resolve().parent.parent.parent / "tools" / "codeql-queries" / "src")
    # 自定义查询包根：语言专属包为 tools/codeql-queries/<language>/src（默认不含 java，
    # java 直接走上面那个历史目录）。多语言工作区各语言互不串包：把 java 的 .ql
    # （import java.qll/java-all）喂给 javascript 库 analyze 会直接失败。
    _CUSTOM_PACK_ROOT = Path(__file__).resolve().parent.parent.parent / "tools" / "codeql-queries"

    def __init__(self, codeql_bin: Optional[str] = None, threads: Optional[int] = None, ram_mb: Optional[int] = None):
        # 路径查找/代码默认。详见 src.core.config_registry。链路修通后**默认启用**，
        # 仅 SAST_AI_DISABLE_CODEQL=1（或 yaml enabled:false）时禁用。
        _disabled = not _cfg_codeql_enabled(default=True)
        if _disabled:
            self._codeql = None
        else:
            # 优先级：显式入参 > config(CODEQL_BIN / bin_path=auto 探测) > PATH 查找
            # 入参可能是配置里的 "auto" 字样，按「未指定」处理，否则 Path("auto").exists
            # 为 False，会直接把 CodeQL 降级掉。
            explicit = str(codeql_bin or "").strip()
            if explicit.lower() == "auto":
                explicit = ""
            candidate = explicit or _cfg_codeql_bin() or shutil.which("codeql")
            # 传入的路径必须真实存在，否则视为不可用（回退内置规则）
            self._codeql = candidate if (candidate and Path(candidate).exists()) else None
        # 线程护栏保留固定小值（编译分层也吃 CPU，与后端/Ollama 共存）。
        self._threads = int(threads if threads is not None else _cfg_codeql_threads(default=2))
        # 内存预算配置：None=动态计算（默认）；0=不传 --ram（CodeQL 按机器自适应）；
        # >0=固定值（保留人工覆盖能力）。真正的解析在 _resolve_ram_mb。
        self._ram_mb_cfg = self._parse_ram_cfg(
            ram_mb if ram_mb is not None else _cfg_codeql_ram(default=4096))

    @staticmethod
    def _parse_ram_cfg(raw: Any) -> Optional[int]:
        """把入参/环境变量解析成 ram 配置：None（未配置）/ 0（禁用护栏）/ 正整数（固定值）。"""
        if raw is None or raw == "":
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    # heap 仅 1344MB，TaintedPath.ql（CWE-022 重查询）OOM；4GB 时 TaintedPath 11.2s 成功。
    # 故上下限都定 4096：低于 4GB 会丢 path traversal 查询，高于 4GB 会与靶场/前端抢内存
    # （历史 6-16GB 导致 40 次 JVM OOM）。
    _RAM_MIN_MB = 4096
    _RAM_MAX_MB = 4096

    @staticmethod
    def _commit_stats_mb() -> Optional[tuple]:
        """读取 Windows Commit 真实读数，返回 (commit_limit_mb, commit_free_mb, phys_avail_mb)。

        注意：psutil 在 Windows 的 swap_memory 是「页面文件使用率」（本机页面文件 8GB，
        total=8192），NOT CommitLimit——CommitLimit = 物理内存 + 页面文件（本机约 40.6GB）。
        正确来源是 GlobalMemoryStatusEx：ullTotalPageFile=CommitLimit，ullAvailPageFile=CommitFree。
        非 Windows 或调用失败返回 None。
        """
        if os.name != "nt":
            return None
        try:
            import ctypes

            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            st = _MEMORYSTATUSEX()
            st.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return None
            mb = 1024 * 1024
            return (
                int(st.ullTotalPageFile) // mb,
                int(st.ullAvailPageFile) // mb,
                int(st.ullAvailPhys) // mb,
            )
        except Exception:
            return None

    def _resolve_ram_mb(self) -> int:
        """计算本次 analyze 的 --ram 预算（MB）。

        -J-Xmx1800M + off-heap 1565M，security-extended 127 条查询编译分层即 OOM
        （115 次 OutOfMemoryError，栈在 QLStratificationReporter/SCC.tarjan，status 99，
        29.6 分钟纯无效功）。固定小值=坏慢，固定大值=撞 Commit 上限，故改动态：
        - Commit 维度取 CommitFree 的 50%：这是 CodeQL 撞「页面文件太小」的直接约束维度；
        - 物理可用取 60%：留给 Ollama/后端/靶场共存；
        - 两者取小后 clamp 到 [6144, 16384]；
        - 预算低于下限（机器吃紧）时返回 0：不传 --ram，交 CodeQL 按机器自适应，
          宁可让它小堆慢跑也不由护栏把系统顶爆。
        读数失败（无 Windows API、无 psutil）同样返回 0。
        """
        if self._ram_mb_cfg is not None:
            return max(0, int(self._ram_mb_cfg))
        # （不传 --ram），CodeQL 自适应可能吃 5.6GB 且不可控；固定 4096 实测全量 4216 告警成功。
        return self._RAM_MAX_MB

    @classmethod
    def custom_queries(cls, language: str = "java") -> List[str]:
        """返回 SAVR 自定义 .ql 列表（按文件名排序，保证结果可复现）。

        M12 起按语言取包：Java 走历史目录 ``tools/codeql-queries/src``；
        其余语言取 ``tools/codeql-queries/<language>/src``。
        **没有该语言的自定义包时返回空列表，绝不回退 Java 包** ——
        Java 查询 import java.qll / java-all.qll，套到 javascript 库上 analyze 会失败，
        而「analyze 失败」在 A1 又会被记账成无漏洞，属于静默丢召回。
        """
        if not str(language or "").strip():
            language = "java"
        if language == "java":
            d = Path(cls._CUSTOM_QUERY_DIR)
        else:
            d = Path(cls._CUSTOM_PACK_ROOT) / language / "src"
        if not d.is_dir():
            return []
        return sorted(str(p) for p in d.glob("*.ql") if not p.name.startswith("_"))

    @staticmethod
    def default_db_path(project_path: str, language: str) -> str:
        """默认库路径按语言分开（M12 多语言前提）。

        Java 沿用 ``.codeql-db`` 以保持历史路径与既有对账口径一致（重扫前核 Phase1
        文件数就数这个目录）；其余语言各用 ``.codeql-db-<language>``。
        共用同一 source-root 时，若不分开，第二种语言的库会把第一种覆盖掉。
        """
        suffix = "" if language == "java" else "-" + str(language)
        return str(Path(project_path) / (".codeql-db" + suffix))

    def is_available(self) -> bool:
        return bool(self._codeql)

    def version(self) -> str:
        if not self.is_available():
            return ""
        try:
            out = subprocess.run(
                [self._codeql, "--version"], capture_output=True, text=True, errors="replace",
                stdin=subprocess.DEVNULL,
                timeout=_cfg_codeql_timeout("version", 30)
            )
            return (out.stdout or "").strip().splitlines()[0] if out.stdout else ""
        except Exception:
            return ""

    @staticmethod
    def _env_with_mvn_shim(project_path: Optional[str] = None) -> Dict[str, str]:
        """兼容入口：转调模块级 ``_env_with_mvn_shim``（含构建 JDK 绑定）。

        保留这个方法名是因为单测与外部脚本都在用 ``CodeQLAdapter._env_with_mvn_shim``，
        改成模块函数后旧调用方不该跟着改。
        """
        return _env_with_mvn_shim(project_path)

    # 套件别名 → 官方套件后缀。CLI 2.23+ 只认 ``<language>-<suite>`` 形式，
    # 裸名（如 "security-extended"）会被当成 query pack 名解析并报
    # "Query pack security-extended cannot be found"，导致整轮 analyze 零产出。
    _SUITE_ALIAS = {
        "security-extended": "security-extended",
        "security-and-quality": "security-and-quality",
        "experimental": "security-experimental",
        "security-experimental": "security-experimental",
        "code-quality": "code-quality",
    }

    @classmethod
    def _normalize_suite(cls, suite: Optional[str], language: str) -> str:
        """把套件简写名规范化为 CLI 可解析的 ``<language>-<suite>``。"""
        raw = (suite or "security-extended").strip()
        if raw.startswith(language + "-") or "/" in raw or raw.endswith(".qls"):
            return raw
        tail = cls._SUITE_ALIAS.get(raw, raw)
        return f"{language}-{tail}"

    @staticmethod
    def _is_finalized(db_path: str) -> bool:
        """判断 CodeQL 库是否已 finalize（未 finalize 的库 analyze 会直接失败）。

        判据：``codeql-database.yml`` 里存在 ``inProgress:`` 段即代表未 finalize。
        """
        yml = Path(db_path) / "codeql-database.yml"
        if not yml.exists():
            return False
        try:
            txt = yml.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False
        return "inProgress:" not in txt

    # ``create_database`` 只看 ``_is_finalized`` 就 ``reused=True`` 直接复用，
    # 于是 analyze 跑在旧库上、产出 0 告警，上层把结论写成
    # ``build_failed_or_empty`` —— 看起来像「构建失败」，实际是**复用了过期快照**。
    # 连带后果：我为了修构建 JDK 做的绑定，在这条路径上根本没被执行到。
    # 现在要求三件事同时成立才复用：已 finalize、source-root 一致、库比最新源码新。
    _SOURCE_SUFFIX = (".java", ".kt", ".gradle", ".kts")
    _SOURCE_NAMES = ("pom.xml", "build.gradle", "build.gradle.kts")
    # 指纹文件名：写在库目录里，记录「建库时的源码内容指纹」。
    _FP_FILE = ".sastai_src_fp"

    # 扫描目录时必须排除**所有** `.codeql-db*` 变体，不能只排精确的 `.codeql-db`。
    #
    # （`.codeql-db.partial2..5` 等，共 4.3 万文件 / 420MB，是此前
    # 「Refusing to create database: exists and is not empty」时改名留下的）。
    # CodeQL 建库时把源码目录当 source root 复制，于是把这些**库目录也当源码复制**，
    # **超过 Windows MAX_PATH(260)** ⇒ `AccessDeniedException` ⇒
    # ① 复制源文件失败（properties extractor 报错）；
    # ② finalize 清理 `cache/cached-strings/pools/*/info` 时被拒 → 无限重试（死循环）；
    # ③ 库不完整（finalised=false）⇒ analyze 阶段 `java: empty` ⇒ 上层笼统记成
    #    `build_failed_or_empty` ⇒ **静态侧整轮降级启发式**（A1 findings 断崖）。
    #
    # 修法：源码遍历一律跳过 `.codeql-db` 前缀的所有目录。
    _SKIP_DIR_NAMES = frozenset({
        "target", "build", "node_modules", ".git", "out", "bin", "generated",
    })

    @classmethod
    def _filter_source_dirs(cls, dirnames: list) -> list:
        """过滤源码遍历要进入的子目录：跳过构建产物与**所有** `.codeql-db*` 变体。"""
        return [d for d in dirnames
                if d not in cls._SKIP_DIR_NAMES
                and not d.startswith(".codeql-db")]

    @classmethod
    def _source_fingerprint(cls, project_path: str, limit: int = 20000) -> str:
        """源码内容指纹（sha256）。

        `src/main/resources/url/*.xml`（**内容没变**，git status 干净），
        mtime 判据因此把刚建好的库判成 stale，**每轮都重建 CodeQL 库**（A1 从 3 分钟涨到 8 分钟）。
        内容指纹不受 touch 影响，且只覆盖真正决定 CodeQL Java 库的东西：
        `.java/.kt` + 构建文件。**刻意不含资源 XML**——MyBatis mapper 不参与 CodeQL 建库。
        """
        import hashlib
        h = hashlib.sha256()
        files = []
        try:
            for dirpath, dirnames, filenames in os.walk(project_path):
                dirnames[:] = cls._filter_source_dirs(dirnames)
                for fn in filenames:
                    if not (fn.endswith(cls._SOURCE_SUFFIX) or fn in cls._SOURCE_NAMES):
                        continue
                    files.append(os.path.join(dirpath, fn))
        except Exception:
            return ""
        files.sort()
        for p in files[:limit]:
            try:
                rel = os.path.relpath(p, project_path).replace("\\", "/")
                h.update(rel.encode("utf-8", "replace"))
                with open(p, "rb") as fh:
                    h.update(fh.read())
            except OSError:
                continue
        return h.hexdigest()

    @classmethod
    def _read_db_fingerprint(cls, db_path: str) -> str:
        try:
            with open(os.path.join(db_path, cls._FP_FILE), encoding="utf-8") as fh:
                return fh.read().strip()
        except Exception:
            return ""

    @classmethod
    def _write_db_fingerprint(cls, db_path: str, project_path: str) -> None:
        try:
            fp = cls._source_fingerprint(project_path)
            if fp:
                with open(os.path.join(db_path, cls._FP_FILE), "w", encoding="utf-8") as fh:
                    fh.write(fp)
        except Exception:
            pass

    @staticmethod
    def _db_meta(db_path: str) -> Dict[str, Any]:
        """读 ``codeql-database.yml`` 的关键字段（不引入额外依赖，用 yaml 但失败即空）。"""
        yml = Path(db_path) / "codeql-database.yml"
        try:
            import yaml  # 项目已依赖 PyYAML（config_registry 在用）
            with open(yml, encoding="utf-8", errors="ignore") as fh:
                data = yaml.safe_load(fh) or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @classmethod
    def _newest_source_mtime(cls, project_path: str, limit: int = 20000) -> float:
        """项目内最新源码文件的 mtime（epoch 秒）。超限时返回已扫到的最大值。"""
        newest = 0.0
        seen = 0
        try:
            for dirpath, dirnames, filenames in os.walk(project_path):
                dirnames[:] = cls._filter_source_dirs(dirnames)
                for fn in filenames:
                    if not (fn.endswith(cls._SOURCE_SUFFIX) or fn in cls._SOURCE_NAMES):
                        continue
                    seen += 1
                    if seen > limit:
                        return newest
                    try:
                        mt = os.path.getmtime(os.path.join(dirpath, fn))
                        if mt > newest:
                            newest = mt
                    except OSError:
                        continue
        except Exception:
            return newest
        return newest

    @classmethod
    def _pick_db_target(cls, base_db: str, project_path: str) -> tuple:
        """挑一个可用的库目录。返回 ``(path, reused, reason)``。

        为什么不是「删掉旧库再原地重建」：本环境下两条路都被堵死——
        ①``shutil.rmtree`` 撞沙箱批量删除护栏（CodeQL 库 5000+ 文件，阈值 50）；
        ②``os.rename`` 报 WinError 5（库被占用）。
        于是改成「**旧库原样保留，新库建到兄弟目录**」：
          - ``.codeql-db``            规范路径（历史口径，Phase1 核文件数就数它）
          - ``.codeql-db.fresh-<ts>`` 源码变更后新建的库
        每次先在所有候选里找「可用且最新」的那个，没有才新建。
        代价是残留旧库目录需要人工清理，但不会因为删不掉而让 A1 永远降级。
        """
        candidates = []
        if os.path.isdir(base_db):
            candidates.append(base_db)
        try:
            parent = os.path.dirname(base_db) or "."
            stem = os.path.basename(base_db)
            for name in os.listdir(parent):
                if name.startswith(stem + ".fresh-"):
                    candidates.append(os.path.join(parent, name))
        except Exception:
            pass
        usable = []
        reasons = []
        for c in candidates:
            ok, why = cls._db_is_usable(c, project_path)
            if ok:
                usable.append(c)
            else:
                reasons.append(f"{os.path.basename(c)}:{why}")
        if usable:
            usable.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            return usable[0], True, "ok"
        # 新建：base 目录若已存在（且不可用），改用带时间戳的兄弟目录
        if not os.path.isdir(base_db):
            return base_db, False, ";".join(reasons) or "no_db"
        import time as _time
        return f"{base_db}.fresh-{int(_time.time())}", False, ";".join(reasons)

    @classmethod
    def _touch_sources(cls, project_path: str) -> int:
        """把所有 Java/Kotlin 源文件的 mtime 更新到当前时刻，返回处理的文件数。

        目的只有一个：让 Maven/Gradle 的增量编译判定为「源码比 class 新」，
        从而真的调用 javac —— CodeQL 的 Java tracer 只能通过 javac 调用提取 TRAP。

        为什么不是删 `target/classes`：靶场可能正跑在 target 下（OWASP 的
        `target/tomcat9x`、`target/db`），删目录会撞上文件锁；touch 无锁、无副作用，
        且**内容不变** ⇒ `_source_fingerprint` 不受影响，不会引发无谓重建。
        """
        root = os.path.abspath(project_path)
        skip = {"target", "build", "node_modules", ".git", "out", "bin", "generated"}
        n = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".codeql")]
            for fn in filenames:
                if not fn.endswith((".java", ".kt")):
                    continue
                try:
                    os.utime(os.path.join(dirpath, fn), None)
                    n += 1
                except OSError:
                    continue
        return n

    @classmethod
    def _db_is_usable(cls, db_path: str, project_path: str) -> tuple:
        """库能不能直接复用。返回 ``(usable, reason)``。

        ``reason`` 会被日志打出来，避免再出现「为什么没重建」这种需要猜的问题。
        """
        if not os.path.isdir(db_path):
            return False, "db_not_exists"
        if not cls._is_finalized(db_path):
            return False, "db_not_finalized"
        meta = cls._db_meta(db_path)
        # source-root 必须一致：库是对另一个目录建的，分析结果会张冠李戴
        prefix = str(meta.get("sourceLocationPrefix") or "")
        if prefix:
            try:
                if os.path.normcase(os.path.abspath(prefix)) != \
                        os.path.normcase(os.path.abspath(project_path)):
                    return False, f"source_root_mismatch({prefix})"
            except Exception:
                return False, "source_root_unparsable"
        # 新鲜度：优先用**内容指纹**（免疫 touch），没有指纹才退回 mtime 启发式。
        fp_now = cls._source_fingerprint(project_path)
        fp_db = cls._read_db_fingerprint(db_path)
        if fp_now and fp_db:
            if fp_now != fp_db:
                return False, "source_changed(since_build)"
            return True, "ok"
        created = 0.0
        raw = ((meta.get("creationMetadata") or {}) if isinstance(meta.get("creationMetadata"), dict) else {}).get("creationTime")
        if raw:
            try:
                import re as _re
                from datetime import datetime, timezone
                if isinstance(raw, datetime):
                    # PyYAML 会把 YAML 1.1 的时间戳直接解析成 datetime（本机就是这种），
                    # 此时 strptime 那条路根本走不到 —— 第一版漏了这个分支。
                    created = (raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)).timestamp()
                else:
                    # strptime 的 %f 只吃 1~6 位，否则解析失败、created 退化成 0，
                    # 整个新鲜度校验被静默跳过。
                    _s = str(raw).strip()
                    _m = _re.match(
                        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?", _s)
                    if _m:
                        _base, _frac, _tz = _m.group(1), (_m.group(2) or "")[:6], _m.group(3) or "Z"
                        _norm = _base + ("." + _frac.ljust(6, "0") if _frac else "") + \
                            ("+0000" if _tz == "Z" else _tz.replace(":", ""))
                        for _fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
                            try:
                                created = datetime.strptime(_norm, _fmt).timestamp()
                                break
                            except ValueError:
                                continue
            except Exception:
                created = 0.0
        if created:
            newest = cls._newest_source_mtime(project_path)
            # 留 60s 余量：构建期间源码被 touch 不该触发无谓重建
            if newest > created + 60:
                from datetime import datetime, timezone
                return False, (f"stale_db(created="
                               f"{datetime.fromtimestamp(created, timezone.utc):%Y-%m-%d}, "
                               f"newest_src="
                               f"{datetime.fromtimestamp(newest, timezone.utc):%Y-%m-%d})")
        return True, "ok"

    def finalize_database(self, db_path: str) -> Dict[str, Any]:
        """codeql database finalize。

        CLI 2.x 的 ``database create`` 不保证完成 finalize（构建超时/构建失败时会把
        TRAP 留在未 finalize 状态）。未 finalize 的库执行 analyze 会直接报
        "needs to be finalized before running queries"，整轮 A1 注入类零产出。
        """
        if not self.is_available():
            return {"status": "unavailable", "reason": "codeql CLI not found"}
        try:
            proc = subprocess.run(
                [self._codeql, "database", "finalize", db_path],
                capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL,
                timeout=_cfg_codeql_timeout("finalize", 900), env=self._env_with_mvn_shim(),
            )
            if proc.returncode != 0:
                return {"status": "error", "reason": (proc.stderr or proc.stdout or "")[:500]}
            return {"status": "ok"}
        except Exception as exc:
            return {"status": "error", "reason": str(exc)}

    def _run_create(self, cmd, db: str, project_path: str, finalized_grace: float = 300.0):
        """跑 ``codeql database create``，并在「已 finalize 但 cleanup 卡住」时提前收工。

        只负责删 TRAP 临时文件）会无限期挂住——进程活着、内存不动、TRAP 目录不再缩小。
        干等的话 ``create`` 会耗到 1800s 超时，A1 整轮降级成启发式。
        但 cleanup 只是**磁盘回收**，不影响库可用性：``finalised: true`` 之后
        analyze 就能正常跑。所以这里做「已 finalize 后再宽限 N 秒，仍未退出就杀掉并当成功」。

        输出走临时文件而不是管道：CodeQL 会派生 JVM 子进程，若子进程继承了管道句柄，
        ``subprocess.run(capture_output=True)`` 会在 CLI 已退出后仍阻塞在读端。
        """
        import tempfile
        import time as _time
        import types

        env = self._env_with_mvn_shim(project_path)
        out_path = os.path.join(tempfile.gettempdir(), f"codeql_create_{int(_time.time())}.log")
        out_fh = open(out_path, "w", encoding="utf-8", errors="replace")
        rc = None
        finalized_at = 0.0
        hard_timeout = float(_cfg_codeql_timeout("create", 1800))
        try:
            p = subprocess.Popen(cmd, stdout=out_fh, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, env=env)
            deadline = _time.time() + hard_timeout
            while p.poll() is None:
                now = _time.time()
                if now > deadline:
                    p.kill()
                    logger.warning("[codeql] database create 超时（%ss），已终止", int(hard_timeout))
                    break
                if not finalized_at and self._is_finalized(db):
                    finalized_at = now
                    logger.info("[codeql] 数据库已 finalize，等待 cleanup 收尾（最多 %ss）",
                                int(finalized_grace))
                if finalized_at and (now - finalized_at) > finalized_grace:
                    p.kill()
                    logger.warning(
                        "[codeql] cleanup 卡住（已 finalize %ss 仍未退出）→ 终止并视为成功；"
                        "库本身可用，只是 TRAP 临时文件没删干净",
                        int(now - finalized_at))
                    break
                _time.sleep(3)
            rc = p.poll()
        finally:
            try:
                out_fh.close()
            except Exception:
                pass
        text = ""
        try:
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except Exception:
            pass
        ok = self._is_finalized(db)
        return types.SimpleNamespace(returncode=0 if ok else (rc if rc is not None else 1),
                                     stdout=text, stderr=text)

    @classmethod
    def _quarantine_stale_db_dirs(cls, project_path: str, keep: str = "") -> List[str]:
        """把源码根下的**残留 CodeQL 库目录**移出源码根（不删除）。

        ``codeql database create --source-root=<项目根>`` 会把源码根**整个复制**进库目录
        。若源码根里残留了
        半成品库（``.codeql-db.partial*`` / ``.codeql-db.broken-*`` / ``.codeql-db.fresh-*``），
        它们会被当成源码一起复制，路径变成
        ⇒ **超过 Windows MAX_PATH(260)** ⇒ ``AccessDeniedException`` ⇒
        源文件复制失败 + finalize 清理 cache 时无限重试（死循环）+ 库不完整
        ⇒ analyze 得到 ``java: empty`` ⇒ 上层记成 ``build_failed_or_empty``
        ⇒ **静态侧整轮降级启发式**（A1 findings 断崖式下跌）。

        实测残留库里确实含源码副本（``.codeql-db.fresh-*`` 里有 77 个 .java +
        480 个 .properties），这就是被复制进去的东西。

        ## 为什么必须「移出源码根」而不是「在根内改名」
        改名后目录**仍在 source-root 内**，其中的 .java/.properties 照样会被复制 ——
        路径依然爆表。CLI 没有排除参数，唯一可靠解法是让它们**不在 source-root 内**。

        ## 为什么是「移走」而不是「删除」
        删除 4 万个文件既慢又会撞上文件锁/安全钩子（本机实测删除耗时 3 分钟且
        反复失败）；移动是 O(1) 的原子操作，且**可回滚**（保留原名 + 时间戳）。
        移出的目录放在系统临时目录下，任务结束后可手工清理。

        返回被移走的目录名列表（供日志/诊断）。
        """
        moved: List[str] = []
        try:
            root = os.path.abspath(project_path)
        except Exception:
            return moved
        if not os.path.isdir(root):
            return moved
        keep_abs = os.path.abspath(keep) if keep else ""
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            return moved
        # 目标落点：系统临时目录下的隔离区（**必须在 source-root 之外**）
        try:
            import tempfile
            quarantine_root = os.path.join(tempfile.gettempdir(),
                                           "SAVR-codeql-quarantine")
            os.makedirs(quarantine_root, exist_ok=True)
        except Exception as _qe:
            logger.warning("[codeql] 无法创建隔离目录（跳过隔离）：%s", _qe)
            return moved
        stamp = str(int(time.time()))
        for name in entries:
            if not name.startswith(".codeql-db"):
                continue
            p = os.path.join(root, name)
            if not os.path.isdir(p):
                continue
            if keep_abs and os.path.abspath(p) == keep_abs:
                continue
            dst = os.path.join(quarantine_root, "%s.%s" % (name, stamp))
            try:
                shutil.move(p, dst)
                moved.append(name)
                logger.warning(
                    "[codeql] 已把残留库目录移出源码根（避免被当源码复制导致 MAX_PATH 溢出）："
                    "%s → %s", name, dst)
            except Exception as _oe:
                logger.warning("[codeql] 移走残留库目录失败（%s）：%s", name, _oe)
        return moved

    def create_database(self, project_path: str, language: str, db_path: Optional[str] = None, build_command: Optional[str] = None) -> Dict[str, Any]:
        """codeql database create。Java 需构建环境，失败返回 error（调用方回退）。

        构建时把 Maven shim 注入 PATH（改进清单 P0#1）：本机 mvn 启动脚本损坏，
        codeql autobuild 默认解析到的 mvn 会失败，注入可用 shim 后即可正常构建 Java 数据库。

        Java 默认用显式 ``--command="mvn -B compile"`` 而非 autobuild 的 ``clean package``：
        autobuild 的 package 流程下 CodeQL tracer 常捕获不到 javac（报 no-source-code-seen），
        而 ``mvn compile`` 经 shim 直启 Maven 可被 tracer 正确提取（已在 java-quote 验证）。
        """
        if not self.is_available():
            return {"status": "unavailable", "reason": "codeql CLI not found"}
        db = db_path or CodeQLAdapter.default_db_path(project_path, language)
        # 旧库被直接拿来分析，产出 0 告警并被上层记成 build_failed_or_empty。
        # 现在要求「已 finalize + source-root 一致 + 比最新源码新」三者同时成立；
        # 不成立时不删旧库，改建到 `.fresh-<ts>` 兄弟目录（见 _pick_db_target 注释）。
        db, reused, why = self._pick_db_target(db, project_path)
        if reused:
            logger.info("[codeql] 复用已有数据库（%s）", db)
            return {"status": "ok", "database": db, "reused": True}
        # 不隔离的话它们会被 --source-root 复制进新库 → 路径爆 MAX_PATH(260)
        # → AccessDenied → finalize 死循环 → 库不完整 → 静态侧整轮降级启发式。
        # 详见 _quarantine_stale_db_dirs 的说明。
        try:
            CodeQLAdapter._quarantine_stale_db_dirs(project_path, keep=db)
        except Exception as _qe:  # noqa: BLE001  fail-open：隔离失败仍继续建库
            logger.warning("[codeql] 隔离残留库目录失败（忽略）：%s", _qe)
        logger.warning("[codeql] 新建数据库（原因：%s）→ %s", why, db)
        if os.path.isdir(db):
            # 走到这里说明目标目录存在却不可用（例如上次被中断留下半成品）。
            # 仍然不删：CodeQL 支持 --overwrite，交给它覆盖即可。
            logger.warning("[codeql] 目标目录已存在但不可用，将用 --overwrite 覆盖：%s", db)
        cmd = [self._codeql, "database", "create", db, "--language=" + language, "--source-root=" + project_path]
        # 目标目录非空时 CodeQL 会直接拒绝（"exists and is not an empty directory"），
        # 所以显式给 --overwrite；正常路径下 db 是新目录，这个分支不会触发。
        try:
            if os.path.isdir(db) and os.listdir(db):
                cmd.append("--overwrite")
        except Exception:
            pass
        if language == "java" and build_command is None:
            build_command = "mvn -B compile"
        if build_command:
            cmd += ["--command=" + build_command]
        # target/classes 已是最新时 javac **一次都不跑**，CodeQL tracer 抓不到任何 javac
        # ⇒ 建库「成功」但告警为 0，上层记成 build_failed_or_empty（日志是
        # "detected code written in Java/Kotlin but could not process any of it"）。
        #
        # 不能用 `mvn clean compile`：靶场正跑在 `target/tomcat9x` + `target/db` 上，
        # clean 会删运行中的文件——实测直接卡死在 "Deleting .../target"（文件被 JVM 锁住），
        # 建库挂 5 分钟无进展。
        # 只 touch 源码时间戳：不删任何文件、不碰运行中的目录，且内容不变 ⇒ 源码指纹不受影响。
        if language in ("java", "kotlin"):
            try:
                _n = CodeQLAdapter._touch_sources(project_path)
                if _n:
                    logger.info("[codeql] 已 touch %d 个源文件以强制重新编译（增量编译会让 tracer 抓不到 javac）", _n)
            except Exception as _te:  # noqa: BLE001  fail-open：touch 失败仍继续，只是可能抓到 0 告警
                logger.warning("[codeql] touch 源文件失败（%s），构建可能因增量编译而不产出 TRAP", _te)
        try:
            proc = self._run_create(cmd, db, project_path)
            if proc.returncode != 0:
                # 构建命令失败但 TRAP 可能已部分落盘：仍尝试 finalize 抢救，避免整轮零产出
                fin = self.finalize_database(db)
                if fin.get("status") == "ok":
                    return {"status": "ok", "database": db, "finalized": "after-failed-create"}
                return {
                    "status": "error",
                    "reason": "database create failed: " + (proc.stderr or "")[:400]
                    + " | finalize: " + str(fin.get("reason", ""))[:200],
                    "database": db,
                }
            # create 成功也必须显式 finalize：CLI 2.x 不保证 create 完成 finalize。
            # 但**已经 finalize 的库不能再 finalize 一次**——CodeQL 会报错，
            # 进而让 create_database 返回 error、整轮 A1 降级。
            # 此时库已 finalised=true，冗余的 finalize 直接把它打回 build_failed。
            if self._is_finalized(db):
                self._write_db_fingerprint(db, project_path)
                return {"status": "ok", "database": db, "finalized": "by-create"}
            fin = self.finalize_database(db)
            if fin.get("status") != "ok":
                return {
                    "status": "error",
                    "reason": "database finalize failed: " + str(fin.get("reason", ""))[:400],
                    "database": db,
                }
            # 记下建库时的源码指纹：下次判「能不能复用」用它，而不是 mtime
            # （mtime 会被无关的 touch 打乱，导致每轮重建）。
            self._write_db_fingerprint(db, project_path)
            return {"status": "ok", "database": db, "finalized": True}
        except Exception as exc:
            return {"status": "error", "reason": str(exc), "database": db}

    def analyze(
        self,
        db_path: str,
        query_suite: Optional[str] = "security-extended",
        language: str = "java",
        extra_queries: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """codeql database analyze，产出 SARIF。

        - ``query_suite`` 支持官方简写名（security-extended / experimental 等），
          内部统一规范化成 CLI 可解析的 ``<language>-<suite>``。
        - ``extra_queries`` 是叠加的自定义 .ql 列表（SAVR 自有查询），与套件一起执行。
        """
        if not self.is_available():
            return {"status": "unavailable", "reason": "codeql CLI not found"}
        suite = self._normalize_suite(query_suite, language)
        out_sarif = str(Path(db_path)) + ".sarif"
        # 第一次成功后文件留存，后续 analyze 全部 10s 返回 error（reason 只有 "Running queries."），
        # 导致 A1 永久 fallback heuristic。analyze 前必须清理旧文件。
        try:
            if os.path.exists(out_sarif):
                os.remove(out_sarif)
        except Exception:
            pass
        cmd = [self._codeql, "database", "analyze", db_path, suite]
        # + 5 个自定义 .ql 一起跑」→ query filter 'tags contain' 约束失败 + exit 1，整轮
        # analyze 失败、官方结果一起丢。现改为官方套件单独跑（主结果），自定义查询由
        # analyze_extra 隔离执行、容错合并。extra_queries 参数保留兼容但不拼进主命令。
        # 内存护栏：动态预算（见 _resolve_ram_mb），预算<=0 时不传 --ram 让 CodeQL 自适应，
        # 避免再出现「护栏本身把堆压到 1800M 致编译分层 OOM」的坏慢路径。
        cmd += ["--threads=" + str(self._threads)]
        ram_mb = self._resolve_ram_mb()
        if ram_mb > 0:
            cmd += ["--ram=" + str(ram_mb)]
        cmd += [
            "--format=sarif-latest",
            "--output=" + out_sarif,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                  stdin=subprocess.DEVNULL,
                                  timeout=_cfg_codeql_timeout("analyze", 3600), env=self._env_with_mvn_shim())
            if proc.returncode != 0:
                return {"status": "error", "reason": (proc.stderr or "")[:500], "sarif": out_sarif}
            return {"status": "ok", "sarif": out_sarif}
        except Exception as exc:
            return {"status": "error", "reason": str(exc), "sarif": out_sarif}

    def analyze_extra(self, db_path: str, extra_queries: Optional[List[str]] = None) -> Dict[str, Any]:
        """单独执行自定义 .ql（与官方套件隔离，失败不影响官方结果）。

        让整轮 analyze exit 1、官方结果一起丢。隔离后官方套件成功即产出主结果，
        自定义查询失败只降级为 warning。
        """
        if not self.is_available():
            return {"status": "unavailable", "reason": "codeql CLI not found"}
        qs = [q for q in (extra_queries or []) if q]
        if not qs:
            return {"status": "skipped", "reason": "no extra queries"}
        out_sarif = str(Path(db_path)) + ".extra.sarif"
        # 同 analyze：CodeQL 拒绝覆盖已存在的输出文件，先清理。
        try:
            if os.path.exists(out_sarif):
                os.remove(out_sarif)
        except Exception:
            pass
        cmd = [self._codeql, "database", "analyze", db_path] + qs
        cmd += ["--threads=" + str(self._threads)]
        ram_mb = self._resolve_ram_mb()
        if ram_mb > 0:
            cmd += ["--ram=" + str(ram_mb)]
        cmd += ["--format=sarif-latest", "--output=" + out_sarif]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace",
                timeout=_cfg_codeql_timeout("analyze", 3600), env=self._env_with_mvn_shim())
            if proc.returncode != 0:
                return {"status": "error", "reason": (proc.stderr or "")[:500], "sarif": out_sarif}
            return {"status": "ok", "sarif": out_sarif}
        except Exception as exc:
            return {"status": "error", "reason": str(exc), "sarif": out_sarif}

    def scan(self, project_path: str, language: str = "python") -> Dict[str, Any]:
        """完整 CodeQL 扫描：create database + analyze。

        返回结构（新增 status 字段，供上层区分「确实无漏洞」与「构建失败未扫描」）：
        - status="unavailable"      ：CLI 不存在（available=False）
        - status="build_failed"     ：数据库构建失败（如 Maven/Gradle 损坏、依赖缺失）；available=True 表示 CLI 在，
                                      但本次扫描未产生任何注入类结果，上层必须告警而非当作「无漏洞」。
        - status="analyze_failed"   ：分析失败（查询套件执行错误）
        - status="ok"               ：正常产出 alerts
        - status="no_vuln"          ：扫描成功但 0 告警（区别于 build_failed，代表真实无注入类告警）
        """
        if not self.is_available():
            return {"available": False, "status": "unavailable", "alerts": [], "reason": "codeql CLI not found"}
        created = self.create_database(project_path, language)
        if created.get("status") != "ok":
            return {
                "available": True,
                "status": "build_failed",
                "alerts": [],
                "reason": "database create failed: " + str(created.get("reason", ""))[:400],
            }
        # 官方 security-extended 单独跑（主结果）；自定义 .ql 隔离执行、容错合并。
        # 套件名来自 config/codeql.yaml（suite），_normalize_suite 负责规范化成 CLI 可解析形式。
        analyzed = self.analyze(
            created["database"], query_suite=_cfg_codeql_suite(default="java-security-extended"), language=language)
        if analyzed.get("status") != "ok":
            return {
                "available": True,
                "status": "analyze_failed",
                "alerts": [],
                "reason": "analyze failed: " + str(analyzed.get("reason", ""))[:400],
            }
        alerts = self._parse_sarif(analyzed.get("sarif", ""))
        extra = self.analyze_extra(created["database"], self.custom_queries(language))
        if extra.get("status") == "ok":
            alerts = alerts + self._parse_sarif(extra.get("sarif", ""))
        elif extra.get("status") == "error":
            logger.warning("[codeql] 自定义查询单独跑失败（官方套件结果保留）：%s",
                           str(extra.get("reason", ""))[:200])
        return {
            "available": True,
            "status": "ok" if alerts else "no_vuln",
            "alerts": alerts,
            "sarif": analyzed.get("sarif", ""),
            "extra_status": extra.get("status", "skipped"),
        }

    @staticmethod
    def _parse_sarif(sarif_path: str) -> List[Dict[str, Any]]:
        """从 SARIF 提取告警列表（ruleId / message / location）。解析失败返回空。"""
        if not sarif_path or not Path(sarif_path).exists():
            return []
        try:
            data = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
        except Exception:
            return []
        alerts: List[Dict[str, Any]] = []
        for run in data.get("runs", []) or []:
            rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []}
            for res in run.get("results", []) or []:
                rule = rules.get(res.get("ruleId"), {})
                loc = ((res.get("locations") or [{}])[0].get("physicalLocation", {}) or {})
                # 数据流告警携带 relatedLocations（污点源/汇/净化节点），供 A1→A2 注入真实
                # entry_candidates / source_candidates（④ Step1：CodeQL 证据作为 A2 稳定喂入）。
                related = []
                for rl in (res.get("relatedLocations") or []) or []:
                    rloc = (rl.get("physicalLocation", {}) or {})
                    related.append({
                        "id": rl.get("id"),
                        "kind": rl.get("kind", "") or "",
                        "file": (rloc.get("artifactLocation", {}) or {}).get("uri", ""),
                        "line": (rloc.get("region", {}) or {}).get("startLine", 0),
                        "message": (rl.get("message", {}) or {}).get("text", "") or "",
                    })
                alerts.append({
                    "rule_id": res.get("ruleId", ""),
                    "message": (res.get("message", {}) or {}).get("text", "") or rule.get("shortDescription", {}).get("text", ""),
                    "file": (loc.get("artifactLocation", {}) or {}).get("uri", ""),
                    "line": (loc.get("region", {}) or {}).get("startLine", 0),
                    "severity": (res.get("properties", {}) or {}).get("problem.severity", "warning"),
                    "related_locations": related,
                })
        return alerts
