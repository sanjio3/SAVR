"""SCA + 代码可达性双条件判定。

为什么必须有这一层
------------------
SCA 只能证明「依赖树里存在某个漏洞版本的库」。但真正能打，还差两件事：

1. classpath 可达：该依赖确实被项目构建文件声明并打进产物。
   SCA 扫到的可能只是某个 lock 文件里的传递依赖残留、shaded 改名副本、
   或 test scope 里根本不进生产 classpath 的库 —— 这些都不可能成为 gadget 来源。
2. 利用路径可达：代码里存在能被外部输入触发的对应入口。
   反序列化尤其如此：库在 classpath 上，但代码里根本没有 readObject / parseObject 调用点，
   那这条链永远走不到 —— 拿 gadget 去打只会得到一次假阴性。

两条都过才允许选弹。判不出来就明确判 False 并把原因写清楚，
**宁可漏选（D1 老实降级），不可误选**（误选会拿不存在的 gadget 去打，
把一次本该有效的验证污染成假阴性，且极难回溯）。

严格程度按 family 分级
----------------------
- 需要精确 gadget 链的族（反序列化系）：classpath + 入口 双命中才放行。
- 文本型族（SSTI / SQLi / 命令执行）：payload 与库版本无关，不需要 classpath 门控，
  直接放行并标注不适用，避免把门控误用在不需要它的场景上产生假阴性。
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 需要「classpath + 利用入口」双条件才允许选弹的族。
# 这些族的 payload 是精确字节构造的 gadget 链，打错库版本就是废弹。
GADGET_FAMILIES = frozenset({
    "deserialization",
    "insecure-deserialization",
    "insecure_deserialization",
    "unsafe-deserialization",
    "unsafe_deserialization",
    "unserialize",
    "java-deserialization",
})

# family → 必须存在于代码里的利用入口模式。
# 只有 classpath 命中而代码里没有这些调用点，说明该库虽然在依赖里但没被用作反序列化入口，
# 打过去必然走不到 sink。
_FAMILY_ENTRY_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "deserialization": (
        r"new\s+ObjectInputStream\s*\(",
        r"\.\s*readObject\s*\(",
        r"\.\s*readUnshared\s*\(",
        r"JSON\s*\.\s*parseObject\s*\(",
        r"JSON\s*\.\s*parse\s*\(",
        r"JSONObject\s*\.\s*parseObject\s*\(",
        r"JSONArray\s*\.\s*parseArray\s*\(",
        r"\.\s*readValue\s*\(",
        r"\.\s*fromXML\s*\(",
        r"XStream\s*\(",
        r"\.\s*enableDefaultTyping\s*\(",
        r"ObjectMapper\s*\(",
        r"\.\s*readObject\s*\(\s*\)",
    ),
}
# 同义 family 复用同一组入口模式
for _alias in ("insecure-deserialization", "insecure_deserialization",
               "unsafe-deserialization", "unsafe_deserialization",
               "unserialize", "java-deserialization"):
    _FAMILY_ENTRY_PATTERNS[_alias] = _FAMILY_ENTRY_PATTERNS["deserialization"]

# 扫描源码时的文件大小上限与后缀白名单：避免把 minified js / 大资源文件读进来空转。
_MAX_SCAN_BYTES = 2 * 1024 * 1024
_SCAN_SUFFIXES = {".java", ".kt", ".scala", ".jsp", ".xml", ".properties", ".py", ".js", ".ts"}
# 目录黑名单：依赖目录/构建产物不参与「项目自身代码」的入口判定，
# 否则会把第三方 jar 源码里的 readObject 当成本项目的利用入口（必然误判为可达）。
_SKIP_DIRS = {
    "node_modules", "target", "build", "dist", ".git", ".idea", "__pycache__",
    "venv", ".venv", "site-packages", "out", "bin", "obj", ".gradle", ".mvn",
}

_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts", "package.json", "requirements.txt")


# --------------------------------------------------------------------------- 版本工具


def _version_tokens(version: str) -> List[int]:
    """把版本号切成可比较的数字段：'1.2.3.RELEASE' → [1, 2, 3]。

    只取前导数字段，忽略 qualifier（RELEASE / Final / -SNAPSHOT 等），
    因为它们不影响「这是不是同一个大版本」的判定，却能轻易让朴素的字典序比较出错。
    """
    toks: List[int] = []
    for part in str(version or "").replace("-", ".").replace("_", ".").split("."):
        m = re.match(r"^\d+", part.strip())
        if not m:
            break
        toks.append(int(m.group()))
    return toks


def version_matches(declared: str, detected: str) -> bool:
    """构建文件声明的版本与 SCA 检出版本是否可视为同一个依赖。

    - 声明为空、或是 Maven 属性占位符（${spring.version}）→ 无法解析，按 name 命中放行。
      这里选择放行而非拒绝：name 已经匹配，版本只是没写死，拒绝会误杀真实可达的库。
    - 两边都有版本 → 按数字段逐段比较，短的一方按 0 补齐（3.1 == 3.1.0）。
    """
    d = str(declared or "").strip()
    t = str(detected or "").strip()
    if not d or "${" in d or not t:
        return True
    dt, tt = _version_tokens(d), _version_tokens(t)
    if not dt or not tt:
        return True
    n = max(len(dt), len(tt))
    dt += [0] * (n - len(dt))
    tt += [0] * (n - len(tt))
    return dt == tt


def _name_matches(declared: str, target: str) -> bool:
    """依赖名匹配。

    Maven 生态 SCA 常报 'groupId:artifactId'，构建文件里也是 groupId:artifactId；
    但也有只写 artifactId 的情况。故：全等命中，或「冒号后一段」相等也算命中。
    """
    d = str(declared or "").strip().lower()
    t = str(target or "").strip().lower()
    if not d or not t:
        return False
    if d == t:
        return True
    d_tail = d.rsplit(":", 1)[-1]
    t_tail = t.rsplit(":", 1)[-1]
    return bool(d_tail) and d_tail == t_tail


# --------------------------------------------------------------------------- 构建文件解析


def _parse_maven(path: Path) -> List[Dict[str, str]]:
    deps: List[Dict[str, str]] = []
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as exc:
        logger.debug("[reachability] pom 解析失败 %s: %s", path, exc)
        return deps
    ns = ""
    root = tree.getroot()
    # Maven POM 默认带命名空间，取 tag 时要剥掉
    m = re.match(r"^\{(.+?)\}", root.tag)
    if m:
        ns = m.group(1)

    def _tag(name: str) -> str:
        return f"{{{ns}}}{name}" if ns else name

    for dep in root.iter(_tag("dependency")):
        gid = dep.findtext(_tag("groupId"), "").strip()
        aid = dep.findtext(_tag("artifactId"), "").strip()
        ver = dep.findtext(_tag("version"), "").strip()
        scope = dep.findtext(_tag("scope"), "").strip()
        if not aid:
            continue
        name = f"{gid}:{aid}" if gid else aid
        deps.append({"ecosystem": "maven", "name": name, "version": ver, "scope": scope,
                     "source": str(path)})
    return deps


def _parse_gradle(path: Path) -> List[Dict[str, str]]:
    """解析 build.gradle / build.gradle.kts 的依赖声明。

    覆盖三种常见写法：
        implementation 'group:artifact:version'
        implementation "group:artifact:version"
        implementation(group = "x", name = "y", version = "z")
    """
    deps: List[Dict[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return deps

    for m in re.finditer(
        r"""(?:implementation|compile|api|runtimeOnly|compileOnly|testImplementation|testCompile)\s*[\("']\s*"""
        r"""["']?([\w.\-]+)\s*:\s*([\w.\-]+)\s*(?::\s*([\w.\-]+))?""",
        text,
    ):
        gid, aid, ver = m.group(1), m.group(2), m.group(3) or ""
        deps.append({"ecosystem": "maven", "name": f"{gid}:{aid}", "version": ver,
                     "scope": "", "source": str(path)})

    # Kotlin DSL 具名参数写法
    for m in re.finditer(
        r"""(?:implementation|compile|api|runtimeOnly)\s*\(\s*group\s*=\s*["']([\w.\-]+)["']\s*,\s*"""
        r"""name\s*=\s*["']([\w.\-]+)["']\s*(?:,\s*version\s*=\s*["']([\w.\-]+)["'])?""",
        text,
    ):
        deps.append({"ecosystem": "maven", "name": f"{m.group(1)}:{m.group(2)}",
                     "version": m.group(3) or "", "scope": "", "source": str(path)})
    return deps


def _parse_package_json(path: Path) -> List[Dict[str, str]]:
    deps: List[Dict[str, str]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (ValueError, OSError):
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            deps.append({"ecosystem": "npm", "name": str(name), "version": str(ver or ""),
                         "scope": section, "source": str(path)})
    return deps


def _parse_requirements(path: Path) -> List[Dict[str, str]]:
    deps: List[Dict[str, str]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return deps
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([\w.\-\[\]]+)\s*(?:[=~><!]=?|@)\s*([\w.\-\*]+)", line)
        if m:
            deps.append({"ecosystem": "pypi", "name": m.group(1), "version": m.group(2),
                         "scope": "", "source": str(path)})
    return deps


_DEPS_CACHE: Dict[tuple, List[Dict[str, str]]] = {}


def resolve_declared_dependencies(code_root: Optional[str]) -> List[Dict[str, str]]:
    """从项目构建文件解析出「显式声明」的依赖清单。

    只看直接声明，不解析传递依赖树 —— 传递依赖要跑 mvn dependency:tree，
    成本高且易受网络影响；而「是不是传递来的」本身就是可达性的弱信号，
    这里优先保证判定快、稳、可离线。

    结果按 (code_root, 构建文件指纹) 缓存：`judge_reachability` 逐组件调用，
    同一棵树的 pom 会被重复解析 90+ 次（见 find_usage_entries 的说明）。
    """
    if not code_root:
        return []
    root = Path(code_root)
    if not root.exists():
        return []

    _build_paths = []
    for name in _BUILD_FILES:
        for path in list(root.glob(name)) + list(root.glob(f"*/{name}")):
            if path.is_file():
                _build_paths.append(path)
    _fp = tuple(sorted(
        (str(p), p.stat().st_mtime_ns if p.exists() else 0) for p in _build_paths
    ))
    _key = (code_root, _fp)
    _hit = _DEPS_CACHE.get(_key)
    if _hit is not None:
        return [dict(d) for d in _hit]

    deps: List[Dict[str, str]] = []
    for name in _BUILD_FILES:
        for path in list(root.glob(name)) + list(root.glob(f"*/{name}")):
            if not path.is_file():
                continue
            try:
                if path.name == "pom.xml":
                    deps.extend(_parse_maven(path))
                elif path.name.startswith("build.gradle"):
                    deps.extend(_parse_gradle(path))
                elif path.name == "package.json":
                    deps.extend(_parse_package_json(path))
                elif path.name == "requirements.txt":
                    deps.extend(_parse_requirements(path))
            except Exception as exc:  # 单个构建文件解析失败不影响其他文件
                logger.debug("[reachability] 解析 %s 失败：%s", path, exc)
    return deps


def find_dependency_declaration(component: Dict[str, Any],
                                code_root: Optional[str]) -> Optional[Dict[str, str]]:
    """在构建文件里找该 SCA 组件的显式声明，命中返回声明详情，否则 None。"""
    if not component:
        return None
    target = str(component.get("name") or component.get("component_name") or "").strip()
    if not target:
        return None
    detected_ver = str(component.get("version") or component.get("component_version") or "").strip()
    for dep in resolve_declared_dependencies(code_root):
        if not _name_matches(dep.get("name", ""), target):
            continue
        if not version_matches(dep.get("version", ""), detected_ver):
            continue
        return dep
    return None


# --------------------------------------------------------------------------- 利用入口扫描


_FP_CACHE: Dict[str, tuple] = {}
# TTL 比计算本身还短 ⇒ 缓存永远失效，等于每调一次就重扫一遍源码树。
# 实测后果：本轮卡在注册后的后处理阶段 30 分钟，0 次重放、0 个探针事件，
# 但进程系统 CPU 时间高达 1877s（全花在 stat 上）。
# 现在改成「自适应」：TTL = max(30, 上次实测耗时 × 20)，且可用环境变量覆盖。
_FP_TTL_S = float(os.environ.get("SAST_AI_FP_TTL", "0") or 0)  # 0 = 自适应
_FP_MIN_TTL_S = 300.0


def code_root_fingerprint(code_root: Optional[str]) -> tuple:
    """源码树指纹：只 stat 不读内容，用来给缓存判失效。

    为什么不用 root 目录的 mtime：改一个 .java 文件不会更新父目录 mtime，
    只看目录 mtime 会把「刚改过代码」的树当成没变。这里遍历一遍源文件取
    (文件数, 最新 mtime_ns)。

    带 5s TTL 的原因：本函数被 `find_usage_entries` / `resolve_declared_dependencies`
    的缓存键调用，而可达性判定是**逐组件**的（一次造弹 90+ 个组件）。
    不做 TTL 时，光是算指纹就是 90 × 0.7s ≈ 1 分钟/spec。
    5s 内的源码变化视为同一版本——一次扫描期间源码本就不该被改；
    真改了也有 `clear_reachability_cache` 兜底。
    """
    if not code_root:
        return ("", -1, -1)
    _now = time.time()
    _hit = _FP_CACHE.get(code_root)
    if _hit is not None:
        # 自适应 TTL：至少 30s，且不小于「上次实测耗时 × 20」——
        # 保证「算一次指纹的代价」远小于「它省下的重复遍历」。
        _ttl = _FP_TTL_S or max(_FP_MIN_TTL_S, float(_hit[2] or 0) * 20)
        if (_now - _hit[1]) < _ttl:
            return _hit[0]

    root = Path(code_root)
    if not root.exists():
        _fp = (str(root), -1, -1)
    else:
        count = 0
        newest = 0
        for path in _iter_source_files(root):
            count += 1
            try:
                newest = max(newest, path.stat().st_mtime_ns)
            except OSError:
                continue
        _fp = (str(root), count, newest)
    _FP_CACHE[code_root] = (_fp, _now, time.time() - _now)
    return _fp


def _iter_source_files(root: Path):
    """遍历源文件，**在目录层就剪枝**。

    旧实现是 `root.rglob("*")` 再逐个过滤：rglob 会先走进 target/、node_modules/、
    .git/ 这些大目录，把里面的文件全部 stat 一遍才被 `_SKIP_DIRS` 丢掉。
    而可达性判定要按组件反复遍历（见 find_usage_entries），累计就是分钟级。
    改成 os.walk + dirnames 就地剪枝后，同一次遍历降到几十毫秒。
    """
    skip = set(_SKIP_DIRS)
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in _SCAN_SUFFIXES:
                continue
            if any(part in skip for part in path.parts):
                continue
            try:
                if path.stat().st_size > _MAX_SCAN_BYTES:
                    continue
            except OSError:
                continue
            yield path


_ENTRY_CACHE: Dict[tuple, List[Dict[str, Any]]] = {}
_ENTRY_CACHE_MAX = 64


def clear_reachability_cache() -> None:
    """清空所有可达性缓存（入口扫描 / 构建文件解析 / 源码树指纹）。"""
    _ENTRY_CACHE.clear()
    _DEPS_CACHE.clear()
    _FP_CACHE.clear()


def find_usage_entries(family: str, code_root: Optional[str], limit: int = 20) -> List[Dict[str, Any]]:
    """扫描项目自身代码，找该 family 的利用入口调用点。

    只扫项目代码，跳过依赖目录 —— 第三方 jar 源码里的 readObject
    不是「本项目的利用入口」，算进来会让可达性判定永远为真。

    但 `judge_reachability` 是**逐 SCA 组件**调用的（一次造弹 90+ 个组件），
    于是同一个源码树被完整读 90 遍。本轮实测单条 deserialization spec 在
    `sca_forge_attack_payloads` 里卡 5 分钟以上，17 条 spec 把 D2 批墙钟(600s)
    和单条墙钟(300s)全部吃光 ⇒ 整批降级、**一条请求都没发出去**
    （17 条 deser spec 零 attempt 的真因）。缓存键带源码树指纹，改代码即失效。
    """
    fam = str(family or "").strip().lower()
    patterns = _FAMILY_ENTRY_PATTERNS.get(fam)
    if not patterns or not code_root:
        return []
    root = Path(code_root)
    if not root.exists():
        return []

    key = (fam, code_root, int(limit), code_root_fingerprint(code_root))
    cached = _ENTRY_CACHE.get(key)
    if cached is not None:
        return [dict(h) for h in cached]

    compiled = [(p, re.compile(p)) for p in patterns]
    hits: List[Dict[str, Any]] = []
    for path in _iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for raw, rx in compiled:
                if rx.search(line):
                    hits.append({
                        "file": str(path),
                        "line": lineno,
                        "pattern": raw,
                        "snippet": line.strip()[:200],
                    })
                    break
        if len(hits) >= limit:
            break

    if len(_ENTRY_CACHE) >= _ENTRY_CACHE_MAX:
        _ENTRY_CACHE.clear()
    _ENTRY_CACHE[key] = hits
    return [dict(h) for h in hits]


# --------------------------------------------------------------------------- 综合判定


def judge_reachability(component: Dict[str, Any],
                       family: str = "",
                       code_root: Optional[str] = None) -> Dict[str, Any]:
    """SCA 命中 + 代码可达性 双条件判定。

    返回 dict：
        reachable       是否允许据此选弹
        classpath_hit   该依赖是否在构建文件里显式声明
        entry_hit       代码里是否存在对应利用入口
        reason          判定理由（不可达时会写清是哪一条件没过）
        confidence      high / medium / low
        evidence        {declaration, entries}

    判定矩阵（反序列化等需要精确 gadget 的族）：
        classpath_hit 且 entry_hit → reachable（high）
        classpath_hit 但无 entry   → 不可达（库在依赖里却没被用作入口，打了也走不到 sink）
        无 classpath 但有 entry    → 不可达（代码在调用，但声明的库版本对不上，gadget 必然打空）
        两者都无                    → 不可达
    """
    fam = str(family or "").strip().lower()
    component = component or {}

    # 文本型族：payload 与库版本无关，不设 classpath 门控，放行以免产生假阴性。
    if fam and fam not in GADGET_FAMILIES:
        return {
            "reachable": True,
            "classpath_hit": False,
            "entry_hit": False,
            "reason": f"family={fam} 为文本型漏洞，payload 不依赖特定库版本的 gadget 链，不启用 classpath/入口门控",
            "confidence": "high",
            "evidence": {"declaration": None, "entries": []},
        }

    declaration = find_dependency_declaration(component, code_root)
    entries = find_usage_entries(fam or "deserialization", code_root)
    classpath_hit = declaration is not None
    entry_hit = bool(entries)

    evidence = {"declaration": declaration, "entries": entries[:5]}
    target = str(component.get("name") or component.get("component_name") or "")

    if classpath_hit and entry_hit:
        return {
            "reachable": True,
            "classpath_hit": True,
            "entry_hit": True,
            "reason": (
                f"{target} 已在构建文件声明（{Path(declaration['source']).name}）"
                f"且代码中存在 {len(entries)} 处利用入口调用点，classpath 与利用路径均可达"
            ),
            "confidence": "high",
            "evidence": evidence,
        }
    if classpath_hit and not entry_hit:
        return {
            "reachable": False,
            "classpath_hit": True,
            "entry_hit": False,
            "reason": (
                f"{target} 在 classpath 上，但代码里找不到 {fam or 'deserialization'} 利用入口调用点"
                "（无 readObject/parseObject 等），gadget 无法被触发，不予选弹"
            ),
            "confidence": "medium",
            "evidence": evidence,
        }
    if entry_hit and not classpath_hit:
        return {
            "reachable": False,
            "classpath_hit": False,
            "entry_hit": True,
            "reason": (
                f"代码存在利用入口，但 {target} 未在构建文件里显式声明"
                "（可能仅为传递依赖/已被 shaded 改名/版本不符），gadget 链不适用，不予选弹"
            ),
            "confidence": "medium",
            "evidence": evidence,
        }
    return {
        "reachable": False,
        "classpath_hit": False,
        "entry_hit": False,
        "reason": (
            f"{target} 既未在构建文件声明，代码里也无利用入口"
            + ("" if code_root else "（code_root 为空，无法做代码可达性判定）")
        ),
        "confidence": "low",
        "evidence": evidence,
    }
