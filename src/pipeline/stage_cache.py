"""① 缓存确定性阶段（2026-09-26 落地）。

背景：同一静态靶场（benchmark-sample-200 等代码字节不变），A1/CodeQL 与 A2 对静态
finding 的 LLM 语义分析是**确定性**的——输入不变输出就不变。回归轮完全可以复用这两段
的产物，只重跑动态 D1/D2 闭环，一轮从 ~2.3h 砍到 ~30-40min。

缓存键 = target_code_hash(源码内容) + config_hash(影响 a1/a2 产物的源文件) +
         model_profile + prompt_version + STAGE_CACHE_VERSION。
- 命中且代码未变 → 跳过 run_a1_scan / run_a2_scan，直接 load 缓存的 a1/a2 产物。
- 任一哈希变化（改了 safe_patterns / adjudicator / D2 / A2 逻辑 / 模型 / 靶场代码）→ bust，全量重跑。

产物用 pickle 序列化（a1_results / a2_results 均为 dataclass 树，可 pickle）。任何加载/
序列化异常一律 fail-open 回退全量执行，绝不因缓存损坏冻住扫描。

失效边界（必须靠哈希捕获，不能靠人记）：
- 靶场代码变 → target_code_hash 变 → 自动 bust。
- safe_patterns.py / normalize.py / a2_contract_planner.py / pipeline/a2/service.py 等变
  → config_hash 变 → 自动 bust。a2_llm_client 不缓存（无状态 HTTP 客户端，命中后置 None）。
- STAGE_CACHE_VERSION 变更 → 全部 bust（schema 不兼容时手动 bump）。
"""
from __future__ import annotations

import hashlib
import logging
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# schema 兼容版本：a1/a2 产物结构变化（ScanResult/Vulnerability 字段增删）时手动 +1 全量 bust。
STAGE_CACHE_VERSION = "1"

# 影响 A1/A2 产物、但不在靶场代码里的源文件（相对项目根）。任一变化 → config_hash 变 → bust。
_CONFIG_SOURCES = (
    "src/core/safe_patterns.py",
    "src/core/normalize.py",
    "src/agents/a2_contract_planner.py",
    "src/pipeline/a2/service.py",
    "src/agents/a2_intelligent_agent.py",
    "src/agents/a2_ai_agent.py",
    # 2026-09-27 补入：落盘的是**后处理之后的最终 a2_results**，而 _backfill_code_snippets /
    # _merge_a1_evidence_into_a2_results / _pre_resolve_a2_endpoints / proof_second_pass /
    # plan_pocs 全在 benchmark_cli 里执行 —— 它们直接塑造缓存内容，必须计入哈希。
    # 不纳入的后果：改了后处理仍命中旧缓存（round-17/18 正是靠这个缺口复验命中），长期会读到
    # 陈旧产物。纳入后改 benchmark_cli 即自动 bust；代价是它改动频繁、缓存更常失效，
    # 但正确性优先 —— 缓存只是加速手段，读到错产物比慢更致命。
    "src/cli/benchmark_cli.py",
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _file_path_of(f: Any) -> Optional[str]:
    """扫描文件对象统一取出磁盘路径（string / .path 属性 / dict 三形态）。

    2026-10-03 踩坑：FileScanner.scan() 返回的是 **dict**（path/rel_path/name），
    getattr(dict, "path") 永远返回 None，于是 dict 项被静跳过 → 哈希退化成「空输入哈希」
    → 同工作区里**任意两个不同作用域算出同一个缓存键**。OWASP 分片 16 片全命中 run 53
    的 xpathi 产物（a1 finding_count 一片 159、trigger_specs 全是 /xpathi-00/*）就是这么来的。
    这里必须和 scan_scope._path_of_file 用同一套键表。
    """
    if isinstance(f, str):
        return f
    if isinstance(f, dict):
        for k in ("path", "file_path", "filepath", "rel_path", "name"):
            v = f.get(k)
            if v:
                return str(v)
        return None
    p = getattr(f, "path", None) or getattr(f, "file", None)
    if isinstance(p, str):
        return p
    # ScanResult 里的 file 有时是相对/绝对混合，兜底转字符串
    return str(p) if p is not None else None


def compute_target_code_hash(files: List[Any], scan_root: str = "") -> str:
    """对靶场源码做内容哈希（确定性、与 mtime/复制无关）。

    用内容而非 mtime：_prepare_scan_root 常把源码复制到临时目录，每次 mtime 不同会导致
    缓存永远不命中。内容哈希保证「代码字节不变」→ 同 hash → 命中。
    """
    h = hashlib.sha256()
    norm: List[Tuple[str, bytes]] = []
    read_ok = 0
    for f in files:
        p = _file_path_of(f)
        if not p:
            continue
        try:
            data = Path(p).read_bytes()
            read_ok += 1
        except Exception:
            # 读不到也占一个位：路径已知，只是内容缺失，它本身就是与「空输入」不同的事实
            data = b""
        rel = p
        if scan_root:
            try:
                rel = os.path.relpath(p, scan_root)
            except Exception:
                rel = p
        norm.append((rel, data))
    # fail-closed：给了文件却一个都读不到（典型是路径解析又退化成空哈希），
    # 绝不产出「空输入哈希」——那个哈希与作用域无关，会让同工作区里所有不同作用域
    # 共用同一个缓存键（OWASP 分片串味就是这么发生的）。抛错由调用方降级成「不命中缓存」。
    if files and read_ok == 0:
        raise ValueError(
            f"compute_target_code_hash: 文件清单 {len(files)} 个，可读回内容的却 0 个"
            "（路径解析或读取全部失败），拒绝产出可碰撞的哈希")
    # 排序保证「同集合不同遍历顺序」产生同 hash
    for rel, data in sorted(norm, key=lambda x: x[0]):
        h.update(rel.encode("utf-8", "replace"))
        h.update(data)
    return h.hexdigest()


def _src_tree_fingerprint() -> bytes:
    """对 src/ 下全部 *.py 做确定性内容指纹（2026-10-04 补）。

    为什么不能只靠上面的白名单：`_CONFIG_SOURCES` 是**手工维护**的，任何没被列进去的文件
    改动都不会让缓存失效。2026-10-04 实测：改 `src/core/vuln_hash.py` 的族名归一后提交复跑，
    run 89 的 `a2_poc.duration_seconds` 是 0.0（run 88 是 2769s）——**阶段缓存命中**，
    A1/A2 拿到的仍是旧族名产物，于是「修复后复跑」验的是修复前的代码，结论不可信。

    这类失误比慢更致命：闭环的最后一环（复跑验证）会静默失效。所以这里改成对整个 src/
    做指纹——任何代码改动都自动 bust。开销实测可忽略（294 个文件 / 4.9MB / 约 20ms），
    而一次全量扫描要几小时，正确性优先。
    """
    root = _project_root() / "src"
    items = []
    try:
        for p in root.rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            try:
                data = p.read_bytes()
            except Exception:
                data = b"__READ_ERR__"
            try:
                rel = str(p.relative_to(root)).replace("\\", "/")
            except Exception:
                rel = str(p)
            items.append((rel, hashlib.sha256(data).hexdigest()))
    except Exception:
        return b"__SRC_SCAN_ERR__"
    items.sort()
    h = hashlib.sha256()
    for rel, digest in items:
        h.update(rel.encode("utf-8"))
        h.update(digest.encode("utf-8"))
    return h.digest()


def compute_config_hash() -> str:
    """对影响 A1/A2 产物的源文件做内容哈希。

    两段组成：白名单文件逐一哈希（保留可读的「谁影响产物」语义，且对文件缺失敏感），
    加上整个 src/ 的树指纹（覆盖白名单之外的任何代码改动，见 _src_tree_fingerprint）。
    """
    h = hashlib.sha256()
    root = _project_root()
    for rel in _CONFIG_SOURCES:
        fp = root / rel
        try:
            h.update(fp.read_bytes())
        except Exception:
            # 文件缺失也并入哈希（缺失本身即一种「变化」），避免静默命中陈旧缓存
            h.update(("__MISSING__:" + rel).encode("utf-8"))
    h.update(b"__SRC_TREE__")
    h.update(_src_tree_fingerprint())
    return h.hexdigest()


def compute_stage_cache_key(target_code_hash: str, config_hash: str,
                             model_profile: str, prompt_version: str) -> str:
    h = hashlib.sha256()
    h.update(target_code_hash.encode())
    h.update(config_hash.encode())
    h.update(("mp=" + str(model_profile)).encode())
    h.update(("pv=" + str(prompt_version)).encode())
    h.update(("v=" + STAGE_CACHE_VERSION).encode())
    return h.hexdigest()


def _cache_dir(workspace_id: int) -> Path:
    return _project_root() / "data" / "workspaces" / str(workspace_id) / "cache" / "stages"


def _cache_path(workspace_id: int, key: str) -> Path:
    return _cache_dir(workspace_id) / (key + ".pkl")


def load_latest_stages(workspace_id: int) -> Optional[Tuple[List[Any], List[Any]]]:
    """加载该 workspace 下**最新**的一份 A1/A2 产物（忽略 cache key）。

    用途（2026-10-31）：调试 D 阶段（D1 重放 / D2 裁决）时的加速开关。
    背景：`compute_config_hash` 把整个 src/ 树指纹并进 key（这是对的，防「复跑验的是
    修复前代码」，见 `_src_tree_fingerprint` 注释），代价是**改任何 .py 都会 bust**，
    于是调一条 D2 判据也要等 35 分钟的 A2 重跑。实测本轮因此白等约 70 分钟。

    纪律：**只在确认 A1/A2 代码没变时使用**（调用方用 `SAST_AI_REUSE_STAGES=1` 显式开启，
    并打 warning 日志）。A1/A2 改动不会被本函数检测到 —— 这正是它快的原因，也是它的风险。
    """
    d = _cache_dir(workspace_id)
    if not d.exists():
        return None
    try:
        cands = sorted(d.glob("*.pkl"), key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return None
    for fp in cands[:3]:  # 最近的 3 个里找一个能读的（容忍个别损坏）
        try:
            with fp.open("rb") as fh:
                obj = pickle.load(fh)
            if isinstance(obj, (tuple, list)) and len(obj) >= 2:
                return obj[0], obj[1]
        except Exception:
            continue
    return None


def try_load_stages(workspace_id: int, key: str) -> Optional[Tuple[List[Any], List[Any]]]:
    """命中返回 (a1_results, a2_results)，未命中/损坏/异常返回 None（fail-open）。"""
    fp = _cache_path(workspace_id, key)
    if not fp.exists():
        return None
    try:
        with fp.open("rb") as fh:
            obj = pickle.load(fh)
        if not (isinstance(obj, tuple) and len(obj) == 2):
            logger.warning("[stage_cache] 缓存结构异常（非二元组），丢弃：%s", fp)
            return None
        a1_results, a2_results = obj
        logger.info("[stage_cache] 命中并反序列化成功（ws=%s key=%s）", workspace_id, key[:16])
        return (a1_results, a2_results)
    except Exception as _e:  # noqa: BLE001
        logger.warning("[stage_cache] 反序列化失败，回退全量：%s", _e)
        return None


def save_stages(workspace_id: int, key: str, a1_results: List[Any], a2_results: List[Any]) -> bool:
    """持久化 a1/a2 产物。失败仅告警不抛（不影响本轮扫描）。"""
    fp = _cache_path(workspace_id, key)
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        with fp.open("wb") as fh:
            pickle.dump((a1_results, a2_results), fh, protocol=pickle.HIGHEST_PROTOCOL)
        logger.info("[stage_cache] 已写入（ws=%s key=%s，a1=%d a2=%d）",
                    workspace_id, key[:16], len(a1_results), len(a2_results))
        return True
    except Exception as _e:  # noqa: BLE001
        logger.warning("[stage_cache] 写入失败（不影响本轮）：%s", _e)
        return False


def stage_cache_enabled() -> bool:
    return str(os.environ.get("SAST_AI_STAGE_CACHE", "1")) != "0"
