"""POC 记忆库（RAG 升级的检索侧基础）。

设计目标（用户指令「攻击计划 RAG+LLM 全量升级」步骤一）：
- 把**已验证正样本**（exploit_spec → attack_plan → 实际投放的 POC → IAST 观测结论）沉淀成可检索库，
  供后续同族/同框架/同 sink 形态的漏洞在生成攻击计划时做 few-shot 检索。
- 键 = (family, framework, sink_signature)。sink_signature 由 exploit_spec 的 sink 类型/方法归一得到。
- 跨轮缓存：落盘 JSON 文件（默认 data/poc_memory.json），进程重启后仍在；永久缓存键复用，
  避免重复向 LLM 索取已掌握的样本。
- 任何异常降级为空（RAG 是增强项，绝不阻断主链路）。

仅读取/写入本地文件，不触碰 app.db，不修改任何运行数据。
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_PATH = os.environ.get("SAST_AI_POC_MEMORY_PATH") or "data/poc_memory.json"

# 同族 sink 归一表：把零散的 sink 方法名收口到规范签名，提升检索命中。
_SINK_NORMALIZE = {
    "sql": "sql-exec",
    "jdbc": "sql-exec",
    "statement": "sql-exec",
    "executequery": "sql-exec",
    "command": "command-exec",
    "runtime": "command-exec",
    "processbuilder": "command-exec",
    "exec": "command-exec",
    "xss": "xss-reflect",
    "getwriter": "xss-reflect",
    "expression": "expression-eval",
    "spel": "expression-eval",
    "ognl": "expression-eval",
    "template": "template-eval",
    "freemarker": "template-eval",
    "velocity": "template-eval",
    "path": "path-traversal",
    "file": "path-traversal",
    "xxe": "xxe-parse",
    "xml": "xxe-parse",
    "deserialization": "deserialization-readobject",
    "readobject": "deserialization-readobject",
    "ssrf": "ssrf-url",
    "url": "ssrf-url",
    "ldap": "ldap-lookup",
}


def normalize_sink_signature(family: str, sink_type: str = "", sink_method: str = "") -> str:
    """把 (family, sink_type, sink_method) 归一为稳定的 sink_signature 字符串。

    用于记忆库键的第三维；归一失败回退到 family 本身，绝不抛。
    """
    tokens = " ".join([str(sink_type or ""), str(sink_method or "")]).lower()
    for needle, sig in _SINK_NORMALIZE.items():
        if needle in tokens:
            return sig
    if family:
        return f"{family}-generic"
    return "unknown"


def _key(family: str, framework: str, sink_signature: str) -> str:
    return f"{family}|{framework or 'any'}|{sink_signature or 'any'}"


class PocMemoryStore:
    """线程安全的 POC 记忆库（JSON 落盘 + 内存缓存）。

    用法：
        store = PocMemoryStore                      # 默认 data/poc_memory.json
        store.record(sample)                          # 写入/更新一条正样本
        few = store.retrieve(family, framework, sig)   # 检索 top-k
    """

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or _DEFAULT_PATH)
        self._lock = threading.RLock()
        self._data: Dict[str, List[Dict[str, Any]]] = {}
        self._loaded = False

    # ---- 持久化 ----
    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._data = self._load_from_disk()
            self._loaded = True

    def _load_from_disk(self) -> Dict[str, List[Dict[str, Any]]]:
        try:
            if not self.path.exists():
                return {}
            raw = self.path.read_text(encoding="utf-8", errors="ignore")
            if not raw.strip():
                return {}
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception as _e:  # 任何读取异常都不应阻断主链路
            logger.debug("[poc_memory] 读取失败（降级为空）：%s", _e)
        return {}

    def _save_to_disk(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        except Exception as _e:  # 写入失败仅告警，内存态仍可用
            logger.warning("[poc_memory] 落盘失败（内存态保留）：%s", _e)

    # ---- 写入 ----
    def record(self, sample: Dict[str, Any]) -> None:
        """写入/更新一条样本。sample 需含 family/framework/sink_signature；缺少则尽力补全。

        同 key 内按 (canary_form, attack_shape) 去重：已存在则合并（hit_count++、刷新 observation）。
        只持久化 verified=True 的样本（记忆库只收正样本，避免污染 few-shot）。
        """
        try:
            family = str(sample.get("family") or "").lower()
            framework = str(sample.get("framework") or "").lower()
            sig = str(sample.get("sink_signature") or normalize_sink_signature(
                family, str(sample.get("sink_type") or ""), str(sample.get("sink_method") or "")))
            if not family:
                return
            if not sample.get("verified"):
                # 记忆库只收已验证正样本；未验证的不写入。
                return
            key = _key(family, framework, sig)
            canary_form = str(sample.get("canary_form") or "plain")
            shape = str(sample.get("attack_shape") or "unknown")
            with self._lock:
                self._ensure_loaded()
                bucket = self._data.setdefault(key, [])
                for existing in bucket:
                    if existing.get("canary_form") == canary_form and existing.get("attack_shape") == shape:
                        existing["hit_count"] = int(existing.get("hit_count", 0) or 0) + 1
                        existing["last_seen"] = time.time()
                        existing["observation"] = sample.get("observation", existing.get("observation"))
                        existing["attack_plan"] = sample.get("attack_plan", existing.get("attack_plan"))
                        self._save_to_disk()
                        return
                bucket.append({
                    "family": family,
                    "framework": framework,
                    "sink_signature": sig,
                    "canary_form": canary_form,
                    "attack_shape": shape,
                    "attack_plan": sample.get("attack_plan"),
                    "exploit_spec_summary": sample.get("exploit_spec_summary"),
                    "observation": sample.get("observation"),
                    "verified": True,
                    "hit_count": 1,
                    "created_at": time.time(),
                    "last_seen": time.time(),
                })
                self._save_to_disk()
        except Exception as _e:
            logger.debug("[poc_memory] record 失败（忽略）：%s", _e)

    # ---- 检索 ----
    def retrieve(self, family: str, framework: str = "", sink_signature: str = "", top_k: int = 3) -> List[Dict[str, Any]]:
        """检索最相关 top-k 样本。

        相关性排序：先精确 (family,framework,sink) → 再 (family,framework) → 再 (family,*)，
        桶内按 hit_count 降序。返回的是样本 dict 列表（不含内部元数据噪声）。
        """
        try:
            family = str(family or "").lower()
            framework = str(framework or "").lower()
            sig = str(sink_signature or "").lower()
            if not family:
                return []
            with self._lock:
                self._ensure_loaded()
                exact = self._data.get(_key(family, framework, sig), [])
                fam_fw = self._data.get(_key(family, framework, "any"), [])
                fam_any = self._data.get(_key(family, "any", "any"), [])
                # 合并去重（同 attack_shape 优先 exact，其次 fam_fw）
                seen_shapes = set()
                ordered: List[Dict[str, Any]] = []
                for bucket in (exact, fam_fw, fam_any):
                    for item in sorted(bucket, key=lambda x: -int(x.get("hit_count", 0) or 0)):
                        shape_key = (item.get("framework"), item.get("sink_signature"), item.get("attack_shape"))
                        if shape_key in seen_shapes:
                            continue
                        seen_shapes.add(shape_key)
                        ordered.append(item)
                return ordered[:max(0, top_k)]
        except Exception as _e:
            logger.debug("[poc_memory] retrieve 失败（降级为空）：%s", _e)
            return []

    def size(self) -> int:
        with self._lock:
            self._ensure_loaded()
            return sum(len(v) for v in self._data.values())


# 模块级单例（跨调用复用内存态 + 跨轮落盘），供 D2 链路直接 import 使用。
_default_store: Optional[PocMemoryStore] = None


def default_store() -> PocMemoryStore:
    global _default_store
    if _default_store is None:
        _default_store = PocMemoryStore()
    return _default_store


def retrieve_few_shot(family: str, framework: str = "", sink_signature: str = "", top_k: int = 3) -> List[Dict[str, Any]]:
    return default_store().retrieve(family, framework, sink_signature, top_k)


def record_verified_sample(sample: Dict[str, Any]) -> None:
    default_store().record(sample)
