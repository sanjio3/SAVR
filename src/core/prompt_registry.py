"""提示词版本化注册表。

把散落在 ``src/prompts/`` 的提示词模板收敛成一个带 **版本 / hash / golden_ref /
changelog** 的清单，并提供「族名 → 语言 → default」的分级回退选择。

模板内容的 sha256 即 ``prompt_hash``，用途有二：
  1. 作为 LLM 响应缓存的 ``cache_salt``——改提示词文本自动失效旧缓存，无需手工清；
  2. 写入 ``model_runs.prompt_hash`` 做按提示词版本归因（配合 1.2 P1-7 的埋点列）。

模型无关性：本模块完全不感知具体模型，只管「哪个版本的提示词、内容指纹是什么」，
因此无论云端大模型还是本地小模型，都走同一套版本/缓存口径，换模型不换提示词治理。

fail-open：注册表或某个文件缺失时回退到「直接读 yaml」，保证现有流程不受影响。
"""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

_PROMPTS_DIR = Path(__file__).resolve().parents[1] / "prompts"
_REGISTRY_PATH = _PROMPTS_DIR / "registry.yaml"


def compute_prompt_hash(name: str, version: str, text: str) -> str:
    """模板指纹：name + version + 内容 的 sha256 前 16 位。

    内容一改，hash 必变 → 缓存 salt 变化 → 旧缓存自动失效。
    """
    h = hashlib.sha256()
    h.update(f"{name}|{version}|".encode("utf-8"))
    h.update((text or "").encode("utf-8"))
    return h.hexdigest()[:16]


class PromptEntry:
    """单条（name, version）提示词记录。"""

    __slots__ = ("name", "version", "file", "key", "text", "golden_ref", "changelog", "hash")

    def __init__(self, name: str, version: str, file: str, key: str, text: str,
                 golden_ref: str = "", changelog: str = ""):
        self.name = name
        self.version = version
        self.file = file
        self.key = key
        self.text = text
        self.golden_ref = golden_ref
        self.changelog = changelog
        self.hash = compute_prompt_hash(name, version, text)

    def to_meta(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "hash": self.hash,
            "golden_ref": self.golden_ref,
            "changelog": self.changelog,
        }


class PromptRegistry:
    """提示词清单：name -> {version -> PromptEntry}，支持分级回退。"""

    def __init__(self, registry_path: Path = _REGISTRY_PATH):
        self._registry_path = Path(registry_path)
        self._entries: Dict[str, Dict[str, PromptEntry]] = {}
        self._default_version: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._load()

    # ---- 加载 ----
    def _load(self) -> None:
        spec: Dict = {}
        if self._registry_path.exists():
            try:
                spec = yaml.safe_load(self._registry_path.read_text(encoding="utf-8")) or {}
            except Exception:
                spec = {}
        prompts_spec = spec.get("prompts", {}) or {}
        for name, entry in prompts_spec.items():
            if not isinstance(entry, dict):
                continue
            versions = entry.get("versions") or []
            if isinstance(versions, dict):
                versions = [versions]  # 单版本也可写成 dict
            default_ver = str(entry.get("default") or (versions[0].get("version") if versions else ""))
            for v in versions:
                if not isinstance(v, dict):
                    continue
                ver = str(v.get("version") or "")
                if not ver:
                    continue
                text = self._read_template(str(v.get("file") or entry.get("file") or ""),
                                          str(v.get("key") or entry.get("key") or name))
                pe = PromptEntry(
                    name=name, version=ver, file=str(v.get("file") or entry.get("file") or ""),
                    key=str(v.get("key") or entry.get("key") or name), text=text,
                    golden_ref=str(v.get("golden_ref") or ""),
                    changelog=str(v.get("changelog") or ""),
                )
                self._entries.setdefault(name, {})[ver] = pe
                if ver == default_ver:
                    self._default_version[name] = ver
            if name not in self._default_version and self._entries.get(name):
                # 没显式 default 时用最新（字典序最大）版本兜底
                self._default_version[name] = sorted(self._entries[name].keys())[-1]

    @staticmethod
    def _read_template(file_name: str, key: str) -> str:
        if not file_name:
            return ""
        p = _PROMPTS_DIR / file_name
        if not p.exists():
            return ""
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            return ""
        prompts = data.get("prompts", {}) or {}
        return str(prompts.get(key) or "")

    # ---- 查询 ----
    def get(self, name: str, version: Optional[str] = None,
            family: Optional[str] = None, language: Optional[str] = None) -> Optional[PromptEntry]:
        """分级回退选择：

        优先级：name@family@language → name@family → name@version(显式) → name@default。
        这样族专属模板（如 sql_injection）真正可被选中，而不是永远走 default。
        """
        with self._lock:
            by_ver = self._entries.get(name, {})
            if not by_ver:
                return None
            # 1) 族 + 语言专属版本（约定 key：f"{name}@{family}@{language}" 作为 version 后缀）
            if family:
                fam_ver = f"{family}"
                if language:
                    fam_ver_lang = f"{family}@{language}"
                    for cand in (fam_ver_lang, fam_ver):
                        # 在 versions 里找以该后缀结尾的版本
                        hit = self._match_suffix(by_ver, cand)
                        if hit:
                            return hit
            # 2) 显式版本
            if version and version in by_ver:
                return by_ver[version]
            # 3) default
            dv = self._default_version.get(name)
            if dv and dv in by_ver:
                return by_ver[dv]
            # 4) 任意最新
            return by_ver[sorted(by_ver.keys())[-1]]

    @staticmethod
    def _match_suffix(by_ver: Dict[str, PromptEntry], suffix: str) -> Optional[PromptEntry]:
        # 版本名形如 "v1-sql" / "v1-sql-java"；后缀匹配最后一个 '-' 段
        for ver, pe in by_ver.items():
            if ver == suffix or ver.endswith("-" + suffix) or ver.endswith("@" + suffix):
                return pe
        return None

    def available_versions(self, name: str) -> List[str]:
        with self._lock:
            return sorted(self._entries.get(name, {}).keys())

    def names(self) -> List[str]:
        """全部已登记模板名（用于按名逐条做版本感知的选择）。"""
        with self._lock:
            return list(self._entries.keys())

    def default_version(self, name: str) -> str:
        with self._lock:
            return self._default_version.get(name, "")

    def all(self) -> List[PromptEntry]:
        out: List[PromptEntry] = []
        with self._lock:
            for by_ver in self._entries.values():
                out.extend(by_ver.values())
        return out


_REGISTRY: Optional[PromptRegistry] = None
_REG_LOCK = threading.Lock()


def get_registry() -> PromptRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        with _REG_LOCK:
            if _REGISTRY is None:
                _REGISTRY = PromptRegistry()
    return _REGISTRY


def get_prompt_template(name: str, version: Optional[str] = None,
                        family: Optional[str] = None,
                        language: Optional[str] = None) -> Tuple[str, Dict[str, str]]:
    """便捷函数：返回 (模板文本, 元数据)。未命中返回 ("", {})。"""
    pe = get_registry().get(name, version=version, family=family, language=language)
    if pe is None:
        return "", {}
    return pe.text, pe.to_meta()


def load_prompts_dict(version: Optional[str] = None) -> Dict[str, str]:
    """把注册表所有模板摊平为 {key: text}，兼容现有 ``self.prompts.get(key)`` 访问方式。

    同时把 {key}.hash / {key}.version 也一并返回，供调用方做缓存 salt 与版本归因。
    未命中注册表的 key（旧代码直接读 yaml 的情况）这里不会包含，但不影响——旧路径仍可用。

    ``all`` 里每个版本的正文都写进 ``out[pe.name]``，同名多版本会互相覆盖，且调用方
    （A2）从不传版本 → ``prompt_version`` 只进 metadata、从不真正驱动模板选择。
    现在改为**逐名调用 ``registry.get(name, version=...)``**：命中指定版本用该版本正文，
    未命中按 default → 最新版本回退（分级回退语义与 ``PromptRegistry.get`` 一致）。
    ``version=None`` 时退化为「取每个名的 default」，与旧行为在单版本场景下等价。
    """
    out: Dict[str, str] = {}
    reg = get_registry()
    for name in reg.names():
        pe = reg.get(name, version=version)
        if pe is None:
            continue
        out[pe.name] = pe.text
        out[f"{pe.name}.hash"] = pe.hash
        out[f"{pe.name}.version"] = pe.version
    return out
