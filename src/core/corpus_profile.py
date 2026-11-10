"""语料 / 技术栈画像层：把「随语料变化的词汇表」挪出裁决核心。

## 为什么需要这一层（r60 之后的代码卫生整改）

r60 的裁决核心 `safe_verdict` 里躺着两条**只对某一个语料成立**的规则：

    safe_getter_source     need_all = (r"\\.getTheValue\\s*\\(",)      ← 某个基准的 helper 名
    bench_safe_list_index  need_all = (r"\\.add\\s*\\(\\s*\"(?:also|more)?safe\"", ...)  ← 规则名里直接写 bench

它们的生效前提是「被测代码里有一个叫 getTheValue 的类、且它 return 一个常量」。
换成任何别的项目，这两条**必然零命中**，等于死代码；更糟的是它们让核心裁决看起来
像在做事，掩盖了「真正通用的判据根本没写」这件事（实测：换掉它们之后精确率反而
从 58.59% 涨到 62.62%，召回零损失）。

所以这一层不是给规则搬家，而是把「**随语料变化的那部分知识**」显式外置：

    1. 哪些 API 读外部输入（Servlet / Spring / JAX-RS / Struts / JDK 各不相同）
    2. 哪些族的成立需要「攻击者可控输入」（注入类）vs 只看 API 选择（算法类）

第 2 条尤其关键，它是 r60 那次「通用化反而掉 44 个 TP」的根因：
把「值不可控所以安全」用在 weak_hash 上是错的 —— 用 MD5 哈希一个常量仍然是漏洞。
**族是否需要外部输入，是漏洞语义模型的一部分，不是某个语料的特性。**

## 用法

    from src.core.corpus_profile import active_profile
    p = active_profile()
    p.is_input_driven("sql_injection")      # True
    p.is_input_driven("weak_hash")          # False
    p.external_input_re().search(src)       # 是否有读外部输入的 API

切换画像：`SAST_AI_STACK_PROFILE=spring` 或放 `config/stack_profiles/<name>.yaml`。
缺省 `default` 画像只含**跨框架通用**的词汇，不含任何特定靶场/基准的东西。
"""
from __future__ import annotations

import logging
import os
import re
from typing import Dict, Iterable, Optional, Tuple

logger = logging.getLogger("corpus_profile")

# ── 缺省画像：外部输入 API（只认跨框架通用的入口，绝不写具体类名）──────────
# 判据：调用这些方法拿到的值，攻击者可能控制。
_DEFAULT_EXTERNAL_INPUT: Tuple[str, ...] = (
    # Servlet / JSP
    r"getParameter\s*\(", r"getParameterValues\s*\(", r"getParameterMap\s*\(",
    r"getParameterNames\s*\(", r"getHeader\w*\s*\(", r"getCookies\s*\(",
    r"getQueryString\s*\(", r"getRequestURI\s*\(", r"getRequestURL\s*\(",
    r"getPathInfo\s*\(", r"getServletPath\s*\(", r"getInputStream\s*\(",
    r"getReader\s*\(", r"getAttribute\s*\(", r"getParts?\s*\(",
    # Spring
    r"getRequestParams?\s*\(", r"PathVariable", r"RequestParam", r"ModelAttribute",
    r"RequestHeader", r"CookieValue", r"RequestPart", r"RequestBody",
    # 通用 IO / 环境
    r"readLine\s*\(", r"new\s+Scanner\s*\(", r"System\.getProperty\s*\(",
    r"System\.getenv\s*\(", r"args\s*\[\s*\d*\s*\]", r"getProperty\s*\(",
)

# ── 输入驱动族：漏洞成立需要「攻击者可控数据到达 sink」──────────────────
# 反例（必须排除）：weak_hash / weak_crypto / weak_random / secure_cookie ——
# 这类漏洞只看「用了什么 API / 算法」，输入是不是常量无所谓。
# r60 实测：不加这个区分，通用判据会误杀 44 个 TP（TPR 降 3.11pp，超门限）。
_INPUT_DRIVEN: Tuple[str, ...] = (
    "sql_injection", "sqli", "xss", "path_traversal", "command_execution", "cmdi",
    "code_injection", "ldap_injection", "ldapi", "xpathi", "xpath_injection",
    "ssrf", "xxe", "ssti", "template_injection", "template-injection",
    "log_injection", "open_redirect", "file_upload", "deserialization",
    "http_response_splitting", "crlf", "csrf", "redirect",
)

# ── API 选择族：漏洞成立与输入取值无关（显式登记，缺省哨兵用）────────────
_API_CHOICE: Tuple[str, ...] = (
    "weak_hash", "weak_crypto", "weak_random", "secure_cookie",
    "weak_password_storage", "weak_password", "sensitive_data_leak",
    "sensitive_data_exposure", "cookie", "hardcoded_credential",
)

_PROFILE_DIR_CANDIDATES = ("config/stack_profiles", "config/corpus_profiles")


def _norm(fam: str) -> str:
    return (fam or "").strip().lower().replace("-", "_").replace(" ", "_")


class StackProfile:
    """一份语料 / 技术栈画像。"""

    def __init__(self, name: str, external_input: Iterable[str] = (),
                 input_driven: Iterable[str] = (), api_choice: Iterable[str] = ()) -> None:
        self.name = name
        self.external_input: Tuple[str, ...] = tuple(external_input) or _DEFAULT_EXTERNAL_INPUT
        self.input_driven = frozenset(_norm(f) for f in input_driven) | frozenset(
            _norm(f) for f in _INPUT_DRIVEN)
        self.api_choice = frozenset(_norm(f) for f in api_choice) | frozenset(
            _norm(f) for f in _API_CHOICE)
        self._re: Optional[re.Pattern] = None

    # ── 外部输入 API ──
    def external_input_re(self) -> re.Pattern:
        if self._re is None:
            try:
                self._re = re.compile("|".join(self.external_input), re.IGNORECASE)
            except re.error:  # pragma: no cover
                self._re = re.compile("|".join(_DEFAULT_EXTERNAL_INPUT), re.IGNORECASE)
        return self._re

    def has_external_input(self, text: str) -> bool:
        return bool(text) and bool(self.external_input_re().search(text))

    # ── 族语义分类 ──
    def is_input_driven(self, family: str) -> bool:
        """该族的成立是否需要「攻击者可控输入到达 sink」。

        未知族一律 **False**（保守）：不认识的族不允许用「值不可控」来抑制，
        宁可少抑制也不误杀 —— 与 safe_verdict 的 fail-open 一致。
        """
        f = _norm(family)
        if f in self.api_choice:
            return False
        return f in self.input_driven

    def is_api_choice(self, family: str) -> bool:
        return _norm(family) in self.api_choice


def _profile_dir() -> Optional[str]:
    for rel in _PROFILE_DIR_CANDIDATES:
        if os.path.isdir(rel):
            return rel
    return None


def load_profile(name: str) -> StackProfile:
    """按名字加载画像：缺省画像 + 同名 YAML 覆盖（不存在就用缺省）。

    YAML 只支持三个键：external_input / input_driven / api_choice，都是列表，
    与缺省值**取并集**——画像只能加宽，不能收窄缺省的保守判据，避免配置把安全
    判据关掉。
    """
    base = StackProfile(name or "default")
    d = _profile_dir()
    if not d or not name or name == "default":
        return base
    for ext in (".yaml", ".yml", ".json"):
        path = os.path.join(d, name + ext)
        if not os.path.isfile(path):
            continue
        try:
            if ext == ".json":
                import json
                blob = json.loads(open(path, "r", encoding="utf-8").read())
            else:
                import yaml
                blob = yaml.safe_load(open(path, "r", encoding="utf-8").read()) or {}
        except Exception as exc:  # pragma: no cover
            logger.warning("[corpus-profile] 画像 %s 读取失败，回落缺省：%s", path, exc)
            return base
        if not isinstance(blob, dict):
            return base
        return StackProfile(
            name,
            tuple(base.external_input) + tuple(blob.get("external_input") or ()),
            tuple(blob.get("input_driven") or ()),
            tuple(blob.get("api_choice") or ()),
        )
    return base


_CACHE: Dict[str, StackProfile] = {}


def active_profile(name: Optional[str] = None) -> StackProfile:
    """当前生效画像。显式传 name 优先，否则读 SAST_AI_STACK_PROFILE，缺省 default。"""
    key = name or os.environ.get("SAST_AI_STACK_PROFILE", "") or "default"
    p = _CACHE.get(key)
    if p is None:
        p = load_profile(key)
        if len(_CACHE) > 32:  # pragma: no cover
            _CACHE.clear()
        _CACHE[key] = p
    return p
