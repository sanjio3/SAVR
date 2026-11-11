"""LLM 输出契约层（ Output Contract ）。

解决问题：`src/agents/a2_ai_agent.py` 原有的 `_parse_response` 在输出被 max_tokens 截断时，
括号永远配不平 → `json.loads` 抛错 → 一行 `logger.error` 后 `return []`。
结果是「模型明明扫出了漏洞，平台拿到 0 条」，且没有任何可观测信号——前端只显示扫完了没检出。

本地小模型（qwen3:8b、num_ctx 有限、输出预算紧）下这个坑会被放大到常态。
本模块把「从 LLM 文本里拿到结构化数据」变成一条明确的多级降级链：

    直接解析 → 围栏/裸片段定位 → 未转义引号修复 → 字符串感知配平 → 截断修复 → 数组元素抢救 → 失败并留证

每一级都记录 strategy 与原因，调用方拿到的是 `(data, diagnostics)`，
**不存在「返回空但不知道为什么空」这种情况**。

另外一个隐藏 bug 一并修掉：原实现的括号配平不感知字符串，
遇到 `{"snippet": "if (x) {"}` 这种代码里有大括号的 JSON，
会把字符串里的 `{` 当成结构的一部分，直接配平失败。
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 触发「输出被截断」判定的 finish_reason。各家叫法不同，一并认。
TRUNCATION_REASONS = {"length", "max_tokens", "model_length", "max_completion_tokens"}

_OPENERS = "{["
_CLOSERS = "}]"
# 判定「引号是字符串收尾」的后续结构符（见 _escape_inner_quotes）
_STRUCT_FOLLOWERS = (",", "}", "]", ":")


@dataclass
class ParseDiagnostics:
    """一次解析发生了什么。用于埋点、排障与 A/B，不参与业务判定。"""

    ok: bool = False
    strategy: str = ""  # direct | fenced | quote-escape | balanced | repaired | array-salvage | empty | failed
    finish_reason: str = ""
    truncated: bool = False
    repaired: bool = False
    salvaged_items: int = 0
    error: str = ""
    span_found: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "strategy": self.strategy,
            "finish_reason": self.finish_reason,
            "truncated": self.truncated,
            "repaired": self.repaired,
            "salvaged_items": self.salvaged_items,
            "error": self.error[:300] if self.error else "",
            "span_found": self.span_found,
        }


def is_truncated(finish_reason: str = "", text: str = "") -> bool:
    """判定输出是否被截断：优先看 finish_reason，其次做形态兜底。"""
    reason = (finish_reason or "").strip().lower()
    if reason in TRUNCATION_REASONS:
        return True
    stripped = (text or "").rstrip()
    if not stripped:
        return False
    # 形态兜底：没有收尾符号但明显是半截 JSON（用于 provider 不给 finish_reason 的情况）
    if stripped[-1] not in ("}", "]", '"') and ("{" in stripped or "[" in stripped):
        return True
    return False


_CODE_FENCE_RE = re.compile(r"```(?:json|JSON|jsonc)?\s*(.*?)```", re.DOTALL)


def strip_fences(text: str) -> str:
    """剥 ```json ... ``` 围栏并保留其中内容；无围栏时原样返回。"""
    if not text:
        return ""
    stripped = text.strip()
    if "```" not in stripped:
        return stripped
    matches = _CODE_FENCE_RE.findall(stripped)
    if matches:
        # 多个代码块时取最长的一个（模型常先给解释再给 JSON，或反之）
        return max(matches, key=len).strip()
    # 围栏不成对（被截断）；尽量取首个围栏之后的内容
    idx = stripped.find("```")
    tail = stripped[idx + 3:] if idx >= 0 else stripped
    # 去掉紧随其后的语言标记行
    tail = re.sub(r"^\s*(json|JSON|jsonc)?\s*\n", "", tail)
    return tail.strip()


def _strip_json_comments(text: str) -> str:
    """去掉 // 与 /* */ 注释、以及尾随逗号。仅在修复路径使用（模型偶尔会加注释）。"""
    out: List[str] = []
    in_str = False
    esc = False
    idx = 0
    while idx < len(text):
        ch = text[idx]
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            idx += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            idx += 1
            continue
        if ch == "/" and idx + 1 < len(text) and text[idx + 1] == "/":
            while idx < len(text) and text[idx] != "\n":
                idx += 1
            continue
        if ch == "/" and idx + 1 < len(text) and text[idx + 1] == "*":
            idx += 2
            while idx + 1 < len(text) and not (text[idx] == "*" and text[idx + 1] == "/"):
                idx += 1
            idx += 2
            continue
        out.append(ch)
        idx += 1
    cleaned = "".join(out)
    cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    return cleaned


def _escape_inner_quotes(text: str) -> Tuple[str, int]:
    """把「字符串值内部未转义的双引号」补上转义，返回 (修复文本, 转义处数)。

    为什么需要：LLM（尤其小参数本地模型）把源码片段塞进 JSON 字符串时经常不转义内部引号，
    典型如 ``"signature": "String sql = "SELECT ..."``。这类文本严格解析必然失败，且会连带
    把 `_balanced_end` 的字符串感知带偏 —— 实测它会**只框住内层那个恰好合法的子对象**
    于是上层拿到「键看着对、内容全空」的对象，LLM 产出被静默丢弃。

    判定规则：一个引号是不是字符串的收尾引号，看它后面（跳过空白）是否紧跟结构符
    `,` `}` `]` `:`。不是 → 判为字符串内部的裸引号，转义之。该规则只在本函数被调用时
    生效（即严格解析已失败之后），且结果仍要过 json.loads 才算修复成功，故不会污染正常文本。
    """
    out: List[str] = []
    escaped = 0
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if not in_str:
            out.append(ch)
            if ch == '"':
                in_str = True
            i += 1
            continue
        if ch == "\\":
            # 已有转义序列：原样带走下一个字符，避免把 \" 当成收尾引号
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == '"':
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] in _STRUCT_FOLLOWERS:
                out.append(ch)
                in_str = False
            else:
                out.append('\\"')
                escaped += 1
            i += 1
            continue
        out.append(ch)
        i += 1
    return ("".join(out), escaped)


def _balanced_end(text: str, start: int) -> int:
    """字符串感知的括号配平。返回闭合位置下标；不闭合返回 -1。"""
    stack: List[str] = []
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in _OPENERS:
            stack.append(ch)
        elif ch in _CLOSERS:
            if not stack:
                return -1
            opener = stack.pop()
            if _CLOSERS.index(ch) != _OPENERS.index(opener):
                return -1
            if not stack:
                return i
    return -1


def find_json_span(text: str) -> Tuple[int, int]:
    """定位首个结构完整的 JSON 片段，返回 (start, end)；找不到返回 (-1, -1)。"""
    if not text:
        return (-1, -1)
    for idx, ch in enumerate(text):
        if ch in _OPENERS:
            end = _balanced_end(text, idx)
            if end != -1:
                return (idx, end)
    return (-1, -1)


def repair_truncated_json(text: str) -> str:
    """把半截 JSON 补成可能可解析的形态。

    处理三件事：截断在字符串内部（补引号）、未闭合的括号（依次补尾符）、尾随逗号。
    这是「尽力而为」的修复，解析成功与否由调用方判断。
    """
    if not text:
        return ""
    body = _strip_json_comments(text)
    # 去掉最后一个不完整的 token 之后的内容不好判断，直接在末尾补齐结构
    stack: List[str] = []
    in_str = False
    esc = False
    for ch in body:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in _OPENERS:
            stack.append(ch)
        elif ch in _CLOSERS:
            if stack:
                stack.pop()
    out = body
    if in_str:
        # 字符串没闭合：砍掉最后一个不完整的字符串片段再收尾
        cut = out.rfind('"')
        out = out[:cut] if cut > 0 else out
        out = out.rstrip().rstrip(",")
    for opener in reversed(stack):
        out += "}" if opener == "{" else "]"
    out = re.sub(r",(\s*[}\]])", r"\1", out)
    return out


def salvage_array_elements(text: str) -> List[Any]:
    """抢救被截断的 JSON 数组里「已经完整」的元素。

    典型场景：模型逐个吐 finding 的数组 `{"findings":[{...},{...},{...` 在中间被截断。
    原实现会整段丢弃（0 条），这里把截断前已闭合的元素逐个解析出来照常返回——
    对小模型而言这一条直接决定了「扫出 8 条」还是「扫出 0 条」。
    """
    start = text.find("[")
    if start == -1:
        return []
    items: List[Any] = []
    idx = start + 1
    n = len(text)
    while idx < n:
        # 跳到下一个元素起点
        while idx < n and text[idx] in ", \n\r\t":
            idx += 1
        if idx >= n or text[idx] == "]":
            break
        if text[idx] in "{[":
            end = _balanced_end(text, idx)
            if end == -1:
                break  # 这个元素本身是半截的，后面也不用看了
            chunk = text[idx:end + 1]
            try:
                items.append(json.loads(chunk))
            except ValueError:
                try:
                    items.append(json.loads(_strip_json_comments(chunk)))
                except ValueError:
                    pass
            idx = end + 1
        else:
            # 标量元素（数字/字符串/true/false）：读到逗号或右括号
            close = idx
            while close < n and text[close] not in ",]":
                close += 1
            chunk = text[idx:close].strip()
            if chunk:
                try:
                    items.append(json.loads(chunk))
                except ValueError:
                    pass
            idx = close
    return items


def parse_llm_json(
    text: str,
    *,
    finish_reason: str = "",
    expect: str = "auto",  # auto | object | array
    allow_salvage: bool = True,
) -> Tuple[Any, ParseDiagnostics]:
    """把 LLM 输出解析成 Python 对象，永不静默返回空。

    返回 `(data, diagnostics)`：
    - 成功时 data 为 dict / list，diag.ok=True 且 diag.strategy 说明走了哪条路；
    - 失败时 data 为 None（**不是 []**，避免与「模型判定无问题」混淆），diag.ok=False 带原因。
    """
    diag = ParseDiagnostics(finish_reason=finish_reason or "")
    diag.truncated = is_truncated(finish_reason, text)

    raw = (text or "").strip()
    if not raw:
        diag.strategy = "empty"
        diag.error = "empty output"
        return (None, diag)

    # 1) 直接整体解析
    try:
        data = json.loads(raw)
        diag.ok = True
        diag.strategy = "direct"
        diag.error = ""
        return (data, diag)
    except ValueError as exc:
        diag.error = str(exc)

    # 2) 剥围栏后再试
    fenced = strip_fences(raw)
    if fenced and fenced != raw:
        try:
            data = json.loads(fenced)
            diag.ok = True
            diag.strategy = "fenced"
            diag.error = ""
            return (data, diag)
        except ValueError:
            pass
        base = fenced
    else:
        base = raw

    #      必须在「定位 JSON 片段」之前做：裸引号会把 _balanced_end 的字符串感知带偏，
    #      使 find_json_span 只框住内层恰好合法的子对象 → 上层拿到空壳却判成功（静默丢数据）。
    esc_base, n_escaped = _escape_inner_quotes(base)
    if n_escaped:
        try:
            data = json.loads(esc_base)
            diag.ok = True
            diag.strategy = "quote-escape"
            diag.repaired = True
            diag.error = ""
            return (data, diag)
        except ValueError as exc:
            diag.error = str(exc)
        base = esc_base

    # 3) 定位首个完整 JSON 片段（字符串感知）
    start, end = find_json_span(base)
    if start != -1:
        diag.span_found = True
        chunk = base[start:end + 1]
        try:
            data = json.loads(chunk)
            diag.ok = True
            diag.strategy = "balanced"
            diag.error = ""
            return (data, diag)
        except ValueError:
            try:
                data = json.loads(_strip_json_comments(chunk))
                diag.ok = True
                diag.strategy = "balanced"
                diag.repaired = True
                diag.error = ""
                return (data, diag)
            except ValueError as exc:
                diag.error = str(exc)

    # 4) 截断修复
    repaired_text = repair_truncated_json(base[start:] if start != -1 else base)
    if repaired_text:
        try:
            data = json.loads(repaired_text)
            diag.ok = True
            diag.strategy = "repaired"
            diag.repaired = True
            diag.error = ""
            return (data, diag)
        except ValueError as exc:
            diag.error = str(exc)

    # 5) 数组元素抢救：数组半截时，把已完整的元素捞回来
    if allow_salvage:
        items = salvage_array_elements(base)
        if items:
            diag.ok = True
            diag.strategy = "array-salvage"
            diag.repaired = True
            diag.salvaged_items = len(items)
            diag.error = ""
            return (items, diag)

    if not diag.strategy:
        diag.strategy = "failed"
    return (None, diag)


def parse_llm_list(text: str, *, finish_reason: str = "") -> Tuple[List[Any], ParseDiagnostics]:
    """按「期望拿到列表」的语义解析，把各种外层形态归一成 list。

    模型常见外层形态有：`[...]`、`{"findings":[...]}`、`{"vulnerabilities":[...]}`、
    `{"result":{...}}`。全部归一成 list 返回，失败返回空 list 并把原因留在 diag 里。
    """
    data, diag = parse_llm_json(text, finish_reason=finish_reason)
    if data is None:
        return ([], diag)
    if isinstance(data, list):
        return (data, diag)
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "items", "data", "issues", "list"):
            value = data.get(key)
            if isinstance(value, list):
                return (value, diag)
            if isinstance(value, dict):
                return ([value], diag)
        # 单对象也当作一条结果，避免丢件
        return ([data], diag)
    return ([], diag)
