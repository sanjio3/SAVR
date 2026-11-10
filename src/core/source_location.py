"""源位置判定（Phase 0a）：从 servlet 源码确定性判定 param_location。

背景
----
A2 的 `param_location` 常默认猜 `query`，而 OWASP servlet 的源可能是 header/cookie/body。
实测 run 364 约半数 spec 的 `param_location` 与 servlet 实际取源不符 → D1 把 payload
注到 query，而 servlet 从 header 取 → payload 到不了 sink → 漏报（FN）。

本模块只读源码、确定性判定（剥注释后按真实调用），不看 LLM 猜测：
  request.getHeader("X") / getHeaders("X")      → header
  request.getParameter("X") / getParameterValues("X") / getParameterMap() → query
  request.getCookies() + cookie.getName().equals("X") → cookie
  request.getInputStream() / getReader()          → body
"""
from __future__ import annotations

import os
import re
from typing import Optional

# 合法取值与 D1 `_inject` 支持的注入位置一致（query/header/cookie/path/body）
_VALID = {"query", "header", "cookie", "body", "path"}


def strip_java_comments(code: str) -> str:
    """剥 // 与 /* */ 注释，避免注释里的 getParameter 文字污染判定。"""
    code = re.sub(r"/\*.*?\*/", "", code or "", flags=re.S)
    code = re.sub(r"//[^\n]*", "", code)
    return code


def _case_name_from_path(path: str) -> str:
    base = os.path.basename(str(path or ""))
    return base[:-5] if base.endswith(".java") else base


def detect_source_location(
    path: Optional[str] = None,
    code: Optional[str] = None,
    case_name: Optional[str] = None,
) -> Optional[str]:
    """判定该 servlet 的源位置。优先用文件内**该用例名**对应的真实取源调用。

    返回 'query'/'header'/'cookie'/'body'/'path' 或 None（无法判定）。
    """
    if code is None:
        if not path or not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                code = fh.read()
        except Exception:
            return None
    code = strip_java_comments(code)
    name = case_name or _case_name_from_path(path or "")
    esc = re.escape(name) if name else r'[^"]+'

    # 1) 精确用例名匹配（最强证据）
    if re.search(rf'getHeaders?\s*\(\s*"{esc}"', code):
        return "header"
    if re.search(rf'getParameterValues?\s*\(\s*"{esc}"', code):
        return "query"
    if re.search(rf'getParameter\s*\(\s*"{esc}"', code):
        return "query"
    if re.search(r'getCookies\s*\(', code) and re.search(
            rf'getName\(\)\s*\.equals\(\s*"{esc}"', code):
        return "cookie"

    # 2) body（无参数名，独立特征）
    if re.search(r'getInputStream\s*\(|getReader\s*\(', code):
        return "body"

    # 3) 该 servlet 只有一种源时按唯一特征兜底
    has_h = bool(re.search(r'getHeaders?\s*\(', code))
    has_p = bool(re.search(r'getParameter', code))
    has_c = bool(re.search(r'getCookies\s*\(', code))
    if has_h and not has_p and not has_c:
        return "header"
    if has_c and not has_p and not has_h:
        return "cookie"
    if has_p and not has_h and not has_c:
        return "query"
    # 多源并存且无精确名匹配 → 无法判定（交由调用方保留原值）
    return None


def is_valid_location(loc: Optional[str]) -> bool:
    return str(loc or "").lower() in _VALID


# 名注入（name injection）：部分 servlet 把「参数/头的**名字**」当污点值，而 D1 默认把 canary
# 注在**值**里 → 这类用例永远到不了真 sink（r106 实测 trustbound 4 个真 TP 全为此类，
# 如 BenchmarkTest00251 取首个非标准 header 的 name 存 session）。
# 更隐蔽的是：D1 无条件加的 X-SASTAI-Trace 头本身也是「非标准 header」，会抢走 251 的选中
# 名额 —— 故名注入源必须**跳过主值注入与 trace 头**，只发名注入（2026-10-18 活靶场验证：
# 仅发 `marker: BenchmarkTest00251` 头时 session 正确落 `[userid, <marker小写>]`）。
_NAME_SOURCE_PATTERNS = (
    (re.compile(r'getHeaderNames\s*\(\s*\)'), "header_name"),
    (re.compile(r'getParameterNames\s*\(\s*\)'), "param_name"),
    (re.compile(r'getCookies\s*\(\s*\)[\s\S]{0,400}?getName\s*\(\s*\)\s*\.equals\s*\(\s*(?:"[^"]*"|\w+)\s*\)'), "cookie_name"),
)


def detect_name_source(
    path: Optional[str] = None,
    code: Optional[str] = None,
) -> Optional[str]:
    """判定该 servlet 是否把「参数/头的名字」当作污点值。

    返回 'header_name' / 'param_name' / 'cookie_name' / None。
    只认三种高置信源码形态（剥注释后匹配），避免把普通读值 servlet 误判成名注入源。
    """
    if code is None:
        if not path or not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                code = fh.read()
        except Exception:
            return None
    code = strip_java_comments(code)
    for pat, kind in _NAME_SOURCE_PATTERNS:
        if pat.search(code):
            return kind
    return None
