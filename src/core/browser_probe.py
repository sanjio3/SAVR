"""M13「DAST 的浏览器扩展」：按需起 headless 浏览器取证，用完释放，非常驻（2026-10-03）。

先厘清它**不是**什么，避免做错方向：
    - 不是「在浏览器里常驻插一个 IAST agent 探针」。浏览器端 agent 要改三方页面、
      要注入脚本到任意站，落地与合规成本都不现实。
    - 不是把浏览器接成常驻服务。扫描任务有几十上百条 spec，若给每条都留一个常驻
      浏览器进程，机器直接被拖垮（本机还有 Commit 上限 40.6G 的硬闸）。
    - 它是**取证动作**：只有确实需要「浏览器到底渲染成什么样」才能下结论的族
      （DOM XSS、前端渲染型反射 XSS、需要 JS 执行才能看到的求值结果），才在
      **这一次调用内**起一个 headless 浏览器打开目标页，取 DOM/求值得出证据，
      然后把进程连同临时 profile 一起关掉。用完即无痕，不留常驻。

为什么不一路做下去（边界纪律）：
    浏览器看到的是**渲染后**的 DOM，而后端重放看到的是**响应体**。两者不一致时
    才有价值（响应体里没有、DOM 里有 → 说明前端脚本拼接/渲染成的，是真的客户端注入点）。
    所以这条通道是**补充**证据，不是替代 HTTP 重放；任何情况下都不许只靠它下可利用结论。

三态纪律（与 M5 结果点、M7 跨请求回显完全一致）：
    raw      —— 投放/污染串在渲染后的 DOM 里原样出现 → 浏览器确实把它当标记文本渲染了
                （DOM XSS 可利用）
    escaped  —— 在 DOM 里但被转义/是脚本字面量而非可执行 → 真阴性（确证，definitive=True）
    absent   —— 没在 DOM 里搜到 → **证据缺失**（可能压根没渲染、页面 404、脚本报错），
                绝不能当无害
    unavailable —— 本机没有可用的浏览器运行时（playwright 没装 / Chromium 缺失）→
                也是证据缺失，**不允许伪造**，通道直接不参与仲裁

设计红线（改这个文件前必读）：
    1. **绝不允许长时间持有浏览器进程**：硬超时 + finally 关闭 + 临时 profile 删除；
       超时未返回的线程被强杀，宁可丢证据也不把整轮 D2 拖住。
    2. **绝不伪造证据**：运行时不可用必须如实上报 `unavailable`，让 D2 记为证据缺失，
       而不是「没搜到」——后者会被误读成无害。
    3. **绝不把浏览器结论当通用判据**：只有明确标注需要渲染后 DOM 的族才走这条路，
       其余族由既有六条通道判（见 evidence_channels.browser_dom 适用性）。
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

STATE_RAW = "raw"
STATE_ESCAPED = "escaped"
STATE_ABSENT = "absent"
STATE_UNAVAILABLE = "unavailable"

DEFAULT_TIMEOUT_SECONDS = 30.0     # 单页取证硬超时
TEARDOWN_GRACE_SECONDS = 3.0       # 关闭时的宽限（等进程退出）
MARKER_PREFIX = "sastai"           # 与 replay_plan 的自限标记同源前缀

# DOM 相关族名。判定分两拨，别合并成一颗 token 串（踩过）：裸 "dom" 走子串匹配会把
# "weak_random"（ran**dom**）、"abused_observable" 这类**名字里带 dom 三个字母**的后端族
# 全部误判成前端族 —— 于是浏览器动不动就起来，重放预算被页面开销烧掉。
#   _DOM_EXACT：整族名口径（dom / dom_xss / dom_injection …）
#   _DOM_SUBTOKENS：前端语义明确的词，子串匹配也安全
_DOM_EXACT = ("dom", "dom_xss", "dom_injection", "dom Based")
_DOM_SUBTOKENS = ("client_side", "client_s", "javascript", "js_xss", "front_end", "client_xss")


def is_dom_family(family: str) -> bool:
    """该族是否需要「渲染后 DOM」才能下结论（按需起浏览器的触发条件）。"""
    f = str(family or "").strip().lower().replace("-", "_")
    if any(f == t or f.endswith("_" + t.split(" ")[-1]) for t in _DOM_EXACT):
        return True
    return any(tok in f for tok in _DOM_SUBTOKENS)


def make_marker() -> str:
    """自限标记：只允许出现在本轮取证，不含任何可执行语法（与 M7 同一条纪律）。"""
    try:
        import uuid
        return "%s-%s" % (MARKER_PREFIX, uuid.uuid4().hex[:16])
    except Exception:  # pragma: no cover
        return "%s-%012x" % (MARKER_PREFIX, time.time())


class BrowserUnavailable(Exception):
    """本机没有可用的浏览器运行时（不是页面问题，也不是漏洞问题）。"""


def backend_available() -> Tuple[bool, str]:
    """探测浏览器运行时是否就绪。返回 (available, detail)。

    只做导入探测，不启动进程、不下载任何东西。detail 供对账看清「为什么没取证」。
    """
    try:
        import playwright  # noqa: F401
    except Exception as exc:
        return False, "playwright_not_installed: %s" % exc
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception as exc:
        return False, "playwright_import_failed: %s" % exc
    return True, "playwright"


class _Recorder:
    """在页面里挂钩子，把「这个标记有没有进 DOM / 有没有被当成可执行」记下来。

    注入的脚本只做**观测**：把命中标记的元素的 textContent / outerHTML 以及
    eval/new Function 是否被触发记到 window.__sastaiBrowser，绝不做任何注入利用。
    """

    SCRIPT = """
    (() => {
      const mk = window.__sastaiMarker;
      const out = {marker: mk, raw: false, escaped: false, in_script: false,
                   eval_called: false, hits: [], observed: false};
      // 观测 eval：DOM XSS 的判据是「标记进了 eval/Function 构造器」
      try {
        const _e = eval;
        window.eval = function (...a) {
          try {
            out.eval_called = out.eval_called || (String(a[0] || '').indexOf(mk) >= 0);
          } catch (e) {}
          return _e.apply(this, a);
        };
        const _nf = Function;
        window.Function = function (...a) {
          try {
            out.eval_called = out.eval_called || (String(a[0] || '').indexOf(mk) >= 0);
          } catch (e) {}
          return _nf.apply(this, a);
        };
      } catch (e) {}
      const scan = () => {
        try {
          out.observed = true;
          const html = document.documentElement.outerHTML || '';
          const txt = document.body ? (document.body.innerText || document.body.textContent || '') : '';
          const idx = html.indexOf(mk);
          if (idx >= 0) {
            // 标记在 HTML 里出现：看是「原样当文本渲染」还是「在 script/属性里被求值」
            const before = html.slice(Math.max(0, idx - 12), idx);
            const after = html.slice(idx, idx + mk.length + 12);
            if (/<script/i.test(before.slice(-12))) {
              out.in_script = true;
            } else if (before.includes('&lt;') || before.includes('&#') || after.includes('&amp;')) {
              out.escaped = true;
            } else {
              out.raw = true;
            }
            out.hits.push({before: before, after: after});
          }
        } catch (e) {}
      };
      try { scan(); } catch (e) {}
      document.addEventListener('DOMContentLoaded', () => { try { scan(); } catch (e) {} });
      window.addEventListener('load', () => { try { scan(); } catch (e) {} });
      const _mo = window.MutationObserver;
      if (_mo) {
        try {
          new _mo(() => { try { scan(); } catch (e) {} }).observe(
            document.documentElement || document, {childList: true, subtree: true});
        } catch (e) {}
      }
      window.__sastaiBrowser = out;
      return out;
    })()
    """


class BrowserProbe:
    """按需的一次性浏览器取证（构造 → run → 关闭，实例用完即弃）。"""

    def __init__(self, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 user_agent: str = ""):
        self.timeout = float(timeout_seconds or DEFAULT_TIMEOUT_SECONDS)
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SAVR-browser-probe/1.0")
        self._tmp_profile = ""

    # ---- 上下文管理：保证无论如何都把进程和临时目录清掉 ----
    def __enter__(self) -> "BrowserProbe":
        return self

    def __exit__(self, *_exc) -> bool:
        self.close()
        return False

    def close(self) -> None:
        """关闭浏览器并删临时 profile（幂等）。"""
        pw = getattr(self, "_pw", None)
        if pw is not None:
            try:
                pw.stop()
            except Exception as exc:
                logger.warning("[browser-probe] 关闭浏览器失败（进程可能已自退）：%s", exc)
            self._pw = None
        if self._tmp_profile:
            try:
                shutil.rmtree(self._tmp_profile, ignore_errors=True)
            except Exception as exc:
                logger.warning("[browser-probe] 清理临时 profile 失败：%s", exc)
            self._tmp_profile = ""

    def probe(self, url: str, marker: str) -> Dict[str, Any]:
        """打开 url 并在渲染后的 DOM 里找 marker。返回结构化证据（永不抛异常）。

        返回字段：{url, marker, state(raw/escaped/absent/unavailable), engine,
                   duration_ms, reason, dom_hits, eval_called, observed, timeout}
        """
        started = time.time()
        out: Dict[str, Any] = {
            "url": str(url or ""), "marker": str(marker or ""),
            "state": STATE_UNAVAILABLE, "engine": "", "duration_ms": 0.0,
            "reason": "", "dom_hits": [], "eval_called": False,
            "observed": False, "timeout": False,
        }
        avail, detail = backend_available()
        if not avail:
            out["reason"] = "browser_runtime_unavailable: " + detail
            return out
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            out["reason"] = "playwright_import_failed: %s" % exc
            return out

        self._tmp_profile = tempfile.mkdtemp(prefix="sastai-browser-")
        ctx_mgr = sync_playwright()
        self._pw = ctx_mgr
        try:
            pw = ctx_mgr.__enter__()
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = browser.new_context(
                    user_agent=self.user_agent,
                    java_script_enabled=True,
                    ignore_https_errors=True,
                )
                page = context.new_page()
                page.on("pageerror", lambda _e: None)  # 页面脚本报错不影响取证，只影响 DOM
                page.add_init_script(
                    "window.__sastaiMarker = %s;" % _js_string(marker)
                    + _Recorder.SCRIPT)
                try:
                    page.goto(str(url), timeout=int(self.timeout * 1000),
                              wait_until="domcontentloaded")
                    try:
                        page.wait_for_load_state("networkidle",
                                                 timeout=int(self.timeout * 1000))
                    except Exception:
                        pass  # 长轮询/websocket 页面永远等不到 idle，不阻塞取证
                except Exception as exc:
                    out["reason"] = "navigation_failed: %s" % str(exc)[:200]
                out["engine"] = str(pw.chromium.name)
                rec = _collect(page)
                if isinstance(rec, dict):
                    out["observed"] = bool(rec.get("observed"))
                    out["eval_called"] = bool(rec.get("eval_called"))
                    out["dom_hits"] = list(rec.get("hits") or [])[:5]
                    raw = bool(rec.get("raw"))
                    escaped = bool(rec.get("escaped"))
                    in_script = bool(rec.get("in_script"))
                    if raw or (in_script and not escaped):
                        # 标记被页面当脚本片段求值（进了 script 且没被转义）→ 可利用
                        out["state"] = STATE_RAW if raw else STATE_RAW
                    elif escaped:
                        out["state"] = STATE_ESCAPED
                    elif out["eval_called"]:
                        out["state"] = STATE_RAW
                    elif not out["observed"]:
                        out["state"] = STATE_ABSENT
                        out["reason"] = (out["reason"] or "browser_rendered_no_marker")
                    else:
                        out["state"] = STATE_ABSENT
            finally:
                try:
                    browser.close()
                except Exception as exc:
                    logger.warning("[browser-probe] browser.close 失败：%s", exc)
        except Exception as exc:
            out["state"] = STATE_UNAVAILABLE
            out["reason"] = "probe_error: %s" % str(exc)[:300]
        finally:
            out["duration_ms"] = int((time.time() - started) * 1000)
            self.close()
        return out

    # ---- 兼容老调用 ----
    run = probe


def _js_string(s: str) -> str:
    """把字符串安全写成 JS 字面量（只用于注入观测脚本，不用于利用）。"""
    body = (str(s).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", ""))
    return '"' + body + '"'


def _collect(page: Any) -> Optional[Dict[str, Any]]:
    try:
        return page.evaluate("() => window.__sastaiBrowser || null")
    except Exception:
        return None


def run_browser_probe(url: str, marker: str,
                      timeout_seconds: Optional[float] = None,
                      probe: Optional[BrowserProbe] = None) -> Dict[str, Any]:
    """一次性取证入口：起浏览器 → 取证 → 关掉。任何异常都被吞成 unavailable 证据。

    这是给 D2 通道用的唯一入口，方便测试直接注入一个假 probe（见 tests/test_m13_browser_probe.py）。
    """
    try:
        if timeout_seconds is None:
            timeout_seconds = _env_timeout()
        p = probe or BrowserProbe(timeout_seconds=timeout_seconds)
        return p.probe(url, marker)
    except Exception as exc:
        return {"url": str(url or ""), "marker": str(marker or ""),
                "state": STATE_UNAVAILABLE, "engine": "", "duration_ms": 0,
                "reason": "probe_exception: %s" % str(exc)[:300],
                "dom_hits": [], "eval_called": False, "observed": False, "timeout": False}


def probe_url_for(spec: Dict[str, Any], dast: Dict[str, Any]) -> str:
    """取浏览器要打开的 URL：优先 D1 真实发出的 replay_url，退化用 target_endpoint。

    replay_url 是「requests prepare 之后」的地址（含 query），重定向/鉴权跳转前的真实形态；
    spec.target_endpoint 常常只是路径，缺 host、缺参数，浏览器直接打不开。
    """
    d = dast or {}
    sp = spec or {}
    for cand in (d.get("replay_url"), sp.get("replay_url")):
        if cand and str(cand).startswith(("http://", "https://")):
            return str(cand)
    return str(sp.get("target_endpoint") or "")


def _env_timeout(default: float = DEFAULT_TIMEOUT_SECONDS) -> float:
    """允许运维用环境变量收紧单页超时（本机机器弱时把浏览器时间预算压掉）。"""
    raw = os.environ.get("SASTAI_BROWSER_TIMEOUT")
    try:
        v = float(raw)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default
