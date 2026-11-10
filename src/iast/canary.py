"""双段 canary：生成（A2 侧 TriggerSpec）与匹配（摄取侧 I1）。

canary 是什么？（设计依据 重构文档 3.16 / 7.2 方向B）
- 平台向被测应用的 HTTP 参数/请求体里注入一段「特殊污染标记字符串」，叫 canary
  （金丝雀）。它像煤矿里的金丝雀一样：只要它在应用的某个危险 sink（SQL 执行、
  命令执行、反序列化、表达式解析…）里被观测到，就证明「外部输入确实穿透到了危险
  操作」，是 IAST 运行时的核心证据。
- 双段结构：
  * 身份段 identity = `s4st41` + 16 位十六进制（全局唯一、纯字母数字、能过各种转义）。
  * 元字符段 metacharacter = 按漏洞家族定形（如 `$(id)` / `<svg` / `../`）+ 随机指纹。
    用于区分「业务代码本来就写死的一串 $(id)」与「我们的 canary 真正到达 sink」。
  * 身份段置前，因为探针 maxSampleLength=512 会截断尾部，置前确保身份段不被截掉。


设计依据：重构文档 3.16 / 7.2 方向B。
- 身份段（identity segment）：`s4st41` + 16 位十六进制，纯字母数字，能过 URL/HTML/引号转义，
  全局唯一，且因探针 maxSampleLength=512 会截断尾部，身份段**置前**确保不被截掉。
- 元字符段（metacharacter segment）：按 vulnType 定形，并嵌入随机指纹串，用于区分
  "业务代码本来就写死的一串 $(id)" 与 "我们的 canary 真正到达 sink"。
- 类型感知退化（7.2 方向B）：受格式约束参数（数字 ID/URL/枚举）退化为 typed 形态
  （大随机整数嵌隐藏位指纹），保留三态判定。
"""
import html
import re
import secrets
import string
import urllib.parse
from typing import Optional

IDENTITY_PREFIX = "s4st41"
IDENTITY_HEX_LEN = 16
META_FINGERPRINT_LEN = 8
MAX_TOTAL_LEN = 512

# 元字符段基形（不含指纹）。key 用 vuln_hash 归一后的 family。
META_BY_FAMILY = {
    "sql-injection": "|OR1=1",
    "command-execution": "$(id)",
    "xss": '"><svg',
    "path-traversal": "../",
}


class CanaryStates:
    NO_ARRIVAL = "no-arrival"
    ARRIVED = "arrived"
    SINK_REACHED = "sink-reached"
    # 设计一①：探针在 sink 现场显式断言 canary 抵达危险函数实参（区别于 Python 被动兜底 sink-reached）。
    SINK_REACHED_PROBE = "sink-reached-probe"
    ARRIVAL_SANITIZED = "arrival-sanitized"


# ---------------------------------------------------------------------------
# 单一真相源：canary 语义判据（2026-09-07 收口）
#
# 事故背景：sink_reached 恒 0。根因是两类散落各处的自造判据——
#   ① 全等比较：trigger_specs.taint_marker 是「身份段 + 元字符段」完整串，而
#      iast_events.canary 只有 22 字符身份段，`WHERE taint_marker = canary` 恒 0 命中。
#   ② 漏掉探针态：`state == "sink-reached"` 把 sink-reached-probe（探针在 sink 现场
#      显式断言，设计上是最强证据）排除在「已抵达」之外，实测 29/39 条证据被丢弃。
# 此后任何「是否到达 sink」「canary 如何比对」的判断一律走下面三个函数，禁止就地自造。
# ---------------------------------------------------------------------------
SINK_REACHED_STATES = (CanaryStates.SINK_REACHED, CanaryStates.SINK_REACHED_PROBE)


def is_sink_reached(state: str) -> bool:
    """state 是否属于「canary 已抵达 sink」语义（含探针显式断言 sink-reached-probe）。"""
    return str(state or "").strip().lower() in SINK_REACHED_STATES


def canary_key(value: str) -> str:
    """把任意 canary 文本归一为身份段（s4st41 + 16hex，22 字符）。

    输入可以是完整 taint_marker（身份段+元字符段）、事件 canary、trace_id 或更长样本；
    输出恒为身份段，用于两侧比对。抽不出身份段时原样返回（向后兼容历史数据）。
    """
    text = str(value or "")
    return CanaryMatcher.find_identity(text) or text.strip()


def _rand_hex(length: int) -> str:
    # secrets.token_hex(n) returns 2n hex chars; trim to exact length.
    return secrets.token_hex((length + 1) // 2)[:length]


def _fingerprint() -> str:
    return _rand_hex(META_FINGERPRINT_LEN)


class CanaryFactory:
    """A2 侧：构造 TriggerSpec.taint_marker。"""

    @staticmethod
    def identity_segment(run_nonce: Optional[str] = None) -> str:
        """身份段 = `s4st41` + 16 位十六进制。

        - 默认（run_nonce=None）：16 位纯随机，全局唯一。
        - 传入 run_nonce（4 位十六进制）：采用 `4 位 run_nonce + 12 位随机`，使同一任务
          一次登记周期内的所有 spec 共享同一 run_nonce，与该任务之前/之后的运行、以及其他
          任务的 canary 天然处于**不相交命名空间**。配合「D1 重放前清空本任务旧 canary 缓存」
          （purge_task_canary_events），可彻底杜绝跨任务/跨运行的陈旧 canary 串互相串扰。
          正则 s4st41[0-9a-fA-F]{16} 与 CanaryMatcher._extract_identity 仍精确匹配 16 位。
        """
        if run_nonce:
            return IDENTITY_PREFIX + run_nonce + _rand_hex(IDENTITY_HEX_LEN - len(run_nonce))
        return IDENTITY_PREFIX + _rand_hex(IDENTITY_HEX_LEN)

    @staticmethod
    def metachar_segment(family: str) -> str:
        base = META_BY_FAMILY.get(family, "PAYLOAD")
        return base + _fingerprint()

    @classmethod
    def build(cls, family: str, run_nonce: Optional[str] = None) -> str:
        canary = cls.identity_segment(run_nonce) + cls.metachar_segment(family)
        if len(canary) > MAX_TOTAL_LEN:
            canary = canary[:MAX_TOTAL_LEN]  # 截断尾部（元字符段），身份段已置前保全
        return canary

    @staticmethod
    def typed(family: str, typed_value: str) -> str:
        """7.2 方向B：格式约束参数。typed_value 已是合法形态（如大随机整数），
        其内嵌指纹随值一同到达/被变形，保留三态判定。"""
        return CanaryFactory.identity_segment() + typed_value + _fingerprint()

    @staticmethod
    def typed_for_param_type(family: str, param_type: str) -> str:
        """§7.2 方向B：按 param_type 自动生成「合法形态带可搜索指纹」的 canary。
        - numeric_id: 大随机整数 + 指纹后缀，过整数格式校验
        - url: /<fingerprint>/<rand> 合法路径形态，过 URL 格式校验
        - enum: enum_<fingerprint>，过枚举值校验
        - default/其他: 退化为 typed()。
        """
        fp = _fingerprint()
        if param_type == "numeric_id":
            n = secrets.randbelow(10**9 - 10**8) + 10**8  # 9 位整数
            return CanaryFactory.identity_segment() + str(n) + fp
        if param_type == "url":
            rand = _rand_hex(4)
            return CanaryFactory.identity_segment() + f"/{fp}/{rand}"
        if param_type == "enum":
            return CanaryFactory.identity_segment() + f"enum_{fp}"
        return CanaryFactory.typed(family, "")

    # ----------------------------------------------------------------------
    # 多形态 canary（覆盖加固缺口二）：同一参数同时投放多种编码形态的同一 canary，
    # 应对应用侧对输入做 base64/双重 base64/hex 等变换后污点才抵达 sink 的场景。
    # 各形态共享同一身份段（run_nonce 绑定），仅元字符段/外层编码不同；任一形态到达 sink
    # 即证明污点贯通，避免「明文 canary 被先编码导致 no-arrival」的漏判。
    # ----------------------------------------------------------------------
    @classmethod
    def multi_form(cls, family: str, run_nonce: Optional[str] = None) -> "Dict[str, str]":
        """生成 {form_name: canary_string}。form_name ∈ {plain, b64, b64_double, hex}。

        所有形态共用同一身份段；plain 是原始串，b64 = base64(plain)，b64_double = base64(b64)，
        hex = hex(plain)。探测侧对同参数多形态各自匹配，取最强态（见 CanaryMatcher.best_of）。
        """
        plain = cls.build(family, run_nonce)
        out = {"plain": plain}
        try:
            import base64
            b = base64.b64encode(plain.encode("utf-8")).decode("ascii")
            out["b64"] = b
            out["b64_double"] = base64.b64encode(b.encode("utf-8")).decode("ascii")
            out["hex"] = plain.encode("utf-8").hex()
        except Exception:
            pass
        return out


# 多形态/三态优先级：no-arrival < arrival-sanitized < arrived < sink-reached < sink-reached-probe。
_STATE_RANK = {
    CanaryStates.NO_ARRIVAL: 0,
    CanaryStates.ARRIVAL_SANITIZED: 1,
    CanaryStates.ARRIVED: 2,
    CanaryStates.SINK_REACHED: 3,
    CanaryStates.SINK_REACHED_PROBE: 4,
}

# 字符串态版本的单一真相源（v2 证据分层 D1）：编排器 / 关联层用字符串态（"sink-reached" 等）
# 比较强弱，禁止各自另立一份 —— 此前 orchestrator 与 correlation 各抄了一份且序位错乱
# （arrived/sanitized 反转、sink-reached-probe 被压到与 sink-reached 同档），是 confirmed_runtime
# 口径漂移的根因。统一收敛到此：探针在 sink 实参显式断言的抵达态（sink-reached-probe）须为最强。
STATE_RANK_STR = {
    "no-arrival": 0,
    "arrival-sanitized": 1,
    "arrived": 2,
    "sink-reached": 3,
    "sink-reached-probe": 4,
}


class CanaryMatcher:
    """摄取侧：对事件 payload 样本做编码容错三态匹配。"""

    def __init__(self, canary: str):
        self.canary = canary or ""
        self.identity = self._extract_identity(self.canary)
        self.meta = self.canary[len(self.identity):] if self.identity else ""

    @staticmethod
    def _extract_identity(canary: str) -> str:
        if canary.startswith(IDENTITY_PREFIX):
            hex_part = canary[len(IDENTITY_PREFIX): len(IDENTITY_PREFIX) + IDENTITY_HEX_LEN]
            if hex_part and all(c in string.hexdigits for c in hex_part):
                return IDENTITY_PREFIX + hex_part
        return ""

    # 子串搜索：canary 抵达 sink 后往往被拼接进 SQL/命令/表达式的「中间」，因此必须
    # 在任意文本（事件 payload / context / traceId）里做子串匹配，而非要求身份段位于开头。
    _IDENTITY_RE = re.compile(r"s4st41[0-9a-fA-F]{16}")

    @staticmethod
    def find_identity(text: str) -> str:
        """在任意文本中查找 s4st41<16hex> 身份段（子串匹配）。"""
        if not text:
            return ""
        m = CanaryMatcher._IDENTITY_RE.search(text)
        return m.group(0) if m else ""

    @staticmethod
    def _decode_candidates(sample: str) -> set[str]:
        candidates = {sample}
        try:
            candidates.add(urllib.parse.unquote(sample))
        except Exception:
            pass
        try:
            candidates.add(html.unescape(sample))
        except Exception:
            pass
        return candidates

    def match(self, sample: str) -> str:
        if not self.identity:
            return CanaryStates.NO_ARRIVAL
        candidates = self._decode_candidates(sample)
        if not any(self.identity in c for c in candidates):
            return CanaryStates.NO_ARRIVAL
        if self.meta:
            if any(self.meta in c for c in candidates):
                return CanaryStates.SINK_REACHED
            return CanaryStates.ARRIVAL_SANITIZED
        return CanaryStates.ARRIVED

    @staticmethod
    def _state_rank(state: str) -> int:
        return _STATE_RANK.get(str(state or "").strip().lower(), 0)

    @classmethod
    def best_of(cls, states) -> str:
        """多形态 canary：从一组到达态里取最强（单向升级语义）。

        用法：同一参数投放 plain/b64/b64_double/hex 多种形态，各自匹配得到一组 state，
        调用 best_of 合成一个最终态——任一形态 sink-reached 即证明污点贯通。
        """
        best = CanaryStates.NO_ARRIVAL
        for s in states or []:
            if cls._state_rank(s) > cls._state_rank(best):
                best = str(s)
        return best

    def match_best_of(self, samples: list) -> str:
        """对一组样本（同一参数的多形态 canary 落地值）取最强态。"""
        return self.best_of([self.match(str(s)) for s in samples or []])
