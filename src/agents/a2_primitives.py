"""A2 原语判别器。

## 定位

把 A2 的"判断"与"创造"分开。判断类任务（是不是真漏洞、参数位置、净化强度、可利用难度）
只输出一行定长短串，1 到 3 个 token 量级；只有判断通过的 finding 才值得花长输出去构造
payload。这是 TypeSafe Jev（System One 模型）的核心手法：判别式原语 + 条件生成。

## 输出契约（七段定长，零容错解析）

每个 finding 一行，按文件顺序输出，例如：

L=42 V=1 VP=0.87 LOC=q LP=0.92 S=w SP=0.61 K=0.78

字段含义：
  L   行号（回显用，便于审计对账）
  V   Noul：是不是真漏洞，0/1
  VP  Noul 概率，0.00-1.00
  LOC Choice：注入位置 q/h/c/b/m/p/u = query/header/cookie/body/multipart/path/unknown
  LP  位置概率
  S   Choice：净化强度 s/w/n/u = strong/weak/none/unknown
  SP  净化概率
  K   Score：可利用难度 0.00-1.00，越高越容易打通（供 D2 排序）

## 纪律

- 定长格式解析失败先回灌重试一次，再失败降级 JSON；绝不静默丢 finding。
- 早停只用于"高置信判否"（默认 VP>=0.9 且 V=0），且判否结论仍落库可审计——
  早停是省生成成本，不是剥夺 D2 的最终裁决权（D2 仍可翻案）。
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# 早停阈值：V=0 且 VP 不低于该值才跳过生成。默认 0.9（保守），可用环境变量调。
EARLY_STOP_MIN_VP = float(os.environ.get("SAST_AI_A2_EARLY_STOP_MIN_VP", "0.90"))

_LOC_CODES = {"q": "query", "h": "header", "c": "cookie", "b": "body",
              "m": "multipart", "p": "path", "u": "unknown"}
_S_CODES = {"s": "strong", "w": "weak", "n": "none", "u": "unknown"}

_SYSTEM = """你是静态扫描结果的"一审判别器"。给你一段 Java 源码和若干条静态扫描告警，
你对**每条告警**输出一行定长判定，不输出任何其它文字。

每行格式（七段，空格分隔，必须严格遵守）：
L=<行号> V=<0|1> VP=<0.00~1.00> LOC=<q|h|c|b|m|p|u> LP=<0.00~1.00> S=<s|w|n|u> SP=<0.00~1.00> K=<0.00~1.00>

输出示例（两行对应两条告警）：
L=42 V=1 VP=0.87 LOC=q LP=0.92 S=w SP=0.61 K=0.78
L=57 V=0 VP=0.95 LOC=c LP=0.80 S=s SP=0.90 K=0.10

字段口径：
- V=1 表示这是真漏洞（污点可达 sink 且无有效净化）；V=0 表示误报（已参数化/强净化/不可达）。
- VP 是你对 V 这个判断的置信度。**没有把握时 VP 要低**（例如 0.5），不要假装确定。
- LOC 是最可能的注入位置：q=query 参数、h=请求头、c=cookie、b=请求体、m=multipart、
  p=路径、u=不确定。
- S 是净化强度：s=强净化（参数化/白名单/ESAPI 有效校验）、w=弱净化（可绕过的过滤）、
  n=无净化、u=不确定。
- K 是利用难度评分：1.00=裸拼接直通，0.00=几乎不可能打通。

判据（重要，按族区分）：
%s

要求：只输出 N 行（N=告警条数），按告警出现顺序，每行必须七段齐全；不要编号、不要解释、
不要代码块、不要包成 JSON 对象的键。"""


def _family_hint_block(families: List[str]) -> str:
    """复用 A2 分析师的族判据（同一套标准，避免两处判据不一致）。"""
    try:
        from src.agents.a2_integrated_analyst import _family_hint
        seen, out = set(), []
        for f in families:
            h = _family_hint(str(f or ""))
            if h and h not in seen:
                seen.add(h)
                out.append(h)
        return "\n\n".join(out)
    except Exception:  # noqa: BLE001
        return ""


@dataclass
class Primitives:
    """一条 finding 的原语判定结果。"""

    line: Optional[int] = None
    vuln: bool = False
    vuln_prob: float = 0.0
    location: str = "unknown"
    location_prob: float = 0.0
    sanitizer: str = "unknown"
    sanitizer_prob: float = 0.0
    exploitability: float = 0.0
    raw: str = ""
    source: str = "llm"        # llm | fallback

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line": self.line, "vuln": self.vuln, "vuln_prob": self.vuln_prob,
            "location": self.location, "location_prob": self.location_prob,
            "sanitizer": self.sanitizer, "sanitizer_prob": self.sanitizer_prob,
            "exploitability": self.exploitability, "source": self.source,
        }

    @property
    def early_stoppable(self) -> bool:
        """高置信判否才允许早停（省生成成本）；其余一律走完整路径保召回。"""
        return (not self.vuln) and self.vuln_prob >= EARLY_STOP_MIN_VP


# 且经常省略 LP/SP 概率段（如 {"L=45 V=1 VP=0.95 LOC=c S=n K=1.00":true}）。
# 故正则设计为：L/V/VP 核心三段必需，LOC/LP、S/SP、K 各自成组可选，缺省按 unknown/0 处理。
_LINE_RE = re.compile(
    r"L=(?P<L>\d+)\s+V=(?P<V>[01])\s+VP=(?P<VP>[01]\.\d{1,2}|[01])"
    r"(?:\s+LOC=(?P<LOC>[qhcbmpu])\s+LP=(?P<LP>[01]\.\d{1,2}|[01]))?"
    r"(?:\s+S=(?P<S>[swnu])\s+SP=(?P<SP>[01]\.\d{1,2}|[01]))?"
    r"(?:\s+K=(?P<K>[01]\.\d{1,2}|[01]))?")


def parse_primitives(text: str, expect: Optional[int] = None) -> List[Primitives]:
    """定长解析。支持两种模型行为：

    1. 纯文本多行（每行一条七段判定）；
    2. format=json 强制下的 JSON 包装——模型会把整行判定当成 JSON 对象的**键**
       。

    因此这里不做逐行 search，而是对全文做 finditer 提取所有七段行，JSON 包装、
    纯文本、多行混排都能解析。缺行/坏行按 expect 补 fallback（V=0 VP=0，不早停）。
    """
    out: List[Primitives] = []
    for m in _LINE_RE.finditer(str(text or "")):
        try:
            loc = m.group("LOC")
            s = m.group("S")
            out.append(Primitives(
                line=int(m.group("L")),
                vuln=m.group("V") == "1",
                vuln_prob=float(m.group("VP")),
                location=_LOC_CODES.get(loc, "unknown") if loc else "unknown",
                location_prob=float(m.group("LP")) if m.group("LP") else 0.0,
                sanitizer=_S_CODES.get(s, "unknown") if s else "unknown",
                sanitizer_prob=float(m.group("SP")) if m.group("SP") else 0.0,
                exploitability=float(m.group("K")) if m.group("K") else 0.0,
                raw=m.group(0)[:200],
            ))
        except Exception:  # noqa: BLE001
            continue
    if expect is not None:
        while len(out) < expect:
            out.append(Primitives(source="fallback"))
    return out


def _user_prompt(code: str, filename: str, findings: List[Dict[str, Any]],
                 extra_context: str = "") -> str:
    fams = [str(f.get("family") or "") for f in findings]
    sys_hint = _family_hint_block(fams)
    items = []
    for i, f in enumerate(findings, 1):
        items.append("%d. line=%s family=%s note=%s" % (
            i, f.get("line"), f.get("family") or "?",
            str(f.get("note") or "")[:200]))
    ctx = ("\n\n【跨文件上下文（净化器/来源可能在别的文件）】\n" + extra_context) if extra_context else ""
    return (
        "文件：%s\n\n【源码】\n%s\n\n【待判告警】\n%s%s\n\n"
        "请对每条告警输出一行七段判定（共 %d 行，顺序一致）。"
        % (filename, code, "\n".join(items), ctx, len(findings))
    )


def discriminate(code: str, filename: str, findings: List[Dict[str, Any]],
                 extra_context: str = "",
                 llm_call: Optional[Callable[[List[Dict[str, str]]], str]] = None
                 ) -> List[Primitives]:
    """一次请求对全部 finding 出原语判定。任何失败都返回 fallback 列表（不抛）。"""
    if not findings:
        return []
    if llm_call is None:
        from src.agents.a2_integrated_analyst import ollama_chat
        llm_call = lambda msgs: ollama_chat(msgs)  # noqa: E731
    fams = [str(f.get("family") or "") for f in findings]
    msgs = [
        {"role": "system", "content": _SYSTEM % _family_hint_block(fams)},
        {"role": "user", "content": _user_prompt(code, filename, findings, extra_context)},
    ]
    for attempt in (1, 2):
        try:
            raw = llm_call(msgs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[a2-primitives] 判别调用失败（第 %d 次）：%s", attempt, exc)
            raw = ""
        got = parse_primitives(raw, expect=None)
        if len(got) >= len(findings):
            return got
        if attempt == 1:
            # 缺行：把已解析到的行数回灌，要求补齐
            msgs.append({"role": "assistant", "content": (raw or "")[:2000]})
            msgs.append({"role": "user", "content": (
                "只解析到 %d 行，需要 %d 行。请补齐剩余行的七段判定，不要重复已给出的行，"
                "不要任何解释。" % (len(got), len(findings)))})
    logger.info("[a2-primitives] %s 判别两次均不足（%d/%d），降级 fallback",
                filename, len(got), len(findings))
    while len(got) < len(findings):
        got.append(Primitives(source="fallback"))
    return got
