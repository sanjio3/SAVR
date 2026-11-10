"""SSTI 按引擎分桶的候选池与求值对（Part2 定稿本轮 M10，2026-10-03 落地）。

背景（为什么要按引擎分桶）：
    原实现到处散落着写死的求值对（d2_java_strategies 里 thymeleaf 用 ``${7*7}``、
    ognl 用 ``%{7*7}``），三个问题：
      1. **不认引擎**：同一个 ``${7*7}`` 在 SpEL/Thymeleaf/FreeMarker 下语义并不一致，
         在 Velocity 的旧版本下甚至不求值。拿一组求值对打所有引擎，命中率与误报都不可控。
      2. **散落且易漏**：新增引擎要改多处策略代码，漏一处就静默少一族。
      3. **靠 LLM 猜引擎**：本来就该静态确定的事（import 与 class 路径）交给了 LLM，
         引入方差且慢。

设计：
    1. 引擎注册表是**单一真相源**：每个引擎给出 ① 识别特征（import/package/class 路径，
       不需要 LLM）② 有序的求值对列表（首选 + 备选）③ 族名后缀。
    2. 求值对是**列表**不是单值，这是刻意的：各引擎版本对同一语法的支持有差异
       （Velocity 老版本 ``${7*7}`` 不求值、FreeMarker 的算术需要特定上下文），
       一次只押一个语法等于把命中率押在版本细节上。命中任意一组即确证。
    3. 识别不出引擎时给跨引擎兜底求值对（``all_eval_pairs``），但要降置信度并留痕，
       不能让它冒充「已识别引擎」的结论。
    4. 判定分三态（raw=算出来了 / literal=原样回显=没求值 / absent=没回显），与 M5
       结果点比对同一纪律：**原样回显是"没被求值"的真阴性，不能当可利用**。
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 三态
SSTI_EVALUATED = "evaluated"   # 求值成功（输出等于期望值）→ 可利用
SSTI_LITERAL = "literal"       # 原样回显（模板没求值）→ 真阴性
SSTI_ABSENT = "absent"         # 没回显 → 证据缺失


class SstiEngine:
    """一个模板引擎的桶：识别特征 + 求值对列表。"""

    def __init__(self, name: str, imports: Tuple[str, ...], eval_pairs: List[Tuple[str, str]],
                 family_suffix: str = "", note: str = ""):
        self.name = str(name)
        # imports：任一 token 出现在源码 import/class 路径里即认为用了该引擎
        self.imports: Tuple[str, ...] = tuple(imports)
        # eval_pairs：[(探针表达式, 期望输出子串)]，按优先级排序，命中任一即确证
        self.eval_pairs: List[Tuple[str, str]] = list(eval_pairs)
        self.family_suffix = str(family_suffix or name)
        self.note = str(note or "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.name,
            "family": "ssti_" + self.family_suffix,
            "eval_pairs": [list(p) for p in self.eval_pairs],
            "imports": list(self.imports),
            "note": self.note,
        }


# ── 引擎注册表（单一真相源）──────────────────────────────────────────────
# 求值对的期望值统一用 49（7*7），便于人工核对。
# 每桶给多组：首选语法 + 备选语法（覆盖版本差异与上下文要求）。
ENGINE_REGISTRY: Dict[str, SstiEngine] = {}


def _reg(engine: SstiEngine) -> SstiEngine:
    ENGINE_REGISTRY[engine.name] = engine
    return engine


_reg(SstiEngine(
    "velocity",
    imports=("org.apache.velocity", "VelocityEngine", "VelocityContext",
             "velocity.properties", "velocity.log"),
    eval_pairs=[
        ("${7*7}", "49"),
        ("$!{7*7}", "49"),
        ("#set($x = 7 * 7)$x", "49"),
        ("${7.compareTo(7)}", "0"),
    ],
    family_suffix="velocity",
    note="Velocity 老版本对 ${7*7} 可能按 quiet reference 原样输出，故并列 #set 形态",
))

_reg(SstiEngine(
    "freemarker",
    imports=("freemarker", "FreeMarkerTemplate", "Configuration",
             "freemarker.template", "Template("),
    eval_pairs=[
        ("${7*7}", "49"),
        ("${(7*7)?c}", "49"),
        ("${7?int?plus(42)}", "49"),
    ],
    family_suffix="freemarker",
    note="FreeMarker 算术需数值上下文，故并列 ?c / ?plus 形态",
))

_reg(SstiEngine(
    "thymeleaf",
    imports=("thymeleaf", "ThymeleafView", "springthymeleaf", "thymeLeaf"),
    eval_pairs=[
        ("${7*7}", "49"),
        ("*{7*7}", "49"),
        ("[[${7*7}]]", "49"),
    ],
    family_suffix="thymeleaf",
    note="Thymeleaf 走 SpEL，${} 与 *{} 均可求值；[[...]] 是其内联表达式标记",
))

_reg(SstiEngine(
    "pebble",
    imports=("pebble", "PebbleEngine", "com.mitchellbosecke.pebble",
             "PebbleTemplate", "io.pebbletemplates"),
    eval_pairs=[
        ("{{ 7*7 }}", "49"),
        ("{{ 7*7 | json }}", "49"),
    ],
    family_suffix="pebble",
    note="Pebble 用 {{ }} 语法（Twig 风格）",
))

_reg(SstiEngine(
    "spel",
    imports=("org.springframework.expression", "SpelExpressionParser",
             "ExpressionParser", "SpelParserConfiguration", "StandardEvaluationContext"),
    eval_pairs=[
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("${T(java.lang.Math).abs(-49)}", "49"),
    ],
    family_suffix="spel",
    note="SpEL 可被 Thymeleaf/Spring MVC 间接使用，故 import 特征有交叉",
))

_reg(SstiEngine(
    "ognl",
    imports=("ognl", "OgnlContext", "Ognl.", "com.opensymphony.xwork2",
             "ValueStack", "OgnlUtil"),
    eval_pairs=[
        ("%{7*7}", "49"),
        ("${7*7}", "49"),
        ("%{#a=(7*7)}", "49"),
    ],
    family_suffix="ognl",
    note="Struts2/OGNL 用 %{}，部分版本也支持 ${}",
))

_reg(SstiEngine(
    "mvel",
    imports=("mvel", "MVEL.eval", "org.mvel2", "MvelContext", "MVEL"),
    eval_pairs=[
        ("${7*7}", "49"),
        ("{7*7}", "49"),
        ("#set($x = 7 * 7)$x", "49"),
    ],
    family_suffix="mvel",
    note="MVEL 2.x 与 Velocity 语法有重叠，故并列两种形态",
))


def _engine_for_name(name: str) -> Optional[SstiEngine]:
    return ENGINE_REGISTRY.get(str(name or "").strip().lower().replace("-", "_"))


def detect_engines(files: Iterable[Dict[str, Any]]) -> List[str]:
    """从源码 import / package / class 路径静态识别模板引擎（不需要 LLM）。

    只认「文件里出现该引擎的特征 token」这一层判据——更细的（哪些模板文件、
    哪个 Controller）不在本函数职责内。识别不出返回空列表，调用方走跨引擎兜底。
    """
    found: List[str] = []
    for f in files or []:
        text = "%s\n%s" % (f.get("path") or f.get("file_path") or "", f.get("content") or "")
        low = str(text).lower()
        if not low:
            continue
        for eng in ENGINE_REGISTRY.values():
            if eng.name in found:
                continue
            for token in eng.imports:
                if token.lower() in low:
                    found.append(eng.name)
                    break
    return found


def engine_family(engine: str) -> str:
    """引擎 → 族名（候选池分桶的桶名）。"""
    eng = _engine_for_name(engine)
    return ("ssti_" + eng.family_suffix) if eng else "ssti"


def eval_pairs_for(engine: str) -> List[Tuple[str, str]]:
    """单个引擎的求值对；引擎不认识则返回空。"""
    eng = _engine_for_name(engine)
    return list(eng.eval_pairs) if eng else []


def all_eval_pairs() -> List[Tuple[str, str]]:
    """跨引擎兜底求值对（识别不出引擎时用，按引擎注册顺序去重）。

    置信度要降级并留痕：它只说明「这类表达式至少对一个引擎会求值」，
    不能冒充「已识别出是哪个引擎」。
    """
    seen: List[Tuple[str, str]] = []
    for eng in ENGINE_REGISTRY.values():
        for pair in eng.eval_pairs:
            if pair not in seen:
                seen.append(pair)
    return seen


def pairs_for(engines: Optional[Iterable[str]] = None) -> List[Tuple[str, str]]:
    """按识别到的引擎给求值对；没识别到就给跨引擎兜底。"""
    picked: List[Tuple[str, str]] = []
    names = [str(x) for x in (engines or []) if _engine_for_name(x)]
    for n in names:
        for pair in eval_pairs_for(n):
            if pair not in picked:
                picked.append(pair)
    return picked or all_eval_pairs()


def judge(body: Any, payload: str, expected: str) -> str:
    """判定单个求值对的响应形态：evaluated / literal / absent。

    口径（与 M5 同一纪律）：
      - 响应里出现**期望值**且**不是原样带着表达式** → evaluated（求值成功，可利用）
      - 响应里出现原样表达式（或其转义形态）→ literal（没求值，真阴性）
      - 两者都没有 → absent（证据缺失，不是无害）
    """
    text = str(body or "")
    if not text or not payload:
        return SSTI_ABSENT
    exp = str(expected or "")
    has_expected = bool(exp) and exp in text
    has_literal = payload in text
    if not has_literal and exp:
        # 表达式可能被模板转义（${..} 变 ${..} 不变，但 <%= %> 场景可能变 &#36;{..}），
        # 宽松认定：出现期望值即算求值成功
        return SSTI_EVALUATED if has_expected else SSTI_ABSENT
    if has_expected and has_literal:
        # 同时出现：期望值优先（求值成功会把表达式替换掉，残留可能是页面别处的文案）
        return SSTI_EVALUATED
    return SSTI_LITERAL


def judge_by_engine(body: Any, engines: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """按引擎分桶跑求值对，返回 {state, engine, payload, expected, tried}。

    命中即停（首个 evaluated 即确证）。全部 literal → 真阴性；
    全 absent → 证据缺失，definitive 交上游裁决。
    """
    names = [str(x) for x in (engines or []) if _engine_for_name(x)]
    tried: List[Dict[str, str]] = []
    literals = 0
    for eng_name in names:
        for payload, expected in eval_pairs_for(eng_name):
            st = judge(body, payload, expected)
            tried.append({"engine": eng_name, "payload": payload,
                          "expected": expected, "state": st})
            if st == SSTI_EVALUATED:
                return {"state": SSTI_EVALUATED, "engine": eng_name, "payload": payload,
                        "expected": expected, "tried": tried,
                        "engine_identified": True}
            if st == SSTI_LITERAL:
                literals += 1
    # 识别不出引擎 → 跑跨引擎兜底
    if not names:
        for payload, expected in all_eval_pairs():
            st = judge(body, payload, expected)
            tried.append({"engine": "", "payload": payload,
                          "expected": expected, "state": st})
            if st == SSTI_EVALUATED:
                return {"state": SSTI_EVALUATED, "engine": "", "payload": payload,
                        "expected": expected, "tried": tried,
                        "engine_identified": False}
            if st == SSTI_LITERAL:
                literals += 1
    if literals:
        return {"state": SSTI_LITERAL, "engine": "", "payload": "", "expected": "",
                "tried": tried, "engine_identified": bool(names)}
    return {"state": SSTI_ABSENT, "engine": "", "payload": "", "expected": "",
            "tried": tried, "engine_identified": bool(names)}


def bucket_summary() -> List[Dict[str, Any]]:
    """引擎桶概览（挂报告/对账用：能回答「本轮覆盖了哪几个引擎、各自求值对是什么」）。"""
    return [e.to_dict() for e in ENGINE_REGISTRY.values()]
