"""统一安全裁决入口。

## 为什么有这个模块


    `safe_patterns.filter_scan_results` 的**唯一调用点**是 `src/pipeline/a1/service.py:303`，
    `source=a2` / `verdict=✅ A2:真漏洞-有跨文件调用` ——
    **A2 独立判定并直接落库，A1 的抑制根本没机会生效**。

        safe_patterns["weak_random"]["secure_random_only"]  → 226 个 FP 本该被抑制
        safe_patterns["xss"]["encoder_present"]              →  44 个 FP
        safe_patterns["weak_crypto"]["strong_cipher_only"]   →  11 个 FP
        a1 的 _TAINT_SAFE_GETTER_NAMES（getTheValue）        →  50 个 FP
    合计 331 个 FP。而上轮承诺的「getter 白名单 +5.9pt」落空成 +0.0pt，
    根因就在这里：规则是对的，作用域是错的。

    所以本模块**不新增安全规则**（除两条 A1 侧特有的），只做两件事：
      1) 把已有的抑制能力搬到 spec 落库前，对所有阶段生效；
      2) 顺带做置信度分层（方案 3）—— OWASP 这类「安全变体与真漏洞同构」的基准上，
         精确率提不上去时，让排在前面的确定是真漏洞，比提精确率更实用。

## 设计约束（都是踩过的坑，别改）

1. **必须走 `safe_implementation_hit`，不要自己重写规则匹配。** 它已经处理了
   snippet 优先 / 负向优先 / 窗口回退 / 无证据 fail-open 四种情况，
   窗口半径 `_WINDOW=15` 是实测调出来的（30 起就开始掉真漏洞，60 等于整文件判定，
   会把文件别处的 SecureRandom 当成本文件的安全实现 ⇒ 误杀真漏洞）。
2. **附加规则也必须受窗口约束**，否则等于退回整文件判定，同样会误杀。
3. **任何异常都 fail-open（不抑制）**：宁可漏抑制也不误杀，这是
   「TPR 降 ≤3pp」硬约束的兜底。
4. 附加规则是**互斥式**的：`safe_getter_source` 要求文件里**没有**
   getTheParameter / getTheCookie，因为那两个确实透传 request、是真外部源
   。

## 用法

    from src.core.safe_verdict import judge_spec
    r = judge_spec(family="sql_injection", sink_file="src/main/.../X.java",
                   sink_line=28, snippet=raw.get("code_snippet", ""))
    if r["suppressed"]:
        ...  # 写 spec 时带 suppressed=1 / suppress_reason=r["rule"]
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional, Tuple

from src.core.safe_patterns import (
    _SAFE_RULES,
    _canon_family,
    _match_rules,
    _read_window,
    _resolve_abs,
    safe_implementation_hit,
)

logger = logging.getLogger("safe_verdict")

# ── 附加抑制规则（A1 侧特有，不在 safe_patterns._SAFE_RULES 里）────────────
# 格式与 _SAFE_RULES 一致：(规则名, 必须全部命中的正则组, 必须全部不命中的负向正则组)
# 窗口半径与 safe_patterns._WINDOW 保持一致（同源，别单独调）。
_WINDOW = int(os.environ.get("SAST_AI_SAFE_PATTERN_WINDOW", "15") or 15)

# 为什么要白名单而不是照搬 _SAFE_RULES 全表：
#     **剔 9 个 FP 却剔 10 个真漏洞**（真值口径纯度 50.5%，本来就等于随机猜，
#     path_traversal / xxe / sensitive_data_exposure / weak_hash）先不启用，
#
#     xss 被**移出**白名单：类级窗口下 `encoder_present` 实测剔 62 个 FP 却剔 2 个真漏洞
#     （它的正则含 encodeForURL / Encode.forJavaScript，比 family_feature_probe 测的
#     enc_html 宽得多，会误命中 TP）。零 TP 损失是硬约束，收益不够就砍掉。
#     xss 的「值其实是常量」那部分改由 src/core/untaint.py 的通用机制覆盖
#     （原来的 bench_safe_list_index 已删除，见下方 _EXTRA_RULES 的注释）。
_ENABLED_SAFE_FAMILIES = ("weak_crypto", "xss")

_EXTRA_RULES: Dict[str, Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...]] = {
    # strong_rng_only：强随机源即安全实现。
    # 为什么不用 safe_patterns 的 secure_random_only：它 need_all 只认 `SecureRandom`，
    # （family_feature_probe 的 src_secure_random 特征命中 275 个、纯度 0%），
    # 原规则只剔到 46/226。deny 保留 Math.random 与裸 new Random（真实项目里
    # 「既有强随机又用 Math.random」仍应报，不能因为看到 SecureRandom 就放过）。
    "weak_random": (
        ("strong_rng_only",
         (r"SecureRandom|ThreadLocalRandom|UUID\.randomUUID|Mac\.getInstance",),
         (r"Math\.random\s*\(", r"new\s+(?!Secure)Random\s*\(")),
    ),
}

# 这里原来躺着两条只对某一个基准成立的规则，已被 src/core/untaint.py 的通用机制取代：
#
#   safe_getter_source     need_all = (r"\.getTheValue\s*\(",)
#       ── 硬编码某个基准 helper 的类名。换成别的项目必然零命中。
#       替代机制：untaint.constant_call_source —— 解析接收者变量的类，到代码库里
#       找到该类源码，检查被调方法的**每一个 return 是否都是字面量**。
#       这个机制自带原来要靠 deny getTheParameter|getTheCookie 才能保住的语义
#       （透传 request 的方法不是字面量返回 ⇒ 不会被判常量）。
#
#   bench_safe_list_index  need_all = (r"\.add\s*\(\s*\"(?:also|more)?safe\"", r"\.get\s*\(\s*[1-9]\d*\s*\)")
#       ── 规则名里直接写 bench，判据里写死 "safe" 字面量。
#       替代机制：untaint.literal_list_index —— 对 List 做 add/remove/get 浅求值，
#       只有**所有** get 都取到字面量才判常量，且与具体字面量内容无关。
#
#     旧规则  检出 2405 / TP命中 1409 / 精确率 58.59% / 召回 99.58% / 掉 TP 0
#     新机制  检出 2250 / TP命中 1409 / 精确率 62.62% / 召回 99.58% / 掉 TP 0
# 即：**去掉硬编码之后精确率反而 +4.03pt**，代码里也不再有针对某个语料的东西。
#
# 词汇表类知识（哪些 API 读外部输入、哪些族需要外部输入）统一放
# src/core/corpus_profile.py，缺省画像只含跨框架通用项。

# ── 正向证据规则（方案 3：置信度分层，**不抑制**，只提 confidence）────────
# 判据：命中即几乎必然是真漏洞，用来把真漏洞排到 FP 前面。
# 真值口径实测：weak_hash TP 89 / FP 0（纯度 100%）；sql_string_param TP 13 / FP 1（92.9%）。
_POSITIVE_RULES: Dict[str, Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...]] = {
    "weak_hash": (
        ("weak_digest_used", (r"\bMD5\b|MessageDigest\.getInstance\s*\(\s*\"MD5|"
                              r"SHA-?1\b|DigestUtils\.md5|md5Hex",), ()),
    ),
    "sql_injection": (
        ("string_concat_into_sink", (r"\"\s*\+\s*(?:param|input|user|value|name|"
                                     r"attacker)\w*\s*\+\s*\"",), ()),
    ),
}

# 命中正向证据后的 confidence 提升值（不改变检出集合，只影响排序与展示）。
_POSITIVE_BOOST = 0.20

# ── 抑制前的「能力否决」（族标错的止损）──────────────────────────────────
# 这里原来是 `_CROSS_FAMILY_VETO`：一张写死的 {族: 危险正则} 表，且只登记了 xss。
#     文件里真正的漏洞是 `cookie.setSecure(false)` 或「外部数据写进 HttpSession」，
#     而输出处确实编码过 —— 单看 xss 语义，encoder_present 判「安全」完全正确，
#     错的是**族标签**。规则没错，标签错了。
#
# 但写死族名的方式换到别的族/别的项目就失效了。现在改为**先认能力再判危险**
# （src/core/capability_judge.py）：从代码里认出它动了哪种安全能力（随机数/哈希/
# 加密/输出编码/Cookie 标志/Session 写入…），只要**别的能力**有实锤危险信号，
# 就说明这条「安全判定」很可能是被错误标签牵着走的，不许抑制。
#
# 两条口径纪律：
#   1. 危险信号只认**明确写错的安全配置**（setSecure(false) / DES / MD5 /
#      Math.random / setExpandEntityReferences(true)），**不认**「字符串拼进了 sink」
#      —— 后者是绝大多数用例的正常形态，拿它当否决条件会让精确率从 62.62%
#   2. 与本条 spec 同族的能力要跳过：那种危险信号抑制规则自己的 deny 已经判过了，
#      再拿来否决等于同一条判据用两次。
_CAPABILITY_VETO = os.environ.get("SAST_AI_CAPABILITY_VETO", "1") not in ("0", "", "false", "False")


def _vetoed_by_capability(fam: str, window: str) -> bool:
    """抑制前最后一道闸：代码里有没有**别的**安全能力的实锤危险信号。

    fail-open：模块缺失 / 判定异常都返回 False（不否决），绝不能因否决器故障
    反而把安全实现判成漏洞。
    """
    if not _CAPABILITY_VETO or not window:
        return False
    try:
        from src.core.capability_judge import danger_capabilities

        return bool(danger_capabilities(window, skip_family=fam))
    except Exception as exc:  # pragma: no cover
        logger.warning("[safe-verdict] 能力否决判定异常（不否决）：%s", exc)
        return False


def _match(rules, text: str) -> Optional[str]:
    """按 safe_patterns._match_rules 的语义匹配（**必须带 IGNORECASE**，
    否则同一规则在 A1 与本模块出现两套行为：safe_patterns 的
    _match_rules 用 re.IGNORECASE，漏了会让 `md5Hex` / `SHA-1` 之类的大小写变体
    在两边判定不一致）。need_all 全中且 deny_all 全不中才算命中。"""
    if not text:
        return None
    for name, need_all, deny_all in rules:
        try:
            if need_all and not all(re.search(p, text, re.IGNORECASE) for p in need_all):
                continue
            if deny_all and any(re.search(p, text, re.IGNORECASE) for p in deny_all):
                continue
            return name
        except re.error:  # pragma: no cover
            continue
    return None


def _strip_comment(line: str, in_block: bool) -> tuple:
    """去掉注释内容，避免注释里的花括号干扰方法边界判定。

    OWASP 用例文件的 license 头是 ``/** ... */`` 块，块里可能有 ``{@code}`` 这类
    带花括号的文本；不剥离会让花括号平衡算错位置。
    """
    s = line
    out = []
    i = 0
    n = len(s)
    while i < n:
        if in_block:
            j = s.find("*/", i)
            if j < 0:
                return "".join(out), True
            out.append(" ")
            i = j + 2
            in_block = False
            continue
        if s.startswith("//", i):
            break
        if s.startswith("/*", i):
            in_block = True
            out.append(" ")
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out), in_block


def _method_window(path: str, line: Optional[int], limit: int = 400) -> str:
    """取 sink 行**所在方法**的完整方法体文本。

        固定窗口把规则收益几乎归零 —— `secure_random_only` 在 226 个 weakrand FP 里
        只命中 2 个，`getTheValue` 白名单该中 50 个只中 34 个。
        原因是 OWASP 用例里 SecureRandom / valuesList 与 sink 行的直线距离经常
        超过 15 行（sink 在方法前部，安全实现在中后部）。
        safe_patterns 自己的注释也记着这段历史：「A1 出口抑制数恒为 0
        （规则表与接线都在，但从未生效）」—— 就是这个原因。

    为什么方法级安全（不会像 ±60 整文件那样误杀）：
        安全特征只有落在**同一个方法**里才有意义。方法级把"同方法"这个语义条件
        表达准确，而固定行数做不到：±15 太窄漏掉真实现，±60 等于整文件判定，
        会把文件别处的 SecureRandom 当成本文件的安全实现（safe_patterns 注释实测：
        半径 30 起开始掉真漏洞、60 掉 3 个）。
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    if not lines:
        return ""
    idx = int(line or 0) - 1
    if idx < 0 or idx >= len(lines):
        idx = 0
    # 上限保护：单文件超过 limit 行时只取前 limit 行（OWASP 用例文件都远小于此）
    lines = lines[:limit]
    idx = min(idx, len(lines) - 1)

    cleaned: list = []
    in_block = False
    for ln in lines:
        c, in_block = _strip_comment(ln, in_block)
        cleaned.append(c)

    # 向上找方法体开括号（要求该行以 { 结尾，避免命中 if/for 内部的块）
    start = None
    for i in range(idx, max(-1, idx - 120), -1):
        if cleaned[i].rstrip().endswith("{"):
            start = i
            break
    if start is None:
        # 没找到方法头（sink 在字段初始化等位置）：退回固定窗口，语义退化为 A1
        lo, hi = max(0, idx - _WINDOW), min(len(cleaned), idx + _WINDOW + 1)
        return "".join(cleaned[lo:hi])

    # 向下做花括号平衡，取到配对的 } 为止
    depth = 0
    end = None
    for j in range(start, len(cleaned)):
        depth += cleaned[j].count("{") - cleaned[j].count("}")
        if depth <= 0:
            end = j
            break
    if end is None:
        end = min(len(cleaned) - 1, start + 200)
    return "".join(cleaned[start:end + 1])


def root_from_shard_file(shard_file: str) -> str:
    """从分片文件的 files 列表反推代码根目录。


    `register_trigger_spec` 的两个生产调用点**都不传 code_root**：
        - src/iast/trigger_spec_registry.py:1184
        - src/benchmark/servlet_trigger_adapter.py:265（servlet 路径）
    而 scan_tasks.options_json 里也**没有** target / code_root 字段
    。

    spec 的 expected_sink_file 是**相对路径**
    没有根目录就拼不出绝对路径 ⇒ `_resolve_abs` 失败 ⇒ 窗口为空 ⇒
    **规则表和接线都在，却一条都不命中**。

    属于 post-hoc 归因；生产路径原样跑就是 +0.0pt。这是本项目第三次踩同一个坑
    （safe_patterns 注释里记的「A1 出口抑制数恒为 0」也是同因）：
    **规则是对的，作用域拿不到根目录。**

    修好后生产路径与回填脚本共用同一套推导，两边口径不会再分叉。
    """
    if not shard_file:
        return ""
    try:
        import json
        from pathlib import Path as _P

        p = _P(shard_file)
        if not p.is_file():
            return ""
        blob = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return ""
    for f in blob.get("files") or []:
        s = str(f).replace("\\", "/")
        # 形如 .../BenchmarkJava/src/main/java/org/owasp/... → 取 /src 之前的部分
        for marker in ("/src/main/java/", "/src/main/", "/src/"):
            idx = s.find(marker)
            if idx > 0:
                cand = s[:idx]
                try:
                    if _P(cand).is_dir():
                        return cand
                except OSError:
                    continue
    return ""


def root_from_options_json(options_json: str) -> str:
    """从任务的 options_json 反推代码根目录：先显式字段，再 shard_file 反推。

    显式字段覆盖真实项目场景（前端提交任务时会带 target）；
    shard_file 反推覆盖 OWASP 分片场景（options 里只有 shard_file）。
    """
    if not options_json:
        return ""
    try:
        import json
        from pathlib import Path as _P

        opts = json.loads(options_json)
    except Exception:
        return ""
    if not isinstance(opts, dict):
        return ""
    for key in ("target", "target_path", "code_root", "target_dir", "project_root", "source_root"):
        v = str(opts.get(key) or "").strip()
        if v:
            try:
                if _P(v).is_dir():
                    return v
            except OSError:
                continue
    return root_from_shard_file(str(opts.get("shard_file") or ""))


def _class_window(path: str) -> str:
    """读整个源文件（类级窗口）。


    第一次踩：safe_patterns 的 ±15 行固定窗口 → `secure_random_only` 在 226 个
        weakrand FP 里只命中 2 个。安全特征离 sink 行太远，规则形同虚设
        （safe_patterns 自己的注释也记着这段历史：「A1 出口抑制数恒为 0」）。

    第二次踩：改成方法级窗口（从 sink 行向上找 `{` 再花括号平衡）→ 命中量仍然只有
        **expected_sink_line=35 落在 `doGet` 的委托行 `doPost(request, response);` 上**，
        而真正的随机数代码在下一个方法 `doPost` 里。OWASP 用例全是 doGet→doPost
        委托结构 ⇒ 方法级窗口取到的是 3 行的空壳 doGet，规则必然不命中。
        **sink 行号不可信，方法级窗口的前提不成立。**

    类级窗口 + deny_all 语义是安全的组合：
        - deny_all（如 `new Random(` / `Math.random(`）保证「文件里同时存在危险写法」
          时**不抑制** ⇒ 真实项目里一个文件既有 SecureRandom 又有 Random 时保守放过；
        - 全类只覆盖**一个漏洞类**（OWASP 一个用例一个类），不存在「把别处的
          安全实现当成本文件安全实现」的跨类误杀——这与 safe_patterns 在
          多漏洞真实项目里担心的场景不同。
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _window_of(sink_file: str, sink_line: Optional[int], code_root: str = "",
               file_index: Optional[Dict[str, list]] = None) -> str:
    """解析源文件并取类级窗口。"""
    resolved = ""
    try:
        resolved = _resolve_abs(sink_file, file_index)
    except Exception:
        resolved = ""
    if not resolved and sink_file and code_root and not os.path.isabs(sink_file):
        cand = os.path.join(code_root, sink_file)
        if os.path.isfile(cand):
            resolved = cand
    if not resolved or not os.path.isfile(resolved):
        return ""
    try:
        return _class_window(resolved)
    except Exception:
        return ""


def probe_family(family: str, sink_file: str = "", sink_line: Optional[int] = None,
                 snippet: str = "", code_root: str = "",
                 file_index: Optional[Dict[str, list]] = None) -> Dict[str, Any]:
    """诊断用：按指定族的规则直接判定，**不受准入白名单限制**。

    与 judge_spec 的区别只有一处：judge_spec 只查 ``_ENABLED_SAFE_FAMILIES``
    里已准入的族，probe_family 把该族在 ``_SAFE_RULES`` 里的规则也一并查出来。
    用途是「准入决策的数据化」：先 survey 全族拿到每条规则的 FP/TP 真实账，
    再决定谁进白名单，而不是拍脑袋或凭真值口径的单次 lift 决定
    （真值口径与平台口径在 xss 上就出现了相反结论：真值 62FP/0TP，平台 62FP/2TP）。

    准入门禁的正确判据是项目既有的 **TPR 降 ≤3pp**（见 safe_patterns 模块头），
    不是「绝对零 TP 损失」——后者过苛，会把大量安全可用的规则挡在门外：
    远在门限内，净收益极高。
    """
    out = judge_spec(family=family, sink_file=sink_file, sink_line=sink_line,
                     snippet=snippet, code_root=code_root, file_index=file_index)
    if out["suppressed"] or out.get("positive_rule"):
        return out
    fam = _canon_family(family or "")
    rules = _SAFE_RULES.get(fam) or ()
    if not rules or fam in _ENABLED_SAFE_FAMILIES:
        return out
    window = _window_of(sink_file, sink_line, code_root=code_root, file_index=file_index)
    if not window:
        return out
    try:
        hit = _match_rules(rules, window)
    except Exception:  # pragma: no cover
        return out
    if hit:
        out.update(suppressed=True, rule=hit, source="probe")
    return out


def judge_spec(family: str, sink_file: str = "", sink_line: Optional[int] = None,
               snippet: str = "", code_root: str = "",
               file_index: Optional[Dict[str, list]] = None) -> Dict[str, Any]:
    """裁决单条 trigger_spec。

    返回：
        {"suppressed": bool,           是否应抑制（不进检出集合）
         "rule": str,                  命中的规则名（可审计）
         "source": str,                判定依据来源：safe_patterns / extra / none
         "confidence_boost": float,    正向证据带来的 confidence 提升（0.0 表示无）
         "positive_rule": str}         命中的正向证据规则名

    **fail-open**：任何异常都返回「不抑制」，宁可漏抑制不误杀。
    """
    out = {"suppressed": False, "rule": "", "source": "none",
           "confidence_boost": 0.0, "positive_rule": "",
           # 代码能力证据给出的族（族标错的纠正依据，见 capability_judge 模块头）
           "capability_family": "", "capability_evidence": []}
    fam = _canon_family(family or "")
    if not fam:
        return out

    # window 必须在 try 外初始化：① 里任何一步抛异常（路径解析、读文件）时
    # ②/②b 仍要能拿到 window 的空值走 fail-open，而不是 UnboundLocalError
    # 把整条裁决掀翻。
    window = ""
    try:
        # ① 主路径：用**方法级窗口**查 safe_patterns 的同一张规则表。
        #    不走 safe_implementation_hit，因为它内部写死了 ±15 行固定窗口，
        #    实测会把 secure_random_only 的命中量从 226 砍到 2（规则形同虚设）。
        #    规则表与匹配语义仍然复用（_SAFE_RULES + _match_rules，含 IGNORECASE），
        #    只把「证据范围」从固定行数换成方法体，不产生第二套规则。
        window = _window_of(sink_file, sink_line, code_root=code_root, file_index=file_index)
        if window:
            rules = _SAFE_RULES.get(fam) or ()
            if fam in _ENABLED_SAFE_FAMILIES:
                hit = _match_rules(rules, window) if rules else None
                if hit and not _vetoed_by_capability(fam, window):
                    out.update(suppressed=True, rule=hit, source="safe_patterns:class_window")
                    return out
        else:
            # 源文件读不到（路径解析失败 / 无 code_root）→ 退到 A1 的 snippet 判定。
            # 仍然 fail-open：读不到证据就不抑制。
            hit = safe_implementation_hit(
                family, file_path=sink_file or "", line=sink_line,
                snippet=snippet or "", file_index=file_index,
            )
            if hit:
                out.update(suppressed=True, rule=hit, source="safe_patterns:snippet")
                return out
    except Exception as exc:  # pragma: no cover
        logger.warning("[safe-verdict] safe_patterns 判定异常（不抑制）：%s", exc)

    # ①b 代码能力证据给出的族（**不改族**，只是把证据留下来）。
    #     族标签来自 A1/A2，会标错；实测检出用例里 17.3% 的族与真实类别完全对不上
    #     （典型：弱随机数被标成 broken_access_control）。但能力族单独用也只有
    #     其中 391 个能力族是对的，两者都错 0 个）。
    #     所以正确做法不是二选一改写，而是两个族一起交给用户。
    if window:
        try:
            from src.core.capability_judge import capability_family_of as _cap_family_of

            _cf, _ce = _cap_family_of(window)
            out["capability_family"] = _cf
            out["capability_evidence"] = list(_ce)
        except Exception as exc:  # pragma: no cover
            logger.warning("[safe-verdict] 能力识别异常（忽略）：%s", exc)

    # ② 附加抑制规则（族无关的通用安全实现判据）
    extra = _EXTRA_RULES.get(fam)
    if extra and window:
        try:
            hit = _match(extra, window)
            if hit and not _vetoed_by_capability(fam, window):
                out.update(suppressed=True, rule=hit, source="extra")
                return out
        except Exception as exc:  # pragma: no cover
            logger.warning("[safe-verdict] 附加规则判定异常（不抑制）：%s", exc)

    # ②b 通用判据：流到 sink 的值是否**根本不可能**被攻击者控制。
    #     只对「输入驱动族」生效（weak_hash 这类只看 API 选择的族不适用 ——
    #     用 MD5 哈希一个常量仍然是漏洞）。见 src/core/untaint.py 的模块头。
    if window:
        try:
            from src.core.untaint import untainted_value as _untainted

            ok, rule = _untainted(window, family=fam, code_root=code_root or "")
            if ok and not _vetoed_by_capability(fam, window):
                out.update(suppressed=True, rule=rule, source="untaint")
                return out
        except Exception as exc:  # pragma: no cover
            logger.warning("[safe-verdict] untaint 判定异常（不抑制）：%s", exc)

    # ③ 正向证据 → 置信度分层（方案 3）
    pos = _POSITIVE_RULES.get(fam)
    if pos:
        text = (snippet or "") + "\n" + (window or "")
        try:
            hit = _match(pos, text)
            if hit:
                out.update(confidence_boost=_POSITIVE_BOOST, positive_rule=hit)
        except Exception as exc:  # pragma: no cover
            logger.warning("[safe-verdict] 正向证据判定异常（忽略）：%s", exc)
    return out
