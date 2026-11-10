"""安全实现负向模式（2026-09-26 F4 后精确率整改②）。

背景：OWASP benchmark 的 99 个 FP 全部是「同一危险 API 的安全实现」（安全编码、
参数化查询、SecureRandom、强哈希等）。平台此前只认「调用了危险 API」就报，
不识别该调用是否实际安全 → 精确率贴着真值占比 ≈53%（近掷硬币）。

本模块提供「命中已知安全实现 → 抑制该 finding」的确定性判定：
- 判据只认高特异性安全特征（PreparedStatement+绑定参数、ESAPI/Encoder 编码、
  SecureRandom、SHA-256+、setHttpOnly(true)+setSecure(true) 等），宁可漏抑制也不误杀
  （严格 TPR 降 ≤3pp 是硬约束）。
- 族名先经 normalize_family 归一，再查本表；未登记族不抑制（fail-open）。
- 证据源：finding 自带 code_snippet 优先，否则读源文件按 sink 行取方法窗口。
  两者皆缺时不抑制（无证据不杀人）。

只做抑制判定，不碰 findings 表（A1 出口处过滤，下游自然收窄）。
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.normalize import normalize_family

logger = logging.getLogger(__name__)

# 方法窗口半径：以 sink 行为中心上下各取 N 行作为安全特征扫描窗口。
#
# 2026-09-26 由 60 收敛到 15（实测，见 scripts/_sim_safe_patterns.py）：
# benchmark 用例文件普遍 <100 行，±60 等于「整文件判定」——一旦 sink 行号偏移到
# 注解/方法签名上（实测 BenchmarkTest00100 落在 @WebServlet 行、01552 落在 @Override 行），
# 窗口就会把文件别处的 PreparedStatement / SecureRandom 当成安全实现，误杀真漏洞。
# 窗口半径敏感性实测（掉 TP 用例数 / 掉 FP 用例数）：
#   6→0/1   10→0/3   15→0/4   20→0/5   30→1/8   60→3/11
# 取 15：零真漏洞损失，精确率 +1.2pp（54.7%→55.9%）。
_WINDOW = int(os.environ.get("SAST_AI_SAFE_PATTERN_WINDOW", "15") or 15)

# 每族安全特征规则：(规则名, 必须全部命中的正则组, 必须全部不命中的负向正则组)
# need_all=() 表示单特征即可；deny_all=() 表示无负向要求。
_SAFE_RULES: Dict[str, Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...]] = {
    "sql_injection": (
        ("prepared_statement_bound", (r"PreparedStatement", r"\.set(?:String|Int|Long|Double|Float|Date|Object|Boolean|Byte|Short|BigDecimal|Timestamp)\s*\("), ()),
    ),
    "xss": (
        ("encoder_present", (r"encodeForHTML|Encode\.forHtml(?:Content|UnquotedContent)?|HTMLEntityEncode|ESAPI\.encoder|escapeHtml4?|HtmlUtils\.htmlEscape|encodeForURL|Encode\.forJavaScript",), ()),
    ),
    "path_traversal": (
        ("canonical_prefix_check", (r"getCanonicalPath\s*\(", r"\.startsWith\s*\("), ()),
    ),
    "command_execution": (
        ("input_allowlist", (r"isLetterOrDigit|\.matches\s*\(\s*\"[^\"]*\"\s*\)|ALLOWED_|allowed_|whitelist|allowlist",), ()),
    ),
    "weak_crypto": (
        ("strong_cipher_only", (r"GCM|AES/GCM|PBKDF2|PBEWITH|ChaCha20|SHA-?256|SHA-?512|SHA256|SHA512",), (r"\bDES\b|\bRC4\b|\bMD5\b|SHA-?1\b|Blowfish|ARC4",)),
    ),
    "weak_hash": (
        ("strong_digest_only", (r"SHA-?(?:256|384|512)|SHA256|SHA512|SHA3|PBKDF2",), (r"\bMD5\b|\bMD4\b|SHA-?1\b",)),
    ),
    "weak_random": (
        ("secure_random_only", (r"SecureRandom",), (r"new\s+Random\s*\(|Math\.random\s*\(",)),
    ),
    "secure_cookie": (
        ("httponly_and_secure", (r"setHttpOnly\s*\(\s*true\s*\)", r"setSecure\s*\(\s*true\s*\)"), ()),
    ),
    "trust_boundary_violation": (
        ("validated_before_store", (r"Pattern\.matches\s*\(|\.matches\s*\(\s*\"[^\"]*\"\s*\)|sanitize|whitelist|allowlist",), ()),
    ),
    "ldap_injection": (
        ("ldap_encoder", (r"encodeForLDAP|LDAPEncoder|escapeDN",), ()),
    ),
    "xxe": (
        ("doctype_disallowed", (r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|accessExternal",), ()),
    ),
    # sensitive_data_exposure：静态侧无高特异性安全特征（靠运行时/配置判定），登记为空 = 永不抑制。
    "sensitive_data_exposure": (),
}


def _canon_family(family: str) -> str:
    try:
        return normalize_family(family)
    except Exception:
        return (family or "").strip().lower()


def build_file_index(files: Any) -> Dict[str, List[str]]:
    """用 A1 入参 files（绝对路径）建 basename → 绝对路径列表 索引。

    用途：CodeQL 告警的 file 来自 SARIF，是**相对项目根**的路径（如
    "src/main/java/.../BenchmarkTest00317.java"），A1 运行时 cwd 又不是项目根，
    直接 open(相对路径) 必然 OSError → _read_window 返回空 → fail-open 不抑制。
    实测这正是 safe_patterns 长期「看着生效、实际零抑制」的根因之一。
    """
    idx: Dict[str, List[str]] = {}
    for f in files or []:
        p = f.get("path") if isinstance(f, dict) else getattr(f, "path", None)
        if not p:
            continue
        norm = str(p).replace("\\", "/")
        idx.setdefault(os.path.basename(norm), []).append(str(p))
    return idx


def _resolve_abs(file_path: str, file_index: Optional[Dict[str, List[str]]]) -> str:
    """把（可能相对的）finding 路径解析成可读的绝对路径；失败返回空串。"""
    p = str(file_path or "").strip()
    if not p:
        return ""
    if os.path.isabs(p):
        return p if os.path.exists(p) else ""
    if os.path.exists(p):
        return os.path.abspath(p)
    if not file_index:
        return ""
    norm = p.replace("\\", "/")
    for cand in file_index.get(os.path.basename(norm), ()):
        if cand.replace("\\", "/").endswith(norm):
            return cand
    return ""


def _match_rules(rules, text: str) -> Optional[str]:
    for rule_name, need_all, deny_all in rules:
        try:
            if all(re.search(pat, text, re.IGNORECASE) for pat in need_all) and \
               not any(re.search(pat, text, re.IGNORECASE) for pat in deny_all):
                return rule_name
        except re.error:  # pragma: no cover
            continue
    return None


def _any_deny(rules, text: str) -> bool:
    """片段里出现任一负向特征（如 new Random( / Math.random( / MD5）→ 判定为「有危险证据」。"""
    for _rule_name, _need_all, deny_all in rules:
        for pat in deny_all:
            try:
                if re.search(pat, text, re.IGNORECASE):
                    return True
            except re.error:  # pragma: no cover
                continue
    return False


def _read_window(file_path: str, line: Optional[int]) -> str:
    """读源文件并返回以 line 为中心的窗口文本；失败返回空串（fail-open 不抑制）。"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    if not lines:
        return ""
    if not line:
        return "".join(lines[: _WINDOW * 2])
    lo = max(0, int(line) - 1 - _WINDOW)
    hi = min(len(lines), int(line) + _WINDOW)
    return "".join(lines[lo:hi])


def safe_implementation_hit(family: str, file_path: str = "", line: Optional[int] = None,
                            snippet: str = "",
                            file_index: Optional[Dict[str, List[str]]] = None) -> Optional[str]:
    """判定该 (family, 位置) 是否命中已知安全实现。

    返回命中的规则名（表示应抑制），未命中/无证据/未登记族返回 None。

    2026-09-26 修复「证据源」——原实现是 **snippet 优先**：只要 snippet 非空就永远
    不读源文件。而 A2 回填的 snippet 常是残缺片段（实测 BenchmarkTest00317 只有
    `String bar = thing.doSomething(param);`），既不含 SecureRandom 也不含 Random，
    于是规则既不能命中也不能否认 → 静默放行。叠加 file_path 是相对路径读不到窗口，
    实测 A1 出口抑制数恒为 0（规则表与接线都在，但从未生效）。

    新逻辑（保守优先，宁可漏抑制）：
      1) snippet 命中安全特征 → 抑制；
      2) snippet 命中负向特征（危险写法确实存在）→ 不抑制，且**不回退窗口**；
      3) snippet 既无正向也无负向（残缺片段）→ 回退读源文件窗口再判一次。
    """
    fam = _canon_family(family)
    rules = _SAFE_RULES.get(fam)
    if not rules:
        return None

    snip = (snippet or "").strip()
    if snip:
        hit = _match_rules(rules, snip)
        if hit:
            return hit
        if _any_deny(rules, snip):
            return None  # 片段里就带危险写法：有证据表明不安全，不再看窗口

    resolved = _resolve_abs(file_path, file_index)
    window = _read_window(resolved, line) if resolved else ""
    if not window:
        return None  # 无证据不杀人（fail-open，保召回）
    return _match_rules(rules, window)


def filter_vulnerabilities(vulns: List[Any],
                           file_index: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Any], List[Dict[str, str]]]:
    """对 Vulnerability 列表应用安全实现抑制。

    返回 (保留列表, 被抑制记录列表)。抑制记录含 family/file/line/rule，供审计与
    _last_scan_meta 上报。任何异常都 fail-open（异常条目原样保留）。
    """
    kept: List[Any] = []
    suppressed: List[Dict[str, str]] = []
    for v in vulns or []:
        try:
            fam = getattr(v, "type", "") or ""
            rule = safe_implementation_hit(
                fam,
                file_path=str(getattr(v, "file", "") or ""),
                line=getattr(v, "line", None),
                snippet=str(getattr(v, "code_snippet", "") or ""),
                file_index=file_index,
            )
            if rule:
                suppressed.append({
                    "family": _canon_family(fam),
                    "file": str(getattr(v, "file", "") or ""),
                    "line": str(getattr(v, "line", "") or ""),
                    "rule": rule,
                })
                continue
        except Exception as _e:  # pragma: no cover
            logger.warning("[safe-patterns] 抑制判定异常（保留该条）：%s", _e)
        kept.append(v)
    return kept, suppressed


def filter_scan_results(results: List[Any],
                        file_index: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Any], List[Dict[str, str]]]:
    """对 A1 的每文件 ScanResult 列表应用安全实现抑制（就地清空被抑制的 vulnerabilities）。

    file_index 由 build_file_index(files) 产出，用于把 SARIF 相对路径解析成可读绝对路径。
    """
    kept_results: List[Any] = []
    all_suppressed: List[Dict[str, str]] = []
    for r in results or []:
        vulns = list(getattr(r, "vulnerabilities", []) or [])
        kept, suppressed = filter_vulnerabilities(vulns, file_index=file_index)
        all_suppressed.extend(suppressed)
        try:
            r.vulnerabilities = kept
        except Exception:  # pragma: no cover
            pass
        kept_results.append(r)
    return kept_results, all_suppressed
