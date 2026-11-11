"""族分类 → CWE 对齐。

## 为什么做

的目录布局**长出来的：`/sqli-00/`、`/crypto-00/` 这类路由段既是真实 URL，也是族标签。
两个后果：

2. **报告口径绑定靶场** —— 对外交付时说「sql_injection」不如说「CWE-89」通用。


## 本模块职责

- `FAMILY_TO_CWE`：内部族 → CWE 编号（一个族可对应多个 CWE，取主 CWE）。
- `family_to_cwe(family)`：族名 → "CWE-89" 形式；未知族返回空串（**不猜**）。
- `case_to_cwe_from_csv(csv_path)`：从 expectedresults CSV 建 case → CWE 映射
  （case 级最精确，优先于族级）。
- `cwe_of(vuln)`：综合入口 —— 有 case 号走 case 级，否则走族级。

## 纪律

- 未知族**返回空串**而不是瞎猜一个 CWE（错误的 CWE 比没有更糟）。
- 本模块只做**输出口径**的对齐，**不参与任何判定**（不改 verdict、不改门禁方向），
  避免「换了 CWE 口径就改变了检测结果」。
"""
from __future__ import annotations

import csv
import os
import re
from typing import Any, Dict, Optional

_CASE_RE = re.compile(r"BenchmarkTest\d+")

# 内部族 → 主 CWE（辅 CWE 以元组给出，第一个为主）
FAMILY_TO_CWE: Dict[str, Any] = {
    "sql_injection": (89,),
    "sqli": (89,),
    "xss": (79,),
    "path_traversal": (22,),
    "pathtraver": (22,),
    "command_execution": (78,),
    "cmdi": (78,),
    "ldap_injection": (90,),
    "ldapi": (90,),
    "xpathi": (643,),
    "xpath_injection": (643,),
    "xxe": (611,),
    "ssrf": (918,),
    "weak_hash": (328,),
    "hash": (328,),
    "weak_crypto": (327,),
    "insecure_crypto_algorithm": (327,),
    "crypto": (327,),
    "weak_random": (338,),
    "random": (338,),
    "secure_cookie": (614,),
    "securecookie": (614,),
    "http response splitting": (113,),
    "response_splitting": (113,),
    "stack trace exposure": (209,),
    "error message exposure": (209,),
    "trust_boundary_violation": (862,),
    "trustbound": (862,),
    "format_string": (134,),
    "tainted format string": (134,),
    "expression_language": (917,),
    "server_side_template_injection": (1336,),
    "csrf": (352,),
    "deserialization": (502,),
    "open_redirect": (601,),
    "xxe_injection": (611,),
}


def _norm(family: Any) -> str:
    return str(family or "").strip().lower().replace("-", "_").replace(" ", "_")


def family_to_cwe(family: Any) -> str:
    """族名 → "CWE-89" 形式。未知族返回空串（不猜）。"""
    f = _norm(family)
    if not f:
        return ""
    cwes = FAMILY_TO_CWE.get(f)
    if not cwes:
        # 「insecure crypto algorithm」这类带空格/多词的族名再试一次
        cwes = FAMILY_TO_CWE.get(str(family or "").strip().lower())
    if not cwes:
        return ""
    return "CWE-%d" % int(cwes[0])


def cwe_list(family: Any) -> list:
    """族名 → 全部 CWE（["CWE-89", ...]）；未知返回空列表。"""
    f = _norm(family)
    cwes = FAMILY_TO_CWE.get(f) or FAMILY_TO_CWE.get(str(family or "").strip().lower())
    if not cwes:
        return []
    return ["CWE-%d" % int(c) for c in cwes]


def case_to_cwe_from_csv(csv_path: str) -> Dict[str, str]:
    """从 expectedresults CSV 建 case → "CWE-nn" 映射。

    兼容两种表头：
    """
    out: Dict[str, str] = {}
    if not csv_path or not os.path.isfile(csv_path):
        return out
    with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
        sample = fh.readline()
        fh.seek(0)
        has_header = sample.lstrip().startswith("#") is False and "," in sample \
            and not sample.split(",")[0].strip().startswith("BenchmarkTest")
        reader = csv.reader(fh)
        if has_header:
            head = [h.strip().lower() for h in next(reader)]
            try:
                ti = head.index("test name") if "test name" in head else head.index("test")
            except ValueError:
                ti = 0
            ci = next((i for i, h in enumerate(head) if h.startswith("cwe")), None)
            for row in reader:
                if len(row) <= max(ti, ci or 0):
                    continue
                m = _CASE_RE.search(row[ti])
                if not m or ci is None:
                    continue
                cwe_raw = row[ci].strip()
                if not cwe_raw:
                    continue
                if cwe_raw.upper().startswith("CWE-"):
                    cwe_raw = cwe_raw[4:]
                digits = re.sub(r"\D", "", cwe_raw)
                if digits:
                    out[m.group(0)] = "CWE-%s" % digits
        else:
            for row in reader:
                if len(row) < 4:
                    continue
                m = _CASE_RE.search(row[0])
                if not m:
                    continue
                digits = re.sub(r"\D", "", row[3])
                if digits:
                    out[m.group(0)] = "CWE-%s" % digits
    return out


def cwe_of(vuln: Optional[Dict[str, Any]], case_map: Optional[Dict[str, str]] = None) -> str:
    """综合取 CWE：case 级优先（更精确），否则族级。取不到返回空串。"""
    if not isinstance(vuln, dict):
        return ""
    blob = " ".join(str(vuln.get(k) or "") for k in (
        "case", "test_name", "file", "file_path", "target_endpoint", "endpoint", "route"))
    m = _CASE_RE.search(blob)
    if m and case_map:
        c = case_map.get(m.group(0))
        if c:
            return c
    fam = vuln.get("family") or vuln.get("display_family") or vuln.get("type") or vuln.get("category")
    return family_to_cwe(fam)
