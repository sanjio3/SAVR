"""
CVE 关联模块
从漏洞特征匹配已知 CVE 编号
"""
import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CVEMatcher:
    """CVE 关联匹配器"""

    # 漏洞类型到 CVE 模式的映射
    # 格式: {漏洞类型: [(正则模式, CVE前缀)]}
    CVE_PATTERNS = {
        # SQL Injection
        "sql injection": [
            (r"(?i)select.*from.*where.*\+", "CVE-2012-2122"),  # MySQL 认证绕过
            (r"(?i)union.*select", "CVE-2012-2122"),
            (r"(?i)executeQuery.*\+", "CVE-2021-21311"),  # SQLi in MyBatis
        ],
        # XSS
        "xss": [
            (r"(?i)innerHTML", "CVE-2020-11022"),  # jQuery XSS
            (r"(?i)dangerouslySetInnerHTML", "CVE-2021-23337"),
            (r"(?i)response\.write.*\+", "CVE-2021-23337"),
        ],
        # Command Injection
        "command injection": [
            (r"(?i)exec\(.*request", "CVE-2021-44228"),  # Log4Shell 相关
            (r"(?i)Runtime\.getRuntime\(\)\.exec", "CVE-2020-1945"),  # Apache ShenYu
            (r"(?.i)process\.spawn", "CVE-2021-23337"),
        ],
        # Deserialization
        "deserialization": [
            (r"(?i)ObjectInputStream", "CVE-2020-1945"),
            (r"(?i)readObject", "CVE-2020-1945"),
            (r"(?i)pickle\.load", "CVE-2021-23337"),
            (r"(?i)yaml\.load.*Loader=None", "CVE-2020-1744"),
        ],
        # SSRF
        "ssrf": [
            (r"(?i)urlopen", "CVE-2021-22946"),
            (r"(?i)requests\.get.*url", "CVE-2021-23337"),
            (r"(?i)curl_exec", "CVE-2016-5385"),
        ],
        # Path Traversal
        "path traversal": [
            (r"(?i)open\(.*\+", "CVE-2021-23337"),
            (r"(?i)send_file.*\+", "CVE-2019-5418"),
            (r"(?i)FileInputStream", "CVE-2020-1945"),
        ],
        # XXE
        "xxe": [
            (r"(?i)DocumentBuilder", "CVE-2021-21346"),
            (r"(?i)XMLReader", "CVE-2016-3706"),
            (r"(?i)SAXParser", "CVE-2021-21346"),
        ],
        # File Upload
        "file upload": [
            (r"(?i)move_uploaded_file", "CVE-2021-23337"),
            (r"(?i)multipart.*file", "CVE-2018-20657"),
        ],
        # Template Injection
        "template injection": [
            (r"(?i)render_template_string", "CVE-2021-23337"),
            (r"(?i)freemarker.*\+", "CVE-2020-1947"),
            (r"(?i)velocity.*\+", "CVE-2020-13933"),
        ],
    }

    # 常见框架/组件到 CVE 的映射
    FRAMEWORK_CVES = {
        # Spring
        "spring": [
            "CVE-2022-22965",  # Spring4Shell
            "CVE-2021-22096",
            "CVE-2021-22144",
        ],
        # Struts
        "struts": [
            "CVE-2020-17530",
            "CVE-2019-0230",
            "CVE-2017-5638",
        ],
        # Log4j
        "log4j": [
            "CVE-2021-44228",  # Log4Shell
            "CVE-2021-45046",
        ],
        # Fastjson
        "fastjson": [
            "CVE-2020-26116",
            "CVE-2020-26142",
        ],
        # Jackson
        "jackson": [
            "CVE-2020-36518",
            "CVE-2019-14379",
        ],
        # Django
        "django": [
            "CVE-2021-44420",
            "CVE-2021-32803",
        ],
        # Flask
        "flask": [
            "CVE-2021-23337",
            "CVE-2021-32672",
        ],
        # jQuery
        "jquery": [
            "CVE-2020-11022",
            "CVE-2020-11023",
        ],
        # React
        "react": [
            "CVE-2021-23337",  # 通用
        ],
    }

    def __init__(self):
        self.cve_cache = {}
        self.matched_cves = []

    def match_cve(self, vuln_type: str, code_snippet: str, file_path: str = "") -> List[Dict]:
        """
        从漏洞代码匹配已知 CVE

        Args:
            vuln_type: 漏洞类型
            code_snippet: 漏洞代码片段
            file_path: 文件路径

        Returns:
            匹配到的 CVE 列表
        """
        matched_cves = []

        # 1. 从代码模式匹配
        type_lower = vuln_type.lower()
        patterns = self.CVE_PATTERNS.get(type_lower, [])

        for pattern, cve_id in patterns:
            try:
                if re.search(pattern, code_snippet):
                    matched_cves.append({
                        "cve_id": cve_id,
                        "match_type": "code_pattern",
                        "matched_pattern": pattern,
                        "confidence": "high" if len(code_snippet) > 50 else "medium"
                    })
            except re.error as exc:
                logger.warning("Skipping invalid CVE regex pattern %r for %s: %s", pattern, cve_id, exc)

        # 2. 从文件路径/框架匹配
        path_lower = (file_path + " " + code_snippet).lower()

        for framework, cve_list in self.FRAMEWORK_CVES.items():
            if framework in path_lower:
                for cve_id in cve_list:
                    # 避免重复
                    if not any(m['cve_id'] == cve_id for m in matched_cves):
                        matched_cves.append({
                            "cve_id": cve_id,
                            "match_type": "framework",
                            "framework": framework,
                            "confidence": "medium"
                        })

        return matched_cves

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        获取 CVE 详细信息（模拟数据，实际可对接 NVD API）

        Args:
            cve_id: CVE 编号

        Returns:
            CVE 详情字典
        """
        # 模拟 CVE 数据
        cve_data = {
            "CVE-2021-44228": {
                "name": "Log4Shell",
                "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "severity": "CRITICAL",
                "cvss": 10.0,
                "affected": "Log4j 2.0-beta9 to 2.14.1",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                ]
            },
            "CVE-2022-22965": {
                "name": "Spring4Shell",
                "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding on JDK 9+.",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "affected": "Spring Framework 5.3.0 to 5.3.17",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
                ]
            },
            "CVE-2020-11022": {
                "name": "jQuery XSS",
                "description": "In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute arbitrary code.",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "affected": "jQuery 1.2 to 3.4.1",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"
                ]
            },
            "CVE-2021-23337": {
                "name": "Command Injection in Python Frameworks",
                "description": " urllib.parse insecure usage of untrusted data in Python web frameworks.",
                "severity": "HIGH",
                "cvss": 8.1,
                "affected": "Flask, Django, Pyramid",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
                ]
            },
        }

        return cve_data.get(cve_id)

    def match_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        为漏洞列表匹配 CVE

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            带 CVE 信息的漏洞列表
        """
        results = []

        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            code_snippet = vuln.get('code_snippet', '')
            file_path = vuln.get('file', '')

            # 匹配 CVE
            matched = self.match_cve(vuln_type, code_snippet, file_path)

            # 获取详细信息
            for match in matched:
                details = self.get_cve_details(match['cve_id'])
                if details:
                    match.update(details)

            # 添加到结果
            vuln_with_cve = vuln.copy()
            vuln_with_cve['cve_matches'] = matched

            results.append(vuln_with_cve)

        return results


def match_cve_by_fingerprint(code_snippet: str, vuln_type: str = "") -> Tuple[str, float]:
    """
    快速匹配函数 - 根据代码指纹返回最可能的 CVE

    Args:
        code_snippet: 代码片段
        vuln_type: 漏洞类型

    Returns:
        (最可能的CVE编号, 置信度)
    """
    matcher = CVEMatcher()

    # 扩展类型匹配
    extended_type = vuln_type.lower()
    if "sql" in extended_type:
        extended_type = "sql injection"
    elif "command" in extended_type or "cmd" in extended_type:
        extended_type = "command injection"
    elif "deserialize" in extended_type:
        extended_type = "deserialization"
    elif "template" in extended_type or "ssti" in extended_type:
        extended_type = "template injection"

    patterns = matcher.CVE_PATTERNS.get(extended_type, [])

    best_match = (None, 0.0)
    for pattern, cve_id in patterns:
        if re.search(pattern, code_snippet):
            confidence = 0.8 if len(code_snippet) > 50 else 0.5
            if confidence > best_match[1]:
                best_match = (cve_id, confidence)

    return best_match
