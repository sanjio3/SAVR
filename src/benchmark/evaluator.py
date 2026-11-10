"""
Benchmark 评估器
计算准确率、覆盖率等指标
"""
import logging
from typing import List, Dict, Set
from difflib import SequenceMatcher

from ..core.models import ScanResult, BenchmarkResult
from .ground_truth import get_ground_truth, count_total_vulnerabilities

logger = logging.getLogger(__name__)


class Evaluator:
    """Benchmark 评估器"""

    def __init__(self):
        self.ground_truth = get_ground_truth()

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """标准化漏洞类型名称"""
        type_map = {
            'sql injection': 'SQL Injection',
            'sqli': 'SQL Injection',
            'sql': 'SQL Injection',
            'command injection': 'Command Injection',
            'cmd injection': 'Command Injection',
            'rce': 'Command Injection',
            'xxe': 'XXE',
            'ssrf': 'SSRF',
            'server-side request forgery': 'SSRF',
            'path traversal': 'Path Traversal',
            'directory traversal': 'Path Traversal',
            'xss': 'XSS',
            'cross-site scripting': 'XSS',
            'deserialization': 'Deserialization',
            'insecure deserialization': 'Deserialization',
            'file upload': 'File Upload',
            'upload': 'File Upload',
            'url redirect': 'URL Redirect',
            'open redirect': 'URL Redirect',
            'redirect': 'URL Redirect',
            'spel injection': 'SpEL Injection',
            'spel': 'SpEL Injection',
            'ssti': 'SSTI',
            'template injection': 'SSTI',
            'ognl injection': 'OGNL Injection',
            'ognl': 'OGNL Injection',
            'jsonp': 'JSONP',
            'crlf injection': 'CRLF Injection',
            'crlf': 'CRLF Injection',
            'jwt': 'JWT',
            'xstream': 'XStream RCE',
            'xstream rce': 'XStream RCE',
            'log4j': 'Log4j RCE',
            'ldap injection': 'LDAP Injection',
            'ldap': 'LDAP Injection',
            'xpath injection': 'XPath Injection',
            'xpath': 'XPath Injection',
            'qlexpress': 'QLExpress Injection',
        }

        normalized = vuln_type.lower().strip()
        return type_map.get(normalized, vuln_type)

    def _is_match(self, detected_type: str, expected_types: List[str]) -> bool:
        """判断检测到的漏洞类型是否匹配预期"""
        normalized_detected = self._normalize_vuln_type(detected_type)

        for expected in expected_types:
            normalized_expected = self._normalize_vuln_type(expected)

            # 完全匹配
            if normalized_detected == normalized_expected:
                return True

            # 包含匹配
            if normalized_expected in normalized_detected or normalized_detected in normalized_expected:
                return True

        return False

    def evaluate(self, results: List[ScanResult], agent: str = 'a1') -> BenchmarkResult:
        """
        评估扫描结果

        Args:
            results: 扫描结果列表
            agent: 'a1' 或 'a2'

        Returns:
            BenchmarkResult
        """
        result = BenchmarkResult()
        result.total_vulnerabilities = count_total_vulnerabilities()

        # 统计检测到的漏洞
        detected_vulns = {}  # {filename: [vuln_types]}

        for scan_result in results:
            if scan_result.error:
                continue

            filename = scan_result.file
            # 标准化路径分隔符
            filename = filename.replace('\\', '/')

            # 提取文件名作为 key
            for key in self.ground_truth:
                if key in filename or filename in key:
                    if key not in detected_vulns:
                        detected_vulns[key] = []
                    for vuln in scan_result.vulnerabilities:
                        detected_vulns[key].append(vuln.type)

        # 计算 TP, FP, FN
        matched_vulns = set()  # (filename, vuln_type)

        for filename, detected_types in detected_vulns.items():
            expected_types = self.ground_truth.get(filename, [])

            for detected in detected_types:
                is_matched = False
                for expected in expected_types:
                    if self._is_match(detected, [expected]):
                        is_matched = True
                        matched_vulns.add((filename, detected))
                        break

                if agent == 'a1':
                    if is_matched:
                        result.a1_true_positive += 1
                    else:
                        result.a1_false_positive += 1
                else:
                    if is_matched:
                        result.a2_true_positive += 1
                    else:
                        result.a2_false_positive += 1

        # 计算检测总数
        if agent == 'a1':
            result.a1_detected = result.a1_true_positive + result.a1_false_positive
            result.a1_false_negative = result.total_vulnerabilities - result.a1_true_positive
        else:
            result.a2_detected = result.a2_true_positive + result.a2_false_positive
            result.a2_false_negative = result.total_vulnerabilities - result.a2_true_positive

        logger.info(f"Evaluation for {agent}: TP={result.a1_true_positive if agent == 'a1' else result.a2_true_positive}, "
                   f"FP={result.a1_false_positive if agent == 'a1' else result.a2_false_positive}, "
                   f"FN={result.a1_false_negative if agent == 'a1' else result.a2_false_negative}")

        return result

    def evaluate_combined(self, a1_results: List[ScanResult], a2_results: List[ScanResult]) -> Dict[str, BenchmarkResult]:
        """
        评估 A1 和 A2 的组合结果

        Returns:
            Dict with 'a1', 'a2' keys
        """
        return {
            'a1': self.evaluate(a1_results, 'a1'),
            'a2': self.evaluate(a2_results, 'a2')
        }
