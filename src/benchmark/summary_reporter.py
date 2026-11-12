"""
总结性报告生成器
合并 A1/A2 结果，去重，生成最终报告
"""
from typing import List, Dict
from collections import defaultdict
from datetime import datetime
import logging

from ..core.models import ScanResult
from ..core.config import config

logger = logging.getLogger(__name__)


class SummaryReporter:
    """总结性报告生成器"""

    def __init__(self):
        self.output_dir = config.get('output.output_dir', 'output')

    def _normalize_vuln_key(self, vuln: Dict) -> str:
        """生成漏洞的唯一标识 key"""
        # 使用 文件名 + 漏洞类型 + 行号 的组合作为唯一标识
        file_path = vuln.get('file', '')
        # 提取文件名
        filename = file_path.split('/')[-1].split('\\')[-1]
        vuln_type = vuln.get('type', '')
        line = vuln.get('line', 0)

        return f"{filename}:{vuln_type}:{line}"

    def _is_same_vuln(self, v1: Dict, v2: Dict) -> bool:
        """判断两个漏洞是否是同一个"""
        # 同一文件、同一类型、同一行号
        f1 = v1.get('file', '').split('/')[-1].split('\\')[-1]
        f2 = v2.get('file', '').split('/')[-1].split('\\')[-1]

        return (f1 == f2 and
                v1.get('type', '').lower() == v2.get('type', '').lower() and
                abs(v1.get('line', 0) - v2.get('line', 0)) <= 3)  # 允许3行误差

    def merge_and_deduplicate(self, a1_results: List[ScanResult], a2_results: List[ScanResult],
                             d2_verifications: List[Dict]) -> Dict:
        """
        合并 A1、A2 结果，并进行去重

        Returns:
            {
                'total_vulns': int,
                'by_severity': {'HIGH': x, 'MEDIUM': y, 'LOW': z},
                'by_type': {'SQL Injection': x, ...},
                'by_file': {'file1.java': x, ...},
                'vulnerabilities': [
                    {
                        'file': str,
                        'type': str,
                        'line': int,
                        'severity': str,
                        'description': str,
                        'sources': ['A1', 'A2'],
                        'exploitable': str,
                        'confidence': str,
                        'test_payloads': [str]
                    }
                ],
                'statistics': {
                    'a1_only': int,  # 仅 A1 检测到
                    'a2_only': int,   # 仅 A2 检测到
                    'both': int,      # A1 和 A2 都检测到
                    'verified': int   # D2 验证为可利用
                }
            }
        """
        all_vulns = []

        # 收集 A1 结果
        for result in a1_results:
            if result.error:
                continue
            for vuln in result.vulnerabilities:
                all_vulns.append({
                    'file': result.file,
                    'type': vuln.type,
                    'line': vuln.line,
                    'severity': vuln.severity,
                    'description': vuln.description,
                    'source': 'A1',
                    'code_snippet': vuln.code_snippet
                })

        # 收集 A2 结果
        for result in a2_results:
            if result.error:
                continue
            for vuln in result.vulnerabilities:
                all_vulns.append({
                    'file': result.file,
                    'type': vuln.type,
                    'line': vuln.line,
                    'severity': vuln.severity,
                    'description': vuln.description,
                    'source': 'A2',
                    'code_snippet': vuln.code_snippet
                })

        # 去重
        unique_vulns = []

        for vuln in all_vulns:
            self._normalize_vuln_key(vuln)
            is_duplicate = False

            for seen_vuln in unique_vulns:
                if self._is_same_vuln(vuln, seen_vuln):
                    # 合并来源
                    if vuln['source'] not in seen_vuln['sources']:
                        seen_vuln['sources'].append(vuln['source'])
                    is_duplicate = True
                    break

            if not is_duplicate:
                vuln['sources'] = [vuln['source']]
                unique_vulns.append(vuln)

        # 添加 D2 验证结果
        for vuln in unique_vulns:
            # 查找对应的 D2 验证结果
            for verify in d2_verifications:
                if self._is_same_vuln(vuln, verify):
                    vuln['exploitable'] = verify.get('exploitable', 'Unknown')
                    vuln['confidence'] = verify.get('confidence', 'low')
                    vuln['reason'] = verify.get('reason', '')
                    vuln['test_payloads'] = verify.get('test_payloads', [])
                    break
            else:
                vuln['exploitable'] = 'Unknown'
                vuln['confidence'] = 'low'
                vuln['reason'] = '未经过 D2 动态验证'
                vuln['test_payloads'] = []

        # 统计
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        by_file = defaultdict(int)
        a1_only = 0
        a2_only = 0
        both = 0
        verified = 0

        for vuln in unique_vulns:
            severity = vuln.get('severity', 'UNKNOWN')
            by_severity[severity] += 1

            vuln_type = vuln.get('type', 'Unknown')
            by_type[vuln_type] += 1

            filename = vuln.get('file', '').split('/')[-1].split('\\')[-1]
            by_file[filename] += 1

            sources = vuln.get('sources', [])
            if 'A1' in sources and 'A2' in sources:
                both += 1
            elif 'A1' in sources:
                a1_only += 1
            elif 'A2' in sources:
                a2_only += 1

            if vuln.get('exploitable') in ['Likely', 'Yes']:
                verified += 1

        # D2 动态测试统计
        d2_stats = {
            'needs_runtime': 0,
            'exploitable_likely': 0,
            'exploitable_unlikely': 0,
            'mitigations_found': 0
        }
        for vuln in unique_vulns:
            if vuln.get('needs_runtime'):
                d2_stats['needs_runtime'] += 1
            if vuln.get('exploitable') == 'Likely':
                d2_stats['exploitable_likely'] += 1
            if vuln.get('exploitable') == 'Unlikely':
                d2_stats['exploitable_unlikely'] += 1
            if vuln.get('mitigations'):
                d2_stats['mitigations_found'] += 1

        return {
            'total_vulns': len(unique_vulns),
            'by_severity': dict(by_severity),
            'by_type': dict(by_type),
            'by_file': dict(by_file),
            'vulnerabilities': unique_vulns,
            'statistics': {
                'a1_only': a1_only,
                'a2_only': a2_only,
                'both': both,
                'verified': verified
            },
            'd2_stats': d2_stats
        }

    def generate_report(self, merged: Dict, output_file: str = None) -> str:
        """
        生成 Markdown 格式的报告

        Returns:
            报告内容
        """
        lines = []

        lines.append("# SAST AI 安全审计报告")
        lines.append("")
        lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # 执行摘要
        lines.append("## 执行摘要")
        lines.append("")
        lines.append(f"**总漏洞数**: {merged['total_vulns']}")
        lines.append("")

        # 统计
        stats = merged.get('statistics', {})
        lines.append("### 来源统计")
        lines.append("")
        lines.append(f"- 仅 A1 检测: {stats.get('a1_only', 0)}")
        lines.append(f"- 仅 A2 检测: {stats.get('a2_only', 0)}")
        lines.append(f"- A1 和 A2 均检测: {stats.get('both', 0)}")
        lines.append("")

        # D2 动态测试统计
        lines.append("### D2 动态测试结果")
        lines.append("")
        d2_stats = merged.get('d2_stats', {})
        lines.append(f"- 待运行时验证: {d2_stats.get('needs_runtime', 0)}")
        lines.append(f"- 评估为可利用 (Likely): {d2_stats.get('exploitable_likely', 0)}")
        lines.append(f"- 评估为不可利用 (Unlikely): {d2_stats.get('exploitable_unlikely', 0)}")
        lines.append(f"- 检测到缓解措施: {d2_stats.get('mitigations_found', 0)}")
        lines.append("")

        # 按严重程度
        lines.append("### 按严重程度")
        lines.append("")
        for severity in ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = merged['by_severity'].get(severity, 0)
            if count > 0:
                lines.append(f"- **{severity}**: {count}")
        lines.append("")

        # 按类型
        lines.append("### 按漏洞类型")
        lines.append("")
        for vuln_type, count in sorted(merged['by_type'].items(), key=lambda x: -x[1]):
            lines.append(f"- {vuln_type}: {count}")
        lines.append("")

        # 详细漏洞列表
        lines.append("## 详细漏洞列表")
        lines.append("")

        # 按文件分组
        by_file = merged.get('by_file', {})
        for filename in sorted(by_file.keys()):
            lines.append(f"### {filename}")
            lines.append("")

            for vuln in merged['vulnerabilities']:
                f = vuln.get('file', '').split('/')[-1].split('\\')[-1]
                if f != filename:
                    continue

                # 漏洞标题
                severity_icon = {'HIGH': '[H]', 'MEDIUM': '[M]', 'LOW': '[L]'}.get(vuln.get('severity', ''), '[?]')
                lines.append(f"#### {severity_icon} {vuln.get('type', 'Unknown')} (Line {vuln.get('line', 'N/A')})")
                lines.append("")

                # 基本信息
                lines.append(f"- **严重程度**: {vuln.get('severity', 'UNKNOWN')}")
                lines.append(f"- **来源**: {', '.join(vuln.get('sources', []))}")

                # D2 验证结果
                exploitable = vuln.get('exploitable', 'Unknown')
                if exploitable in ['Likely', 'Yes']:
                    lines.append(f"- **可利用性**: [OK] {exploitable}")
                elif exploitable == 'Unlikely':
                    lines.append(f"- **可利用性**: [FAIL] {exploitable}")
                else:
                    lines.append(f"- **可利用性**: [WARN] {exploitable}")

                lines.append(f"- **置信度**: {vuln.get('confidence', 'low')}")
                lines.append("")

                # 描述
                if vuln.get('description'):
                    lines.append("**描述**:")
                    lines.append("```")
                    lines.append(vuln.get('description', '')[:200])
                    lines.append("```")
                    lines.append("")

                # 验证理由
                if vuln.get('reason'):
                    lines.append(f"**分析**: {vuln.get('reason')}")
                    lines.append("")

                # 测试 Payload
                if vuln.get('test_payloads'):
                    lines.append("**测试 Payload**:")
                    for payload in vuln.get('test_payloads', [])[:3]:
                        lines.append(f"- `{payload}`")
                    lines.append("")

                lines.append("---")
                lines.append("")

        report = '\n'.join(lines)

        # 保存到文件
        if output_file:
            import os
            os.makedirs(self.output_dir, exist_ok=True)
            output_path = os.path.join(self.output_dir, output_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved to: {output_path}")

        return report

    def print_summary(self, merged: Dict):
        """打印摘要到控制台"""
        print("\n" + "=" * 60)
        print("SUMMARY REPORT")
        print("=" * 60)

        print(f"\n[TOTAL] Total Vulnerabilities: {merged['total_vulns']}")

        stats = merged.get('statistics', {})
        print(f"\n[STATS] Statistics:")
        print(f"   A1 only:     {stats.get('a1_only', 0)}")
        print(f"   A2 only:    {stats.get('a2_only', 0)}")
        print(f"   Both:       {stats.get('both', 0)}")
        print(f"   Verified:   {stats.get('verified', 0)}")

        print(f"\n[SEVERITY] By Severity:")
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            count = merged['by_severity'].get(severity, 0)
            print(f"   {severity}: {count}")

        print(f"\n[TYPES] Top Types:")
        for vuln_type, count in sorted(merged['by_type'].items(), key=lambda x: -x[1])[:5]:
            print(f"   {vuln_type}: {count}")

        print("\n" + "=" * 60)
