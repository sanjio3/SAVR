"""
Benchmark 报告生成器
"""
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict

from ..core.models import ScanResult, BenchmarkResult
from ..core.config import config


class Reporter:
    """报告生成器"""

    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir or config.get('output.output_dir', 'output'))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_results(self, a1_results: List[ScanResult], a2_results: List[ScanResult],
                     benchmark_result: Dict[str, BenchmarkResult], format: str = 'json'):
        """
        保存扫描结果

        Args:
            a1_results: A1 扫描结果
            a2_results: A2 扫描结果
            benchmark_result: 评估结果
            format: 输出格式
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if format == 'json':
            self._save_json(a1_results, a2_results, benchmark_result, timestamp)
        elif format == 'markdown':
            self._save_markdown(a1_results, a2_results, benchmark_result, timestamp)

    def _save_json(self, a1_results: List[ScanResult], a2_results: List[ScanResult],
                   benchmark_result: Dict[str, BenchmarkResult], timestamp: str):
        """保存 JSON 格式报告"""
        output = {
            'timestamp': timestamp,
            'a1_results': [r.to_dict() for r in a1_results],
            'a2_results': [r.to_dict() for r in a2_results],
            'benchmark': {
                'a1': benchmark_result['a1'].to_dict() if 'a1' in benchmark_result else {},
                'a2': benchmark_result['a2'].to_dict() if 'a2' in benchmark_result else {}
            }
        }

        output_file = self.output_dir / f'report_{timestamp}.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"JSON report saved to: {output_file}")

    def _save_markdown(self, a1_results: List[ScanResult], a2_results: List[ScanResult],
                       benchmark_result: Dict[str, BenchmarkResult], timestamp: str):
        """保存 Markdown 格式报告"""
        lines = []

        lines.append(f"# SAST AI Benchmark Report")
        lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"\n---\n")

        # 评估结果摘要
        lines.append("## Evaluation Summary")
        lines.append("\n| Metric | A1 (Rule) | A2 (AI) |")
        lines.append("|--------|-----------|---------|")

        a1_metrics = benchmark_result.get('a1')
        a2_metrics = benchmark_result.get('a2')

        if a1_metrics and a2_metrics:
            lines.append(f"| Total Ground Truth | {a1_metrics.total_vulnerabilities} | {a2_metrics.total_vulnerabilities} |")
            lines.append(f"| Detected | {a1_metrics.a1_detected} | {a2_metrics.a2_detected} |")
            lines.append(f"| True Positive | {a1_metrics.a1_true_positive} | {a2_metrics.a2_true_positive} |")
            lines.append(f"| False Positive | {a1_metrics.a1_false_positive} | {a2_metrics.a2_false_positive} |")
            lines.append(f"| False Negative | {a1_metrics.a1_false_negative} | {a2_metrics.a2_false_negative} |")
            lines.append(f"| **Precision** | **{a1_metrics.a1_precision:.2%}** | **{a2_metrics.a2_precision:.2%}** |")
            lines.append(f"| **Recall** | **{a1_metrics.a1_recall:.2%}** | **{a2_metrics.a2_recall:.2%}** |")
            lines.append(f"| **F1 Score** | **{a1_metrics.a1_f1:.2%}** | **{a2_metrics.a2_f1:.2%}** |")

        lines.append("\n---\n")

        # A1 详细结果
        lines.append("## A1 (Rule-based) Results")
        for result in a1_results:
            if result.vulnerabilities:
                lines.append(f"\n### {result.file}")
                for vuln in result.vulnerabilities:
                    lines.append(f"- **{vuln.type}** (Line {vuln.line}) - {vuln.description}")

        lines.append("\n---\n")

        # A2 详细结果
        lines.append("## A2 (AI-powered) Results")
        for result in a2_results:
            if result.vulnerabilities:
                lines.append(f"\n### {result.file}")
                for vuln in result.vulnerabilities:
                    lines.append(f"- **{vuln.type}** (Line {vuln.line}) - {vuln.description}")

        output_file = self.output_dir / f'report_{timestamp}.md'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        print(f"Markdown report saved to: {output_file}")

    def print_summary(self, benchmark_result: Dict[str, BenchmarkResult]):
        """打印摘要到控制台"""
        print("\n" + "=" * 60)
        print("BENCHMARK RESULTS")
        print("=" * 60)

        a1_metrics = benchmark_result.get('a1')
        a2_metrics = benchmark_result.get('a2')

        if a1_metrics:
            print(f"\n[A1 Rule-based Agent]")
            print(f"  Detected:    {a1_metrics.a1_detected}")
            print(f"  True Pos:    {a1_metrics.a1_true_positive}")
            print(f"  False Pos:   {a1_metrics.a1_false_positive}")
            print(f"  False Neg:   {a1_metrics.a1_false_negative}")
            print(f"  Precision:   {a1_metrics.a1_precision:.2%}")
            print(f"  Recall:     {a1_metrics.a1_recall:.2%}")
            print(f"  F1 Score:   {a1_metrics.a1_f1:.2%}")

        if a2_metrics:
            print(f"\n[A2 AI-powered Agent]")
            print(f"  Detected:    {a2_metrics.a2_detected}")
            print(f"  True Pos:    {a2_metrics.a2_true_positive}")
            print(f"  False Pos:   {a2_metrics.a2_false_positive}")
            print(f"  False Neg:   {a2_metrics.a2_false_negative}")
            print(f"  Precision:   {a2_metrics.a2_precision:.2%}")
            print(f"  Recall:      {a2_metrics.a2_recall:.2%}")
            print(f"  F1 Score:    {a2_metrics.a2_f1:.2%}")

        print("\n" + "=" * 60)
