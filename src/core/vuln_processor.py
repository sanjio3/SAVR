"""
漏洞结果合并与误报过滤模块
智能合并 A1 和 A2 的结果，并根据多种因素过滤误报
支持基于代码相似度的模糊去重
"""
import re
import logging
from typing import List, Dict, Set, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


def normalize_code(code: str) -> str:
    """
    标准化代码：去除空白、注释，得到纯净的代码用于相似度比较
    """
    if not code:
        return ""

    # 去除单行注释
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'#.*', '', code)

    # 去除多行注释
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)

    # 去除字符串字面量（替换为空字符串占位符）
    code = re.sub(r'"[^"]*"', '""', code)
    code = re.sub(r"'[^']*'", "''", code)

    # 去除多余空白
    code = re.sub(r'\s+', ' ', code)

    return code.strip()


def extract_ngrams(text: str, n: int = 3) -> Set[str]:
    """
    提取 n-gram 特征集合

    Args:
        text: 输入文本
        n: n-gram 大小，默认3

    Returns:
        n-gram 特征集合
    """
    text = text.lower()
    if len(text) < n:
        return {text} if text else set()

    ngrams = set()
    for i in range(len(text) - n + 1):
        ngrams.add(text[i:i+n])
    return ngrams


def calculate_jaccard_similarity(set1: Set, set2: Set) -> float:
    """
    计算 Jaccard 相似度

    Args:
        set1: 特征集合1
        set2: 特征集合2

    Returns:
        相似度分数 (0-1)
    """
    if not set1 or not set2:
        return 0.0

    intersection = len(set1 & set2)
    union = len(set1 | set2)

    return intersection / union if union > 0 else 0.0


def calculate_code_similarity(code1: str, code2: str) -> float:
    """
    计算两段代码的相似度 (0-1)

    使用 n-gram + Jaccard 相似度算法

    Args:
        code1: 代码片段1
        code2: 代码片段2

    Returns:
        相似度分数，范围 0-1
    """
    if not code1 or not code2:
        return 0.0

    # 标准化代码
    normalized1 = normalize_code(code1)
    normalized2 = normalize_code(code2)

    if not normalized1 or not normalized2:
        return 0.0

    # 提取 3-gram 特征
    ngrams1 = extract_ngrams(normalized1, n=3)
    ngrams2 = extract_ngrams(normalized2, n=3)

    # 计算 Jaccard 相似度
    similarity = calculate_jaccard_similarity(ngrams1, ngrams2)

    return similarity


def fuzzy_deduplicate(vulnerabilities: List[Dict], threshold: float = 0.7) -> List[Dict]:
    """
    模糊去重 - 允许近似匹配

    基于代码相似度进行去重，对于相似度高于阈值的漏洞进行合并

    Args:
        vulnerabilities: 漏洞列表
        threshold: 相似度阈值，默认 0.7

    Returns:
        去重后的漏洞列表
    """
    if not vulnerabilities:
        return []

    unique_vulns = []
    processed_indices = set()

    for i, vuln in enumerate(vulnerabilities):
        if i in processed_indices:
            continue

        # 将当前漏洞加入唯一列表
        unique_vulns.append(vuln)
        processed_indices.add(i)

        # 与后续漏洞比较
        code1 = vuln.get('code_snippet', '')

        for j in range(i + 1, len(vulnerabilities)):
            if j in processed_indices:
                continue

            vuln2 = vulnerabilities[j]
            code2 = vuln2.get('code_snippet', '')

            # 检查是否可能是同一漏洞
            # 1. 类型相同
            # 2. 文件相同或在相近位置
            # 3. 代码相似度高

            same_type = vuln.get('type') == vuln2.get('type')
            same_file = vuln.get('file') == vuln2.get('file')

            # 行号相近（10行以内）
            line_diff = abs(vuln.get('line', 0) - vuln2.get('line', 0)) <= 10

            # 如果类型相同且在同一文件或行号相近，才进行代码相似度比较
            if same_type and (same_file or line_diff):
                similarity = calculate_code_similarity(code1, code2)

                if similarity >= threshold:
                    # 标记为重复
                    processed_indices.add(j)

                    # 合并来源
                    sources = unique_vulns[-1].get('sources', [])
                    new_source = vuln2.get('source', '')
                    if new_source and new_source not in sources:
                        sources.append(new_source)
                    unique_vulns[-1]['sources'] = sources

                    # 合并描述（取更详细的）
                    desc1 = unique_vulns[-1].get('description', '')
                    desc2 = vuln2.get('description', '')
                    if len(desc2) > len(desc1):
                        unique_vulns[-1]['description'] = desc2

                    # 标记相似度信息
                    if 'similar_vulns' not in unique_vulns[-1]:
                        unique_vulns[-1]['similar_vulns'] = []
                    unique_vulns[-1]['similar_vulns'].append({
                        'file': vuln2.get('file'),
                        'line': vuln2.get('line'),
                        'similarity': similarity
                    })

    logger.info(f"Fuzzy deduplication: {len(vulnerabilities)} -> {len(unique_vulns)} (threshold: {threshold})")
    return unique_vulns


class VulnerabilityMerger:
    """漏洞结果合并与去重"""

    def __init__(self, similarity_threshold: float = 0.6):
        """
        Args:
            similarity_threshold: 相似度阈值，高于此值认为是同一漏洞
        """
        self.similarity_threshold = similarity_threshold

    def merge_results(self, a1_results: List[Dict], a2_results: List[Dict]) -> List[Dict]:
        """
        合并 A1 和 A2 的漏洞结果

        Args:
            a1_results: A1 规则扫描结果
            a2_results: A2 AI 扫描结果

        Returns:
            合并后的漏洞列表
        """
        all_vulns = []

        # 添加 A1 结果
        for r in a1_results:
            for v in r.get('vulnerabilities', []):
                vuln = dict(v)
                vuln['source'] = 'A1'
                vuln['file'] = r.get('file', '')
                all_vulns.append(vuln)

        # 添加 A2 结果
        for r in a2_results:
            for v in r.get('vulnerabilities', []):
                vuln = dict(v)
                vuln['source'] = 'A2'
                vuln['file'] = r.get('file', '')
                all_vulns.append(vuln)

        # 去重
        merged = self._deduplicate(all_vulns)

        logger.info(f"Merged {len(all_vulns)} vulns into {len(merged)} unique vulns")
        return merged

    def _deduplicate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """去重 - 使用精确匹配 + 模糊匹配"""
        # 第一轮：精确匹配去重
        unique_vulns = []
        seen_keys = set()

        # 按文件分组
        by_file = defaultdict(list)
        for v in vulnerabilities:
            file_path = v.get('file', '')
            by_file[file_path].append(v)

        # 在每个文件内去重
        for file_path, vulns in by_file.items():
            for vuln in vulns:
                key = self._generate_key(vuln)

                if key not in seen_keys:
                    seen_keys.add(key)
                    unique_vulns.append(vuln)
                else:
                    # 合并来源
                    for existing in unique_vulns:
                        if self._generate_key(existing) == key:
                            sources = existing.get('sources', [])
                            if 'A1' not in sources and vuln.get('source'):
                                sources.append(vuln['source'])
                            existing['sources'] = sources

                            # 合并描述（取更详细的）
                            if len(vuln.get('description', '')) > len(existing.get('description', '')):
                                existing['description'] = vuln['description']

                            break

        # 第二轮：模糊匹配去重（基于代码相似度）
        if self.similarity_threshold > 0:
            unique_vulns = fuzzy_deduplicate(unique_vulns, self.similarity_threshold)

        return unique_vulns

    def _generate_key(self, vuln: Dict) -> str:
        """生成唯一键"""
        # 使用文件、行号、类型生成键
        file_path = vuln.get('file', '')
        line = vuln.get('line', 0)
        vuln_type = vuln.get('type', '')

        return f"{file_path}:{line}:{vuln_type}"

    def calculate_confidence(self, vuln: Dict) -> float:
        """
        计算漏洞可信度

        Args:
            vuln: 漏洞信息

        Returns:
            可信度分数 (0-1)
        """
        confidence = 0.0

        # 来源数量
        sources = vuln.get('sources', [])
        if len(sources) >= 2:
            confidence += 0.4  # A1 和 A2 都报告
        elif len(sources) == 1:
            if sources[0] == 'A1':
                confidence += 0.2  # 规则匹配
            else:
                confidence += 0.3  # AI 分析

        # 严重程度
        severity = vuln.get('severity', '').upper()
        if severity == 'HIGH':
            confidence += 0.3
        elif severity == 'MEDIUM':
            confidence += 0.2
        elif severity == 'LOW':
            confidence += 0.1

        # 代码上下文检查
        code = vuln.get('code_snippet', '')
        if code:
            # 危险函数检查
            dangerous_patterns = [
                'executeQuery', 'executeUpdate', 'exec(', 'system(',
                'Runtime.getRuntime()', 'ProcessBuilder', 'eval(',
                'execSQL', 'Statement', 'PreparedStatement'
            ]
            for pattern in dangerous_patterns:
                if pattern.lower() in code.lower():
                    confidence += 0.2
                    break

        # 限制最大值为 1.0
        return min(confidence, 1.0)


class FalsePositiveFilter:
    """误报过滤器"""

    # 已知的误报模式
    FALSE_POSITIVE_PATTERNS = {
        'sql_injection': [
            r'//.*TODO.*',
            r'/\*.*TODO.*\*/',
            r'test',
            r'mock',
            r'Example',
            r'Sample',
            r'Demo',
            r'assertEquals.*\?',  # 测试代码
        ],
        'xss': [
            r'//.*TODO.*',
            r'test',
            r'mock',
            r'Example',
            r'UnitTest',
            r'\.setContentType\(',  # 设置了类型
        ],
        'command_injection': [
            r'//.*TODO.*',
            r'example',
            r'test',
            r'Runtime\.getRuntime\(\)',  # 需要检查实际调用
        ]
    }

    def __init__(self):
        self.filtered_count = 0

    def is_false_positive(self, vuln: Dict, context_lines: List[str] = None) -> Tuple[bool, str]:
        """
        判断是否为误报

        Args:
            vuln: 漏洞信息
            context_lines: 上下文代码行

        Returns:
            (是否为误报, 原因)
        """
        vuln_type = vuln.get('type', '').lower()
        code_snippet = vuln.get('code_snippet', '').lower()

        # 检查是否在测试代码中
        test_indicators = ['test', 'mock', 'example', 'demo', 'sample', 'unit']
        for indicator in test_indicators:
            if indicator in code_snippet:
                return True, f"Code appears to be test/example: {indicator}"

        # 检查是否有安全防护
        if self._has_security_mitigation(vuln, context_lines):
            return True, "Code has security mitigation"

        # 检查特定类型的误报模式
        for vtype, patterns in self.FALSE_POSITIVE_PATTERNS.items():
            if vtype in vuln_type:
                import re
                for pattern in patterns:
                    if re.search(pattern, code_snippet, re.IGNORECASE):
                        return True, f"Matched false positive pattern: {pattern}"

        return False, ""

    def _has_security_mitigation(self, vuln: Dict, context_lines: List[str] = None) -> bool:
        """检查是否有安全缓解措施"""
        code = vuln.get('code_snippet', '').lower()

        # SQL 注入防护
        if 'sql' in vuln.get('type', '').lower():
            safe_patterns = [
                'preparedstatement',
                'parameterized',
                'preparedstatement',
                'querybuilder',
                'mybatis',
                '#{',  # MyBatis 参数
                '${',  # 注意这个可能不安全
            ]
            for pattern in safe_patterns:
                if pattern in code:
                    return True

        # XSS 防护
        if 'xss' in vuln.get('type', '').lower():
            safe_patterns = [
                'escapehtml',
                'escapexml',
                'escapejavascript',
                'encoder.encodeforhtml',
                'th:text',
                'th:utext',  # Thymeleaf
                '@annotation',  # Spring
            ]
            for pattern in safe_patterns:
                if pattern in code:
                    return True

        # 命令注入防护
        if 'command' in vuln.get('type', '').lower():
            safe_patterns = [
                'whitelist',
                'allowlist',
                'validate',
                'sanitize',
            ]
            for pattern in safe_patterns:
                if pattern in code:
                    return True

        # 检查上下文
        if context_lines:
            context_text = '\n'.join(context_lines).lower()

            # 参数化查询
            if 'preparedstatement' in context_text or 'parameterized' in context_text:
                return True

            # 白名单验证
            if 'whitelist' in context_text or 'allowlist' in context_text:
                return True

        return False

    def filter_results(self, vulnerabilities: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        过滤误报

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            (有效漏洞, 误报列表)
        """
        valid_vulns = []
        false_positives = []

        for vuln in vulnerabilities:
            is_fp, reason = self.is_false_positive(vuln)

            if is_fp:
                vuln['filtered_reason'] = reason
                vuln['filtered'] = True
                false_positives.append(vuln)
                self.filtered_count += 1
                logger.debug(f"Filtered false positive: {vuln.get('file')}:{vuln.get('line')} - {reason}")
            else:
                valid_vulns.append(vuln)

        logger.info(f"Filtered {self.filtered_count} false positives from {len(vulnerabilities)} total")
        return valid_vulns, false_positives


class ResultGrouper:
    """结果分组器 - 按不同维度组织漏洞"""

    @staticmethod
    def group_by_severity(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """按严重程度分组"""
        groups = defaultdict(list)

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            groups[severity].append(vuln)

        return dict(groups)

    @staticmethod
    def group_by_type(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """按漏洞类型分组"""
        groups = defaultdict(list)

        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            groups[vuln_type].append(vuln)

        return dict(groups)

    @staticmethod
    def group_by_file(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """按文件分组"""
        groups = defaultdict(list)

        for vuln in vulnerabilities:
            file_path = vuln.get('file', 'unknown')
            groups[file_path].append(vuln)

        return dict(groups)

    @staticmethod
    def get_top_risks(vulnerabilities: List[Dict], top_n: int = 10) -> List[Dict]:
        """获取最高风险漏洞"""
        # 按严重程度和可信度排序
        severity_weight = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}

        scored = []
        for vuln in vulnerabilities:
            sev_weight = severity_weight.get(vuln.get('severity', 'UNKNOWN').upper(), 0)
            confidence = vuln.get('confidence', 0.5)
            score = sev_weight * confidence
            scored.append((score, vuln))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [v for _, v in scored[:top_n]]

    @staticmethod
    def cluster_by_similarity(vulnerabilities: List[Dict], threshold: float = 0.7) -> List[List[Dict]]:
        """
        按代码相似度聚类漏洞

        Args:
            vulnerabilities: 漏洞列表
            threshold: 相似度阈值

        Returns:
            漏洞簇列表，每个簇包含相似的漏洞
        """
        if not vulnerabilities:
            return []

        clusters = []
        processed = set()

        for i, vuln in enumerate(vulnerabilities):
            if i in processed:
                continue

            # 创建新簇
            cluster = [vuln]
            processed.add(i)

            code1 = vuln.get('code_snippet', '')

            # 查找相似的漏洞
            for j in range(i + 1, len(vulnerabilities)):
                if j in processed:
                    continue

                vuln2 = vulnerabilities[j]

                # 快速筛选：同类型 + 同文件或相近行号
                same_type = vuln.get('type') == vuln2.get('type')
                same_file = vuln.get('file') == vuln2.get('file')
                line_diff = abs(vuln.get('line', 0) - vuln2.get('line', 0)) <= 10

                if same_type and (same_file or line_diff):
                    code2 = vuln2.get('code_snippet', '')
                    similarity = calculate_code_similarity(code1, code2)

                    if similarity >= threshold:
                        cluster.append(vuln2)
                        processed.add(j)

                        # 记录相似度
                        vuln2['similarity_to_cluster'] = similarity

            clusters.append(cluster)

        logger.info(f"Clustered {len(vulnerabilities)} vulnerabilities into {len(clusters)} clusters")
        return clusters


def process_vulnerabilities(a1_results: List[Dict], a2_results: List[Dict]) -> Dict:
    """
    处理漏洞结果：合并、去重、过滤

    Args:
        a1_results: A1 扫描结果
        a2_results: A2 扫描结果

    Returns:
        处理后的结果字典
    """
    # 合并
    merger = VulnerabilityMerger()
    merged = merger.merge_results(a1_results, a2_results)

    # 计算可信度
    for vuln in merged:
        vuln['confidence'] = merger.calculate_confidence(vuln)

    # 过滤误报
    fp_filter = FalsePositiveFilter()
    valid_vulns, false_positives = fp_filter.filter_results(merged)

    # 分组统计
    grouper = ResultGrouper()
    by_severity = grouper.group_by_severity(valid_vulns)
    by_type = grouper.group_by_type(valid_vulns)
    top_risks = grouper.get_top_risks(valid_vulns)

    return {
        'all_vulnerabilities': merged,
        'valid_vulnerabilities': valid_vulns,
        'false_positives': false_positives,
        'by_severity': by_severity,
        'by_type': by_type,
        'top_risks': top_risks,
        'stats': {
            'total': len(merged),
            'valid': len(valid_vulns),
            'false_positives': len(false_positives),
            'high_severity': len(by_severity.get('HIGH', [])),
            'medium_severity': len(by_severity.get('MEDIUM', [])),
            'low_severity': len(by_severity.get('LOW', []))
        }
    }
