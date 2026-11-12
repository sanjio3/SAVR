"""
共享上下文 (Shared Context)
用于Agent间的状态共享和数据交换
"""
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
import json

from ..core.models import Vulnerability
from ..agents.r0_recon_agent import ProjectInfo as R0ProjectInfo

logger = logging.getLogger(__name__)


class ContextState(Enum):
    """上下文状态"""
    INITIAL = "initial"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    ERROR = "error"


# 使用R0 Agent的ProjectInfo
ProjectInfo = R0ProjectInfo


@dataclass
class AnalysisProgress:
    """分析进度"""
    a1_completed: bool = False
    a2_completed: bool = False
    d2_completed: bool = False
    current_phase: str = "initial"
    progress_percent: int = 0
    errors: List[str] = field(default_factory=list)


class SharedContext:
    """
    共享上下文

    用于Agent间共享:
    - 项目结构信息
    - 漏洞列表
    - Agent决策记录
    - 分析进度
    """

    def __init__(self, project_path: str = ""):
        self.project_path = project_path
        self.lock = threading.RLock()

        # 项目信息
        self.project_info = ProjectInfo(path=project_path)

        # 审计计划 (P0)
        self.audit_plan = None

        # 漏洞存储 - 按Agent分类
        self.vulnerabilities: Dict[str, List[Vulnerability]] = {
            'a1': [],
            'a2': [],
            'd2': []
        }

        # 合并后的漏洞列表
        self.merged_vulnerabilities: List[Vulnerability] = []

        # Agent决策记录
        self.agent_decisions: List[Dict] = []

        # 分析进度
        self.progress = AnalysisProgress()

        # 分析状态
        self.state = ContextState.INITIAL

        # 错误记录
        self.errors: List[Dict] = []

        # 统计信息
        self.stats: Dict[str, Any] = {}

        # D2执行信息 (策略、容器能力等)
        self.d2_metadata: Dict[str, Any] = {}

    def update_d2_metadata(self, strategy: str = "", capability: Dict = None, docker_available: bool = False):
        """
        更新D2元数据

        Args:
            strategy: 测试策略
            capability: 能力配置
            docker_available: Docker是否可用
        """
        with self.lock:
            self.d2_metadata = {
                'strategy': strategy,
                'capability': capability or {},
                'docker_available': docker_available
            }

    def update_project_info(self, key: str, value: Any):
        """更新项目信息"""
        with self.lock:
            if hasattr(self.project_info, key):
                setattr(self.project_info, key, value)

    def update_vulnerabilities(self, agent: str, vulns: List[Vulnerability]):
        """
        更新漏洞列表

        Args:
            agent: Agent名称 (a1/a2/d2)
            vulns: 漏洞列表
        """
        with self.lock:
            if agent in self.vulnerabilities:
                self.vulnerabilities[agent] = vulns
                logger.info(f"Updated {agent} vulnerabilities: {len(vulns)}")
            else:
                logger.warning(f"Unknown agent: {agent}")

    def add_vulnerability(self, agent: str, vuln: Vulnerability):
        """
        添加单个漏洞

        Args:
            agent: Agent名称
            vuln: 漏洞对象
        """
        with self.lock:
            if agent not in self.vulnerabilities:
                self.vulnerabilities[agent] = []
            self.vulnerabilities[agent].append(vuln)

    def get_vulnerabilities(self, agent: str = None) -> List[Vulnerability]:
        """
        获取漏洞列表

        Args:
            agent: Agent名称 (None表示所有)

        Returns:
            漏洞列表
        """
        with self.lock:
            if agent:
                return self.vulnerabilities.get(agent, []).copy()
            else:
                # 合并所有漏洞
                all_vulns = []
                for vulns in self.vulnerabilities.values():
                    all_vulns.extend(vulns)
                return all_vulns

    def merge_vulnerabilities(self) -> List[Vulnerability]:
        """
        合并漏洞列表 (去重) 并融合D2验证结果

        Returns:
            合并后的漏洞列表
        """
        with self.lock:
            seen = set()
            merged = []

            # 获取D2验证结果
            d2_decisions = self.get_decisions('d2')
            d2_results = {}
            for decision in d2_decisions:
                details = decision.get('details', {})
                canonical_key = details.get('canonical_group_key', '')
                if canonical_key:
                    d2_results[('canonical', canonical_key)] = details
                for match_key in details.get('match_keys', []) or []:
                    d2_results[('match', match_key)] = details
                key = (details.get('file_path', ''), details.get('line', 0), details.get('vuln_type', ''))
                d2_results[key] = details

            for agent, vulns in self.vulnerabilities.items():
                for vuln in vulns:
                    # 创建唯一标识
                    key = (vuln.file, vuln.line, vuln.type)
                    lookup_keys = []
                    if vuln.canonical_group_key:
                        lookup_keys.append(('canonical', vuln.canonical_group_key))
                    lookup_keys.append(key)
                    for node in vuln.supporting_nodes or []:
                        lookup_keys.append(('match', f"raw:{node.get('file', '')}:{node.get('type', '')}:{node.get('line', 0)}"))

                    if key not in seen:
                        seen.add(key)

                        # 融合D2验证结果
                        d2_data = next((d2_results[item] for item in lookup_keys if item in d2_results), None)
                        if d2_data:
                            vuln.executed = d2_data.get('executed', False)
                            vuln.vulnerable = d2_data.get('vulnerable', False)
                            vuln.exploitable = d2_data.get('vulnerable', False)  # 兼容字段
                            vuln.confidence = d2_data.get('confidence', '')
                            vuln.poc = d2_data.get('payload', '')
                            vuln.poc_type = d2_data.get('poc_type', '')
                            vuln.no_poc_reason = d2_data.get('no_poc_reason', '')
                            vuln.d2_output = d2_data.get('output', '')
                            vuln.d2_error = d2_data.get('error', '')
                            # 设置证据
                            if d2_data.get('vulnerable'):
                                vuln.d2_evidence = f"D2验证确认漏洞存在，置信度: {d2_data.get('confidence', 'low')}"
                            elif d2_data.get('executed'):
                                vuln.d2_evidence = "D2验证确认漏洞不存在或无法利用"
                            else:
                                vuln.d2_evidence = f"D2未执行: {d2_data.get('no_poc_reason', '未知原因')}"

                        merged.append(vuln)

            self.merged_vulnerabilities = merged
            logger.info(f"Merged vulnerabilities: {len(merged)} unique")
            return merged

    def add_decision(self, agent: str, decision_type: str, details: Dict):
        """
        记录Agent决策

        Args:
            agent: Agent名称
            decision_type: 决策类型
            details: 决策详情
        """
        with self.lock:
            decision = {
                'agent': agent,
                'type': decision_type,
                'details': details,
                'timestamp': time.time()
            }
            self.agent_decisions.append(decision)
            logger.debug(f"Agent decision: {agent} - {decision_type}")

    def get_decisions(self, agent: str = None) -> List[Dict]:
        """
        获取决策记录

        Args:
            agent: Agent名称过滤

        Returns:
            决策列表
        """
        with self.lock:
            if agent:
                return [d for d in self.agent_decisions if d['agent'] == agent]
            return self.agent_decisions.copy()

    def update_progress(self, phase: str, completed: bool = False, percent: int = 0):
        """
        更新分析进度

        Args:
            phase: 当前阶段
            completed: 是否完成
            percent: 进度百分比
        """
        with self.lock:
            if 'a1' in phase.lower():
                self.progress.a1_completed = completed
            elif 'a2' in phase.lower():
                self.progress.a2_completed = completed
            elif 'd2' in phase.lower():
                self.progress.d2_completed = completed

            self.progress.current_phase = phase
            self.progress.progress_percent = percent

    def add_error(self, agent: str, error: str):
        """
        记录错误

        Args:
            agent: Agent名称
            error: 错误信息
        """
        with self.lock:
            error_record = {
                'agent': agent,
                'error': error,
                'timestamp': time.time()
            }
            self.errors.append(error_record)
            self.progress.errors.append(error)
            logger.error(f"Agent error ({agent}): {error}")

    def set_state(self, state: ContextState):
        """设置状态"""
        with self.lock:
            self.state = state

    def get_state(self) -> ContextState:
        """获取状态"""
        with self.lock:
            return self.state

    def get_stats(self) -> Dict[str, Any]:
        """
        获取统计信息

        Returns:
            统计字典
        """
        with self.lock:
            stats = {
                'total_files': len(self.project_info.files),
                'a1_vulns': len(self.vulnerabilities.get('a1', [])),
                'a2_vulns': len(self.vulnerabilities.get('a2', [])),
                'd2_vulns': len(self.vulnerabilities.get('d2', [])),
                'merged_vulns': len(self.merged_vulnerabilities),
                'total_decisions': len(self.agent_decisions),
                'total_errors': len(self.errors),
                'state': self.state.value,
                'progress': {
                    'a1': self.progress.a1_completed,
                    'a2': self.progress.a2_completed,
                    'd2': self.progress.d2_completed,
                    'percent': self.progress.progress_percent
                }
            }
            self.stats = stats
            return stats

    def to_dict(self) -> Dict:
        """
        导出为字典

        Returns:
            字典表示
        """
        with self.lock:
            return {
                'project_path': self.project_path,
                'project_info': {
                    'language': self.project_info.language,
                    'framework': self.project_info.framework,
                    'files_count': len(self.project_info.files),
                    'entry_points': self.project_info.entry_points,
                    'dependencies': self.project_info.dependencies
                },
                'vulnerabilities': {
                    'a1': len(self.vulnerabilities.get('a1', [])),
                    'a2': len(self.vulnerabilities.get('a2', [])),
                    'd2': len(self.vulnerabilities.get('d2', [])),
                    'merged': len(self.merged_vulnerabilities)
                },
                'progress': self.progress.__dict__,
                'stats': self.stats
            }

    def save_to_file(self, filepath: str):
        """
        保存到文件

        Args:
            filepath: 文件路径
        """
        with self.lock:
            data = self.to_dict()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Context saved to {filepath}")

    @classmethod
    def load_from_file(cls, filepath: str) -> 'SharedContext':
        """
        从文件加载

        Args:
            filepath: 文件路径

        Returns:
            SharedContext对象
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        ctx = cls(project_path=data.get('project_path', ''))
        # 恢复基本状态
        if 'project_info' in data:
            ctx.project_info.language = data['project_info'].get('language', '')
            ctx.project_info.framework = data['project_info'].get('framework', '')

        return ctx


# 全局共享上下文
_shared_context: Optional[SharedContext] = None


def get_shared_context(project_path: str = "") -> SharedContext:
    """
    获取全局共享上下文

    Args:
        project_path: 项目路径

    Returns:
        SharedContext实例
    """
    global _shared_context
    if _shared_context is None:
        _shared_context = SharedContext(project_path)
    return _shared_context


def reset_shared_context(project_path: str = "") -> SharedContext:
    """
    重置共享上下文

    Args:
        project_path: 新的项目路径

    Returns:
        新的SharedContext实例
    """
    global _shared_context
    _shared_context = SharedContext(project_path)
    return _shared_context
