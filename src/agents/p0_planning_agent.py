"""
P0 Planning Agent - 策略规划
负责分析项目信息，制定审计计划，输出结构化JSON
"""
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AuditPlan:
    """审计计划"""
    scan_depth: str = "deep"           # shallow/medium/deep
    vulnerability_priority: str = "all"  # high_only/all
    a1_rules: str = "all"              # high_only/all/language_specific
    d2_scope: str = "all"              # high_only/a2_confirmed/all

    # 规则配置
    enabled_rules: List[str] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)

    # 自定义配置
    custom_config: Dict = field(default_factory=dict)

    # 策略说明
    strategy_reasoning: str = ""

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def to_dict(self) -> Dict:
        return {
            'scan_depth': self.scan_depth,
            'vulnerability_priority': self.vulnerability_priority,
            'a1_rules': self.a1_rules,
            'd2_scope': self.d2_scope,
            'enabled_rules': self.enabled_rules,
            'disabled_rules': self.disabled_rules,
            'custom_config': self.custom_config,
            'strategy_reasoning': self.strategy_reasoning
        }


class P0PlanningAgent:
    """P0 Planning 策略规划 Agent"""

    def __init__(self, project_info):
        self.project_info = project_info

    def create_plan(self) -> AuditPlan:
        """
        基于项目信息创建审计计划

        默认策略: 深层分析 + 全量扫描 + 全部规则 + 全部漏洞验证
        """
        logger.info("Creating audit plan...")

        plan = AuditPlan()

        # 1. 扫描深度 - 默认深层
        plan.scan_depth = "deep"
        plan.strategy_reasoning += "使用深层完整分析，扫描所有源代码文件。"

        # 2. 漏洞优先级 - 全量
        plan.vulnerability_priority = "all"
        plan.strategy_reasoning += "全量扫描，不遗漏任何潜在漏洞。"

        # 3. A1规则 - 全部
        plan.a1_rules = "all"
        plan.strategy_reasoning += f"启用全部规则({self.project_info.language})。"

        # 4. D2验证范围 - 全部
        plan.d2_scope = "all"
        plan.strategy_reasoning += "对所有漏洞进行动态验证。"

        # 5. 根据技术栈调整规则
        plan.custom_config = self._get_custom_config()

        # 6. 添加特定语言的高危规则
        plan.enabled_rules = self._get_enabled_rules()

        logger.info(f"Audit plan created: depth={plan.scan_depth}, rules={plan.a1_rules}")
        return plan

    def _get_custom_config(self) -> Dict:
        """获取自定义配置"""
        config = {
            'project': {
                'name': self.project_info.name,
                'language': self.project_info.language or 'unknown',
                'framework': self.project_info.framework or 'unknown',
            },
            'scan_targets': {
                'source_dirs': self.project_info.source_dirs,
                'exclude_dirs': ['test', 'vendor', 'node_modules', 'target'],
            },
            'http_routes': len(self.project_info.http_routes),
            'dependencies': len(self.project_info.dependencies),
        }

        # 根据框架添加特定配置
        framework = self.project_info.framework
        if framework == 'spring':
            config['framework_config'] = {
                'check_actuator': True,
                'check_jolokia': True,
                'check_h2_console': True
            }
        elif framework == 'django':
            config['framework_config'] = {
                'check_debug': True,
                'check_secret_key': True,
                'check_allow_hosts': True
            }
        elif framework == 'flask':
            config['framework_config'] = {
                'check_debug': True,
                'check_secret_key': True
            }

        return config

    def _get_enabled_rules(self) -> List[str]:
        """获取启用的规则列表"""
        rules = []

        # 基础安全规则 - 全部
        base_rules = [
            'SQLI001', 'SQLI002', 'SQLI003',  # SQL注入
            'XSS001', 'XSS002', 'XSS003',      # XSS
            'CMD001', 'CMD002', 'CMD003',      # 命令注入
            'DES001', 'DES002', 'DES003',      # 反序列化
            'SSRF001', 'SSRF002',               # SSRF
            'PATH001', 'PATH002',               # 路径穿越
            'XXE001', 'XXE002',                 # XXE
            'FILE001', 'FILE002',               # 文件操作
            'AUTH001', 'AUTH002',               # 认证
            'CSRF001', 'CSRF002',               # CSRF
        ]
        rules.extend(base_rules)

        # 语言特定规则
        lang = self.project_info.language or 'java'  # 默认Java
        if lang == 'java':
            rules.extend([
                'JNDI001', 'JNDI002',           # JNDI注入
                'OGNL001', 'OGNL002',           # OGNL注入
                'SPEL001', 'SPEL002',           # SpEL注入
                'JAXB001',                      # XML绑定
            ])
        elif lang == 'python':
            rules.extend([
                'PYSQL001', 'PYSQL002',         # Python SQL注入
                'PYCMD001', 'PYCMD002',         # Python命令注入
                'PYCODE001',                    # 代码执行
                'PYPICKLE001',                  # pickle反序列化
                'PYDEBUG001',                   # Debug模式
            ])
        elif lang == 'javascript':
            rules.extend([
                'NODE001', 'NODE002',           # Node.js特定
                'EXPRESS001',                   # Express配置
                'JWT001', 'JWT002',             # JWT
            ])

        return rules

    def save_plan(self, plan: AuditPlan, output_path: str):
        """保存审计计划到JSON文件"""
        data = {
            'project': {
                'name': self.project_info.name,
                'language': self.project_info.language or 'unknown',
                'framework': self.project_info.framework or 'unknown',
            },
            'plan': plan.to_dict(),
            'project_info_summary': {
                'source_dirs': self.project_info.source_dirs,
                'dependencies_count': len(self.project_info.dependencies),
                'http_routes_count': len(self.project_info.http_routes),
                'user_inputs_count': len(self.project_info.user_inputs),
            }
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Audit plan saved to {output_path}")
