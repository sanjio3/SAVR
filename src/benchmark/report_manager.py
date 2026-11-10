"""
报告管理器
管理最终安全审计报告（经 D2 动态验证的最终汇总报告）生成
支持 API 覆盖率和漏洞覆盖率统计
"""
import json
import os
import re
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
import logging
from urllib.parse import urlparse

from ..core.models import ScanResult
from ..core.config import config
from ..core.exploit_spec import empty_chain_proof, empty_exploit_spec, exploit_spec_completeness, is_business_logic_family, merge_exploit_specs, normalize_chain_proof, normalize_exploit_spec, derive_flow_type
from ..core.d2_zero_audit import summarize_d2_zero_audit
from src.core.vuln_hash import canonicalize_vuln_for_hash, vulnerability_hash_v2
from src.core import workspace_runtime
from src.core.normalize import normalize_family, normalize_severity, normalize_type

logger = logging.getLogger(__name__)

# ── E12（2026-10-26）：CWE 对齐输出（只做输出口径，不参与判定）────────────────
# case 级映射需要外部真值 CSV（SAST_AI_CWE_MAP 指向 expectedresults-*.csv）；
# 没配置就退化为族级映射。缓存避免每条漏洞都读一次文件。
_CWE_CASE_MAP_CACHE: Dict[str, dict] = {}


def _cwe_of_entry(file_path: str, vtype: str, family: str = "") -> str:
    """取条目的 CWE（case 级优先，族级兜底）；取不到返回空串（不猜）。"""
    try:
        from src.core.cwe_map import cwe_of, case_to_cwe_from_csv
    except Exception:  # noqa: BLE001
        return ""
    case_map = None
    csv_path = str(os.environ.get("SAST_AI_CWE_MAP", "") or "").strip()
    if csv_path:
        if csv_path not in _CWE_CASE_MAP_CACHE:
            _CWE_CASE_MAP_CACHE[csv_path] = case_to_cwe_from_csv(csv_path)
        case_map = _CWE_CASE_MAP_CACHE[csv_path] or None
    return cwe_of({"file_path": file_path, "family": family or vtype}, case_map)


# 漏洞类型映射（用于覆盖率统计）
VULNERABILITY_RULES = {
    'sql_injection': 'SQL注入',
    'xss': '跨站脚本(XSS)',
    'command_injection': '命令注入',
    'ssrf': '服务器端请求伪造(SSRF)',
    'path_traversal': '路径穿越',
    'xxe': 'XML外部实体(XXE)',
    'deserialization': '不安全反序列化',
    'file_upload': '文件上传',
    'url_redirect': '开放重定向',
    'authentication': '认证问题',
    'authorization': '授权问题',
    'information_disclosure': '信息泄露',
    'hardcoded_credentials': '硬编码凭证',
    'weak_cryptography': '弱加密',
    'xml_injection': 'XML注入',
    'json_injection': 'JSON注入',
    'ldap_injection': 'LDAP注入',
    'template_injection': '模板注入',
    'deser': '反序列化',
    'rce': '远程代码执行'
}


def has_meaningful_poc(vuln: Dict) -> bool:
    """Only count non-placeholder POCs."""
    poc = vuln.get('poc') or {}
    if not isinstance(poc, dict):
        return False
    for key in ('python', 'java', 'nodejs'):
        content = (poc.get(key) or '').strip()
        if content and content.lower() != '# could not generate poc':
            return True
    return False


def is_tested_status(status: str) -> bool:
    return (status or '').upper() in {'DONE', 'VULNERABLE', 'CONFIRMED'}


def verification_status(vuln: Dict) -> str:
    decision = vuln.get('verification_decision') or {}
    return str(decision.get('verification_status', '') or '')


def is_confirmed_exploitable(vuln: Dict) -> bool:
    status = verification_status(vuln)
    if status:
        return status == 'confirmed_exploitable'
    return vuln.get('exploitable') == 'Yes'


def is_sink_control_only(vuln: Dict) -> bool:
    return verification_status(vuln) == 'confirmed_sink_control'


def _vuln_family_token(vuln: Dict) -> str:
    """从 vuln 推导归一化族名（小写、下划线转连字符），供业务类判定。"""
    spec = vuln.get('exploit_spec') or {}
    if isinstance(spec, dict):
        payload = spec.get('payload') or {}
        pf = payload.get('payload_family') if isinstance(payload, dict) else None
        if pf:
            return str(pf).strip().lower().replace('_', '-')
        blc = spec.get('business_logic_category')
        if blc:
            return str(blc).strip().lower().replace('_', '-')
    return str(vuln.get('family') or vuln.get('type') or '').strip().lower().replace('_', '-')


def is_contract_ready_item(vuln: Dict) -> bool:
    """D2 候选门禁。

    Q5 修正：业务类漏洞（越权/竞态/状态机/批量赋值等）没有「安全门 / success_signal」
    这种注入型概念，原逻辑用 `status in {'missing','partial'} → return False` 第一道 early
    return 架空了末行的 `a21_selected is True` 豁免条款（死代码），导致 46 条 a21_selected=True
    的 finding 被拒、mainline 仅 5 条。

    新规则：a21_selected=True 且族为业务类且解析出可达入口（entry.route 非空）→ 直接进 D2
    候选，契约 completeness 状态只作展示、不再阻断。非业务类 / 未选中项维持原 strict 逻辑。
    """
    completeness = vuln.get('contract_completeness') or {}
    failure = vuln.get('failure_classification') or {}
    a21_selected = vuln.get('a21_selected') is True
    if a21_selected and is_business_logic_family(_vuln_family_token(vuln)):
        spec = vuln.get('exploit_spec') or {}
        entry = (spec.get('entry') or {}) if isinstance(spec, dict) else {}
        if entry.get('route'):
            return True
    if completeness.get('status') in {'missing', 'partial'}:
        return False
    if failure.get('category') == 'contract_incomplete':
        return False
    return bool(a21_selected or completeness.get('status') == 'ready')


def is_mainline_d2_item(vuln: Dict) -> bool:
    return str(vuln.get('proof_tier', 'broad_static') or 'broad_static') == 'chain_proven' and is_contract_ready_item(vuln)


# §③ 未执行标记（2026-09-22，闭环 D2_NOT_SCHEDULED）：报告层会为未获 D2 验证的 finding 写入
# 「显式未验证原因」状态（not_scheduled / no_verification_record）。这两个状态的意思是
# 「没跑 / 跑了但结果丢了」，**不是「跑过」**。凡是拿「verification_decision 非空」当「已执行」
# 判据的地方（is_executed_d2_item → count_dynamic_stats.confirmed_count / aggregation 的
# execution_items）都必须先排除它们，否则会把未验证条目的数字抬进「已执行/已确认」口径。
D2_NOT_EXECUTED_STATUSES = frozenset({'not_scheduled', 'no_verification_record'})


def is_executed_d2_item(vuln: Dict) -> bool:
    if not is_mainline_d2_item(vuln):
        return False
    # 显式未验证原因优先：有该标记即「未执行」，不再被下面的 verification_decision 真值判据抬成已执行。
    if verification_status(vuln) in D2_NOT_EXECUTED_STATUSES:
        return False
    if int(vuln.get('steps_executed', 0) or 0) > 0:
        return True
    test_status = str(vuln.get('test_status', '') or '').upper()
    if test_status in {'DONE', 'VULNERABLE', 'CONFIRMED', 'ERROR'}:
        return True
    if vuln.get('execution_evidence') or vuln.get('verification_decision'):
        return True
    return False


def is_excluded_d2_fallback_item(vuln: Dict) -> bool:
    if is_mainline_d2_item(vuln) or is_executed_d2_item(vuln):
        return False
    completeness = vuln.get('contract_completeness') or {}
    failure = vuln.get('failure_classification') or {}
    test_status = str(vuln.get('test_status', '') or '').upper()
    return bool(
        test_status == 'NOT_TESTED'
        and (
            vuln.get('reason')
            or vuln.get('no_poc_reason')
            or vuln.get('attack_plan')
            or vuln.get('poc_details')
            or vuln.get('poc_generated')
            or has_meaningful_poc(vuln)
        )
        and (
            completeness.get('status') in {'missing', 'partial', ''}
            or failure.get('category') == 'contract_incomplete'
        )
    )


def count_dynamic_stats(vulns: List[Dict], *, mainline_only: bool = True) -> Dict[str, int]:
    scoped = list(vulns)
    if mainline_only:
        scoped = [vuln for vuln in scoped if is_mainline_d2_item(vuln)]
    return {
        'exploitable_count': sum(1 for vuln in scoped if is_confirmed_exploitable(vuln)),
        'confirmed_count': sum(1 for vuln in scoped if is_executed_d2_item(vuln)),
        'poc_count': sum(1 for vuln in scoped if vuln.get('poc_generated') or has_meaningful_poc(vuln)),
        'verified_poc_count': sum(1 for vuln in scoped if vuln.get('poc_verified') and is_confirmed_exploitable(vuln)),
    }


def count_proof_tiers(vulns: List[Dict]) -> Dict[str, int]:
    chain_proven = 0
    contract_ready = 0
    for vuln in vulns:
        if str(vuln.get('proof_tier', 'broad_static') or 'broad_static') == 'chain_proven':
            chain_proven += 1
        if vuln.get('a21_selected') is True:
            contract_ready += 1
    return {
        'broad_static_count': len(vulns),
        'chain_proven_count': chain_proven,
        'contract_ready_count': contract_ready,
    }


def calculate_coverage_stats(discovered_endpoints: List[Dict] = None,
                               tested_endpoints: List[Dict] = None,
                               vulnerability_types: List[str] = None) -> Dict:
    """
    计算覆盖率统计

    Args:
        discovered_endpoints: 发现的端点列表
        tested_endpoints: 已测试的端点列表
        vulnerability_types: 发现的漏洞类型列表

    Returns:
        覆盖率统计字典
    """
    stats = {
        'api_coverage': {
            'total_discovered': 0,
            'tested': 0,
            'untested': 0,
            'coverage_rate': 0.0
        },
        'vulnerability_coverage': {
            'total_rules': len(VULNERABILITY_RULES),
            'rules_covered': 0,
            'types_found': 0,
            'coverage_rate': 0.0,
            'missing_types': []
        }
    }

    # API 覆盖率
    if discovered_endpoints:
        total = len(discovered_endpoints)
        tested = len(tested_endpoints) if tested_endpoints else 0

        stats['api_coverage'] = {
            'total_discovered': total,
            'tested': tested,
            'untested': total - tested,
            'coverage_rate': round(tested / total * 100, 2) if total > 0 else 0.0
        }

    # 漏洞覆盖率
    if vulnerability_types:
        found_types = set()
        for vtype in vulnerability_types:
            vtype_lower = vtype.lower()
            for rule_key in VULNERABILITY_RULES:
                if rule_key in vtype_lower or vtype_lower in rule_key:
                    found_types.add(rule_key)

        stats['vulnerability_coverage']['types_found'] = len(found_types)
        stats['vulnerability_coverage']['rules_covered'] = len(found_types)
        stats['vulnerability_coverage']['coverage_rate'] = round(
            len(found_types) / len(VULNERABILITY_RULES) * 100, 2
        )

        # 找出未发现的漏洞类型
        missing = []
        for rule_key in VULNERABILITY_RULES:
            if rule_key not in found_types:
                missing.append(VULNERABILITY_RULES[rule_key])
        stats['vulnerability_coverage']['missing_types'] = missing[:5]  # 只显示前5个

    return stats


class ReportManager:
    """报告管理器 - 管理最终安全审计报告生成"""

    def __init__(self):
        self.output_dir = config.get('output.output_dir', 'output')
        os.makedirs(self.output_dir, exist_ok=True)

    def _confidence_cn(self, value: str) -> str:
        mapping = {
            'high': '高',
            'medium': '中',
            'low': '低',
            'confirmed': '已确认',
            'probable': '较可能',
            'uncertain': '不确定',
        }
        return mapping.get((value or '').lower(), value or '未知')

    @staticmethod
    def _normalize_verdict_text(verdict: str) -> str:
        text = (verdict or '').strip()
        return re.sub(r'^[✅❌⚠️\s]+', '', text)

    def _build_verdict_summary(self, vuln: Dict) -> Dict[str, str]:
        static_verdict = self._normalize_verdict_text(vuln.get('verdict', ''))
        exploitable = 'Yes' if is_confirmed_exploitable(vuln) else vuln.get('exploitable', 'Unknown')
        poc_verified = bool(vuln.get('poc_verified')) and is_confirmed_exploitable(vuln)
        verification_state = verification_status(vuln)
        # §③ 未验证原因上抬（2026-09-22）：报告层为未获 D2 验证的 finding 写了显式原因
        # （verification_decision.verification_status + scheduling_reason）。这里把它带进用户可见的
        # 裁决摘要 note，避免「为什么没验证」只存在于结构化字段里、而在 final/note 上读不到。
        _vd_raw = vuln.get('verification_decision') or {}
        _unverified_note = ''
        if str(_vd_raw.get('verification_status') or '') in D2_NOT_EXECUTED_STATUSES:
            _unverified_note = 'D2 未执行该 finding：%s' % (
                str(_vd_raw.get('scheduling_reason') or '未记录原因')
            )

        if poc_verified or exploitable == 'Yes':
            note = ''
            if static_verdict and ('假漏洞' in static_verdict or '无调用点' in static_verdict):
                note = f'静态预判曾给出“{static_verdict}”，但已被 D2 动态利用成功和成功证据推翻。'
            elif static_verdict and '可疑' in static_verdict:
                note = f'静态阶段仅给出“{static_verdict}”，D2 已补足动态实证。'
            return {
                'final': '✅ D2:真漏洞-已动态验证成功',
                'static': static_verdict,
                'note': note,
            }

        if verification_state == 'confirmed_sink_control':
            return {
                'final': 'D2: confirmed sink control only',
                'static': static_verdict,
                'note': 'D2 confirmed sink control or expression execution, but did not reach a high-impact exploit outcome.',
            }

        if exploitable == 'No':
            # Q1 呈现层：禁止把 D2 的「未验证」渲染成「非漏洞」。若 A2 静态已判「真漏洞」，
            # 必须保留该信号，不与 D2 的「未验证成功」互相覆盖——用户视角应是
            # 「A2 检出真漏洞，但 D2 未动态确认」，而非「不是漏洞」。
            if '真漏洞' in static_verdict:
                return {
                    'final': '⚠️ 已检出（A2 判真漏洞）- D2 未验证成功',
                    'static': static_verdict,
                    'note': (vuln.get('verification_note', '') or '') +
                            ' A2 静态判定为真漏洞，D2 未能提供动态实证，属「已检出未验证」而非「已排除」。',
                }
            return {
                'final': '❌ D2:未验证成功-当前无动态实证',
                'static': static_verdict,
                'note': vuln.get('verification_note', '') or '',
            }

        if static_verdict:
            return {
                'final': static_verdict,
                'static': static_verdict,
                'note': _unverified_note,
            }

        return {
            'final': '⚠️ 未完成最终判定',
            'static': '',
            'note': _unverified_note,
        }

    @staticmethod
    def _static_verdict_explanation(verdict: str) -> str:
        text = verdict or ''
        if 'A1:可疑-需A2验证' in text:
            return 'A1 规则命中到了危险模式，但单靠规则还不足以确认真实调用链或入口点，需要 A2/D2 继续确认。'
        if 'A2:假漏洞-无调用点' in text:
            return 'A2 在静态分析阶段未找到可到达的调用点或入口链路，所以把它先当作静态假阳性处理。'
        if 'A1:假漏洞-无跨文件调用链' in text:
            return 'A1 在跨文件层面没有拼出足够的调用链，因此将其降为静态假阳性。'
        return ''

    def _explain_text(self, text: str) -> str:
        if not text:
            return ''

        explanations = []
        lower = text.lower()

        if 'did not complete a successful dynamic exploit verification' in lower:
            explanations.append('中文解释：D2 写出了利用代码或攻击思路，但真正发请求、跑容器、观测响应时，没有拿到足够证据证明漏洞已被成功利用。')
        if 'access is denied' in lower and 'buildx' in lower:
            explanations.append('中文解释：Docker CLI 试图访问本地 buildx 锁文件时被系统拒绝，属于本机 Docker 配置或权限问题，不是目标代码本身导致。')
        if 'dockerdesktoplinuxengine' in lower and 'access is denied' in lower:
            explanations.append('中文解释：当前进程没有权限连接 Docker Desktop 的 Linux 引擎命名管道，所以容器根本没有真正启动。')
        if 'connection refused' in lower or 'failed to establish a new connection' in lower:
            explanations.append('中文解释：目标端口上没有服务监听，通常表示容器未启动成功、服务尚未就绪，或端口映射不正确。')
        if 'connection aborted' in lower or 'remote end closed connection without response' in lower:
            explanations.append('中文解释：连接建立后被对端主动断开，通常表示服务崩溃、请求触发异常，或中间件提前关闭连接。')
        if 'ysoserial' in lower:
            explanations.append('中文解释：该利用链依赖 ysoserial 生成真实反序列化 gadget payload；缺少该工具时，只能做入口确认或理论利用。')

        if not explanations:
            return ''
        return ' '.join(explanations)

    def _build_attack_chain(self, vuln: Dict) -> str:
        if self._is_project_deserialization_chain(vuln):
            dc = workspace_runtime.deserialization_chain()
            entry = dc.get('entry_route', '/debug/import')
            trigger = dc.get('trigger_route', '/api/quote/random')
            return (
                f"POST {entry} -> QuoteService.setQuoteCache -> "
                f"GET {trigger} -> CacheProcessor.process(userConfig)"
            )
        parts = []
        if vuln.get('entry_point'):
            parts.append(f"入口: {vuln.get('entry_point')}")
        if vuln.get('callers'):
            parts.append(f"调用链: {vuln.get('callers')}")
        if vuln.get('data_flow'):
            parts.append(f"数据流: {vuln.get('data_flow')}")
        if vuln.get('sink'):
            parts.append(f"危险点: {vuln.get('sink')}")
        if not parts:
            return "当前条目缺少完整调用链，暂以静态命中结果展示"
        return " -> ".join(parts)

    @staticmethod
    def _is_project_deserialization_chain(vuln: Dict) -> bool:
        canonical_key = str(vuln.get('canonical_group_key', '') or '').strip().lower()
        chain_id = str(vuln.get('chain_id', '') or '').strip().lower()
        if canonical_key == 'deserialization:project_chain' or chain_id == 'deserialization:project_chain':
            return True
        text = " ".join(
            str(part or '')
            for part in [
                vuln.get('original_type', ''),
                vuln.get('description', ''),
                vuln.get('entry_point', ''),
                vuln.get('sink', ''),
                vuln.get('callers', ''),
                vuln.get('data_flow', ''),
                json.dumps(vuln.get('supporting_nodes', []), ensure_ascii=False),
            ]
        ).lower()
        markers = tuple(workspace_runtime.deserialization_chain().get('markers', []))
        chain_id_prefix = workspace_runtime.deserialization_chain().get('chain_id_prefix', 'deserialization:project_chain')
        return (canonical_key.startswith(chain_id_prefix) or chain_id.startswith(chain_id_prefix)) and any(marker in text for marker in markers)

    @staticmethod
    def _project_chain_display_title() -> str:
        return "Java \u53cd\u5e8f\u5217\u5316\u94fe"

    @staticmethod
    def _display_title_for_family(family: str) -> str:
        normalized = str(family or '').strip().lower()
        mapping = {
            'deserialization': '反序列化',
            'path_traversal': '路径穿越',
            'command_injection': '命令注入',
            'xss': 'XSS',
            'csrf': 'CSRF',
            'sql_injection': 'SQL 注入',
        }
        return mapping.get(normalized, normalized or 'Unknown')

    @staticmethod
    def _chain_context_rank(item: Dict) -> tuple:
        proof = normalize_chain_proof(item.get('chain_proof') or empty_chain_proof())
        spec = normalize_exploit_spec(item.get('exploit_spec') or empty_exploit_spec())
        completeness = item.get('contract_completeness') or {}
        missing = list(item.get('proof_gaps', []) or proof.get('proof_gaps', []) or [])
        filled_spec = exploit_spec_completeness(spec)
        score = int(completeness.get('score', 0) or 0)
        if score <= 0:
            score = int(filled_spec.get('score', 0) or 0)
        return (
            str(item.get('proof_tier', 'broad_static')) == 'chain_proven',
            not missing,
            -len(missing),
            score,
            bool(item.get('a21_selected')),
            bool(spec.get('entry', {}).get('route')),
            bool(spec.get('payload', {}).get('payload_family')),
            bool(spec.get('success_signal', {}).get('signal_type')),
        )

    def _promote_chain_context(self, canonical: Dict, support_nodes: List[Dict]) -> Dict:
        candidates = [dict(canonical)]
        for node in support_nodes or []:
            candidate = dict(node)
            candidate['chain_proof'] = normalize_chain_proof(candidate.get('chain_proof') or empty_chain_proof())
            candidate['exploit_spec'] = normalize_exploit_spec(candidate.get('exploit_spec') or empty_exploit_spec())
            candidate['proof_gaps'] = list(candidate.get('proof_gaps', []) or candidate['chain_proof'].get('proof_gaps', []) or [])
            candidate['contract_completeness'] = candidate.get('contract_completeness') or exploit_spec_completeness(candidate['exploit_spec'])
            candidates.append(candidate)

        strongest = max(candidates, key=self._chain_context_rank)
        canonical['exploit_spec'] = merge_exploit_specs(
            strongest.get('exploit_spec') or empty_exploit_spec(),
            canonical.get('exploit_spec') or empty_exploit_spec(),
        )
        canonical['chain_proof'] = normalize_chain_proof(strongest.get('chain_proof') or canonical.get('chain_proof') or empty_chain_proof())
        canonical['proof_gaps'] = list(strongest.get('proof_gaps', []) or canonical['chain_proof'].get('proof_gaps', []) or [])
        canonical['proof_tier'] = strongest.get('proof_tier') or canonical.get('proof_tier', 'broad_static')
        if strongest.get('a21_selected') is not None and canonical.get('a21_selected') is None:
            canonical['a21_selected'] = strongest.get('a21_selected')
        if strongest.get('a21_reason') and not canonical.get('a21_reason'):
            canonical['a21_reason'] = strongest.get('a21_reason')
        if int(strongest.get('a21_candidate_score', 0) or 0) > int(canonical.get('a21_candidate_score', 0) or 0):
            canonical['a21_candidate_score'] = int(strongest.get('a21_candidate_score', 0) or 0)
        completeness = canonical.get('contract_completeness') or {}
        current_score = int(completeness.get('score', 0) or 0)
        strongest_score = int((strongest.get('contract_completeness') or {}).get('score', 0) or 0)
        if strongest_score > current_score:
            canonical['contract_completeness'] = strongest.get('contract_completeness')
        return canonical

    def _normalize_display_fields(self, vuln: Dict) -> Dict:
        original_type = str(vuln.get('original_type') or vuln.get('type') or '').strip()
        family = str(vuln.get('display_family') or self._canonical_family(vuln) or '').strip().lower()
        chain_id = str(vuln.get('chain_id') or vuln.get('canonical_group_key') or '').strip()
        vuln['original_type'] = original_type
        vuln['display_family'] = family
        # 2026-09-18（E2 评审）：族名自洽校验。
        # original_type 记 LLM 原始类型、family 是系统归一结果，两者不同本属正常
        # （如 xxe → JNDI Injection 是有意纠正）；但若归一让一个注入 / 重定向类原话落到
        # 完全无关的族（实测 id=4840：original_type="SSRF/开放重定向" 而归一后 family=csrf），
        # 那就是归一规则出错，必须暴露出来而不是静默吞掉。只标记，不改族名——族名取舍
        # 涉及召回口径，须先请示。
        _mismatch = self._family_mismatch(original_type, family)
        if _mismatch:
            vuln['family_mismatch'] = _mismatch
            logger.warning(
                "[report] 族名不自洽：%s -> %s（%s:%s）",
                original_type, family, vuln.get('file'), vuln.get('line'),
            )
        if self._is_project_deserialization_chain(vuln):
            vuln['type'] = self._project_chain_display_title()
            vuln['display_title'] = self._project_chain_display_title()
            vuln['finding_family'] = 'java_deserialization_chain'
            return vuln
        if chain_id:
            if family == 'deserialization':
                vuln['display_title'] = f"{self._display_title_for_family(family)}链"
            else:
                vuln['display_title'] = self._display_title_for_family(family)
        else:
            vuln['display_title'] = original_type or self._display_title_for_family(family)
        vuln['type'] = vuln['display_title']
        vuln['finding_family'] = family
        return vuln

    # 有意纠正白名单：这些 (original_type 归一结果, 最终 family) 组合是系统刻意为之，不算不自洽。
    # 生效点见 src/agents/a2_intelligent_agent.py::_correct_llm_family。
    _INTENTIONAL_FAMILY_FIXES = {
        ("xxe", "jndi_injection"),
        ("xxe", "jndi-injection"),
        ("csrf", "xss"),
    }

    def _family_mismatch(self, original_type: str, family: str) -> str:
        """族名自洽校验（2026-09-18，E2）：返回不自洽描述，自洽则返回空串。

        判据：把 original_type 单独归一，结果与最终 family 不同、且不在有意纠正白名单内，
        即判为不自洽（返回 "原归一 -> 最终族"）。只标记不修改。
        """
        ot = str(original_type or "").strip()
        fam = str(family or "").strip().lower()
        if not ot or not fam:
            return ""
        try:
            ot_fam = str(normalize_family(ot) or "").strip().lower()
        except Exception:
            return ""
        if not ot_fam or ot_fam == fam:
            return ""
        if (ot_fam, fam) in self._INTENTIONAL_FAMILY_FIXES:
            return ""
        return "%s -> %s" % (ot_fam, fam)

    def _project_chain_routes(self) -> Dict[str, str]:
        dc = workspace_runtime.deserialization_chain()
        entry = dc.get('entry_route', '/debug/import')
        trigger = dc.get('trigger_route', '/api/quote/random')
        chain_id_prefix = dc.get('chain_id_prefix', 'deserialization:project_chain')
        return {
            'entry_route': entry,
            'trigger_route': trigger,
            'attack_chain_summary': self._build_attack_chain({'canonical_group_key': chain_id_prefix}),
        }

    def _rewrite_project_chain_poc(self, vuln: Dict, details: Dict) -> None:
        poc = dict(vuln.get('poc', {}) or {})
        dc = workspace_runtime.deserialization_chain()
        target_url = details.get('target_url') or dc.get('entry_route', '/debug/import')
        trigger_route = details.get('trigger_route') or dc.get('trigger_route', '/api/quote/random')
        target_param = details.get('target_param') or 'data'
        poc['target_url'] = target_url
        poc['curl'] = "\n".join([
            '# Step 1: import serialized object',
            f"curl -X POST 'http://localhost:8080{target_url}' --data-urlencode '{target_param}=<BASE64_SERIALIZED_OBJECT>'",
            '',
            '# Step 2: trigger cache processing',
            f"curl 'http://localhost:8080{trigger_route}'",
        ])
        poc['python'] = "\n".join([
            'import requests',
            '',
            "base = 'http://localhost:8080'",
            "payload = '<BASE64_SERIALIZED_OBJECT>'",
            f"import_resp = requests.post(base + '{target_url}', data={{'{target_param}': payload}}, timeout=10)",
            f"trigger_resp = requests.get(base + '{trigger_route}', timeout=10)",
            "print('import:', import_resp.status_code, import_resp.text[:200])",
            "print('trigger:', trigger_resp.status_code, trigger_resp.text[:200])",
        ])
        vuln['poc'] = poc

    def _priority_score(self, vuln: Dict) -> int:
        family = str(vuln.get('canonical_group_key', '') or '')
        vuln_type = str(vuln.get('type', '') or '').lower()
        file_path = str(vuln.get('file', '') or '').lower()
        snippet = str(vuln.get('code_snippet', '') or '').lower()
        score = {'HIGH': 80, 'MEDIUM': 45, 'LOW': 20}.get(str(vuln.get('severity', '')).upper(), 10)
        if vuln.get('exploitable') == 'Yes':
            score += 40
        if vuln.get('poc_verified'):
            score += 30
        if vuln.get('has_http_entry') or vuln.get('entry_point'):
            score += 20
        if vuln.get('has_call_chain') or vuln.get('callers'):
            score += 15
        if 'controller' in file_path:
            score += 10
        if self._is_project_deserialization_chain(vuln):
            score += 160
        elif 'deserialization' in family or 'deserialize' in vuln_type:
            score += 70
        elif 'path_traversal' in family:
            score += 35
        elif 'csrf' in vuln_type:
            score -= 40
        if 'readobject' in snippet or 'objectinputstream' in snippet:
            score += 30
        if 'process(userconfig)' in snippet or 'transform(' in snippet or '.put(' in snippet:
            score += 18
        return score

    def _sort_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        for vuln in vulnerabilities:
            vuln['priority_score'] = self._priority_score(vuln)
            vuln['is_primary_chain'] = self._is_project_deserialization_chain(vuln)
        return sorted(
            vulnerabilities,
            key=lambda item: (
                -int(item.get('priority_score', 0) or 0),
                -int(item.get('supporting_node_count', 0) or 0),
                str(item.get('file', '')),
                int(item.get('line', 0) or 0),
            ),
        )

    def _enrich_key_finding_details(self, vuln: Dict) -> Dict:
        self._normalize_display_fields(vuln)
        if not self._is_project_deserialization_chain(vuln):
            return vuln

        routes = self._project_chain_routes()
        vuln.setdefault('original_type', vuln.get('original_type') or vuln.get('type', ''))
        vuln['type'] = self._project_chain_display_title()
        vuln['display_title'] = self._project_chain_display_title()
        vuln['display_family'] = 'deserialization'
        vuln['finding_family'] = 'java_deserialization_chain'
        vuln['is_primary_chain'] = True
        vuln['entry_route'] = routes['entry_route']
        vuln['trigger_route'] = routes['trigger_route']
        vuln['attack_chain_summary'] = routes['attack_chain_summary']

        details = dict(vuln.get('poc_details', {}) or {})
        details['target_url'] = routes['entry_route']
        details['target_param'] = 'data'
        details['business_scenario'] = '调试接口导入序列化对象，业务接口二次触发缓存处理'
        details['scenario_rationale'] = f"这不是单步回显型漏洞，而是先通过 {routes['entry_route']} 导入序列化对象，再通过 {routes['trigger_route']} 触发 CacheProcessor.process(userConfig) 的两步链。"
        details['exploit_chain'] = routes['attack_chain_summary']
        details['entry_route'] = routes['entry_route']
        details['trigger_route'] = routes['trigger_route']
        details['description'] = 'Java 反序列化两步验证模板：先导入 Base64 序列化对象，再访问触发接口观察缓存处理副作用。'

        attack_plan = dict(details.get('attack_plan', {}) or {})
        attack_plan['business_goal'] = '验证 Java 反序列化对象是否能够在后续业务流中被二次触发'
        attack_plan['source'] = attack_plan.get('source') or 'deterministic'
        attack_plan['input_role'] = '攻击者提交的 Base64 序列化对象数据'
        attack_plan['delivery_shape'] = f"先通过 POST {routes['entry_route']} 导入，再通过 GET {routes['trigger_route']} 触发处理"
        attack_plan['trigger_condition'] = f"服务端随后访问 {routes['trigger_route']}，并进入 CacheProcessor.process(userConfig)"
        attack_plan['verification_signal'] = '观察导入请求与触发请求的响应、日志、副作用或异常行为是否符合 gadget 执行特征'
        attack_plan['entrypoint'] = {'path': routes['entry_route'], 'method': 'POST', 'parameter': 'data'}
        attack_plan['trigger'] = {'path': routes['trigger_route'], 'method': 'GET'}
        attack_plan['steps'] = [
            f"向 {routes['entry_route']} 提交 Base64 序列化对象，导入恶意缓存配置。",
            f"随后访问 {routes['trigger_route']}，触发缓存处理逻辑。",
            '观察响应、异常日志或业务副作用，判断 gadget 是否被真正执行。',
        ]
        details['attack_plan'] = attack_plan
        details['success_effect'] = '说明导入的序列化对象已进入后续业务链，并在 gadget 触发点产生可观测效果。'
        details['failure_effect'] = '说明当前 payload、依赖条件或运行环境不足以在 CacheProcessor 链路中形成成功利用。'

        no_poc_reason = str(vuln.get('no_poc_reason', '') or '')
        if not vuln.get('poc_verified') and (not no_poc_reason or '?' in no_poc_reason or 'java_header_probe.py' in no_poc_reason or '/api/endpoint' in no_poc_reason):
            vuln['no_poc_reason'] = f"当前目标是 Java 反序列化两步链，需要先向 {routes['entry_route']} 导入对象，再通过 {routes['trigger_route']} 触发缓存处理，不能用通用单步 HTTP probe 判定。"

        vuln['d2_candidate_ready'] = True
        vuln['d2_status'] = 'verified_success' if vuln.get('poc_verified') else ('verified_failed' if vuln.get('poc_generated') else 'plan_ready')
        self._rewrite_project_chain_poc(vuln, details)
        vuln['poc_details'] = details
        return vuln

    def _required_tools(self, vuln: Dict) -> List[str]:
        details = vuln.get('poc_details', {}) or {}
        tools = list(details.get('required_tools', []) or [])
        poc = vuln.get('poc', {}) or {}
        if poc.get('curl') and 'curl' not in tools:
            tools.append('curl')
        if poc.get('python') and 'Python 3' not in tools:
            tools.append('Python 3')
        if poc.get('java') and 'Java' not in tools:
            tools.append('Java')
        return tools

    @staticmethod
    def _canonical_family(vuln: Dict) -> str:
        type_text = str(vuln.get('type', '') or '').lower()
        desc_text = str(vuln.get('description', '') or '').lower()
        text = f"{type_text} {desc_text}"
        if any(token in type_text for token in ('deserialize', 'serialization', '反序列化')):
            return 'deserialization'
        if any(token in type_text for token in ('path', 'traversal', '路径')):
            return 'path_traversal'
        if any(token in type_text for token in ('command', '命令')):
            return 'command_execution'
        if any(token in type_text for token in ('xss', '跨站')):
            return 'xss'
        if 'csrf' in type_text:
            return 'csrf'
        if any(token in text for token in ('deserialize', 'serialization', '反序列化', 'readobject', 'commons-collections')):
            return 'deserialization'
        if any(token in text for token in ('path', 'traversal', '路径穿越')):
            return 'path_traversal'
        if any(token in text for token in ('command', '命令注入', 'processbuilder', 'runtime.exec')):
            return 'command_execution'
        if any(token in text for token in ('xss', '跨站', '存储型xss')):
            return 'xss'
        if 'csrf' in text:
            return 'csrf'
        return normalize_family(vuln.get('type', '') or 'unknown')

    @staticmethod
    def _semantic_tokens(vuln: Dict) -> set:
        text = " ".join([
            str(vuln.get('description', '') or ''),
            str(vuln.get('code_snippet', '') or ''),
            str(vuln.get('callers', '') or ''),
            str(vuln.get('entry_point', '') or ''),
            str(vuln.get('sink', '') or ''),
            str((vuln.get('data_flow') or '')[:400]),
        ]).lower()
        tokens = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_#.\-/]{2,}', text))
        stop = {
            'java', 'spring', 'string', 'object', 'public', 'private', 'class', 'return',
            'this', 'null', 'true', 'false', 'high', 'medium', 'low', 'http', 'https',
            'code', 'user', 'data', 'map', 'value', 'file', 'path',
        }
        return {token for token in tokens if token not in stop}

    def _build_canonical_group_key(self, vuln: Dict) -> str:
        existing_key = str(vuln.get('canonical_group_key', '') or '').strip()
        if existing_key:
            return existing_key
        family = self._canonical_family(vuln)
        if family != 'deserialization':
            return f"{family}:{workspace_runtime.normalize_group_key_path(str(vuln.get('file', '') or ''))}:{vuln.get('line', 0)}"

        tokens = self._semantic_tokens(vuln)
        file_path = str(vuln.get('file', '') or '').lower()
        # 反序列化链标记：基底来自 workspace 配置（java-quote 默认值），附加少量靶场无关的结构性标记
        chain_markers = list(workspace_runtime.deserialization_chain().get('markers', [])) + [
            'quotecontroller', 'quoteservice', 'processuserconfig', 'decoratedmap',
        ]
        matched = sorted(marker for marker in chain_markers if any(marker in token for token in tokens))
        if (
            matched or
            vuln.get('has_http_entry') or
            any(part in file_path for part in ('pom.xml', 'controller', 'service', 'processor')) or
            any(token in tokens for token in ('readobject', 'transformer', 'commons-collections', 'processor.process'))
        ):
            return f"{family}:project_chain"
        if matched:
            return f"{family}:chain:{'|'.join(matched[:6])}"
        return f"{family}:{workspace_runtime.normalize_group_key_path(str(vuln.get('file', '') or ''))}:{vuln.get('line', 0)}"

    def _canonical_score(self, vuln: Dict) -> int:
        score = 0
        file_path = str(vuln.get('file', '') or '').lower()
        snippet = str(vuln.get('code_snippet', '') or '').lower()
        family = self._canonical_family(vuln)
        if vuln.get('has_http_entry') or vuln.get('entry_point'):
            score += 50
        if 'controller' in file_path:
            score += 40
        if family == 'deserialization' and any(token in snippet for token in ('readobject', 'objectinputstream')):
            score += 35
        if any(token in snippet for token in ('transform(', '.put(', 'putall(', 'process(userconfig)', 'writestatus(', 'processbuilder')):
            score += 25
        if 'service' in file_path:
            score += 10
        if file_path.endswith('pom.xml'):
            score -= 20
        score += {'HIGH': 15, 'MEDIUM': 8, 'LOW': 4}.get(str(vuln.get('severity', '')).upper(), 0)
        return score

    def _aggregate_canonical_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        # 2026-09-18（A2 方案二）：聚合吸收成员补行必须排除出分组。
        # 补行刻意沿用所属聚合组的 canonical_group_key（下游靠它做关联与展示折叠），
        # 而 _build_canonical_group_key 对已存在的 key 直接返回原值 —— 若不在此处摘出，
        # 补行会被重新并入同一组、再被 ranked[1:] 吸收进 supporting_nodes，
        # 补行等于白做（覆盖率与关联桥仍为空）。
        absorbed_rows = [dict(v) for v in vulnerabilities if self._is_absorbed_row(v)]
        groupable = [v for v in vulnerabilities if not self._is_absorbed_row(v)]

        grouped = {}
        for vuln in groupable:
            key = self._build_canonical_group_key(vuln)
            grouped.setdefault(key, []).append(vuln)

        aggregated = []
        for group_key, items in grouped.items():
            if len(items) == 1:
                vuln = dict(items[0])
                vuln['canonical_group_key'] = group_key
                vuln['chain_id'] = vuln.get('chain_id') or group_key
                vuln['is_canonical'] = True
                vuln['supporting_nodes'] = list(vuln.get('supporting_nodes', []) or [])
                vuln['supporting_node_count'] = len(vuln['supporting_nodes'])
                vuln['chain_proof'] = normalize_chain_proof(vuln.get('chain_proof') or empty_chain_proof())
                vuln['proof_gaps'] = list(vuln.get('proof_gaps', []) or vuln['chain_proof'].get('proof_gaps', []) or [])
                vuln['exploit_spec'] = normalize_exploit_spec(vuln.get('exploit_spec') or empty_exploit_spec())
                vuln['contract_completeness'] = vuln.get('contract_completeness') or exploit_spec_completeness(vuln['exploit_spec'])
                vuln = self._promote_chain_context(vuln, vuln['supporting_nodes'])
                aggregated.append(vuln)
                continue

            ranked = sorted(items, key=lambda item: (-self._canonical_score(item), str(item.get('file', '')), int(item.get('line', 0) or 0)))
            canonical = dict(ranked[0])
            canonical['canonical_group_key'] = group_key
            canonical['chain_id'] = canonical.get('chain_id') or group_key
            canonical['is_canonical'] = True
            # 2026-11-01（P3）：把被吸收成员的 vhash 记在 canonical 行上。
            # 聚合只保留 ranked[0]，其余进 supporting_nodes；而 findings 表只落 canonical 行，
            # 于是被吸收成员的 spec 因「vhash 在 findings 里查不到」被 reconcile_orphan_specs
            # 当孤儿硬删（本轮删了 16 条，含 Fastjson L23 / Deserialize L50 / Rce L113——
            # 它们本来有 spec，是 finding 在聚合阶段丢了）。
            # 记下来后孤儿判定能认出「这条 spec 属于某个被吸收成员」，不再误删。
            try:
                _absorbed = []
                for _m in ranked[1:]:
                    _h = vulnerability_hash_v2(canonicalize_vuln_for_hash(_m))
                    if _h:
                        _absorbed.append(str(_h))
                if _absorbed:
                    canonical['absorbed_vhashes'] = _absorbed
            except Exception:
                pass

            test_status_rank = {
                'CONFIRMED': 4,
                'VULNERABLE': 3,
                'DONE': 2,
                'ERROR': 1,
                'NOT_TESTED': 0,
            }
            confidence_rank = {
                'confirmed': 4,
                'high': 3,
                'medium': 2,
                'low': 1,
                'unknown': 0,
            }
            evidence_rank = lambda item: (
                bool(item.get('poc_verified')),
                item.get('exploitable') == 'Yes',
                bool(item.get('poc_generated') or has_meaningful_poc(item)),
                test_status_rank.get((item.get('test_status') or '').upper(), -1),
                confidence_rank.get((item.get('confidence') or '').lower(), -1),
                self._canonical_score(item),
            )
            evidence_item = max(items, key=evidence_rank)

            support_nodes = []
            seen_support_nodes = set()
            merged_sources = set(canonical.get('sources', []) or [])
            for node in canonical.get('supporting_nodes', []) or []:
                node_key = (node.get('file', ''), node.get('line', 0), node.get('type', ''))
                if node_key in seen_support_nodes:
                    continue
                seen_support_nodes.add(node_key)
                support_nodes.append(node)
            for item in ranked[1:]:
                merged_sources.update(item.get('sources', []) or [])
                node = {
                    'file': item.get('file', ''),
                    'line': item.get('line', 0),
                    'type': item.get('type', ''),
                    'severity': item.get('severity', ''),
                    'description': item.get('description', ''),
                    'code_snippet': item.get('code_snippet', ''),
                    'entry_point': item.get('entry_point', ''),
                    'sink': item.get('sink', ''),
                    'callers': item.get('callers', ''),
                    'chain_id': item.get('chain_id', '') or item.get('canonical_group_key', ''),
                    'proof_tier': item.get('proof_tier', 'broad_static'),
                    'chain_proof': normalize_chain_proof(item.get('chain_proof') or empty_chain_proof()),
                    'proof_gaps': list(item.get('proof_gaps', []) or []),
                }
                node_key = (node.get('file', ''), node.get('line', 0), node.get('type', ''))
                if node_key in seen_support_nodes:
                    continue
                seen_support_nodes.add(node_key)
                support_nodes.append(node)

            canonical['sources'] = sorted(merged_sources)
            canonical['supporting_nodes'] = support_nodes
            canonical['supporting_node_count'] = len(support_nodes)
            canonical['evidence_files'] = [f"{node['file']}:{node['line']}" for node in support_nodes]
            merged_exploit_spec = normalize_exploit_spec(canonical.get('exploit_spec') or empty_exploit_spec())
            for item in items:
                merged_exploit_spec = merge_exploit_specs(merged_exploit_spec, item.get('exploit_spec') or empty_exploit_spec())
            canonical['exploit_spec'] = merged_exploit_spec
            proof_item = max(
                items,
                key=lambda item: (
                    str(item.get('proof_tier', 'broad_static')) == 'chain_proven',
                    len(item.get('proof_gaps', []) or [] ) == 0,
                    len(item.get('supporting_nodes', []) or []),
                    self._canonical_score(item),
                ),
            )
            canonical['proof_tier'] = proof_item.get('proof_tier', 'broad_static')
            canonical['chain_proof'] = normalize_chain_proof(proof_item.get('chain_proof') or empty_chain_proof())
            canonical['proof_gaps'] = list(proof_item.get('proof_gaps', []) or canonical['chain_proof'].get('proof_gaps', []) or [])
            canonical['contract_completeness'] = canonical.get('contract_completeness') or exploit_spec_completeness(canonical['exploit_spec'])
            canonical = self._promote_chain_context(canonical, support_nodes)

            if any(item.get('exploitable') == 'Yes' for item in items):
                canonical['exploitable'] = 'Yes'
            elif any(item.get('exploitable') == 'No' for item in items):
                canonical['exploitable'] = 'No'
            else:
                canonical['exploitable'] = evidence_item.get('exploitable', canonical.get('exploitable', 'Unknown'))

            mainline_items = [item for item in items if is_mainline_d2_item(item)]
            execution_items = [item for item in mainline_items if is_executed_d2_item(item)]
            canonical['poc_generated'] = any(item.get('poc_generated') or has_meaningful_poc(item) for item in mainline_items)
            canonical['poc_verified'] = any(item.get('poc_verified') for item in mainline_items)
            canonical['docker_attempted'] = any(item.get('docker_attempted') for item in execution_items)
            canonical['docker_used'] = any(item.get('docker_used') for item in execution_items)
            canonical['local_jar_attempted'] = any(item.get('local_jar_attempted') for item in execution_items)
            canonical['runtime_source'] = next((item.get('runtime_source', '') for item in execution_items if item.get('runtime_source')), '')
            canonical['runtime_type'] = next((item.get('runtime_type', '') for item in execution_items if item.get('runtime_type')), '')
            canonical['container_kept_running'] = any(item.get('container_kept_running') for item in execution_items)
            canonical['service_ready'] = any(item.get('service_ready') for item in execution_items)

            strongest_test = max(items, key=lambda item: test_status_rank.get((item.get('test_status') or '').upper(), -1))
            strongest_confidence = max(items, key=lambda item: confidence_rank.get((item.get('confidence') or '').lower(), -1))
            canonical['test_status'] = strongest_test.get('test_status', canonical.get('test_status', 'NOT_TESTED'))
            canonical['confidence'] = strongest_confidence.get('confidence', canonical.get('confidence', 'low'))
            if evidence_item.get('failure_classification'):
                canonical['failure_classification'] = evidence_item.get('failure_classification')
            if evidence_item.get('contract_completeness'):
                canonical['contract_completeness'] = evidence_item.get('contract_completeness')
            if evidence_item.get('execution_evidence'):
                canonical['execution_evidence'] = evidence_item.get('execution_evidence')
            if evidence_item.get('verification_decision'):
                canonical['verification_decision'] = evidence_item.get('verification_decision')

            for field in (
                'poc',
                'poc_file',
                'llm_poc_code',
                'poc_details',
                'verification_note',
                'no_poc_reason',
                'reason',
                'container_id',
                'service_url',
                'raw_output',
                'verified_bundle',
            ):
                if evidence_item.get(field):
                    canonical[field] = evidence_item.get(field)

            canonical['step_errors'] = evidence_item.get('step_errors', canonical.get('step_errors', []))

            # R23-1：canonical 取自 ranked[0]，可能恰好是不带 A1 证据的同族副本；此处取组内
            # 「首个非空」a1_evidence 兜底，避免证据在报告聚合阶段被静默丢掉（单副本分支
            # 走 dict(items[0]) 天然保留，无需处理）。
            if not canonical.get('a1_evidence'):
                for item in items:
                    if item.get('a1_evidence'):
                        canonical['a1_evidence'] = dict(item.get('a1_evidence') or {})
                        break

            aggregated.append(canonical)

        # 2026-09-18（A2 方案二）：补行原样回填。它们不参与分组/吸收，也不参与 canonical 的
        # supporting_nodes 派生，仅作为「独立 findings 行」存在 —— 目的单一：
        # 让 file_path 维度统计与 iast_events 关联桥能看到这些被吸收的节点自己所在的文件。
        # 消费侧门禁：is_absorbed=True 不参与 D2 候选（a2_contract_planner 硬闸 + is_mainline_d2_item）。
        aggregated.extend(absorbed_rows)
        return aggregated

    @staticmethod
    def _is_absorbed_row(vuln: Dict) -> bool:
        """聚合吸收成员补行判定（兼容 dict 的 bool/字符串两种落盘形态）。"""
        raw = vuln.get('is_absorbed')
        if isinstance(raw, str):
            return raw.strip().lower() in ('1', 'true', 'yes')
        return bool(raw)

    @staticmethod
    def _verification_matches(vuln: Dict, verification: Dict) -> bool:
        canonical_key = str(vuln.get('canonical_group_key', '') or '').strip()
        if canonical_key and canonical_key == str(verification.get('canonical_group_key', '') or '').strip():
            return True

        # §#3②：权威关联键。verification 携带 spec 的 vulnerability_hash_v2（trigger_spec_hash /
        # vulnerability_hash_v2），与 finding 的 vulnerability_hash_v2 同源计算，严格绑定校验↔finding。
        # 这是与 #7（bind_specs_to_findings 按 vuln_hash 绑定 spec↔finding）一致的权威关联口径。
        _vh = str(vuln.get('vulnerability_hash_v2') or '').strip()
        _vh_v = str(
            verification.get('vulnerability_hash_v2')
            or verification.get('trigger_spec_hash')
            or ''
        ).strip()
        if _vh and _vh == _vh_v:
            return True

        match_keys = verification.get('match_keys', []) or []
        raw_key = f"raw:{vuln.get('file', '')}:{vuln.get('type', '')}:{vuln.get('line', 0)}"
        if raw_key in match_keys:
            return True

        if (
            verification.get('file') == vuln.get('file')
            and verification.get('type') == vuln.get('type')
            and abs(int(verification.get('line', 0) or 0) - int(vuln.get('line', 0) or 0)) <= 3
        ):
            return True

        # §A1/A2 孪生兜底：同一漏洞在 A1（如 "Deserialization"/"Java 反序列化链"）与 A2
        # （如 "反序列化"/"反序列化链"）常给出不同 chain_id / type 标签，精确匹配全部 miss，
        # 导致 A1 那条 finding 始终显 Unknown。这里按「同文件(basename) + 同 family」兜底衔接，
        # 只把已确证态归因到孪生 finding，不跨文件、不跨族误归因（避免假阳性）。
        return ReportManager._verification_fallback_match(vuln, verification)

    # §孪生兜底行邻近阈值（2026-09-22）：同一漏洞的 A1/A2 两个身份常报在不同行
    # （/spel/vuln2 是 33 与 37、/jwt/createToken 是 31 与 38），精确键与既有 Δ≤3 都吃不下。
    _FALLBACK_LINE_TOLERANCE = 10

    @staticmethod
    def _verification_fallback_match(vuln: Dict, verification: Dict) -> bool:
        """同文件(basename，大小写无关) + 同族 **或** 行邻近 兜底匹配。

        衔接 A1 canonical 与 A2 假说对同一条漏洞给出的不同身份标签。

        2026-09-22 扩展（14 条 enqueued_but_no_verification_record 的真因）：
        run 37 实测 D2 **确实执行并产出记录**（如 /jwt/createToken 有 confirmed_exploitable 记录），
        但记录携带的是另一端身份 —— A1 源，其 vulnerability_hash_v2 可能是 hex
        （746982d7…）也可能是 cgk 形态（"jwt硬编码或弱密钥:src\\...\\jwt.java:38"）；
        而 finding 是 A2 源（Jwt.java:31 / vertical_privesc）。五个精确键全 miss，
        报告层因此判「无验证记录」，写成 enqueued_but_no_verification_record。
        故兜底必须覆盖「同 basename + 同族 或 行邻近」：
        - basename 来源扩到 chain_id / canonical_group_key / vulnerability_hash_v2(cgk 形态) / file；
        - 行号从上述 cgk 形态或 verification.line 取，容忍 Δ≤_FALLBACK_LINE_TOLERANCE；
        - 两端族标签不同（jwt硬编码或弱密钥 vs vertical_privesc）时以行邻近放行。

        2026-09-22 二次扩展（run 38 残留 4 条）：部分 verification 记录**只带 endpoint，不带
        file/sink_line**（如 /url/vuln/contains 的 confirmed 记录 sink_file=None），basename 兜底
        无从下手。而 finding 侧 `exploit_spec.entry.route` 就是端点。故补端点级兜底：
        端点相等即视为同一漏洞。**限多段端点**（'/' 出现 ≥2 次）以排除类级基路径
        （/ssrf、/cors、/jwt 这类单段基路径由 ② 类级路由改动单独治理，不在此误收）。
        """
        # §端点级兜底（多段端点才认，避免类级基路径误收）
        # 键名坑（2026-09-22 实测）：本函数吃的是 **D2 原始 verification 字典**，它没有顶层
        # `endpoint` —— 端点在 `trigger_spec_detail.endpoint` 下（顶层 `endpoint` 只存在于
        # `_d2_verification_detail` 抽出的 verifications_detail 投影里）。首版只读顶层键 →
        # 恒为空 → 端点兜底从未生效（run 39 实测残留仍 4 条，与 run 38 一致）。两处都读。
        _ep_v = str(
            verification.get('endpoint')
            or (verification.get('trigger_spec_detail') or {}).get('endpoint')
            or ''
        ).strip()
        _ep_f = str(((vuln.get('exploit_spec') or {}).get('entry') or {}).get('route') or '').strip()
        if _ep_v and _ep_f and _ep_v == _ep_f and _ep_v.count('/') >= 2:
            return True

        def _fam(s):
            s = (s or '').lower()
            # 中文标签 → 英文族 token（A1 canonical 用拉丁 "deserialization"，A2 假说用中文 "反序列化"）
            zh_map = {
                '反序列化': 'deserialization',
                '路径': 'path_traversal', '目录': 'path_traversal', '穿越': 'path_traversal',
                '跨站': 'xss',
                '注入': 'injection',
                '泄露': 'info_disclosure', '泄漏': 'info_disclosure',
                '赋值': 'mass_assignment',
                '越权': 'idor',
                # 2026-09-22 扩：jwt / 重定向 / 白名单 / spel / crlf / 命令执行 / ssrf / 提权
                'jwt': 'jwt', '弱密钥': 'jwt', '硬编码': 'jwt',
                '重定向': 'url_redirect',
                '白名单': 'url_whitelist',
                '表达式': 'spel',
                '换行': 'crlf',
                '命令': 'command_execution',
                '服务端请求': 'ssrf',
                '提权': 'idor',
            }
            for zh, tok in zh_map.items():
                if zh in s:
                    return tok
            if 'deserial' in s:
                return 'deserialization'
            if 'travers' in s or 'path' in s:
                return 'path_traversal'
            if 'xss' in s:
                return 'xss'
            if 'sqli' in s or 'sql' in s or 'injection' in s:
                return 'injection'
            if 'disclos' in s or 'info' in s:
                return 'info_disclosure'
            if 'mass' in s:
                return 'mass_assignment'
            if 'idor' in s or 'bola' in s:
                return 'idor'
            if 'redirect' in s:
                return 'url_redirect'
            if 'whitelist' in s:
                return 'url_whitelist'
            if 'jwt' in s:
                return 'jwt'
            if 'spel' in s:
                return 'spel'
            if 'crlf' in s:
                return 'crlf'
            if 'privesc' in s:
                return 'idor'
            return s

        def _base_and_line(text, fallback_file=None, fallback_line=None):
            """从 cgk / chain_id / hash 形态串解析 (basename, line)；解析不出则退到 file/line。"""
            t = str(text or '').strip()
            m = re.search(r'([^/\\:]+?)\.java\s*:\s*(\d+)\s*$', t, re.IGNORECASE)
            if m:
                return m.group(1).lower(), int(m.group(2))
            if fallback_file:
                return re.sub(r'\.java$', '', os.path.basename(str(fallback_file)), flags=re.IGNORECASE).lower(), fallback_line
            return None, fallback_line

        # verification 侧：身份串可能落在 chain_id / canonical_group_key / vulnerability_hash_v2(cgk 形态)
        v_base, v_line = None, None
        for _vid in (
            verification.get('chain_id'),
            verification.get('canonical_group_key'),
            verification.get('vulnerability_hash_v2'),
        ):
            v_base, v_line = _base_and_line(_vid)
            if v_base:
                break
        if not v_base:
            v_base, v_line = _base_and_line(None, fallback_file=verification.get('file'), fallback_line=verification.get('line'))

        # finding 侧
        f_base, f_line = None, None
        for _fid in (
            vuln.get('chain_id'),
            vuln.get('canonical_group_key'),
            vuln.get('vulnerability_hash_v2'),
        ):
            f_base, f_line = _base_and_line(_fid)
            if f_base:
                break
        if not f_base:
            f_base, f_line = _base_and_line(None, fallback_file=vuln.get('file'), fallback_line=vuln.get('line'))

        if not v_base or not f_base or v_base != f_base:
            return False

        # 行邻近（两端行号都拿到才算）
        try:
            _vl = int(v_line) if v_line is not None else None
            _fl = int(f_line) if f_line is not None else None
        except (TypeError, ValueError):
            _vl = _fl = None
        _near = (
            _vl is not None and _fl is not None
            and abs(_vl - _fl) <= ReportManager._FALLBACK_LINE_TOLERANCE
        )

        v_fam = (
            _fam(verification.get('chain_id'))
            or _fam(str((verification.get('trigger_spec_detail') or {}).get('family', '')))
            or _fam(verification.get('type'))
            or _fam(verification.get('vulnerability_hash_v2'))
        )
        f_fam = _fam(vuln.get('chain_id')) or _fam(vuln.get('canonical_group_key')) or _fam(vuln.get('type'))
        _same_fam = bool(v_fam and f_fam and v_fam == f_fam)
        return bool(_same_fam or _near)

    @staticmethod
    def _verification_priority(vuln: Dict, verification: Dict) -> tuple:
        canonical_key = str(vuln.get('canonical_group_key', '') or '').strip()
        verification_key = str(verification.get('canonical_group_key', '') or '').strip()
        # §#3②：vuln_hash 权威关联优先于一切模糊匹配键
        _vh = str(vuln.get('vulnerability_hash_v2') or '').strip()
        _vh_v = str(
            verification.get('vulnerability_hash_v2')
            or verification.get('trigger_spec_hash')
            or ''
        ).strip()
        exact_vuln_hash = bool(_vh and _vh == _vh_v)
        exact_file = verification.get('file') == vuln.get('file')
        exact_type = verification.get('type') == vuln.get('type')
        line_delta = abs(int(verification.get('line', 0) or 0) - int(vuln.get('line', 0) or 0))
        exact_line = line_delta == 0
        match_keys = verification.get('match_keys', []) or []
        raw_key = f"raw:{vuln.get('file', '')}:{vuln.get('type', '')}:{vuln.get('line', 0)}"
        exact_raw_key = raw_key in match_keys
        test_status = str(verification.get('test_status', '') or '').upper()
        test_status_rank = {
            'CONFIRMED': 4,
            'VULNERABLE': 3,
            'DONE': 2,
            'ERROR': 1,
            'NOT_TESTED': 0,
        }
        confidence_rank = {
            'confirmed': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'unknown': 0,
        }
        # §带裁决优先（2026-09-22，⑦-3）：候选里混着「同文件另一条、但根本没裁决」的记录
        # （孪生兜底放宽后尤其常见），若按精确键优先选中它，finding 会被写成
        # 「有 execution_evidence 却无 verification_decision」的空壳 —— 实测 Rce.java:90、
        # SocketHookImpl.java:112/137 这 3 条 chain_proven 就是这么丢的（已归
        # A21_CONTRACT_FAILURE，实为折叠取错记录）。已通过 _verification_matches 的候选
        # 都是同一漏洞的可信身份，故「带裁决」理应压过「键更精确但无裁决」。
        _vd = verification.get('verification_decision') or {}
        has_decision = bool(
            str(_vd.get('verification_status') or '').strip()
            or str(verification.get('final_state') or '').strip()
        )
        return (
            has_decision,
            exact_vuln_hash,
            exact_raw_key,
            bool(canonical_key and canonical_key == verification_key and exact_file and exact_type and line_delta <= 3),
            bool(exact_file and exact_type and exact_line),
            bool(exact_file and exact_type and line_delta <= 3),
            verification.get('exploitable') == 'Yes',
            bool(verification.get('poc_verified')),
            bool(verification.get('poc_generated') or has_meaningful_poc(verification)),
            test_status_rank.get(test_status, -1),
            confidence_rank.get(str(verification.get('confidence', '') or '').lower(), -1),
        )

    def _select_best_verification(self, vuln: Dict, verifications: List[Dict]) -> Dict:
        candidates = [verification for verification in verifications if self._verification_matches(vuln, verification)]
        if not candidates:
            return {}
        return max(candidates, key=lambda verification: self._verification_priority(vuln, verification))

    def _read_text_file(self, path_text: str) -> str:
        if not path_text:
            return ''
        try:
            return Path(path_text).read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return ''

    def _read_json_file(self, path_text: str) -> Dict:
        if not path_text:
            return {}
        try:
            return json.loads(Path(path_text).read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            return {}

    def _build_project_overview(self, target_path: str, files: List[Dict], discovered_endpoints: Dict[str, List[Dict]], vulnerabilities: List[Dict]) -> Dict:
        file_type_breakdown = {}
        for file_info in files or []:
            rel_path = file_info.get('rel_path', '')
            suffix = Path(rel_path).suffix.lower().lstrip('.') or 'unknown'
            file_type_breakdown[suffix] = file_type_breakdown.get(suffix, 0) + 1

        total_routes = sum(len(items) for items in (discovered_endpoints or {}).values())
        sink_points = set()
        for vuln in vulnerabilities:
            sink = (vuln.get('sink') or '').strip()
            if sink:
                sink_points.add(f"{vuln.get('file', '')}:{sink}")
            else:
                sink_points.add(f"{vuln.get('file', '')}:{vuln.get('line', '')}:{vuln.get('type', '')}")

        tested_routes = set()
        for vuln in vulnerabilities:
            # P1-3：R7 实测 vuln 记录里 poc_details/raw_output 不含可解析的 http_request URL
            # （导致 tested_route 恒为 0 / 覆盖率恒 0%），但每个 vuln 真实携带 entry_route /
            # trigger_route / exploit_spec.entry.route —— 即 D1/D2 实际打点的路由。把真实路由纳入，
            # 使「已测试路由数 / 覆盖率」反映真实 DAST 覆盖范围而非恒 0（仍 0 才是真没测）。
            for _r in (
                vuln.get('entry_route'),
                vuln.get('trigger_route'),
                (((vuln.get('exploit_spec') or {}).get('entry') or {}).get('route')),
            ):
                if _r and isinstance(_r, str) and _r.strip():
                    tested_routes.add(_r.strip())
            details = vuln.get('poc_details', {}) or {}
            result_json = self._read_json_file(details.get('result_json', ''))
            attack_requests = (result_json.get('attack_requests') or {}) if result_json else {}
            for request_key in ('import_request', 'trigger_request'):
                request_info = attack_requests.get(request_key) or {}
                request_url = request_info.get('url', '')
                if request_url:
                    parsed = urlparse(request_url)
                    tested_routes.add(parsed.path or request_url)

            raw_output = vuln.get('raw_output', '')
            if not raw_output:
                continue
            try:
                payload = json.loads(raw_output)
            except Exception:
                continue
            steps = payload.get('steps', []) if isinstance(payload, dict) else payload if isinstance(payload, list) else []
            for step in steps:
                if step.get('tool') != 'http_request':
                    continue
                step_result = step.get('result', {}) or {}
                url = step_result.get('url') or step.get('params', {}).get('url') or ''
                if url:
                    parsed = urlparse(url)
                    tested_routes.add(parsed.path or url)

        coverage_rate = round(len(tested_routes) / total_routes * 100, 2) if total_routes else 0.0
        return {
            'target_path': target_path,
            'file_count': len(files or []),
            'file_type_breakdown': file_type_breakdown,
            'route_count': total_routes,
            'tested_route_count': len(tested_routes),
            'route_coverage_rate': coverage_rate,
            'sink_count': len(sink_points),
        }

    def _format_http_request_block(self, request_info: Dict) -> str:
        method = request_info.get('method', 'GET')
        url = request_info.get('url', '')
        headers = request_info.get('headers', {}) or {}
        body = request_info.get('body_preview', '')
        lines = [f"{method} {url} HTTP/1.1"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        if body:
            lines.append("")
            lines.append(body)
        return "\n".join(lines)

    def _format_http_response_block(self, response_info: Dict) -> str:
        status_code = response_info.get('status_code', '')
        body = response_info.get('body', '')
        lines = [f"HTTP/1.1 {status_code}"]
        if body:
            lines.append("")
            lines.append(body)
        return "\n".join(lines)

    def _format_curl_command(self, request_info: Dict) -> str:
        method = request_info.get('method', 'GET')
        url = request_info.get('url', '')
        headers = request_info.get('headers', {}) or {}
        body = request_info.get('body_preview', '')
        parts = [f'curl -X {method} "{url}"']
        for key, value in headers.items():
            parts.append(f'-H "{key}: {value}"')
        if body:
            safe_body = body.replace('"', '\\"')
            parts.append(f'--data "{safe_body}"')
        return " ".join(parts)

    def _save_json(self, data: Dict, filename: str):
        """保存 JSON 格式"""
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"JSON saved: {output_path}")
        return output_path

    def _save_markdown(self, content: str, filename: str):
        """保存 Markdown 格式"""
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Markdown saved: {output_path}")
        return output_path

    def generate_b1_report(self, a1_results: List[ScanResult], a2_results: List[ScanResult],
                           discovered_endpoints: List[Dict] = None) -> Dict:
        """
        生成 B1 报告 - 初步静态分析结论

        Args:
            a1_results: A1 规则扫描结果
            a2_results: A2 AI 扫描结果
            discovered_endpoints: 可选，发现的端点列表

        Returns:
            报告数据字典
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # 收集所有漏洞
        a1_vulns = []
        a2_vulns = []

        for result in a1_results:
            if result.error:
                continue
            for vuln in result.vulnerabilities:
                vuln_dict = vuln.to_dict()
                vuln_dict['file'] = result.file
                vuln_dict['source'] = 'A1'
                a1_vulns.append(vuln_dict)

        for result in a2_results:
            if result.error:
                continue
            for vuln in result.vulnerabilities:
                vuln_dict = vuln.to_dict()
                vuln_dict['file'] = result.file
                vuln_dict['source'] = 'A2'
                a2_vulns.append(vuln_dict)

        a2_suppressed = []
        for result in a2_results:
            if result.error:
                continue
            for item in getattr(result, 'suppressed_vulnerabilities', []) or []:
                suppressed_item = dict(item)
                suppressed_item['file'] = suppressed_item.get('file') or result.file
                a2_suppressed.append(suppressed_item)

        # 统计
        total_vulns = len(a1_vulns) + len(a2_vulns)
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        by_type = {}

        by_flow_type: Dict[str, int] = {}
        for v in a1_vulns + a2_vulns:
            sev = normalize_severity(v.get('severity', 'UNKNOWN'))
            by_severity[sev] = by_severity.get(sev, 0) + 1

            vtype = normalize_type(v.get('type', 'Unknown'))
            by_type[vtype] = by_type.get(vtype, 0) + 1

            # 第三轴：流量类型（业务差分 / 注入重放 / 暴露配置）。暴露配置类不计入 18/17 召回口径。
            vfamily = v.get('family') or v.get('display_family') or v.get('type') or v.get('category') or ''
            ft = derive_flow_type(vfamily)
            by_flow_type[ft] = by_flow_type.get(ft, 0) + 1

        # 计算覆盖率统计
        all_vuln_types = list(by_type.keys())
        coverage_stats = calculate_coverage_stats(
            discovered_endpoints=discovered_endpoints,
            vulnerability_types=all_vuln_types
        )

        # 构建报告
        report = {
            'report_type': 'B1',
            'title': 'SAST AI 初步静态分析报告',
            'timestamp': timestamp,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_vulnerabilities': total_vulns,
                'a1_count': len(a1_vulns),
                'a2_count': len(a2_vulns),
                'a2_retained_count': len(a2_vulns),
                'a2_suppressed_boundary_count': len(a2_suppressed),
                'a2_raw_count': len(a2_vulns) + len(a2_suppressed),
                'by_severity': by_severity,
                'by_type': by_type,
                'by_flow_type': by_flow_type
            },
            'coverage': coverage_stats,
            'a1_results': a1_vulns,
            'a2_results': a2_vulns,
            'a2_suppressed_boundary_findings': a2_suppressed,
            'note': '此为初步静态分析报告，包含A1规则扫描和A2 AI分析结果，需经D2动态验证后生成最终报告'
        }

        # 保存 JSON
        json_path = self._save_json(report, f'b1_report_{timestamp}.json')

        return {
            'report': report,
            'markdown_file': '',
            'json_file': json_path
        }

    def _generate_b1_markdown(self, report: Dict) -> str:
        """生成 B1 Markdown 报告"""
        lines = []

        lines.append("# B1 初步静态分析报告")
        lines.append("")
        lines.append(f"**生成时间**: {report['generated_at']}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 执行摘要
        lines.append("## 执行摘要")
        lines.append("")
        summary = report['summary']
        lines.append(f"**总漏洞数**: {summary['total_vulnerabilities']}")
        lines.append(f"- A1 规则扫描发现: {summary['a1_count']}")
        lines.append(f"- A2 AI 分析发现: {summary['a2_count']}")
        lines.append("")

        # 覆盖率统计
        coverage = report.get('coverage', {})
        if coverage:
            lines.append("## 覆盖率统计")
            lines.append("")

            api_cov = coverage.get('api_coverage', {})
            if api_cov.get('total_discovered', 0) > 0:
                lines.append("### API 覆盖率")
                lines.append("")
                lines.append(f"- 发现端点: {api_cov.get('total_discovered', 0)}")
                lines.append(f"- 已测试: {api_cov.get('tested', 0)}")
                lines.append(f"- 覆盖率: {api_cov.get('coverage_rate', 0)}%")
                lines.append("")

            vuln_cov = coverage.get('vulnerability_coverage', {})
            if vuln_cov.get('types_found', 0) > 0:
                lines.append("### 漏洞类型覆盖率")
                lines.append("")
                lines.append(f"- 规则总数: {vuln_cov.get('total_rules', 0)}")
                lines.append(f"- 发现类型: {vuln_cov.get('types_found', 0)}")
                lines.append(f"- 覆盖率: {vuln_cov.get('coverage_rate', 0)}%")
                if vuln_cov.get('missing_types'):
                    lines.append(f"- 未覆盖类型: {', '.join(vuln_cov['missing_types'])}")
                lines.append("")

        # 按严重程度
        lines.append("### 按严重程度")
        lines.append("")
        for sev in ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = summary['by_severity'].get(sev, 0)
            if count > 0:
                icon = {'HIGH': '[H]', 'MEDIUM': '[M]', 'LOW': '[L]'}.get(sev, '[?]')
                lines.append(f"- {icon} **{sev}**: {count}")
        lines.append("")

        # 按类型
        lines.append("### 按漏洞类型")
        lines.append("")
        for vtype, count in sorted(summary['by_type'].items(), key=lambda x: -x[1]):
            lines.append(f"- {vtype}: {count}")
        lines.append("")

        # 按流量类型（第三轴：暴露/配置类独立于注入/业务，不计入 18/17 召回口径）
        lines.append("### 按流量类型")
        lines.append("")
        _flow_labels = {
            'business_logic': '业务逻辑（差分证明）',
            'injection': '注入型（污点重放）',
            'exposure': '暴露/配置（第三轴，不计入召回）',
        }
        for _ft in ('business_logic', 'injection', 'exposure'):
            _fc = (summary.get('by_flow_type') or {}).get(_ft, 0)
            if _fc > 0:
                lines.append(f"- {_flow_labels[_ft]}: {_fc}")
        lines.append("")

        lines.append("---")
        lines.append("> **注意**: 此为初步静态分析报告，需经 D2 动态验证后生成最终安全审计报告。")
        lines.append("")

        return '\n'.join(lines)

    def generate_final_report(self, a1_results: List[ScanResult], a2_results: List[ScanResult],
                           d2_verifications: Dict, files: List[Dict] = None,
                           discovered_endpoints: Dict[str, List[Dict]] = None,
                           target_path: str = '') -> Dict:
        """
        生成最终安全审计报告 - 最终汇总报告(含 POC)

        Args:
            a1_results: A1 规则扫描结果
            a2_results: A2 AI 扫描结果
            d2_verifications: D2 统一验证链路结果 (D1重放 + I1关联 + D2核实 + I2裁决, 含 POC)

        Returns:
            报告数据字典
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # 收集所有漏洞
        all_vulns = []
        seen = set()

        for result in a1_results + a2_results:
            if result.error:
                continue
            for vuln in result.vulnerabilities:
                key = f"{result.file}:{vuln.type}:{vuln.line}"
                if key not in seen:
                    seen.add(key)

                    # 获取verdict信息
                    verdict = getattr(vuln, 'verdict', '')
                    has_call_chain = getattr(vuln, 'has_call_chain', False)
                    callers = getattr(vuln, 'callers', '')

                    all_vulns.append({
                        'file': result.file,
                        'type': vuln.type,
                        'line': vuln.line,
                        'severity': vuln.severity,
                        'description': vuln.description,
                        'code_snippet': vuln.code_snippet,
                        'sources': [result.agent.upper()],
                        'verdict': verdict,
                        'has_call_chain': has_call_chain,
                        'callers': callers,
                        'entry_point': getattr(vuln, 'entry_point', ''),
                        'sink': getattr(vuln, 'sink', ''),
                        'data_flow': getattr(vuln, 'data_flow', ''),
                        'has_http_entry': getattr(vuln, 'has_http_entry', False),
                        'canonical_group_key': getattr(vuln, 'canonical_group_key', ''),
                        'chain_id': getattr(vuln, 'chain_id', '') or getattr(vuln, 'canonical_group_key', ''),
                        'is_canonical': getattr(vuln, 'is_canonical', False),
                        # 2026-09-18（A2 方案二）：聚合吸收成员补行标记。
                        # is_absorbed=True 的行只用于恢复「按 file_path 的覆盖率统计」与
                        # iast_events 关联桥，不参与 D2 候选（见 a2_contract_planner 硬闸），
                        # 前端列表按该标记折叠展示，避免与所属聚合 finding 重复。
                        'is_absorbed': bool(getattr(vuln, 'is_absorbed', False)),
                        'absorbed_by_group_key': str(getattr(vuln, 'absorbed_by_group_key', '') or ''),
                        'supporting_nodes': list(getattr(vuln, 'supporting_nodes', []) or []),
                        'supporting_node_count': int(getattr(vuln, 'supporting_node_count', 0) or 0),
                        'proof_tier': getattr(vuln, 'proof_tier', 'broad_static'),
                        'chain_proof': normalize_chain_proof(getattr(vuln, 'chain_proof', {}) or empty_chain_proof()),
                        'proof_gaps': list(getattr(vuln, 'proof_gaps', []) or []),
                        # 路径 C：二次证明留痕（模型补证了哪些项、是否升级），供报告与前端展示
                        'proof_second_pass': dict(getattr(vuln, 'proof_second_pass', {}) or {}),
                        'proof_context_summary': dict(getattr(vuln, 'proof_context_summary', {}) or {}),
                        'exploit_spec': normalize_exploit_spec(getattr(vuln, 'exploit_spec', {}) or empty_exploit_spec()),
                        'contract_gaps': list(getattr(vuln, 'contract_gaps', []) or []),
                        'a21_selected': getattr(vuln, 'a21_selected', None),
                        'a21_reason': getattr(vuln, 'a21_reason', ''),
                        # E12（2026-10-26）：CWE 对齐输出。**只做输出口径**（不参与任何判定），
                        # 让报告可跨靶场通用。case 级映射需外部真值 CSV（SAST_AI_CWE_MAP 指向
                        # expectedresults-*.csv），没配就只给族级映射。
                        'cwe': _cwe_of_entry(result.file, vuln.type,
                                             getattr(vuln, 'family', '')),
                        'a21_candidate_score': int(getattr(vuln, 'a21_candidate_score', 0) or 0),
                        # 污点流假说与确认态（sink ≠ 危险，需完整 flow 才可断言）
                        'taint_flow_hypothesis': dict(getattr(vuln, 'taint_flow_hypothesis', {}) or {}),
                        'confirmed': bool(getattr(vuln, 'confirmed', False)),
                        'is_dangerous': bool(getattr(vuln, 'is_dangerous', False)),
                        'severity_claimed': str(getattr(vuln, 'severity_claimed', '') or ''),
                        # A1 规则命中标记（不走污点流四维度评判）：detection_method + 中文规则名
                        'detection_method': str(getattr(vuln, 'detection_method', '') or ''),
                        'rule_name': str(getattr(vuln, 'rule_name', '') or ''),
                        # §#3②：权威关联键。与 run_d2_verify / enrich_finding_hash 同口径：
                        # 经 canonicalize_vuln_for_hash 归一后算 vulnerability_hash_v2，使报告层
                        # finding 与 D2 验证产物按 vuln_hash 严格绑定（而非仅依赖 chain_id / file:line 模糊匹配）。
                        # 校验↔finding 关联失败时，旧匹配键仍可兜底，故此处只增不强。
                        'vulnerability_hash_v2': vulnerability_hash_v2(canonicalize_vuln_for_hash(vuln)),
                        # R23-1（a1_evidence 落库时序）：报告层必须原样携带 A1 证据，否则收尾
                        # replace_for_task 的 INSERT 无从取值，A1 证据只能靠「注册期注册器用
                        # 全局 vhash UPDATE」滞后写进上一轮的行（详见 trigger_spec_registry
                        # auto_register_from_a2 的时序注释）。此处随报告 payload 一并下发，
                        # 使本任务证据在本任务行内一次落定。
                        'a1_evidence': dict(getattr(vuln, 'a1_evidence', {}) or {}),
                    })
                else:
                    # 合并来源
                    for v in all_vulns:
                        if (v['file'] == result.file and
                            v['type'] == vuln.type and
                            abs(v['line'] - vuln.line) <= 3):
                            if result.agent.upper() not in v['sources']:
                                v['sources'].append(result.agent.upper())
                            merged_supporting = list(v.get('supporting_nodes', []) or [])
                            incoming_supporting = list(getattr(vuln, 'supporting_nodes', []) or [])
                            if incoming_supporting and len(incoming_supporting) >= len(merged_supporting):
                                v['supporting_nodes'] = incoming_supporting
                                v['supporting_node_count'] = int(getattr(vuln, 'supporting_node_count', 0) or len(incoming_supporting))
                            for field in ('verdict', 'callers', 'entry_point', 'sink', 'data_flow', 'canonical_group_key', 'chain_id', 'proof_tier'):
                                incoming = getattr(vuln, field, None)
                                if incoming not in (None, "", 0, False):
                                    v[field] = incoming
                            if getattr(vuln, 'has_call_chain', False):
                                v['has_call_chain'] = True
                            if getattr(vuln, 'has_http_entry', False):
                                v['has_http_entry'] = True
                            if getattr(vuln, 'confirmed', False):
                                v['confirmed'] = True
                            if getattr(vuln, 'is_dangerous', False):
                                v['is_dangerous'] = True
                            if str(getattr(vuln, 'severity_claimed', '') or ''):
                                v['severity_claimed'] = str(getattr(vuln, 'severity_claimed') or '')
                            if getattr(vuln, 'detection_method', ''):
                                v['detection_method'] = str(getattr(vuln, 'detection_method') or '')
                            if getattr(vuln, 'rule_name', ''):
                                v['rule_name'] = str(getattr(vuln, 'rule_name') or '')
                            incoming_flow = dict(getattr(vuln, 'taint_flow_hypothesis', {}) or {})
                            current_flow = dict(v.get('taint_flow_hypothesis') or {})
                            flow_dims = ('source_present', 'sink_present', 'reachable', 'barrier_free')
                            if incoming_flow and sum(1 for _k in flow_dims if incoming_flow.get(_k)) > sum(1 for _k in flow_dims if current_flow.get(_k)):
                                v['taint_flow_hypothesis'] = incoming_flow
                            incoming_proof = normalize_chain_proof(getattr(vuln, 'chain_proof', {}) or empty_chain_proof())
                            incoming_spec = normalize_exploit_spec(getattr(vuln, 'exploit_spec', {}) or empty_exploit_spec())
                            if self._chain_context_rank({'chain_proof': incoming_proof, 'proof_tier': getattr(vuln, 'proof_tier', 'broad_static'), 'proof_gaps': getattr(vuln, 'proof_gaps', []), 'exploit_spec': incoming_spec, 'contract_completeness': {}}) > self._chain_context_rank({'chain_proof': v.get('chain_proof', {}), 'proof_tier': v.get('proof_tier', 'broad_static'), 'proof_gaps': v.get('proof_gaps', []), 'exploit_spec': v.get('exploit_spec', {}), 'contract_completeness': {}}):
                                v['chain_proof'] = incoming_proof
                                v['proof_gaps'] = list(getattr(vuln, 'proof_gaps', []) or incoming_proof.get('proof_gaps', []) or [])
                                v['exploit_spec'] = incoming_spec
                                v['proof_context_summary'] = dict(getattr(vuln, 'proof_context_summary', {}) or {})
                                v['contract_gaps'] = list(getattr(vuln, 'contract_gaps', []) or [])
                                v['a21_selected'] = getattr(vuln, 'a21_selected', None)
                                v['a21_reason'] = getattr(vuln, 'a21_reason', '')
                                v['a21_candidate_score'] = int(getattr(vuln, 'a21_candidate_score', 0) or 0)
                            break

        # 添加 D2 统一验证链路结果和 POC
        verifications = d2_verifications.get('verifications', [])
        pocs = d2_verifications.get('pocs', [])
        # §③ 调度留痕索引（2026-09-22，闭环 D2_NOT_SCHEDULED）：run_d2_verify 现会把门禁未入队的
        # 条目逐条落原因（stage_results.d2.scheduling）。这里按 (file,type,line) 建索引，供下面的
        # 未匹配分支写出「显式未验证原因」，替代此前一律空的 verification_decision。
        _d2_sched_skip = {
            (item.get('file'), item.get('type'), item.get('line')): item.get('reason')
            for item in ((d2_verifications.get('scheduling') or {}).get('skipped') or [])
        }

        for vuln in all_vulns:
            v = self._select_best_verification(vuln, verifications)
            if v:
                vuln['exploitable'] = v.get('exploitable', 'Unknown')
                vuln['confidence'] = v.get('confidence', 'low')
                vuln['test_status'] = v.get('test_status', 'NOT_TESTED')
                vuln['reason'] = v.get('reason', '')
                vuln['evidence'] = v.get('evidence', [])
                vuln['attack_plan'] = v.get('attack_plan', {})
                vuln['exploit_spec'] = normalize_exploit_spec(v.get('exploit_spec') or vuln.get('exploit_spec') or empty_exploit_spec())
                vuln['contract_completeness'] = v.get('contract_completeness', {})
                vuln['failure_classification'] = v.get('failure_classification', {})
                vuln['execution_evidence'] = v.get('execution_evidence', {})
                vuln['verification_decision'] = v.get('verification_decision', {})
                vuln['docker_attempted'] = v.get('docker_attempted', False)
                vuln['docker_used'] = v.get('docker_used', False)
                vuln['local_jar_attempted'] = v.get('local_jar_attempted', False)
                vuln['container_id'] = v.get('container_id', '')
                vuln['service_url'] = v.get('service_url', '')
                vuln['runtime_source'] = v.get('runtime_source', '')
                vuln['runtime_type'] = v.get('runtime_type', '')
                vuln['container_kept_running'] = v.get('container_kept_running', False)
                vuln['service_ready'] = v.get('service_ready', False)
                vuln['poc_generated'] = v.get('poc_generated', False)
                vuln['poc_verified'] = v.get('poc_verified', False)
                vuln['verification_note'] = v.get('verification_note', '')
                vuln['no_poc_reason'] = v.get('no_poc_reason', '')
                vuln['llm_poc_code'] = v.get('llm_poc_code', '')
                vuln['poc_details'] = v.get('poc_details', {})
                vuln['fix_suggestion'] = v.get('fix_suggestion', '')
                vuln['steps_executed'] = v.get('steps_executed', 0)
                vuln['execution_time'] = v.get('execution_time', 0.0)
                vuln['raw_output'] = v.get('raw_output')
                vuln['step_errors'] = v.get('step_errors', [])
                vuln['verified_bundle'] = v.get('verified_bundle', {})
                # §D2 裁决回填（报告层缺口修复）：把统一 verify() 产物的五态裁决与运行时证据透传到
                # 每条 finding，使前端无需交叉引用 stage_results.d2.verifications_detail 也能看到
                # confirmed_attributable / sink-reached / canary 身份段。历史版本只填了 exploitable /
                # verification_decision，导致已确证的漏洞在前端仍显 Unknown/None。
                vuln['final_state'] = v.get('final_state') or ''
                vuln['iast_evidence'] = v.get('iast_evidence') or {}
                vuln['dast_impact_evidence'] = v.get('dast_impact_evidence') or {}
                vuln['trigger_spec_provided'] = bool(v.get('trigger_spec_provided', False))
                vuln['trigger_spec_hash'] = v.get('trigger_spec_hash')
                vuln['trigger_spec_detail'] = v.get('trigger_spec_detail') or {}
                vuln['d2_verdict'] = v.get('d2_verdict') or {}
                vuln['next_action'] = v.get('next_action') or {}

                # §字段同步（point ① 修复）：D2 裁决产物的「确认」真相只存在于
                # final_state / d2_verdict.harmful / verification_decision.verification_status /
                # iast_evidence.iast_authz_confirmed，而 VerificationResult.to_dict() 从不输出顶层
                # confirmed / test_status，导致报告层与前端「验证状态」长期读到 False / NOT_TESTED，
                # 把「已确认可利用」渲染成「未验证=非漏洞」（task3 实测 54 条全 False/NOT_TESTED 但 10 条
                # d2_verdict.harmful=True）。此处用已合并的裁决字段反向回填顶层 confirmed / test_status /
                # exploitable，使展示与裁决一致。派生逻辑为纯只读归并，不引入任何新证据。
                _d2v = vuln.get('d2_verdict') or {}
                _vd = vuln.get('verification_decision') or {}
                _ie = vuln.get('iast_evidence') or {}
                _fstate = str(vuln.get('final_state') or '')
                _vstatus = str(_vd.get('verification_status') or '')
                _confirmed = (
                    bool(_d2v.get('harmful'))
                    or _fstate in ('confirmed', 'confirmed_attributable', 'runtime_confirmed')
                    or _vstatus == 'confirmed_exploitable'
                    or bool(_ie.get('iast_authz_confirmed'))
                )
                vuln['confirmed'] = _confirmed
                # 回填 test_status 时不得覆盖 verification 自身的执行态：已被执行过（DONE/VULNERABLE/
                # CONFIRMED/ERROR）的验证不应被「未确认」反推成 NOT_TESTED，否则前端把「已测试未确认」
                # 渲染成「未测试=非漏洞」。仅当 verification 自身也未报告执行态时才降级为 NOT_TESTED。
                _raw_ts = str(vuln.get('test_status') or '').upper()
                _executed = _raw_ts in ('DONE', 'VULNERABLE', 'CONFIRMED', 'ERROR')
                vuln['test_status'] = (
                    'CONFIRMED' if _confirmed
                    else (_raw_ts if _executed else ('TESTED' if _fstate else 'NOT_TESTED'))
                )
                vuln['exploitable'] = 'Yes' if _confirmed else (vuln.get('exploitable') or 'No')

                # §P2：把通道 A 的 target_endpoint（统一 verify() 透传到 trigger_spec_detail.endpoint）
                # 回写通道 B 的 exploit_spec.entry.route。业务/越权类因 resolve_trigger_endpoint 是 sink
                # 驱动、无 sink→route 恒空，导致大批 a21_selected 真漏洞 entry.route 为空、被门禁错杀、
                # 进不了 D2 主线（召回率漏斗第二层根因）。回写保底：仅当通道 B 的 entry.route 为空且通道
                # A 有端点时补填，不清空既有 entry 其它字段、也不覆盖已存在的真实 route。
                _tsd = vuln.get('trigger_spec_detail')
                if isinstance(_tsd, dict) and _tsd.get('endpoint'):
                    _spec = vuln.get('exploit_spec')
                    if isinstance(_spec, dict):
                        _entry = _spec.get('entry') or {}
                        if not _entry.get('route'):
                            _entry = dict(_entry)
                            _entry['route'] = _tsd['endpoint']
                            if _tsd.get('http_method') and not _entry.get('method'):
                                _entry['method'] = _tsd['http_method']
                            _spec = dict(_spec)
                            _spec['entry'] = _entry
                            vuln['exploit_spec'] = _spec
                # §⑦-3 补（2026-09-22）：匹配到了 verification、但该记录**本身没有裁决**
                # （无 verification_status 也无 final_state）时，vuln 会被写成空壳 decision，
                # 与「压根没匹配到」不可区分，违反「未测必须显式记 runtime 原因，不得留 unknown」。
                # 实测 SocketHookImpl.java:112/137（run 38/39 两轮稳定复现）：D2 以
                # trigger_spec=None 跑了 verify（trace 记 spec_found=0），产物无裁决。
                # 此处补显式记因，与 else 分支同口径。
                if not str((vuln.get('verification_decision') or {}).get('verification_status') or ''):
                    # 首版漏 third 态：要求 final_state 也为空才记因，而实测这两条 **有**
                    # final_state='no_evidence'（D2 跑过、只是没写进 verification_decision）
                    # —— 条件过严导致仍未闭环。判据收敛为「只看有没有显式 verification_status」。
                    _fs0 = str(vuln.get('final_state') or '')
                    vuln['verification_decision'] = {
                        'verification_status': _fs0 or 'no_verification_record',
                        'judge_reason': (
                            'D2 已执行该 finding，但产物未携带显式裁决'
                            '（final_state=%s；trace 记 spec_found=0 → 本条以 trigger_spec=None 运行，'
                            '无参数位可注入，属无注入点而非打不通）' % (_fs0 or '空')
                        ),
                        'scheduling_reason': 'verified_without_explicit_decision',
                        'final_state': _fs0 or 'no_verification_record',
                    }
            else:
                vuln['exploitable'] = 'Unknown'
                vuln['confidence'] = 'low'
                vuln['test_status'] = 'NOT_TESTED'
                vuln['evidence'] = []
                vuln['attack_plan'] = {}
                vuln['exploit_spec'] = normalize_exploit_spec(vuln.get('exploit_spec') or empty_exploit_spec())
                vuln['contract_completeness'] = vuln.get('contract_completeness') or exploit_spec_completeness(vuln['exploit_spec'])
                vuln['failure_classification'] = {}
                vuln['execution_evidence'] = {}
                # §③ 显式记未验证原因（2026-09-22，闭环 D2_NOT_SCHEDULED）：需求约定「未测必须
                # 显式记 runtime 原因，不得留 unknown」。此前无匹配 verification 时一律写
                # verification_decision={}，报告里成为既无证据、也无原因的沉默空壳，
                # d2_zero_audit 只能猜「疑似未入队」。现按调度留痕落明确状态：
                #   not_scheduled —— 未进入 D2 执行队列（附门禁原因）
                #   no_verification_record —— chain_proven 已强制入队但仍无验证记录（上游结果丢失，属缺陷，须查）
                _sched_reason = _d2_sched_skip.get((vuln.get('file'), vuln.get('type'), vuln.get('line')))
                if not _sched_reason:
                    _sched_reason = str(vuln.get('d2_scheduling_reason') or '')
                if _sched_reason:
                    vuln['verification_decision'] = {
                        'verification_status': 'not_scheduled',
                        'judge_reason': 'D2 未执行该 finding：%s' % _sched_reason,
                        'scheduling_reason': _sched_reason,
                        'final_state': 'not_scheduled',
                    }
                elif str(vuln.get('proof_tier') or '') == 'chain_proven':
                    vuln['verification_decision'] = {
                        'verification_status': 'no_verification_record',
                        'judge_reason': (
                            'chain_proven finding 已按强制入队规则进 D2 候选，但本次未产出/未折回其验证记录'
                            '（属上游结果丢失，须查 stage_results.d2.scheduling 与 D2 日志）'
                        ),
                        'scheduling_reason': 'enqueued_but_no_verification_record',
                        'final_state': 'no_verification_record',
                    }
                else:
                    vuln['verification_decision'] = {}
                vuln['docker_attempted'] = False
                vuln['docker_used'] = False
                vuln['local_jar_attempted'] = False
                vuln['container_id'] = ''
                vuln['service_url'] = ''
                vuln['runtime_source'] = ''
                vuln['runtime_type'] = ''
                vuln['container_kept_running'] = False
                vuln['service_ready'] = False
                vuln['poc_generated'] = False
                vuln['poc_verified'] = False
                vuln['verification_note'] = ''
                vuln['no_poc_reason'] = ''
                vuln['llm_poc_code'] = ''
                vuln['poc_details'] = {}
                vuln['fix_suggestion'] = ''
                vuln['steps_executed'] = 0
                vuln['execution_time'] = 0.0
                vuln['raw_output'] = None
                vuln['step_errors'] = []
                vuln['verified_bundle'] = {}
            vuln['proof_context_summary'] = dict(vuln.get('proof_context_summary', {}) or {})
            vuln['contract_gaps'] = list(vuln.get('contract_gaps', []) or [])
            vuln['a21_reason'] = str(vuln.get('a21_reason', '') or '')

            # 匹配 POC
            for poc in pocs:
                if self._verification_matches(vuln, poc):
                    vuln['poc'] = poc.get('poc', {})
                    vuln['poc_file'] = poc.get('poc_file', '')
                    if poc.get('llm_poc_code'):
                        vuln['llm_poc_code'] = poc.get('llm_poc_code', '')
                    if poc.get('poc_details'):
                        vuln['poc_details'] = poc.get('poc_details', {})
                    break

            verdict_summary = self._build_verdict_summary(vuln)
            vuln['final_verdict'] = verdict_summary.get('final', '')
            vuln['static_verdict'] = verdict_summary.get('static', '')
            vuln['verdict_note'] = verdict_summary.get('note', '')
            vuln['static_verdict_explanation'] = self._static_verdict_explanation(vuln.get('verdict', ''))
            # Q1 呈现层：每条 finding 带显式验证状态，供前端「验证状态」独立列绑定
            # （confirmed=已确认 / detected_unverified=已检出未验证 / disproven=动态证伪 / static_pending=静态待确认）
            vuln['verification_state'] = ReportManager.compute_verification_state(vuln)
            # #3（Q1 修复）：A2 判定「真漏洞-HTTP入口可触发」但 D2 运行时未产出动态实证时，
            # 渲染「已检出未验证」而非「未验证=非漏洞」，避免 D2 的「未验证」覆盖 A2 真漏洞结论
            # （task7 实测：REPORTING_OR_PIPELINE_MISMATCH 23 条即此症状——「我不知道」被渲染成「不是漏洞」）。
            # verification_decision 为空即「无 D2 实证」；此时 d2_status 置非空（unverified）而非留 NULL。
            # §③（2026-09-22）：报告层现在也会给「未获 D2 验证」的 finding 写入显式原因状态
            # （not_scheduled / no_verification_record）。这类 decision 非空但同样代表「无 D2 实证」，
            # 故判据从「decision 是否为空」改为「是否有真正的 D2 实证」，避免这些 finding 丢掉
            # 「已检出未验证」的渲染、退回成 A2 的 ✅ 真漏洞结论。
            _vd_now = vuln.get('verification_decision') or {}
            _has_real_d2_evidence = bool(_vd_now) and str(
                _vd_now.get('verification_status') or ''
            ) not in D2_NOT_EXECUTED_STATUSES
            _static_v = ReportManager._normalize_verdict_text(vuln.get('verdict', ''))
            _a2_real = '真漏洞' in _static_v
            if _a2_real and not _has_real_d2_evidence:
                vuln['d2_status'] = vuln.get('d2_status') or 'unverified'
                _fv = str(vuln.get('final_verdict') or '')
                if '真漏洞' not in _fv and '已验证' not in _fv and 'confirmed' not in _fv.lower():
                    vuln['final_verdict'] = ('⚠️ 已检出未验证：A2 判定为真实漏洞（HTTP 入口可触发），'
                                            '但 D2 运行时未产出动态实证')

        mainline_verifications = [v for v in verifications if is_mainline_d2_item(v)]
        executed_mainline_verifications = [v for v in mainline_verifications if is_executed_d2_item(v)]
        excluded_fallback_verifications = [v for v in verifications if is_excluded_d2_fallback_item(v)]

        # §统一链路口径（修复「命中=0」根因）：D2 运行时指标直接取自流水线 D2 统一校验产物
        # （run_d2_verify 返回 + _aggregate_d2_verdict 聚合），不再依赖 is_mainline_d2_item 对
        # verifications 的过滤。历史口径下 verifications 不带 proof_tier / contract_completeness，
        # is_mainline_d2_item 恒为 False → mainline_verifications 恒空 → raw_d2_stats.exploitable_count
        # 恒为 0，导致最终报告与前端「确认可利用 / sink 到达」全 0，与 stage_results.d2（=7）及
        # 监控 FINAL 口径严重背离。现改为以权威指标为准（与 D2 面板、IAST 关联口径一致）。
        _agg = (d2_verifications.get('aggregate') or {}) if isinstance(d2_verifications, dict) else {}
        _d2m = {
            'verified_count': int(d2_verifications.get('total_vulnerabilities')
                                  or _agg.get('verified_count') or 0),
            'exploitable_count': int(d2_verifications.get('exploitable_count')
                                     or _agg.get('confirmed_exploitable_count') or 0),
            'verified_poc_count': int(d2_verifications.get('verified_poc_count') or 0),
            'sink_reached_count': int(_agg.get('sink_reached_count') or 0),
            'harmful_count': int(_agg.get('harmful_count') or 0),
            'impact_count': int(_agg.get('impact_count') or 0),
        }
        raw_d2_stats = {
            'exploitable_count': _d2m['exploitable_count'],
            'confirmed_count': _d2m['verified_count'],
            'poc_count': _d2m['verified_poc_count'],
            'verified_poc_count': _d2m['verified_poc_count'],
            'sink_reached_count': _d2m['sink_reached_count'],
            'harmful_count': _d2m['harmful_count'],
            'impact_count': _d2m['impact_count'],
        }

        # 阶段漏斗（2026-10-31）：报告装配是「候选消失」的高发区——
        # 本轮里 framework 的 deserialization 命中就是在这一步没的（同文件 csrf 却进得去）。
        # 这里记录 (输入条数, 去重后, 聚合后) 三点，下一轮定位断点时不用再靠三处数字倒推。
        _in_total = 0
        try:
            from src.core.stage_funnel import record, family_hist
            _in_total = sum(len(getattr(r, "vulnerabilities", []) or [])
                            for r in (a1_results + a2_results) if not getattr(r, "error", False))
            record(getattr(self, "_funnel_task_id", None), "report.dedup",
                   in_count=_in_total, out_count=len(all_vulns),
                   reasons={"dedup_same_file_type_line": _in_total - len(all_vulns)},
                   families=family_hist(all_vulns, family_of=lambda v: v.get("type")))
        except Exception:
            pass

        all_vulns = self._aggregate_canonical_findings(all_vulns)
        try:
            from src.core.stage_funnel import record
            record(getattr(self, "_funnel_task_id", None), "report.aggregate",
                   in_count=_in_total or len(all_vulns), out_count=len(all_vulns))
        except Exception:
            pass
        for vuln in all_vulns:
            self._enrich_key_finding_details(vuln)
            verdict_summary = self._build_verdict_summary(vuln)
            vuln['final_verdict'] = verdict_summary.get('final', '')
            vuln['static_verdict'] = verdict_summary.get('static', '')
            vuln['verdict_note'] = verdict_summary.get('note', '')
            vuln['static_verdict_explanation'] = self._static_verdict_explanation(vuln.get('verdict', ''))
        all_vulns = self._sort_findings(all_vulns)

        # 统计
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        by_type = {}

        for v in all_vulns:
            sev = normalize_severity(v.get('severity', 'UNKNOWN'))
            by_severity[sev] = by_severity.get(sev, 0) + 1

            vtype = normalize_type(v.get('type', 'Unknown'))
            by_type[vtype] = by_type.get(vtype, 0) + 1

        # canonical 视角同样以权威 D2 指标为准（exploitable / poc / confirmed 不再被 mainline 过滤清零），
        # 仅保留 count_dynamic_stats 作为一致性兜底（两者应相等）。
        _cd = count_dynamic_stats(all_vulns)
        # D2（2026-10-10）：移除 `or` 兜底——`_d2m` 与 `_cd` 是两个独立口径的 D2 指标，
        # 用 `or` 静默回退会掩盖两者不一致（如 _d2m 计 0 而 _cd 计非 0，本应是口径冲突，
        # 却被兜底成 _cd 值，掩盖了统计缺陷）。改为以权威口径 _d2m 为准，并显式记录 metric_conflicts。
        canonical_d2_stats = {
            'exploitable_count': _d2m['exploitable_count'],
            'confirmed_count': _d2m['verified_count'],
            'poc_count': _d2m['verified_poc_count'],
            'verified_poc_count': _d2m['verified_poc_count'],
        }
        metric_conflicts = {}
        if (_d2m.get('verified_count') or 0) != (_cd.get('confirmed_count') or 0):
            metric_conflicts['confirmed_count'] = {
                'd2_metrics': _d2m.get('verified_count'), 'dynamic_stats': _cd.get('confirmed_count')}
        if (_d2m.get('verified_poc_count') or 0) != (_cd.get('poc_count') or 0):
            metric_conflicts['poc_count'] = {
                'd2_metrics': _d2m.get('verified_poc_count'), 'dynamic_stats': _cd.get('poc_count')}
        proof_stats = count_proof_tiers(all_vulns)
        zero_audit = summarize_d2_zero_audit(all_vulns)

        # 2026-11-03（r17b 验证）：报告定稿前按最终 decision 重算一次验证状态。
        # verification_state 在 1961 行按当时的 decision 算好；之后 confirm-gate 回补等 post-pass
        # 仍会改写 decision，导致两者脱节（jsc 609 实测 1 条 SpEL：state=disproven 但
        # verification_decision.verification_status=confirmed_exploitable）。重算幂等。
        for _v in all_vulns:
            if isinstance(_v, dict):
                _v['verification_state'] = ReportManager.compute_verification_state(_v)

        # 构建报告
        report = {
            'report_type': 'FINAL',
            'title': 'SAST-AI 最终安全审计报告',
            'timestamp': timestamp,
            'generated_at': datetime.now().isoformat(),
            'project_overview': self._build_project_overview(target_path, files or [], discovered_endpoints or {}, all_vulns),
            'summary': {
                'total_vulnerabilities': len(all_vulns),
                'canonical_findings': len(all_vulns),
                'broad_static_count': proof_stats['broad_static_count'],
                'broad_static_deduped_chain_count': len(all_vulns),
                'chain_proven_count': proof_stats['chain_proven_count'],
                'contract_ready_count': proof_stats['contract_ready_count'],
                'd2_verified_count': (d2_verifications.get('aggregate') or {}).get(
                    'verified_count', canonical_d2_stats['verified_poc_count']
                ),
                'chain_proven_but_d2_failed_count': sum(
                    1 for v in all_vulns
                    if str(v.get('proof_tier', 'broad_static')) == 'chain_proven' and not v.get('poc_verified')
                ),
                'aggregated_supporting_nodes': sum(v.get('supporting_node_count', 0) for v in all_vulns),
                'by_severity': by_severity,
                'by_type': by_type,
                'exploitable_count': canonical_d2_stats['exploitable_count'],
                'confirmed_count': canonical_d2_stats['confirmed_count'],
                'poc_count': canonical_d2_stats['poc_count'],
                'verified_poc_count': canonical_d2_stats['verified_poc_count'],
                'excluded_d2_fallback_count': len(excluded_fallback_verifications),
                'a1_count': sum(len(r.vulnerabilities) for r in a1_results if not r.error),
                'a2_count': sum(len(r.vulnerabilities) for r in a2_results if not r.error),
                'd2_tested_count': raw_d2_stats['confirmed_count'],
                'a1_findings': sum(len(r.vulnerabilities) for r in a1_results if not r.error),
                'a2_findings': sum(len(r.vulnerabilities) for r in a2_results if not r.error),
                'd2_tested': raw_d2_stats['confirmed_count'],
                'd2_confirmed_exploitable': raw_d2_stats['exploitable_count'],
                'd2_poc_generated': raw_d2_stats['poc_count'],
                'd2_verified_poc': raw_d2_stats['verified_poc_count'],
                'd2_sink_reached_count': raw_d2_stats['sink_reached_count'],
                'd2_harmful_count': raw_d2_stats['harmful_count'],
                'd2_impact_count': raw_d2_stats['impact_count'],
                'd2_candidate_count': sum(1 for v in all_vulns if is_mainline_d2_item(v)),
                'canonical_tested_count': canonical_d2_stats['confirmed_count'],
                'canonical_exploitable_count': canonical_d2_stats['exploitable_count'],
                'canonical_poc_count': canonical_d2_stats['poc_count'],
                'canonical_verified_poc_count': canonical_d2_stats['verified_poc_count'],
                # D2（2026-10-10）：口径冲突显式暴露——_d2m 与 count_dynamic_stats 两独立口径
                # 对 confirmed / poc 计数不一致时如实记录，绝不静默 `or` 兜底掩盖。
                'metric_conflicts': metric_conflicts,
                'docker_used': d2_verifications.get('docker_used', False),
                'docker_attempted': d2_verifications.get('docker_attempted', False),
                'local_jar_attempted': d2_verifications.get('local_jar_attempted', False),
                'runtime_source': d2_verifications.get('runtime_source', ''),
                'runtime_type': d2_verifications.get('runtime_type', ''),
                'd2_zero_audit': zero_audit,
            },
            'vulnerabilities': all_vulns,
            'd2_stats': {
                'total_tested': raw_d2_stats['confirmed_count'],
                'exploitable': raw_d2_stats['exploitable_count'],
                'canonical_exploitable': canonical_d2_stats['exploitable_count'],
                'poc_count': raw_d2_stats['poc_count'],
                'verified_poc_count': raw_d2_stats['verified_poc_count'],
                'canonical_verified_poc_count': canonical_d2_stats['verified_poc_count'],
                'sink_reached_count': raw_d2_stats['sink_reached_count'],
                'harmful_count': raw_d2_stats['harmful_count'],
                'impact_count': raw_d2_stats['impact_count'],
                'd2_candidate_count': sum(1 for v in all_vulns if is_mainline_d2_item(v)),
                'excluded_fallback_count': len(excluded_fallback_verifications),
                'false_positives': max(0, raw_d2_stats['confirmed_count'] - raw_d2_stats['exploitable_count']),
                'docker_status': d2_verifications.get('docker_status', {}),
                'failure_reasons': d2_verifications.get('failure_reasons', []),
                'd2_zero_audit': zero_audit,
            }
        }

        # 生成 Markdown
        md_content = self._generate_final_markdown(report)
        md_path = self._save_markdown(md_content, f'final_report_{timestamp}.md')

        # 保存 JSON
        json_path = self._save_json(report, f'final_report_{timestamp}.json')

        return {
            'report': report,
            'markdown_file': md_path,
            'json_file': json_path
        }

    def _generate_final_markdown(self, report: Dict) -> str:
        """生成最终安全审计报告 Markdown（现代精简版）。"""
        L = []
        a = L.append

        a("# SAST-AI 安全审计报告")
        a("")
        a(f"> 报告类型：**最终安全审计报告**（A1/A2 静态发现 + D2 动态验证 + I1/I2 IAST 运行时关联）  ")
        a(f"> 生成时间：{report.get('generated_at', '')}  ")
        a("")

        summary = report.get('summary', {}) or {}
        project = report.get('project_overview', {}) or {}

        # 一、扫描概览
        a("## 一、扫描概览")
        a("")
        rows = []
        if project.get('target_path'):
            rows.append(("扫描目标", f"`{project.get('target_path')}`"))
        rows.append(("文件总数", project.get('file_count', 0)))
        rows.append(("发现路由数", project.get('route_count', 0)))
        rows.append(("已测试路由数", project.get('tested_route_count', 0)))
        rows.append(("路由覆盖率", f"{project.get('route_coverage_rate', 0)}%"))
        rows.append(("识别 Sink 点", project.get('sink_count', 0)))
        rows.append(("总发现数", summary.get('total_vulnerabilities', 0)))
        if summary.get('sca_count'):
            rows.append(("SCA 依赖风险", summary.get('sca_count')))
        if summary.get('idor_count'):
            rows.append(("D1 越权候选", summary.get('idor_count')))
        for k, v in rows:
            a(f"- **{k}**：{v}")
        a("")

        # 二、执行摘要
        a("## 二、执行摘要")
        a("")
        by_sev = summary.get('by_severity', {}) or {}
        a("### 风险分布")
        a("")
        # 本质修复 #2：遍历全 severity 桶（CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN），
        # 不再硬编码 HIGH/MEDIUM/LOW，避免 SCA 的 18 条 CRITICAL 在交付报告中完全不可见。
        _sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
        _sev_label = {
            "CRITICAL": "严重（CRITICAL）",
            "HIGH": "高危（HIGH）",
            "MEDIUM": "中危（MEDIUM）",
            "LOW": "低危（LOW）",
            "INFO": "信息（INFO）",
            "UNKNOWN": "未知",
        }
        for _sev in _sev_order:
            _cnt = int(by_sev.get(_sev, 0) or 0)
            if _cnt:
                a(f"- {_sev_label[_sev]}：**{_cnt}**")
        a("")
        a("### 各引擎贡献")
        a("")
        a(f"- A1 规则扫描：{summary.get('a1_count', 0)}")
        a(f"- A2 AI 语义分析：{summary.get('a2_count', 0)}")
        a(f"- D2 动态验证：已测 {summary.get('d2_tested_count', 0)} / 可利用 {summary.get('d2_confirmed_exploitable', 0)} / 已验证 POC {summary.get('d2_verified_poc', 0)}")
        if summary.get('sca_count'):
            a(f"- SCA 依赖扫描：{summary.get('sca_count')}")
        if summary.get('idor_count'):
            a(f"- D1 越权分析：{summary.get('idor_count')}")
        a(f"- Canonical 发现（链级去重后）：{summary.get('canonical_findings', summary.get('total_vulnerabilities', 0))}")
        a(f"- 链级已证实（chain-proven）：{summary.get('chain_proven_count', 0)}")
        a(f"- A2.1 Contract Ready：{summary.get('contract_ready_count', 0)}")
        a("")
        a("### 动态验证结论（D2）")
        a("")
        if summary.get('verified_poc_count', 0) > 0:
            a(f"- 已通过动态执行确认可利用的漏洞：**{summary.get('verified_poc_count', 0)}** 个。")
        else:
            a("- 本次未产生“动态验证成功”的漏洞。")
        zero = summary.get('d2_zero_audit', {}) or {}
        # 矛盾措辞修复：仅当本轮确实 0 确认（verified_poc_count==0）时才输出「D2=0 归因」，
        # 避免与上方「已通过动态执行确认可利用的漏洞：N 个」并存产生自相矛盾。DB 为真相源，
        # task-2 实测 13 个 D2 确认 POC，故真实报告只显示确认数，不显示 0 归因。
        if zero.get('summary') and not summary.get('verified_poc_count', 0):
            a(f"- D2=0 归因：{zero.get('summary')}")
        if summary.get('docker_used'):
            a("- 动态环境：已实际启动 Docker 完成验证。")
        elif summary.get('docker_attempted'):
            a("- 动态环境：已尝试启动 Docker，但未成功。")
        elif (summary.get('d2_tested_count') or summary.get('d2_tested')
              or summary.get('d2_sink_reached_count') or summary.get('d2_verified_poc_count')):
            # P1-3：D2 验证链路确实跑过（IAST/canary 运行时，未必走 Docker），不能再说「未启动」。
            a("- 动态验证：D2 验证链路已执行（IAST/canary 运行时，本轮未使用 Docker 容器）。")
        else:
            a("- 动态环境：未启动（本轮未做动态验证或未配置目标）。")
        reason = self._select_d2_summary_reason(report)
        if reason:
            label = 'POC 未验证成功原因' if reason.get('kind') == 'verification_failed' else 'POC 未生成原因'
            a(f"- {label}：{reason.get('text', '')}")
            ex = self._explain_text(reason.get('text', ''))
            if ex:
                a(f"  - {ex}")
        a("")
        a("> 说明：`已生成 POC` 表示 D2 给出利用思路/代码；`已验证成功 POC` 表示动态执行确实拿到利用证据，后者才代表真正落地验证。")
        a("")

        # 三、漏洞清单
        vulns = report.get('vulnerabilities', []) or []
        a("## 三、漏洞清单")
        a("")
        if not vulns:
            a("_本轮未发现需要跟踪的漏洞。_")
            a("")
        else:
            a("| # | 严重度 | 类型 | 位置 | 来源 | 验证状态 |")
            a("| --- | --- | --- | --- | --- | --- |")
            for i, v in enumerate(vulns, 1):
                sev = v.get('severity', 'UNKNOWN')
                vtype = v.get('type') or v.get('vulnerability_id') or v.get('category') or 'Unknown'
                loc = self._short_location(v)
                src = '/'.join(v.get('sources', []) or []) or '-'
                status = self._verification_badge(v)
                a(f"| {i} | {sev} | {vtype} | {loc} | {src} | {status} |")
            a("")

        # 三-补充：已检出未验证清单（A2 判真漏洞但 D2 未动态确认，属「看见了但没钉死」）
        detected_unverified = [
            v for v in vulns
            if ReportManager.compute_verification_state(v) == 'detected_unverified'
        ]
        if detected_unverified:
            a("### 3.1 已检出未验证清单")
            a("")
            a("以下漏洞 A2 静态分析已判为真漏洞（HTTP 入口可触发），但 D2 动态验证未给出可利用证据。"
              "它们属于「已检出未验证」，不是「已排除」，应优先作为下一步动态验证 / 人工复核的重点，"
              "不应被渲染成非漏洞。")
            a("")
            a("| # | 严重度 | 类型 | 位置 | A2 静态判定 |")
            a("| --- | --- | --- | --- | --- |")
            for i, v in enumerate(detected_unverified, 1):
                sev = v.get('severity', 'UNKNOWN')
                vtype = v.get('type') or v.get('vulnerability_id') or v.get('category') or 'Unknown'
                loc = self._short_location(v)
                a2v = self._normalize_verdict_text(v.get('verdict', '')) or '-'
                a(f"| {i} | {sev} | {vtype} | {loc} | {a2v} |")
            a("")

        # 四、详细发现
        a("## 四、详细发现")
        a("")
        if not vulns:
            a("_无。_")
        else:
            for i, v in enumerate(vulns, 1):
                self._md_finding(L, i, v)
        a("")

        # 五、IAST 关联验证
        iast = report.get('iast_summary')
        a("## 五、IAST 运行时关联验证")
        a("")
        if iast and iast.get('findings'):
            self._md_iast_section(L, iast)
        else:
            a("_未检出 IAST 运行数据。_")
            a("")
            a("> I1 监听器、D2 校验器、I2 裁决器依赖目标应用挂载的 IAST 探针实时上报事件。")
            a("> 当前任务未采集到任何 `iast_events` / `trigger_specs` 记录，因此 I1 全 `no-arrival`、D2 全 `no-arrival`、I2 无覆盖率——这是运行环境侧问题（探针未注册/未启动），并非检测逻辑缺失。")
            a("> 在目标应用挂载并注册 IAST 探针、跑通流量后重跑本报告，即可在此处看到 I1/D2/I2 的观测态与覆盖率。")
            a("")

        # 六、SCA 依赖风险
        sca = report.get('sca_summary')
        if sca:
            a("## 六、依赖组件风险（SCA）")
            a("")
            self._md_sca_section(L, sca)
            a("")

        # 七、附录
        a("## 七、附录与术语")
        a("")
        a("- **A1/A2/D2**：规则扫描 / AI 语义分析 / 动态验证三大引擎。")
        a("- **D1**：DAST 越权（IDOR/BOLA）重放分析。")
        a("- **I1/I2/D2**：IAST 监听器 / 裁决器 / 校验器（运行时观测）。")
        a("- **canary 三态**：`no-arrival`（未到达 sink）/ `arrival-sanitized`（到达但被净化）/ `sink-reached`（到达并利用成功）。")
        a("- **Canonical Finding**：同一条利用链上多个证据点被聚合后的唯一代表发现。")
        a("")
        return '\n'.join(L)

    @staticmethod
    def _short_location(v: Dict) -> str:
        f = v.get('file') or v.get('file_path') or ''
        line = v.get('line')
        if f:
            f = f.split('/')[-1].split('\\')[-1]
            return f"{f}:{line}" if line else f
        pkg = v.get('package') or v.get('component') or v.get('target')
        if pkg:
            ver = v.get('installed_version') or v.get('version') or ''
            return f"{pkg}@{ver}" if ver else str(pkg)
        return v.get('location') or '-'

    @staticmethod
    def compute_verification_state(vuln: Dict) -> str:
        """Q1 呈现层：把一条 finding 归一到四种验证状态之一，供前端「验证状态」列与报告小节使用。

        - confirmed：D2 动态确认可利用（is_confirmed_exploitable）。
        - detected_unverified：A2 静态判「真漏洞」但 D2 未给出动态实证（已检出未验证，不是已排除）。
        - disproven：D2 动态证伪（非 A2 真漏洞类且 exploitable==No）。
        - static_pending：其余静态待确认。
        """
        static = ReportManager._normalize_verdict_text(vuln.get('verdict', ''))
        a2_real = '真漏洞' in static
        if is_confirmed_exploitable(vuln):
            return 'confirmed'
        if vuln.get('exploitable') == 'No':
            return 'detected_unverified' if a2_real else 'disproven'
        if a2_real:
            return 'detected_unverified'
        if vuln.get('poc_generated'):
            return 'detected_unverified' if a2_real else 'static_pending'
        return 'static_pending'

    @staticmethod
    def _verification_badge(v: Dict) -> str:
        state = ReportManager.compute_verification_state(v)
        return {
            'confirmed': '已验证利用',
            'detected_unverified': '已检出未验证',
            'disproven': '动态证伪',
            'static_pending': '静态待确认',
        }.get(state, '静态待确认')

    def _md_finding(self, L: list, idx: int, v: Dict) -> None:
        a = L.append
        sev = v.get('severity', 'UNKNOWN')
        vtype = v.get('type') or v.get('vulnerability_id') or v.get('category') or 'Unknown'
        loc = self._short_location(v)
        icon = {'HIGH': 'H', 'MEDIUM': 'M', 'LOW': 'L'}.get(sev, '?')
        a(f"### [{icon}] {idx}. {vtype}  ")
        a(f"> {loc}")
        a("")
        facts = []
        facts.append(f"**严重程度**：{sev}")
        src = '/'.join(v.get('sources', []) or []) or '-'
        facts.append(f"**来源**：{src}")
        fv = v.get('final_verdict') or v.get('verdict') or ''
        if fv:
            facts.append(f"**最终判定**：{self._normalize_verdict_text(fv)}")
        conf = v.get('confidence')
        if conf:
            facts.append(f"**置信度**：{self._confidence_cn(conf)}")
        exp = v.get('exploitable')
        if exp:
            if exp == 'Yes':
                facts.append("**可利用性**：已验证可利用")
            elif exp == 'No':
                facts.append("**可利用性**：已验证不可利用")
            else:
                facts.append(f"**可利用性**：{exp}")
        if v.get('proof_tier'):
            facts.append(f"**证明层级**：{v.get('proof_tier')}")
        for f in facts:
            a(f"- {f}")
        proof = v.get('chain_proof') or {}
        if proof:
            a(f"- **链级证明**：reachable={bool(proof.get('reachable'))}, attacker_control={bool(proof.get('attacker_control_proven'))}, gate={bool(proof.get('gate_bypass_or_satisfaction_proven'))}, payload_shape={bool(proof.get('payload_shape_proven'))}")
        if v.get('proof_gaps'):
            a(f"- **证明缺口**：{', '.join(v.get('proof_gaps', []))}")
        fix = v.get('fix_suggestion') or ''
        if fix:
            a(f"- **修复建议**：{fix}")
        has_poc = bool(v.get('poc_details') or v.get('poc') or v.get('llm_poc_code') or v.get('poc_verified') is not None or v.get('no_poc_reason'))
        if has_poc:
            a("")
            a("<details>")
            a("<summary>利用验证与 POC 详情</summary>")
            a("")
            self._md_poc_block(L, v)
            a("")
            a("</details>")
        a("")

    def _md_poc_block(self, L: list, v: Dict) -> None:
        a = L.append
        if v.get('poc_verified') and v.get('working_payload'):
            a(f"- **成功 Payload**：`{v.get('working_payload')}`")
        details = v.get('poc_details') or {}
        if isinstance(details, dict) and (details.get('exploit_chain') or v.get('exploit_spec')):
            a(f"- **利用链**：{details.get('exploit_chain') or self._build_attack_chain(v)}")
        ap = (details.get('attack_plan') or {}) if isinstance(details, dict) else {}
        if ap:
            if ap.get('input_role'):
                a(f"- 输入角色：{ap.get('input_role')}")
            if ap.get('delivery_shape'):
                a(f"- 投递形态：{ap.get('delivery_shape')}")
            if ap.get('trigger_condition'):
                a(f"- 触发条件：{ap.get('trigger_condition')}")
            if ap.get('verification_signal'):
                a(f"- 成功信号：{ap.get('verification_signal')}")
        if v.get('no_poc_reason'):
            a(f"- **未生成 POC 原因**：{v.get('no_poc_reason')}")
            ex = self._explain_text(v.get('no_poc_reason', ''))
            if ex:
                a(f"  - {ex}")
        if v.get('verification_note'):
            a(f"- **POC 验证说明**：{v.get('verification_note')}")
        tools = self._required_tools(v)
        if tools:
            a(f"- **所需工具**：{', '.join(tools)}")
        curl = details.get('curl_example') if isinstance(details, dict) else None
        if curl and 'not available' not in str(curl).lower():
            a("- **curl 复现示例**：")
            a("```bash")
            a(str(curl))
            a("```")
        poc = v.get('poc') or {}
        if isinstance(poc, dict) and poc.get('python'):
            a("- **POC 代码（节选）**：")
            a("```python")
            a('\n'.join(poc['python'].split('\n')[:20]))
            a("```")
        if v.get('llm_poc_code'):
            a("- **D2 生成的利用思路**：")
            a("```text")
            a('\n'.join(v.get('llm_poc_code', '').split('\n')[:30]))
            a("```")

    @staticmethod
    def _md_iast_section(L: list, iast: Dict) -> None:
        a = L.append
        stats = iast.get('stats', {}) or {}
        a(f"- SAST 假说总数：{stats.get('total_hypotheses', 0)}")
        a(f"- IAST 观测命中：{stats.get('iast_observed', 0)}")
        a(f"- confirmed_runtime（sink-reached）：{stats.get('confirmed_runtime', 0)}")
        ratio = stats.get('coverage_ratio', 0) or 0
        a(f"- 观测覆盖率：{ratio:.1%}" if isinstance(ratio, (int, float)) else f"- 观测覆盖率：{ratio}")
        for asset in stats.get('per_asset', []) or []:
            a(f"- 资产 {asset.get('asset')}：total={asset.get('total')} observed={asset.get('observed')} confirmed_runtime={asset.get('confirmed_runtime')}")
        a("")
        a("#### 各 Finding 观测态")
        a("")
        findings = iast.get('findings', []) or []
        if findings:
            a("| 类型 | 观测态 | 位置 | 来源 |")
            a("| --- | --- | --- | --- |")
            for f in findings:
                iinfo = f.get('iast', {}) or {}
                state = iinfo.get('state') or 'no-observation'
                tag = 'confirmed_runtime' if iinfo.get('confirmed_runtime') else state
                loc = f"{f.get('file_path', '')}:{f.get('line', '')}"
                a(f"| {f.get('finding_type', '')} | {tag} | {loc} | {'+'.join(f.get('sources', []) or [])} |")
            a("")

    @staticmethod
    def _md_sca_section(L: list, sca: Dict) -> None:
        a = L.append
        a(f"- 状态：{sca.get('status', '-')}")
        # 2026-09-24：SCA 工具全部失败时，0 漏洞与「真干净」不可区分，必须显式告警，
        # 否则会被误当成健康基线（run 47 即此坑）。
        _health = sca.get('sca_health')
        if _health == 'all_tools_failed':
            a(f"- 警告：SCA 全部工具执行失败（{', '.join(str(t) for t in (sca.get('tools_failed') or []))}），"
              f"本轮 0 漏洞不可信，不得作为健康基线。")
        elif _health == 'partial_tools_failed':
            a(f"- 警告：部分 SCA 工具执行失败（{', '.join(str(t) for t in (sca.get('tools_failed') or []))}），"
              f"结果可能不完整。")
        fc = sca.get('finding_count', 0) or len(sca.get('findings', []) or [])
        a(f"- 风险组件数：{fc}")
        if sca.get('tool'):
            a(f"- 扫描工具：{sca.get('tool')}")
        findings = sca.get('findings', []) or []
        if findings:
            a("")
            a("| 组件 | 版本 | 漏洞 | 严重度 |")
            a("| --- | --- | --- | --- |")
            for f in findings[:50]:
                name = f.get('package') or f.get('component') or f.get('name') or '-'
                ver = f.get('installed_version') or f.get('version') or '-'
                vid = f.get('vulnerability_id') or f.get('advisory') or f.get('title') or '-'
                sev = f.get('severity', '-')
                a(f"| {name} | {ver} | {vid} | {sev} |")
            if len(findings) > 50:
                a("")
                a(f"_（仅显示前 50 条，共 {len(findings)} 条）_")
            a("")

    @staticmethod
    def _select_d2_summary_reason(report: Dict) -> Dict[str, str]:
        vulnerabilities = report.get('vulnerabilities', []) or []
        if not vulnerabilities:
            return {}

        def priority(vuln: Dict) -> tuple:
            return (
                0 if vuln.get('is_primary_chain') else 1,
                0 if vuln.get('d2_candidate_ready') else 1,
                0 if vuln.get('severity') == 'HIGH' else (1 if vuln.get('severity') == 'MEDIUM' else 2),
                vuln.get('line', 0) or 0,
            )

        verification_failures = []
        generation_failures = []
        for vuln in vulnerabilities:
            reason = str(vuln.get('reason', '') or '').strip()
            no_poc_reason = str(vuln.get('no_poc_reason', '') or '').strip()
            if vuln.get('poc_generated') and not vuln.get('poc_verified') and reason:
                verification_failures.append((priority(vuln), reason))
            elif no_poc_reason:
                generation_failures.append((priority(vuln), no_poc_reason))

        if verification_failures:
            verification_failures.sort(key=lambda item: item[0])
            return {'kind': 'verification_failed', 'text': verification_failures[0][1]}

        if generation_failures:
            generation_failures.sort(key=lambda item: item[0])
            return {'kind': 'generation_missing', 'text': generation_failures[0][1]}

        return {}

    def print_b1_summary(self, a1_results: List[ScanResult], a2_results: List[ScanResult],
                         discovered_endpoints: List[Dict] = None):
        """打印 B1 摘要"""
        a1_count = sum(len(r.vulnerabilities) for r in a1_results if not r.error)
        a2_count = sum(len(r.vulnerabilities) for r in a2_results if not r.error)

        # 计算覆盖率
        vuln_types = []
        for r in a1_results + a2_results:
            if r.error:
                continue
            for v in r.vulnerabilities:
                vuln_types.append(v.type)

        coverage = calculate_coverage_stats(
            discovered_endpoints=discovered_endpoints,
            vulnerability_types=vuln_types
        )

        print("\n" + "=" * 60)
        print("B1 初步静态分析报告")
        print("=" * 60)
        print(f"\n[统计]")
        print(f"   A1 规则扫描: {a1_count} 个漏洞")
        print(f"   A2 AI 分析:  {a2_count} 个漏洞")
        a2_suppressed = sum(getattr(r, 'suppressed_count', 0) for r in a2_results if not r.error)
        if a2_suppressed:
            print(f"   A2 保留项:   {a2_count} 个")
            print(f"   A2 抑制项:   {a2_suppressed} 个")
        print(f"   总计:        {a1_count + a2_count} 个漏洞")

        # 显示覆盖率
        api_cov = coverage.get('api_coverage', {})
        if api_cov.get('total_discovered', 0) > 0:
            print(f"\n[覆盖率]")
            print(f"   API覆盖率: {api_cov.get('coverage_rate', 0)}% ({api_cov.get('tested', 0)}/{api_cov.get('total_discovered', 0)})")

        vuln_cov = coverage.get('vulnerability_coverage', {})
        if vuln_cov.get('types_found', 0) > 0:
            print(f"   漏洞类型覆盖率: {vuln_cov.get('coverage_rate', 0)}% ({vuln_cov.get('types_found', 0)}/{vuln_cov.get('total_rules', 0)})")

        print("\n" + "=" * 60)

    def print_final_summary(self, report: Dict):
        """打印最终安全审计报告摘要"""
        summary = report.get('summary', {})

        print("\n" + "=" * 60)
        print("最终安全审计报告")
        print("=" * 60)
        print(f"\n[统计]")
        print(f"   总漏洞数:     {summary.get('total_vulnerabilities', 0)}")
        print(f"   高危:        {summary.get('by_severity', {}).get('HIGH', 0)}")
        print(f"   中危:        {summary.get('by_severity', {}).get('MEDIUM', 0)}")
        print(f"   低危:        {summary.get('by_severity', {}).get('LOW', 0)}")
        print(f"\n[动态验证]")
        print(f"   原始D2可利用: {summary.get('d2_confirmed_exploitable', 0)}")
        print(f"   原始D2 POC:   {summary.get('d2_poc_generated', 0)}")
        print(f"   链级已证实:   {summary.get('chain_proven_count', 0)}")
        print(f"   ContractReady: {summary.get('contract_ready_count', 0)}")
        print(f"   Canonical可利用: {summary.get('canonical_exploitable_count', summary.get('exploitable_count', 0))}")
        print(f"   Canonical POC:   {summary.get('canonical_poc_count', summary.get('poc_count', 0))}")
        print("\n" + "=" * 60)
