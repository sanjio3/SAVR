"""
漏洞数据模型
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
import re
from .exploit_spec import empty_chain_proof, empty_exploit_spec, failure_classification
from .proof_obligations import empty_taint_flow_hypothesis


def coerce_line_number(raw: Any) -> Optional[int]:
    """P1-1：LLM 返回的 line 归一为 int（choke point）。

    LLM 输出 line 常是字符串（"42"、"L42"、区间文本），未归一流入下游
    十余个 int 比较点会抛 TypeError（int < str），被逐文件容错吞掉后
    变成静默漏检。规则：
    - int 直接返回（<= 0 视为无效置 0）
    - bool 先排除（bool 是 int 子类，True 不能当行号 1）
    - float 仅整数部分有效时取整
    - str 纯数字直接转；否则取首个连续数字段（如 "L42"、"42-45" 取 42）
    - 其余（None/空串/无数字文本）一律 0

    不可解析统一返回 **0 而非 None**（2026-09-13 实测修正）：全项目对 line 的判空
    口径是 `line_no <= 0` 即无效，没有任何 `line is None` 分支；返回 None 会让
    `start_line <= vuln_line <= end_line` 这类比较抛 "'<=' not supported between
    instances of 'int' and 'NoneType'"，容错照样吞成静默漏检。0 既符合既有判空口径，
    又保证任何 int 比较都不再崩溃。
    """
    if raw is None:
        return 0
    if isinstance(raw, bool):
        return 0
    if isinstance(raw, int):
        return raw if raw > 0 else 0
    if isinstance(raw, float):
        iv = int(raw)
        return iv if iv > 0 and iv == raw else 0
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return 0
        if s.isdigit():
            v = int(s)
            return v if v > 0 else 0
        m = re.search(r"\d+", s)
        if m:
            return int(m.group())
        return 0
    return 0


# 规则族 / 英文类型 → 中文展示名（用于 A1「XX规则命中」展示）
FAMILY_ZH = {
    "sql-injection": "SQL注入",
    "command-execution": "命令执行",
    "command-injection": "命令注入",
    "code-injection": "代码注入",
    "expression-injection": "表达式注入",
    "template-injection": "模板注入",
    "path-injection": "路径注入",
    "path-traversal": "路径穿越",
    "ldap-injection": "LDAP注入",
    "xpath-injection": "XPath注入",
    "header-injection": "头注入",
    "log-injection": "日志注入",
    "xss": "XSS",
    "cross-site-scripting": "XSS",
    "ssrf": "SSRF",
    "server-side-request-forgery": "SSRF",
    "unsafe-deserialization": "反序列化",
    "deserialization": "反序列化",
    "url-redirection": "开放重定向",
    "open-redirect": "开放重定向",
    "xxe": "XXE",
    "xml-external-entity": "XXE",
    "no-sql-injection": "NoSQL注入",
    "nosql-injection": "NoSQL注入",
    "business-logic": "业务逻辑",
    "privilege-escalation": "权限提升",
    "authentication-bypass": "认证绕过",
    "resource-exhaustion": "资源耗尽",
    "idor": "IDOR",
    "bola": "越权",
    "auth-session": "会话认证",
    "state-machine": "状态机",
    "calculation-logic": "计算逻辑",
    "abuse-dos": "滥用DOS",
    # 2026-09-18（A1 配置类检测通道）：暴露 / 配置轴两族的展示名
    "config-security": "安全配置",
    "information-disclosure": "信息泄露",
}

TYPE_ZH = {
    "SQL Injection": "SQL注入",
    "Command Injection": "命令注入",
    "Command Execution": "命令执行",
    "Code Injection": "代码注入",
    "Expression Injection": "表达式注入",
    "Template Injection": "模板注入",
    "Path Traversal": "路径穿越",
    "LDAP Injection": "LDAP注入",
    "XPath Injection": "XPath注入",
    "Header Injection": "头注入",
    "Log Injection": "日志注入",
    "XSS": "XSS",
    "SSRF": "SSRF",
    "XXE": "XXE",
    "Deserialization": "反序列化",
    "URL Redirect": "开放重定向",
    "OGNL Injection": "OGNL注入",
    "SpEL Injection": "SpEL注入",
    "SSTI": "SSTI",
    # 2026-09-18（A1 配置类检测通道）
    "Security Misconfiguration": "安全配置不当",
    "Sensitive Data Exposure": "敏感信息泄露",
}


def rule_hit_label(type_: str = "", family: str = "", rule_id: str = "") -> str:
    """返回 A1 规则命中展示名（如 'SQL注入'），供前端 'XX规则命中' 使用。"""
    for key in (family, type_, rule_id):
        key_l = str(key or "").lower()
        if key_l in FAMILY_ZH:
            return FAMILY_ZH[key_l]
    if type_ in TYPE_ZH:
        return TYPE_ZH[type_]
    if type_:
        return type_
    return "规则"


class Severity(Enum):
    """漏洞严重程度"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class VulnerabilityType(Enum):
    """漏洞类型"""
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    XXE = "XXE"
    SSRF = "SSRF"
    PATH_TRAVERSAL = "Path Traversal"
    XSS = "XSS"
    DESERIALIZATION = "Deserialization"
    FILE_UPLOAD = "File Upload"
    URL_REDIRECT = "URL Redirect"
    OGNL_INJECTION = "OGNL Injection"
    SPEL_INJECTION = "SpEL Injection"
    LDAP_INJECTION = "LDAP Injection"
    XPATH_INJECTION = "XPath Injection"
    SSTI = "SSTI"
    UNKNOWN = "Unknown"


@dataclass
class Vulnerability:
    """漏洞数据模型"""
    type: str
    severity: str
    line: Optional[int] = None
    description: str = ""
    fix: str = ""
    file: str = ""
    code_snippet: str = ""
    # 数据流分析扩展字段
    entry_point: str = ""      # 入口点（用户输入来源）
    sink: str = ""             # 危险函数
    data_flow: str = ""        # 数据流路径
    has_http_entry: bool = False  # 是否有HTTP入口

    # 调用链分析字段 (新增)
    has_call_chain: bool = False  # 是否有调用链
    callers: str = ""            # 调用者信息
    verdict: str = ""           # 真假判定: "真漏洞" / "假漏洞" / "待分析"
    source: str = ""            # 来源: "a1" / "a2" / "a1+a2"

    # D2动态验证字段 (统一链路: D1重放 + I1关联 + D2核实 + I2裁决)
    exploitable: Optional[bool] = None       # 是否可利用
    vulnerable: Optional[bool] = None        # 是否存在漏洞 (兼容字段)
    confidence: str = ""                    # 置信度: high/medium/low
    poc: str = ""                           # POC代码
    poc_type: str = ""                      # POC类型
    executed: bool = False                   # 是否执行了POC
    no_poc_reason: str = ""                 # 无法生成POC的原因
    d2_evidence: str = ""                   # D2验证证据
    d2_output: str = ""                     # D2执行输出
    d2_error: str = ""                      # D2错误信息
    canonical_group_key: str = ""
    is_canonical: bool = False
    supporting_nodes: List[dict] = field(default_factory=list)
    supporting_node_count: int = 0
    chain_id: str = ""
    # 2026-09-18（A2 方案二）：聚合吸收成员补行标记。
    # 聚合（_merge_chain_vulnerabilities / _aggregate_canonical_findings）把同族非 canonical 节点
    # 并入聚合 finding 的 supporting_nodes 后，该节点原本不再有自己的 findings 行 —— 于是
    # 「按 file_path 统计覆盖」把 Shiro.java 这类只有成员资格、无独立行的文件读成 0 覆盖，
    # 且 iast_events.correlated_finding_id 关联桥挂不上（证据链只认有行的文件）。
    # 现在被吸收的成员保留独立行（is_canonical=False），本组字段标注它的归属聚合组，
    # 使覆盖率统计与关联桥恢复；同时消费方据此把它排除出 D2 候选池、避免重复展示。
    is_absorbed: bool = False
    absorbed_by_group_key: str = ""
    proof_tier: str = "broad_static"
    chain_proof: Dict[str, Any] = field(default_factory=empty_chain_proof)
    proof_gaps: List[str] = field(default_factory=list)
    # 路径 C（2026-09-20）：聚焦提示词二次证明的留痕。
    # 记录这条漏洞是否被二次证明处理过、问了哪些项、模型给了什么依据、最终是否升级。
    # 用途：区分「规则层证成的 chain_proven」与「模型二次证明补成的 chain_proven」，
    # 避免把模型判断冒充成静态证据；也便于按 prompt 版本做 A/B。
    proof_second_pass: Dict[str, Any] = field(default_factory=dict)
    proof_context_summary: Dict[str, Any] = field(default_factory=dict)
    exploit_spec: Dict[str, Any] = field(default_factory=empty_exploit_spec)
    contract_gaps: List[str] = field(default_factory=list)
    failure_classification: Dict[str, Any] = field(default_factory=failure_classification)
    a21_candidate_score: int = 0
    a21_selected: Optional[bool] = None
    a21_reason: str = ""
    # 入口解析结果（_pre_resolve_a2_endpoints 写入）：落盘便于事后归因「每条当时解析到哪一步」
    # entry_resolved 默认 None（尚未解析），与「显式 False=解析确认无可达入口」区分——
    # _score_candidate / is_mainline_d2_item 用 `getattr(vuln,"entry_resolved",None) is False` 判定，
    # 默认 None 不触发门禁（与旧行为一致），仅 pre-resolve 显式置 False 才拦截。
    entry_resolution: Dict[str, Any] = field(default_factory=dict)
    entry_resolved: Optional[bool] = None

    # §R5：A2 LLM 显式给出的 HTTP 入口绑定。
    # prompt 要求模型从 @GetMapping/@PostMapping 注解或 A1 证据取真实路由，并明确
    # "严禁编造：不确定时留空"。比事后用正则从正文捞路由可靠 —— 此前的 /admin/、"/"
    # 这类假路由正是正则兜底的产物，导致 findings 转不成 trigger_spec 被整批丢弃。
    llm_route: str = ""            # LLM 给出的 HTTP 路由（如 /order/{id}）
    llm_entry_method: str = ""     # LLM 给出的入口方法（如 OrderController#detail）
    llm_params: List[dict] = field(default_factory=list)

    # 污点流假说（sink 本身不等于危险，需 source→sink 可达且无 barrier）
    taint_flow_hypothesis: Dict[str, Any] = field(default_factory=empty_taint_flow_hypothesis)
    confirmed: bool = False                 # 完整 flow 是否已证实（静态或运行时）
    is_dangerous: bool = False              # 是否可断言「危险」（flow 完整才为真）
    severity_claimed: str = ""              # LLM 原始声称的严重度（审计用，保留不被覆盖）
    detection_method: str = ""              # "rule"（A1 规则命中）/ "taint_flow"（A2 污点流证成）
    rule_name: str = ""                    # 规则命中展示名（如 "SQL注入"），供前端 "XX规则命中" 使用

    def __post_init__(self):
        # P1-1：Vulnerability 构造的单一 choke point，line 类型归一。
        # 所有构造点（a2_ai_agent/a2_intelligent_agent/a1_*）统一经过这里，
        # 下游比较点（line_no <= 0、0 < vuln_line <= len(lines) 等）不再遇 str 崩溃。
        coerced = coerce_line_number(self.line)
        if coerced is not self.line:
            self.line = coerced

    def to_dict(self):
        data = {
            'type': self.type,
            'severity': self.severity,
            'line': self.line,
            'description': self.description,
            'fix': self.fix,
            'file': self.file,
            'code_snippet': self.code_snippet,
            'entry_point': self.entry_point,
            'sink': self.sink,
            'data_flow': self.data_flow,
            'has_http_entry': self.has_http_entry,
            'has_call_chain': self.has_call_chain,
            'callers': self.callers,
            'verdict': self.verdict,
            'source': self.source,
            # D2验证字段
            'exploitable': self.exploitable,
            'vulnerable': self.vulnerable,
            'confidence': self.confidence,
            'poc': self.poc,
            'poc_type': self.poc_type,
            'executed': self.executed,
            'no_poc_reason': self.no_poc_reason,
            'd2_evidence': self.d2_evidence,
            'd2_output': self.d2_output,
            'd2_error': self.d2_error,
            'canonical_group_key': self.canonical_group_key,
            'is_canonical': self.is_canonical,
            'supporting_nodes': self.supporting_nodes,
            'supporting_node_count': self.supporting_node_count,
            'chain_id': self.chain_id,
            # 2026-09-18（A2 方案二）：聚合吸收成员补行标记，供覆盖率统计与关联桥识别
            'is_absorbed': self.is_absorbed,
            'absorbed_by_group_key': self.absorbed_by_group_key,
            'proof_tier': self.proof_tier,
            'chain_proof': self.chain_proof,
            'proof_gaps': self.proof_gaps,
            'proof_second_pass': self.proof_second_pass,
            'proof_context_summary': self.proof_context_summary,
            'exploit_spec': self.exploit_spec,
            'contract_gaps': self.contract_gaps,
            'failure_classification': self.failure_classification,
            'a21_candidate_score': self.a21_candidate_score,
            'a21_selected': self.a21_selected,
            'a21_reason': self.a21_reason,
            # 入口解析结果落盘（Q3③）
            'entry_resolution': self.entry_resolution,
            'entry_resolved': self.entry_resolved,
            # 污点流假说与确认态
            'taint_flow_hypothesis': self.taint_flow_hypothesis,
            'confirmed': self.confirmed,
            'is_dangerous': self.is_dangerous,
            'severity_claimed': self.severity_claimed,
            'detection_method': self.detection_method,
            'rule_name': self.rule_name,
        }
        return data


@dataclass
class ScanResult:
    """扫描结果"""
    file: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    agent: str = ""  # 'a1' or 'a2'
    error: Optional[str] = None
    suppressed_count: int = 0
    suppressed_vulnerabilities: List[dict] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            'file': self.file,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'agent': self.agent,
            'error': self.error,
            'count': len(self.vulnerabilities),
            'suppressed_count': self.suppressed_count,
            'suppressed_vulnerabilities': self.suppressed_vulnerabilities,
            'evidence': self.evidence,
        }


@dataclass
class BenchmarkResult:
    """Benchmark 评估结果"""
    # Ground Truth
    total_vulnerabilities: int = 0

    # A1 规则匹配结果
    a1_detected: int = 0
    a1_true_positive: int = 0
    a1_false_positive: int = 0
    a1_false_negative: int = 0

    # A2 AI 分析结果
    a2_detected: int = 0
    a2_true_positive: int = 0
    a2_false_positive: int = 0
    a2_false_negative: int = 0

    # 准确率
    @property
    def a1_precision(self) -> float:
        if self.a1_detected == 0:
            return 0.0
        return self.a1_true_positive / self.a1_detected

    @property
    def a1_recall(self) -> float:
        if self.total_vulnerabilities == 0:
            return 0.0
        return self.a1_true_positive / self.total_vulnerabilities

    @property
    def a1_f1(self) -> float:
        if self.a1_precision + self.a1_recall == 0:
            return 0.0
        return 2 * self.a1_precision * self.a1_recall / (self.a1_precision + self.a1_recall)

    @property
    def a2_precision(self) -> float:
        if self.a2_detected == 0:
            return 0.0
        return self.a2_true_positive / self.a2_detected

    @property
    def a2_recall(self) -> float:
        if self.total_vulnerabilities == 0:
            return 0.0
        return self.a2_true_positive / self.total_vulnerabilities

    @property
    def a2_f1(self) -> float:
        if self.a2_precision + self.a2_recall == 0:
            return 0.0
        return 2 * self.a2_precision * self.a2_recall / (self.a2_precision + self.a2_recall)

    def to_dict(self):
        return {
            'total_vulnerabilities': self.total_vulnerabilities,
            'a1': {
                'detected': self.a1_detected,
                'true_positive': self.a1_true_positive,
                'false_positive': self.a1_false_positive,
                'false_negative': self.a1_false_negative,
                'precision': round(self.a1_precision, 4),
                'recall': round(self.a1_recall, 4),
                'f1': round(self.a1_f1, 4)
            },
            'a2': {
                'detected': self.a2_detected,
                'true_positive': self.a2_true_positive,
                'false_positive': self.a2_false_positive,
                'false_negative': self.a2_false_negative,
                'precision': round(self.a2_precision, 4),
                'recall': round(self.a2_recall, 4),
                'f1': round(self.a2_f1, 4)
            }
        }
