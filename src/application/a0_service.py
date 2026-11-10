"""A0 预处理编排（重构文档 §8.1 职责整合 + §8.4 保证不漏 4 点机制）。

把原本各自独立的 A0PreprocessService（路径校验）+ R0ReconAgent（信息收集）+ EntryDiscoveryService
（入口发现）+ P0PlanningAgent（审计计划）整合成一个 A0 编排，统一 A0 三项核心职责：

职责① 直接读路径、校验项目可访问可扫描（A0PreprocessService.validate_workspace_path）。
职责② 环境识别前置（ExternalTarget 前置探查，见 IastService.check_environment_readiness，可选）。
职责③ 入口发现 + 框架特化 + IAST 补盲闭环（§8.4）：
  - 静态多方法融合：EntryDiscoveryService 正则 + AST（已做），此处再融合 R0 框架特化路由去重。
  - R0 框架特化：R0 识别技术栈/框架 → 传给 entry discovery 做框架感知（§8.4 第2点）。
  - IAST 补盲回灌：IAST observed_only（观测有、假说无）的入口 → 回灌成规则候选（§8.4 第3点）。
  - representative_request_params 运行时回采：静态拿不到，留接口标注（§8.4 第4点）。

注意：R0ReconAgent 自带 _extract_entry_points 与 EntryDiscoveryService 功能重叠（§9.1「择优保留其一」），
本编排统一用 EntryDiscoveryService 做入口发现（含 request_params 参数采集），R0 仅贡献技术栈/框架/依赖/数据流。
"""
import logging
from typing import Any, Dict, List, Optional

from src.application.entry_discovery_service import EntryDiscoveryService
from src.pipeline.a0.service import A0PreprocessService

logger = logging.getLogger(__name__)


class A0Service:
    """A0 预处理编排器（§8.1/§8.4）。"""

    def __init__(
        self,
        preprocess: Optional[A0PreprocessService] = None,
        entry_discovery: Optional[EntryDiscoveryService] = None,
        r0_agent_cls: Any = None,
        p0_agent_cls: Any = None,
        iast_service: Any = None,
    ):
        self.preprocess = preprocess or A0PreprocessService()
        self.entry_discovery = entry_discovery or EntryDiscoveryService()
        self.r0_agent_cls = r0_agent_cls
        self.p0_agent_cls = p0_agent_cls
        self.iast_service = iast_service

    def run(
        self,
        project_path: str,
        workspace: Any = None,
        task_id: Optional[int] = None,
        external_target: Optional[Dict[str, Any]] = None,
        iast_observed_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """执行 A0 三职责整合，产出统一 A0 产物。"""
        result: Dict[str, Any] = {
            "status": "completed",
            "path_validation": None,
            "project_info": None,
            "framework": "",
            "entries": [],
            "entry_count": 0,
            "rule_candidates": [],
            "blindspot_backfill": [],
            "audit_plan": None,
            "environment_readiness": None,
        }

        # 职责① 路径校验（A0PreprocessService）
        if workspace is not None and hasattr(workspace, "target_path"):
            path_validation = self.preprocess.validate_workspace_path(workspace)
        else:
            from pathlib import Path
            p = Path(project_path)
            path_validation = (
                {"status": "ok", "message": str(p)}
                if p.is_dir()
                else {"status": "error", "message": f"Path is not a directory: {project_path}"}
            )
        result["path_validation"] = path_validation
        if path_validation.get("status") != "ok":
            result["status"] = "error"
            result["message"] = path_validation.get("message", "路径校验失败")
            return result

        # 黑板阶段二：A0 必读知识（target_profile + pitfall），best-effort 非致命。
        # 不阻断 A0，仅日志化载入，供后续环境识别 / 补盲回灌参考。workspace_id 缺失时读全局(0)。
        try:
            from src.core.knowledge_entries import read_for_stage
            workspace_id = getattr(workspace, "id", None) if workspace is not None else None
            result["knowledge_context"] = read_for_stage(workspace_id, "a0")
        except Exception as _e:
            logger.warning("[A0] 知识必读加载失败（不阻断）：%s", _e)

        # 职责③ 之 R0 框架特化（§8.4 第2点）：R0 识别技术栈/框架/依赖，喂给 entry discovery
        framework = ""
        project_info: Optional[Any] = None
        if self.r0_agent_cls is not None:
            try:
                r0 = self.r0_agent_cls(project_path)
                project_info = r0.scan()
                framework = getattr(project_info, "framework", "") or ""
                result["project_info"] = project_info.to_dict() if hasattr(project_info, "to_dict") else None
            except Exception as exc:  # R0 失败不阻断 A0，入口发现仍可跑
                result["r0_error"] = str(exc)

        # 职责③ 之 静态多方法融合 + 框架特化入口发现
        try:
            discovery = self.entry_discovery.discover(project_path, framework=framework)
        except Exception as exc:
            result["status"] = "error"
            result["message"] = f"入口发现失败：{exc}"
            return result
        result["framework"] = framework
        result["entries"] = discovery.get("entries", [])
        result["entry_count"] = discovery.get("entry_count", 0)
        result["rule_candidates"] = discovery.get("rule_candidates", [])

        # 注：原 §8.4 第4点「运行时流量回采」（消费 iast_request_params 补齐
        # representative_request_params）已于 2026-09-01 全链路移除：探针从不发送
        # request_observed，该表恒为空，回采分支从未真正产出。入口参数采集现完全由
        # EntryDiscoveryService 的静态提取（_extract_request_params）承担。

        # 职责③ 之 IAST 补盲回灌（§8.4 第3点）：observed_only 入口 → 规则候选
        if iast_observed_entries:
            result["blindspot_backfill"] = self.backfill_blindspots(iast_observed_entries)
            result["rule_candidates"] = list(result["rule_candidates"]) + result["blindspot_backfill"]

        # P0 审计计划（基于 R0 project_info）
        if self.p0_agent_cls is not None and project_info is not None:
            try:
                plan = self.p0_agent_cls(project_info).create_plan()
                result["audit_plan"] = plan.to_dict() if hasattr(plan, "to_dict") else None
            except Exception as exc:
                result["p0_error"] = str(exc)

        # 职责② 环境识别前置（可选，有 external_target 且 iast_service 具备 check_environment_readiness 时）
        if external_target and self.iast_service is not None and hasattr(self.iast_service, "check_environment_readiness"):
            try:
                result["environment_readiness"] = self.iast_service.check_environment_readiness(
                    external_target.get("service_url", ""),
                    external_target.get("app_name", ""),
                    external_target.get("agent_id", ""),
                )
            except Exception as exc:
                result["environment_readiness"] = {"ready": False, "error": str(exc)}

        return result

    def backfill_blindspots(self, iast_observed_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """§8.4 第3点：把 IAST observed_only（运行时真实命中但静态没发现）的入口回灌成规则候选。

        iast_observed_entries 每项形如 {"sink_method": "...", "sink_file": "...", "sink_line": N}。
        回灌产物作为 entry_discovery 的规则候选（status=candidate，人工审定），供下一轮静态发现更全。
        """
        candidates: List[Dict[str, Any]] = []
        seen: set = set()
        for e in iast_observed_entries or []:
            sink = str(e.get("sink_method") or "")
            file = str(e.get("sink_file") or "")
            line = int(e.get("sink_line") or 0)
            # 用 sink 方法名作为规则模式（补盲入口 → 规则候选）
            pattern = sink or file
            if not pattern or pattern in seen:
                continue
            seen.add(pattern)
            candidates.append({
                "entry_type": "web_route",
                "pattern": pattern,
                "status": "candidate",
                "confidence": "low",
                "source": "iast-blindspot-backfill",
                "sink_file": file,
                "sink_line": line,
                "rule_hash": EntryDiscoveryService._rule_hash("iast-blindspot", pattern),
            })
        return candidates
