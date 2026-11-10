
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from src.core.vuln_hash import enrich_finding_hash
from src.infrastructure.db import Database
from src.pipeline.sca.service import SCAPipelineService


def _derive_sca_health(tool_result: Dict[str, Any]) -> Dict[str, Any]:
    """由 SCA 工具结果推导健康度，避免「全部工具失败却被记为 0 漏洞 = 扫描通过」。

    返回 dict：sca_health / tools_failed / tools_succeeded / warnings。
    不改动 status 语义（避免连带把整轮任务判失败），只暴露真实健康度供报告与基线核对。
    """
    out: Dict[str, Any] = {"sca_health": None, "tools_failed": [], "tools_succeeded": [], "warnings": []}
    tool_results = list(tool_result.get("tool_results") or [])
    if not tool_results:
        return out  # 未实际跑工具（skipped 等）→ 不置评
    completed = [t for t in tool_results if str(t.get("status")) == "completed"]
    failed = [t for t in tool_results if str(t.get("status")) == "failed"]
    out["tools_failed"] = [t.get("tool") for t in failed]
    out["tools_succeeded"] = [t.get("tool") for t in completed]
    if failed and not completed:
        out["sca_health"] = "all_tools_failed"
        out["warnings"].append(
            "全部 SCA 工具执行失败（{}），本轮 0 漏洞不可信，不得作为健康基线。".format(
                ", ".join(str(t) for t in out["tools_failed"]))
        )
    elif failed:
        out["sca_health"] = "partial_tools_failed"
    elif completed:
        out["sca_health"] = "ok"
    return out


class SCAAssetService:
    """Independent SCA asset center: component inventory, SBOM, advisory findings and impact query."""

    SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "target", "dist", "build", "__pycache__", ".pytest_cache"}

    def __init__(self, db: Optional[Database] = None, output_root: str = "output/sca"):
        self.db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        self.output_root = Path(output_root)

    def tool_statuses(self) -> List[Dict[str, Any]]:
        return SCAPipelineService.available_tools()

    def scan_project(
        self,
        project_path: str,
        *,
        workspace_id: Optional[int] = None,
        task_id: Optional[int] = None,
        output_dir: Optional[str] = None,
        tool: str = "auto",
        severity_threshold: str = "LOW",
        ignore_unfixed: bool = False,
        run_tool: bool = True,
        persist: bool = True,
    ) -> Dict[str, Any]:
        started = time.time()
        root = Path(project_path).resolve()
        if not root.exists():
            return {"status": "error", "message": f"project path does not exist: {project_path}", "component_count": 0, "vulnerability_count": 0}

        output = Path(output_dir) if output_dir else self.output_root / datetime.utcnow().strftime("%Y%m%d-%H%M%S-%f")
        output.mkdir(parents=True, exist_ok=True)
        components = self.discover_components(str(root))
        sbom = self.build_sbom(components, project_name=root.name)
        sbom_path = output / "sbom.cyclonedx.json"
        sbom_path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")

        tool_result = {"status": "skipped", "tool": tool, "finding_count": 0, "findings": []}
        if run_tool:
            tool_result = SCAPipelineService(tool=tool).scan(
                str(root),
                str(output),
                severity_threshold=severity_threshold,
                ignore_unfixed=ignore_unfixed,
            )
        findings = tool_result.get("findings") or []
        enriched_findings = [enrich_finding_hash(item) for item in findings]
        summary = {
            "status": "completed" if tool_result.get("status") in {"completed", "skipped"} else tool_result.get("status", "completed"),
            "project_path": str(root),
            "tool": tool,
            "component_count": len(components),
            "vulnerability_count": len(enriched_findings),
            "finding_count": len(enriched_findings),
            "sbom_path": str(sbom_path),
            "tool_result": {k: v for k, v in tool_result.items() if k != "findings"},
            "duration_seconds": round(time.time() - started, 3),
        }
        # 提升交叉验证/去重计数到顶层，供前端 stage_results.sca 与 SCA 资产中心直接读取
        # （union_count=并集全量，intersection_count=双重检测交集，single_tool_count=单工具检测）。
        for _k in ("union_count", "intersection_count", "single_tool_count", "cross_validated_count", "not_affected_count"):
            if tool_result.get(_k) is not None:
                summary[_k] = tool_result[_k]
        # 2026-09-24：SCA 全部工具失败时，不得把 0 漏洞伪装成「扫描通过」（run 47 即此坑）。
        # 显式标注健康度，供报告与基线核对识别；不改 status 语义（避免连带把整轮任务判失败）。
        _health = _derive_sca_health(tool_result)
        for _hk in ("sca_health", "tools_failed", "tools_succeeded", "warnings"):
            summary[_hk] = _health[_hk]
        run_id = None
        if persist:
            run_id = self._persist_scan_run(
                workspace_id=workspace_id,
                task_id=task_id,
                project_path=str(root),
                tool=tool,
                status=summary["status"],
                components=components,
                findings=enriched_findings,
                sbom_path=str(sbom_path),
                summary=summary,
            )
        summary["run_id"] = run_id
        summary["components"] = components
        summary["findings"] = enriched_findings
        return summary

    def discover_components(self, project_path: str) -> List[Dict[str, Any]]:
        root = Path(project_path)
        discovered: List[Dict[str, Any]] = []
        for path in root.rglob("*"):
            if not path.is_file() or self._is_skipped(path):
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            name = path.name.lower()
            try:
                if name.startswith("requirements") and path.suffix == ".txt":
                    discovered.extend(self._parse_requirements(path, rel))
                elif name == "pyproject.toml":
                    discovered.extend(self._parse_pyproject(path, rel))
                elif name == "package.json":
                    discovered.extend(self._parse_package_json(path, rel))
                elif name == "package-lock.json":
                    discovered.extend(self._parse_package_lock(path, rel))
                elif name == "pom.xml":
                    discovered.extend(self._parse_pom(path, rel))
                elif name in {"build.gradle", "build.gradle.kts"}:
                    discovered.extend(self._parse_gradle(path, rel))
                elif name == "go.mod":
                    discovered.extend(self._parse_go_mod(path, rel))
                elif name == "cargo.toml":
                    discovered.extend(self._parse_cargo(path, rel))
            except Exception as exc:
                discovered.append({
                    "ecosystem": "unknown",
                    "name": rel,
                    "version": "",
                    "package_manager": "parse-error",
                    "source_file": rel,
                    "purl": "",
                    "scope": "unknown",
                    "direct_dependency": False,
                    "metadata": {"error": str(exc)},
                })
        return self._dedupe_components(discovered)

    def build_sbom(self, components: List[Dict[str, Any]], project_name: str = "project") -> Dict[str, Any]:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"component": {"type": "application", "name": project_name}},
            "components": [
                {
                    "type": "library",
                    "name": item.get("name", ""),
                    "version": item.get("version", ""),
                    "purl": item.get("purl", ""),
                    "scope": item.get("scope", "required"),
                    "properties": [
                        {"name": "ecosystem", "value": item.get("ecosystem", "")},
                        {"name": "package_manager", "value": item.get("package_manager", "")},
                        {"name": "source_file", "value": item.get("source_file", "")},
                    ],
                }
                for item in components
            ],
        }

    def list_components(self, workspace_id: Optional[int] = None, name: str = "", ecosystem: str = "") -> List[Dict[str, Any]]:
        sql = "SELECT * FROM sca_components"
        clauses, params = [], []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if name:
            clauses.append("LOWER(name) LIKE ?")
            params.append(f"%{name.lower()}%")
        if ecosystem:
            clauses.append("LOWER(ecosystem) = ?")
            params.append(ecosystem.lower())
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY last_seen_at DESC, ecosystem ASC, name ASC LIMIT 1000"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._component_row(row) for row in rows]

    def list_vulnerabilities(self, workspace_id: Optional[int] = None, advisory_id: str = "", component_name: str = "") -> List[Dict[str, Any]]:
        sql = "SELECT * FROM sca_vulnerabilities"
        clauses, params = [], []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if advisory_id:
            clauses.append("(LOWER(advisory_id) = ? OR LOWER(aliases_json) LIKE ?)")
            params.extend([advisory_id.lower(), f"%{advisory_id.lower()}%"])
        if component_name:
            clauses.append("LOWER(component_name) LIKE ?")
            params.append(f"%{component_name.lower()}%")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC LIMIT 1000"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._vulnerability_row(row) for row in rows]

    def impact_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        advisory_id = str(query.get("advisory_id") or query.get("cve") or query.get("ghsa") or "").strip()
        component_name = str(query.get("component_name") or query.get("package") or "").strip()
        ecosystem = str(query.get("ecosystem") or "").strip().lower()
        workspace_id = query.get("workspace_id")
        vulns = self.list_vulnerabilities(workspace_id=workspace_id, advisory_id=advisory_id, component_name=component_name)
        components = self.list_components(workspace_id=workspace_id, name=component_name, ecosystem=ecosystem)
        affected_components = []
        seen = set()
        for vuln in vulns:
            key = (vuln.get("ecosystem"), vuln.get("component_name"), vuln.get("component_version"))
            if key not in seen:
                seen.add(key)
                affected_components.append({"ecosystem": key[0], "name": key[1], "version": key[2], "source": "advisory"})
        for component in components:
            key = (component.get("ecosystem"), component.get("name"), component.get("version"))
            if key not in seen:
                seen.add(key)
                affected_components.append({"ecosystem": key[0], "name": key[1], "version": key[2], "source": "component_inventory", "source_file": component.get("source_file")})
        return {
            "query": query,
            "affected_component_count": len(affected_components),
            "vulnerability_count": len(vulns),
            "affected_components": affected_components,
            "vulnerabilities": vulns,
            "recommendation": "Upgrade affected components to fixed_versions where available, otherwise assess vendor mitigation or remove the dependency.",
        }

    def _persist_scan_run(self, *, workspace_id: Optional[int], task_id: Optional[int], project_path: str, tool: str, status: str, components: List[Dict[str, Any]], findings: List[Dict[str, Any]], sbom_path: str, summary: Dict[str, Any]) -> int:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO sca_scan_runs
            (workspace_id, task_id, project_path, tool, status, component_count, vulnerability_count, sbom_path, summary_json, created_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, task_id, project_path, tool, status, len(components), len(findings), sbom_path, self.db.dumps(summary), now, now),
        )
        row = self.db.execute("SELECT id FROM sca_scan_runs ORDER BY id DESC LIMIT 1", fetchone=True)
        run_id = int(row["id"])
        component_ids: Dict[Tuple[str, str, str], int] = {}
        for component in components:
            self.db.execute(
                """
                INSERT INTO sca_components
                (workspace_id, task_id, run_id, ecosystem, name, version, package_manager, source_file, purl, scope, direct_dependency, metadata_json, first_seen_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace_id,
                    task_id,
                    run_id,
                    component.get("ecosystem", ""),
                    component.get("name", ""),
                    component.get("version", ""),
                    component.get("package_manager", ""),
                    component.get("source_file", ""),
                    component.get("purl", ""),
                    component.get("scope", ""),
                    1 if component.get("direct_dependency", True) else 0,
                    self.db.dumps(component.get("metadata") or {}),
                    now,
                    now,
                ),
            )
            comp_row = self.db.execute("SELECT id FROM sca_components ORDER BY id DESC LIMIT 1", fetchone=True)
            component_ids[(component.get("ecosystem", ""), component.get("name", ""), component.get("version", ""))] = int(comp_row["id"])
        for finding in findings:
            sca = finding.get("sca") or {}
            key = (sca.get("ecosystem", ""), sca.get("component_name", ""), sca.get("component_version", ""))
            self.db.execute(
                """
                INSERT INTO sca_vulnerabilities
                (workspace_id, task_id, run_id, component_id, ecosystem, component_name, component_version, advisory_id, aliases_json, severity, summary, details, fixed_versions_json, references_json, status, vulnerability_hash_v2, raw_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
                """,
                (
                    workspace_id,
                    task_id,
                    run_id,
                    component_ids.get(key),
                    sca.get("ecosystem", ""),
                    sca.get("component_name", ""),
                    sca.get("component_version", ""),
                    sca.get("vulnerability_id", ""),
                    self.db.dumps(sca.get("aliases") or []),
                    finding.get("severity", "UNKNOWN"),
                    finding.get("display_title") or finding.get("description", ""),
                    finding.get("description", ""),
                    self.db.dumps(sca.get("fixed_versions") or []),
                    self.db.dumps(sca.get("references") or []),
                    finding.get("vulnerability_hash_v2", ""),
                    self.db.dumps(finding),
                    now,
                ),
            )
        return run_id

    def _parse_requirements(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        items = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            text = line.split("#", 1)[0].strip()
            if not text or text.startswith(("-", "--")):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<|=)?\s*([A-Za-z0-9_.!*+-]*)", text)
            if match:
                items.append(self._component("PyPI", match.group(1), match.group(2).strip("*"), "pip", rel))
        return items

    def _parse_pyproject(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        items = []
        for match in re.finditer(r"[\"']([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<|=)?\s*([A-Za-z0-9_.!*+-]*)[\"']", text):
            items.append(self._component("PyPI", match.group(1), match.group(2).strip("*"), "pyproject", rel))
        for match in re.finditer(r"^([A-Za-z0-9_.-]+)\s*=\s*[\"']\^?([A-Za-z0-9_.+-]+)[\"']", text, re.M):
            items.append(self._component("PyPI", match.group(1), match.group(2), "poetry", rel))
        return items

    def _parse_package_json(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        items = []
        for scope_name, deps in (("required", data.get("dependencies") or {}), ("optional", data.get("devDependencies") or {}), ("optional", data.get("peerDependencies") or {})):
            for name, version in deps.items():
                items.append(self._component("npm", name, str(version).lstrip("^~>=<"), "npm", rel, scope=scope_name))
        return items

    def _parse_package_lock(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        items = []
        for name, meta in (data.get("dependencies") or {}).items():
            items.append(self._component("npm", name, str((meta or {}).get("version", "")), "npm-lock", rel, direct=False))
        return items[:5000]

    def _parse_pom(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        root = ET.fromstring(path.read_text(encoding="utf-8", errors="ignore"))
        items = []
        for dep in root.iter():
            if self._tag(dep.tag) != "dependency":
                continue
            group = artifact = version = scope = ""
            for child in list(dep):
                tag = self._tag(child.tag)
                if tag == "groupId":
                    group = child.text or ""
                elif tag == "artifactId":
                    artifact = child.text or ""
                elif tag == "version":
                    version = child.text or ""
                elif tag == "scope":
                    scope = child.text or "required"
            if group and artifact:
                items.append(self._component("Maven", f"{group}:{artifact}", version, "maven", rel, scope=scope or "required"))
        return items

    def _parse_gradle(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        items = []
        for match in re.finditer(r"['\"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^'\"]+)['\"]", text):
            items.append(self._component("Maven", f"{match.group(1)}:{match.group(2)}", match.group(3), "gradle", rel))
        return items

    def _parse_go_mod(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        items = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            text = line.strip()
            if not text or text.startswith(("module", "go", "require (", ")")):
                continue
            parts = text.split()
            if len(parts) >= 2 and "/" in parts[0]:
                items.append(self._component("Go", parts[0], parts[1].lstrip("v"), "go", rel))
        return items

    def _parse_cargo(self, path: Path, rel: str) -> List[Dict[str, Any]]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        items = []
        for match in re.finditer(r"^([A-Za-z0-9_-]+)\s*=\s*[\"']([^\"']+)[\"']", text, re.M):
            items.append(self._component("crates.io", match.group(1), match.group(2), "cargo", rel))
        return items

    def _component(self, ecosystem: str, name: str, version: str, manager: str, rel: str, *, scope: str = "required", direct: bool = True) -> Dict[str, Any]:
        name = name.strip()
        version = str(version or "").strip()
        return {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "package_manager": manager,
            "source_file": rel,
            "purl": self._purl(ecosystem, name, version),
            "scope": scope or "required",
            "direct_dependency": direct,
            "metadata": {},
        }

    @staticmethod
    def _purl(ecosystem: str, name: str, version: str) -> str:
        eco = ecosystem.lower()
        purl_type = {"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang", "crates.io": "cargo"}.get(eco, eco)
        suffix = f"@{version}" if version else ""
        return f"pkg:{purl_type}/{name}{suffix}"

    def _is_skipped(self, path: Path) -> bool:
        return any(part in self.SKIP_DIRS for part in path.parts)

    @staticmethod
    def _tag(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    @staticmethod
    def _dedupe_components(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        result = []
        for item in items:
            key = (str(item.get("ecosystem", "")).lower(), str(item.get("name", "")).lower(), str(item.get("version", "")), str(item.get("source_file", "")))
            if not item.get("name") or key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _component_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "task_id": row["task_id"],
            "run_id": row["run_id"],
            "ecosystem": row["ecosystem"],
            "name": row["name"],
            "version": row["version"],
            "package_manager": row["package_manager"],
            "source_file": row["source_file"],
            "purl": row["purl"],
            "scope": row["scope"],
            "direct_dependency": bool(row["direct_dependency"]),
            "metadata": Database.loads(row["metadata_json"]),
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
        }

    @staticmethod
    def _vulnerability_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "task_id": row["task_id"],
            "run_id": row["run_id"],
            "component_id": row["component_id"],
            "ecosystem": row["ecosystem"],
            "component_name": row["component_name"],
            "component_version": row["component_version"],
            "advisory_id": row["advisory_id"],
            "aliases": Database.loads(row["aliases_json"]),
            "severity": row["severity"],
            "summary": row["summary"],
            "details": row["details"],
            "fixed_versions": Database.loads(row["fixed_versions_json"]),
            "references": Database.loads(row["references_json"]),
            "status": row["status"],
            "vulnerability_hash_v2": row["vulnerability_hash_v2"],
            "raw": Database.loads(row["raw_json"]),
            "created_at": row["created_at"],
        }
