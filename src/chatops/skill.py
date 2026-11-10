"""ChatOps SCA skill (G11).

Turns a parsed query into the structured answer the 第四版 §2.15 spec asks for:
- 是否使用（该组件在资产库中是否存在）
- 项目列表（命中的 workspace/source_file）
- 是否命中漏洞版本（advisory 版本区间匹配）
- 暴露面（受影响组件数）
- 修复建议（fixed_versions / 升级建议）

Reuses G10's :class:`AdvisoryService` (advisory intel) and the SCA component
inventory. Fully offline.
"""

import os
from typing import Any, Dict, List, Optional

from src.application.advisory_service import AdvisoryService
from src.chatops.parser import parse_query
from src.infrastructure.db import Database


class ScaChatOpsSkill:
    def __init__(self, db: Optional[Database] = None, *, advisory_service: Optional[AdvisoryService] = None):
        self.db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        self.advisory_service = advisory_service or AdvisoryService(self.db)

    def query(self, text: str, *, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        intent = parse_query(text)
        name = intent.get("name") or ""
        version = intent.get("version") or ""
        ecosystem = intent.get("ecosystem") or ""

        installations = self._installations(name, workspace_id) if name else []
        in_use = bool(installations)
        projects = sorted({inst["source_file"] for inst in installations if inst.get("source_file")})

        # Vulnerability matches: use provided version, else every installed version.
        vuln_hits: List[Dict[str, Any]] = []
        versions_to_check = [version] if version else sorted({i["version"] for i in installations if i.get("version")})
        for ver in versions_to_check or ([version] if version else []):
            eco = ecosystem or (installations[0]["ecosystem"] if installations else "")
            vuln_hits.extend(self.advisory_service.match_component(ecosystem=eco, name=name, version=ver))

        # Advisory-id direct lookups (CVE/GHSA/...): report their metadata too.
        advisory_lookups = self._advisory_lookups(intent.get("advisory_ids") or [])

        malicious = [h for h in vuln_hits if h.get("malicious")]
        fixed_versions = sorted({v for h in vuln_hits for v in (h.get("fixed_versions") or [])})

        return {
            "query": text,
            "parsed": intent,
            "in_use": in_use,
            "projects": projects,
            "installations": installations,
            "vulnerable": bool(vuln_hits),
            "vulnerability_hits": vuln_hits,
            "advisory_lookups": advisory_lookups,
            "exposure": {
                "installation_count": len(installations),
                "vulnerable_hit_count": len(vuln_hits),
                "malicious": bool(malicious),
            },
            "remediation": self._remediation(name, fixed_versions, bool(malicious)),
        }

    def _installations(self, name: str, workspace_id: Optional[int]) -> List[Dict[str, Any]]:
        sql = "SELECT workspace_id, ecosystem, name, version, source_file FROM sca_components WHERE LOWER(name) = ?"
        params: List[Any] = [name.lower()]
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [
            {
                "workspace_id": row["workspace_id"],
                "ecosystem": row["ecosystem"],
                "name": row["name"],
                "version": row["version"],
                "source_file": row["source_file"],
            }
            for row in rows
        ]

    def _advisory_lookups(self, advisory_ids: List[str]) -> List[Dict[str, Any]]:
        if not advisory_ids:
            return []
        wanted = {a.upper() for a in advisory_ids}
        hits = []
        for record in self.advisory_service.repo.list(limit=5000):
            ids = {record["advisory_id"].upper(), *[a.upper() for a in (record.get("aliases") or [])]}
            if ids & wanted:
                hits.append(record)
        return hits

    @staticmethod
    def _remediation(name: str, fixed_versions: List[str], malicious: bool) -> str:
        if malicious:
            return f"检测到恶意/投毒组件 {name}：立即移除该依赖并轮换可能泄露的凭据。"
        if fixed_versions:
            return f"升级 {name} 至已修复版本之一：{', '.join(fixed_versions)}。"
        if name:
            return f"{name} 当前未命中已知漏洞版本；保持关注上游情报。"
        return "未能从查询中解析出组件，请提供组件名或注册表 URL。"
