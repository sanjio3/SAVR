"""Tool adapters for the SCA (Software Composition Analysis) pipeline.

Each adapter wraps a real, market-standard SCA tool and knows how to (a) build the
tool-specific command line, (b) load the tool's native JSON output and (c) normalize
it into the unified finding shape used across the platform.  This lets the SCA layer
invoke OSV-Scanner, Trivy, Grype or Syft interchangeably instead of being coupled to
a single tool.

Unified finding shape produced by ``normalize``::

    {
        "type": "SCA",
        "display_title": "SCA: <component> <advisory>",
        "display_family": "sca",
        "severity": "LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN",
        "file": "<manifest/lockfile path>",
        "line": 0,
        "description": "...",
        "fix": "...",
        "source": "sca",
        "sca": {
            "source_tool": "<tool name>",
            "component_name": "...",
            "component_version": "...",
            "ecosystem": "...",
            "vulnerability_id": "...",
            "aliases": [...],
            "fixed_versions": [...],
            "source_path": "...",
            "references": [...],
        },
    }
"""

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.vuln_hash import enrich_finding_hash
from src.core.normalize import normalize_severity  # 唯一权威实现；本模块不再自持别名表

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_rank(value: Any) -> int:
    return SEVERITY_ORDER.get(normalize_severity(value), 0)


def make_finding(
    tool: str,
    *,
    name: str,
    version: str,
    ecosystem: str,
    vulnerability_id: str,
    severity: str,
    source_path: str,
    description: str = "",
    aliases: Optional[List[str]] = None,
    fixed_versions: Optional[List[str]] = None,
    references: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    fixed = [v for v in (fixed_versions or []) if v]
    item = {
        "type": "SCA",
        "display_title": f"SCA: {name or 'unknown'} {vulnerability_id}".strip(),
        "display_family": "sca",
        "severity": normalize_severity(severity),
        "file": source_path or "",
        "line": 0,
        "description": description or vulnerability_id or "Dependency vulnerability",
        "fix": "Upgrade to a fixed version" if fixed else "Review advisory and replace or mitigate the vulnerable component",
        "source": "sca",
        "sca": {
            "source_tool": tool,
            "component_name": name or "",
            "component_version": version or "",
            "ecosystem": ecosystem or "",
            "vulnerability_id": vulnerability_id or "",
            "aliases": list(aliases or []),
            "fixed_versions": fixed,
            "source_path": source_path or "",
            "references": list(references or []),
        },
    }
    return enrich_finding_hash(item)


# ---------------------------------------------------------------------------
# 交叉验证 + fixed 版本核查
# ---------------------------------------------------------------------------
_QUAL_RANK = {
    "": 4, "release": 4, "final": 4, "ga": 4, "stable": 4,
    "sp": 3, "rc": 2, "preview": 2, "beta": 1, "alpha": 0, "snapshot": -1,
}


def compare_versions(a: str, b: str) -> int:
    """语义化版本比较：a > b 返回 1，a == b 返回 0，a < b 返回 -1。

    支持 Maven/semver/npm 常见写法：``1.2.3``、``1.2.3-SNAPSHOT``、
    ``1.2.3.RELEASE``、``2.0.0-rc1``、带 ``v`` 前缀、主版本段不足 3 段补零。
    无法解析时退化为字符串比较（不抛异常）。
    """

    def _parse(v: str):
        v = (v or "").strip().lower()
        v = re.sub(r"^v", "", v)
        m = re.match(r"^(\d+(?:\.\d+){0,3})(.*)$", v)
        if not m:
            return ([0, 0, 0], 0, v)
        nums = [int(x) for x in m.group(1).split(".")]
        while len(nums) < 3:
            nums.append(0)
        qual = re.sub(r"^[.\-_]+", "", m.group(2) or "")
        rank = _QUAL_RANK.get(qual, 3)
        return (nums, rank, qual)

    na, qa, _ = _parse(a)
    nb, qb, _ = _parse(b)
    if na != nb:
        return 1 if na > nb else -1
    if qa != qb:
        return 1 if qa > qb else -1
    return 0


def _norm_eco(e: str) -> str:
    """归一化生态标识：Maven/pom/java/java-archive/gradle → maven 等，便于跨工具比对。"""
    e = (e or "").strip().lower()
    mapping = {
        "maven": "maven", "pom": "maven", "java": "maven", "java-archive": "maven",
        "gradle": "maven", "jar": "maven",
        "npm": "npm", "node": "npm", "nodejs": "npm", "yarn": "npm",
        "pip": "pypi", "pypi": "pypi", "python": "pypi", "poetry": "pypi",
        "gomod": "go", "go": "go", "golang": "go",
        "gem": "gem", "ruby": "gem",
        "cargo": "cargo", "rust": "cargo",
    }
    return mapping.get(e, e)


def _norm_ver(v: str) -> str:
    return (v or "").strip().lower()


def _norm_comp_name(name: str, ecosystem: str = "") -> str:
    """归一化组件名，消除跨工具同一组件的命名口径差异。

    Maven 生态下 OSV-Scanner 报 ``groupId:artifactId``、Trivy 也报 ``groupId:artifactId``，
    而 Grype 报裸 ``artifactId``（ecosystem=java-archive）。三者指向同一组件，但字符串不同，
    导致 reconcile_cross_validation 按组件名分组时落入不同桶、交叉比对永远不触发，
    cross_validated 恒为 0。

    规则：Maven 生态且名称含 ``:`` 时，取最后一段（裸 artifactId）作为归一名；
    其余生态原样返回（仅 strip+lower 消除大小写/空格差异）。
    注意：只用于分组与比对；findings 里存储的 component_name 保持原样（展示名不变）。
    """
    name = (name or "").strip()
    if not name:
        return ""
    if _norm_eco(ecosystem) == "maven" and ":" in name:
        return name.rsplit(":", 1)[-1].strip().lower()
    return name.lower()


def _finding_aliases(f: Dict[str, Any]) -> set:
    """跨工具同一 advisory 的身份集合：vulnerability_id + aliases（CVE/GHSA/别名）。

    不含 fixed_versions——fixed 版本是「是否已修复」语义（见 apply_fixed_version_check），
    放进身份比对会让两个不同 CVE 因恰巧同 fixed 版本而被误判为同一 advisory。
    """
    sca = f.get("sca") or {}
    ids = {str(sca.get("vulnerability_id", "") or "")}
    ids.update(str(a) for a in (sca.get("aliases") or []))
    return {x for x in ids if x}


def _same_advisory(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """跨工具同 advisory 判定。

    先要求组件名一致；再按优先级：
    1) 任一共同 advisory 别名（CVE/GHSA/别名）相交 → 同一 advisory（最强信号，跨工具 ID
       格式不同——osv 用 GHSA、trivy/grype 用 CVE——也能命中）；
    2) 兜底：组件 + 生态归一 + 版本归一 三者全同 → 同一 advisory。
    不再因生态/版本字符串差异（Maven vs pom vs java-archive）误判为不同 advisory。
    """
    sa, sb = a.get("sca") or {}, b.get("sca") or {}
    cn_a = _norm_comp_name(sa.get("component_name", ""), sa.get("ecosystem", ""))
    cn_b = _norm_comp_name(sb.get("component_name", ""), sb.get("ecosystem", ""))
    if cn_a != cn_b:
        return False
    if _finding_aliases(a) & _finding_aliases(b):
        return True
    if (_norm_eco(sa.get("ecosystem")) and _norm_eco(sb.get("ecosystem"))
            and _norm_eco(sa.get("ecosystem")) == _norm_eco(sb.get("ecosystem"))
            and _norm_ver(sa.get("component_version")) and _norm_ver(sb.get("component_version"))
            and _norm_ver(sa.get("component_version")) == _norm_ver(sb.get("component_version"))):
        return True
    return False


def _mark_cross(a: Dict[str, Any], b: Dict[str, Any]) -> None:
    sa, sb = a.setdefault("sca", {}), b.setdefault("sca", {})
    da = sa.setdefault("detected_by", [sa.get("source_tool", "")])
    db = sb.setdefault("detected_by", [sb.get("source_tool", "")])
    for t in list(db):
        if t and t not in da:
            da.append(t)
    for t in list(da):
        if t and t not in db:
            db.append(t)
    sa["cross_validated"] = True
    sb["cross_validated"] = True
    sa["confidence"] = "high"
    sb["confidence"] = "high"


def reconcile_cross_validation(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """跨工具交叉验证：同组件下，若两个 finding 来自不同工具且 alias/fixed 集相交，
    视为同一 advisory 被多工具共同报出，标记 cross_validated=True 并统一 detected_by。
    仅当 detected_by 含 ≥2 个不同工具才视为高置信（用户需求：双工具都报才算高置信）。"""
    by_comp: Dict[tuple, List[int]] = {}
    for idx, f in enumerate(findings):
        sca = f.get("sca") or {}
        # 用归一化组件名+归一化生态分组：OSV 报 groupId:artifactId / Grype 报裸 artifactId
        # 必须先归一（剥 groupId）才能落到同一桶做交叉比对。
        key = (_norm_comp_name(sca.get("component_name", ""), sca.get("ecosystem", "")), _norm_eco(sca.get("ecosystem")))
        by_comp.setdefault(key, []).append(idx)
    for idxs in by_comp.values():
        n = len(idxs)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = findings[idxs[i]], findings[idxs[j]]
                ta = (a.get("sca") or {}).get("source_tool", "")
                tb = (b.get("sca") or {}).get("source_tool", "")
                if ta and tb and ta != tb and _same_advisory(a, b):
                    _mark_cross(a, b)
    # 单工具或同工具多命中：cross_validated 仅在 ≥2 不同工具时为真，否则明确置 False
    for f in findings:
        sca = f.setdefault("sca", {})
        dby = sca.get("detected_by") or [sca.get("source_tool", "")]
        distinct = {t for t in dby if t}
        sca["cross_validated"] = bool(sca.get("cross_validated")) and len(distinct) >= 2
        if "confidence" not in sca:
            sca["confidence"] = "medium"
    return findings


def _version_line(version: str) -> tuple:
    """取「主版本.次版本」作为发布线：9.0.35 -> (9, 0)，11.0.0-M11 -> (11, 0)。

    跨分支 backport 的 advisory 会同时列出多条线的修复版本（如 8.5.96 / 9.0.83 /
    10.1.16）。判定时必须先看组件所属发布线，不能拿 A 线的版本去和 B 线的修复版本比。
    """
    nums = re.findall(r"\d+", str(version or ""))
    major = int(nums[0]) if len(nums) > 0 else 0
    minor = int(nums[1]) if len(nums) > 1 else 0
    return (major, minor)


def apply_fixed_version_check(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """fixed 版本比对实际版本：按**发布线**判定组件是否已升级到修复版本。

    判定规则（顺序执行）：
    1. 若 advisory 列出了组件所属发布线的修复版本，则只有实际版本 ≥ 该线的修复版本
       才算已修复（not_affected=True）。
    2. 若本发布线没有修复版本，仅当实际版本高于全部修复线（属更新的大版本）才视为
       已修复；否则保守判定为仍受影响——本线未 backport 修复即不能断言安全。

    修正前的实现是 ``any(actual >= fx for fx in all_fixed)``，会把 9.0.35 与 8.5.96
    比较后误判为「已修复」，属跨线误判。
    """
    for f in findings:
        sca = f.setdefault("sca", {})
        actual = sca.get("component_version", "")
        fixed = sca.get("fixed_versions") or []
        if not actual or not fixed:
            sca["not_affected"] = False
            continue
        actual_line = _version_line(actual)
        same_line = [fx for fx in fixed if _version_line(fx) == actual_line]
        if same_line:
            not_affected = any(compare_versions(actual, fx) >= 0 for fx in same_line)
        else:
            # 本线无修复：仅当实际版本高于全部修复线才视为已修复，否则保守判受影响
            lines = [_version_line(fx) for fx in fixed]
            not_affected = bool(lines) and all(actual_line > ln for ln in lines)
        sca["not_affected"] = not_affected
        if not_affected:
            # 已修复：降级展示置信，但保留 cross_validated 标记（双工具仍都报了）
            if sca.get("confidence") == "high":
                sca["confidence"] = "medium"
            sca["fixed_status"] = "already_fixed"
    return findings


def _candidate_paths(name: str) -> List[str]:
    """常见安装路径兜底：用户 home 的 go/bin、pip --user 等。"""
    from pathlib import Path

    candidates: List[str] = []
    home = Path.home()
    candidates.append(str(home / "go" / "bin" / f"{name}.exe"))
    candidates.append(str(home / "go" / "bin" / name))
    candidates.append(str(home / ".local" / "bin" / name))
    candidates.append(str(home / "AppData" / "Local" / "Microsoft" / "WindowsApps" / f"{name}.exe"))
    return candidates


class SCAToolAdapter:
    """Base class for a concrete SCA tool integration."""

    name = ""
    role = "vulnerability"  # "vulnerability" scanners emit findings; "sbom" tools emit an inventory
    install_hint = "Install the tool and ensure it is on PATH"
    report_filename = "sca_report.json"
    success_codes: Tuple[int, ...] = (0,)
    # 依赖树/OSV API 易超时；放宽到 600s 减少误报「SCA failed」。trivy 拉 DB 失败属镜像源问题，不在此限。
    timeout = 600

    def executable(self) -> Optional[str]:
        found = shutil.which(self.name)
        if found:
            return found
        for candidate in _candidate_paths(self.name):
            if shutil.which(candidate) or Path(candidate).is_file():
                return candidate
        return None

    def is_available(self) -> bool:
        return bool(self.executable())

    def tool_status(self) -> Dict[str, Any]:
        executable = self.executable()
        if not executable:
            return {"tool": self.name, "role": self.role, "available": False, "version": "", "install_hint": self.install_hint}
        return {
            "tool": self.name,
            "role": self.role,
            "available": True,
            "path": executable,
            "version": self._version(executable),
            "install_hint": "",
        }

    def build_command(self, executable: str, project_path: str, *, ignore_unfixed: bool = False) -> List[str]:
        raise NotImplementedError

    def load_payload(self, raw_text: str) -> Dict[str, Any]:
        return json.loads(raw_text or "{}")

    def normalize(self, payload: Dict[str, Any], severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def run(self, project_path: str, output_dir: str, severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> Dict[str, Any]:
        from pathlib import Path

        started = time.time()
        executable = self.executable()
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        result_file = output / self.report_filename
        if not executable:
            return {
                "status": "skipped",
                "tool": self.name,
                "finding_count": 0,
                "findings": [],
                "message": self.install_hint,
                "duration_seconds": round(time.time() - started, 3),
            }
        command = self.build_command(executable, project_path, ignore_unfixed=ignore_unfixed)
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout)
            raw_text = completed.stdout or "{}"
            result_file.write_text(raw_text, encoding="utf-8")
            payload = self.load_payload(raw_text)
            findings = self.normalize(payload, severity_threshold=severity_threshold, ignore_unfixed=ignore_unfixed)
            is_success = completed.returncode in self.success_codes
            return {
                "status": "completed" if is_success else "failed",
                "tool": self.name,
                "command": command,
                "returncode": completed.returncode,
                "report_file": str(result_file),
                "finding_count": len(findings),
                "findings": findings,
                "stderr": self._sanitize_stderr(completed.stderr or "", is_success),
                "duration_seconds": round(time.time() - started, 3),
            }
        except subprocess.TimeoutExpired:
            return {"status": "failed", "tool": self.name, "finding_count": 0, "findings": [], "message": f"{self.name} timed out", "duration_seconds": round(time.time() - started, 3)}
        except Exception as exc:  # noqa: BLE001 - surface tool failure without crashing the scan
            return {"status": "failed", "tool": self.name, "finding_count": 0, "findings": [], "message": str(exc), "duration_seconds": round(time.time() - started, 3)}

    @staticmethod
    def _sanitize_stderr(stderr: str, is_success: bool) -> str:
        """清理并截断 stderr，避免把工具内部警告全文回显给用户。"""
        if not stderr:
            return ""
        # OSV-Scanner 在成功时经常输出大量 gitignore 路径解析警告，对使用者无意义
        if is_success and "can't make" in stderr.lower() and "relative to" in stderr.lower():
            return ""
        # 成功时只需要摘要；失败时保留更多上下文用于排查
        limit = 280 if is_success else 1200
        text = stderr.strip().replace("\r\n", "\n")
        lines = text.splitlines()
        if len(lines) > 8 and is_success:
            text = "\n".join(lines[:8]) + f"\n... ({len(lines) - 8} more lines omitted)"
        if len(text) > limit:
            text = text[:limit] + "...[truncated]"
        return text

    def _passes(self, severity: str, fixed_versions: List[str], threshold: str, ignore_unfixed: bool) -> bool:
        if severity_rank(severity) < SEVERITY_ORDER.get(str(threshold or "LOW").upper(), 1):
            return False
        if ignore_unfixed and not fixed_versions:
            return False
        return True

    @staticmethod
    def _version(executable: str) -> str:
        try:
            completed = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=15)
            text = (completed.stdout or completed.stderr or "").strip()
            return text.splitlines()[0] if text else ""
        except Exception as exc:  # noqa: BLE001
            return f"version check failed: {exc}"


class OSVScannerAdapter(SCAToolAdapter):
    name = "osv-scanner"
    install_hint = "Install OSV-Scanner and ensure `osv-scanner` is on PATH: https://github.com/google/osv-scanner"
    report_filename = "sca_osv_report.json"
    success_codes = (0, 1)

    def build_command(self, executable: str, project_path: str, *, ignore_unfixed: bool = False) -> List[str]:
        return [executable, "scan", "--recursive", "--format", "json", project_path]

    def normalize(self, payload: Dict[str, Any], severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for result in payload.get("results", []) or []:
            source = result.get("source") or {}
            source_path = source.get("path") or result.get("path") or ""
            for package in result.get("packages", []) or []:
                pkg = package.get("package") or {}
                for vuln in package.get("vulnerabilities", []) or []:
                    severity = self._osv_severity(vuln)
                    fixed_versions = self._osv_fixed_versions(vuln)
                    if not self._passes(severity, fixed_versions, severity_threshold, ignore_unfixed):
                        continue
                    findings.append(make_finding(
                        self.name,
                        name=pkg.get("name", ""),
                        version=pkg.get("version", ""),
                        ecosystem=pkg.get("ecosystem", ""),
                        vulnerability_id=vuln.get("id", ""),
                        severity=severity,
                        source_path=source_path,
                        description=vuln.get("summary") or vuln.get("details") or vuln.get("id", ""),
                        aliases=vuln.get("aliases", []) or [],
                        fixed_versions=fixed_versions,
                        references=vuln.get("references", []) or [],
                    ))
        return findings

    @staticmethod
    def _osv_severity(vuln: Dict[str, Any]) -> str:
        database_specific = vuln.get("database_specific") or {}
        raw = str(database_specific.get("severity") or "").upper()
        if raw in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            return raw
        for item in vuln.get("severity") or []:
            score = str((item or {}).get("score", ""))
            if score.startswith("9") or ("AV:N/AC:L" in score and "/C:H" in score):
                return "CRITICAL"
        return "UNKNOWN"

    @staticmethod
    def _osv_fixed_versions(vuln: Dict[str, Any]) -> List[str]:
        versions: List[str] = []
        for affected in vuln.get("affected", []) or []:
            for item in affected.get("ranges", []) or []:
                for event in item.get("events", []) or []:
                    fixed = event.get("fixed")
                    if fixed and fixed not in versions:
                        versions.append(fixed)
        return versions


class TrivyAdapter(SCAToolAdapter):
    name = "trivy"
    install_hint = "Install Trivy and ensure `trivy` is on PATH: https://github.com/aquasecurity/trivy"
    report_filename = "sca_trivy_report.json"

    def build_command(self, executable: str, project_path: str, *, ignore_unfixed: bool = False) -> List[str]:
        command = [executable, "fs", "--quiet", "--format", "json", "--scanners", "vuln"]
        if ignore_unfixed:
            command.append("--ignore-unfixed")
        command.append(project_path)
        return command

    def normalize(self, payload: Dict[str, Any], severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for result in payload.get("Results", []) or []:
            source_path = result.get("Target", "") or ""
            ecosystem = result.get("Type", "") or ""
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = normalize_severity(vuln.get("Severity"))
                fixed_raw = vuln.get("FixedVersion") or ""
                fixed_versions = [part.strip() for part in fixed_raw.split(",") if part.strip()]
                if not self._passes(severity, fixed_versions, severity_threshold, ignore_unfixed):
                    continue
                references = vuln.get("References") or []
                if not references and vuln.get("PrimaryURL"):
                    references = [vuln.get("PrimaryURL")]
                findings.append(make_finding(
                    self.name,
                    name=vuln.get("PkgName", ""),
                    version=vuln.get("InstalledVersion", ""),
                    ecosystem=ecosystem,
                    vulnerability_id=vuln.get("VulnerabilityID", ""),
                    severity=severity,
                    source_path=source_path,
                    description=vuln.get("Title") or vuln.get("Description") or vuln.get("VulnerabilityID", ""),
                    aliases=vuln.get("CweIDs", []) or [],
                    fixed_versions=fixed_versions,
                    references=references,
                ))
        return findings


class GrypeAdapter(SCAToolAdapter):
    name = "grype"
    install_hint = "Install Grype and ensure `grype` is on PATH: https://github.com/anchore/grype"
    report_filename = "sca_grype_report.json"

    def build_command(self, executable: str, project_path: str, *, ignore_unfixed: bool = False) -> List[str]:
        command = [executable, f"dir:{project_path}", "-o", "json"]
        if ignore_unfixed:
            command.extend(["--only-fixed"])
        return command

    def normalize(self, payload: Dict[str, Any], severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for match in payload.get("matches", []) or []:
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            severity = normalize_severity(vuln.get("severity"))
            fix = vuln.get("fix") or {}
            fixed_versions = [v for v in (fix.get("versions") or []) if v]
            if not self._passes(severity, fixed_versions, severity_threshold, ignore_unfixed):
                continue
            locations = artifact.get("locations") or []
            source_path = (locations[0] or {}).get("path", "") if locations else ""
            aliases = [rel.get("id") for rel in (match.get("relatedVulnerabilities") or []) if rel.get("id")]
            references = vuln.get("urls") or ([vuln.get("dataSource")] if vuln.get("dataSource") else [])
            findings.append(make_finding(
                self.name,
                name=artifact.get("name", ""),
                version=artifact.get("version", ""),
                ecosystem=artifact.get("type", ""),
                vulnerability_id=vuln.get("id", ""),
                severity=severity,
                source_path=source_path,
                description=vuln.get("description") or vuln.get("id", ""),
                aliases=aliases,
                fixed_versions=fixed_versions,
                references=references,
            ))
        return findings


class SyftAdapter(SCAToolAdapter):
    """Syft generates a CycloneDX SBOM inventory; it is not a vulnerability scanner."""

    name = "syft"
    role = "sbom"
    install_hint = "Install Syft and ensure `syft` is on PATH: https://github.com/anchore/syft"
    report_filename = "sbom.syft.cyclonedx.json"

    def build_command(self, executable: str, project_path: str, *, ignore_unfixed: bool = False) -> List[str]:
        return [executable, f"dir:{project_path}", "-o", "cyclonedx-json"]

    def normalize(self, payload: Dict[str, Any], severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> List[Dict[str, Any]]:
        # Syft does not report vulnerabilities; the SBOM it produces feeds the component inventory.
        return []


ADAPTER_CLASSES: Tuple[type, ...] = (OSVScannerAdapter, TrivyAdapter, GrypeAdapter, SyftAdapter)
ADAPTERS: Dict[str, type] = {cls.name: cls for cls in ADAPTER_CLASSES}
VULNERABILITY_TOOLS: Tuple[str, ...] = tuple(cls.name for cls in ADAPTER_CLASSES if cls.role == "vulnerability")


def get_adapter(name: str) -> SCAToolAdapter:
    cls = ADAPTERS.get((name or "").strip().lower(), OSVScannerAdapter)
    return cls()


def all_tool_statuses() -> List[Dict[str, Any]]:
    return [cls().tool_status() for cls in ADAPTER_CLASSES]
