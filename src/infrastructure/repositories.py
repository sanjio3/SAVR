from datetime import datetime
from typing import Any, Dict, List, Optional
import logging

from src.domain.models import FindingRecord, ReportRecord, ScanTask, TaskEvent, TaskStatus, Workspace
from src.infrastructure.db import Database
from src.core.vuln_hash import enrich_finding_hash, _norm_family
from src.core.exploit_spec import canonical_business_logic_family, canonical_family, derive_flow_type
from src.core.normalize import correct_family_by_evidence, normalize_severity, normalize_type

logger = logging.getLogger(__name__)


def _norm_source(raw: Any) -> str:
    """P2-2：findings.source 落库归一（choke point）。

    source 此前直存 A2 原文 type 字符串（sql注入 / xxe (xml external entity) /
    url重定向 等），同族中英文并存导致统计与对账在 findings/trigger_specs 两张表口径
    不一致。两级归一：先 _norm_family（词边界 needle，含中文「上传/命令/路径」等），
    再 canonical_family（exploit_spec 唯一别名表，已补中文变体）。agent 标记
    （a1/a2/sca）与未知 token 原样保留；原文始终保留在 raw_json 不丢信息。
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        family = _norm_family({"type": text})
        family = canonical_family(family)
        return str(family or text)
    except Exception:
        return text


def slugify(text: str) -> str:
    """把 workspace 名称转成 URL 友好的 slug（小写、非字母数字转连字符、截断）。"""
    import re
    s = (text or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s[:48] or "ws"


class WorkspaceRepository:
    def __init__(self, db: Database):
        self.db = db

    def list(self, include_archived: bool = False) -> List[Workspace]:
        rows = self.db.execute("SELECT * FROM workspaces ORDER BY updated_at DESC, id DESC", fetchall=True) or []
        if not include_archived:
            rows = [row for row in rows if not bool(Database.loads(row["settings_json"]).get("archived", False))]
        return [self._row_to_workspace(row) for row in rows]

    def get(self, workspace_id: int) -> Optional[Workspace]:
        row = self.db.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,), fetchone=True)
        return self._row_to_workspace(row) if row else None

    def get_by_slug(self, slug: str) -> Optional[Workspace]:
        row = self.db.execute("SELECT * FROM workspaces WHERE slug = ?", (slug,), fetchone=True)
        return self._row_to_workspace(row) if row else None

    def create(self, workspace: Workspace) -> Workspace:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (workspace.name, workspace.target_path, workspace.description, self.db.dumps(workspace.settings), now, now),
        )
        row = self.db.execute("SELECT * FROM workspaces ORDER BY id DESC LIMIT 1", fetchone=True)
        ws = self._row_to_workspace(row)
        # slug = slugify(name) + '-' + id，保证全局可读且唯一（不同 workspace 不会因同名冲突）。
        slug = f"{slugify(ws.name)}-{ws.id}"
        self.db.execute("UPDATE workspaces SET slug = ? WHERE id = ?", (slug, ws.id))
        ws.slug = slug
        return ws

    def update(self, workspace_id: int, payload: Dict[str, Any]) -> Optional[Workspace]:
        current = self.get(workspace_id)
        if current is None:
            return None
        merged_settings = dict(current.settings)
        merged_settings.update(payload.get("settings") or {})
        new_name = payload.get("name", current.name)
        # 仅当用户显式给了 slug 才用；否则沿用 id 派生规则（name 变了则重派生）。
        explicit_slug = payload.get("slug")
        if explicit_slug:
            slug = slugify(explicit_slug)
        else:
            slug = f"{slugify(new_name)}-{workspace_id}"
        self.db.execute(
            """
            UPDATE workspaces
            SET name = ?, target_path = ?, description = ?, settings_json = ?, slug = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                new_name,
                payload.get("target_path", current.target_path),
                payload.get("description", current.description),
                self.db.dumps(merged_settings),
                slug,
                datetime.utcnow().isoformat(),
                workspace_id,
            ),
        )
        return self.get(workspace_id)

    def delete(self, workspace_id: int) -> None:
        self.db.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))

    @staticmethod
    def _row_to_workspace(row) -> Workspace:
        settings = Database.loads(row["settings_json"])
        return Workspace(
            id=row["id"],
            name=row["name"],
            target_path=row["target_path"],
            description=row["description"],
            settings=settings,
            archived=bool(settings.get("archived", False)),
            slug=row.get("slug") or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


class TaskRepository:
    def __init__(self, db: Database):
        self.db = db

    def create(self, task: ScanTask) -> ScanTask:
        self.db.execute(
            """
            INSERT INTO scan_tasks
            (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.workspace_id,
                task.name,
                task.status.value,
                task.phase,
                task.output_dir,
                self.db.dumps(task.options),
                self.db.dumps(task.summary),
                task.error_message,
                task.created_at,
                task.started_at,
                task.finished_at,
            ),
        )
        row = self.db.execute("SELECT * FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._row_to_task(row)

    def update(self, task_id: int, **fields: Any) -> Optional[ScanTask]:
        current = self.get(task_id)
        if current is None:
            return None
        self.db.execute(
            """
            UPDATE scan_tasks
            SET name = ?, status = ?, phase = ?, output_dir = ?, options_json = ?, summary_json = ?,
                error_message = ?, started_at = ?, finished_at = ?
            WHERE id = ?
            """,
            (
                fields.get("name", current.name),
                str(getattr(fields.get("status", current.status), "value", fields.get("status", current.status.value))),
                fields.get("phase", current.phase),
                fields.get("output_dir", current.output_dir),
                self.db.dumps(fields.get("options", current.options)),
                self.db.dumps(fields.get("summary", current.summary)),
                fields.get("error_message", current.error_message),
                fields.get("started_at", current.started_at),
                fields.get("finished_at", current.finished_at),
                task_id,
            ),
        )
        return self.get(task_id)

    def get(self, task_id: int) -> Optional[ScanTask]:
        row = self.db.execute("SELECT * FROM scan_tasks WHERE id = ?", (task_id,), fetchone=True)
        return self._row_to_task(row) if row else None

    def list(self, workspace_id: Optional[int] = None) -> List[ScanTask]:
        if workspace_id is None:
            rows = self.db.execute("SELECT * FROM scan_tasks ORDER BY id DESC", fetchall=True) or []
        else:
            rows = self.db.execute("SELECT * FROM scan_tasks WHERE workspace_id = ? ORDER BY id DESC", (workspace_id,), fetchall=True) or []
        return [self._row_to_task(row) for row in rows]

    # 旧 delete 只删 scan_tasks 一行，trigger_specs / model_runs / hypotheses /
    # vuln_blackboard / scan_runs / scan_task_events / findings / reports 全部残留
    # 。submit 脚本的
    # D-1 预检只清「下一个预测 id」，绕过脚本直接调 REST 时全量残留。
    # 现在级联删下沉到仓库层：删任务必删子表，顺序为子表在前、父表在后。
    TASK_CHILD_TABLES = (
        "trigger_specs",
        "model_runs",
        "hypotheses",
        "vuln_blackboard",
        "scan_runs",
        "scan_task_events",
        "findings",
        "reports",
    )

    def _delete_children(self, task_ids: tuple) -> int:
        """级联删除子表中这些 task_id 的行；单表失败不影响其余（best-effort 记日志）。"""
        if not task_ids:
            return 0
        removed = 0
        placeholders = ",".join("?" for _ in task_ids)
        for table in self.TASK_CHILD_TABLES:
            try:
                cur = self.db.execute(
                    f"DELETE FROM {table} WHERE task_id IN ({placeholders})",
                    tuple(task_ids),
                    return_rowcount=True,
                )
                removed += int(cur or 0)
            except Exception as _e:
                logger.warning("[TaskRepository._delete_children] 清理 %s 失败（跳过）：%s", table, _e)
        return removed

    def delete(self, task_id: int) -> None:
        self._delete_children((int(task_id),))
        self.db.execute("DELETE FROM scan_tasks WHERE id = ?", (task_id,))

    def delete_by_workspace(self, workspace_id: int) -> None:
        rows = self.db.execute(
            "SELECT id FROM scan_tasks WHERE workspace_id = ?", (workspace_id,), fetchall=True
        ) or []
        task_ids = tuple(int(r["id"]) for r in rows)
        self._delete_children(task_ids)
        self.db.execute("DELETE FROM scan_tasks WHERE workspace_id = ?", (workspace_id,))

    def delete_all(self) -> int:
        """删除全部任务及其全部子表行（全量清理入口）。"""
        rows = self.db.execute("SELECT id FROM scan_tasks", fetchall=True) or []
        task_ids = tuple(int(r["id"]) for r in rows)
        self._delete_children(task_ids)
        self.db.execute("DELETE FROM scan_tasks", ())
        return len(task_ids)

    def purge_orphans(self) -> int:
        """清理孤儿子表行：task_id 在 scan_tasks 里已无对应任务的历史残留。

        注意不能整表清（本轮提交后 scan_runs / scan_task_events 即有新行），
        必须以「task_id 不在现存 scan_tasks」为判据。
        """
        removed = 0
        for table in self.TASK_CHILD_TABLES:
            try:
                cur = self.db.execute(
                    f"DELETE FROM {table} WHERE task_id IS NOT NULL AND task_id NOT IN "
                    "(SELECT id FROM scan_tasks)",
                    return_rowcount=True,
                )
                removed += int(cur or 0)
            except Exception as _e:
                logger.warning("[TaskRepository.purge_orphans] 清理 %s 失败（跳过）：%s", table, _e)
        return removed

    @staticmethod
    def _row_to_task(row) -> ScanTask:
        return ScanTask(
            id=row["id"],
            workspace_id=row["workspace_id"],
            name=row["name"],
            status=TaskStatus(row["status"]),
            phase=row["phase"],
            output_dir=row["output_dir"],
            options=Database.loads(row["options_json"]),
            summary=Database.loads(row["summary_json"]),
            error_message=row["error_message"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )


class TaskEventRepository:
    def __init__(self, db: Database):
        self.db = db

    def add(self, event: TaskEvent) -> TaskEvent:
        self.db.execute(
            "INSERT INTO scan_task_events (task_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
            (event.task_id, event.event_type, self.db.dumps(event.payload), event.created_at),
        )
        row = self.db.execute("SELECT * FROM scan_task_events ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._row_to_event(row)

    def list(self, task_id: int) -> List[TaskEvent]:
        rows = self.db.execute(
            "SELECT * FROM scan_task_events WHERE task_id = ? ORDER BY id ASC",
            (task_id,),
            fetchall=True,
        ) or []
        return [self._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_event(row) -> TaskEvent:
        return TaskEvent(
            id=row["id"],
            task_id=row["task_id"],
            event_type=row["event_type"],
            payload=Database.loads(row["payload_json"]),
            created_at=row["created_at"],
        )


def _normalize_file_path(raw_file: str, project_root: str) -> str:
    """mapper findings 路径归一。

    收尾写入层落库时，file_path 列存在三种形态混杂：绝对路径（D:\\...\\src\\...）、
    相对路径（src\\...）、以及其他（已相对）。为统一口径、消除「同一文件绝对/相对两种
    写法被当成两条不同定位」的小瑕疵，把绝对路径按 workspace 的 target_path 归一成
    相对路径；相对路径与非匹配绝对路径原样保留。注意：仅作用于落库的 file_path 列，
    enriched 原 dict（含 raw_json / vhash 计算输入）保持不动。
    """
    if not raw_file or not project_root:
        return raw_file or ""
    raw = raw_file.replace("\\", "/")
    root = project_root.replace("\\", "/").rstrip("/")
    if not root:
        return raw
    if raw == root:
        return ""
    if raw.startswith(root + "/"):
        return raw[len(root) + 1:]
    return raw


class FindingRepository:
    def __init__(self, db: Database):
        self.db = db

    def replace_for_task(self, task_id: int, workspace_id: int, findings: List[Dict[str, Any]]) -> None:
        # 路径归一：一次性取出本 workspace 的 target_path 作项目根，避免循环内反复查库。
        _project_root = ""
        try:
            _ws = self.db.execute(
                "SELECT target_path FROM workspaces WHERE id = ?", (workspace_id,), fetchone=True
            )
            if _ws:
                _project_root = _ws.get("target_path") or ""
        except Exception as _we:
            logger.warning("[FindingRepository] 取 workspace target_path 失败，file_path 不归一：%s", _we)
            _project_root = ""
        self.db.execute("DELETE FROM findings WHERE task_id = ?", (task_id,))
        now = datetime.utcnow().isoformat()
        _dropped = 0
        for item in findings:
            enriched = enrich_finding_hash(dict(item or {}))
            _raw_family = enriched.get("family") or enriched.get("display_family") or enriched.get("type") or enriched.get("category") or ""
            enriched["flow_type"] = derive_flow_type(_raw_family)
            title = enriched.get("attack_chain_summary") or enriched.get("display_title") or enriched.get("description", enriched.get("type", "Unknown"))
            vuln_hash = str(enriched.get("vulnerability_hash_v2") or "")
            components = enriched.get("hash_components") or {}
            # P2-2：source 过归一 choke point（原文保留在 raw_json）
            source = _norm_source(enriched.get("source") or enriched.get("agent") or enriched.get("display_family") or "")
            # 历史实现不含该列，A1 证据只能靠 trigger_spec_registry 在注册期用「全局 vhash」
            # UPDATE 滞后写入 —— 而登记发生时本任务行尚未落库（findings 由本方法收尾统一重写），
            # 该 UPDATE 只能命中「上一轮已完成任务」的同 vhash 行，于是表现为：每个 task 的
            # a1_evidence 实为下一轮 A1 产物、最新一轮恒为 {}。
            # 这里显式写入，彻底消除跨任务滞后与污染。
            _a1_ev = enriched.get("a1_evidence")
            if isinstance(_a1_ev, str):
                # 兼容从 DB 回读的 JSON 字符串，避免二次编码
                try:
                    Database.loads(_a1_ev)
                    a1_evidence_json = _a1_ev
                except Exception:
                    a1_evidence_json = self.db.dumps({})
            else:
                a1_evidence_json = self.db.dumps(_a1_ev or {})
            # 逐行容错：单条 finding 写入失败（FK/约束/类型异常）只记警告并跳过该条，
            # 绝不中断整轮事务——否则 DELETE 已执行而 INSERT 中断会导致本任务全部 findings 静默丢失。
            # display_title 形如 "SCA: <component> <advisory>"，不应塞进 finding_type（否则 by_type
            # 聚合把同一族 SCA 拆成几百种取值）。组件/编号拆到独立列，finding_type 仅留族名 "sca"。
            _sca = enriched.get("sca") or {}
            _is_sca = source == "sca" or enriched.get("display_family") == "sca" or bool(_sca)
            if _is_sca:
                _sca_comp = str(_sca.get("component_name") or "").strip()
                _sca_adv = str(_sca.get("vulnerability_id") or "").strip()
                _finding_type = "sca"
            else:
                _sca_comp = ""
                _sca_adv = ""
                _finding_type = normalize_type(enriched.get("display_title") or enriched.get("type", "Unknown"))
                # 归一落库，而上游 A2 自由文本会把 CRLF 判成「命令注入」、URLRedirect 判成 ssrf、
                # URLWhiteList 判成 path_traversal——错概念原样落库，只能靠确定性的 4 元组证据
                # 兜底容忍族名漂移（「路由对、族不对」）。这里按同样的**确定性证据**
                # （路由 / 源文件名 / sink API）纠正，与 trigger_spec_registry 的 spec 侧纠族同源。
                # 安全边界：①位于 vuln_hash 之后（hash 已随参算好）→ 不会打断 spec↔finding 哈希绑定；
                # ②沿用规则表的「可覆盖族集合」与 file_dedicated 授权 → 不会越权改窄正确族名。
                _corr = correct_family_by_evidence(
                    _finding_type,
                    route=str(enriched.get("route") or (enriched.get("entry") or {}).get("route") or ""),
                    file=str(enriched.get("file") or ""),
                    sink=str(enriched.get("sink") or ""),
                    allow_file_without_route=True,
                )
                if _corr.get("corrected") == "1":
                    logger.info("[FindingType] 证据纠族 %s -> %s（rule=%s, evidence=%s, file=%s）",
                                _finding_type, _corr["family"], _corr.get("rule"),
                                _corr.get("evidence"), enriched.get("file"))
                    _finding_type = _corr["family"]
            # mapper 路径归一：file_path 列统一为相对项目根的路径（不影响 vhash / raw_json）。
            _file_path = _normalize_file_path(enriched.get("file", ""), _project_root)
            try:
                self.db.execute(
                    """
                    INSERT INTO findings
                    (task_id, workspace_id, finding_type, severity, file_path, line, title, raw_json, vulnerability_hash_v2, hash_components_json, source, created_at, a1_evidence, sca_component, sca_advisory_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        workspace_id,
                        _finding_type,
                        normalize_severity(enriched.get("severity", "UNKNOWN")),
                        _file_path,
                        int(enriched.get("line") or 0),
                        title,
                        self.db.dumps(enriched),
                        vuln_hash,
                        self.db.dumps(components),
                        source,
                        now,
                        a1_evidence_json,
                        _sca_comp,
                        _sca_adv,
                    ),
                )
                if vuln_hash:
                    self._upsert_vulnerability_instance(workspace_id, task_id, enriched, now)
            except Exception as _fe:
                _dropped += 1
                logger.warning(
                    "[FindingRepository] findings 逐行写入跳过 task=%s vhash=%s type=%s：%s",
                    task_id, vuln_hash, enriched.get("display_title") or enriched.get("type"), _fe,
                )
        if _dropped:
            logger.error("[FindingRepository] task=%s 共 %d 条 finding 因写入异常被跳过（其余已落库）", task_id, _dropped)
        # 这一层的缺口如果只靠「findings 表里查不到」发现，就会误判成「规则没生效」。
        try:
            from src.core.stage_funnel import record, family_hist
            record(task_id, "findings.persist",
                   in_count=len(findings or []),
                   out_count=max(0, len(findings or []) - _dropped),
                   reasons={"insert_failed": _dropped},
                   families=family_hist(findings or [], family_of=lambda f: f.get("type")))
        except Exception:
            pass
        # 数据卫生：清掉「无对应 finding 行」的孤儿 trigger_spec。
        # 杠杆一（孤儿清理改全局）：旧实现按「同 task」匹配（f.task_id = ts.task_id）判断孤儿，
        # 会把「finding 仅存在于更早 task」的本 task 合法 spec 误删。
        # 正确口径见 trigger_spec_registry.reconcile_orphan_specs：只要该 vulnerability_hash_v2 在 findings
        # 表**任何 task** 存在，spec 就非孤儿（漏洞真实、重放目标有效，不得剪掉 D1 待重放的 spec）；
        # 仅当全局都查无此 hash 的 finding 时才视为真孤儿（A2 假说未被持久化为 finding）予以清理。
        # reconcile_orphan_specs 已按「杠杆一 vhash 一致性」后两端一致的 vhash 做全局匹配。
        try:
            from src.iast.trigger_spec_registry import reconcile_orphan_specs
            reconcile_orphan_specs(task_id)
        except Exception as _e:
            logger.warning("[FindingRepository] reconcile_orphan_specs 失败（跳过）：%s", _e)

        # #1/#7 spec↔finding 绑定：findings 已落库且孤儿 spec 已清，按 vulnerability_hash_v2 全局关联，
        # 回写 spec.finding_id 并用品干净字段覆盖 finding.trigger_spec_detail.endpoint（解 A2 pre-resolve
        # 写入的 Windows 源码路径）。延迟导入避免循环依赖。
        try:
            from src.iast.trigger_spec_registry import bind_specs_to_findings
            bind_specs_to_findings(task_id)
        except Exception as _e:
            logger.warning("[FindingRepository] bind_specs_to_findings 失败（跳过）：%s", _e)

        # #2B 孤儿 spec 清理后，重新聚合本 task 的 D1 重放指标，使 pipeline summary 与 DB 实际
        # spec 数一致（否则会出现「D1 显示重放 8 条、但清理后 DB 仅 7 条」的口径错乱）。
        try:
            self._reaggregate_d1_summary(task_id)
        except Exception as _e:
            logger.warning("[FindingRepository] 重新聚合 D1 summary 失败（跳过）：%s", _e)

        # 快照计数统一真相源：孤儿 spec 清理后，以 trigger_specs 实表行数为唯一真相，
        # 回填所有展示用计数快照（attack_plan.plan_count / a2_poc.registered_trigger_specs /
        # d1.candidate_count），消除与 DB 实表长期不一致（70/55/38 vs 21）。
        try:
            self._reconcile_spec_count_snapshots(task_id)
        except Exception as _e:
            logger.warning("[FindingRepository] #396 快照计数统一失败（跳过）：%s", _e)

    def _reconcile_spec_count_snapshots(self, task_id: int) -> None:
        """快照计数统一真相源。

        以 trigger_specs 表实际行数为唯一真相，回填所有展示用计数快照，消除
        attack_plan.plan_count / a2_poc.registered_trigger_specs / d1.candidate_count
        与 DB 实表长期不一致（孤儿 spec 清理后快照未同步所致）。
        孤儿清理后调用，保证 pipeline / results / stage_results 三处投影一致。
        """
        try:
            row = self.db.execute(
                "SELECT summary_json FROM scan_tasks WHERE id = ?", (task_id,), fetchone=True
            )
            if not row:
                return
            summary = Database.loads(row["summary_json"]) or {}
            # 不再各自以 trigger_specs 行数自存快照。那类「事后对账补丁」由此收敛为
            # 「黑板派生 + 一致性自检」，黑板未同步时回退实表行数（保证老任务不受影响）。
            truth = None
            try:
                from src.core import blackboard as _bb
                _run_id = _bb.resolve_run_id(self.db, task_id)
                if _run_id:
                    _counts = _bb.derive_counts(self.db, task_id, _run_id)
                    if int(_counts.get("blackboard_rows") or 0) > 0:
                        truth = int(_counts.get("confirmed") or 0)
            except Exception as _bb_e:
                logger.warning("[FindingRepository] 黑板派生计数失败，回退实表行数：%s", _bb_e)
            if truth is None:
                truth = int((self.db.execute(
                    "SELECT count(*) c FROM trigger_specs WHERE task_id = ?", (task_id,), fetchone=True
                ) or {"c": 0})["c"])
            cur_hashes = {
                str(r["vulnerability_hash_v2"])
                for r in (self.db.execute(
                    "SELECT vulnerability_hash_v2 FROM trigger_specs WHERE task_id = ?",
                    (task_id,), fetchall=True,
                ) or [])
                if r.get("vulnerability_hash_v2")
            }

            # 1) attack_plan：优先以当前 DB 重新投影（entries 与 plan_count 天然一致）；
            #    失败则退化为只修正 plan_count 并截断 entries 到真相数量（最佳努力）。
            #    同时修正 stale message（如「攻击计划已生成 70 条」→ 21 条）并同步 metrics 子键，
            #    覆盖前端两种读取路径（top-level 与 ap.metrics）。
            ap_data = None
            try:
                from src.application.attack_plan_service import AttackPlanService
                # #point-2 修复：重投影必须带 enrich_runtime=True，否则 AP runtime_status 被清空，
                # 前端「运行时命中」徽章全空（muted）。D2 裁决与 canary 事件均由此回填。
                ap_data = AttackPlanService(self.db).build(task_id=task_id, enrich_runtime=True)
            except Exception as _ap_e:
                logger.warning("[FindingRepository] 重投影 attack_plan 失败，退化为只修正 plan_count：%s", _ap_e)
            for bucket in (summary.get("results", {}), summary.get("stage_results", {}), summary.get("pipeline", {})):
                apb = bucket.get("attack_plan") if isinstance(bucket, dict) else None
                if not isinstance(apb, dict):
                    continue
                if ap_data is not None:
                    apb["plan_count"] = ap_data["plan_count"]
                    apb["entries"] = ap_data["entries"]
                    apb["by_family"] = ap_data["by_family"]
                    _pc = ap_data["plan_count"]
                else:
                    apb["plan_count"] = truth
                    if isinstance(apb.get("entries"), list) and len(apb["entries"]) > truth:
                        apb["entries"] = apb["entries"][:truth]
                    _pc = truth
                _runtime = bool(apb.get("runtime_enriched"))
                apb["message"] = "攻击计划已生成 {} 条".format(_pc) + ("（含运行时命中回填）" if _runtime else "")
                if isinstance(apb.get("metrics"), dict):
                    apb["metrics"]["plan_count"] = _pc
                    apb["metrics"]["entries"] = apb["entries"]
                    apb["metrics"]["by_family"] = apb["by_family"]

            # 2) a2_poc.registered_trigger_specs = 真相
            for bucket in (summary.get("results", {}), summary.get("stage_results", {})):
                a2 = bucket.get("a2_poc") if isinstance(bucket, dict) else None
                if isinstance(a2, dict):
                    a2["registered_trigger_specs"] = truth

            # 3) d1.candidate_count = 真相，并过滤 replayed_specs_detail 到当前仍存在的 spec
            #    读的是 summary.results[stage][metric]，那是计数唯一的消费路径。
            #    pipeline.d1 顶层那份没有任何读取方，且与 pipeline.d1.metrics 口径分裂
            #    故此处不再写顶层，并顺手清掉历史脏值。
            _res_d1 = (summary.get("results") or {}).get("d1")
            if isinstance(_res_d1, dict):
                _res_d1["candidate_count"] = truth
            _pip_d1 = (summary.get("pipeline") or {}).get("d1")
            if isinstance(_pip_d1, dict):
                _pip_d1.pop("candidate_count", None)
                _pip_d1.pop("replayed_count", None)
            for d1 in (_res_d1, _pip_d1):
                if not isinstance(d1, dict):
                    continue
                detail = d1.get("replayed_specs_detail")
                if isinstance(detail, list) and cur_hashes:
                    d1["replayed_specs_detail"] = [
                        d for d in detail
                        if str(d.get("vulnerability_hash_v2") or "") in cur_hashes
                    ]

            self.db.execute(
                "UPDATE scan_tasks SET summary_json = ? WHERE id = ?",
                (Database.dumps(summary), task_id),
            )
            logger.info("[FindingRepository] #396 快照计数已统一为真相源 %d（task_id=%s）", truth, task_id)
        except Exception as _e:
            logger.warning("[FindingRepository] _reconcile_spec_count_snapshots 失败（跳过）：%s", _e)

    def _reaggregate_d1_summary(self, task_id: int) -> None:
        """按本 task 当前 trigger_specs 实际数量，收敛 pipeline.d1.metrics 的重放计数快照。

        pipeline.d1 顶层不再持有 candidate_count / replayed_count。
        """
        try:
            row = self.db.execute(
                "SELECT summary_json FROM scan_tasks WHERE id = ?", (task_id,), fetchone=True
            )
            if not row:
                return
            summary = Database.loads(row["summary_json"]) or {}
            pipeline = summary.get("pipeline") or {}
            d1 = pipeline.get("d1") or {}
            metrics = d1.get("metrics") if isinstance(d1.get("metrics"), dict) else {}
            spec_count = self.db.execute(
                "SELECT count(*) c FROM trigger_specs WHERE task_id = ?", (task_id,), fetchone=True
            )
            spec_count = int(spec_count["c"]) if spec_count else 0
            replayed = metrics.get("candidate_count") or 0
            # candidate_count 不应超过实际 spec 数（清理后收敛）；取两者较小者，并修正文案。
            new_candidate = min(replayed, spec_count) if replayed else spec_count
            metrics["candidate_count"] = new_candidate
            metrics["replayed_count"] = new_candidate
            d1["metrics"] = metrics
            d1.pop("candidate_count", None)
            d1.pop("replayed_count", None)
            d1_message = d1.get("message", "")
            if d1_message:
                _impacts = metrics.get("finding_count") or 0
                _arrivals = metrics.get("iast_arrivals") or 0
                d1["message"] = (
                    f"D1 统一重放（已并入 verify 链路）：驱动重放 {new_candidate} 条 TriggerSpec，"
                    f"{_impacts} 条 DAST impact，{_arrivals} 条 IAST arrival"
                )
            pipeline["d1"] = d1
            summary["pipeline"] = pipeline
            self.db.execute(
                "UPDATE scan_tasks SET summary_json = ? WHERE id = ?",
                (Database.dumps(summary), task_id),
            )
        except Exception as _e:
            logger.warning("[FindingRepository] _reaggregate_d1_summary 失败（跳过）：%s", _e)

    def list(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> List[FindingRecord]:
        """读 findings。

        findings 与报告里了，删数据是不可逆的；而抑制的语义是「这条不该算数」，
        读取时不算数就足够了，且对历史数据同样生效（零迁移、零删除）。
        实现上先取该 task 下被抑制 spec 的 finding_id 集合（一次小查询），
        再用 NOT IN 过滤，避免每次都跑相关子查询。
        """
        sql = "SELECT * FROM findings"
        params: List[Any] = []
        clauses: List[str] = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        sup = self._suppressed_finding_ids(task_id) if task_id is not None else []
        if sup:
            clauses.append("id NOT IN (%s)" % ",".join("?" for _ in sup))
            params.extend(sup)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        if task_id is not None:
            sql += " ORDER BY id ASC"
        else:
            sql += " ORDER BY task_id DESC, id ASC"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row_to_finding(row) for row in rows]

    def _suppressed_finding_ids(self, task_id: int) -> List[int]:
        """该任务下被 safe_verdict 抑制的 spec 所绑定的 finding_id 集合（读侧过滤用）。"""
        try:
            rows = self.db.execute(
                "SELECT finding_id FROM trigger_specs "
                "WHERE task_id = ? AND COALESCE(suppressed_by_safe_verdict, 0) = 1 "
                "AND finding_id IS NOT NULL AND finding_id > 0",
                (task_id,), fetchall=True,
            ) or []
            return sorted({int(r["finding_id"]) for r in rows if r.get("finding_id")})
        except Exception as _e:
            # 过滤失败时返回空 = 不过滤（保持既有行为，不因读侧补丁挡住主流程）
            logger.warning("[FindingRepository] 读取 suppressed finding 失败（不过滤）：%s", _e)
            return []

    def get(self, finding_id: int) -> Optional[FindingRecord]:
        row = self.db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,), fetchone=True)
        return self._row_to_finding(row) if row else None

    def list_by_hash(self, workspace_id: int, vulnerability_hash_v2: str) -> List[FindingRecord]:
        rows = self.db.execute(
            "SELECT * FROM findings WHERE workspace_id = ? AND vulnerability_hash_v2 = ? ORDER BY id DESC",
            (workspace_id, vulnerability_hash_v2),
            fetchall=True,
        ) or []
        return [self._row_to_finding(row) for row in rows]

    def update_raw(self, finding_id: int, raw: Dict[str, Any]) -> Optional[FindingRecord]:
        current = self.get(finding_id)
        if current is None:
            return None
        title = raw.get("attack_chain_summary") or raw.get("display_title") or raw.get("description") or current.title
        raw = enrich_finding_hash(raw)
        vuln_hash = str(raw.get("vulnerability_hash_v2") or "")
        # finding_type 统一 "sca"，组件/编号拆到独立列；其余走 normalize_type（与写路径口径一致）。
        _sca = raw.get("sca") or {}
        _is_sca = (raw.get("source") == "sca") or (raw.get("display_family") == "sca") or bool(_sca)
        if _is_sca:
            _sca_comp = str(_sca.get("component_name") or current.sca_component or "").strip()
            _sca_adv = str(_sca.get("vulnerability_id") or current.sca_advisory_id or "").strip()
            _finding_type = "sca"
        else:
            _sca_comp = current.sca_component or ""
            _sca_adv = current.sca_advisory_id or ""
            _finding_type = normalize_type(raw.get("display_title") or raw.get("type") or current.finding_type)
        self.db.execute(
            """
            UPDATE findings
            SET finding_type = ?, severity = ?, file_path = ?, line = ?, title = ?, raw_json = ?, vulnerability_hash_v2 = ?, hash_components_json = ?, source = ?, sca_component = ?, sca_advisory_id = ?
            WHERE id = ?
            """,
            (
                _finding_type,
                raw.get("severity") or current.severity,
                raw.get("file") or current.file_path,
                int(raw.get("line") or current.line or 0),
                title,
                self.db.dumps(raw),
                vuln_hash,
                self.db.dumps(raw.get("hash_components") or {}),
                # P2-2：source 过归一 choke point
                _norm_source(raw.get("source") or current.finding_type),
                _sca_comp,
                _sca_adv,
                finding_id,
            ),
        )
        if vuln_hash:
            self._upsert_vulnerability_instance(current.workspace_id, current.task_id, raw, datetime.utcnow().isoformat())
        return self.get(finding_id)

    def _upsert_vulnerability_instance(self, workspace_id: int, task_id: int, item: Dict[str, Any], now: str) -> None:
        vuln_hash = str(item.get("vulnerability_hash_v2") or "")
        # 落库规范化（簇五硬规范）：vulnerability_instances.family 一律存规范 token。
        # canonical_business_logic_family 对已是规范 token 的输入幂等，对别名/大小写形态归一。
        _raw_family = (item.get("hash_components") or {}).get("family") or item.get("display_family") or item.get("type") or "unknown"
        family = canonical_business_logic_family(_raw_family) or _raw_family
        severity = str(item.get("severity") or "UNKNOWN")
        title = str(item.get("attack_chain_summary") or item.get("display_title") or item.get("description") or family)[:500]
        # P2-2：source 过归一 choke point
        source = _norm_source(item.get("source") or item.get("agent") or family)[:120]
        existing = self.db.execute(
            "SELECT id, created_at FROM vulnerability_instances WHERE workspace_id = ? AND vulnerability_hash_v2 = ?",
            (workspace_id, vuln_hash),
            fetchone=True,
        )
        if existing:
            self.db.execute(
                """
                UPDATE vulnerability_instances
                SET family = ?, severity = ?, title = ?, source = ?, last_seen_task_id = ?, updated_at = ?
                WHERE id = ?
                """,
                (family, severity, title, source, task_id, now, existing["id"]),
            )
            return
        self.db.execute(
            """
            INSERT INTO vulnerability_instances
            (workspace_id, vulnerability_hash_v2, family, severity, title, status, source, first_seen_task_id, last_seen_task_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
            """,
            (workspace_id, vuln_hash, family, severity, title, source, task_id, task_id, now, now),
        )

    @staticmethod
    def _row_to_finding(row) -> FindingRecord:
        # 老行（迁移前）可能缺 sca_component/sca_advisory_id 列，用 .get 容错（缺列时取空串）。
        _sca_comp = row.get("sca_component") if isinstance(row, dict) else getattr(row, "sca_component", "")
        _sca_adv = row.get("sca_advisory_id") if isinstance(row, dict) else getattr(row, "sca_advisory_id", "")
        return FindingRecord(
            id=row["id"],
            task_id=row["task_id"],
            workspace_id=row["workspace_id"],
            finding_type=row["finding_type"],
            severity=row["severity"],
            file_path=row["file_path"],
            line=row["line"],
            title=row["title"],
            raw=Database.loads(row["raw_json"]),
            created_at=row["created_at"],
            sca_component=_sca_comp or "",
            sca_advisory_id=_sca_adv or "",
        )


class ReportRepository:
    def __init__(self, db: Database):
        self.db = db

    def replace_for_task(self, task_id: int, workspace_id: int, reports: List[Dict[str, str]]) -> None:
        self.db.execute("DELETE FROM reports WHERE task_id = ?", (task_id,))
        now = datetime.utcnow().isoformat()
        for report in reports:
            self.db.execute(
                "INSERT INTO reports (task_id, workspace_id, report_type, file_path, generated_at) VALUES (?, ?, ?, ?, ?)",
                (task_id, workspace_id, report["report_type"], report["file_path"], now),
            )

    def list(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> List[ReportRecord]:
        sql = "SELECT * FROM reports"
        params: List[Any] = []
        clauses: List[str] = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row_to_report(row) for row in rows]

    @staticmethod
    def _row_to_report(row) -> ReportRecord:
        return ReportRecord(
            id=row["id"],
            task_id=row["task_id"],
            workspace_id=row["workspace_id"],
            report_type=row["report_type"],
            file_path=row["file_path"],
            generated_at=row["generated_at"],
        )


class ModelRunRepository:
    """Persists AI model invocations (gateway ledger) for cost/latency observability."""

    def __init__(self, db: Database):
        self.db = db

    def record(
        self,
        *,
        purpose: str,
        model: str = "",
        model_profile: str = "default",
        prompt_version: str = "",
        input_summary: str = "",
        output_summary: str = "",
        status: str = "completed",
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
        latency_ms: int = 0,
        error_message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        task_id: Optional[int] = None,
        prompt_hash: str = "",
        stage: str = "",
        workspace_id: Optional[int] = None,
    ) -> int:
        now = datetime.utcnow().isoformat()
        # 环境变量（benchmark_cli.run_benchmark 在子进程启动时写入）。之所以用环境变量而非
        # 逐层透传，是因为 LLM 调用分散在多个线程/agent，逐层传参改动面太大且易漏。
        if task_id is None:
            import os
            env_tid = (os.environ.get("SAST_AI_CURRENT_TASK_ID") or "").strip()
            task_id = int(env_tid) if env_tid.isdigit() else None
        # 按 task_id → scan_tasks.workspace_id 解析，使未来行自动带上工作区（无需逐层透传）。
        # 历史 task_id 为 NULL 的调用仍无法归因，保持 NULL（不伪造）。
        if workspace_id is None and task_id is not None:
            try:
                ws_row = self.db.execute(
                    "SELECT workspace_id FROM scan_tasks WHERE id = ?", (int(task_id),), fetchone=True
                )
                if ws_row:
                    workspace_id = ws_row.get("workspace_id")
            except Exception:
                pass
        self.db.execute(
            """
            INSERT INTO model_runs
            (purpose, model_profile, model, prompt_version, input_summary, output_summary, status,
             input_tokens, output_tokens, cost_usd, latency_ms, error_message, metadata_json,
             task_id, prompt_hash, stage, workspace_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (purpose, model_profile, model, prompt_version, input_summary, output_summary, status,
             int(input_tokens), int(output_tokens), float(cost_usd), int(latency_ms), error_message,
             self.db.dumps(metadata or {}), task_id, prompt_hash or "", (stage or purpose or ""),
             workspace_id, now),
        )
        row = self.db.execute("SELECT id FROM model_runs ORDER BY id DESC LIMIT 1", fetchone=True)
        return int(row["id"])

    def list(self, purpose: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        if purpose:
            rows = self.db.execute(
                "SELECT * FROM model_runs WHERE purpose = ? ORDER BY id DESC LIMIT ?",
                (purpose, int(limit)),
                fetchall=True,
            ) or []
        else:
            rows = self.db.execute("SELECT * FROM model_runs ORDER BY id DESC LIMIT ?", (int(limit),), fetchall=True) or []
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "purpose": row["purpose"],
            "model_profile": row["model_profile"],
            "model": row["model"],
            "prompt_version": row["prompt_version"],
            "input_summary": row["input_summary"],
            "output_summary": row["output_summary"],
            "status": row["status"],
            "input_tokens": row["input_tokens"],
            "output_tokens": row["output_tokens"],
            "cost_usd": row["cost_usd"],
            "latency_ms": row["latency_ms"],
            "error_message": row["error_message"],
            "metadata": Database.loads(row["metadata_json"]),
            "created_at": row["created_at"],
        }


class ReviewRepository:
    """Persists AI reviews and human decisions into dedicated tables (not just raw_json)."""

    def __init__(self, db: Database):
        self.db = db

    def add_ai_review(
        self,
        *,
        finding_id: int,
        vulnerability_hash_v2: str,
        verdict: str,
        confidence: str,
        model: str = "",
        prompt_version: str = "",
        model_run_id: Optional[int] = None,
        criteria: Optional[Dict[str, Any]] = None,
        missing_evidence: Optional[List[Any]] = None,
    ) -> int:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO ai_reviews
            (finding_id, vulnerability_hash_v2, model_run_id, model, prompt_version, verdict, confidence,
             criteria_json, missing_evidence_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (finding_id, vulnerability_hash_v2, model_run_id, model, prompt_version, verdict, confidence,
             self.db.dumps(criteria or {}), self.db.dumps(missing_evidence or []), now),
        )
        row = self.db.execute("SELECT id FROM ai_reviews ORDER BY id DESC LIMIT 1", fetchone=True)
        return int(row["id"])

    def add_human_review(
        self,
        *,
        finding_id: int,
        vulnerability_hash_v2: str,
        decision: str,
        reviewer: str = "local",
        reason_type: str = "",
        reason_detail: str = "",
        adopted_ai_judgement: bool = False,
    ) -> int:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO human_reviews
            (finding_id, vulnerability_hash_v2, reviewer, decision, reason_type, reason_detail, adopted_ai_judgement, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (finding_id, vulnerability_hash_v2, reviewer, decision, reason_type, reason_detail,
             1 if adopted_ai_judgement else 0, now),
        )
        row = self.db.execute("SELECT id FROM human_reviews ORDER BY id DESC LIMIT 1", fetchone=True)
        return int(row["id"])

    def ai_reviews_for_hash(self, vulnerability_hash_v2: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM ai_reviews WHERE vulnerability_hash_v2 = ? ORDER BY id DESC",
            (vulnerability_hash_v2,),
            fetchall=True,
        ) or []
        return [self._ai_row(row) for row in rows]

    def human_reviews_for_hash(self, vulnerability_hash_v2: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM human_reviews WHERE vulnerability_hash_v2 = ? ORDER BY id DESC",
            (vulnerability_hash_v2,),
            fetchall=True,
        ) or []
        return [self._human_row(row) for row in rows]

    def metrics(self) -> Dict[str, Any]:
        ai_rows = self.db.execute("SELECT verdict FROM ai_reviews", fetchall=True) or []
        human_rows = self.db.execute("SELECT decision, adopted_ai_judgement FROM human_reviews", fetchall=True) or []
        ai_total = len(ai_rows)
        ai_false = sum(1 for row in ai_rows if row["verdict"] == "false_positive")
        ai_true = sum(1 for row in ai_rows if row["verdict"] == "true_positive")
        human_total = len(human_rows)
        adopted = sum(1 for row in human_rows if row["adopted_ai_judgement"])
        return {
            "ai_review_total": ai_total,
            "ai_false_positive": ai_false,
            "ai_true_positive": ai_true,
            "human_review_total": human_total,
            "adopted_ai_judgement": adopted,
            "adoption_rate": round(adopted / human_total, 4) if human_total else 0.0,
        }

    @staticmethod
    def _ai_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "finding_id": row["finding_id"],
            "vulnerability_hash_v2": row["vulnerability_hash_v2"],
            "model_run_id": row["model_run_id"],
            "model": row["model"],
            "prompt_version": row["prompt_version"],
            "verdict": row["verdict"],
            "confidence": row["confidence"],
            "criteria": Database.loads(row["criteria_json"]),
            "missing_evidence": Database.loads(row["missing_evidence_json"]),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _human_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "finding_id": row["finding_id"],
            "vulnerability_hash_v2": row["vulnerability_hash_v2"],
            "reviewer": row["reviewer"],
            "decision": row["decision"],
            "reason_type": row["reason_type"],
            "reason_detail": row["reason_detail"],
            "adopted_ai_judgement": bool(row["adopted_ai_judgement"]),
            "created_at": row["created_at"],
        }


class VulnerabilityInstanceRepository:
    """Reads and drives lifecycle status for vulnerability instances."""

    def __init__(self, db: Database):
        self.db = db

    def get_by_hash(self, workspace_id: int, vulnerability_hash_v2: str) -> Optional[Dict[str, Any]]:
        row = self.db.execute(
            "SELECT * FROM vulnerability_instances WHERE workspace_id = ? AND vulnerability_hash_v2 = ?",
            (workspace_id, vulnerability_hash_v2),
            fetchone=True,
        )
        return self._row(row) if row else None

    def list(self, workspace_id: Optional[int] = None, status: str = "") -> List[Dict[str, Any]]:
        sql = "SELECT * FROM vulnerability_instances"
        clauses, params = [], []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC, id DESC LIMIT 1000"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row(row) for row in rows]

    def set_status(self, workspace_id: int, vulnerability_hash_v2: str, status: str) -> Optional[Dict[str, Any]]:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            "UPDATE vulnerability_instances SET status = ?, updated_at = ? WHERE workspace_id = ? AND vulnerability_hash_v2 = ?",
            (status, now, workspace_id, vulnerability_hash_v2),
        )
        return self.get_by_hash(workspace_id, vulnerability_hash_v2)

    def inherit(
        self,
        workspace_id: int,
        vulnerability_hash_v2: str,
        *,
        status: str,
        review_conclusion: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Carry a prior instance's status/review conclusion onto a new hash."""
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            UPDATE vulnerability_instances
            SET status = ?, review_conclusion = ?, updated_at = ?
            WHERE workspace_id = ? AND vulnerability_hash_v2 = ?
            """,
            (status, review_conclusion, now, workspace_id, vulnerability_hash_v2),
        )
        return self.get_by_hash(workspace_id, vulnerability_hash_v2)

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        keys = row.keys() if hasattr(row, "keys") else []
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "vulnerability_hash_v2": row["vulnerability_hash_v2"],
            "hash_version": row["hash_version"],
            "family": row["family"],
            "severity": row["severity"],
            "title": row["title"],
            "status": row["status"],
            "review_conclusion": row["review_conclusion"] if "review_conclusion" in keys else "",
            "source": row["source"],
            "first_seen_task_id": row["first_seen_task_id"],
            "last_seen_task_id": row["last_seen_task_id"],
            "owner": row["owner"],
            "sla_due_at": row["sla_due_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


class HashMigrationRepository:
    """Records fuzzy hash migrations (old_hash -> new_hash) for identity continuity."""

    def __init__(self, db: Database):
        self.db = db

    def record(
        self,
        *,
        old_hash: str,
        new_hash: str,
        similarity: float,
        reason: str = "",
        workspace_id: int = 0,
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT OR IGNORE INTO hash_migrations
            (workspace_id, old_hash, new_hash, similarity, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, old_hash, new_hash, round(float(similarity), 4), reason, now),
        )
        row = self.db.execute(
            "SELECT * FROM hash_migrations WHERE workspace_id = ? AND old_hash = ? AND new_hash = ?",
            (workspace_id, old_hash, new_hash),
            fetchone=True,
        )
        return self._row(row)

    def get_by_new_hash(self, new_hash: str, workspace_id: int = 0) -> Optional[Dict[str, Any]]:
        row = self.db.execute(
            "SELECT * FROM hash_migrations WHERE workspace_id = ? AND new_hash = ? ORDER BY similarity DESC, id DESC",
            (workspace_id, new_hash),
            fetchone=True,
        )
        return self._row(row) if row else None

    def list(self, workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM hash_migrations"
        params: List[Any] = []
        if workspace_id is not None:
            sql += " WHERE workspace_id = ?"
            params.append(workspace_id)
        sql += " ORDER BY id DESC LIMIT 1000"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "old_hash": row["old_hash"],
            "new_hash": row["new_hash"],
            "similarity": row["similarity"],
            "reason": row["reason"],
            "created_at": row["created_at"],
        }


class RetestRepository:
    """Persists retest runs against a vulnerability instance."""

    def __init__(self, db: Database):
        self.db = db

    def add(
        self,
        *,
        workspace_id: Optional[int],
        vulnerability_hash_v2: str,
        finding_id: Optional[int],
        strategy: str,
        result: str,
        previous_status: str,
        new_status: str,
        detail: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        created_by: str = "local",
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO retest_runs
            (workspace_id, vulnerability_hash_v2, finding_id, strategy, result, previous_status, new_status, detail, evidence_json, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, vulnerability_hash_v2, finding_id, strategy, result, previous_status, new_status,
             detail, self.db.dumps(evidence or {}), created_by, now),
        )
        row = self.db.execute("SELECT * FROM retest_runs ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._row(row)

    def list_for_hash(self, vulnerability_hash_v2: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM retest_runs WHERE vulnerability_hash_v2 = ? ORDER BY id DESC",
            (vulnerability_hash_v2,),
            fetchall=True,
        ) or []
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "vulnerability_hash_v2": row["vulnerability_hash_v2"],
            "finding_id": row["finding_id"],
            "strategy": row["strategy"],
            "result": row["result"],
            "previous_status": row["previous_status"],
            "new_status": row["new_status"],
            "detail": row["detail"],
            "evidence": Database.loads(row["evidence_json"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
        }


class AutonomyRepository:
    """Persists conditional-autonomy policies and every automatic action taken."""

    def __init__(self, db: Database):
        self.db = db

    def upsert_policy(self, **fields: Any) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        name = str(fields["name"])
        existing = self.db.execute("SELECT id, created_at FROM autonomy_policies WHERE name = ?", (name,), fetchone=True)
        values = (
            fields.get("action", "auto_close"),
            fields.get("min_confidence", "high"),
            fields.get("verdict", "false_positive"),
            fields.get("max_impact", "medium"),
            int(fields.get("gray_percent", 0)),
            1 if fields.get("require_ai_agree", True) else 0,
            1 if fields.get("enabled", True) else 0,
            fields.get("description", ""),
        )
        if existing:
            self.db.execute(
                """
                UPDATE autonomy_policies
                SET action=?, min_confidence=?, verdict=?, max_impact=?, gray_percent=?,
                    require_ai_agree=?, enabled=?, description=?, updated_at=?
                WHERE id=?
                """,
                (*values, now, existing["id"]),
            )
        else:
            self.db.execute(
                """
                INSERT INTO autonomy_policies
                (name, action, min_confidence, verdict, max_impact, gray_percent, require_ai_agree, enabled, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (name, *values, now, now),
            )
        return self.get_policy_by_name(name)

    def list_policies(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM autonomy_policies"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id ASC"
        rows = self.db.execute(sql, (), fetchall=True) or []
        return [self._policy_row(row) for row in rows]

    def get_policy_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM autonomy_policies WHERE name = ?", (name,), fetchone=True)
        return self._policy_row(row) if row else None

    def add_action(self, **fields: Any) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO autonomy_actions
            (workspace_id, policy_id, policy_name, finding_id, vulnerability_hash_v2, action, decision,
             previous_status, new_status, gray_bucket, applied, rolled_back, reason, evidence_json, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (
                fields.get("workspace_id"),
                fields.get("policy_id"),
                fields.get("policy_name", ""),
                fields.get("finding_id"),
                fields.get("vulnerability_hash_v2", ""),
                fields.get("action", ""),
                fields.get("decision", ""),
                fields.get("previous_status", ""),
                fields.get("new_status", ""),
                int(fields.get("gray_bucket", 0)),
                1 if fields.get("applied", False) else 0,
                fields.get("reason", ""),
                self.db.dumps(fields.get("evidence") or {}),
                fields.get("created_by", "system"),
                now,
            ),
        )
        row = self.db.execute("SELECT * FROM autonomy_actions ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._action_row(row)

    def get_action(self, action_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM autonomy_actions WHERE id = ?", (action_id,), fetchone=True)
        return self._action_row(row) if row else None

    def mark_rolled_back(self, action_id: int) -> None:
        self.db.execute(
            "UPDATE autonomy_actions SET rolled_back = 1, rolled_back_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), action_id),
        )

    def list_actions(self, workspace_id: Optional[int] = None, limit: int = 200) -> List[Dict[str, Any]]:
        if workspace_id is not None:
            rows = self.db.execute(
                "SELECT * FROM autonomy_actions WHERE workspace_id = ? ORDER BY id DESC LIMIT ?",
                (workspace_id, int(limit)), fetchall=True,
            ) or []
        else:
            rows = self.db.execute("SELECT * FROM autonomy_actions ORDER BY id DESC LIMIT ?", (int(limit),), fetchall=True) or []
        return [self._action_row(row) for row in rows]

    @staticmethod
    def _policy_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "action": row["action"],
            "min_confidence": row["min_confidence"],
            "verdict": row["verdict"],
            "max_impact": row["max_impact"],
            "gray_percent": row["gray_percent"],
            "require_ai_agree": bool(row["require_ai_agree"]),
            "enabled": bool(row["enabled"]),
            "description": row["description"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _action_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "policy_id": row["policy_id"],
            "policy_name": row["policy_name"],
            "finding_id": row["finding_id"],
            "vulnerability_hash_v2": row["vulnerability_hash_v2"],
            "action": row["action"],
            "decision": row["decision"],
            "previous_status": row["previous_status"],
            "new_status": row["new_status"],
            "gray_bucket": row["gray_bucket"],
            "applied": bool(row["applied"]),
            "rolled_back": bool(row["rolled_back"]),
            "reason": row["reason"],
            "evidence": Database.loads(row["evidence_json"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "rolled_back_at": row["rolled_back_at"],
        }


class EntryAssetRepository:
    """Persists discovered attack-surface entries and rule candidates for feedback."""

    def __init__(self, db: Database):
        self.db = db

    def upsert_entry(self, workspace_id: Optional[int], task_id: Optional[int], entry: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        entry_hash = str(entry.get("entry_hash") or "")
        existing = self.db.execute(
            "SELECT id, status FROM entry_assets WHERE workspace_id IS ? AND entry_hash = ?",
            (workspace_id, entry_hash), fetchone=True,
        )
        if existing:
            self.db.execute(
                "UPDATE entry_assets SET task_id=?, confidence=?, signature=?, last_seen_at=? WHERE id=?",
                (task_id, entry.get("confidence", "medium"), entry.get("signature", ""), now, existing["id"]),
            )
            return self.get_entry(existing["id"])
        self.db.execute(
            """
            INSERT INTO entry_assets
            (workspace_id, task_id, entry_hash, entry_type, file_path, line, signature, confidence, status, source, metadata_json, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'discovered', ?, ?, ?, ?)
            """,
            (
                workspace_id, task_id, entry_hash, entry.get("entry_type", ""),
                entry.get("file", ""), int(entry.get("line") or 0), entry.get("signature", ""),
                entry.get("confidence", "medium"), entry.get("source", ""),
                self.db.dumps(entry.get("metadata") or {}), now, now,
            ),
        )
        row = self.db.execute("SELECT * FROM entry_assets ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._entry_row(row)

    def get_entry(self, entry_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM entry_assets WHERE id = ?", (entry_id,), fetchone=True)
        return self._entry_row(row) if row else None

    def list_entries(self, workspace_id: Optional[int] = None, entry_type: str = "") -> List[Dict[str, Any]]:
        sql, params, clauses = "SELECT * FROM entry_assets", [], []
        if workspace_id is not None:
            clauses.append("workspace_id = ?"); params.append(workspace_id)
        if entry_type:
            clauses.append("entry_type = ?"); params.append(entry_type)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT 2000"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._entry_row(row) for row in rows]

    def set_entry_status(self, entry_id: int, status: str) -> Optional[Dict[str, Any]]:
        self.db.execute("UPDATE entry_assets SET status = ? WHERE id = ?", (status, entry_id))
        return self.get_entry(entry_id)

    def upsert_rule_candidate(self, workspace_id: Optional[int], candidate: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        rule_hash = str(candidate.get("rule_hash") or "")
        existing = self.db.execute(
            "SELECT id, occurrences FROM entry_rule_candidates WHERE workspace_id IS ? AND rule_hash = ?",
            (workspace_id, rule_hash), fetchone=True,
        )
        if existing:
            self.db.execute(
                "UPDATE entry_rule_candidates SET occurrences = ?, updated_at = ? WHERE id = ?",
                (int(existing["occurrences"]) + 1, now, existing["id"]),
            )
            return self.get_rule_candidate(existing["id"])
        self.db.execute(
            """
            INSERT INTO entry_rule_candidates
            (workspace_id, rule_hash, entry_type, pattern, confidence, status, occurrences, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'candidate', 1, ?, ?)
            """,
            (workspace_id, rule_hash, candidate.get("entry_type", ""), candidate.get("pattern", ""),
             candidate.get("confidence", "medium"), now, now),
        )
        row = self.db.execute("SELECT * FROM entry_rule_candidates ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._rule_row(row)

    def get_rule_candidate(self, rule_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM entry_rule_candidates WHERE id = ?", (rule_id,), fetchone=True)
        return self._rule_row(row) if row else None

    def list_rule_candidates(self, workspace_id: Optional[int] = None, status: str = "") -> List[Dict[str, Any]]:
        sql, params, clauses = "SELECT * FROM entry_rule_candidates", [], []
        if workspace_id is not None:
            clauses.append("workspace_id = ?"); params.append(workspace_id)
        if status:
            clauses.append("status = ?"); params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY occurrences DESC, id DESC LIMIT 1000"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._rule_row(row) for row in rows]

    def set_rule_status(self, rule_id: int, status: str, confirmed_by: str = "") -> Optional[Dict[str, Any]]:
        self.db.execute(
            "UPDATE entry_rule_candidates SET status = ?, confirmed_by = ?, updated_at = ? WHERE id = ?",
            (status, confirmed_by, datetime.utcnow().isoformat(), rule_id),
        )
        return self.get_rule_candidate(rule_id)

    @staticmethod
    def _entry_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"], "workspace_id": row["workspace_id"], "task_id": row["task_id"],
            "entry_hash": row["entry_hash"], "entry_type": row["entry_type"], "file_path": row["file_path"],
            "line": row["line"], "signature": row["signature"], "confidence": row["confidence"],
            "status": row["status"], "source": row["source"], "metadata": Database.loads(row["metadata_json"]),
            "first_seen_at": row["first_seen_at"], "last_seen_at": row["last_seen_at"],
        }

    @staticmethod
    def _rule_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"], "workspace_id": row["workspace_id"], "rule_hash": row["rule_hash"],
            "entry_type": row["entry_type"], "pattern": row["pattern"], "confidence": row["confidence"],
            "status": row["status"], "occurrences": row["occurrences"], "confirmed_by": row["confirmed_by"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }


class TaintRuleRepository:
    """Persists taint (source/sink/sanitizer) rule candidates for the whitebox
    rule feedback closure: AI discovery -> human confirm -> regression -> merge."""

    def __init__(self, db: Database):
        self.db = db

    def upsert_candidate(self, workspace_id: Optional[int], candidate: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        rule_hash = str(candidate.get("rule_hash") or "")
        existing = self.db.execute(
            "SELECT id, occurrences FROM taint_rule_candidates WHERE workspace_id IS ? AND rule_hash = ?",
            (workspace_id, rule_hash), fetchone=True,
        )
        if existing:
            self.db.execute(
                "UPDATE taint_rule_candidates SET occurrences = ?, updated_at = ? WHERE id = ?",
                (int(existing["occurrences"]) + 1, now, existing["id"]),
            )
            return self.get_candidate(existing["id"])
        self.db.execute(
            """
            INSERT INTO taint_rule_candidates
            (workspace_id, rule_hash, kind, language, pattern, family, confidence, status, occurrences, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'candidate', 1, ?, ?)
            """,
            (workspace_id, rule_hash, candidate.get("kind", "sink"), candidate.get("language", ""),
             candidate.get("pattern", ""), candidate.get("family", ""),
             candidate.get("confidence", "medium"), now, now),
        )
        row = self.db.execute("SELECT * FROM taint_rule_candidates ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._row(row)

    def get_candidate(self, rule_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM taint_rule_candidates WHERE id = ?", (rule_id,), fetchone=True)
        return self._row(row) if row else None

    def list_candidates(self, workspace_id: Optional[int] = None, status: str = "", kind: str = "") -> List[Dict[str, Any]]:
        sql, params, clauses = "SELECT * FROM taint_rule_candidates", [], []
        if workspace_id is not None:
            clauses.append("workspace_id = ?"); params.append(workspace_id)
        if status:
            clauses.append("status = ?"); params.append(status)
        if kind:
            clauses.append("kind = ?"); params.append(kind)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY occurrences DESC, id DESC LIMIT 1000"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row(row) for row in rows]

    def set_status(
        self,
        rule_id: int,
        status: str,
        *,
        confirmed_by: str = "",
        regression_passed: Optional[bool] = None,
        regression_detail: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        now = datetime.utcnow().isoformat()
        fields = ["status = ?", "updated_at = ?"]
        params: List[Any] = [status, now]
        if confirmed_by:
            fields.append("confirmed_by = ?"); params.append(confirmed_by)
        if regression_passed is not None:
            fields.append("regression_passed = ?"); params.append(1 if regression_passed else 0)
        if regression_detail is not None:
            fields.append("regression_detail_json = ?"); params.append(self.db.dumps(regression_detail))
        params.append(rule_id)
        self.db.execute(f"UPDATE taint_rule_candidates SET {', '.join(fields)} WHERE id = ?", params)
        return self.get_candidate(rule_id)

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row["id"], "workspace_id": row["workspace_id"], "rule_hash": row["rule_hash"],
            "kind": row["kind"], "language": row["language"], "pattern": row["pattern"],
            "family": row["family"], "confidence": row["confidence"], "status": row["status"],
            "regression_passed": bool(row["regression_passed"]),
            "regression_detail": Database.loads(row["regression_detail_json"]),
            "occurrences": row["occurrences"], "confirmed_by": row["confirmed_by"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }


class EvaluationRepository:
    """Persists evaluation runs (golden-set scoring) and per-case results."""

    def __init__(self, db: Database):
        self.db = db

    def add_run(self, summary: Dict[str, Any], results: List[Dict[str, Any]]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO evaluation_runs
            (name, model, prompt_version, dataset, total, true_positive, false_positive, false_negative,
             true_negative, precision, recall, f1, accuracy, pass_at_3, pass_hat_3, scan_mode, agent_impl,
             summary_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                summary.get("name", ""), summary.get("model", ""), summary.get("prompt_version", ""),
                summary.get("dataset", ""), int(summary.get("total", 0)), int(summary.get("true_positive", 0)),
                int(summary.get("false_positive", 0)), int(summary.get("false_negative", 0)),
                int(summary.get("true_negative", 0)), float(summary.get("precision", 0.0)),
                float(summary.get("recall", 0.0)), float(summary.get("f1", 0.0)),
                float(summary.get("accuracy", 0.0)), float(summary.get("pass_at_3", 0.0)),
                float(summary.get("pass_hat_3", 0.0)), summary.get("scan_mode", ""),
                summary.get("agent_impl", ""), self.db.dumps(summary), now,
            ),
        )
        run_row = self.db.execute("SELECT * FROM evaluation_runs ORDER BY id DESC LIMIT 1", fetchone=True)
        run_id = int(run_row["id"])
        for result in results:
            self.db.execute(
                """
                INSERT INTO evaluation_results
                (run_id, case_id, family, expected, predicted, outcome, confidence, detail_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, result.get("case_id", ""), result.get("family", ""), result.get("expected", ""),
                 result.get("predicted", ""), result.get("outcome", ""), result.get("confidence", ""),
                 self.db.dumps(result.get("detail") or {}), now),
            )
        return self._run_row(run_row)

    def list_runs(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM evaluation_runs ORDER BY id DESC LIMIT ?", (int(limit),), fetchall=True) or []
        return [self._run_row(row) for row in rows]

    def results_for_run(self, run_id: int) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM evaluation_results WHERE run_id = ? ORDER BY id ASC", (run_id,), fetchall=True) or []
        return [
            {
                "id": row["id"], "run_id": row["run_id"], "case_id": row["case_id"], "family": row["family"],
                "expected": row["expected"], "predicted": row["predicted"], "outcome": row["outcome"],
                "confidence": row["confidence"], "detail": Database.loads(row["detail_json"]),
            }
            for row in rows
        ]

    @staticmethod
    def _run_row(row) -> Dict[str, Any]:
        return {
            "id": row["id"], "name": row["name"], "model": row["model"], "prompt_version": row["prompt_version"],
            "dataset": row["dataset"], "total": row["total"], "true_positive": row["true_positive"],
            "false_positive": row["false_positive"], "false_negative": row["false_negative"],
            "true_negative": row["true_negative"], "precision": row["precision"], "recall": row["recall"],
            "f1": row["f1"], "accuracy": row["accuracy"],
            "pass_at_3": row["pass_at_3"], "pass_hat_3": row["pass_hat_3"],
            "scan_mode": row["scan_mode"], "agent_impl": row["agent_impl"],
            "summary": Database.loads(row["summary_json"]),
            "created_at": row["created_at"],
        }


class AuditLogRepository:
    """Append-only operation audit log."""

    def __init__(self, db: Database):
        self.db = db

    def add(self, *, actor: str = "anonymous", role: str = "", action: str, method: str = "",
            path: str = "", status_code: int = 0, target: str = "", detail: Optional[Dict[str, Any]] = None) -> None:
        self.db.execute(
            """
            INSERT INTO audit_log (actor, role, action, method, path, status_code, target, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (actor, role, action, method, path, int(status_code), target, self.db.dumps(detail or {}),
             datetime.utcnow().isoformat()),
        )

    def list(self, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),), fetchall=True) or []
        return [
            {
                "id": row["id"], "actor": row["actor"], "role": row["role"], "action": row["action"],
                "method": row["method"], "path": row["path"], "status_code": row["status_code"],
                "target": row["target"], "detail": Database.loads(row["detail_json"]), "created_at": row["created_at"],
            }
            for row in rows
        ]


class FixFeedbackRepository:
    """Records developer feedback on fix suggestions (第四版 G7 / )."""

    def __init__(self, db: Database):
        self.db = db

    def add(self, *, workspace_id: Optional[int], finding_id: Optional[int], vulnerability_hash_v2: str = "",
            suggestion_id: str = "", adopted: bool = False, misleading: bool = False,
            led_to_retest_pass: bool = False, comment: str = "", created_by: str = "local") -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO fix_feedback
            (workspace_id, finding_id, vulnerability_hash_v2, suggestion_id, adopted, misleading,
             led_to_retest_pass, comment, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, finding_id, vulnerability_hash_v2, suggestion_id, int(bool(adopted)),
             int(bool(misleading)), int(bool(led_to_retest_pass)), comment, created_by, now),
        )
        row = self.db.execute("SELECT * FROM fix_feedback ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._row(row)

    def list(self, *, workspace_id: Optional[int] = None, finding_id: Optional[int] = None) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if finding_id is not None:
            clauses.append("finding_id = ?")
            params.append(finding_id)
        sql = "SELECT * FROM fix_feedback"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row(row) for row in rows]

    def metrics(self, *, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        items = self.list(workspace_id=workspace_id)
        total = len(items)
        adopted = sum(1 for item in items if item["adopted"])
        misleading = sum(1 for item in items if item["misleading"])
        retest_pass = sum(1 for item in items if item["led_to_retest_pass"])

        def _rate(n: int) -> float:
            return round(n / total, 4) if total else 0.0

        return {
            "total": total,
            "adopted": adopted,
            "misleading": misleading,
            "led_to_retest_pass": retest_pass,
            "adoption_rate": _rate(adopted),
            "misleading_rate": _rate(misleading),
            "retest_pass_rate": _rate(retest_pass),
        }

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "finding_id": row["finding_id"],
            "vulnerability_hash_v2": row["vulnerability_hash_v2"],
            "suggestion_id": row["suggestion_id"],
            "adopted": bool(row["adopted"]),
            "misleading": bool(row["misleading"]),
            "led_to_retest_pass": bool(row["led_to_retest_pass"]),
            "comment": row["comment"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
        }


class AdvisoryRepository:
    """Persists ingested SCA advisories (independent intelligence layer)."""

    def __init__(self, db: Database):
        self.db = db

    def upsert(self, advisory: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        source = str(advisory.get("source") or "")
        advisory_id = str(advisory.get("advisory_id") or "")
        ecosystem = str(advisory.get("ecosystem") or "")
        package_name = str(advisory.get("package_name") or "")
        existing = self.db.execute(
            "SELECT id FROM advisories WHERE source = ? AND advisory_id = ? AND ecosystem = ? AND package_name = ?",
            (source, advisory_id, ecosystem, package_name),
            fetchone=True,
        )
        values = (
            source,
            advisory_id,
            ecosystem,
            package_name,
            self.db.dumps(advisory.get("aliases") or []),
            self.db.dumps(advisory.get("affected_ranges") or []),
            self.db.dumps(advisory.get("fixed_versions") or []),
            str(advisory.get("severity") or "UNKNOWN"),
            str(advisory.get("summary") or ""),
            str(advisory.get("details") or ""),
            1 if advisory.get("malicious") else 0,
            self.db.dumps(advisory.get("raw") or {}),
        )
        if existing:
            self.db.execute(
                """
                UPDATE advisories
                SET aliases_json = ?, affected_ranges_json = ?, fixed_versions_json = ?, severity = ?,
                    summary = ?, details = ?, malicious = ?, raw_json = ?
                WHERE id = ?
                """,
                (values[4], values[5], values[6], values[7], values[8], values[9], values[10], values[11], existing["id"]),
            )
            return self.get(existing["id"])
        self.db.execute(
            """
            INSERT INTO advisories
            (source, advisory_id, ecosystem, package_name, aliases_json, affected_ranges_json,
             fixed_versions_json, severity, summary, details, malicious, raw_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values + (now,),
        )
        row = self.db.execute("SELECT id FROM advisories ORDER BY id DESC LIMIT 1", fetchone=True)
        return self.get(row["id"])

    def get(self, advisory_row_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM advisories WHERE id = ?", (advisory_row_id,), fetchone=True)
        return self._row(row) if row else None

    def list_for_package(self, ecosystem: str, package_name: str) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM advisories WHERE LOWER(package_name) = ? AND (ecosystem = '' OR LOWER(ecosystem) = ?)",
            (package_name.lower(), (ecosystem or "").lower()),
            fetchall=True,
        ) or []
        return [self._row(row) for row in rows]

    def list(self, *, malicious_only: bool = False, limit: int = 1000) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM advisories"
        if malicious_only:
            sql += " WHERE malicious = 1"
        sql += " ORDER BY id DESC LIMIT ?"
        rows = self.db.execute(sql, (limit,), fetchall=True) or []
        return [self._row(row) for row in rows]

    def _row(self, row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "source": row["source"],
            "advisory_id": row["advisory_id"],
            "ecosystem": row["ecosystem"],
            "package_name": row["package_name"],
            "aliases": Database.loads(row["aliases_json"]),
            "affected_ranges": Database.loads(row["affected_ranges_json"]),
            "fixed_versions": Database.loads(row["fixed_versions_json"]),
            "severity": row["severity"],
            "summary": row["summary"],
            "details": row["details"],
            "malicious": bool(row["malicious"]),
            "raw": Database.loads(row["raw_json"]),
            "created_at": row["created_at"],
        }


class ScanCostRepository:
    """Persists per-scan cost records for annual cost estimation (G9)."""

    def __init__(self, db: Database):
        self.db = db

    def add(self, *, workspace_id: Optional[int], project: str = "", branch: str = "", commit_sha: str = "",
            scan_mode: str = "", model: str = "", input_tokens: int = 0, output_tokens: int = 0,
            cost_usd: float = 0.0, latency_ms: int = 0) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO scan_cost_records
            (workspace_id, project, branch, commit_sha, scan_mode, model, input_tokens, output_tokens, cost_usd, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, project, branch, commit_sha, scan_mode, model,
             int(input_tokens), int(output_tokens), float(cost_usd), int(latency_ms), now),
        )
        row = self.db.execute("SELECT * FROM scan_cost_records ORDER BY id DESC LIMIT 1", fetchone=True)
        return self._row(row)

    def list(self, workspace_id: Optional[int] = None, *, project: str = "", limit: int = 1000) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM scan_cost_records"
        clauses, params = [], []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if project:
            clauses.append("project = ?")
            params.append(project)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "project": row["project"],
            "branch": row["branch"],
            "commit_sha": row["commit_sha"],
            "scan_mode": row["scan_mode"],
            "model": row["model"],
            "input_tokens": row["input_tokens"],
            "output_tokens": row["output_tokens"],
            "cost_usd": row["cost_usd"],
            "latency_ms": row["latency_ms"],
            "created_at": row["created_at"],
        }


class ScanTriggerPolicyRepository:
    """Persists scan-trigger timing policies (G9)."""

    def __init__(self, db: Database):
        self.db = db

    def upsert(self, *, workspace_id: Optional[int], name: str, trigger: str = "",
               scan_mode: str = "filter_first", model: str = "", monthly_frequency: float = 0.0,
               enabled: bool = True) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        existing = self.db.execute(
            "SELECT id, created_at FROM scan_trigger_policy WHERE workspace_id IS ? AND name = ?",
            (workspace_id, name),
            fetchone=True,
        )
        if existing:
            self.db.execute(
                """
                UPDATE scan_trigger_policy
                SET trigger = ?, scan_mode = ?, model = ?, monthly_frequency = ?, enabled = ?, updated_at = ?
                WHERE id = ?
                """,
                (trigger, scan_mode, model, float(monthly_frequency), 1 if enabled else 0, now, existing["id"]),
            )
            return self.get(existing["id"])
        self.db.execute(
            """
            INSERT INTO scan_trigger_policy
            (workspace_id, name, trigger, scan_mode, model, monthly_frequency, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, name, trigger, scan_mode, model, float(monthly_frequency), 1 if enabled else 0, now, now),
        )
        row = self.db.execute("SELECT id FROM scan_trigger_policy ORDER BY id DESC LIMIT 1", fetchone=True)
        return self.get(row["id"])

    def get(self, policy_id: int) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM scan_trigger_policy WHERE id = ?", (policy_id,), fetchone=True)
        return self._row(row) if row else None

    def list(self, workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM scan_trigger_policy"
        params: List[Any] = []
        if workspace_id is not None:
            sql += " WHERE workspace_id = ?"
            params.append(workspace_id)
        sql += " ORDER BY id ASC"
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "workspace_id": row["workspace_id"],
            "name": row["name"],
            "trigger": row["trigger"],
            "scan_mode": row["scan_mode"],
            "model": row["model"],
            "monthly_frequency": row["monthly_frequency"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
