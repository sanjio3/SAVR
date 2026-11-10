import json
import logging
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


def _dict_row_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    """将 sqlite 行转为 dict，使调用方既能用 row['col'] 也能用 row.get('col')。

    原实现用 sqlite3.Row，但它没有 .get() 方法，导致 IastService 等模块
    对查询结果调用 row.get(...) 时抛 AttributeError。dict 行同时兼容
    row['col'] 与 row.get('col')，且保留列顺序。
    """
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


# 写锁冲突的重试策略（2026-09-19，run 21 事故根治）。
# 现象：扫描收尾写终态时撞 `database is locked`，watcher 翻态失败 → scan_tasks 卡 running 数小时，
# 前端一直显示陈旧态，只能靠人工跑 reconcile_orphaned_tasks 回收。
# 机理：busy_timeout=30000 只放大「单次忙等窗口」，但跨进程长写事务（findings 批量重写、
# 探针事件突发 ingest）仍可能让忙等超时后抛错；而终态写入只是一条短 UPDATE，重试成本极低。
# 故在 execute 这一层对「锁类错误」统一做指数退避重试，使终态写入等关键短写自愈。
_LOCK_ERROR_MARKERS = ("database is locked", "database is busy", "database table is locked")
_LOCK_RETRY_ATTEMPTS = 5
_LOCK_RETRY_BASE_DELAY = 0.4


def _is_lock_error(exc: BaseException) -> bool:
    """是否为 SQLite 写锁冲突（可安全重试）。"""
    msg = str(exc).lower()
    return any(marker in msg for marker in _LOCK_ERROR_MARKERS)


class Database:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialized = False
        # 2026-09-18（F2 ②连接复用）：按线程缓存连接。
        # 原实现每次 execute 都新建 sqlite3 连接并跑 4 条 PRAGMA（foreign_keys / journal_mode /
        # synchronous / busy_timeout），用完既不显式关闭也不复用，只靠 GC 回收。在 ingest 热路径上
        # 每事件 2~5 次查询，等于每事件新建并丢弃 2~5 个连接；而 WAL 库打开连接需要读 WAL 索引，
        # 库越大（本项目 app.db 已 GB 级）开连接越慢 —— 2026-09-15 实测这正是 ingest 端到端耗时的
        # 主要来源（解析阶段占 98.7%，且隔离小库 260~404 条/秒、真实库仅 78.7 条/秒）。
        # 按线程缓存而非全局单连接：语义与现状完全一致（连接从不被两个线程同时使用），
        # 且不会把 cursor 跨线程暴露出去。
        self._local = threading.local()

    def connect(self) -> sqlite3.Connection:
        cached = getattr(self._local, "connection", None)
        if cached is not None:
            return cached
        with self._lock:
            connection = sqlite3.connect(str(self.path), check_same_thread=False)
            connection.row_factory = _dict_row_factory
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            # 2026-09-14：写锁忙等窗口。Python sqlite3 默认 timeout=5 秒，在数 GB 级库上做长写事务
            # （sync_blackboard 逐行乐观锁、findings 批量重写、探针事件突发写入）极易超时，表现为
            # sqlite3.OperationalError: database is locked（/api/agent/events 返回 500）。
            # WAL 只解决读并发，写仍然串行，故必须显式放大忙等窗口。
            connection.execute("PRAGMA busy_timeout = 30000")
            if not self._initialized:
                self._init_schema(connection)
                self._initialized = True
            self._local.connection = connection
            return connection

    def close(self) -> None:
        """关闭本线程缓存的连接（幂等）。

        连接复用的配套回收口：进程退出、测试隔离、或确认不再使用该 Database 实例时调用。
        不调用也不会出错（与原实现一致，交由 GC 回收），只是少了一次显式释放。
        """
        connection = getattr(self._local, "connection", None)
        if connection is None:
            return
        try:
            connection.close()
        except Exception:
            pass
        self._local.connection = None

    def _init_schema(self, connection: sqlite3.Connection) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_path TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            settings_json TEXT NOT NULL DEFAULT '{}',
            slug TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            phase TEXT NOT NULL,
            output_dir TEXT NOT NULL,
            options_json TEXT NOT NULL DEFAULT '{}',
            summary_json TEXT NOT NULL DEFAULT '{}',
            error_message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_task_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(task_id) REFERENCES scan_tasks(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            workspace_id INTEGER NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line INTEGER NOT NULL DEFAULT 0,
            title TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',
            hash_components_json TEXT NOT NULL DEFAULT '{}',
            source TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            a1_evidence TEXT NOT NULL DEFAULT '{}',
            sca_component TEXT NOT NULL DEFAULT '',
            sca_advisory_id TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(task_id) REFERENCES scan_tasks(id) ON DELETE CASCADE,
            FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            workspace_id INTEGER NOT NULL,
            report_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            FOREIGN KEY(task_id) REFERENCES scan_tasks(id) ON DELETE CASCADE,
            FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
        );


        CREATE TABLE IF NOT EXISTS vulnerability_instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            vulnerability_hash_v2 TEXT NOT NULL,
            hash_version TEXT NOT NULL DEFAULT 'v2',
            family TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            source TEXT NOT NULL DEFAULT '',
            first_seen_task_id INTEGER,
            last_seen_task_id INTEGER,
            owner TEXT NOT NULL DEFAULT '',
            sla_due_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(workspace_id, vulnerability_hash_v2)
        );

        CREATE TABLE IF NOT EXISTS model_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purpose TEXT NOT NULL,
            model_profile TEXT NOT NULL DEFAULT 'default',
            model TEXT NOT NULL DEFAULT '',
            prompt_version TEXT NOT NULL DEFAULT '',
            input_summary TEXT NOT NULL DEFAULT '',
            output_summary TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'completed',
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            cost_usd REAL NOT NULL DEFAULT 0,
            latency_ms INTEGER NOT NULL DEFAULT 0,
            error_message TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        -- 2026-09-19（P0-3）：prompt→response 缓存。
        -- 目的：同一份 prompt 反复调试时不再重复消耗算力/额度，且任务中断后重跑
        -- 已算过的调用直接命中（LLM 级断点续跑）。键是 prompt+模型+参数的指纹，
        -- 因此改提示词、改模型、改采样参数都会自动失效，不需要手工清缓存。
        CREATE TABLE IF NOT EXISTS llm_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cache_key TEXT NOT NULL UNIQUE,
            provider TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            prompt_hash TEXT NOT NULL DEFAULT '',
            text TEXT NOT NULL,
            telemetry_json TEXT NOT NULL DEFAULT '{}',
            hit_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_access_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_llm_cache_access
            ON llm_cache(last_access_at);

        CREATE TABLE IF NOT EXISTS ai_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            vulnerability_hash_v2 TEXT NOT NULL,
            model_run_id INTEGER,
            model TEXT NOT NULL DEFAULT '',
            prompt_version TEXT NOT NULL DEFAULT '',
            verdict TEXT NOT NULL,
            confidence TEXT NOT NULL,
            criteria_json TEXT NOT NULL DEFAULT '{}',
            missing_evidence_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS human_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            vulnerability_hash_v2 TEXT NOT NULL,
            reviewer TEXT NOT NULL DEFAULT 'local',
            decision TEXT NOT NULL,
            reason_type TEXT NOT NULL DEFAULT '',
            reason_detail TEXT NOT NULL DEFAULT '',
            adopted_ai_judgement INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sca_scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            task_id INTEGER,
            project_path TEXT NOT NULL,
            tool TEXT NOT NULL,
            status TEXT NOT NULL,
            component_count INTEGER NOT NULL DEFAULT 0,
            vulnerability_count INTEGER NOT NULL DEFAULT 0,
            sbom_path TEXT NOT NULL DEFAULT '',
            report_path TEXT NOT NULL DEFAULT '',
            summary_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            finished_at TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS sca_components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            task_id INTEGER,
            run_id INTEGER,
            ecosystem TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '',
            package_manager TEXT NOT NULL DEFAULT '',
            source_file TEXT NOT NULL DEFAULT '',
            purl TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT '',
            direct_dependency INTEGER NOT NULL DEFAULT 1,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sca_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            task_id INTEGER,
            run_id INTEGER,
            component_id INTEGER,
            ecosystem TEXT NOT NULL DEFAULT '',
            component_name TEXT NOT NULL,
            component_version TEXT NOT NULL DEFAULT '',
            advisory_id TEXT NOT NULL,
            aliases_json TEXT NOT NULL DEFAULT '[]',
            severity TEXT NOT NULL DEFAULT 'UNKNOWN',
            summary TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            fixed_versions_json TEXT NOT NULL DEFAULT '[]',
            references_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'open',
            vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS advisories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            ecosystem TEXT NOT NULL DEFAULT '',
            package_name TEXT NOT NULL DEFAULT '',
            aliases_json TEXT NOT NULL DEFAULT '[]',
            affected_ranges_json TEXT NOT NULL DEFAULT '[]',
            fixed_versions_json TEXT NOT NULL DEFAULT '[]',
            severity TEXT NOT NULL DEFAULT 'UNKNOWN',
            summary TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            malicious INTEGER NOT NULL DEFAULT 0,
            raw_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE(source, advisory_id, ecosystem, package_name)
        );

        CREATE TABLE IF NOT EXISTS dast_apps (
            app_id TEXT PRIMARY KEY,
            app_name TEXT NOT NULL,
            base_url TEXT NOT NULL DEFAULT '',
            service_name TEXT NOT NULL DEFAULT '',
            auth_type TEXT NOT NULL DEFAULT 'cookie',
            role_boundaries_json TEXT NOT NULL DEFAULT '[]',
            settings_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dast_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT '',
            tenant TEXT NOT NULL DEFAULT '',
            subject TEXT NOT NULL DEFAULT '',
            auth_headers_json TEXT NOT NULL DEFAULT '{}',
            auth_cookies_json TEXT NOT NULL DEFAULT '{}',
            token_ref TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE(app_id, account_id)
        );

        CREATE TABLE IF NOT EXISTS dast_apis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            api_key TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            operation_id TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            params_json TEXT NOT NULL DEFAULT '[]',
            body_schema_json TEXT NOT NULL DEFAULT '{}',
            resource_id_fields_json TEXT NOT NULL DEFAULT '[]',
            auth_required INTEGER NOT NULL DEFAULT 1,
            risk_level TEXT NOT NULL DEFAULT 'medium',
            tags_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            UNIQUE(app_id, api_key)
        );

        CREATE TABLE IF NOT EXISTS dast_traffic_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            api_id INTEGER,
            sample_key TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT '',
            tenant TEXT NOT NULL DEFAULT '',
            subject TEXT NOT NULL DEFAULT '',
            resource_owner TEXT NOT NULL DEFAULT '',
            resource_tenant TEXT NOT NULL DEFAULT '',
            resource_id TEXT NOT NULL DEFAULT '',
            request_json TEXT NOT NULL DEFAULT '{}',
            response_json TEXT NOT NULL DEFAULT '{}',
            status_code INTEGER NOT NULL DEFAULT 0,
            response_body TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dast_scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'imported_traffic',
            status TEXT NOT NULL,
            candidate_count INTEGER NOT NULL DEFAULT 0,
            replayed_count INTEGER NOT NULL DEFAULT 0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            summary_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            finished_at TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS dast_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            app_id TEXT NOT NULL,
            api_id INTEGER,
            vulnerability_hash_v2 TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'HIGH',
            title TEXT NOT NULL,
            decision_json TEXT NOT NULL DEFAULT '{}',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            finding_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS retest_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            vulnerability_hash_v2 TEXT NOT NULL,
            finding_id INTEGER,
            strategy TEXT NOT NULL DEFAULT 'manual',
            result TEXT NOT NULL DEFAULT 'inconclusive',
            previous_status TEXT NOT NULL DEFAULT '',
            new_status TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT 'local',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS autonomy_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT 'auto_close',
            min_confidence TEXT NOT NULL DEFAULT 'high',
            verdict TEXT NOT NULL DEFAULT 'false_positive',
            max_impact TEXT NOT NULL DEFAULT 'medium',
            gray_percent INTEGER NOT NULL DEFAULT 0,
            require_ai_agree INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(name)
        );

        CREATE TABLE IF NOT EXISTS autonomy_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            policy_id INTEGER,
            policy_name TEXT NOT NULL DEFAULT '',
            finding_id INTEGER,
            vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL DEFAULT '',
            decision TEXT NOT NULL DEFAULT '',
            previous_status TEXT NOT NULL DEFAULT '',
            new_status TEXT NOT NULL DEFAULT '',
            gray_bucket INTEGER NOT NULL DEFAULT 0,
            applied INTEGER NOT NULL DEFAULT 0,
            rolled_back INTEGER NOT NULL DEFAULT 0,
            reason TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT 'system',
            created_at TEXT NOT NULL,
            rolled_back_at TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS entry_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            task_id INTEGER,
            entry_hash TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            file_path TEXT NOT NULL DEFAULT '',
            line INTEGER NOT NULL DEFAULT 0,
            signature TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'discovered',
            source TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(workspace_id, entry_hash)
        );

        -- 知识条目（黑板阶段二）：环境事实 / 靶场档案 / 已知坑的一等公民化。
        -- 替代「把经验压进早期设计笔记文档」——改为机器可读、阶段必读的 DB 真相源。
        -- kind 枚举：target_profile / env_fact / pitfall / family_alias / verified_conclusion。
        -- 首期只灌已实测确认过的硬事实（详见 src/core/knowledge_entries.py 的种子函数）。
        CREATE TABLE IF NOT EXISTS knowledge_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL DEFAULT 0,
            kind TEXT NOT NULL,
            key TEXT NOT NULL,
            value_json TEXT NOT NULL DEFAULT '{}',
            source TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium',
            ttl TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            superseded_by TEXT NOT NULL DEFAULT '',
            UNIQUE(workspace_id, kind, key)
        );

        CREATE TABLE IF NOT EXISTS entry_rule_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            rule_hash TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            pattern TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'candidate',
            occurrences INTEGER NOT NULL DEFAULT 1,
            confirmed_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(workspace_id, rule_hash)
        );

        CREATE TABLE IF NOT EXISTS taint_rule_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            rule_hash TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'sink',
            language TEXT NOT NULL DEFAULT '',
            pattern TEXT NOT NULL DEFAULT '',
            family TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'candidate',
            regression_passed INTEGER NOT NULL DEFAULT 0,
            regression_detail_json TEXT NOT NULL DEFAULT '{}',
            occurrences INTEGER NOT NULL DEFAULT 1,
            confirmed_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(workspace_id, rule_hash)
        );

        CREATE TABLE IF NOT EXISTS evaluation_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            prompt_version TEXT NOT NULL DEFAULT '',
            dataset TEXT NOT NULL DEFAULT '',
            total INTEGER NOT NULL DEFAULT 0,
            true_positive INTEGER NOT NULL DEFAULT 0,
            false_positive INTEGER NOT NULL DEFAULT 0,
            false_negative INTEGER NOT NULL DEFAULT 0,
            true_negative INTEGER NOT NULL DEFAULT 0,
            precision REAL NOT NULL DEFAULT 0,
            recall REAL NOT NULL DEFAULT 0,
            f1 REAL NOT NULL DEFAULT 0,
            accuracy REAL NOT NULL DEFAULT 0,
            pass_at_3 REAL NOT NULL DEFAULT 0,
            pass_hat_3 REAL NOT NULL DEFAULT 0,
            scan_mode TEXT NOT NULL DEFAULT '',
            agent_impl TEXT NOT NULL DEFAULT '',
            summary_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evaluation_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            case_id TEXT NOT NULL DEFAULT '',
            family TEXT NOT NULL DEFAULT '',
            expected TEXT NOT NULL DEFAULT '',
            predicted TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sbom_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            task_id INTEGER,
            run_id INTEGER,
            format TEXT NOT NULL DEFAULT 'CycloneDX',
            spec_version TEXT NOT NULL DEFAULT '1.5',
            component_count INTEGER NOT NULL DEFAULT 0,
            file_path TEXT NOT NULL DEFAULT '',
            content_hash TEXT NOT NULL DEFAULT '',
            document_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL DEFAULT 'anonymous',
            role TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            status_code INTEGER NOT NULL DEFAULT 0,
            target TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hitl_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL DEFAULT 0,
            action TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            route TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT '',
            tool_id TEXT NOT NULL DEFAULT '',
            approval_mode TEXT NOT NULL DEFAULT '',
            stage TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS fix_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            finding_id INTEGER,
            vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',
            suggestion_id TEXT NOT NULL DEFAULT '',
            adopted INTEGER NOT NULL DEFAULT 0,
            misleading INTEGER NOT NULL DEFAULT 0,
            led_to_retest_pass INTEGER NOT NULL DEFAULT 0,
            comment TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT 'local',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hash_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL DEFAULT 0,
            old_hash TEXT NOT NULL,
            new_hash TEXT NOT NULL,
            similarity REAL NOT NULL DEFAULT 0,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(workspace_id, old_hash, new_hash)
        );

        CREATE TABLE IF NOT EXISTS scan_cost_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            project TEXT NOT NULL DEFAULT '',
            branch TEXT NOT NULL DEFAULT '',
            commit_sha TEXT NOT NULL DEFAULT '',
            scan_mode TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            cost_usd REAL NOT NULL DEFAULT 0,
            latency_ms INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_trigger_policy (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER,
            name TEXT NOT NULL,
            trigger TEXT NOT NULL DEFAULT '',
            scan_mode TEXT NOT NULL DEFAULT 'filter_first',
            model TEXT NOT NULL DEFAULT '',
            monthly_frequency REAL NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(workspace_id, name)
        );

        CREATE TABLE IF NOT EXISTS quota_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            subject_type TEXT NOT NULL DEFAULT 'workspace',
            subject_id INTEGER,
            dimension TEXT NOT NULL,
            limit_value REAL NOT NULL DEFAULT 0,
            period TEXT NOT NULL DEFAULT 'total',
            action TEXT NOT NULL DEFAULT 'reject',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(subject_type, subject_id, dimension, period)
        );
        CREATE INDEX IF NOT EXISTS idx_quota_subject ON quota_policies(subject_type, subject_id);

        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS iast_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            app_name TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            target_url TEXT NOT NULL,
            code_path TEXT NOT NULL DEFAULT '',
            probe_mode TEXT NOT NULL DEFAULT 'iast',
            status TEXT NOT NULL DEFAULT 'unknown',
            last_heartbeat_at TEXT NOT NULL DEFAULT '',
            registered_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            settings_json TEXT NOT NULL DEFAULT '{}',
            probe_token TEXT NOT NULL DEFAULT '',
            probe_version TEXT NOT NULL DEFAULT '',
            sast_code_version TEXT NOT NULL DEFAULT '',
            version_status TEXT NOT NULL DEFAULT 'unknown',
            FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
            UNIQUE(workspace_id, app_name, agent_id)
        );

        CREATE TABLE IF NOT EXISTS iast_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            workspace_id INTEGER NOT NULL,
            task_id INTEGER,
            app_name TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            vuln_type TEXT NOT NULL DEFAULT '',
            trace_id TEXT NOT NULL DEFAULT '',
            canary TEXT NOT NULL DEFAULT '',
            canary_match INTEGER NOT NULL DEFAULT 0,
            canary_state TEXT NOT NULL DEFAULT '',
            sink_file TEXT NOT NULL DEFAULT '',
            sink_line INTEGER NOT NULL DEFAULT 0,
            sink_method TEXT NOT NULL DEFAULT '',
            source_name TEXT NOT NULL DEFAULT '',
            source_type TEXT NOT NULL DEFAULT '',
            source_value TEXT NOT NULL DEFAULT '',
            principal TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'INFO',
            stack_trace TEXT NOT NULL DEFAULT '',
            taint_path_json TEXT NOT NULL DEFAULT '{}',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            correlated_finding_id INTEGER,
            correlated_instance_id INTEGER,
            ingested_at TEXT NOT NULL,
            ingest_bucket INTEGER NOT NULL DEFAULT 0,
            sink_reached INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(session_id) REFERENCES iast_sessions(id) ON DELETE CASCADE,
            FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
            FOREIGN KEY(task_id) REFERENCES scan_tasks(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS trigger_specs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            session_id INTEGER,
            task_id INTEGER,
            finding_id INTEGER,
            vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',
            family TEXT NOT NULL DEFAULT '',
            target_endpoint TEXT NOT NULL DEFAULT '',
            http_method TEXT NOT NULL DEFAULT 'GET',
            param_name TEXT NOT NULL DEFAULT '',
            param_name_source TEXT NOT NULL DEFAULT 'unknown',
            param_location TEXT NOT NULL DEFAULT 'query',
            content_type TEXT NOT NULL DEFAULT '',
            principal TEXT NOT NULL DEFAULT '',
            taint_marker TEXT NOT NULL DEFAULT '',
            expected_sink_file TEXT NOT NULL DEFAULT '',
            expected_sink_line INTEGER NOT NULL DEFAULT 0,
            representative_request_params_json TEXT NOT NULL DEFAULT '{}',
            raw_json TEXT NOT NULL DEFAULT '{}',
            category TEXT NOT NULL DEFAULT '',
            business_logic_category TEXT NOT NULL DEFAULT '',
            attack_payloads_json TEXT NOT NULL DEFAULT '[]',
            accounts_json TEXT NOT NULL DEFAULT '[]',
            victim_resource_id TEXT NOT NULL DEFAULT '',
            victim_identifiers TEXT NOT NULL DEFAULT '[]',
            auth_binding_json TEXT NOT NULL DEFAULT '{}',
            replayable INTEGER NOT NULL DEFAULT 1,
            business_logic_confirmed INTEGER NOT NULL DEFAULT 0,
            verification_status TEXT NOT NULL DEFAULT '',
            iast_state TEXT NOT NULL DEFAULT '',
            -- 2026-10-02（净化器判定九问 Q5）：non_bypassable 真阴性的「一等公民证据」。
            -- 此前 verdict 只埋 raw_json.filter_verdict，闭环/前端难查询、难审计；判死后零运行时证据。
            -- bypass_state: bypassable/non_bypassable/undetermined（与 filter_verdict 同义，冗余落库便于对账）
            -- bypass_reason: 判定理由（人类可读）
            -- filter_spec_json: 结构化约束（FilterSpec.to_dict）+ source + 置信度
            bypass_state TEXT NOT NULL DEFAULT '',
            bypass_reason TEXT NOT NULL DEFAULT '',
            filter_spec_json TEXT NOT NULL DEFAULT '{}',
            -- 2026-10-24（可见率治本）：族级行为 oracle 观测结果（不参与判定）。
            oracle_state TEXT NOT NULL DEFAULT '',
            oracle_signal TEXT NOT NULL DEFAULT '',
            -- 2026-10-03（Part2 M1 度量地基）：「未确认」的四值判责列。
            -- 旧口径里 no_evidence/unconfirmed 是大杂烩：探针没插桩、spec 从未重放、
            -- 靶场环境不支持、真打不通全在同一桶里，导致任何改进都无法判断自己修了什么。
            -- failure_attribution: env_unsupported / probe_not_covered / pipeline_gap / true_miss
            --   （判责顺序 env→probe→pipeline→true_miss，见 src/core/failure_attribution.py）
            -- failure_attribution_reason: 人类可读的判责依据
            failure_attribution TEXT NOT NULL DEFAULT '',
            failure_attribution_reason TEXT NOT NULL DEFAULT '',
            -- 2026-11-04：阶段层归因（与上面的「责任归属」并行，不替代）。
            -- failure_attribution 回答「该谁修」（env/probe/pipeline/true_miss），
            -- failure_attribution_layer 回答「卡在流水线哪一层」：
            --   layer1_spec（A2 未产出载荷）/ layer2_replay（D1 未发或路由不通）/
            --   layer3_verdict（canary 已到 sink 但 D2 未确认）/
            --   layer4_iast（已重放但 canary 未到 sink）
            -- 四层串联、症状同为「未确认」，没有这一列就只能人工回查每个 spec
            -- （2026-11-04 jsc 615 的 10 个未覆盖点即如此逐点归因）。
            failure_attribution_layer TEXT NOT NULL DEFAULT '',
            failure_attribution_layer_reason TEXT NOT NULL DEFAULT '',
            -- 2026-10-05（r58 精确率整改方案 1+2+3）：
            -- suppressed_by_safe_verdict: 1 = 命中已知安全实现，不计入检出集合。
            --   判定器 src/core/safe_verdict.py，对所有阶段生效（含 A2）——
            --   原先 safe_patterns 只接在 A1 出口（pipeline/a1/service.py:303），
            --   A2 独立落库绕过了它，规则表在而作用域不对，实测 331 个 FP 白报。
            -- suppress_rule: 命中的规则名（审计用）。
            -- confidence_boost / positive_evidence_rule: 方案 3 置信度分层，
            --   正向证据命中（hash:weak_hash 纯度 100%、sqli:sql_string_param 92.9%）
            --   只提 confidence 不改检出集合，让真漏洞排在 FP 前面。
            suppressed_by_safe_verdict INTEGER NOT NULL DEFAULT 0,
            suppress_rule TEXT NOT NULL DEFAULT '',
            confidence_boost REAL NOT NULL DEFAULT 0,
            positive_evidence_rule TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES iast_sessions(id) ON DELETE CASCADE,
            FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
        );
        -- 注：trigger_specs.session_id 可空。该表本质是 A2 预测的 poc 假说（canary 来源），
        -- 在 A2 阶段即可登记，此时探针会话可能尚未挂载；会话挂载后由 A3 自动重放驱动 D1/IAST 关联。

        -- 注：iast_request_params 已于 2026-09-01 全链路移除（探针从不发送 request_observed，
        -- 表内仅有扫描器字典盲打噪声；param_resolver 早已将观测面降权为 Tier0 回退且恒为空）。

        -- ===== 黑板（单一真相源）与轮次体系（2026-09-07 落地）=====
        -- scan_runs：每轮扫描的**不可变**运行记录。轮次身份从「task.name 字符串 + 独立 txt 文件」
        -- 收进 DB，并携带代码版本指纹，杜绝「旧 backend 跑旧代码」类假阳性（历史 P0-2 事故）。
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            round_no INTEGER NOT NULL DEFAULT 0,
            code_fingerprint TEXT NOT NULL DEFAULT '',
            git_revision TEXT NOT NULL DEFAULT '',
            key_files_json TEXT NOT NULL DEFAULT '[]',
            backend_pid INTEGER,
            options_json TEXT NOT NULL DEFAULT '{}',
            metrics_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'running',
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
        );

        -- vuln_blackboard：跨 session / 跨轮次的漏洞状态单一真相源。
        -- 以 vulnerability_instances（跨 task 全局去重）的 vuln_hash 为锚，按 (workspace, vhash, run)
        -- 钉住「检出 / 确认 / 运行时证据」三态 + 证据指针。
        -- 铁律：所有展示计数一律从本表派生，禁止各处自存快照（消灭 #396 那类事后对账补丁）。
        CREATE TABLE IF NOT EXISTS vuln_blackboard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            vulnerability_hash_v2 TEXT NOT NULL,
            run_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            family TEXT NOT NULL DEFAULT '',
            -- detect_state: detected（findings 或 spec 命中）/ undetected
            detect_state TEXT NOT NULL DEFAULT 'undetected',
            -- confirm_state: confirmed（有族+路由都对的 spec，进 D1 重放门禁）/ unconfirmed
            confirm_state TEXT NOT NULL DEFAULT 'unconfirmed',
            -- 运行时证据：canary 是否到达 sink（当前 sink_reached_count=0 的主要观测位）
            sink_reached INTEGER NOT NULL DEFAULT 0,
            verification_status TEXT NOT NULL DEFAULT '',
            iast_state TEXT NOT NULL DEFAULT '',
            -- 证据指针（只存 id，不复制内容）
            finding_id INTEGER,
            trigger_spec_id INTEGER,
            iast_event_id INTEGER,
            instance_id INTEGER,
            target_endpoint TEXT NOT NULL DEFAULT '',
            http_method TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            -- 黑板阶段三（2026-09-10）：并发读改写合并。
            -- version：乐观锁版本号。写入一律 `UPDATE ... WHERE version=?`，影响行数 0
            --   说明有人抢先写过 → 重读最新行、按合并语义重算后再写，杜绝 lost update。
            -- last_writer：最后写入者标记，格式 "task:<id>/run:<rid>/pid:<pid>"，
            --   用于事后定位「这条最强态是谁写的」。
            version INTEGER NOT NULL DEFAULT 0,
            last_writer TEXT NOT NULL DEFAULT '',
            UNIQUE(workspace_id, vulnerability_hash_v2, run_id)
        );

        -- 黑板写入审计（阶段三）：记录每次写入的 who / when / from / to，便于事后回放。
        -- op：insert（首次落行）/ merge（与既有行合并后覆盖）/ noop（合并后无变化，未写库）。
        -- version_before / version_after：乐观锁版本变迁，version_after = version_before
        --   即 noop；merge 必 +1。before_json / after_json 存合并前后的状态快照。
        CREATE TABLE IF NOT EXISTS blackboard_entries_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            vulnerability_hash_v2 TEXT NOT NULL,
            run_id INTEGER NOT NULL DEFAULT 0,
            task_id INTEGER NOT NULL DEFAULT 0,
            blackboard_id INTEGER,
            op TEXT NOT NULL,
            version_before INTEGER NOT NULL DEFAULT 0,
            version_after INTEGER NOT NULL DEFAULT 0,
            before_json TEXT NOT NULL DEFAULT '{}',
            after_json TEXT NOT NULL DEFAULT '{}',
            writer TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bb_audit_vh
            ON blackboard_entries_audit(workspace_id, vulnerability_hash_v2);

        -- 假说表（2026-09-14 新增，Q1 第三因「没有差集载体」的落地）：
        -- 此前「假说」只以自然语言 reason 字符串存在于 I2 反馈里，没有生命周期记录，
        -- 因而无法计算「SAST 假说集 ⊖ IAST 观测集」，闭环只能做关键词分流。
        -- 本表以 vulnerability_hash_v2 为锚，记录每条假说的声称（claimed_chain_json）、
        -- 状态（proposed/confirmed/refuted/open）与首末出现轮次，供差集回流使用。
        CREATE TABLE IF NOT EXISTS hypotheses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            run_id INTEGER NOT NULL DEFAULT 0,
            vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',
            family TEXT NOT NULL DEFAULT '',
            target_endpoint TEXT NOT NULL DEFAULT '',
            http_method TEXT NOT NULL DEFAULT 'GET',
            claimed_chain_json TEXT NOT NULL DEFAULT '{}',
            state TEXT NOT NULL DEFAULT 'proposed',
            state_reason TEXT NOT NULL DEFAULT '',
            evidence_event_count INTEGER NOT NULL DEFAULT 0,
            first_seen_task_id INTEGER NOT NULL DEFAULT 0,
            last_seen_task_id INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hypotheses_task
            ON hypotheses(task_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_hypotheses_ws_vh_run
            ON hypotheses(workspace_id, vulnerability_hash_v2, run_id);
        """
        connection.executescript(schema)
        self._migrate_existing_schema(connection)
        connection.commit()

    def _migrate_existing_schema(self, connection: sqlite3.Connection) -> None:
        def ensure_column(table: str, column: str, definition: str) -> None:
            columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

        ensure_column("findings", "vulnerability_hash_v2", "TEXT NOT NULL DEFAULT ''")
        # 2026-09-19（P1-7 埋点归属）：model_runs 原本没有任务与提示词指纹维度，
        # 导致成本与耗时只能按时间窗聚合，tasks.py 的注释自承「非精确归属」。
        # 补三列后即可按 task / stage 精确归因，这也是调本地模型时最需要的观测维度。
        ensure_column("model_runs", "task_id", "INTEGER")
        ensure_column("model_runs", "prompt_hash", "TEXT NOT NULL DEFAULT ''")
        ensure_column("model_runs", "stage", "TEXT NOT NULL DEFAULT ''")
        # 2026-09-22：工作区前向归属。历史 task_id 为 NULL 的调用无法逆归因（无外键），
        # 故只对未来行生效；record() 会在插入时按 task_id 自动解析 workspace_id。
        ensure_column("model_runs", "workspace_id", "INTEGER")
        ensure_column("findings", "vulnerability_hash_v1", "TEXT NOT NULL DEFAULT ''")
        ensure_column("findings", "hash_components_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column("findings", "source", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "poc_chain_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column("trigger_specs", "param_name_source", "TEXT NOT NULL DEFAULT 'unknown'")
        # 2026-08-29 D1 真实攻击：spec 需携带 A2 构造的攻击载荷与账户上下文。
        # category: 漏洞大类（普通 owasp 族 或 业务逻辑族 bola/race/vertical_privesc/...）
        # attack_payloads_json: A2 产出的真实攻击 payload 列表（反序列化等需真 gadget 链）
        # accounts_json / victim_resource_id / auth_binding_json: 账户发现产物（差分重放用）
        ensure_column("trigger_specs", "category", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "business_logic_category", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "attack_payloads_json", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column("trigger_specs", "accounts_json", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column("trigger_specs", "victim_resource_id", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "victim_identifiers", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column("trigger_specs", "auth_binding_json", "TEXT NOT NULL DEFAULT '{}'")
        # 2026-09-01 验证链路可控性：replayable=0 表示 spec 已登记但 D1 不应自动重放（如路由落在
        # 探针/诊断端点、或不依赖 canary 重放的业务逻辑类目待登录账号配置）。D1 在 verify() 前据此
        # 跳过，避免向不存在/错误的端点发请求、污染命中统计。默认 1（可重放）。
        ensure_column("trigger_specs", "replayable", "INTEGER NOT NULL DEFAULT 1")
        # 2026-09-02 §#3③：D2 业务/技术验证裁决回填，供攻击计划(AP)读 business_logic_confirmed /
        # verification_status / iast_state 正确呈现「运行时命中态」，不再只依赖 IAST canary 事件
        # （业务差分重放不产生 canary sink 事件，原 AP 分类器恒判 not_hit）。三处同步：base schema +
        # ensure_column + 旧表重建块。
        ensure_column("trigger_specs", "business_logic_confirmed", "INTEGER NOT NULL DEFAULT 0")
        ensure_column("trigger_specs", "verification_status", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "iast_state", "TEXT NOT NULL DEFAULT ''")
        # 2026-10-02（净化器判定九问 Q5）：non_bypassable 真阴性的一等公民证据列。
        ensure_column("trigger_specs", "bypass_state", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "bypass_reason", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "filter_spec_json", "TEXT NOT NULL DEFAULT '{}'")
        # 2026-10-24（可见率治本）：族级行为 oracle 的观测结果（不参与判定，先观测后接线）。
        # oracle_state ∈ exploitable / not_exploitable / inconclusive / ''（未跑）；
        # oracle_signal ∈ boolean_diff / time_delay / file_signature / reflection_raw / ...
        ensure_column("trigger_specs", "oracle_state", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "oracle_signal", "TEXT NOT NULL DEFAULT ''")
        # 2026-10-03（Part2 M1 度量地基）：未确认结果的四值判责（详见 base schema 注释）。
        # 三处同步：base schema + ensure_column + 旧表重建块。
        ensure_column("trigger_specs", "failure_attribution", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "failure_attribution_reason", "TEXT NOT NULL DEFAULT ''")
        # 2026-11-04：阶段层归因（四层：spec/replay/verdict/iast），与责任归属并行。
        ensure_column("trigger_specs", "failure_attribution_layer", "TEXT NOT NULL DEFAULT ''")
        ensure_column("trigger_specs", "failure_attribution_layer_reason", "TEXT NOT NULL DEFAULT ''")
        # 2026-10-05（r58 精确率整改方案 1+2）：安全实现抑制标记。
        # suppressed_by_safe_verdict=1 表示 src/core/safe_verdict.py 判定该 spec
        # 命中已知安全实现（如 weak_random 用了 SecureRandom、sqli 源头是返回常量的
        # getTheValue helper），不应计入检出集合。**这是 A2 也生效的抑制**——
        # 原先 safe_patterns 只在 A1 出口接线（src/pipeline/a1/service.py:303），
        # A2 独立判定直接落库，规则表在但作用域不对，实测 331 个 FP 白报。
        # suppress_rule 记命中的规则名，供审计与「为什么这条没进检出」答疑。
        # 用例级否决（方案 2）由 src/iast/service.py 在写入时聚合判定：
        # 同一用例的全部 spec 都抑制，才把该用例移出检出集合。
        ensure_column("trigger_specs", "suppressed_by_safe_verdict", "INTEGER NOT NULL DEFAULT 0")
        ensure_column("trigger_specs", "suppress_rule", "TEXT NOT NULL DEFAULT ''")
        # 方案 3（置信度分层）：正向证据规则命中的标记（不改检出集合，只提 confidence）。
        # 依据 r58 全族普查：hash:weak_hash 命中纯度 100%（TP 89/FP 0）、
        # sqli:sql_string_param 纯度 92.9% —— 命中即几乎必然是真漏洞。
        ensure_column("trigger_specs", "confidence_boost", "REAL NOT NULL DEFAULT 0")
        ensure_column("trigger_specs", "positive_evidence_rule", "TEXT NOT NULL DEFAULT ''")
        # 族标错的纠正依据：**代码能力证据**给出的族（src/core/capability_judge.py）。
        # 族标签是 A1/A2 打的，会标错 —— 实测 17.3% 的检出用例，平台报的族与真实
        # 类别完全对不上（典型：弱随机数被标成 broken_access_control，用户照着
        # 标签去查越权，方向全错）。能力族单独用吻合率 75.4%，与平台族**并集 100%**
        # （r60 实测：平台族错的 391 个用例，能力族 391 个都对，两者都错 0 个）。
        # 所以不改族、只把能力族一并记下来，展示时两个族一起给用户。
        ensure_column("trigger_specs", "capability_family", "TEXT NOT NULL DEFAULT ''")
        ensure_column("iast_events", "taint_path_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column("iast_events", "sink_reached", "INTEGER NOT NULL DEFAULT 0")
        ensure_column("vulnerability_instances", "review_conclusion", "TEXT NOT NULL DEFAULT ''")
        # Point5 语义分级：confirmed_runtime(=status) 是「污点抵达 sink」的传播证明（taint_reached），
        # 不代表「已可利用」；exploit_confirmed 是 D2 harmful 裁决确认的可观测危害（exploited）。
        # 两栏并存，前端据此分「潜在命中(taint reached)」与「真命中(exploited)」两档展示。
        ensure_column("vulnerability_instances", "exploit_confirmed", "INTEGER DEFAULT 0")
        ensure_column("evaluation_runs", "pass_at_3", "REAL NOT NULL DEFAULT 0")
        ensure_column("evaluation_runs", "pass_hat_3", "REAL NOT NULL DEFAULT 0")
        ensure_column("evaluation_runs", "scan_mode", "TEXT NOT NULL DEFAULT ''")
        ensure_column("evaluation_runs", "agent_impl", "TEXT NOT NULL DEFAULT ''")
        ensure_column("iast_sessions", "probe_version", "TEXT NOT NULL DEFAULT ''")
        ensure_column("iast_sessions", "sast_code_version", "TEXT NOT NULL DEFAULT ''")
        ensure_column("iast_sessions", "version_status", "TEXT NOT NULL DEFAULT 'unknown'")
        # 方案 3：探针挂载阶段（WARMING_UP 预热中 / READY 已就绪），由探针心跳上报，前端据此提示。
        ensure_column("iast_sessions", "agent_phase", "TEXT NOT NULL DEFAULT 'unknown'")
        # 2026-10-02（净化器判定九问 Q8）：探针上报的「已织桩 sink 清单」，用于把笼统 no-arrival
        # 拆成 probe_not_instrumented / probe_unavailable / genuine_no_arrival 三态。缺失则保守回退。
        ensure_column("iast_sessions", "coverage_manifest_json", "TEXT NOT NULL DEFAULT '{}'")
        # 2026-08-28 ③ 选项A：活跃扫描会话归属。replay 窗口内无 canary 身份段的事件据此归属到
        # 当前活跃扫描 task，避免多 task workspace 下事件被静默归 NULL（结构性丢数据）。
        ensure_column("iast_sessions", "current_task_id", "INTEGER")
        ensure_column("workspaces", "slug", "TEXT")
        # 2026-09-07 黑板/轮次体系：scan_tasks.run_id 把「轮次身份」从 name 字符串与独立 txt 文件
        # 收进 DB，与 scan_runs 强绑定。此前轮次 out-of-band 导致同一 task 被多轮覆写成混合库，
        # 单轮归因做不到（task-3 事故：漏斗读数 47→25 自相矛盾）。
        ensure_column("scan_tasks", "run_id", "INTEGER")
        # 回填历史 workspace 的 slug（slug 为空时按 id 派生，保证 URL 可读且唯一）。
        try:
            import re
            rows = connection.execute("SELECT id, name, slug FROM workspaces WHERE slug IS NULL OR slug = ''").fetchall()
            for r in rows:
                raw = (r["name"] or "").strip().lower()
                s = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")[:48] or "ws"
                connection.execute("UPDATE workspaces SET slug = ? WHERE id = ?", (f"{s}-{r['id']}", r["id"]))
        except Exception:
            pass
        # 2026-08-28 ④：A1/CodeQL 证据持久化，供 A2 阶段稳定消费（已通过 a1_evidence_index 注入 A2 prompt）。
        ensure_column("findings", "a1_evidence", "TEXT NOT NULL DEFAULT '{}'")
        # 2026-09-15 item 3：SCA 命名空间从 finding_type 剥离。组件名/编号拆到独立列，
        # finding_type 仅留族名 "sca"。旧库自动补齐两列（默认空串），不重建 findings 表。
        ensure_column("findings", "sca_component", "TEXT NOT NULL DEFAULT ''")
        ensure_column("findings", "sca_advisory_id", "TEXT NOT NULL DEFAULT ''")
        # 2026-09-10 黑板阶段三：vuln_blackboard 并发读改写合并需要的两个列。
        # 旧库只有 UNIQUE(workspace_id, vhash, run_id) 无版本列，靠 ensure_column 补齐，
        # 不必重建表；缺列时 blackboard.py 会自动退化为「直接覆盖」的旧行为（见 _upsert_merged）。
        ensure_column("vuln_blackboard", "version", "INTEGER NOT NULL DEFAULT 0")
        ensure_column("vuln_blackboard", "last_writer", "TEXT NOT NULL DEFAULT ''")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(workspace_id, vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sca_component_name ON sca_components(workspace_id, ecosystem, name, version)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sca_advisory ON sca_vulnerabilities(advisory_id, component_name)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dast_samples_api ON dast_traffic_samples(app_id, api_id, resource_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dast_findings_hash ON dast_findings(app_id, vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_ai_reviews_hash ON ai_reviews(vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_human_reviews_hash ON human_reviews(vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_instances_status ON vulnerability_instances(workspace_id, status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_retest_runs_hash ON retest_runs(workspace_id, vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_autonomy_actions_hash ON autonomy_actions(workspace_id, vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_entry_assets_type ON entry_assets(workspace_id, entry_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_entry_rules_status ON entry_rule_candidates(workspace_id, status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_taint_rules_status ON taint_rule_candidates(workspace_id, status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_taint_rules_kind ON taint_rule_candidates(kind, language)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_eval_results_run ON evaluation_results(run_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_fix_feedback_finding ON fix_feedback(workspace_id, finding_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_fix_feedback_hash ON fix_feedback(vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_hash_migrations_old ON hash_migrations(workspace_id, old_hash)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_hash_migrations_new ON hash_migrations(workspace_id, new_hash)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_advisories_package ON advisories(ecosystem, package_name)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_advisories_advisory_id ON advisories(advisory_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_cost_project ON scan_cost_records(workspace_id, project, branch)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_trigger_ws ON scan_trigger_policy(workspace_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iast_sessions_ws ON iast_sessions(workspace_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iast_sessions_app ON iast_sessions(app_name, agent_id)")
        # 2026-08-24 探针挂载端口持久化：用户在「Register IAST target」表单填写，
        # 挂载命令据此生成 -Dserver.port=PORT，避免目标项目随机跳端口。
        try:
            connection.execute("ALTER TABLE iast_sessions ADD COLUMN server_port INTEGER NOT NULL DEFAULT 8899")
        except Exception:
            pass  # 列已存在则忽略
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iast_events_canary ON iast_events(workspace_id, canary)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iast_events_session ON iast_events(session_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iast_events_sink ON iast_events(workspace_id, sink_file, sink_line)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iast_events_task ON iast_events(task_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_trigger_specs_hash ON trigger_specs(workspace_id, vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_trigger_specs_session ON trigger_specs(session_id)")
        # 2026-10-24（upsert 前置）：唯一键 (task_id, vulnerability_hash_v2)。
        # 背景：闭环二次回灌是「先 DELETE 整表再 INSERT」，spec id 全变 ⇒ replay_attempts.spec_id
        # 49% 变成孤儿（458 实测 652/1339），verification_status 也被清空导致整轮重放。
        # 改为 upsert 后 id 稳定，孤儿归零。建唯一索引前必须先消除历史重复（老库 run 364 有 25 组）。
        try:
            _dups = connection.execute(
                "SELECT task_id, vulnerability_hash_v2, COUNT(*) AS c FROM trigger_specs "
                "GROUP BY 1, 2 HAVING COUNT(*) > 1").fetchall()
            if _dups:
                # 只对重复组做小范围清理（组数极少：老库仅 25 组）。
                # 早期版本用「全表自连接 + 相关子查询」删除，在 59k 行上退化为 O(n²)，
                # 把后端启动拖死过一次（2026-10-24 实测）。这里改为逐组取 id 列表、保留最大 id。
                _removed = 0
                for _row in _dups:
                    try:
                        _tid, _vh = _row["task_id"], _row["vulnerability_hash_v2"]
                    except Exception:
                        _tid, _vh = tuple(_row)[0], tuple(_row)[1]
                    _ids = [int(r[0]) for r in connection.execute(
                        "SELECT id FROM trigger_specs WHERE task_id=? AND vulnerability_hash_v2=? "
                        "ORDER BY id DESC", (_tid, _vh)).fetchall()]
                    for _sid in _ids[1:]:
                        connection.execute("DELETE FROM trigger_specs WHERE id=?", (_sid,))
                        _removed += 1
                connection.commit()
                logger.warning("[db] trigger_specs 去重 %d 组、删除 %d 行（保留最大 id），用于建立唯一索引",
                               len(_dups), _removed)
        except Exception as _dd_exc:  # noqa: BLE001
            logger.warning("[db] trigger_specs 去重失败（跳过唯一索引）：%s", _dd_exc)
        try:
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_trigger_specs_task_vhash "
                "ON trigger_specs(task_id, vulnerability_hash_v2)")
        except Exception as _ux_exc:  # noqa: BLE001
            logger.warning("[db] 唯一索引 ux_trigger_specs_task_vhash 创建失败（不影响运行）：%s", _ux_exc)
        # 2026-10-23（观察层）：每次 D1 重放一行「请求 + 响应 + 判定输入」。
        # 背景：此前响应证据只落在 19MB 的报告 JSON 里（dast_impact_evidence），
        # 跨轮不可查、LLM 判因读不到；I2 只能靠规则表猜「是 payload 被拦还是打法错」。
        # 本表是「可观察的响应」的结构化落点，供 i2 判因、闭环定向重放、净化器知识复用。
        connection.execute(
            "CREATE TABLE IF NOT EXISTS replay_attempts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "task_id INTEGER NOT NULL,"
            "workspace_id INTEGER NOT NULL DEFAULT 0,"
            "spec_id INTEGER,"
            "vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',"
            "attempt_no INTEGER NOT NULL DEFAULT 1,"
            "family TEXT NOT NULL DEFAULT '',"
            "target_endpoint TEXT NOT NULL DEFAULT '',"
            "http_method TEXT NOT NULL DEFAULT 'GET',"
            "param_name TEXT NOT NULL DEFAULT '',"
            "param_location TEXT NOT NULL DEFAULT 'query',"
            "payload TEXT NOT NULL DEFAULT '',"
            "encoding TEXT NOT NULL DEFAULT '',"
            "content_type TEXT NOT NULL DEFAULT '',"
            "extra_headers_json TEXT NOT NULL DEFAULT '{}',"
            "status_code INTEGER,"
            "resp_headers_digest TEXT NOT NULL DEFAULT '',"
            "resp_body_head TEXT NOT NULL DEFAULT '',"
            "resp_body_len INTEGER NOT NULL DEFAULT 0,"
            "elapsed_ms INTEGER NOT NULL DEFAULT 0,"
            "waf_blocked INTEGER NOT NULL DEFAULT 0,"
            "read_state TEXT NOT NULL DEFAULT '',"
            "iast_state TEXT NOT NULL DEFAULT '',"
            "verdict TEXT NOT NULL DEFAULT '',"
            "reason TEXT NOT NULL DEFAULT '',"
            "action_json TEXT NOT NULL DEFAULT '{}',"
            "created_at TEXT NOT NULL"
            ")"
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_replay_attempts_task ON replay_attempts(task_id, spec_id, attempt_no)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_replay_attempts_hash ON replay_attempts(vulnerability_hash_v2)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_replay_attempts_created ON replay_attempts(task_id, created_at)")
        # 2026-10-25（plan §19.1 / 20.4.1，探索图 + 单步意图）：I2 判因不再只产 reason 文本，
        # 而是产出结构化 intent 记录；下一轮 A2 只注入意图摘要（状态外置），确定性检查回写 status。
        connection.execute(
            "CREATE TABLE IF NOT EXISTS replay_intents ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "task_id INTEGER NOT NULL,"
            "workspace_id INTEGER NOT NULL DEFAULT 0,"
            "spec_id INTEGER,"
            "vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',"
            "round_no INTEGER NOT NULL DEFAULT 1,"
            "target_endpoint TEXT NOT NULL DEFAULT '',"
            "http_method TEXT NOT NULL DEFAULT 'GET',"
            "param_name TEXT NOT NULL DEFAULT '',"
            "param_location TEXT NOT NULL DEFAULT 'query',"
            "action TEXT NOT NULL DEFAULT '',"
            "payload_hint TEXT NOT NULL DEFAULT '',"
            "encoding_hint TEXT NOT NULL DEFAULT '',"
            "header_hint TEXT NOT NULL DEFAULT '',"
            "rationale TEXT NOT NULL DEFAULT '',"
            "priority INTEGER NOT NULL DEFAULT 0,"
            "status TEXT NOT NULL DEFAULT 'pending',"
            "evidence_ref TEXT NOT NULL DEFAULT '',"
            "created_at TEXT NOT NULL,"
            "updated_at TEXT NOT NULL)"
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_replay_intents_task ON replay_intents(task_id, spec_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_replay_intents_pending ON replay_intents(task_id, status, priority)")
        # 2026-10-25（plan §20.5.1，决策缓存）：代码片段指纹 + 族 → 判定结果，跨任务复用。
        # Benchmark 模板化代码多，同一段净化器/注入点在多个 task 里重复，缓存可跳过重复 LLM 判别。
        connection.execute(
            "CREATE TABLE IF NOT EXISTS decision_cache ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "code_hash TEXT NOT NULL DEFAULT '',"
            "family TEXT NOT NULL DEFAULT '',"
            "verdict TEXT NOT NULL DEFAULT '',"
            "spec_json TEXT NOT NULL DEFAULT '{}',"
            "confidence REAL NOT NULL DEFAULT 0.0,"
            "source TEXT NOT NULL DEFAULT '',"
            "created_at TEXT NOT NULL)"
        )
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_decision_cache_key ON decision_cache(code_hash, family)")
        # 2026-08-25 重命名：iast_trigger_specs -> trigger_specs（该表实为 A2 预测 poc 假说，非 IAST 专属）。
        # 仅在旧表存在时执行；全新库已是 trigger_specs，ALTER 会失败，忽略即可。
        try:
            connection.execute("ALTER TABLE iast_trigger_specs RENAME TO trigger_specs")
        except Exception:
            pass
        # 旧表 session_id 为 NOT NULL，放宽以便 A2 阶段（会话未挂载时）也能登记。
        # 仅对「旧表 session_id 为 NOT NULL」的历史库执行重建；全新库 base schema 已是 nullable，
        # 直接跳过——否则每次初始化都 DROP/RENAME 会把 ensure_column 后续新增的列（如 poc_chain_json）
        # 一并抹掉，导致 register_trigger_spec 插入失败、trigger_specs 登记静默归零。
        _ts_cols = {r["name"]: r["notnull"] for r in connection.execute("PRAGMA table_info(trigger_specs)").fetchall()}
        if _ts_cols.get("session_id", 0) == 1:  # notnull == 1 表示旧表
            try:
                connection.execute(
                    "CREATE TABLE trigger_specs_new ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id INTEGER NOT NULL, "
                    "session_id INTEGER, task_id INTEGER, finding_id INTEGER, "
                    "vulnerability_hash_v2 TEXT NOT NULL DEFAULT '', family TEXT NOT NULL DEFAULT '', "
                    "target_endpoint TEXT NOT NULL DEFAULT '', http_method TEXT NOT NULL DEFAULT 'GET', "
                    "param_name TEXT NOT NULL DEFAULT '', param_name_source TEXT NOT NULL DEFAULT 'unknown', param_location TEXT NOT NULL DEFAULT 'query', "
                    "content_type TEXT NOT NULL DEFAULT '', principal TEXT NOT NULL DEFAULT '', "
                    "taint_marker TEXT NOT NULL DEFAULT '', expected_sink_file TEXT NOT NULL DEFAULT '', "
                    "expected_sink_line INTEGER NOT NULL DEFAULT 0, "
                    "representative_request_params_json TEXT NOT NULL DEFAULT '{}', raw_json TEXT NOT NULL DEFAULT '{}', "
                    "poc_chain_json TEXT NOT NULL DEFAULT '{}', "
                    "category TEXT NOT NULL DEFAULT '', business_logic_category TEXT NOT NULL DEFAULT '', attack_payloads_json TEXT NOT NULL DEFAULT '[]', "
                    "accounts_json TEXT NOT NULL DEFAULT '[]', victim_resource_id TEXT NOT NULL DEFAULT '', "
                    "victim_identifiers TEXT NOT NULL DEFAULT '[]', "
                    "auth_binding_json TEXT NOT NULL DEFAULT '{}', business_logic_confirmed INTEGER NOT NULL DEFAULT 0, verification_status TEXT NOT NULL DEFAULT '', iast_state TEXT NOT NULL DEFAULT '', bypass_state TEXT NOT NULL DEFAULT '', bypass_reason TEXT NOT NULL DEFAULT '', filter_spec_json TEXT NOT NULL DEFAULT '{}', "
                    "failure_attribution TEXT NOT NULL DEFAULT '', failure_attribution_reason TEXT NOT NULL DEFAULT '', "
                    "created_at TEXT NOT NULL, "
                    "FOREIGN KEY(session_id) REFERENCES iast_sessions(id) ON DELETE CASCADE, "
                    "FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE)"
                )
                connection.execute(
                    "INSERT INTO trigger_specs_new (id, workspace_id, session_id, task_id, finding_id, "
                    "vulnerability_hash_v2, family, target_endpoint, http_method, param_name, param_name_source, param_location, "
                    "content_type, principal, taint_marker, expected_sink_file, expected_sink_line, "
                    "representative_request_params_json, raw_json, poc_chain_json, "
                    "category, business_logic_category, attack_payloads_json, accounts_json, victim_resource_id, victim_identifiers, auth_binding_json, business_logic_confirmed, verification_status, iast_state, bypass_state, bypass_reason, filter_spec_json, failure_attribution, failure_attribution_reason, created_at) "
                    "SELECT id, workspace_id, session_id, task_id, finding_id, vulnerability_hash_v2, family, "
                    "target_endpoint, http_method, param_name, param_name_source, param_location, content_type, principal, "
                    "taint_marker, expected_sink_file, expected_sink_line, "
                    "representative_request_params_json, raw_json, poc_chain_json, "
                    "category, business_logic_category, attack_payloads_json, accounts_json, victim_resource_id, victim_identifiers, auth_binding_json, business_logic_confirmed, verification_status, iast_state, bypass_state, bypass_reason, filter_spec_json, created_at FROM trigger_specs"
                )
                connection.execute("DROP TABLE trigger_specs")
                connection.execute("ALTER TABLE trigger_specs_new RENAME TO trigger_specs")
            except Exception:
                pass
        # 2026-09-01：iast_request_params 随「运行时观测请求面」链路一并移除，老库残留表在此清理。
        try:
            connection.execute("DROP TABLE IF EXISTS iast_request_params")
        except Exception:
            pass
        # Record applied schema migration versions (versioned, idempotent).
        for version in ("2026-07-15-autonomy-entry-eval-audit", "2026-07-15-fix-feedback", "2026-07-15-eval-passk-matrix", "2026-07-15-taint-rule-candidates", "2026-07-15-hash-migrations", "2026-07-15-sca-advisories", "2026-07-15-cost-ops"):
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, datetime.utcnow().isoformat()),
            )

    def execute(
        self,
        sql: str,
        params: Iterable[Any] = (),
        *,
        fetchone: bool = False,
        fetchall: bool = False,
        return_rowcount: bool = False,
    ) -> Optional[Any]:
        last_exc: Optional[BaseException] = None
        for _attempt in range(_LOCK_RETRY_ATTEMPTS):
            try:
                with self._lock, self.connect() as connection:
                    cursor = connection.execute(sql, tuple(params))
                    connection.commit()
                    if fetchone:
                        return cursor.fetchone()
                    if fetchall:
                        return cursor.fetchall()
                    if return_rowcount:
                        return cursor.rowcount
                    return None
            except sqlite3.OperationalError as _exc:
                if not _is_lock_error(_exc) or _attempt == _LOCK_RETRY_ATTEMPTS - 1:
                    raise
                last_exc = _exc
                time.sleep(_LOCK_RETRY_BASE_DELAY * (2 ** _attempt))
        raise last_exc  # pragma: no cover - 循环必定 return 或 raise

    def executemany(
        self,
        sql: str,
        seq_params: Iterable[Iterable[Any]],
        *,
        return_rowcount: bool = False,
    ) -> Optional[Any]:
        """批量执行（单事务）。item 4 方向 1：把 ingest_events 的逐条提交改为攒批落库，

        事务数从「每条 1 个」降到「每批 1 个」，fsync / 锁开销同比例下降。
        SQLite 单写者约束下，调用方须自行串行化并发写（IastService 用 _INGEST_FLUSH_LOCK）。
        """
        # 同 execute：对锁类错误退避重试。批量写（findings 重写）单次代价大，重试次数收敛为 3。
        last_exc: Optional[BaseException] = None
        for _attempt in range(3):
            try:
                with self._lock, self.connect() as connection:
                    cursor = connection.executemany(sql, [tuple(p) for p in seq_params])
                    connection.commit()
                    if return_rowcount:
                        return cursor.rowcount
                    return None
            except sqlite3.OperationalError as _exc:
                if not _is_lock_error(_exc) or _attempt == 2:
                    raise
                last_exc = _exc
                time.sleep(_LOCK_RETRY_BASE_DELAY * (2 ** _attempt))
        raise last_exc  # pragma: no cover - 循环必定 return 或 raise

    @staticmethod
    def dumps(value: Any) -> str:
        return json.dumps({} if value is None else value, ensure_ascii=False)

    @staticmethod
    def loads(value: Optional[str]) -> Any:
        if not value:
            return {}
        loaded = json.loads(value)
        return {} if loaded is None else loaded
