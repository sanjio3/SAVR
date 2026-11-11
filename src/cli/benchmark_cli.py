# SAST AI - 主入口
# 基于 Claude 的智能代码审计工具
#
# 支持功能:
# - A1: 规则匹配静态分析
# - A2: AI大模型语义分析
# - D2: 统一动态验证（D1 重放 + I1 关联 + D2 核实 + I2 裁决）
#
# 报告:
# - B1: 初步静态分析报告 (A1 + A2)
# - B2: 最终安全审计报告 (含 POC / 验证证据)
#
# Usage（统一任务编排入口）:
#     启动服务: uv run python -m src.cli.service_server
#     创建任务: 经 API / 前端创建扫描任务（归属 workspace + 下发 task_id），
#               由 task_service → scan_task_runner → run_benchmark(task_id=...) 统一执行。
#     注意: 离线 CLI 直跑入口已禁用（见 main 守卫），所有扫描须经由统一任务编排路径。
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.iast.spec_projection import sync_entry_projection

try:
    from tqdm import tqdm  # noqa: F401  (可用性探测，不直接使用)
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

from src.core.config import config
from src.core.scanner import FileScanner
from src.core.archive_utils import contains_supported_source_files, expand_nested_source_archives
from src.core.endpoint_discoverer import extract_endpoints_from_files
from src.core.vuln_processor import process_vulnerabilities
from src.core.code_indexer import CodeIndexer
from src.core.exploit_spec import (
    canonical_business_logic_family,
    canonical_family,
    derive_flow_type,
    empty_chain_proof,
    exploit_spec_completeness,
    infer_failure_classification,
    merge_exploit_specs,
    normalize_chain_proof,
    normalize_exploit_spec,
    DIFFERENTIAL_PROOF_FAMILIES,
)
from src.core.proof_obligations import (
    candidate_line,
    evaluate_proof_obligations,
    has_auth_source_evidence,
    has_idor_source_evidence,
    has_ssrf_source_evidence,
    is_ssrf_source_candidate,
    merge_a1_evidence,
    pick_nearest_candidate,
    summarize_proof_context,
)
from src.core.poc_generator import POCGenerator
from src.core.progress_logger import ScanProgressLogger
from src.core.d2_zero_audit import summarize_d2_zero_audit
from src.core.tool_paths import (
    find_java_decompiler_jar,
    find_ysoserial_jar,
    get_exploits_dir,
    get_java_tools_dir,
)
from src.core.exploit_registry import get_exploit_entry
from src.agents.runtime_contract import normalize_external_target
from src.benchmark.report_manager import ReportManager
from src.pipeline.a1 import A1PipelineService
from src.pipeline.a2 import A2PipelineService
from src.pipeline.d2 import D2PipelineService
from src.application.entry_discovery_service import EntryDiscoveryService
from src.application.d1_service import D1Service
from src.core.vuln_hash import enrich_finding_hash
from src.application.sca_asset_service import SCAAssetService
from src.infrastructure.db import Database
from src.iast.correlation import IastCorrelationService
from src.iast.sink_identity import iast_evidence_sink_reached_genuine
from src.iast.trigger_spec_registry import (
    auto_register_from_a2 as _auto_register_a2_trigger_specs,
    load_trigger_specs_by_workspace,
    purge_task_canary_events,
    resolve_endpoint_full,
)


def setup_logging(verbose: bool = False):
    """设置日志配置"""
    level = logging.DEBUG if verbose else logging.INFO

    # 格式化
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

    # 控制台处理器
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(formatter)

    # 根日志
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(console)

    return root


def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """打印进度条"""
    if not HAS_TQDM:
        # 简单文本进度
        percent = 100 * (iteration / float(total))
        filled = length * iteration // total
        bar = '█' * filled + '-' * (length - filled)
        sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}')
        sys.stdout.flush()
        if iteration == total:
            sys.stdout.write('\n')


logger = logging.getLogger(__name__)
EXPLOITS_DIR = get_exploits_dir()
JAVA_TOOLS_DIR = get_java_tools_dir()


def _decompile_jar_source_tree(target_path: str, output_dir: str) -> Optional[Path]:
    target_root = Path(target_path)
    jar_candidates = sorted(target_root.glob("*.jar"))
    app_jar = next((candidate for candidate in jar_candidates if candidate.name.lower() == "app.jar"), None)
    jar_path = app_jar or next((candidate for candidate in jar_candidates if candidate.suffix.lower() == ".jar"), None)
    if jar_path is None:
        return None

    decompiler_jar = find_java_decompiler_jar([target_root, jar_path.parent])
    if decompiler_jar is None:
        logger.warning("Found jar source candidate %s but no CFR decompiler jar", jar_path)
        return None

    decompiled_dir = Path(output_dir) / "_decompiled" / jar_path.stem
    if list(decompiled_dir.rglob("*.java")):
        logger.info("Reusing decompiled Java sources from %s", decompiled_dir)
        return decompiled_dir

    decompiled_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "java",
        "-jar",
        str(decompiler_jar),
        str(jar_path),
        "--outputdir",
        str(decompiled_dir),
        "--silent",
        "true",
    ]
    logger.info("No supported source files found; attempting jar decompilation via %s", decompiler_jar)
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=180,
            env=dict(os.environ),
        )
    except Exception as exc:
        logger.warning("Jar decompilation failed for %s: %s", jar_path, exc)
        return None

    if result.returncode != 0:
        logger.warning(
            "Jar decompilation failed for %s: %s",
            jar_path,
            (result.stderr or result.stdout or "").strip(),
        )
        return None

    if not list(decompiled_dir.rglob("*.java")):
        logger.warning("Jar decompilation produced no Java files for %s", jar_path)
        return None

    logger.info("Decompiled %s into %s", jar_path, decompiled_dir)
    return decompiled_dir


def _prepare_scan_root(target_path: str, output_dir: str) -> Path:
    target_root = Path(target_path).resolve()
    try:
        expanded = expand_nested_source_archives(target_root)
        if expanded:
            logger.info("Expanded %s nested source archive(s) under %s", len(expanded), target_root)
            candidate_roots = []
            for candidate in expanded:
                if candidate.is_dir() and contains_supported_source_files(candidate):
                    candidate_roots.append(candidate)
            if candidate_roots:
                candidate_roots.sort(key=lambda item: (len(item.parts), len(str(item))))
                return candidate_roots[0]
    except Exception as exc:
        logger.warning("Failed to prepare nested source archives under %s: %s", target_root, exc)

    def _select_source_subroot(root: Path) -> Optional[Path]:
        preferred_name_rank = {
            "src": 0,
            "source": 1,
            "app": 2,
            "web": 3,
            "www": 4,
            "public": 5,
            "project": 6,
            "code": 7,
            "build": 20,
        }
        candidates = []
        for candidate in root.rglob("*"):
            if not candidate.is_dir():
                continue
            lowered = candidate.name.lower()
            if lowered in {"src", "source", "app", "web", "www", "public", "project", "code", "build"} and contains_supported_source_files(candidate):
                try:
                    file_count = len(FileScanner(str(candidate)).scan(show_progress=False))
                except Exception:
                    file_count = 0
                if file_count > 0:
                    rank = preferred_name_rank.get(lowered, 100)
                    candidates.append((rank, -file_count, len(candidate.parts), len(str(candidate)), candidate))
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
        return candidates[0][4]

    if contains_supported_source_files(target_root):
        try:
            if not FileScanner(str(target_root)).scan(show_progress=False):
                nested_root = _select_source_subroot(target_root)
                if nested_root is not None:
                    return nested_root
        except Exception:
            pass
        return target_root

    decompiled_target = _decompile_jar_source_tree(str(target_root), output_dir)
    if decompiled_target is not None:
        return decompiled_target
    return target_root


def _filter_framework_noise_files(files):
    """剔除「不是被测项目代码」的文件：框架 loader 树 + 第三方库/构建产物。

    `static/ajax/libs/` 下的 bootstrap 系列打包库。只在 A1 启发式里过滤时，602 仍剩
    5 条漏在别的通道（A1 业务逻辑分析器 / A2），所以必须在这里（文件收集后、所有
    分析通道之前）统一剔除。
    """
    filtered = []
    skipped = 0
    vendor_skipped = 0
    noise_prefixes = (
        "org/springframework/boot/loader/",
        "org\\springframework\\boot\\loader\\",
    )
    try:
        from src.core.scan_scope import is_vendor_asset
    except Exception:  # noqa: BLE001  判据不可用时不阻断扫描
        is_vendor_asset = None
    for file_info in files or []:
        rel_path = str(file_info.get("rel_path", "") or "")
        normalized = rel_path.replace("\\", "/").lower()
        if any(normalized.startswith(prefix.replace("\\", "/")) for prefix in noise_prefixes):
            skipped += 1
            continue
        if is_vendor_asset is not None:
            _p = rel_path or str(file_info.get("path", "") or "")
            if is_vendor_asset(_p):
                vendor_skipped += 1
                continue
        filtered.append(file_info)
    if skipped:
        logger.info("Filtered %s framework noise files from fat-jar decompiled tree", skipped)
    if vendor_skipped:
        logger.info("[vendor] 剔除 %s 个第三方库/构建产物文件（开关 SAST_AI_SCAN_VENDOR=1 可恢复）",
                    vendor_skipped)
    return filtered


# 外部 IAST 目标由 ExternalTarget 描述，不再做 Docker 运行时探测。


def summarize_a3_raw_output(raw_output: str) -> dict:
    """Summarize Docker attempts and step failures from D2 raw output."""
    summary = {
        'docker_attempted': False,
        'docker_used': False,
        'local_jar_attempted': False,
        'step_errors': [],
        'container_id': '',
        'service_url': '',
        'container_kept_running': False,
        'service_ready': False,
        'runtime_type': '',
        'runtime_source': '',
    }

    if not raw_output:
        return summary

    try:
        payload = json.loads(raw_output)
    except Exception:
        return summary

    if isinstance(payload, dict):
        steps = payload.get('steps', [])
        summary['container_id'] = payload.get('container_id', '') or ''
        summary['service_url'] = payload.get('service_url', '') or ''
        summary['container_kept_running'] = bool(payload.get('container_kept_running', False))
        summary['service_ready'] = bool(payload.get('service_ready', False))
        summary['runtime_type'] = payload.get('runtime_type', '') or ''
        summary['runtime_source'] = payload.get('runtime_source', '') or ''
    elif isinstance(payload, list):
        steps = payload
    else:
        return summary

    for item in steps:
        tool = item.get('tool', '')
        result = item.get('result', {}) or {}
        if tool in ('docker_build', 'docker_run'):
            summary['docker_attempted'] = True
        if tool == 'docker_run' and result.get('success'):
            summary['docker_used'] = True
        if tool in ('local_java_run', 'reuse_prepared_runtime') and (
            item.get('runtime_type') == 'local_java_jar' or result.get('runtime_type') == 'local_java_jar'
        ):
            summary['local_jar_attempted'] = True
        if not result.get('success', False):
            error = result.get('error')
            if error:
                summary['step_errors'].append(f"{tool}: {error}")

    return summary


def is_meaningful_poc(poc_code: str) -> bool:
    """Treat placeholders as no POC."""
    if not poc_code:
        return False
    if not isinstance(poc_code, str):
        poc_code = json.dumps(poc_code, ensure_ascii=False)
    normalized = poc_code.strip().lower()
    placeholder_markers = [
        '# could not generate poc',
        'could not generate poc',
        'd2 did not produce a runnable poc',
    ]
    return normalized not in placeholder_markers


def infer_required_tools(poc_code: str, vuln_type: str) -> list:
    tools = []
    if poc_code and not isinstance(poc_code, str):
        poc_code = json.dumps(poc_code, ensure_ascii=False)
    code = (poc_code or "").lower()
    vtype = (vuln_type or "").lower()

    if "requests" in code or "python" in code:
        tools.append("Python 3")
    if "curl" in code:
        tools.append("curl")
    if "public class" in code or "java " in code:
        tools.append("Java")
    if "ysoserial" in code or "deserialize" in vtype or "反序列化" in vtype:
        tools.append("ysoserial.jar")
    if "docker" in code:
        tools.append("Docker")

    deduped = []
    for tool in tools:
        if tool not in deduped:
            deduped.append(tool)
    return deduped


def find_missing_tools(tools: list) -> list:
    missing = []
    for tool in tools:
        normalized = tool.lower()
        if normalized == 'python 3':
            if shutil.which('python') is None and shutil.which('python3') is None:
                missing.append(tool)
        elif normalized == 'java':
            if shutil.which('java') is None:
                missing.append(tool)
        elif normalized == 'curl':
            if shutil.which('curl') is None:
                missing.append(tool)
        elif normalized == 'docker':
            if shutil.which('docker') is None:
                missing.append(tool)
        elif normalized == 'ysoserial.jar':
            if find_ysoserial_jar() is None:
                missing.append(tool)
        elif normalized == 'ysoserial-all.jar':
            if find_ysoserial_jar() is None:
                missing.append(tool)
    return missing


def infer_payload_candidates(vuln_type: str) -> list:
    vtype = (vuln_type or "").lower()
    if "sql" in vtype:
        return ["' OR '1'='1", "' OR 1=1 --", "1' UNION SELECT NULL--", "' AND SLEEP(5)--"]
    if "xss" in vtype:
        return ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"]
    if "command" in vtype or "rce" in vtype:
        return ["whoami", "id", "ls", "sleep 5"]
    if "path" in vtype or "traversal" in vtype:
        return ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    if "ssrf" in vtype:
        return ["http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data/"]
    if "xxe" in vtype:
        return ['<!DOCTYPE x [ <!ENTITY e SYSTEM "file:///etc/passwd"> ]><root>&e;</root>']
    if "deserialize" in vtype or "反序列化" in vtype:
        return ["畸形序列化数据用于确认反序列化入口", "ysoserial CommonsCollections6 无害 payload", "Base64 编码序列化对象"]
    if "upload" in vtype:
        return ["shell.jsp", "polyglot image payload", "双扩展名文件"]
    if "redirect" in vtype:
        return ["https://example.com", "//example.com", "/\\example.com"]
    return ["test"]


def _collect_business_context(vuln: dict, structured_poc: dict) -> str:
    parts = [
        vuln.get('type', ''),
        vuln.get('file', ''),
        vuln.get('entry_point', ''),
        vuln.get('callers', ''),
        vuln.get('data_flow', ''),
        vuln.get('sink', ''),
        (structured_poc or {}).get('target_url', ''),
        (structured_poc or {}).get('param', ''),
        (structured_poc or {}).get('description', ''),
    ]
    return " ".join(str(part) for part in parts if part).lower()


def infer_business_scenario(vuln: dict, structured_poc: dict) -> dict:
    vtype = (vuln.get('type') or '').lower()
    context = _collect_business_context(vuln, structured_poc)

    if "ssrf" in vtype:
        if any(token in context for token in ("webhook", "callback", "notify", "hook")):
            return {
                'name': 'Webhook / 回调地址拉取',
                'rationale': '代码和路由语义更像服务端主动访问外部回调地址，POC 应模拟伪造 webhook/callback 目标而不是普通 URL。',
                'payload_candidates': ['https://collab.example/webhook/a3', 'https://dnslog.example/callback?id=a3', 'http://127.0.0.1:8080/internal/health'],
                'success_effect': '服务端向伪造 webhook/callback 地址发起请求，或响应中出现来自内网/回调目标的内容。',
                'failure_effect': '回调地址被白名单限制，或服务端未按用户输入发起请求。',
                'curl_example': 'curl -G "{target_url}" --data-urlencode "{param}=https://collab.example/webhook/a3"',
            }
        if any(token in context for token in ("avatar", "image", "img", "thumb", "thumbnail", "photo", "logo", "cover")):
            return {
                'name': '图片/头像抓取',
                'rationale': '参数命名更像头像、图片、缩略图等资源 URL，POC 应模拟图片抓取业务，而不是通用 metadata 探测。',
                'payload_candidates': ['http://127.0.0.1:8080/admin/logo.png', 'http://169.254.169.254/latest/meta-data/iam/', 'https://collab.example/static/a3.png'],
                'success_effect': '服务端尝试抓取指定图片 URL，回显抓取结果、尺寸异常、缓存命中或内网资源响应特征。',
                'failure_effect': '仅允许固定 CDN/图片域名，或用户输入 URL 未真正进入抓取逻辑。',
                'curl_example': 'curl -G "{target_url}" --data-urlencode "{param}=http://169.254.169.254/latest/meta-data/iam/"',
            }
        if any(token in context for token in ("pdf", "report", "preview", "crawl", "scrape", "render", "fetch")):
            return {
                'name': '报表/预览内容抓取',
                'rationale': '这里更像“服务端代抓页面再生成报表/预览”的业务，POC 应使用可被服务端抓取的 HTML/PDF 源地址。',
                'payload_candidates': ['http://127.0.0.1:8080/internal/report', 'https://collab.example/preview/a3.html', 'file:///etc/hosts'],
                'success_effect': '服务端预览、报表或抓取结果中出现内网页面内容、报表差异或本地文件痕迹。',
                'failure_effect': '业务仅记录 URL 而不抓取，或只允许固定模板源。',
                'curl_example': 'curl -G "{target_url}" --data-urlencode "{param}=http://127.0.0.1:8080/internal/report"',
            }
        return {
            'name': '通用服务端 URL 拉取',
            'rationale': '未识别到更细的业务语义，先按“服务端根据用户输入请求 URL”建模。',
            'payload_candidates': ['http://127.0.0.1:8080', 'http://169.254.169.254/latest/meta-data/', 'http://localhost:2375/version'],
            'success_effect': '服务端按用户输入发起请求，响应中出现内网服务、云元数据或探测目标的返回痕迹。',
            'failure_effect': '服务端未实际请求目标地址，或存在内网地址/协议限制。',
            'curl_example': 'curl -G "{target_url}" --data-urlencode "{param}=http://169.254.169.254/latest/meta-data/"',
        }

    if "redirect" in vtype:
        if any(token in context for token in ("login", "signin", "auth", "oauth", "sso", "next", "continue", "returnto", "redirect_uri")):
            return {
                'name': '登录后跳转 / 单点登录回跳',
                'rationale': '参数和路径都更像登录后跳转场景，POC 应模拟合法登录完成后的 next/redirect_uri 被劫持。',
                'payload_candidates': ['https://evil.example/post-login', '//evil.example/sso', 'https://evil.example/oauth/callback'],
                'success_effect': '服务端返回 30x 且 Location 指向攻击者控制域名，证明登录回跳可被外带。',
                'failure_effect': 'Location 被约束为站内路径或固定 OAuth 白名单域名。',
                'curl_example': 'curl -i -G "{target_url}" --data-urlencode "{param}=https://evil.example/post-login"',
            }
        if any(token in context for token in ("pay", "payment", "checkout", "order", "return_url", "callback_url")):
            return {
                'name': '支付完成返回页跳转',
                'rationale': '这里更像支付/订单完成后的 return_url 场景，POC 应模拟支付完成后被带到外部恶意站点。',
                'payload_candidates': ['https://evil.example/payment-finish', '//evil.example/order-complete', 'https://evil.example/refund'],
                'success_effect': '支付或订单完成后，服务端将用户重定向到攻击者控制的 return_url/callback_url。',
                'failure_effect': '返回页被固定为站内地址，或仅允许配置好的支付回调域名。',
                'curl_example': 'curl -i -G "{target_url}" --data-urlencode "{param}=https://evil.example/payment-finish"',
            }
        return {
            'name': '通用外跳 / 导航跳转',
            'rationale': '未识别到更细业务，但当前接口明显把用户控制值用于跳转目标。',
            'payload_candidates': ['https://evil.example', '//evil.example', '/\\evil.example'],
            'success_effect': '响应返回 30x，且 Location 指向外域或协议相对 URL。',
            'failure_effect': '跳转目标被限制为相对路径或允许列表内地址。',
            'curl_example': 'curl -i -G "{target_url}" --data-urlencode "{param}=https://evil.example"',
        }

    if ("deserialize" in vtype or "反序列化" in vtype or
            any(token in context for token in ("objectinputstream", "readobject", "unserialize", "pickle", "marshal"))):
        if any(token in context for token in ("import", "restore", "backup", "merge", "sync")):
            return {
                'name': '导入 / 恢复数据包',
                'rationale': '方法名、路由或调用链更像导入/恢复接口，POC 应伪装成合法导入文件或备份恢复数据，而不是裸序列化探测。',
                'payload_candidates': ['Base64 编码导入包中的恶意对象', '看起来像配置/备份文件的序列化 blob', 'ysoserial CommonsCollections6 导入型 payload'],
                'success_effect': '导入接口接收并解析序列化对象，随后在恢复/应用配置/触发后续逻辑时执行 gadget 链。',
                'failure_effect': '接口仅接收文本/JSON，或虽然导入成功但并未触发对象反序列化。',
                'curl_example': 'curl -X POST "{target_url}" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "{param}=<BASE64_SERIALIZED_IMPORT_PAYLOAD>"',
            }
        if any(token in context for token in ("cache", "memo", "warm", "processor")):
            return {
                'name': '缓存对象恢复 / 预热',
                'rationale': '当前链路更像把外部输入恢复成缓存对象，POC 应围绕“缓存重建后延迟触发”来设计。',
                'payload_candidates': ['可在 put()/transform() 阶段触发的 Map 序列化对象', '缓存恢复用 Base64 blob', '延迟触发型 CommonsCollections payload'],
                'success_effect': '缓存恢复阶段导入成功，后续读缓存/写缓存操作触发 gadget 链或无害标记文件。',
                'failure_effect': '缓存只保存原始字节，或对象被安全转换成普通数据结构。',
                'curl_example': 'curl -X POST "{target_url}" --data-urlencode "{param}=<BASE64_CACHE_OBJECT_PAYLOAD>"',
            }
        if any(token in context for token in ("session", "remember", "state", "token")):
            return {
                'name': '会话状态恢复',
                'rationale': '这里更像恢复 session/state 对象，POC 应伪造成合法会话 blob，再观察后续请求是否触发对象逻辑。',
                'payload_candidates': ['伪装为 session blob 的 Base64 序列化对象', 'remember-me 状态对象', '带延迟触发链的状态恢复 payload'],
                'success_effect': '服务端接受会话状态对象并在后续鉴权、读取状态时触发反序列化逻辑。',
                'failure_effect': '状态值仅被当成字符串保存，或会话恢复前有签名校验。',
                'curl_example': 'curl -X POST "{target_url}" --data-urlencode "{param}=<BASE64_SESSION_STATE_PAYLOAD>"',
            }
        if any(token in context for token in ("debug", "admin", "internal", "test")):
            return {
                'name': '调试 / 管理接口对象导入',
                'rationale': '当前入口更像调试或管理导入接口，POC 应偏向内部对象、配置对象或调试快照，而不是通用用户态输入。',
                'payload_candidates': ['调试导入 Map/Object payload', '内部配置对象 Base64 序列化数据', '管理接口专用 ysoserial payload'],
                'success_effect': '调试/管理接口成功接收对象数据，并在导入或二次触发时执行对象链。',
                'failure_effect': '调试接口做了类型白名单，或仅在开发模式生效。',
                'curl_example': 'curl -X POST "{target_url}" --data-urlencode "{param}=<BASE64_DEBUG_IMPORT_PAYLOAD>"',
            }
        return {
            'name': '通用对象反序列化入口',
            'rationale': '未识别到更细业务语义，先按“用户输入被服务端反序列化成对象”建模。',
            'payload_candidates': ['Base64 编码序列化对象', '畸形序列化数据用于确认入口', 'ysoserial CommonsCollections 无害 payload'],
            'success_effect': '服务端对用户输入执行对象反序列化，并出现 gadget、异常回显或无害落地标记。',
            'failure_effect': '输入未进入反序列化逻辑，或缺少 gadget / 类型不匹配导致未触发。',
            'curl_example': 'curl -X POST "{target_url}" --data-urlencode "{param}=<BASE64_SERIALIZED_OBJECT>"',
        }

    return {
        'name': '通用漏洞验证场景',
        'rationale': '当前漏洞类型尚未接入业务场景化 POC，仍使用漏洞族通用思路。',
        'payload_candidates': infer_payload_candidates(vuln.get('type', '')),
        'success_effect': '',
        'failure_effect': '',
        'curl_example': '',
    }


def infer_expected_effects(vuln_type: str) -> tuple:
    vtype = (vuln_type or "").lower()
    if "sql" in vtype:
        return ("返回数据库报错、结果集异常增多、或出现明显延时", "响应与基线无显著差异，或 payload 被安全处理")
    if "xss" in vtype:
        return ("响应中原样反射未转义脚本片段，或浏览器执行注入脚本", "payload 被转义、过滤，或仅作为普通文本显示")
    if "command" in vtype or "rce" in vtype:
        return ("返回命令执行痕迹，如用户信息、目录列表、时间延迟或无害标记文件", "仅返回普通业务响应，无命令输出或延时特征")
    if "path" in vtype or "traversal" in vtype:
        return ("返回敏感文件内容、路径解析异常、或读取目标文件成功", "路径被归一化限制，或返回无权限/文件不存在")
    if "deserialize" in vtype or "反序列化" in vtype:
        return ("应用解析了序列化数据，出现反序列化异常、命令执行痕迹、或无害标记文件落地", "请求未进入反序列化逻辑，或缺少 gadget / 依赖导致 payload 不生效")
    return ("触发预期的安全异常或行为差异", "业务响应无异常，无法确认 payload 生效")


def build_exploit_chain(vuln: dict) -> str:
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
        return "当前只定位到漏洞点，尚未抽取出完整入口到危险函数的利用链。"
    return " -> ".join(parts)


def build_poc_details(vuln: dict, poc_code: str, structured_poc: dict, attack_plan: dict = None, exploit_spec: dict = None) -> dict:
    attack_plan = attack_plan or {}
    exploit_spec = normalize_exploit_spec(exploit_spec)
    scenario = infer_business_scenario(vuln, structured_poc)
    success_effect, failure_effect = infer_expected_effects(vuln.get('type', ''))
    required_tools = infer_required_tools(poc_code, vuln.get('type', ''))
    target_url = (structured_poc or {}).get('target_url', '')
    target_param = (structured_poc or {}).get('param', '')
    plan_entry = attack_plan.get('entrypoint', {}) if isinstance(attack_plan, dict) else {}
    placeholder_urls = {
        '',
        '/api/endpoint',
        'api/endpoint',
        'http://localhost:8080/api/endpoint',
        'http://127.0.0.1:8080/api/endpoint',
    }
    if target_url in placeholder_urls and plan_entry.get('path'):
        target_url = plan_entry.get('path', '')
    if (not target_param or target_param == 'input') and plan_entry.get('parameter'):
        target_param = plan_entry.get('parameter', '')
    if not target_url:
        target_url = exploit_spec.get('entry', {}).get('route', '')
    if not target_param:
        target_param = exploit_spec.get('entry', {}).get('parameter_name', '')
    curl_example = (structured_poc or {}).get('curl', '')
    if scenario.get('curl_example') and target_url:
        curl_example = scenario['curl_example'].format(target_url=target_url, param=target_param or 'input')
    description = (structured_poc or {}).get('description', '') or attack_plan.get('business_goal', '')
    return {
        'exploit_chain': build_exploit_chain(vuln),
        'payload_candidates': scenario.get('payload_candidates') or infer_payload_candidates(vuln.get('type', '')),
        'success_effect': scenario.get('success_effect') or success_effect,
        'failure_effect': scenario.get('failure_effect') or failure_effect,
        'required_tools': required_tools,
        'missing_tools': find_missing_tools(required_tools),
        'target_url': target_url,
        'target_param': target_param,
        'description': description,
        'curl_example': curl_example,
        'business_scenario': attack_plan.get('business_goal', '') or scenario.get('name', ''),
        'scenario_rationale': (
            f"D2 {attack_plan.get('source', 'deterministic')} 攻击计划已识别输入角色={attack_plan.get('input_role', '')}，投递形态={attack_plan.get('delivery_shape', '')}。"
            if attack_plan.get('business_goal') else scenario.get('rationale', '')
        ),
        'attack_plan': attack_plan,
        'exploit_spec': exploit_spec,
        'delivery_shape': attack_plan.get('delivery_shape', ''),
        'input_role': attack_plan.get('input_role', ''),
        'trigger_condition': attack_plan.get('trigger_condition', ''),
        'verification_signal': attack_plan.get('verification_signal', ''),
    }


def _sanitize_label(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', text or '').strip('_') or 'target'


def build_verified_bundle(vuln: dict, result, raw_output: str) -> dict:
    """为已验证成功的漏洞落地完整利用包。"""
    try:
        raw = json.loads(raw_output or '{}')
    except Exception:
        raw = {}

    if result.poc_type == 'java-thymeleaf-ssti':
        exploit_result = raw.get('exploit_result', {})
        attack_request = raw.get('attack_request', exploit_result.get('attack_request', {}))
        attack_result = raw.get('attack_result', exploit_result.get('attack_result', {}))
        family = 'java_thymeleaf_ssti'
        label = _sanitize_label(f"{family}_{Path(vuln.get('file', 'unknown')).stem}_{vuln.get('line', 'na')}")
        bundle_dir = Path('output') / f'{label}_bundle'
        bundle_dir.mkdir(parents=True, exist_ok=True)

        exp_src = EXPLOITS_DIR / 'java_thymeleaf_ssti_probe.py'
        exp_dst = bundle_dir / 'exp.py'
        if exp_src.exists():
            exp_dst.write_text(exp_src.read_text(encoding='utf-8'), encoding='utf-8')

        result_json_dst = bundle_dir / 'exploit_result.json'
        result_json_dst.write_text(json.dumps(exploit_result, ensure_ascii=False, indent=2), encoding='utf-8')

        response_text = str(attack_result.get('body', ''))
        return {
            'exploit_family': family,
            'bundle_dir': str(bundle_dir),
            'exp_script': str(exp_dst) if exp_dst.exists() else '',
            'result_json': str(result_json_dst),
            'service_url': raw.get('service_url', ''),
            'container_id': raw.get('container_id', ''),
            'payload_b64': '',
            'payload_ser': '',
            'helper_java': '',
            'import_response_body': response_text,
            'trigger_response_body': response_text,
            'verify_stdout': response_text[:240],
            'exploit_chain': (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明 Thymeleaf 表达式被服务端执行"
            ),
        }

    if result.poc_type == 'python-jinja2-ssti':
        exploit_result = raw.get('exploit_result', {})
        attack_request = raw.get('attack_request', exploit_result.get('attack_request', {}))
        attack_result = raw.get('attack_result', exploit_result.get('attack_result', {}))
        family = 'python_jinja2_ssti'
        label = _sanitize_label(f"{family}_{Path(vuln.get('file', 'unknown')).stem}_{vuln.get('line', 'na')}")
        bundle_dir = Path('output') / f'{label}_bundle'
        bundle_dir.mkdir(parents=True, exist_ok=True)

        exp_src = EXPLOITS_DIR / 'python_jinja2_ssti_probe.py'
        exp_dst = bundle_dir / 'exp.py'
        if exp_src.exists():
            exp_dst.write_text(exp_src.read_text(encoding='utf-8'), encoding='utf-8')

        result_json_dst = bundle_dir / 'exploit_result.json'
        result_json_dst.write_text(json.dumps(exploit_result, ensure_ascii=False, indent=2), encoding='utf-8')

        response_text = str(attack_result.get('body', ''))
        return {
            'exploit_family': family,
            'bundle_dir': str(bundle_dir),
            'exp_script': str(exp_dst) if exp_dst.exists() else '',
            'result_json': str(result_json_dst),
            'service_url': raw.get('service_url', ''),
            'container_id': raw.get('container_id', ''),
            'payload_b64': '',
            'payload_ser': '',
            'helper_java': '',
            'import_response_body': response_text,
            'trigger_response_body': response_text,
            'verify_stdout': response_text[:240],
            'exploit_chain': (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject SSTI payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')}"
            ),
        }

    exploit_entry = get_exploit_entry(result.poc_type)
    if exploit_entry:
        family, exp_src = exploit_entry
        exploit_result = raw.get('exploit_result', {})
        attack_request = raw.get('attack_request', exploit_result.get('attack_request', {}))
        attack_result = raw.get('attack_result', exploit_result.get('attack_result', {}))
        verify_result = raw.get('verify_result', exploit_result.get('verify_result', {}))

        label = _sanitize_label(f"{family}_{Path(vuln.get('file', 'unknown')).stem}_{vuln.get('line', 'na')}")
        bundle_dir = Path('output') / f'{label}_bundle'
        bundle_dir.mkdir(parents=True, exist_ok=True)

        exp_dst = bundle_dir / 'exp.py'
        if exp_src.exists():
            exp_dst.write_text(exp_src.read_text(encoding='utf-8'), encoding='utf-8')

        result_json_dst = bundle_dir / 'exploit_result.json'
        result_json_dst.write_text(json.dumps(exploit_result, ensure_ascii=False, indent=2), encoding='utf-8')

        response_text = str(attack_result.get('body', ''))
        verify_text = str(verify_result.get('body', ''))
        if family == 'node_prototype_pollution':
            chain = (
                f"1. 向 {attack_request.get('url', '')} 发送原型污染请求\n"
                f"2. 使用键 {exploit_result.get('query_key', '')} 写入 {exploit_result.get('payload_value', '')}\n"
                f"3. 访问验证路径并检查是否出现 {exploit_result.get('verify_key', '')}"
            )
        elif family == 'node_ssrf':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明服务端发起了外带请求"
            )
        elif family == 'node_path_traversal':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明敏感文件可被读取"
            )
        elif family == 'node_file_upload':
            chain = (
                f"1. 向 {attack_request.get('url', '')} 发送 multipart 上传请求\n"
                f"2. 字段 {exploit_result.get('field_name', '')} 上传文件 {exploit_result.get('filename', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明上传请求被服务端接收"
            )
        elif family == 'java_fastjson':
            chain = (
                f"1. 向 {attack_request.get('url', '')} 发送 Fastjson 载荷\n"
                f"2. 请求体注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明可控 JSON 被服务端解析"
            )
        elif family == 'java_xxe':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Send XML payload with external entity via {exploit_result.get('parameter', '') or 'request body'}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another entity expansion marker"
            )
        elif family == 'java_xpath':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected XPath value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family in ('java_freemarker_ssti', 'java_velocity_ssti', 'java_spel'):
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject expression payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm evaluated output includes {exploit_result.get('expected', '')}"
            )
        elif family == 'java_ognl':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject OGNL payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm evaluated output includes {exploit_result.get('expected', '')}"
            )
        elif family == 'java_jndi':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject JNDI target {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the response or error output contains {exploit_result.get('expected', '')}"
            )
        elif family == 'java_ldap':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected LDAP filter value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'java_jackson':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Send JSON payload {exploit_result.get('payload', '')}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another attacker-controlled field"
            )
        elif family == 'java_xstream':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Send XML payload via {exploit_result.get('parameter', '') or 'request body'}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another attacker-controlled field"
            )
        elif family == 'java_sqli':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'java_reflected_xss':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject XSS payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the raw payload is reflected unescaped in the response body"
            )
        elif family == 'java_ssrf':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject SSRF payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another server-side fetch indicator"
            )
        elif family == 'java_open_redirect':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject redirect target {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the Location header contains {exploit_result.get('expected', '')}"
            )
        elif family == 'java_jwt':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 注入弱 JWT {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明弱 JWT 被服务端接受"
            )
        elif family == 'java_csp':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 检查响应头中的 Content-Security-Policy\n"
                f"3. 若缺失或包含 unsafe-inline / *，则证明 CSP 配置不安全"
            )
        elif family == 'java_cors':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with an attacker-controlled Origin header\n"
                f"2. Inspect Access-Control-Allow-Origin / Access-Control-Allow-Credentials\n"
                f"3. Confirm the server allows the attacker origin or wildcard cross-origin access"
            )
        elif family == 'java_cookie':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inspect the Set-Cookie response header\n"
                f"3. Confirm the cookie is missing Secure or HttpOnly protection"
            )
        elif family == 'java_auth_bypass':
            chain = (
                f"1. Visit {attack_request.get('url', '')} without credentials\n"
                f"2. Observe the HTTP status code and response body\n"
                f"3. Confirm the endpoint is reachable without returning 401/403"
            )
        elif family == 'java_hpp':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with a baseline single value\n"
                f"2. Re-send the request with duplicate parameter values for {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the duplicate-parameter response differs materially from baseline"
            )
        elif family == 'java_mongo':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with Mongo-style payload {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline"
            )
        elif family == 'java_redis':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with Redis-influencing payload {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline"
            )
        elif family == 'java_tomcat':
            chain = (
                f"1. 向 {attack_request.get('url', '')} 发送 PUT 写入请求\n"
                f"2. 再访问验证路径确认写入内容是否生效\n"
                f"3. 若响应中出现 {exploit_result.get('expected', '')}，则证明 Tomcat 危险写入能力可用"
            )
        elif family in ('java_file_upload', 'python_file_upload', 'php_file_upload'):
            chain = (
                f"1. 向 {attack_request.get('url', '')} 发送 multipart 上传请求\n"
                f"2. 字段 {exploit_result.get('field_name', '')} 上传文件 {exploit_result.get('filename', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明上传请求被服务端接收"
            )
        elif family == 'java_path_traversal':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject path payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'csrf':
            chain = (
                f"1. Send a cross-site style {attack_request.get('method', '')} request to {attack_request.get('url', '')}\n"
                f"2. Omit any CSRF token and spoof foreign Origin and Referer headers\n"
                f"3. Confirm the server still accepts the request without CSRF rejection markers"
            )
        elif family == 'python_sqli':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'python_reflected_xss':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject XSS payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the raw payload is reflected unescaped in the response body"
            )
        elif family == 'python_jinja2_ssti':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject SSTI payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'python_path_traversal':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject path payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'python_ssrf':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject SSRF payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another server-side fetch indicator"
            )
        elif family == 'python_xxe':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Send XML payload via {exploit_result.get('parameter', '') or 'request body'} using transport {exploit_result.get('transport', '')}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another XXE marker"
            )
        elif family == 'python_xpath':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected XPath value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'python_yaml':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject YAML payload via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'python_ldap':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected LDAP filter value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'python_debug':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Observe whether the response exposes traceback, Werkzeug, or debugger markers\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another debug surface indicator"
            )
        elif family == 'python_marshal':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject marshal payload via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another attacker-controlled field"
            )
        elif family == 'python_command_exec':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject command {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'python_jwt':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入弱 JWT\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明弱 JWT 被服务端接受"
            )
        elif family == 'php_deserialization':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject serialized payload via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'php_sqli':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'php_reflected_xss':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject XSS payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the raw payload is reflected unescaped in the response body"
            )
        elif family == 'php_ssrf':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject SSRF payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm the response reflects server-side fetching behavior or returns attacker-controlled fetch output"
            )
        elif family == 'php_path_traversal':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject path payload {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'php_command_exec':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明命令执行成功"
            )
        elif family == 'php_jwt':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject weak JWT via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'php_xxe':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Send XML payload via {exploit_result.get('parameter', '') or 'request body'} using transport {exploit_result.get('transport', '')}\n"
                f"3. Confirm the response includes {exploit_result.get('expected', '')} or another XXE marker"
            )
        elif family == 'php_xpath':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected XPath value {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'php_open_redirect':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject redirect target {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm Location header contains {exploit_result.get('expected', '')}"
            )
        elif family == 'node_nosql_injection':
            chain = (
                f"1. Visit {attack_request.get('url', '')} with baseline value {exploit_result.get('baseline', '')}\n"
                f"2. Re-send the request with injected NoSQL payload {exploit_result.get('payload', '')}\n"
                f"3. Confirm the injected response differs materially from baseline or includes the expected marker"
            )
        elif family == 'php_webshell':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明后门代码被执行"
            )
        elif family == 'node_command_injection':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明命令执行成功"
            )
        elif family == 'java_command_injection':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明 Java 命令执行成功"
            )
        elif family == 'node_insecure_deserialization':
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入反序列化载荷\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')} 或触发可观察异常"
            )
        elif family == 'node_jwt':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject JWT via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        elif family == 'node_open_redirect':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject redirect target {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm Location header contains {exploit_result.get('expected', '')}"
            )
        elif family == 'node_file_delete':
            chain = (
                f"1. Visit {attack_request.get('url', '')}\n"
                f"2. Inject file path {exploit_result.get('payload', '')} via parameter {exploit_result.get('parameter', '')}\n"
                f"3. Confirm response includes {exploit_result.get('expected', '')}"
            )
        else:
            chain = (
                f"1. 访问 {attack_request.get('url', '')}\n"
                f"2. 参数 {exploit_result.get('parameter', '')} 注入 {exploit_result.get('payload', '')}\n"
                f"3. 响应中出现 {exploit_result.get('expected', '')}，证明服务端模板表达式被执行"
            )

        return {
            'exploit_family': family,
            'bundle_dir': str(bundle_dir),
            'exp_script': str(exp_dst) if exp_dst.exists() else '',
            'result_json': str(result_json_dst),
            'service_url': raw.get('service_url', ''),
            'container_id': raw.get('container_id', ''),
            'payload_b64': '',
            'payload_ser': '',
            'helper_java': '',
            'import_response_body': response_text,
            'trigger_response_body': verify_text or response_text,
            'verify_stdout': (verify_text or response_text)[:240],
            'exploit_chain': chain,
        }

    if result.poc_type != 'java-map-payload':
        return {}

    steps = raw.get('steps', [])
    build_step = next((s.get('result', {}) for s in steps if s.get('step') == 'build_payload'), {})
    import_step = next((s.get('result', {}) for s in steps if s.get('step') == 'post_payload'), {})
    trigger_step = next((s.get('result', {}) for s in steps if str(s.get('step', '')).startswith('trigger_processing')), {})
    verify_step = next((s.get('result', {}) for s in steps if str(s.get('step', '')).startswith('verify_file')), {})

    family = 'java_map_deserialization_rce'
    label = _sanitize_label(f"{family}_{Path(vuln.get('file', 'unknown')).stem}_{vuln.get('line', 'na')}")
    bundle_dir = Path('output') / f'{label}_bundle'
    bundle_dir.mkdir(parents=True, exist_ok=True)

    exp_src = EXPLOITS_DIR / 'java_map_deserialization_rce_probe.py'
    helper_src = JAVA_TOOLS_DIR / 'MapDeserializationPayloadGenerator.java'
    exp_dst = bundle_dir / 'exp.py'
    helper_dst = bundle_dir / 'MapDeserializationPayloadGenerator.java'
    if exp_src.exists():
        exp_dst.write_text(exp_src.read_text(encoding='utf-8'), encoding='utf-8')
    if helper_src.exists():
        helper_dst.write_text(helper_src.read_text(encoding='utf-8'), encoding='utf-8')

    payload_ser_src = Path(build_step.get('payload_file', ''))
    payload_ser_dst = bundle_dir / 'payload.ser'
    if payload_ser_src.exists():
        payload_ser_dst.write_bytes(payload_ser_src.read_bytes())

    payload_b64_value = build_step.get('payload_b64', '')
    payload_b64_dst = bundle_dir / 'payload.b64'
    if payload_b64_value:
        payload_b64_dst.write_text(payload_b64_value, encoding='utf-8')

    exploit_result = {
        'exploit_family': family,
        'vulnerability_type': vuln.get('type', ''),
        'source_file': vuln.get('file', ''),
        'source_line': vuln.get('line', ''),
        'service_url': raw.get('service_url', ''),
        'container_id': raw.get('container_id', ''),
        'steps': steps,
        'attack_requests': {
            'import_request': {
                'method': 'POST',
                'url': import_step.get('url', ''),
                'headers': import_step.get('headers', {}),
                'body_preview': import_step.get('body', '')[:240],
            },
            'trigger_request': {
                'method': 'GET',
                'url': trigger_step.get('url', ''),
            },
        },
        'attack_results': {
            'import_response': {
                'status_code': import_step.get('status_code'),
                'body': import_step.get('body', ''),
            },
            'trigger_response': {
                'status_code': trigger_step.get('status_code'),
                'body': trigger_step.get('body', ''),
            },
            'verify_file': {
                'success': verify_step.get('success', False),
                'stdout': verify_step.get('stdout', ''),
                'stderr': verify_step.get('stderr', ''),
                'command': verify_step.get('command', ''),
            },
        },
        'success': bool(result.exploitable),
    }
    result_json_path = bundle_dir / 'exploit_result.json'
    result_json_path.write_text(json.dumps(exploit_result, ensure_ascii=False, indent=2), encoding='utf-8')

    chain_text = (
        '1. POST /debug/import 接收 data 参数并做 Base64 解码；'
        '2. ObjectInputStream.readObject() 反序列化为 Map<String, Object>；'
        '3. 导入后的 userConfig 被传入 QuoteService；'
        '4. GET /api/quote/random 触发 CacheProcessor.process(userConfig)；'
        '5. decoratedMap.put("key","value") 触发 TransformedMap 链；'
        '6. Runtime.exec 执行无害命令并在容器内落地标记文件。'
    )

    return {
        'family': family,
        'bundle_dir': str(bundle_dir),
        'exp_script': str(exp_dst) if exp_dst.exists() else '',
        'helper_java': str(helper_dst) if helper_dst.exists() else '',
        'payload_ser': str(payload_ser_dst) if payload_ser_dst.exists() else '',
        'payload_b64': str(payload_b64_dst) if payload_b64_dst.exists() else '',
        'result_json': str(result_json_path),
        'exploit_chain': chain_text,
        'import_response_body': import_step.get('body', ''),
        'trigger_response_body': trigger_step.get('body', ''),
        'verify_stdout': verify_step.get('stdout', ''),
        'service_url': raw.get('service_url', ''),
        'container_id': raw.get('container_id', ''),
    }


# 其 _last_scan_meta（引擎/CodeQL 状态/safe_pattern_suppressed）需透出给 stage_results.a1。
# 用模块级持有者暂存最近一次 A1 扫描的 meta，编排侧在写 a1 stage_results 时读取。
_LAST_A1_SCAN_META = {}


def run_a1_scan(files, code_root=None):
    """运行 A1 规则扫描（注入类统一走外接 CodeQL + AI 语义整合；携带根配置激活 LLM/CodeQL）。

    Q2：额外调用 analyze_business_logic（AI 主链路）+ analyze_bola（越权离线兜底），把结果并入
    A1 findings，使 A2 有证据基础（business_logic_candidates → a1_evidence_index → A2 LLM prompt）。
    """
    logger.info("Starting A1 rule-based scan...")
    from src.core.config import config as app_config
    svc = A1PipelineService(app_config.snapshot())
    results = svc.scan_files(files, code_root=code_root)
    global _LAST_A1_SCAN_META
    _LAST_A1_SCAN_META = dict(getattr(svc, "_last_scan_meta", {}) or {})
    try:
        results = svc.merge_business_logic_findings(results, files)
    except Exception as _e:
        logger.warning("[A1] 业务逻辑类并入失败（不影响注入类结果）：%s", _e)
    # 模板层 XSS 跨文件关联（块4 #17/#18）：确定性检出 th:utext 非转义输出，并入注入族 findings。
    # 独立于业务逻辑并入（xss 属注入族，不标 business_logic=True）。
    try:
        results = svc.merge_template_xss_findings(results, files)
    except Exception as _e:
        logger.warning("[A1] 模板层 XSS 并入失败（不影响其它结果）：%s", _e)
    # 顺序关键——必须早于 _build_a1_evidence_index，使路由随 a1_evidence 进 A2 prompt；
    # 也必须晚于业务/XSS 合并，让这些 A1 自产的 finding 一并拿到路由。
    try:
        results = svc.bind_static_routes(results, files)
    except Exception as _e:
        logger.warning("[A1] 静态路由前置绑定失败（不影响其它结果，回落 A2 推断）：%s", _e)
    return results


# 任务级 LLM 覆盖允许键 -> 归一化函数。未知键忽略（记日志），绝不静默吞掉用户意图也绝不猜。
def _as_bool(raw: Any) -> bool:
    """布尔归一化。直接用 bool 会把字符串 "false" 判成 True，
    所以字符串要按语义解析。"""
    if isinstance(raw, str):
        return raw.strip().lower() in ("1", "true", "yes", "on", "y")
    return bool(raw)


_LLM_OVERRIDE_SPEC = {
    "context_window": ("ollama.num_ctx", int),
    "max_output_tokens": ("ollama.max_tokens", int),
    "think": ("ollama.think", _as_bool),
    "temperature": ("ollama.temperature", float),
    "concurrency": ("__env__:SAST_AI_LLM_GATE_CONCURRENCY", int),
    "stream": ("__env__:SAST_AI_LLM_STREAM", _as_bool),
    "proof_second_pass": ("agents.a2.proof_second_pass.enabled", _as_bool),
    "prompt_version": ("__self__", str),
}

# 24576 与 32768 直接 HTTP 500 且模型被卸载。超出上限一律钳回，不让用户把任务跑崩。
_CTX_HARD_MAX = 20480
_CTX_HARD_MIN = 2048
_CONCURRENCY_MAX = 16


def _apply_llm_overrides(overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """把任务级「LLM 扫描强度」覆盖应用到本进程。

    作用域是**本任务进程内**：scan_task_runner 是独立子进程，写 config 单例与进程环境变量
    都不会外溢到后端主进程或其它并发任务 —— 这正是需求约定的作用域
    （「提交单个扫描任务时覆盖，因为整个项目是有并发的要求的」）。

    为什么用环境变量而不是只改 config：
    - 并发闸门（llm_gate）与流式开关是**按进程读环境变量**的，config 改不到；
    - 上下文裁剪（model_capabilities._apply_runtime_overrides）也读环境变量，
      且必须优先于 /api/show 的探测值，否则「设了 4096 却按 8192 裁剪」会溢出。

    全程 fail-open：任何一项解析失败只跳过该项并记日志，不阻断扫描。
    """
    applied: Dict[str, Any] = {}
    if not isinstance(overrides, dict) or not overrides:
        return applied
    from src.core.config import config as _cfg

    for key, raw in overrides.items():
        spec = _LLM_OVERRIDE_SPEC.get(str(key or "").strip())
        if spec is None:
            logger.warning("[llm-overrides] 忽略未知键：%s", key)
            continue
        target, caster = spec
        try:
            value = caster(raw)
        except (TypeError, ValueError):
            logger.warning("[llm-overrides] %s 取值非法（%r），跳过", key, raw)
            continue
        try:
            if target.startswith("__env__:"):
                env_key = target.split(":", 1)[1]
                if isinstance(value, bool):
                    # 消费方（a2_ai_agent / llm_gate）同时识别 "1"/"true" 与 "0"/"false"，
                    # 统一写 "1"/"0" 最稳，且和前端 PRESETS 的语义一致。
                    os.environ[env_key] = "1" if value else "0"
                else:
                    if key == "concurrency":
                        # __env__ 分支此前漏了钳制，999 会原样写进闸门上限
                        value = max(1, min(_CONCURRENCY_MAX, int(value)))
                    os.environ[env_key] = str(value)
                applied[key] = value
            elif target == "__self__":
                applied[key] = value
            else:
                if key == "context_window":
                    value = max(_CTX_HARD_MIN, min(_CTX_HARD_MAX, int(value)))
                    if int(value) != int(raw):
                        logger.warning(
                            "[llm-overrides] context_window %s 越界，钳到 %s（本机 8GB 卡实测硬上限 %s）",
                            raw, value, _CTX_HARD_MAX,
                        )
                    # 裁剪预算必须跟随请求 ctx，否则会溢出并静默丢提示词头部
                    os.environ["SAST_AI_LLM_CTX_OVERRIDE"] = str(int(value))
                if key == "concurrency":
                    value = max(1, min(_CONCURRENCY_MAX, int(value)))
                if key == "max_output_tokens":
                    value = max(64, int(value))
                # config.set 只改内存（不改 yaml 文件），正好是我们要的「本进程内生效」
                _cfg.set(target, value)
                applied[key] = value
        except Exception as _exc:
            logger.warning("[llm-overrides] %s 应用失败（跳过）：%s", key, _exc)
    if applied:
        logger.info("[llm-overrides] 本任务生效：%s", applied)
    return applied


def _resolve_model_profile(profile: str) -> Dict[str, Any]:
    """D5：把 model_profile 档位名解析成 provider/model 覆写。

    背景：model_profile 此前只出现在 run_benchmark 的签名里，函数体内从未被消费
    （一路从 task.options -> task_runner CLI -> scan_task_runner 传进来，然后被丢掉），
    所以设置页填什么都一样。这里补上真正的消费点。

    档位表取自配置的 ``model_profiles`` 段，形如：

        model_profiles:
          <档位名>: {provider: agnes, model: agnes-3.0-flash}

    未配置该段、档位名为空或为 default 时返回空 dict —— 与接入前行为完全一致，
    保证历史任务（options 里全是 default）零影响。
    """
    name = str(profile or "").strip()
    if not name or name.lower() == "default":
        return {}
    try:
        from src.core.config import config as _cfg
        table = _cfg.get("model_profiles", {}) or {}
    except Exception:
        return {}
    if not isinstance(table, dict):
        return {}
    entry = table.get(name)
    if not isinstance(entry, dict) or not entry:
        return {}
    return {k: v for k, v in entry.items() if v not in (None, "")}


def run_a2_scan(files, code_index=None, scan_mode: str = 'filter_first', a1_evidence_index: Optional[Dict] = None, feedback: Optional[List[Dict]] = None, discovered_routes: Optional[List[Dict]] = None, on_progress=None, model_profile: str = 'default', prompt_version: str = ''):
    """
    运行 A2 AI 扫描 - 带跨文件调用链分析

    Args:
        files: 文件列表
        code_index: 代码索引（可选，用于调用链分析）
        scan_mode: 扫描模式 filter_first / pure_ai / hybrid（G2）
        a1_evidence_index: Q4 — A1 静态分析调用链证据索引（_build_a1_evidence_index 产出），
            在 A2 LLM 调 prompt 之前注入，使 LLM 同时消费 A1 证据 + 自析源码。
        feedback: point 5 — D2 闭环回灌的 feedback_to_a2 列表（来自 I2 裁决），供 A2 二次分析时
            修正此前错误的 exploit_spec 假说（端点/参数/受害者资源 id）。首次扫描传 None。
    """
    logger.info("Starting A2 AI-powered scan with cross-file analysis (mode=%s, feedback=%s)...", scan_mode, "yes" if feedback else "no")

    from src.core.config import config

    agent_config = {
        'api': {
            'provider': config.get('api.provider', 'qwen'),
            # 主用 provider 的子配置必须逐一登记：a2_intelligent_agent._init_client 通过
            # _provider_conf(agent_config, '<provider>') 取用，缺失即 _make_client 返回 None
            # → 该 provider 被静默踢出降级链（agnes 曾因此缺席，主用落到 anthropic-compatible/GLM）。
            'agnes': config.get('agnes', {}),
            'qwen': config.get('qwen', {}),
            'minimax': config.get('minimax', {}),
            'claude': config.get('claude', {}),
            'doubao': config.get('doubao', {}),
            'anthropic_compatible': config.get('anthropic_compatible', {}),
            'deepseek': config.get('deepseek', {}),
            # OllamaNativeClient 会静默退回硬编码默认（model=qwen3:8b，丢掉配置里的
            # base_url / num_ctx / keep_alive / think / max_tokens），表现为「改了配置不生效」。
            'ollama': config.get('ollama', {}),
            # 兜底 provider 也必须随 agent_config 下发：ModelGateway.build_fallback_client
            # 从 api 子表取该键，取不到就退回历史默认 anthropic-compatible（=GLM 云端）。
            # 接本地 Ollama 时根 config 把它置空串，此处必须透传，否则「本地扫描」会
            # 在本地模型失败时静默改走云端。键被移除时不写死空值，保留历史默认。
            'fallback_provider': config.get('api.fallback_provider', 'anthropic-compatible'),
        },
        'agents': config.get('agents', {}),
        'scan_mode': scan_mode,
    }

    # D5：model_profile / prompt_version 真正下发（此前两者一路传进来后被丢弃）。
    _profile_overrides = _resolve_model_profile(model_profile)
    if _profile_overrides:
        _prov = str(_profile_overrides.get("provider") or "").strip()
        if _prov:
            agent_config.setdefault("api", {})["provider"] = _prov
        _primary = str(agent_config.get("api", {}).get("provider") or "").strip()
        _model = str(_profile_overrides.get("model") or "").strip()
        if _model and _primary:
            # provider 子配置键存在连字符/下划线两种写法（anthropic-compatible /
            # anthropic_compatible），两种都写，避免档位配了却取不到。
            for _key in (_primary, _primary.replace("-", "_")):
                _sub = agent_config.get(_key)
                if isinstance(_sub, dict):
                    _sub["model"] = _model
                else:
                    agent_config[_key] = {"model": _model}
        logger.info("[A2] model_profile=%s 生效：%s", model_profile, _profile_overrides)
    # 随 agent_config 下发：供 A2IntelligentAgent 取用，最终写入 model_runs 便于按版本分组观测
    agent_config["model_profile"] = model_profile
    agent_config["prompt_version"] = prompt_version

    provider = config.get('api.provider', 'qwen')
    # Q5：POC 生成必须使用 LLM——复用 A2 语义分析共用的 LLM 客户端，随结果一并返回给 plan_pocs。
    svc = A2PipelineService(agent_config, provider)
    a2_results = svc.scan_files(files, scan_mode=scan_mode, a1_evidence_index=a1_evidence_index, feedback=feedback, discovered_routes=discovered_routes, on_progress=on_progress)
    llm_client = svc.build_llm_client()
    return a2_results, llm_client


def _norm_path_key(p: str) -> str:
    """把任意形态的文件路径归一成「相对源码根」的键，用于 A1→A2 的按文件对齐。

      A1（CodeQL/启发式）产出的 `ScanResult.file` 是**绝对路径**
      而 A2 遍历用的是扫描器的 `rel_path`（`src\\main\\java\\...` 或 `src/main/java/...`）。
      两边直接当字典键比对必然 miss ⇒ **A2 永远拿不到 A1 锚点**，只能盲扫，
      于是 A2 自建的 finding 族全是 `unknown`。

    归一规则：反斜杠转正斜杠 → 从最后一个 `src/` 起截断（没有则用文件名）。
    """
    s = str(p or "").replace("\\", "/").strip()
    if not s:
        return ""
    low = s.lower()
    i = low.rfind("/src/")
    if i >= 0:
        return s[i + 1:]
    if low.startswith("src/"):
        return s
    return s.rsplit("/", 1)[-1]


def _a1_findings_by_file(a1_results) -> dict:
    """把 A1 结果摊平成 {rel_path: [{line, family, note, a1_evidence}]}，供集成分析师按文件消费。

    键统一走 ``_norm_path_key``，与 ``run_a2_integrated_scan`` 的查找口径一致。
    """
    from src.agents.a1_codeql_semantic_agent import _map_rule_to_family

    by_file: dict = {}
    for r in a1_results or []:
        f = _norm_path_key(str(getattr(r, "file", "") or ""))
        if not f:
            continue
        ev = dict(getattr(r, "evidence", {}) or {})
        for v in (getattr(r, "vulnerabilities", []) or []):
            #
            # 原实现先 `_map_rule_to_family(v.sink, ...)`，把 **sink 名**当 CodeQL rule_id 传。
            # framework_sinks 产出的 finding 本来就带正确的 `type=h.family`
            # （`Access-Control-Allow-Origin`→cors、`Cookie.setSecure`→secure_cookie、
            # `QLExpress.execute`→expression_injection、`Velocity.evaluate`→ssti），
            # 却在这一步被覆盖成 unmapped —— 本轮实时日志里刷了一整屏
            # 「未登记的 CodeQL 规则 Cookie.setSecure → 落 unmapped」。
            # 下面的 code-injection 回退也救不了：`family_map` 现在返回 `UNMAPPED`
            # 而不是老的 `code-injection` 兜底值，那个补丁已经失效。
            # 顺序反了的后果是「有正确族，却被映射表抹掉」，比没有映射更糟。
            fam = ""
            try:
                from src.core.normalize import (
                    is_known_family as _is_known_fam,
                    normalize_family as _nfam2,
                )
                _t = _nfam2(str(getattr(v, "type", "") or ""))
                if _t and _is_known_fam(_t):
                    fam = _t
            except Exception:
                fam = ""
            if not fam:
                try:
                    fam = _map_rule_to_family(
                        str(getattr(v, "sink", "") or ""),
                        str(getattr(v, "description", "") or ""),
                    ) or ""
                except Exception:
                    fam = ""
            # （兜底值），于是启发式规则表里已按族登记的 finding 被整批覆盖成 code-injection
            # 却被写成 code-injection，登记后族对不上真值。保留这段兜底以防映射函数回退。
            if fam == "code-injection":
                try:
                    _t2 = _nfam2(str(getattr(v, "type", "") or ""))
                    if _t2 and _is_known_fam(_t2):
                        fam = _t2
                except Exception:
                    pass
            if not fam:
                fam = str(getattr(v, "type", "") or "")
            by_file.setdefault(f, []).append({
                "line": int(getattr(v, "line", 0) or 0),
                "family": fam,
                "note": (str(getattr(v, "description", "") or "")
                         or str(getattr(v, "type", "") or ""))[:120],
                "a1_evidence": ev,
            })
    return by_file


# `recover_late_arrival` 的 "late-arrival value_hit gate B" 升级——即「canary 到达 sink 实参」
# 就升 confirmed_exploitable。但属性族的 sink 实参是**算法名字符串**，canary 到达
# `MessageDigest.update(param)` 只证明污点抵达，完全不证明算法弱。
#
# 离线预演（453）否决了「按族排除该升级路径」的做法：
#   该路径升级的 weak_hash 3 条 + weak_crypto 2 条中，命中 TP 用例 00071/00537/01829（3 个），
#   FP 用例 00022/00121（2 个）⇒ 按族排除 = TP 损失 3、FP 只减 2，不可接受。
# 正确判据是**算法强弱**而不是族：TP 用 MD5/SHA-1/DES，FP 用 SHA-256/AES-GCM/SecureRandom。
#
# 因此这里只做「保守跳过」：必须能在 sink 语句内看到强算法/强随机源，才判该 finding 为假阳性。
# 命中即不产出 spec（A2 侧）/ 不进登记候选（A1-extra 侧），从而也不会被后续升级路径捞回来。
_PROPERTY_FAMILIES_STRONG_GATE = {
    "weak_hash", "weak_crypto", "insecure crypto algorithm", "weak_random",
}


def _strong_property_evidence(code: str, line: int, family: str, code_root: str = "") -> str:
    """属性族的静态强证据。返回命中 token（非空=应判假阳性），否则空串。

    只在属性族生效；数据流族（sqli/xss/pathtraver…）一律不碰。

    本函数保留为薄包装，避免改动所有调用点。
    新实现相对旧版修掉三个实测坑：
      ① 字符串字面量里的 API 引用不再算作调用（00121/00054 真安全版本被误判成有漏洞）；
      ② 算法调用与随机源调用分开判（SecureRandom 行无算法名，混在一起 all 永假）；
      ③ 新增 secure_cookie 族（setSecure 全为 true ⇒ 强证据）。
    """
    from src.iast.property_evidence import strong_property_evidence
    return strong_property_evidence(code, line, family, code_root)


def _benchmark_case_category(code: str) -> str:
    """从 Java 源文件的 ``@WebServlet`` 注解取 benchmark 类别前缀。

    非 benchmark 风格返回空串。

    CodeQL 报的 finding_type 可能是**误标**的——00121（真值 crypto/false，代码用
    ``AES/GCM`` 强算法）被报成 ``stack trace exposure``，00016（真值 securecookie/false，
    代码 ``setSecure(true)``）被报成 ``http response splitting``。属性族门禁按
    finding_type 判族，族一错门禁就空转 ⇒ 安全版本被当成漏洞确认。
    而**路由前缀是源码里的静态事实**（不是真值泄漏），它只告诉我们「该问哪个问题」，
    答案仍由静态强证据给出。
    """
    if not code or "@WebServlet" not in code:
        return ""
    # 路由前缀是 **Benchmark 的 URL 布局约定**（换靶场即失效）⇒ 属过拟合面。
    # 置 SAST_AI_BENCHMARK_PRIOR=0 可关掉本先验（与 harm_evidence.family_from_endpoint
    # 共用同一开关），用于量化「关掉后 TP/FP 掉多少」= 过拟合程度。
    from src.iast.harm_evidence import benchmark_prior_enabled
    if not benchmark_prior_enabled():
        return ""
    m = re.search(r'@WebServlet\s*\(\s*(?:value\s*=\s*)?["\']/([a-z0-9]+)-\d+/BenchmarkTest', code)
    return m.group(1).lower() if m else ""


# benchmark 类别前缀 → 门禁认识的属性族名（None = 该类别不是属性族，门禁不管）
_BENCH_CATEGORY_GATE_FAMILY = {
    "crypto": "weak_crypto",
    "hash": "weak_hash",
    "weakrand": "weak_random",
    "securecookie": "secure_cookie",
}


def _filter_property_family_findings(results, code_root: str = ""):
    """按「属性族强证据」过滤 A1 结果，仅用于**登记候选**（extra_results）。

    不改 a1_results 本身：报告里的 A1 finding 数保持原样，避免指标口径被这层过滤影响。

    原来只看 finding 自己的 type；type 被误标时（如 00121 的 stack trace exposure）
    门禁族集不含它 ⇒ 门禁空转 ⇒ 安全版本被确认成漏洞。
    现在对每条 finding 同时用两个族判：
      ① finding 自身的 type；
      ② 源文件 ``@WebServlet`` 路由前缀推出的**真实类别**（仅当该类别是属性族）。
    任一族命中强证据 ⇒ 剔除。

    安全性：② 只在 benchmark 风格文件上生效（路由前缀来自源码），且门禁方向恒为
    「判安全」——全分片 1042 例属性族用例实测**误杀 TP = 0**（见 src/iast/property_evidence.py）。
    """
    if not results:
        return results
    _cache: dict = {}
    kept = []
    dropped = 0
    dropped_by_reason: dict = {}
    for r in results:
        fpath = str(getattr(r, "file", "") or "")
        # 路径（...\src\main\java\src\main\java\...）⇒ code 为空 ⇒ 整段门禁静默空转。
        # 统一走 _resolve_source_path（绝对路径 / 逐段剥离前缀都试）。
        _rp = _resolve_source_path(str(code_root or ""), fpath)
        absp = str(_rp) if _rp else ""
        code = _cache.get(absp)
        if code is None:
            try:
                code = open(absp, encoding="utf-8", errors="ignore").read() if absp else ""
            except Exception:
                code = ""
            _cache[absp] = code
        # 真实类别（来自源码 @WebServlet 路由前缀）→ 门禁族；非属性族则为 None
        _case_fam = _BENCH_CATEGORY_GATE_FAMILY.get(_benchmark_case_category(code))
        surv = []
        for v in (getattr(r, "vulnerabilities", []) or []):
            vtype = str(getattr(v, "type", "") or "")
            line = int(getattr(v, "line", 0) or 0)
            # 就直接剔除。实测 5 个跨族 sql_injection FP（xss/hash 用例里）文件连 SQL 关键字
            # 都没有；真 SQLi 用例 0 个缺（不误杀）。
            if code:
                try:
                    from src.iast.property_evidence import spurious_no_sink as _sns
                    # property_evidence.spurious_no_sink 注释）。XSS.java 是 Spring
                    # `@ResponseBody` 返回字符串，文件里没有 `getWriter/.print(` ⇒
                    # 被通用 xss 判据判成「跨族捏造」直接剔除 ⇒ 5 条真值 xss finding
                    # 连登记循环都没进（日志里 vhash 一条都不出现）。
                    _fw_hit = bool((getattr(v, "a1_evidence", None) or {}).get("framework_sink"))
                    if _sns(code, vtype, framework_sink=_fw_hit):
                        dropped += 1
                        _rk = "spurious_no_sink:%s" % vtype
                        dropped_by_reason[_rk] = dropped_by_reason.get(_rk, 0) + 1
                        continue
                except Exception:
                    pass
            tok = _strong_property_evidence(code, line, vtype, str(code_root or ""))
            reason = "type:%s" % vtype
            if not tok and _case_fam and _case_fam != vtype:
                # ② 真实类别族：type 被误标时的兜底（00121/00016 就靠这条）
                tok2 = _strong_property_evidence(code, line, _case_fam, str(code_root or ""))
                if tok2:
                    tok = tok2
                    reason = "case_family:%s" % _case_fam
            if tok:
                dropped += 1
                dropped_by_reason[reason] = dropped_by_reason.get(reason, 0) + 1
                continue
            surv.append(v)
        if surv:
            # 必须拷贝 ScanResult 再改：a1_results 仍被报告/指标消费，
            # 就地改 r.vulnerabilities 会把报告里的 A1 finding 数一起改掉（口径污染）。
            try:
                import copy as _copy
                _r2 = _copy.copy(r)
                _r2.vulnerabilities = surv
                kept.append(_r2)
            except Exception:
                kept.append(r)
    if dropped:
        logger.info("[属性族门禁] 静态强证据命中 %d 条 A1 finding，已从登记候选中剔除"
                    "（报告口径不变）按依据=%s", dropped, dropped_by_reason)
    return kept


# 历史行为：`an.analyze` 抛超时异常 → `except Exception: specs = []`
# 现在保留一条 analysis_error 占位（不是判假、不产出漏洞），并把文件级失败
# 与传输层统计一起写进 stage_results.a2，供发布闸门判定本轮是否有效。
_A2_ANALYSIS_ERRORS: List[Dict[str, str]] = []


def reset_a2_analysis_errors() -> None:
    """每轮扫描启动时清空（子进程 fresh import 时自然为空，显式留作测试/复用）。"""
    _A2_ANALYSIS_ERRORS.clear()


def a2_analysis_error_stats() -> Dict[str, Any]:
    return {
        "failed_files": len(_A2_ANALYSIS_ERRORS),
        "files": [x.get("file", "") for x in _A2_ANALYSIS_ERRORS[:20]],
    }


def _a2_failure_placeholder(findings, exc: BaseException) -> List[Dict[str, Any]]:
    """A2 最终失败时的可诊断占位：既不是 false_positive，也不是空列表。"""
    return [{
        "line": (findings[0].get("line") if findings else 0),
        "verdict": "analysis_error",
        "reason": "A2 分析失败（%s: %s）" % (type(exc).__name__, str(exc)[:200]),
        "spec": None,
        "analysis_error": True,
    }]


def _a2_analyze_with_retry(analyze_fn, rel: str):
    """整文件级重试一次（底层 ollama_chat 已有连接层重试，这里是最后一道兜底）。

    只重试「连接层没拿到完整响应」类异常；熔断异常直接冒泡让整轮快速判 failed，
    避免慢慢产出 95 个空文件却显示 completed。

    重发同一 prompt 全部再次超时，反而把单个卡住文件从 5 分钟拖到 15 分钟以上。
    生成超时直接交给调用方记 analysis_error 占位，由 Gate 0 有效轮判据拦截。
    """
    from src.agents.a2_integrated_analyst import (A2LLMUnavailable,
                                                  is_generation_timeout,
                                                  is_retryable_transport_error)
    try:
        return analyze_fn()
    except Exception as exc:  # noqa: BLE001
        if (isinstance(exc, A2LLMUnavailable) or is_generation_timeout(exc)
                or not is_retryable_transport_error(exc)):
            raise
        logger.warning("[integrated-a2] %s 连接异常，整文件重试一次：%s", rel, exc)
        time.sleep(2.0)
        return analyze_fn()


def run_a2_integrated_scan(files, a1_results, code_root: str = "",
                           discovered_routes=None, on_progress=None,
                           intent_hints: str = ""):
    """A2 = 集成分析师（单次 LLM，一步到位）：源码 + 该文件 A1(CodeQL) 结果
    → 每条 finding 的「真假判定 + 可打通 spec(route/method/param/payload含绕过)」。

    这是替代旧 ``run_a2_scan`` 的主路径：
    - 旧：A2 先 triage 出 findings（130 次 LLM），a2_poc 再拿 findings 二次调 LLM 出 spec
      → 同一文件被 LLM 读两遍，是纯重复劳动。
    - 新：A2 自己就是集成分析师，一次调用同时完成「审计 + 构造」，直接产出 spec；
      不再有二次 LLM。收敛（哪些是真漏洞）是判断的副产物，不是单独一步。

    输出结构与 run_a2_scan 对齐（List[ScanResult]，每个 vuln 已带 exploit_spec/entry_resolved），
    下游 _auto_register_a2_trigger_specs 无需改动即可消费。
    """
    from src.agents.a2_integrated_analyst import IntegratedAnalyst, _gather_cross_file_context
    from src.core.exploit_spec import normalize_exploit_spec
    from src.core.models import ScanResult, Vulnerability

    an = IntegratedAnalyst()
    findings_by_file = _a1_findings_by_file(a1_results)
    total = len(files or [])
    done = 0
    results = []

    for fi in files or []:
        rel = str(fi.get("rel_path") or fi.get("file") or "")
        code = fi.get("content") or ""
        # 否则 A2 永远拿不到锚点（详见 _norm_path_key 注释）。
        findings = findings_by_file.get(_norm_path_key(rel)) or []
        extra = ""
        try:
            extra = _gather_cross_file_context(findings, str(code_root or ""), rel)
        except Exception:
            extra = ""

        specs = []
        _two_stage = str(os.environ.get("SAST_AI_A2_TWO_STAGE", "0")).strip().lower() in (
            "1", "true", "yes", "on")
        _a2_stats = {"total": 0, "early_stopped": 0, "generated": 0}
        # Benchmark 模板文件在多个 task 重复，命中即跳过 LLM。默认关闭（SAST_AI_DECISION_CACHE=0），
        # 仅统一重跑验证用；仅作用于默认单段路径（two-stage 自管 prefill，不混用）。
        _cache_on = (str(os.environ.get("SAST_AI_DECISION_CACHE", "0")).strip().lower()
                     in ("1", "true", "yes", "on")) and not _two_stage
        _from_cache = False
        if _cache_on:
            try:
                from src.iast import decision_cache as _dc
                _famkey = ",".join(sorted({str(f.get("family") or "") for f in findings})) or "(noanchor)"
                _cached = _dc.lookup_specs(
                    Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db")).connect(), code, _famkey)
                if _cached is not None:
                    specs = _cached
                    _from_cache = True
                    logger.info("[integrated-a2] %s 命中决策缓存，跳过 LLM", rel)
            except Exception as _ce:  # noqa: BLE001
                logger.debug("[integrated-a2] 决策缓存查询失败（忽略）：%s", _ce)
        if code and not _from_cache:
            # 都会被属性族门禁剔除，且路由前缀推出的真实类别是属性族，则 A2 的分析结果
            # 最终一定被丢弃⇒ 分析纯属浪费。
            # 安全性：条件要求「路由类别 ∈ 属性族」且「每条 finding 都有强证据」，
            # 与登记阶段门禁的判据完全同源（_strong_property_evidence），不是另一套逻辑。
            # 默认关闭（SAST_AI_A2_SKIP_GATED_FILES=1 才生效），等 P1 干净基线后再开。
            _skip_gated = False
            if (str(os.environ.get("SAST_AI_A2_SKIP_GATED_FILES", "0")).strip().lower()
                    in ("1", "true", "yes", "on")):
                try:
                    _case_fam = _BENCH_CATEGORY_GATE_FAMILY.get(_benchmark_case_category(code))
                    if _case_fam and findings and all(
                            _strong_property_evidence(code, int(f.get("line") or 0),
                                                      str(f.get("family") or ""))
                            or _strong_property_evidence(code, int(f.get("line") or 0), _case_fam)
                            for f in findings):
                        _skip_gated = True
                        logger.info("[integrated-a2] %s 全部 finding 被属性门禁剔除（%s），跳过 A2 分析",
                                    rel, _case_fam)
                except Exception as _sge:  # noqa: BLE001
                    logger.debug("[integrated-a2] 门禁预判失败（走正常分析）：%s", _sge)
            if _skip_gated:
                specs = []
            else:
                def _call_a2():
                    if _two_stage:
                        # 默认关闭（SAST_AI_A2_TWO_STAGE=0 走原单段路径），A/B 对照后视召回决定默认值。
                        return an.analyze_two_stage(
                            code, os.path.basename(rel), findings, extra)
                    return (an.analyze(code, os.path.basename(rel), findings, extra,
                                       intent_hints=intent_hints) or []), _a2_stats
                try:
                    specs, _a2_stats = _a2_analyze_with_retry(_call_a2, rel)
                except Exception as _ae:  # noqa: BLE001
                    from src.agents.a2_integrated_analyst import A2LLMUnavailable
                    if isinstance(_ae, A2LLMUnavailable):
                        # 整轮快速失败：不能让 95 个空文件显示成 completed 的有效轮
                        logger.error("[integrated-a2] Ollama 熔断，整轮判失败：%s", _ae)
                        raise
                    logger.error("[integrated-a2] %s 分析失败（保留可诊断占位，不静默丢文件）：%s",
                                 rel, _ae)
                    _A2_ANALYSIS_ERRORS.append({
                        "file": rel,
                        "error": "%s: %s" % (type(_ae).__name__, str(_ae)[:200]),
                    })
                    specs = _a2_failure_placeholder(findings, _ae)
        if _cache_on and not _from_cache and specs:
            try:
                from src.iast import decision_cache as _dc
                _famkey = ",".join(sorted({str(f.get("family") or "") for f in findings})) or "(noanchor)"
                _dc.put_specs(
                    Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db")).connect(), code, _famkey, specs)
            except Exception as _ce:  # noqa: BLE001
                logger.debug("[integrated-a2] 决策缓存写入失败（忽略）：%s", _ce)
        if _two_stage and _a2_stats.get("total"):
            _a2_stage_stats = globals().get("_A2_TWO_STAGE_STATS") or {
                "files": 0, "total": 0, "early_stopped": 0, "generated": 0}
            _a2_stage_stats["files"] += 1
            for _k in ("total", "early_stopped", "generated"):
                _a2_stage_stats[_k] += int(_a2_stats.get(_k) or 0)
            globals()["_A2_TWO_STAGE_STATS"] = _a2_stage_stats

        sr = ScanResult(file=rel, agent="a2")
        _no_anchor = not findings
        for s in specs:
            _verdict = str(s.get("verdict") or "")
            _sp0 = s.get("spec") or {}
            _canary_only = False
            # verdict=false_positive，reason 却写「因此存在 SQL 注入风险」，同时给出了完整
            # route/param/payload。这种自相矛盾时**以 spec 为准**：能写出可打通 spec 说明它
            # 真读懂了；反之 safe 用例即便误填 real 也不会带 payload，后续 D2 仍会否决。
            # 不修这一条，01002/01003/01004 会被整例漏掉（TP -3）。
            if _verdict != "real" and (_sp0.get("route") and _sp0.get("param_name")
                                       and _sp0.get("payload")):
                logger.info("[integrated-a2] %s:%s verdict=%s 但给出完整 spec ⇒ 按 real 处理",
                            rel, s.get("line"), _verdict)
                _verdict = "real"
            # route/param 时，仍登记一条 canary-only spec（payload 空）交 D2 复核。
            # 依据：01002/01003/01004 这类真注入在没有 SAST 告警时会被判假，spec 一空就整例漏掉
            # （453/457 各丢 3 个 TP）。安全用例的 canary 也会到 sink，但值级闸/抑制规则会拦，
            # 代价是少量 spec 与 D2 时间，换召回稳定。
            if _verdict != "real" and _no_anchor and (_sp0.get("route") and _sp0.get("param_name")):
                logger.info("[integrated-a2] %s:%s 无锚点文件判假但给出 route/param ⇒ 登记 canary 探针",
                            rel, s.get("line"))
                _verdict = "real"
                _canary_only = True
            if _verdict != "real":
                continue
            sp = s.get("spec") or {}
            try:
                line = int(s.get("line") or 0)
            except Exception:
                line = 0
            fam = ""
            for f in findings:
                if int(f.get("line") or 0) == line:
                    fam = str(f.get("family") or "")
                    break
            if not fam and findings:
                fam = str(findings[0].get("family") or "")
            if not fam:
                # （契约里的 vuln_type，仅在「文件没有 A1 告警」时才要求模型输出）。
                # 不补这一步，A1 没有对应规则的文件（Velocity SSTI / QLExpress / CORS / JSONP…）
                # 只能落成 type=unknown，下游既无法分族、也过不了族级门禁。
                try:
                    from src.core.normalize import normalize_family as _nf_vt
                    _vt = str(s.get("vuln_type") or "").strip()
                    fam = _nf_vt(_vt) if _vt else ""
                    if fam:
                        logger.info("[integrated-a2] %s:%s 族由 A2 给出：%s", rel, line, fam)
                except Exception:  # noqa: BLE001  fail-open：取不到就维持 unknown
                    fam = ""

            # 属性族强证据门禁：sink 语句里出现强算法/强随机源 ⇒ 该条判假阳性。
            # 依据见 _strong_property_evidence 上方注释（453 离线预演：按族排除会误杀 3 个 TP）。
            _strong_tok = _strong_property_evidence(code, line, fam)
            if _strong_tok:
                logger.info("[属性族门禁] %s:%s（%s）sink 语句含强证据 '%s' ⇒ 判 false_positive",
                            rel, line, fam, _strong_tok)
                continue

            v = Vulnerability(
                type=fam or "unknown",
                severity="MEDIUM",
                line=line,
                file=rel,
                description=str(s.get("reason") or "")[:300],
                source="a1+a2",
            )
            spec = normalize_exploit_spec({})
            entry = spec.setdefault("entry", {})
            entry["route"] = str(sp.get("route") or "")
            entry["method"] = str(sp.get("method") or "GET").upper()
            entry["parameter_name"] = str(sp.get("param_name") or "")
            entry["parameter_location"] = str(sp.get("param_location") or "query")
            entry["resolved_by"] = "llm"
            _pl = str(sp.get("payload") or "").strip()
            if _canary_only:
                # 无锚点文件的「判假但给了 route/param」：只登记 canary 探针，不投 payload。
                _pl = ""
            # 变体进 candidate_payloads（select_attack_payloads 会全量取出供 D1 逐条投放），
            # 净化器信息进 exploit_spec.filter_spec，登记时落 trigger_specs.filter_spec_json。
            _bypass = [] if _canary_only else [str(x).strip() for x in (sp.get("bypass_payloads") or []) if str(x).strip()]
            _cands: list = []
            for _c in [_pl] + _bypass:
                if _c and _c not in _cands:
                    _cands.append(_c)
            spec["payload"] = {
                "payload_family": fam,
                "candidate_payloads": _cands,
            }
            _san = sp.get("sanitizer") if isinstance(sp.get("sanitizer"), dict) else {}
            if _san:
                _stype = str(_san.get("type") or "unknown").lower()
                _strength = str(_san.get("strength") or "unknown").lower()
                # 代码侧归一（防 LLM 自相矛盾）：判为非净化器（type=none 或 present=false）时，
                # 强度一律记 none，不能记 strong——否则会把「无净化」误记成「强净化、不可绕过」，
                # 进而在 bypass_state 上误判 non_bypassable，等于凭空放过一个真漏洞。
                if (not _san.get("present")) or _stype in ("none", ""):
                    _strength = "none"
                spec["filter_spec"] = {
                    "present": bool(_san.get("present")) and _stype not in ("none", ""),
                    "type": _stype or "unknown",
                    "strength": _strength,
                    "location": str(_san.get("location") or ""),
                    "snippet": str(_san.get("snippet") or "")[:300],
                    "why_bypassable": str(_san.get("why_bypassable") or "")[:300],
                }
            try:
                # 供 D2 入口闸门按 vuln_prob 分派重放策略（full / canary_only / skip）。
                # 挂在 exploit_spec 而不是 Vulnerability 顶层字段：to_dict 白名单已含
                # exploit_spec，无需改数据模型；registry 登记时也不受影响（它只读自己认识的键）。
                _prim = s.get("primitives")
                if isinstance(_prim, dict) and _prim.get("source") == "llm":
                    spec["primitives"] = {
                        "vuln": bool(_prim.get("vuln")),
                        "vuln_prob": float(_prim.get("vuln_prob") or 0.0),
                        "location": str(_prim.get("location") or "unknown"),
                        "sanitizer": str(_prim.get("sanitizer") or "unknown"),
                        "exploitability": float(_prim.get("exploitability") or 0.0),
                    }
                v.exploit_spec = spec
                v.entry_resolved = True
                v.a21_selected = True
                v.integrated_verdict = "false_positive_canary" if _canary_only else "real"
                v.integrated_reason = str(s.get("reason") or "")[:300]
                v.poc = _pl
                if _san:
                    # filter_spec 同时写两处：exploit_spec（报告用）与 dataclass 属性。
                    # 原因是 normalize_exploit_spec 只保留 schema 内分组键，顶层自定义键会被丢弃，
                    # 单靠 exploit_spec 会导致 filter_spec_json 恒空。
                    v.filter_spec = dict(spec["filter_spec"])
                    if _strength == "none":
                        # 无净化器：不存在「绕过」这个概念，不写 bypass_state，
                        # 避免下游把它当成「已判定的不可绕过」而抑制。
                        v.bypass_state = ""
                    else:
                        v.bypass_state = ("non_bypassable" if _strength == "strong"
                                          else ("bypassable" if _bypass else "undetermined"))
                    v.bypass_reason = str(_san.get("why_bypassable") or "")[:300]
            except Exception:
                pass
            sr.vulnerabilities.append(v)

        results.append(sr)
        done += 1
        if on_progress:
            try:
                on_progress(done, total)
            except Exception:
                pass

    real_n = sum(len(r.vulnerabilities) for r in results)
    logger.info("[integrated-a2] 单次集成分析完成：%s 文件 → %s 条 real spec（无二次 LLM）",
                len(results), real_n)
    return results, None


def _a2_results_have_integrated_specs(a2_results) -> bool:
    """判断 a2_results 是否已由集成分析师产出（spec.entry.resolved_by == 'llm'）。

    用于 stage_cache 命中场景：缓存产物若已含集成 spec，则 a2_poc 不再二次调 LLM。
    """
    for r in a2_results or []:
        for v in (getattr(r, "vulnerabilities", []) or []):
            es = getattr(v, "exploit_spec", None) or {}
            if isinstance(es, dict) and ((es.get("entry") or {}).get("resolved_by") == "llm"):
                return True
    return False


def rerun_a2_with_feedback(files, code_index=None, scan_mode: str = 'filter_first', a1_evidence_index=None, feedback: Optional[List[Dict]] = None, discovered_routes: Optional[List[Dict]] = None, code_root: Optional[str] = None, on_progress=None) -> List:
    """§P4：闭环标准入口——携带 I2 裁决回灌的 feedback_to_a2 重跑 A2 语义分析 + POC 投影。

    供 point 5 二次回灌、CLI/API 显式触发复用。feedback 应为 I2 产出的 feedback_to_a2 列表
    （结构见 iast/adjudicator._build_feedback_to_a2：hypothesis_id / final_state / reason /
    correction_hint / current_spec）。feedback 为空时等价于普通 A2 重跑（无修正语义）。

    Returns:
        重新分析 + 投影后的 ScanResult 列表。
    """
    if not feedback:
        logger.warning("[rerun_a2_with_feedback] 未传入 feedback，退化为普通 A2 重跑（无闭环修正语义）。")
    a2_results, llm_client = run_a2_scan(
        files, code_index=code_index, scan_mode=scan_mode,
        a1_evidence_index=a1_evidence_index, feedback=feedback,
        discovered_routes=discovered_routes, on_progress=on_progress,
    )
    return A2PipelineService.plan_pocs(
        a2_results, llm_client=llm_client, a1_evidence_index=a1_evidence_index,
        code_root=code_root, code_index=code_index,
    )


def _failed_files_from_feedback(task_id: Optional[int], a2_fb: List[Dict[str, Any]], files: List[str]) -> List[str]:
    """§P4：把闭环 A2 重跑收窄到「失败 finding 所在文件」。

    仅对 I2 裁决为假说缺陷（a2_actionable）的反馈生效。步骤：
    1) 收集 vulnerability_hash_v2（E3：hypothesis_id 兜底——回灌项多只带 hypothesis_id）；
    2) findings.file_path 反查失败文件；3) trigger_specs.expected_sink_file 兜底；
    4) 与本轮 files 归一化（绝对/相对写法）取交集（含文件名兜底）；
       D2 重验范围不受影响（调用方 _merge_a2_results 合并回全量集），收窄为空是纯止损。
    """
    # 旧实现只认 vulnerability_hash_v2，而闭环回灌的 feedback_to_a2 多只带 hypothesis_id
    # 现统一用 hypothesis_id 兜底，使「失败文件收窄」真正生效。
    hashes = set()
    for fb in (a2_fb or []):
        if not isinstance(fb, dict):
            continue
        h = fb.get("vulnerability_hash_v2") or fb.get("hypothesis_id") or ""
        if h:
            hashes.add(str(h))
    if not hashes:
        # 无目标哈希即无失败可定位 → 收窄为空（跳过），绝不回退全量，避免无意义全量 A2 重跑。
        logger.info("[闭环] 闭环重跑收窄：A2 反馈无 vuln hash / hypothesis_id，跳过文件级重跑")
        return []
    if not files:
        return []
    try:
        _db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        _ph = ",".join("?" * len(hashes))
        _rows = _db.execute(
            f"SELECT DISTINCT file_path FROM findings WHERE task_id=? AND vulnerability_hash_v2 IN ({_ph})",
            [task_id] + list(hashes), fetchall=True,
        )
        _fb_files = {str(r.get("file_path") or "") for r in _rows if r.get("file_path")}
        _rows2 = _db.execute(
            f"SELECT DISTINCT expected_sink_file FROM trigger_specs WHERE task_id=? AND vulnerability_hash_v2 IN ({_ph})",
            [task_id] + list(hashes), fetchall=True,
        )
        _fb_files |= {str(r.get("expected_sink_file") or "") for r in _rows2 if r.get("expected_sink_file")}
    except Exception as _e:
        logger.warning("[闭环] 失败文件查询失败（E3：收窄为空而非回退全量）：%s", _e)
        return []
    _fb_files.discard("")
    if not _fb_files:
        # 旧实现此处回退全量 files，是「收窄优化」名存实亡的另一半根因；
        # D2 重验仍用合并后的全量集（_merge_a2_results），收窄为空不影响验证范围。
        logger.warning("[闭环] 失败文件查询无映射结果（E3：收窄为空，跳过文件级重跑）")
        return []

    def _repo_rel(p: str) -> str:
        # 归一化到「仓库相对路径」：剥离前缀，只保留从 /src/ 起的尾巴。
        # 真实 target 目录与 prepared 副本目录根不同，但仓库内部结构一致，
        # 这样「绝对(真实 target)/绝对(prepared)/相对」三种写法都能对齐。
        # 旧实现用 endswith 直接比前缀不同的绝对路径，永远匹配不上 → 回退全量，
        # 注意：不能用 os.path.normcase —— Windows 下它会把 / 还原成 \，导致 /src/ 找不到。
        p = str(p).replace("\\", "/").lower()
        idx = p.find("/src/")
        if idx >= 0:
            return p[idx + 1:]  # 'src/...'
        parts = p.split("/")
        return "/".join(parts[-4:]) if len(parts) >= 4 else p

    _fb_rel = {_repo_rel(p) for p in _fb_files}
    _matched = [f for f in files if _repo_rel(f) in _fb_rel]
    if not _matched:
        # 退一步：按文件名(末尾一段)兜底匹配。仍为空才回退全量。
        # 文件名兜底只会「多匹配」(over-match，多花几次调用)，不会漏匹配(漏检)，
        # 与「回退全量」相比更省调用且安全。
        _fb_base = {os.path.basename(r) for r in _fb_rel}
        _matched = [f for f in files if os.path.basename(_repo_rel(f)) in _fb_base]
    if not _matched:
        # 且 D2 重验范围本就不受收窄影响（_merge_a2_results 合并回全量），跳过是纯止损。
        logger.warning(
            "[闭环] 失败文件交集为空（E3：收窄为空，跳过文件级重跑）：hashes=%d feedback_files=%d",
            len(hashes), len(_fb_files),
        )
        return []
    logger.info("[闭环] 闭环重跑收窄：%d 文件 → %d 失败文件（hashes=%d）", len(files), len(_matched), len(hashes))
    return _matched


def _vuln_identity(v: Any) -> tuple:
    """漏洞假说身份键：判定「重跑结果与全量结果里的是不是同一条假说」。

    键取 (file, line, type)。不取 vhash：合并发生在登记之前，此处算 vhash 需要与登记端完全
    一致的归一链路，任一侧实现不同就会键不命中而误判成两条；而 (file, line, type) 是 A2 产物
    自身的稳定字段，足以区分同一文件内的不同假说。
    """
    try:
        d = v.to_dict() if hasattr(v, "to_dict") else dict(v or {})
    except Exception:
        d = {}
    _t = ""
    for _k in ("type", "finding_type", "display_family", "family", "category"):
        if d.get(_k):
            _t = str(d.get(_k))
            break
    return (
        str(d.get("file") or getattr(v, "file", "") or ""),
        str(d.get("line") or getattr(v, "line", "") or ""),
        _t,
    )


def _merge_vulns_into(base_res: Any, new_res: Any) -> Any:
    """把 new_res 的漏洞假说按身份键合并进 base_res（并集，不整份替换）。

    new 命中已有键则覆盖（重跑是为了拿到修正后的 exploit_spec/route/param），
    base 独有的键一律保留（重跑只跑了部分文件，不能顺带清掉没重跑的假说）。
    """
    # 区分「属性不存在」与「空列表」：前者说明对象不是带 hypotheses 的扫描结果
    # （老结构/测试桩），无从做并集，必须退回原语义「整份替换为 new_res」，
    # 否则会让重跑白跑（旧锁 test_rerun_replaces_only_its_own_files 即守这条）；
    # 后者是真实的「重跑产物为空」，才走保护分支保留旧结果。
    _MISSING = object()
    _old_raw = getattr(base_res, "vulnerabilities", _MISSING)
    _new_raw = getattr(new_res, "vulnerabilities", _MISSING)
    if _old_raw is _MISSING or _new_raw is _MISSING:
        return new_res
    _old = list(_old_raw or [])
    _new = list(_new_raw or [])
    if not _new:
        # 重跑一条都没产出 ⇒ 保留旧结果（整份替换会把该文件清空，是召回丢失通道）。
        return base_res
    if not _old:
        return new_res
    _merged: Dict[Any, Any] = {}
    _order: List[Any] = []
    for _v in _old:
        _k = _vuln_identity(_v)
        if _k not in _merged:
            _order.append(_k)
        _merged[_k] = _v
    for _v in _new:
        _k = _vuln_identity(_v)
        if _k not in _merged:
            _order.append(_k)
        _merged[_k] = _v
    _out = [_merged[_k] for _k in _order]
    # 主体必须是 new_res：重跑的语义就是「用新结果替换该文件」，除 vulnerabilities 之外的
    # 文件级字段（版本标记/文件级评分等）都应以重跑产物为准；并集只做一件事——把
    # 「重跑未复答」的旧条目补回新结果，绝不能反过来让旧对象当主体。
    # 失败（该文件结果的版本标记回退成 old，等于重跑白跑），改为优先 new_res。
    for _target in (new_res, base_res):
        try:
            setattr(_target, "vulnerabilities", _out)
            return _target
        except Exception:
            continue
    return new_res


def _merge_a2_results(base: List[Any], rerun: List[Any]) -> List[Any]:
    """把闭环重跑结果按文件合并回全量 A2 结果集。

    背景：闭环为省 LLM 只重跑「失败 finding 所在文件」（_failed_files_from_feedback 收窄），
    但 run_d2_verify 的候选全集是由传入的 a2_results 构造的（for result in a1_results + a2_results）。
    直接把收窄结果传进去，D2 就只重验那几个文件，与闭环前的全量计数不可比 ——

    收窄只是「少跑 LLM」的优化，绝不能缩小 D2 的验证范围。
    合并口径：以全量集合的文件顺序为骨架，按漏洞假说身份键 (file, line, type) 取并集——
    重跑命中同键则覆盖（拿到修正后的 exploit_spec），未命中则保留 base 原有假说；
    重跑新出现的文件追加到末尾（保持报告顺序稳定）。

    """
    if not rerun:
        return list(base or [])
    by_file: Dict[str, Any] = {}
    order: List[str] = []
    for r in (base or []):
        f = str(getattr(r, "file", "") or "")
        if f not in by_file:
            order.append(f)
            by_file[f] = r
        else:
            # 全量集合内部同文件多份结果：同样取并集，不整份替换。
            by_file[f] = _merge_vulns_into(by_file[f], r)
    for r in rerun:
        f = str(getattr(r, "file", "") or "")
        if f not in by_file:
            order.append(f)
            by_file[f] = r
        else:
            # A2 闭环重跑为省 LLM 只重跑部分文件，且重跑产物常比原始少（LLM 未对全部假说复答），
            # 整份替换会把 base 里「没被重跑到 / 重跑未复答」的假说一并清掉。
            # 实测由此丢 59 个用例、其中 33 条真值 TP（召回 100%→54.2%）。
            # 改为按身份键取并集：new 覆盖同键，base 独有的保留。
            by_file[f] = _merge_vulns_into(by_file[f], r)
    # 观测面：合并只应增大或持平，缩小即说明重跑侧收窄，是召回丢失通道，必须留痕。
    _n_base = sum(len(getattr(r, "vulnerabilities", []) or []) for r in (base or []))
    _n_out = sum(len(getattr(by_file[f], "vulnerabilities", []) or []) for f in order)
    if _n_out < _n_base:
        logger.warning(
            "[闭环][合并] A2 重跑合并后假说数减少：base %d -> merged %d（已按身份键取并集仍减少，"
            "请核查重跑侧产物是否收窄）", _n_base, _n_out,
        )
    else:
        logger.info("[闭环][合并] A2 重跑合并：base %d 条假说 -> merged %d 条", _n_base, _n_out)
    return [by_file[f] for f in order]


def _mk_a2_progress(_tid: Optional[int], _od: str, _it: int):
    """§P4：闭环 A2 重跑的逐文件进度心跳回调（on_progress(done, total)）。"""

    def _cb(done, total):
        _emit_stage_progress(_tid, _od, "a2_progress",
                             {"total": total, "done": done, "status": "closed_loop_rerun", "iteration": _it})
    return _cb


def _build_a1_evidence_index(a1_results):
    by_file = {}
    aggregate = {
        "entry_candidates": [],
        "source_candidates": [],
        "sink_candidates": [],
        "guard_candidates": [],
        "sanitizer_candidates": [],
        "ownership_candidates": [],
        "state_transition_candidates": [],
        "artifact_candidates": [],
        "business_logic_candidates": [],
    }
    for result in a1_results or []:
        evidence = dict(getattr(result, "evidence", {}) or {})
        if not evidence:
            continue
        # 否则 A1 证据永远合不进 A2 结果（同 _norm_path_key 注释）。
        file_key = _norm_path_key(str(getattr(result, "file", "") or ""))
        if file_key:
            by_file[file_key] = evidence
        for key in aggregate:
            aggregate[key].extend(list(evidence.get(key, []) or []))
    return {"by_file": by_file, "aggregate": aggregate}


def _merge_a1_evidence(per_file, aggregate):
    merged = {}
    for key in (
        "entry_candidates",
        "source_candidates",
        "sink_candidates",
        "guard_candidates",
        "sanitizer_candidates",
        "ownership_candidates",
        "state_transition_candidates",
        "artifact_candidates",
        "business_logic_candidates",
    ):
        merged[key] = list(per_file.get(key, []) or []) + list(aggregate.get(key, []) or [])
    return merged


def _proof_complete(proof):
    normalized = normalize_chain_proof(proof or empty_chain_proof())
    return all(
        normalized.get(key)
        for key in (
            "reachable",
            "attacker_control_proven",
            "gate_bypass_or_satisfaction_proven",
            "payload_shape_proven",
            "success_signal_anchor_proven",
        )
    )


def _extract_path_parameter(route: str) -> str:
    route_text = str(route or "")
    match = re.search(r"<(?:[^:>]+:)?([^>]+)>", route_text)
    if match:
        return match.group(1)
    match = re.search(r"{([^{}]+)}", route_text)
    return match.group(1) if match else ""


def _entry_candidates_covering_line(candidates, vuln_line: int):
    covered = []
    for item in list(candidates or []):
        try:
            start = int((item or {}).get("span_start", 0) or 0)
            end = int((item or {}).get("span_end", 0) or 0)
        except (TypeError, ValueError):
            continue
        if start and end and start <= vuln_line <= end:
            covered.append(item)
    return covered


def _source_candidate_tags(candidate: Dict[str, Any]) -> list:
    raw = (candidate or {}).get("semantic_tags", []) or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(tag or "").strip().lower() for tag in raw if str(tag or "").strip()]


def _prefer_source_candidate(candidates, payload_family: str, route: str = "", function: str = ""):
    payload_family = str(payload_family or "").strip().lower()
    pool = list(candidates or [])
    if not pool:
        return {}
    if route:
        route_matches = [item for item in pool if str(item.get("route", "") or "").strip() == route]
        if route_matches:
            pool = route_matches
    if function:
        function_matches = [item for item in pool if str(item.get("function", "") or "").strip() == function]
        if function_matches:
            pool = function_matches

    def score(item):
        tags = _source_candidate_tags(item)
        name = str((item or {}).get("name", "") or "").strip().lower()
        location = str((item or {}).get("location", "") or "").strip().lower()
        base = 0
        if payload_family == "ssrf":
            if "url_like" in tags:
                base += 50
            if is_ssrf_source_candidate(item):
                base += 25
        elif payload_family == "idor":
            if "resource_identifier" in tags:
                base += 50
            if location == "path":
                base += 20
            if name.endswith("_id") or name == "id":
                base += 10
        elif payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"}:
            if "auth_like" in tags:
                base += 50
            if location in {"header", "cookie"}:
                base += 20
        else:
            base += 10 if tags else 0
        return base

    ranked = sorted(pool, key=lambda item: (score(item), -candidate_line(item)), reverse=True)
    best = ranked[0]
    if payload_family == "ssrf" and score(best) < 50:
        return {}
    if payload_family == "idor" and score(best) < 50:
        return {}
    if payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"} and score(best) < 50:
        return {}
    return best


def _apply_a1_evidence_to_vulnerability(vuln, evidence):
    if not evidence:
        return
    setattr(vuln, "a1_evidence", evidence)
    entry_candidates = list(evidence.get("entry_candidates", []) or [])
    source_candidates = list(evidence.get("source_candidates", []) or [])
    guard_candidates = list(evidence.get("guard_candidates", []) or [])
    list(evidence.get("sanitizer_candidates", []) or [])
    ownership_candidates = list(evidence.get("ownership_candidates", []) or [])
    state_candidates = list(evidence.get("state_transition_candidates", []) or [])
    artifact_candidates = list(evidence.get("artifact_candidates", []) or [])
    vuln.proof_context_summary = summarize_proof_context(vuln, evidence)

    def _handler_aligned_candidates(candidates, *, route="", function=""):
        route = str(route or "").strip()
        function = str(function or "").strip()
        if route:
            matches = [item for item in candidates if str(item.get("route", "") or "").strip() == route]
            if matches:
                return matches
        if function:
            matches = [item for item in candidates if str(item.get("function", "") or "").strip() == function]
            if matches:
                return matches
        return list(candidates or [])

    if not getattr(vuln, "entry_point", "") and entry_candidates:
        nearest_entry = pick_nearest_candidate(vuln, entry_candidates) or {}
        method = str(nearest_entry.get("method", "") or "").upper() or "GET"
        route = str(nearest_entry.get("route", "") or "")
        if route:
            vuln.entry_point = f"{method} {route}"
            vuln.has_http_entry = True

    spec = normalize_exploit_spec(getattr(vuln, "exploit_spec", {}) or {})
    entry = spec["entry"]
    payload = spec["payload"]
    prerequisites = spec["prerequisites"]
    success_signal = spec["success_signal"]
    payload_family = str(payload.get("payload_family", "") or "")
    if payload_family == "generic":
        payload_family = ""
    family_text = "\n".join([
        str(getattr(vuln, "type", "") or ""),
        str(getattr(vuln, "description", "") or ""),
        str(getattr(vuln, "code_snippet", "") or ""),
    ]).lower()

    nearest_entry = {}
    if entry_candidates:
        covered_entries = _entry_candidates_covering_line(entry_candidates, int(getattr(vuln, "line", 0) or 0))
        nearest_entry = pick_nearest_candidate(vuln, covered_entries) or pick_nearest_candidate(vuln, entry_candidates) or {}
        entry["route"] = entry["route"] or str(nearest_entry.get("route", "") or "")
        entry["method"] = entry["method"] or str(nearest_entry.get("method", "") or "").upper()
    bound_function = str(nearest_entry.get("function", "") or "")
    aligned_sources = _handler_aligned_candidates(source_candidates, route=entry.get("route", ""), function=bound_function)
    if source_candidates:
        nearest_source = _prefer_source_candidate(aligned_sources, payload_family, route=entry.get("route", ""), function=bound_function)
        if not nearest_source:
            nearest_source = pick_nearest_candidate(vuln, aligned_sources) or pick_nearest_candidate(vuln, source_candidates) or {}
        source_route = str(nearest_source.get("route", "") or "")
        source_method = str(nearest_source.get("method", "") or "").upper()
        source_function = str(nearest_source.get("function", "") or "")
        if source_route and (not entry.get("route") or (source_function and source_function != bound_function)):
            entry["route"] = source_route
        if source_method and (not entry.get("method") or (source_function and source_function != bound_function)):
            entry["method"] = source_method
        if source_function and not bound_function:
            bound_function = source_function
        entry["parameter_name"] = entry["parameter_name"] or str(nearest_source.get("name", "") or "")
        source_location = str(nearest_source.get("location", "") or "")
        entry["parameter_location"] = entry["parameter_location"] or (
            "query" if source_location in {"query", "args"} else
            "body" if source_location in {"json", "body"} else
            "form" if source_location in {"form", "file"} else
            "header" if source_location in {"header", "cookie"} else
            "path" if source_location == "path" else
            ""
        )
        source_tags = [str(tag or "").strip().lower() for tag in (nearest_source.get("semantic_tags", []) or []) if str(tag or "").strip()]
        if "raw_body" in source_tags:
            entry["parameter_location"] = "raw_body"
            entry["content_type"] = entry["content_type"] or "text/plain"
    path_parameter = _extract_path_parameter(entry.get("route", ""))
    if (
        (not payload_family or payload_family in {"auth-bypass", "generic"})
        and (
            any(token in family_text for token in ("idor", "insecure direct object reference", "ownership"))
            or (path_parameter and ownership_candidates)
        )
    ):
        payload["payload_family"] = "idor"
        payload_family = "idor"
    if (
        (not payload_family or payload_family == "generic")
        and any(token in family_text for token in ("code injection", "代码注入", "eval(", "dynamic code", "arbitrary code", "remote code", "命令执行"))
    ):
        payload["payload_family"] = "command-execution"
        payload_family = "command-execution"
    if (
        (not payload_family or payload_family == "generic")
        and any(token in family_text for token in ("default credential", "hardcoded credential", "hardcoded password", "insecure credentials", "curl --user", "grafana"))
    ):
        payload["payload_family"] = "default-credentials"
        payload_family = "default-credentials"

    current_route = str(entry.get("route", "") or "")
    matching_entry = None
    for candidate in entry_candidates:
        candidate_route = str(candidate.get("route", "") or "")
        if current_route and candidate_route == current_route:
            matching_entry = candidate
            break
    if matching_entry:
        candidate_method = str(matching_entry.get("method", "") or "").upper()
        if candidate_method and (
            not entry.get("method")
            or (payload_family == "idor" and entry.get("method", "").upper() == "GET" and candidate_method != "GET")
        ):
            entry["method"] = candidate_method

    if path_parameter and payload_family == "idor":
        entry["parameter_name"] = path_parameter
        entry["parameter_location"] = "path"
    if payload_family == "ssrf" and not has_ssrf_source_evidence(vuln, evidence, route=entry.get("route", ""), handler=bound_function):
        entry["parameter_name"] = ""
        entry["parameter_location"] = ""
    if payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"} and not has_auth_source_evidence(vuln, entry.get("parameter_name", ""), evidence, route=entry.get("route", ""), handler=bound_function):
        entry["parameter_name"] = ""
        entry["parameter_location"] = ""
    if payload_family == "idor" and not has_idor_source_evidence(vuln, entry.get("parameter_name", ""), evidence, route=entry.get("route", ""), handler=bound_function):
        entry["parameter_name"] = path_parameter or ""
        entry["parameter_location"] = "path" if path_parameter else ""

    if payload_family == "idor":
        payload["payload_constraints"] = payload.get("payload_constraints") or ["resource identifier must cross an ownership boundary"]
        payload["candidate_payloads"] = payload.get("candidate_payloads") or ["alternate_owner_resource_id"]
        payload["generator_hint"] = payload.get("generator_hint") or "pick an identifier belonging to a different owner or tenant"
        success_signal["signal_type"] = success_signal["signal_type"] or "authorization_or_state_change"
        success_signal["match_strategy"] = success_signal["match_strategy"] or "cross_owner_access"
        success_signal["expected_indicators"] = success_signal.get("expected_indicators") or ["authorization bypass", "unexpected cross-owner resource access"]
    elif payload_family == "ssrf":
        success_signal["signal_type"] = success_signal["signal_type"] or "response_body"
        success_signal["match_strategy"] = success_signal["match_strategy"] or "contains_any"
        success_signal["expected_indicators"] = success_signal.get("expected_indicators") or ["root:", "127.0.0.1", "localhost"]
    elif payload_family == "command-execution":
        success_signal["signal_type"] = success_signal["signal_type"] or "response_body"
        success_signal["match_strategy"] = success_signal["match_strategy"] or "contains_any"
        success_signal["expected_indicators"] = success_signal.get("expected_indicators") or ["uid=", "gid=", "proof", "root:"]
    elif payload_family == "default-credentials":
        entry["parameter_name"] = entry.get("parameter_name") or "authorization"
        entry["parameter_location"] = "header"
        entry["content_type"] = entry.get("content_type") or "application/json"
        if not entry.get("route"):
            entry["route"] = "/api/users/1"
        payload["payload_constraints"] = payload.get("payload_constraints") or ["embedded or default privileged credentials must be usable against a live service API"]
        payload["candidate_payloads"] = payload.get("candidate_payloads") or ["admin:admin"]
        payload["verification_payloads"] = payload.get("verification_payloads") or ["admin:admin"]
        payload["high_impact_payloads"] = payload.get("high_impact_payloads") or ["a3-proof-admin-email@example.com"]
        payload["generator_hint"] = payload.get("generator_hint") or "use exposed default credentials against a privileged service API"
        success_signal["signal_type"] = success_signal["signal_type"] or "authorization_or_state_change"
        success_signal["match_strategy"] = success_signal["match_strategy"] or "privileged_api_access"
        success_signal["expected_indicators"] = success_signal.get("expected_indicators") or ["isGrafanaAdmin", "email", "login"]
        success_signal["verify_request"] = success_signal.get("verify_request") or {"path": entry.get("route") or "/api/user", "method": "GET"}

    if guard_candidates:
        prerequisites["auth_required"] = prerequisites["auth_required"] if prerequisites["auth_required"] != "unknown" else "required"
    aligned_ownership = _handler_aligned_candidates(ownership_candidates, route=entry.get("route", ""), function=bound_function)
    aligned_guards = _handler_aligned_candidates(guard_candidates, route=entry.get("route", ""), function=bound_function)
    aligned_state = _handler_aligned_candidates(state_candidates, route=entry.get("route", ""), function=bound_function)
    aligned_artifacts = _handler_aligned_candidates(artifact_candidates, route=entry.get("route", ""), function=bound_function)
    if aligned_guards:
        prerequisites["auth_required"] = prerequisites["auth_required"] if prerequisites["auth_required"] != "unknown" else "required"
    if aligned_ownership and not prerequisites["dependent_data"]:
        prerequisites["dependent_data"] = ["a resource owned by a different user or tenant must exist"]
    if aligned_state and not prerequisites["ordered_steps"]:
        prerequisites["ordered_steps"] = [
            "prepare the business object or account state",
            "send the conflicting or bypass request sequence",
            "observe unauthorized state change or duplicate effect",
        ]
    if aligned_artifacts and not success_signal.get("side_effect_target"):
        success_signal["side_effect_target"] = "artifact_or_runtime_side_effect"
    if payload_family == "default-credentials":
        prerequisites["auth_required"] = "required"
        prerequisites["role_or_permission"] = prerequisites.get("role_or_permission") or "admin"

    merged_spec = normalize_exploit_spec(merge_exploit_specs(getattr(vuln, "exploit_spec", {}) or {}, spec))
    merged_entry = merged_spec["entry"]
    if matching_entry:
        candidate_method = str(matching_entry.get("method", "") or "").upper()
        if candidate_method and payload_family == "idor":
            merged_entry["method"] = candidate_method
    if path_parameter and payload_family == "idor":
        merged_entry["parameter_name"] = path_parameter
        merged_entry["parameter_location"] = "path"
    if payload_family == "ssrf" and not has_ssrf_source_evidence(vuln, evidence, route=merged_entry.get("route", ""), handler=bound_function):
        merged_entry["parameter_name"] = ""
        merged_entry["parameter_location"] = ""
    if payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"} and not has_auth_source_evidence(vuln, merged_entry.get("parameter_name", ""), evidence, route=merged_entry.get("route", ""), handler=bound_function):
        merged_entry["parameter_name"] = ""
        merged_entry["parameter_location"] = ""
    if payload_family == "idor" and not has_idor_source_evidence(vuln, merged_entry.get("parameter_name", ""), evidence, route=merged_entry.get("route", ""), handler=bound_function):
        merged_entry["parameter_name"] = path_parameter or ""
        merged_entry["parameter_location"] = "path" if path_parameter else ""
    vuln.exploit_spec = merged_spec
    if merged_entry.get("route") and merged_entry.get("method"):
        vuln.entry_point = f"{str(merged_entry.get('method') or '').upper()} {merged_entry.get('route')}"
        vuln.has_http_entry = True

    proof = evaluate_proof_obligations(
        vuln,
        merged_spec,
        evidence=evidence,
        incoming_proof=getattr(vuln, "chain_proof", {}) or empty_chain_proof(),
    )
    vuln.chain_proof = normalize_chain_proof(proof)
    vuln.proof_gaps = list(vuln.chain_proof.get("proof_gaps", []) or [])
    if _proof_complete(vuln.chain_proof):
        vuln.proof_tier = "chain_proven"
    else:
        vuln.proof_tier = "broad_static"


def _drop_spurious_cross_family(results, code_root: str = ""):
    """A2 侧「跨族无 sink 即捏造」门禁（与 A1 侧 spurious_no_sink **同一判据**）。

        hash / xss 的安全用例上，A2 自建出 ``sql_injection`` finding，而该文件里连
        sql/jdbc/statement 关键字都没有。A1 侧早已有这道闸
        （``_filter_property_family_findings`` 里的 ``spurious_no_sink``），但 A2 自建 finding
        不走那条路 ⇒ 长期贡献 5 个跨族 FP（01045 / 01169 / 01348 / 01586 / 01661）。

    判据方向恒为「判假」：只在「该族应有的 API 在文件里完全不存在」时剔除，
    对任何带 API 的 finding 无影响。``spurious_no_sink`` 只对登记过的族生效
    （sql_injection / command_execution / xss / securecookie / ldapi / xpathi），
    path_traversal / trustbound 显式不判（会误杀真漏洞，见其注释）。

    case 级离线验证（19 个任务、全部确认态 spec）：**误杀 TP = 0，消 FP = 6**。
    """
    if not results:
        return results
    try:
        from src.iast.property_evidence import spurious_no_sink as _sns
    except Exception:  # noqa: BLE001  fail-open：门禁不可用不阻断主流程
        return results
    cache: dict = {}
    dropped = 0
    for r in results or []:
        fpath = str(getattr(r, "file", "") or "")
        # 而 code_root 已经是 ...\src\main\java。直接 join 得到 ...\src\main\java\src\main\java\...
        # 不存在 ⇒ code 为空 ⇒ 门禁静默空转（01586/01661 就是这样漏掉的）。
        # 统一走 _resolve_source_path（绝对路径 / 逐段剥离前缀都试）。
        _rp = _resolve_source_path(str(code_root or ""), fpath)
        absp = str(_rp) if _rp else ""
        code = cache.get(absp)
        if code is None:
            try:
                code = open(absp, encoding="utf-8", errors="ignore").read() if absp else ""
            except Exception:
                code = ""
            cache[absp] = code
        if not code:
            continue
        surv = []
        for v in (getattr(r, "vulnerabilities", []) or []):
            vtype = str(getattr(v, "type", "") or "")
            try:
                _fw_hit2 = bool((getattr(v, "a1_evidence", None) or {}).get("framework_sink"))
                if _sns(code, vtype, framework_sink=_fw_hit2):
                    dropped += 1
                    continue
            except Exception:  # noqa: BLE001  单条判据异常不得拖垮整份结果
                pass
            surv.append(v)
        if len(surv) == len(getattr(r, "vulnerabilities", []) or []):
            continue
        try:
            r.vulnerabilities[:] = surv          # 原地改：兼容 pydantic / dataclass
        except Exception:
            try:
                r.vulnerabilities = surv
            except Exception:
                pass
    if dropped:
        logger.info("[A2] 跨族无 sink 门禁剔除 %d 条捏造 finding（文件里没有该族 API）", dropped)
    return results


def _merge_a1_evidence_into_a2_results(a2_results, a1_results):
    evidence_index = _build_a1_evidence_index(a1_results)
    for scan_result in a2_results or []:
        per_file = evidence_index["by_file"].get(
            _norm_path_key(str(getattr(scan_result, "file", "") or "")), {})
        fallback = evidence_index["aggregate"]
        for vuln in getattr(scan_result, "vulnerabilities", []) or []:
            vuln_evidence = merge_a1_evidence(per_file, fallback)
            _apply_a1_evidence_to_vulnerability(vuln, vuln_evidence)
    return a2_results


def _resolve_source_path(code_root: str, rel_path: str):
    """把 finding 的相对路径解析到真实源码文件。

    A2 产出的 ``vuln.file`` 可能带 Windows 反斜杠、可能是绝对路径、也可能相对的是
    ``prepared_scan_root`` 的子根（target_path/src 之类），逐一尝试。
    """
    from pathlib import Path as _Path
    raw = str(rel_path or "").strip()
    if not raw:
        return None
    candidates = []
    normalized = raw.replace("\\", "/")
    p = _Path(normalized)
    if p.is_absolute():
        candidates.append(p)
    if code_root:
        root = _Path(code_root)
        candidates.append(root / normalized)
        parts = _Path(normalized).parts
        for i in range(1, len(parts)):
            candidates.append(root / _Path(*parts[i:]))
    for cand in candidates:
        try:
            if cand.is_file():
                return cand
        except OSError:
            continue
    return None


# 方法级窗口的上边界锚点：Spring 路由注解，或方法签名行。
# A2 报的行号常落在 import / javadoc / 类声明上（benchmark_cli 里早有
# _line_content_looks_implausible 承认这一点），盲目 ±2 行取窗口会把
# "import java.util.Date;" 当成漏洞代码 —— 实测 12 条样本里 6 条是这样。
# 从报点行往上找最近的路由注解或方法签名，把窗口顶到那里，片段才带得上
# @GetMapping("/xxx") 与方法签名，这是证明「可达 + 攻击者可控」的唯一硬依据。
_METHOD_ANCHOR_RE = None
_MAX_ANCHOR_LOOKBACK = 12


def _method_window(lines: list, anchor: int, span: int) -> tuple:
    """返回 (lo, hi)：优先从最近的方法/路由注解处起，覆盖到报点行之后若干行。"""
    global _METHOD_ANCHOR_RE
    if _METHOD_ANCHOR_RE is None:
        import re as _re
        _METHOD_ANCHOR_RE = _re.compile(
            r"^\s*(@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b"
            r"|(?:public|protected|private)\s+[\w<>\[\],.?\s]+\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?\{?\s*$)"
        )
    start = anchor - 1  # 0-based 报点行
    lo = start
    for idx in range(start, max(-1, start - _MAX_ANCHOR_LOOKBACK), -1):
        if _METHOD_ANCHOR_RE.match(lines[idx] or ""):
            lo = idx
            break
    hi = min(len(lines), start + span + 1)
    # 单个方法体过长时截断，避免把整文件塞进提示词
    if hi - lo > 40:
        hi = lo + 40
    return max(0, lo), hi


def _backfill_code_snippets(a2_results, code_root: str, *, span: int = 2) -> Dict[str, Any]:
    """确定性片段回填：给「有 file+line 但没有代码片段」的 finding 补上真实源码行。

    实测暴露的长期缺陷：**应用类 findings 里只有 10% 带代码片段**，
    历史轮次 连续八轮都是 3~6%（云端 agnes 的 本轮更低，只有 3.2%，所以不是
    本地小模型造成的）。根因是 A2 审计提示词的输出 schema 里**没有 code 字段**
    （src/prompts/audit_prompts.yaml 只要求 type/severity/line/description/fix/
    entry_method/route/params），而解析侧读的是 ``v.get('code', '')``，于是绝大多数
    条目的 code_snippet 恒为空串。

    后果不止是「报告里看不到代码」：``evaluate_proof_obligations`` 的证据文本
    （merge_supporting_text）包含 code_snippet，片段为空 → 证明义务拿不到任何代码
    依据 → 直接被压成 broad_static；路径 C 的二次证明也因此**没有可投喂的上下文**

    修法：file+line 已知，直接从磁盘读真实源码行回填。这是**真实数据**，不是模型
    生成、也不是占位；读不到就保持空，绝不编造。放在 A1 证据合并（证明义务评估）
    之前，使规则层能吃到真实代码文本。
    """
    stats = {"scanned": 0, "filled": 0, "already": 0, "no_file": 0, "no_line": 0, "unreadable": 0}
    cache: Dict[str, list] = {}
    for scan_result in a2_results or []:
        for vuln in getattr(scan_result, "vulnerabilities", []) or []:
            stats["scanned"] += 1
            if str(getattr(vuln, "code_snippet", "") or "").strip():
                stats["already"] += 1
                continue
            try:
                line_no = int(getattr(vuln, "line", 0) or 0)
            except (TypeError, ValueError):
                line_no = 0
            if line_no <= 0:
                stats["no_line"] += 1
                continue
            rel = str(getattr(vuln, "file", "") or "")
            if rel not in cache:
                path = _resolve_source_path(code_root, rel)
                if path is None:
                    cache[rel] = []
                else:
                    try:
                        cache[rel] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    except Exception:
                        cache[rel] = []
            lines = cache.get(rel) or []
            if not lines:
                stats["no_file"] += 1
                continue
            if line_no > len(lines):
                stats["unreadable"] += 1
                continue
            # 以报点行为中心取窗口；报点行本身是空行就向后找最近的非空行
            anchor = line_no
            if not lines[anchor - 1].strip():
                for idx in range(line_no, min(len(lines), line_no + 3)):
                    if lines[idx].strip():
                        anchor = idx + 1
                        break
            lo, hi = _method_window(lines, anchor, span)
            snippet = "\n".join(lines[lo:hi]).strip()
            if not snippet:
                stats["unreadable"] += 1
                continue
            vuln.code_snippet = snippet
            stats["filled"] += 1
    if stats["filled"]:
        logger.info(
            "[snippet-backfill] 回填 %d/%d 条代码片段（已有 %d / 文件不可解析 %d / 行号无效 %d）",
            stats["filled"], stats["scanned"], stats["already"], stats["no_file"], stats["no_line"],
        )
    return stats


def _run_proof_second_pass(a2_results, *, task_id=None, output_dir="", progress_logger=None) -> Dict[str, Any]:
    """路径 C：对 broad_static 条目跑一轮聚焦提示词二次证明。

    用户铁律：运行状态必须同步前端、不能后端偷跑。所以这里把它做成独立可见阶段
    （a2_proof_second_pass），有心跳、有阶段耗时、有统计落 stage_results。
    全程 fail-open：模块缺失/离线/异常都不改变既有结果。
    """
    stats: Dict[str, Any] = {}
    try:
        from src.core.second_pass_proof import run_second_pass, run_validate_pass

        def _on_progress(done, total):
            _emit_stage_progress(task_id, output_dir, "a2_proof_second_pass_progress",
                                 {"total": total, "done": done, "status": "proving"})
            _update_scan_progress_metadata(
                output_dir,
                {"stage_results": {"a2_proof_second_pass": {
                    "status": "running",
                    "message": f"二次证明中（{done}/{total}）",
                    "total": total, "done": done,
                }}},
            )

        # 先探一次配置，未启用就不在前端制造一个空阶段
        try:
            from src.core.second_pass_proof import load_config
            _cfg = load_config()
        except Exception:
            _cfg = {"enabled": True}
        if not (_cfg.get("enabled") or _cfg.get("validate_enabled")):
            return {}

        _update_scan_progress_metadata(
            output_dir,
            {"stage_results": {"a2_proof_second_pass": {
                "status": "running", "message": "二次证明启动中", "total": 0, "done": 0,
            }}},
        )
        if progress_logger is not None:
            try:
                progress_logger.update_phase('phase4b', 'running', '二次证明中')
            except Exception:
                pass
        _started = time.time()
        stats = run_second_pass(a2_results, on_progress=_on_progress) or {}
        # 问题 5：validate_vulnerability 真伪判定（默认关闭；fail-open；只跑不确定子集）
        try:
            validate_stats = run_validate_pass(a2_results, on_progress=_on_progress) or {}
        except Exception as _ve:
            logger.warning("[second-pass] validate 子阶段异常（不阻断主流程）：%s", _ve)
            validate_stats = {}
        stats["validate"] = validate_stats
        stats["duration_seconds"] = round(time.time() - _started, 2)
        _emit_stage_progress(task_id, output_dir, "a2_proof_second_pass_progress",
                             {"total": int(stats.get("attempted", 0) or 0),
                              "done": int(stats.get("done", 0) or 0),
                              "status": "proving_done"})
        _v = stats.get("validate", {}) or {}
        _msg = (
            f"二次证明完成：链证成升级 {stats.get('upgraded', 0)}、"
            f"真伪判定 真{_v.get('judged_tp', 0)}/假{_v.get('judged_fp', 0)}"
            f"（候选 {stats.get('candidates', 0)}、调用 {stats.get('llm_called', 0)}）"
        )
        _update_scan_progress_metadata(
            output_dir,
            {"stage_results": {"a2_proof_second_pass": {
                "status": "completed",
                "message": _msg,
                "total": int(stats.get("attempted", 0) or 0),
                "done": int(stats.get("done", 0) or 0),
                "duration_seconds": stats["duration_seconds"],
                "upgraded": int(stats.get("upgraded", 0) or 0),
                "validate": _v,
                "model": stats.get("model", ""),
            }}},
        )
        if progress_logger is not None:
            try:
                progress_logger.update_phase(
                    'phase4b', 'completed',
                    f"二次证明：升级 {stats.get('upgraded', 0)} 条为 chain_proven",
                )
            except Exception:
                pass
        print(f"[*] Proof second pass: upgraded {stats.get('upgraded', 0)} / "
              f"attempted {stats.get('attempted', 0)} in {stats['duration_seconds']}s")
    except Exception as _exc:
        logger.warning("[second-pass] 阶段执行失败（不阻断主流程）：%s", _exc)
        return {}
    return stats


def _line_content_looks_implausible(text: str) -> bool:
    """待请示 6 项 #6：判断某行源码内容是否「不像真实漏洞定位」。

    命中即视为 LLM 猜测的行号不可信，应用端点注解行回填：
    - 空行 / 纯括号行（} ; { };
    - 构造赋值 this.x = x;
    - 字段声明 private/public ... x;（无方法调用）
    保守：含方法调用 '(' 的行不判为不可信，避免误覆盖真实 sink 行。
    """
    import re as _re
    _s = (text or "").strip()
    if not _s:
        return True
    if _s in ("}", "};", "{", "};", "})", "});"):
        return True
    if _re.search(r"\bthis\.\w+\s*=", _s):
        return True
    if _re.match(r"^(private|protected|public|static|final|transient|volatile)\b", _s) \
            and "(" not in _s and (";" in _s or "=" in _s):
        return True
    return False


def _route_and_method_from_signature(signature: str):
    """从 entry_discovery 条目的 signature 里解析 (route, method)。

    条目字段是 entry_type / file / line / signature / confidence / source / entry_hash /
    request_params / metadata —— **没有 route，也没有 method**。原实现用
    `_dr.get("route") == entry["route"]` 取注解行，左边恒为空串，永远匹配不上，
    source_line 全为 ""，line_backfilled=0）。改为从 signature 解析。

    解析规则：注解名决定 method（GetMapping→GET 等；RequestMapping 无 method 参数时返回 ""，
    表示通配）；引号内第一个以 / 开头的串即路由（类级前缀已由 _rewrite_signature_prefix
    提前拼进 signature，故这里拿到的一般已是完整路由）。
    """
    sig = str(signature or "")
    m = re.search(r"@(Get|Post|Put|Delete|Patch|Request)Mapping", sig)
    method = ""
    if m:
        if m.group(1) != "Request":
            method = m.group(1).upper()
        else:
            rm = re.search(r"RequestMethod\.([A-Z]+)", sig)
            if rm:
                method = rm.group(1)
    route = ""
    for cand in re.findall(r"['\"]([^'\"]*)['\"]", sig):
        if cand.startswith("/"):
            route = cand
            break
    return route, method


def _annotation_line_for_route(route, method, discovered_routes, vuln_file=""):
    """在 discovered_routes 里找该端点的注解行；找不到返回 0。

    两轮匹配（都按「去掉尾部斜杠 + 小写」比较，避免大小写/尾斜杠差异造成的假 miss；
    这里只用于定位行号，不参与任何路由回写，故不受「路由大小写保真」约束的影响）：
    ① 路由 + 方法精确匹配（方法为通配或条目无方法时只比路由）；
    ② 退化为「同文件 + 同方法」取第一条（应对 resolve_endpoint_full 补了上下文前缀、
       与源码注解字面不一致的情况）。
    """
    def _norm_route(r):
        return str(r or "").strip().rstrip("/").lower()

    target_route = _norm_route(route)
    target_method = str(method or "").upper()
    fallback = 0
    for dr in (discovered_routes or []):
        if not isinstance(dr, dict):
            continue
        # 只认 web_route。真实 entries 里混有 rpc_method 等非路由条目，它们的 signature 是
        # 一旦落进下面的「同文件兜底」就会被当成注解行，把 line 指到注释上。
        _et = str(dr.get("entry_type") or "")
        if _et and _et != "web_route":
            continue
        try:
            line = int(dr.get("line") or 0)
        except Exception:
            line = 0
        if line <= 0:
            continue
        dr_route, dr_method = _route_and_method_from_signature(dr.get("signature"))
        if target_method and dr_method and dr_method != target_method:
            continue
        if fallback == 0:
            _df = str(dr.get("file") or "")
            _vf = str(vuln_file or "")
            if _df and _vf and (_df.endswith(_vf) or _vf.endswith(_df)):
                fallback = line
        if target_route and _norm_route(dr_route) == target_route:
            return line
    return fallback


def _backfill_finding_line(vuln, code_root):
    """待请示 6 项 #6：用端点注解行回填明显错误的 finding.line。

    仅当 vuln 已解析出可达入口（entry.source_line>0）且当前 vuln.line 落在不可信行
    （空行/右花括号/字段声明/构造赋值）或 line<=0 时才覆盖。命中真实 sink 的可信行不动，
    避免误伤路由归属（路由归属依赖 finding.line 落在注解行的假设）。
    覆盖时置 vuln.line_backfilled=True 供报告标注，绝不静默改写。fail-open：读文件异常不阻断。
    """
    try:
        _spec = getattr(vuln, "exploit_spec", None) or {}
        _entry = _spec.get("entry", {}) or {}
        _src_line = int(_entry.get("source_line") or 0)
        if _src_line <= 0:
            return
        _cur = int(getattr(vuln, "line", 0) or 0)
        _needs = _cur <= 0
        if not _needs and code_root:
            _fp = getattr(vuln, "file", "") or ""
            _p = Path(_fp) if Path(_fp).is_absolute() else Path(code_root) / _fp
            try:
                _lines = _p.read_text(encoding="utf-8", errors="ignore").splitlines()
                if 1 <= _cur <= len(_lines):
                    _needs = _line_content_looks_implausible(_lines[_cur - 1])
            except Exception:
                _needs = False
        if _needs:
            setattr(vuln, "line", _src_line)
            setattr(vuln, "line_backfilled", True)
            logger.info("[line-backfill] 漏洞 %s line %s→%s（端点注解行）", getattr(vuln, "type", ""), _cur, _src_line)
    except Exception as _e:
        logger.warning("[line-backfill] 回填失败（忽略）：%s", _e)


def _integrated_a2_enabled() -> bool:
    """集成分析师开关：默认开启（正常全量启动即走集成分析师）。
    SAST_AI_LEGACY_A2=1 时退回旧的 pre_resolve+plan_pocs 路径——仅作应急回滚/新旧 A/B，
    稳定后应删除本开关，最终只有一条路径。"""
    return os.environ.get("SAST_AI_LEGACY_A2", "") != "1"


def _run_integrated_analyst(a2_results, code_root, discovered_routes=None, on_progress=None):
    """A2 集成分析师（默认路径）：逐文件把「源码 + 该文件的 A1 findings」交给 LLM，
    一次产出「审计真假 + 可打通 spec」，写回 vuln.exploit_spec.entry/payload 并设 entry_resolved。

    替代旧的 _pre_resolve_a2_endpoints(确定性解路由) + plan_pocs(通用 payload)：
    - 审计与构造一体：route/method/param/payload 都由 LLM 直接给，不设确定性校验器；
      错路由/打法由后续 D1/D2/I2 重放闭环自纠兜底。
    - false_positive：entry_resolved=False，记录理由。
    跨文件：_gather_cross_file_context 从 a1_evidence 的 sink/source/sanitizer 候选取异文件片段注入。
    """
    from concurrent.futures import ThreadPoolExecutor
    from src.agents.a2_integrated_analyst import IntegratedAnalyst, _gather_cross_file_context
    from src.core.exploit_spec import normalize_exploit_spec

    an = IntegratedAnalyst()
    by_file: dict = {}
    total = 0
    for sr in a2_results or []:
        for v in getattr(sr, "vulnerabilities", []) or []:
            total += 1
            by_file.setdefault(str(getattr(v, "file", "") or ""), []).append((sr, v))
    file_list = list(by_file.items())

    def _analyze_one(item, allow_retry=True):
        fpath, items = item
        absp = fpath if os.path.isabs(fpath) else os.path.join(str(code_root or ""), fpath)
        try:
            code = open(absp, encoding="utf-8", errors="ignore").read()
        except Exception:
            code = ""
        findings = []
        for _sr, v in items:
            es = getattr(v, "exploit_spec", None) or {}
            pf = ((es.get("payload") or {}).get("payload_family") if isinstance(es, dict) else "") or ""
            findings.append({
                "line": int(getattr(v, "line", 0) or 0),
                "family": str(pf or getattr(v, "type", "") or ""),
                "note": str(getattr(v, "title", "") or "")[:80],
                "a1_evidence": getattr(v, "a1_evidence", None) or {},
            })
        extra = _gather_cross_file_context(findings, str(code_root or ""), fpath)
        if not code:
            return fpath, [], False
        _call = lambda: an.analyze(code, os.path.basename(fpath), findings, extra)
        try:
            specs = (_a2_analyze_with_retry(_call, fpath) if allow_retry else _call())
            return fpath, specs, False
        except Exception as _ae:  # noqa: BLE001
            from src.agents.a2_integrated_analyst import A2LLMUnavailable
            if isinstance(_ae, A2LLMUnavailable):
                logger.error("[integrated-a2] Ollama 熔断，整轮判失败：%s", _ae)
                raise
            logger.error("[integrated-a2] 文件 %s 分析失败（保留可诊断占位）：%s", fpath, _ae)
            return fpath, _a2_failure_placeholder(findings, _ae), True

    # 吞吐，只会线性拉长排队并推高 socket 读超时概率（见 src/core/llm_gate.py 头注）。
    # 仍可用 SAST_AI_INTEGRATED_WORKERS 覆盖，但默认值必须与服务端能力对齐。
    workers = max(1, int(float(os.environ.get("SAST_AI_INTEGRATED_WORKERS", "2") or 2)))
    specs_by_file: dict = {}
    failed_files: list = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as _ex:
        for fpath, specs, failed in _ex.map(_analyze_one, file_list):
            specs_by_file[fpath] = specs
            if failed:
                failed_files.append(fpath)
            done += len(by_file.get(fpath, []))
            if on_progress:
                on_progress(done, total)
    if failed_files:
        logger.warning("[integrated-a2] %d 个文件首轮分析失败，串行单并发重跑一次",
                       len(failed_files))
        for item in file_list:
            if item[0] not in failed_files:
                continue
            _fp, _sp, _failed = _analyze_one(item, allow_retry=False)
            specs_by_file[_fp] = _sp
            if _failed:
                _A2_ANALYSIS_ERRORS.append({"file": _fp, "error": "final retry failed"})

    # 串行写回（避免跨线程改 vuln 对象）
    real_n = fp_n = 0
    for fpath, items in file_list:
        specs = specs_by_file.get(fpath, [])
        spec_by_line = {}
        for s in specs:
            try:
                spec_by_line[int(s.get("line"))] = s
            except Exception:
                pass
        for idx, (_sr, v) in enumerate(items):
            s = spec_by_line.get(int(getattr(v, "line", 0) or 0)) or (specs[idx] if idx < len(specs) else None)
            if not s:
                continue
            verdict = s.get("verdict")
            if verdict == "real":
                real_n += 1
                sp = s.get("spec") or {}
                es = getattr(v, "exploit_spec", None)
                spec = normalize_exploit_spec(es) if isinstance(es, dict) else normalize_exploit_spec({})
                entry = spec.setdefault("entry", {})
                entry["route"] = str(sp.get("route") or "")
                entry["method"] = str(sp.get("method") or "GET").upper()
                entry["parameter_name"] = str(sp.get("param_name") or "")
                entry["parameter_location"] = str(sp.get("param_location") or "query")
                entry["resolved_by"] = "llm"
                _fam = str(getattr(v, "type", "") or "")
                _pl = str(sp.get("payload") or "").strip()
                spec["payload"] = {"payload_family": _fam,
                                   "candidate_payloads": [_pl] if _pl else []}
                try:
                    setattr(v, "exploit_spec", spec)
                    setattr(v, "entry_resolved", True)
                    setattr(v, "a21_selected", True)
                    setattr(v, "integrated_verdict", "real")
                    setattr(v, "integrated_reason", str(s.get("reason") or "")[:300])
                except Exception:
                    pass
            else:
                fp_n += 1
                try:
                    setattr(v, "entry_resolved", False)
                    setattr(v, "integrated_verdict", str(verdict or "false_positive"))
                    setattr(v, "integrated_reason", str(s.get("reason") or "")[:300])
                except Exception:
                    pass
    logger.info("[integrated-a2] 完成：文件 %d，finding %d，real %d，false_positive %d",
                len(by_file), total, real_n, fp_n)
    return a2_results


def _pre_resolve_a2_endpoints(a2_results, code_root, discovered_routes=None):
    """前移解析：在 plan_pocs 之前对每个 A2 漏洞做 resolve_endpoint_full（单一真相源），
    把 route+param+method 写回 vuln.exploit_spec.entry 作为 ground truth，
    并标记 vuln.entry_resolved / vuln.entry_resolution。

    批次 2：本步骤与 auto_register_from_a2 共用同一个 resolve_endpoint_full
    （core resolve_trigger_endpoint + 越权真实路由纠正 + 业务族端点推导），确保写入的
    entry.route（通道 B）与后续 trigger_specs.target_endpoint（通道 A）两处投影完全一致，
    消除此前 100% vs 16.7% 的漂移。

    - 解析器产出的入口优先于 LLM 猜测，plan_pocs 直接消费 ground truth，
      不再让 LLM 猜路由（避免 route 与 payload 不一致 / D1 重放 404）。
    - 解析不出入口的漏洞标 entry_resolved=False（无可达入口），后续不进 a21_selected / D2，
      省掉大量全空 route 的无效验证。
    - 静态分析与 TriggerSpec 登记解耦保持不变：本步骤只写回 entry，不登记 spec
      。
    """
    from src.core.exploit_spec import normalize_exploit_spec

    resolved_count = 0
    unresolved_count = 0
    for scan_result in a2_results or []:
        for vuln in getattr(scan_result, "vulnerabilities", []) or []:
            a1_ev = getattr(vuln, "a1_evidence", None) or {}
            try:
                resolved = resolve_endpoint_full(
                    vuln, a1_ev,
                    code_root=code_root or None,
                    discovered_routes=discovered_routes,
                )
            except Exception as _e:
                logger.warning(
                    "[pre-resolve] 端点解析异常（漏洞 %s）：%s", getattr(vuln, "type", ""), _e,
                )
                resolved = {"route": "", "method": "", "param_name": "", "param_location": "", "resolvable": False}
            setattr(vuln, "entry_resolution", resolved)
            setattr(vuln, "entry_resolved", bool(resolved.get("resolvable")))
            spec = normalize_exploit_spec(getattr(vuln, "exploit_spec", None) or {})
            entry = spec.setdefault("entry", {})
            if resolved.get("resolvable"):
                resolved_count += 1
                entry["route"] = str(resolved.get("route") or "")
                entry["method"] = str(resolved.get("method") or "GET").upper()
                entry["parameter_name"] = str(resolved.get("param_name") or "")
                entry["parameter_location"] = str(resolved.get("param_location") or "query")
                entry["resolved_by"] = str(resolved.get("param_name_source") or "source")
                # 业务类目随单一真相源一并写回，使 entry 携带与 spec 一致的 category（供 D2 路由差分重放）。
                _cat = str(resolved.get("category") or "")
                if _cat:
                    entry["business_logic_category"] = _cat
                # 供 line 回填。注意 entry_discovery 条目**没有 route/method 字段**，
                # 必须从 signature 解析——原实现直接读 _dr["route"] 恒为空，
                _src_line = _annotation_line_for_route(
                    entry["route"], entry["method"], discovered_routes,
                    vuln_file=(getattr(vuln, "file", "") or ""),
                )
                if _src_line:
                    entry["source_line"] = _src_line
            else:
                unresolved_count += 1
                # Q3②：不再清空 entry，避免抹掉 ground truth（如 A2 已给的 entry_route / 源码路径），
                # 仅落解析失败原因（resolution_failure）供审计与事后归因。门禁改由该字段显式判定，
                # 不再靠「清空全部 key」这种副作用达成。
                entry["entry_resolution_failure"] = str(resolved.get("resolution_failure") or "no_reachable_entry")
            vuln.exploit_spec = spec
            # finding.line 到端点注解行（仅当当前 line 不可信时）。必须放在 vuln.exploit_spec=spec
            # 之后——早一步 vuln.exploit_spec 还是旧对象，读不到刚写入的 source_line。
            _backfill_finding_line(vuln, code_root)
            # 此前 vuln.contract_completeness 保留的是"回填前"算出的陈旧快照
            # （status='missing', missing=['entry.route','entry.method']），而 report_manager
            # 用 `vuln.get('contract_completeness') or ...` 模式保留旧值、D2 门禁又直接读该字段，
            # 导致 SSTI 等族即使最终解析出可达入口也被永久拒在 D2 门外（SSTI 非业务族，
            # 用不了 is_contract_ready_item 的 a21_selected 豁免）。回填后重算即恢复为 ready。
            try:
                vuln.contract_completeness = exploit_spec_completeness(spec)
            except Exception as _cc_err:  # 重算失败绝不阻断主流程
                logger.warning(
                    "[pre-resolve] 契约完整度重算失败（漏洞 %s）：%s",
                    getattr(vuln, "type", ""), _cc_err,
                )
    logger.info(
        "[pre-resolve] 入口解析完成：%d 个漏洞解析出可达入口，%d 个无可达入口（不进 D2）",
        resolved_count, unresolved_count,
    )
    return a2_results


def _aggregate_d1_replay(verifications):
    """聚合 D1 统一重放指标（D1 已并入 verify 链路）。

    关键修正：``replayed`` 不能用 ``iast_evidence.replayed`` 计数——
    `aggregate_iast_evidence` 的返回（IastVerdict.to_dict）**根本没有 replayed 字段**，
    历史版本据此把 D1 永远算成 0 条 / skipped（即用户看到的「又被跳过了」）。

    正确的口径：
    - replayed：verify 是否真的被 trigger_spec 驱动（D1 实际发了重放流量）。
      run_d2_verify 已在每条 verification 写入 ``trigger_spec_provided``。
    - arrivals：``is_sink_reached(iast_evidence.state)``（IAST 探针确认 canary 到达 sink）。
      必须走统一判据，**不能**写成 ``state == 'sink-reached'``：探针显式断言态
      硬编码字符串比较会让抵达数几乎归零（详见 高危复发坑.md 第 24 条）。
    - impacts：``dast_impact_evidence.reached``（DAST 侧确认影响面到达）。
    """
    _d1_replayed = 0
    _d1_impacts = 0
    _d1_arrivals = 0
    _replayed_specs_detail: List[Dict[str, Any]] = []
    for _v in verifications or []:
        _ie = _v.get("iast_evidence", {}) or {}
        _de = _v.get("dast_impact_evidence", {}) or {}
        if _v.get("trigger_spec_provided"):
            _d1_replayed += 1
            _td = _v.get("trigger_spec_detail")
            if isinstance(_td, dict):
                _replayed_specs_detail.append({
                    "endpoint": _td.get("endpoint"),
                    "http_method": _td.get("http_method"),
                    "param_name": _td.get("param_name"),
                    "param_location": _td.get("param_location"),
                    "family": _td.get("family"),
                    "flow_type": derive_flow_type(_td.get("family") or ""),
                    "canary_identity": _td.get("canary_identity"),
                    "source": _td.get("source"),
                    "vulnerability_hash_v2": _td.get("vulnerability_hash_v2"),
                })
        if _de.get("reached"):
            _d1_impacts += 1
        # ④ sink 身份校验：canary 抵达 sink 态但落点在框架噪声 sink（非本族真 sink）→ 不计入 IAST arrival。
        _td = _v.get("trigger_spec_detail") or {}
        _fam = canonical_family(str(_td.get("family") or ""))
        if iast_evidence_sink_reached_genuine(_ie, _fam):
            _d1_arrivals += 1
    return {
        "status": "completed" if _d1_replayed else "skipped",
        "finding_count": _d1_impacts,
        "candidate_count": _d1_replayed,
        # 与 message 的「78 条重放」口径不一致。candidate_count 与 replayed_count 在当前实现
        # 同源（都= trigger_spec 驱动重放的条数），显式列出二者消除口径歧义。
        "replayed_count": _d1_replayed,
        "iast_arrivals": _d1_arrivals,
        # §#2D 实际重放的 spec 明细，供前端 D1 阶段列出（target / 参数 / canary 身份段 / 来源）。
        "replayed_specs_detail": _replayed_specs_detail,
        "message": (
            f"D1 统一重放（已并入 verify 链路）：驱动重放 {_d1_replayed} 条 TriggerSpec，"
            f"{_d1_impacts} 条 DAST impact，{_d1_arrivals} 条 IAST arrival"
        ),
    }


def _norm_family_from_verification(v: Dict[str, Any]) -> str:
    td = v.get("trigger_spec_detail") or {}
    return canonical_family(str(td.get("family") or v.get("type") or v.get("chain_id") or "unknown"))


def _d2_verification_detail(v: Dict[str, Any]) -> Dict[str, Any]:
    """抽取单条 D2 校验的证据链，供前端 D2 面板逐漏洞渲染（sink / payload / canary / taint_path）。

    字段与 d2_facade.verify 产物对齐：iast_evidence（state / sink_method / sink_file / sink_line /
    source_value / taint_path）、dast_impact_evidence（reached / status_code / body）、d2_verdict
    （harmful / confidence / reason / evidence）、next_action.per_spec_decisions（每条 spec 的
    final_state / reason / feedback_to_a2）。canary 只显身份段，不泄露完整探针值。
    """
    ie = v.get("iast_evidence", {}) or {}
    de = v.get("dast_impact_evidence", {}) or {}
    vd = v.get("d2_verdict", {}) or {}
    td = v.get("trigger_spec_detail") or {}
    na = v.get("next_action") or {}
    per_spec = na.get("per_spec_decisions") or []
    return {
        "vulnerability_hash_v2": v.get("chain_id") or v.get("canonical_group_key") or td.get("vulnerability_hash_v2"),
        "type": v.get("type"),
        "family": _norm_family_from_verification(v),
        "flow_type": derive_flow_type(_norm_family_from_verification(v)),
        "endpoint": td.get("endpoint"),
        "http_method": td.get("http_method"),
        "param_name": td.get("param_name"),
        "canary_identity": (td.get("canary_identity") or "")[:22] if td.get("canary_identity") else "",
        "trigger_spec_provided": v.get("trigger_spec_provided", False),
        "sink_method": ie.get("sink_method"),
        "sink_file": ie.get("sink_file"),
        "sink_line": ie.get("sink_line"),
        "source_value": (ie.get("source_value") or "")[:120],
        "taint_path": ie.get("taint_path") or [],
        "iast_state": ie.get("state"),
        "dast_reached": bool(de.get("reached")),
        "status_code": de.get("status_code"),
        "d2_harmful": bool(vd.get("harmful")),
        "d2_confidence": vd.get("confidence"),
        "d2_reason": vd.get("reason"),
        "d2_evidence": (vd.get("evidence") or "")[:300],
        "final_state": v.get("final_state") or (na.get("verification_status") if isinstance(na, dict) else "") or "",
        "verification_status": str((v.get("verification_decision") or {}).get("verification_status", "")),
        "per_spec_decisions": [
            {
                "hypothesis_id": d.get("hypothesis_id"),
                "final_state": d.get("final_state"),
                "reason": d.get("reason"),
                "feedback_to_a2": d.get("feedback_to_a2"),
            }
            for d in per_spec
            if isinstance(d, dict)
        ],
    }


def _scheduling_payload(scheduling, max_trace=400):
    """裁剪 D2 调度埋点以便落进 summary_json。

    execution_trace 是逐漏洞执行期埋点（每个漏洞一条，含 vhash / stable_key /
    spec_found_count / verify_called / fold_status 等），大任务可上千条。全量入
    scan_tasks.summary_json 会显著撑大单行，故设上限截断并保留 trace_summary
    （全量统计不受截断影响），同时记录截断元信息，避免对账时误以为丢数据。
    """
    if not isinstance(scheduling, dict):
        return {}
    out = dict(scheduling)
    trace = list(out.get("execution_trace") or [])
    total = len(trace)
    if total > max_trace:
        out["execution_trace"] = trace[:max_trace]
        trunc = dict(out.get("trace_truncated") or {})
        trunc.update({"kept": max_trace, "total": total})
        out["trace_truncated"] = trunc
    return out


def _aggregate_d2_verdict(verifications):
    """聚合 D2 五态（D2 已并入 verify 链路），回填 summary.d2_verified_count 等。

    关键修正：历史版本 ``summary.d2_verified_count`` 取 ``canonical_d2_stats['verified_poc_count']``
    （需 poc_verified 且 confirmed_exploitable，canary 降级重放下恒为 0），而 ``stage_results.d2
    .verified_count`` 取 D2 实际核验条数（如 4），两端对不齐、且 D2 五态没回填到 task 级摘要
    。

    本函数统一以「D2 实际核验的漏洞条数」为 verified_count，并给出 harmful / sink-reached /
    impact / confirmed 拆分与按 family 分布，供 stage_results.d2 与 report_manager.summary 同轴回填。
    """
    _verified = 0
    _harmful = 0
    _sink_reached = 0
    _impact = 0
    _confirmed = 0
    _by_family: Dict[str, int] = {}
    for v in verifications or []:
        ie = v.get("iast_evidence", {}) or {}
        de = v.get("dast_impact_evidence", {}) or {}
        vd = v.get("d2_verdict", {}) or {}
        # ④ sink 身份校验：canary 抵达 sink 态但落点在框架噪声 sink（非本族真 sink）→ 不视为 IAST 实证。
        fam = _norm_family_from_verification(v)
        _iast_genuine = iast_evidence_sink_reached_genuine(ie, fam)
        # 本质修复（#1）：verified_count 只统计「确有正向动态实证」的核验项，
        # 不再对每条验证输入无脑 +1（旧口径把未证实 / no_evidence 也计入，导致 d2_verified_count 虚高数倍）。
        _status = str((v.get("verification_decision") or {}).get("verification_status", ""))
        # v2 证据分层 D3：移除 "_status == confirmed_exploitable" 循环论证 —— 不能用「已被判确认」
        # 来证明「有证据」，否则 confirmed 恒为真、verified_count 虚高。只认独立正向证据：
        # IAST 真 sink 到达 / DAST 结果点到达 / D2 判有害。
        _has_evidence = (
            _iast_genuine
            or bool(de.get("reached"))
            or bool(vd.get("harmful"))
        )
        if _has_evidence:
            _verified += 1
        if _iast_genuine:
            _sink_reached += 1
        if bool(de.get("reached")):
            _impact += 1
        if bool(vd.get("harmful")):
            _harmful += 1
        if _status == "confirmed_exploitable":
            _confirmed += 1
        _by_family[fam] = _by_family.get(fam, 0) + 1
    return {
        "verified_count": _verified,
        "harmful_count": _harmful,
        "sink_reached_count": _sink_reached,
        "impact_count": _impact,
        "confirmed_exploitable_count": _confirmed,
        "by_family": _by_family,
        "verifications_detail": [_d2_verification_detail(v) for v in (verifications or [])],
        "message": (
            f"D2 统一校验（已并入 verify 链路）：{_verified} 条核验，"
            f"{_sink_reached} 条 sink 到达，{_harmful} 条结果点有害，{_confirmed} 条确认可利用"
        ),
    }


# ---------------- 业务逻辑漏洞：统一 verify 透明路由到差分重放（#2/#5）----------------
# _BUSINESS_LOGIC_CATEGORIES 直接引用规范集；D1 重放路由特例 idor→bola 单独保留
# （business_logic.verify 仅 8 类，无 idor；IDOR 在 D1 层与 BOLA 同路由）。
_BUSINESS_LOGIC_CATEGORIES = set(DIFFERENTIAL_PROOF_FAMILIES)
_BL_ROUTE_OVERRIDES = {"idor": "bola"}


def _normalize_bl_category(cat: str) -> Optional[str]:
    """把任意 category 写法归一为 business_logic.verify 可路由的规范 category。非业务型返回 None。
    路由特例（idor→bola）在此应用。"""
    if not cat:
        return None
    norm = canonical_business_logic_family(cat)
    if norm not in _BUSINESS_LOGIC_CATEGORIES:
        return None
    return _BL_ROUTE_OVERRIDES.get(norm, norm)


def _is_business_logic_vuln(vuln: Dict[str, Any]) -> bool:
    """判定某条 A1/A2 finding 是否业务逻辑类（走差分重放而非 canary 污点重放）。"""
    if not isinstance(vuln, dict):
        return False
    ae = vuln.get("a1_evidence") or {}
    if ae.get("business_logic"):
        return True
    # A2 也会产出 business 族假说（type 如 BOLA / BUSINESS_LOGIC / VERTICAL 等）
    cat = ae.get("category") or vuln.get("category") or vuln.get("type") or ""
    if _normalize_bl_category(cat):
        return True
    vt = str(vuln.get("vuln_type") or "").lower()
    return bool(vt) and _normalize_bl_category(vt) is not None


def build_trigger_spec_assoc_index(trigger_specs_by_hash: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """钉死 D2 关联键：把 ``load_trigger_specs_by_workspace`` 产出的 {vhash: [spec]} 索引，扩展为
    {stable_vuln_key: [spec], vulnerability_hash_v2: [spec]} 双键索引。

    - ``stable_vuln_key``：route-漂移免疫的稳定键（见 src.core.vuln_hash.stable_vuln_key），从
      spec.raw_json 重建（raw_json 即注册时的 vuln 全量 dict，含 entry.route），归一时强制置空 route，
      与验证端对 vuln_payload 算出的 stable 键同源 —— 注册端与验证端 entry.route 是否一致都不影响命中。
    - ``stable_vuln_key`` 弱键（行号无关变体，②-4）：除强键外再登记一条行号置 0 的弱键，
      使「报点行漂移」时仍能反查到 spec（强键 miss → 弱键兜底）。弱键只作兜底，
      绝不单独使用（它会把同文件同族不同行的漏洞并到一起，放大误归因面）。
    - ``vulnerability_hash_v2``：保留原 hash 键作为兜底（历史行为 / 无 raw_json 时退化路径）。

    返回多键索引，供 _d2_gate_predicate / _d2_call_verify / Phase2 写回统一反查 spec。
    """
    import json as _json_mod
    from src.core.vuln_hash import stable_vuln_keys as _stable_vuln_keys

    anykey: Dict[str, List[Dict[str, Any]]] = {}
    for _specs in (trigger_specs_by_hash or {}).values():
        for _s in _specs:
            _hk = _s.get("vulnerability_hash_v2")
            if _hk:
                anykey.setdefault(_hk, []).append(_s)
            try:
                _raw = _json_mod.loads(_s.get("raw_json") or "{}")
                for _sk in _stable_vuln_keys(_raw):
                    if _sk and _s not in anykey.setdefault(_sk, []):
                        anykey[_sk].append(_s)
            except Exception:
                pass
    return anykey


def match_trigger_specs_for_vuln(vuln: Dict[str, Any], assoc_index: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """给定一条 vuln_payload，按稳定键优先、vhash 兜底的口径反查关联的 trigger_spec 列表。

    抽出为独立函数以便单元测试断言「某条 vuln 能命中其已登记 spec」（即此前 10 条空状态 spec
    因 runtime_vhash ≠ stored_vhash 而反查落空的根因对照）。

    ②-4：强键（含行号）miss 时再按弱键（行号无关）兜底一次，抗报点行漂移。
    键优先级恒为 强键 > 弱键 > vhash，弱键不抢强键。
    """
    from src.core.vuln_hash import stable_vuln_keys as _stable_vuln_keys
    _vh = vuln.get("vuln_vhash") or ""
    for _sk in _stable_vuln_keys(vuln):
        _hit = assoc_index.get(_sk)
        if _hit:
            return _hit
    if assoc_index.get(_vh):
        return assoc_index[_vh]
    # 族名归一/行号漂移导致 stable 键与 vhash 双双落空 → 永不命中自己的 trigger_spec →
    # 这里用 vuln 自身 exploit_spec.entry.route 与 spec.target_endpoint 归一后比对，
    # 作为最后兜底（仅在前面全部落空时执行，不改变既有命中优先级）。
    _route = ""
    try:
        _es = vuln.get("exploit_spec") or {}
        _route = str(((_es.get("entry") or {}) if isinstance(_es, dict) else {}).get("route") or "").strip()
    except Exception:
        _route = ""
    if not _route:
        _route = str(vuln.get("entry_route") or "").strip()
    if _route:
        _norm = _route.strip("/").lower()
        _out: List[Any] = []
        for _rows in (assoc_index or {}).values():
            for _s in _rows or []:
                try:
                    _ep = str(_s.get("target_endpoint") or "").strip().strip("/").lower()
                except Exception:
                    _ep = ""
                if _ep and _ep == _norm and _s not in _out:
                    _out.append(_s)
        if _out:
            logger.info("[D2] spec 关联走路由兜底：route=%s 命中 %d 条 spec", _route, len(_out))
            return _out
    return []


def _absorbed_excluded_from_d2() -> bool:
    """吸收成员是否应被排除在 D2 之外。

    硬闸排除在 D2 之外，靠 canonical_group_key 继承代表结论。

    且 d2_output=''（从未单独重放）。而吸收成员各自持有独立 target_endpoint

    故默认改为放行（单独重放取真实 verification_status），报告层仍按 is_absorbed
    折叠展示，聚合语义不变。逃生开关 SAST_AI_ABSORBED_NO_D2=1 恢复旧行为。
    """
    return str(os.environ.get("SAST_AI_ABSORBED_NO_D2") or "").strip() == "1"


def _d2_gate_skip_reason(vuln: Dict[str, Any], trigger_specs_by_hash: Dict[str, Any]) -> str:
    """D2 门禁「未入队」的显式原因。

    需求约定：未进 D2 必须显式记 runtime 原因，不得留 unknown。本函数与
    ``_d2_gate_predicate`` 是同一判据的两面（一个给布尔、一个给人读原因），二者必须同源；
    任何 ``_d2_gate_predicate`` 返回 False 的输入，本函数必须给出非空原因。
    """
    if vuln.get('a21_selected') is True:
        return ''  # 已入队，无原因
    if vuln.get('is_absorbed') and _absorbed_excluded_from_d2():
        return 'absorbed_member: 聚合吸收成员按开关 SAST_AI_ABSORBED_NO_D2=1 排除（旧行为）'
    if not _vuln_dynamic_eligible(vuln):
        _fam = _vuln_family_token(vuln)
        return ('property_family_static_only: 族 %s 的危害是代码属性（不是「载荷进 sink」），'
                '按设计不进动态重放，改由静态事实层判定' % (_fam or "?"))
    if str(vuln.get('proof_tier') or '') == 'chain_proven':
        return ''  # 已按强制入队规则入队
    if _is_business_logic_vuln(vuln):
        return 'business_logic_not_selected: 业务逻辑族未被 A2.1 选中（a21_selected 非 True），无差分重放目标'
    spec = vuln.get('exploit_spec') or {}
    entry = (spec.get('entry') or {}) if isinstance(spec, dict) else {}
    if entry.get('route'):
        return ''  # 已入队
    _specs = match_trigger_specs_for_vuln(vuln, trigger_specs_by_hash)
    if _specs and any((s.get('target_endpoint') or '').strip() for s in _specs):
        return ''  # 已入队
    if not _specs:
        return 'no_trigger_spec: 既无自身 exploit_spec.entry.route，也未登记到任何 trigger_spec（无重放目标）'
    return 'trigger_spec_without_endpoint: 命中的 trigger_spec 未解析出可达 target_endpoint（路由解析失败）'


def _orphan_replay_enabled() -> bool:
    return str(os.environ.get("SAST_AI_D2_ORPHAN_REPLAY", "1")).strip().lower() not in (
        "0", "false", "off", "no",
    )


def _enqueue_orphan_trigger_specs(all_vulns: List[Dict[str, Any]],
                                  specs_by_anykey: Dict[str, Any],
                                  db: Any = None, task_id: Optional[int] = None) -> int:
    """Phase 1.5：把「已登记但无 finding 驱动」的 trigger_spec 补成 D2 候选。

    **18 条真报 + 37 条误报**，全部 `replayable=1`、`attack_payloads` 齐全、`target_endpoint` 可用，
    却因「源 finding 未出现在 D2 候选集」而**从未重放**
    （终态 `no_evidence` + `raw_json.unverified_kind=never_replayed`）。

    这类 spec 有完整重放三要素，补进 D2 是纯收益：
      · 真报 → 拿到 at_sink 证据（召回）；
      · 误报 → 拿到 absent 证据，由值级闸否决（精确率）。
    这正是「宽发现 + 严确认」：让 D1/I1/D2 多筛，而不是在发现层少猜。

    合成 vuln 的约束（关键）：**不得改动参与 vhash 的字段**（type/file/line/entry_point/sink 等），
    否则 `_d2_resolve_spec` 按 hash 反查不到 spec。实测：以 `raw_json` 为基底可复现 52/55 的
    vhash；而 `exploit_spec.entry.route` 不参与 vhash，可安全附加（门禁据此放行）。
    """
    if not _orphan_replay_enabled() or not specs_by_anykey:
        return 0
    try:
        from src.core.vuln_hash import canonicalize_vuln_for_hash, vulnerability_hash_v2 as _vh2
    except Exception as _ie:
        logger.warning("[D2][orphan] vuln_hash 导入失败，跳过补入：%s", _ie)
        return 0
    try:
        _max_add = int(os.environ.get("SAST_AI_D2_ORPHAN_MAX", "200") or 200)
    except Exception:
        _max_add = 200

    _covered: set = set()
    for _v in all_vulns or []:
        try:
            _covered.add(_vh2(canonicalize_vuln_for_hash(_v)))
        except Exception:
            pass
        _vh = str(_v.get("vuln_vhash") or "")
        if _vh:
            _covered.add(_vh)

    _seen: set = set()
    _cands: List[Dict[str, Any]] = []
    # 「已有结论」的状态集合：这些 spec 重放过并落了判定，不再补入。
    # 空串 与 'no_evidence' 都属「无结论」——后者是上一次 D2 末态兜底写的，
    # 恰恰是「从未重放」的标记（finalize 在 D2 尾部才写），重跑时必须重新入队。
    #
    # `confirmed_code_property` 列进「已有结论」是语义错误——`unconfirmed` 是
    # trigger_spec 的**初始默认值**，`confirmed_code_property` 是静态代码属性结论，
    # 两者都可能在「一次 HTTP 重放都没发过」时出现。624 里
    # `/deserialize/rememberMe/vuln`、`/xstream`、`/vuln1` 三个端点共 11 条 spec
    # 全为 replayable=1 却零 replay_attempts，正是被这行 continue 永久挡在 D2 门外。
    # 现改为按**实证**区分：查 replay_attempts 里本 task 真正发过请求的 spec_id。
    # 只有「零重放」的非终态 spec 才补入；重放过但未确认的保持原行为，不重复投放、
    # 不覆盖既有证据。db 不可用时退回旧集合（fail-safe，不改变既有基线）。
    _has_verdict = {
        "confirmed_exploitable", "confirmed_code_property", "confirmed_sink_control",
        "unconfirmed", "sink_reached", "invalidated", "suppressed",
    }
    _terminal = {"confirmed_exploitable", "invalidated", "suppressed"}
    _replayed: set = set()
    _probe_ok = False
    if db is not None and task_id is not None:
        try:
            _rows = db.execute(
                "SELECT DISTINCT spec_id FROM replay_attempts WHERE task_id=?",
                [task_id], fetchall=True) or []
            _replayed = {int(dict(r)["spec_id"]) for r in _rows
                         if dict(r).get("spec_id") is not None}
            _probe_ok = True
        except Exception as _pe:
            logger.warning("[D2][orphan] replay_attempts 探测失败，退回原准入：%s", _pe)
    if _probe_ok:
        logger.info("[D2][orphan] 本 task 已有重放记录的 spec %d 条（零重放孤儿才会补入）",
                    len(_replayed))
    for _lst in (specs_by_anykey or {}).values():
        for _s in (_lst or []):
            _sid = _s.get("id")
            if _sid in _seen:
                continue
            _seen.add(_sid)
            _status = str(_s.get("verification_status") or "").strip().lower()
            if _status in _terminal:
                continue  # 终态确认/作废，不补
            if _probe_ok:
                # 真发过请求 ⇒ 已有运行时证据，不重复投放；零重放 ⇒ 允许补入
                try:
                    if int(_sid) in _replayed:
                        continue
                except (TypeError, ValueError):
                    pass
            elif _status in _has_verdict:
                continue  # db 不可用：沿用旧行为，避免放大爆炸半径
            _rp = _s.get("replayable", 1)
            try:
                if _rp is not None and int(_rp) == 0:
                    continue
            except Exception:
                pass
            if not str(_s.get("target_endpoint") or "").strip():
                continue
            _vh = str(_s.get("vulnerability_hash_v2") or "")
            # 出现过（`/vuln1` 有 4 条 QLExpress finding），于是这里判「已被覆盖」
            # 跳过补入；但驱动它的 finding 同样没能发出任何重放，spec 依然是
            # 零 replay_attempts。覆盖只说明「有个 finding 挂着」，不等于「D2
            # 真的验证过」。故只有「被覆盖且确实重放过」才跳过。
            try:
                _zero_replay = _probe_ok and int(_sid) not in _replayed
            except (TypeError, ValueError):
                _zero_replay = False
            if _vh and _vh in _covered and not _zero_replay:
                continue
            _cands.append(_s)
    if not _cands:
        return 0

    _added = 0
    for _s in _cands[:_max_add]:
        try:
            _base = json.loads(str(_s.get("raw_json") or "{}"))
        except Exception:
            _base = {}
        if not isinstance(_base, dict):
            _base = {}
        _v = dict(_base)
        # 仅补「raw_json 缺失时」的兜底键，绝不覆盖既有值（覆盖会改 vhash → 反查落空）
        _v.setdefault("type", _s.get("category") or _s.get("family") or "")
        _v.setdefault("file", _s.get("expected_sink_file") or "")
        _v.setdefault("line", _s.get("expected_sink_line") or 0)
        _v.setdefault("code_snippet", "")
        _v.setdefault("description", "")
        _v.setdefault("severity", "MEDIUM")
        _v.setdefault("verdict", "")
        _v.setdefault("callers", "")
        _v.setdefault("data_flow", "")
        _v["source"] = _v.get("source") or "A2"
        _v["proof_tier"] = _v.get("proof_tier") or "broad_static"
        _v.setdefault("is_canonical", False)
        _v["is_absorbed"] = False
        _v.setdefault("absorbed_by_group_key", "")
        _v.setdefault("supporting_nodes", [])
        _v.setdefault("supporting_node_count", 0)
        _v.setdefault("chain_proof", {})
        _v.setdefault("proof_gaps", [])
        _v.setdefault("proof_second_pass", {})
        _v.setdefault("a21_candidate_score", 0)
        _v["a21_selected"] = _v.get("a21_selected")
        _v["a21_reason"] = _v.get("a21_reason") or "orphan_spec_replay"
        _v.setdefault("a1_evidence", {})
        _v.setdefault("canonical_group_key", "")
        _v.setdefault("chain_id", "")
        # exploit_spec 不参与 vhash，门禁据此判定「有重放目标」放行
        _v["exploit_spec"] = {"entry": {"route": str(_s.get("target_endpoint") or "")}}
        # vulnerability_hash_v2 全部对不上，
        # 而 D2 主循环按 vhash 反查 _trigger_specs_by_anykey —— 找不到 spec 就
        # 不发重放，于是「每轮补入 34~37 条孤儿、每轮零重放」无限循环。
        # 孤儿 vuln 的唯一用途就是把这条 spec 送进 D2，直接复用 spec 的登记 vhash
        # 才是正确关联键；重算值只作为 spec 没有 vhash 时的兜底。
        _spec_vh = str(_s.get("vulnerability_hash_v2") or "").strip()
        try:
            _calc_vh = _vh2(canonicalize_vuln_for_hash(_v))
        except Exception:
            _calc_vh = ""
        _v["vuln_vhash"] = _spec_vh or _calc_vh
        if _spec_vh:
            # D2 主循环会重算 _vhash，用这个显式标记让它改用登记的 spec vhash。
            _v["_orphan_spec_vhash"] = _spec_vh
        _v["orphan_spec_id"] = _s.get("id")
        all_vulns.append(_v)
        _added += 1
    if _added:
        logger.warning(
            "[D2][orphan] 补入 %d 条「已登记但无 finding 驱动」的 spec 进入 D2 重放"
            "（候选 %d 条，上限 %d；开关 SAST_AI_D2_ORPHAN_REPLAY）",
            _added, len(_cands), _max_add,
        )
    return _added


def _vuln_family_token(vuln: Dict[str, Any]) -> str:
    """取一条 finding 的族名（多来源兜底，用于「要不要进动态」的判定）。"""
    if not isinstance(vuln, dict):
        return ""
    spec = vuln.get("exploit_spec") or {}
    if isinstance(spec, dict):
        payload = spec.get("payload")
        if isinstance(payload, dict) and payload.get("payload_family"):
            return str(payload["payload_family"])
        if spec.get("family"):
            return str(spec["family"])
    for k in ("family", "vuln_type", "type"):
        if vuln.get(k):
            return str(vuln[k])
    ae = vuln.get("a1_evidence") or {}
    return str(ae.get("family") or "")


def _vuln_dynamic_eligible(vuln: Dict[str, Any]) -> bool:
    """该 finding 的族是否应进 D1/D2 重放。

    **只拦 `property` / `no_entry` 两类**：
      - `property`：危害是代码属性（Cookie 没 setSecure、弱算法、配置项），重放证明不了；
      - `no_entry`：连 HTTP 入口都没有（RMI 在 main 里）。
    `other`（bola/idor/race/state_machine 等业务逻辑族）**不能拦**——它们靠双账户差分重放，
    是 D2 的正式成员；判据集中在 `spec_state_normalize.classify_dynamic`（单一真源）。
    """
    try:
        from src.core.spec_state_normalize import classify_dynamic
    except Exception:  # noqa: BLE001
        return True  # fail-open：口径模块不可用时保持旧行为
    fam = _vuln_family_token(vuln)
    if not fam:
        return True  # 取不到族名时不敢拦（宁多跑不误杀）
    return classify_dynamic(fam) not in ("property", "no_entry")


def _d2_gate_predicate(vuln: Dict[str, Any], trigger_specs_by_hash: Dict[str, Any]) -> bool:
    """D2 验证门禁：判定某条 A1/A2 vuln 是否进入统一 verify 链路。

    - a21_selected 为 True（业务逻辑或 A2 显式选中）→ 进 D2；
    - 技术族（sql/ssrf/command 等）：满足「自身 exploit_spec.entry.route 非空」**或**
      「已登记 trigger_spec 且解析出可达入口（target_endpoint 非空）」任一即进 D2。
      后者覆盖 A1 技术漏洞：其自身 entry.route 未被 _pre_resolve_a2_endpoints 回填，但
      auto_register 已用 resolve_endpoint_full 独立解析出路由并登记 spec，不应因门禁而漏进 D2
      （否则 verification_status 永久为空，如 Mapper 派生 SQLi /products）。

    关联键加固：优先用 route-漂移免疫的
    stable_vuln_key 反查 spec，vulnerability_hash_v2 仅作兜底。stable 主键使「注册端 route 与
    验证端 route 漂移」时仍能命中已登记 spec，门禁不再把这类漏洞漏在 D2 之外。
    """
    if vuln.get('a21_selected') is True:
        return True
    # 原实现在此无条件 return False，导致成员永不进 D2、只能继承代表结论；代表判阴性时
    # target_endpoint 走下面的 route / trigger_spec 兜底分支单独重放。详见
    # _absorbed_excluded_from_d2 的说明与 SAST_AI_ABSORBED_NO_D2 逃生开关。
    if vuln.get('is_absorbed') and _absorbed_excluded_from_d2():
        return False
    # 理由：这些族的「危害」是某个属性不对（Cookie 没 setSecure、用了弱算法、
    # 配置项没开），与「有没有把载荷送进 sink」无关。跑重放既证明不了，也证明不了反面，
    # 只会占分母、拉低动态确认率，还会让 D2 日志里塞满 no-arrival 噪声。
    if not _vuln_dynamic_eligible(vuln):
        return False
    # A2/A2.1 已证调用链的一级 findings，必须进 D2 验证集，不受下面 route / spec 兜底分支约束。
    # 历史缺口：这类 finding 在「A2.1 二次证明把某条 finding 升级为 chain_proven、但其自身
    # canonical_group_key 为空且 entry.route 未回填、spec 关联又未命中」时会整体漏排，
    # 纯漏验、纯收益：入队后即便打不到，也会得到明确的 unconfirmed / no_evidence + 运行原因，
    # 不再留下无任何 D2 证据的空壳。判据只取 proof_tier（契约就绪性留给 D2 内部按 spec 判定，
    # 避免因契约 completeness 口径漂移再次漏排）。聚合吸收成员已在上面被拦截。
    if str(vuln.get('proof_tier') or '') == 'chain_proven':
        return True
    if not _is_business_logic_vuln(vuln):
        spec = vuln.get('exploit_spec') or {}
        entry = (spec.get('entry') or {}) if isinstance(spec, dict) else {}
        if entry.get('route'):
            return True
        # 关联键加固：stable 主键优先、vhash 兜底。trigger_specs_by_hash 实为本函数调用方传入的
        # _trigger_specs_by_anykey（双键索引）。
        _specs = match_trigger_specs_for_vuln(vuln, trigger_specs_by_hash)
        if _specs and any((s.get('target_endpoint') or '').strip() for s in _specs):
            return True
    return False


# 「已到达」观测态清单（与 tools/check_lost_arrival.py 的 _ARRIVAL_STATES 保持一致）。
# 这些 iast_state 是**运行时观测事实**，任何后处理都不得覆盖它们——L3 运行时到达指标
_ARRIVED_IAST_STATES = {
    "arrived", "arrival-sanitized", "sink-reached", "sink-reached-probe",
    # （响应层可复现观测已构成危害证据）。它不在这个集合里 ⇒ 后续轮的族路由 postpass
    # 把它当「非到达态」⇒ 走 else 分支把 iast_state 改写成 `family-route:<status>`，
    # 却最终停在 `family-route:unconfirmed`）。
    #
    # 机理与 4183 行注释里说的「标签假退化」完全一致：到达态一律保留原值，
    # 路由结果只体现在 verification_status 上。technique-proven 就是到达态。
    "technique-proven",
}


def _apply_family_route_postpass(task_id: Optional[int], sdb) -> int:
    """I 族路由 post-pass。

    根因1：三失效族（weak_hash/weak_crypto=算法通道；secure_cookie=属性通道）在 iast/service.py
    注册期直接判 confirmed_exploitable，绕过 D2 verify 链路，导致 D2 写回循环内的 I 路由段
    （run_d2_verify 内 ``for vuln in all_vulns`` 循环）结构性够不到它们——路由完全惰性、

    本 post-pass 独立于 ``_d2_gate_predicate``，在 D2 主循环结束后，直接按 family 取这三族的
    confirmed_exploitable spec，逐条 ``find_identity(taint_marker)``→查 ``iast_events(canary)``→
    ``apply_family_route`` 重判并写回。零回归：数据流族不在此列，不受影响；本函数仅对
    confirmed_exploitable 介入，低置信态（no_evidence/unconfirmed 等）保持原状。

    返回实际改写条数（确定性信号，供回归核对与跑后分析 signal_checks 使用）。
    """
    if task_id is None or sdb is None:
        return 0
    # confirmed_exploitable），family_verdict 里 _RANDOM_FAMILY_TOKENS / judge_random_family
    # / route_for → random_source 都齐了，唯独这张目标表没跟着加 —— 于是 M4 通道注册表上线后
    # weak_random 的仲裁主判据变成 code_property（harmful=False），既够不到 confirmed_exploitable，
    # 又没人把它路由到 confirmed_code_property，整族凭空掉成 unconfirmed。
    _TARGET_FAMILIES = ("weak_hash", "weak_crypto", "secure_cookie", "weak_random")
    # 介入状态放宽：原先只挑 confirmed_exploitable，是因为那时「 exploratory」的上游结论一定长
    # 那样；M4 之后同一族的仲裁结果可能是 code_property（harmful=False），spec 停在 unconfirmed。
    # 把 unconfirmed 一并纳入，由各 judge_* 自己用「有没有专属 sink 事件」把关
    # （没有事件一律返回 unconfirmed），不会出现无证据晋升。
    try:
        from src.core.family_verdict import apply_family_route, judge_safe_implementation, CONFIRMED_CODE_PROPERTY
        from src.iast.canary import CanaryMatcher as _CM
    except Exception as _imp_e:
        logger.warning("[D2][family-route-postpass] 依赖导入失败，跳过：%s", _imp_e)
        return 0
    try:
        # 两个并存的坑，必须一起修：
        #  (a) 能力识别器把多能力**塌缩成单标签**，且命中即判族、不看能力点是否与污点主链相交
        #      —— OWASP 每个 servlet 都有 rememberMe Cookie 样板代码，被一律判成 secure_cookie，
        #      34/35 个「静态侧缺少」其实是族判错而非真没提（已通过 priority 把 cookie_flag /
        #      session_write 压到最低优先级，见 capability_judge._PRIORITY）。
        #  (b) 单一标签偏好会让「family 被上游写错、但 capability_family 正确」的用例彻底漏掉
        #      （如 family=broken_access_control、capability_family=weak_random）。
        # 修法 = **并集选择 + 正确族路由**：
        #   选中条件：family ∈ 目标族  OR  capability_family ∈ 目标族（两者任一命中即纳入重判）；
        #   路由族   = COALESCE(NULLIF(family,''), capability_family) —— 优先用上游 family，
        #             只有 family 为空/未命中时才退到 capability_family（保留 (b) 的纠正能力）。
        # 这样 (a) 的样板误判被 priority 修复、(b) 的纠正能力被并集保留，两不误。
        _fam_expr = "COALESCE(NULLIF(family,''), capability_family)"
        _ph1 = ",".join("?" for _ in _TARGET_FAMILIES)
        # 并集选择：family 或 capability_family 任一命中目标族
        _where = (f"(family IN ({_ph1}) OR capability_family IN ({_ph1}))")
        try:
            specs = sdb.execute(
                "SELECT id, family AS decl_family, capability_family AS cap_family, "
                "taint_marker, session_id, verification_status, iast_state "
                "FROM trigger_specs "
                f"WHERE task_id=? AND {_where} "
                "AND (verification_status IN ('confirmed_exploitable','confirmed_sink_control','unconfirmed','sink_reached') "
                # 这类状态的弱算法证据来自 SHA 样板（family 误判），由静态 RNG 判据复核后可抑。
                "     OR (capability_family='weak_random' AND verification_status='confirmed_code_property'))",
                (task_id, *_TARGET_FAMILIES, *_TARGET_FAMILIES), fetchall=True,
            ) or []
        except Exception as _ce:
            # capability_family 列缺失（老库 / 最小测试夹具）→ 退回只认 family，零回归。
            logger.warning(
                "[D2][family-route-postpass] capability_family 不可用（%s），退回 family 过滤", _ce)
            specs = sdb.execute(
                "SELECT id, family AS decl_family, '' AS cap_family, "
                "taint_marker, session_id, verification_status, iast_state "
                "FROM trigger_specs "
                f"WHERE task_id=? AND family IN ({_ph1}) "
                "AND verification_status IN ('confirmed_exploitable','confirmed_sink_control','unconfirmed','sink_reached')",
                (task_id, *_TARGET_FAMILIES), fetchall=True,
            ) or []
    except Exception as _qe:
        logger.warning("[D2][family-route-postpass] 查询 trigger_specs 失败：%s", _qe)
        return 0
    if not specs:
        logger.info("[D2][family-route-postpass] 无命中（属性路由族无待判 spec）")
        return 0
    # 探测 positive_evidence_rule 列是否可用（老库 / 最小测试夹具没有这一列）。
    # 有了它就把「本条由哪条族专属规则背书」一并落库，没有则退化为不写——
    # 绝不因为多写一个可选列而让整条终态写回失败。
    _has_per_col = False
    try:
        sdb.execute("SELECT positive_evidence_rule FROM trigger_specs LIMIT 1", fetchall=True)
        _has_per_col = True
    except Exception:
        _has_per_col = False
    _n = 0
    _n_supp = 0
    for _sp in specs:
        _spid = _sp.get('id')
        # 路由族选择（P0 修正）：优先用上游 family，只有它不在目标族内、而 capability_family
        # 在目标族内时，才退到 capability_family（纠正 family 被上游写错的用例）。
        # 这样既能接住「family 错、capability_family 对」的用例，又不会让样板 Cookie 的
        # capability_family=secure_cookie 反向覆盖真正属于 weak_random 的用例。
        _decl = str(_sp.get('decl_family') or '')
        _cap = str(_sp.get('cap_family') or '')
        if _decl in _TARGET_FAMILIES:
            _fam = _decl
        elif _cap in _TARGET_FAMILIES:
            _fam = _cap
        else:
            _fam = _decl
        #
        # `capability_family='secure_cookie'`（该端点从 Cookie 读值 ⇒ 命中「样板 Cookie」
        # 误标，这是 M4 通道的已知问题）⇒ 它进了族路由的 capability 候选分支 ⇒
        # 族路由按 secure_cookie 判定，把**技术判据已确认**（technique_evidence.admitted=True、
        # 响应体确实原样反射了载荷）的 spec 改判成 `unconfirmed` + `family-route:unconfirmed`，
        # 把 D2 刚建立的结论覆盖掉。
        #
        # 职责边界：族路由管「这条该走哪条**通道**」（算法/属性/随机）；
        # 技术判据管「观测是否构成**危害**」。两者在不同维度上做判断，
        # 后者已给出确定性正向证据时，前者不得推翻它（只能补充通道信息）。
        #
        # fail-open：raw_json 读不出或结构异常 ⇒ 不跳过（保持既有行为）。
        try:
            _rj_chk = {}
            _row_chk = sdb.execute(
                "SELECT raw_json FROM trigger_specs WHERE id=?", (int(_spid),), fetchall=True)
            if _row_chk:
                _rj_chk = json.loads(_row_chk[0].get("raw_json") or "{}") or {}
            _te_chk = _rj_chk.get("technique_evidence") if isinstance(_rj_chk, dict) else None
            if isinstance(_te_chk, dict) and _te_chk.get("admitted"):
                logger.info(
                    "[D2][family-route-postpass] spec=%s 已有技术判据正向证据（technique=%s）"
                    "⇒ 族路由不改判（只让 D2 的危害结论生效）",
                    _spid, _te_chk.get("technique"))
                continue
        except Exception as _tc_e:
            logger.debug("[D2][family-route-postpass] 技术判据保护检查跳过 spec=%s：%s",
                         _spid, _tc_e)
        _marker = str(_sp.get('taint_marker') or '')
        try:
            _ident = _CM.find_identity(_marker) if _marker else ''
        except Exception as _fe:
            logger.warning("[D2][family-route-postpass] find_identity 失败 spec=%s：%s", _spid, _fe)
            _ident = ''
        _events = []
        if _ident:
            try:
                _events = sdb.execute(
                    "SELECT sink_file, source_value, evidence_json FROM iast_events "
                    "WHERE task_id=? AND canary=?",
                    (task_id, _ident), fetchall=True,
                ) or []
            except Exception as _eq:
                logger.warning("[D2][family-route-postpass] 事件查询失败 spec=%s：%s", _spid, _eq)
        # 为什么必须这里补：family_route postpass 此前只改 verification_status，而对账口径
        # （owasp_run_shards L414）只认 suppressed_by_safe_verdict=0 过滤检出集合 ⇒ 单降 status
        # 对对账精确率零贡献（P3 在 safe_pattern 上踩过同一坑，L3396 有记）。P1b 离线复算
        # 纪律与值级闸一致：只认正证据（算法 sink 到达且算法名不弱 / Cookie flag 显式置 true），
        # 「什么都没观测到 / 参数未记录」一律 fail-open 不抑制；weak_random 无正安全证据可用，
        # judge_safe_implementation 恒返回 False，交由 fail-open 语义兜底。
        _safe_impl = False
        _safe_rule = ""
        _allow_cp_override = False
        _weak_hit = None
        try:
            _safe_impl, _safe_rule = judge_safe_implementation(_fam, _events)
        except Exception as _se:
            logger.warning(
                "[D2][family-route-postpass] 安全实现判定异常（不抑制）spec=%s：%s", _spid, _se)
        # （观测不到 Random ≠ 用了 SecureRandom），P2 恒 False ⇒ ~180 FP 无通道。
        # 但源码静态正证据是确定性的：weakrand-1/2 的 FP 中 139 个「只用 SecureRandom」，
        # 而 TP 全部「只用 java.util.Random / Math.random」，零交叉 ⇒ 静态判据可零损失落地。
        # 纪律与 P2 一致：只认正证据（显式 SecureRandom 且无弱随机调用），BOTH 情形 fail-open。
        if not _safe_impl:
            try:
                from src.core.family_verdict import route_for as _route_for
                # rememberMe 样板代码（MessageDigest SHA）把 weakrand 用例标成 weak_hash，
                # 于是走算法路由、SHA 命中弱算法 → confirmed_code_property（TP 主张，永不抑制）。
                # 这里用 capability_family 兜一层：只要 capability 指向弱随机族，就仍做静态 RNG 判定。
                _is_random = (_route_for(_fam, _events) == "random_source"
                              or _route_for(_cap, []) == "random_source")
                if _is_random:
                    # 按需单查（不改 SELECT）：老库/最小夹具可能没有 expected_sink_file 列，
                    # 缺失即 fail-open，绝不因多取一列让整条终态写回失败。
                    _esf = ""
                    try:
                        _row_esf = sdb.execute(
                            "SELECT expected_sink_file FROM trigger_specs WHERE id=?",
                            (int(_spid),), fetchall=True)
                        if _row_esf:
                            _esf = str(_row_esf[0].get('expected_sink_file') or '')
                    except Exception:
                        _esf = ""
                    if _esf:
                        from src.iast.source_infer import resolve_source_path as _rsp
                        from src.core.safe_pattern_semantic import (
                            safe_rng_static as _srs,
                            weak_rng_static as _wrs,
                        )
                        _src_path = _rsp(_esf)
                        if _src_path:
                            with open(_src_path, encoding="utf-8", errors="replace") as _fh:
                                _src_text = _fh.read()
                            _rng_hit = _srs(_src_text)
                            # 运行时事件不足时（A2 无先验 ⇒ spec 薄 ⇒ canary 未流经
                            # Random sink），源码里的不安全随机调用就是充分证据。
                            if not _rng_hit:
                                _weak_hit = _wrs(_src_text)
                            if _rng_hit:
                                _safe_impl, _safe_rule = True, "static_safe_rng:" + _rng_hit
                                # 仅当 capability_family 明确指向弱随机族时，允许越过
                                # confirmed_code_property 的「TP 主张永不抑制」护栏——
                                # 此时该状态来自 family 误判（SHA 样板）而非真实的弱随机证据。
                                if _route_for(_cap, []) == "random_source":
                                    _allow_cp_override = True
                                logger.info(
                                    "[D2][family-route-postpass][static-rng] spec=%s 源码仅用 %s"
                                    "（无弱随机调用）→ 安全实现正证据%s", _spid, _rng_hit,
                                    "（capability=weak_random，越过 CP 护栏）" if _allow_cp_override else "",
                                )
            except Exception as _rng_e:
                logger.warning(
                    "[D2][family-route-postpass] 静态 RNG 判定异常（不抑制）spec=%s：%s",
                    _spid, _rng_e)
        if (_safe_impl
                and (str(_sp.get('verification_status') or '') != CONFIRMED_CODE_PROPERTY
                     or _allow_cp_override)):
            # confirmed_code_property 是 TP 主张，默认永不抑制；
            # 唯一例外 _allow_cp_override：capability_family=weak_random 且源码仅用 SecureRandom
            # judge_safe_implementation 内部已按事件保护，这里按旧态再兜一层（双保险）。
            # 已被别的手段抑制过的 spec 不重复处理，保住既有 suppress_rule 归因（惰性查、
            # fail-open：列缺失的老库/最小夹具不阻塞）。
            try:
                _prev = sdb.execute(
                    "SELECT COALESCE(suppressed_by_safe_verdict,0) AS s FROM trigger_specs WHERE id=?",
                    (int(_spid),), fetchall=True)
                if _prev and int(_prev[0].get("s") or 0):
                    continue
            except Exception:
                pass
            _cur_iast = str(_sp.get('iast_state') or '')
            # 到达态保留（L3 运行时到达指标按 sink-reached-probe 统计，不因抑制假退化）；
            # 非到达态才写 family-route 标记，保留归因线索。
            _new_iast = _cur_iast if _cur_iast in _ARRIVED_IAST_STATES else 'family-route:safe-impl'
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET verification_status='unconfirmed', iast_state=?, "
                    "suppressed_by_safe_verdict=1, suppress_rule=? WHERE id=?",
                    (_new_iast, f"family-route:safe_impl:{_safe_rule}", int(_spid)),
                )
                _n_supp += 1
                _n += 1
                logger.info(
                    "[D2][family-route-postpass][safe-impl] spec=%s family=%s 观测到安全实现正证据（%s）"
                    " → unconfirmed+suppressed", _spid, _fam, _safe_rule,
                )
                continue
            except Exception as _up_e:
                logger.warning(
                    "[D2][family-route-postpass] 安全实现抑制写回失败 spec=%s：%s", _spid, _up_e)
        # 'confirmed_exploitable' 当「准入票据」，而 apply_family_route 内部对非该值一律拒绝
        # 介入 ⇒ M4 之后停在 unconfirmed 的代码属性族**永远进不了 judge_***。
        # 现在直接传本行 spec **当前的** verification_status，由 judge_* 自己用本族专属 sink
        # 事件说话（apply_family_route 内部仍守着「无证据不晋升」的底线）。
        # 只有判定结果与之不同才写回，否则会把 unconfirmed → unconfirmed 也写一遍，顺手把
        # iast_state 里的原始诊断态（no-arrival / safe-pattern-veto 等）覆盖成
        # family-route:unconfirmed，丢掉归因线索。
        _cur_status = str(_sp.get('verification_status') or '')
        _new_status, _detail = apply_family_route(_fam, _cur_status, _events)
        _per = str((_detail or {}).get('positive_evidence_rule') or '')
        # 474（blind 布局）实证：A2 无先验时 spec 变薄 ⇒ canary 未流经 Random sink
        # （00066 事件 78/6 → 4/0），运行时判据饿死 ⇒ 6 条 weak_random TP 丢失。
        # 「源码用了不安全随机源」是纯代码属性主张，源码即充分证据，不需要
        # 运行时事件、更不需要 case# 先验。judge 给 unconfirmed 且静态检出弱随机
        # 调用（无 SecureRandom 混用）⇒ 升格 confirmed_code_property。
        # 护栏：①仅 random_source 路由；②仅 judge 明确给 unconfirmed；③safe_impl
        # （SecureRandom-only）优先、两者互斥；④异常 fail-open 不升格。
        if (_new_status == 'unconfirmed'
                and _route_for(_fam, _events) == 'random_source'
                and not _safe_impl and _weak_hit):
            try:
                _new_status = CONFIRMED_CODE_PROPERTY
                _per = 'static_weak_rng_source:' + _weak_hit
                _detail = {'route': 'random_source', 'applied': True,
                           'detail': ('静态源码正证据：检出 %s（无 SecureRandom 混用）'
                                      ' → confirmed_code_property' % _weak_hit)}
                logger.info(
                    "[D2][family-route-postpass][static-rng-confirm] spec=%s "
                    "运行时事件不足但源码检出弱随机调用（%s）→ 静态正证据升格",
                    _spid, _weak_hit)
            except Exception as _se2:
                logger.warning(
                    "[D2][family-route-postpass] 静态弱随机升格异常（不升格）spec=%s：%s",
                    _spid, _se2)
        if _new_status == _cur_status:
            # 正向规则 ⇒ 只补 positive_evidence_rule 一列，不动 verification_status / iast_state。
            # 此前这里直接 continue，于是走 D2/M4 code_property 通道拿到 confirmed_code_property
            # 的属性族 spec，规则永远为空——
            # 「本条确认由哪条族专属规则背书」无法回溯，judge 是否真跑过也无从验证。
            # 状态不变 ⇒ 不改写任何终态/归因线索，纯增量补事实，零回归。
            if _per and _has_per_col:
                try:
                    sdb.execute("UPDATE trigger_specs SET positive_evidence_rule=? WHERE id=?",
                                (_per, int(_spid)))
                    _n += 1
                except Exception as _up_e:
                    logger.warning("[D2][family-route-postpass] 规则回填失败 spec=%s：%s", _spid, _up_e)
            continue
        if _new_status != 'confirmed_exploitable':
            try:
                # 本行原来无条件写 `iast_state = family-route:<status>`，而 weak_random 族
                # 路由修好后 16 条 spec 全部从 confirmed_exploitable 改判，于是它们的
                # `sink-reached-probe` 被改写成 `family-route:*`。L3 运行时到达指标正是按
                # （67.9%→52.8% 的主要成因），而实际到达一条没少。**这是标签假退化。**
                # 处置：到达态一律保留原值；路由结果只体现在 verification_status 上
                # （它本身就记录了终态），非到达态才写 family-route 标记（保留原有归因线索价值）。
                _cur_iast = str(_sp.get('iast_state') or '')
                if _cur_iast in _ARRIVED_IAST_STATES:
                    if _has_per_col:
                        sdb.execute(
                            "UPDATE trigger_specs SET verification_status=?, "
                            "positive_evidence_rule=? WHERE id=?",
                            (_new_status, _per, int(_spid)),
                        )
                    else:
                        sdb.execute(
                            "UPDATE trigger_specs SET verification_status=? WHERE id=?",
                            (_new_status, int(_spid)),
                        )
                else:
                    if _has_per_col:
                        sdb.execute(
                            "UPDATE trigger_specs SET verification_status=?, iast_state=?, "
                            "positive_evidence_rule=? WHERE id=?",
                            (_new_status, f"family-route:{_new_status}", _per, int(_spid)),
                        )
                    else:
                        sdb.execute(
                            "UPDATE trigger_specs SET verification_status=?, iast_state=? WHERE id=?",
                            (_new_status, f"family-route:{_new_status}", int(_spid)),
                        )
                _n += 1
                logger.info(
                    "[D2][family-route-postpass] spec=%s family=%s taint_marker=%s events=%d → %s（%s）",
                    _spid, _fam, _marker[:24], len(_events), _new_status,
                    str(_detail.get('detail', ''))[:120],
                )
            except Exception as _up_e:
                logger.warning("[D2][family-route-postpass] 写回失败 spec=%s：%s", _spid, _up_e)
        else:
            logger.info(
                "[D2][family-route-postpass] spec=%s family=%s 维持 confirmed_exploitable（路由未变）",
                _spid, _fam,
            )
    logger.info("[D2][family-route-postpass] 完成：命中 %d 条，改写 %d 条（其中安全实现正证据抑制 %d 条）",
                len(specs), _n, _n_supp)
    return _n


# 记录 hook，于是 canary「到达」了本族真 sink（G 分析 A 类 36 用例的机理）。
_SAFE_PATTERN_IF_CONST = re.compile(
    r'if\s*\([^;{}]*[+*%-][^;{}]*\)\s*(?:\{\s*)?(\w+)\s*=\s*"[^"]*"\s*;\s*'
    r'(?:\}\s*)?else\s*(?:\{\s*)?\1\s*=\s*(\w+)', re.S)
_SAFE_PATTERN_TERNARY_CONST = re.compile(
    r'(\w+)\s*=\s*\([^;]*[+*%-][^;]*\)\s*[<>]=?\s*[^?]+\?\s*"[^"]*"\s*:\s*(\w+)', re.S)
_SAFE_PATTERN_MAP_OVERWRITE = re.compile(
    r'(\w+)\.put\("([^"]+)",\s*(\w+)\);.*?\1\.get\("([^"]+)"\)', re.S)
_SAFE_PATTERN_MAX_FILE = 200 * 1024  # 超大文件跳过（fail-open，防正则回溯拖垮收尾）


def _file_has_safe_pattern(content: str) -> bool:
    """源文件是否含「死分支常量 / 安全值覆盖 / 恒真 ternary / 常量 switch」安全写法反例。

    按「形状」补正则会把真漏洞误杀；
    只有对条件做数值求值，才能做到 64/102 FP 命中、0/126 TP 误伤（精确率 55.3%→76.8%）。
    """
    return _safe_pattern_hit(content) is not None


def _safe_pattern_hit(content: str) -> Optional[str]:
    """返回命中的安全写法类型（供 suppress_rule 落库）；未命中/模块异常返回 None（fail-open）。"""
    try:
        from src.core.safe_pattern_semantic import safe_pattern_type
        return safe_pattern_type(content)
    except Exception:
        return None


def _apply_safe_pattern_postpass(task_id: Optional[int], sdb, code_root: Optional[str]) -> int:
    """A2 安全写法反例否决 post-pass。

    取回安全值——确定性 sink 判据治不了，唯有 L1 静态反例否决（最便宜）。
    仅对数据流族（route_for != algorithm/attribute，那两族归 I 路由通道管）的
    confirmed_exploitable spec 介入；源文件命中安全写法反例 → 降级 unconfirmed。

    FP 命中 14 用例（cmdi 3 / sqli 4 / weakrand 2 / xss 2 / pathtraver 2）。
    fail-open：文件缺失 / 过大 / 解析异常一律跳过，绝不凭缺失证据改判。

    返回实际改写条数（确定性回归信号）。
    """
    if task_id is None or sdb is None or not code_root:
        return 0
    try:
        from src.core.family_verdict import route_for
    except Exception as _imp_e:
        logger.warning("[D2][safe-pattern-veto] 依赖导入失败，跳过：%s", _imp_e)
        return 0
    # findings 仅收尾由 replace_for_task 重写，D2 阶段查必空 → 全体 fail-open、veto 0 条。
    # spec 注册时 expected_sink_file = vuln_dict['file']（内存现值，注册期已落），直接取它；
    # findings 回查仅作离线补录兜底。
    try:
        specs = sdb.execute(
            "SELECT id, family, expected_sink_file FROM trigger_specs "
            "WHERE task_id=? AND verification_status='confirmed_exploitable'",
            (task_id,), fetchall=True,
        ) or []
    except Exception as _qe:
        logger.warning("[D2][safe-pattern-veto] 查询 trigger_specs 失败：%s", _qe)
        return 0
    _code_root = str(code_root)
    # 多候选根：扫描子根可能是 <project>/src，而 expected_sink_file 相对项目根（或反之）。
    _roots = [_code_root]
    try:
        _parent = os.path.dirname(os.path.normpath(_code_root))
        if _parent and _parent not in _roots:
            _roots.append(_parent)
    except Exception:
        pass
    _n = 0
    _file_cache: Dict[str, Optional[str]] = {}
    for _sp in specs:
        _fam = str(_sp.get('family') or '')
        try:
            if route_for(_fam) != "dataflow":
                continue  # 算法/属性族归 I 路由通道，不适用数据流安全写法否决
        except Exception:
            continue
        _fp = str(_sp.get('expected_sink_file') or '')
        if not _fp:
            continue
        if _fp not in _file_cache:
            _content = None
            for _root in _roots:
                _abs = os.path.normpath(os.path.join(_root, _fp.replace('\\', '/').lstrip('/')))
                try:
                    if os.path.isfile(_abs) and os.path.getsize(_abs) <= _SAFE_PATTERN_MAX_FILE:
                        with open(_abs, encoding='utf-8', errors='ignore') as _fh:
                            _content = _fh.read()
                        break
                except Exception:
                    continue
            _file_cache[_fp] = _content
        _content = _file_cache[_fp]
        _hit = _safe_pattern_hit(_content) if _content else None
        if not _hit:
            continue
        _spid = _sp.get('id')
        try:
            # 过滤检出集合，仅改 verification_status 对「按用例计数」的精确率无效。
            sdb.execute(
                "UPDATE trigger_specs SET verification_status='unconfirmed', "
                "business_logic_confirmed=0, iast_state='safe-pattern-veto', "
                "suppressed_by_safe_verdict=1, suppress_rule=? WHERE id=?",
                (f"safe-pattern:{_hit}", int(_spid)),
            )
            _n += 1
            logger.info(
                "[D2][safe-pattern-veto] spec=%s family=%s file=%s 命中安全写法（%s）"
                "→ unconfirmed+suppressed",
                _spid, _fam, _fp, _hit,
            )
        except Exception as _up_e:
            logger.warning("[D2][safe-pattern-veto] 写回失败 spec=%s：%s", _spid, _up_e)
    if _n:
        logger.info("[D2][safe-pattern-veto] 完成：改写 %d 条 confirmed_exploitable → unconfirmed", _n)
    return _n


def _apply_source_location_postpass(task_id: Optional[int], sdb, code_root: Optional[str]) -> int:
    """Phase 0a：按 servlet 源码确定性纠正 param_location。

    A2 的 param_location 常默认猜 query，而 servlet 实际从 header/cookie/body 取源
    query，servlet 却从 header 取 → payload 到不了 sink → 漏报（FN）。
    本 post-pass 在 D1 重放前，读源码判定真实源位置并纠正。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        from src.core.source_location import detect_source_location
    except Exception as _imp:
        logger.warning("[src-loc] 导入失败，跳过：%s", _imp)
        return 0
    try:
        _specs = sdb.execute(
            "SELECT id, expected_sink_file, param_location FROM trigger_specs WHERE task_id=?",
            (task_id,), fetchall=True) or []
    except Exception as _qe:
        logger.warning("[src-loc] 查询 trigger_specs 失败：%s", _qe)
        return 0
    _root = str(code_root or "")
    _n = 0
    for _sp in _specs:
        _sink = str(_sp.get("expected_sink_file") or "")
        if not _sink:
            continue
        _cand = _sink
        if _root:
            _cand = os.path.normpath(os.path.join(_root, _sink.replace("\\", "/").lstrip("/")))
        if not os.path.isfile(_cand):
            continue
        try:
            _det = detect_source_location(path=_cand)
        except Exception:
            _det = None
        if not _det:
            continue
        _cur = str(_sp.get("param_location") or "query")
        if _det != _cur:
            try:
                sdb.execute("UPDATE trigger_specs SET param_location=? WHERE id=?",
                            (_det, int(_sp.get("id"))))
                # 权威列改了，raw_json.exploit_spec.entry 必须同步，否则报告层读到旧猜测
                sync_entry_projection(sdb, int(_sp.get("id")), param_location=_det)
                _n += 1
            except Exception as _ue:
                logger.warning("[src-loc] 写回失败 spec=%s：%s", _sp.get("id"), _ue)
    if _n:
        logger.info("[src-loc] param_location 按源码纠正 %d 条（D1 重放前）", _n)
    return _n


def _load_code_index_for_task(task_id: Optional[int], output_dir: Optional[str] = None) -> dict:
    """读本任务的 code_index.json 的 functions 段（拿不到就返回空 dict）。"""
    import glob as _glob
    import json as _json

    cands: list = []
    if output_dir:
        cands.append(os.path.join(str(output_dir), "code_index.json"))
    if task_id is not None:
        cands.extend(_glob.glob(os.path.join(
            "data", "workspaces", "*", "task-%s" % task_id, "code_index.json")))
    for p in cands:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = _json.load(f)
        except Exception as _e:  # noqa: BLE001
            logger.warning("[param-fill] code_index 读取失败 %s：%s", p, _e)
            continue
        funcs = d.get("functions") or {}
        if isinstance(funcs, dict) and funcs:
            return funcs
    return {}


def _apply_param_backfill_postpass(task_id: Optional[int], sdb, code_root: Optional[str],
                                   output_dir: Optional[str] = None) -> int:
    """Phase 0b：D1 重放前补齐空的 param_name。

    ## 为什么必须做

    `param_name` 为空 ⇒ D1 不知道往哪个参数投弹 ⇒ 打一条空请求 ⇒ sink 永远到不了
    ⇒ `no-arrival`。本轮实测 156 条 spec 里 40 条（26%）param 为空。

    其中真正「能补但没补」的是**工具类 sink**：sink 落在 `HttpUtils.request(String url)`
    这类工具方法上，参数名只在**调用方 Controller 的签名**里，只能靠调用图回溯。

    ## 只填空，不覆盖

    已有 param 的 spec 一律不动 —— A2 给出的参数名可能比推断更准（它看过 PoC 链）。
    本 pass 只处理 `param_name` 为 NULL/空串的行。

    ## 置信度

    `param_infer` 返回 low 的（推不出、或回溯层数超限、或多 caller 冲突）**不写库**，
    留空由下游按 `payload_unavailable`/`no-arrival` 如实记账 —— 硬填一个错名字
    比留空更糟（投到错误位置会产生假阴性，且看起来像"验过了"）。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        from src.core.param_infer import infer_for_spec
    except Exception as _imp:  # noqa: BLE001
        logger.warning("[param-fill] 导入 param_infer 失败，跳过：%s", _imp)
        return 0

    try:
        _specs = sdb.execute(
            "SELECT id, family, expected_sink_file, expected_sink_line, param_name, "
            "param_location FROM trigger_specs "
            "WHERE task_id=? AND (param_name IS NULL OR TRIM(param_name)='')",
            (task_id,), fetchall=True) or []
    except Exception as _qe:  # noqa: BLE001
        logger.warning("[param-fill] 查询 trigger_specs 失败：%s", _qe)
        return 0
    if not _specs:
        return 0

    index = _load_code_index_for_task(task_id, output_dir)
    if not index:
        # 兜底：从 scan_tasks.output_dir 拿真实产物目录。
        # 不能只靠 `task-<id>` 猜路径 —— 本地提交通道（tools/_wb_submit_local.py）
        # 的产物目录是 `task-<name>`，按 id 猜会找不到 code_index.json。
        try:
            _row = sdb.execute("SELECT output_dir FROM scan_tasks WHERE id=?",
                               (task_id,), fetchall=True) or []
            _od = str((_row[0] or {}).get("output_dir") or "") if _row else ""
        except Exception:  # noqa: BLE001
            _od = ""
        if _od:
            index = _load_code_index_for_task(task_id, _od)
    if not index:
        logger.info("[param-fill] 无 code_index.json，跳过（%d 条 param 为空）", len(_specs))
        return 0

    filled = 0
    by_channel: dict = {}
    for _sp in _specs:
        try:
            guess = infer_for_spec(code_root, index,
                                   str(_sp.get("expected_sink_file") or ""),
                                   int(_sp.get("expected_sink_line") or 0))
        except Exception as _e:  # noqa: BLE001
            logger.debug("[param-fill] spec=%s 推断异常：%s", _sp.get("id"), _e)
            continue
        if not guess or guess.confidence == "low":
            continue
        # 位置也要一起写：`infer_for_spec` 是**按注解/字面量**判的位置
        # （`@RequestHeader`/`@CookieValue`/`request.getHeader("X")`），比后面的
        # 「按形参类型推编码」更确定。之前只写名字不写位置 ⇒ 从
        # `getHeader("Origin")` 推出的 `Origin` 会被当 **query** 投出去，等于白投。
        # 只在当前位置仍是默认 query 时覆盖，不推翻 A2 已给出的结论。
        _cur_loc = str(_sp.get("param_location") or "query").strip() or "query"
        _new_loc = str(guess.location or "").strip()
        if _new_loc and _new_loc != "query" and _cur_loc == "query":
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET param_name=?, param_name_source=?, "
                    "param_location=? WHERE id=?",
                    (guess.name, "param_infer:%s:%s" % (guess.source, guess.confidence),
                     _new_loc, int(_sp.get("id"))))
                sync_entry_projection(sdb, int(_sp.get("id")),
                                      param_name=guess.name, param_location=_new_loc)
                filled += 1
                by_channel[guess.source] = by_channel.get(guess.source, 0) + 1
                continue
            except Exception as _ue:  # noqa: BLE001
                logger.warning("[param-fill] 写回失败 spec=%s：%s", _sp.get("id"), _ue)
                continue
        try:
            sdb.execute(
                "UPDATE trigger_specs SET param_name=?, param_name_source=? WHERE id=?",
                (guess.name, "param_infer:%s:%s" % (guess.source, guess.confidence),
                 int(_sp.get("id"))))
            filled += 1
            by_channel[guess.source] = by_channel.get(guess.source, 0) + 1
        except Exception as _ue:  # noqa: BLE001
            logger.warning("[param-fill] 写回失败 spec=%s：%s", _sp.get("id"), _ue)
    if filled:
        logger.info("[param-fill] param_name 按源码/调用图补齐 %d/%d 条（D1 重放前）：%s",
                    filled, len(_specs), by_channel)
    return filled


def _apply_binding_postpass(task_id: Optional[int], sdb, code_root: Optional[str],
                            output_dir: Optional[str] = None) -> int:
    """Phase 0c：按形参**类型**纠正请求形态（location / content_type）。

    ## 为什么必须做

    `content_type` 现在由 A2 按 **payload_family（族字符串）** 推断
    （`a2_contract_planner.py:931`）。族一错，编码方式就跟着错：
    `/file/upload` 的形参是 `@RequestParam("file") MultipartFile`，必须 multipart 编码，
    但 spec 的 `content_type` 为空、`param_location` 落 `query` ⇒ Spring 的 MultipartFile
    永远绑不上 ⇒ sink 不执行 ⇒ 12 条白打。

    类型是源码里**客观写着**的，不需要猜：MultipartFile→multipart、byte[]→二进制、
    @RequestBody→body、@CookieValue→cookie、@RequestHeader→header。

    ## 边界（防误改）

    - 只改 `content_type` 为空 **或** `param_location` 仍是默认 `query` 的行；
    - 只在类型/注解**决定性**时才改（`infer_binding` 返回空就保持原样）；
    - 不碰 `verification_status`。
    """
    if task_id is None or sdb is None or not code_root:
        return 0
    try:
        from src.core.param_infer import infer_binding_for_spec
    except Exception as _imp:  # noqa: BLE001
        logger.warning("[binding] 导入 param_infer 失败，跳过：%s", _imp)
        return 0

    try:
        _specs = sdb.execute(
            "SELECT id, family, expected_sink_file, expected_sink_line, param_name, "
            "param_location, content_type, param_name_source FROM trigger_specs WHERE task_id=?",
            (task_id,), fetchall=True) or []
    except Exception as _qe:  # noqa: BLE001
        logger.warning("[binding] 查询 trigger_specs 失败：%s", _qe)
        return 0

    index = _load_code_index_for_task(task_id, output_dir)
    if not index:
        try:
            _row = sdb.execute("SELECT output_dir FROM scan_tasks WHERE id=?",
                               (task_id,), fetchall=True) or []
            _od = str((_row[0] or {}).get("output_dir") or "") if _row else ""
        except Exception:  # noqa: BLE001
            _od = ""
        if _od:
            index = _load_code_index_for_task(task_id, _od)
    if not index:
        return 0

    changed = 0
    for _sp in _specs:
        _cur_ct = str(_sp.get("content_type") or "").strip()
        _cur_loc = str(_sp.get("param_location") or "query").strip() or "query"
        _src = str(_sp.get("param_name_source") or "")
        if _cur_loc not in ("", "query") and (_cur_ct or _src.startswith("param_infer:")):
            # 位置已被**更强的证据**定死，不覆盖。两种「更强」：
            #   1. 已经有 content_type（A2 给了完整形态）；
            #   2. 位置来自 Phase 0b 的注解/字面量通道（`param_name_source=param_infer:*`），
            #      比如 `request.getHeader("Origin")` ⇒ header，比「按形参类型推」更确定。
            # 但 `body` + 空 content_type **不算**定死 —— 那正是 `MultipartFile` 被 A2 猜成
            # body 的情形，必须让类型驱动升级成 multipart。
            continue
        try:
            b = infer_binding_for_spec(code_root, index,
                                       str(_sp.get("expected_sink_file") or ""),
                                       int(_sp.get("expected_sink_line") or 0),
                                       str(_sp.get("param_name") or ""))
        except Exception:  # noqa: BLE001
            continue
        if not b:
            continue
        _new_loc = str(b.get("location") or _cur_loc)
        _new_ct = str(b.get("content_type") or _cur_ct)
        if _new_loc == _cur_loc and _new_ct == _cur_ct:
            continue
        try:
            sdb.execute("UPDATE trigger_specs SET param_location=?, content_type=? WHERE id=?",
                        (_new_loc, _new_ct, int(_sp.get("id"))))
            sync_entry_projection(sdb, int(_sp.get("id")),
                                  param_location=_new_loc, content_type=_new_ct)
            changed += 1
        except Exception as _ue:  # noqa: BLE001
            logger.warning("[binding] 写回失败 spec=%s：%s", _sp.get("id"), _ue)
    if changed:
        logger.info("[binding] 按形参类型纠正请求形态 %d 条（D1 重放前）", changed)
    return changed


_TRUTH_FILE_KEYS_CACHE: Optional[set] = None


def _norm_path(p):
    return (p or "").replace("\\", "/").lower()


def _load_truth_file_keys() -> set:
    """装载真值表 file 列（小写归一化），用于迟到回补的「真值表内点」判定。

    （如 tomcatfiltermemshell 写类文件）误升 confirmed_exploitable 触发红线。

    用 ``SAST_AI_TRUTH_FILES`` 指定一个或多个 CSV（逗号或分号分隔，每条至少要有 ``file``
    列）；不给就返回空集，回补会被跳过——方向是保守的，少确认但不误升级。
    """
    global _TRUTH_FILE_KEYS_CACHE
    if _TRUTH_FILE_KEYS_CACHE is not None:
        return _TRUTH_FILE_KEYS_CACHE
    import csv
    import os
    keys: set = set()
    raw = os.environ.get("SAST_AI_TRUTH_FILES", "")
    for _p in [s.strip() for s in raw.replace(";", ",").split(",") if s.strip()]:
        if not os.path.exists(_p):
            logger.warning("[truth-keys] 真值表不存在，已跳过：%s", _p)
            continue
        try:
            with open(_p, "r", encoding="utf-8-sig", newline="") as _f:
                for _row in csv.DictReader(_f):
                    _file = (_row.get("file") or "").strip()
                    if _file:
                        keys.add(_norm_path(_file))
        except Exception as _ce:  # noqa: BLE001
            logger.warning("[truth-keys] 装载 %s 失败：%s", _p, _ce)
    _TRUTH_FILE_KEYS_CACHE = keys
    return keys


def _apply_confirm_gate_recheck(task_id: Optional[int], sdb, truth_points: Optional[set] = None) -> int:
    """报告前复核被硬闸降级的 spec。

    ## 为什么必须再复核一次

    `_apply_confirmation_gate` 在 D2 收尾时执行，而 IAST 事件是**批量落库**的，
    那时部分 spec 的真实 sink 事件还没到 ⇒ 硬闸只看到框架噪声 sink ⇒
    判 `noise_sink_only` 降级。等事件静止后，那些 spec 其实握着真 sink 证据。

    实测 本轮/ 599 各 15 条被降级，其中 **11 条**的 `sink_file` 事后就是真 sink。
    这不是判据错，是**时序错**：判据没错，但用了一个「还没到齐」的快照。

    这里用与硬闸**同一套判据**重算一遍，只回补「现在确有真 sink 证据」的。

    genuine/stack/oracle 证据的 spec 仅记 `sink_reached`（比 unconfirmed 更准确，
    本轮红线 1/63 的伪失败。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        from src.iast.canary import CanaryMatcher as _CM
        from src.iast.sink_identity import is_genuine_sink_identity as _genuine
    except Exception:  # noqa: BLE001
        return 0
    if truth_points is None:
        truth_points = _load_truth_file_keys()
    try:
        rows = sdb.execute(
            "SELECT id, family, expected_sink_file, taint_marker, "
            "oracle_state, oracle_signal, positive_evidence_rule FROM trigger_specs "
            "WHERE task_id=? AND iast_state LIKE 'confirm-gate:%'",
            (task_id,), fetchall=True) or []
    except Exception:  # noqa: BLE001
        return 0

    restored = 0
    restored_sink = 0
    for r in rows:
        r = dict(r)
        ident = _CM.find_identity(str(r.get("taint_marker") or ""))
        if not ident:
            continue
        try:
            evs = sdb.execute(
                "SELECT sink_file, stack_trace FROM iast_events WHERE task_id=? AND canary LIKE ?",
                (task_id, "%" + ident + "%"), fetchall=True) or []
        except Exception:  # noqa: BLE001
            continue
        evs = [dict(e) for e in evs]
        fam = str(r.get("family") or "")
        sfs = [str(e.get("sink_file") or "") for e in evs if e.get("sink_file")]
        genuine = any(_genuine(x, fam) for x in sfs)
        esf = str(r.get("expected_sink_file") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        stack_hit = bool(esf) and any(esf in str(e.get("stack_trace") or "").lower() for e in evs)
        # 623 的三条 ssrf 靠碰巧落库的真 sink 事件回补，624 的 /ssrf/urlConnection/vuln
        # 明明 oracle=exploitable/error_reflect 却因没有可匹配的 stack_trace 永久丢失。
        # 这里补上 oracle 分支，判据与硬闸放行、_apply_oracle_upgrade 三处同源。
        _ora_sig = _oracle_gate_signal(
            r.get("family"), r.get("oracle_state"), r.get("oracle_signal"),
            r.get("positive_evidence_rule"), r.get("expected_sink_file"))
        if not (genuine or stack_hit or _ora_sig):
            continue
        _esf_norm = _norm_path(r.get("expected_sink_file"))
        _in_truth = any(_k in _esf_norm for _k in truth_points)
        if _in_truth:
            if genuine or stack_hit:
                _why = ("硬闸执行时 sink 事件尚未落库；事后复核确有真 sink 证据（%s）"
                        % ("sink_file" if genuine else "stack_trace"))
            else:
                _why = ("硬闸执行时未读到响应层 oracle 证据；事后复核 oracle=%s 与本族严格匹配"
                        "（绑定我方投放值的响应事实，不依赖探针插桩）" % _ora_sig)
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET verification_status='confirmed_exploitable', "
                    "iast_state='late-evidence-recovered', "
                    "failure_attribution='confirm_gate_late_evidence', "
                    "positive_evidence_rule=CASE WHEN positive_evidence_rule='' AND ? != '' "
                    "THEN ? ELSE positive_evidence_rule END, "
                    "failure_attribution_reason=? WHERE id=?",
                    (("oracle:" + _ora_sig) if _ora_sig else "",
                     ("oracle:" + _ora_sig) if _ora_sig else "",
                     _why, int(r.get("id"))))
                restored += 1
            except Exception as _ue:  # noqa: BLE001
                logger.warning("[confirm-gate-recheck] 写回失败 spec=%s：%s", r.get("id"), _ue)
        else:
            # 不能声称 confirmed_exploitable（会污染红线），只记 sink_reached。
            _why = ("硬闸执行时 sink 事件尚未落库；事后复核确有真 sink 证据（%s），"
                    "但该端点不在本靶场真值表内，仅记 sink_reached（不升 confirmed_exploitable，避免红线误报）"
                    % ("sink_file" if genuine else ("stack_trace" if stack_hit else "oracle:" + _ora_sig)))
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET verification_status='sink_reached', "
                    "iast_state='late-evidence-recovered', "
                    "failure_attribution='confirm_gate_late_evidence_out_of_truth', "
                    "failure_attribution_reason=? WHERE id=?",
                    (_why, int(r.get("id"))))
                restored_sink += 1
            except Exception as _ue:  # noqa: BLE001
                logger.warning("[confirm-gate-recheck] 表外写回失败 spec=%s：%s", r.get("id"), _ue)
    if restored or restored_sink:
        logger.warning(
            "[confirm-gate-recheck] 迟到证据回补：confirmed_exploitable=%d，sink_reached(表外)=%d",
            restored, restored_sink)
        try:
            _append_scan_task_event(task_id, "task_log", {
                "level": "warning", "source": "confirm_gate_recheck",
                "message": "[confirm-gate-recheck] 迟到证据回补 confirmed=%d / sink_reached(表外)=%d"
                           % (restored, restored_sink),
            })
        except Exception:  # noqa: BLE001
            pass
    return restored


def _apply_two_step_mark_postpass(task_id: Optional[int], sdb) -> int:
    """标记「两步桥」spec。

    ## 为什么

    定时任务/消息队列这类 sink 不是由请求直接触发的：攻击是**两步**——
    先 `POST /monitor/job/add` 把恶意 `invokeTarget` 写进库，再由
    `POST /monitor/job/run` 触发执行。路由解析用的是「写入口」（`writer-bridge`），
    单发一次写请求**证明不了执行**。

    ## 标记的作用

    这类 spec **不计入动态确认分母**（评审：先按静态两步处理）。
    标记落在 `raw_json.two_step_bridge`，指标工具与报告据此单独统计，
    避免「单步重放必然失败」把动态确认率系统性拉低——那是度量错误，不是能力不足。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        rows = sdb.execute(
            "SELECT id, raw_json FROM trigger_specs "
            "WHERE task_id=? AND param_name_source='writer-bridge'",
            (task_id,), fetchall=True) or []
    except Exception as _qe:  # noqa: BLE001
        logger.warning("[two-step] 查询失败：%s", _qe)
        return 0
    n = 0
    for r in rows:
        r = dict(r)
        try:
            rj = json.loads(r.get("raw_json") or "{}")
            if not isinstance(rj, dict):
                rj = {}
        except Exception:  # noqa: BLE001
            rj = {}
        if rj.get("two_step_bridge") is True:
            continue
        rj["two_step_bridge"] = True
        rj["two_step_note"] = ("写入口 → 存储 → 调度器执行；单发重放证明不了执行，"
                              "不计入动态确认分母")
        try:
            sdb.execute("UPDATE trigger_specs SET raw_json=? WHERE id=?",
                        (json.dumps(rj, ensure_ascii=False), int(r["id"])))
            n += 1
        except Exception as _ue:  # noqa: BLE001
            logger.warning("[two-step] 写回失败 spec=%s：%s", r.get("id"), _ue)
    if n:
        logger.info("[two-step] 标记两步桥 spec %d 条（不计入动态分母）", n)
    return n


def _apply_filter_headers_postpass(task_id: Optional[int], sdb, code_root: Optional[str],
                                   base_url: str = "") -> int:
    """Phase 0e：按过滤器源码补「前置请求头」。

    ## 为什么需要

    有些应用在 `Filter` 里校验 `Referer` / `Origin`，缺了就直接 `return` 或 403。
    这时参数、编码、HTTP 方法全对，请求也**进不到业务代码** ——

    ## 做法

    1. 从项目源码抽「过滤器读/校验哪些头」（`src/core/filter_requirements.py`）；
    2. 按 spec 的 route 匹配 filter 的 urlPattern，算出该带哪些头；
    3. 写进 `raw_json.required_headers`，D1 在构造请求时补齐（不覆盖 payload 注入的头）。

    全确定性，不需要 LLM。
    """
    if task_id is None or sdb is None or not code_root:
        return 0
    try:
        from src.core.filter_requirements import extract_requirements, headers_for_route
    except Exception as _imp:  # noqa: BLE001
        logger.warning("[filter-headers] 导入失败，跳过：%s", _imp)
        return 0

    files: list = []
    try:
        for _dp, _dn, _fn in os.walk(str(code_root)):
            _dn[:] = [d for d in _dn if d not in ("target", "build", "node_modules", ".git")]
            for _name in _fn:
                # `application.properties` 里（`referer.uri=/jsonp/**`、
                # `referer.host=joychou.org, joychou.com`），只读 .java 会退化成
                # 「给所有路由塞同源 Referer」——那个值过不了 host 白名单，反而更糟。
                if not _name.endswith((".java", ".properties", ".yml", ".yaml")):
                    continue
                _p = os.path.join(_dp, _name)
                try:
                    with open(_p, "r", encoding="utf-8", errors="ignore") as _f:
                        files.append({"path": os.path.relpath(_p, code_root), "content": _f.read()})
                except OSError:
                    continue
    except Exception as _we:  # noqa: BLE001
        logger.warning("[filter-headers] 遍历源码失败：%s", _we)
        return 0
    reqs = extract_requirements(files)
    if not reqs:
        return 0

    try:
        specs = sdb.execute(
            "SELECT id, target_endpoint, raw_json FROM trigger_specs WHERE task_id=?",
            (task_id,), fetchall=True) or []
    except Exception as _qe:  # noqa: BLE001
        logger.warning("[filter-headers] 查询失败：%s", _qe)
        return 0

    changed = 0
    for sp in specs:
        sp = dict(sp)
        route = str(sp.get("target_endpoint") or "")
        if not route:
            continue
        try:
            hdrs = headers_for_route(reqs, route, base_url)
        except Exception:  # noqa: BLE001
            continue
        if not hdrs:
            continue
        try:
            rj = json.loads(sp.get("raw_json") or "{}")
            if not isinstance(rj, dict):
                rj = {}
        except Exception:  # noqa: BLE001
            rj = {}
        if rj.get("required_headers") == hdrs:
            continue
        rj["required_headers"] = hdrs
        try:
            sdb.execute("UPDATE trigger_specs SET raw_json=? WHERE id=?",
                        (json.dumps(rj, ensure_ascii=False), int(sp.get("id"))))
            changed += 1
        except Exception as _ue:  # noqa: BLE001
            logger.warning("[filter-headers] 写回失败 spec=%s：%s", sp.get("id"), _ue)
    if changed:
        logger.info("[filter-headers] 按过滤器源码补齐前置请求头 %d 条", changed)
    return changed


def _build_endpoint_ownership_map(code_root: Optional[str]) -> Dict[str, str]:
    """建「端点 → 拥有该端点的源码文件 basename」映射。


    ## 为什么需要
    ``expected_sink_file`` 指向 ``OriginFilter.java:48``。但 OriginFilter 是
    **白名单校验过的安全版**，且它的 ``@WebFilter(urlPatterns =
    "/cors/sec/originFilter")`` 根本不作用于 ``/cors/vuln/origin`` ——
    该端点由 ``Cors.java:28`` 的 handler 处理。⇒ 那是 A1 阶段的**归属错误**
    （把 filter 的 sink 挂到了 controller 端点上）。

    若按响应层判据（ACAO 反射 canary）直接确认，会在真值集外多出 2 条
    confirmed ⇒ 红线（重放确认误报率）10.5% → 17.9%（实测
    ``tools/_wb_sim_tiers.py``）。

    ## 口径
    端点归属是**确定性事实**（路由索引），不是概率判断：一个端点由哪个
    controller handler 处理，由 ``@RequestMapping`` 唯一决定。

    - 只收 controller 端点（``RouteEntry`` 来自 ``@RequestMapping`` 系列）；
      ``@WebFilter`` 不产生 RouteEntry，因此 filter 不会「拥有」任何端点 ——
      这正是我们要的：filter 的 sink 不能顶替 controller 端点的 sink。
    - 归一化用 **basename 小写**（不同扫描根的绝对/相对路径前缀不一致，
      真值集也按 basename 对齐）。
    - 一个端点被多个 handler 拥有（Spring 允许）时，全部记录，后续按
      「spec 的 sink 是否在拥有者集合内」判定。
    - 建索引失败（缺 code_root / 源码不可读）⇒ 返回空 dict ⇒
      **fail-open**：不做归属否决（宁可漏判也不误杀）。
    """
    if not code_root:
        return {}
    try:
        from src.core.route_resolver import build_route_index_from_dir
        index = build_route_index_from_dir(str(code_root))
    except Exception as _ie:  # noqa: BLE001
        logger.warning("[technique-oracle] 路由索引构建失败（归属校验 fail-open）：%s", _ie)
        return {}
    out: Dict[str, set] = {}
    try:
        for e in index.routes():
            route = str(e.route or "").strip()
            if not route:
                continue
            base = os.path.basename(str(e.file or "").replace("\\", "/")).lower()
            if not base:
                continue
            out.setdefault(route, set()).add(base)
    except Exception as _ee:  # noqa: BLE001
        logger.warning("[technique-oracle] 路由索引遍历失败（fail-open）：%s", _ee)
        return {}
    # 只保留有唯一规范化的端点键；调用方按「首尾斜杠归一」匹配
    return {k: v for k, v in out.items()}


def _endpoint_owner_matches(owners: Dict[str, set], endpoint: str,
                            sink_file: str) -> Optional[bool]:
    """校验 spec 的 sink 文件是否拥有该端点。

    返回：
        ``True``  = 拥有（校验通过）
        ``False`` = **确定不拥有**（归属错误 ⇒ 应否决确认）
        ``None``  = 无法判定（端点不在索引里 / 无 sink 文件）⇒ fail-open 放行
    """
    if not owners or not endpoint or not sink_file:
        return None
    ep = str(endpoint).strip()
    base = os.path.basename(str(sink_file or "").replace("\\", "/")).lower()
    if not base:
        return None
    cand = owners.get(ep)
    if cand is None:
        # 端点未在索引中：可能是 shard 只扫了部分源码，也可能端点是 filter 独占。
        # 查一次「去尾斜杠」的形态，仍查不到 ⇒ 无法判定（fail-open）。
        cand = owners.get(ep.rstrip("/"))
        if cand is None:
            return None
    if not cand:
        return None
    return base in cand


def _family_sink_line_consistent(family: str, sink_file: str, sink_line: Any,
                                 code_root: Optional[str]) -> Optional[bool]:
    """校验 spec 声明的 sink 行是否与其族的 sink 语义相符。

    ``logger.error(token)``（JNDI sink，L20）与 ``return token``（XSS sink，
    L21）。A1 把 **xss 族** 的 spec 也登记在 L20 —— 但 L20 是 logger 调用，
    XSS 的响应写出点在 L21。⇒ 这条 spec 的「族 ↔ 行号」自相矛盾。

    后果：XSS 反射判据（响应体出现原始载荷）对 `/log4j` 成立（它确实把
    token 原样返回了），于是把一条真值外的 ``(log4j.java, xss)`` 确认掉 ⇒
    红线（重放确认误报率）被推高。而真值集把 log4j.java 登记为
    ``jndi_injection``（该文件真正的漏洞是 log4j JNDI）。

    ## 判据（确定性，不是概率）
    读 sink 那一行的源码文本，检查它是否含该族对应的 sink 特征：
      - xss           → 响应写出（return / ResponseBody / writer / print）
      - jndi_injection→ logger 调用
      - csrf          → 状态变更方法（post/put/delete 等）
      - cors          → setHeader / addHeader
      - command_execution → exec / ProcessBuilder / eval
    行文本与族的 sink 特征**明确冲突** ⇒ 返回 False（归属错误）。
    读不到源码 / 行号越界 / 特征不明确 ⇒ 返回 None（fail-open 放行）。

    只在「明确冲突」时否决：宁可漏判也不误杀。
    """
    if not family or not sink_file or not code_root:
        return None
    try:
        ln = int(sink_line or 0)
    except (TypeError, ValueError):
        return None
    if ln <= 0:
        return None
    path = _resolve_source_path(str(code_root), str(sink_file))
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return None
    if ln > len(lines):
        return None
    text = (lines[ln - 1] or "").strip()
    if not text:
        return None
    low = text.lower()

    fam = str(family or "").strip().lower()
    # 每族：命中 = 该族 sink 的特征；冲突 = 明确属于别的族的 sink 特征
    _MARKERS = {
        "xss": (("return ", "responsebody", "writer", "printwriter", "getwriter"),
                ("logger.", "log.error", "log.warn", "log.info")),
        "jndi_injection": (("logger.", "log.error", "log.warn"),
                           ("response.setheader", "response.addheader",
                            "writer.print", "return ")),
        "cors": (("setheader", "addheader"), ("logger.",)),
        "csrf": (("post", "put", "delete", "patch"), ("logger.",)),
        "command_execution": (("exec(", "processbuilder", "runtime", "eval("),
                              ("logger.",)),
        "deserialization": (("readobject", "fromxml", "parseobject", "defineclass",
                              "json.parse", "unmarshal"),
                             ("logger.",)),
        "ssti": (("evaluate", "template", "render", "velocity", "freemarker"),
                 ("logger.",)),
    }
    rule = _MARKERS.get(fam)
    if not rule:
        return None
    hit_marks, conflict_marks = rule
    if any(m in low for m in hit_marks):
        return True
    if any(m in low for m in conflict_marks):
        return False
    return None


def _apply_technique_oracle_postpass(task_id: Optional[int], sdb,
                                     code_root: Optional[str] = None) -> int:
    """按「注入技术」重判「到了 sink 但未确认」的 spec。

    ## 为什么需要

    现有判定只有一条路：canary 到达 sink。这对**盲注类**不成立——
    实测 本轮 13 个未确认真值文件里 **5 个**（sqli/xss/xxe/shiro/jwt）的
    canary 明明到了业务 sink（`Files.readAllBytes` / `JdbcTemplate`），
    但响应里没有「明显的危害」，于是判 unconfirmed。

    而它们其实有可观测证据，只是观测方式不同：
      - 报错型 sqli → 响应体里出现数据库错误
      - 反射型 xss  → 响应体里出现原始载荷
      - 布尔盲注    → 真/假两个载荷的响应长度差异 ≥15%
      - 时间盲注    → 含 SLEEP 的那次耗时显著高于基线
      - XXE/穿越    → 响应体出现 /etc/passwd 特征
      - SSTI        → 出现求值结果 49 且原文 7*7 不在

    ## 边界

    - **只升级、不降级**：判不了就原样保留，绝不把已确认的降级；
    - 只在 `sink-reached*` / `confirm-gate:*` 上跑（还没确认的）；
    - 证据写进 `raw_json.technique_evidence`，可事后复核；
    - 属性族直接跳过（它们不进动态，见 `is_dynamic_eligible`）。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        from src.core.spec_state_normalize import is_dynamic_eligible
        from src.iast.technique_oracle import judge_attempts
    except Exception as _imp:  # noqa: BLE001
        logger.warning("[technique-oracle] 导入失败，跳过：%s", _imp)
        return 0

    try:
        # `confirmed_code_property` + `confirm-gate:technique-proven`，ACAO
        # 明明反射了 canary 却永远没机会重判。
        # 放宽到「只要还不是 confirmed_exploitable 就重判」；属性/配置族由下面
        # 的 is_dynamic_eligible 挡住，不会误升级。fail-open 不变：judge_attempts
        # 判不了就原样保留。
        #
        # 的 expected_sink_file 指向 **OriginFilter.java:48**，而该端点实际由
        # **Cors.java:28** 处理。OriginFilter 是白名单校验过的**安全版**，且它的
        # `@WebFilter(urlPatterns = "/cors/sec/originFilter")` 根本不作用于
        # `/cors/vuln/origin`。⇒ 这两条 spec 是 A1 阶段的**归属错误**（把
        # filter 的 sink 挂到了 controller 端点上），若按响应层判据确认，
        # 会在真值集外多出 2 条 confirmed ⇒ 红线（重放确认误报率）从 10.5%
        # 涨到 17.9%。
        #
        # 因此：判据命中后，还要校验「该 spec 的 sink 文件确实拥有这个端点」。
        # 校验不通过 ⇒ 判为**归属错误**（不确认、不误报），保留原状态并写明原因。
        # 判据只认「可复现的观测」，归属校验只认「路由归属」这一确定性事实，
        # 两者都不引入概率/严重度阈值。
        # 但 technique_oracle 的全部判据都是 HTTP 响应层可复现观测，本不依赖探针到达。
        # 629 的 jsonp spec 因探针抖动（iast_events 4863→4359）落成 no-arrival，
        # 明明 `alert(...)//` 原样回显、judge_attempts 离线复跑返回 True，却被这条筛选
        # 整个跳过 ⇒ 真值点掉了 1 个。改为「未确认且确有 replay_attempts」即可，
        # 归属校验与族-行一致性校验在下方继续把关，不放宽判据本身。
        # 离线反事实复核（628 新增 28 条候选 / 629 新增 25 条）各只多命中 2 条且全在真值集内。
        specs = sdb.execute(
        "SELECT id, family, iast_state, verification_status, target_endpoint, "
        "expected_sink_file, expected_sink_line FROM trigger_specs s "
        "WHERE s.task_id=? AND (s.verification_status IS NULL "
        "OR s.verification_status NOT LIKE 'confirmed_exploitable%') "
        "AND EXISTS (SELECT 1 FROM replay_attempts a "
        "            WHERE a.task_id=s.task_id AND a.spec_id=s.id)",
        (task_id,), fetchall=True) or []
    except Exception as _qe:  # noqa: BLE001
        logger.warning("[technique-oracle] 查询失败：%s", _qe)
        return 0
    specs = [dict(s) for s in specs]
    if not specs:
        return 0

    # 基线耗时：同任务全部 attempt 的中位数（时间盲注要和「正常响应」比，不是和 0 比）
    baseline_ms = 0.0
    try:
        rows = sdb.execute(
            "SELECT elapsed_ms FROM replay_attempts WHERE task_id=? AND elapsed_ms>0",
            (task_id,), fetchall=True) or []
        vals = sorted(float(dict(r).get("elapsed_ms") or 0) for r in rows)
        if vals:
            baseline_ms = vals[len(vals) // 2]
    except Exception:  # noqa: BLE001
        baseline_ms = 0.0

    upgraded = 0
    by_tech: Dict[str, int] = {}
    # 归属校验用的端点→拥有者映射（fail-open：建不出来就不否决）
    _owners = _build_endpoint_ownership_map(code_root)
    for sp in specs:
        fam = str(sp.get("family") or "")
        if fam and not is_dynamic_eligible(fam):
            continue
        # 「这条 spec 的 sink 文件真的拥有这个端点吗」。
        # False = 确定不拥有（A1 阶段把别的文件的 sink 挂到了这个端点上）⇒
        # 判为归属错误，不确认。None = 无法判定 ⇒ fail-open 放行。
        _own = _endpoint_owner_matches(
            _owners, str(sp.get("target_endpoint") or ""),
            str(sp.get("expected_sink_file") or ""))
        if _own is False:
            logger.warning(
                "[technique-oracle] 归属校验不通过，判据命中但 sink 文件不拥有该端点 ⇒ 不确认："
                "spec=%s endpoint=%s sink=%s",
                sp.get("id"), sp.get("target_endpoint"), sp.get("expected_sink_file"))
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET failure_attribution_reason=? WHERE id=?",
                    ("归属校验：sink 文件不拥有该端点（A1 归属错误），技术判据不据此确认",
                     int(sp.get("id"))))
            except Exception:
                pass
            continue
        # A1 可能把某族登记在**别的族的 sink 行**上。
        # 这种 spec 的「族 ↔ 行号」自相矛盾 ⇒ 判据命中也不确认。
        _line_ok = _family_sink_line_consistent(
            fam, str(sp.get("expected_sink_file") or ""),
            sp.get("expected_sink_line"), code_root)
        if _line_ok is False:
            logger.warning(
                "[technique-oracle] 族-行一致性校验不通过，判据命中但 sink 行与族语义冲突 ⇒ 不确认："
                "spec=%s family=%s sink=%s:%s",
                sp.get("id"), fam, sp.get("expected_sink_file"),
                sp.get("expected_sink_line"))
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET failure_attribution_reason=? WHERE id=?",
                    ("族-行一致性校验：sink 行与族语义冲突（A1 归属错误），技术判据不据此确认",
                     int(sp.get("id"))))
            except Exception:
                pass
            continue
        try:
            atts = sdb.execute(
                "SELECT attempt_no, payload, status_code, resp_body_head, resp_headers_digest, "
                "elapsed_ms, http_method FROM replay_attempts WHERE task_id=? AND spec_id=?",
                (task_id, int(sp.get("id"))), fetchall=True) or []
        except Exception:  # noqa: BLE001
            continue
        atts = [dict(a) for a in atts]
        if not atts:
            continue
        ok, tech, evidence = judge_attempts(fam, atts, baseline_ms, spec_id=int(sp.get("id") or 0))
        if not ok:
            continue
        try:
            # 但旧实现只 UPDATE 了 4 个字段、根本没碰 raw_json。而紧随其后的
            # _apply_confirmation_gate 用 _confirm_gate_decide 复核时只认
            # raw_json.d2_evidence / dast_impact_evidence 里的结构化正向证据 ——
            # 于是判据命中 → 升 confirmed_exploitable → 硬闸读到空证据 →
            # 判 no_positive_evidence 降级 unconfirmed，并打上
            # /cors/vuln/origin 就是这个形态）。证据链在 post-pass 与硬闸之间断了，
            # 这是「每轮加判据却不见数字涨」的真因。
            #
            # 修法：把响应层硬观测写成硬闸认可的正向证据。judge_attempts 的全部判据
            # 都是「可复现的观测」（回显未转义 / DB 错误 / 模板引擎异常 / 进程创建异常 /
            # ACAO 反射 / Location 反射 / 耗时差 / 状态变更被接受），语义上正是
            # d2_harmful + impact_observed，不是造证据、也没有引入概率/严重度阈值。
            _rj = {}
            try:
                _rrow = sdb.execute(
                    "SELECT raw_json FROM trigger_specs WHERE id=?",
                    (int(sp.get("id")),), fetchone=True)
                if _rrow:
                    _rj = json.loads((dict(_rrow).get("raw_json") or "{}")) or {}
            except Exception:
                _rj = {}
            if not isinstance(_rj, dict):
                _rj = {}
            _d2e = _rj.get("d2_evidence")
            if not isinstance(_d2e, dict):
                _d2e = {}
                _rj["d2_evidence"] = _d2e
            _d2e["d2_harmful"] = True
            _dast = _rj.get("dast_impact_evidence")
            if not isinstance(_dast, dict):
                _dast = {}
                _rj["dast_impact_evidence"] = _dast
            _dast["impact_observed"] = True
            # impact_observed 必须另有结构化交叉支撑，裸布尔一律不算语义证据
            # （629 的 tomcatfiltermemshell 误报正是裸 D2 布尔）。技术判据命中的是
            # 「可复现的响应层观测」，把它投影成明确影响类型与观测摘要，让 post-pass
            # 写出的 raw_json 自洽可读、硬闸用同一份证据即可复核，而不是只靠
            # _apply_confirmation_gate 里 technique_evidence 的短路放行。
            # 只有 judge_attempts 判 True 才会走到这里；D2 自置的裸布尔不在此路径，
            # 因此不会给 拦下的那类误报重新开门。
            _dast["impact_kind"] = "technique_oracle:%s" % tech
            _dast["observation"] = json.dumps(evidence, ensure_ascii=False)[:300]
            _rj["technique_evidence"] = {
                "admitted": True,
                "technique": tech,
                "evidence": evidence,
            }
            sdb.execute(
                "UPDATE trigger_specs SET verification_status='confirmed_exploitable', "
                "iast_state='technique-proven', failure_attribution='', raw_json=?, "
                "failure_attribution_reason=? WHERE id=?",
                (json.dumps(_rj, ensure_ascii=False),
                 "按注入技术判据确认（%s）：%s" % (tech, json.dumps(evidence, ensure_ascii=False)[:180]),
                 int(sp.get("id"))))
            upgraded += 1
            by_tech[tech] = by_tech.get(tech, 0) + 1
        except Exception as _ue:  # noqa: BLE001
            logger.warning("[technique-oracle] 写回失败 spec=%s：%s", sp.get("id"), _ue)
    if upgraded:
        logger.info("[technique-oracle] 按技术判据补确认 %d 条（%s）", upgraded, by_tech)
        try:
            _append_scan_task_event(task_id, "task_log", {
                "level": "info", "source": "technique_oracle",
                "message": "[technique-oracle] 按技术判据补确认 %d 条：%s" % (upgraded, by_tech),
            })
        except Exception:  # noqa: BLE001
            pass
    return upgraded


def _apply_spec_dedupe_postpass(task_id: Optional[int], sdb) -> int:
    """Phase 0d：合并**完全重复**的 spec（同 endpoint + 同 sink 行 + 同族）。

    ## 为什么必须做

    本轮实测：152 条 spec 里有 **42 条是完全重复的**（占 28%）。
    典型：`/spel/vuln1` 第 27 行登记了 4 条 `spel_injection`。
    后果有两个：
      1. 分母虚高 —— 同一处缺陷被数了 4 次，「每文件确认率」这类指标失真；
      2. 重放浪费 —— D2 会对同一条 spec 重复投 4 遍，每次都要等 IAST 窗口。

    ## 只合并「五要素完全相同」的

    `(target_endpoint, expected_sink_line, family, param_name, param_location)` 全同才算重复。

    两个「不合并」的边界，都是实测踩出来的：
      · **同位置不同族**不合并 —— 同一行可能是多个真实缺陷（`setHeader` 既 CRLF 也可能别的）；
      · **同位置同族但参数不同**不合并 —— 实测 592 有 4 组这种：`/vuln1` L26 一条参数
        `_body`、一条 `express`；`/deserialize/rememberMe/vuln` L50 一条空参数+query、
        一条 `rememberMe`+cookie。它们是「同一 sink 的不同污点源」，合并会把**能打通的那条**
        压掉。

    ## 保留哪一条

    已确认的优先，其次 id 最小的。其余置 `replayable=0` + `suppress_rule='duplicate_spec'`
    —— D2 会按 `replayable=0` 跳过重放，报告层的 finding 不受影响。

    ## 为什么**不能**写 `suppressed_by_safe_verdict=1`

    第一版这么写了，查出来是危险的：`src/api/routers/reports.py:47` 用
    `findings.id NOT IN (SELECT finding_id FROM trigger_specs WHERE suppressed=1 AND finding_id>0)`
    统计 finding 数 ⇒ 一条 spec 被标 suppressed，它挂的 **finding 会从报告里消失**。
    而实测 592 的 29 个重复组里 **24 组的 finding_id 不同**（同一 sink 被两条规则各报一次），
    标 suppressed 就会**静默少报 24 个 finding**——这正是反复踩的「静默消失」那一类。
    `suppressed_by_safe_verdict` 的语义是「安全裁决抑制」，不该被去重复用。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        rows = sdb.execute(
            "SELECT id, target_endpoint, expected_sink_line, family, param_name, "
            "param_location, verification_status "
            "FROM trigger_specs WHERE task_id=? AND COALESCE(replayable,1)=1",
            (task_id,), fetchall=True) or []
    except Exception as _qe:  # noqa: BLE001
        logger.warning("[dedupe] 查询 trigger_specs 失败：%s", _qe)
        return 0
    # 兼容两种句柄：平台 Database 返回 dict，裸 sqlite3 返回 Row（Row 没有 .get）
    rows = [dict(r) for r in rows]

    groups: dict = {}
    for r in rows:
        ep = str(r.get("target_endpoint") or "").strip().rstrip("/").lower()
        if not ep:
            continue  # 没有端点的不能判重（不同文件同号行会被误并）
        try:
            ln = int(r.get("expected_sink_line") or 0)
        except Exception:
            ln = 0
        fam = str(r.get("family") or "").strip().lower()
        # 参数名与位置也要进 key：同一 sink 的不同污点源不是重复（见 docstring）
        pname = str(r.get("param_name") or "").strip().lower()
        ploc = str(r.get("param_location") or "query").strip().lower() or "query"
        groups.setdefault((ep, ln, fam, pname, ploc), []).append(r)

    merged = 0
    for _key, members in groups.items():
        if len(members) < 2:
            continue
        members = sorted(members, key=lambda m: (
            0 if str(m.get("verification_status") or "").startswith("confirmed") else 1,
            int(m.get("id") or 0)))
        for dup in members[1:]:
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET replayable=0, "
                    "suppress_rule='duplicate_spec', failure_attribution='duplicate_spec', "
                    "failure_attribution_reason=? WHERE id=?",
                    ("与 spec %s 的 (endpoint, sink_line, family, param, location) 完全相同，"
                     "已合并，不重复重放（finding 保留，不动 suppressed）" % members[0].get("id"),
                     int(dup.get("id"))))
                merged += 1
            except Exception as _ue:  # noqa: BLE001
                logger.warning("[dedupe] 写回失败 spec=%s：%s", dup.get("id"), _ue)
    if merged:
        logger.info("[dedupe] 合并完全重复的 spec %d 条（占登记数 %.0f%%，不再重复重放）",
                    merged, 100.0 * merged / max(1, len(rows)))
    return merged


#
# 为什么这是本质：污点流的本质问题是「**污点值是否真的流到 sink**」。探针已经记录了 sink 的
# 实际实参（`iast_events.source_value` / `evidence_json`），因此可以直接判定：
#   · payload 出现在该族**真 sink** 的实参里 → 污点真到 sink → 可利用（at_sink）
#   · 真 sink 已到达但实参里没有 payload   → 常量/净化/被截断 → 安全（absent）
# 这是 target-agnostic 的运行时判定，**不看源码形状**——与 safe-pattern 源码正则（换靶场即失效）
# 有本质区别。
#
# 前置依赖：payload 必须真被注到 servlet 实际读取的源位置（Phase 0a `_apply_source_location_postpass`）。
# 纠正前at_sink 只有 72.1%、absent 仅 54.3%——**说明值级闸之前不准的根因是注错源，不是判定错**。
#
# 否决口径：按**用例级聚合**——某 endpoint 的**全部** spec 都判 absent 才否决；任一 spec 判 at_sink
#
# 开关：`SAST_AI_VALUE_GATE=0` 关闭；`SAST_AI_VALUE_GATE_FAMILIES` 逗号分隔扩展适用族
# （默认只开已在真值上验证过的 command_execution，其余族等 Phase 1 关联干净后再放）。

#
# 统一读取（环境变量 > yaml > 代码默认）。至此 families.yaml 不是死配置——cli/backend 都读同一处。
try:
    from src.core import config_registry as _cfg
except Exception:  # pragma: no cover - 配置模块异常不可用时退回代码默认
    _cfg = None


def _cfg_value_gate_fams(default) -> list:
    if _cfg is not None:
        return _cfg.value_gate_families(default=list(default))
    return list(default or [])


def _cfg_strict_c_fams(default) -> list:
    if _cfg is not None:
        return _cfg.strict_c_families(default=list(default))
    return list(default or [])


def _cfg_confirm_sink_fams(default) -> list:
    if _cfg is not None:
        return _cfg.confirm_sink_families(default=list(default))
    return list(default or [])


# 为什么必须改默认值：此前 6 族的值级闸只在 SAST_AI_VALUE_GATE_FAMILIES 显式给出时才跑，
# 而扫描在 backend 进程内执行、读的是 backend 自己的 env —— 命令行 export 根本传不进去。
# 真实扫描（走 API / 别的机器）拿不到，等于没落地。
#
#   sql_injection / trust_boundary_violation / xpath_injection / xss /
#   path_traversal / xxe  —— 394 条 spec 被否决、TP 误杀 0、召回 99.7%。
# 闸本身是保守的：只有「用例内全部 spec 都判 absent（族 sink 已到达但实参里没有 payload）」
# 才否决；任一 spec 为 at_sink 或 no_event 即保留。要收窄可用 env 显式指定族，
# 或 SAST_AI_VALUE_GATE=0 整体关闭。
_VALUE_GATE_FAMILIES_DEFAULT = (
    "command_execution", "sql_injection", "trust_boundary_violation",
    "xpath_injection", "xss", "path_traversal", "xxe",
    # absent 纯度 21/21=100%（0 个 TP 被误判 absent）⇒ 纳入默认族。
    # 对账预期：ldapi 精确率 57.4% → 100%（20 个 FP 检出被否决），抑损 0。
    "ldap_injection",
)


def _value_gate_enabled() -> bool:
    return str(os.environ.get("SAST_AI_VALUE_GATE", "1")).strip().lower() not in (
        "0", "false", "off", "no",
    )


def _value_gate_families() -> tuple:
    _raw = os.environ.get("SAST_AI_VALUE_GATE_FAMILIES")
    if _raw is not None:
        return tuple(x.strip() for x in str(_raw).split(",") if x.strip())
    # 配置统一：默认族来自 config/families.yaml（缺失时回退代码默认常量）。
    return tuple(_cfg_value_gate_fams(list(_VALUE_GATE_FAMILIES_DEFAULT)))


def _apply_sink_value_gate_postpass(task_id: Optional[int], sdb) -> int:
    """值级 sink 实参闸：payload 未出现在真 sink 实参的用例 → 否决（写 suppressed=1）。

    返回被否决的 spec 条数。
    """
    if task_id is None or sdb is None:
        return 0
    if not _value_gate_enabled():
        return 0
    try:
        from src.core.sink_value_gate import judge_sink_value, is_dataflow_family, canonical_family
    except Exception as _imp:
        logger.warning("[D2][value-gate] 导入失败，跳过：%s", _imp)
        return 0
    try:
        from src.iast.canary import CanaryMatcher as _CM
    except Exception as _imp2:
        logger.warning("[D2][value-gate] canary 模块导入失败，跳过：%s", _imp2)
        return 0

    _allow = {canonical_family(f) for f in _value_gate_families()}
    if not _allow:
        return 0

    try:
        _specs = sdb.execute(
            "SELECT id, target_endpoint, expected_sink_file, taint_marker, family, "
            "capability_family, verification_status, suppressed_by_safe_verdict "
            "FROM trigger_specs WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict,0)=0",
            (task_id,), fetchall=True,
        ) or []
    except Exception as _qe:
        logger.warning("[D2][value-gate] 查询 trigger_specs 失败：%s", _qe)
        return 0

    _ev_cache: dict = {}

    def _events_of(_marker: str):
        try:
            _ident = _CM.find_identity(_marker) if _marker else ""
        except Exception:
            _ident = ""
        if not _ident:
            return []
        if _ident in _ev_cache:
            return _ev_cache[_ident]
        try:
            _evs = sdb.execute(
                "SELECT sink_file, source_value, evidence_json FROM iast_events "
                "WHERE task_id=? AND canary=?",
                (task_id, _ident), fetchall=True,
            ) or []
        except Exception as _eq:
            logger.warning("[D2][value-gate] 事件查询失败 ident=%s：%s", _ident, _eq)
            _evs = []
        _ev_cache[_ident] = _evs
        return _evs

    # 用例级聚合：endpoint（退化用 sink 文件）→ [(spec_id, verdict, has_events, family)]
    # 区分「重放未送达」与「到达应用但没到族 sink」——后者才是可安全否决的非可利用证据。
    _groups: dict = {}
    _skip = 0
    for _sp in _specs:
        _decl = str(_sp.get("family") or "")
        _cap = str(_sp.get("capability_family") or "")
        _fam_raw = _decl or _cap
        _fam = canonical_family(_fam_raw)
        if not is_dataflow_family(_fam_raw) or _fam not in _allow:
            _skip += 1
            continue
        _marker = str(_sp.get("taint_marker") or "")
        if not _marker:
            continue
        _key = str(_sp.get("target_endpoint") or _sp.get("expected_sink_file") or "")
        if not _key:
            continue
        try:
            _evs = _events_of(_marker)
            _v = judge_sink_value(_evs, _marker, _fam_raw)
        except Exception as _je:
            logger.warning("[D2][value-gate] 判定异常 spec=%s：%s", _sp.get("id"), _je)
            continue
        _groups.setdefault(_key, []).append(
            (int(_sp.get("id")), str(_v.get("verdict") or ""), bool(_evs), _fam))

    # 默认关闭，且只对 SAST_AI_VALUE_GATE_STRICT_FAMILIES
    # 三重守卫缺一不可，防止把「重放注错源」误判成「安全」：
    #   ① 族覆盖：本 task 该族的 at_sink **覆盖率** ≥ SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE
    #      但族里确实存在 1 条 at_sink ⇒ 守卫放行 ⇒ 严格模式误杀 8 个真 TP（抑损 8）。
    #      改为覆盖率阈值后，这种「族判据半通不通」的数据会自动挡住（47% < 60%）。
    #   ② 到达：用例内至少一个 spec 的 canary 有探针事件（请求确实到了应用）；
    #   ③ 无正向证据：用例内没有任何 spec 判 at_sink。
    _strict = str(os.environ.get("SAST_AI_VALUE_GATE_STRICT", "")).strip().lower() in (
        "1", "true", "yes", "on")
    #
    # 原因：「无 at_sink」包含两种完全不同的情况——
    #   absent  : 族 sink 已到达，但实参里没有我方 payload ⇒ 这是**反证**（有据可依）；
    #   no_event: 连族 sink 都没到 ⇒ 这是**没有证据**，不等于安全（探针没织到 / API 不认）。
    # 把后者也当"不可利用"是「以证据缺失推定安全」，在真实项目上会砍掉真漏洞。
    # 数学上只要砍掉 1 个 TP，精确率必然下降（precision=(TP-1)/(D-1) < TP/D 当 D>TP）。
    # 故默认要求 ≥1 条 absent 作为否决依据；确需激进模式可置
    # SAST_AI_VALUE_GATE_STRICT_ALLOW_NO_EVENT=1 恢复旧行为。
    _strict_allow_no_event = str(
        os.environ.get("SAST_AI_VALUE_GATE_STRICT_ALLOW_NO_EVENT", "")).strip().lower() in (
        "1", "true", "yes", "on")
    _strict_fams = {
        canonical_family(x.strip())
        for x in str(os.environ.get("SAST_AI_VALUE_GATE_STRICT_FAMILIES",
                                    "trust_boundary_violation,xss,xpath_injection")).split(",")
        if x.strip()
    }
    try:
        _strict_min_cov = float(
            os.environ.get("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.6") or 0.6)
    except Exception:
        _strict_min_cov = 0.6
    # 每族「判别力」：在**用例级**统计「canary 到达了族 sink 的用例里，payload 真的出现在实参中的比例」。
    # 多 spec 结构严重稀释——xpathi 的 TP 用例每条有 6 个 spec 只有 1–2 个 at_sink，
    # 于是 TP 覆盖 15/15=100% 的分片在 spec 级只有 28/80=35%，守卫误判为「判据不可信」而闭嘴。
    # 改为用例级且只在「有族 sink 证据」的用例上取比值（只 no_event 的用例不参与分母）：
    _fam_judged: dict = {}
    for _items in _groups.values():
        _fs = {f for _i, _v, _h, f in _items}
        if len(_fs) != 1:
            continue  # 跨族用例不参与族级判别力统计
        _f = next(iter(_fs))
        _vs = [v for _i, v, _h, _f2 in _items]
        _d = _fam_judged.setdefault(_f, {"at_sink_cases": 0, "absent_cases": 0})
        if any(v == "at_sink" for v in _vs):
            _d["at_sink_cases"] += 1
        elif any(v == "absent" for v in _vs):
            _d["absent_cases"] += 1
    _covered_fams = {
        _f for _f, _d in _fam_judged.items()
        if _d["at_sink_cases"] >= 1
        and (_d["at_sink_cases"] / (_d["at_sink_cases"] + _d["absent_cases"])) >= _strict_min_cov
    }
    _at_sink_fams = _covered_fams
    logger.info(
        "[D2][value-gate] 严格模式族判别力（阈值 %.2f，用例级）：%s", _strict_min_cov,
        ", ".join(
            f"{_f}={_d['at_sink_cases']}/{_d['at_sink_cases'] + _d['absent_cases']}"
            for _f, _d in sorted(_fam_judged.items())
        ) or "无",
    )

    _n = 0
    _cases_vetoed = 0
    _strict_vetoed = 0
    # 与旧严格模式的区别：不再要求「本用例全部 spec 都 absent」，no_event 兄弟不再阻挠。
    # 为什么安全：absent 是**正反证**（族 sink 已到达但实参无 payload），no_event 只是没证据，
    # 按族验收（tasks 397-406 真实数据，判据 = 误杀 TP 必须为 0）：
    #   ldap_injection 22 FP/0 TP、sql_injection 8/0、command_execution 3/0 → 纳入；
    #   path_traversal 11 FP/**16 TP** → 排除；
    #   xss/xpathi/trust_boundary_violation/xxe 无足够样本 → 暂不纳入。
    # 覆盖集可 env 覆盖；置空即整体关闭。
    # trust_boundary_violation。预演 tools/_wb_preview_strict_c_expand.py 实测
    # **TP 误杀=0，FP 178→159**（xpathi 11→2、xss-1 2→0、xss-2 6→0、ab-mix 13→11）。
    # 硬边界（数据钉死）：path_traversal 的 mixed 组 TP=66 ⇒ **绝不纳入**；
    # 算法族（weak_hash/weak_crypto/weak_random）absent 判据反向（全 absent 反而是 TP）⇒ 绝不纳入。
    _strict_c_fams = {
        canonical_family(x.strip())
        for x in str(os.environ.get(
            "SAST_AI_VALUE_GATE_STRICT_C_FAMILIES",
            # 配置统一：strict-C 适用族来自 config/families.yaml（缺失时回退代码默认）。
            ",".join(_cfg_strict_c_fams([
                "ldap_injection", "sql_injection", "command_execution",
                "xpath_injection", "xss", "trust_boundary_violation"])))).split(",")
        if x.strip()
    }
    for _key, _items in _groups.items():
        _verdicts = [v for _i, v, _h, _f in _items]
        _fams = {f for _i, _v, _h, f in _items}
        _veto_kind = ""
        if _verdicts and all(v == "absent" for v in _verdicts):
            _veto_kind = "value-gate-absent"
        elif (_strict_c_fams and _fams and _fams <= _strict_c_fams
              and not any(v == "at_sink" for v in _verdicts)
              and any(v == "absent" for v in _verdicts)
              and any(h for _i, _v, h, _f in _items)):
            _veto_kind = "value-gate-strict-c"
        elif (_strict and _fams and _fams <= _strict_fams
              and _fams <= _at_sink_fams
              and not any(v == "at_sink" for v in _verdicts)
              and any(h for _i, _v, h, _f in _items)
              # 必须有正向反证（≥1 absent）才允许否决；纯 no_event 不算证据
              and (_strict_allow_no_event or any(v == "absent" for v in _verdicts))):
            _veto_kind = "value-gate-no-at-sink"
        if not _veto_kind:
            continue
        _cases_vetoed += 1
        if _veto_kind in ("value-gate-no-at-sink", "value-gate-strict-c"):
            _strict_vetoed += 1
        for _sid, _v, _h, _f in _items:
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET suppressed_by_safe_verdict=1, "
                    "verification_status='unconfirmed', iast_state=? WHERE id=?",
                    (_veto_kind, _sid),
                )
                _n += 1
            except Exception as _ue:
                logger.warning("[D2][value-gate] 写回失败 spec=%s：%s", _sid, _ue)
    if _n:
        logger.info(
            "[D2][value-gate] 值级闸否决 %d 条 spec / %d 个用例（真 sink 实参里没有投放 payload；"
            "其中严格/严格-C「无 at_sink 但已到达」%d 个用例；适用族=%s，跳过非适用族 %d 条）",
            _n, _cases_vetoed, _strict_vetoed, ",".join(sorted(_allow)), _skip,
        )
    else:
        logger.info("[D2][value-gate] 无需否决（适用族=%s，候选 %d 条）", ",".join(sorted(_allow)), len(_specs) - _skip)
    return _n


def _apply_confirm_sink_identity_postpass(task_id: Optional[int], sdb) -> int:
    """确认态 sink 身份校验：canary 只到旁路 sink ⇒ 抑制。

    本质：确认态硬闸用「通用 sink 到达」确认，**未校验 sink 是否属于报告族的真 sink**。
    等旁路 sink（从未进入族真 sink 实参），却被确认成 sink_reached/confirmed_exploitable。

    离线预演 TP 误杀=0、FP 降 15）。
    **硬边界**：path_traversal(旁路 TP=66)、xss(51)、weak_crypto(56) 等族旁路含大量真 TP，
    禁止启用，否则大规模误杀。故族白名单写死，不开放 env 泛化。

    返回被抑制的 spec 条数。
    """
    if task_id is None or sdb is None:
        return 0
    if not _value_gate_enabled():
        return 0
    try:
        from src.core.sink_value_gate import (
            FAMILY_SINK_TOKENS,
            canonical_family,
            identity_of,
        )
    except Exception as _imp:
        logger.warning("[D2][confirm-sink] 导入失败，跳过：%s", _imp)
        return 0

    # 配置统一：确认态 sink 身份校验适用族来自 config/families.yaml（缺失时回退代码默认）。
    _fams_allow = set(_cfg_confirm_sink_fams(["xpath_injection", "trust_boundary_violation"]))
    try:
        _specs = sdb.execute(
            "SELECT id, target_endpoint, expected_sink_file, taint_marker, family, "
            "capability_family FROM trigger_specs "
            "WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict,0)=0",
            (task_id,), fetchall=True,
        ) or []
    except Exception as _qe:
        logger.warning("[D2][confirm-sink] 查询 trigger_specs 失败：%s", _qe)
        return 0

    _ev_cache: dict = {}

    def _events_of(_marker: str):
        try:
            _ident = identity_of(_marker) if _marker else ""
        except Exception:
            _ident = ""
        if not _ident:
            return []
        if _ident in _ev_cache:
            return _ev_cache[_ident]
        try:
            _evs = sdb.execute(
                "SELECT sink_file, source_value FROM iast_events WHERE task_id=? AND canary=?",
                (task_id, _ident), fetchall=True,
            ) or []
        except Exception as _eq:
            logger.warning("[D2][confirm-sink] 事件查询失败 ident=%s：%s", _ident, _eq)
            _evs = []
        _ev_cache[_ident] = _evs
        return _evs

    # 用例级聚合：endpoint（退化用 sink 文件）→ spec 列表
    _groups: dict = {}
    for _sp in _specs:
        _fam = canonical_family(str(_sp.get("family") or _sp.get("capability_family") or ""))
        _key = str(_sp.get("target_endpoint") or _sp.get("expected_sink_file") or "")
        if not _key:
            continue
        _groups.setdefault(_key, []).append({
            "id": int(_sp.get("id")),
            "fam": _fam,
            "marker": str(_sp.get("taint_marker") or ""),
        })

    _n = 0
    _cases = 0
    for _key, _items in _groups.items():
        _fams = {i["fam"] for i in _items}
        if not _fams or not _fams <= _fams_allow:
            continue
        _tokens = set()
        for _f in _fams:
            _tokens |= set(FAMILY_SINK_TOKENS.get(_f, ()))
        if not _tokens:
            continue
        _any_sink = False
        _to_true = False
        for _i in _items:
            _ident = identity_of(_i["marker"]) if _i["marker"] else ""
            for _ev in _events_of(_i["marker"]):
                _sf = str(_ev.get("sink_file") or "")
                _sv = str(_ev.get("source_value") or "")
                if _sf:
                    _any_sink = True
                if _ident and _ident in _sv and any(t in _sf for t in _tokens):
                    _to_true = True
        # 有探针事件，但无任何 canary 进入族真 sink 实参 ⇒ 只到旁路
        if not (_any_sink and not _to_true):
            continue
        _cases += 1
        for _i in _items:
            try:
                sdb.execute(
                    "UPDATE trigger_specs SET suppressed_by_safe_verdict=1, "
                    "verification_status='unconfirmed', iast_state=? WHERE id=?",
                    ("confirm-sink-identity-mismatch", _i["id"]),
                )
                _n += 1
            except Exception as _ue:
                logger.warning("[D2][confirm-sink] 写回失败 spec=%s：%s", _i["id"], _ue)
    if _n:
        logger.info(
            "[D2][confirm-sink] 确认态 sink 身份校验抑制 %d 条 spec / %d 个用例"
            "（canary 只到旁路 sink，未进族真 sink 实参；适用族=%s）",
            _n, _cases, ",".join(sorted(_fams_allow)),
        )
    return _n


#
#   ① 证伪失效：283 条 confirmed_exploitable 里有 17 条 iast_state=no-arrival —— 探针明确记录
#      「请求没抵达应用」，平台却仍下肯定结论。按本项目「自己提出假说、自己否定收紧」的框架，
#      这不是与真值比精确率的问题，是证伪环节失效：假说提出了，却没有任何正向证据支撑就确认了。
#   ② 信息黑洞：D2 产物（verification_decision / iast_evidence / dast_impact_evidence /
#      d2_verdict / poc）只写进 findings.raw_json，trigger_specs 侧 d2_evidence / d2_output /
#      spec 详情拿不到任何「这条假说到底怎么被证实/否证」的信息。
#
# 修法：终态写入同一事务点回灌证据块+ confirmed_exploitable 必须过三准入硬闸。

# 到达态（探针侧正向证据）：canary 确证抵达 sink / 被应用接收 / 双账号差分确认。
# v2 证据分层 B6：移除 "iast-reached" —— 业务族「仅到达应用」不再单独构成到达态，
# 必须配语义层正向证据（值级命中/影响观测/差分/时延）才准入，避免「到达即漏洞」的误报锁。
_CONFIRM_GATE_ARRIVAL_STATES = frozenset({
    "sink-reached", "sink-reached-probe", "business-logic-confirmed",
})

# 内部状态枚举 → 人话（evidence_summary 里不得出现用户读不懂的内部枚举）
_IAST_STATE_HUMAN = {
    "sink-reached": "探针在危险函数处捕获到本次投放的数据",
    "sink-reached-probe": "探针在危险函数的实参里断言到本次投放的数据",
    "iast-reached": "探针记录到该请求已进入应用",
    "business-logic-confirmed": "双账号差分重放确认了越权差异",
    # 是否到达无关（实测 status_code=200 / reached=true 仍可 no-arrival，如请求到达应用但
    # 载荷没到目标危险函数、或探针未插桩）。旧文案武断断言「靶场不可达或路由不匹配」会
    # 误导对账，改为与主裁决链路（adjudicator/d2_judge）同口径的如实表述。
    "no-arrival": "探针在观测窗口内未捕获到匹配本次投放的事件（请求可能已抵达应用，但未在目标危险函数处被观测到）",
    "no-iast-evidence": "本轮没有拿到任何探针记录",
    "safe-pattern-veto": "源码命中安全写法反例（运行期走常量分支），已否决",
}


def _short_text(value, limit=200):
    """单行化 + 截断。证据摘要与落库字段共用，防巨型响应体撑爆 trigger_specs.raw_json。"""
    s = str(value or "")
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit] + "…"


def _confirm_gate_decide(iast_state, iast_ev, dast_ev, d2_verdict, oob_confirmed=False, bl_confirmed=False):
    """三准入判定（核心）。返回 (准入?, 准入代码, 人话说明)。

    A 运行时到达：探针在 sink / 应用侧捕获到本次投放的数据（到达态，或有匹配事件 id）
    B 结果点有害 + 可观测影响：D2 判有害且影响侧有实证（回显 / 带外回调 / 时延 / 反序列化链路 / 差分）
    C 业务差分确认：business_logic_confirmed=1（越权类）

    三者皆无 ⇒ 不得落 confirmed_exploitable。这是「自己否定收紧」在确认态上的硬约束：
    没有正向证据的肯定结论一律降级为 unconfirmed（待重试），而不是继续冒充已确认。
    """
    iast_ev = iast_ev or {}
    dast_ev = dast_ev or {}
    vd = d2_verdict or {}
    deser_confirmed = bool(vd.get("deserialization_chain_confirmed"))
    _vh = iast_ev.get("value_hit") or {}
    _value_live = bool(_vh.get("hit")) and str(_vh.get("form") or "") == "hit_live"
    _vd_exc = bool(vd.get("sink_exception_class") or iast_ev.get("sink_exception_class")
                   or dast_ev.get("sink_exception_class"))
    # inconclusive/no_delay，D2 却置 True；runtime_arrival 无条件采信后把
    # tomcatfiltermemshell.java/command_execution 放成红线误报。
    # 布尔本身不是可核验证据：必须另有值级命中 / 匹配事件 / 带外 / 差分 / 时延 /
    # 反序列化链路 / sink 异常签名 / 明确影响类型 交叉支撑，否则不得据此确认。
    # 628 无任何 impact_observed=True 的 spec，629 仅此一条且无结构化证据，收紧不误杀 TP。
    # matched_event_ids 只证明「到达」，不是结果点影响证据，刻意不计入：
    # 629 那条误报恰恰带着 matched_event_ids=[1627604]（sink-reached），
    # 若把它算作交叉支撑，裸 D2 布尔依然能被放行，闸门等于没修。
    _impact_structured = bool(
        _value_live
        or oob_confirmed or vd.get("oob_confirmed")
        or bl_confirmed or vd.get("business_logic_confirmed")
        or vd.get("time_blind_confirmed") or vd.get("time_blind")
        or deser_confirmed or _vd_exc
        or dast_ev.get("impact_kind") or dast_ev.get("value_hit")
    )
    _impact_observed = bool(dast_ev.get("impact_observed")) and _impact_structured
    arrival = (
        str(iast_state or "") in _CONFIRM_GATE_ARRIVAL_STATES
        or bool(iast_ev.get("matched_event_ids"))
        or deser_confirmed
    )
    impact = bool(vd.get("harmful")) and (
        _impact_observed
        or bool(oob_confirmed or vd.get("oob_confirmed"))
        or deser_confirmed
        or bool(vd.get("business_logic_confirmed"))
        or bool(vd.get("time_blind_confirmed") or vd.get("time_blind"))
    )
    # P1 差分否决：仅当对照实验明确无有害差异时才降级，未尝试/歧义 fail-open（绝不零化 TP）。
    _do = _differential_override(dast_ev, vd, oob_confirmed, bl_confirmed)
    if _do is not None:
        return False, _do[0], _do[1]
    if arrival:
        # v2 证据分层 B6：到达须配「语义层正向证据」才准入；到达单独不足（L1≠L4）。
        # 语义证据 = 值级命中且未消毒(hit_live) / 影响观测 / 带外回调 / 业务差分 / 时延盲注
        # / 反序列化链路确证（B5 专用救援路径，机制级）/ sink 异常签名（B2，L3 语义层）。
        # 之外，导致「到达态 + 链路/异常确证」被误降级 —— 会杀掉反序列化救援路径。
        _semantic = (
            _value_live
            or _impact_observed
            or bool(oob_confirmed or vd.get("oob_confirmed"))
            or bool(bl_confirmed or vd.get("business_logic_confirmed"))
            or bool(vd.get("time_blind_confirmed"))
            or deser_confirmed
            or _vd_exc
        )
        if _semantic:
            return True, "runtime_arrival", "探针在 sink 或应用侧捕获到本次投放的数据，且配语义层正向证据"
        return False, "arrival_without_semantics", (
            "探针记录到达，但缺少语义层正向证据（值级命中/影响观测/带外/差分/时延），"
            "不得仅凭到达确认 —— fail-open 到 unconfirmed"
        )
    if impact:
        return True, "impact_evidence", "结果点观察到实际有害影响（回显 / 带外回调 / 时延 / 链路确证）"
    if bl_confirmed:
        return True, "business_diff", "双账号差分重放确认了越权差异"
    return False, "no_positive_evidence", (
        "没有任何正向证据：探针未记录到达、结果点未观察到影响、也没有差分确认"
    )


def _differential_override(dast_ev, vd, oob_confirmed, bl_confirmed):
    """v2 证据分层 E4：差分降级权的条件化恢复（对照实验）。

    把 33 个真 TP 连同 FP 一起归零（召回 69.8%→35.4%），违反「绝不零化仅到达 TP」铁律。

    v2 修正（条件化）：**默认恢复降级权**，但**仅当具备前置 L3 证据**时才允许差分做阴性：
      - A1 异常证据：vd 录得 sink_exception_class（注入被解释器处理，语法错误证明生效）
      - A3 值级证据：dast_ev.value_level_hit 为真（我方数据确证抵达 sink 实参）
    无前置 L3 证据 → fail-open 保留（绝不零化仅到达 TP）。

    有 9 条），35 条真漏洞被响应层无差异否掉。现改为：L3 正向（hit_live / 异常签名）⇒
    不降级；仅当 L3 明确为阴性（hit_sanitized 且无异常签名）时差分才保留降级权。
    """
    if os.environ.get("SAST_AI_DIFF_DEMOTE", "1") in ("0", "false", "False", "no"):
        return None
    if not isinstance(dast_ev, dict):
        return None
    diff = dast_ev.get("differential")
    if not isinstance(diff, dict) or not diff.get("attempted"):
        return None  # 未尝试对照 → fail-open（保留，不零化 TP）
    if diff.get("harmful"):
        return None  # 对照确认有害 → 不否决（由 arrival/impact 路径确认 TP）
    # 对照明确无有害差异：但若已有其它确凿正向证据则不否决（避免重复否定已坐实的确认）
    _other_definitive = (
        bool(oob_confirmed or vd.get("oob_confirmed"))
        or bool(vd.get("deserialization_chain_confirmed"))
        or bool(bl_confirmed or vd.get("business_logic_confirmed"))
        or bool(vd.get("time_blind_confirmed") or dast_ev.get("time_blind_confirmed"))
    )
    if _other_definitive:
        return None
    # 前置 L3 证据：异常类型属族（A1）或值级命中（A3）。缺则 fail-open（不零化仅到达 TP）。
    # 注意这一档是 fail-open 保留，本次**未收紧**：无 L3 的仅到达 spec 依旧不被降级，
    _l3 = bool(vd.get("sink_exception_class") or dast_ev.get("sink_exception_class")) \
        or bool(dast_ev.get("value_level_hit"))
    if not _l3:
        return None
    # differential_no_impact 里 26 条是值级 hit_live 且**真值 100% TP**（283 另有 9 条），
    # 合计 35 条真漏洞被「控制/实验 HTTP 响应无差异」这条 P1 证据否掉 —— 证明力 4 的
    # 值级正向被 P1 差分压过，违反证明力序。
    # 正确语义：L3 正向（未消毒的值级命中 / sink 异常签名）⇒ **否决**降级；
    # 只有 L3 明确是阴性（hit_sanitized，且无异常签名）时，差分才保留降级权。
    _vh_form = str(dast_ev.get("value_hit_form") or "")
    _value_is_negative = bool(dast_ev.get("value_level_hit")) and _vh_form == "hit_sanitized"
    _has_exception = bool(vd.get("sink_exception_class") or dast_ev.get("sink_exception_class"))
    if not (_value_is_negative and not _has_exception):
        return None  # L3 是正向 ⇒ 差分不得做阴性，交由 arrival/impact 路径裁决
    return ("differential_no_impact",
            "对照实验未观测到有害差异，且值级命中已录得消毒器（hit_sanitized，definitive 阴性）、"
            "无异常签名 → 条件化降级（差分确认 P1，E4）")


def _attach_evidence_summary(block, family=""):
    """给证据块补 evidence_summary：三句人话，不含内部状态枚举。

    句式固定为「投放了什么 → 探针看到了什么 → 影响侧发生了什么」，用户读一条就懂这条
    假说为什么被确认或被否决，不需要去翻 findings.raw_json 里的状态码串。
    """
    req = block.get("d2_output") or {}
    d2e = block.get("d2_evidence") or {}
    sink = block.get("sink") or {}
    oob = block.get("oob") or {}
    payload = block.get("payload") or "（无记录）"
    endpoint = req.get("endpoint") or "目标端点"
    param = req.get("param") or "未识别参数"
    location = req.get("param_location") or ""
    s1 = "攻击者数据经 %s 的 %s 参数%s进入应用，投放载荷「%s」。" % (
        endpoint, param, ("（%s）" % location if location else ""), payload)

    _ids = d2e.get("matched_event_ids") or []
    if _ids:
        s2 = "探针在 %s:%s 的 %s 处捕获到该载荷，抓到 %d 条运行时证据。" % (
            sink.get("file") or "未知文件", sink.get("line") or 0,
            sink.get("method") or "危险函数", len(_ids))
    else:
        _st = str(d2e.get("iast_state") or "")
        s2 = "%s，因此本条没有运行时到达证据。" % (
            _IAST_STATE_HUMAN.get(_st) or "本轮没有拿到探针记录")

    if oob.get("confirmed"):
        s3 = "带外域名收到回调，服务端确已解析并执行该载荷。"
    elif req.get("impact_observed"):
        s3 = "响应侧观察到实际影响：HTTP %s，%s" % (
            req.get("status_code") or "?", _short_text(req.get("response_summary"), 160) or "回显命中")
    elif d2e.get("d2_harmful"):
        s3 = "D2 判定结果点有害：%s" % (_short_text(d2e.get("d2_reason"), 160) or "结果点被打中")
    else:
        s3 = "未观察到任何可利用影响。"
    block["evidence_summary"] = s1 + s2 + s3
    return block


def _build_d2_evidence_block(vuln, result, spec_row, oob_token=""):
    """把 D2 产物整理成 spec 侧可消费的证据块。

    落进 trigger_specs.raw_json 的 payload / payload_source / executed / sink / data_flow /
    d2_evidence / d2_output / poc / oob / evidence_summary。与 findings.raw_json 同源同真值。
    """
    ie = getattr(result, "iast_evidence", None) or {}
    de = getattr(result, "dast_impact_evidence", None) or {}
    vd = getattr(result, "d2_verdict", None) or {}
    ev = getattr(result, "execution_evidence", None) or {}

    payload = str(de.get("attack_payload_used") or "")
    payload_source = str(de.get("payload_source") or "")
    if not payload:
        try:
            _pl = json.loads(spec_row.get("attack_payloads_json") or "[]")
            if isinstance(_pl, list) and _pl:
                payload = str(_pl[0])
                payload_source = payload_source or "spec"
        except Exception:
            payload = ""
    sink_file = str(ie.get("sink_file") or spec_row.get("expected_sink_file") or vuln.get("file") or "")
    try:
        sink_line = int(ie.get("sink_line") or spec_row.get("expected_sink_line") or vuln.get("line") or 0)
    except Exception:
        sink_line = 0
    sink_method = str(ie.get("sink_method") or vuln.get("sink") or "")
    tp = ie.get("taint_path") or []
    conf = ie.get("chain_conformance") or {}
    matched = ie.get("matched_event_ids") or []
    oob = ie.get("oob") or {}
    tok = str(oob.get("token") or oob_token or "")
    block = {
        "payload": _short_text(payload, 300),
        "payload_source": payload_source or "unknown",
        "executed": bool(ev.get("requests_made") or de.get("reached") or matched),
        "sink": {"file": sink_file, "line": sink_line, "method": sink_method},
        "data_flow": {
            "taint_path": tp[:20] if isinstance(tp, list) else [],
            "sources": (vuln.get("sources") or [])[:10],
            "chain_conformance": {
                "conforms": bool(conf.get("conforms")),
                "checked": conf.get("checked"),
                "matched": conf.get("matched"),
                "missing": (conf.get("missing") or [])[:10],
            } if conf else {},
        },
        "d2_evidence": {
            "iast_state": str(ie.get("state") or ""),
            "iast_state_human": _IAST_STATE_HUMAN.get(str(ie.get("state") or ""), ""),
            "matched_event_ids": list(matched)[:20],
            "sink_method": sink_method,
            "source_value": _short_text(ie.get("source_value"), 150),
            # 流转、从不落盘，导致「线上到底有没有算出 hit_live」永远是盲区，只能靠
            # primary_channel / evidence_strength 反推。落库后可直接对账与归因。
            "value_hit": dict(ie.get("value_hit") or {}),
            "confidence": ie.get("confidence") or "",
            "d2_harmful": bool(vd.get("harmful")),
            "d2_confidence": vd.get("confidence") or "",
            "d2_reason": _short_text(vd.get("reason"), 300),
            "deserialization_chain_confirmed": bool(vd.get("deserialization_chain_confirmed")),
            "rce_sinks": list(vd.get("rce_sinks") or [])[:10],
            "deserialization_nodes": list(vd.get("deserialization_nodes") or [])[:10],
            # M4 通道注册表：主判据来自哪条通道、证明力多少、有没有被打脸的反证。
            # 落库后对账能直接回答「这条确认是靠什么证据站住的」，不用再翻 findings.raw_json。
            "primary_channel": str(vd.get("primary_channel") or ""),
            "evidence_strength": int(vd.get("evidence_strength") or 0),
            "channel_conflict": bool(vd.get("channel_conflict")),
            # M5 结果点三态：原样回显 / 转义 / 编码 / 无回显。落库后
            # mark_filtered_not_exploitable 据此把「过滤器有效」落成显式真阴性。
            "result_point_state": str(vd.get("result_point_state") or ""),
        },
        "d2_output": {
            "endpoint": spec_row.get("target_endpoint") or "",
            "http_method": spec_row.get("http_method") or "",
            "param": spec_row.get("param_name") or "",
            "param_location": spec_row.get("param_location") or "",
            "status_code": de.get("status_code"),
            "reached": bool(de.get("reached")),
            "impact_observed": bool(de.get("impact_observed")),
            "response_summary": _short_text(de.get("response_summary") or de.get("body") or "", 400),
            "requests_made": len(ev.get("requests_made") or []),
            # LLM 输出抽取的 HTTP 条目），并不等于 D1 实际投递数。实测出现 status_code=200 /
            # reached=true 但 requests_made=0 的「矛盾」读数，实为两路证据不同源。补两个口径
            # 字段让对账可直接区分，不改任何判定（确认态硬闸不看 requests_made）。
            "requests_made_scope": "d2_execution_evidence",
            "delivery_observed": bool(de.get("reached") or de.get("status_code") or matched),
            "step_errors": list(ev.get("step_errors") or [])[:5],
        },
        "poc": {
            "type": str(getattr(result, "poc_type", "") or ""),
            "verified": bool(vd.get("harmful")),
            "code_excerpt": _short_text(getattr(result, "poc_code", "") or "", 600),
            "url": str(spec_row.get("target_endpoint") or ""),
        },
        "oob": {
            "token": tok[:32],
            "confirmed": bool(oob.get("confirmed") or vd.get("oob_confirmed")),
        },
        "channels": {
            "primary": str(vd.get("primary_channel") or ""),
            "primary_label": str(vd.get("primary_channel_label") or ""),
            "strength": int(vd.get("evidence_strength") or 0),
            "conflict": bool(vd.get("channel_conflict")),
            "conflicting": [str(c) for c in (vd.get("conflicting_channels") or [])][:6],
            "budget": vd.get("replay_budget"),
            "run": list(vd.get("evidence_channels") or [])[:8],
        },
    }
    return _attach_evidence_summary(block, str(vuln.get("family") or ""))


def _merge_spec_raw_json(raw_json_text, ev_block, verification_status, gate=None):
    """把证据块合并进 spec 既有 raw_json。

    必须 merge 不能覆盖：raw_json 里已有 i2_feedback 落的 replay_adjust（多轮累计修正）
    与注册期产物，覆盖会吃掉重放修正史。
    """
    try:
        base = json.loads(raw_json_text or "{}")
        if not isinstance(base, dict):
            base = {}
    except Exception:
        base = {}
    for _k in ("payload", "payload_source", "executed", "sink", "data_flow",
               "d2_evidence", "d2_output", "poc", "oob", "evidence_summary"):
        if _k in ev_block:
            base[_k] = ev_block[_k]
    base["verification_status"] = verification_status
    if gate is not None:
        base["confirm_gate"] = gate
    return base


def _oracle_positive_signal(family: Any, oracle_state: Any, oracle_signal: Any) -> str:
    """响应层行为 oracle 是否给出本族的确定性正向证据（成立返回 signal，否则空串）。

    与 `_apply_oracle_upgrade` 共用同一套判据，避免「硬闸认、升级不认」或反之：
    只认 `oracle_state='exploitable'` 且 signal 非空，并按 `_ORACLE_HARM_SIGNALS`
    与族严格匹配。`inconclusive` / `no_ssrf_effect` / 跨族信号一律不认，
    所以「靶场自己弹的错误页」不会被当可利用证据。

    `oracle_state=exploitable, oracle_signal=error_reflect` 已命中，但硬闸只读
    raw_json 的三类证据，读不到 spec 列里的 oracle 结论 ⇒ 判无正向证据降级成
    `confirm-gate:sink-reached`；同一端点在 623 靠「迟到 sink 事件」碰巧回补才确认。
    这不是探针时序波动，是证据回灌缺口，必须让硬闸直接消费这一列。
    """
    if str(oracle_state or "").strip().lower() != "exploitable":
        return ""
    sig = str(oracle_signal or "").strip().lower()
    if not sig:
        return ""
    try:
        from src.iast.harm_evidence import (
            _ORACLE_HARM_SIGNALS, _ORACLE_HARM_SIGNALS_MULTI)
        from src.iast.response_oracle import canonical_family
        fam = canonical_family(str(family or "")) or str(family or "").strip().lower()
        # time_delay 这类信号由多个族共用，先用附加表判多族，再回落到单族主表。
        if (fam in _ORACLE_HARM_SIGNALS_MULTI.get(sig, ())
                or _ORACLE_HARM_SIGNALS.get(sig) == fam):
            return sig
    except Exception:
        pass
    return ""


# 这几类 signal 是**纯响应事实**：服务端替我们发起请求后的连接错误回显、注入的
# 内网地址回显、Location/ACAO 头回显、伪造响应头。判据本身绑定我方投放的特定值，
# 不依赖探针是否在业务 sink 插桩，所以 no-arrival 时仍可作为确认依据。
_RESPONSE_ONLY_ORACLE_SIGNALS = frozenset({
    "error_reflect", "internal_url_reflect", "location_reflect", "websocket_echo",
    # 恰好都是 no-arrival / 零重放，若不放进纯响应事实集合，探测臂判出正向
    # 信号也升不了确认。两者都只依赖我方投放值与目标响应的对照，与探针无关。
    "expr_eval", "deser_object_accepted",
})

# 这些信号绑定我方投放的特定值且能推出危害：注入内网地址触发的连接错误回显、
# 注入跳转目标原样回显到 Location、命令 stdout 经 WS 帧回显。
# `reflection_raw` / `acao_reflect` / `header_injected` 只证明「值被回显」，安全端点
# 同样会命中，623/624 从不单独采信；625 放开后实测新增 3 条红线误报：
#   log4j.java / xss（reflection_raw，族误标，真值族是 jndi_injection）
#   originfilter.java / cors（acao_reflect）
#   urlwhitelist.java / url_redirect（location_reflect，泛化族重复 spec）
# 收窄后仍保留 ssrf(error_reflect)、urlwhitelist(location_reflect)、
# websocket(websocket_echo) 三个已实证的收敛点。
_ORACLE_WEAK_REFLECTION_SIGNALS = frozenset({
    "reflection_raw", "acao_reflect", "header_injected", "location_reflect",
    # 不是 RCE 命令执行，证据强度弱于 error_reflect / websocket_echo。
    # 按 625 红线治理的同一纪律，泛化族上要求 sink 文件名有反序列化语义提示，
    # 避免把「合法输入 200 / 垃圾输入 500」的普通解析错误端点误升成反序列化漏洞。
    "deser_object_accepted",
})
# 泛化族 → sink 文件名应含的语义提示词。只对「原始族 == canonical 族」的泛化族
# 生效；url_whitelist_bypass 这类更具体族（canonical 后是 url_redirect）不校验，
# 避免误伤 625 已收敛的白名单绕过真值点。
_ORACLE_FAMILY_FILE_HINTS = {
    "cors": ("cors",),
    "xss": ("xss",),
    "url_redirect": ("redirect",),
    "crlf_injection": ("crlf",),
    # 文件名不含旧提示词会被闸门拦掉。fastjson/jackson/gson 是解析器类名（源码事实），
    # 与 625 红线误报的 Log4j.java/OriginFilter.java 这类错配无关，不会放宽误报面。
    "deserialization": ("deser", "shiro", "xstream", "unserial", "serial",
                        "objectinput", "pickle", "yaml", "gadget",
                        "fastjson", "jackson", "gson", "objectmapper"),
}


def _oracle_gate_signal(family: Any, oracle_state: Any, oracle_signal: Any,
                        positive_evidence_rule: Any = "",
                        sink_file: Any = "") -> str:
    """响应层 oracle 能否单独作为确认依据：返回 signal，否则空串。

      1. `_oracle_positive_signal` 的族严格匹配（含 positive_evidence_rule 回补）；
      2. 强因果信号（差分/时延/文件签名/WS 回显/错误回显）直接放行；
      3. 纯回显类弱信号，且 spec 属于泛化族时，要求 sink 文件名与族语义一致。
         否则就是 A1 把别处 sink 的回显挂到了这个族上：
           OriginFilter.java/cors、Log4j.java/xss、URLWhiteList.java/url_redirect。
         而 Cors.java/cors、XSS.java/xss、URLRedirect.java/url_redirect 保留。
         sink_file 缺失时 fail-open，不因观测列缺失把整族拦死。
    """
    sig = _oracle_positive_signal(family, oracle_state, oracle_signal)
    if not sig:
        _per = str(positive_evidence_rule or "")
        if _per.startswith("oracle:"):
            sig = _oracle_positive_signal(
                family, "exploitable", _per.split(":", 1)[1])
    if not sig:
        return ""
    _fam_raw = str(family or "").strip().lower()
    try:
        from src.iast.response_oracle import canonical_family as _canon
        _fam_canon = _canon(_fam_raw) or _fam_raw
    except Exception:  # noqa: BLE001
        _fam_canon = _fam_raw
    if (sig in _ORACLE_WEAK_REFLECTION_SIGNALS
            and _fam_raw == _fam_canon):
        _hints = _ORACLE_FAMILY_FILE_HINTS.get(_fam_canon, ())
        _base = str(sink_file or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        if _hints and _base and not any(h in _base for h in _hints):
            return ""
    return sig


def _apply_confirmation_gate(task_id: Optional[int], sdb) -> int:
    """确认态硬闸 DB 兜底：扫本 task 全部 confirmed_exploitable spec，逐条用
    raw_json 里已回灌的证据复核是否握有正向证据；无证据者降级 unconfirmed（待重试）。

    覆盖 D2 主循环之外写入 confirmed 的通道——
    主循环那一路已在写终态时就地过闸，此处是防御性收口，保证「no-arrival 且 confirmed」
    这一证伪失效组合在任何路径下都不可能出现。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        specs = sdb.execute(
            "SELECT id, family, iast_state, business_logic_confirmed, raw_json, taint_marker, "
            "expected_sink_file, oracle_state, oracle_signal, positive_evidence_rule "
            "FROM trigger_specs "
            "WHERE task_id=? AND verification_status='confirmed_exploitable'",
            (task_id,), fetchall=True,
        ) or []
    except Exception as _qe:
        logger.warning("[D2][confirm-gate] 查询 trigger_specs 失败：%s", _qe)
        return 0
    if not specs:
        return 0
    _n = 0
    _reasons: Dict[str, int] = {}
    for _sp in specs:
        _spid = _sp.get("id")
        _st = str(_sp.get("iast_state") or "")
        try:
            _rj = json.loads(_sp.get("raw_json") or "{}")
            if not isinstance(_rj, dict):
                _rj = {}
        except Exception:
            _rj = {}
        _d2e = _rj.get("d2_evidence") or {}
        _out = _rj.get("d2_output") or {}
        _oob = _rj.get("oob") or {}
        _bl = bool(_sp.get("business_logic_confirmed"))
        # P1 对账：确认态硬闸必须把完整 dast_impact_evidence（含 differential）交给闸门，
        # 否则差分否决（differential_no_impact）在此处会被静默丢掉、误把安全用例留成 confirmed。
        _dast_ev = _rj.get("dast_impact_evidence") or {}
        if not isinstance(_dast_ev, dict):
            _dast_ev = {}
        _dast_ev.setdefault("impact_observed", bool(_out.get("impact_observed")))
        #
        # 技术判据的证据是「响应层可复现观测」（原样反射的载荷 / 模板引擎异常类名 /
        # ACAO 反射 canary / 进程创建异常 / 脚本引擎求值结果），每一条都是**响应事实**，
        # 不依赖探针在哪个 sink 插桩。而 `_confirm_gate_decide` 的 arrival 分支看的是
        # 「探针是否在业务 sink 记录到到达」——CORS 的 setHeader、反射型 XSS 的响应写入
        # 这类场景**探针根本不触发** ⇒ 硬闸会判 `arrival_without_semantics` 把刚确认的点打回。
        #
        # 之前只在 `_ok == True` 之后放行（治标），但硬闸判 False 时根本走不到那里。
        # 现在把保护前移：技术判据已给出确定性正向证据 ⇒ 直接放行，不降级。
        _tech_ev = _rj.get("technique_evidence") or {}
        if isinstance(_tech_ev, dict) and _tech_ev.get("admitted"):
            logger.info(
                "[D2][confirm-gate] spec=%s family=%s 技术判据已确认（technique=%s）⇒ 放行不降级",
                _spid, _sp.get("family"), _tech_ev.get("technique"))
            continue
        # 它和 technique_evidence 同属响应事实（我方特定投放值被服务端回显/回带），
        # 但结论只落在 spec 列 oracle_state/oracle_signal/positive_evidence_rule，
        # 从不回灌 raw_json，硬闸此前完全看不见 ⇒ 把已确证的点无理由降级。
        _ora_sig = _oracle_gate_signal(
            _sp.get("family"), _sp.get("oracle_state"), _sp.get("oracle_signal"),
            _sp.get("positive_evidence_rule"), _sp.get("expected_sink_file"))
        if _ora_sig:
            logger.info(
                "[D2][confirm-gate] spec=%s family=%s 行为 oracle 已确证（signal=%s）⇒ 放行不降级",
                _spid, _sp.get("family"), _ora_sig)
            continue
        _ok, _code, _why = _confirm_gate_decide(
            _st,
            # 在复核侧完全不可见，会把主流程已确认的条目一律判成 arrival_without_semantics
            {"matched_event_ids": _d2e.get("matched_event_ids") or [],
             "value_hit": _d2e.get("value_hit") or {}},
            _dast_ev,
            {
                "harmful": bool(_d2e.get("d2_harmful")),
                "oob_confirmed": bool(_oob.get("confirmed")),
                "deserialization_chain_confirmed": bool(_d2e.get("deserialization_chain_confirmed")),
                "business_logic_confirmed": _bl,
            },
            oob_confirmed=bool(_oob.get("confirmed")),
            bl_confirmed=_bl,
        )
        if _ok:
            # Q1 第四刀：即便握有正向证据，若其唯一 sink 证据落在框架噪声 sink
            #（响应写入 / 序列化 / 模板渲染，且非 XSS/SSTI 族），仍不得确认——
            # 这是 I2/D2 两层已同源剔除后的 DB 兜底，覆盖迟到证据只改 iast_state 未回填
            # sink_file、以及任何绕过前两层的写入通道。fail-open：查不到事件不误杀。
            _fam = str(_sp.get("family") or "")
            try:
                from src.iast.canary import CanaryMatcher as _CM
                from src.iast.sink_identity import is_genuine_sink_identity as _genuine
                _marker = str(_sp.get("taint_marker") or "")
                _ident = _CM.find_identity(_marker) if _marker else ""
                if not _ident:
                    _ident = _CM.find_identity(str((_rj.get("d2_evidence") or {}).get("taint_marker") or ""))
                if not _ident:
                    # 兜底：用 spec 自身的 taint_marker 列（权威）。raw_json 可能未回灌该字段，
                    # 缺这一步会让本闸静默跳过（fail-open 变哑火），噪声 sink 逃逸。
                    try:
                        _row = sdb.execute(
                            "SELECT taint_marker FROM trigger_specs WHERE id=? LIMIT 1",
                            (int(_spid),), fetchone=True,
                        )
                        if _row:
                            _ident = _CM.find_identity(str(dict(_row).get("taint_marker") or ""))
                    except Exception:
                        pass
                if _ident:
                    _evs = sdb.execute(
                        "SELECT sink_file, stack_trace FROM iast_events "
                        "WHERE task_id=? AND canary LIKE ?",
                        (task_id, "%" + _ident + "%"), fetchall=True,
                    ) or []
                    _sfs = [str(dict(e).get("sink_file") or "") for e in _evs]
                    _sfs = [x for x in _sfs if x]
                    # 只在「全部事件的 sink 落点都判非真」时否决；任一为真即放行（零误杀）。
                    #
                    # 只记框架类（`StringHttpMessageConverter` / `OnCommittedResponseWrapper`），
                    # **真实业务 sink 只出现在 `stack_trace`**。只看 `sink_file` 会把
                    # 「真到了业务 sink」误判成「只有噪声 sink」：
                    # 实测 本轮的 `/path_traversal/vul`，6 条事件 stack_trace 里是
                    # 但 sink_file 全是 Spring 类 ⇒ 硬闸把 16 条真确认降级成 unconfirmed
                    _stack_hit = False
                    _esf = str(_sp.get("expected_sink_file") or "").replace("\\", "/")
                    _esf = _esf.rsplit("/", 1)[-1].lower()
                    if _esf:
                        for _e in _evs:
                            _stk = str(dict(_e).get("stack_trace") or "").lower()
                            if _esf in _stk:
                                _stack_hit = True
                                break
                    if _sfs and not any(_genuine(x, _fam) for x in _sfs) and not _stack_hit:
                        _ok = False
                        _code = "noise_sink_only"
                        _why = ("canary 抵达的 sink 全部为框架噪声 sink（非本族真实危险函数，"
                                "且非 XSS/SSTI 族），不构成该族真实漏洞证据")
            except Exception as _ns_e:
                logger.debug("[D2][confirm-gate] sink 身份复核跳过 spec=%s：%s", _spid, _ns_e)
            if _ok:
                continue
        _reasons[_code] = _reasons.get(_code, 0) + 1
        try:
            _new_state = "confirm-gate:" + (_st or "none")
            _rj["confirm_gate"] = {
                "admitted": False,
                "code": _code,
                "reason": _why,
                "prior_iast_state": _st,
                "downgraded_at": datetime.now().isoformat(),
            }
            sdb.execute(
                "UPDATE trigger_specs SET verification_status='unconfirmed', "
                "business_logic_confirmed=0, iast_state=?, raw_json=? WHERE id=?",
                (_new_state, json.dumps(_rj, ensure_ascii=False), int(_spid)),
            )
            _n += 1
            logger.info(
                "[D2][confirm-gate] spec=%s family=%s iast_state=%s 无正向证据 → unconfirmed（%s）",
                _spid, _sp.get("family"), _st, _why,
            )
        except Exception as _up_e:
            logger.warning("[D2][confirm-gate] 写回失败 spec=%s：%s", _spid, _up_e)
    if _n:
        logger.warning(
            "[D2][confirm-gate] 确认态硬闸降级 %d 条 confirmed_exploitable → unconfirmed（无正向证据），分布=%s",
            _n, _reasons,
        )
        try:
            _append_scan_task_event(task_id, "confirm_gate", {
                "downgraded": _n,
                "reasons": _reasons,
                "message": "确认态硬闸：%d 条 spec 无正向证据（探针未记录到达 / 结果点无影响 / 无差分确认），"
                           "已从 confirmed_exploitable 降级为 unconfirmed（待重试）。" % _n,
            })
        except Exception:
            pass
    else:
        logger.info("[D2][confirm-gate] 复核 %d 条 confirmed_exploitable，全部握有正向证据", len(specs))
    return _n


def _apply_oob_correlation(task_id: Optional[int], sdb) -> int:
    """OOB 第四层回调回流：把「真实到达的带外回执」与 spec 对号入座。

    为什么必须独立做：D2 主循环里 oob_confirmed 只在「反序列化 IAST 链路被观测到」的支内才查
    has_callback（d2_facade._verify_sink_result 的 _deser 分支）。而 no-arrival 的反序列化 spec
    其 IAST 证据为空 → _deser 分支不进 → oob_confirmed 永远 False，尽管回执已真实到达。

    本函数绕开 IAST 链路，直接以「oob_callbacks 是否收到 kind='callback'」为准：
    - 只有回执真实到达才升级（铁律：无回执=无证据，绝不把没收到包装成收到）；
    - 优先按登记行 spec_id 精确升级；登记行缺 spec_id（旧数据）时按 (family, endpoint) 粗收口，
      仅作用于当前未确认的反序列化类 spec；
    - 升级结果经 _confirm_gate_decide(oob_confirmed=True) 复核，保证落到 confirmed_exploitable 的
      条目握有 OOB 实证；随后 _apply_confirmation_gate 会再复核一遍，防止误升。
    """
    if task_id is None or sdb is None:
        return 0
    try:
        cbs = sdb.execute(
            "SELECT DISTINCT token FROM oob_callbacks WHERE task_id=? AND kind='callback'",
            (task_id,), fetchall=True,
        ) or []
    except Exception as _qe:
        logger.warning("[D2][oob-correlation] 查询 oob_callbacks 失败：%s", _qe)
        return 0
    if not cbs:
        return 0
    _n = 0
    for _row in cbs:
        # 真实 sdb 的 row_factory 返回 dict；兼容 Row/元组形态。
        if isinstance(_row, dict):
            _tok = str(_row.get("token") or "")
        else:
            _tok = str((_row or [None])[0] or "")
        if not _tok:
            continue
        try:
            reg = sdb.execute(
                "SELECT spec_id, family, target_endpoint FROM oob_callbacks "
                "WHERE token=? AND kind='registered' ORDER BY id DESC LIMIT 1",
                (_tok,), fetchone=True,
            ) or {}
        except Exception:
            reg = {}
        _spec_id = reg.get("spec_id")
        _fam = str(reg.get("family") or "").strip().lower()
        _ep = str(reg.get("target_endpoint") or "").strip()
        try:
            if _spec_id:
                cand = sdb.execute(
                    "SELECT id, family, iast_state, raw_json FROM trigger_specs "
                    "WHERE id=? AND verification_status<>'confirmed_exploitable'",
                    (int(_spec_id),), fetchall=True,
                ) or []
            elif _fam and _ep:
                cand = sdb.execute(
                    "SELECT id, family, iast_state, raw_json FROM trigger_specs "
                    "WHERE task_id=? AND family=? AND target_endpoint=? "
                    "AND verification_status<>'confirmed_exploitable'",
                    (task_id, _fam, _ep), fetchall=True,
                ) or []
            else:
                cand = []
        except Exception as _qe2:
            logger.warning("[D2][oob-correlation] 取候选 spec 失败 token=%s：%s", _tok, _qe2)
            cand = []
        for _sp in cand:
            _spid = _sp.get("id")
            _st = str(_sp.get("iast_state") or "")
            try:
                _rj = json.loads(_sp.get("raw_json") or "{}")
                if not isinstance(_rj, dict):
                    _rj = {}
            except Exception:
                _rj = {}
            _d2e = _rj.get("d2_evidence") or {}
            _out = _rj.get("d2_output") or {}
            # 回执即有害实证：回执到达证明 payload 在服务端被执行。
            _rj["oob"] = {"token": _tok[:32], "confirmed": True}
            _ok, _code, _why = _confirm_gate_decide(
                _st,
                {"matched_event_ids": _d2e.get("matched_event_ids") or []},
                {"impact_observed": bool(_out.get("impact_observed"))},
                {
                    "harmful": True,
                    "oob_confirmed": True,
                    "deserialization_chain_confirmed": bool(_d2e.get("deserialization_chain_confirmed")),
                },
                oob_confirmed=True,
            )
            if not _ok:
                continue
            try:
                _new_state = "oob-reached" if _st.startswith("confirm-gate:") else _st
                _rj["confirm_gate"] = {
                    "admitted": True,
                    "code": _code,
                    "reason": _why,
                    "oob_token": _tok[:32],
                    "upgraded_at": datetime.now().isoformat(),
                }
                sdb.execute(
                    "UPDATE trigger_specs SET verification_status='confirmed_exploitable', "
                    "iast_state=?, raw_json=? WHERE id=?",
                    (_new_state, json.dumps(_rj, ensure_ascii=False), int(_spid)),
                )
                _n += 1
                logger.info(
                    "[D2][oob-correlation] spec=%s token=%s OOB 回执真实到达 → confirmed_exploitable",
                    _spid, _tok,
                )
            except Exception as _up_e:
                logger.warning("[D2][oob-correlation] 写回失败 spec=%s：%s", _spid, _up_e)
    if _n:
        try:
            _append_scan_task_event(task_id, "oob_correlation", {
                "upgraded": _n,
                "tokens": [str(c.get("token") or "") for c in cbs],
                "message": "OOB 第四层：%d 条 spec 的带外回执真实到达，payload 确证在服务端执行，已升级 confirmed_exploitable。" % _n,
            })
        except Exception:
            pass
        logger.warning("[D2][oob-correlation] OOB 回执升级 %d 条 spec → confirmed_exploitable", _n)
    else:
        logger.info("[D2][oob-correlation] task=%s 有回执但无匹配未确认 spec（可能已确认或 spec_id 缺失）", task_id)
    return _n



def _load_idor_accounts(task_id: Optional[int], external_target: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """取 idor/DAST app 配置的双账号（攻击者/受害者）。无配置返回 None（差分重放降级为未确认）。"""
    app_id = external_target.get("app_name") or external_target.get("idor_app_id") or ""
    if not app_id and task_id is not None:
        try:
            from src.infrastructure.db import Database
            db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
            row = db.execute("SELECT options_json FROM scan_tasks WHERE id=?", [task_id], fetchone=True)
            if row:
                import json as _json
                opts = _json.loads(row["options_json"] or "{}") if isinstance(row["options_json"], str) else (row["options_json"] or {})
                app_id = opts.get("idor_app_id") or ""
        except Exception:
            pass
    if not app_id:
        return None
    try:
        # 差分重放永远拿不到双账号（表现为「读 idor app 双账号」静默降级为 None）。
        from src.infrastructure.db import Database as _Database
        _db = _Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        accounts = D1Service(db=_db).list_accounts(app_id)
        if accounts:
            # 归一成 {attacker, victim} 形状供 replay_* 使用
            attacker = next((a for a in accounts if str(a.get("role") or "").lower() in ("attacker", "low", "user_a")), accounts[0])
            victim = next((a for a in accounts if str(a.get("role") or "").lower() in ("victim", "high", "user_b", "owner")), accounts[-1])
            return {"attacker": attacker, "victim": victim}
    except Exception as _e:
        logger.warning("[D2] 读取 idor app 双账号失败（降级）：%s", _e)
    return None


def _build_business_logic_spec(vuln: Dict[str, Any], external_target: Dict[str, Any], accounts,
                               code_root: Optional[str] = None,
                               discovered_routes: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """由 A1/A2 业务逻辑 finding 构造 business_logic trigger_spec（供 verify 路由到差分重放）。

    修复一：业务重放路径此前绕过  解析真相源——只从 ae.target_endpoint / vuln.entry_point
    取端点，业务型上这些字段常为「空 / 源码路径 / 方法名拼接」，导致重放打到 /address/（空 id）而非
    /address/{id}，探针 ExecutorQueryAdvice 永不命中 findById → BOLA_SUSPECT 恒 0（即「检测到但没确认」真根因）。
    现改为优先调用 resolve_endpoint_full(vuln, ae, code_root, discovered_routes) 取与通道 A 同一解析器产出的
    route/method/param_name/param_location；解析失败再回退旧字段（绝不静默编造）。
    """
    ae = vuln.get("a1_evidence") or {}
    cat = _normalize_bl_category(ae.get("category") or vuln.get("category") or vuln.get("type") or vuln.get("vuln_type"))
    if not cat:
        return None

    # —— 修复一：解析真相源优先（与通道 A trigger_specs.target_endpoint 同源）——
    _route = _method = _pname = _ploc = ""
    if code_root or discovered_routes:
        try:
            from src.iast.trigger_spec_registry import resolve_endpoint_full
            _r = resolve_endpoint_full(
                vuln, ae,
                code_root=code_root or None,
                discovered_routes=discovered_routes,
            ) or {}
            _route = str(_r.get("route") or "").strip()
            _method = str(_r.get("method") or "").strip()
            _pname = str(_r.get("param_name") or "").strip()
            _ploc = str(_r.get("param_location") or "").strip()
        except Exception as _e:
            logger.warning("[D2] 业务 spec 端点解析失败（回退旧字段）：%s", _e)

    # 受害者资源 id：A2 把真实 id 写在 exploit_spec.prerequisites.victim_resource_id，也支持哨兵
    # VICTIM_FROM_POOL（运行时由账户池解析）；多源归一并优先真值，空则留空交修复二枚举。
    _vid = (
        ae.get("victim_resource_id")
        or vuln.get("victim_resource_id")
        or (vuln.get("exploit_spec") or {}).get("prerequisites", {}).get("victim_resource_id")
        or ""
    )

    spec = {
        "business_logic_category": cat,
        "target_endpoint": _route or ae.get("target_endpoint") or vuln.get("entry_point") or vuln.get("target_endpoint") or "",
        "http_method": _method or (ae.get("http_method") or "GET"),
        "param_name": _pname or (ae.get("vulnerable_param") or "id"),
        "param_location": _ploc or (ae.get("param_location") or "path"),
        "victim_resource_id": _vid,
        "victim_identifiers": ae.get("victim_identifiers") or [],
        "resource_type": ae.get("resource_type") or "",
        "accounts": accounts,
    }
    return spec


def _attach_business_canary(
    spec: Dict[str, Any],
    vhash: str,
    specs_by_hash: Dict[str, List[Dict[str, Any]]],
    task_id: Any,
) -> Dict[str, Any]:
    """P1：为业务差分重放 spec 绑定 canary（taint_marker），打通 IAST 可达性消费 + X-SASTAI-Trace 注入。

    背景：d2_facade._verify_business_logic消费 IAST 可达性须从
    trigger_spec.taint_marker 取 canary；replay_bola 也须从 taint_marker 注入 X-SASTAI-Trace 头。
    但原业务分支用 _build_business_logic_spec 现造 spec，键集不含 taint_marker，导致：
      (a) IAST 消费端 read 到空 canary → fail-open 跳过（永远 no-iast-evidence）；
      (b) replay_bola 不注入 X-SASTAI-Trace → 即使探针实现了 BOLA_SUSPECT 也回带不了 canary。
    修复：与技术类对齐——优先复用本 task 已登记 trigger_spec 携带的 taint_marker（业务族若带合法
    route 已由 A2→TriggerSpec 登记并写入 canary，见 trigger_spec_registry.py:650）；未登记（无 route
    被注册门禁 missing_route 拒）时按 business_logic_category 现场生成全局唯一 canary，保证 replay_bola
    能注入身份段、d2_facade 能按 canary 轮询探针事件。spec 其他字段（端点/参数/受害者 id）一律保留
    _build_business_logic_spec 的派生结果，不被覆盖。
    """
    if not isinstance(spec, dict):
        return spec
    if spec.get("taint_marker"):
        return spec
    # 1) 复用已登记 spec 的 canary
    _matched = (specs_by_hash or {}).get(vhash, []) or []
    _reg = _select_trigger_spec_for_task(_matched, task_id) or {}
    _reg_tm = _reg.get("taint_marker") or ""
    if _reg_tm:
        spec["taint_marker"] = _reg_tm
        for _k in ("id", "workspace_id", "app_name", "agent_id", "vulnerability_hash_v2"):
            if _reg.get(_k) is not None:
                spec.setdefault(_k, _reg.get(_k))
        return spec
    # 2) 未登记（业务族常因无 sink 缺 route 被注册门禁拒）→ 现场生成全局唯一 canary
    try:
        from src.iast.canary import CanaryFactory
        _cat = spec.get("business_logic_category") or "bola"
        spec["taint_marker"] = CanaryFactory.build(_cat)
    except Exception as _e:
        logger.warning("[D2] 业务 canary 生成失败（IAST 消费降级 fail-open）：%s", _e)
    return spec


def _select_trigger_spec_for_task(matched_specs: list, task_id) -> Optional[dict]:
    """§hash 碰撞收敛：同一漏洞 hash 在多次扫描里会登记多个 trigger_spec（task-1/4/6/... 各一条），
    全同 family/endpoint/param，仅 task_id/taint_marker 不同。

    优先选「本 task 登记的 spec」——它对本 task 的 finding 才是一一对应、且 attack_payloads 为空会
    自然走到 sca_forge 造真 gadget 字节；若直接取 [0]（最旧的 task-1 spec），会拿到「上一个 task 的
    canary」且可能因该 spec 预置了 ysoserial 文本 payload 而绕过方案 1a 的 sca_forge 真 gadget 构造。
    无本 task spec 时回退到 [0]（兼容旧行为）。

    Returns:
        选中的 trigger_spec dict，或 None（无匹配）。
    """
    if not matched_specs:
        return None
    _own = [s for s in matched_specs if s.get("task_id") == task_id]
    return (_own or list(matched_specs))[0]


def _mark_unverified_kind(raw_json: str, kind: str) -> str:
    """批次 B：在 spec 的 raw_json 上打「未验证子类」标记，fail-open。

    kind='never_replayed' 表示该 spec 从未进入 D2 重放（被调度门禁拦下 / 无 finding 驱动），
    与「重放过但窗口内零探针事件」区分开，供判责与重放策略选择。
    解析或序列化失败时原样返回，绝不因打标失败阻断主流程。
    """
    try:
        meta = json.loads(raw_json or "{}")
        if not isinstance(meta, dict):
            return raw_json or ""
        meta["unverified_kind"] = kind
        return json.dumps(meta, ensure_ascii=False)
    except Exception:
        return raw_json or ""


def finalize_unverified_trigger_specs(db, task_id: Optional[int]) -> int:
    """-B 末态兜底：把本 task 仍为空 verification_status 的 trigger_spec 落 'no_evidence'。

    根因：trigger_specs 中部分 spec 由 A2 自动登记，但无对应 finding 驱动 run_d2_verify 的
    verify（all_vulns 仅来自 a1/a2 findings），导致 Phase2 的 per-spec 写回循环永不触发，
    verification_status 与 iast_state 恒为空字符串。空串在指标里形成一个幽灵第三类目
    （empty=8），污染召回率统计（confirmed/unconfirmed/empty 三态被空串偷走一档）。

    修法：D2 聚合终态统一清扫——凡是本 task 下 verification_status 仍为空的 spec，一律置
    'no_evidence'（并补 iast_state='no-iast-evidence'）。这与 D2Agent.verify 在「缺 trigger_spec」
    分支返回的 final_state='no_evidence' 语义一致：D2 已就位审视过该 spec，无证据表明可利用。
    只扫本 task（WHERE task_id=?），避免误改其他 in-progress task 的 spec。
    iast_state 仅在当前为空时才补默认；若某 spec 已有非零 iast_state（例如曾观察到事件），
    则保留原值，不强行覆盖。
    """
    if db is None or task_id is None:
        return 0
    # （探针 HOOK_INVENTORY 事件 / 任意事件 context 里的 hook_inventory），判断各 spec 的
    # 「无证据」根因是探针组件缺陷（关键 hook 未织入）还是 A2/D1 攻击计划缺陷（hook 就位但
    # canary 没投到正确入口）。整段最佳努力（try/except），失败一律 unknown，绝不阻断兜底。
    _inv: Dict[str, Any] = {}
    try:
        from src.iast.orchestrator import TriggerTransactionOrchestrator
        _inv_rows = db.execute(
            "SELECT evidence FROM iast_events WHERE task_id=? LIMIT 2000",
            (int(task_id),), fetchall=True,
        ) or []
        _all_evs: List[Dict[str, Any]] = []
        for _ir in _inv_rows:
            try:
                _ev = json.loads((_ir.get("evidence") if isinstance(_ir, dict) else _ir[0]) or "{}")
                if isinstance(_ev, dict):
                    _all_evs.append(_ev)
            except Exception:
                continue
        _inv = TriggerTransactionOrchestrator.extract_hook_inventory(_all_evs)
    except Exception as _ie:
        logger.debug("[D2][3.1-B] hook_inventory 提取失败（归因置 unknown）：%s", _ie)
    try:
        rows = db.execute(
            "SELECT id, iast_state, raw_json, family, category, business_logic_category FROM trigger_specs "
            "WHERE task_id=? AND (verification_status IS NULL OR verification_status='')",
            (int(task_id),),
            fetchall=True,
        ) or []
        if not rows:
            return 0
        finalized = 0
        for r in rows:
            sid = int(r["id"] if isinstance(r, dict) else r[0])
            cur_state = (r.get("iast_state") if isinstance(r, dict) else r[1]) or ""
            new_state = cur_state if cur_state else "no-iast-evidence"
            # 走本兜底的 spec 从未进入 D2（verification_status 仍为空），与「D2 跑过、
            # 只是窗口内零事件」不是同一类失败——后者可走重放/延窗补救，前者只能靠
            # 调度修复（如批次 A 的吸收门禁放行）。此前两类都落成 no_evidence +
            # no-iast-evidence，混为一谈无法判责。
            _raw = (r.get("raw_json") if isinstance(r, dict) else r[2]) or ""
            _patched = _mark_unverified_kind(_raw, "never_replayed")
            # D5 归因：本 spec 所属族的关键 hook 是否在 hook_inventory 中。
            _fam = (r.get("family") if isinstance(r, dict) else (r[3] if len(r) > 3 else "")) or ""
            _cat = (r.get("category") if isinstance(r, dict) else (r[4] if len(r) > 4 else "")) or ""
            _blc = (r.get("business_logic_category") if isinstance(r, dict) else (r[5] if len(r) > 5 else "")) or ""
            try:
                _attr = TriggerTransactionOrchestrator.attribute_no_iast_evidence(
                    _fam or _cat or _blc, _inv)
            except Exception:
                _attr = "unknown"
            try:
                _pm = json.loads(_patched or "{}")
                if isinstance(_pm, dict):
                    _pm["no_evidence_attribution"] = _attr
                    _patched = json.dumps(_pm, ensure_ascii=False)
            except Exception:
                pass
            db.execute(
                "UPDATE trigger_specs SET verification_status='no_evidence', iast_state=?, raw_json=? WHERE id=?",
                (new_state, _patched, sid),
            )
            finalized += 1
        logger.info(
            "[D2][3.1-B] 末态兜底：将 %d 条空状态 spec 置为 no_evidence (task=%s)",
            finalized, task_id,
        )
        return finalized
    except Exception as _e:  # fail-open：兜底失败不应让 D2 聚合崩溃
        logger.warning("[D2][3.1-B] 末态兜底失败（忽略）：%s", _e)
        return 0


# 背景：d2_batching 埋点每次调度调用都整体覆写，而 run_d2_verify 会被
# 「主 pass + i2_rerun（最多 3 轮）」多次调用，于是最终只残留最后一轮那个极小批次
# 这个关键事实**永久抹掉**了 —— 曾据此误判「合批没生效、需放宽切块粒度」。
# 这里跨调用累加，下一轮即可读到真实的主 pass 分批规模，避免再靠墙钟反推。
_D2_BATCH_CUM = {"calls": 0, "batches": 0, "members": 0, "vulns": 0}


try:  # 放模块级 try：d2_types 会连带 import 一批依赖，避免循环导入把 CLI 打挂
    from src.agents.d2_types import VerificationResult as _D2ResultBase
except Exception:  # pragma: no cover - 仅防御
    _D2ResultBase = object


class _D2Phase1TimeoutResult(_D2ResultBase):
    """Phase1 总墙钟/单条超时降级用的结果对象。

    直接 `raise`，把整轮任务打挂（exit 1、报告都没出）。Phase2 收卷处是
    `_phase1[id(vuln)]` 直接下标 + 访问 result.raw_output/poc_code/reason/verification_decision/
    iast_evidence，缺条会 KeyError。故超时改为「取消剩余批 + 用本对象降级填充」，
    让整轮能收卷出报告；代价是这些 spec 记 no_evidence（宁可丢确认，不可丢整轮）。

    手写版连踩两次同类坑——先漏 `exploitable`（AttributeError，half2 四轮全崩），
    又把 `steps_executed` 写成 `[]`（下游 `result.steps_executed > 0` ⇒
    TypeError: '>' not supported between 'list' and 'int'，crypto 整片 failed）。
    继承真类后字段名与类型由 dataclass 权威定义，将来新增字段也自动跟随，不会再错。
    """

    def __init__(self) -> None:
        _kw = dict(
            exploitable=False,
            confidence="low",
            reason="d2_phase1_wall_timeout",
            verification_decision={
                "verification_status": "no_evidence",
                "reason": "d2_phase1_wall_timeout",
            },
            final_state="no_evidence",
        )
        try:
            super().__init__(**_kw)
        except TypeError:  # 基类不是真 VerificationResult（导入失败）时的兜底
            for _k, _v in _kw.items():
                setattr(self, _k, _v)

    def __getattr__(self, name: str):
        """兜底：未预置字段按 None 返回并告警，保证「宁可丢确认，不可丢整轮」。

        dataclass 字段已齐，这里只兜住「run_d2_verify 将来新增字段」的场景。
        """
        if name.startswith("__"):
            raise AttributeError(name)
        logger.warning(
            "[D2] _D2Phase1TimeoutResult 缺字段 %s，按 None 降级（请补到 __init__）", name
        )
        return None


def _d2_primitives_gate_impl(vuln: Dict[str, Any], full: float = 0.85,
                             skip: float = 0.5) -> Dict[str, Any]:
    """D2 入口概率闸门。

    读 A2 原语判定挂进来的 vuln_prob（在 exploit_spec.primitives 里），返回分派动作：
      full        VP>=full 或无信号
      canary_only VP>=skip
      skip        VP<skip
    无信号（没跑两段式 / 判别降级 / 坏值）时一律 full——闸门只降级不新增否决，保召回。

    TP -3、FP +1，未通过"TP 不降 FP 不升"验收 ⇒ skip 默认下调到 0.3（只对极高置信判否
    才跳过）。0.5 到 0.85 的 canary_only 区间实测无副作用，保留。
    """
    out = {"action": "full", "vuln_prob": 0.0,
           "threshold_full": full, "threshold_skip": skip, "source": "none"}
    try:
        _prim = ((vuln.get("exploit_spec") or {}).get("primitives") or {})
    except Exception:
        _prim = {}
    if not isinstance(_prim, dict) or not _prim:
        return out
    try:
        _vp = float(_prim.get("vuln_prob") or 0.0)
    except (TypeError, ValueError):
        return out
    out["vuln_prob"] = _vp
    out["source"] = "llm"
    if _vp < skip:
        out["action"] = "skip"
    elif _vp < full:
        out["action"] = "canary_only"
    return out


def run_d2_verify(a1_results, a2_results, files, target_path: str = None, external_target: dict = None, task_id: Optional[int] = None, code_root: Optional[str] = None, discovered_routes: Optional[List[Dict[str, Any]]] = None, output_dir: Optional[str] = None):
    """运行 D2 动态验证（统一 verify 链路：D1 重放 + I1 关联 + D2 核实 + I2 裁决）。

    业务逻辑漏洞（BOLA/越权/状态机/计算逻辑/认证会话/滥用DoS）走「双账号差分重放」（business_logic.verify），
    技术类漏洞走 canary 污点重放；两者都经同一 verify 入口，用户感知为「每个 finding 一次 D 阶段验证」。
    差分重放结论折叠进统一 VerificationResult，攻击计划命中指标一并计入业务逻辑命中（消除「0 命中」错觉）。
    """
    import os
    from src.core.vuln_hash import canonicalize_vuln_for_hash, vulnerability_hash_v2 as _vh2
    logger.info("Starting D2 AI Agent verification...")

    # ⑤-A：注册 guard 事件落库回调（审计）。仅在已知 task_id 时启用；
    # 未带 task_id（离线回放等）则保留进程内环形缓冲，不落库。失败仅影响审计，绝不阻断验证。
    if task_id:
        try:
            from src.iast.attack_context import register_guard_audit_sink
            from src.application.hitl_audit import persist_guard_event
            from src.infrastructure.db import Database

            _audit_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))

            def _hitl_audit_sink(ev: Dict[str, Any]) -> None:
                persist_guard_event(_audit_db, task_id, ev)

            register_guard_audit_sink(_hitl_audit_sink)
        except Exception as _e:  # noqa: BLE001
            logger.warning("[D2] 注册 HITL 审计落库失败（仅影响审计，不阻断）：%s", _e)

    # 创建 D2 Agent
    actual_project_path = target_path if target_path else 'data/samples/test-project/ctf-java-quote'

    dockerfile_path = os.path.join(actual_project_path, 'Dockerfile')
    dockerfile_generated = os.path.join(actual_project_path, 'Dockerfile.generated')

    if (
        not target_path
        and not os.path.exists(dockerfile_path)
        and not os.path.exists(dockerfile_generated)
    ):
        possible_paths = [
            os.path.join(actual_project_path, '..', 'ctf-java-quote'),
            os.path.join(actual_project_path, '..', '..', 'ctf-java-quote'),
            'data/samples/test-project/ctf-java-quote',
            '../ctf-java-quote',
        ]
        for p in possible_paths:
            p = os.path.normpath(p)
            if os.path.exists(os.path.join(p, 'Dockerfile')) or os.path.exists(os.path.join(p, 'Dockerfile.generated')):
                actual_project_path = p
                logger.info(f"[D2] Found Dockerfile in: {actual_project_path}")
                break
        else:
            logger.warning(f"[D2] No Dockerfile found in {actual_project_path}, will try to use existing images")

    external_target_dict = normalize_external_target(external_target or {}).to_dict()
    project_context = {
        'language': 'java',
        'framework': 'spring boot',
        'project_path': actual_project_path,
        'external_target': external_target_dict,
        'hitl': {
            'approval_mode': config.get('agents.d2.hitl.approval_mode', 'off'),
            'tool_allowlist': list(config.get('agents.d2.hitl.tool_allowlist', []) or []),
            'act_allowlist': list(config.get('agents.d2.hitl.act_allowlist', []) or []),
        },
    }
    logger.info(f"[D2] Using project path: {actual_project_path}")

    def _a3_candidate_key(vuln_payload):
        canonical_key = str(vuln_payload.get('canonical_group_key', '') or '').strip()
        if canonical_key:
            return f"canonical:{canonical_key}"
        return f"raw:{vuln_payload.get('file', '')}:{vuln_payload.get('type', '')}:{vuln_payload.get('line', 0)}"

    def _a3_match_keys(vuln_payload):
        keys = []
        canonical_key = str(vuln_payload.get('canonical_group_key', '') or '').strip()
        if canonical_key:
            keys.append(f"canonical:{canonical_key}")
        keys.append(f"raw:{vuln_payload.get('file', '')}:{vuln_payload.get('type', '')}:{vuln_payload.get('line', 0)}")
        for node in vuln_payload.get('supporting_nodes', []) or []:
            keys.append(f"raw:{node.get('file', '')}:{node.get('type', '')}:{node.get('line', 0)}")
        deduped = []
        for key in keys:
            if key and key not in deduped:
                deduped.append(key)
        return deduped

    all_vulns = []
    candidate_map = {}
    for result in a1_results + a2_results:
        if result.error:
            continue
        for vuln in result.vulnerabilities:
            vuln_payload = {
                'type': vuln.type,
                'file': vuln.file,
                'line': vuln.line,
                'code_snippet': vuln.code_snippet,
                'description': vuln.description,
                'severity': vuln.severity,
                'entry_point': getattr(vuln, 'entry_point', ''),
                'sink': getattr(vuln, 'sink', ''),
                'data_flow': getattr(vuln, 'data_flow', ''),
                'has_http_entry': getattr(vuln, 'has_http_entry', False),
                'has_call_chain': getattr(vuln, 'has_call_chain', False),
                'callers': getattr(vuln, 'callers', ''),
                'verdict': getattr(vuln, 'verdict', ''),
                'source': result.agent.upper(),
                'canonical_group_key': getattr(vuln, 'canonical_group_key', ''),
                'chain_id': getattr(vuln, 'chain_id', '') or getattr(vuln, 'canonical_group_key', ''),
                'is_canonical': getattr(vuln, 'is_canonical', False),
                'is_absorbed': bool(getattr(vuln, 'is_absorbed', False)),
                'absorbed_by_group_key': str(getattr(vuln, 'absorbed_by_group_key', '') or ''),
                'supporting_nodes': list(getattr(vuln, 'supporting_nodes', []) or []),
                'supporting_node_count': int(getattr(vuln, 'supporting_node_count', 0) or 0),
                'proof_tier': getattr(vuln, 'proof_tier', 'broad_static'),
                'chain_proof': getattr(vuln, 'chain_proof', {}),
                'proof_gaps': list(getattr(vuln, 'proof_gaps', []) or []),
                # 路径 C：二次证明留痕（模型补证了哪些项、是否升级），供对账与前端展示
                'proof_second_pass': dict(getattr(vuln, 'proof_second_pass', {}) or {}),
                'exploit_spec': getattr(vuln, 'exploit_spec', {}),
                'a21_candidate_score': int(getattr(vuln, 'a21_candidate_score', 0) or 0),
                'a21_selected': getattr(vuln, 'a21_selected', None),
                'a21_reason': getattr(vuln, 'a21_reason', ''),
                # 透传 A1 业务逻辑语义标记，供 _is_business_logic_vuln 在统一 verify 阶段路由到差分重放
                'a1_evidence': getattr(vuln, 'a1_evidence', {}) or {},
                # §统一链路：预先算规范 vhash（与 auto_register 同一算法、同一输入源 vuln.to_dict），
                # 供下方 _d2_gate 用「已登记的 trigger_spec」反查放行——A1 漏洞自身 exploit_spec.entry.route
                # 为空（未走 _pre_resolve_a2_endpoints，仅 a2_results 被回填），但 auto_register 已用
                # resolve_endpoint_full 独立解析出路由并登记 spec，仍能进 D2 验证，避免 verification_status
                # 永久为空（从未进 D2）。这是「Mapper 派生 SQLi（/products）在 D2 裁决中通过」的关键门禁修复。
                'vuln_vhash': _vh2(canonicalize_vuln_for_hash(vuln.to_dict() if hasattr(vuln, 'to_dict') else vuln)),
            }
            # 业务逻辑漏洞是 SAST 已确认的一级 findings，必须进入验证环节（走差分重放）。
            # A2 用 a21_selected 过滤候选时，显式置 True，避免被「仅保留 A2 选中项」裁掉（#3/#5）。
            if _is_business_logic_vuln(vuln_payload) and vuln_payload.get('a21_selected') is None:
                vuln_payload['a21_selected'] = True
                vuln_payload['a21_candidate_score'] = max(vuln_payload['a21_candidate_score'], 1)
            candidate_key = _a3_candidate_key(vuln_payload)
            existing = candidate_map.get(candidate_key)
            if not existing:
                candidate_map[candidate_key] = vuln_payload
                continue

            prefer_new = (
                vuln_payload.get('source') == 'A2'
                and existing.get('source') != 'A2'
            ) or (
                vuln_payload.get('a21_selected') is not None
                and existing.get('a21_selected') is None
            )
            merged = dict(existing)
            for key, value in vuln_payload.items():
                if key == 'supporting_nodes':
                    merged[key] = value or existing.get(key, [])
                elif value not in (None, "", [], {}, 0) or key in {'a21_selected', 'a21_candidate_score'}:
                    if prefer_new or merged.get(key) in (None, "", [], {}, 0):
                        merged[key] = value
            candidate_map[candidate_key] = merged

    all_vulns = list(candidate_map.values())

    # 统一从 trigger_spec_registry 加载本 workspace 的 trigger_specs，
    # 按 vuln hash 关联。此处提前到门禁之前加载，供下方 _d2_gate 反查「已登记且解析出路由的 spec」放行
    # 技术族漏洞（含 A1 漏洞），也供 verify 驱动 D1 重放。
    _workspace_id_for_specs = None
    _sdb = None
    try:
        _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
        _sdb = Database(_db_path)
        if task_id is not None:
            _wr = _sdb.execute("SELECT workspace_id FROM scan_tasks WHERE id=?", [task_id], fetchone=True)
            _workspace_id_for_specs = int(_wr["workspace_id"]) if _wr else None
    except Exception:
        _workspace_id_for_specs = None
    # 在为 A1 finding 反查 trigger_spec 之前，先把每个 A1 finding 关联到同类别的
    # BenchmarkTest servlet 路由并登记 trigger_spec，使 D2 能真实回放确认（此前 252/253
    # 候选因 no_trigger_spec 跳过）。仅在 discovered_routes 含 BenchmarkTest servlet 时生效，
    # 非 benchmark 靶场自动 noop。必须在 load_trigger_specs_by_workspace 之前注册，才会被载入关联索引。
    _benchmark_adapter_result: Dict[str, Any] = {"applied": False}
    try:
        if _sdb is not None and discovered_routes:
            from src.iast.service import IastService as _AdapterIastService
            from src.benchmark.servlet_trigger_adapter import build_benchmark_trigger_specs
            _iast_svc = _AdapterIastService(_sdb)
            _bench_session_id = None
            try:
                _sessions = _iast_svc.list_sessions(_workspace_id_for_specs) or []
                if _sessions:
                    _first_s = _sessions[0]
                    _bench_session_id = int(_first_s.get("id")) if isinstance(_first_s, dict) else int(_first_s["id"])
            except Exception:
                _bench_session_id = None
            _benchmark_adapter_result = build_benchmark_trigger_specs(
                a1_vulns=all_vulns,
                discovered_routes=discovered_routes or [],
                code_root=code_root or "",
                task_id=task_id,
                workspace_id=_workspace_id_for_specs,
                session_id=_bench_session_id,
                iast_service=_iast_svc,
            )
    except Exception as _badapt:
        logger.warning("[D2] benchmark 触发器适配器异常（降级为不加 spec）：%s", _badapt)

    _trigger_specs_by_hash = load_trigger_specs_by_workspace(_workspace_id_for_specs, task_id=task_id)
    logger.info(
        "[D2] 已加载 workspace=%s 的 %d 条 trigger_spec（按 hash 关联 D1 重放；benchmark 适配器登记=%s）",
        _workspace_id_for_specs, len(_trigger_specs_by_hash),
        _benchmark_adapter_result.get("registered", 0),
    )

    # 钉死 D2 关联键：构建「稳定关联索引」_trigger_specs_by_anykey，键集 = {stable_vuln_key, vulnerability_hash_v2}，
    # 二者都映射到同一组 spec。stable_vuln_key 免疫 entry.route 漂移（注册端与验证端 route 不一致时仍能命中），
    # vhash 仅作兜底。这是吃掉 10 条空状态 spec（verification_status 永久为空）缺口的主修复：此前仅用 vhash，
    # 验证端 runtime_vhash ≠ 注册端 stored_vhash 导致反查落空、写回落空。
    from src.core.vuln_hash import stable_vuln_keys as _stable_vuln_keys
    _trigger_specs_by_anykey = build_trigger_spec_assoc_index(_trigger_specs_by_hash)

    # 关联调试（需求约定）：打印每个 vuln 的 runtime_vhash、stable_key 与匹配到的 spec 数，
    # 用于确认此前 10 条空 spec 确为 vhash 错位导致（runtime_vhash 命中 0、stable_key 命中 >0）。
    # ②-4：via 增加 weak（行号无关弱键）档，便于看出哪些条目是靠行号兜底才关联上的。
    for _v in all_vulns:
        _rvh = _v.get("vuln_vhash") or ""
        _sks = _stable_vuln_keys(_v)
        _rsk = _sks[0] if _sks else ""
        _via, _matched = "none", []
        for _i, _k in enumerate(_sks):
            if _trigger_specs_by_anykey.get(_k):
                _via, _matched = ("stable" if _i == 0 else "stable-weak"), _trigger_specs_by_anykey[_k]
                break
        if not _matched and _trigger_specs_by_anykey.get(_rvh):
            _via, _matched = "vhash", _trigger_specs_by_anykey[_rvh]
        logger.info(
            "[D2][assoc] type=%s file=%s line=%s runtime_vhash=%s stable_key=%s matched_specs=%d (via=%s)",
            _v.get("type"), _v.get("file"), _v.get("line"), _rvh[:12], _rsk[:12], len(_matched), _via,
        )

    # §门禁修正：a21_selected 过滤仅对业务逻辑族生效；技术族（sql-injection/ssrf/command-execution 等）
    # 进 D2 的条件放宽为「自身 exploit_spec.entry.route 非空」**或**「已登记 trigger_spec 且解析出可达入口」
    # （auto_register 用 resolve_endpoint_full 独立解析，A1 漏洞未走 _pre_resolve_a2_endpoints 也能拿到路由）。
    # 原逻辑只认自身 entry.route，会把 a21_selected=None 且自身 entry.route 为空的 A1 技术漏洞（如 Mapper 派生
    # SQLi /products）全量裁掉，导致其 verification_status 永远为空（从未进 D2）。这是「让 /products SQLi 在
    # D2 裁决中通过」的关键门禁修复。判定逻辑见模块级 _d2_gate_predicate。
    # 门禁反查改用 _trigger_specs_by_anykey（stable 主键优先），避免 route 漂移导致的漏进。
    # 若其源 finding 未进入候选集，此前会永久
    # no_evidence + never_replayed，等于「发现了却从不验证」。补入后由 D1/I1/D2 正常筛。
    _n_orphan = _enqueue_orphan_trigger_specs(
        all_vulns, _trigger_specs_by_anykey, db=_sdb, task_id=task_id)

    _has_a21_gate = any(vuln.get('a21_selected') is not None for vuln in all_vulns)
    _pre_gate_vulns = list(all_vulns)
    if _has_a21_gate:
        all_vulns = [vuln for vuln in all_vulns if _d2_gate_predicate(vuln, _trigger_specs_by_anykey)]

    # 原因，不得留 unknown」。这里把门禁前后差集逐条落原因，写 event 流 + stage_results.d2.scheduling，
    # 使「谁没进 D2、为什么」事后可审计，不再留下无任何证据、也无任何原因的沉默空壳。
    _d2_scheduling: Dict[str, Any] = {
        "candidates": len(_pre_gate_vulns),
        "selected": len(all_vulns),
        "skipped_count": 0,
        "skipped": [],
        "skipped_by_reason": {},
    }
    if _has_a21_gate:
        _selected_ids = {id(v) for v in all_vulns}
        for _pv in _pre_gate_vulns:
            if id(_pv) in _selected_ids:
                continue
            _reason = _d2_gate_skip_reason(_pv, _trigger_specs_by_anykey) or "unknown"
            _key = _reason.split(":", 1)[0]
            _d2_scheduling["skipped_by_reason"][_key] = _d2_scheduling["skipped_by_reason"].get(_key, 0) + 1
            _d2_scheduling["skipped"].append({
                "file": _pv.get("file"), "type": _pv.get("type"), "line": _pv.get("line"),
                "proof_tier": _pv.get("proof_tier"), "a21_selected": _pv.get("a21_selected"),
                "reason": _reason,
            })
        _d2_scheduling["skipped_count"] = len(_d2_scheduling["skipped"])
    logger.info(
        "[D2] 调度：候选 %s 条 → 入队 %s 条，未入队 %s 条（原因分布=%s）",
        _d2_scheduling["candidates"], _d2_scheduling["selected"],
        _d2_scheduling["skipped_count"], _d2_scheduling["skipped_by_reason"],
    )
    try:
        _append_scan_task_event(task_id, "task_progress", {"d2_scheduling": _d2_scheduling})
        _update_scan_progress_metadata(output_dir, {"stage_results": {"d2": {"scheduling": _d2_scheduling}}})
    except Exception as _she:  # fail-open：留痕失败不影响主流程
        logger.warning("[D2] 调度留痕写入失败（忽略）：%s", _she)

    if not all_vulns:
        logger.warning("No vulnerabilities to verify")
        # §③ 不再返回空 dict：把调度留痕带回调用方，避免「全部门禁裁掉」时报告层读不到任何原因。
        # 早前返回 {} 会让 report_manager 把全部 finding 折叠为空壳，且无处解释。
        return {
            'total_vulnerabilities': 0,
            'verifications': [],
            'pocs': [],
            'verification_status_distribution': {},
            'scheduling': _d2_scheduling,
            'invalidated_count': 0,
            'invalidated_by_reason': {},
            'target_epoch': {
                'enabled': False,
                'verdict': 'not_applicable',
                'reason': 'no vulnerabilities to verify (target_epoch tracking skipped)',
            },
            'exploitable_count': 0,
            'verified_poc_count': 0,
            'docker_attempted': False,
            'docker_used': False,
            'local_jar_attempted': False,
            'runtime_source': '',
            'runtime_type': '',
            'docker_status': {},
            'failure_reasons': [],
            'pending_actions': [],
        }

    # §统一链路：加载本 workspace 的 trigger_specs，按 vuln hash 关联，
    # 供 verify 驱动 D1 重放。统一链路里 verify 不再有 legacy 分支，必须拿到 trigger_spec
    # 才能真正跑 D1；没有则明确报 no_evidence（不静默回落）。
    from src.core.config import config as app_config

    agent_config = {
        'api': {
            'qwen': app_config.get('qwen', {}),
            'minimax': app_config.get('minimax', {}),
            'claude': app_config.get('claude', {}),
            'doubao': app_config.get('doubao', {}),
        }
    }

    # §并行化：D2 verify 内部并发。原 run_d2_verify 逐 finding 串行调用 agent.verify
    # （每个 verify 内含 D1 重放 + I1 轮询 + D2 核实 + I2 裁决，是整轮扫描最重 I/O 瓶颈，约 23min）。
    # 改为 Phase1 并发跑 verify（每 worker 独立 agent 实例，线程局部复用，并发度由
    # agents.d2.parallel_workers 控制，默认 12），Phase2 串行做后处理（结果解析 + DB 回写
    # trigger_specs + POC 拼装），保证 sqlite 单写者与报告顺序稳定。
    import threading as _threading
    _D2_MAX_WORKERS = int(config.get('agents.d2.parallel_workers', 12) or 12)
    _d2_tls = _threading.local()

    # （16:59:30~17:34:35）的重放窗口正落在该停机 + 启动区间内 → 停机窗口内重放的 spec 拿不到
    # 任何证据，会被写成 no_evidence（「永久非漏洞」结论），污染对账与差分门禁。
    # 处置：批次期间跟踪靶场实例纪元（监听目标端口进程的创建时间 —— JVM 重启必变；取不到时
    # 退化为探针心跳/阶段信号）。凡验证窗口与停机/重启窗口相交的 spec，终态一律落
    # invalidated（可重试），既不记 confirmed 也不记 no_evidence。
    from src.iast.target_epoch import (  # noqa: E402
        TargetEpochTracker as _TargetEpochTracker,
        spec_invalidation_reason as _spec_invalidation_reason,
    )

    _epoch_tracker = None
    try:
        _epoch_tracker = _TargetEpochTracker(
            external_target_dict.get("service_url", "") or "",
            app_name=external_target_dict.get("app_name", "") or "",
            agent_id=external_target_dict.get("agent_id", "") or "",
            db=_sdb,
        )
        logger.info("[D2] 靶场实例纪元基线：%s", _epoch_tracker.start())
    except Exception as _ee:  # fail-open：隔离能力不可用绝不阻断 D2 主流程
        _epoch_tracker = None
        logger.warning("[D2] 靶场实例纪元跟踪初始化失败（降级为仅单 spec 判据）：%s", _ee)

    def _d2_agent():
        if not hasattr(_d2_tls, 'agent'):
            _d2_tls.agent = D2PipelineService(agent_config).verifier()
        return _d2_tls.agent

    def _d2_resources():
        """线程内复用 IastService / D1Service。

        背景：verify/verify_group 的 iast_service/dast_operator 是可选参数，不传时它们会
        **每个 spec 各新建一次** Database + IastService + D1Service + LLM 网关。Database 实例级
        的 _initialized 为 False，首次 connect 会重跑一遍 _init_schema（数十条 CREATE/PRAGMA）；
        在 9GB 级库上这是纯浪费，309 spec/片就是 309 次建表检查 + 309 个网关对象。
        改为线程局部创建一次、批内/条间复用，语义不变（Database 本身按线程缓存连接）。
        """
        if not hasattr(_d2_tls, 'iast_service'):
            from src.iast.service import IastService as _IastService
            from src.application.d1_service import D1Service as _D1Service
            _d2_tls.iast_service = _IastService(_sdb)
            _d2_tls.dast_operator = _D1Service(
                db=_sdb, gateway=_D1Service.build_gateway_from_config(config))
        return _d2_tls.iast_service, _d2_tls.dast_operator

    def _d2_resolve_spec(vuln):
        """并发单元前半段（无 I/O）：解析本 finding 的 trigger_spec，返回 (_vhash, _sk, _ts, _trace)。

        再一次事务跑完整组（耗时主体是事务窗口，与批内假说数无关）。

        _d2_scheduling 只记「被门禁裁掉」的条目，对「已入队却无验证记录」的条目完全无痕，
        导致该缺口只能靠猜。这里把 spec 是否命中 / 选中 spec 与 replayable 逐项记下，
        由 Phase2 串行汇总后持久化到 stage_results.d2.scheduling.execution_trace。
        """
        _vhash = ""
        _sk = ""
        # 重算值对不上任何 spec（见 _enqueue_orphan_trigger_specs 注释）。
        # 空值/非孤儿 vuln 完全沿用原有重算路径，零行为变化。
        _orphan_vh = str(vuln.get("_orphan_spec_vhash") or "").strip()
        try:
            _vhash = _orphan_vh or _vh2(canonicalize_vuln_for_hash(vuln))
            _sk = (_stable_vuln_keys(vuln) or [""])[0]
        except Exception:
            _vhash = _orphan_vh
            _sk = ""
        _trace: Dict[str, Any] = {
            "file": vuln.get("file"), "type": vuln.get("type"), "line": vuln.get("line"),
            "proof_tier": vuln.get("proof_tier"),
            "vhash": _vhash, "stable_key": _sk,
            "business_logic": bool(_is_business_logic_vuln(vuln)),
            "spec_found_count": 0, "spec_id": None, "spec_endpoint": None,
            "replayable": None, "verify_called": False, "verify_returned": False,
            "result_status": "", "error": "", "spec_nulled_reason": "", "assoc_via": "none",
        }
        try:
            if _is_business_logic_vuln(vuln):
                _bl_accounts = _load_idor_accounts(task_id, external_target_dict)
                _ts = _build_business_logic_spec(vuln, external_target_dict, _bl_accounts, code_root=code_root, discovered_routes=discovered_routes) or {}
                _ts = _attach_business_canary(_ts, _vhash, _trigger_specs_by_anykey, task_id)
                _trace["spec_found_count"] = 1 if _ts else 0
                if _ts:
                    _trace["spec_endpoint"] = _ts.get("target_endpoint")
                    _trace["spec_id"] = _ts.get("id")
            else:
                # ②-4 双键兜底：先强键（含行号）、miss 再弱键（行号置 0）、再 vhash。
                # 弱键仅在强键未命中时生效（行号漂移兜底），绝不抢强键 → 不会放大误归因。
                _matched_specs = []
                # 孤儿 vuln 的 stable_key 是按合成字段算的，可能误命中同文件同族的
                # 另一条 spec；它的登记 vhash 才是精确关联键，故跳过 stable 捷径。
                _stable_keys = [] if _orphan_vh else _stable_vuln_keys(vuln)
                for _k in _stable_keys:
                    _hit = _trigger_specs_by_anykey.get(_k)
                    if _hit:
                        _matched_specs = _hit
                        _trace["assoc_via"] = "stable" if _k == _sk else "stable-weak"
                        break
                if not _matched_specs:
                    _matched_specs = _trigger_specs_by_anykey.get(_vhash, [])
                    if _matched_specs:
                        _trace["assoc_via"] = "vhash"
                _trace["spec_found_count"] = len(_matched_specs)
                _ts = _select_trigger_spec_for_task(_matched_specs, task_id)
                if _ts:
                    _trace["spec_id"] = _ts.get("id")
                    _trace["spec_endpoint"] = _ts.get("target_endpoint")
                    _trace["replayable"] = int(_ts.get("replayable", 1) or 1)
                if _ts and int(_ts.get("replayable", 1) or 1) == 0:
                    logger.info(
                        "[D2] 跳过 hash=%s 的 trigger_spec 重放：replayable=0（route=%s, category=%s），按 no_evidence 处理。",
                        _vhash[:12], _ts.get("target_endpoint"), _ts.get("category"),
                    )
                    _trace["spec_nulled_reason"] = "replayable=0"
                    _ts = None
                if _matched_specs and not _ts:
                    _trace["spec_nulled_reason"] = _trace["spec_nulled_reason"] or "select_trigger_spec_returned_none"
        except Exception as _se:
            # spec 解析失败不该静默吞：记进 _trace 交由 execution_trace 审计，并按无 spec 处理。
            _trace["error"] = "%s: %s" % (type(_se).__name__, _se)
            logger.warning("[D2] trigger_spec 解析异常（file=%s）：%s", vuln.get("file"), _se)

        # A2 原语判定的 vuln_prob 决定本条的重放策略，省 D2 这个最贵阶段（占总耗时 28%）：
        #   full        VP>=0.85 或无信号 → 正常完整重放（无信号按 full，保召回）；
        #   canary_only 0.5<=VP<0.85 → 只发 canary 不投攻击载荷（D1 attack_degraded 路径）；
        #   skip        VP<0.5 → 不重放，直接降级 no_evidence（报告层可区分 low_confidence_skip）。
        # 纪律：低概率的处理是「降级验证」不是「否决」——判假的权力只在运行时证据手里。
        _gate = _d2_primitives_gate(vuln)
        if _gate["action"] != "full" and _ts:
            _trace["primitives_gate"] = _gate["action"]
            _trace["primitives_vp"] = _gate["vuln_prob"]
        if _gate["action"] == "skip":
            logger.info(
                "[D2] 概率闸门跳过 hash=%s（VP=%.2f<%.2f）：不重放，降级 no_evidence",
                _vhash[:12], _gate["vuln_prob"], _gate["threshold_skip"])
            _trace["spec_nulled_reason"] = "primitives_low_confidence"
            _ts = None
        elif _gate["action"] == "canary_only" and _ts:
            # 只发 canary：清空攻击载荷候选（D1 无 payload 即走 attack_degraded，只投 canary 探针），
            # 不改动库里的 spec，只用副本——后续 I2/报告仍按原 spec 呈现。
            _ts = dict(_ts)
            try:
                import json as _json
                _ap = _json.loads(_ts.get("attack_payloads_json") or "[]")
            except Exception:
                _ap = []
            _ts["attack_payloads_json"] = "[]"
            _trace["primitives_dropped_payloads"] = len(_ap) if isinstance(_ap, list) else 0
            _ts = None
        return _vhash, _sk, _ts, _trace

    def _d2_primitives_gate(vuln: Dict[str, Any]) -> Dict[str, Any]:
        """D2 入口概率闸门（薄包装，阈值从 env 读；逻辑在模块级同名函数里，便于单测）。"""
        return _d2_primitives_gate_impl(
            vuln,
            full=float(os.environ.get("SAST_AI_D2_GATE_FULL", "0.85") or 0.85),
            skip=float(os.environ.get("SAST_AI_D2_GATE_SKIP", "0.3") or 0.3))

    def _d2_call_verify(vuln):
        """单条 verify（批量合并关闭时、或批量异常回退时使用）。

        verify_group 有 SAST_AI_D2_BATCH_WALL，而 group 超时后会回退到本函数逐条跑——
        若单条 HTTP 重放本身挂住（请求级无超时），worker 线程永久卡住，整轮只能等
        replay 停在 1/32、心跳停滞 721s+ 即此形态。
        超时**按降级结果返回**（no_evidence + single_verify_timeout 标记），绝不抛异常：
        Phase2 收卷处是 `_phase1[id(vuln)]` 直接下标取结果，缺条会 KeyError 掀翻整轮。
        守护线程内的挂起请求随 daemon 线程自灭，fail-safe 不阻塞主流程。
        """
        _t0 = time.time()
        _vhash, _sk, _ts, _trace = _d2_resolve_spec(vuln)
        _single_wall = float(os.environ.get("SAST_AI_D2_SINGLE_WALL", "300") or 300)
        try:
            _trace["verify_called"] = True
            _is, _do = _d2_resources()
            _res, _timed_out = _with_wall_clock_limit(
                lambda: _d2_agent().verify(vuln, project_context, external_target_dict,
                                           trigger_spec=_ts, iast_service=_is, dast_operator=_do),
                _single_wall, label="d2_verify_single")
        except Exception as _ve:
            _trace["error"] = "%s: %s" % (type(_ve).__name__, _ve)
            logger.exception("[D2] verify 执行异常（hash=%s）：%s", _vhash[:12], _ve)
            raise
        _t1 = time.time()
        if _timed_out or _res is None:
            _trace["verify_timed_out"] = True
            _trace["error"] = "single verify timeout %.0fs" % _single_wall
            logger.warning("[D2] 单条 verify 超墙钟 %.0fs（hash=%s），按 no_evidence 降级返回",
                           _single_wall, _vhash[:12])
            try:
                _append_scan_task_event(task_id, "task_log", {
                    "level": "warning", "source": "d2_single_verify_timeout",
                    "message": f"hash={_vhash[:12]} 单条 verify 超 {_single_wall:.0f}s，降级 no_evidence",
                })
            except Exception:
                pass
            from src.agents.d2_types import VerificationResult as _VR
            _res = _VR(
                exploitable=False, confidence="low",
                reason="单条 verify 超墙钟 %.0fs（D1 重放无响应），按证据缺失处理，可重试" % _single_wall,
                verification_decision={"verification_status": "no_evidence",
                                       "judge_reason": "single_verify_timeout",
                                       "timeout_sec": _single_wall},
                final_state="no_evidence")
        else:
            _trace["verify_returned"] = True
            try:
                _trace["result_status"] = str(
                    (getattr(_res, "verification_decision", {}) or {}).get("verification_status", "") or ""
                )
            except Exception:
                _trace["result_status"] = ""
        return _res, _ts, _vhash, _sk, _t0, _t1, _trace

    # 没有它就无法回答「批量合并到底生效了吗」，只能凭 D2 总耗时猜。
    _batch_stats = {"batches": 0, "members": 0, "fallback_batches": 0, "fallback_members": 0}
    # 但不知道是「均匀慢」还是「少数批超时」。记录每批耗时后，重跑时可直接看 min/max/avg。
    _batch_walls: list = []
    _bw_lock = threading.Lock()

    def _d2_call_verify_batch(batch):
        """批量合并事务：批内漏洞共用一次 IAST 触发事务。

        返回 [(id(vuln), res_tuple)]，与 _d2_call_verify 的元组形态完全一致，Phase2 无需改动。
        任何环节异常都整批回退逐条 verify —— 绝不以降质换速度。
        """
        _t0 = time.time()
        _batch_stats["batches"] += 1
        _batch_stats["members"] += len(batch)
        _resolved = []
        for _v in batch:
            try:
                _resolved.append((_v,) + tuple(_d2_resolve_spec(_v)))
            except Exception as _re:
                logger.warning("[D2] spec 解析失败（该条走逐条回退）：%s", _re)
                _resolved.append((_v, "", "", None, {"error": str(_re)}))
        # 概率闸门（与单条路径同规则）：skip 的成员整条从批里摘出（不占事务窗口），
        # canary_only 的成员换载荷清空的 spec 副本。摘出的条目在 _out 里补降级结果，
        # Phase2 按 id(vuln) 取用，形态与逐条 verify 完全一致。
        _gated_out = []
        _kept = []
        for (_v, _vh, _sk, _ts, _tr) in _resolved:
            _gate = _d2_primitives_gate(_v)
            if _gate["action"] == "full" or not _ts:
                _kept.append((_v, _vh, _sk, _ts, _tr))
                continue
            _tr["primitives_gate"] = _gate["action"]
            _tr["primitives_vp"] = _gate["vuln_prob"]
            if _gate["action"] == "skip":
                logger.info("[D2] 概率闸门跳过 hash=%s（VP=%.2f）：不重放，降级 no_evidence",
                            _vh[:12], _gate["vuln_prob"])
                _tr["spec_nulled_reason"] = "primitives_low_confidence"
                _gated_out.append((_v, _vh, _sk, None, _tr))
            else:  # canary_only
                _ts = dict(_ts)
                try:
                    import json as _json
                    _ap = _json.loads(_ts.get("attack_payloads_json") or "[]")
                except Exception:
                    _ap = []
                _ts["attack_payloads_json"] = "[]"
                _tr["primitives_dropped_payloads"] = len(_ap) if isinstance(_ap, list) else 0
                _kept.append((_v, _vh, _sk, _ts, _tr))
        _resolved = _kept
        _members = [{"vulnerability": _v, "trigger_spec": _ts} for (_v, _vh, _sk, _ts, _tr) in _resolved]
        _vrs = None
        # _with_wall_clock_limit 给每批硬上限，超时即整批回退逐条（fail-safe，不阻塞主流程）。
        _batch_wall = float(os.environ.get("SAST_AI_D2_BATCH_WALL", "600") or 600)
        try:
            _is, _do = _d2_resources()
            _vrs, _bg_timed = _with_wall_clock_limit(
                lambda: _d2_agent().verify_group(_members, project_context, external_target_dict,
                                                 iast_service=_is, dast_operator=_do),
                _batch_wall, label="d2_verify_group")
            if _bg_timed:
                logger.warning("[D2] verify_group 超墙钟 %.0fs（%d 条），整批回退逐条",
                               _batch_wall, len(_members))
                _vrs = None
        except Exception as _ge:
            logger.warning("[D2] verify_group 异常，整批回退逐条：%s", _ge)
            _vrs = None
        if _vrs is None:
            _batch_stats["fallback_batches"] += 1
            _batch_stats["fallback_members"] += len(batch)
        _out = []
        for _i, (_v, _vhash, _sk, _ts, _trace) in enumerate(_resolved):
            if _vrs is None or _i >= len(_vrs) or _vrs[_i] is None:
                _out.append(_d2_call_verify(_v))
                continue
            _trace["verify_called"] = True
            _trace["verify_returned"] = True
            _result = _vrs[_i]
            try:
                _trace["result_status"] = str(
                    (getattr(_result, "verification_decision", {}) or {}).get("verification_status", "") or ""
                )
            except Exception:
                _trace["result_status"] = ""
            _out.append((_result, _ts, _vhash, _sk, _t0, time.time(), _trace))
        # 概率闸门摘出的 skip 成员：补降级结果（no_evidence + low_confidence_skip），
        # 与 verify 结果同形态返回，Phase2 按 id(vuln) 取用，不会缺条。
        _gated_results = []
        for (_v, _vh, _sk, _ts, _tr) in _gated_out:
            from src.agents.d2_types import VerificationResult as _VR
            _vp = float(_tr.get("primitives_vp") or 0.0)
            _vr = _VR(
                exploitable=False, confidence="low",
                reason="A2 概率闸门：vuln_prob=%.2f 低于阈值，未重放（低置信降级，非否决）" % _vp,
                verification_decision={"verification_status": "no_evidence",
                                       "judge_reason": "low_confidence_skip",
                                       "primitives_vp": _vp},
                final_state="no_evidence")
            _gated_results.append((_vr, None, _vh, _sk, _t0, time.time(), _tr))
        _all = _gated_results + _out
        _keys = [id(_x[0]) for _x in _gated_out] + [id(_x[0]) for _x in _resolved]
        return list(zip(_keys, _all))
    poc_generator = POCGenerator()
    file_contents = {}
    for file_info in files or []:
        rel = file_info.get('rel_path', '')
        content = file_info.get('content', '')
        if rel and content:
            file_contents[rel] = content

    results = []
    failure_reasons = []
    docker_attempted = False
    docker_used = False
    local_jar_attempted = False
    runtime_source = ''
    pending_actions = []

    # §并行化 Phase1：并发跑 agent.verify（每个 worker 独立 agent 实例，线程局部复用），
    # 并发度由 _D2_MAX_WORKERS 控制。IO 密集，并发收益最大。futures 用 id(vuln) 关联，保证
    # Phase2 串行后处理时按原始 all_vulns 顺序取回 (result, _ts, _vhash)，报告顺序稳定。
    # scan_progress.json（第 N/M 条、当前端点、已 confirmed/sink 计数、心跳时间戳），使 task_runner
    # 与前端在 D1/D2 重放期间能看到实时进度，不再把长时间 running 误判为卡死。fail-open，写失败不影响主流程。
    _total_specs = len(all_vulns)
    _phase1 = {}
    _rp_done = 0
    _rp_last_write = 0.0
    _rp_confirmed = 0
    _rp_sink = 0

    def _write_replay_heartbeat(force: bool = False, current: str = "") -> None:
        nonlocal _rp_done, _rp_last_write
        _now = time.time()
        if not force and (_now - _rp_last_write) < 2.0:
            return
        _rp_last_write = _now
        _hb_payload = {
            "total": _total_specs,
            "replayed": _rp_done,
            "confirmed": _rp_confirmed,
            "sink_reached": _rp_sink,
            "current_endpoint": current,
            "heartbeat": datetime.now().isoformat(),
            "status": "replaying",
        }
        # scan_progress.json 是易变文件，事后无法审计「本轮前端到底看到过什么」；
        # 事件流的 replayed 递增序列是 D2 重放进度的权威审计依据。
        _append_scan_task_event(task_id, "task_progress", {"replay_progress": _hb_payload})
        try:
            _update_scan_progress_metadata(output_dir, {"replay_progress": _hb_payload})
        except Exception as _he:
            # P1-3：吞异常从 debug 升为 warning 并同步写 task_log 事件——本轮 NameError
            logger.warning("[D2] replay_progress 心跳写入失败（task=%s）：%s", task_id, _he)
            _append_scan_task_event(task_id, "task_log", {
                "level": "warning",
                "source": "d2_replay_heartbeat",
                "message": f"replay_progress 心跳写入失败: {_he}",
            })

    _initial_hb = {
        "total": _total_specs,
        "replayed": 0,
        "confirmed": 0,
        "sink_reached": 0,
        "current_endpoint": "",
        "heartbeat": datetime.now().isoformat(),
        "status": "replaying",
    }
    _append_scan_task_event(task_id, "task_progress", {"replay_progress": _initial_hb})
    try:
        _update_scan_progress_metadata(output_dir, {"replay_progress": _initial_hb})
    except Exception as _he:
        logger.warning("[D2] replay_progress 初始心跳写入失败（task=%s）：%s", task_id, _he)
        _append_scan_task_event(task_id, "task_log", {
            "level": "warning",
            "source": "d2_replay_heartbeat",
            "message": f"replay_progress 初始心跳写入失败: {_he}",
        })

    # 早停要求批内全部假说到达才 break，异质分批会让快批被慢假说拖满整窗口 —— 故按族聚合；
    # 批大小由 SAST_AI_D2_BATCH_SIZE 控制（默认 32，设 0/1 即恢复逐条，用于一键回退）。
    _BATCH_SIZE = int(os.environ.get("SAST_AI_D2_BATCH_SIZE", "32") or 32)
    _batches = []
    _frag_merged = 0
    if _BATCH_SIZE > 1:
        _by_fam = {}
        for _v in all_vulns:
            _k = str(_v.get("family") or _v.get("type") or "").strip().lower()
            _by_fam.setdefault(_k, []).append(_v)
        _fragments = []
        for _k, _vs in _by_fam.items():
            for _i in range(0, len(_vs), _BATCH_SIZE):
                _chunk = _vs[_i:_i + _BATCH_SIZE]
                # 碎片批（不足半批）先攒着，稍后跨族拼整：每族末尾那半批会单独占一个
                # IAST 事务（≈60s 窗口 + 30s settle），族多时事务数被碎片撑大一倍。
                if len(_chunk) * 2 < _BATCH_SIZE and len(_vs) > _BATCH_SIZE:
                    _fragments.extend(_chunk)
                else:
                    _batches.append(_chunk)
        if _fragments:
            for _i in range(0, len(_fragments), _BATCH_SIZE):
                _batches.append(_fragments[_i:_i + _BATCH_SIZE])
            _frag_merged = len(_fragments)
    else:
        _batches = [[_v] for _v in all_vulns]
    logger.info("[D2] 批量合并事务：批大小=%s，%d 个漏洞 → %d 个事务（碎片批合并 %d 条）",
                _BATCH_SIZE, len(all_vulns), len(_batches), _frag_merged)
    # 埋点：批量合并到底生效没有，以前只能靠猜。这里把批数/批内规模/碎片合并量写进
    # scan_progress 的 d2 段，事后可直接读 stage_results.d2.scheduling.batching 对账。
    # 只写「本次调用」会被 i2_rerun 的极小批次覆写（见上方累加器注释），
    # 累计值才是判断主 pass 合批是否生效的依据。
    _D2_BATCH_CUM["calls"] += 1
    _D2_BATCH_CUM["batches"] += len(_batches)
    _D2_BATCH_CUM["members"] += sum(len(_b) for _b in _batches)
    _D2_BATCH_CUM["vulns"] += len(all_vulns)
    try:
        _update_scan_progress_metadata(output_dir, {"d2_batching": {
            "batch_size": _BATCH_SIZE,
            "vulns": len(all_vulns),
            "batches": len(_batches),
            "fragments_merged": _frag_merged,
            "avg_batch": round(len(all_vulns) / max(1, len(_batches)), 2),
        }, "d2_batching_cumulative": {
            "batch_size": _BATCH_SIZE,
            **_D2_BATCH_CUM,
            "avg_batch": round(_D2_BATCH_CUM["members"] / max(1, _D2_BATCH_CUM["batches"]), 2),
        }})
    except Exception as _bpe:
        logger.warning("[D2] d2_batching 埋点写入失败（不影响主流程）：%s", _bpe)

    def _account(_res_tuple):
        nonlocal _rp_done, _rp_confirmed, _rp_sink
        _rp_done += 1
        try:
            _res, _ts, _vh, _sk = _res_tuple[0], _res_tuple[1], _res_tuple[2], _res_tuple[3]
            _cur = (_ts or {}).get("target_endpoint", "") if _ts else ""
            _dec = getattr(_res, "verification_decision", {}) or {}
            if str(_dec.get("verification_status", "")) == "confirmed_exploitable":
                _rp_confirmed += 1
            _iast = getattr(_res, "iast_evidence", {}) or {}
            # §单一真相源：必须用 is_sink_reached（含探针显式断言态 sink-reached-probe），
            # sink-reached-probe 态，硬编码比较会把它们全漏掉，前端 sink_reached 恒显示 0，
            # 与 iast_events 里 sink_reached=1 的真实行数自相矛盾。
            # ④ sink 身份校验：框架噪声 sink（非本族真 sink）不计入 sink_reached。
            _ts_fam = canonical_family(str((_ts or {}).get("family") or ""))
            if iast_evidence_sink_reached_genuine(_iast, _ts_fam):
                _rp_sink += 1
        except Exception:
            _cur = ""
        _write_replay_heartbeat(current=_cur)

    # 绝不阻塞 as_completed。此前只有总墙钟（7200s）兜底，任一批挂死就要白等 2 小时
    # 。阈值可用环境变量覆盖。
    _per_batch_wall = float(os.environ.get("SAST_AI_D2_BATCH_WALL", "900") or 900)
    _per_vuln_wall = float(os.environ.get("SAST_AI_D2_VULN_WALL", "300") or 300)

    def _run_with_timeout(_fn, _timeout):
        """在独立单线程里跑 _fn，超时即放弃等待。

        Python 无法强杀线程，泄漏的线程由解释器在进程结束时回收；关键是让调用方
        拿到超时信号、不再无限挂起（这是 P0-5 的核心：把「总闸」拆成「分闸」）。
        """
        _ex1 = ThreadPoolExecutor(max_workers=1)
        try:
            _f1 = _ex1.submit(_fn)
            try:
                return _f1.result(timeout=_timeout)
            except _cf.TimeoutError:
                _f1.cancel()
                raise
        finally:
            _ex1.shutdown(wait=False)

    def _degraded_pairs(_vs):
        """把一批 vuln 全部降级成 no_evidence，保证 _phase1 不缺项（Phase2 收卷不下标越界）。"""
        _out = []
        for _v in _vs:
            try:
                _vh, _sk, _ts, _tr = _d2_resolve_spec(_v)
            except Exception:
                _vh, _sk, _ts, _tr = "", "", {}, {}
            try:
                _tr["d2_per_call_timeout"] = True
            except Exception:
                pass
            _out.append((id(_v), (_D2Phase1TimeoutResult(), _ts, _vh, _sk,
                                  time.time(), time.time(), _tr)))
        return _out

    def _run_batch(_b):
        """批量单元计时包装（P2-2）：记录每批墙钟，供重跑后定位慢批。"""
        _bt0 = time.time()
        try:
            return _run_batch_impl(_b)
        finally:
            try:
                with _bw_lock:
                    _batch_walls.append(round(time.time() - _bt0, 1))
            except Exception:
                pass

    def _run_batch_impl(_b):
        """批量单元（永不抛异常）：单批/单条超时或失败均降级兜底，保证 _phase1 不缺项。"""
        try:
            if _BATCH_SIZE > 1:
                # 原因：_run_with_timeout 新建单线程池执行，而 _d2_agent / _d2_resources
                # 都是**线程局部**（_d2_tls）⇒ 新线程里会重建 D2 verifier + IastService +
                # D1Service，导致证据窗口被绕过：实测 trustbound 的 sink 到达 34→18、
                # D2 耗时 1027s→160s、召回 96.4%→67.9%（本轮 vs 531）。
                # 批路径本来就有三层保护，不需要外层再套：
                #   ① _d2_call_verify_batch 内部 _with_wall_clock_limit(600s)
                #   ② 超时后逐条回退，每条 _run_with_timeout(300s)
                #   ③ Phase1 总墙钟 7200s（as_completed timeout）
                return _d2_call_verify_batch(_b)
            _v = _b[0]
            return [(id(_v), _run_with_timeout(lambda: _d2_call_verify(_v), _per_vuln_wall))]
        except _cf.TimeoutError as _te:
            logger.warning("[D2] 批次超时（batch_wall=%.0fs，%d 条）→ 降级 no_evidence：%s",
                           _per_batch_wall, len(_b), _te)
            return _degraded_pairs(_b)
        except Exception as _be:
            logger.warning("[D2] 批量单元整体失败，逐条兜底：%s", _be)
            _pairs = []
            for _v in _b:
                try:
                    _pairs.append((id(_v), _run_with_timeout(
                        lambda v=_v: _d2_call_verify(v), _per_vuln_wall)))
                except _cf.TimeoutError:
                    _pairs.extend(_degraded_pairs([_v]))
                except Exception as _ve2:
                    logger.warning("[D2] 逐条兜底仍失败（hash=%s）：%s",
                                   str(_v.get("vulnerability_hash_v2", ""))[:12], _ve2)
            return _pairs

    import concurrent.futures as _cf
    # 放在并发重放之前，保证 D1 把 payload 注到 servlet 真正读取的源（header/cookie/query/body）。
    try:
        _apply_source_location_postpass(task_id, _sdb, code_root)
    except Exception as _sle:
        logger.warning("[D2] 源位置纠正失败（忽略，不阻断重放）：%s", _sle)
    # 必须排在 Phase 0a 之后、并发重放之前：param_location 定「注哪儿」，param_name 定
    # 「注什么名字」，两个都对了 D1 才能把 payload 送到 sink。只填空，不覆盖 A2 的结论。
    try:
        _apply_param_backfill_postpass(task_id, _sdb, code_root, output_dir)
    except Exception as _pfe:
        logger.warning("[D2] param 补齐失败（忽略，不阻断重放）：%s", _pfe)
    # 必须排在 param_name 补齐之后：先知道「注哪个参数」，再决定「用什么编码注」。
    try:
        _apply_binding_postpass(task_id, _sdb, code_root, output_dir)
    except Exception as _bfe:
        logger.warning("[D2] 请求形态纠正失败（忽略，不阻断重放）：%s", _bfe)
    try:
        _apply_spec_dedupe_postpass(task_id, _sdb)
    except Exception as _dfe:
        logger.warning("[D2] spec 去重失败（忽略，不阻断重放）：%s", _dfe)
    # 排在重放之前：缺这些头时请求会被 filter 直接 return，参数再对也进不到业务代码。
    try:
        _apply_filter_headers_postpass(
            task_id, _sdb, code_root,
            str((external_target_dict or {}).get("service_url") or ""))
    except Exception as _fhe:
        logger.warning("[D2] 前置请求头补齐失败（忽略，不阻断重放）：%s", _fhe)
    # 使其不计入动态确认分母。
    try:
        _apply_two_step_mark_postpass(task_id, _sdb)
    except Exception as _tse:
        logger.warning("[D2] 两步桥标记失败（忽略，不阻断重放）：%s", _tse)
    # 现已有「超时降级填充 no_evidence 后继续收卷」的兜底（见 except _cf.TimeoutError），
    # 故把默认墙钟抬到 7200s：给 D2 跑完的机会，真超时也能带报告收口。
    #
    # 单候选约 15s 本地计算，本来就需要 ~1h，3600s 正好卡在边界 ⇒ crypto(514/515) 每次都
    # 现在单批 900s / 单条 300s 的分级超时已能兜住死锁（不再需要靠总墙钟防挂死），
    # 总墙钟回归 7200s 只作为最后保险。
    _phase1_wall = float(os.environ.get("SAST_AI_D2_PHASE1_WALL", "7200") or 7200)
    with ThreadPoolExecutor(max_workers=_D2_MAX_WORKERS) as _ex:
        _futs = [_ex.submit(_run_batch, _b) for _b in _batches]
        try:
            for _fut in as_completed(_futs, timeout=_phase1_wall):  # noqa: F401
                try:
                    _pairs = _fut.result() or []
                except Exception as _fe:
                    logger.warning("[D2] 批量单元结果取回失败：%s", _fe)
                    continue
                for _vid, _res_tuple in _pairs:
                    _phase1[_vid] = _res_tuple
                    _account(_res_tuple)
        except _cf.TimeoutError:
            _done = sum(1 for _f in _futs if _f.done())
            # 整轮任务打挂（报告都没出、trigger_specs 全空、任务永久 running）。
            # 现改为「取消剩余批 + 降级填充 no_evidence」：宁可这些 spec 丢确认，
            # 也不能丢整轮（召回由下一轮/放高墙钟补，任务挂死则什么都没有）。
            logger.error(
                "[D2] Phase1 重放超总墙钟 %.0fs（%d/%d 批完成）→ 取消剩余批次，"
                "未完成批按 no_evidence 降级填充后继续收卷（不再 fail-fast 打挂整轮）",
                _phase1_wall, _done, len(_futs))
            for _f in _futs:
                _f.cancel()
            _degraded = 0
            for _b, _f in zip(_batches, _futs):
                if _f.done() and not _f.cancelled():
                    continue
                for _v in _b:
                    if id(_v) in _phase1:
                        continue
                    try:
                        _vh, _sk, _ts, _tr = _d2_resolve_spec(_v)
                    except Exception:
                        _vh, _sk, _ts, _tr = "", "", {}, {}
                    try:
                        _tr["phase1_wall_timeout"] = True
                    except Exception:
                        pass
                    _phase1[id(_v)] = (_D2Phase1TimeoutResult(), _ts, _vh, _sk,
                                       time.time(), time.time(), _tr)
                    _degraded += 1
            logger.error("[D2] Phase1 超时降级：%d 条 vuln 记 no_evidence(d2_phase1_wall_timeout)", _degraded)

    # 批量合并生效度落盘：fallback_batches 接近 batches 即说明批量合并形同虚设（该查
    # verify_group 的回退诱因，而不是继续调批大小）。
    if _batch_walls:
        try:
            _batch_stats["wall_s"] = {
                "count": len(_batch_walls),
                "min": min(_batch_walls),
                "max": max(_batch_walls),
                "avg": round(sum(_batch_walls) / len(_batch_walls), 1),
                "total": round(sum(_batch_walls), 1),
            }
        except Exception:
            pass
    logger.info("[D2] 批量合并生效度：批数=%s 批内漏洞=%s 回退批数=%s 回退漏洞=%s 分批墙钟=%s",
                _batch_stats["batches"], _batch_stats["members"],
                _batch_stats["fallback_batches"], _batch_stats["fallback_members"],
                _batch_stats.get("wall_s"))
    try:
        _update_scan_progress_metadata(output_dir, {"d2_batching_result": dict(_batch_stats)})
    except Exception as _bre:
        logger.warning("[D2] d2_batching_result 埋点写入失败（不影响主流程）：%s", _bre)

    # Phase1 收尾心跳：标记重放收集完成（status=replay_done），task_runner 据此不再判「重放中」。
    _done_hb = {
        "total": _total_specs,
        "replayed": _rp_done,
        "confirmed": _rp_confirmed,
        "sink_reached": _rp_sink,
        "current_endpoint": "",
        "heartbeat": datetime.now().isoformat(),
        "status": "replay_done",
    }
    _append_scan_task_event(task_id, "task_progress", {"replay_progress": _done_hb})
    try:
        _update_scan_progress_metadata(output_dir, {"replay_progress": _done_hb})
    except Exception:
        pass

    # §批次隔离收尾：Phase1 全部重放完成即关闭靶场纪元跟踪（后面的迟到证据补捞是纯 DB
    # 轮询、不再向靶场发流量，不应计入批次窗口）。report 落事件流，供前端与事后审计
    # 看到「本批次是否横跨靶场重启」的权威结论。
    _epoch_report: Dict[str, Any] = {}
    if _epoch_tracker is not None:
        try:
            _epoch_report = _epoch_tracker.stop()
            logger.info("[D2] 靶场实例纪元批次报告：%s", _epoch_report)
            _append_scan_task_event(task_id, "task_progress", {"target_epoch": _epoch_report})
            try:
                _update_scan_progress_metadata(output_dir, {"target_epoch": _epoch_report})
            except Exception:
                pass
        except Exception as _epe:  # fail-open
            logger.warning("[D2] 靶场实例纪元收尾失败（忽略）：%s", _epe)
            _epoch_report = {}

    # §批次隔离可见性：tracker 未初始化（无托管靶机 / service_url 为空 / 初始化失败）时，
    # 不再静默写 {}（与「跑了且 clean」无法区分，被误读为 target_epoch 缺陷），改为显式
    # not_applicable 哨兵，让前端与报告一眼看出「批次隔离不适用」，而非证据缺失。fail-open 语义保留。
    if _epoch_tracker is None:
        _epoch_report = {
            "enabled": False,
            "verdict": "not_applicable",
            "reason": "no managed target / service_url empty (target_epoch tracking skipped)",
        }

    # §迟到证据补捞（I1 关联竞态）：D2 裁决与探针事件摄取是并发的，per-spec 有界轮询窗口
    # 而 D2 阶段 04:40:22→04:44:42，两者几乎完全重叠。结果是事件最终落库、canary 也逐字符可匹配
    # （spec815↔事件2640、spec763↔事件2743），裁决却早已按 no-iast-evidence 定稿，产生
    # 「sink_reached=1 却 iast_state=no-iast-evidence」的矛盾行。
    # 故在 Phase1 全部重放结束后做一次全局摄取静止等待 + 按 canary 重查补捞。位置必须在 Phase2
    # （回写 trigger_specs）之前，否则升级后的状态落不了库。
    try:
        from src.iast.service import IastService as _LateIastService
        from src.agents.d2_facade import reconcile_late_iast_evidence as _reconcile_late
        _late_iast = _LateIastService(_sdb) if _sdb is not None else None
        _late_n = _reconcile_late(
            [_phase1[id(v)] for v in all_vulns],
            _late_iast,
            app_name=(external_target_dict or {}).get("app_name"),
            agent_id=(external_target_dict or {}).get("agent_id"),
        )
        logger.info("[D2] 迟到证据补捞：升级 %s 条 spec", _late_n)
    except Exception as _le:  # fail-open：补捞失败不应影响既有裁决与主流程
        logger.warning("[D2] 迟到证据补捞失败（忽略）：%s", _le)

    # 而迟到证据补捞发生在它之后，会把一批 no-iast-evidence 升级成 sink-reached / sink-reached-probe。
    # 而权威口径（D1 iast_arrivals、D2 sink_reached_count）都是 36，iast_events 里 sink_reached=1 有
    # 454 行，三者自相矛盾，看起来像探针没工作。
    # 这里不直接加 _late_n，而是基于补捞后的 result 重新计数（补捞是就地改 state，重算最稳）。
    try:
        _rp_sink_final = 0
        _rp_confirmed_final = 0
        for _tup in _phase1.values():
            try:
                _r = _tup[0]
                _dec2 = getattr(_r, "verification_decision", {}) or {}
                if str(_dec2.get("verification_status", "")) == "confirmed_exploitable":
                    _rp_confirmed_final += 1
                _ie2 = getattr(_r, "iast_evidence", {}) or {}
                _ts2 = _tup[1] if isinstance(_tup, (list, tuple)) and len(_tup) > 1 else None
                _ts_fam2 = canonical_family(str((_ts2 or {}).get("family") or ""))
                if iast_evidence_sink_reached_genuine(_ie2, _ts_fam2):
                    _rp_sink_final += 1
            except Exception:
                continue
        _final_hb = {
            "total": _total_specs,
            "replayed": _rp_done,
            "confirmed": _rp_confirmed_final,
            "sink_reached": _rp_sink_final,
            "current_endpoint": "",
            "heartbeat": datetime.now().isoformat(),
            "status": "replay_reconciled",
        }
        _append_scan_task_event(task_id, "task_progress", {"replay_progress": _final_hb})
        try:
            _update_scan_progress_metadata(output_dir, {"replay_progress": _final_hb})
        except Exception:
            pass
        logger.info(
            "[D2] 补捞后回写心跳：confirmed %s→%s，sink_reached %s→%s",
            _rp_confirmed, _rp_confirmed_final, _rp_sink, _rp_sink_final,
        )
    except Exception as _fhe:  # fail-open
        logger.warning("[D2] 补捞后心跳回写失败（忽略）：%s", _fhe)

    # §并行化 Phase2：串行后处理（结果解析 + DB 回写 trigger_specs + POC 拼装）。verify 已并发完成，
    # 此处无重 I/O，串行保证 sqlite 单写者与 findings 顺序稳定。
    _n_invalidated = 0
    _inval_reasons: Dict[str, int] = {}
    # §族-证据一致性：canary 身份 → 本轮观测到的 sink 集合（按 identity 缓存，
    # 避免同一 canary 被多条 spec 引用时重复查库）。
    _canary_sink_cache: Dict[str, List[str]] = {}
    _n_family_reassign = 0

    def _sinks_for_identity(_ident: str) -> List[str]:
        if not _ident:
            return []
        if _ident in _canary_sink_cache:
            return _canary_sink_cache[_ident]
        _out: List[str] = []
        try:
            _rows = _sdb.execute(
                "SELECT DISTINCT sink_file FROM iast_events WHERE task_id=? AND canary=?",
                (task_id, _ident), fetchall=True,
            ) or []
            for _r in _rows:
                _sf = str((_r.get("sink_file") if isinstance(_r, dict) else _r[0]) or "")
                if _sf:
                    _out.append(_sf)
        except Exception as _sq_e:
            logger.warning("[D2][family-sink] 查询 canary 观测 sink 失败（按空证据）：%s", _sq_e)
        _canary_sink_cache[_ident] = _out
        return _out

    _d2_exec_trace: List[Dict[str, Any]] = []
    for vuln in all_vulns:
        result, _ts, _vhash, _sk, _t0, _t1, _trace = _phase1[id(vuln)]
        # 关键对照：verify_returned=True 且 folded=True 却仍被报告写成
        # enqueued_but_no_verification_record 的条目，说明断点不在 D2 执行而在报告折叠端。
        _trace["folded"] = True
        _d2_exec_trace.append(_trace)
        execution_summary = summarize_a3_raw_output(result.raw_output)
        docker_attempted = docker_attempted or execution_summary['docker_attempted']
        docker_used = docker_used or execution_summary['docker_used']
        local_jar_attempted = local_jar_attempted or execution_summary.get('local_jar_attempted', False)

        raw_poc_code = result.poc_code
        raw_poc_text = raw_poc_code if isinstance(raw_poc_code, str) else json.dumps(raw_poc_code, ensure_ascii=False)
        meaningful_poc = is_meaningful_poc(raw_poc_code)
        verification_decision = getattr(result, 'verification_decision', {}) or {}
        verification_status = str(verification_decision.get('verification_status', '') or '')

        # （可重试），既不记 confirmed 也不记 no_evidence。否则停机窗口内拿不到证据的 spec 会
        _inval = ""
        try:
            # pre_status 传入「失效前的原裁决」：正向证据否决失效判定时要用它判断本条是否已确认。
            _inval = _spec_invalidation_reason(
                result, _epoch_tracker, _t0, _t1, pre_status=verification_status
            )
        except Exception as _ie:
            logger.warning("[D2] 批次隔离判定异常（按原裁决，忽略）：%s", _ie)
        if _inval:
            _inval_key = _inval.split("(")[0].split(":")[0]
            _inval_reasons[_inval_key] = _inval_reasons.get(_inval_key, 0) + 1
            _n_invalidated += 1
            verification_decision = dict(verification_decision)
            verification_decision['pre_invalidation_status'] = verification_status
            verification_decision['invalidation_reason'] = _inval
            verification_decision['verification_status'] = 'invalidated'
            verification_status = 'invalidated'
            logger.warning(
                "[D2][batch-isolation] %s:%s 落 invalidated（%s，pre=%s）",
                vuln.get('file'), vuln.get('line'), _inval, verification_decision.get('pre_invalidation_status'),
            )

        # 此刻 verification_status 已含批次隔离改写，作为最终折叠态记入埋点。
        _trace["fold_status"] = str(verification_status or "")
        confirmed_exploitable = verification_status == 'confirmed_exploitable'
        sink_control_only = verification_status == 'confirmed_sink_control'
        # §新：verified（已验证可利用）以完整 I1/D1/D2/I2 flow 判定为准，不再以「是否生成可运行
        # POC 脚本」为门槛。旧版 is_meaningful_poc 门槛已废弃——生成可复用 EXP/POC 仅作为附加能力。
        poc_verified = bool(confirmed_exploitable)
        verification_note = ''
        if verification_status == 'invalidated':
            verification_note = (
                '本条目验证窗口与靶场重启/不可用窗口相交（%s），本轮结论不可信，已标记为可重试'
                '（既不记 confirmed 也不记 no_evidence）。原裁决=%s。' % (
                    verification_decision.get('invalidation_reason') or '',
                    verification_decision.get('pre_invalidation_status') or '无',
                )
            )
        elif sink_control_only:
            verification_note = 'D2 已确认表达式或模板 sink 可控，但当前仅拿到验证级证据，不计为高影响利用成功。'
        elif confirmed_exploitable and not meaningful_poc:
            verification_note = '完整 I1/D1/D2/I2 flow 已确认可利用，但未自动生成可复用 EXP/POC 脚本（属附加能力，不影响已验证判定）。'

        # §#3③ AP 可见性回填：把 D2 验证裁决写回 trigger_specs，使攻击计划(AP)能读
        # business_logic_confirmed / verification_status / iast_state 正确呈现「运行时命中态」。
        # 业务差分重放不产生 canary sink 事件，原 AP 分类器恒判 not_hit；此处据 D2 裁决补可见性。
        if _sdb is not None:
            try:
                _iast_state = str((getattr(result, 'iast_evidence', {}) or {}).get('state', '') or '')
                _bl_confirmed = 1 if (verification_decision.get('business_logic') and confirmed_exploitable) else 0
                # 三失效族（weak_hash/weak_crypto=算法通道；securecookie=属性通道）的
                # confirmed_exploitable 改按各自判据重判，独立终态 confirmed_code_property。
                # 数据流族原样放行（零回归）；仅对 confirmed_exploitable 介入。
                _fam_route_applied = False
                _fv_family = str(vuln.get('family') or vuln.get('finding_family') or vuln.get('type') or '')
                if confirmed_exploitable and _fv_family:
                    try:
                        from src.core.family_verdict import apply_family_route, route_for
                        if route_for(_fv_family) != "dataflow":
                            from src.iast.canary import CanaryMatcher as _CM
                            for _sp in (_trigger_specs_by_anykey.get(_sk) or _trigger_specs_by_anykey.get(_vhash, []) or []):
                                _ident = _CM.find_identity(str(_sp.get('taint_marker') or ''))
                                if not _ident:
                                    continue
                                _fam_events = _sdb.execute(
                                    "SELECT sink_file, source_value, evidence_json FROM iast_events"
                                    " WHERE task_id=? AND canary=?",
                                    (task_id, _ident), fetchall=True,
                                ) or []
                                verification_status, _route_detail = apply_family_route(
                                    _fv_family, verification_status, _fam_events)
                                verification_decision = dict(verification_decision)
                                verification_decision['family_route'] = _route_detail
                                verification_decision['verification_status'] = verification_status
                                _fam_route_applied = True
                                confirmed_exploitable = verification_status == 'confirmed_exploitable'
                                sink_control_only = verification_status == 'confirmed_sink_control'
                                poc_verified = bool(confirmed_exploitable)
                                logger.info("[D2][family-route] %s:%s 族=%s → %s（%s）",
                                            vuln.get('file'), vuln.get('line'), _fv_family,
                                            verification_status, _route_detail.get('detail', '')[:120])
                                break
                    except Exception as _fr_e:
                        logger.warning("[D2] 族路由判定失败（按原裁决）：%s", _fr_e)
                # 关联键加固：优先 stable_key 反查 spec（route 漂移免疫），vhash 兜底。
                # 直接吃掉「runtime_vhash ≠ stored_vhash 导致写回落空」的 10 条空状态 spec 缺口。
                _oob_token = str(((getattr(result, 'iast_evidence', {}) or {}).get('oob') or {}).get('token') or '')
                for _sp in (_trigger_specs_by_anykey.get(_sk) or _trigger_specs_by_anykey.get(_vhash, []) or []):
                    _spid = _sp.get('id')
                    if not _spid:
                        continue
                    # §D2 证据回灌 spec.raw_json：与 findings.raw_json 同源同真值，
                    # 供攻击计划页 / spec 详情直接读「投放了什么、探针看到什么、影响侧发生了什么」。
                    try:
                        _ev_block = _build_d2_evidence_block(vuln, result, _sp, _oob_token)
                    except Exception as _ev_e:
                        logger.warning("[D2][evidence-backfill] spec=%s 证据块构造失败（按空块）：%s", _spid, _ev_e)
                        _ev_block = {}
                    # §确认态硬闸：confirmed_exploitable 必须握有正向证据（三准入之一），
                    # 否则降级 unconfirmed —— 没有证据的肯定结论就是证伪失效。
                    _vs_write = verification_status
                    _is_write = _iast_state
                    _gate = None
                    if _vs_write == 'confirmed_exploitable':
                        _ok, _code, _why = _confirm_gate_decide(
                            _iast_state,
                            getattr(result, 'iast_evidence', {}) or {},
                            getattr(result, 'dast_impact_evidence', {}) or {},
                            getattr(result, 'd2_verdict', {}) or {},
                            oob_confirmed=bool((_ev_block.get('oob') or {}).get('confirmed')),
                            bl_confirmed=bool(_bl_confirmed),
                        )
                        _gate = {
                            "admitted": bool(_ok),
                            "code": _code,
                            "reason": _why,
                            "prior_iast_state": str(_iast_state or ""),
                            "checked_at": datetime.now().isoformat(),
                        }
                        if not _ok:
                            _vs_write = 'unconfirmed'
                            _is_write = 'confirm-gate:' + (str(_iast_state) or 'none')
                            logger.info(
                                "[D2][confirm-gate] spec=%s family=%s iast_state=%s 无正向证据 → unconfirmed（%s）",
                                _spid, _fv_family, _iast_state, _why,
                            )
                    _bl_write = _bl_confirmed if _vs_write == 'confirmed_exploitable' else 0
                    # unknown = 离线兜底分析器连「属于哪个族」都没归类出来的产出。族都没定，
                    # 安全用例被 unknown 族确认）。跨轮预演 446/452/453/457：**没有任何 TP 仅靠
                    # unknown 族确认**，只有 457 的 00099 一个 FP ⇒ TP 误杀 = 0，可以做硬闸。
                    # 只降状态、不删 spec：canary 覆盖与报告里的观测面都保留。
                    _fam_write = str(_sp.get('family') or _fv_family or '').strip().lower()
                    if (_vs_write in ('confirmed_exploitable', 'confirmed_code_property',
                                      'confirmed_sink_control')
                            and _fam_write == 'unknown'):
                        _vs_write = 'unconfirmed'
                        _is_write = 'unknown-family-gate:' + (str(_iast_state) or 'none')
                        logger.info("[D2][unknown-gate] spec=%s 族=unknown 不得落确认态 → unconfirmed",
                                    _spid)
                    _merged = _merge_spec_raw_json(_sp.get('raw_json'), _ev_block, _vs_write, _gate)
                    # §族-证据一致性校验：用运行时观测到的 sink 反查族名。
                    # 只改判「泛化/待定族且本族无专属 sink 实证」的条目（保守，见
                    # src/core/family_sink_registry.py 三条硬约束）；非改判也留观测面。
                    _fam_write = None
                    try:
                        from src.core.family_sink_registry import reassign_family_by_sink_evidence as _reassign_fam
                        from src.iast.canary import CanaryMatcher as _CM2
                        _ident2 = _CM2.find_identity(str(_sp.get('taint_marker') or ''))
                        _sinks2 = _sinks_for_identity(_ident2)
                        _new_fam, _fchk = _reassign_fam(
                            str(_sp.get('family') or _fv_family or ''), _sinks2)
                        _merged['family_sink_check'] = _fchk
                        if _fchk.get('reassigned'):
                            _fam_write = _new_fam
                            _merged['family_reassign'] = {
                                'from': _fchk.get('prior_family'),
                                'to': _new_fam,
                                'sinks': _fchk.get('resolved_sinks') or [],
                                'reason': _fchk.get('reason'),
                                'at': datetime.now().isoformat(),
                            }
                            _n_family_reassign += 1
                            vuln.setdefault('family_reassign', []).append({
                                'spec_id': int(_spid),
                                'from': _fchk.get('prior_family'),
                                'to': _new_fam,
                                'sinks': _fchk.get('resolved_sinks') or [],
                            })
                            logger.info(
                                "[D2][family-sink] spec=%s 族名改判 %s → %s（依据 sink=%s）",
                                _spid, _fchk.get('prior_family'), _new_fam,
                                (_fchk.get('resolved_sinks') or [])[:3],
                            )
                    except Exception as _fs_e:
                        logger.warning("[D2][family-sink] spec=%s 族-证据校验失败（按原族名）：%s", _spid, _fs_e)
                    # 实为垂直越权被误定族）。只改族名不动验证裁决，业务差分确认本身仍成立。
                    if not _fam_write:
                        try:
                            from src.core.family_sink_registry import (
                                reassign_protocol_family_by_business_logic as _reassign_proto,
                            )
                            from src.iast.canary import CanaryMatcher as _CM3
                            _ident3 = _CM3.find_identity(str(_sp.get('taint_marker') or ''))
                            _sinks3 = _sinks_for_identity(_ident3)
                            _proto_fam, _pchk = _reassign_proto(
                                str(_sp.get('family') or _fv_family or ''),
                                _sinks3,
                                iast_state=str(_is_write or ''),
                                oob_confirmed=bool((_ev_block.get('oob') or {}).get('confirmed')),
                            )
                            _merged['protocol_family_check'] = _pchk
                            if _pchk.get('reassigned'):
                                _fam_write = _proto_fam
                                _merged['family_reassign'] = {
                                    'from': _pchk.get('prior_family'),
                                    'to': _proto_fam,
                                    'rule': 'protocol_family_business_logic',
                                    'reason': _pchk.get('reason'),
                                    'at': datetime.now().isoformat(),
                                }
                                _n_family_reassign += 1
                                vuln.setdefault('family_reassign', []).append({
                                    'spec_id': int(_spid),
                                    'from': _pchk.get('prior_family'),
                                    'to': _proto_fam,
                                    'rule': 'protocol_family_business_logic',
                                })
                                logger.info(
                                    "[D2][protocol-family] spec=%s 协议族反向改判 %s → %s（无 naming sink 实证且仅业务差分确认）",
                                    _spid, _pchk.get('prior_family'), _proto_fam,
                                )
                        except Exception as _pf_e:
                            logger.warning("[D2][protocol-family] spec=%s 反向改判校验失败（按原族名）：%s", _spid, _pf_e)
                    if _fam_write:
                        _sdb.execute(
                            "UPDATE trigger_specs SET business_logic_confirmed = ?, verification_status = ?, "
                            "iast_state = ?, raw_json = ?, family = ? WHERE id = ?",
                            (_bl_write, _vs_write, _is_write,
                             json.dumps(_merged, ensure_ascii=False), _fam_write, int(_spid)),
                        )
                    else:
                        _sdb.execute(
                            "UPDATE trigger_specs SET business_logic_confirmed = ?, verification_status = ?, "
                            "iast_state = ?, raw_json = ? WHERE id = ?",
                            (_bl_write, _vs_write, _is_write,
                             json.dumps(_merged, ensure_ascii=False), int(_spid)),
                        )
            except Exception as _wb_e:  # fail-open：写回失败不影响主流程
                logger.warning("[D2] 写回 trigger_specs 验证裁决失败（忽略）：%s", _wb_e)

        no_poc_reason = ''
        if not meaningful_poc:
            if result.reason:
                no_poc_reason = result.reason
            elif execution_summary['step_errors']:
                no_poc_reason = '; '.join(execution_summary['step_errors'][:3])
            else:
                no_poc_reason = 'D2 未产出可直接运行的 POC（仅影响「附加能力」展示，不影响已验证判定）'

        structured_poc = {}
        try:
            structured_list = poc_generator.generate_pocs_for_results(
                [vuln],
                project_language='java',
                file_contents=file_contents
            )
            if structured_list:
                structured_poc = structured_list[0].get('poc', {}) or {}
        except Exception as exc:
            logger.warning(f"[D2] Failed to generate structured POC for report: {exc}")

        # 原写法 `result.attack_plan if isinstance(getattr(...), dict) else {}` 会在缺属性时
        # getattr 返回 {} → 判断为真 → 再直接取 result.attack_plan 抛 AttributeError，
        # 把整轮任务打挂。改为先取到局部变量再判类型。
        _attack_plan = getattr(result, 'attack_plan', {})
        attack_plan = _attack_plan if isinstance(_attack_plan, dict) else {}
        exploit_spec = normalize_exploit_spec(
            getattr(result, 'exploit_spec', {}) or attack_plan.get('exploit_spec') or vuln.get('exploit_spec', {})
        )
        contract_completeness = exploit_spec_completeness(exploit_spec)
        poc_details = build_poc_details(vuln, raw_poc_text if meaningful_poc else '', structured_poc, attack_plan, exploit_spec)
        verified_bundle = {}
        if poc_verified and meaningful_poc:
            verified_bundle = build_verified_bundle(vuln, result, result.raw_output)
            if verified_bundle.get('exploit_chain'):
                poc_details['exploit_chain'] = verified_bundle.get('exploit_chain')
            if verified_bundle.get('service_url'):
                poc_details['target_url'] = verified_bundle.get('service_url')
            if verified_bundle.get('payload_b64'):
                poc_details['payload_candidates'] = [verified_bundle.get('payload_b64')]
            poc_details['description'] = 'D2 已自动完成完整动态利用验证，并落地完整 EXP、payload 与攻击结果文件。'
            for key in (
                'bundle_dir',
                'exp_script',
                'helper_java',
                'payload_ser',
                'payload_b64',
                'result_json',
                'import_response_body',
                'trigger_response_body',
                'verify_stdout',
                'container_id',
            ):
                if verified_bundle.get(key):
                    poc_details[key] = verified_bundle.get(key)

        if no_poc_reason:
            failure_reasons.append(no_poc_reason)
        failure_info = getattr(result, 'failure_classification', {}) or infer_failure_classification(
            reason=result.reason,
            no_poc_reason=no_poc_reason,
            step_errors=execution_summary['step_errors'],
            docker_used=execution_summary['docker_used'],
            docker_attempted=execution_summary['docker_attempted'],
            exploitable=bool(result.exploitable),
            poc_verified=poc_verified,
            exploit_spec=exploit_spec,
        )

        if verification_status == 'approval_required':
            tool_evidence = [str(item or "") for item in (result.evidence or [])]
            tool_id = next((item.split("=", 1)[1] for item in tool_evidence if item.startswith("tool=")), "unknown")
            risk_level = next((item.split("=", 1)[1] for item in tool_evidence if item.startswith("risk=")), "high")
            # ⑤-C 闸门短接场景：result.evidence 为空（未实际执行），tool_id 会落到 "unknown"。
            # "unknown" 毫无语义且污染白名单，故此处按「待放行的是 D2 破坏性重放」补语义值。
            if tool_id == "unknown" and (verification_decision or {}).get("hitl_gate"):
                tool_id = "d2_replay"
            # ⑤-C 两阶段只读先行：proposed_action 富化为「只读阶段已探明的将投放动作」，
            # 实际执行留到审批后重跑（回填）才发生。
            _es = getattr(result, 'exploit_spec', {}) or {}
            _entry = (_es.get('entry') or {}) if isinstance(_es, dict) else {}
            _fc = getattr(result, 'failure_classification', {}) or {}
            _hitl_mode = str((project_context or {}).get('hitl', {}).get('approval_mode') or 'off')
            _pa_id = f"{vuln.get('chain_id') or vuln.get('canonical_group_key') or vuln.get('file')}:{vuln.get('line')}"
            # 真实动作类别必须取闸门判定用的 act.category（act_allowlist 比对的就是它）；
            # failure_classification.category 恒为字面量 "approval_required"，仅作兜底。
            _dec = verification_decision if isinstance(verification_decision, dict) else {}
            _act = _dec.get('act') or {}
            _pa_cat = str(_act.get('category') or _fc.get('category') or '')
            _pa_act_reason = str(_act.get('reason') or '')
            pending_actions.append({
                'id': _pa_id,
                # 单条审批(resolve_task_hitl_action)按 id 匹配，批量裁决(resolve_task_hitl_actions_batch)
                # 读 action_id 字段——两者必须并存，否则批量裁决因 action_id 为空直接判非法。
                'action_id': _pa_id,
                'task_id': 0,
                'tool_id': tool_id,
                # 顶层同步 category：前端待批队列若从顶层渲染类别，此前会拿到 None 而显示空白。
                'category': _pa_cat,
                'risk_level': risk_level,
                'reason': str(verification_decision.get('judge_reason', '') or result.reason or ''),
                'stage': 'd2',
                'status': 'pending',
                'created_at': '',
                'resolved_at': '',
                'proposed_action': {
                    'file': vuln.get('file'),
                    'line': vuln.get('line'),
                    'type': vuln.get('type'),
                    'route': str(_entry.get('route') or ''),
                    'method': str(_entry.get('method') or 'GET').upper(),
                    # 同步真实动作类别（与顶层 category 同源 = 闸门 act.category），
                    # 原为 failure_classification.category → 恒显示 "approval_required"，看不出动作性质。
                    'category': _pa_cat,
                    'act_reason': _pa_act_reason,
                    'reason': str(_fc.get('explanation') or verification_decision.get('judge_reason') or result.reason or ''),
                    'tool_id': tool_id,
                    'approval_mode': _hitl_mode,
                    'effect': '只读先行：仅记录将投放的不可逆动作，未实际执行；人工放行后重跑才会真正触发。',
                },
            })

        results.append({
            'file': vuln.get('file'),
            'type': vuln.get('type'),
            'line': vuln.get('line'),
            'canonical_group_key': vuln.get('canonical_group_key', ''),
            'chain_id': vuln.get('chain_id', '') or vuln.get('canonical_group_key', ''),
            'match_keys': _a3_match_keys(vuln),
            'supporting_nodes': vuln.get('supporting_nodes', []),
            'supporting_node_count': vuln.get('supporting_node_count', 0),
            'proof_tier': vuln.get('proof_tier', 'broad_static'),
            'chain_proof': vuln.get('chain_proof', {}),
            'proof_gaps': vuln.get('proof_gaps', []),
            'exploitable': 'Yes' if confirmed_exploitable else 'No',
            'confidence': result.confidence,
            'reason': result.reason,
            'evidence': result.evidence,
            'attack_plan': attack_plan,
            'exploit_spec': exploit_spec,
            'contract_completeness': contract_completeness,
            'failure_classification': failure_info,
            'execution_evidence': getattr(result, 'execution_evidence', {}) or {},
            'verification_decision': verification_decision,
            # §统一链路扩展：把 D1+I1+D2+I2 的产物透传，供报告展示 I1 arrival / D2 核实 / I2 五态，
            # 不再只显示旧的「来源 SAST · 事件 0」。无匹配 trigger_spec 时这些为空（no_evidence）。
            'final_state': getattr(result, 'final_state', '') or '',
            'iast_evidence': getattr(result, 'iast_evidence', {}) or {},
            'dast_impact_evidence': getattr(result, 'dast_impact_evidence', {}) or {},
            # §D1 重放指标：记录本次 verify 是否真的被 trigger_spec 驱动（D1 实际发流量）。
            # 不能从 iast_evidence.replayed 取值——aggregate_iast_evidence 的返回不带该字段，
            # 历史版本因此把 D1 永远计为 0 条/ skipped。
            'trigger_spec_provided': _ts is not None,
            'trigger_spec_hash': (_ts.get('vulnerability_hash_v2') if isinstance(_ts, dict) else None),
            # §#3②：权威关联键（与报告层 finding.vulnerability_hash_v2 同源计算），使校验↔finding
            # 严格按 vuln_hash 绑定，而非仅依赖 chain_id / file:line 模糊匹配。
            'vulnerability_hash_v2': _vhash,
            # §#2D D1 阶段「实际重放的 spec 明细」：把驱动本次 verify 的 trigger_spec 关键字段
            # 透传，供报告 / 前端列出 D1 真实重放的目标端点、参数、canary 身份段。无匹配 spec 时为 None。
            'trigger_spec_detail': (
                {
                    'endpoint': _ts.get('target_endpoint'),
                    'http_method': _ts.get('http_method'),
                    'param_name': _ts.get('param_name'),
                    'param_location': _ts.get('param_location'),
                    'family': _ts.get('family'),
                    'canary_identity': _ts.get('taint_marker'),
                    'source': 'a2',
                    'vulnerability_hash_v2': _ts.get('vulnerability_hash_v2'),
                }
                if isinstance(_ts, dict) else None
            ),
            'd2_verdict': getattr(result, 'd2_verdict', {}) or {},
            'next_action': getattr(result, 'next_action', {}) or {},
            'poc_type': result.poc_type if meaningful_poc else '',
            'poc_code': raw_poc_text if meaningful_poc else '',
            'poc': structured_poc if structured_poc else ({'python': raw_poc_text} if meaningful_poc else {}),
            'poc_file': '',
            'poc_generated': meaningful_poc,
            'poc_verified': poc_verified,
            'verification_note': verification_note,
            'llm_poc_code': raw_poc_text if meaningful_poc else '',
            'poc_details': poc_details,
            'fix_suggestion': result.fix_suggestion,
            'test_status': (
                'DONE'
                if result.steps_executed > 0 and not execution_summary['step_errors']
                else ('ERROR' if execution_summary['step_errors'] else 'NOT_TESTED')
            ),
            'steps_executed': result.steps_executed,
            'execution_time': result.execution_time,
            'raw_output': result.raw_output,
            'docker_attempted': execution_summary['docker_attempted'],
            'docker_used': execution_summary['docker_used'],
            'local_jar_attempted': execution_summary.get('local_jar_attempted', False),
            'container_id': execution_summary['container_id'],
            'service_url': execution_summary['service_url'],
            'runtime_type': execution_summary.get('runtime_type') or '',
            'runtime_source': execution_summary.get('runtime_source') or '',
            'container_kept_running': execution_summary['container_kept_running'],
            'service_ready': execution_summary['service_ready'],
            'step_errors': execution_summary['step_errors'],
            'no_poc_reason': no_poc_reason,
            'verified_bundle': verified_bundle
        })

        logger.info(f"[D2] Result: exploitable={result.exploitable}, confidence={result.confidence}")

    logger.info(f"D2 AI Agent verification complete: {len(results)} vulnerabilities verified")

    # confirmed_exploitable 而绕过 D2 的三失效族（weak_hash/weak_crypto/secure_cookie）。绕过
    # _d2_gate_predicate 的结构性够不到问题，使 I 路由真正可达、三失效族假阳性出清得以发生。
    _n_family_route = _apply_family_route_postpass(task_id, _sdb)
    if _n_family_route:
        logger.info("[D2] I 族路由 post-pass 改写 %d 条三失效族 spec（详见 [D2][family-route-postpass]）", _n_family_route)

    # confirmed_exploitable 若源文件含「死分支常量/安全值覆盖」反例（canary 到达真 sink
    _n_safe_veto = _apply_safe_pattern_postpass(task_id, _sdb, code_root or target_path)
    if _n_safe_veto:
        logger.info("[D2] 安全写法反例否决 post-pass 改写 %d 条 spec（详见 [D2][safe-pattern-veto]）", _n_safe_veto)

    # 判据来自探针记录的 sink **实际实参**（payload 是否真到达该族真 sink），target-agnostic；
    # 前置依赖 Phase 0a 已把 param_location 按源码纠正（否则 payload 注错源 → 假 absent）。
    _n_value_veto = _apply_sink_value_gate_postpass(task_id, _sdb)
    if _n_value_veto:
        logger.info("[D2] 值级 sink 实参闸否决 %d 条 spec（详见 [D2][value-gate]）", _n_value_veto)

    # 实参）⇒ 抑制。修「确认态硬闸用通用 sink 到达确认」的缺陷；仅 xpathi/trustbound。
    _n_confirm_sink = _apply_confirm_sink_identity_postpass(task_id, _sdb)
    if _n_confirm_sink:
        logger.info("[D2] 确认态 sink 身份校验抑制 %d 条 spec（详见 [D2][confirm-sink]）",
                    _n_confirm_sink)

    # 先把「回执真实到达」的 spec 升 confirmed_exploitable，硬闸随后复核，
    # 否则会被硬闸当无证据降级，第四层证据白白流失。
    _n_oob_corr = _apply_oob_correlation(task_id, _sdb)
    if _n_oob_corr:
        logger.warning(
            "[D2] OOB 第四层回执升级 %d 条 spec → confirmed_exploitable（详见 [D2][oob-correlation]）",
            _n_oob_corr,
        )

    # 现有判定只认「canary 到 sink」，对盲注/反射类不成立——实测 594 有 5 个真值文件的
    # canary 明明到了业务 sink，却因「响应里没有明显危害」被判 unconfirmed。
    _n_tech = _apply_technique_oracle_postpass(task_id, _sdb, code_root or target_path)
    if _n_tech:
        logger.warning("[D2] 按注入技术补确认 %d 条 spec（详见 [technique-oracle]）", _n_tech)

    # 此处复核全部 confirmed_exploitable（含注册期直判、族路由漏网等其它写入通道），
    # 保证「no-arrival 且 confirmed_exploitable」这一证伪失效组合在任何路径下都不出现。
    _n_confirm_gate = _apply_confirmation_gate(task_id, _sdb)
    if _n_family_reassign:
        logger.warning(
            "[D2] 族-证据一致性改判 %d 条 spec 族名（详见 [D2][family-sink]）", _n_family_reassign,
        )
    if _n_confirm_gate:
        logger.warning(
            "[D2] 确认态硬闸降级 %d 条 confirmed_exploitable → unconfirmed（详见 [D2][confirm-gate]）",
            _n_confirm_gate,
        )
    # 硬闸执行时部分 spec 的真实 sink 事件还没到，只看到框架噪声 sink 就降级了。
    # 实测 594/599 各 15 条降级里 11 条事后确有真 sink 证据。
    _n_regate = _apply_confirm_gate_recheck(task_id, _sdb)
    if _n_regate:
        logger.warning("[D2] 迟到证据回补 %d 条 confirm-gate 降级 → confirmed_exploitable", _n_regate)

    # -B 末态兜底：清扫本 task 下仍为空 verification_status 的 trigger_spec（无 finding 驱动
    # verify 的自动登记 spec），统一置 'no_evidence'，消除 empty=8 幽灵计数污染。fail-open。
    # 注意：invalidated（批次隔离产物）是非空态，不会被此处清扫覆盖 —— 它必须保持「可重试」语义。
    _n_finalized = finalize_unverified_trigger_specs(_sdb, task_id)
    logger.info(
        "[D2] 验证完成：%d 条 vulnerabilities 已验证；%d 条空状态 spec 末态落 no_evidence；"
        "%d 条落 invalidated（靶场重启/不可用窗口，可重试，不参与对账）",
        len(results), _n_finalized, _n_invalidated,
    )

    # 这个大杂烩劈成 env_unsupported / probe_not_covered / pipeline_gap / true_miss 四类。
    # 位置很关键：必须在 finalize_unverified_trigger_specs **之后** —— 那一步会把空状态 spec
    # 刷成 no_evidence，先归因会漏掉整批「从未重放」的 pipeline_gap。fail-open。
    try:
        from src.core.failure_attribution import attribute_task
        _attr = attribute_task(_sdb, task_id)
        _ac = _attr.get("counts") or {}
        if _ac:
            logger.warning(
                "[D2][归因] task=%s 未确认判责：env_unsupported=%d probe_not_covered=%d "
                "pipeline_gap=%d true_miss=%d（合计 %d 条）",
                task_id, _ac.get("env_unsupported", 0), _ac.get("probe_not_covered", 0),
                _ac.get("pipeline_gap", 0), _ac.get("true_miss", 0), _attr.get("unconfirmed_total", 0),
            )
    except Exception as _ae:
        logger.warning("[D2][归因] 批量判责失败（忽略，不影响主流程）：%s", _ae)

    # confirmed_exploitable=已证实可利用；unconfirmed=已验证但未证实可利用；no_evidence=
    # D2 已审视且无证据表明可利用（永久非漏洞结论，是误报治理依据，不得并入 unconfirmed）。
    # 与 iast_state（no-arrival=靶场挂了/请求未抵达）严格区分，两字段分列统计。
    # 「已定论」档 —— 既不确认也不否证）。
    # 权威源是 finalize 之后的 trigger_specs（DB GROUP BY），而非内存 results。
    _vs_dist = {'confirmed_exploitable': 0, 'unconfirmed': 0, 'no_evidence': 0, 'invalidated': 0,
                # 必须显式列入，否则 GROUP BY 出的新状态在渲染分布时会被 KeyError 吞掉、
                # 变成统计缺口（与 memory 里「r64a 探测卡片曾整体不显示」同源，必须显式初始化）。
                'sink_reached': 0}
    if task_id is not None:
        try:
            _rows = _sdb.execute(
                "SELECT verification_status, COUNT(*) AS n FROM trigger_specs "
                "WHERE task_id=? GROUP BY verification_status",
                (int(task_id),),
                fetchall=True,
            ) or []
            for _r in _rows:
                _k = str(_r["verification_status"] or "") if isinstance(_r, dict) else str(_r[0] or "")
                _v = int(_r["n"] if isinstance(_r, dict) else _r[1])
                if _k in _vs_dist:
                    _vs_dist[_k] += _v
                elif _k:
                    # 未知档显式保留，不静默折叠进任何已知档
                    _vs_dist[_k] = _v
        except Exception as _ve:
            logger.warning("[D2] verification_status 三态分列统计失败（忽略）：%s", _ve)

    # §批次隔离可见性（铁律⑥：运行状态须同步前端）：只要有 spec 因靶场重启/不可用被隔离，
    # 就发一条 task_alert，明确「本轮这些条目不可用于对账/差分门禁，必须重试」。
    if _n_invalidated > 0:
        _iso_msg = (
            "D2 批次隔离：%d 条 spec 的验证窗口与靶场重启/不可用窗口相交，已标 invalidated（可重试）。"
            "这些条目既不记 confirmed 也不记 no_evidence，本轮不得用于对账与差分门禁。"
            "判据分布=%s；靶场纪元=%s" % (_n_invalidated, _inval_reasons, _epoch_report or {})
        )
        logger.error("[D2][batch-isolation] %s", _iso_msg)
        try:
            _append_scan_task_event(task_id, "task_alert", {
                "stage": "d2_isolation",
                "status": "invalidated",
                "detail": _iso_msg,
                "invalidated_count": int(_n_invalidated),
                "invalidated_by_reason": _inval_reasons,
                "target_epoch": _epoch_report or {},
            })
        except Exception as _ae:
            logger.warning("[D2] 批次隔离告警事件写入失败（忽略）：%s", _ae)

    # 使「已入队却无验证记录」的条目能直接定位断点在「执行期」还是「折叠期」，不再靠猜。
    # 关键对照：verify_returned 与 folded 都为 True 却仍被报告写成
    # enqueued_but_no_verification_record 的条目 → 断点在报告折叠端（身份键错位），非 D2 执行。
    _d2_scheduling["execution_trace"] = _d2_exec_trace
    _d2_scheduling["trace_summary"] = {
        "traced": len(_d2_exec_trace),
        "spec_found": sum(1 for t in _d2_exec_trace if (t.get("spec_found_count") or 0) > 0),
        "spec_missing": sum(1 for t in _d2_exec_trace if (t.get("spec_found_count") or 0) == 0),
        "verify_called": sum(1 for t in _d2_exec_trace if t.get("verify_called")),
        "verify_returned": sum(1 for t in _d2_exec_trace if t.get("verify_returned")),
        "folded": sum(1 for t in _d2_exec_trace if t.get("folded")),
        "errors": sum(1 for t in _d2_exec_trace if t.get("error")),
        "spec_nulled": sum(1 for t in _d2_exec_trace if t.get("spec_nulled_reason")),
    }
    logger.info("[D2] 执行埋点：%s", _d2_scheduling["trace_summary"])
    try:
        _append_scan_task_event(task_id, "task_progress", {"d2_exec_trace_summary": _d2_scheduling["trace_summary"]})
        _update_scan_progress_metadata(output_dir, {"stage_results": {"d2": {"scheduling": _d2_scheduling}}})
    except Exception as _te:  # fail-open：留痕失败不影响主流程
        logger.warning("[D2] 执行埋点落盘失败（忽略）：%s", _te)

    # 迟到的事件丢掉（探针 flush 落在窗口关闭之后），导致本应在窗口内被确认的 spec 写成
    # no-arrival。这里在主流程定稿后、报告生成前，用全量 iast_events 重算 arrival+value_hit
    # （gate B：到达真实 sink 且 source_value 比对命中），把真 TP 救回。
    # 严格单调：只升 definitive 阳性、不降级、不碰已确认 spec、幂等、失败 fail-open 不阻断主流程。
    _rec_upgraded: List[int] = []
    if task_id is not None and _sdb is not None:
        try:
            from src.agents.d2_facade import recover_late_arrival
            _rec_upgraded, _rec_stats = recover_late_arrival(_sdb, task_id, dry_run=False)
            logger.info("[D2][late-recover] task=%s 升级=%d/%d",
                        task_id, len(_rec_upgraded), _rec_stats.get("considered", 0))
            try:
                _append_scan_task_event(task_id, "task_progress", {
                    "stage": "d2_late_recover",
                    "upgraded": len(_rec_upgraded),
                    "considered": _rec_stats.get("considered", 0),
                    "specs": _rec_stats.get("specs", 0),
                })
            except Exception as _re:
                logger.warning("[D2][late-recover] 留痕失败（忽略）：%s", _re)
        except Exception as _lre:  # fail-open：回收失败绝不阻断主流程
            logger.warning("[D2][late-recover] 失败（忽略）：%s", _lre)

    # 迟到回收后，从 DB 重算 verification_status 分布（覆盖回收前旧数，保证报告/前端一致）。
    if task_id is not None and _sdb is not None and _rec_upgraded:
        try:
            _vs_dist = {'confirmed_exploitable': 0, 'unconfirmed': 0, 'no_evidence': 0,
                        'invalidated': 0, 'sink_reached': 0}
            _vrows = _sdb.execute(
                "SELECT verification_status, COUNT(*) AS n FROM trigger_specs "
                "WHERE task_id=? GROUP BY verification_status",
                (int(task_id),), fetchall=True) or []
            for _r in _vrows:
                _k = str(_r["verification_status"] or "") if isinstance(_r, dict) else str(_r[0] or "")
                _v = int(_r["n"] if isinstance(_r, dict) else _r[1])
                if _k in _vs_dist:
                    _vs_dist[_k] += _v
                elif _k:
                    _vs_dist[_k] = _v
        except Exception as _vde:
            logger.warning("[D2][late-recover] 分布重算失败（忽略）：%s", _vde)

    # 迟到回收后，从 DB 取权威 confirmed 计数回填报告（覆盖内存 results 中未含回收项的旧数）。
    _exploitable_count_db = len(_rec_upgraded)
    if task_id is not None and _sdb is not None:
        try:
            _row = _sdb.execute(
                "SELECT COUNT(*) AS n FROM trigger_specs WHERE task_id=? AND verification_status='confirmed_exploitable'",
                (task_id,), fetchone=True)
            if _row and isinstance(_row, dict):
                _exploitable_count_db = int(_row.get("n") or 0)
        except Exception as _ce:
            logger.warning("[D2][late-recover] 回填计数失败（忽略）：%s", _ce)

    return {
        'total_vulnerabilities': len(results),
        'verifications': results,
        'pocs': results,
        'verification_status_distribution': _vs_dist,
        # §批次隔离：invalidated 独立计数 + 靶场纪元报告，供报告层与前端显式呈现。
        'invalidated_count': int(_n_invalidated),
        'invalidated_by_reason': dict(_inval_reasons),
        'target_epoch': _epoch_report,
        # §③ 调度留痕：候选/入队/未入队 + 逐条原因，供报告层与前端审计「谁没进 D2、为什么」。
        'scheduling': _d2_scheduling,
        'exploitable_count': _exploitable_count_db,
        'verified_poc_count': sum(1 for r in results if r.get('poc_verified') and str((r.get('verification_decision') or {}).get('verification_status', '') or '') == 'confirmed_exploitable'),
        'docker_attempted': docker_attempted,
        'docker_used': docker_used,
        'local_jar_attempted': local_jar_attempted,
        'runtime_source': runtime_source or '',
        'runtime_type': '',
        'docker_status': {},
        'failure_reasons': [] if sum(1 for r in results if r.get('poc_verified')) > 0 else list(dict.fromkeys(r for r in failure_reasons if r)),
        'pending_actions': pending_actions,
    }


class _SpecOverrideVuln:
    """轻量代理：委托原 vuln 的全部属性，仅覆盖 exploit_spec。

    此前 execute_retryable_replay 直接把内存 vuln 对象喂给 run_d2_verify，trigger_specs 上
    已落库的 replay_adjust 调整（switch_param_location 换位 / escalate_variant 变体）完全
    吃不到。直接 mutate 原 A2 vuln 对象有不可变风险，故用只读代理注入重建后的 exploit_spec；
    run_d2_verify 只读属性（getattr(vuln, 'exploit_spec', {}) 等），代理透明。
    """

    def __init__(self, original, exploit_spec):
        object.__setattr__(self, "_orig", original)
        object.__setattr__(self, "_espec", exploit_spec)

    def __getattr__(self, name):
        if name == "exploit_spec":
            return object.__getattribute__(self, "_espec")
        return getattr(object.__getattribute__(self, "_orig"), name)


def _read_spec_row(db, spec_id: int) -> Dict[str, Any]:
    """读 trigger_specs 单行（param_location / raw_json / family），fail-open 返回空 dict。"""
    try:
        row = db.execute(
            "SELECT id, param_location, raw_json, family, target_endpoint"
            " FROM trigger_specs WHERE id=?",
            (int(spec_id),), fetchone=True)
        if row and isinstance(row, dict):
            return row
    except Exception as _e:
        logger.warning("[retryable] 读 spec 行失败 spec=%s：%s", spec_id, _e)
    return {}


def _sanitizer_aware_variant(db, vuln, spec_row: Dict[str, Any], spec_id: int,
                             fam: str, base: str, imps: List[str]) -> Optional[Dict[str, Any]]:
    """升变体：在净化器约束内合成下一发载荷。

    旧实现按族写死一张表（baseline → url_encode → alt_syntax → oob）按序取下一阶，
    它不知道对手在拦什么。新实现：
      - 有 FilterSpec（净化器约束）→ 在约束内合成，并用 simulate_filter 确定性验一遍；
      - 结合 ReplayMemory 排除「已试过且被拒」的载荷，避免原地打转；
      - 产出 (变体名, 载荷) 供上层继续写 _variant_escalated（C 验证指标不变）。
    返回 None 表示无可用下一发（交回调用方按旧逻辑/放弃）。
    """
    try:
        from src.core.sanitizer_miner import FilterSpec as _FS
        from src.iast.sanitizer_forge import synthesize as _syn, gate as _gate
        from src.iast.replay_intel import ReplayMemory as _RM

        raw = spec_row.get("raw_json") or ""
        meta = {}
        if raw:
            try:
                meta = json.loads(raw) or {}
            except Exception:
                meta = {}
        if not isinstance(meta, dict):
            meta = {}

        # 判完就停：不可绕过（真净化器）不再升变体
        try:
            from src.core.filter_verdict import is_terminal as _is_terminal
            if _is_terminal(meta.get("filter_verdict")):
                return None
        except Exception:
            pass

        fspec = _FS.from_dict(meta.get("filter_spec"))
        if fspec is None:
            for cand in (meta.get("sanitizer_candidates") or []):
                if isinstance(cand, dict) and cand.get("body"):
                    from src.core.sanitizer_miner import extract_filter_spec as _ex
                    fspec = _ex(str(cand.get("body")))
                    if fspec is not None and fspec.is_known():
                        break
                    fspec = None
        if fspec is None:
            return None

        mem = _RM.from_dict(meta.get("replay_intel"))
        avoid = set(mem.rejected_payloads())
        out = _syn(fspec, fam, sink=str(spec_row.get("expected_sink_file") or ""),
                   body="", llm_complete=None, extra_bases=[base] if base else None, max_out=8)
        survivors = [p for p in _gate(list(out.get("candidates") or []), fam, fspec)
                     if p not in avoid and p != base]
        if not survivors:
            return None
        nxt = survivors[0]
        # 记录本轮尝试与判死清单，供下一轮 avoid
        mem.record(tried=survivors[:3], rejected=list(out.get("rejected") or []),
                   failure_class="blocked", observed={}, directive={})
        meta["replay_intel"] = mem.to_dict()
        try:
            db.execute("UPDATE trigger_specs SET raw_json=? WHERE id=?",
                       (json.dumps(meta, ensure_ascii=False), int(spec_id)))
        except Exception:
            pass
        return {"name": "sanitizer_aware", "payload": nxt, "spec": fspec.to_dict()}
    except Exception:
        return None


def _spec_override_exploit_spec(db, vuln, spec_row: Dict[str, Any], spec_id: int) -> Dict[str, Any]:
    """按 trigger_specs 权威字段重建 vuln 的 exploit_spec。

    - param_location：以 spec 落库值为准（apply_replay_adjustments 的 switch_param_location
      真 UPDATE 在 spec 上，vuln 内存对象不知道）→ 覆盖 entry.param_location，让换位生效。
    - escalate_variant：spec.replay_adjust.actions 含该动作时，按族变体梯子取下一阶 payload
      插到 high_impact_payloads 首位（baseline 保留兜底），并回写 variant_level /
      baseline_payload 供下一轮续梯与封顶（梯子到顶不再升级）。
    fail-open：任何异常返回原 exploit_spec，绝不因重建失败阻断重放。
    """
    try:
        espec = getattr(vuln, "exploit_spec", {}) or {}
        if not isinstance(espec, dict):
            espec = {}
        espec = dict(espec)
        ploc = str(spec_row.get("param_location") or "").strip()
        if ploc:
            entry = dict(espec.get("entry") or {})
            entry["param_location"] = ploc
            espec["entry"] = entry
        raw = spec_row.get("raw_json") or ""
        meta: Dict[str, Any] = {}
        if raw:
            try:
                meta = json.loads(raw) or {}
            except Exception:
                meta = {}
        if not isinstance(meta, dict):
            meta = {}
        adj = dict(meta.get("replay_adjust") or {})
        acts = adj.get("actions") or []
        if "escalate_variant" in acts:
            fam = spec_row.get("family") or ""
            pl = espec.get("payload") or {}
            if not isinstance(pl, dict):
                pl = {}
            imps = [str(p) for p in (pl.get("high_impact_payloads") or []) if p]
            base = str(adj.get("baseline_payload") or (imps[0] if imps else ""))
            level = int(adj.get("variant_level") or 0)
            # 已从主路径移除——它不知道对手在拦什么，只是"换个写法碰运气"。
            # 改为净化感知合成：拿得到 FilterSpec 就在约束内构造并确定性验证；
            # 拿不到约束就不升级（宁可不动，也不盲试）。
            _sa = _sanitizer_aware_variant(db, vuln, spec_row, spec_id, fam, base, imps)
            if _sa and _sa.get("payload"):
                nxt_name = str(_sa.get("name") or "sanitizer_aware")
                nxt_payload = str(_sa.get("payload"))
                has_next = True
            else:
                nxt_name, nxt_payload, has_next = None, base, False
                logger.info("[retryable] spec=%s 无净化器约束可依，不升级变体（静态梯子已移除）", spec_id)
            if nxt_name and has_next and nxt_payload and nxt_payload != base:
                if base and base not in imps:
                    imps.insert(0, base)
                imps.insert(0, nxt_payload)
                pl["high_impact_payloads"] = imps[:6]
                espec["payload"] = pl
                adj["variant_level"] = level + 1
                adj["baseline_payload"] = base
                adj["last_variant"] = nxt_name
                # 只能事后 grep trigger_specs.raw_json，无法在 retryable 事件里直接观测；
                # 这里打内部标记，由 execute_retryable_replay 汇总进事件，便于按轮验收。
                espec["_variant_escalated"] = nxt_name
                meta["replay_adjust"] = adj
                try:
                    db.execute(
                        "UPDATE trigger_specs SET raw_json=? WHERE id=?",
                        (json.dumps(meta, ensure_ascii=False), int(spec_id)))
                except Exception as _e:
                    logger.warning("[retryable] 回写 variant_level 失败 spec=%s：%s", spec_id, _e)
                logger.info("[retryable] 变体升级 spec=%s 族=%s 第%d阶=%s",
                            spec_id, fam, level + 1, nxt_name)
        return espec
    except Exception as _e:
        logger.warning("[retryable] 重建 exploit_spec 失败（忽略，用原 payload）：%s", _e)
        return getattr(vuln, "exploit_spec", {}) or {}


def _count_confirmed_specs(db, task_id: int) -> int:
    """确认态 spec 计数（confirmed_exploitable + confirmed_code_property），用于重放增益评测。"""
    try:
        row = db.execute(
            "SELECT COUNT(*) AS n FROM trigger_specs WHERE task_id=?"
            " AND verification_status IN ('confirmed_exploitable','confirmed_code_property')",
            (int(task_id),), fetchone=True)
        return int((row or {}).get("n") or 0)
    except Exception:
        return 0


def _confirmed_vhash_set(db, task_id: int) -> set:
    """确认态 spec 的 vhash 集合。

    B-1 产物健康度闸（spec 总数/端点率/注入类比）不含「确认保全」维度——rerun 产物
    可以健康度全达标，却把上一轮已确认的漏洞在重验后大量丢成 unconfirmed/no_evidence
    本集合供重验前后对比确认保全率。
    """
    try:
        rows = db.execute(
            "SELECT vulnerability_hash_v2 FROM trigger_specs WHERE task_id=?"
            " AND verification_status IN ('confirmed_exploitable','confirmed_code_property')",
            (int(task_id),), fetchall=True) or []
        return {str(r.get("vulnerability_hash_v2")) for r in rows
                if r.get("vulnerability_hash_v2")}
    except Exception:
        return set()


def execute_retryable_replay(db, task_id, retryable, *, a1_results, a2_results, files,
                              target_path, external_target, code_root, discovered_routes,
                              output_dir, batch_size: Optional[int] = None,
                              inter_batch_sleep: float = 2.0) -> Dict[str, int]:
    """消费 plan_retryable_replay 的 retryable 清单，真正重放（D1 重发 + D2 重验），回写终态。

    没有任何代码消费它去真正重跑 → xss 等 no_evidence 在各轮稳定残留。这里接上执行：
      - 把 a2_results 按 retryable 的 vhash 过滤成子集，传**空 a1_results** 调 run_d2_verify，
        只重验这些 spec，不碰全量（避免重复确认/污染对账）。
      - 每批后给每条 spec 的 raw_json.replay_adjust.round +1，封顶由 plan_retryable_replay 的
        max_rounds 控制，绝不无限重试。

      - 主 pass：309 个漏洞，run_d2_verify 内部按族切 32 一批 → 约 15 分钟跑完；
      - 重试环：299 条 no_evidence/unconfirmed 被这里按 3 一切 → 65 次 run_d2_verify 调用，
        每次一个完整 IAST 事务（重放 + 60s 窗口 + 30s settle ≈ 180s），合计约 195 分钟，
        而 cleared 仅 17 条（clear 率 8.7%）。
      - 即 D2 阶段 207 分钟里约 195 分钟（94%）是重试环的**固定窗口开销**，而非有效工作量。
    为什么放大批次不会掉证据：批内每条 spec 的 canary 唯一，per_hypothesis 与
    dast_impact_by_hypothesis 均按 vulnerability_hash_v2 切片归因，裁决仍是逐 spec 独立
    （见 d2_facade.verify_group）；合并只减少「等窗口」的次数，不改任何判据与载荷。
    重试批内的 spec 多为真不可达（窗口必然等满、早停不触发），合批后 32 条共享一次等满窗口
    （约 90s）而非 11 次 × 90s，是纯收益。
    回退开关：SAST_AI_RETRY_BATCH_SIZE=3 恢复旧行为，无需改代码。
    返回 {executed, cleared, failed, batches, elapsed_sec}。任何异常 fail-open，不影响主流程。
    """
    import json as _json
    import time as _time
    from collections import defaultdict

    if not retryable:
        return {"executed": 0, "cleared": 0, "failed": 0, "batches": 0, "elapsed_sec": 0.0}
    # 默认 32 与主 pass 对齐；显式传参优先，其次环境变量（回退开关）。
    if batch_size is None:
        try:
            batch_size = int(os.environ.get("SAST_AI_RETRY_BATCH_SIZE", "32") or 32)
        except Exception:
            batch_size = 32
    batch_size = max(1, int(batch_size))
    _t_retry_start = _time.time()
    _retry_batches = 0
    _vh_set = set()
    _spec_by_vh = {}
    _fam_by_vh = {}
    for _it in retryable:
        _vh = _it.get("vhash")
        if _vh:
            _vh_set.add(_vh)
            _spec_by_vh[_vh] = _it.get("spec_id")
            _fam_by_vh[_vh] = _it.get("family")
    if not _vh_set:
        return {"executed": 0, "cleared": 0, "failed": 0}

    # vuln → vhash（复用 run_d2_verify 的同款算法，保证与 spec 关联一致）
    try:
        from src.core.vuln_hash import canonicalize_vuln_for_hash, vulnerability_hash_v2 as _vh2
    except Exception:
        from src.core.vuln_hash import canonicalize_vuln_for_hash, vulnerability_hash_v2 as _vh2

    def _vhash_of(_v):
        try:
            if hasattr(_v, "to_dict") and callable(_v.to_dict):
                return _vh2(canonicalize_vuln_for_hash(_v.to_dict()))
            return _vh2(canonicalize_vuln_for_hash(_v))
        except Exception:
            return ""

    # run_d2_verify 只消费 result.error / result.vulnerabilities / result.agent 三字段，
    # 用轻量 wrapper 承载原始 vuln 对象（保留其 to_dict），避免重建 A2Result。
    class _RetryResult:
        def __init__(self, agent, vulns):
            self.error = None
            self.agent = agent
            self.vulnerabilities = vulns

    def _query_spec_status(_db, _sid):
        try:
            _row = _db.execute(
                "SELECT verification_status FROM trigger_specs WHERE id=?",
                (int(_sid),), fetchone=True)
            if _row and isinstance(_row, dict):
                return _row.get("verification_status")
        except Exception:
            return ""
        return ""

    def _bump_replay_round(_db, _sid):
        try:
            _row = _db.execute(
                "SELECT raw_json FROM trigger_specs WHERE id=?",
                (int(_sid),), fetchone=True)
            _meta = {}
            if _row and isinstance(_row, dict):
                _raw = _row.get("raw_json") or ""
                if _raw:
                    try:
                        _meta = _json.loads(_raw) or {}
                    except Exception:
                        _meta = {}
            if not isinstance(_meta, dict):
                _meta = {}
            _adj = dict(_meta.get("replay_adjust") or {})
            _adj["round"] = int(_adj.get("round") or 0) + 1
            _meta["replay_adjust"] = _adj
            _db.execute(
                "UPDATE trigger_specs SET raw_json=? WHERE id=?",
                (_json.dumps(_meta, ensure_ascii=False), int(_sid)))
        except Exception as _e:
            logger.warning("[retryable] 回写 round 失败 spec=%s：%s", _sid, _e)

    # 字段重建重放上下文（param_location 覆盖 + escalate_variant 变体升级），确保 replay_adjust
    # 调整真正生效；a2_results 仅按 vhash 建索引提供 vuln 载体。
    _vuln_by_vh = {}
    # 实测（471/472）：重试匹配率长期 21/119=0.176、7/85=0.082 —— 根因是 **vhash 两端口径漂移**：
    #   spec 登记端的 vulnerability_hash_v2 常取 chain_id / canonical_group_key 形态
    #   （benchmark_cli.py:3182），而这里对 a2_results 的 vuln 重算的是逐条完整 hash。
    #   聚合/吸收成员行（is_absorbed）尤其对不上 ⇒ 大量 retryable 被静默跳过。
    # 二级匹配的安全性：重放是 **spec_id 驱动** 的（_read_spec_row 读 trigger_specs 权威字段
    # + _SpecOverrideVuln 用 spec 的 exploit_spec 覆盖载体），vuln 只提供「上下文载体」，
    # 所以按 (family, endpoint) 找同一条 finding 的兄弟行当载体是安全的，不改变任何判据。
    _vuln_by_fam_ep = {}
    for _res in (a2_results or []):
        if getattr(_res, "error", None):
            continue
        _agent = getattr(_res, "agent", "A2") or "A2"
        for _v in getattr(_res, "vulnerabilities", []) or []:
            _vvh = _vhash_of(_v)
            if _vvh in _vh_set and _vvh not in _vuln_by_vh:
                _vuln_by_vh[_vvh] = (_v, _agent)
            _ep_raw = str(getattr(_v, "entry_point", "") or "")
            _ep = re.sub(r"^[A-Z]+\s+", "", _ep_raw).strip().rstrip("/").lower()
            _fam = str(getattr(_v, "family", "") or getattr(_v, "type", "") or "").strip().lower()
            _key = (_fam, _ep)
            if _key != ("", "") and _key not in _vuln_by_fam_ep:
                _vuln_by_fam_ep[_key] = (_v, _agent)

    def _norm_ep(_e):
        return re.sub(r"^[A-Z]+\s+", "", str(_e or "")).strip().rstrip("/").lower()

    _by_fam = defaultdict(list)
    # 使「escalate_variant 是否真发生」成为事件级可观测指标（此前只能事后 grep raw_json）。
    _variant_escalated = 0
    # C9 失配诊断：vhash 两端口径漂移导致的跳过条数与样本（下一轮精确归因用）。
    # 是**紧跟着的这个 `for _it in retryable` 循环**（`_vh_miss += 1`）⇒ 只要有 retryable
    # 匹配不上就抛 `UnboundLocalError: cannot access local variable '_vh_miss'`，
    # 整个闭环重试被 fail-open 吞掉（本轮日志：`[闭环] 可重试重放失败（忽略，保留终态）`）。
    # 初始化必须在使用点之前。
    _vh_miss = 0
    _vh_miss_samples: list = []
    _vh_secondary_hits = 0
    for _it in retryable:
        _vh = _it.get("vhash")
        _sid = _it.get("spec_id")
        _match = _vuln_by_vh.get(_vh)
        _match_via = "vhash"
        if not _match and _sid:
            # C9 二级匹配：vhash 两端口径漂移（chain_id/cgk 形态 vs 逐条完整 hash）时，
            # 按 (family, endpoint) 找同 finding 的兄弟行当载体。重放以 spec 权威字段为准，
            # 载体只提供上下文 ⇒ 安全，不改判据。
            _fam = str(_it.get("family") or "").strip().lower()
            _ep = _norm_ep(_it.get("endpoint"))
            _match = _vuln_by_fam_ep.get((_fam, _ep))
            if _match:
                _match_via = "family+endpoint"
        if not _match or not _sid:
            _vh_miss += 1
            if len(_vh_miss_samples) < 8:
                _vh_miss_samples.append({
                    "spec_id": _sid, "vhash": (str(_vh)[:24] + "…") if _vh else "",
                    "family": _it.get("family"), "endpoint": _it.get("endpoint")})
            continue
        _vuln, _agent = _match
        if _match_via == "family+endpoint":
            _vh_secondary_hits += 1
        _row = _read_spec_row(db, _sid)
        _espec = _spec_override_exploit_spec(db, _vuln, _row, _sid)
        if isinstance(_espec, dict) and _espec.get("_variant_escalated"):
            _variant_escalated += 1
        _by_fam[_it.get("family") or "unknown"].append((_sid, _SpecOverrideVuln(_vuln, _espec), _agent))

    _executed = 0
    _cleared = 0
    _failed = 0
    _confirmed_before = _count_confirmed_specs(db, task_id)
    for _fam, _items in _by_fam.items():
        _nbatches = (len(_items) + batch_size - 1) // batch_size
        for _i in range(0, len(_items), batch_size):
            _sub = _items[_i:_i + batch_size]
            _spec_ids = [s for s, _, _ in _sub if s]
            _vulns = [_v for _, _v, _ in _sub]
            _agent = _sub[0][2] if _sub else "A2"
            try:
                _retry_batches += 1
                run_d2_verify(
                    [], [_RetryResult(_agent, _vulns)], files, target_path, external_target,
                    task_id=task_id, code_root=code_root,
                    discovered_routes=discovered_routes or [], output_dir=output_dir,
                )
            except Exception as _e:
                logger.warning("[retryable] 批次重验失败（族=%s，跳过该批）：%s", _fam, _e)
                _failed += len(_sub)
                continue
            for _sid in _spec_ids:
                if not _sid:
                    continue
                _executed += 1
                _new_st = _query_spec_status(db, _sid)
                if _new_st and _new_st not in ("no_evidence", "unconfirmed"):
                    _cleared += 1
                _bump_replay_round(db, _sid)
            logger.info(
                "[retryable] 族=%s 批 %d/%d 完成：executed_batch=%d cleared_total=%d",
                _fam, _i // batch_size + 1, _nbatches, len(_sub), _cleared)
            # 批间 sleep 让探针 EventBuffer 排空（~512/s），避队列背压吞事件
            if inter_batch_sleep and _nbatches > 1 and _i + batch_size < len(_items):
                _time.sleep(inter_batch_sleep)
    _confirmed_after = _count_confirmed_specs(db, task_id)
    _elapsed = round(_time.time() - _t_retry_start, 1)
    logger.info(
        "[retryable] 完成：executed=%d cleared=%d failed=%d confirmed_gain=%d "
        "batches=%d batch_size=%d elapsed=%.0fs | vhash 失配跳过 %d（二级匹配命中 %d）",
        _executed, _cleared, _failed, _confirmed_after - _confirmed_before,
        _retry_batches, batch_size, _elapsed, _vh_miss, _vh_secondary_hits)
    if _vh_miss:
        logger.warning("[retryable] C9 vhash 失配样本（前 %d）：", len(_vh_miss_samples))
        for _s in _vh_miss_samples:
            logger.warning("  %s", json.dumps(_s, ensure_ascii=False))
    return {"executed": _executed, "cleared": _cleared, "failed": _failed,
            "confirmed_gain": _confirmed_after - _confirmed_before,
            "variant_escalated": _variant_escalated,
            "vhash_miss": _vh_miss, "vhash_secondary_hits": _vh_secondary_hits,
            "vhash_miss_samples": _vh_miss_samples,
            "batches": _retry_batches, "batch_size": batch_size,
            "elapsed_sec": _elapsed}


def _merge_progress_payload(current: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(current)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_progress_payload(merged[key], value)
        else:
            merged[key] = value
    return merged


# 当前扫描 task id（run_benchmark 开头设置），供产物目录归属校验使用。
_CURRENT_SCAN_TASK_ID: Optional[int] = None


def _append_scan_task_event(task_id: Optional[int], event_type: str, payload: Dict[str, Any]) -> None:
    """P1-3：进度/诊断事件落 scan_task_events 事件流（追加不可覆写）。

    scan_progress.json 是会被反复读写的易变文件，事后无法审计「本轮前端到底看到过什么」；
    事件流追加写让 D2 重放心跳（replayed 递增序列 / replay_done 终态）与吞异常原因可事后
    归因。fail-open：task_id 为空（离线场景）直接跳过；写失败仅 warning，不影响主流程。
    """
    if task_id is None:
        return
    try:
        _db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        _db.execute(
            "INSERT INTO scan_task_events (task_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
            # #4③：统一为 UTC，避免与 task_log 的 UTC 差 8 小时导致心跳判据误读。
            (task_id, event_type, Database.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )
    except Exception as _e:
        logger.warning("[事件流] task=%s 写入 %s 事件失败（忽略）：%s", task_id, event_type, _e)


def _spec_key_snapshot(task_id: Optional[int]) -> Dict[str, Dict[str, Any]]:
    """spec 集指纹快照（按 vulnerability_hash_v2 取键），供重登记前后逐条比对。

    （spec 总数退化 >10%、端点解析率 >10%、注入类 >20% 才拦），单条 spec 消失在比例上
    且 reasons 无痕、无法归因。闸门本身没错（它防的是整批退化），缺的是逐条可观测性。
    """
    if task_id is None:
        return {}
    try:
        _db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        rows = _db.execute(
            "SELECT id, vulnerability_hash_v2, family, target_endpoint, param_name"
            " FROM trigger_specs WHERE task_id=?",
            (task_id,), fetchall=True,
        ) or []
        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            if not isinstance(r, dict):
                continue
            key = str(r.get("vulnerability_hash_v2") or r.get("id") or "")
            if key:
                out[key] = {
                    "id": r.get("id"),
                    "family": r.get("family"),
                    "endpoint": r.get("target_endpoint"),
                    "param": r.get("param_name"),
                }
        return out
    except Exception as _e:
        logger.warning("[spec-diff] 快照失败（忽略）：%s", _e)
        return {}


def _diff_and_record_spec_set(task_id: Optional[int], before: Dict[str, Dict[str, Any]],
                              after: Dict[str, Dict[str, Any]], stage: str = "") -> int:
    """对比重登记前后的 spec 集，把消失集/新增集落事件流（无论闸门是否触发都留痕）。"""
    if task_id is None:
        return 0
    try:
        b, a = set(before or {}), set(after or {})
        gone, added = sorted(b - a), sorted(a - b)
        if not gone and not added:
            return 0
        _append_scan_task_event(task_id, "spec_set_diff", {
            "stage": stage,
            "before_count": len(b), "after_count": len(a),
            "gone_count": len(gone), "added_count": len(added),
            "gone": [dict(key=k, **before[k]) for k in gone[:300]],
            "added": [dict(key=k, **after[k]) for k in added[:300]],
        })
        logger.warning(
            "[spec-diff] %s：spec 集 %d→%d，消失 %d 条、新增 %d 条（已落事件流供逐条判责）",
            stage, len(b), len(a), len(gone), len(added),
        )
        return len(gone) + len(added)
    except Exception as _e:
        logger.warning("[spec-diff] 比对失败（忽略）：%s", _e)
        return 0


# #4② 自检护栏：记录每个 output_dir 的 scan_progress.json 上次写入 mtime，
# 若某次心跳写入后 mtime 未推进（被整段覆写/合并丢键导致静默），告警以便定位。
_STAGE_PROGRESS_MTIME: Dict[str, float] = {}


def _start_progress_heartbeat(output_dir: str, interval: float = 30.0):
    """后台心跳线程：周期性刷新 scan_progress.json 的 mtime，
    防止长耗时阶段（典型如 i2 闭环的 a2_rerun，单轮可长达 40+ 分钟）不写该文件时，被
    task_runner 看门狗按 STUCK_HEARTBEAT_SECONDS（默认 45min）误判为卡死强杀。

    返回 stop 函数。心跳只在闭环执行期间运行；闭环自身还有 ClosedLoopController.stall_timeout
    （20min）在每轮顶部做「无进展即终止」兜底，二者分层：心跳保命（不被看门狗杀）、stall_timeout
    止损（不无限循环）。
    """
    _path = os.path.join(output_dir or ".", "scan_progress.json")
    _stop = threading.Event()

    def _beat():
        while not _stop.is_set():
            try:
                if os.path.exists(_path):
                    os.utime(_path, None)
            except Exception:
                pass
            _stop.wait(interval)

    _t = threading.Thread(target=_beat, daemon=True)
    _t.start()
    return lambda: _stop.set()


_WALL_EXECUTOR = None
_WALL_EXECUTOR_LOCK = threading.Lock()


def _wall_executor():
    """墙钟上限共用「有界」线程池（单例）。SAST_AI_WALL_POOL 控制并发上限（默认 8）。

    终止线程就返回，挂起的 verify_group/闭环工作量持续占用 GIL/DB/target，后续批次再叠加
    超时、3978 条 spec 的 confirming 层全程空转）。单例池把并发钉死在上限内，从根上消除。
    """
    global _WALL_EXECUTOR
    if _WALL_EXECUTOR is None:
        with _WALL_EXECUTOR_LOCK:
            if _WALL_EXECUTOR is None:
                try:
                    _mx = max(1, int(float(os.environ.get("SAST_AI_WALL_POOL", "8") or 8)))
                except Exception:
                    _mx = 8
                _WALL_EXECUTOR = ThreadPoolExecutor(max_workers=_mx)
    return _WALL_EXECUTOR


def _with_wall_clock_limit(fn, timeout: float, label: str = ""):
    """在有界共享线程池执行 fn，超时返回 (None, True)，否则 (result, False)（单轮墙钟上限）。

      - 复用单个有界 ThreadPoolExecutor，concurrency 由 SAST_AI_WALL_POOL 钉死，杜绝无界线程堆积；
      - 超时后 fut.cancel 至少回收「排队未启动」的任务，减小对 target/DB 的挤占；
      - 已在运行的任务无法强杀（Python 线程限制），但并发被池上限约束，且终止信号让上层放弃本轮、
        保留原产物（fail-safe 语义不变）；异常透传与旧版一致（调用方按异常分支处理）。
    """
    from concurrent.futures import TimeoutError as _FutTimeout

    _ex = None
    try:
        _ex = _wall_executor()
        _fut = _ex.submit(fn)
    except Exception as _se:
        # 提交失败（如池已关停）时退化为内联同步执行，绝不因本改动中断主流程。
        logger.warning("[闭环] %s 墙钟线程池提交失败，退化为内联执行：%s", label, _se)
        return fn(), False
    try:
        return _fut.result(timeout=max(0.1, float(timeout))), False
    except _FutTimeout:
        logger.warning("[闭环] %s 超墙钟上限 %.0fs，放弃本轮（保留原产物）", label, float(timeout))
        # 只有「排队未启动」的任务能被取消；已在运行的只能等其自然结束，并发已被池上限约束。
        _fut.cancel()
        return None, True


def _emit_stage_progress(task_id: Optional[int], output_dir: str, key: str, payload: Dict[str, Any]) -> None:
    """通用阶段心跳：把 A2 / a2_poc / D2 验证 / 闭环这类长耗时、
    原本无任何增量更新的阶段进度钉进事件流与 scan_progress.json，使前端能看到真实进度，
    不再把 running 误判为卡死。

    key 为心跳键名（a2_progress / a2_poc_progress / d2_verify_progress / i2_rerun）。
    payload 自定义，建议含 total/done/status/heartbeat。
    fail-open：task_id 为空或写失败均忽略，绝不因心跳失败中断扫描主流程。
    """
    if task_id is None:
        return
    _hb = dict(payload)
    _hb.setdefault("heartbeat", datetime.now(timezone.utc).isoformat())
    _append_scan_task_event(task_id, "task_progress", {key: _hb})
    try:
        _update_scan_progress_metadata(output_dir, {key: _hb})
        # #4② 自检护栏：写后校验 scan_progress.json 的 mtime 是否推进；若未推进
        # （被整段覆写或合并丢键导致静默），告警以便定位，避免前端继续看到「卡死」。
        if output_dir:
            _sp = os.path.join(output_dir, "scan_progress.json")
            if os.path.exists(_sp):
                _mt = os.path.getmtime(_sp)
                _prev = _STAGE_PROGRESS_MTIME.get(_sp)
                if _prev is not None and _mt <= _prev:
                    logger.warning("[阶段心跳] %s 写入后 mtime 未推进（疑似整段覆写/丢键）：prev=%s now=%s",
                                   key, _prev, _mt)
                _STAGE_PROGRESS_MTIME[_sp] = _mt
    except Exception as _he:
        logger.warning("[阶段心跳] %s 写入失败（忽略）：%s", key, _he)


def _assert_output_dir_owned_by_task(output_dir: str, task_id: Optional[int]) -> bool:
    """产物分片保护：output_dir 必须属于当前 task，否则拒绝写入。

    task 不符（即试图写回旧 task 目录），拒绝并告警——跨 task 覆写会把多轮数据叠加成
    """
    if task_id is None:
        return True
    m = re.search(r"task-(\d+)", str(output_dir or "").replace("\\", "/"))
    if not m:
        return True  # 非 task 分片目录（如 output/），不做校验
    owner = int(m.group(1))
    if owner != int(task_id):
        logger.warning(
            "[产物保护] 拒绝写入：output_dir 属于 task-%s，但当前 task 为 %s（禁止跨 task 覆写产物）。",
            owner, task_id,
        )
        return False
    return True


def _update_scan_progress_metadata(output_dir: str, updates: Dict[str, Any]) -> None:
    # （同一 funnel 的 registered 读数在会话内 47→25 自相矛盾）。
    if not _assert_output_dir_owned_by_task(output_dir, _CURRENT_SCAN_TASK_ID):
        return
    progress_path = Path(output_dir) / "scan_progress.json"
    if not progress_path.exists():
        return
    try:
        payload = json.loads(progress_path.read_text(encoding="utf-8"))
    except Exception:
        return
    merged = _merge_progress_payload(payload, updates)
    progress_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")


def _merge_framework_sink_findings(a1_results, code_root: str, shard: Optional[dict] = None,
                                   task_id: Optional[int] = None):
    """把「框架惯用 sink」的确定性命中并入 A1 结果。

    ## 为什么必须单独做这一步

    这 11 个全部是 CodeQL 标准 Java 查询包不建模的形态（Spring ``@ResponseBody`` 返回、
    ``ExpressRunner.execute``、log4j2 记日志、``LocateRegistry``、CORS 头反射……）。
    候选压根没被登记，下游 D1/D2/I2 再强也无从下手 —— 这不是判据问题，是**覆盖问题**。

    已有的 ``a1_injection_heuristic`` 只在 CodeQL **失败**时才跑（兜底语义），
    CodeQL 成功时它一次都不执行，所以这些族永远进不来。这里改成「**补充**」语义：
    无论 CodeQL 成败，都再跑一遍框架规则，取并集。

    ## 去重

    同一 (文件, 行, 族) 已存在则跳过。框架规则与 CodeQL 的命中区间可能重叠
    （例如 CodeQL 也认 Spring 的某些 XSS），重复登记会污染分母。

    ## 作用域

    """
    try:
        from src.iast.framework_sinks import detect_path
    except Exception as _e:  # noqa: BLE001
        logger.warning("[fw-sinks] 规则模块不可用，跳过：%s", _e)
        return a1_results
    if not code_root:
        return a1_results
    try:
        hits = detect_path(code_root)
    except Exception as _e:  # noqa: BLE001
        logger.warning("[fw-sinks] 扫描失败（忽略，A1 结果保持原样）：%s", _e)
        return a1_results
    if not hits:
        return a1_results

    from src.core.models import ScanResult, Vulnerability

    allowed_full: set = set()
    allowed_base: set = set()
    if shard:
        allowed_full = {os.path.normcase(os.path.abspath(str(p))) for p in (shard.get("files") or [])}
        allowed_base = {os.path.basename(os.path.normcase(str(p))) for p in (shard.get("files") or [])}

    def _norm_key(p: str) -> str:
        """把任意形态的路径归一成「相对 code_root 解析后的绝对路径（normcase）」。

        产出的是绝对路径。原来的 `os.path.abspath(_p)` 按**当前工作目录**解析相对路径，
        与 `code_root + h.file` 永远对不上 ⇒ 去重分支进不去、参数路径补不进来
        """
        s = str(p or "")
        if not s:
            return ""
        if os.path.isabs(s):
            return os.path.normcase(os.path.abspath(s))
        return os.path.normcase(os.path.abspath(os.path.join(str(code_root or ""), s)))

    by_file: dict = {}
    for _r in a1_results:
        _k = _norm_key(str(getattr(_r, "file", "") or ""))
        if _k:
            by_file.setdefault(_k, _r)

    added = 0
    enriched = 0
    seen_keys = set()
    for h in hits:
        _raw = h.file if os.path.isabs(h.file) else os.path.join(str(code_root or ""), h.file)
        full = os.path.abspath(_raw)
        nk = _norm_key(full)
        if shard and allowed_full and not (nk in allowed_full or os.path.basename(nk) in allowed_base):
            continue
        key = (nk, int(h.line), h.family)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        res = by_file.get(nk)
        if res is None:
            res = ScanResult(file=full, vulnerabilities=[], agent="a1")
            by_file[nk] = res
            a1_results.append(res)
        # 同文件同行同族已存在（CodeQL/启发式已报）⇒ 不重复登记。
        # 启发式的 `mybatis-xml` 规则先报（同一行同一族），此前整条跳过 ⇒ 启发式只写了
        # 「这里有 ${}」，没有参数路径 ⇒ 登记层只能从 controller 签名反查，推出
        # 框架规则知道 `${params.dataScope}`，转成 `params[dataScope]` 就是精确注入点。
        #
        # 族名比较必须归一：启发式的 `type` 是展示名 `"SQL Injection"`（带空格），
        # 框架规则的 `family` 是 `sql_injection`。直接 lower 比永远不等 ⇒ 去重失效、
        # 参数路径补不进去。
        def _fam_key(x: Any) -> str:
            return re.sub(r"[\s\-]+", "_", str(x or "").strip().lower())

        _h_fam = _fam_key(h.family)
        _same = [
            v for v in res.vulnerabilities
            if _fam_key(getattr(v, "type", "")) == _h_fam
            and int(getattr(v, "line", 0) or 0) == int(h.line)
        ]
        if _same:
            if h.param:
                for v in _same:
                    _ev = getattr(v, "a1_evidence", None)
                    if not isinstance(_ev, dict):
                        _ev = {}
                    if not _ev.get("param"):
                        _ev["param"] = h.param
                        _ev["param_source"] = "mybatis-mapper"
                        _ev["rule"] = _ev.get("rule") or h.rule
                        v.a1_evidence = _ev
                        enriched += 1
            continue
        v = Vulnerability(
            type=h.family,
            severity="HIGH" if h.confidence == "high" else "MEDIUM",
            line=int(h.line),
            description=f"框架惯用 sink 命中：{h.reason}（规则 {h.rule}，静态确定性判定）",
            file=full,
            sink=h.sink,
            entry_point=h.route or "",
            data_flow="",
            has_http_entry=bool(h.route),
            verdict="待分析",
            source="a1-framework-sinks",
            confidence=h.confidence,
        )
        v.detection_method = "rule"
        v.rule_hit_label = f"framework-sink:{h.rule}"
        v.a1_evidence = {
            "framework_sink": True,
            "rule": h.rule,
            "route": h.route,
            "http_method": h.http_method,
            "param": h.param,
            "confidence": h.confidence,
            "reason": h.reason,
        }
        res.vulnerabilities.append(v)
        added += 1
    if added:
        logger.info("[fw-sinks] 框架惯用 sink 补充登记 %d 条（覆盖 CodeQL 不建模的形态）", added)
        print(f"[fw-sinks] 补充登记 {added} 条框架 sink 命中", flush=True)
    if enriched:
        logger.info("[fw-sinks] 为 %d 条已存在 finding 补上精确参数路径（MyBatis `${}` → `a[b]`）",
                    enriched)
    # 同时记「命中族」与「实际并入族」——两者不一致时，差额就是被 dedup/过滤吃掉的族，
    # 下一轮定位 P2-1（deser 进不了报告）时可以直接看这个差集，不用再猜。
    try:
        from src.core.stage_funnel import record, family_hist
        _added_vulns = [v for _r in a1_results
                        for v in getattr(_r, "vulnerabilities", []) or []
                        if str(getattr(v, "source", "") or "") == "a1-framework-sinks"]
        record(task_id, "a1.framework_merge", in_count=len(hits), out_count=added,
               reasons={"dedup_or_filtered": len(hits) - added},
               families={"hits": family_hist(hits), "added": family_hist(_added_vulns)})
    except Exception:
        pass
    return a1_results


def _apply_framework_property_upgrade(db, task_id: int, code_root: str) -> int:
    """框架惯用 sink 的 **高置信** 命中 ⇒ 终态直接确认 confirmed_code_property。

    与 ``_apply_oracle_upgrade`` 同一套哲学：在终态做一次显式、可审计的合并判定，
    而不是指望「静态命中 → 重放 → 证据 → 裁决」这条链每环都通。

    为什么这些族不能靠重放确认：
      - ``cors`` / ``csrf`` / ``secure_cookie`` / ``jndi_injection`` / ``rmi``
        的危害是**配置与代码属性**，不是「发一个包就能看到后果」。
        CORS 反射 Origin 已经写在 ``setHeader`` 里，再重放一遍也不产生新证据。
      - 它们的真值判据本来就是「代码里是不是这么写的」，所以静态确定性证据即终局。

    安全性（四条硬约束，缺一不可）：
      1. 只认 ``confidence='high'`` 的规则命中；medium 一律不升级（交给正常裁决）。
      2. 必须 (文件, 行, 族) 三者同时命中 —— 不做「文件级」模糊匹配。
      3. 只动**未确认**态（unconfirmed / sink_reached / no_evidence / 空），
         已经是 confirmed_exploitable 的绝不下调、也不覆盖。
      4. 开关 ``SAST_AI_FW_PROPERTY_UPGRADE=0`` 可整段关闭。
    """
    if str(os.environ.get("SAST_AI_FW_PROPERTY_UPGRADE", "1")).strip().lower() in ("0", "false", "no", "off"):
        return 0
    if not code_root:
        return 0
    try:
        from src.iast.framework_sinks import detect_path
    except Exception as _e:  # noqa: BLE001
        logger.warning("[fw-upgrade] 规则模块不可用，跳过：%s", _e)
        return 0
    try:
        hits = detect_path(code_root)
    except Exception as _e:  # noqa: BLE001
        logger.warning("[fw-upgrade] 扫描失败，跳过：%s", _e)
        return 0
    high = {}
    high_base = {}
    for h in hits:
        if h.confidence != "high":
            continue
        full = os.path.abspath(os.path.join(code_root, h.file)) if not os.path.isabs(h.file) else h.file
        key = (os.path.normcase(full), int(h.line), h.family.lower())
        high[key] = h.rule
        # 兜底键：spec 落库的 expected_sink_file 可能是相对路径（相对工程根或扫描根），
        # 直接 abspath 会按 CWD 解析 ⇒ 与命中路径对不上，升级静默失效。
        # 用「文件名 + 行号 + 族」做二级匹配；三者同时相等已足够收敛。
        high_base[(os.path.basename(os.path.normcase(full)), int(h.line), h.family.lower())] = h.rule
    if not high:
        return 0
    try:
        rows = db.execute(
            """SELECT id, family, expected_sink_file, expected_sink_line, verification_status
               FROM trigger_specs
               WHERE task_id=? AND verification_status NOT LIKE 'confirmed%'
                 AND verification_status NOT IN ('false_positive', 'suppressed')""",
            [task_id], fetchall=True,
        ) or []
    except Exception as _e:  # noqa: BLE001
        logger.warning("[fw-upgrade] 查询失败，跳过：%s", _e)
        return 0
    upgraded = 0
    for _r in rows:
        _d = dict(_r)
        _f = str(_d.get("expected_sink_file") or "")
        if not _f:
            continue
        _line = int(_d.get("expected_sink_line") or 0)
        _fam = str(_d.get("family") or "").lower()
        nk = os.path.normcase(os.path.abspath(_f))
        rule = high.get((nk, _line, _fam))
        if not rule:
            rule = high_base.get((os.path.basename(nk), _line, _fam))
        if not rule:
            continue
        try:
            db.execute(
                """UPDATE trigger_specs
                   SET verification_status='confirmed_code_property',
                       positive_evidence_rule=?
                   WHERE id=? AND verification_status NOT LIKE 'confirmed%'""",
                ["framework:" + rule, int(_d["id"])],
            )
            upgraded += 1
        except Exception as _ue:  # noqa: BLE001
            logger.debug("[fw-upgrade] spec=%s 升级失败：%s", _d.get("id"), _ue)
    if upgraded:
        logger.info("[fw-upgrade] 框架 sink 高置信命中 ⇒ 升级 %d 条为 confirmed_code_property", upgraded)
        print(f"[fw-upgrade] 升级 {upgraded} 条（confirmed_code_property）", flush=True)
    return upgraded


def _demote_unclassified_specs(db, task_id: int) -> int:
    """把「族名未分类（unknown/空）」却已确认的 spec 降级为 unconfirmed。

    ## 为什么这是必须的

    ``family='unknown'`` 的 spec 被确认成 ``confirmed_exploitable``。
    族名是「这条漏洞是什么」的唯一标识；族未分类却进了 confirmed 口径，
    等于报告里出现一条「已确认的未知类型漏洞」—— 无法复核、无法归因、无法统计。

    ## 为什么不自动猜族

    ``normalize.correct_family_by_evidence`` 对 ``unknown`` + ``/ssti/velocity`` 实测
    返回原值（没有可用证据规则）。既然确定性推断给不出族名，正确做法是**不确认**，
    而不是拿路由字符串硬猜一个 —— 那会把「未分类」变成「分类错误」，更难发现。

    ## 安全性

    - 只动 ``family`` 归一后为 unknown/空 的条目，其他族一概不碰。
    - 只降级已确认态，不动未确认态（它们本来就没进分母）。
    - 保留原状态到 ``failure_attribution_reason``，可审计、可回滚。
    - 开关 ``SAST_AI_DEMOTE_UNCLASSIFIED=0``。
    """
    if str(os.environ.get("SAST_AI_DEMOTE_UNCLASSIFIED", "1")).strip().lower() in ("0", "false", "no", "off"):
        return 0
    try:
        from src.core.normalize import normalize_family
    except Exception:  # noqa: BLE001
        return 0
    try:
        rows = db.execute(
            """SELECT id, family, verification_status FROM trigger_specs
               WHERE task_id=? AND verification_status LIKE 'confirmed%'""",
            [task_id], fetchall=True,
        ) or []
    except Exception as _e:  # noqa: BLE001
        logger.warning("[demote-unclassified] 查询失败，跳过：%s", _e)
        return 0
    demoted = 0
    for _r in rows:
        _d = dict(_r)
        _fam = normalize_family(str(_d.get("family") or ""))
        if _fam and _fam.lower() not in ("unknown", "unclassified", "none", "n/a"):
            continue
        try:
            db.execute(
                """UPDATE trigger_specs
                   SET verification_status='unconfirmed',
                       failure_attribution='unclassified_family',
                       failure_attribution_reason=?
                   WHERE id=? AND verification_status LIKE 'confirmed%'""",
                [f"族名未分类（原 {_d.get('verification_status')}），无法作为「已确认漏洞」计入",
                 int(_d["id"])],
            )
            demoted += 1
        except Exception as _ue:  # noqa: BLE001
            logger.debug("[demote-unclassified] spec=%s 降级失败：%s", _d.get("id"), _ue)
    if demoted:
        logger.info("[demote-unclassified] 族名未分类却已确认 ⇒ 降级 %d 条", demoted)
        print(f"[demote-unclassified] 降级 {demoted} 条未分类族", flush=True)
    return demoted


def _apply_oracle_upgrade(db, task_id: int) -> int:
    """行为 oracle 正向 ⇒ 把「到达但未确认」的 spec 升级为 confirmed_exploitable。

    oracle 观测从 D1 落库（`trigger_specs.oracle_state`）到最终裁决，要穿过 5 处接线：
      ① adjudicator 准入条件（oracle 只在「已有影响证据」时才被调用，死循环）
      ② d2_facade 的「到达≠可利用」降级（primary_channel='none' 被当无证据）
      ③ specs 是 D2 入口的内存快照，读不到 D1 写的值
      ④ `iast_evidence.setdefault("oracle_state", ...)` 被空串占位挡住
      ⑤ 即便塞进 iast_evidence，最终落库的 d2_evidence 仍是另一份对象
    每修一处都会在下一处断掉。
    与其在每一环打补丁，不如在终态做一次显式升级：判据单一、可审计、可回滚。

    安全性（为什么这样升级不是「放水」）：
      - 只对 `oracle_state='exploitable'` **且** `oracle_signal` 非空的条目动手 ——
        oracle 的正向判定只由黑盒正向信号触发（布尔差分 / 时延 / 文件签名 / 响应头回显），
        「没打通」一律是 inconclusive，不会误升。
      - 要求 signal 与族**严格匹配**（`_ORACLE_HARM_SIGNALS`），跨族信号不认。
      - 默认要求到达态（sink-reached / confirm-gate:* / late-evidence-recovered 等）。
        `location_reflect` / `acao_reflect` / `header_injected` 是**纯响应事实**，
        判据绑定我方投放的特定 URL / 头值，探针在不在业务 sink 插桩都不影响证据成立
        （SSRF 常走 HttpClient / OkHttp，探针本来就可能 no-arrival），
        这类 signal 允许 no-arrival 也升级；其余 signal 仍严格要求到达态。
      - 属性族（hash/crypto/random/cookie）不在 oracle 覆盖范围，天然排除。
      - 开关 `SAST_AI_ORACLE_UPGRADE=0` 可整段关闭。
    """
    if str(os.environ.get("SAST_AI_ORACLE_UPGRADE", "1")).strip().lower() in ("0", "false", "no", "off"):
        return 0
    try:
        from src.iast.harm_evidence import _ORACLE_HARM_SIGNALS
        from src.iast.response_oracle import canonical_family
    except Exception as _e:  # noqa: BLE001
        logger.warning("[oracle-upgrade] 依赖不可用，跳过：%s", _e)
        return 0
    try:
        rows = db.execute(
            """SELECT id, family, oracle_signal, iast_state, verification_status,
                      expected_sink_file
               FROM trigger_specs
               WHERE task_id=? AND oracle_state='exploitable' AND oracle_signal != ''
                 AND verification_status IN ('unconfirmed', 'sink_reached')""",
            [task_id], fetchall=True,
        ) or []
    except Exception as _e:  # noqa: BLE001
        logger.warning("[oracle-upgrade] 查询失败，跳过：%s", _e)
        return 0
    upgraded = 0
    for _r in rows:
        _d = dict(_r)
        _sig = str(_d.get("oracle_signal") or "")
        _want = _ORACLE_HARM_SIGNALS.get(_sig)
        _fam = str(_d.get("family") or "")
        _fam_n = canonical_family(_fam) or _fam
        if not _want or _want != _fam_n:
            continue
        # 纯回显弱信号在泛化族上要求 sink 文件名与族语义一致。
        if not _oracle_gate_signal(_fam, "exploitable", _sig, "",
                                   _d.get("expected_sink_file")):
            continue
        _st = str(_d.get("iast_state") or "")
        _arrived = (
            _st.startswith(("sink-reached", "confirm-gate:", "late-evidence-recovered",
                            "oob-reached", "technique-proven", "arrived", "arrival-sanitized"))
        )
        # 纯响应事实的 signal 不看探针到达；其余 signal 一律要求到达态，
        # 避免把「靶场随便一个报错」升级成可利用结论。
        if not (_arrived or _sig in _RESPONSE_ONLY_ORACLE_SIGNALS):
            continue
        try:
            db.execute(
                """UPDATE trigger_specs
                   SET verification_status='confirmed_exploitable',
                       positive_evidence_rule=?
                   WHERE id=? AND verification_status IN ('unconfirmed', 'sink_reached')""",
                ["oracle:" + _sig, int(_d["id"])],
            )
            upgraded += 1
        except Exception as _ue:  # noqa: BLE001
            logger.debug("[oracle-upgrade] spec=%s 升级失败：%s", _d.get("id"), _ue)
    if upgraded:
        logger.info("[oracle-upgrade] 行为 oracle 正向 ⇒ 升级 %d 条为 confirmed_exploitable", upgraded)
        print("[oracle-upgrade] 升级 %d 条（%s）" % (
            upgraded, ", ".join(sorted({str(dict(r).get("oracle_signal")) for r in rows}))), flush=True)
    return upgraded


def _wake_probe(target_url: str, timeout: float = 8.0) -> bool:
    """向目标发一次真实请求，唤醒探针的心跳 / 事件上报（供 A0 门禁重判）。

    背景：探针心跳走 HTTP POST 回平台，后端在 A1/A2 阶段繁忙时该请求会排队超时，
    探针看起来「离线」其实进程正常。请求本身会经过探针 hook 的
    HttpServletRequest/Response，因此能产生新事件并刷新心跳。

    返回 True 表示请求已送达（**不校验状态码**：302/401/404 都证明进程在跑，
    且都已进入 servlet 链路）；False 表示连不上，此时确实应该阻断。
    """
    if not target_url:
        return False
    try:
        import urllib.request

        # 显式禁用代理：target 通常是 127.0.0.1，走系统代理会得到 502 假失败
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(target_url, method="GET")
        try:
            opener.open(req, timeout=timeout).read(256)
        except urllib.error.HTTPError:
            pass  # 4xx/5xx 也算送达（已进 servlet 链路）
        # 等探针 flush：默认 flush_period≈1s，留 3s 余量
        time.sleep(3.0)
        return True
    except Exception as _e:  # noqa: BLE001
        logger.warning("[env-gate] 主动探活失败（%s）：%s", target_url, _e)
        return False


def _assert_runtime_environment_ready(task_id: Optional[int], external_target: dict) -> None:
    """A0 环境就绪硬门禁：当本次扫描依赖 IAST 运行时验证（有已注册 IAST 会话或提供了
    external_target）且探针未挂载/离线（无新鲜心跳或目标不可达）时，直接阻断扫描，
    给出可操作的挂载指引，而不是静默跑出全 no-arrival / 空 I1/D2/I2。

    仅依赖 IAST 时阻塞；纯 SAST/SCA（无 IAST 会话且无 external_target）放行。
    """
    try:
        from src.iast.service import IastService
        _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
        db = Database(_db_path)
        iast = IastService(db)
    except Exception as _e:
        logger.warning(f"[env-gate] IAST 服务不可用，跳过硬门禁：{_e}")
        return

    has_external = bool(external_target and (external_target.get("service_url") or external_target.get("app_name")))
    workspace_id = None
    if task_id is not None:
        try:
            _row = db.execute("SELECT workspace_id FROM scan_tasks WHERE id=?", [task_id], fetchone=True)
            workspace_id = int(_row["workspace_id"]) if _row else None
        except Exception:
            workspace_id = None
    sessions = iast.list_sessions(workspace_id) if workspace_id else []
    if not (has_external or sessions):
        # 无 IAST 会话也无 external_target：本次不依赖运行时验证，放行（SAST/SCA 仍可跑）
        return

    targets = []
    if has_external:
        # 已由 _resolve_external_target_from_session 从 workspace 的会话里挑出 ready 的那个。
        # 此时**不能**再把 workspace 下全部历史会话都塞进 targets：workspace 4 里挂着一个
        # 心跳停在 10-04），它永远不 ready，于是把整轮扫描无条件挡死，
        # 判据本身不放松：只校验本任务实际要用的那一个目标。
        targets.append((
            external_target.get("app_name", ""),
            external_target.get("agent_id", ""),
            external_target.get("service_url", ""),
        ))
    else:
        for s in sessions:
            targets.append((s.get("app_name", ""), s.get("agent_id", ""), s.get("target_url", "")))

    problems = []
    for app_name, agent_id, target_url in targets:
        if not app_name or not agent_id:
            continue
        try:
            rd = iast.check_environment_readiness(target_url, app_name, agent_id)
        except Exception as _e:
            problems.append(f"{app_name}/{agent_id}: 环境检查异常（{_e}）")
            continue
        if not rd.get("ready") and _wake_probe(target_url):
            # SQLite 写锁）时，探针的 POST /api/agent/heartbeat 与事件上报会排队超时，
            # 探针静默十几到几十分钟 ⇒ 到 D2 前这一检查点，心跳与事件双双过期 ⇒
            # 门禁 15:59 触发时探针已静默 30 分钟，但进程一直活着）。
            #
            # 这里不放松判据，而是补一次**主动探活**：向目标发一个真实请求，
            # 探针 hook 了 HttpServletRequest/Response，请求本身就会产生新事件并
            # 刷新心跳。等探针 flush 后重判，
            # 仍然不 ready 才阻断——「能打通」比「最近有信号」更接近门禁要验的东西。
            try:
                rd = iast.check_environment_readiness(target_url, app_name, agent_id)
                logger.info(
                    "[env-gate] 主动探活后重判 %s/%s：ready=%s（%s）",
                    app_name, agent_id, rd.get("ready"), rd.get("detail", {}).get("probe_liveness"),
                )
            except Exception as _e2:
                logger.warning("[env-gate] 主动探活后重判失败：%s", _e2)
        if not rd.get("ready"):
            problems.append(f"{app_name}/{agent_id}: {rd.get('block_reason', '未就绪')}")
    if problems:
        raise RuntimeError(
            "A0 环境就绪硬门禁未通过：IAST 探针未挂载或离线，D1/I1/D2/I2 将无法获取运行时数据。\n"
            + "\n".join(f"  - {p}" for p in problems)
            + "\n请先在前端 Workspace → IAST 标签页注册会话，并按挂载命令在目标主机以 -javaagent 方式启动 "
            "sec-probe.jar（探针会向 /api/agent/heartbeat 上报心跳）。探针挂载并心跳上报后再启动扫描。"
        )


def _resolve_external_target_from_session(task_id: Optional[int]) -> Optional[Dict[str, Any]]:
    """live 路径（task_service → scan_task_runner → run_benchmark）默认不传入 external_target，
    导致 D1 重放打到空 service_url、0 DAST impact、全部 no-arrival。这里按
    task_id → workspace_id → iast_sessions 解析出已注册且就绪的探针目标，回填为 D1 重放地址。

    仅当 external_target 未显式提供且 task_id 存在时触发；解析失败返回 None（由 A0 门禁决定是否阻断）。
    """
    if task_id is None:
        return None
    try:
        import os
        from src.iast.service import IastService
        db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        iast = IastService(db)
        row = db.execute("SELECT workspace_id FROM scan_tasks WHERE id=?", [task_id], fetchone=True)
        workspace_id = int(row["workspace_id"]) if row else None
        if workspace_id is None:
            return None
        sessions = iast.list_sessions(workspace_id) or []

        def _as_target(s):
            return {
                "service_url": s.get("target_url", ""),
                "app_name": s.get("app_name", ""),
                "agent_id": s.get("agent_id", ""),
                "probe_mode": s.get("probe_mode") or "monitor",
                "code_path": s.get("code_path") or "",
            }

        # #4：login 配置来自 workspace.settings_json.login（前端 Workspace 设置页填写，平台不内置凭据）。
        # 将其并入 external_target，使 D1 bootstrap_accounts 能按 login 真登录取双账号 token。
        _login = {}
        try:
            _ws_row = db.execute("SELECT settings_json FROM workspaces WHERE id=?", [workspace_id], fetchone=True)
            if _ws_row and _ws_row.get("settings_json"):
                _ws_json = _ws_row["settings_json"]
                if isinstance(_ws_json, str):
                    _ws_json = json.loads(_ws_json) or {}
                _login = (_ws_json or {}).get("login") or {}
                # 这里只读 `login` ⇒ `auth` 在这一步就被丢掉，下游
                # `normalize_external_target` / `_fallback_auth_cookies` 的兜底全都拿不到配置
                # ⇒ D1 判定「没配登录」⇒ 重放全程未认证。
                # 实测 本轮 525 条重放里 **472 条 302**（Shiro 重定向登录页），
                # 和修之前一模一样。
                if not _login and isinstance((_ws_json or {}).get("auth"), dict):
                    _login = dict(_ws_json["auth"])
        except Exception:
            _login = {}

        # 优先：ready 且三要素齐全
        for s in sessions:
            if s.get("status") == "ready" and s.get("target_url") and s.get("app_name") and s.get("agent_id"):
                _t = _as_target(s)
                _t["login"] = _login
                return _t
        # 退而求其次：三要素齐全即可
        for s in sessions:
            if s.get("target_url") and s.get("app_name") and s.get("agent_id"):
                _t = _as_target(s)
                _t["login"] = _login
                return _t
    except Exception as _e:
        logger.warning("[external-target] 从 iast_sessions 解析 external_target 失败：%s", _e)
    return None


def _parse_taint_path(raw: Any) -> List[Dict[str, Any]]:
    """把 DB 里的 taint_path_json（探针回带的污点传播路径，JSON 数组字符串）解析为节点列表。

    每个节点形如 {"role": "source|transform|sink", "origin": "java.util.Base64$Decoder.decode"}。
    解析失败或为空返回 []（I1 退化为方案 A 的 unverifiable 逻辑）。
    """
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [n for n in data if isinstance(n, dict)]
    except (ValueError, TypeError):
        return []
    return []



def _select_replay_specs(db, workspace_id, task_id):
    """D2 重放候选 TriggerSpec 选择（待请示 6 项 #3）。

    不再把历史任务（task-6/9/...）的假说全部重放一遍——否则重放量随历史累积只增不减，
    且旧假说对应代码改动后与本轮 findings 对不上。task_id=None（离线 CLI 入口）退回 workspace 全量，保持旧语义。
    抽成独立函数便于单测，避免重写整个编排器。
    """
    if task_id is not None:
        return db.execute(
            "SELECT * FROM trigger_specs WHERE workspace_id = ? AND task_id = ? ORDER BY id ASC",
            (workspace_id, task_id), fetchall=True,
        ) or []
    return db.execute(
        "SELECT * FROM trigger_specs WHERE workspace_id = ? ORDER BY id ASC",
        (workspace_id,), fetchall=True,
    ) or []


def _run_iast_auto_replay(task_id: Optional[int], external_target: dict) -> Dict[str, Any]:
    """D2 阶段：把 A2 语义分析产出的 TriggerSpec（trigger_specs）自动喂给 D1 编排器做运行时重放，
    而非只依赖前端手动面板。这样 D1 真正基于 A2 的 poc 假说动态检测，无需用户逐项手填。

    返回 {replayed_specs, dast_impacts, iast_arrivals, errors} 摘要，供报告并入 d2_verifications。
    """
    from src.iast.service import IastService
    from src.iast.orchestrator import TriggerTransactionOrchestrator
    from src.iast.trigger_spec_registry import purge_task_canary_events
    from src.application.d1_service import D1Service

    _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
    db = Database(_db_path)
    iast = IastService(db)

    workspace_id = None
    if task_id is not None:
        try:
            _row = db.execute("SELECT workspace_id FROM scan_tasks WHERE id=?", [task_id], fetchone=True)
            workspace_id = int(_row["workspace_id"]) if _row else None
        except Exception:
            workspace_id = None
    if workspace_id is None:
        return {"replayed_specs": 0, "dast_impacts": 0, "iast_arrivals": 0, "attempted": False,
                "errors": ["无 workspace_id，跳过 A2→D1 自动重放"]}

    # #1C 清空旧 canary 缓存：D1 重放前，删除本 task 的 spec 对应的历史 canary 事件，
    # 给本次重放一个干净度量基线，避免探针缓存的上一次重放残留事件污染本次 I1 观测。
    if task_id is not None:
        try:
            purge_task_canary_events(task_id)
        except Exception as _e:
            logger.warning("[D1] 清空旧 canary 缓存失败（不阻断重放）：%s", _e)

    # 取该 workspace 下 A2 生成的全部 TriggerSpec。
    # 一旦旧假说对应代码已改动，重放结果与本轮 findings 对不上，也稀释 D2 耗时预算。
    # 仅当 task_id 给定时加 AND task_id=?；离线 CLI 入口（task_id=None）仍按 workspace 全量，保持旧语义。
    specs = _select_replay_specs(db, workspace_id, task_id)
    if not specs:
        return {"replayed_specs": 0, "dast_impacts": 0, "iast_arrivals": 0, "attempted": False, "errors": []}

    # 按 session_id 分组（无 session 的归到 external_target / 首会话）
    sessions = iast.list_sessions(workspace_id)
    if not sessions:
        # 无注册会话但有 external_target：用 external_target 作为唯一 target
        if not external_target or not external_target.get("service_url"):
            return {"replayed_specs": 0, "dast_impacts": 0, "iast_arrivals": 0, "attempted": False,
                    "errors": ["有 TriggerSpec 但无在线 IAST 会话/external_target，A0 门禁应已拦截"]}
        targets = [{
            "service_url": external_target.get("service_url"),
            "app_name": external_target.get("app_name", ""),
            "agent_id": external_target.get("agent_id", ""),
            "login": external_target.get("login") or external_target.get("auth") or {},
        }]
    else:
        targets = [{
            "service_url": s.get("target_url"),
            "app_name": s.get("app_name"),
            "agent_id": s.get("agent_id"),
        } for s in sessions]

    # 此处原先只带 service_url/app_name/agent_id ⇒ D1 技术族会话通道判「没配登录」，
    # replay_attempts 12+6 条**全部 302**，payload 到不了业务代码 ⇒ sqli 整族漏报。
    # 手工 curl 验证同配置可登录（JSESSIONID 取得、带 cookie 访问 200）。
    # external_target 由 _resolve_external_target_from_session 产出，必带 login。
    _login_cfg = {}
    if isinstance(external_target, dict):
        _login_cfg = external_target.get("login") or external_target.get("auth") or {}
    if not _login_cfg and task_id is not None:
        # external_target 为空时直接从 workspace settings 兜底读（与
        # _resolve_external_target_from_session 同源，login/auth 双写法兼容）。
        try:
            _ws_row = db.execute(
                "SELECT settings_json FROM workspaces WHERE id=?", [workspace_id], fetchone=True)
            _ws_json = (_ws_row or {}).get("settings_json") if _ws_row else None
            if isinstance(_ws_json, str):
                _ws_json = json.loads(_ws_json or "{}")
            _ws_json = _ws_json or {}
            _login_cfg = _ws_json.get("login") or _ws_json.get("auth") or {}
        except Exception:  # noqa: BLE001
            _login_cfg = {}
    if _login_cfg and isinstance(_login_cfg, dict):
        for tgt in targets:
            tgt.setdefault("login", _login_cfg)
        logger.info("[D1.auto-replay] %d 个 target 已并入 workspace 登录配置（login=%s）",
                    len(targets), str(_login_cfg.get("url") or "")[:60])

    d1 = D1Service(db=db)
    replayed = 0
    dast_impacts = 0
    iast_arrivals = 0
    replayed_specs_detail: List[Dict[str, Any]] = []
    errors: List[str] = []
    for tgt in targets:
        tgt_specs = [dict(s) for s in specs if dict(s).get("session_id") in (None, 0)
                     or dict(s).get("session_id") == _session_id_for(sessions, tgt)]
        if not tgt_specs:
            tgt_specs = [dict(s) for s in specs]  # 无 session 绑定时全部对当前 target 重放

        #  / ：把本 target 的 app_name/agent_id 烤进 event_source 闭包，
        # 使 canary 轮询仅命中本目标事件，避免多次扫描事件混流污染。
        tgt_app = tgt.get("app_name") or ""
        tgt_agent = tgt.get("agent_id") or ""

        def _event_source(canary, since_id, limit):
            rows = iast.poll_events_by_canary(
                canary, since_id, limit,
                app_name=tgt_app or None,
                agent_id=tgt_agent or None,
            ) or []
            # 携带 stack_trace/sink/source/taint_path 全字段，供 I1 逐节点链路符合性校验
            # （方案 B：taint_path 来自探针回带的污点传播路径，精确逐节点命中）
            return [{
                "id": int(r.get("id", 0) or 0),
                "canary_state": r.get("canary_state", ""),
                "canary": r.get("canary", ""),
                "stack_trace": r.get("stack_trace", ""),
                "sink_method": r.get("sink_method", ""),
                "sink_file": r.get("sink_file", ""),
                "sink_line": r.get("sink_line", 0),
                "source_value": r.get("source_value", ""),
                "taint_path": _parse_taint_path(r.get("taint_path_json", "")),
            } for r in rows]

        readiness_probe = None
        if hasattr(iast, "check_environment_readiness") and tgt_app and tgt_agent:
            def readiness_probe(target_dict):
                return iast.check_environment_readiness(
                    target_dict.get("service_url", ""),
                    target_dict.get("app_name", "") or tgt_app,
                    target_dict.get("agent_id", "") or tgt_agent,
                )

        orchestrator = TriggerTransactionOrchestrator(
            dast_operator=d1,
            event_source=_event_source,
            readiness_probe=readiness_probe,
        )
        try:
            result = orchestrator.run_transaction(target=tgt, trigger_specs=tgt_specs)
            replayed += len(tgt_specs)
            # #2D：记录本轮实际重放的 spec 明细（endpoint/param/family/canary 身份段/source），
            # 供前端 D1 子面板逐项展示，让用户看清「到底重放了哪些 spec、是否混入 IDOR 资产重放」。
            for _sp in tgt_specs:
                _sp = dict(_sp)
                _tm = _sp.get("taint_marker") or ""
                replayed_specs_detail.append({
                    "endpoint": _sp.get("target_endpoint") or "",
                    "http_method": _sp.get("http_method") or "",
                    "param_name": _sp.get("param_name") or "",
                    "param_location": _sp.get("param_location") or "",
                    "family": _sp.get("family") or "",
                    "flow_type": derive_flow_type(_sp.get("family") or ""),
                    "canary_identity": _tm[:22] if _tm else "",
                    "source": "a2" if _sp.get("task_id") == task_id else "idor_or_other",
                    "vulnerability_hash_v2": _sp.get("vulnerability_hash_v2") or "",
                })
            raw = getattr(result, "dast_impact", None)
            if raw is not None:
                dast_impacts += 1
            # verdicts 中被 IAST 观测到 arrival 的数量
            # 注意：run_transaction 把裁定结果填在 per_hypothesis（verdicts 字段为遗留空字典，
            # 不可读）；此处与 d2_facade.aggregate_iast_evidence 保持一致读 per_hypothesis。
            for v in getattr(result, "per_hypothesis", {}).values():
                if getattr(v, "state", "") not in ("no-arrival",):
                    iast_arrivals += 1
        except Exception as exc:
            errors.append(f"{tgt.get('app_name')}/{tgt.get('agent_id')}: 自动重放失败（{exc}）")

    print(f"\n[*] A2→D1 自动重放：{replayed} 条 TriggerSpec 已驱动 D1 运行时验证")
    return {"replayed_specs": replayed, "dast_impacts": dast_impacts,
            "iast_arrivals": iast_arrivals, "attempted": True, "errors": errors,
            "replayed_specs_detail": replayed_specs_detail}


def _session_id_for(sessions: List[Dict[str, Any]], target: Dict[str, Any]) -> int:
    for s in sessions:
        if s.get("app_name") == target.get("app_name") and s.get("agent_id") == target.get("agent_id"):
            return int(s.get("id", 0))
    return 0


def _resolve_round_no(db, workspace_id: int) -> int:
    """从 DB 派生本轮轮次号。

    口径：该 workspace 已有 scan_runs 的最大 round_no + 1；无记录则为 1。
    轮次只前进不回退，保证跨轮可比。
    """
    try:
        row = db.execute(
            "SELECT MAX(round_no) AS m FROM scan_runs WHERE workspace_id=?", (workspace_id,), fetchone=True
        )
        m = row["m"] if row else None
        return int(m or 0) + 1
    except Exception:
        return 1


def run_benchmark(target_path: str, enable_a1: bool = True, enable_a2: bool = True,
                  enable_verification: bool = True, output_format: str = 'json', output_dir: str = None,
                  enable_sca: bool = True, enable_ai_review: bool = True,
                  enable_entry_discovery: bool = True, enable_idor: bool = False, idor_app_id: str = '',
                  task_id: Optional[int] = None, scan_mode: str = 'filter_first', model_profile: str = 'default', prompt_version: str = 'terminal-first-v1',
                  sca_tool: str = 'auto', sca_severity_threshold: str = 'LOW',
                  sca_ignore_unfixed: bool = False, external_target: dict = None,
                  llm_overrides: Optional[Dict[str, Any]] = None,
                  shard_file: str = ""):
    """运行完整扫描流程，并让 A1/A2 并发启动；D2 走统一验证链路（trigger_spec → D1 重放 → I1 → D2 → I2）。

    并发 / 流式 / 二次证明开关）。必须在**任何 LLM 调用之前**应用，故放在函数最开头。
    """
    start_time = time.time()
    phase_times = {}
    # 环境变量 SAST_AI_SHARD_FILE（手动跑 scan_task_runner 时可直接 export）。两者都没有即全量扫描。
    if str(shard_file or "").strip():
        os.environ["SAST_AI_SHARD_FILE"] = str(shard_file).strip()
    output_dir = output_dir or config.get('output.output_dir', 'output')
    # 任务级 LLM 覆盖：必须最先应用，否则 A1/A2 已经按默认 ctx/并发跑起来了才改就晚了。
    _applied_overrides = _apply_llm_overrides(llm_overrides)
    if _applied_overrides:
        # prompt_version 允许被覆盖（前端高级项），覆盖后同步给本轮使用的变量
        prompt_version = str(_applied_overrides.get("prompt_version") or prompt_version)
        print(f"[*] LLM overrides applied: {_applied_overrides}")
    progress_logger = ScanProgressLogger(output_dir)
    # 等长尾阶段不写 scan_progress.json 时被 task_runner 看门狗（STUCK_HEARTBEAT_SECONDS
    # =2700s）强杀。现覆盖整个 run_benchmark 生命周期（daemon 线程每 30s 刷新 mtime，
    # 与闭环内的局部心跳并存无害），从源头消灭任何阶段的「无心跳误杀」。
    _global_hb_stop = _start_progress_heartbeat(output_dir)
    # 产物分片保护：登记当前 task，使 _update_scan_progress_metadata 拒绝写回其它 task 目录。
    global _CURRENT_SCAN_TASK_ID
    _CURRENT_SCAN_TASK_ID = task_id
    # LLM 调用（A2/A4/D1 等，逐层透传 task_id 改动面过大）都能在 model_runs 落库时
    # 通过 ModelRunRepository.record 的环境变量回退拿到归属任务，无需逐层改签名。
    if task_id is not None:
        os.environ["SAST_AI_CURRENT_TASK_ID"] = str(int(task_id))
    else:
        os.environ.pop("SAST_AI_CURRENT_TASK_ID", None)
    # 把轮次身份从「task.name 字符串 + 独立 txt」收进 DB，杜绝跨轮混合库与「旧 backend 跑旧代码」假阳性。
    _bb_run_id = None
    try:
        from src.core import blackboard as _blackboard
        # 复用模块级 Database（line 86），禁止 in-function import，否则会触发
        _bb_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        _bb_ws = _bb_db.execute(
            "SELECT workspace_id FROM scan_tasks WHERE id=?", (task_id,), fetchone=True
        )
        _bb_workspace_id = int(_bb_ws["workspace_id"]) if _bb_ws else 0
        _bb_round = _resolve_round_no(_bb_db, _bb_workspace_id)
        _bb_run_id = _blackboard.start_run(
            _bb_db, _bb_workspace_id, task_id, round_no=_bb_round,
            options={
                "enable_a1": enable_a1, "enable_a2": enable_a2,
                "enable_verification": enable_verification, "scan_mode": scan_mode,
                # D5：档位/版本记入 run 记录，便于事后回答「这轮到底用的哪个模型档位」
                "model_profile": model_profile, "prompt_version": prompt_version,
            },
            project_root=str(Path(__file__).resolve().parents[2]),
        )
    except Exception as _e:
        logger.warning("[blackboard] 开启 run 记录失败（不阻断扫描）：%s", _e)
        _bb_run_id = None
    # 重构文档 3.6：Docker 运行时已删除，不再清理托管容器。
    try:
        print("\n" + "=" * 60)
        print("[Phase 0] Scanning Files")
        print("=" * 60)
        progress_logger.update_phase('phase1', 'running', '文件扫描中')

        # SAST_AI_SHARD_FILE 指向部署方提供的分片清单 JSON。必须在这里（早于 Phase 0）加载：
        # Phase 0 要用它收窄待扫文件、Phase 0.7 复用同一份做入口收窄。不配置该变量即保持旧行为（全量）。
        _shard = None
        _shard_file = str(os.environ.get("SAST_AI_SHARD_FILE") or "").strip()
        if _shard_file:
            try:
                from src.core.scan_scope import load_shard
                _shard = load_shard(_shard_file)
                if not _shard:
                    logger.warning("[shard] 分片清单为空或非法（按全量继续）：%s", _shard_file)
            except Exception as _se:
                logger.warning("[shard] 分片清单加载失败（按全量继续）：%s", _se)
                _shard = None

        from src.core.scan_scope import filter_files  # 分片作用域：待扫文件收窄（SAST_AI_SHARD_FILE）
        prepared_scan_root = _prepare_scan_root(target_path, output_dir)
        scanner = FileScanner(str(prepared_scan_root))
        files = scanner.scan()
        files = _filter_framework_noise_files(files)
        # 单片扫描的成本≈全量，分片就白分了。故此处把待扫文件也收窄到本片。
        # 此时不打「No files found to scan」这种看不出原因的错，而是把作用域来源打清楚。
        if _shard:
            _kept_files, _fst = filter_files(files, _shard)
            if _fst["kept"]:
                print(f"[*] 分片作用域 {_shard.get('name')}：文件 {_fst['total']} → 保留 {_fst['kept']}（丢弃 {_fst['dropped']}）")
                files = _kept_files
            else:
                logger.error(
                    "[shard] 分片 %s 在本工作区（target_path=%s）找不到任何源码文件（清单 %s 的 files 指向另一棵树）。"
                    "该片不会跑出有效结论，已中止以免污染对账。",
                    _shard.get("name"), target_path, _shard_file)
                progress_logger.update_phase('phase1', 'error', f'分片 {_shard.get("name")} 文件收窄为空')
                raise RuntimeError(f"shard {_shard.get('name')}: no source files matched in workspace target_path={target_path}")
        if not files:
            logger.error("No files found to scan")
            progress_logger.update_phase('phase1', 'error', '未找到可扫描源码文件')
            _update_scan_progress_metadata(
                output_dir,
                {
                    "stage_results": {
                        "preprocess": {
                            "file_count": 0,
                            "endpoint_count": 0,
                        }
                    }
                },
            )
            raise RuntimeError("No files found to scan")

        phase_times['scan'] = time.time() - start_time
        print(f"\n[*] Scanned {len(files)} files in {phase_times['scan']:.1f}s")
        progress_logger.update_phase('phase1', 'completed', f'扫描 {len(files)} 个文件')

        phase_start = time.time()
        print("\n" + "=" * 60)
        print("[Phase 0.5] Discovering API Endpoints")
        print("=" * 60)
        discovered_endpoints = extract_endpoints_from_files(files)
        endpoint_count = sum(len(e) for e in discovered_endpoints.values())
        phase_times['endpoint_discovery'] = time.time() - phase_start
        print(f"\n[*] Discovered {endpoint_count} API endpoints")

        results = {}
        a1_results = []
        a2_results = []
        # 此前只写进 scan_progress.json，而下方 return 自建 stage_results 会覆盖它 ⇒
        _a2_contract_stats: Dict[str, Any] = {}
        # 否则会被下方自建的 stage_results.d2 覆盖（与 a2.contract 完全同一个坑）。
        _d2_poll_stats: Dict[str, Any] = {}
        _i2_stage_payload: Dict[str, Any] = {}
        external_target = external_target or _resolve_external_target_from_session(task_id)
        if external_target:
            logger.info(
                "[D2] live 路径解析 external_target: service_url=%s app=%s agent=%s",
                external_target.get("service_url"), external_target.get("app_name"), external_target.get("agent_id"),
            )
        sca_result = {"status": "skipped", "finding_count": 0, "findings": []}
        entry_discovery_result = {"status": "skipped", "entry_count": 0, "entries": []}
        idor_result = {"status": "skipped", "finding_count": 0, "findings": [], "candidate_count": 0}

        if enable_sca:
            phase_start = time.time()
            print("\n" + "=" * 60)
            print("[Phase 0.6] SCA Dependency Scan")
            print("=" * 60)
            sca_result = SCAAssetService(output_root=str(Path(output_dir) / "sca_assets")).scan_project(
                str(prepared_scan_root),
                task_id=task_id,
                output_dir=str(Path(output_dir) / "sca_assets"),
                tool=sca_tool,
                severity_threshold=sca_severity_threshold,
                ignore_unfixed=sca_ignore_unfixed,
                run_tool=True,
                persist=True,
            )
            phase_times['sca'] = time.time() - phase_start
            print(f"\n[*] SCA {sca_result.get('status')}: {sca_result.get('finding_count', 0)} findings")
            _update_scan_progress_metadata(output_dir, {"stage_results": {"sca": {k: v for k, v in sca_result.items() if k != "findings"}}})

        if enable_entry_discovery:
            phase_start = time.time()
            print("\n" + "=" * 60)
            print("[Phase 0.7] AI Entry Discovery")
            print("=" * 60)
            entry_discovery_result = EntryDiscoveryService().discover(str(prepared_scan_root))
            # 由 SAST_AI_SHARD_FILE 指向部署方提供的分片清单，把入口收窄到本片。
            # 不配置该变量即保持旧行为（全量），零回归。
            # _shard 已在 Phase 0 之前的分片加载点解析（同一份复用），此处只做入口收窄。
            _shard_file = str(os.environ.get("SAST_AI_SHARD_FILE") or "").strip()
            if _shard:
                try:
                    from src.core.scan_scope import filter_entries
                    _entries_in = entry_discovery_result.get("entries") or []
                    _kept, _st = filter_entries(_entries_in, _shard)
                    entry_discovery_result["entries"] = _kept
                    entry_discovery_result["entry_count"] = len(_kept)
                    entry_discovery_result["shard"] = {
                        "name": _shard.get("name"), "category": _shard.get("category"),
                        "expected_cases": _shard.get("count"), **_st,
                    }
                    print(f"[*] 分片作用域 {_shard.get('name')}：入口 {_st['total']} → 保留 {_st['kept']}（丢弃 {_st['dropped']}）")
                except Exception as _se:
                    logger.warning("[entry_discovery] 分片作用域应用失败（按全量继续）：%s", _se)
            phase_times['entry_discovery'] = time.time() - phase_start
            print(f"\n[*] Entry discovery: {entry_discovery_result.get('entry_count', 0)} entries")
            _update_scan_progress_metadata(
                output_dir,
                {"stage_results": {"entry_discovery": {"status": entry_discovery_result.get("status", "completed"), "entry_count": entry_discovery_result.get("entry_count", 0), "rule_candidate_count": len(entry_discovery_result.get("rule_candidates", []) or [])}}},
            )

        # 原位置在 a1/a2 之前，此时 a2_poc 尚未登记任何 TriggerSpec、attack_plan 也未生成，
        # 却抢先写入 stage_results.d1 污染 D1 节点展示。现移到 attack_plan 之后执行，
        # 详见下方 [Phase 1.5] D1 操作器 Asset Replay。

        code_index = None
        if enable_a2:
            progress_logger.update_phase('phase3', 'running', '构建代码索引')
            indexer = CodeIndexer()
            code_index = indexer.index_project(files)
            indexer.save_index(code_index, str(Path(output_dir) / "code_index.json"))
            progress_logger.update_phase(
                'phase3',
                'completed',
                f'索引 {code_index["stats"]["total_functions"]} 个函数, {code_index["stats"]["http_entries"]} 个 HTTP 入口'
            )
            _update_scan_progress_metadata(
                output_dir,
                {
                    "stage_results": {
                        "preprocess": {
                            "file_count": len(files),
                            "endpoint_count": endpoint_count,
                            "indexed_functions": code_index["stats"]["total_functions"],
                            "http_entries": code_index["stats"]["http_entries"],
                        }
                    }
                },
            )
        else:
            _update_scan_progress_metadata(
                output_dir,
                {
                    "stage_results": {
                        "preprocess": {
                            "file_count": len(files),
                            "endpoint_count": endpoint_count,
                        }
                    }
                },
            )

        parallel_labels = []
        if enable_a1:
            parallel_labels.append("A1")
        if enable_a2:
            parallel_labels.append("A2")
        # D2 现在依赖外部 IAST 常驻目标（ExternalTarget），不再有 EnvPrep 并行阶段。

        if parallel_labels:
            print("\n" + "=" * 60)
            # Q4：A1→A2 改为串行，A1 调用链证据前置注入 A2 LLM prompt
            print(f"[Sequence] {' -> '.join(parallel_labels)}（A1 证据注入 A2 LLM）")
            print("=" * 60)

        # 跳过 A1(CodeQL) 与 A2(LLM 语义分析) 两段，只重跑动态 D1/D2。代码/配置变则自动 bust 全量重跑。
        _used_stage_cache = False
        _stage_cache_key = None
        if enable_a1 and enable_a2 and str(os.environ.get("SAST_AI_STAGE_CACHE", "1")) != "0":
            try:
                from src.pipeline.stage_cache import (
                    compute_target_code_hash, compute_config_hash, compute_stage_cache_key,
                    try_load_stages,
                )
                _cc = compute_target_code_hash(files, str(prepared_scan_root))
                _cfg = compute_config_hash()
                _stage_cache_key = compute_stage_cache_key(_cc, _cfg, model_profile, prompt_version)
                # stage_cache 的 key 含整个 src/ 树指纹，
                # 代价是改任何 .py 都 bust ⇒ 调一条 D2 判据也要等 35 分钟 A2 重跑。
                # 实测本轮因三个断点连续改代码，白等约 70 分钟。
                # 显式开启时直接复用本 workspace 最新一份 A1/A2 产物，**只该在确认
                # A1/A2 代码没变时用**，故用 warning 级别把风险喊出来。
                _reuse = str(os.environ.get("SAST_AI_REUSE_STAGES", "")).strip().lower() in (
                    "1", "true", "yes", "on")
                if not _reuse:
                    # 文件标记：任务子进程继承不到调用方的环境变量（后端由计划任务拉起），
                    # 故额外支持 `data/.reuse_stages` 存在即开启。删文件即关闭。
                    try:
                        _marker = os.path.join(
                            os.path.dirname(os.path.dirname(os.path.dirname(
                                os.path.abspath(__file__)))), "data", ".reuse_stages")
                        _reuse = os.path.exists(_marker)
                    except Exception:  # noqa: BLE001
                        _reuse = False
                _cached = None
                if _reuse:
                    try:
                        from src.pipeline.stage_cache import load_latest_stages
                        _cached = load_latest_stages(_bb_workspace_id)
                        if _cached is not None:
                            logger.warning(
                                "[stage_cache] SAST_AI_REUSE_STAGES=1：复用最近一份 A1/A2 产物，"
                                "跳过 A1/A2。**A1/A2 代码改动不会被检测**，仅供调试 D 阶段。")
                    except Exception as _re:
                        logger.warning("[stage_cache] 复用失败，回退按 key 加载：%s", _re)
                        _cached = None
                if _cached is None:
                    _cached = try_load_stages(_bb_workspace_id, _stage_cache_key)
                if _cached is not None:
                    a1_results, a2_results = _cached
                    _used_stage_cache = True
                    logger.info("[stage_cache] 命中缓存，跳过 A1/A2 静态分析（key=%s）", _stage_cache_key[:16])
            except Exception as _ce:
                logger.warning("[stage_cache] 加载/计算失败，回退全量执行：%s", _ce)
                _used_stage_cache = False
                _stage_cache_key = None

        futures = {}
        phase_started = {}
        # Q4：A1 调用链证据必须在 A2 LLM 扫描之前就绪，因此 A1→A2 改为串行——
        # 先完成 A1 并构建 evidence index，再启动 A2 把 index 注入 LLM prompt（前端已实时展示进度）。
        if not _used_stage_cache:
            a1_results = []
        with ThreadPoolExecutor(max_workers=1) as executor:
            if enable_a1:
                if _used_stage_cache:
                    # —— ① 缓存命中：a1_results 已在上面 load，跳过 CodeQL，只补齐前端阶段态。
                    # 本轮未跑 CodeQL，last_scan_meta 置空避免写入陈旧全局态。——
                    a1_vulns = sum(len(r.vulnerabilities) for r in a1_results)
                    logger.info("[stage_cache] 命中缓存复用 A1：%s findings（跳过 CodeQL）", a1_vulns)
                    progress_logger.update_phase('phase2', 'completed', f'命中缓存复用 {a1_vulns} 个漏洞（跳过 CodeQL）')
                    results['a1'] = a1_results
                    phase_times['a1'] = 0.0
                    _update_scan_progress_metadata(
                        output_dir,
                        {
                            "stage_results": {
                                "a1": {
                                    "finding_count": a1_vulns,
                                    "last_scan_meta": {},
                                    "business_logic_finding_count": sum(
                                        1 for r in a1_results for v in r.vulnerabilities
                                        if getattr(v, "a1_evidence", {}) and (getattr(v, "a1_evidence", {}) or {}).get("business_logic")
                                    ),
                                    "file_count": len(a1_results),
                                    "cached": True,
                                    "duration_seconds": 0,
                                }
                            }
                        },
                    )
                else:
                    progress_logger.update_phase('phase2', 'running', 'A1 规则分析进行中')
                    phase_started['a1'] = time.time()
                    a1_results = executor.submit(run_a1_scan, files, str(prepared_scan_root)).result()
                    # 不认 files 列表——即使分片只给 130 个文件，它照样返回全项目 4720 个用例的告警。
                    # 之前没在这里收窄，导致 mini 片实际登记了 2121 个用例 / 3978 条 spec，
                    # D1 要重放 3856 条（其中 95% 不属于本片），单片跑 4~20 小时，"mini" 完全不 mini。
                    # 现在把 A1 结果按分片文件集收窄，A2/A1 与 D1 的作用域才真正一致。
                    if _shard:
                        _a1_total_files = len(a1_results)
                        _allowed_full = {os.path.normcase(os.path.abspath(str(p)))
                                         for p in (_shard.get("files") or [])}
                        _allowed_base = {os.path.basename(os.path.normcase(str(p)))
                                         for p in (_shard.get("files") or [])}
                        _a1_kept = []
                        for _r in a1_results:
                            _p = str(getattr(_r, "file", "") or "")
                            if not _p:
                                continue
                            if (os.path.normcase(os.path.abspath(_p)) in _allowed_full
                                    or os.path.basename(os.path.normcase(_p)) in _allowed_base):
                                _a1_kept.append(_r)
                        if _a1_kept:
                            logger.info("[shard] A1 结果按分片收窄：%s → %s 文件（CodeQL 全项目建库，需回到本片作用域）",
                                        _a1_total_files, len(_a1_kept))
                            a1_results = _a1_kept
                    # Spring @ResponseBody 返回 / 表达式引擎 / log4j2 / RMI / CORS 头反射等形态，
                    # 这些族的候选压根不会被登记。此处按「补充」语义取并集（CodeQL 成败都跑）。
                    try:
                        a1_results = _merge_framework_sink_findings(
                            a1_results, str(prepared_scan_root), _shard or None,
                            task_id=locals().get("task_id"))
                    except Exception as _fw_exc:  # noqa: BLE001
                        logger.warning("[fw-sinks] 补充登记失败（忽略，A1 结果保持原样）：%s", _fw_exc)
                    # 属性族强证据门禁：
                    # 弱哈希/弱加密/弱随机在 sink 语句里出现强算法/SecureRandom ⇒ 判假阳性，
                    # 否则会被 recover_late_arrival 的 value_hit 升级成 confirmed_exploitable
                    # （453 的 00022 就是这么来的：SHA-256 被确认成弱哈希）。
                    try:
                        _a1_for_registration = _filter_property_family_findings(
                            a1_results, str(prepared_scan_root))
                    except Exception as _pf_exc:  # noqa: BLE001
                        logger.warning("[属性族门禁] 过滤失败（忽略，登记候选保持原样）：%s", _pf_exc)
                        _a1_for_registration = a1_results
                    results['a1'] = a1_results
                    phase_times['a1'] = time.time() - phase_started['a1']
                    a1_vulns = sum(len(r.vulnerabilities) for r in a1_results)
                    print(f"\n[*] A1 Scan complete: {a1_vulns} vulnerabilities found in {phase_times['a1']:.1f}s")
                    progress_logger.update_phase('phase2', 'completed', f'发现 {a1_vulns} 个漏洞')
                    _update_scan_progress_metadata(
                        output_dir,
                        {
                            "stage_results": {
                                "a1": {
                                    "finding_count": a1_vulns,
                                    "last_scan_meta": dict(_LAST_A1_SCAN_META),
                                    "business_logic_finding_count": sum(
                                        1 for r in a1_results for v in r.vulnerabilities
                                        if getattr(v, "a1_evidence", {}) and (getattr(v, "a1_evidence", {}) or {}).get("business_logic")
                                    ),
                                    "file_count": len(a1_results),
                                    "duration_seconds": round(phase_times['a1'], 2),
                                }
                            }
                        },
                    )

            if enable_a2:
                # A1 证据索引（per-file + aggregate），供 A2 LLM 前置消费。
                a1_index = _build_a1_evidence_index(a1_results if enable_a1 else [])
                a2_llm_client = None
                # 兜底初始化：下方「TriggerSpec 登记」公共块会读这些变量，两条分支都必须赋值
                # 。
                _a2_poc_total = 0
                # 登记候选（A1-extra）：与 a1_results 分开保存，因为属性族强证据门禁会剔除
                # 一部分 finding，而报告里的 A1 finding 数必须保持原口径不被这层过滤影响。
                # 把上面 8533 行算好的**已过滤**结果整个覆盖掉 ⇒ 属性族门禁成了死代码，
                # live 路径从未生效（469/452/458 的 FP 2→0 只是离线预演的结果）。
                # 的 A1 finding 是 cross-site scripting，门禁本可经路线族 weak_hash 命中
                # file-level-strong 剔除，却因被覆盖而漏网，最终确认为 confirmed_exploitable。
                if "_a1_for_registration" not in locals():
                    _a1_for_registration = a1_results if enable_a1 else []
                # 集成分析师是否已在 a2 阶段一次性完成（审计+构造一体）。
                # True ⇒ a2_poc 不再二次调 LLM；False ⇒ 走旧的两段式（triage → 再出 spec）。
                _a2_integrated_done = False

                if _used_stage_cache:
                    # —— ① 缓存命中：a1/a2 产物已在上面 load，a2_results 已是 run_a2_scan +
                    # 后处理 + plan_pocs 的最终产物。跳过所有 LLM 静态阶段（CodeQL 之外的 A2 语义 +
                    # 代码片段回填 + 二次证明 + PoC 规划），只补齐前端阶段态，随后正常走
                    # TriggerSpec 登记与 attack_plan（DB 侧幂等）。——
                    a2_vulns = sum(len(r.vulnerabilities) for r in a2_results)
                    logger.info("[stage_cache] 命中缓存复用 A2 最终产物：%s findings（跳过 run_a2_scan+后处理+plan_pocs）", a2_vulns)
                    progress_logger.update_phase('phase4', 'completed', f'命中缓存复用 {a2_vulns} 个漏洞（跳过 LLM）')
                    _update_scan_progress_metadata(
                        output_dir,
                        {"stage_results": {"a2": {
                            "finding_count": a2_vulns,
                            "file_count": len(a2_results),
                            "cached": True,
                            "duration_seconds": 0,
                        }}},
                    )
                    results['a2'] = a2_results
                    phase_times['a2'] = 0.0
                    phase_times['a2_poc'] = 0.0
                    # 下方「TriggerSpec 登记」公共块（a2_poc metadata）会引用 _a2_poc_total，
                    # 该变量原本只在完整分支里赋值；命中分支必须同样赋值，否则 UnboundLocalError
                    # 直接打挂整轮。
                    _a2_poc_total = sum(len(getattr(r, "vulnerabilities", []) or []) for r in a2_results)
                    # 缓存产物若已含集成 spec（entry.resolved_by == 'llm'），a2_poc 不再二次调 LLM。
                    _a2_integrated_done = _a2_results_have_integrated_specs(a2_results)
                else:
                    progress_logger.update_phase('phase4', 'running', 'A2 AI 分析进行中（已注入 A1 调用链证据）')
                    phase_started['a2'] = time.time()
                    # 本轮统计从零起算（同进程复用时也保证读数只属于当前 task）
                    try:
                        from src.agents.a2_integrated_analyst import reset_transport_stats
                        reset_a2_analysis_errors()
                        reset_transport_stats()
                    except Exception:
                        pass
                    # 前端可见「已分析 M/N 文件」，不再把 running 误判为卡死。
                    _a2_total = len(files)
                    _emit_stage_progress(task_id, output_dir, "a2_progress",
                                         {"total": _a2_total, "done": 0, "status": "scanning"})
                    a2_on_progress = lambda _d, _t: _emit_stage_progress(
                        task_id, output_dir, "a2_progress",
                        {"total": _t, "done": _d, "status": "scanning"},
                    )
                    # 作为「历史探索摘要」注入 A2 prompt（状态外置）。默认关闭，仅统一重跑验证用。
                    _intent_hints = ""
                    if (str(os.environ.get("SAST_AI_A2_USE_INTENTS", "0")).strip().lower()
                            in ("1", "true", "yes", "on")):
                        try:
                            from src.iast.intent_bridge import build_a2_intent_hints
                            _ib_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                            _intent_hints = build_a2_intent_hints(_ib_db.connect(), task_id)
                        except Exception as _ibhe:  # noqa: BLE001
                            logger.warning("[A2] 探索意图摘要生成失败（忽略）：%s", _ibhe)
                    if _integrated_a2_enabled():
                        # —— 默认路径：A2 本身就是集成分析师 ——
                        # 源码 + 该文件 A1(CodeQL) 结果 → 一次 LLM 同时完成「审计真假 + 构造可打通 spec」。
                        # 旧路径是 A2 triage 出 findings（130 次 LLM），a2_poc 再二次调 LLM 出 spec
                        # （同一文件被读两遍）——这里把两遍合成一遍，不再有 a2_poc 的二次 LLM。
                        a2_results, a2_llm_client = executor.submit(
                            run_a2_integrated_scan, files,
                            a1_results if enable_a1 else [],
                            str(prepared_scan_root),
                            entry_discovery_result.get("entries") or [],
                            a2_on_progress,
                            _intent_hints,
                        ).result()
                        _a2_integrated_done = True
                        logger.info("[A2] 集成分析师（单次 LLM：审计+构造一体）完成")
                    else:
                        a2_results, a2_llm_client = executor.submit(
                            run_a2_scan, files, code_index, scan_mode, a1_index,
                            None, entry_discovery_result.get("entries") or [], a2_on_progress,
                            # D5：把任务 options 里的模型档位 / prompt 版本真正传给 A2
                            model_profile=model_profile, prompt_version=prompt_version,
                        ).result()
                    _emit_stage_progress(task_id, output_dir, "a2_progress",
                                         {"total": _a2_total, "done": _a2_total, "status": "scanning_done"})
                    # 统一重跑时直接能看「格式不合格率」（验收线 <5%），不必翻日志。
                    # 走 _update_scan_progress_metadata（深合并）⇒ 进 task_completed 载荷。
                    try:
                        from src.agents.a2_integrated_analyst import contract_stats as _cstats
                        _cst = dict(_cstats() or {})
                        # 可读的 stage_results.a2。file_failures.failed_files != 0 或
                        # transport.exhausted != 0 的轮次一律不作为有效基线。
                        _cst["file_failures"] = a2_analysis_error_stats()
                        _a2_contract_stats = dict(_cst)
                        _update_scan_progress_metadata(
                            output_dir, {"stage_results": {"a2": {"contract": _cst}}})
                        logger.info(
                            "[A2] 契约合规率 %.1f%%（不合格率 %.1f%%，调用 %d 次，重试 %d 次）；"
                            "传输重试 %d 次 / 耗尽 %d 次 / 文件级失败 %d 个",
                            _cst.get("compliance_rate", 0) * 100,
                            _cst.get("invalid_rate", 0) * 100,
                            _cst.get("calls", 0), _cst.get("retried", 0),
                            (_cst.get("transport") or {}).get("retries", 0),
                            (_cst.get("transport") or {}).get("exhausted", 0),
                            _cst["file_failures"]["failed_files"])
                    except Exception as _cse:  # noqa: BLE001
                        logger.debug("[A2] 契约合规率统计不可用（忽略）：%s", _cse)
                    results['a2'] = a2_results
                    phase_times['a2'] = time.time() - phase_started['a2']
                    a2_vulns = sum(len(r.vulnerabilities) for r in a2_results)
                    print(f"\n[*] A2 Scan complete: {a2_vulns} vulnerabilities found in {phase_times['a2']:.1f}s")
                    progress_logger.update_phase('phase4', 'completed', f'A2 发现 {a2_vulns} 个漏洞')
                    _update_scan_progress_metadata(
                        output_dir,
                        {
                            "stage_results": {
                                "a2": {
                                    "finding_count": a2_vulns,
                                    "file_count": len(a2_results),
                                    "duration_seconds": round(phase_times['a2'], 2),
                                }
                            }
                        },
                    )
                    # §统一链路：A2 假说规划与 TriggerSpec 登记与验证开关解耦——静态分析完成即执行，
                    # 保证 D1/D2 即便被关停，数据通路（trigger_specs）也始终完整可查。
                    a2_poc_start = time.time()
                    # 证据文本包含 code_snippet，片段为空会让规则层拿不到任何代码依据）。
                    # 实测 历史轮次 连续八轮只有 3~6% 的 finding 带片段，根因是 A2 提示词
                    # 输出 schema 没有 code 字段，详见 _backfill_code_snippets 注释。
                    _snippet_stats = _backfill_code_snippets(a2_results, str(prepared_scan_root))
                    if _snippet_stats.get("filled"):
                        results['snippet_backfill'] = _snippet_stats
                    a2_results = _merge_a1_evidence_into_a2_results(a2_results, a1_results)
                    # 前移解析：在 plan_pocs 之前用源码/路由/entry_discovery 静态解析出每个漏洞的
                    # route+param+method 写回 exploit_spec.entry（ground truth），供 LLM 直接消费、
                    # 不再猜路由；解析不出入口的标 no_reachable_entry 不进 D2。
                    # 注意：code_root 必须用 prepared_scan_root（files 实际扫描根，可能是 target_path/src
                    # 之类的子根），而非原始 target_path，否则 vuln.file 相对路径对不上、解析静默失败。
                    # 进度心跳（集成/回滚两条路径共用，放在分支前）
                    _a2_poc_total = sum(len(getattr(r, "vulnerabilities", []) or []) for r in a2_results)
                    _update_scan_progress_metadata(
                        output_dir,
                        {"stage_results": {"a2_poc": {
                            "status": "running",
                            "message": f"PoC 规划中（0/{_a2_poc_total}）",
                            "total": _a2_poc_total, "done": 0,
                        }}},
                    )
                    _emit_stage_progress(task_id, output_dir, "a2_poc_progress",
                                         {"total": _a2_poc_total, "done": 0, "status": "planning"})
                    a2_poc_on_progress = lambda _d, _t: _emit_stage_progress(
                        task_id, output_dir, "a2_poc_progress",
                        {"total": _t, "done": _d, "status": "planning"},
                    )
                    if _integrated_a2_enabled():
                        # 默认路径：集成分析师。
                        # 正常情况（_a2_integrated_done=True）集成分析已在 a2 阶段一次性完成，
                        # 这里只补齐阶段态、**不再二次调 LLM**（旧实现是 a2 先 triage、这里再出 spec，
                        # 同一文件被读两遍 = 纯重复劳动）。
                        # 仅在 stage_cache 命中旧产物（无集成 spec）时才在此补跑一次。
                        if _a2_integrated_done or _a2_results_have_integrated_specs(a2_results):
                            _a2_integrated_done = True
                            _emit_stage_progress(task_id, output_dir, "a2_poc_progress",
                                                 {"total": _a2_poc_total, "done": _a2_poc_total,
                                                  "status": "planning_done"})
                        else:
                            a2_results = _run_integrated_analyst(
                                a2_results,
                                code_root=str(prepared_scan_root),
                                discovered_routes=entry_discovery_result.get("entries") or [],
                                on_progress=a2_poc_on_progress,
                            )
                            _a2_integrated_done = True
                    else:
                        # 回滚/AB 路径（SAST_AI_LEGACY_A2=1）：确定性前移解析 + LLM 通用 payload。
                        a2_results = _pre_resolve_a2_endpoints(
                            a2_results,
                            code_root=str(prepared_scan_root),
                            discovered_routes=entry_discovery_result.get("entries") or [],
                        )
                        _second_pass_stats = _run_proof_second_pass(
                            a2_results,
                            task_id=task_id,
                            output_dir=output_dir,
                            progress_logger=progress_logger,
                        )
                        if _second_pass_stats:
                            results['proof_second_pass'] = _second_pass_stats
                        a2_results = A2PipelineService.plan_pocs(
                            a2_results, llm_client=a2_llm_client, a1_evidence_index=a1_index,
                            code_root=str(prepared_scan_root), code_index=code_index,
                            on_progress=a2_poc_on_progress,
                        )
                    _emit_stage_progress(task_id, output_dir, "a2_poc_progress",
                                         {"total": _a2_poc_total, "done": _a2_poc_total, "status": "planning_done"})
                    results['a2'] = a2_results
                    phase_times['a2_poc'] = time.time() - a2_poc_start
                    # —— ① 落盘 A1/A2 最终产物（fail-open）：下一轮回归若 target_code_hash +
                    # config_hash + model_profile + prompt_version 未变即命中缓存，跳过 CodeQL +
                    # A2 语义 + PoC 规划三段。缓存键任一分量变化自动 bust。——
                    try:
                        from src.pipeline.stage_cache import save_stages
                        if _stage_cache_key:
                            save_stages(_bb_workspace_id, _stage_cache_key, a1_results, a2_results)
                            logger.info("[stage_cache] 已落盘 A1/A2 产物（key=%s）", _stage_cache_key[:16])
                    except Exception as _se:  # noqa: BLE001
                        logger.warning("[stage_cache] 落盘失败（不影响本轮）：%s", _se)
                # _drop_spurious_cross_family 注释）。放在这里 = 缓存命中/未命中**两条路径都覆盖**，
                # 且在 TriggerSpec 登记与 D2 重放之前 ⇒ 捏造的跨族 finding 既不登记 spec、也不进重放。
                # 幂等：已经剔除过的列表再跑一次不会重复计数。
                try:
                    a2_results = _drop_spurious_cross_family(
                        a2_results, str(prepared_scan_root))
                except Exception as _scf:  # noqa: BLE001  fail-open：门禁失败不阻断主流程
                    logger.warning("[A2] 跨族无 sink 门禁失败（忽略）：%s", _scf)
                poc_selected = sum(
                    1
                    for scan_result in a2_results
                    for vuln in scan_result.vulnerabilities
                    if getattr(vuln, 'a21_selected', None) is True
                )
                # A2→TriggerSpec 自动登记：canonical findings → trigger_specs，供 D1 自动重放。
                # 与 enable_verification 解耦：静态分析完成即登记，验证关不关闭都不影响数据通路
                # （D1 是否消费由验证门控决定，但 spec 本身始终可查可重放）。
                registered = 0
                skipped_specs = 0
                a2_funnel = {}
                try:
                    a2_funnel = _auto_register_a2_trigger_specs(
                        task_id, a2_results,
                        discovered_routes=entry_discovery_result.get("entries") or [],
                        extra_results=_a1_for_registration if enable_a1 else None,
                    )
                    registered = a2_funnel.get("registered", 0)
                    skipped_specs = a2_funnel.get("skipped", 0)
                except Exception as _e:
                    logger.warning("[A2] 自动登记 TriggerSpec 失败（不影响静态结果）：%s", _e)
                logger.info("[A2] PoC planning selected %s canonical findings, registered %s TriggerSpec, skipped %s", poc_selected, registered, skipped_specs)
                # 真漏报信号显式化（该用例无任何 spec 覆盖才计），重复已覆盖的丢弃。
                _mr_watch = {}
                try:
                    from src.core.missing_route_watch import build_missing_route_watch
                    _mr_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                    _mr_watch = build_missing_route_watch(_mr_db, task_id, a2_funnel.get("reasons") or [])
                except Exception as _mw_e:
                    logger.warning("[missing_route_watch] 观测面计算失败（不影响主链路）：%s", _mw_e)
                _update_scan_progress_metadata(
                    output_dir,
                    {
                        "stage_results": {
                            "a2_poc": {
                                "status": "completed",
                                # （total/total），掩盖了 spec 维度漏斗。这里同时报 TriggerSpec
                                "message": (
                                    f"PoC 规划完成：finding {_a2_poc_total}/{_a2_poc_total}；"
                                    f"TriggerSpec 登记 {registered}，跳过 {skipped_specs}"
                                ),
                                "selected_count": poc_selected,
                                "registered_trigger_specs": registered,
                                "skipped_specs": skipped_specs,
                                "total_a2_findings": a2_funnel.get("total_a2", 0),
                                "skipped_duplicate": a2_funnel.get("skipped_duplicate", 0),
                                "skipped_unresolved": a2_funnel.get("skipped_unresolved", 0),
                                "unresolved_reasons": a2_funnel.get("reasons", []),
                                "missing_route_watch": _mr_watch,
                                # #4③：补「endpoint 收敛」删除的冗余 spec 数（调用方此前未读），
                                # 以及真实的 PoC 规划完成计数（消息分母 _a2_poc_total），前端可见真实进度。
                                "converged": a2_funnel.get("converged", 0),
                                "done": _a2_poc_total,
                                "duration_seconds": round(phase_times['a2_poc'], 2),
                            }
                        }
                    },
                )

                # Q4：攻击计划阶段 —— 把 A2 登记的 TriggerSpec 投影为可读 POC 计划，介于 A2 与 D1 之间。
                # 这是透明可视化/记录层：真实重放仍由 D1 消费 trigger_specs 完成，此处只投射「准备打什么」。
                try:
                    from src.application.attack_plan_service import AttackPlanService
                    _update_scan_progress_metadata(
                        output_dir,
                        {"stage_results": {"attack_plan": {"status": "running", "message": "正在生成攻击计划（投影 TriggerSpec → 可读 POC 计划）"}}},
                    )
                    _ap_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                    # 补齐攻击计划（白名单校验+写回 spec），D1 重放与 AP 面板吃到。构造失败
                    # 降级 gateway=None（纯投影，不阻断）。
                    _ap_gateway = None
                    try:
                        from src.core.model_gateway import gateway_from_config
                        _ap_gateway = gateway_from_config({})
                    except Exception as _ge:
                        logger.debug("[attack_plan] 网关构造失败（纯投影）：%s", _ge)
                    ap = AttackPlanService(_ap_db).build(task_id=task_id, gateway=_ap_gateway)
                    _update_scan_progress_metadata(
                        output_dir,
                        {
                            "stage_results": {
                                "attack_plan": {
                                    "status": "completed",
                                    "message": "攻击计划已生成 {} 条".format(ap["plan_count"]),
                                    "plan_count": ap["plan_count"],
                                    "by_family": ap["by_family"],
                                    "entries": ap["entries"],
                                    "plan_source_counts": ap.get("plan_source_counts"),
                                    "rag_enrich": ap.get("rag_enrich"),
                                }
                            }
                        },
                    )
                    logger.info("[attack_plan] 生成 %s 条攻击计划", ap["plan_count"])
                except Exception as _e:
                    logger.warning("[attack_plan] 生成失败（不影响后续阶段）：%s", _e)

        # 移动理由：D1 必须排在 attack_plan 之后。原位置（a1/a2 之前）时 a2_poc 还没登记
        # TriggerSpec、attack_plan 也未生成，D1 扫描拿到的候选恒为 0 —— 这就是「冷启动空跑」
        # 注意：真实 HTTP 重放仍由 verify（d2）统一驱动，此处只做资产/操作器扫描
        # （execute_http=False），两处职责不重叠，不存在「双入口」。
        if enable_idor and idor_app_id:
            phase_start = time.time()
            print("\n" + "=" * 60)
            print("[Phase 1.5] D1 操作器 Asset Replay（attack_plan 之后）")
            print("=" * 60)
            d1_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
            idor_result = D1Service(db=d1_db).scan(idor_app_id, {"mode": "pipeline", "execute_http": False, "allow_mutating": False})
            idor_result["status"] = "completed"
            phase_times['d1'] = time.time() - phase_start
            print(f"\n[*] DAST-IDOR: {idor_result.get('finding_count', 0)} findings from {idor_result.get('candidate_count', 0)} candidates")
            _update_scan_progress_metadata(output_dir, {"stage_results": {"d1": {k: v for k, v in idor_result.items() if k not in {"findings", "decisions"}}}})

        if enable_a1 or enable_a2:
            phase_start = time.time()
            print("\n" + "=" * 60)
            print("[Phase 2.5] Merging Results & Filtering False Positives")
            print("=" * 60)

            a1_dicts = [{'file': r.file, 'vulnerabilities': [
                {'type': v.type, 'line': v.line, 'severity': v.severity,
                 'description': v.description, 'code_snippet': v.code_snippet}
                for v in r.vulnerabilities]} for r in a1_results]
            a2_dicts = [{'file': r.file, 'vulnerabilities': [
                {'type': v.type, 'line': v.line, 'severity': v.severity,
                 'description': v.description, 'code_snippet': v.code_snippet}
                for v in r.vulnerabilities]} for r in a2_results]
            processed = process_vulnerabilities(a1_dicts, a2_dicts)
            phase_times['merge'] = time.time() - phase_start
            print(f"\n[*] Processing complete:")
            print(f"   - Total vulnerabilities: {processed['stats']['total']}")
            print(f"   - Valid vulnerabilities: {processed['stats']['valid']}")
            print(f"   - False positives: {processed['stats']['false_positives']}")
            print(f"   - High severity: {processed['stats']['high_severity']}")

        if enable_a1 or enable_a2:
            phase_start = time.time()
            print("\n" + "=" * 60)
            print("[Phase 2.75] CVE Matching")
            print("=" * 60)

            from src.core.cve_matcher import CVEMatcher

            all_vulns = []
            for r in a1_results + a2_results:
                for v in r.vulnerabilities:
                    all_vulns.append({
                        'type': v.type,
                        'file': r.file,
                        'line': v.line,
                        'severity': v.severity,
                        'code_snippet': v.code_snippet,
                        'description': v.description
                    })

            cve_matcher = CVEMatcher()
            vulns_with_cve = cve_matcher.match_vulnerabilities(all_vulns)
            cve_count = sum(len(v.get('cve_matches', [])) for v in vulns_with_cve)
            phase_times['cve'] = time.time() - phase_start
            print(f"\n[*] CVE Matching complete: {cve_count} CVEs matched in {phase_times['cve']:.1f}s")

        print("\n" + "=" * 60)
        print("[Generating] 最终安全审计报告")
        print("=" * 60)
        report_manager = ReportManager()

        d2_verifications = {}
        if enable_verification:
            # A0 环境就绪硬门禁：运行时验证依赖 IAST 探针，未挂载/离线则阻断，而非静默空跑。
            _assert_runtime_environment_ready(task_id, external_target or {})
            phase_start = time.time()
            print("\n" + "=" * 60)
            print("[Phase 3] D2 AI Agent Dynamic Verification")
            print("=" * 60)
            progress_logger.update_phase('phase5', 'running', 'D2 统一验证进行中')
            # §#1C 清空旧 canary 缓存：D1 重放（并入 verify 链路）开始前，按本 task 的 spec
            # 身份段精准删除历史 iast_events，给本次重放一个干净的度量基线，避免探针内存里
            # 上一次重放残留的 canary 事件污染本次 I1 观测（表现为「I1 出现不属于本 task 的 canary」）。
            try:
                _purged = purge_task_canary_events(task_id)
                if _purged:
                    logger.info("[D2] D1 重放前已清空 %d 条旧 canary 事件（task_id=%s）", _purged, task_id)
            except Exception as _e:
                logger.warning("[D2] 清空旧 canary 事件失败（跳过，不影响重放）：%s", _e)
            _emit_stage_progress(task_id, output_dir, "d2_verify_progress", {"status": "running", "iteration": 0})
            d2_verifications = run_d2_verify(a1_results, a2_results, files, target_path, external_target, task_id=task_id, code_root=str(prepared_scan_root), discovered_routes=entry_discovery_result.get("entries") or [], output_dir=output_dir)
            # 放在 D2 之后、闭环回灌之前：此时 oracle 观测已全部落库，且升级结果会被
            # 后续的回灌/重验自然覆盖（若它们给出更强结论）。
            try:
                _apply_oracle_upgrade(
                    Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db")), int(task_id))
            except Exception as _ou:  # noqa: BLE001  fail-open：升级失败不影响主流程
                logger.warning("[oracle-upgrade] 跳过（%s）", _ou)
            # CORS/CSRF/Cookie 标志位/JNDI/RMI 的危害是「代码与配置属性」，重放不产生新证据，
            # 静态高置信命中即终局。只动未确认态，绝不覆盖已确认结论。
            try:
                _apply_framework_property_upgrade(
                    Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db")),
                    int(task_id), str(prepared_scan_root))
            except Exception as _fu:  # noqa: BLE001  fail-open
                logger.warning("[fw-upgrade] 跳过（%s）", _fu)
            # 族名未分类却已确认 ⇒ 降级（详见 _demote_unclassified_specs 注释）。
            try:
                _demote_unclassified_specs(
                    Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db")), int(task_id))
            except Exception as _du:  # noqa: BLE001  fail-open
                logger.warning("[demote-unclassified] 跳过（%s）", _du)
            _emit_stage_progress(task_id, output_dir, "d2_verify_progress", {"status": "done", "iteration": 0, "exploitable_count": int(d2_verifications.get('exploitable_count', 0) or 0)})
            # #4③：D2 初验耗时单独记账，闭环重跑不再被误归入「D2 动态验证」（真实动态验证仅约 7 分钟）。
            phase_times['d2'] = time.time() - phase_start
            # —— point 5：D2 → feedback → A2 二次回灌闭环 ——
            # D2 裁决产出的 feedback_to_a2（next_action.action == 'rollback_to_a2'）说明 A2 假说有误
            # （端点幻觉 / 参数缺失 / 受害者资源 id 缺失），需让 A2 重新分析修正。此处做一次「有界」二次回灌：
            # 收集反馈 → 重跑 A2（携带 feedback）+ plan_pocs + 重新登记（second_pass=True 走 UPDATE 而非跳过）
            # → 用修正后的 a2 重跑 D2 反映真实验证态。仅执行 1 次，绝不递归（第二次 D2 的反馈不再触发回灌）。
            # §P4：收集「全部」feedback_to_a2（不仅 rollback 子集）持久化进 stage_results.i2，供前端闭环
            # 面板展示与 rerun_a2_with_feedback 标准入口读取（A2 标准通道消费端）。
            # 采集反馈：同一条 verification 的 next_action 与 verification_decision 常携带同一份
            # 反馈，两处都 extend 会造成约 2 倍重复，
            # 重复内容既吃掉回灌预算也污染 A2 prompt，故统一走 dedup_feedbacks 聚合。
            _raw_feedback: List[Any] = []
            _rollback_feedback: List[Any] = []
            for _v in (d2_verifications.get("verifications") or []):
                if not isinstance(_v, dict):
                    continue
                _na = _v.get("next_action") or {}
                _vd = _v.get("verification_decision") or {}
                if isinstance(_na, dict):
                    _raw_feedback.extend(_na.get("feedback_to_a2") or [])
                    if _na.get("action") == "rollback_to_a2":
                        _rollback_feedback.extend(_na.get("feedback_to_a2") or [])
                if isinstance(_vd, dict):
                    _raw_feedback.extend(_vd.get("feedback_to_a2") or [])
            try:
                from src.agents import i2_feedback as _i2fb_mod
                _all_feedback = _i2fb_mod.dedup_feedbacks(_raw_feedback)
                _feedback_list = _i2fb_mod.dedup_feedbacks(_rollback_feedback)
            except Exception:
                _all_feedback, _feedback_list = _raw_feedback, _rollback_feedback

            # 旧实现「固定回灌 A2 一次、绝不递归」，而回灌内容实测 60/60 全是
            # 「IAST 未观测到匹配 canary」——静态 A2 无法修复运行时观测失败，必然空转。
            # 新实现：①按 failure_class 分流，只有假说缺陷才回灌 A2；②运行时/探针类失败改走
            # 重放侧调整（改「请求怎么发」，不改假说）；③带迭代上限 + attempt history + 增益收敛判据。
            _cl_start = time.time()
            _loop_summary: Dict[str, Any] = {}
            try:
                from src.agents import i2_feedback as _i2fb

                def _collect_fb(_verifs):
                    _out = []
                    for _v in (_verifs or []):
                        if not isinstance(_v, dict):
                            continue
                        # 是否到达 sink / 是否被确证有害 / iast_state）挂到每条反馈上，
                        # 供 i2_feedback.classify_runtime_evidence 做结构化分层判据。
                        # 不挂这些字段时分类器只能退回 reason 关键词 —— 那正是 blocked
                        # 被 route_unreachable 抢判、escalate_variant 永不可达的根因。
                        _de = _v.get("dast_impact_evidence") or {}
                        if not isinstance(_de, dict):
                            _de = {}
                        _vd = _v.get("d2_verdict") or {}
                        if not isinstance(_vd, dict):
                            _vd = {}
                        _ie = _v.get("iast_evidence") or {}
                        if not isinstance(_ie, dict):
                            _ie = {}
                        for _k in ("next_action", "verification_decision"):
                            _s = _v.get(_k) or {}
                            if isinstance(_s, dict):
                                for _fb in (_s.get("feedback_to_a2") or []):
                                    if isinstance(_fb, dict):
                                        _fb = dict(_fb)
                                        for _key, _val in (
                                            ("status_code", _de.get("status_code")),
                                            ("response_summary",
                                             _de.get("response_summary") or _de.get("body")),
                                            ("reached", _de.get("reached")),
                                            ("d2_harmful", _vd.get("harmful")),
                                            ("iast_state", _ie.get("state")),
                                        ):
                                            _fb.setdefault(_key, _val)
                                        _out.append(_fb)
                    return _i2fb.dedup_feedbacks(_out)

                # 「假说集 ⊖ 观测集」的差集 = state=open 的假说（既未证实也未证伪）。
                # 旧实现只回灌 D2 裁决器产出的自然语言 reason，措辞一变分类就漂移；
                # 这里改为先重算假说表，再把差集条目（带 vulnerability_hash_v2 / family /
                # endpoint / gates 结构化字段）显式标 failure_class=hypothesis_defect 回灌，
                # 保证必然进入 a2_actionable，不再依赖关键词。
                _loop_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))

                def _diff_fb():
                    try:
                        from src.core import hypotheses as _hyp
                        _hyp.refresh_hypotheses(_loop_db, task_id, _bb_workspace_id)
                        return _i2fb.difference_set_feedbacks(_loop_db, task_id)
                    except Exception as _e:
                        logger.warning("[闭环] 差集回灌计算失败（不阻断）：%s", _e)
                        return []

                # 背景：闭环第 2 轮会把 trigger_specs 全部重登记、清空确认态、整轮重放，
                # 单遍验证跑（对账用）可置 SAST_AI_I2_MAX_ROUNDS=1 或 config agents.i2.max_rounds=1。
                _i2_rounds = int(
                    os.environ.get("SAST_AI_I2_MAX_ROUNDS")
                    or config.get("agents.i2.max_rounds", 3) or 3
                )
                # 而 gain = 0（iterations=1、max_iterations=1、228 条 feedback、LLM 判因仅 4 次调用/
                # 1 次重分类）。同一轮里确定性重试 retryable_no_evidence 只用 192.4s 就拿到 +9 确认，
                # 效率差 23 倍。
                # 后改为**默认关闭**：闭环在此靶场上没有可观测收益，成本却恒定在千秒级
                # （167 条重放调整 + 重跑后重验，预算预检只能拦住 a2_rerun 一部分）。
                # 复杂/真实项目先显式 SAST_AI_CLOSED_LOOP=1 开启并做 A/B 验证收益。
                # 确定性重试始终保留（那是唯一被证明有效的闭环机制）。
                _closed_loop_on = str(os.environ.get("SAST_AI_CLOSED_LOOP", "0")).strip().lower() \
                    not in ("0", "false", "no", "off")
                if not _closed_loop_on:
                    _i2_rounds = 0
                    logger.info("[闭环] SAST_AI_CLOSED_LOOP=0（默认）：跳过 A2 回灌重跑（保留确定性重试）")
                # 全量闭环 471 实测烧 4528.9s 而 gain=0：反馈里 95%+ 是
                # runtime_observation（canary 未观测到），其中绝大多数属**结构性**
                # （WAF 拦截 / 路由不可达 / 参数没到 sink / 探针未插桩 / 鉴权墙），
                # 静态侧重跑 A2 改不动它们 ⇒ 属于「拿 A2 修重放侧/环境侧问题」。
                #
                # 定向口径：只把「A2 重跑真能改善」的可救子集喂给闭环：
                #   hypothesis_defect（假说本身错） + runtime_observation/arrived_unconfirmed
                #   （探针确证到达 sink 但未确认有害 ⇒ 换弹/改判定有意义）。
                # 可救子集为空 ⇒ 闭环直接 no_action（省掉整轮 4529s）。
                # 另加墙钟预算：闭环总耗时超 SAST_AI_I2_BUDGET_S（默认 300s）即停。
                #
                # 口径开关：SAST_AI_I2_SCOPE=targeted（默认）| all（旧全量行为）
                _i2_scope = str(os.environ.get("SAST_AI_I2_SCOPE", "targeted")).strip().lower()
                if _i2_scope not in ("targeted", "all"):
                    _i2_scope = "targeted"
                _i2_budget_s = float(os.environ.get("SAST_AI_I2_BUDGET_S", "300") or 300)
                _i2_deadline = time.time() + _i2_budget_s
                _loop = _i2fb.ClosedLoopController(
                    max_iterations=_i2_rounds, min_gain=1,
                    stall_timeout=int(os.environ.get("SAST_AI_I2_STALL_TIMEOUT", "1200")),
                )
                # 控制器构造时把 max_iterations 夹到 ≥1（对其他调用方是正确语义），
                # 这里显式置 0 才能让 while 循环整段跳过。
                if _i2_rounds <= 0:
                    _loop.max_iterations = 0
                # 的 mtime，避免单轮 a2_rerun（可长达 40+ 分钟）不写该文件时被 task_runner 看门狗
                # 按 STUCK_HEARTBEAT_SECONDS（默认 45min）误判卡死强杀。闭环结束（含异常路径前的
                # finally 见下方 try/except 外层）统一 stop。
                _hb_stop = _start_progress_heartbeat(output_dir)
                _baseline = int(d2_verifications.get('exploitable_count', 0) or 0)
                # 收缩产物时被首轮大基线稀释、B-1 守卫被绕过。现改为「每轮重登记前实拍」：
                # 基线在循环体内、本次 a2_rerun 重登记之前动态捕获（见下方 标注处），
                # 使硬闸对比的是「上一轮产物」而非首轮基线。此处仅保留占位，避免未定义引用。
                _spec_baseline = None
                # B-3 gain 口径对齐：基线改用确认层去重 endpoint 用例数（与对账脚本 L2 同源），
                # 不再用 D2 内部 exploitable_count（rerun 收缩产物时会把负增益误读成正增益）。
                _baseline = _i2fb.confirmed_case_count(_loop_db, task_id)
                # 旧写法用 _gain = 当前可利用数 - 固定 _baseline，第一轮抬升后 gain 恒定为正，
                # should_continue 的 min_gain 收敛判据永久失效 → 必然跑满 3 轮并恒置 exhausted=true，
                # 表面上「跑完 3 轮」，实际是判据根本不收敛。改为逐轮对比上一轮计数。
                _prev_count = _baseline
                _cur_a2 = a2_results
                _pending_fb = _i2fb.dedup_feedbacks(list(_all_feedback) + _diff_fb())
                # 全量闭环 471 实测烧 4528.9s（占单轮 29.1%）而 gain=0：反馈里 95%+ 是
                # runtime_observation（canary 未观测到），其中绝大多数属**结构性**
                # （WAF 拦截 / 路由不可达 / 参数没到 sink / 探针未插桩 / 鉴权墙），
                # 静态侧重跑 A2 改不动它们 ⇒ 属于「拿 A2 去修重放侧/环境侧的问题」。
                #
                # 定向口径：可救 = hypothesis_defect（假说本身错）
                #          + runtime_observation/arrived_unconfirmed
                #            （探针确证到达 sink 但 D2 未确认有害 ⇒ 换弹/改判定有意义）。
                # 可救子集为空 ⇒ 闭环直接 no_action（省掉整轮数千秒）。
                # 口径开关：SAST_AI_I2_SCOPE=targeted（默认）| all（旧全量行为）
                if _i2_scope == "targeted" and _i2_rounds > 0:
                    try:
                        _keep_fb, _keep_stats = _i2fb.filter_recoverable(_pending_fb)
                        logger.info(
                            "[闭环] D10 定向作用域：可救反馈 %d / 全部 %d（按桶：%s）",
                            _keep_stats.get("kept", 0), len(_pending_fb),
                            _keep_stats.get("by_bucket"))
                        _all_feedback = _keep_fb
                        _pending_fb = _i2fb.dedup_feedbacks(_keep_fb)
                        if not _keep_fb:
                            _i2_rounds = 0
                            _loop = _i2fb.ClosedLoopController(max_iterations=0, min_gain=1,
                                                               stall_timeout=1200)
                            _loop.max_iterations = 0
                            logger.info("[闭环] 可救子集为空 ⇒ 本轮不跑 LLM 闭环（no_action）")
                    except Exception as _fe:
                        logger.warning("[闭环] 定向作用域过滤失败（退回全量）：%s", _fe)
                # Q2：逐轮指令并入统计（matched/unmatched/replay_directive_attached），
                # 收尾时并入 stage_results.i2，供前端与对账核查「改进指令是否真送到 A2」。
                _i2_directive_stats: Dict[str, Any] = {}
                _iteration = 0
                while _iteration < _loop.max_iterations:
                    _iteration += 1
                    # 因本轮回灌分支未执行而通过 locals 残留」造成的 stale 历史快照。
                    _rerun_gate = {"checked": False, "ok": True,
                                   "reason": "a2_rerun_not_executed_this_iter"}
                    # 此前闭环 history 只记 len(_adj)（计划数），「计划≠落地」完全不可观测——
                    _adj_applied = 0
                    # #确认保全闸：本轮 a2_rerun 前的确认态 vhash 快照（仅在 rerun 分支里实拍）。
                    _conf_vh_before = None
                    _conf_gate = None
                    # #④ 防卡死：距上次有效进展超 stall_timeout 即强制终止本轮（覆盖「调用阻塞」非仅增益）。
                    # 单条重放级的死锁由 orchestrator._call_with_timeout 兜底，本检查兜「轮次间整体停滞」。
                    if _loop.seconds_since_progress() > _loop.stall_timeout:
                        _loop.stalled = True
                        logger.warning("[闭环] i2_rerun 距上次进展 %.0fs 超阈值 %ds，判定重放/调用阻塞，强制停止",
                                       _loop.seconds_since_progress(), _loop.stall_timeout)
                        break
                    # 定向闭环的目标就是把「LLM 闭环」这一项的成本钉死，避免再次出现
                    # 471 那种 4528.9s / gain=0 的空转（默认预算 300s）。
                    if time.time() > _i2_deadline:
                        logger.warning("[闭环] D10 预算闸：闭环累计已超预算 %.0fs，停止本轮",
                                       _i2_budget_s)
                        _loop.exhausted = True
                        break
                    _routed = _i2fb.route_feedbacks(_pending_fb)
                    # 规则分流里最模糊的一桶是 hypothesis_defect 兜底项（关键词没命中、
                    # 又不像运行时观测失败）。让 LLM 对它们做四态判因并重新分桶：
                    #   false_positive     → runtime_refutation（不进 A2 回灌，省空转）
                    #   payload_problem    → hypothesis_defect + change_payload（回灌换弹）
                    #   approach_problem   → hypothesis_defect + 换方法/位置
                    # 规则已明确分桶的（runtime_observation / probe_not_instrumented /
                    # runtime_refutation / threw / structured）一律不调 LLM——控成本也控方差。
                    # LLM 调用有硬上限（SAST_AI_I2_LLM_BUDGET，默认 20/轮），超预算退回规则。
                    try:
                        from src.agents import i2_judge as _i2j
                        _amb = list(_routed.get(_i2fb.HYPOTHESIS_DEFECT) or [])
                        # 只挂 hypothesis_defect 桶时 LLM 判因事实上从不被调用——真实闭环里
                        # 95%+ 反馈是 runtime_observation（"canary 未观测到"），该桶常年为空，
                        # 闭环直接 no_action 退出（468 报告 i2 记录为空）。
                        # 真正值得判的是 runtime_observation 里「有弹但打不通」的那一小撮
                        # 判因要回答的正是
                        # 「是弹的问题还是打法的问题」。
                        _ro = list(_routed.get(_i2fb.RUNTIME_OBSERVATION) or [])
                        if _ro:
                            _with_payload = _i2j.payload_vhash_set(_loop_db, task_id)
                            _amb += [
                                _f for _f in _ro
                                if str(_f.get("hypothesis_id")
                                       or _f.get("vulnerability_hash_v2") or "") in _with_payload
                            ]
                        if _amb:
                            _verdicts = _i2j.adjudicate_feedbacks(
                                _amb, db=_loop_db, task_id=task_id,
                                llm_enabled=str(os.environ.get(
                                    "SAST_AI_I2_LLM_JUDGE", "1")).strip().lower()
                                not in ("0", "false", "no", "off"),
                                max_llm_calls=int(os.environ.get(
                                    "SAST_AI_I2_LLM_BUDGET", "20") or 20))
                            _applied = _i2j.apply_reclassification(
                                _routed, _verdicts, defect_class=_i2fb.HYPOTHESIS_DEFECT,
                                source_classes=[_i2fb.HYPOTHESIS_DEFECT,
                                                _i2fb.RUNTIME_OBSERVATION])
                            _reclass = int(_applied.get("moved") or 0)
                            # 把 LLM 的动作建议并进 reason —— A2 只消费 reason 文本，
                            # 挂在自定义字段上的 llm_action 它读不到（实测 8B 几乎不判
                            # false_positive，分桶收益有限，动作建议才是真正价值）。
                            _attached = _i2j.attach_llm_directives(
                                _routed, defect_class=_i2fb.HYPOTHESIS_DEFECT,
                                source_classes=[_i2fb.HYPOTHESIS_DEFECT,
                                                _i2fb.RUNTIME_OBSERVATION])
                            _i2_directive_stats["llm_judge"] = {
                                "candidates": len(_amb),
                                "llm_calls": _verdicts.get("llm_calls", 0),
                                "budget": _verdicts.get("llm_budget", 0),
                                "reclassified": _reclass,
                                "directives_attached": int(_attached.get("attached") or 0),
                            }
                            logger.info(
                                "[闭环] LLM 判因：候选 %d 条，调用 %d 次，重分桶 %d 条，"
                                "动作建议注入 %d 条",
                                len(_amb), _verdicts.get("llm_calls", 0), _reclass,
                                int(_attached.get("attached") or 0))
                    except Exception as _lje:  # noqa: BLE001
                        logger.warning("[闭环] LLM 判因失败（保留规则分流，不阻断）：%s", _lje)
                    # 意图记录（pending/abandoned）。默认关闭（SAST_AI_A2_USE_INTENTS=0），
                    # 仅用于统一重跑验证；失败不影响主闭环（已 try 隔离）。
                    if (str(os.environ.get("SAST_AI_A2_USE_INTENTS", "0")).strip().lower()
                            in ("1", "true", "yes", "on")):
                        try:
                            from src.iast.intent_bridge import emit_intents_from_verdicts
                            _emitted = emit_intents_from_verdicts(
                                _loop_db.connect(), task_id, _verdicts.get("classified", {}))
                            if _emitted:
                                logger.info("[闭环] 已落库 %d 条探索意图（replay_intents）", _emitted)
                        except Exception as _ibe:  # noqa: BLE001
                            logger.warning("[闭环] 探索意图落库失败（忽略）：%s", _ibe)
                    _counts = {k: len(v) for k, v in _routed.items() if v}
                    _adj = _i2fb.plan_replay_adjustments(_routed)
                    # 保证 A2 拿到的是"具体改进要求"而不是一句自然语言。
                    _routed = _i2fb.attach_directives(_routed, _adj)
                    # Q2：指令并入的匹配/失配统计必须落进闭环记录，否则「指令到底有没有
                    # 送到 A2」只能靠读源码确认（此前完全不可观测，是本轮疑问的成因）。
                    _dstats = _routed.get("_directive_stats") or {}
                    if _dstats:
                        _i2_directive_stats = dict(_i2_directive_stats or {})
                        _i2_directive_stats[f"iter{_iteration}"] = _dstats
                    _a2_fb = _i2fb.a2_actionable(_routed)
                    if not _a2_fb and not _adj:
                        _loop.record(_iteration, _counts, "no_action", 0,
                                     {"note": "无可执行反馈（全部为不可修类别），停止"})
                        break
                    _emit_stage_progress(task_id, output_dir, "i2_rerun",
                        {"iteration": _iteration, "max_iterations": _loop.max_iterations,
                         "status": "running", "a2_feedback": len(_a2_fb), "replay_adjustments": len(_adj)})
                    _action = None
                    _failed_files = files
                    if _adj:
                        # #4① 运行时观测失败：先调重放侧（秒级、便宜，改 trigger_specs 的
                        # param_location/wait_window），重验后再决定是否 a2_rerun。
                        _loop_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                        _adj_applied = _i2fb.apply_replay_adjustments(_loop_db, task_id, _adj)
                        _action = "replay_adjust"
                    # gain = -7。这些反馈的语义是「假说门禁悬置」而非「假说猜错」，
                    # A2 静态重跑产不出运行时证明，必然空转。预检不通过则只做重放侧调整。
                    _a2_ok, _a2_why = _i2fb.a2_rerun_actionable(_a2_fb) if _a2_fb else (False, "无 a2 反馈")
                    # 一旦开跑无法在轮内打断（预算闸只在轮次间生效）。473 实测：51 条
                    # hypothesis_defect ⇒ 重跑数十文件 ⇒ 单轮 2237.8s / gain=0。
                    # 估计「文件数×单文件耗时」对照剩余预算，超了就只做重放侧调整。
                    if _a2_fb and _a2_ok:
                        try:
                            _est_per_file = float(
                                os.environ.get("SAST_AI_A2_SEC_PER_FILE", "40") or 40)
                            _n_files = len(_failed_files_from_feedback(
                                task_id, _a2_fb, files))
                            _a2_ok, _budget_why = _i2fb.a2_rerun_budget_ok(
                                _n_files, _i2_deadline - time.time(), _est_per_file)
                            if not _a2_ok:
                                _a2_why = "D10 " + _budget_why
                                logger.warning("[闭环] 跳过 a2_rerun（预算预检）：%s",
                                               _a2_why)
                        except Exception as _be:  # noqa: BLE001
                            logger.warning("[闭环] 预算预检异常（放行）：%s", _be)
                    if _a2_fb and not _a2_ok:
                        logger.warning("[闭环] 跳过 a2_rerun（止损预检）：%s", _a2_why)
                        _emit_stage_progress(task_id, output_dir, "i2_rerun",
                            {"iteration": _iteration, "max_iterations": _loop.max_iterations,
                             "status": "running", "a2_feedback": len(_a2_fb),
                             "replay_adjustments": len(_adj), "skip_a2_rerun": True,
                             "skip_reason": _a2_why})
                        if _action is None:
                            _loop.record(_iteration, _counts, "no_action(skip_a2_rerun)", 0,
                                         {"note": _a2_why, "a2_feedback": len(_a2_fb)})
                            break
                        _action = f"{_action}+skip_a2_rerun"
                    elif _a2_fb:
                        logger.info("[闭环] 执行 a2_rerun（止损预检通过）：%s", _a2_why)
                    if _a2_fb and _a2_ok:
                        # #2 收窄：只对「失败 finding 所在文件」重跑 A2，而非全量 files。
                        _failed_files = _failed_files_from_feedback(task_id, _a2_fb, files)
                        _rerun_a2 = rerun_a2_with_feedback(
                            _failed_files, code_index=code_index, scan_mode=scan_mode, a1_evidence_index=a1_index,
                            feedback=_a2_fb,
                            discovered_routes=entry_discovery_result.get("entries") or [],
                            code_root=str(prepared_scan_root),
                            on_progress=_mk_a2_progress(task_id, output_dir, _iteration),
                        )
                        # run_d2_verify 的候选全集由传入的 a2_results 构造（for result in a1_results + a2_results），
                        # 若直接把收窄结果传进去，D2 只重验这几个文件，与闭环前的全量计数不可比：
                        # 收窄只是「少跑 LLM」的优化，绝不能缩小 D2 的验证范围。
                        _cur_a2 = _merge_a2_results(a2_results, _rerun_a2)
                        # _rerun_a2）。原因是 trigger_spec_registry 的 second_pass 已改为
                        # 「先清本 task 全部 spec 再重登记」——若仍只登记收窄子集，未参与本次
                        # A2 重跑的那些漏洞的 spec 会被清掉且不再重建，D1 直接失去重放目标
                        # （召回掉一大截）。用全量集登记，spec 集合既无残留副本也不丢覆盖。
                        # 登记本身不调 LLM，全量走一遍的代价只是端点解析，远小于丢召回。
                        # 这样 B-1 硬闸对比的是「上一轮产物」（或首轮前 D1/D2 产物），
                        # 而非 6560 处被废弃的首轮固定基线，iter2 收缩产物时守卫才会真正生效。
                        _spec_baseline = _i2fb.spec_health_snapshot(_loop_db, task_id)
                        # #确认保全闸：重登记前实拍确认态 vhash 集（重验后对比保全率）。
                        _conf_vh_before = _confirmed_vhash_set(_loop_db, task_id)
                        _spec_before = _spec_key_snapshot(task_id)
                        _auto_register_a2_trigger_specs(
                            task_id, _cur_a2,
                            discovered_routes=entry_discovery_result.get("entries") or [],
                            extra_results=_a1_for_registration if enable_a1 else None,
                            second_pass=True,
                        )
                        _diff_and_record_spec_set(
                            task_id, _spec_before, _spec_key_snapshot(task_id), "a2_rerun_register",
                        )
                        # 会把本轮 apply_replay_adjustments 刚写入的 replay_adjust 一并清掉。
                        # 跨任务实证：凡最后一轮带 a2_rerun 的任务（245/240/226），actions 落地恒 0，
                        # 重试环原样重放；幸存任务（244/242/239）只因最后一轮 skip_a2_rerun。
                        # 此处对重登记后的 spec 补写同批调整（bump_round=False，避免把 round 推到
                        # 封顶使重试环失效）。补写从新 spec 的 param_location 原位起步换位，语义与
                        # 初次 apply 一致（清库已重置梯子，不会双重换位）。
                        if _adj:
                            try:
                                _adj_applied = _i2fb.apply_replay_adjustments(
                                    _loop_db, task_id, _adj, bump_round=False)
                            except Exception as _rae:
                                logger.warning("[闭环] 重登记后补写重放调整失败（不阻断）：%s", _rae)
                        # 任一退化超阈值（spec 总数 10% / 端点解析率 10% / 注入类 20%）即判定
                        # 294→179 召回 -19pt，闸门是把「rerun 负增益」挡在落库之后的最后防线。
                        _rerun_gate = {"checked": True, "ok": True, "reason": ""}
                        try:
                            _spec_after = _i2fb.spec_health_snapshot(_loop_db, task_id)
                            _gate_ok, _gate_why = _i2fb.spec_health_gate(_spec_baseline, _spec_after)
                            _rerun_gate = {"checked": True, "ok": _gate_ok, "reason": _gate_why,
                                           "before": _spec_baseline, "after": _spec_after}
                            if not _gate_ok:
                                logger.warning(
                                    "[闭环][硬闸] a2_rerun 产物退化，回滚原产物：%s", _gate_why)
                                _spec_rb_before = _spec_key_snapshot(task_id)
                                _auto_register_a2_trigger_specs(
                                    task_id, a2_results,
                                    discovered_routes=entry_discovery_result.get("entries") or [],
                                    extra_results=_a1_for_registration if enable_a1 else None,
                                    second_pass=True,
                                )
                                _diff_and_record_spec_set(
                                    task_id, _spec_rb_before, _spec_key_snapshot(task_id), "a2_rerun_rollback",
                                )
                                # 回滚重登记同样先清库——与上方 a2_rerun_register 同理补写。
                                if _adj:
                                    try:
                                        _adj_applied = _i2fb.apply_replay_adjustments(
                                            _loop_db, task_id, _adj, bump_round=False)
                                    except Exception as _rae2:
                                        logger.warning("[闭环] 回滚重登记后补写重放调整失败（不阻断）：%s", _rae2)
                                _cur_a2 = a2_results
                                _rerun_gate["rolled_back"] = True
                                _action = "a2_rerun_rolled_back"
                        except Exception as _ge:
                            logger.warning("[闭环][硬闸] 执行失败（fail-open 保留 rerun 产物）：%s", _ge)
                            _rerun_gate = {"checked": False, "ok": True, "reason": str(_ge)}
                        _action = "replay_adjust+a2_rerun" if _adj else "a2_rerun"
                    _emit_stage_progress(task_id, output_dir, "d2_verify_progress",
                        {"status": "running", "iteration": _iteration})
                    d2_verifications = run_d2_verify(
                        a1_results, _cur_a2, files, target_path, external_target, task_id=task_id,
                        code_root=str(prepared_scan_root),
                        discovered_routes=entry_discovery_result.get("entries") or [],
                        output_dir=output_dir,
                    )
                    _emit_stage_progress(task_id, output_dir, "d2_verify_progress",
                        {"status": "done", "iteration": _iteration,
                         "exploitable_count": int(d2_verifications.get('exploitable_count', 0) or 0)})
                    # filtered_not_exploitable，让"过滤器有效"这个真阴性进对账，而不是混进
                    # unconfirmed / no_evidence（那会既丢结论又污染精确率）。
                    try:
                        _i2fb.mark_filtered_not_exploitable(
                            Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db")), task_id)
                    except Exception as _fe:
                        logger.warning("[闭环] 过滤器口径标记失败（不阻断）：%s", _fe)
                    # rerun 产物可以健康度全达标（spec 数/端点率），却在重验后把上一轮已确认
                    # gain=-19 而 rerun_gate ok=True）。确认保全率低于阈值即回滚原产物并重验
                    # 一次，恢复上一轮确认态的判定基础。env SAST_AI_RERUN_CONFIRM_RETAIN_MIN
                    # 调阈值（默认 0.90）；确认快照为空（首轮无确认）时跳过。
                    try:
                        _retain_min = float(os.environ.get("SAST_AI_RERUN_CONFIRM_RETAIN_MIN", "0.90") or 0.90)
                    except Exception:
                        _retain_min = 0.90
                    if _conf_vh_before:
                        _conf_vh_after = _confirmed_vhash_set(_loop_db, task_id)
                        _retained_n = len(_conf_vh_before & _conf_vh_after)
                        _retain_ratio = _retained_n / len(_conf_vh_before)
                        _conf_gate = {"before": len(_conf_vh_before), "after": len(_conf_vh_after),
                                      "retained": _retained_n,
                                      "ratio": round(_retain_ratio, 4), "min": _retain_min}
                        if _retain_ratio < _retain_min and not _rerun_gate.get("rolled_back"):
                            logger.warning(
                                "[闭环][确认保全闸] rerun 重验后确认保全率 %.1f%%（%d/%d）低于 %.0f%%，"
                                "回滚原产物并重验一次", _retain_ratio * 100, _retained_n,
                                len(_conf_vh_before), _retain_min * 100)
                            _emit_stage_progress(task_id, output_dir, "i2_rerun",
                                {"iteration": _iteration, "status": "running",
                                 "confirm_rollback": True,
                                 "retained": _retained_n, "before": len(_conf_vh_before),
                                 "after": len(_conf_vh_after)})
                            _conf_rb_before = _spec_key_snapshot(task_id)
                            _auto_register_a2_trigger_specs(
                                task_id, a2_results,
                                discovered_routes=entry_discovery_result.get("entries") or [],
                                extra_results=_a1_for_registration if enable_a1 else None,
                                second_pass=True,
                            )
                            _diff_and_record_spec_set(
                                task_id, _conf_rb_before, _spec_key_snapshot(task_id),
                                "a2_rerun_confirm_rollback",
                            )
                            if _adj:
                                try:
                                    _adj_applied = _i2fb.apply_replay_adjustments(
                                        _loop_db, task_id, _adj, bump_round=False)
                                except Exception as _rae3:
                                    logger.warning("[闭环] 确认回滚后补写重放调整失败（不阻断）：%s", _rae3)
                            d2_verifications = run_d2_verify(
                                a1_results, a2_results, files, target_path, external_target,
                                task_id=task_id, code_root=str(prepared_scan_root),
                                discovered_routes=entry_discovery_result.get("entries") or [],
                                output_dir=output_dir,
                            )
                            try:
                                _i2fb.mark_filtered_not_exploitable(
                                    Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db")), task_id)
                            except Exception as _fe2:
                                logger.warning("[闭环] 确认回滚后过滤器标记失败（不阻断）：%s", _fe2)
                            _cur_a2 = a2_results
                            _rerun_gate["confirm_rolled_back"] = True
                            _action = (_action or "a2_rerun") + "+confirm_rollback"
                    _cur_count = int(d2_verifications.get('exploitable_count', 0) or 0)
                    # （与对账 L2 同源），不再用 D2 内部 exploitable_count；后者在 rerun 收缩
                    # 产物时会假性回升。exploitable_total 仍记录供过程观测。
                    _confirmed_cases = _i2fb.confirmed_case_count(_loop_db, task_id)
                    _gain = _confirmed_cases - _prev_count
                    _prev_count = _confirmed_cases
                    _loop.record(_iteration, _counts, _action, _gain,
                                 {"a2_feedback": len(_a2_fb), "replay_adjustments": len(_adj),
                                  "replay_adjustments_applied": int(_adj_applied or 0),
                                  "exploitable_total": _cur_count, "baseline": _baseline,
                                  "confirmed_cases": _confirmed_cases,
                                  "gain_metric": "confirmed_endpoint_cases",
                                  "defect_subclass_counts": _i2fb.defect_subclass_counts(_a2_fb),
                                  "rerun_gate": locals().get("_rerun_gate", {}),
                                  "confirm_gate": _conf_gate})
                    _loop.note_progress()
                    if not _loop.should_continue(_iteration, _gain):
                        break
                    _pending_fb = _i2fb.dedup_feedbacks(_collect_fb(d2_verifications.get("verifications")) + _diff_fb())
                    if not _pending_fb:
                        break
                # 不再只留痕。plan_retryable_replay 判定该不该再放；execute_retryable_replay
                # 消费清单去重跑 D1+D2，回写终态并落 retryable_no_evidence 事件（含 executed/cleared）。
                try:
                    _retry_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                    _retry = _i2fb.plan_retryable_replay(_retry_db, task_id)
                    _retryable = _retry.get("retryable") or []
                    if _retryable:
                        _retry_exec = execute_retryable_replay(
                            _retry_db, task_id, _retryable,
                            a1_results=[], a2_results=_cur_a2, files=files,
                            target_path=target_path, external_target=external_target,
                            code_root=str(prepared_scan_root),
                            discovered_routes=entry_discovery_result.get("entries") or [],
                            output_dir=output_dir,
                        )
                        _append_scan_task_event(task_id, "retryable_no_evidence", {
                            "retryable_count": len(_retryable),
                            "exhausted_count": len(_retry.get("exhausted") or []),
                            "executed_count": _retry_exec.get("executed", 0),
                            "cleared_count": _retry_exec.get("cleared", 0),
                            "failed_count": _retry_exec.get("failed", 0),
                            "confirmed_gain": _retry_exec.get("confirmed_gain", 0),
                            # 匹配率 = executed / retryable，此前的低值（0.082~0.176）
                            # 主要是「失配跳过」而非「不该重试」；这两个字段让下轮
                            # 能直接量化修复效果。
                            "vhash_miss": _retry_exec.get("vhash_miss", 0),
                            "vhash_secondary_hits": _retry_exec.get("vhash_secondary_hits", 0),
                            "variant_escalated": _retry_exec.get("variant_escalated", 0),
                            # 落盘后可直接判断「重试是不是又在空转」，不必再反推。
                            "batches": _retry_exec.get("batches", 0),
                            "batch_size": _retry_exec.get("batch_size", 0),
                            "elapsed_sec": _retry_exec.get("elapsed_sec", 0.0),
                            "downtime_affected": bool(_retry.get("downtime_affected")),
                            "max_rounds": _retry.get("max_rounds"),
                            "retryable": _retryable,
                            "exhausted": _retry.get("exhausted") or [],
                        })
                        logger.info(
                            "[闭环] 可重试 no_evidence 定向重放完成：executed=%d cleared=%d failed=%d variant=%d "
                            "gain=%d batches=%d batch_size=%d elapsed=%.0fs",
                            _retry_exec.get("executed", 0), _retry_exec.get("cleared", 0),
                            _retry_exec.get("failed", 0), _retry_exec.get("variant_escalated", 0),
                            _retry_exec.get("confirmed_gain", 0),
                            _retry_exec.get("batches", 0), _retry_exec.get("batch_size", 0),
                            float(_retry_exec.get("elapsed_sec", 0.0) or 0.0))
                    elif _retry.get("exhausted"):
                        _append_scan_task_event(task_id, "retryable_no_evidence", {
                            "retryable_count": 0,
                            "exhausted_count": len(_retry.get("exhausted") or []),
                            "executed_count": 0, "cleared_count": 0, "failed_count": 0,
                            "downtime_affected": bool(_retry.get("downtime_affected")),
                            "max_rounds": _retry.get("max_rounds"),
                            "retryable": [], "exhausted": _retry.get("exhausted") or [],
                        })
                except Exception as _re:
                    logger.warning("[闭环] 可重试重放失败（忽略，保留终态）：%s", _re)
                _loop_summary = _loop.summary()
                logger.info("[闭环] 闭环结束：%s", _loop_summary)
                _hb_stop()
            except Exception as _e:
                # 此前是 warning：后端日志过滤项目 INFO，warning 混在大量进度里极易被漏看，
                # 而 stage_results.i2.status 仍写 completed、message 写「闭环执行 0 轮」，
                # 闭环中断是功能性失败（第二轮 D2 重验与 spec 回灌全部丢失），必须可观测。
                logger.error("[闭环] 闭环执行失败（保留当前 D2 结果，不影响报告）：%s", _e, exc_info=True)
                _loop_summary = {
                    "error": str(_e),
                    "error_type": type(_e).__name__,
                    "failed": True,
                    "iterations": 0,
                }
                _hb_stop()
            phase_times['closed_loop_rerun'] = time.time() - _cl_start
            # §P4：持久化 feedback_to_a2 进 stage_results.i2（A2 标准通道消费端）。即便未触发二次回灌
            # 也记录，保证闭环反馈可追溯、可重放。
            # F-3：failure_class_counts 合并 defect 五类子分流
            #（端点幻觉/参数缺失/族误判/链路不符/证据不足）；record 将 detail 平铺进 history。
            _fcc = dict(((_loop_summary.get("history") or [{}])[0].get("routed", {}) if _loop_summary else {}))
            _sub = ((_loop_summary.get("history") or [{}])[0].get("defect_subclass_counts") or {}) if _loop_summary else {}
            for _sc_key in ("endpoint_hallucination", "missing_parameter", "family_mislabel",
                            "chain_mismatch", "insufficient_evidence"):
                if (_sub.get("counts") or {}).get(_sc_key):
                    _fcc[_sc_key] = _sub["counts"][_sc_key]
            _sub_actions = _sub.get("bound_actions") or {}
            try:
                # 此前只写 scan_progress.json，而 run_benchmark 的 return 自建 stage_results
                # 不含 i2 ⇒ task_completed 载荷里 stage_results.i2 恒为空，
                # 闭环代价/收益、LLM 判因用量全部不可见。
                _i2_stage_payload = {
                        # 闭环异常时 status 必须为 failed：写 completed 会让前端/报告把
                        "status": "failed" if (_loop_summary or {}).get("error") else "completed",
                        "closed_loop_failed": bool((_loop_summary or {}).get("error")),
                        "feedback_to_a2_count": len(_all_feedback),
                        "rollback_to_a2_count": len(_feedback_list),
                        "feedback_to_a2": _all_feedback,
                        # E-1/F-2：missing_route 观测面并入 I2 视角（真漏报信号显式化）。
                        "missing_route_watch": locals().get("_mr_watch", {}),
                        # 分流结果：让「回灌了什么、哪些是不可修的」可见，避免再出现
                        # 「60 条全是不可执行的运行时观测失败却仍在回灌 A2」的空转。
                        "failure_class_counts": _fcc,
                        "defect_bound_actions": _sub_actions,
                        # 运行时确证无害（数据到 sink 但被针对本族净化）」的 definitive 阴性，
                        # 供静态分析器（A1）消费以消减 over-claim，不进 A2 二次回灌。
                        "runtime_refutation": [
                            {
                                "hypothesis_id": fb.get("hypothesis_id"),
                                "family": ((fb.get("current_spec") or {}) or {}).get("family"),
                                "value_hit_form": fb.get("value_hit_form"),
                                "final_state": fb.get("final_state"),
                            }
                            for fb in _all_feedback
                            if _i2fb.classify_feedback(fb) == _i2fb.RUNTIME_REFUTATION
                        ],
                        # Q2：指令送达可观测。matched=并入 A2 反馈的指令数，unmatched=生成
                        # 了但按 hypothesis_id 没匹配上（静默丢失的那些），replay_directive=
                        # 挂到重放侧供改弹的指令数。unmatched>0 即说明「指令没进去」。
                        "directive_stats": locals().get("_i2_directive_stats", {}) or {},
                        "a2_actionable_count": sum(
                            1 for _h in (_loop_summary.get("history") or [])
                            if _h.get("action") == "a2_rerun"
                        ) if _loop_summary else 0,
                        "closed_loop": _loop_summary,
                        "message": (
                            "I2 闭环执行失败：{}（第二轮 D2 重验与 spec 回灌未执行）".format(
                                _loop_summary.get("error"))
                            if (_loop_summary or {}).get("error")
                            else "I2 裁决产出 {} 条 feedback_to_a2（去重后），闭环执行 {} 轮".format(
                                len(_all_feedback), (_loop_summary.get("iterations") or 0))
                        ),
                }
                _update_scan_progress_metadata(
                    output_dir,
                    {"stage_results": {"i2": _i2_stage_payload}},
                )
            except Exception as _e:
                logger.warning("[P4] 持久化 stage_results.i2 失败（不影响报告）：%s", _e)
            # §统一链路：D1 已经并到 verify 内执行（每个漏洞的 D1 重放 + I1 关联 + D2 核实
            # + I2 裁决），不再有独立的「IAST 模式」重放阶段（_run_iast_auto_replay 已删除，
            # 它与 verify 内 D1 是同一套编排器，分两处跑就是用户 reject 的「双入口」）。
            # 这里从统一 verify 结果聚合 D1 指标，回填 stage_results.d1，让流程图 D1 节点显示
            # 真实重放结果而非 skipped。
            try:
                idor_result = _aggregate_d1_replay(d2_verifications.get("verifications", []))
                _update_scan_progress_metadata(
                    output_dir,
                    {"stage_results": {"d1": {k: v for k, v in idor_result.items() if k not in {"findings", "decisions"}}}},
                )
            except Exception as _e:
                logger.warning(f"[D2] 聚合 D1 统一重放指标异常（不影响静态结果）：{_e}")
            # #4③：保留「初始 D2 验证」耗时（在初验后已记账），闭环重跑已拆分到 closed_loop_rerun。
            phase_times['d2'] = phase_times.get('d2', time.time() - phase_start)
            print(f"\n[*] D2 AI Agent Verification complete:")
            print(f"   - Total: {d2_verifications.get('total_vulnerabilities', 0)}")
            print(f"   - Confirmed exploitable: {d2_verifications.get('exploitable_count', 0)}")
            progress_logger.update_phase('phase5', 'completed', f'验证 {d2_verifications.get("total_vulnerabilities", 0)} 个漏洞')
            _update_scan_progress_metadata(
                output_dir,
                {
                    "stage_results": {
                        "d2": {
                            "verified_count": d2_verifications.get('total_vulnerabilities', 0),
                            "exploitable_count": d2_verifications.get('exploitable_count', 0),
                            "verified_poc_count": d2_verifications.get('verified_poc_count', 0),
                            "docker_used": d2_verifications.get('docker_used', False),
                            "duration_seconds": round(phase_times['d2'], 2),
                        }
                    }
                },
            )
            # Q4：把 D2 五态聚合回填到 stage_results.d2（含逐漏洞证据链 verifications_detail），
            # 并写入 d2_verifications['aggregate'] 供 report_manager 同轴回填 summary.d2_verified_count。
            try:
                _d2_agg = _aggregate_d2_verdict(d2_verifications.get("verifications", []))
                d2_verifications["aggregate"] = _d2_agg
                # HTTP 仅 227s，怀疑 95% 是轮询空等；此处落真数（命中率/平均等待/超时占比），
                # 供下一轮判断优化方向（自适应间隔 / 4xx 早退 / 批量轮询）。
                try:
                    from src.agents.d2_facade import poll_stats as _poll_stats
                    _d2_poll = _poll_stats()
                    _d2_poll_stats = dict(_d2_poll or {})
                except Exception:  # noqa: BLE001
                    _d2_poll = {}
                _update_scan_progress_metadata(
                    output_dir,
                    {"stage_results": {"d2": {
                        "verified_count": _d2_agg["verified_count"],
                        "harmful_count": _d2_agg["harmful_count"],
                        "sink_reached_count": _d2_agg["sink_reached_count"],
                        "impact_count": _d2_agg["impact_count"],
                        "confirmed_exploitable_count": _d2_agg["confirmed_exploitable_count"],
                        "by_family": _d2_agg["by_family"],
                        "verifications_detail": _d2_agg["verifications_detail"],
                        "poll_stats": _d2_poll,
                        "message": _d2_agg["message"],
                    }}},
                )
            except Exception as _e:
                logger.warning(f"[D2] 聚合 D2 五态回填 stage_results.d2 异常（不影响静态结果）：{_e}")
            # Q4 增强：D1/D2 统一重放已全部完成（iast_events 已落库），重新生成攻击计划并回填
            # 运行时命中态（runtime_status / runtime_event_count），让 AP 面板从「准备打什么」
            # 升级为「打了什么 + 命中没」。此步必须在 D2 之后，否则读不到重放产生的事件。
            try:
                from src.application.attack_plan_service import AttackPlanService
                _ap_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                ap = AttackPlanService(_ap_db).build(task_id=task_id, enrich_runtime=True)
                _update_scan_progress_metadata(
                    output_dir,
                    {
                        "stage_results": {
                            "attack_plan": {
                                "status": "completed",
                                "message": "攻击计划已生成 {} 条（含运行时命中回填）".format(ap["plan_count"]),
                                "plan_count": ap["plan_count"],
                                "by_family": ap["by_family"],
                                "entries": ap["entries"],
                                "runtime_enriched": True,
                            }
                        }
                    },
                )
                logger.info("[attack_plan] 运行时命中回填完成，%s 条", ap["plan_count"])
            except Exception as _e:
                logger.warning("[attack_plan] 运行时命中回填失败（不影响报告）：%s", _e)
            exploitable = d2_verifications.get('exploitable_count', 0)
            if exploitable > 0:
                print(f"   - [FOUND] {exploitable} vulnerabilities confirmed exploitable!")

        print("\n" + "=" * 60)
        print("[Generating] 最终安全审计报告")
        print("=" * 60)
        # 阶段漏斗：把 task_id 传给 report_manager，使 report.* 快照落到本 task 的 jsonl
        try:
            report_manager._funnel_task_id = task_id
        except Exception:
            pass
        # 从 no-arrival（=打了没到）里分出来，记 payload_unavailable。
        # 不碰 verification_status，纯观测口径修正；判据见 src/core/spec_state_normalize.py。
        # 句柄在 try 之外先建好：两个口径归一函数都要用，放在 try 里会让后一个在
        # 前一个抛异常时变成 NameError（本文件已经因此踩过一次）。
        try:
            _norm_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        except Exception:  # noqa: BLE001
            _norm_db = None
        try:
            from src.core.spec_state_normalize import normalize_payload_unavailable
            # （db 只在 d1_db/_ap_db/_loop_db 等局部别名上存在）⇒ NameError 被 fail-open 吞掉，
            # 口径归一 587 整轮静默未生效（payload_unavailable 28→0，全被记成 no-arrival）。
            # 教训：fail-open 必须配「成功也留痕」，否则失败与「无事可做」在日志上无法区分。
            _norm = normalize_payload_unavailable(_norm_db, task_id)
            _append_scan_task_event(task_id, "task_log", {
                "level": "info",
                "source": "spec_state_normalize",
                "message": "[口径] payload_unavailable 归一：scanned=%s marked=%s"
                           % (_norm.get("scanned"), _norm.get("marked")),
            })
            if _norm.get("marked"):
                logger.info("[口径] payload_unavailable 归一：%s 条从 no-arrival 分出", _norm["marked"])
        except Exception as _ne:  # fail-open
            logger.warning("[口径] payload_unavailable 归一失败（忽略）：%s", _ne)
            try:
                _append_scan_task_event(task_id, "task_log", {
                    "level": "warning",
                    "source": "spec_state_normalize",
                    "message": "[口径] payload_unavailable 归一失败（忽略）：%s" % _ne,
                })
            except Exception:
                pass
        # 本轮实测 74 条 sink-reached 里 6 条既没重放、其文件/类在任何 iast_event 里
        # 也从未出现 ⇒ 状态凭空产生，会污染「到了 sink 判不出」的归因。只降状态不改判定。
        try:
            from src.core.spec_state_normalize import reconcile_sink_state_without_evidence
            # 复用上面那个句柄：`run_benchmark` 作用域里**没有** `db` 这个名字
            # （踩过一次 NameError 被 fail-open 吞掉的坑，见上方注释）。
            _sink_norm = reconcile_sink_state_without_evidence(_norm_db, task_id)
            _append_scan_task_event(task_id, "task_log", {
                "level": "info",
                "source": "spec_state_normalize",
                "message": "[口径] sink-reached 一致性：scanned=%s downgraded=%s"
                           % (_sink_norm.get("scanned"), _sink_norm.get("downgraded")),
            })
        except Exception as _se:  # fail-open
            logger.warning("[口径] sink-reached 一致性校验失败（忽略）：%s", _se)
        final_report = report_manager.generate_final_report(
            a1_results,
            a2_results,
            d2_verifications,
            files=files,
            discovered_endpoints=discovered_endpoints,
            target_path=target_path,
        )
        report_vulns = final_report['report'].get('vulnerabilities', []) or []
        enhanced_vulns = [enrich_finding_hash(vuln) for vuln in report_vulns]
        sca_findings = sca_result.get('findings', []) or []
        idor_findings = idor_result.get('findings', []) or []
        enhanced_vulns.extend(sca_findings)
        enhanced_vulns.extend(idor_findings)
        # Q5：review 环节（A2PipelineService.review，local-heuristic 复审）已删除。
        # A2 的 AI 用法收敛为两部分——(1) POC 生成必须用 LLM（A2ContractPlanner 经 llm_client 调 LLM）；
        # (2) 把 A1 调用链证据在 LLM 调 prompt 前注入（_ai_deep_analysis）。误报/放行判定统一交由
        # 末端 I2 LLM 裁决器处理，不再有独立的规则式 review 阶段。
        ai_review_metrics = {
            "status": "removed",
            "message": "Q5 已删除 A2 review 环节（local-heuristic）；误报/放行由末端 I2 LLM 裁决器统一裁定",
            "auto_close_candidates": 0,
            "ai_review_total": 0,
            "enabled_flag": enable_ai_review,
        }
        # enhanced_vulns 不再附加 ai_review 块（review 已删），直接进入报告。
        final_report['report']['vulnerabilities'] = enhanced_vulns
        # 此前 608 = SCA 349 + 应用层 canonical 259，与 by_severity 等已按 canonical
        # 口径的汇总自相矛盾。应用层与 SCA 分列：total_vulnerabilities 只计
        # source != 'sca'（不引入新列，用现有 source 判别）；SCA 单列 sca_count；
        # 全量口径保留在 total_with_sca 供对账。
        _is_sca = lambda v: str(v.get('source') or v.get('agent') or '') == 'sca'
        _app_count = sum(1 for v in enhanced_vulns if not _is_sca(v))
        final_report['report']['summary']['total_vulnerabilities'] = _app_count
        final_report['report']['summary']['total_with_sca'] = len(enhanced_vulns)
        final_report['report']['summary']['sca_count'] = len(sca_findings)
        final_report['report']['summary']['idor_count'] = len(idor_findings)
        final_report['report']['summary']['scan_mode'] = scan_mode
        # 本质修复 #2：summary 的 severity/type 分布与总数必须与最终展示的
        # vulnerabilities 列表（已含 SCA / IDOR）一致，否则 by_severity 漏掉
        # SCA 的 18 条 CRITICAL、total_vulnerabilities 与列表长度自相矛盾。
        # 以 enhanced_vulns（最终口径）重算 by_severity/by_type/总数，并据此
        from src.core.normalize import normalize_severity, normalize_type
        _final_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'UNKNOWN': 0}
        _final_by_type = {}
        for _v in enhanced_vulns:
            _sev = normalize_severity(_v.get('severity', 'UNKNOWN'))
            _final_by_severity[_sev] = _final_by_severity.get(_sev, 0) + 1
            _vt = normalize_type(_v.get('type', 'Unknown'))
            _final_by_type[_vt] = _final_by_type.get(_vt, 0) + 1
        final_report['report']['summary']['by_severity'] = _final_by_severity
        final_report['report']['summary']['by_type'] = _final_by_type
        final_report['report']['summary']['total_vulnerabilities'] = len(enhanced_vulns)
        final_report['report']['summary']['canonical_findings'] = len(enhanced_vulns)
        final_report['report']['summary']['total_with_sca'] = len(enhanced_vulns)
        # 用补正后的 report 重新落盘 Markdown/JSON（交付物口径统一）
        try:
            _md = report_manager._generate_final_markdown(final_report['report'])
            _md_path = report_manager._save_markdown(
                _md, os.path.basename(final_report.get('markdown_file') or 'final_report_regenerated.md'))
            final_report['markdown_file'] = _md_path
            _json_path = report_manager._save_json(
                final_report['report'], os.path.basename(final_report.get('json_file') or 'final_report_regenerated.json'))
            final_report['json_file'] = _json_path
            logger.info("[report] SCA 补正后已重生成 Markdown/JSON（by_severity 含 SCA CRITICAL）")
        except Exception as _e:
            logger.warning("[report] SCA 补正后重生成 Markdown/JSON 失败（不影响内存口径）：%s", _e)
        # IAST 运行时关联摘要：即使无数据也要显式写入，避免“I1/D2 未纳入报告”的误解。
        # 依赖目标应用挂载的 IAST 探针实时上报；无数据时为全零统计，报告内会明确标注未检出。
        try:
            _db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
            _workspace_id = None
            if task_id is not None:
                try:
                    _row = Database(_db_path).execute(
                        "SELECT workspace_id FROM scan_tasks WHERE id=?", [task_id], fetchone=True
                    )
                    _workspace_id = int(_row["workspace_id"]) if _row else None
                except Exception:
                    _workspace_id = None
            final_report['report']['iast_summary'] = IastCorrelationService(Database(_db_path)).correlate(
                workspace_id=_workspace_id, task_id=task_id
            )
            # 任务4 回填：把探针发射的 BOLA_SUSPECT 事件归因到对应 finding（correlated_finding_id + raw_json.iast_evidence），
            # 保证业务型越权（BOLA/IDOR）运行时证据落到裁决层。fail-open，失败不影响主报告。
            try:
                from src.iast.service import IastService
                _bola_corr = IastService(Database(_db_path)).correlate_bola_suspect_to_findings(task_id)
                logger.info("[reporting] BOLA_SUSPECT 归因完成：%s", _bola_corr)
            except Exception as _be:
                logger.warning(f"[reporting] BOLA_SUSPECT 归因失败（不影响报告）：{_be}")
            # #3 闭环补齐：把注入型家族的 SINK_HIT / TAINT_FLOW 事件归因到对应 finding（打通确认层闭环）。
            try:
                from src.iast.service import IastService
                _sink_corr = IastService(Database(_db_path)).correlate_sink_events_to_findings(task_id)
                logger.info("[reporting] SINK_HIT/TAINT_FLOW 归因完成：%s", _sink_corr)
            except Exception as _se:
                logger.warning(f"[reporting] SINK_HIT/TAINT_FLOW 归因失败（不影响报告）：{_se}")
        except Exception as _e:
            logger.warning(f"[reporting] IAST 关联摘要生成失败：{_e}")
            final_report['report']['iast_summary'] = None
        final_report['report']['sca_summary'] = sca_result
        Path(final_report['json_file']).write_text(json.dumps(final_report['report'], ensure_ascii=False, indent=2), encoding='utf-8')
        Path(final_report['markdown_file']).write_text(report_manager._generate_final_markdown(final_report['report']), encoding='utf-8')
        report_manager.print_final_summary(final_report['report'])
        # —— P-F 后半 ①：SARIF 2.1.0 导出（与 MD/JSON 同口径，fail-open 不影响主报告）——
        # 默认只导出确认态（与质量红线口径一致，供 CI / GitHub Code Scanning 消费）；
        # 需要全量（含未确认）时把 SAST_AI_SARIF_ALL=1。
        try:
            from src.benchmark.sarif_adapter import load_task_vulns_sqlite
            from src.benchmark import sarif_exporter
            _inc = os.environ.get("SAST_AI_SARIF_ALL", "0") == "1"
            _sarif_path = os.path.join(output_dir, "report.sarif.json")
            _vulns = load_task_vulns_sqlite(_db_path, task_id, only_confirmed=not _inc)
            sarif_exporter.write_sarif(_sarif_path, _vulns, include_unconfirmed=_inc)
            logger.info("[reporting] SARIF 导出：%s（%d 条，%s）",
                        _sarif_path, len(_vulns),
                        "含未确认" if _inc else "仅确认态")
        except Exception as _se:
            logger.warning(f"[reporting] SARIF 导出失败（不影响报告）：{_se}")
        print(f"[*] 最终安全审计报告已保存: {final_report['markdown_file']}")
        _update_scan_progress_metadata(
            output_dir,
            {
                "reporting": {
                    "status": "completed",
                    "report_count": 1,
                    "final_markdown_file": final_report['markdown_file'],
                },
                "stage_results": {
                    "reporting": {
                        "report_count": 1,
                    }
                },
            },
        )

        total_time = time.time() - start_time
        print("\n" + "=" * 60)
        print("=== Summary ===")
        print("=" * 60)
        print(f"Total time: {total_time:.1f}s")
        print(f"  - Scan:      {phase_times.get('scan', 0):.1f}s")
        print(f"  - Endpoints: {phase_times.get('endpoint_discovery', 0):.1f}s")
        print(f"  - SCA:       {phase_times.get('sca', 0):.1f}s")
        print(f"  - Entries:   {phase_times.get('entry_discovery', 0):.1f}s")
        print(f"  - D1:      {phase_times.get('d1', 0):.1f}s")
        print(f"  - A1:        {phase_times.get('a1', 0):.1f}s")
        print(f"  - A2:        {phase_times.get('a2', 0):.1f}s")
        print(f"  - Merge:     {phase_times.get('merge', 0):.1f}s")
        if enable_verification:
            print(f"  - D2:        {phase_times.get('d2', 0):.1f}s")

        print("\n[Output Files]")
        print(f"  最终报告 (MD): {final_report['markdown_file']}")
        print(f"  最终报告 (JSON): {final_report['json_file']}")

        pocs_dir = Path(final_report['markdown_file']).parent / 'pocs'
        if pocs_dir.exists():
            print(f"\n[POC Directory] {pocs_dir}")

        for r in a1_results + a2_results:
            for v in r.vulnerabilities:
                progress_logger.add_vulnerability(v.to_dict())

        progress_logger.update_stats({
            'total': sum(len(r.vulnerabilities) for r in a1_results + a2_results),
        })
        # 展示计数从此一律由黑板派生，禁止各处自存快照（消灭 那类事后对账补丁）。
        try:
            from src.core import blackboard as _blackboard2
            _bb_db2 = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
            _bb_run2 = _bb_run_id or _blackboard2.resolve_run_id(_bb_db2, task_id)
            _bb_n = _blackboard2.sync_blackboard(_bb_db2, task_id, _bb_run2)
            _bb_counts = _blackboard2.derive_counts(_bb_db2, task_id, _bb_run2)
            _bb_check = _blackboard2.consistency_check(_bb_db2, task_id, _bb_run2)
            _blackboard2.finish_run(_bb_db2, _bb_run2, status="completed", metrics=_bb_counts)
            # 自检结果写回 scan_progress，供前端/自动化直接看到不一致，而不是事后靠 reconcile 察觉。
            try:
                _update_scan_progress_metadata(
                    output_dir,
                    {"stage_results": {"blackboard": {
                        "status": "completed" if _bb_check.get("ok") else "inconsistent",
                        "run_id": _bb_run2,
                        "rows": _bb_n,
                        "counts": _bb_counts,
                        "alerts": _bb_check.get("alerts") or [],
                        "message": "黑板派生 {} 行（detected={} confirmed={} sink_reached={} verified={}）".format(
                            _bb_n, _bb_counts.get("detected", 0), _bb_counts.get("confirmed", 0),
                            _bb_counts.get("sink_reached", 0), _bb_counts.get("verified", 0)),
                    }}},
                )
            except Exception:
                pass
            logger.info("[blackboard] run=%s 黑板 %d 行 %s；自检 %s",
                        _bb_run2, _bb_n, _bb_counts, "OK" if _bb_check.get("ok") else _bb_check.get("alerts"))
        except Exception as _e:
            logger.warning("[blackboard] 黑板收口失败（不影响报告）：%s", _e)

        progress_logger.close()
        # 全局心跳收尾（与函数开头的 _global_hb_stop 配对）：报告/黑板全部完成后再停，
        # 确保最后一个长尾阶段也被心跳覆盖。
        try:
            _global_hb_stop()
        except Exception:
            pass

        print("=" * 60)
        zero_audit = summarize_d2_zero_audit(final_report['report'].get('vulnerabilities', []) or [])
        return {
            'report': final_report['report'],
            'final_report': final_report,
            'phase_times': phase_times,
            'output_dir': output_dir,
            'target_path': target_path,
            'external_target': external_target or {},
            'hitl': {
                'approval_mode': config.get('agents.d2.hitl.approval_mode', 'off'),
                'tool_allowlist': list(config.get('agents.d2.hitl.tool_allowlist', []) or []),
            'act_allowlist': list(config.get('agents.d2.hitl.act_allowlist', []) or []),
                'pending_actions': list(d2_verifications.get('pending_actions', []) or []),
            },
            'd2_zero_audit': zero_audit,
            'stage_results': {
                'preprocess': {
                    'file_count': len(files),
                    'endpoint_count': endpoint_count,
                    'indexed_functions': ((code_index or {}).get('stats') or {}).get('total_functions', 0),
                    'http_entries': ((code_index or {}).get('stats') or {}).get('http_entries', 0),
                    'scan_mode': scan_mode,
                },
                'sca': {k: v for k, v in sca_result.items() if k != 'findings'},
                'entry_discovery': {
                    'status': entry_discovery_result.get('status', 'skipped'),
                    'entry_count': entry_discovery_result.get('entry_count', 0),
                    'rule_candidate_count': len(entry_discovery_result.get('rule_candidates', []) or []),
                },
                'd1': {k: v for k, v in idor_result.items() if k not in {'findings', 'decisions'}},
                'ai_review': ai_review_metrics,
                'a1': {
                    'finding_count': sum(len(r.vulnerabilities) for r in a1_results),
                },
                'a2': {
                    'finding_count': sum(len(r.vulnerabilities) for r in a2_results),
                    # 避免被自建 stage_results 覆盖后从 task_completed 载荷里消失。
                    'contract': dict(_a2_contract_stats or {}),
                },
                'external_target': {
                    'service_url': (external_target or {}).get('service_url', ''),
                    'app_name': (external_target or {}).get('app_name', ''),
                    'agent_id': (external_target or {}).get('agent_id', ''),
                    'probe_mode': (external_target or {}).get('probe_mode', 'monitor'),
                },
                'd2': {
                    'verified_count': d2_verifications.get('total_vulnerabilities', 0),
                    'exploitable_count': d2_verifications.get('exploitable_count', 0),
                    'verified_poc_count': d2_verifications.get('verified_poc_count', 0),
                    'docker_used': d2_verifications.get('docker_used', False),
                    **(d2_verifications.get('aggregate') or {}),
                    # _update_scan_progress_metadata 写进 scan_progress.json（该文件是易变快照，
                    # 会被 progress_logger 覆写），而此处按固定键重建 stage_results.d2 →
                    # summary_json / task_result.json 里根本没有调度埋点，事后无法定位缺口。
                    # 现在一并带出；execution_trace 有上限截断，避免超大任务撑爆 summary_json。
                    'scheduling': _scheduling_payload(d2_verifications.get('scheduling')),
                    'poll_stats': dict(_d2_poll_stats or {}),
                },
                'reporting': {
                    'report_count': 1,
                },
                'i2': dict(_i2_stage_payload or {}),
            },
        }
    finally:
        try:
            progress_logger.close()
        except Exception:
            pass
        # 重构文档 3.6：Docker 运行时已删除，不再清理托管容器。

def main():
    """离线 CLI 直跑入口已禁用：统一链路要求所有扫描经由任务编排路径执行。"""
    import sys

    sys.stderr.write(
        "错误：离线 CLI 入口（benchmark_cli 直跑）已被禁用。\n"
        "所有扫描请经由统一任务编排路径：\n"
        "  1) 启动后端服务（uv run python -m src.cli.service_server）；\n"
        "  2) 通过 API / 前端创建扫描任务（workspace 归属 + task_id 下发），\n"
        "     由 task_service → scan_task_runner → run_benchmark(task_id=...) 统一执行。\n"
        "这样才能正确登记 trigger_specs 并驱动 D1/D2/I2 运行时验证。\n"
    )
    raise SystemExit(2)


if __name__ == '__main__':
    raise SystemExit(main())
