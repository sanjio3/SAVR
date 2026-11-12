"""
扫描进度记录器 - 实时记录扫描进度到MD文件
"""
import os
import json
import time
import threading
import ctypes
from contextlib import contextmanager
from datetime import datetime
from typing import Dict
import logging

logger = logging.getLogger(__name__)


def _force_delete_file(path: str) -> None:
    """删除文件；Windows 上**优先**用原生 DeleteFileW，绕过 safe-delete 沙箱垫片。

    就直接终止进程——表现为子进程启动 3 秒内 exit code 1、无 traceback、无 task_result.json。
    原来的实现是「先 os.remove，失败再走原生」，等于每次都先去撞垫片，触顶后连兜底机会都没有。
    故 Windows 上改为原生优先。
    """
    if os.name == "nt":
        try:
            k = ctypes.windll.kernel32
            k.DeleteFileW.argtypes = [ctypes.c_wchar_p]
            k.DeleteFileW.restype = ctypes.c_bool
            if k.DeleteFileW(path):
                return
            if not os.path.exists(path):
                raise FileNotFoundError(2, "not found", path)
        except FileNotFoundError:
            raise
        except Exception:
            pass
        # 原生删失败但文件仍在（被占用/权限）：退回 os.remove，保持原语义
        os.remove(path)
        return
    os.remove(path)


def _force_remove_lock(path: str) -> None:
    """释放进程锁时强力删除 lock 文件；文件不存在时静默通过。"""
    try:
        _force_delete_file(path)
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.warning("Failed to remove progress lock %s: %s", path, exc)


class ScanProgressLogger:
    """
    扫描进度实时记录器

    功能:
    - 增量写入MD文件
    - 实时显示扫描进度
    - 记录漏洞发现
    - 支持断点续传
    """

    def __init__(self, output_dir: str = "output", reset_on_start: bool = True):
        self.output_dir = output_dir
        self.md_path = os.path.join(output_dir, "scan_progress.md")
        self.json_path = os.path.join(output_dir, "scan_progress.json")
        self.lock_path = os.path.join(output_dir, "scan_progress.lock")
        self.reset_on_start = reset_on_start
        self._lock = threading.RLock()

        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 初始化文件
        self._init_files()

    def _init_files(self):
        """初始化MD和JSON文件"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self._guard():
            if self.reset_on_start or not os.path.exists(self.md_path):
                with open(self.md_path, 'w', encoding='utf-8') as f:
                    f.write(f"# SAST 扫描进度报告\n\n")
                    f.write(f"**扫描时间**: {timestamp}\n\n")
                    f.write("## 扫描进度\n\n")
                    f.write("| 阶段 | 状态 | 详情 |\n")
                    f.write("|------|------|------|\n")
                    f.write("| Phase 1: 文件扫描 | ⏳ 待开始 | - |\n")
                    f.write("| Phase 2: A1 规则分析 | ⏳ 待开始 | - |\n")
                    f.write("| Phase 3: 代码索引构建 | ⏳ 待开始 | - |\n")
                    f.write("| Phase 4: A2 智能分析 | ⏳ 待开始 | - |\n")
                    f.write("| Phase 5: D2 动态验证 | ⏳ 待开始 | - |\n\n")
                    f.write("---\n\n")
                    f.write("## 漏洞统计\n\n")
                    f.write("| 类型 | 数量 |\n")
                    f.write("|------|------|\n")
                    f.write("| 总漏洞 | 0 |\n")
                    f.write("| 确认真漏洞 | 0 |\n")
                    f.write("| 确认假漏洞 | 0 |\n")
                    f.write("| 待验证 | 0 |\n\n")
                    f.write("---\n\n")
                    f.write("## 漏洞详情\n\n")
                    f.write("*暂无漏洞记录*\n\n")

            if self.reset_on_start or not os.path.exists(self.json_path):
                self._save_json(self._default_json_data(timestamp))

    @staticmethod
    def _default_json_data(timestamp: str = None) -> Dict:
        """返回默认进度JSON结构。"""
        timestamp = timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return {
            'timestamp': timestamp,
            'phases': {
                'phase0': {'status': 'pending', 'details': ''},
                'phase1': {'status': 'pending', 'details': ''},
                'phase2': {'status': 'pending', 'details': ''},
                'phase3': {'status': 'pending', 'details': ''},
                'phase4': {'status': 'pending', 'details': ''},
                'phase5': {'status': 'pending', 'details': ''},
            },
            'vulnerabilities': [],
            'stats': {
                'total': 0,
                'true_positive': 0,
                'false_positive': 0,
                'pending': 0
            }
        }

    @staticmethod
    def _phase_label(phase: str) -> str:
        """统一阶段标签，避免 phase id 与 Markdown 展示不一致。"""
        phase_map = {
            'phase0': 'Phase 0: 信息收集',
            'phase1': 'Phase 1: 文件扫描',
            'phase2': 'Phase 2: A1 规则分析',
            'phase3': 'Phase 3: 代码索引构建',
            'phase4': 'Phase 4: A2 智能分析',
            'phase5': 'Phase 5: D2 动态验证',
        }
        return phase_map.get(phase, phase)

    def _read_md(self) -> str:
        with open(self.md_path, 'r', encoding='utf-8') as f:
            return f.read()

    @contextmanager
    def _guard(self):
        """串行化线程内与跨进程文件访问。"""
        with self._lock:
            self._acquire_process_lock()
            try:
                yield
            finally:
                self._release_process_lock()

    def _acquire_process_lock(self, timeout_seconds: float = 30.0, poll_interval: float = 0.05, stale_seconds: float = 120.0):
        """使用独占 lock 文件做跨进程互斥。"""
        deadline = time.time() + timeout_seconds
        pid = os.getpid()
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.write(fd, f"{pid}\n{datetime.now().isoformat()}".encode('utf-8'))
                self._process_lock_fd = fd
                return
            except FileExistsError:
                try:
                    age = time.time() - os.path.getmtime(self.lock_path)
                    if age > stale_seconds:
                        _force_remove_lock(self.lock_path)
                        logger.warning("Removed stale progress lock: %s", self.lock_path)
                        continue
                except FileNotFoundError:
                    continue
                if time.time() >= deadline:
                    raise TimeoutError(f"Timed out waiting for progress lock: {self.lock_path}")
                time.sleep(poll_interval)

    def _release_process_lock(self):
        fd = getattr(self, '_process_lock_fd', None)
        if fd is None:
            return
        try:
            os.close(fd)
        finally:
            self._process_lock_fd = None
            _force_remove_lock(self.lock_path)

    def _write_md(self, content: str):
        self._atomic_write_text(self.md_path, content)

    @staticmethod
    def _replace_with_retry(temp_path: str, path: str, attempts: int = 6) -> None:
        """原子替换 + 退避重试。Windows 上目标文件可能被前端进度轮询、
        索引服务或杀软短暂持有，os.replace 会抛 WinError 5 / PermissionError。
        就把整轮判 failed，属执行层故障而非能力故障。
        """
        for attempt in range(attempts):
            try:
                os.replace(temp_path, path)
                return
            except PermissionError:
                if attempt == attempts - 1:
                    raise
                time.sleep(0.1 * (attempt + 1))

    @staticmethod
    def _atomic_write_text(path: str, content: str):
        temp_path = f"{path}.tmp"
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        try:
            ScanProgressLogger._replace_with_retry(temp_path, path)
        except PermissionError as exc:
            # 进度 md 是可再生展示物，降级为就地覆盖写；绝不能因为一次文件锁
            # 把整轮扫描判 failed。最坏结果只是前端读到半帧，下次刷新即恢复。
            logger.warning("progress md atomic replace failed, fallback in-place: %s", exc)
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
            except OSError:
                logger.exception("progress md fallback write failed")
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass

    def update_phase(self, phase: str, status: str, details: str = ""):
        """
        更新阶段状态

        Args:
            phase: 阶段名称 (phase1-phase5)
            status: 状态 (pending/running/completed/failed)
            details: 详情
        """
        status_map = {
            'pending': '⏳ 待开始',
            'running': '🔄 进行中',
            'completed': '✅ 完成',
            'failed': '❌ 失败'
        }

        emoji = status_map.get(status, status)

        with self._guard():
            content = self._read_md()

            phase_label = self._phase_label(phase)
            replacement = f"| {phase_label} | {emoji} | {details} |"
            lines = content.splitlines()
            updated = False
            for idx, line in enumerate(lines):
                if line.startswith(f"| {phase_label} |"):
                    lines[idx] = replacement
                    updated = True
                    break
            if not updated:
                try:
                    table_idx = lines.index("|------|------|------|") + 1
                    lines.insert(table_idx, replacement)
                except ValueError:
                    lines.append(replacement)
            self._write_md('\n'.join(lines) + '\n')

            json_data = self._load_json()
            json_data.setdefault('phases', {})
            json_data['phases'][phase] = {
                'status': status,
                'details': details,
                'updated_at': datetime.now().isoformat()
            }
            self._save_json(json_data)

        logger.info(f"[{phase}] {status}: {details}")

    def add_vulnerability(self, vuln: Dict):
        """
        添加漏洞记录

        Args:
            vuln: 漏洞信息字典
        """
        # 判定emoji
        verdict = vuln.get('verdict', '')
        if '真' in verdict or '✅' in verdict:
            emoji = '✅'
        elif '假' in verdict or '❌' in verdict:
            emoji = '❌'
        else:
            emoji = '⚠️'

        with self._guard():
            content = self._read_md()

            vuln_section = f"""### {emoji} {vuln.get('type', 'Unknown')}

- **文件**: {vuln.get('file', 'N/A')}
- **行号**: {vuln.get('line', 'N/A')}
- **判定**: {verdict}
- **来源**: {vuln.get('source', 'N/A')}

```
{vuln.get('code_snippet', 'N/A')}
```

"""

            if '*暂无漏洞记录*' in content:
                content = content.replace('*暂无漏洞记录*', vuln_section.strip())
            else:
                content = content.replace('## 漏洞详情\n\n', f'## 漏洞详情\n\n{vuln_section}')
            self._write_md(content)

            json_data = self._load_json()
            json_data.setdefault('vulnerabilities', []).append(vuln)
            json_data.setdefault('stats', {'total': 0, 'true_positive': 0, 'false_positive': 0, 'pending': 0})

            if '真' in verdict:
                json_data['stats']['true_positive'] += 1
            elif '假' in verdict:
                json_data['stats']['false_positive'] += 1
            else:
                json_data['stats']['pending'] += 1
            json_data['stats']['total'] += 1

            self._save_json(json_data)

    def update_stats(self, stats: Dict):
        """更新统计信息"""
        with self._guard():
            content = self._read_md()
            lines = content.split('\n')

            for key, value in stats.items():
                for i, line in enumerate(lines):
                    if f"| {key} |" in line and '|' in line.replace(f"| {key} |", ''):
                        parts = line.rsplit('|', 2)
                        if len(parts) >= 2:
                            lines[i] = parts[0] + f"| {value} |"
                            break

            self._write_md('\n'.join(lines))

            json_data = self._load_json()
            json_data.setdefault('stats', {}).update(stats)
            self._save_json(json_data)

    def add_summary(self, summary: str):
        """添加总结"""
        with self._guard():
            content = self._read_md()
            content += "---\n\n"
            content += "## 扫描总结\n\n"
            content += summary + "\n\n"
            self._write_md(content)

    def get_progress(self) -> Dict:
        """获取当前进度"""
        return self._load_json()

    def _load_json(self) -> Dict:
        """加载JSON数据"""
        if not os.path.exists(self.json_path):
            return self._default_json_data()

        try:
            with open(self.json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            broken_path = f"{self.json_path}.broken.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            try:
                os.replace(self.json_path, broken_path)
                logger.warning("Progress JSON was corrupted; backed up to %s", broken_path)
            except OSError:
                logger.warning("Progress JSON was corrupted and could not be moved aside: %s", self.json_path)
            logger.warning("Progress JSON reset due to load failure: %s", exc)
            data = self._default_json_data()
            self._save_json(data)

        defaults = self._default_json_data(data.get('timestamp'))
        defaults['phases'].update(data.get('phases', {}))
        defaults['vulnerabilities'] = data.get('vulnerabilities', [])
        defaults['stats'].update(data.get('stats', {}))
        # 保留扫描编排写入的所有扩展字段（stage_results / reports / hitl / external_target /
        # target_epoch / replay_progress / d2_verify_progress / a2_progress / i2_rerun ...）。
        # 凡不在名单里的扩展键，都会被 update_phase / add_vulnerability / update_stats 的
        # target_epoch（「本批次是否横跨靶场重启」的权威结论）与 replay_progress / d2_verify_progress
        # 等被抹成缺失，使「D2 数据是否可对账」在产物里无法审计（事件流仍完整，本文件已丢）。
        # 改为保留 data 中所有未知键：新增扩展字段无需再同步名单，杜绝同类回归（fail-safe）。
        if isinstance(data, dict):
            for _k, _v in data.items():
                if _k not in defaults:
                    defaults[_k] = _v
        return defaults

    def _save_json(self, data: Dict):
        """保存JSON数据"""
        temp_path = f"{self.json_path}.tmp"
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        # 进度 json 是权威中间产物，不能像 md 那样降级覆盖；沿用带退避的
        # 原子替换，重试耗尽仍抛（fail-closed 语义不变），重试次数与 md 统一。
        self._replace_with_retry(temp_path, self.json_path)

    def close(self):
        """关闭记录器"""
        with self._guard():
            content = self._read_md()
            content += f"\n*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
            self._write_md(content)


# 便捷函数
def create_logger(output_dir: str = "output") -> ScanProgressLogger:
    """创建进度记录器"""
    return ScanProgressLogger(output_dir)
