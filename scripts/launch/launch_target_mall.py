"""target-mall 看门狗：以独立进程组拉起 target-mall(8092)+IAST 探针，退出即 5s 后自动重启。
通过 run_in_background 受管任务常驻，使 java 不随 Bash 命令回收而死的。

挂载参数两点必要修正（同 java-quote 教训）：
- -Dsec.server.url 用 http://127.0.0.1:8000（后端只绑 127.0.0.1:8000，localhost 可能解析到 ::1 连不上）
- -Djdk.httpclient.version=HTTP_1_1 强制 HTTP/1.1（JDK HttpClient 对 http:// 默认升级 h2c 致 uvicorn 返回 422）
- -Dsec.app.packages=com.sanjio.mall（jar 实际包名，com.example 会让探针零插桩）

TOKEN 必须每次启动前从 DB 动态解析（不得硬编码）：workspace 删除重建会级联清掉 iast_sessions，
旧 token 立刻失效 → 探针心跳/事件被 authenticate_by_token 全量拒绝（HTTP 200 但 accepted=0），
表现为 iast_events 恒 0 行、D2 全 no_evidence。此处按 (workspace_id, app_name, agent_id) 查
probe_token，查不到就现场注册一条再取。
"""
import os
import sqlite3
import subprocess
import sys
import time
import errno
import atexit
import ctypes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # 项目根（本脚本在 scripts/launch/ 下）
JAVA = (os.environ.get("SAST_AI_JAVA_BIN", "").strip()
        or os.path.join(os.environ.get("JAVA_HOME", "").strip()
                        or r"C://Program Files//Java//jdk-21", "bin", "java.exe"))
_PROBE_LOCAL = os.path.join(ROOT, "probe-java", "target", "sec-probe.jar")
# 探针源码已内置到本项目 probe-java/（见 probe-java/README.md）：优先用项目内构建产物，
# 未构建时回退外部 IAST_RASP 路径，保证过渡期两处都能跑，项目本身可自洽。
PROBE = os.environ.get("SAST_AI_PROBE_JAR", "").strip() or _PROBE_LOCAL
# 靶场是外部项目，不随本仓库分发：用环境变量指定，未设置时按「与本仓库同级目录」约定回退。
CODE_PATH = (os.environ.get("SAST_AI_TARGET_MALL_DIR", "").strip()
            or os.path.join(ROOT, "..", "target-mall"))
JAR = (os.environ.get("SAST_AI_TARGET_MALL_JAR", "").strip()
       or os.path.join(CODE_PATH, "target", "iast-target-mall.jar"))
LOG = (os.environ.get("SAST_AI_WATCHDOG_LOG", "").strip()
       or os.path.join(ROOT, "logs", "target-mall-watchdog.log"))
DB_PATH = os.environ.get("SAST_AI_DB_PATH", os.path.join(ROOT, "data", "app.db"))

APP_NAME = "mall"
AGENT_ID = "target-mall"
TARGET_URL = "http://127.0.0.1:8092"

# CREATE_NEW_PROCESS_GROUP 常驻；窗口策略：默认 CREATE_NO_WINDOW (0x08000000)，
# 避免 detached 子进程每次拉起都新开一个控制台窗口（用户可见的"弹 cmd 窗口"）。
# 需要看窗口时设 SASTAI_SHOW_WINDOW=1，届时改用 DETACHED_PROCESS (0x8)。
# 注意：CREATE_NO_WINDOW 与 DETACHED_PROCESS 互斥（MSDN），只能二选一。
DETACH = 0x00000200 | (0x00000008 if os.environ.get("SASTAI_SHOW_WINDOW") else 0x08000000)


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _norm(p):
    """统一路径分隔符：DB 里存的是 D:/... 形式，Windows 传入的是 D:\\... 形式。"""
    return (p or "").replace("\\", "/").rstrip("/")


def resolve_workspace_id(con):
    row = con.execute("SELECT id FROM workspaces WHERE target_path = ?", (CODE_PATH,), ).fetchone()
    if row:
        return row[0]
    for wid, tp in con.execute("SELECT id, target_path FROM workspaces").fetchall():
        if _norm(tp) == _norm(CODE_PATH):
            return wid
    row = con.execute("SELECT id FROM workspaces WHERE name = ?", (APP_NAME,), ).fetchone()
    return row[0] if row else None


def resolve_token(logf):
    """返回 (token, session_id)；拿不到返回 (None, None)。"""
    wid = None
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        try:
            wid = resolve_workspace_id(con)
            if wid is None:
                logf.write(f"[{now()}] 未找到 target_path={CODE_PATH} 的 workspace，跳过 token 解析\n")
                return None, None
            row = con.execute(
                "SELECT id, probe_token FROM iast_sessions WHERE workspace_id=? AND app_name=? AND agent_id=?",
                (wid, APP_NAME, AGENT_ID),
            ).fetchone()
            if row:
                return row[1], row[0]
        finally:
            con.close()
    except Exception as e:
        logf.write(f"[{now()}] token 解析失败：{e}\n")

    # 会话不存在（例如 workspace 重建后）→ 现场注册一条。
    # 必须带上解析到的 workspace_id，否则 register_session 按 code_path 反查不到时会
    # 「自动建 workspace」，凭空多出一个重复 workspace（历史教训）。
    if wid is None:
        return None, None
    try:
        sys.path.insert(0, HERE)
        from src.infrastructure.db import Database
        from src.iast.service import IastService
        db = Database(DB_PATH)
        sess = IastService(db).register_session({
            "target_url": TARGET_URL,
            "code_path": _norm(CODE_PATH),
            "app_name": APP_NAME,
            "agent_id": AGENT_ID,
            "probe_mode": "iast",
            "server_port": 8092,
            "workspace_id": wid,
            "probe_packages": "com.sanjio.mall",
        })
        logf.write(f"[{now()}] 已自动注册 iast_session id={sess.get('id')} workspace_id={sess.get('workspace_id')}\n")
        return sess.get("probe_token"), sess.get("id")
    except Exception as e:
        logf.write(f"[{now()}] 自动注册 iast_session 失败：{e}\n")
        return None, None


import socket

_SINGLETON_SOCK = None

def _find_pid_on_port(port):
    """返回本机 TCP LISTEN 占用 port 的 PID，无则 None。"""
    try:
        out = subprocess.check_output(
            ["netstat", "-ano", "-p", "TCP"],
            stderr=subprocess.DEVNULL,
        ).decode("gbk", "ignore")
    except Exception:
        return None
    for line in out.splitlines():
        if (":%d" % port) in line and "LISTENING" in line:
            parts = line.split()
            if parts and parts[-1].isdigit():
                return int(parts[-1])
    return None


def _interpreter_of(pid):
    try:
        out = subprocess.check_output(
            ["wmic", "process", "where", "ProcessId=%d" % pid, "get", "CommandLine"],
            stderr=subprocess.DEVNULL,
        ).decode("gbk", "ignore")
        for ln in out.splitlines():
            ln = ln.strip()
            if "python.exe" in ln:
                return ln
    except Exception:
        return ""
    return ""


def _acquire_singleton(port):
    """TCP 哨兵端口单实例守卫（跨会话/跨解释器可靠，无需特殊权限）。

    绑定 127.0.0.1:port 并 listen 作为持锁信号；其余实例 bind 失败即视为已被占用。
    若占用者是'错误解释器'（如 D:\\Python 旧栈）实例，则干掉它后重试，确保正确的 .venv 栈胜出。
    进程退出时 OS 自动释放端口，无需跨进程存活探测。此前基于 ctypes 命名互斥体的实现因
    HANDLE 被截断为 32 位且 GetLastError 不可靠，导致同会话内双实例都以为自己拿到了锁、
    两个 launch_target_mall 抢 8092 端口；TCP 哨兵端口由内核托管，无此问题。"""
    global _SINGLETON_SOCK
    self_exe = sys.executable
    for _ in range(4):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            s.listen(1)
            _SINGLETON_SOCK = s
            return True
        except OSError:
            s.close()
            holder = _find_pid_on_port(port)
            if holder is None:
                return False
            cmd = _interpreter_of(holder)
            if self_exe not in cmd and ".venv" not in cmd:
                try:
                    subprocess.call(
                        ["taskkill", "/PID", str(holder), "/F"],
                        stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    pass
                time.sleep(1)
                continue
            return False
    return False


def main():
    if not _acquire_singleton(7812):
        print(f"[{now()}] [singleton] 已有 launch_target_mall 实例在运行，本实例退出，避免双栈抢 8092 端口", flush=True)
        sys.exit(0)
    logf = open(LOG, "a", buffering=1)
    orig_stdout = sys.stdout  # 保留原始 stdout，用于心跳（防止运行时 idle-kill）
    sys.stdout = logf
    sys.stderr = logf
    _last_heartbeat = 0.0
    while True:
        token, sid = resolve_token(logf)
        if not token:
            logf.write(f"[{now()}] 无可用 probe_token，10s 后重试 =====\n")
            logf.flush()
            time.sleep(10)
            continue
        logf.write(f"[{now()}] ===== starting target-mall (8092 + IAST probe, session {sid}) =====\n")
        logf.flush()
        try:
            p = subprocess.Popen(
                [JAVA,
                 "-Djdk.httpclient.version=HTTP_1_1",
                 "-Dsec.network.timeout.ms=5000",
                 # 熔断：事件环形队列容量（默认 1024，见 ProbeConfig.load 的 sec.event.queue.size）。
                 # 实测 600 并发请求下队列占用达 92%≈943 条即触发熔断（cpu=13% errors=0，
                 # 唯一触发源是队列积压），熔断 10s 内 sink 走 passthrough 会漏检。
                 # 放大到 8192 给突发流量留水线。但实测放大后仍 92%（≈7500 条积压），
                 # 说明真正的瓶颈不是容量而是排空速率：默认刷批 256 条/500ms ≈ 512 条/s，
                 # 低于突发生产速率（600 并发请求约 750 条/s）。故同时把单批提到 2048
                 # （排空 ≈4096 条/s，仍只是 2 次 POST/s，不会打爆后端），二者都可调无需重新打包。
                 "-Dsec.event.queue.size=8192",
                 "-Dsec.event.flush.batch=2048",
                 # 连接泄漏诊断：连接被持住超过 5s 即打印"借出点"调用栈，定位泄漏源（探针 JDBC 插桩 / 靶场 DAO）
                 "-Dspring.datasource.hikari.leak-detection-threshold=5000",
                # 临时放大池容量：扫描并发重放打满 10 连接就会耗尽，放大到 30 争取诊断窗口（非根治）
                "-Dspring.datasource.hikari.maximum-pool-size=30",
                # R10：连接回收强制化（根治而非仅延后）——扫描负载下 HikariCP 连接被持住/泄漏，
                # 中途 500 致 A0 门禁反复判死。强制回收：连接最长存活 30min、空闲 10min 即回收、
                # 最小保活 5、获取连接超时 30s（快速失败而非无限阻塞）。配合自动化 Step0「扫描前重启靶场」。
                "-Dspring.datasource.hikari.minimum-idle=5",
                "-Dspring.datasource.hikari.idle-timeout=600000",
                "-Dspring.datasource.hikari.max-lifetime=1800000",
                "-Dspring.datasource.hikari.connection-timeout=30000",
                 # ---- -Xbootclasspath/a:PROBE ----
                 # 把探针 jar 挂引导类加载器搜索路径，使插桩的 JDK/框架类(java.base/jakarta.servlet/...)
                 # 能解析 agent 自身回调类(HookRuntime/SecurityAgent/...)。JDK11 下 java-sec-code 已验证必需；
                 # 缺此项时 JDK16+ 强封装会让目标-mall 插桩报 NoClassDefFoundError(HookRuntime)、report-sink NPE、全 hook 失效。
                 "-Xbootclasspath/a:" + PROBE,
                 "-javaagent:" + PROBE,
                 "-Dsec.server.url=http://127.0.0.1:8000",
                 "-Dsec.agent.id=target-mall",
                 "-Dsec.app.name=mall",
                 "-Dsec.agent.token=" + token,
                 "-Dsec.app.packages=com.sanjio.mall",
                 "-Dserver.port=8092",
                 "-jar", JAR],
                stdout=logf, stderr=subprocess.STDOUT,
                creationflags=DETACH, close_fds=True,
            )
            rc = p.wait()
            logf.write(f"[{now()}] target-mall exited code={rc}, restart in 5s =====\n")
        except Exception as e:
            logf.write(f"[{now()}] launch error: {e}\n")
        logf.flush()
        # 心跳：周期性向原始 stdout 输出，避免运行时因"后台任务长时间无输出"而 idle-kill
        _hb_now = time.time()
        if _hb_now - _last_heartbeat > 60:
            _last_heartbeat = _hb_now
            try:
                orig_stdout.write(f"[heartbeat] launch_target_mall alive @ {now()}\n")
                orig_stdout.flush()
            except Exception:
                pass
        time.sleep(5)


if __name__ == "__main__":
    main()
