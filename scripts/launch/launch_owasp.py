"""OWASP Benchmark 看门狗：以独立进程组拉起 benchmark(tomcat9x, 8443)+IAST 探针，退出即 5s 后自动重启。

挂载要点（同 launch_target_mall.py / launch_java_seccode.py）：
- OWASP 必须 JDK11：旧 catalina 日志 java.library.path 实证为 JDK11；bat 硬编码 jdk-21 会让
  插桩类(java.base/jakarta.servlet/...)在 JDK16+ 强封装下解析失败、报 NoClassDefFoundError(HookRuntime)、
  report-sink NPE、全 hook 失效（表现为 iast_events 恒 0）。
- -Xbootclasspath/a:PROBE + -javaagent:PROBE 双挂，使插桩的 JDK/框架类能解析 agent 回调类。
- -Dsec.server.url 用 http://127.0.0.1:8000（后端只绑 127.0.0.1，localhost 可能解析 ::1 连不上）。
- -Djdk.httpclient.version=HTTP_1_1 强制 HTTP/1.1（JDK HttpClient 对 http:// 默认升级 h2c 致 422）。
- TOKEN 每次启动前从 DB 动态解析（同 launch_target_mall），不得硬编码。

与 target-mall 不同：OWASP 是 Tomcat（catalina.bat run），不是 -jar 自含 Spring Boot。
"""
import os
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # 项目根（本脚本在 scripts/launch/ 下）
JAVA_HOME = r"C:\Program Files\Java\jdk-11"
# HSQLDB 服务器用 JDK21（独立 DB 服务，JDK 版本无关；与原 run_hsqldb.bat 一致）。
HSQLDB_JAVA = (os.environ.get("SAST_AI_HSQLDB_JAVA", "").strip()
               or os.path.join(JAVA_HOME, "bin", "java.exe"))
_PROBE_LOCAL = os.path.join(ROOT, "probe-java", "target", "sec-probe.jar")
PROBE = os.environ.get("SAST_AI_PROBE_JAR", "").strip() or _PROBE_LOCAL
# HSQLDB 数据/启动目录 = benchmark-sample-200 根（benchmark.db 在 target/db 下，JNDI dbname=benchmarkDataBase）
# 靶场是外部项目，不随本仓库分发：用环境变量指定，未设置时按「与本仓库同级目录」约定回退。
BENCH_ROOT = (os.environ.get("SAST_AI_OWASP_DIR", "").strip()
             or os.path.join(ROOT, "..", "owasp-code", "benchmark-sample-200"))
TOMCAT = (os.environ.get("SAST_AI_OWASP_TOMCAT_DIR", "").strip()
          or os.path.join(BENCH_ROOT, "target", "tomcat9x"))
BIN = os.path.join(TOMCAT, "bin")
APP_NAME = "benchmark"
AGENT_ID = "owasp-benchmark-sample"
TARGET_URL = "http://127.0.0.1:8443/benchmark"
CODE_PATH = BENCH_ROOT
DB_PATH = os.environ.get("SAST_AI_DB_PATH", os.path.join(ROOT, "data", "app.db"))
LOG = (os.environ.get("SAST_AI_WATCHDOG_LOG", "").strip()
       or os.path.join(ROOT, "logs", "owasp-watchdog.log"))

# CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW：脱离运行时作业、常驻、不弹窗。
DETACH = 0x00000200 | 0x08000000


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _norm(p):
    return (p or "").replace("\\", "/").rstrip("/")


def resolve_workspace_id(con):
    row = con.execute("SELECT id FROM workspaces WHERE target_path = ?", (CODE_PATH,)).fetchone()
    if row:
        return row[0]
    for wid, tp in con.execute("SELECT id, target_path FROM workspaces").fetchall():
        if _norm(tp) == _norm(CODE_PATH):
            return wid
    row = con.execute("SELECT id FROM workspaces WHERE name = ?", (APP_NAME,)).fetchone()
    return row[0] if row else None


def resolve_token(logf):
    """#544：统一按三元组取 DB 权威 token，不再靠 CODE_PATH 反推 workspace。

    原实现用 target_path 字符串匹配反推 workspace_id；L1 盲化切换会改
    workspaces.target_path，反推就可能落到别的 workspace 甚至新建孤儿 workspace，
    进而取到错 token。三元组里 workspace_id 是显式常量（可由环境变量覆盖），
    与 tools/run_profiles.yaml 的 owasp-sample profile 一致。
    """
    from src.iast.probe_token import ProbeTokenError, resolve

    wid = int(os.environ.get("SAST_AI_OWASP_SAMPLE_WORKSPACE_ID", "5"))
    try:
        r = resolve(wid, APP_NAME, AGENT_ID, db_path=DB_PATH,
                    allow_env_fallback=False)
        for warning in r.warnings:
            logf.write(f"[{now()}] [WARN] {warning}\n")
        logf.write(f"[{now()}] [token] source={r.source} session={r.session_id} "
                   f"prefix={r.token_prefix}… ws={wid}\n")
        return r.token
    except ProbeTokenError as e:
        logf.write(f"[{now()}] [FATAL] 探针 token 解析失败：{e}\n")
        return None


def build_catalina_opts(token):
    return (
        f"-Xbootclasspath/a:{PROBE} "
        f"-javaagent:{PROBE} "
        f"-Djdk.httpclient.version=HTTP_1_1 "
        f"-Dsec.network.timeout.ms=5000 "
        f"-Dsec.event.queue.size=8192 "
        f"-Dsec.event.flush.batch=2048 "
        f"-Dsec.server.url=http://127.0.0.1:8000 "
        f"-Dsec.agent.id={AGENT_ID} "
        f"-Dsec.app.name={APP_NAME} "
        f"-Dsec.agent.token={token} "
        f"-Dsec.app.packages=org.owasp.benchmark"
    )


def ensure_hsqldb(logf):
    """幂等拉起 OWASP Benchmark 依赖的 HSQLDB 服务器（端口 9001，dbname=benchmarkDataBase）。

    OWASP Benchmark 后台库是 HSQLDB 独立服务器（非 MySQL！）：conf/server.xml 的
    GlobalNamingResources 定义 jdbc/ApplicationContext_BenchmarkDB ->
    jdbc:hsqldb:hsql://localhost/benchmarkDataBase，driver=org.hsqldb.jdbc.JDBCDriver。
    缺失时每请求在 DataBaseFilter.doFilter 抛 NPE -> 全 500 -> 流量到不了 sink -> IAST 事件恒 0。
    Task #274 拆除整栈曾误杀该进程而 launch_owasp 仅拉 Tomcat+探针未覆盖，本次补上。
    """
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15).stdout
        if "0.0.0.0:9001" in out or "[::]:9001" in out:
            logf.write(f"[{now()}] HSQLDB(9001) 已 LISTENING，跳过\n")
            logf.flush()
            return
    except Exception as e:
        logf.write(f"[{now()}] netstat 检查 9001 失败：{e}\n")
    logf.write(f"[{now()}] HSQLDB(9001) 未监听，启动中 =====\n")
    logf.flush()
    env = os.environ.copy()
    env["JAVA_HOME"] = HSQLDB_JAVA
    classes = os.path.join(BENCH_ROOT, "target", "benchmark", "WEB-INF", "classes")
    lib = os.path.join(BENCH_ROOT, "target", "benchmark", "WEB-INF", "lib", "*")
    cp = f"{classes};{lib}"
    try:
        subprocess.Popen(
            [HSQLDB_JAVA, "-cp", cp, "org.hsqldb.Server",
             "--database.0", "file:target/db/benchmark.db",
             "--dbname.0", "benchmarkDataBase"],
            cwd=BENCH_ROOT,
            env=env,
            stdout=logf, stderr=subprocess.STDOUT,
            creationflags=DETACH, close_fds=True,
        )
        logf.write(f"[{now()}] HSQLDB detached 启动命令已发出（cwd={BENCH_ROOT}，JAVA={HSQLDB_JAVA}）\n")
    except Exception as e:
        logf.write(f"[{now()}] HSQLDB 启动失败：{e}\n")
    logf.flush()


def main():
    logf = open(LOG, "a", buffering=1)
    sys.stdout = logf
    sys.stderr = logf
    while True:
        # 先确保后台库在线（HSQLDB 9001），否则 Tomcat 拉起后每请求 500。
        ensure_hsqldb(logf)
        token = resolve_token(logf)
        if not token:
            logf.write(f"[{now()}] 无可用 probe_token，10s 后重试 =====\n")
            logf.flush()
            time.sleep(10)
            continue
        logf.write(f"[{now()}] ===== starting OWASP benchmark (8443 + IAST probe, JDK11) =====\n")
        logf.flush()
        env = os.environ.copy()
        env["JAVA_HOME"] = JAVA_HOME
        env["CATALINA_OPTS"] = build_catalina_opts(token)
        env["CATALINA_HOME"] = TOMCAT
        env["CATALINA_BASE"] = TOMCAT
        try:
            p = subprocess.Popen(
                [os.path.join(BIN, "catalina.bat"), "run"],
                cwd=BIN,
                env=env,
                stdout=logf, stderr=subprocess.STDOUT,
                creationflags=DETACH, close_fds=True,
            )
            rc = p.wait()
            logf.write(f"[{now()}] OWASP catalina exited code={rc}, restart in 5s =====\n")
        except Exception as e:
            logf.write(f"[{now()}] launch error: {e}\n")
        logf.flush()
        time.sleep(5)


if __name__ == "__main__":
    main()
