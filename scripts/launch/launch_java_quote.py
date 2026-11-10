"""java-quote 看门狗（session 2 / workspace 2）：以独立进程组拉起 java-quote(8899)+IAST 探针，
退出即 5s 后自动重启。通过 run_in_background 受管任务常驻，使 java 不随 Bash 命令回收而死的。

挂载参数源自用户 2026-08-29 提供的命令，两点必要修正：
- -Dsec.app.packages 由 com.example 改为 com.quote（归档 jar 实际包名是 com.quote，com.example 会让探针零插桩）
- -Dsec.server.url 由 http://localhost:8000 改为 http://127.0.0.1:8000（后端只绑 127.0.0.1:8000，localhost 可能解析到 ::1 导致连不上）
- jar / JDK / 探针路径全部由环境变量提供，仓库内不保存任何本机绝对路径

TOKEN 每次启动前从 DB 动态解析：workspace 删除重建会级联清掉 iast_sessions，
旧 token 立刻失效 → 探针心跳/事件被 authenticate_by_token 全量拒绝（HTTP 200 但
accepted=0）。2026-11-09起统一走 src.iast.probe_token.resolve 按
(workspace_id, app_name, agent_id) 三元组取唯一权威值：原实现查询不带 workspace，
可能命中别的 workspace 下的同名会话；环境变量只作显式 fallback 且与 DB 不一致时
fail-closed 报错，不再「各 launcher 各挑一个」造成静默丢事件。
2026-11-06 起仓库不再内置任何静态 token，取不到凭据即明确报错退出。
"""
import os
import shutil
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # 项目根（本脚本在 scripts/launch/ 下）
JAVA = os.environ.get("SAST_AI_JAVA", shutil.which("java") or "java")
# 探针源码已内置到本项目 probe-java/：默认用项目内构建产物，可由环境变量覆盖。
PROBE = os.environ.get("SAST_AI_PROBE_JAR",
                       os.path.join(ROOT, "probe-java", "target", "sec-probe.jar"))
# 靶场 jar（CC 3.1 反序列化验证靶场，POST /debug/import）不随仓库分发。
JAR = os.environ.get("SAST_AI_JAVA_QUOTE_JAR", "")
FALLBACK_TOKEN = os.environ.get("SAST_AI_PROBE_TOKEN", "")
LOG = os.environ.get("SAST_AI_JAVA_QUOTE_LOG",
                     os.path.join(ROOT, "java-quote-watchdog.log"))
DB_PATH = os.environ.get("SAST_AI_DB_PATH", os.path.join(ROOT, "data", "app.db"))

APP_NAME = "java"
AGENT_ID = "java-quote"
WORKSPACE_ID = int(os.environ.get("SAST_AI_JAVA_QUOTE_WORKSPACE_ID", "6"))

DETACH = 0x00000200 | 0x00000008  # CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def resolve_token(logf):
    """统一按三元组从 DB 取唯一权威 token；env 与 DB 不一致直接 fail-closed。"""
    from src.iast.probe_token import ProbeTokenError, resolve

    try:
        r = resolve(WORKSPACE_ID, APP_NAME, AGENT_ID, db_path=DB_PATH,
                    env_token=FALLBACK_TOKEN)
        for warning in r.warnings:
            logf.write(f"[{now()}] [WARN] {warning}\n")
        logf.write(f"[{now()}] [token] source={r.source} session={r.session_id} "
                   f"prefix={r.token_prefix}… ws={WORKSPACE_ID}\n")
        return r.token, r.session_id
    except ProbeTokenError as e:
        logf.write(f"[{now()}] [FATAL] 探针 token 解析失败：{e}\n")
        return "", None


def main():
    logf = open(LOG, "a", buffering=1)
    sys.stdout = logf
    sys.stderr = logf
    if not JAR or not os.path.isfile(JAR):
        logf.write(f"[{now()}] [FATAL] 未配置 SAST_AI_JAVA_QUOTE_JAR 或文件不存在：{JAR!r}\n")
        sys.exit(2)
    if not os.path.isfile(PROBE):
        logf.write(f"[{now()}] [FATAL] 探针 jar 不存在：{PROBE!r}（设 SAST_AI_PROBE_JAR）\n")
        sys.exit(2)
    while True:
        token, sid = resolve_token(logf)
        if not token:
            logf.write(f"[{now()}] [FATAL] 未取得探针 token：请在 iast_sessions 注册会话，"
                       f"或设置 SAST_AI_PROBE_TOKEN；不使用内置凭据\n")
            sys.exit(2)
        logf.write(f"[{now()}] ===== starting java-quote (8899 + IAST probe, session {sid}) =====\n")
        logf.flush()
        try:
            p = subprocess.Popen(
                [JAVA,
                 "-Djdk.httpclient.version=HTTP_1_1",
                 "-Dsec.network.timeout.ms=5000",
                 # P0 铁律（2026-09-28 复核）：JDK16+ 强封装下 agent 自身类在 AppClassLoader，
                 # 插桩 java.base 类解析不到 HookRuntime → NoClassDefFoundError + 崩溃循环。
                 # -Xbootclasspath/a 是 JVM 只读共享映射，多靶场可同时挂同一 jar 互不影响。
                 f"-Xbootclasspath/a:{PROBE}",
                 "-javaagent:" + PROBE,
                 "-Dsec.server.url=http://127.0.0.1:8000",
                 "-Dsec.agent.id=java-quote",
                 "-Dsec.app.name=java",
                 "-Dsec.agent.token=" + token,
                 "-Dsec.app.packages=com.quote",
                 "-Dserver.port=8899",
                 "-jar", JAR],
                stdout=logf, stderr=subprocess.STDOUT,
                creationflags=DETACH, close_fds=True,
            )
            rc = p.wait()
            logf.write(f"[{now()}] java-quote exited code={rc}, restart in 5s =====\n")
        except Exception as e:
            logf.write(f"[{now()}] launch error: {e}\n")
        logf.flush()
        time.sleep(5)


if __name__ == "__main__":
    main()
