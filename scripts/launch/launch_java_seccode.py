"""java-sec-code 看门狗：拉起 java-sec-code(8080)+IAST 探针，退出即 5s 自动重启。

要点：
- 2026-09-13 起靶场改用 JDK 11 运行，与探针降版后的字节码目标对齐。
  探针 sec-probe.jar 内 class 已全部降为 major=55(Java 11)，可在 JDK11/17/21 上运行；
  java-sec-code 为 Spring Boot 2.1.5，其官方支持组合就是 Java 8/11，故 JDK 11 是正解。
- 探针类加载(Phase D)尚未改造，零插桩的根因是 AgentClassLoader 私有加载器与
  Spring Boot 2.1.5 LaunchedURLClassLoader 互不可见，与 JVM 版本无关；切 JDK 11
  不会自动消除该问题，但为后续改造提供了干净基线（不再需要 --add-opens 绕 JPMS）。
- 首次启动经 IastService.register_session 自动注册 workspace + iast_session（token 幂等，重复启动不失效）。
- -Dsec.server.url=http://127.0.0.1:8000（后端只绑 127.0.0.1:8000）。
- -Djdk.httpclient.version=HTTP_1_1 强制 HTTP/1.1（JDK HttpClient 对 http:// 默认升级 h2c 致 uvicorn 422）。
- -Dsec.app.packages=org.joychou（java-sec-code 实际包名）。
"""
import os
import sys
import time
import glob
import socket
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # 项目根（本脚本在 scripts/launch/ 下）
JAVA = r"C:\Program Files\Java\jdk-11\bin\java.exe"
_PROBE_LOCAL = os.path.join(ROOT, "probe-java", "target", "sec-probe.jar")
# 探针源码已内置到本项目 probe-java/：优先用项目内构建产物，未构建时回退外部路径。
PROBE = os.environ.get("SAST_AI_PROBE_JAR", "").strip() or _PROBE_LOCAL
CODE_PATH = (os.environ.get("SAST_AI_SECCODE_DIR", "").strip()
            or os.path.join(ROOT, "..", "java-sec-code"))
APP_NAME = "sec-code"
AGENT_ID = "java-sec-code"
TARGET_URL = "http://127.0.0.1:8080"
DB_PATH = os.environ.get("SAST_AI_DB_PATH", os.path.join(ROOT, "data", "app.db"))
LOG = (os.environ.get("SAST_AI_WATCHDOG_LOG", "").strip()
       or os.path.join(ROOT, "logs", "java-seccode-watchdog.log"))
DETACH = 0x00000200 | 0x00000008  # CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
PORT = 8080
# 单实例哨兵端口（与 launch_stack 的 7811、launch_target_mall 的 7812 成一组）。
SINGLETON_PORT = 7813

# 2026-11-06（jsc 625/626 实测）：默认 application.properties 指向
# jdbc:mysql://localhost:3306/java_sec_code，本机无 MySQL 时 /sqli/jdbc/vuln
# 的 DriverManager.getConnection 抛 SQLException 被 catch 后返回空串 —— 布尔对
# 与时间盲注恒无差异，oracle 只能落 boolean_same，sqli.java 真值点结构性漏报。
# 仓库自带 application-h2.properties（内存 H2 + MySQL 兼容模式 + create_db_h2.sql
# 预置 users 表），其注释明确写着「IAST 动态验证专用：本机无 MySQL / Docker 时用」，
# 且 jar 内已打包 h2-1.4.200.jar。8081 隔离实测：' OR '1'='1 返回两行、
# ' OR '1'='2 返回空，布尔差异立刻可判。故 watchdog 拉起时默认带上该 profile；
# 设 SAST_AI_JSC_H2=0 可回退到原仓库默认行为。
JSC_SPRING_ARGS = (
    ["--spring.profiles.active=h2"]
    if os.environ.get("SAST_AI_JSC_H2", "1").strip().lower()
    not in ("0", "false", "off", "no")
    else []
)

_SINGLETON_SOCK = None


def _acquire_singleton(port):
    """TCP 哨兵端口单实例守卫，避免多个 launch_java_seccode 各拉一个 JVM。

    背景（2026-09-22 实测）：本 launcher 此前**没有**单实例守卫（launch_stack 7811、
    launch_target_mall 7812 都有）。运行时重拉D:\\Python 副本时，两个看门狗会各自
    spawn 一个 java-sec-code：只有一个能绑上 8080，其余启动失败即退出，看门狗再重启，
    形成「多个 JVM 同秒拉起 + 端口抢绑 + 日志互相交错」的风暴。历史上日志里 60 次
    `===== starting java-sec-code =====` 即由此产生，也是 D2 期间被判定
    `target_unavailable` 的诱因之一（与探针死锁是两件独立的事）。

    绑定 127.0.0.1:port 并 listen 作为持锁信号；其余实例 bind 失败即退出。进程退出时
    OS 自动释放端口，无需跨进程存活探测。

    与 launch_target_mall 的差异：这里**不主动杀**占用者——若占用者是旧解释器实例，
    让后起的正确实例退出反而更安全（避免误杀正在跑扫描的进程）。
    """
    global _SINGLETON_SOCK
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        _SINGLETON_SOCK = s
        return True
    except OSError:
        return False



def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def find_jar():
    pat = os.path.join(CODE_PATH, "target", "*.jar")
    cands = [f for f in glob.glob(pat) if not f.endswith(("-sources.jar", "-javadoc.jar"))]
    if not cands:
        return None
    cands.sort(key=lambda f: -os.path.getsize(f))  # 优先最重的 fat jar
    return cands[0]


def resolve_token(logf):
    """经 IastService 注册（workspace 不存在则自动建，session 已存在则保留原 token）。"""
    try:
        sys.path.insert(0, HERE)
        from src.infrastructure.db import Database
        from src.iast.service import IastService
        db = Database(DB_PATH)
        sess = IastService(db).register_session({
            "target_url": TARGET_URL,
            "code_path": CODE_PATH.replace("\\", "/"),
            "app_name": APP_NAME,
            "agent_id": AGENT_ID,
            "probe_mode": "iast",
            "server_port": PORT,
            "workspace_id": None,
            "probe_packages": "org.joychou",
            "java_path": JAVA,
        })
        return sess.get("probe_token"), sess.get("id")
    except Exception as e:
        logf.write(f"[{now()}] register_session 失败：{e}\n")
        return None, None


def main():
    if not _acquire_singleton(SINGLETON_PORT):
        print(f"[{now()}] [singleton] 已有 launch_java_seccode 实例在运行，本实例退出，避免双栈抢 8080 端口", flush=True)
        sys.exit(0)
    logf = open(LOG, "a", buffering=1, encoding="utf-8")
    orig_stdout = sys.stdout
    sys.stdout = logf
    sys.stderr = logf
    while True:
        jar = find_jar()
        if not jar:
            logf.write(f"[{now()}] 未找到 jar，等待构建完成，10s 后重试 =====\n")
            logf.flush()
            time.sleep(10)
            continue
        token, sid = resolve_token(logf)
        if not token:
            logf.write(f"[{now()}] 无可用 probe_token，10s 后重试 =====\n")
            logf.flush()
            time.sleep(10)
            continue
        logf.write(f"[{now()}] ===== starting java-sec-code (8080 + IAST probe, session {sid}, jar {os.path.basename(jar)}) =====\n")
        logf.flush()
        try:
            p = subprocess.Popen(
                [JAVA,
                 # ---- -Xbootclasspath/a:PROBE ----
                 # 2026-09-13 重新定性：本参数解决的是「Spring Boot 2.1.5 的 LaunchedURLClassLoader
                 # 看不到 javaagent 的探针回调类」，与 JVM 版本无关，JDK 11 下同样必需。
                 # 实测(00:56)不带此参数时：agent-start 已成功(143 次 transformed, 0 次
                 # UnsupportedClassVersionError)，但应用 Bean 初始化抛
                 # NoClassDefFoundError: com/rasp/probe/HookRuntime -> jolokiaEndpoint 创建失败
                 # -> 8080 永不监听。
                 # 另注：此前注释把「零插桩」归因于本参数导致的 agent-start 反向不可见，该归因有误。
                 # 真正的零插桩根因是 target/sec-probe-bootstrap.jar 仍是 Java21(major 65) 产物，
                 # 在 JDK11 下 TaintHub 加载失败 -> agent-start failed-open（已重建为 major 55 修复）。
                 "-Xbootclasspath/a:" + PROBE,
                 # ---- --add-opens ----
                 # JDK 11 下 JPMS 非法反射仅为 warning 而非 deny，已确认非必需，保持移除。
                 "-Djdk.httpclient.version=HTTP_1_1",
                 # 必须显式放宽：探针默认 sec.network.timeout.ms=50，本地回环也必然超时，
                 # 导致事件发送失败 -> cbErrorThreshold 打满 -> 熔断器跳闸降级 passthrough
                 # (日志表现为 dropped 50 events after send failure + circuit tripped)。
                 # target-mall 一直带 5000，java-sec-code 此前漏配，是插桩数据稀薄的次因。
                 "-Dsec.network.timeout.ms=5000",
                 "-javaagent:" + PROBE,
                 "-Dsec.server.url=http://127.0.0.1:8000",
                 "-Dsec.agent.id=" + AGENT_ID,
                 "-Dsec.app.name=" + APP_NAME,
                 "-Dsec.agent.token=" + token,
                 "-Dsec.app.packages=org.joychou",
                 "-Dserver.port=8080",
                 "-jar", jar] + JSC_SPRING_ARGS,
                stdout=logf, stderr=subprocess.STDOUT,
                creationflags=DETACH, close_fds=True,
            )
            rc = p.wait()
            logf.write(f"[{now()}] java-sec-code exited code={rc}, restart in 5s =====\n")
        except Exception as e:
            logf.write(f"[{now()}] launch error: {e}\n")
        logf.flush()
        try:
            orig_stdout.write(f"[heartbeat] launch_java_seccode alive @ {now()}\n")
            orig_stdout.flush()
        except Exception:
            pass
        time.sleep(5)


if __name__ == "__main__":
    main()
