"""OWASP Benchmark **全集**（2740 用例）看门狗：Tomcat 9x @ 8444 + HSQLDB 9002 + IAST 探针。

与 launch_owasp.py（sample-200 @ 8443）的关系：同一份代码骨架，三个参数化差异。
之所以另起一个实例而不是把 8443 换成全集：

1. **HSQLDB 必须隔离**。Benchmark 的 DatabaseHelper / HibernateUtil 启动时是
   `DROP TABLE IF EXISTS ...` + CREATE（实测见 benchmark.db.script）。两个实例共用
   一个 9001 服务 + 同一个 benchmarkDataBase，会互相清表重建，跑批中途表结构抖动
   ⇒ 每请求 500 ⇒ IAST 事件恒 0 ⇒ D2 看起来"没证据"，其实是自伤。
   故全集用 9002 / benchmarkDataBaseFull。
2. **agent_id 必须隔离**。两个实例共用 agent_id=owasp-benchmark-sample 会让事件
   无法归到任务上（correlation 按 agent_id + app_name 归属）。全集用
   owasp-benchmark-full，对应 workspace 7。
3. **保留 sample-200 实例**。205 用例的小靶场跑单片冒烟只要 1~2 分钟，是 D2 链路的
   快速验证通道；全集 2740 端点冷启动慢，不适合做冒烟。

JDK：必须 JDK11。旧 catalina 日志 java.library.path 实证为 JDK11；用 JDK21 会让插桩类
（java.base / jakarta.servlet）在强封装下解析失败、报 NoClassDefFoundError(HookRuntime)、
report-sink NPE，最终表现为 iast_events 恒 0。

探针挂载与 launch_owasp.py 相同：-Xbootclasspath/a + -javaagent 双挂，
-Djdk.httpclient.version=HTTP_1_1（JDK HttpClient 对 http:// 默认升级 h2c 致 uvicorn 422），
-Dsec.server.url=http://127.0.0.1:8000（后端只绑 127.0.0.1，localhost 可能解析 ::1）。

日志：owasp-full-watchdog.log（与 sample-200 的 owasp-watchdog.log 分开，便于对照）。
"""
import os
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # 项目根（本脚本在 scripts/launch/ 下）
JAVA_HOME = r"C:\Program Files\Java\jdk-11"
# HSQLDB 用 JDK21 起（独立 DB 服务，与 Tomcat 的 JDK 版本无关；同 run_hsqldb.bat）。
HSQLDB_JAVA = (os.environ.get("SAST_AI_HSQLDB_JAVA", "").strip()
               or os.path.join(JAVA_HOME, "bin", "java.exe"))
_PROBE_LOCAL = os.path.join(ROOT, "probe-java", "target", "sec-probe.jar")
PROBE = os.environ.get("SAST_AI_PROBE_JAR", "").strip() or _PROBE_LOCAL

BENCH_ROOT = (os.environ.get("SAST_AI_OWASP_FULL_DIR", "").strip()
             or os.path.join(ROOT, "..", "owasp-code", "BenchmarkJava-master"))
TOMCAT = os.path.join(BENCH_ROOT, "target", "tomcat9x")
BIN = os.path.join(TOMCAT, "bin")
APP_NAME = "benchmark"
AGENT_ID = "owasp-benchmark-full"
TARGET_URL = "http://127.0.0.1:8444/benchmark"
TARGET_PORT = 8444  # 与 TARGET_URL 同源；供 _wait_and_post_setup 轮询端口用
CODE_PATH = BENCH_ROOT
HSQLDB_PORT = 9002
HSQLDB_DBNAME = "benchmarkDataBaseFull"
LDAP_PORT = 10389
DB_PATH = os.environ.get("SAST_AI_DB_PATH", os.path.join(ROOT, "data", "app.db"))
LOG = os.path.join(ROOT, "logs", "owasp-full-watchdog.log")
os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

# CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW：脱离运行时作业、常驻、不弹窗。
DETACH = 0x00000200 | 0x08000000


def bench_classpath():
    """解析 Benchmark 运行期 classes / lib 的真实路径。

    旧代码硬编码 `target/benchmark/WEB-INF/classes`，但该目录在解包布局下不存在
    （只有同级的 lib 存在），导致 2026-11-09 发车时 StartLdap 抛
    NoClassDefFoundError: org/owasp/benchmark/helpers/LDAPServer —— LDAPServer.class
    实际在 target/classes 或 tomcat9x 已解包的 WEB-INF/classes 里。HSQLDB 之所以没
    暴露，是因为 org.hsqldb.Server 在 lib 的 jar 中，与 classes 无关。
    这里按真实存在的目录择优，避免 mvn clean / 解包后目录形态变化再次踩坑。
    """
    classes_cands = [
        os.path.join(BENCH_ROOT, "target", "classes"),
        os.path.join(TOMCAT, "webapps", APP_NAME, "WEB-INF", "classes"),
        os.path.join(BENCH_ROOT, "target", "benchmark", "WEB-INF", "classes"),
    ]
    classes = next((p for p in classes_cands if os.path.isdir(p)), classes_cands[0])
    lib_cands = [
        os.path.join(BENCH_ROOT, "target", "benchmark", "WEB-INF", "lib"),
        os.path.join(TOMCAT, "webapps", APP_NAME, "WEB-INF", "lib"),
    ]
    lib = next((p for p in lib_cands if os.path.isdir(p)), lib_cands[0])
    return classes, os.path.join(lib, "*")


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

    与 launch_owasp.py 同理：target_path 会被 L1 盲化切换改写，反推 workspace
    是 token 不对齐的隐性来源。这里用显式 workspace_id（默认 7，与
    tools/owasp_run_shards.py / config/run_profiles.yaml 的 owasp-full 一致）。
    """
    from src.iast.probe_token import ProbeTokenError, resolve

    wid = int(os.environ.get("SAST_AI_OWASP_WORKSPACE_ID", "7"))
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
    # 2026-10-12（r82 实证）：**关闭探针熔断**，否则 D1 批量重放必然被熔断吃掉。
    # 现象：同一批 spec，慢速重放（4s 间隔）3 条 → 7 条事件；快速重放（0.3s 间隔）
    # 20 条 → **0 条**事件。任务内 107 条连续重放只留下 1~2 条到达，
    # 101 条判 no-arrival，且其 canary 身份段在全库 24 万条事件里一条都查不到
    # （证明不是事件迟到/归属失败，是探针压根没上报）。
    # 机制：CircuitBreaker 在 CPU≥90% 或事件队列占用≥90% 时 tripped，
    # 最短跳闸 10s（sec.circuit.min.trip.ms）+ 恢复需连续 3 次健康采样 ⇒
    # 一旦跳闸，D1 那几十秒内跑完的上百次重放全部落在静默窗口里。
    # 熔断是为保护生产业务设计的；这里是本地一次性靶场、负载可控，不需要保护。
    # 同时把队列/CPU 水线一并抬高做双保险（即使将来重新打开也不会立刻咬人）。
    return (
        # 2026-10-18 内存治理：此前完全没有显式堆参数，JVM 默认最大堆=物理内存 1/4（本机 32G → 8G），
        # metaspace 无上限。探针 ByteBuddy 织入 2900+ 个类，metaspace/native 持续增长，最终
        # 出现 `Native memory allocation (mmap) failed ... G1 virtual space`（hs_err 18 份实证）。
        # 显式收紧到靶场实际所需：堆 3G（2740 servlet + 探针足够）、metaspace 768M、线程栈 512K，
        # 让内存超限表现为可预测的 Java OOM 而不是原生 mmap 失败。
        # 2026-10-19：-Xms 从 1g 降到 256m。原因：同机跑着 VMware（实测占用 7.8G），
        # 物理内存只剩 ~6.8G 可用时，JVM 启动即 commit 1G 触发
        # `Native memory allocation (mmap) failed to map 1073741824 bytes` → Catalina
        # 每 5s 崩溃重启（watchdog 死循环）。初始堆小、上限不变，缺内存时由 GC 自己扛，
        # 至少能起来；彻底解法是让出那 7.8G（关掉/挂起 VMware）。
        f"-Xms256m -Xmx3g -XX:MaxMetaspaceSize=768m -Xss512k "
        f"-XX:+UseG1GC -XX:MaxGCPauseMillis=200 "
        f"-Xbootclasspath/a:{PROBE} "
        f"-javaagent:{PROBE} "
        f"-Djdk.httpclient.version=HTTP_1_1 "
        f"-Dsec.network.timeout.ms=5000 "
        f"-Dsec.event.queue.size=8192 "
        f"-Dsec.event.flush.batch=2048 "
        f"-Dsec.circuit.enabled=false "
        f"-Dsec.circuit.cpu.threshold.percent=99 "
        f"-Dsec.circuit.queue.threshold.percent=99 "
        f"-Dsec.circuit.min.trip.ms=1000 "
        f"-Dsec.circuit.recover.samples=1 "
        f"-Dsec.server.url=http://127.0.0.1:8000 "
        f"-Dsec.agent.id={AGENT_ID} "
        f"-Dsec.app.name={APP_NAME} "
        f"-Dsec.agent.token={token} "
        f"-Dsec.app.packages=org.owasp.benchmark"
    )


def _port_listening(port: int) -> bool:
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                             errors="replace", timeout=15).stdout
    except Exception:
        return False
    return any(f":{port}" in ln and "LISTENING" in ln for ln in out.splitlines())


def _hsqldb_listening() -> bool:
    return _port_listening(HSQLDB_PORT)


def ensure_hsqldb(logf) -> bool:
    """幂等拉起全集实例自己的 HSQLDB（9002 / benchmarkDataBaseFull），**并等到真能连**。

    端口与库名都与 sample-200 的 9001/benchmarkDataBase 隔离，理由见模块 docstring。

    2026-10-06 两个实测坑（都是「进程起了但服务没好」型）：
      (1) `--dbname.0=xxx` / `--port.0=xxx` 的等号形式会让 HSQLDB 启动即失败：
          HsqlException: no valid database paths: malformed database enumerator:
          server.dbname.0=benchmarkDataBaseFull
          而且 `--port.0 N` 也不行（unsupported property: server.port.0），
          正确的是 `--port N`。等号形式被原样当成属性名，进程秒退、端口永不监听。
      (2) **光"发出启动命令"就返回是不够的**。Benchmark 的 DataBaseFilter 在 servlet
          初始化时抓 DataSource 并缓存；若那一刻 HSQLDB 还没起来，它拿到 null 并永久
          NPE（实测 DataBaseFilter.doFilter:44 NullPointerException ⇒ 每请求 500），
          之后 HSQLDB 起来了也不会自愈。表现为"探针没插到 / D2 全 no_evidence"。
      所以这里必须轮询到端口真在监听，才允许启动 Tomcat。
    """
    if _hsqldb_listening():
        logf.write(f"[{now()}] HSQLDB({HSQLDB_PORT}) 已 LISTENING，跳过\n")
        logf.flush()
        return True
    db_dir = os.path.join(BENCH_ROOT, "target", "db")
    os.makedirs(db_dir, exist_ok=True)
    logf.write(f"[{now()}] HSQLDB({HSQLDB_PORT}) 未监听，启动中 dbname={HSQLDB_DBNAME} =====\n")
    logf.flush()
    env = os.environ.copy()
    env["JAVA_HOME"] = os.path.dirname(os.path.dirname(HSQLDB_JAVA))
    classes, lib = bench_classpath()
    cp = f"{classes};{lib}"
    try:
        # 空格分隔，不能用等号（见 docstring 坑 1）；端口是 --port，不是 --port.0。
        subprocess.Popen(
            [HSQLDB_JAVA, "-cp", cp, "org.hsqldb.Server",
             "--database.0", f"file:{db_dir}/benchmark-full.db",
             "--dbname.0", HSQLDB_DBNAME,
             "--port", str(HSQLDB_PORT)],
            cwd=BENCH_ROOT,
            env=env,
            stdout=logf, stderr=subprocess.STDOUT,
            creationflags=DETACH, close_fds=True,
        )
        logf.write(f"[{now()}] HSQLDB detached 启动命令已发出（db={db_dir}, port={HSQLDB_PORT}）\n")
    except Exception as e:
        logf.write(f"[{now()}] HSQLDB 启动失败：{e}\n")
    logf.flush()

    # 轮询到端口真在监听才返回（见 docstring 坑 2：DataBaseFilter 缓存 null DataSource
    # ⇒ 永久 500，HSQLDB 后起来也不自愈）。给 60s，HSQLDB 冷启实测 ~2s。
    for i in range(60):
        if _hsqldb_listening():
            logf.write(f"[{now()}] HSQLDB({HSQLDB_PORT}) 就绪（等待 {i}s）\n")
            logf.flush()
            return True
        time.sleep(1)
    logf.write(f"[{now()}] HSQLDB({HSQLDB_PORT}) 等待 60s 仍未监听，放弃启动 Tomcat\n")
    logf.flush()
    return False


def ensure_ldap(logf) -> bool:
    """幂等拉起 Benchmark 内嵌 ApacheDS LDAP（10389）。

    背景（2026-10-15 实测）：ldapi 族的 servlet 连 `ldap://localhost:10389`（LDAPManager），
    该服务默认没人起 → servlet 抛 `javax.naming.CommunicationException: localhost:10389
    Connection refused`（HTTP 500）→ canary 0 事件 → ldapi 族 0 召回（mini r97 实测 0/4）。
    ApacheDS 的 jar 已在 `WEB-INF/lib`，`LDAPServer` 构造器会 `init()` 起服务并 seed 3 个
    测试用户（foo / Ms Bar / Mr Unknown）；我们只需一个 main 把它拉起来常驻。

    启动器 `tools/ldap/StartLdap.java`（首次使用时由本函数用 JDK11 编译）。
    轮询到 10389 真在监听才返回，避免 servlet 在 LDAP 未就绪时抢连失败。
    """
    if _port_listening(LDAP_PORT):
        logf.write(f"[{now()}] LDAP({LDAP_PORT}) 已 LISTENING，跳过\n")
        logf.flush()
        return True
    launcher_dir = os.path.join(ROOT, "tools", "ldap")
    classes, lib = bench_classpath()
    cp = f"{launcher_dir};{classes};{lib}"
    class_file = os.path.join(launcher_dir, "StartLdap.class")
    if not os.path.isfile(class_file):
        # 分发面只带 .java（*.class 不进仓库），首次使用时编译一次。
        envc = os.environ.copy()
        envc["JAVA_HOME"] = JAVA_HOME
        try:
            proc = subprocess.run(
                [os.path.join(JAVA_HOME, "bin", "javac.exe"), "-cp", f"{classes};{lib}",
                 "-d", launcher_dir, os.path.join(launcher_dir, "StartLdap.java")],
                cwd=launcher_dir, env=envc, capture_output=True, text=True, timeout=120,
            )
            ok = proc.returncode == 0 and os.path.isfile(class_file)
        except Exception as e:  # noqa: BLE001
            logf.write(f"[{now()}] StartLdap 编译异常：{e}\n")
            logf.flush()
            return False
        if not ok:
            logf.write(f"[{now()}] StartLdap 编译失败：{(proc.stderr or '')[:400]}\n")
            logf.flush()
            return False
    env = os.environ.copy()
    env["JAVA_HOME"] = JAVA_HOME
    logf.write(f"[{now()}] LDAP({LDAP_PORT}) 未监听，启动中（StartLdap）=====\n")
    logf.flush()
    try:
        subprocess.Popen(
            [os.path.join(JAVA_HOME, "bin", "java.exe"), "-cp", cp, "StartLdap"],
            cwd=launcher_dir, env=env,
            stdout=logf, stderr=subprocess.STDOUT,
            creationflags=DETACH, close_fds=True,
        )
    except Exception as e:
        logf.write(f"[{now()}] LDAP 启动失败：{e}\n")
        logf.flush()
        return False
    for i in range(60):
        if _port_listening(LDAP_PORT):
            logf.write(f"[{now()}] LDAP({LDAP_PORT}) 就绪（等待 {i}s）\n")
            logf.flush()
            return True
        time.sleep(1)
    logf.write(f"[{now()}] LDAP({LDAP_PORT}) 等待 60s 仍未监听\n")
    logf.flush()
    return False


# webapp 的 Spring dataSource（WEB-INF/classes/context.xml）默认指向 sample-200 的
# 9001/benchmarkDataBase，而全集靶场用 9002/benchmarkDataBaseFull（隔离，见模块 docstring）。
# 不 patch 的话 JDBCtemplate 用例（如 sqli BenchmarkTest00596 的 queryForList）拿不到连接
# （Connection refused）→ 恒 500、永远无法确认。这里在起 Tomcat 前把 dataSource URL 对齐到
# 本实例自己的库（幂等：已对齐则跳过）。
_WEBAPP_CTX = os.path.join(TOMCAT, "webapps", APP_NAME, "WEB-INF", "classes", "context.xml")
_DS_URL_SAMPLE = "jdbc:hsqldb:hsql://localhost/benchmarkDataBase;"
_DS_URL_SELF = f"jdbc:hsqldb:hsql://localhost:{HSQLDB_PORT}/{HSQLDB_DBNAME};"


def ensure_webapp_datasource(logf) -> bool:
    """把 webapp 的 Spring dataSource 对齐到本实例的 HSQLDB（幂等）。返回是否已对齐。"""
    try:
        if not os.path.isfile(_WEBAPP_CTX):
            logf.write(f"[{now()}] context.xml 不存在，跳过 datasource patch：{_WEBAPP_CTX}\n")
            logf.flush()
            return False
        with open(_WEBAPP_CTX, encoding="utf-8") as f:
            txt = f.read()
        if _DS_URL_SELF in txt:
            return True
        if _DS_URL_SAMPLE not in txt:
            logf.write(f"[{now()}] context.xml 未含预期 sample dataSource URL，未 patch\n")
            logf.flush()
            return False
        with open(_WEBAPP_CTX, "w", encoding="utf-8") as f:
            f.write(txt.replace(_DS_URL_SAMPLE, _DS_URL_SELF))
        logf.write(f"[{now()}] 已 patch webapp dataSource → {_DS_URL_SELF}\n")
        logf.flush()
        return True
    except Exception as e:
        logf.write(f"[{now()}] datasource patch 失败：{e}\n")
        logf.flush()
        return False


def ensure_webapp_integrity(logf, post_deploy: bool = False) -> None:
    """修复 webapp 关键文件 + 创建 oracle 专用签名文件（2026-10-26）。

    为什么需要：
    1. `WEB-INF/web.xml` 会被**我们自己的**路径穿越探测写坏。Benchmark 的 pathtraver 族有
       写入型用例（BenchmarkTest00002 用 `new FileOutputStream(fileName, false)`，默认截断），
       oracle 早期拿 `webapps/benchmark/WEB-INF/web.xml` 当签名文件 ⇒ 探测即清零，
       下次重启 `SAXParseException: Premature end of file`，Context[/benchmark] 起不来。
       （run 471 实测：23:43 被清零，整轮跑完后靶场再也起不来。）
    2. 创建 `TOMCAT/oracle-sig.txt`（webapp 之外、**不设只读**）：探测能读到签名，
       写入型 sink 即使打穿，坏的也只是这个签名文件，不碰靶场任何文件。
       （曾放 WEB-INF 下并置只读，结果阻塞 Tomcat 重解包，见下方部署后注释。）

    关键时序（2026-10-26 二次踩坑）：`server.xml` 是 `unpackWARs="true" autoDeploy="true"`，
    Tomcat **每次启动都会重解包 war**（实测 139 秒），会把解包目录里非 war 的文件全部清掉。
    所以签名文件**必须在部署完成之后**创建 —— 这就是 post_deploy 参数的作用。
    同理，war-tracker 也要在部署后写正确值，否则下次启动又要重解包。
    """
    webapp = os.path.join(TOMCAT, "webapps", APP_NAME)
    webxml = os.path.join(webapp, "WEB-INF", "web.xml")
    war = os.path.join(TOMCAT, "webapps", APP_NAME + ".war")
    if not post_deploy:
        # 启动前只做 web.xml 修复（解包会覆盖它，但保留这一步以防 war 缺失时救急）。
        # 2026-10-26 三次踩坑：docBase 不存在/只剩骨架时**绝不能** makedirs 创建
        # WEB-INF/web.xml —— 那会造出一个"看起来合法"的不完整 docBase，Tomcat
        # deployWAR 就地部署它而**不再重解包 war** ⇒ classes 缺失 ⇒
        # ClassNotFoundException DataBaseFilter ⇒ Context 起不来。
        # 所以仅当 docBase 已完整解包（classes/org 存在）才修复 web.xml；
        # 目录缺失时什么都别做，让 Tomcat 自己解包（解包自带 web.xml）。
        try:
            fully_exploded = os.path.isdir(
                os.path.join(webapp, "WEB-INF", "classes", "org"))
            need_fix = (fully_exploded
                        and ((not os.path.isfile(webxml))
                             or os.path.getsize(webxml) == 0))
            if need_fix and os.path.isfile(war):
                import zipfile
                with zipfile.ZipFile(war) as z:
                    data = z.read("WEB-INF/web.xml")
                os.makedirs(os.path.dirname(webxml), exist_ok=True)
                with open(webxml, "wb") as fh:
                    fh.write(data)
                logf.write(f"[{now()}] web.xml 缺失/被截断，已从 war 恢复（{len(data)} 字节）\n")
                logf.flush()
        except Exception as e:  # noqa: BLE001
            logf.write(f"[{now()}] web.xml 修复失败：{e}\n")
            logf.flush()
        return

    # ── 部署后：签名文件 + war-tracker ──
    # 2026-10-26（二次修正）：签名文件放 **webapp 之外**（TOMCAT 根），且**不设只读**。
    # 上一版放在 WEB-INF/ 下并 chmod 只读，后果是 Tomcat 重解包时
    # `ExpandWar.deleteDir` 删不掉 WEB-INF（Windows 只读文件 File.delete() 失败）
    # ⇒ `ContextConfig.beforeStart 上下文[/benchmark] 的异常修复 docBase` ⇒ 上下文起不来。
    # 放到 webapps 同级目录后：重解包不碰它，也不需要只读。
    # 路径与 response_oracle._PATH_CANDIDATES 的 "../../oracle-sig.txt" 对应。
    try:
        sig = os.path.join(TOMCAT, "oracle-sig.txt")
        marker = "SAST_ORACLE_SIG_V1\n"
        need = True
        if os.path.isfile(sig):
            try:
                with open(sig, encoding="utf-8") as fh:
                    need = marker not in fh.read(200)
            except Exception:
                need = True
        if need:
            with open(sig, "w", encoding="utf-8") as fh:
                fh.write(marker)
            logf.write(f"[{now()}] 已创建 oracle 签名文件（webapp 外、非只读）：{sig}\n")
            logf.flush()
    except Exception as e:  # noqa: BLE001
        logf.write(f"[{now()}] oracle 签名文件创建失败：{e}\n")
        logf.flush()

    # war-tracker 写对，避免下次启动又重解包（139s）
    try:
        tracker = os.path.join(webapp, "META-INF", "war-tracker")
        if os.path.isfile(war):
            mt = int(os.path.getmtime(war) * 1000)
            os.makedirs(os.path.dirname(tracker), exist_ok=True)
            with open(tracker, "w", encoding="utf-8") as fh:
                fh.write(str(mt))
            # 2026-10-26 关键：Tomcat 判定"是否需要重解包"看的是 tracker **文件的
            # mtime** 是否等于 war 的 mtime（内容只是参考）。open() 重写文件会把
            # mtime 刷成当前时间 ⇒ 下次启动 tracker 必不匹配 ⇒ 又删目录重解包
            # ⇒ 与残留进程互相踩踏（11:23 实测 classes 被清空成 0）。必须回设 mtime。
            os.utime(tracker, (mt / 1000, mt / 1000))
            logf.write(f"[{now()}] war-tracker 已写入 {mt}（下次启动跳过重解包）\n")
            logf.flush()
    except Exception as e:  # noqa: BLE001
        logf.write(f"[{now()}] war-tracker 写入失败：{e}\n")
        logf.flush()


def _wait_and_post_setup(logf, timeout: float = 240.0) -> None:
    """等 Tomcat 部署真正完成（/benchmark 返回 200）后再做后置修复。

    2026-10-26 三次踩坑：只看端口监听不够 —— NIO 连接器在 init 阶段就 bind 8444
    （catalina 日志 16:40:03.833 初始化协议处理器），而 webapp 解包/部署在它之后
    才进行（16:40:04.4 deployWAR → 16:40:14 ExpandWar 收尾）。旧逻辑「端口通 +3s
    就写 tracker」恰好在 Tomcat 重解包进行中抢跑了 META-INF/war-tracker 的创建，
    Tomcat ExpandWar.java:169 再建同一文件 ⇒ FileAlreadyExists ⇒ fixDocBase 失败
    ⇒ Context[/benchmark] 起不来 ⇒ autoDeploy 反复删目录 ⇒ 死态（webapps/benchmark
    被删成不存在）。改为：先等端口，再等 /benchmark 真正 200 才写签名/tracker；
    一直起不来就 kill 掉 Tomcat 让看门狗主循环干净重启（此时目录已无，重解包无人竞态）。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_listening(TARGET_PORT):
            break
        time.sleep(2)
    else:
        logf.write(f"[{now()}] 等待 8444 超时（{timeout}s），跳过后置修复\n")
        logf.flush()
        return
    import urllib.request
    webapp_classes = os.path.join(TOMCAT, "webapps", APP_NAME, "WEB-INF", "classes")
    # 第二段：等上下文真正可用。三连稳态（两次轮询类文件数不变）避开解包中段；
    # Tomcat 自己解包成功后才会创建 tracker，我们只在 200 之后动手 ⇒ 无竞态。
    ready_deadline = time.time() + 420.0
    stable = 0
    last_n = -1
    while time.time() < ready_deadline:
        try:
            n = sum(len(fs) for _, _, fs in os.walk(webapp_classes)) \
                if os.path.isdir(webapp_classes) else 0
        except Exception:  # noqa: BLE001
            n = 0
        if n > 0 and n == last_n:
            stable += 1
        else:
            stable = 0
        last_n = n
        if stable >= 2:
            try:
                with urllib.request.urlopen(TARGET_URL, timeout=10) as resp:
                    if resp.status == 200:
                        ensure_webapp_integrity(logf, post_deploy=True)
                        return
            except Exception:  # noqa: BLE001
                pass
        time.sleep(5)
    # 一直 200 不了：上下文八成进了自愈不了的坏状态，杀掉让主循环重启
    logf.write(f"[{now()}] /benchmark 420s 未就绪，kill Tomcat 让看门狗干净重启\n")
    logf.flush()
    _kill_tomcat_by_port(logf)


def _kill_tomcat_by_port(logf) -> None:
    """按监听 8444 的 PID 杀 Tomcat（taskkill，无 WMIC/schtasks 依赖）。"""
    try:
        out = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=30
        ).stdout
        pids = set()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[1].endswith(":8444") and parts[3] == "LISTENING":
                pids.add(parts[4])
        for pid in pids:
            subprocess.run(["taskkill", "/F", "/T", "/PID", pid],
                           capture_output=True, timeout=30)
            logf.write(f"[{now()}] 已 kill Tomcat pid={pid}（8444 监听者）\n")
        logf.flush()
    except Exception as e:  # noqa: BLE001
        logf.write(f"[{now()}] kill Tomcat 失败：{e}\n")
        logf.flush()


def main():
    logf = open(LOG, "a", buffering=1)
    sys.stdout = logf
    sys.stderr = logf
    while True:
        if not ensure_hsqldb(logf):
            # 故意不启 Tomcat：DataBaseFilter 会在 servlet 初始化时缓存 DataSource，
            # 拿不到就是永久 NPE（每请求 500），事后补 HSQLDB 也救不回来。
            time.sleep(10)
            continue
        # webapp 的 Spring dataSource 对齐到本实例的库（2026-10-17）：见 ensure_webapp_datasource。
        ensure_webapp_datasource(logf)
        # 2026-10-26：修复被探测写坏的 web.xml + 创建 oracle 专用签名文件（只读）。
        ensure_webapp_integrity(logf)
        # LDAP 不阻塞 Tomcat（ldapi 只影响该族；未就绪则 ldapi servlet 500，其余族不受影响），
        # 但必须在 Tomcat 起来前尽力拉起，否则 ldapi 全族 0 召回。
        ensure_ldap(logf)
        token = resolve_token(logf)
        if not token:
            # token 是探针注册会话时颁发的，不是配置项。这里拿不到只有一个原因：
            # workspace 7 下还没有 agent_id=owasp-benchmark-full 的会话。
            # 用 tools/register_full_target_session.py 登记一次即可，不要写死 token。
            logf.write(
                f"[{now()}] 无可用 probe_token（workspace 7 / agent_id={AGENT_ID}）。\n"
                f"          先跑：.venv\\Scripts\\python.exe tools\\register_full_target_session.py\n"
                f"          10s 后重试 =====\n"
            )
            logf.flush()
            time.sleep(10)
            continue
        logf.write(
            f"[{now()}] ===== starting OWASP benchmark FULL (8444 + 9002 + IAST probe, JDK11) =====\n"
        )
        logf.flush()
        env = os.environ.copy()
        env["JAVA_HOME"] = JAVA_HOME
        env["CATALINA_OPTS"] = build_catalina_opts(token)
        env["CATALINA_HOME"] = TOMCAT
        env["CATALINA_BASE"] = TOMCAT
        # 2026-10-29：datasource patch 接线。此前 ensure_webapp_datasource **只有定义、
        # 从未被调用**（死代码），导致 webapp 一直用 sample-200 的 9001 URL
        # （jdbc:hsqldb:hsql://localhost/benchmarkDataBase）而全集库在 9002/benchmarkDataBaseFull
        # ⇒ 走 Spring JDBCtemplate 的用例恒 500（Connection refused）⇒ canary 到不了 sink
        # ⇒ sqli 召回长期卡在 55~75%。这是本轮定位到的**环境级根因**。
        # 注意：war 才是真正源头（server.xml unpackWARs=true，Tomcat 每次启动重解包会覆盖
        # 解包目录），已同步修正 webapps/benchmark.war 内的 context.xml；此处做启动前兜底，
        # 覆盖「war 被 mvn 重新打包回 sample URL」的场景。
        ensure_webapp_datasource(logf)
        try:
            p = subprocess.Popen(
                [os.path.join(BIN, "catalina.bat"), "run"],
                cwd=BIN,
                env=env,
                stdout=logf, stderr=subprocess.STDOUT,
                creationflags=DETACH, close_fds=True,
            )
            # 2026-10-26：等端口起来后再做后置修复（签名文件必须等 unpackWARs 解包完成，
            # 否则会被重解包清掉）。放到后台线程，不阻塞下面的 p.wait()。
            try:
                import threading
                threading.Thread(target=_wait_and_post_setup, args=(logf,),
                                 daemon=True).start()
            except Exception as _pe:  # noqa: BLE001
                logf.write(f"[{now()}] 后置修复线程启动失败：{_pe}\n")
                logf.flush()
            rc = p.wait()
            logf.write(f"[{now()}] OWASP-full catalina exited code={rc}, restart in 5s =====\n")
        except Exception as e:
            logf.write(f"[{now()}] launch error: {e}\n")
        logf.flush()
        time.sleep(5)


if __name__ == "__main__":
    main()
