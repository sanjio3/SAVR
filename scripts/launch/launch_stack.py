"""SAVR 统一进程看门狗（栈管理器）。

职责：
- 监控 3 个核心进程：后端(8000) / java-quote+IAST 探针(8899) / 前端 vite(5200)
- 端口未监听即按正确命令拉起，退出即 5s 后自动重启（自愈），不再"偷偷死掉"
- 每 5s 把进程状态写入 stack_status.json，供 /api/system/processes 读取并展示到前端
- 幂等：端口已监听则"收养"现有进程（不重复拉起，不破坏已有会话）

用法：python launch_stack.py   （建议通过 run_in_background 受管任务常驻）
"""
import subprocess
import time
import sys
import os
import json
import shutil
import socket

# 运行时路径 / token 一律走环境变量，未配置时用相对仓库根的可移植默认值。
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 项目根
_VENV_BIN = "Scripts" if os.name == "nt" else "bin"
_VENV_EXE = "python.exe" if os.name == "nt" else "python"
VENV_PY = os.environ.get("SAST_AI_VENV_PY",
                         os.path.join(ROOT, ".venv", _VENV_BIN, _VENV_EXE))
FRONTEND = os.environ.get("SAST_AI_FRONTEND_DIR", os.path.join(ROOT, "frontend"))
# 托管运行时的 node 版本目录名带构建号，会随运行时升级变化，因此运行时解析：
# 扫 versions/* 取版本号最大的 node.exe，扫不到再退 PATH 上的 node。
# 可用 SAST_AI_NODE_VERSIONS_DIR 覆盖候选目录。
_NODE_VERSIONS = os.environ.get(
    "SAST_AI_NODE_VERSIONS_DIR",
    os.path.join(os.path.expanduser("~"), ".workbuddy", "binaries", "node", "versions"))


def _resolve_node() -> str:
    try:
        import glob as _glob
        cands = sorted(_glob.glob(os.path.join(_NODE_VERSIONS, "*", "node.exe")))
        if cands:
            return cands[-1]
    except Exception:
        pass
    for name in ("node.exe", "node"):
        found = shutil.which(name)
        if found:
            return found
    return "node.exe"  # 交由 spawn 报错，至少能在日志里看到明确的 FileNotFoundError


NODE = _resolve_node()
JAVA = os.environ.get("SAST_AI_JAVA", shutil.which("java") or "java")
PROBE = os.environ.get("SAST_AI_PROBE_JAR",
                       os.path.join(ROOT, "probe-java", "target", "sec-probe.jar"))
# 靶场 jar 不随仓库分发，必须由部署方显式提供；留空时 java_quote 只监控不启动。
JAR = os.environ.get("SAST_AI_JAVA_QUOTE_JAR", "")
# 探针 token 必须与后端 iast_sessions 注册值一致。绝不提供仓库内置默认值：
# 固定 token 既是安全漏洞，也会在全新部署里静默产生「HTTP 200 但 accepted=0」。
TOKEN = os.environ.get("SAST_AI_PROBE_TOKEN", "")
STATUS_FILE = os.path.join(ROOT, "stack_status.json")
# ysoserial 必须在 JDK8 下生成（JDK9+ 的 JPMS 会挡掉它的反射 gadget 构造）。
# 后端 spawn 时把 YSO_JAVA_HOME 注入后端环境，确保 payload_forge 真正用上 JDK8，
# 不受启动管理器的 shell 环境（可能仍是 JDK24）影响。
JDK8_HOME = os.environ.get("SAST_AI_JDK8_HOME", "")
# 同 launch_target_mall.py：默认 CREATE_NO_WINDOW (0x08000000) 不弹窗，
# SASTAI_SHOW_WINDOW=1 才用 DETACHED_PROCESS (0x8)。两者互斥。
# 同 Job 内被 spawn 的后端与 scan_task_runner 子进程会**一起被杀**
#  两小时的 D2 进度全丢，reconcile 随后把 100/102/103/104/105 全判 failed）。
# 「用户手动重启看门狗」是既定工作流，后端与在跑任务必须能扛住这件事。
DETACH = 0x00000200 | (0x00000008 if os.environ.get("SASTAI_SHOW_WINDOW") else 0x08000000) | 0x01000000
MANAGER_LOG = os.path.join(ROOT, "stack-manager.log")
# 启动宽限期：子进程已 spawn 但端口尚未监听时，在该时间内只等待、不杀、不重建。
# 根因：uvicorn 冷启动约 8s，而看门狗 5s 轮询；启动窗口内"子进程存活但端口
# 未监听"被误判为僵尸并立即杀死，导致每 ~8s 重启一次（restarts 飙到 59，后端永不稳，
# 全量扫描必失败）。宽限期须 > 冷启动时间，给 worker 足够时间完成 bind。
BOOT_GRACE = 30

PROC_DEFS = {
    "backend": {
        "port": 8000,
        "label": "后端 API (FastAPI/uvicorn)",
        "managed": True,
        "cmd": [VENV_PY, "-m", "src.cli.service_server"],
        "cwd": ROOT,
        "log": os.path.join(ROOT, "stack-backend.log"),
    },
    "java_quote": {
        "port": 8899,
        "label": "java-quote 靶机 + IAST 探针",
        "managed": False,  # 已有专用看门狗(launch_java_quote.py)，本管理器只监控不重启
        "cmd": [
            JAVA, "-Djdk.httpclient.version=HTTP_1_1", "-Dsec.network.timeout.ms=5000",
            "-javaagent:" + PROBE,
            "-Dsec.server.url=http://127.0.0.1:8000",
            "-Dsec.agent.id=java-quote", "-Dsec.app.name=java",
            "-Dsec.agent.token=" + TOKEN, "-Dsec.app.packages=com.quote",
            "-Dserver.port=8899", "-jar", JAR,
        ],
        "cwd": None,
        "log": os.path.join(ROOT, "stack-javaquote.log"),
    },
    "frontend": {
        "port": 5200,
        "label": "前端 vite dev server",
        "managed": True,
        # --host 单独出现表示监听所有地址（让 vite.config.ts 的 server.host 生效）；
        # 此前硬编码 --host 0.0.0.0 会强制 IPv4，导致 Edge 解析 localhost 到 IPv6 时拒绝连接。
        "cmd": [NODE, "node_modules/vite/bin/vite.js", "--host", "--port", "5200"],
        "cwd": FRONTEND,
        "log": os.path.join(ROOT, "stack-frontend.log"),
    },
}


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def manager_log(message):
    """写管理器自己的运行日志，记录每次重启、收养、异常的原因，便于排查"进程怎么老崩"。"""
    try:
        with open(MANAGER_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{now()}] {message}\n")
            f.flush()
    except Exception:
        pass


def port_listening(port):
    for host in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            continue
    return False


def pid_on_port(port):
    try:
        proc = subprocess.run(
            ["netstat", "-ano"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10,
        )
        out = proc.stdout
    except Exception:
        return None
    if not out:
        return None
    text = out.decode("gbk", "replace")
    needle = ":" + str(port) + " "
    for line in text.splitlines():
        if needle in line and "LISTENING" in line:
            parts = line.split()
            for p in parts:
                if p.isdigit():
                    return int(p)
    return None


def spawn(defn, env=None):
    logf = open(defn["log"], "a", buffering=1, encoding="utf-8")
    logf.write(f"[{now()}] ===== launching {defn['label']} =====\n")
    logf.flush()
    try:
        p = subprocess.Popen(
            defn["cmd"], cwd=defn["cwd"],
            stdout=logf, stderr=subprocess.STDOUT,
            creationflags=DETACH, close_fds=True, env=env,
        )
        return p
    except Exception as e:
        logf.write(f"[{now()}] launch error: {e}\n")
        logf.flush()
        return None
    finally:
        logf.close()


def _backend_env():
    """后端环境：注入 YSO_JAVA_HOME（默认指向 JDK8），让 ysoserial 走 JDK8；
    并注入 NO_PROXY，使后端对 127.0.0.1/localhost 的调用绕过环境代理。

    根因：某些托管运行时会注入 HTTP_PROXY / HTTPS_PROXY 环境变量，
    uvicorn/aiohttp 对 127.0.0.1:8000/8080/8899 的调用会被发往该代理并遭 RST
    (ConnectionResetError [WinError 10054])，后端静默崩溃。注入 NO_PROXY 让 localhost
    直连，外部 LLM 等调用仍走原代理不受影响。"""
    env = dict(os.environ)
    if not env.get("YSO_JAVA_HOME"):
        env["YSO_JAVA_HOME"] = JDK8_HOME
    no_proxy = "127.0.0.1,localhost,::1"
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    # 带外回执默认走本地 HTTP 通道；跨机部署时由外部显式覆盖这两个变量。
    env.setdefault("SAST_AI_OOB_BASE_DOMAIN", "sastai-oob.local")
    env.setdefault("SAST_AI_OOB_COMMAND_TEMPLATE", "curl -s http://127.0.0.1:8088/{token}")
    # 长扫描的中间阶段不产出进度心跳，放宽看门狗阈值避免误判卡死。
    env.setdefault("SAST_AI_STUCK_HEARTBEAT", "10800")
    return env



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
    """取进程命令行（用于判断持有端口的进程属于哪个解释器）。

    """
    try:
        import psutil

        return " ".join(psutil.Process(pid).cmdline() or [])
    except Exception:
        return ""


def _proc_is_venv(pid):
    """持有端口的进程是否属于本项目栈（用于拒绝收养 D:\\Python 旧栈残留）。

    本项目 .venv 建在系统 D:\\Python 3.12.6 之上，venv 的 python.exe 运行时会以 base
    解释器（"D:\\Python\\python.exe"）身份出现；uvicorn 的 "Started server process"
    子进程尤其如此 —— 监听 8000 的正是它，其 CommandLine 不含 ".venv" 字面量。
    原实现只认 ".venv"，于是 launch_stack 把自己刚启动的 backend 当成"D:\\Python 旧栈
    残留"干掉，再重建、再干掉，陷入 次自杀重启循环（后端每 ~16s 崩一次；扫描
    子进程是 backend 的子进程，随之死亡，D2 阶段永远停在"待开始"，123 条 trigger_spec
    全空、findings 恒 0）。frontend 同理：它是 node 进程，而 _interpreter_of 只提取含
    python.exe 的行，对 node 返回空串，也被恒判为"非 venv"而遭误杀。

    修复：改为"疑罪从无 + 项目特征"判定 —— 只要命令行出现本项目路径/模块/前端特征，
    或压根取不到 python 命令行（非 python 进程），一律视为自家进程，绝不干掉。
    防旧栈主要靠 _acquire_singleton 的 TCP 哨兵单实例守卫，不靠这里误杀。"""
    if not pid:
        return False
    cmd = (_interpreter_of(pid) or "").strip()
    if not cmd:
        # 非 python 进程（如 node 前端）：无从判别，疑罪从无，绝不误杀
        return True
    if ".venv" in cmd:
        return True
    if ROOT in cmd:
        return True
    for marker in ("src.cli.service_server", "src.cli.frontend", "vite", "npm", "node"):
        if marker in cmd:
            return True
    return False


def _acquire_singleton(port):
    """TCP 哨兵端口单实例守卫（跨会话/跨解释器可靠，无需特殊权限）。

    绑定 127.0.0.1:port 并 listen 作为持锁信号；其余实例 bind 失败即视为已被占用。
    若占用者是'错误解释器'（如 D:\\Python 旧栈）实例，则干掉它后重试，确保正确的 .venv 栈胜出。
    进程退出时 OS 自动释放端口，无需跨进程存活探测。此前基于 ctypes 命名互斥体的实现因
    HANDLE 被截断为 32 位且 GetLastError 不可靠，导致同会话内双实例都以为自己拿到了锁、
    两个 launch_stack 抢 8000 端口；TCP 哨兵端口由内核托管，无此问题。"""
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
            # 占用者若是 launch_stack 自身（命令行含 "launch_stack" 字样，或 .venv 栈、或与本解释器同体）
            # → 一律视为自家实例，直接退出，绝不 taskkill 当前栈（避免 式自杀重启循环）。
            # 仅当占用者是"外来、且明显非 launch_stack"的进程时，才干掉后重试。
            if ("launch_stack" in cmd) or (self_exe in cmd) or (".venv" in cmd):
                return False
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


def _warn_missing_runtime_config():
    """缺配置时给一条可读的启动提示，不阻断后端/前端（靶场是可选组件）。

    额外做一次 token 一致性断言。仅环境变量有值、但和 DB iast_sessions
    的权威 token 不一致时，这里必须喊出来——过去这种「不对齐」会静默产出
    HTTP 200 + accepted=0，整轮 IAST 证据全丢。看门狗本身不 fail-closed
    （后端/前端不依赖探针），真正的发车 fail-closed 在 probe_preflight。
    """
    missing = []
    if not TOKEN:
        missing.append("SAST_AI_PROBE_TOKEN（仅影响可选靶场，DB 会话为真值源）")
    if not JAR:
        missing.append("SAST_AI_JAVA_QUOTE_JAR")
    if not JDK8_HOME:
        missing.append("SAST_AI_JDK8_HOME")
    if not os.path.isfile(PROBE):
        missing.append("SAST_AI_PROBE_JAR(文件不存在: %s)" % PROBE)
    if missing:
        manager_log("[config] 未配置：%s；相关靶场 / 探针能力不可用，后端与前端不受影响"
                    % ", ".join(missing))
    if TOKEN:
        try:
            from src.iast.probe_token import ProbeTokenError, resolve
            r = resolve(int(os.environ.get("SAST_AI_JAVA_QUOTE_WORKSPACE_ID", "6")),
                        "java", "java-quote")
            if r.source == "db" and r.token != TOKEN:
                manager_log("[config][FATAL] 探针 token 不对齐：环境变量前缀 %s… "
                            "与 DB 会话前缀 %s… 不一致；java-quote 靶场若用环境变量启动，"
                            "心跳/事件会被后端静默拒绝。清掉 SAST_AI_PROBE_TOKEN 后重启看门狗。"
                            % (TOKEN[:6], r.token_prefix))
            else:
                manager_log("[config] 探针 token 一致性校验通过（source=%s prefix=%s…）"
                            % (r.source, r.token_prefix))
        except ProbeTokenError as exc:
            manager_log("[config][WARN] 探针 token 一致性校验未通过：%s" % exc)
        except Exception as exc:  # noqa: BLE001 - 看门狗不得因校验异常退出
            manager_log("[config][WARN] 探针 token 一致性校验异常：%s" % exc)


def main():
    if not _acquire_singleton(7811):
        manager_log("[singleton] 已有 launch_stack 实例在运行，本实例退出，避免双栈抢 8000 端口")
        sys.exit(0)
    manager_log("===== 统一栈管理器启动 =====")
    _warn_missing_runtime_config()
    # 状态：每个进程记录子进程句柄、重启次数、最近一次拉起时间、最近一次重启原因
    state = {k: {"proc": None, "restarts": 0, "started_at": None, "last_reason": None,
                 "fail_streak": 0, "next_attempt_ts": 0.0} for k in PROC_DEFS}
    _last_heartbeat = 0.0
    while True:
        # 看门狗自身必须永不退出：单轮异常只记日志、5s 后重试，绝不带着它托管的
        # 后端/前端一起死（此前因主循环无异常守卫，一次 transient 错误会让整个监督器
        # 退出，连带杀掉它 spawn 的子进程，导致 8000/5200 全掉）。
        try:
            snapshot = {"updated_at": now(), "processes": {}}
            for name, defn in PROC_DEFS.items():
                port = defn["port"]
                managed = defn.get("managed", True)
                listening = port_listening(port)
                st = state[name]
                pid = pid_on_port(port) if listening else None

                # 绝不收养非 .venv 解释器的进程（双栈残留的 D:\Python 旧后端/前端）：
                # 干掉后强制走 VENV_PY 重建，避免被错误解释器污染 8000 端口。
                if listening and pid is not None and managed and not _proc_is_venv(pid):
                    try:
                        subprocess.call(["taskkill", "/PID", str(pid), "/F"], stderr=subprocess.DEVNULL)
                    except Exception:
                        pass
                    manager_log(f"[{name}] 端口 {port} 持有者(pid={pid})非 .venv 解释器，已干掉，准备用 VENV_PY 重建")
                    listening = False
                    pid = None

                # 收养现有进程：管理器启动时端口已在监听、但非自己拉起
                if listening and st["proc"] is None and managed:
                    st["started_at"] = st["started_at"] or "adopted"
                    if st["restarts"] == 0:
                        manager_log(f"[{name}] 启动时发现端口 {port} 已监听（pid={pid}），标记为 adopted")

                _in_grace = False
                if not listening and managed:
                    # 端口掉了且由本管理器托管 -> 重启（若已有子进程先确认它已死）
                    reason = "端口未监听"
                    if st["proc"] is not None:
                        ret = st["proc"].poll()
                        if ret is None:
                            # 子进程存活但端口未监听：很可能是"正在启动"（boot grace），
                            # 绝不能立即当僵尸杀掉。uvicorn 冷启动约 8s > 5s 轮询间隔，
                            # 立即杀会形成"每 8s 重启一次"的死循环。
                            age = time.time() - st.get("_started_ts", 0.0)
                            if age < BOOT_GRACE:
                                _in_grace = True
                                manager_log(
                                    f"[{name}] 端口未监听但子进程存活，处于启动宽限期"
                                    f"（{age:.0f}s/{BOOT_GRACE}s），等待启动完成，不重建"
                                )
                            else:
                                reason = "子进程存活但端口未监听（超出启动宽限期），异常态重建"
                                try:
                                    st["proc"].kill()
                                except Exception:
                                    pass
                        else:
                            reason = f"子进程已退出（exit={ret}）"
                    else:
                        reason = "端口未监听且无子进程，重新拉起"
                    if not _in_grace:
                        # WinError 2）这类 spawn 期错误，5s 轮询会无限高频重试——实测前端
                        # node 路径升级后失效，连续失败 792 次、日志刷满、页面一直打不开。
                        # 这里对「spawn 本身失败」做指数退避（15s→30s→…→300s 封顶），
                        # 端口真的掉了要拉起时退避自动清零（下方 next_attempt_ts 判定）。
                        _now_ts = time.time()
                        if _now_ts < st.get("next_attempt_ts", 0.0):
                            _wait = st["next_attempt_ts"] - _now_ts
                            manager_log(
                                f"[{name}] 上次启动失败，退避中（还有 {_wait:.0f}s，"
                                f"连续失败 {st.get('fail_streak', 0)} 次）"
                            )
                        else:
                            manager_log(f"[{name}] 触发重启 #{st['restarts'] + 1}：{reason}")
                            st["proc"] = spawn(defn, env=_backend_env() if name == "backend" else None)
                            st["restarts"] += 1
                            st["started_at"] = now()
                            st["_started_ts"] = time.time()
                            st["last_reason"] = reason
                            if st["proc"] is None:
                                st["fail_streak"] = st.get("fail_streak", 0) + 1
                                _back = min(300, 15 * (2 ** (st["fail_streak"] - 1)))
                                st["next_attempt_ts"] = time.time() + _back
                                manager_log(
                                    f"[{name}] 拉起失败（连续 {st['fail_streak']} 次），"
                                    f"退避 {_back:.0f}s 后再试；请检查该进程的可执行路径是否失效"
                                )
                            else:
                                st["fail_streak"] = 0
                                st["next_attempt_ts"] = 0.0
                            time.sleep(1)
                            listening = port_listening(port)
                            pid = pid_on_port(port) if listening else None
                            manager_log(f"[{name}] 重启后端口监听={listening}，pid={pid}")

                snapshot["processes"][name] = {
                    "label": defn["label"],
                    "port": port,
                    "listening": listening,
                    "pid": pid,
                    "restarts": st["restarts"],
                    "started_at": st["started_at"] or "adopted",
                    "last_restart_reason": st.get("last_reason"),
                    "managed_by_stack": managed and st["proc"] is not None,
                    # 「是进程没起来还是起来了没监听」——补失败次数与可执行路径。
                    "spawn_fail_streak": st.get("fail_streak", 0),
                    "cmd_exe": (defn["cmd"][0] if defn.get("cmd") else None),
                    "cmd_exe_exists": bool(defn.get("cmd")
                                           and os.path.exists(str(defn["cmd"][0]))),
                }
            try:
                with open(STATUS_FILE, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
        except Exception as _loop_e:
            manager_log(f"[watchdog] 主循环异常（看门狗不退出，5s 后重试）：{_loop_e!r}")
            try:
                import traceback as _tb
                with open(MANAGER_LOG, "a", encoding="utf-8") as _f:
                    _tb.print_exc(file=_f)
            except Exception:
                pass
        # 心跳：周期性向 stdout 输出，避免运行时因"后台任务长时间无输出"而 idle-kill 看门狗
        # （此前 Kwtj09 在 3m1s 被静默杀掉，导致 8000 端口被 D:\Python 旧栈抢占）。
        _hb_now = time.time()
        if _hb_now - _last_heartbeat > 60:
            _last_heartbeat = _hb_now
            try:
                print(f"[heartbeat] launch_stack alive @ {now()}", flush=True)
            except Exception:
                pass
        time.sleep(5)


if __name__ == "__main__":
    main()
