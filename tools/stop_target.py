"""Stop the OWASP FULL target (Tomcat 8444 + HSQLDB 9002 + watchdog).

Kills:
  - the watchdog python running launch_owasp_full.py
  - any process listening on 8444 (catalina) or 9002 (hsqldb)

Counterpart to up_target_owasp_full.cmd, which now launches the watchdog headless.
This script is safe to run from any window; it only touches the FULL target's
processes, not the backend (8000) or frontend (5200).

If psutil is unavailable, fall back to killing by port via netstat is not done here;
instead print guidance to kill java.exe manually.
"""
import sys

try:
    import psutil
except ImportError:
    print("[stop-target] psutil not available; cannot auto-stop.")
    print("[stop-target] manually: close the target window, or taskkill /F /IM java.exe")
    sys.exit(2)

TARGET_PORTS = (8444, 9002)
WATCHDOG_MARK = "launch_owasp_full.py"


def main():
    victims = {}  # pid -> reason
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            info = p.info
            pid = info["pid"]
            cl = " ".join(info.get("cmdline") or [])
            if WATCHDOG_MARK in cl:
                victims[pid] = "watchdog"
            try:
                for c in (p.connections(kind="inet") or []):
                    if c.status == "LISTEN" and c.laddr.port in TARGET_PORTS:
                        victims[pid] = f"port {c.laddr.port}"
            except Exception:
                # AccessDenied or other per-process connection error; ignore
                pass
        except Exception:
            continue

    if not victims:
        print("[stop-target] nothing on 8444/9002 and no watchdog found - target already stopped")
        return
    for pid, why in sorted(victims.items()):
        try:
            proc = psutil.Process(pid)
            proc.kill()
            print(f"[stop-target] killed PID {pid} ({why})")
        except Exception as e:
            print(f"[stop-target] kill PID {pid} ({why}) failed: {e}")
    print("[stop-target] done. Ports 8444/9002 should now be free.")


if __name__ == "__main__":
    main()
