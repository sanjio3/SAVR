"""JNDI 注入的本地回连探针。

## 为什么必须真监听

`jndi_injection`（log4j `${jndi:ldap://...}`）**在响应里没有任何可判的痕迹**：
返回给客户端的都是原始 token。所以「响应回显」这条路彻底不通。

唯一确定性判据是：**目标真的发起了 LDAP/RMI 连接**。这里在本机起一个裸 TCP
监听（只 accept、不实现 LDAP 协议），投 `${jndi:ldap://127.0.0.1:<port>/a}`：

- 收到连接 ⇒ log4j 执行了 JNDI lookup ⇒ 漏洞成立（不需要真的返回恶意类）；
- 没有连接 ⇒ 要么版本已修，要么参数没进日志，判不成立。

不需要真的实现 LDAP 服务：log4j 在 lookup 阶段就会建连，协议握手失败不影响
「连接已建立」这个事实。

## 边界

- 只绑 `127.0.0.1`，不对外暴露；只 accept 记录，不读不写业务数据。
- 端口随机（bind :0），避免与靶场自带的 1389 冲突。
- 单例：同一进程内多次取端口返回同一个监听器，`reset` 清计数。
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_STATE: Dict[str, Any] = {"sock": None, "port": 0, "hits": [], "thread": None,
                          "lock": threading.Lock(), "current_spec": None,
                          "by_spec": {}}
_MAX_HITS = 64


def begin_spec(spec_id: Any) -> None:
    """标记「接下来这批请求属于哪个 spec」。

    回连是异步到达的（log4j 在写日志的瞬间发起连接，可能比 HTTP 响应还晚），
    所以不能靠「重放前后取差值」——必须由监听线程按当前 spec 归账。
    """
    with _STATE["lock"]:
        _STATE["current_spec"] = spec_id


def hits_for(spec_id: Any) -> int:
    with _STATE["lock"]:
        return int(_STATE["by_spec"].get(spec_id) or 0)


def _serve(sock: socket.socket) -> None:
    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            return  # socket 已关闭
        except Exception:  # noqa: BLE001
            continue
        try:
            with _STATE["lock"]:
                if len(_STATE["hits"]) < _MAX_HITS:
                    _STATE["hits"].append({"peer": "%s:%s" % (addr[0], addr[1])})
                _cur = _STATE.get("current_spec")
                if _cur is not None:
                    _STATE["by_spec"][_cur] = int(_STATE["by_spec"].get(_cur) or 0) + 1
                _n = len(_STATE["hits"])
            logger.info("[jndi-probe] 收到回连 %s:%s（spec=%s，共 %d 次）",
                        addr[0], addr[1], _cur, _n)
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def ensure_listener() -> int:
    """确保本地监听就绪，返回端口（0 表示不可用）。"""
    with _STATE["lock"]:
        if _STATE["sock"] is not None:
            return int(_STATE["port"])
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(16)
            _STATE["sock"] = sock
            _STATE["port"] = int(sock.getsockname()[1])
            t = threading.Thread(target=_serve, args=(sock,), daemon=True)
            t.start()
            _STATE["thread"] = t
            logger.info("[jndi-probe] 本地监听 127.0.0.1:%s", _STATE["port"])
            return _STATE["port"]
        except Exception as exc:  # noqa: BLE001
            logger.warning("[jndi-probe] 监听启动失败（jndi 载荷不可用）：%s", exc)
            return 0


def hit_count() -> int:
    with _STATE["lock"]:
        return len(_STATE["hits"])


def hits() -> List[Dict[str, Any]]:
    with _STATE["lock"]:
        return list(_STATE["hits"])


def reset() -> None:
    """清空命中计数（新一轮重放前调用）。监听本身保持。"""
    with _STATE["lock"]:
        _STATE["hits"] = []


def shutdown() -> None:
    with _STATE["lock"]:
        sock: Optional[socket.socket] = _STATE["sock"]
        _STATE["sock"] = None
        _STATE["port"] = 0
    if sock is not None:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
