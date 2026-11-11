from collections import defaultdict
from queue import Queue
from threading import Lock
from typing import Any, DefaultDict, Dict, List


class TaskEventBus:
    """任务事件总线。

    - 既有能力：按 task_id 订阅（供 ``/ws/tasks/{task_id}`` 单任务详情通道）。
    - 新增：全局订阅（``subscribe_global``），所有事件都会扇出给全局订阅者，
      供 ``/ws/tasks`` 全局推送通道使用（取代前端 10s 轮询 /api/scan-tasks）。

    线程安全：publish 由扫描子进程的 watcher 线程调用，subscribe/unsubscribe 由
    FastAPI 异步上下文调用，统一用一把 Lock 保护订阅表。
    """

    def __init__(self):
        self._subscribers: DefaultDict[int, List[Queue]] = defaultdict(list)
        self._global_subscribers: List[Queue] = []
        self._lock = Lock()

    def publish(self, task_id: int, event: Dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers.get(task_id, [])) + list(self._global_subscribers)
        for queue in subscribers:
            try:
                queue.put(event)
            except Exception:
                # 单个订阅者异常不影响其余（如队列已满或已失效）
                pass

    def subscribe(self, task_id: int) -> Queue:
        queue: Queue = Queue()
        with self._lock:
            self._subscribers[task_id].append(queue)
        return queue

    def unsubscribe(self, task_id: int, queue: Queue) -> None:
        with self._lock:
            subscribers = self._subscribers.get(task_id, [])
            if queue in subscribers:
                subscribers.remove(queue)
            if not subscribers and task_id in self._subscribers:
                del self._subscribers[task_id]

    def subscribe_global(self) -> Queue:
        queue: Queue = Queue()
        with self._lock:
            self._global_subscribers.append(queue)
        return queue

    def unsubscribe_global(self, queue: Queue) -> None:
        with self._lock:
            if queue in self._global_subscribers:
                self._global_subscribers.remove(queue)
