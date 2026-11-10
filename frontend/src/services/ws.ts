import type { TaskEvent } from "@/types";

export function connectTaskSocket(taskId: number, onEvent: (event: TaskEvent) => void) {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws/tasks/${taskId}`);
  socket.onmessage = (message) => {
    onEvent(JSON.parse(message.data) as TaskEvent);
  };
  return socket;
}
