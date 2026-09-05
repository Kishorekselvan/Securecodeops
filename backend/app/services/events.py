import asyncio
import json
from typing import Dict, List, Any
from fastapi import WebSocket

class ScanEventManager:
    def __init__(self):
        # scan_id -> list of active WebSocket connections
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # scan_id -> list of SSE queues
        self.sse_subscribers: Dict[str, List[asyncio.Queue]] = {}

    async def connect_ws(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.setdefault(scan_id, []).append(websocket)

    def disconnect_ws(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)

    def subscribe_sse(self, scan_id: str) -> asyncio.Queue:
        queue = asyncio.Queue()
        self.sse_subscribers.setdefault(scan_id, []).append(queue)
        return queue

    def unsubscribe_sse(self, scan_id: str, queue: asyncio.Queue):
        if scan_id in self.sse_subscribers:
            if queue in self.sse_subscribers[scan_id]:
                self.sse_subscribers[scan_id].remove(queue)

    async def broadcast_event(self, scan_id: str, event_type: str, data: Dict[str, Any]):
        payload = {
            "scan_id": scan_id,
            "event": event_type,
            "data": data
        }
        
        # Broadcast to WebSockets
        if scan_id in self.active_connections:
            for ws in list(self.active_connections[scan_id]):
                try:
                    await ws.send_text(json.dumps(payload))
                except Exception:
                    self.disconnect_ws(scan_id, ws)

        # Broadcast to SSE queues
        if scan_id in self.sse_subscribers:
            for q in list(self.sse_subscribers[scan_id]):
                try:
                    await q.put(payload)
                except Exception:
                    pass

event_manager = ScanEventManager()
