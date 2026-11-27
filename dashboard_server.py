import asyncio
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Set

try:
    from aiohttp import WSMsgType, web
except ImportError as exc:
    raise SystemExit(
        "Missing dependency 'aiohttp'. Install it first with:\n"
        "  pip install -r requirements.txt"
    ) from exc


@dataclass(slots=True)
class AIAlert:
    alert_id: str
    src_ip: str
    severity: str          # "HIGH" or "CRITICAL"
    summary: str
    recommended_action: str
    timestamp: float


class DashboardHub:
    """Manages WebSocket subscribers, active TCP session states, and 1s rate buckets."""

    def __init__(self) -> None:
        self.clients: Set[web.WebSocketResponse] = set()
        self.active_tcp_sessions: Dict[str, Dict[str, Any]] = {}
        self.recent_events: deque[Dict[str, Any]] = deque(maxlen=50)
        self.recent_alerts: deque[Dict[str, Any]] = deque(maxlen=20)

        self._udp_sec_count = 0
        self._tcp_sec_count = 0
        self.total_udp = 0
        self.total_tcp_handshakes = 0

    async def broadcast(self, message: Dict[str, Any]) -> None:
        if not self.clients:
            return
        stale: list[web.WebSocketResponse] = []
        for ws in self.clients:
            try:
                await ws.send_json(message)
            except (ConnectionResetError, RuntimeError):
                stale.append(ws)
        for ws in stale:
            self.clients.discard(ws)

    async def record_event(self, event: Any) -> None:
        """Tracks TCP state machine transitions and forwards live events."""
        payload = asdict(event)
        self.recent_events.append(payload)

        if event.protocol == "UDP":
            self._udp_sec_count += 1
            self.total_udp += 1
        elif event.protocol == "TCP":
            self._tcp_sec_count += 1
            if event.stage == "HANDSHAKE":
                self.total_tcp_handshakes += 1
                self.active_tcp_sessions[event.session_id] = {
                    "session_id": event.session_id,
                    "src_ip": event.src_ip,
                    "dst_port": event.dst_port,
                    "state": "ESTABLISHED",
                    "turns": 0,
                    "updated_at": event.timestamp,
                }
            elif event.stage == "PAYLOAD":
                session = self.active_tcp_sessions.get(event.session_id)
                if session:
                    session["state"] = "ACTIVE_PAYLOAD"
                    session["turns"] += 1
                    session["updated_at"] = event.timestamp
            elif event.stage == "CLOSED":
                self.active_tcp_sessions.pop(event.session_id, None)

        await self.broadcast({
            "type": "socket_event",
            "event": payload,
            "active_sessions": list(self.active_tcp_sessions.values()),
        })

    async def publish_ai_alert(self, alert: AIAlert) -> None:
        alert_dict = asdict(alert)
        self.recent_alerts.append(alert_dict)
        await self.broadcast({
            "type": "ai_alert",
            "alert": alert_dict,
        })

    async def metrics_ticker(self) -> None:
        """Emits 1-second packet-per-second (PPS) telemetry snapshots."""
        while True:
            await asyncio.sleep(1.0)
            snapshot = {
                "type": "metrics_tick",
                "timestamp": time.time(),
                "udp_pps": self._udp_sec_count,
                "tcp_pps": self._tcp_sec_count,
                "active_tcp_count": len(self.active_tcp_sessions),
                "total_udp": self.total_udp,
                "total_tcp_handshakes": self.total_tcp_handshakes,
            }
            self._udp_sec_count = 0
            self._tcp_sec_count = 0
            await self.broadcast(snapshot)

    async def ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=20.0)
        await ws.prepare(request)
        self.clients.add(ws)

        await ws.send_json({
            "type": "init_state",
            "active_sessions": list(self.active_tcp_sessions.values()),
            "recent_events": list(self.recent_events),
            "recent_alerts": list(self.recent_alerts),
        })

        try:
            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    break
        finally:
            self.clients.discard(ws)
        return ws

    async def index_handler(self, request: web.Request) -> web.Response:
        html_path = Path(__file__).with_name("dashboard.html")
        return web.Response(text=html_path.read_text(encoding="utf-8"), content_type="text/html")


async def run_dashboard_server(hub: DashboardHub, host: str = "127.0.0.1", port: int = 8000) -> None:
    app = web.Application()
    app.router.add_get("/", hub.index_handler)
    app.router.add_get("/ws", hub.ws_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[DASHBOARD]  Live UI & WebSocket streaming at http://{host}:{port}")

    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
