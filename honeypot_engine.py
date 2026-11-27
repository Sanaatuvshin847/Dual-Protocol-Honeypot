import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Tuple

from dashboard_server import AIAlert, DashboardHub, run_dashboard_server


@dataclass(slots=True)
class SocketEvent:
    protocol: str          # "TCP" or "UDP"
    src_ip: str
    src_port: int
    dst_port: int
    stage: str             # "DATAGRAM", "HANDSHAKE", "PAYLOAD", "CLOSED"
    session_id: str
    payload_hex: str = ""
    timestamp: float = field(default_factory=time.time)


class SharedDeceptionState:
    """Task-safe runtime state modified dynamically by the AI triage worker."""

    def __init__(self) -> None:
        self.banners: Dict[int, bytes] = {
            2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
            2323: b"\r\nUbuntu 22.04.3 LTS\r\nlogin: ",
        }
        self.blocked_ips: set[str] = set()


class HoneypotUDPProtocol(asyncio.DatagramProtocol):
    """Stateless UDP listener capturing scan probes and malformed datagrams."""

    def __init__(
        self,
        dst_port: int,
        event_queue: asyncio.Queue[SocketEvent],
        state: SharedDeceptionState,
    ) -> None:
        self.dst_port = dst_port
        self.event_queue = event_queue
        self.state = state
        self.transport: asyncio.DatagramTransport | None = None
        self._rate_window: Dict[str, Tuple[int, float]] = {}

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def _allow_reply(self, src_ip: str, limit: int = 5) -> bool:
        """Prevent attackers from using this UDP port as a DDoS amplifier."""
        now = time.monotonic()
        count, window_start = self._rate_window.get(src_ip, (0, now))
        if now - window_start > 10.0:
            self._rate_window[src_ip] = (1, now)
            return True
        if count >= limit:
            return False
        self._rate_window[src_ip] = (count + 1, window_start)
        return True

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        src_ip, src_port = addr[0], addr[1]
        if src_ip in self.state.blocked_ips:
            return

        event = SocketEvent(
            protocol="UDP",
            src_ip=src_ip,
            src_port=src_port,
            dst_port=self.dst_port,
            stage="DATAGRAM",
            session_id=f"udp-{uuid.uuid4().hex[:8]}",
            payload_hex=data[:512].hex(),
        )
        try:
            self.event_queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Shed load cleanly under volumetric flood

        # Minimal decoy response capped to incoming datagram length
        if self.transport and len(data) >= 4 and self._allow_reply(src_ip):
            decoy_ack = b"\x00\x00\x81\x80"
            self.transport.sendto(decoy_ack[: len(data)], addr)


async def handle_tcp_session(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    dst_port: int,
    event_queue: asyncio.Queue[SocketEvent],
    state: SharedDeceptionState,
    conn_semaphore: asyncio.Semaphore,
) -> None:
    """Stateful TCP handler enforcing timeouts and capturing multi-step payloads."""
    peer = writer.get_extra_info("peername")
    src_ip, src_port = (peer[0], peer[1]) if peer else ("unknown", 0)

    if src_ip in state.blocked_ips or conn_semaphore.locked():
        writer.close()
        await writer.wait_closed()
        return

    session_id = f"tcp-{uuid.uuid4().hex[:8]}"
    async with conn_semaphore:
        try:
            await event_queue.put(
                SocketEvent("TCP", src_ip, src_port, dst_port, "HANDSHAKE", session_id)
            )

            banner = state.banners.get(dst_port, b"220 Service Ready\r\n")
            writer.write(banner)
            await writer.drain()

            for _ in range(5):
                chunk = await asyncio.wait_for(reader.read(1024), timeout=10.0)
                if not chunk:
                    break

                await event_queue.put(
                    SocketEvent(
                        "TCP",
                        src_ip,
                        src_port,
                        dst_port,
                        "PAYLOAD",
                        session_id,
                        payload_hex=chunk.hex(),
                    )
                )
                writer.write(b"Permission denied, please try again.\r\n")
                await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            try:
                event_queue.put_nowait(
                    SocketEvent("TCP", src_ip, src_port, dst_port, "CLOSED", session_id)
                )
            except asyncio.QueueFull:
                pass


async def telemetry_and_agent_worker(
    event_queue: asyncio.Queue[SocketEvent],
    state: SharedDeceptionState,
    hub: DashboardHub,
) -> None:
    """Consumes live TCP/UDP events, updates dashboard state, and runs AI triage."""
    ip_history: Dict[str, list[SocketEvent]] = {}
    alerted_ips: set[str] = set()

    while True:
        event = await event_queue.get()
        try:
            await hub.record_event(event)
            history = ip_history.setdefault(event.src_ip, [])
            history.append(event)

            protocols_seen = {e.protocol for e in history}
            if (
                len(protocols_seen) == 2
                and event.stage == "PAYLOAD"
                and event.src_ip not in alerted_ips
            ):
                alerted_ips.add(event.src_ip)
                # Adaptive deception: downgrade SSH banner to older fingerprint to keep bots engaged
                state.banners[2222] = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"

                summary = (
                    f"Correlated UDP recon sweep + TCP payload injection "
                    f"({len(history)} total events across UDP/TCP)."
                )
                action = (
                    f"Rotated SSH decoy banner to OpenSSH_7.4p1 & staged firewall drop for {event.src_ip}"
                )
                print(f"[AI TRIAGE TRIGGER] {event.src_ip} -> {summary}")

                await hub.publish_ai_alert(
                    AIAlert(
                        alert_id=f"alrt-{uuid.uuid4().hex[:6]}",
                        src_ip=event.src_ip,
                        severity="CRITICAL",
                        summary=summary,
                        recommended_action=action,
                        timestamp=time.time(),
                    )
                )
        finally:
            event_queue.task_done()


async def main() -> None:
    loop = asyncio.get_running_loop()
    event_queue: asyncio.Queue[SocketEvent] = asyncio.Queue(maxsize=5000)
    state = SharedDeceptionState()
    hub = DashboardHub()
    tcp_semaphore = asyncio.Semaphore(200)

    udp_ports = [15353, 11610]
    tcp_ports = [2222, 2323]
    udp_transports: list[asyncio.BaseTransport] = []

    try:
        for port in udp_ports:
            transport, _ = await loop.create_datagram_endpoint(
                lambda p=port: HoneypotUDPProtocol(p, event_queue, state),
                local_addr=("0.0.0.0", port),
            )
            udp_transports.append(transport)
            print(f"[UDP SENSOR] Listening on 0.0.0.0:{port}")

        async with asyncio.TaskGroup() as tg:
            tg.create_task(telemetry_and_agent_worker(event_queue, state, hub))
            tg.create_task(hub.metrics_ticker())
            tg.create_task(run_dashboard_server(hub, host="127.0.0.1", port=8000))

            for port in tcp_ports:
                server = await asyncio.start_server(
                    lambda r, w, p=port: handle_tcp_session(
                        r, w, p, event_queue, state, tcp_semaphore
                    ),
                    host="0.0.0.0",
                    port=port,
                    backlog=128,
                )
                print(f"[TCP TRAP]   Listening on 0.0.0.0:{port}")
                tg.create_task(server.serve_forever())
    finally:
        for transport in udp_transports:
            transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Honeypot engine stopped.")
