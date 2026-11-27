# Dual-Protocol Honeypot & Agentic AI Telemetry

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)
![Asyncio](https://img.shields.io/badge/Concurrency-asyncio-green)
![Protocols](https://img.shields.io/badge/Protocols-TCP%20%26%20UDP-orange)
![Dashboard](https://img.shields.io/badge/Dashboard-WebSockets%20%2F%20aiohttp-purple)

An asynchronous Python (`asyncio`) network honeypot and real-time telemetry platform that contrasts **connectionless UDP** and **connection-oriented TCP** mechanics under live simulated attacks, paired with an **autonomous cross-protocol triage loop** and a **WebSocket SOC dashboard**.

> **Screenshot:** Place a capture of your live dashboard at `docs/dashboard-demo.png` to display it automatically below.
> ![Live Telemetry Dashboard](docs/dashboard-demo.png)

---

## Overview

Traditional honeypots passively append connection logs to disk, leaving defenders to manually correlate multi-stage attacks across protocols. This system separates transport duties into two specialized network planes bridged by a bounded event bus and an autonomous triage worker:

1. **Stateless UDP Reconnaissance Plane (`asyncio.DatagramProtocol`):** Ingests high-frequency, connectionless port sweeps and malformed datagrams on ports `15353` and `11610` with zero handshake overhead.
2. **Stateful TCP Deception Plane (`asyncio.start_server`):** Completes full three-way handshakes on emulated SSH (`2222`) and Telnet (`2323`) ports, tracking session state transitions (`ESTABLISHED` $\rightarrow$ `ACTIVE_PAYLOAD` $\rightarrow$ `CLOSED`) and capturing multi-turn brute-force payloads.
3. **Bounded Event Bus & Agentic Triage (`asyncio.Queue`):** Correlates attacker behavior across both protocols in real time. When an IP follows a UDP sweep with TCP payload injection, the triage agent autonomously mutates `SharedDeceptionState`—downgrading the SSH decoy banner (`OpenSSH_8.9p1` $\rightarrow$ `OpenSSH_7.4p1`) to keep automated bots engaged—and dispatches a `CRITICAL` alert.
4. **Real-Time WebSocket Dashboard (`aiohttp`):** Streams 1-second packets-per-second (PPS) metrics, active TCP state rows, raw socket events, and AI triage cards to a zero-dependency browser UI at `http://127.0.0.1:8000`.

---

## System Architecture

```text
  [UDP Probes: 15353, 11610]             [TCP Sessions: 2222, 2323]
               │                                       │
               ▼                                       ▼
 loop.create_datagram_endpoint()             asyncio.start_server()
 (Stateless DatagramProtocol)           (Coroutine + StreamReader/Writer)
               │                                       │
               └───────────────────┬───────────────────┘
                                   ▼
                     asyncio.Queue(maxsize=5000)
                     (Non-blocking backpressure bus)
                                   │
                                   ▼
                    Telemetry & Agentic Triage Worker
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
  Mutates SharedDeceptionState               DashboardHub (aiohttp /ws)
  (Dynamic SSH banner rotation)              (1s PPS buckets & live UI)
```

---

## Repository Structure

```text
dual-protocol-honeypot/
├── docs/
│   └── dashboard-demo.png      # Live dashboard screenshot (add after running)
├── .gitignore                  # Python, virtual env, and local log exclusions
├── README.md                   # Project documentation
├── requirements.txt            # Python dependencies (aiohttp)
├── honeypot_engine.py          # Core asyncio TCP/UDP engine & AI triage worker
├── dashboard_server.py         # aiohttp HTTP server & WebSocket telemetry hub
├── dashboard.html              # Real-time HTML5 Canvas & WebSocket frontend
└── attack_simulator.py         # Loopback dual-protocol traffic generator
```

---

## Quickstart

### 1. Prerequisites & Installation
* **Python 3.11+** (required for `asyncio.TaskGroup` and `@dataclass(slots=True)`)

```bash
git clone https://github.com/<your-username>/dual-protocol-honeypot.git
cd dual-protocol-honeypot
pip install -r requirements.txt
```

### 2. Start the Honeypot & Live Dashboard (Terminal 1)
```bash
python honeypot_engine.py
```
Open **`http://127.0.0.1:8000`** in your browser and confirm the top-right status badge displays **`LIVE STREAM`** in green.

*(Tip: Use `127.0.0.1` explicitly rather than `localhost` on Windows so the browser connects directly over IPv4.)*

### 3. Run the Dual-Protocol Attack Simulator (Terminal 2)
Place your browser window and Terminal 2 side by side, then launch a correlated campaign:

```bash
python attack_simulator.py --scenario correlated --concurrency 6
```

#### Available Simulator Scenarios
| Scenario Flag | Protocol(s) | Behavior Demonstrated |
| :--- | :--- | :--- |
| `--scenario udp_sweep` | UDP | Fires 12 rapid DNS/SNMP/malformed datagrams to test stateless ingestion and anti-amplification rate caps. |
| `--scenario tcp_banner` | TCP | Completes concurrent 3-way handshakes and captures initial service banners across ports `2222` and `2323`. |
| `--scenario tcp_bruteforce` | TCP | Maintains stateful multi-turn sessions sending credentials and simulated shell commands. |
| `--scenario correlated` | UDP + TCP | Executes all three stages sequentially from the same IP, triggering cross-protocol AI triage and banner rotation. |

---

## Engineering & Security Guardrails

* **UDP Anti-Amplification Protection:** `HoneypotUDPProtocol` enforces a per-IP reply rate limit (maximum 5 replies per 10-second window) and truncates decoy acknowledgments to the incoming datagram size so the sensor cannot be abused as a DDoS reflection amplifier.
* **Unprivileged Lab Ports:** Configured to bind to high ports (`15353`, `11610`, `2222`, `2323`, `8000`) so the server runs without administrator/root privileges and avoids collisions with OS mDNS services (`5353`).
* **Backpressure & Resource Bounds:** Uses a fixed-size `asyncio.Queue(maxsize=5000)`, an `asyncio.Semaphore(200)` on TCP connections, and strict 10-second read timeouts to prevent slow-loris or volumetric flood exhaustion.
* **Loopback Simulator Lock:** `attack_simulator.py` verifies that `--host` resolves to a local loopback address (`127.0.0.1`, `localhost`, or `::1`) before transmitting any packets.

---

## Future Enhancements

* **LLM Tool-Calling Triage Agent:** Connect `telemetry_and_agent_worker` to an async structured-output LLM agent equipped with IP reputation lookup tools and automated incident report generation.
* **SQLite Event Persistence:** Persist historical TCP/UDP sessions and AI alerts asynchronously so dashboard metrics survive backend restarts.
* **Fault-Injection Toggle:** Add simulated packet loss and jitter controls to visually contrast TCP head-of-line blocking against UDP packet freshness on the live chart.