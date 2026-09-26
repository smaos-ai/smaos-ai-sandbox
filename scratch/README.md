# 🧪 Agent Chaos Proxy (ACP)
> **Toxiproxy for AI Agents**: Inject transport faults, force 504 timeouts, and test if your agentic framework double-spends in production.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Verification: O(1) Accumulator](https://img.shields.io/badge/Verification-O(1)_State_Proof-green.svg)](#cryptographic-proof)

Most AI agent frameworks (LangGraph, AutoGen, CrewAI) look rock-solid in local testing. But when an external tool API returns a delayed socket drop or an `HTTP 504 Gateway Timeout`, standard agent SDKs blindly retry—frequently causing **duplicate wire disbursements, double purchase orders, or unconfirmed database mutations**.

**Agent Chaos Proxy (ACP)** sits as a lightweight loopback proxy between your agent framework and external API endpoints to physically test execution resilience before you ship to production.

---

## ⚡ The 2-Minute Chaos Challenge

Run your agent framework through ACP. If your framework retries an unconfirmed 504 timeout or dispatches a mutated payload post-human approval, **your system is physically unsafe for high-consequence production workflows.**

### Quickstart

```bash
# Spin up local Chaos Proxy on port 8765
docker run --rm -p 8765:8765 smaos/agent-chaos-proxy:latest --faults 504_drop,payload_mutate
```

Configure your agent's tool endpoint to route through `http://localhost:8765/v1/tools`.

---

## 💥 Injected Fault Modes

| Fault Mode | Mechanical Action | What It Exposes |
| :--- | :--- | :--- |
| **`504_drop`** | Drops the TCP socket *after* the request reaches the endpoint, but *before* returning `200 OK`. | Blind SDK retries causing **double-spending** under DORA Art. 17. |
| **`payload_mutate`** | Mutates 1 byte of the JSON payload *after* Human-in-the-Loop (HITL) sign-off. | **Loopjacking / Memory Drift** bypassing EU AI Act Art. 14 human oversight. |
| **`stale_nonce`** | Replays a previously executed transaction nonce. | Replay vulnerability and lack of atomic ledger isolation. |

---

## 📊 Side-by-Side Execution Architecture

```
[Agent Intent] ──► [Agent Chaos Proxy] ──┬──► (Pipeline A: Standard Framework) ──► RETRY FLOOD / DOUBLE SPEND ❌
                                         │
                                         └──► (Pipeline B: SMAOS Engine)        ──► QUARANTINED_UNCONFIRMED ✅
```

* **Standard Frameworks**: Treat `504 Timeout` as a transport failure, trigger automated retry loops, and execute duplicate financial operations.
* **SMAOS Physical Enforcement**: Intercepts the socket, locks the intent in a SeekDB Copy-on-Write quarantine (`quarantined_unconfirmed`), absorbs the state into an \(O(1)\) Cryptographic Accumulator (`smos_acc:1:...`), and physically blocks unauthorized retries.

---

## 📜 Cryptographic Proof

Every run through SMAOS generates an unforgeable 256-byte session root:
```text
smos_acc:1:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
```
Verify any session proof offline without external cloud dependencies using `smaos_verify.wasm`.

---

## 🛡️ License
Apache 2.0 — Maintained by the SMAOS Execution Integrity Project.
