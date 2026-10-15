# Tether

**A security-first MCP bridge between LLMs and internet-connected microcontrollers.**

Tether is a [Model Context Protocol](https://modelcontextprotocol.io) server that lets any
MCP-compatible LLM client (Claude Desktop, Claude Code, Cursor, …) safely read sensors from and
send commands to ESP32 / Arduino hardware — **without** the LLM, the MCP host, or the device being
trusted blindly.

Pronounced **TETH-er** — /ˈtɛð.ər/ (soft "th", like *feather*).

---

## Why Tether exists

The pattern "LLM calls a tool → tool pokes a microcontroller" already exists (mcp2mqtt, mcp2serial,
the TiNKERIOT Tasmota bridge, and others). What none of them treat as a first-class concern is
**safety**: device authentication, command validation, guardrails against a jailbroken or
hallucinating LLM firing a dangerous actuator, and defence against malicious sensor data poisoning
the model's context.

Tether's whole thesis: **an LLM that can flip a relay in the physical world is an attack surface, and
should be governed like one.** Every tool call passes through a policy engine, an anomaly detector, a
data sanitizer, and an append-only audit log before anything physical happens.

```
  +---------------+         +-------------------------------------------+         +--------------+
  | ESP32/Arduino |  HTTP   |               Tether bridge               |   MCP   |  LLM / MCP   |
  |   sensors &   | <-----> |          (MCP server + safety layer)      | <-----> |     host     |
  |   actuators   | (MQTT   |   policy -> anomaly -> sanitizer -> audit |  stdio  | Claude, GPT  |
  +---------------+  later) +-------------------------------------------+ / HTTP  +--------------+
         ^                                                                              ^
     untrusted                                                                      untrusted
   (spoofable, may                                                            (may be jailbroken,
    send hostile data)                                                        host may be compromised)
```

The device stays **dumb on purpose** — all intelligence and all risk management live in the bridge,
keeping the microcontroller's own attack surface tiny.

## The six safety features

| # | Feature | What it does |
|---|---------|--------------|
| 1 | **Policy engine** | Declarative per-device / per-tool rules (YAML). Deny-by-default. |
| 2 | **Risk tiers** | `read_only` (auto), `low_risk` (auto + log), `high_risk` (human confirmation). |
| 3 | **Anomaly detector** | Flags abnormal call rate, repetition, denial-probing, tier-escalation. |
| 4 | **Data sanitizer** | Validates + neutralizes device→LLM data to block indirect prompt injection. |
| 5 | **Audit log** | Append-only, **hash-chained** (tamper-evident), queryable JSONL record of every call — a forensic trail. |
| 6 | **Threat model** | A published doc that states what Tether defends against and why. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). |

## Documents

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, trust boundaries, attacker types, attack
  scenarios, and the control that stops each one.
- [`docs/SPEC.md`](docs/SPEC.md) — the MCP tools, the call lifecycle, the policy schema, risk-tier
  semantics, the device transport interface, sanitizer rules, anomaly signals, and the audit record
  format.
- [`config/policy.example.yaml`](config/policy.example.yaml) — a fully-annotated example policy.

## Status

Working v1: strict policy loader, HTTP device transport, a mock ESP32 simulator, all six safety
layers (policy, risk tiers, anomaly detection, sanitizer, audit log), the MCP server, an operator
CLI, and a vitest test suite. MQTT transport and transport-layer crypto are on the roadmap (see the
threat model). Build order is in [`docs/SPEC.md`](docs/SPEC.md#11-build-order).

## Quickstart

Requires Node.js ≥ 18.

```bash
# 1. install
npm install

# 2. pick a device token (any string) and export it so Tether and the simulator match
export TETHER_LAB_ESP01_TOKEN=tether-dev-token
#   PowerShell:  $env:TETHER_LAB_ESP01_TOKEN = "tether-dev-token"

# 3. run the fake ESP32 so you can test with no hardware
npm run sim                      # friendly device on http://127.0.0.1:8080
#   npm run sim -- --evil        # hostile device, to watch the sanitizer neutralize/reject its data

# 4a. drive Tether straight from the CLI — no MCP client needed (uses tsx, no build step)
npm run dev -- call read_sensor  --device lab-esp32-01 --sensor temperature
npm run dev -- call set_actuator --device lab-esp32-01 --actuator relay1 --state on   # -> pending
npm run dev -- pending                              # list the queued high-risk action
npm run dev -- approve <actionId>                   # operator approves it out-of-band
npm run dev -- call check_action --action <actionId>  # now it executes

# 4b. or run it as an MCP server (stdio) for a real MCP client
npm run build && node dist/index.js serve --config config/policy.example.yaml
```

Register it in an MCP client by pointing the client at the stdio server:

```json
{
  "mcpServers": {
    "tether": {
      "command": "node",
      "args": ["dist/index.js", "serve", "--config", "config/policy.example.yaml"],
      "env": { "TETHER_LAB_ESP01_TOKEN": "tether-dev-token" }
    }
  }
}
```

## Safety & scope

Tether is for **your own hardware on your own network**, lab learning, and security research. It is a
defensive tool: it exists to make LLM→hardware control *governable and auditable*. Don't point it at
devices you don't own or aren't authorized to control.
