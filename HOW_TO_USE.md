# How to use Tether

Everything you need to run, test, and extend Tether. New here? Read the
[README](README.md) for what it is and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for why it's
built this way.

**Contents**

1. [Prerequisites](#1-prerequisites)
2. [Install](#2-install)
3. [The device token (do this first)](#3-the-device-token-do-this-first)
4. [Run the mock ESP32](#4-run-the-mock-esp32)
5. [Way 1 — drive it from the CLI](#5-way-1--drive-it-from-the-cli)
6. [Way 2 — MCP Inspector](#6-way-2--mcp-inspector)
7. [Way 3 — a real MCP client](#7-way-3--a-real-mcp-client)
8. [Watch the security layers work](#8-watch-the-security-layers-work)
9. [The high-risk confirmation flow](#9-the-high-risk-confirmation-flow)
10. [Pointing Tether at real hardware](#10-pointing-tether-at-real-hardware)
11. [Writing your own policy](#11-writing-your-own-policy)
12. [Reading the audit log](#12-reading-the-audit-log)
13. [Command reference](#13-command-reference)
14. [Troubleshooting](#14-troubleshooting)
15. [Working on Tether itself](#15-working-on-tether-itself)

---

## 1. Prerequisites

| Need | Why | Check |
|------|-----|-------|
| **Node.js ≥ 18** | Tether runs on Node; 18 is the floor for built-in `fetch` | `node -v` |
| **npm** (ships with Node) | dependency install + scripts | `npm -v` |
| Nothing else | the simulator is built in — **no hardware required** | — |

Tether has no broker, cloud, or database dependency. Everything runs on your machine.

## 2. Install

From the project root:

```bash
npm install
```

That installs the MCP SDK, zod, js-yaml, and the dev toolchain (TypeScript, tsx, vitest).

## 3. The device token (do this first)

Tether authenticates to every device with a **per-device bearer token**. The policy file names the
*environment variable* that holds the secret — never the secret itself.

The example policy uses `TETHER_LAB_ESP01_TOKEN`, and the simulator defaults to the value
`tether-dev-token`. **The two sides must match**, or every call fails with `device_auth_failed`.

Set it in **every terminal** you use — both the simulator and Tether:

**PowerShell (Windows, default here)**

```powershell
$env:TETHER_LAB_ESP01_TOKEN = "tether-dev-token"
```

**Git Bash / macOS / Linux**

```bash
export TETHER_LAB_ESP01_TOKEN=tether-dev-token
```

> The value is a dev placeholder. For anything real, use a long random string, e.g.
> `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`, and set the same value
> on the device — not just in your shell.

Tether compares whatever the device receives against its own token on every request, so this is the
one piece of shared state between the two halves. Treat it like a credential: don't commit it, don't
reuse it across devices, and rotate it if it ever lands somewhere it shouldn't.

## 4. Run the mock ESP32

Open **Terminal A** and start the fake device:

```bash
npm run sim
```

You should see:

```
[mock-esp32] listening on http://127.0.0.1:8080  mode=friendly
[mock-esp32] bearer token = "tether-dev-token"
```

It exposes three sensors (`temperature`, `humidity`, `soil_moisture`) and two actuators
(`relay1`, `led`). Every actuator change is printed to this terminal, so you can watch a call land
on the device.

Options:

```bash
npm run sim -- --port 9090       # different port (update the policy to match)
npm run sim -- --token mysecret  # different token
npm run sim -- --evil            # hostile mode: returns injected / out-of-range data
```

Leave Terminal A running and use **Terminal B** for everything below.

## 5. Way 1 — drive it from the CLI

The fastest way to see Tether work. No MCP client, no build step (runs through `tsx`):

```bash
npm run dev -- call list_devices
```

```bash
npm run dev -- call read_sensor --device lab-esp32-01 --sensor temperature
```

```json
{
  "ok": true,
  "deviceId": "lab-esp32-01",
  "sensor": "temperature",
  "value": 21.38,
  "unit": "C",
  "ts": "2026-10-19T09:12:44.301Z"
}
```

Other tools from the CLI:

```bash
npm run dev -- call describe_device --device lab-esp32-01
npm run dev -- call set_actuator --device lab-esp32-01 --actuator relay1 --state on
npm run dev -- call query_audit_log --limit 10
```

`set_actuator` comes back **pending** rather than executing — see
[§9](#9-the-high-risk-confirmation-flow).

> Note: CLI `call` mode does not write the audit file (it's a one-shot process). Use `serve` mode
> ([§7](#7-way-3--a-real-mcp-client)) to build a real audit trail.

## 6. Way 2 — MCP Inspector

MCP Inspector is the official browser UI for poking an MCP server by hand. It lists every tool,
lets you fill in arguments, and shows the raw JSON response.

```bash
npm run build
npx @modelcontextprotocol/inspector node dist/index.js serve --config config/policy.example.yaml
```

It prints a `localhost` URL — open it. You'll see Tether's seven tools. Before calling anything,
put the token in the **Environment Variables** box of the inspector's connection settings:

```
TETHER_LAB_ESP01_TOKEN = tether-dev-token
```

Then pick a tool, fill the args, and hit connect/run. This is the best way to inspect exactly what
an LLM would see.

## 7. Way 3 — a real MCP client

Register Tether as a stdio MCP server. Build first:

```bash
npm run build
```

Then add it to your client's MCP config. Use **absolute paths** (clients often launch with a
different working directory):

```json
{
  "mcpServers": {
    "tether": {
      "command": "node",
      "args": [
        "D:\\Old Forge\\Programming\\Projects\\Tether\\dist\\index.js",
        "serve",
        "--config",
        "D:\\Old Forge\\Programming\\Projects\\Tether\\config\\policy.example.yaml"
      ],
      "env": {
        "TETHER_LAB_ESP01_TOKEN": "tether-dev-token"
      },
      "cwd": "D:\\Old Forge\\Programming\\Projects\\Tether"
    }
  }
}
```

- **Claude Desktop:** `claude_desktop_config.json` — Settings → Developer → Edit Config.
- **Claude Code:** `claude mcp add --transport stdio tether -- node dist/index.js serve --config config/policy.example.yaml`
  (then set the env var in the shell that launches it).
- **Cursor / VS Code / others:** equivalent `mcpServers` entry in their config file.

Restart the client. Tether should appear with its seven tools. Then just talk to it:

> "List the devices Tether can reach."
> "What's the temperature on lab-esp32-01?"
> "Turn relay1 on."

The third one gets **queued, not executed** — see below.

> `cwd` matters: the default pending queue and audit file are relative paths
> (`pending_actions.json`, `tether.audit.jsonl`), so they land in `cwd`. Set it explicitly, or pass
> absolute paths with `--pending` and `--audit`.

## 8. Watch the security layers work

Tether's whole point is that it says **no**. Five quick demos, all runnable with the simulator:

### Deny-by-default

```bash
npm run dev -- call read_sensor --device ghost-device --sensor temperature
```

```json
{ "ok": false, "error": "not_registered", "message": "device 'ghost-device' is not registered" }
```

The device isn't in the policy, so it doesn't exist as far as the LLM is concerned.

### Per-sensor allow-list

```bash
npm run dev -- call read_sensor --device lab-esp32-01 --sensor pressure
```

`pressure` isn't in the policy's `sensors:` list → `policy_denied`.

### Disabled tool

```bash
npm run dev -- call send_raw_command --device lab-esp32-01 --command reboot
```

`send_raw_command` has `allow: false` in the example policy → `policy_denied`. Raw passthrough is
the highest-risk tool, so it ships off.

### The sanitizer vs. a hostile device

Stop the friendly sim (Ctrl+C in Terminal A), then:

```bash
npm run sim -- --evil
```

In Terminal B:

```bash
npm run dev -- call read_sensor --device lab-esp32-01 --sensor temperature
```

```json
{ "ok": false, "error": "sanitizer_rejected", "message": "value 999 is above declared max 60 ..." }
```

The `--evil` simulator returns `999.0` with a prompt-injection payload smuggled into the `unit`
field. Tether rejects the out-of-range value outright and never passes the injected text to the
model. This is threat-model scenario **T4** made real.

### Anomaly detection

The anomaly detector blocks runaway loops — the kind a buggy agent or a hijacked prompt produces.
Its window lives **in memory, per process**, so the one-shot `call` CLI won't demonstrate it (each
invocation is a fresh process with a fresh slate).

To see it, run `serve` mode, then have a client fire the same call repeatedly. With the defaults
(`anomaly.repetition.max_identical: 5`, `per_seconds: 30`) the sixth identical call in 30 seconds is
rejected with `anomaly_blocked` and a reason naming the repetition signal.

The same goes for `denial_burst`: eight denials inside 60 seconds quarantine the device/tool for
120 seconds — so an attacker probing your policy gets shut out rather than answered.

## 9. The high-risk confirmation flow

This is the feature that makes Tether a security product rather than a bridge. High-risk actions
(**anything that changes the physical world** — flipping a relay, unlocking a door) are
**never executed on the LLM's say-so**.

1. **The LLM (or CLI) requests it.**

   ```bash
   npm run dev -- call set_actuator --device lab-esp32-01 --actuator relay1 --state on
   ```

   ```json
   {
     "ok": true,
     "status": "pending_confirmation",
     "actionId": "244db841",
     "message": "This is a high-risk action and was NOT executed...",
     "expiresAt": "2026-10-19T09:17:51.693Z"
   }
   ```

   **Nothing happened on the device.** Check Terminal A — no relay log line.

2. **A human reviews the queue.**

   ```bash
   npm run dev -- pending
   ```

   ```
   244db841  pending   set_actuator {"actuator":"relay1","state":"on"} on lab-esp32-01  (expires ...)
   ```

3. **A human approves (or denies) out-of-band.**

   ```bash
   npm run dev -- approve 244db841
   # or: npm run dev -- deny 244db841
   ```

4. **The result is collected.** Either the LLM calls `check_action`, or you do:

   ```bash
   npm run dev -- call check_action --action 244db841
   ```

   Only now does Tether touch the hardware. You'll see `[mock-esp32] actuator relay1 -> on` in
   Terminal A and `"status": "executed"` in the result.

**Why the split?** Tether deliberately does not trust the MCP client's own "allow this tool?"
prompt — if the host is compromised, that prompt is meaningless (threat model **T2**). The approval
has to happen in a process the LLM cannot reach, on a file the LLM cannot write: `pending_actions.json`.
An operator running `tether approve` is that process.

**Expiry:** a pending action auto-denies after `defaults.confirmation.expiry_seconds` (300s).
Approving an expired action does nothing.

**Modes** (`defaults.confirmation.mode`):

| Mode | Behaviour | Use for |
|------|-----------|---------|
| `queue` | **default** — wait for a human | real hardware, labs |
| `deny` | reject every high-risk call outright | read-only monitoring deployments |
| `auto` | auto-approve, with a loud warning in the log | **automated tests only — never real hardware** |

## 10. Pointing Tether at real hardware

The simulator speaks a small REST surface. Make your device speak the same one and Tether works
unchanged.

### The contract

Every request carries `Authorization: Bearer <token>`. The device must reject anything else with
401.

| What Tether does | Request | Response |
|------------------|---------|----------|
| discover capabilities | `GET /describe` | `{ "firmware": "...", "sensors": [{ "name", "type", "unit", "min", "max" }], "actuators": [{ "name", "states" }] }` |
| read a sensor | `GET /sensor/<name>` | `{ "value": 21.5, "unit": "C" }` |
| set an actuator | `POST /actuator/<name>` body `{"state":"on"}` | `{ "ok": true, "state": "on" }` |
| raw command | `POST /cmd` body `{"command":"..."}` | `{ "ok": true, "response": "..." }` |

`min`/`max` on a sensor are **load-bearing**: the sanitizer rejects any reading outside them. Declare
them narrowly and you get free range validation; declare them vaguely and the sanitizer protects you
less.

### Firmware options

- **ESP32 with ESP-AT / Tasmota:** both expose command endpoints you can shim into the four routes
  above. Tasmota's HTTP API (`/cm?cmnd=...`) maps neatly onto `POST /cmd`.
- **MicroPython / Arduino sketch:** implement the four routes directly against your sensor and relay
  objects — this is the cleanest option and keeps the attack surface small.
- **A Raspberry Pi bridging to serial:** run a thin local REST shim over `pyserial` /
  `serialport`, and point the policy at it.

The device stays **dumb on purpose**. Put no policy, no judgment, and ideally no persistent secrets
on it — Tether holds the smarts, so a compromised device can't be talked into anything.

### Plain HTTP warning

v1 speaks plain HTTP. On a hostile LAN that is MITM-able and the bearer token is visible on the
wire. Keep the device on a trusted segment or a lab VLAN until TLS and per-message HMAC land
(threat model §6).

## 11. Writing your own policy

Copy the example and edit it:

```bash
cp config/policy.example.yaml config/policy.yaml
```

```bash
npm run dev -- serve --config config/policy.yaml
```

`config/policy.yaml` is gitignored — your real device addresses and names stay local.

Every field, annotated, is in [`config/policy.example.yaml`](config/policy.example.yaml). The rules
that matter most:

**Deny-by-default.** A device or tool absent from `devices:` cannot be called. There is no wildcard,
no "allow everything". You add capability one tool at a time.

**A tool entry looks like this:**

```yaml
devices:
  my-esp32:
    description: "Bench board"
    transport:
      kind: http
      address: "http://192.168.1.50"
      auth:
        type: bearer
        token_env: MY_ESP32_TOKEN       # name of the env var, never the secret
    tools:
      read_sensor:
        tier: read_only
        sensors: [temperature, humidity]   # only these are reachable
      set_actuator:
        tier: high_risk
        actuators: [relay1]                # only this one
        rate_limit: { calls: 5, per_seconds: 60 }
      send_raw_command:
        allow: false                       # not exposed at all
```

**Choose tiers honestly.** `read_only` has no physical consequence — auto-run it. `low_risk` is a
reversible, harmless change. `high_risk` is anything you would not want happening unattended:
relays, locks, motors, heaters, anything with a safety implication. **When in doubt, it's
high_risk** — the cost of an unnecessary confirmation is a click; the cost of a missing one is the
threat model.

**Rate limits** are the tightest of three: the global `defaults.rate_limit`, a per-tool
`rate_limit`, and the anomaly windows. Set per-tool limits for anything state-changing.

**The policy is strictly validated.** A typo'd key (`tierr:`) or wrong type is a loud startup error,
not a silently ignored rule — that's intentional.

## 12. Reading the audit log

In `serve` mode every call — allowed, denied, pending, or errored — is appended to
`tether.audit.jsonl` (override with `--audit <path>`).

```bash
tail -f tether.audit.jsonl
```

Each line is one JSON record including `seq`, `ts`, `deviceId`, `tool`, `args`, `tier`, `decision`,
`reason`, `anomalyFlags`, `resultStatus`, `latencyMs`, and `error`. Ask Tether for a slice:

```bash
npm run dev -- call query_audit_log --limit 20
npm run dev -- call query_audit_log --device lab-esp32-01 --decision deny
```

**Tamper-evidence.** Records form a SHA-256 hash chain: each carries `prevHash` and its own `hash`
(over the record *including* `seq` and `prevHash`). Edit, reorder, or delete any line and everything
after it fails to verify. Verify from code:

```ts
import { readFileSync } from "node:fs";
import { verifyChain } from "./src/audit.js";

const records = readFileSync("tether.audit.jsonl", "utf8")
  .trim().split("\n").map((l) => JSON.parse(l));

console.log(verifyChain(records)); // { ok: true }  |  { ok: false, brokenAt: <seq> }
```

A write failure never crashes the bridge — it logs to stderr and keeps the in-memory trail.

## 13. Command reference

### CLI

| Command | What it does |
|---------|--------------|
| `npm run dev -- call list_devices` | devices, their tools, and tiers |
| `npm run dev -- call describe_device --device <id>` | sensors/actuators, filtered to what policy allows |
| `npm run dev -- call read_sensor --device <id> --sensor <name>` | read a sensor |
| `npm run dev -- call set_actuator --device <id> --actuator <name> --state <on\|off>` | state change; high-risk → queued |
| `npm run dev -- call send_raw_command --device <id> --command "<cmd>"` | raw passthrough (disabled by default) |
| `npm run dev -- call check_action --action <id>` | status of a queued action; executes it once approved |
| `npm run dev -- call query_audit_log [--device <id>] [--tool <t>] [--decision <d>] [--limit <n>]` | query the audit trail |
| `npm run dev -- serve [--config <path>] [--audit <path>] [--pending <path>]` | run the MCP server (stdio) |
| `npm run dev -- pending [--pending <path>]` | list the confirmation queue |
| `npm run dev -- approve <actionId> [--pending <path>]` | approve a queued action |
| `npm run dev -- deny <actionId> [--pending <path>]` | reject a queued action |

`npm run dev -- …` runs the TypeScript sources through `tsx`. After `npm run build`, use
`node dist/index.js …` or the `tether` bin instead.

### MCP tools (what the LLM sees)

| Tool | Args | Tier |
|------|------|------|
| `list_devices` | — | read-only |
| `describe_device` | `deviceId` | read-only |
| `read_sensor` | `deviceId`, `sensor` | `read_only` |
| `set_actuator` | `deviceId`, `actuator`, `state` | policy-defined (`low_risk` / `high_risk`) |
| `send_raw_command` | `deviceId`, `command` | `high_risk`, disabled by default |
| `check_action` | `actionId` | read-only |
| `query_audit_log` | `deviceId?`, `tool?`, `decision?`, `limit?` | read-only |

### npm scripts

| Script | Does |
|--------|------|
| `npm run dev -- <args>` | run from source (tsx), no build |
| `npm run build` | compile to `dist/` |
| `npm start -- <args>` | run the compiled build |
| `npm run sim [-- --evil]` | mock ESP32 on :8080 |
| `npm test` | vitest suite |
| `npm run typecheck` | `tsc --noEmit` |

### Files that appear at runtime

| File | Meaning | Git |
|------|---------|-----|
| `tether.audit.jsonl` | audit trail (`serve` mode) | ignored |
| `pending_actions.json` | the confirmation queue | ignored |

## 14. Troubleshooting

**`device_auth_failed`** — the token Tether sends doesn't match the device's. Both read
`TETHER_LAB_ESP01_TOKEN`; set it in **both** terminals. See [§3](#3-the-device-token-do-this-first).

**`device_unreachable`** — the simulator isn't running, or the policy address/port doesn't match.
Check Terminal A and `transport.address`. Also fires on any non-2xx device response.

**`not_registered`** — the device or tool isn't in the policy. Add it to `devices:` / `tools:`.
This is the deny-by-default design working as intended.

**`policy_denied`** — `allow: false`, or a sensor/actuator outside its allow-list.

**`rate_limited`** — you've exceeded `defaults.rate_limit` or a per-tool limit. Wait out the window
(60s by default) or raise the limit deliberately.

**`anomaly_blocked`** — identical calls repeated too fast, or a burst of denials triggered a
quarantine. Tune `anomaly.repetition` / `anomaly.denial_burst`, or fix the loop.

**`sanitizer_rejected`** — the device returned something that failed validation (out of range,
non-numeric, wrong type). Check the device. If its values are legitimately outside the declared
range, widen `min`/`max` in `/describe` rather than loosening the sanitizer.

**`bad_request`** — malformed tool args (e.g. empty `sensor`).

**My `set_actuator` returns `pending_confirmation` and nothing happens** — that's the design. Run
`npm run dev -- approve <actionId>` then `check_action`. See [§9](#9-the-high-risk-confirmation-flow).

**`pending` says a different action disappeared** — actions auto-deny after
`confirmation.expiry_seconds` (300s). It shows as `denied` with reason `expired`.

**Tool calls in a client hang or the server exits immediately** — stdout is the MCP channel. Anything
Tether prints goes to stderr, but a library printing to stdout will corrupt the stream. Run
`node dist/index.js serve ...` in a terminal: if it exits instantly, the config failed to load.

**Port 8080 in use** — `npm run sim -- --port 9090`, and change `transport.address` in the policy to
match.

**MCP client can't find `dist/index.js`** — run `npm run build`, and use absolute paths in the client
config.

## 15. Working on Tether itself

```bash
npm install          # once
npm test             # 29 tests: policy, tiers, anomaly, sanitizer, hash chain, HTTP integration
npm run typecheck    # strict TS, no emit
npm run build        # dist/
```

Layout:

```
src/
  index.ts          CLI entrypoint (serve / approve / deny / pending / call)
  bridge.ts         the pipeline: policy → anomaly → tier → transport → sanitize → audit
  server.ts         MCP tool surface (the only SDK-coupled module)
  policy.ts         policy engine (#1) + risk-tier resolution (#2)
  anomaly.ts        anomaly detector (#3)
  sanitizer.ts      device→LLM sanitizer (#4)
  audit.ts          hash-chained audit log (#5) + verifyChain()
  pending.ts        confirmation queue (file-backed, atomic writes)
  config.ts         zod policy schema + env-var token resolution
  models / types.ts shared data types
  transports/       DeviceTransport interface + HTTP adapter
  sim/mockEsp32.ts  the fake device
tests/              vitest suites
config/             policy.example.yaml (annotated)
docs/               THREAT_MODEL.md, SPEC.md
```

**Process:** new features are written test-first (red → green → refactor). The
[spec](docs/SPEC.md) is the contract — if behaviour changes, the spec changes with it, in the same
commit.

**Adding a transport:** implement `DeviceTransport` in `src/transports/`, register it in
`getTransport()`, add a `kind` to the transport schema, and test it against `buildServer()` from
the simulator.

**Adding a tool:** add the handler in `server.ts`, the logic in `bridge.ts`, a default-denied entry
in the policy schema, and a test.

---

## Quick sanity check

If you've done nothing else, this proves the install works:

```bash
# Terminal A
$env:TETHER_LAB_ESP01_TOKEN = "tether-dev-token"   # once per terminal
npm run sim

# Terminal B
$env:TETHER_LAB_ESP01_TOKEN = "tether-dev-token"   # once per terminal
npm run dev -- call read_sensor --device lab-esp32-01 --sensor temperature
```

A JSON reading with `"ok": true` and a plausible temperature means everything — transport, auth,
policy, sanitizer — is working end to end.
