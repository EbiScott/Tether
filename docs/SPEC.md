# Tether — Specification (v1)

The minimal-but-real contract for the bridge. [`THREAT_MODEL.md`](THREAT_MODEL.md) is the *why*; this
is the *what*. Implementation follows this document.

## 1. Call lifecycle

Every MCP tool call flows through the same pipeline. This ordering is the security model:

```
LLM/MCP host
     |  (1) tool call: tool + args + MCP context
     v
[ resolve ] device + tool known & registered?           -- no -> DENY (not_registered)
     v
[ #1 POLICY ] allowed? which risk tier? within rate?    -- no -> DENY (policy / rate_limited)
     v
[ #3 ANOMALY ] rate/repetition/probe/escalation ok?     -- no -> DENY/THROTTLE (anomaly:*)
     v
[ #2 TIER ]   read_only / low_risk -> execute
              high_risk            -> queue PENDING, return action_id (no hardware touched)
     v
[ transport ] talk to device over HTTP (MQTT later)
     v
[ #4 SANITIZE ] validate + neutralize device response
     v
[ #5 AUDIT ]  append record (always, even on deny/error)
     v
result -> LLM
```

Audit (**#5**) is written for *every* outcome including denials and errors — it wraps the whole
pipeline, it is not a final step that a failure can skip.

## 2. MCP tools exposed to the LLM

| Tool | Params | Tier | Returns |
|------|--------|------|---------|
| `list_devices` | — | read_only | registered devices: id, description, transport, tools+tiers, online |
| `describe_device` | `device_id` | read_only | sensors[] & actuators[] with type/unit/range + per-action tier |
| `read_sensor` | `device_id`, `sensor` | read_only | `{value, unit, ts}` (validated/sanitized) |
| `set_actuator` | `device_id`, `actuator`, `state` | policy-defined (`low_risk`/`high_risk`) | result, or `{status: pending_confirmation, action_id}` |
| `send_raw_command` | `device_id`, `command` | high_risk | raw device response (sanitized). Disabled by default in policy. |
| `check_action` | `action_id` | read_only | status of a queued high-risk action: `pending`/`approved`/`denied`/`executed` + result |
| `query_audit_log` | `device_id?`, `tool?`, `decision?`, `limit?` | read_only | recent audit records (redacted) |

Tool input validation uses pydantic models — malformed args are rejected before policy.

## 3. Risk tiers (#2)

| Tier | Meaning | Default handling |
|------|---------|------------------|
| `read_only` | cannot change physical state | execute, log |
| `low_risk` | state change, reversible / harmless | execute, log |
| `high_risk` | state change with real-world consequence | **queue for human confirmation**, do not execute until an operator approves |

**Confirmation flow (server-side, does not trust the MCP client):**
1. LLM calls a `high_risk` tool → Tether stores a *pending action* `{action_id, device, tool, args,
   requested_at, expires_at}` and returns `{status: "pending_confirmation", action_id, message}`.
   **No hardware is touched.**
2. A human operator reviews out-of-band:
   `tether approve <action_id>` / `tether deny <action_id>` / `tether pending` (list).
3. On approval Tether executes and records the result; the LLM retrieves it via `check_action`.
4. Pending actions expire (`confirmation.expiry_seconds`, default 300s) → auto-denied.

`confirmation.mode`: `queue` (default), `deny` (reject all high-risk), or `auto`
(**dev/testing only** — auto-approve with a loud warning in logs; never for real hardware).

## 4. Policy schema (#1)

Deny-by-default: a device/tool not described in policy cannot be called. See
[`../config/policy.example.yaml`](../config/policy.example.yaml) for an annotated copy.

```yaml
version: 1

defaults:
  rate_limit: { calls: 30, per_seconds: 60 }   # global ceiling, all tools
  confirmation: { mode: queue, expiry_seconds: 300 }

anomaly:
  repetition: { max_identical: 5, per_seconds: 30 }   # same tool+args
  denial_burst: { max_denials: 8, per_seconds: 60, cooldown_seconds: 120 }
  escalation: { max_high_risk_attempts: 3, per_seconds: 60 }

devices:
  lab-esp32-01:
    description: "Lab ESP32 on the bench"
    transport:
      kind: http
      address: "http://127.0.0.1:8080"
      auth: { type: bearer, token_env: TETHER_LAB_ESP01_TOKEN }   # secret via env, never inline
    tools:
      read_sensor:
        tier: read_only
        sensors: [temperature, humidity, soil_moisture]
      set_actuator:
        tier: high_risk
        actuators: [relay1, led]
        rate_limit: { calls: 5, per_seconds: 60 }     # per-tool override (tighter than global)
      send_raw_command:
        allow: false                                   # explicitly disabled
```

Resolution order for a call: tool must be listed → `allow` not false → sensor/actuator in its list →
tier from config → rate limit = tightest of (global, per-device, per-tool).

## 5. Device model & transport interface

A device self-describes its capabilities; the policy constrains which of them are reachable.
Transports implement one interface so HTTP now / MQTT later is a drop-in:

```python
class DeviceTransport(Protocol):
    async def describe(self, dev: DeviceConfig) -> DeviceCapabilities: ...
    async def read_sensor(self, dev: DeviceConfig, sensor: str) -> RawReading: ...
    async def set_actuator(self, dev: DeviceConfig, actuator: str, state) -> RawResult: ...
    async def raw_command(self, dev: DeviceConfig, command: str) -> RawResult: ...
```

**HTTP adapter** maps to the device's REST surface (what the mock ESP32 implements):

| Call | HTTP |
|------|------|
| describe | `GET /describe` → capability JSON |
| read_sensor | `GET /sensor/{name}` → `{value, unit}` |
| set_actuator | `POST /actuator/{name}` `{state}` → `{ok, state}` |
| raw_command | `POST /cmd` `{command}` → `{response}` |

All requests carry `Authorization: Bearer <device token>`; the device rejects anything else (#3/T3).

## 6. Sanitizer rules (#4)

Applied to **everything** crossing device→bridge→LLM, before it becomes a tool result:

1. **Type & range:** numeric readings coerced to declared type; out-of-declared-range → the reading
   is rejected (not silently clamped) and flagged `sanitizer:out_of_range`.
2. **Control chars / ANSI:** stripped from all strings.
3. **Length cap:** strings truncated to `MAX_FIELD_LEN` (default 512) with a `…[truncated]` marker.
4. **Structural neutralization of free text:** device free-text is never returned raw. It is wrapped:
   ```
   <untrusted-device-data device="lab-esp32-01" field="status">
   ...neutralized text...
   </untrusted-device-data>
   ```
   so the model reads it as data. **No reliance on phrase blocklists** — structure, not keyword
   matching, is the defence.
5. **Secrets never echoed:** tokens/addresses are never placed in a tool result or audit `args`.

## 7. Anomaly detector (#3)

Sliding-window signals over the live call stream:

| Signal | Trips when | Response |
|--------|-----------|----------|
| `rate` | calls exceed the applicable rate limit | deny this call (`rate_limited`), log |
| `repetition` | identical `tool`+`args` ≥ `max_identical` in window | deny + flag `anomaly:repetition` |
| `denial_burst` | ≥ `max_denials` denials in window (probing) | cooldown/quarantine device+tool, alert |
| `escalation` | ≥ `max_high_risk_attempts` high-risk attempts in window | alert, log `anomaly:escalation` |

Responses escalate: **flag** (log only) → **throttle** (deny this call) → **quarantine** (temporary
block of device/tool for `cooldown_seconds`). All transitions are audited.

## 8. Audit record (#5)

Append-only JSONL (one object per line, fsync'd). One record per call attempt:

```json
{
  "ts": "2026-10-15T12:34:56.789Z",
  "request_id": "a1b2c3d4",
  "actor": { "host": "claude-desktop", "session": "..." },
  "device_id": "lab-esp32-01",
  "tool": "set_actuator",
  "args": { "actuator": "relay1", "state": "on" },
  "tier": "high_risk",
  "decision": "pending",
  "reason": "high_risk_requires_confirmation",
  "anomaly_flags": [],
  "result_status": "pending",
  "latency_ms": 3,
  "error": null
}
```

`args` are post-sanitization and secret-redacted. Roadmap: per-line hash chaining for tamper-evidence.

## 9. Device authentication

Per-device bearer token. The token value lives in the env var named by `transport.auth.token_env`;
the policy file holds only the *name* of the env var, never the secret. HTTP adapter attaches it;
device validates and 401s otherwise. (TLS + MQTT-TLS + HMAC: roadmap, see threat model §6.)

## 10. Error model

Tool results use a consistent shape so the LLM can reason about failures without seeing internals:

```json
{ "ok": false, "error": "policy_denied", "message": "tool 'send_raw_command' is disabled for lab-esp32-01" }
```

Error codes: `not_registered`, `policy_denied`, `rate_limited`, `anomaly_blocked`,
`pending_confirmation`, `confirmation_denied`, `device_unreachable`, `device_auth_failed`,
`sanitizer_rejected`, `bad_request`.

## 11. Build order

Implemented in this order (each layer depends only on the ones above it):

1. **Config + models** (`config.ts`, `types.ts`) — load & strictly validate policy with zod. ← foundation
2. **Transport interface + HTTP adapter** (`transports/`) + **mock ESP32** (`sim/`). ← something real to hit
3. **Audit log** (`audit.ts`) + **pending store** (`pending.ts`) — needed by the pipeline.
4. **Policy engine + risk tiers** (`policy.ts`).
5. **Sanitizer** (`sanitizer.ts`).
6. **Anomaly detector** (`anomaly.ts`) — last of the security layers; it needs real traffic shapes to tune.
7. **Bridge + MCP server** (`bridge.ts`, `server.ts`) wiring the pipeline, plus the `approve`/`deny`/`pending` operator CLI (`index.ts`).
8. **Tests** (`tests/`, vitest) throughout.
