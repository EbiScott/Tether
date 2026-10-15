import { randomUUID } from "node:crypto";
import { AnomalyDetector } from "./anomaly.js";
import { AuditLog, type DecisionKind, type ResultStatus } from "./audit.js";
import type { DeviceCfg, Policy } from "./config.js";
import { ErrorCode, TetherError } from "./errors.js";
import { PendingStore } from "./pending.js";
import { PolicyEngine } from "./policy.js";
import { Sanitizer } from "./sanitizer.js";
import { getTransport, type DeviceTransport } from "./transports/base.js";
import type { Actor, CallContext, DeviceCapabilities, RiskTier } from "./types.js";

/**
 * The bridge: the one trusted component. Every device tool call flows through the same pipeline
 * (SPEC.md §1):  policy -> anomaly -> tier -> transport -> sanitize -> audit.
 * Audit wraps every outcome, including denials and errors.
 */

export interface BridgeOptions {
  auditPath?: string | null;
  pendingPath?: string;
  /** Override how transports are created (used by tests to inject a fake device). */
  transportFactory?: (kind: string) => DeviceTransport;
}

type BridgeResult = Record<string, unknown>;

const DEVICE_TOOLS = new Set(["read_sensor", "set_actuator", "send_raw_command"]);

export class Bridge {
  private readonly policyEngine: PolicyEngine;
  private readonly anomaly: AnomalyDetector;
  private readonly sanitizer = new Sanitizer();
  private readonly audit: AuditLog;
  private readonly pending: PendingStore;
  private readonly transports = new Map<string, DeviceTransport>();
  private readonly capCache = new Map<string, DeviceCapabilities>();
  private readonly transportFactory: (kind: string) => DeviceTransport;

  constructor(
    private readonly policy: Policy,
    opts: BridgeOptions = {},
  ) {
    this.policyEngine = new PolicyEngine(policy);
    this.anomaly = new AnomalyDetector(policy.anomaly);
    this.audit = new AuditLog(opts.auditPath ?? null);
    this.pending = new PendingStore(opts.pendingPath ?? "pending_actions.json");
    this.transportFactory = opts.transportFactory ?? getTransport;
  }

  // ---- helpers ----

  private transportFor(dev: DeviceCfg): DeviceTransport {
    let t = this.transports.get(dev.transport.kind);
    if (!t) {
      t = this.transportFactory(dev.transport.kind);
      this.transports.set(dev.transport.kind, t);
    }
    return t;
  }

  private ctx(actor: Actor, deviceId: string, tool: string, args: Record<string, unknown>): CallContext {
    return { requestId: randomUUID().slice(0, 8), actor, deviceId, tool, args };
  }

  private log(
    c: CallContext,
    tier: RiskTier | null,
    decision: DecisionKind,
    reason: string,
    resultStatus: ResultStatus,
    latencyMs: number,
    error: string | null,
    flags: string[],
  ): void {
    this.audit.write({
      ts: new Date().toISOString(),
      requestId: c.requestId,
      actor: c.actor,
      deviceId: c.deviceId,
      tool: c.tool,
      args: c.args,
      tier,
      decision,
      reason,
      anomalyFlags: flags,
      resultStatus,
      latencyMs,
      error,
    });
  }

  private err(code: ErrorCode, message: string): BridgeResult {
    return { ok: false, error: code, message };
  }

  private async loadCaps(deviceId: string, dev: DeviceCfg, refresh = false): Promise<DeviceCapabilities> {
    if (!refresh) {
      const cached = this.capCache.get(deviceId);
      if (cached) return cached;
    }
    const caps = await this.transportFor(dev).describe(deviceId, dev);
    this.capCache.set(deviceId, caps);
    return caps;
  }

  /** Perform the actual device action + sanitize. Throws TetherError on device/sanitizer failure. */
  private async execute(
    c: CallContext,
    dev: DeviceCfg,
  ): Promise<{ result: BridgeResult; flags: string[] }> {
    const t = this.transportFor(dev);
    if (c.tool === "read_sensor") {
      const sensor = String(c.args["sensor"] ?? "");
      const caps = await this.loadCaps(c.deviceId, dev);
      const spec = caps.sensors.find((s) => s.name === sensor);
      const raw = await t.readSensor(c.deviceId, dev, sensor);
      const san = this.sanitizer.sanitizeReading(c.deviceId, spec, raw);
      return {
        result: {
          ok: true,
          deviceId: c.deviceId,
          sensor,
          value: san.value,
          unit: san.unit,
          ts: new Date().toISOString(),
        },
        flags: san.flags,
      };
    }
    if (c.tool === "set_actuator") {
      const actuator = String(c.args["actuator"] ?? "");
      const state = String(c.args["state"] ?? "");
      const raw = await t.setActuator(c.deviceId, dev, actuator, state);
      // We echo back only what we controlled, never arbitrary device text.
      return {
        result: { ok: raw.ok, deviceId: c.deviceId, actuator, state },
        flags: [],
      };
    }
    if (c.tool === "send_raw_command") {
      const command = String(c.args["command"] ?? "");
      const raw = await t.rawCommand(c.deviceId, dev, command);
      const san = this.sanitizer.sanitizeText(c.deviceId, "response", raw.text ?? "");
      return { result: { ok: raw.ok, deviceId: c.deviceId, response: san.text }, flags: san.flags };
    }
    throw new TetherError(ErrorCode.BadRequest, `unknown device tool '${c.tool}'`);
  }

  // ---- device tool pipeline ----

  async runDeviceTool(
    actor: Actor,
    deviceId: string,
    tool: string,
    args: Record<string, unknown>,
  ): Promise<BridgeResult> {
    const c = this.ctx(actor, deviceId, tool, args);
    if (!DEVICE_TOOLS.has(tool)) {
      return this.err(ErrorCode.BadRequest, `unknown tool '${tool}'`);
    }

    // #1 policy
    const decision = this.policyEngine.decide(c);
    if (!decision.allowed) {
      const flags = this.anomaly.recordDenial(c);
      this.log(c, null, "deny", decision.reason, "denied", 0, decision.reason, flags);
      return this.err(decision.errorCode ?? ErrorCode.PolicyDenied, decision.reason);
    }
    const tier = decision.tier as RiskTier;

    // #3 anomaly
    const anom = this.anomaly.check(c, tier);
    if (!anom.allowed) {
      const flags = [...anom.flags, ...this.anomaly.recordDenial(c)];
      this.log(c, tier, "deny", anom.reason, "denied", 0, anom.reason, flags);
      return this.err(ErrorCode.AnomalyBlocked, anom.reason);
    }

    const dev = this.policy.devices[deviceId]!; // guaranteed by policy.decide

    // #2 risk tier
    if (tier === "high_risk") {
      return this.handleHighRisk(c, dev, anom.flags);
    }

    // read_only / low_risk -> execute now
    const start = Date.now();
    try {
      const { result, flags } = await this.execute(c, dev);
      this.log(c, tier, "allow", decision.reason, "ok", Date.now() - start, null, [...anom.flags, ...flags]);
      return result;
    } catch (e) {
      return this.handleExecError(c, tier, e, start, anom.flags);
    }
  }

  private async handleHighRisk(
    c: CallContext,
    dev: DeviceCfg,
    anomalyFlags: string[],
  ): Promise<BridgeResult> {
    const mode = this.policy.defaults.confirmation.mode;

    if (mode === "deny") {
      const reason = "high-risk tools are disabled (confirmation.mode: deny)";
      this.log(c, "high_risk", "deny", reason, "denied", 0, reason, anomalyFlags);
      return this.err(ErrorCode.ConfirmationDenied, reason);
    }

    if (mode === "auto") {
      // DEV ONLY — auto-approve with a loud warning. Never for real hardware.
      console.error(
        `[tether] WARNING confirmation.mode=auto — auto-approving high-risk ${c.tool} on ${c.deviceId}`,
      );
      const start = Date.now();
      try {
        const { result, flags } = await this.execute(c, dev);
        this.log(c, "high_risk", "allow", "confirmation_auto_dev", "ok", Date.now() - start, null, [
          ...anomalyFlags,
          "confirmation:auto_dev",
          ...flags,
        ]);
        return result;
      } catch (e) {
        return this.handleExecError(c, "high_risk", e, start, [...anomalyFlags, "confirmation:auto_dev"]);
      }
    }

    // mode === "queue": store a pending action, touch no hardware
    const action = this.pending.create(
      c.deviceId,
      c.tool,
      c.args,
      this.policy.defaults.confirmation.expiry_seconds,
    );
    const reason = "high_risk_requires_confirmation";
    this.log(c, "high_risk", "pending", reason, "pending", 0, null, anomalyFlags);
    return {
      ok: true,
      status: "pending_confirmation",
      actionId: action.actionId,
      message:
        "This is a high-risk action and was NOT executed. An operator must approve it " +
        `(\`tether approve ${action.actionId}\`). Call check_action with this action_id to retrieve the result.`,
      expiresAt: action.expiresAt,
    };
  }

  private handleExecError(
    c: CallContext,
    tier: RiskTier,
    e: unknown,
    start: number,
    flags: string[],
  ): BridgeResult {
    if (e instanceof TetherError) {
      this.log(c, tier, "error", e.message, "error", Date.now() - start, e.message, flags);
      return this.err(e.code, e.message);
    }
    const msg = (e as Error).message ?? String(e);
    this.log(c, tier, "error", msg, "error", Date.now() - start, msg, flags);
    return this.err(ErrorCode.DeviceUnreachable, msg);
  }

  // ---- confirmation retrieval / execution ----

  async checkAction(actor: Actor, actionId: string): Promise<BridgeResult> {
    const a = this.pending.get(actionId);
    if (!a) return this.err(ErrorCode.NotFound, `no such action '${actionId}'`);

    if (a.status === "pending") {
      return { ok: true, status: "pending", actionId, message: "awaiting operator approval", expiresAt: a.expiresAt };
    }
    if (a.status === "denied") {
      return { ok: false, status: "denied", actionId, error: a.resultError ?? "denied" };
    }
    if (a.status === "executed") {
      return { ok: a.resultError == null, status: "executed", actionId, result: a.result, error: a.resultError ?? null };
    }

    // status === "approved" -> execute now, once
    const dev = this.policy.devices[a.deviceId];
    if (!dev) {
      const r = this.pending.markExecuted(actionId, null, "device no longer registered");
      return { ok: false, status: "executed", actionId, error: r?.resultError };
    }
    const c = this.ctx(actor, a.deviceId, a.tool, a.args);
    const start = Date.now();
    try {
      const { result, flags } = await this.execute(c, dev);
      this.pending.markExecuted(actionId, result, null);
      this.log(c, "high_risk", "allow", "confirmation_approved", "ok", Date.now() - start, null, flags);
      return { ok: true, status: "executed", actionId, result };
    } catch (e) {
      const msg = e instanceof TetherError ? e.message : (e as Error).message;
      this.pending.markExecuted(actionId, null, msg);
      this.log(c, "high_risk", "error", msg, "error", Date.now() - start, msg, []);
      return { ok: false, status: "executed", actionId, error: msg };
    }
  }

  // ---- read-only meta tools ----

  listDevices(): BridgeResult {
    const devices = Object.entries(this.policy.devices).map(([id, d]) => ({
      deviceId: id,
      description: d.description,
      transport: d.transport.kind,
      tools: Object.entries(d.tools).map(([name, t]) => ({
        name,
        tier: t.tier,
        enabled: t.allow,
      })),
    }));
    return { ok: true, devices };
  }

  async describeDevice(actor: Actor, deviceId: string): Promise<BridgeResult> {
    const dev = this.policy.devices[deviceId];
    if (!dev) return this.err(ErrorCode.NotRegistered, `device '${deviceId}' is not registered`);
    const c = this.ctx(actor, deviceId, "describe_device", {});
    const start = Date.now();
    try {
      const caps = await this.loadCaps(deviceId, dev, true);
      const toolCfgByTarget = dev.tools;
      this.log(c, "read_only", "allow", "describe", "ok", Date.now() - start, null, []);
      return {
        ok: true,
        deviceId,
        firmware: caps.firmware,
        sensors: caps.sensors.filter(
          (s) => !toolCfgByTarget["read_sensor"]?.sensors || toolCfgByTarget["read_sensor"]!.sensors!.includes(s.name),
        ),
        actuators: caps.actuators.filter(
          (a) => !toolCfgByTarget["set_actuator"]?.actuators || toolCfgByTarget["set_actuator"]!.actuators!.includes(a.name),
        ),
      };
    } catch (e) {
      const msg = e instanceof TetherError ? e.message : (e as Error).message;
      this.log(c, "read_only", "error", msg, "error", Date.now() - start, msg, []);
      return this.err(ErrorCode.DeviceUnreachable, msg);
    }
  }

  queryAudit(filter: { deviceId?: string; tool?: string; decision?: string; limit?: number }): BridgeResult {
    return { ok: true, records: this.audit.query(filter) };
  }

  async close(): Promise<void> {
    for (const t of this.transports.values()) await t.close();
  }
}
