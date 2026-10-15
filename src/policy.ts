import type { Policy, ToolCfg } from "./config.js";
import { ErrorCode } from "./errors.js";
import type { CallContext, Decision, RiskTier } from "./types.js";
import { SlidingWindow } from "./windows.js";

/**
 * Policy engine (feature #1). Deny-by-default: a device or tool absent from the policy cannot be
 * called. Resolves the risk tier, enforces per-sensor / per-actuator allow-lists, and applies the
 * configured rate ceilings (tightest of global and per-tool). Behavioral abuse detection lives in
 * the anomaly detector (#3); this is the static contract.
 */
export class PolicyEngine {
  private readonly windowsByPeriod = new Map<number, SlidingWindow>();

  constructor(private readonly policy: Policy) {}

  private window(perSeconds: number): SlidingWindow {
    let w = this.windowsByPeriod.get(perSeconds);
    if (!w) {
      w = new SlidingWindow(perSeconds);
      this.windowsByPeriod.set(perSeconds, w);
    }
    return w;
  }

  private deny(code: ErrorCode, reason: string): Decision {
    return { allowed: false, tier: null, reason, errorCode: code };
  }

  decide(ctx: CallContext): Decision {
    const dev = this.policy.devices[ctx.deviceId];
    if (!dev) {
      return this.deny(ErrorCode.NotRegistered, `device '${ctx.deviceId}' is not registered`);
    }
    const tool = dev.tools[ctx.tool];
    if (!tool) {
      return this.deny(
        ErrorCode.NotRegistered,
        `tool '${ctx.tool}' is not enabled for '${ctx.deviceId}'`,
      );
    }
    if (!tool.allow) {
      return this.deny(
        ErrorCode.PolicyDenied,
        `tool '${ctx.tool}' is disabled for '${ctx.deviceId}'`,
      );
    }

    if (ctx.tool === "read_sensor" && tool.sensors) {
      const sensor = String(ctx.args["sensor"] ?? "");
      if (!tool.sensors.includes(sensor)) {
        return this.deny(
          ErrorCode.PolicyDenied,
          `sensor '${sensor}' is not allowed on '${ctx.deviceId}'`,
        );
      }
    }
    if (ctx.tool === "set_actuator" && tool.actuators) {
      const actuator = String(ctx.args["actuator"] ?? "");
      if (!tool.actuators.includes(actuator)) {
        return this.deny(
          ErrorCode.PolicyDenied,
          `actuator '${actuator}' is not allowed on '${ctx.deviceId}'`,
        );
      }
    }

    const rate = this.checkRate(ctx, tool);
    if (!rate.ok) return this.deny(ErrorCode.RateLimited, rate.reason);

    return { allowed: true, tier: tool.tier as RiskTier, reason: `policy_allow:${tool.tier}` };
  }

  private checkRate(ctx: CallContext, tool: ToolCfg): { ok: boolean; reason: string } {
    const limits: Array<{ key: string; calls: number; per: number }> = [];
    const g = this.policy.defaults.rate_limit;
    limits.push({ key: "global", calls: g.calls, per: g.per_seconds });
    if (tool.rate_limit) {
      limits.push({
        key: `${ctx.deviceId}:${ctx.tool}`,
        calls: tool.rate_limit.calls,
        per: tool.rate_limit.per_seconds,
      });
    }

    for (const l of limits) {
      if (this.window(l.per).count(l.key) >= l.calls) {
        return { ok: false, reason: `rate limit exceeded (${l.calls}/${l.per}s on ${l.key})` };
      }
    }
    // Admit the call: consume one slot in each applicable window.
    for (const l of limits) this.window(l.per).record(l.key);
    return { ok: true, reason: "" };
  }
}
