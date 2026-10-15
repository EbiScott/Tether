import type { AnomalyCfg } from "./config.js";
import type { CallContext, RiskTier } from "./types.js";
import { Cooldown, SlidingWindow } from "./windows.js";

/**
 * Anomaly detector (feature #3). Watches the live call stream for abuse that the static policy can't
 * see: identical calls hammered in a loop, bursts of denials that look like probing, and repeated
 * attempts at high-risk tools. Responses escalate — flag (log only) -> throttle (deny this call) ->
 * quarantine (temporary cooldown of the device/tool).
 */

export interface AnomalyResult {
  allowed: boolean;
  reason: string;
  flags: string[];
}

function stableArgs(args: Record<string, unknown>): string {
  return JSON.stringify(args, Object.keys(args).sort());
}

export class AnomalyDetector {
  private readonly repetition: SlidingWindow;
  private readonly denials: SlidingWindow;
  private readonly escalation: SlidingWindow;
  private readonly cooldown = new Cooldown();

  constructor(private readonly cfg: AnomalyCfg) {
    this.repetition = new SlidingWindow(cfg.repetition.per_seconds);
    this.denials = new SlidingWindow(cfg.denial_burst.per_seconds);
    this.escalation = new SlidingWindow(cfg.escalation.per_seconds);
  }

  /** Pre-execution behavioral check, run after the policy has allowed the call. */
  check(ctx: CallContext, tier: RiskTier): AnomalyResult {
    const toolKey = `${ctx.deviceId}:${ctx.tool}`;
    const flags: string[] = [];

    if (this.cooldown.active(toolKey)) {
      const secs = Math.ceil(this.cooldown.remainingSeconds(toolKey));
      return {
        allowed: false,
        reason: `quarantined for ~${secs}s after a burst of denials`,
        flags: ["anomaly:quarantined"],
      };
    }

    const repCount = this.repetition.record(`${toolKey}:${stableArgs(ctx.args)}`);
    if (repCount >= this.cfg.repetition.max_identical) {
      return {
        allowed: false,
        reason: `identical call repeated ${repCount}x within ${this.cfg.repetition.per_seconds}s (runaway loop?)`,
        flags: ["anomaly:repetition"],
      };
    }

    if (tier === "high_risk") {
      const escCount = this.escalation.record(`${ctx.deviceId}:high_risk`);
      if (escCount >= this.cfg.escalation.max_high_risk_attempts) {
        flags.push("anomaly:escalation"); // alert only — the confirmation queue already gates these
      }
    }

    return { allowed: true, reason: "", flags };
  }

  /** Feed a denial into the burst detector; may quarantine the tool. Returns any flags raised. */
  recordDenial(ctx: CallContext): string[] {
    const toolKey = `${ctx.deviceId}:${ctx.tool}`;
    const count = this.denials.record(toolKey);
    if (count >= this.cfg.denial_burst.max_denials) {
      this.cooldown.set(toolKey, this.cfg.denial_burst.cooldown_seconds);
      return ["anomaly:denial_burst"];
    }
    return [];
  }
}
