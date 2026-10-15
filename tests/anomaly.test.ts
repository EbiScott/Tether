import { describe, expect, it } from "vitest";
import { AnomalyDetector } from "../src/anomaly.js";
import type { AnomalyCfg } from "../src/config.js";
import type { CallContext } from "../src/types.js";

function cfg(over: Partial<AnomalyCfg> = {}): AnomalyCfg {
  return {
    repetition: { max_identical: 100, per_seconds: 30 },
    denial_burst: { max_denials: 3, per_seconds: 60, cooldown_seconds: 120 },
    escalation: { max_high_risk_attempts: 100, per_seconds: 60 },
    ...over,
  } as AnomalyCfg;
}

function ctx(args: Record<string, unknown> = {}): CallContext {
  return { requestId: "t", actor: {}, deviceId: "dev1", tool: "read_sensor", args };
}

describe("AnomalyDetector", () => {
  it("blocks identical calls repeated past the threshold", () => {
    const a = new AnomalyDetector(cfg({ repetition: { max_identical: 3, per_seconds: 30 } }));
    const c = ctx({ sensor: "temperature" });
    expect(a.check(c, "read_only").allowed).toBe(true);
    expect(a.check(c, "read_only").allowed).toBe(true);
    const third = a.check(c, "read_only");
    expect(third.allowed).toBe(false);
    expect(third.flags).toContain("anomaly:repetition");
  });

  it("quarantines a tool after a burst of denials", () => {
    const a = new AnomalyDetector(cfg());
    const c = ctx();
    a.recordDenial(c);
    a.recordDenial(c);
    expect(a.recordDenial(c)).toContain("anomaly:denial_burst");
    const blocked = a.check(c, "read_only");
    expect(blocked.allowed).toBe(false);
    expect(blocked.flags).toContain("anomaly:quarantined");
  });

  it("flags high-risk escalation as an alert without blocking", () => {
    const a = new AnomalyDetector(cfg({ escalation: { max_high_risk_attempts: 2, per_seconds: 60 } }));
    expect(a.check(ctx({ n: 1 }), "high_risk").flags).not.toContain("anomaly:escalation");
    const second = a.check(ctx({ n: 2 }), "high_risk");
    expect(second.allowed).toBe(true);
    expect(second.flags).toContain("anomaly:escalation");
  });
});
