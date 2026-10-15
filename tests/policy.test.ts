import { describe, expect, it } from "vitest";
import { PolicySchema } from "../src/config.js";
import { ErrorCode } from "../src/errors.js";
import { PolicyEngine } from "../src/policy.js";
import type { CallContext } from "../src/types.js";

function policyFrom(tools: Record<string, unknown>) {
  return PolicySchema.parse({
    devices: { dev1: { transport: { kind: "http", address: "http://localhost:9" }, tools } },
  });
}

function ctx(deviceId: string, tool: string, args: Record<string, unknown> = {}): CallContext {
  return { requestId: "t", actor: {}, deviceId, tool, args };
}

describe("PolicyEngine — deny by default", () => {
  it("denies an unregistered device", () => {
    const p = new PolicyEngine(policyFrom({}));
    const d = p.decide(ctx("ghost", "read_sensor", { sensor: "temperature" }));
    expect(d.allowed).toBe(false);
    expect(d.errorCode).toBe(ErrorCode.NotRegistered);
  });

  it("denies a tool not listed for the device", () => {
    const p = new PolicyEngine(policyFrom({ read_sensor: { tier: "read_only" } }));
    const d = p.decide(ctx("dev1", "set_actuator", { actuator: "relay1", state: "on" }));
    expect(d.allowed).toBe(false);
    expect(d.errorCode).toBe(ErrorCode.NotRegistered);
  });

  it("denies an explicitly disabled tool", () => {
    const p = new PolicyEngine(policyFrom({ send_raw_command: { allow: false } }));
    const d = p.decide(ctx("dev1", "send_raw_command", { command: "x" }));
    expect(d.allowed).toBe(false);
    expect(d.errorCode).toBe(ErrorCode.PolicyDenied);
  });

  it("enforces the per-sensor allow-list and resolves the tier", () => {
    const p = new PolicyEngine(
      policyFrom({ read_sensor: { tier: "read_only", sensors: ["temperature"] } }),
    );
    expect(p.decide(ctx("dev1", "read_sensor", { sensor: "humidity" })).allowed).toBe(false);
    const ok = p.decide(ctx("dev1", "read_sensor", { sensor: "temperature" }));
    expect(ok.allowed).toBe(true);
    expect(ok.tier).toBe("read_only");
  });

  it("rate-limits per tool", () => {
    const p = new PolicyEngine(
      policyFrom({
        read_sensor: {
          tier: "read_only",
          sensors: ["temperature"],
          rate_limit: { calls: 2, per_seconds: 60 },
        },
      }),
    );
    const c = ctx("dev1", "read_sensor", { sensor: "temperature" });
    expect(p.decide(c).allowed).toBe(true);
    expect(p.decide(c).allowed).toBe(true);
    const third = p.decide(c);
    expect(third.allowed).toBe(false);
    expect(third.errorCode).toBe(ErrorCode.RateLimited);
  });
});
