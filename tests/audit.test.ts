import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditLog, verifyChain, type AuditInput } from "../src/audit.js";

function input(over: Partial<AuditInput> = {}): AuditInput {
  return {
    ts: new Date().toISOString(),
    requestId: "r",
    actor: { host: "test" },
    deviceId: "dev1",
    tool: "read_sensor",
    args: { sensor: "temperature" },
    tier: "read_only",
    decision: "allow",
    reason: "ok",
    anomalyFlags: [],
    resultStatus: "ok",
    latencyMs: 1,
    error: null,
    ...over,
  };
}

describe("AuditLog hash chaining", () => {
  it("assigns incrementing seq and links each record to the previous hash", () => {
    const log = new AuditLog();
    const a = log.write(input());
    const b = log.write(input({ tool: "set_actuator" }));
    expect(a.seq).toBe(1);
    expect(b.seq).toBe(2);
    expect(b.prevHash).toBe(a.hash);
    expect(a.hash).not.toBe(b.hash);
    expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifies an untampered chain", () => {
    const log = new AuditLog();
    log.write(input());
    log.write(input({ decision: "deny" }));
    log.write(input({ tool: "set_actuator" }));
    expect(verifyChain(log.query()).ok).toBe(true);
  });

  it("detects a tampered record and reports where the chain breaks", () => {
    const log = new AuditLog();
    log.write(input());
    log.write(input({ decision: "allow" }));
    log.write(input({ tool: "set_actuator" }));
    const records = log.query(); // any order; verifyChain sorts by seq
    const tampered = records.map((r) => (r.seq === 2 ? { ...r, decision: "deny" as const } : r));
    const res = verifyChain(tampered);
    expect(res.ok).toBe(false);
    expect(res.brokenAt).toBe(2);
  });

  it("continues the chain across a restart (seeded from the file)", () => {
    const path = join(tmpdir(), `tether-audit-${randomUUID()}.jsonl`);
    try {
      const log1 = new AuditLog(path);
      log1.write(input());
      log1.write(input({ tool: "set_actuator" }));

      const log2 = new AuditLog(path); // "restart" — must seed seq + lastHash from the file
      const c = log2.write(input({ decision: "deny" }));
      expect(c.seq).toBe(3);

      const all = readFileSync(path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(all).toHaveLength(3);
      expect(all[2].prevHash).toBe(all[1].hash);
      expect(verifyChain(all).ok).toBe(true);
    } finally {
      if (existsSync(path)) rmSync(path);
    }
  });
});
