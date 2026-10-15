import { randomUUID } from "node:crypto";
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Bridge } from "../src/bridge.js";
import type { DeviceCfg } from "../src/config.js";
import { PolicySchema } from "../src/config.js";
import { PendingStore } from "../src/pending.js";
import type { DeviceTransport } from "../src/transports/base.js";
import type { DeviceCapabilities, RawReading, RawResult } from "../src/types.js";

/** A fake device so the pipeline is exercised with no network. */
class FakeTransport implements DeviceTransport {
  actuatorCalls: Array<{ actuator: string; state: string }> = [];
  constructor(private readonly evil = false) {}

  async describe(deviceId: string): Promise<DeviceCapabilities> {
    return {
      deviceId,
      firmware: "fake",
      sensors: [
        { name: "temperature", type: "number", unit: "C", min: -20, max: 60 },
        { name: "status", type: "string" },
      ],
      actuators: [{ name: "relay1", states: ["on", "off"] }],
    };
  }
  async readSensor(_id: string, _dev: DeviceCfg, sensor: string): Promise<RawReading> {
    if (this.evil && sensor === "temperature") return { value: 999, unit: "C\x1b[31m" };
    if (sensor === "temperature") return { value: 22.5, unit: "C" };
    return { value: "ok" };
  }
  async setActuator(
    _id: string,
    _dev: DeviceCfg,
    actuator: string,
    state: string,
  ): Promise<RawResult> {
    this.actuatorCalls.push({ actuator, state });
    return { ok: true, data: { ok: true, state } };
  }
  async rawCommand(): Promise<RawResult> {
    return { ok: true, data: {}, text: "resp" };
  }
  async close(): Promise<void> {}
}

function policy() {
  return PolicySchema.parse({
    devices: {
      lab: {
        transport: { kind: "http", address: "http://localhost:9" },
        tools: {
          read_sensor: { tier: "read_only", sensors: ["temperature", "status"] },
          set_actuator: { tier: "high_risk", actuators: ["relay1"] },
          send_raw_command: { allow: false },
        },
      },
    },
  });
}

let pendingPath = "";
afterEach(() => {
  if (pendingPath && existsSync(pendingPath)) rmSync(pendingPath);
});
function freshPending() {
  pendingPath = join(tmpdir(), `tether-pending-${randomUUID()}.json`);
  return pendingPath;
}

const actor = { host: "test" };

describe("Bridge pipeline", () => {
  it("reads an allowed sensor", async () => {
    const bridge = new Bridge(policy(), {
      auditPath: null,
      pendingPath: freshPending(),
      transportFactory: () => new FakeTransport(),
    });
    const r = await bridge.runDeviceTool(actor, "lab", "read_sensor", { sensor: "temperature" });
    expect(r["ok"]).toBe(true);
    expect(r["value"]).toBe(22.5);
  });

  it("denies an unregistered device (deny-by-default)", async () => {
    const bridge = new Bridge(policy(), {
      auditPath: null,
      pendingPath: freshPending(),
      transportFactory: () => new FakeTransport(),
    });
    const r = await bridge.runDeviceTool(actor, "ghost", "read_sensor", { sensor: "temperature" });
    expect(r["ok"]).toBe(false);
    expect(r["error"]).toBe("not_registered");
  });

  it("blocks a disabled raw command", async () => {
    const bridge = new Bridge(policy(), {
      auditPath: null,
      pendingPath: freshPending(),
      transportFactory: () => new FakeTransport(),
    });
    const r = await bridge.runDeviceTool(actor, "lab", "send_raw_command", { command: "reboot" });
    expect(r["ok"]).toBe(false);
    expect(r["error"]).toBe("policy_denied");
  });

  it("queues a high-risk actuator call and executes it only after approval", async () => {
    const fake = new FakeTransport();
    const path = freshPending();
    const bridge = new Bridge(policy(), {
      auditPath: null,
      pendingPath: path,
      transportFactory: () => fake,
    });

    const queued = await bridge.runDeviceTool(actor, "lab", "set_actuator", {
      actuator: "relay1",
      state: "on",
    });
    expect(queued["status"]).toBe("pending_confirmation");
    expect(fake.actuatorCalls).toHaveLength(0); // NOT executed yet

    // operator approves out-of-band through the shared queue file
    new PendingStore(path).approve(String(queued["actionId"]));

    const done = await bridge.checkAction(actor, String(queued["actionId"]));
    expect(done["status"]).toBe("executed");
    expect(fake.actuatorCalls).toEqual([{ actuator: "relay1", state: "on" }]);
  });

  it("rejects a malicious out-of-range reading via the sanitizer", async () => {
    const bridge = new Bridge(policy(), {
      auditPath: null,
      pendingPath: freshPending(),
      transportFactory: () => new FakeTransport(true),
    });
    const r = await bridge.runDeviceTool(actor, "lab", "read_sensor", { sensor: "temperature" });
    expect(r["ok"]).toBe(false);
    expect(r["error"]).toBe("sanitizer_rejected");
  });
});
