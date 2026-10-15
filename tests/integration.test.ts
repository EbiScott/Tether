import { randomUUID } from "node:crypto";
import { existsSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Bridge } from "../src/bridge.js";
import { PolicySchema } from "../src/config.js";
import { PendingStore } from "../src/pending.js";
import { buildServer } from "../src/sim/mockEsp32.js";

/**
 * Integration test: drives a real Bridge (real HttpTransport, real sockets) against the mock ESP32
 * running in-process. This covers the wire path that the unit tests deliberately stub with a fake
 * transport — HTTP, bearer auth, and the sanitizer acting on genuinely remote bytes.
 */

const TOKEN = "it-token";
process.env["TETHER_LAB_ESP01_TOKEN"] = TOKEN; // resolveToken reads this at call time

function listen(server: Server): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)),
  );
}

function policyFor(port: number) {
  return PolicySchema.parse({
    devices: {
      lab: {
        transport: {
          kind: "http",
          address: `http://127.0.0.1:${port}`,
          auth: { type: "bearer", token_env: "TETHER_LAB_ESP01_TOKEN" },
        },
        tools: {
          read_sensor: { tier: "read_only", sensors: ["temperature", "status"] },
          set_actuator: { tier: "high_risk", actuators: ["relay1"] },
        },
      },
    },
  });
}

let good: Server;
let evil: Server;
let goodBridge: Bridge;
let evilBridge: Bridge;
let pendingPath = "";
const actor = { host: "it" };

beforeAll(async () => {
  good = buildServer(TOKEN, false);
  evil = buildServer(TOKEN, true);
  const goodPort = await listen(good);
  const evilPort = await listen(evil);
  pendingPath = join(tmpdir(), `tether-it-${randomUUID()}.json`);
  goodBridge = new Bridge(policyFor(goodPort), { auditPath: null, pendingPath });
  evilBridge = new Bridge(policyFor(evilPort), { auditPath: null, pendingPath });
});

afterAll(async () => {
  await new Promise<void>((r) => good.close(() => r()));
  await new Promise<void>((r) => evil.close(() => r()));
  await goodBridge.close();
  await evilBridge.close();
  if (pendingPath && existsSync(pendingPath)) rmSync(pendingPath);
});

describe("integration: real HTTP transport against the mock ESP32", () => {
  it("reads a live, sanitized sensor value over HTTP", async () => {
    const r = await goodBridge.runDeviceTool(actor, "lab", "read_sensor", { sensor: "temperature" });
    expect(r["ok"]).toBe(true);
    expect(typeof r["value"]).toBe("number");
  });

  it("queues a high-risk actuator and executes it over HTTP only after approval", async () => {
    const queued = await goodBridge.runDeviceTool(actor, "lab", "set_actuator", {
      actuator: "relay1",
      state: "on",
    });
    expect(queued["status"]).toBe("pending_confirmation");

    new PendingStore(pendingPath).approve(String(queued["actionId"]));

    const done = await goodBridge.checkAction(actor, String(queued["actionId"]));
    expect(done["status"]).toBe("executed");
    expect((done["result"] as Record<string, unknown>)["state"]).toBe("on");
  });

  it("rejects a hostile device's out-of-range + injected reading", async () => {
    const r = await evilBridge.runDeviceTool(actor, "lab", "read_sensor", { sensor: "temperature" });
    expect(r["ok"]).toBe(false);
    expect(r["error"]).toBe("sanitizer_rejected");
  });
});
