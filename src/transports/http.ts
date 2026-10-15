import { resolveToken, type DeviceCfg } from "../config.js";
import { ErrorCode, TetherError } from "../errors.js";
import type {
  ActuatorSpec,
  DeviceCapabilities,
  RawReading,
  RawResult,
  SensorSpec,
} from "../types.js";
import type { DeviceTransport } from "./base.js";

const DEFAULT_TIMEOUT_MS = 4000;

/**
 * HTTP device transport. Maps the generic transport interface onto a device's small REST surface
 * (the one the mock ESP32 implements, and the shape a real Tasmota/ESP-AT board can be adapted to).
 * Attaches the per-device bearer token on every request; translates network/auth failures into
 * stable TetherError codes. Device payloads are typed loosely on purpose — they are untrusted, and
 * the sanitizer (#4) validates them before anything reaches the LLM.
 */
export class HttpTransport implements DeviceTransport {
  constructor(private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS) {}

  private base(dev: DeviceCfg): string {
    return dev.transport.address.replace(/\/+$/, "");
  }

  private headers(dev: DeviceCfg, json: boolean): Record<string, string> {
    const token = resolveToken(dev.transport.auth);
    const h: Record<string, string> = {};
    if (token) h["Authorization"] = `Bearer ${token}`;
    if (json) h["Content-Type"] = "application/json";
    return h;
  }

  private async request(
    method: string,
    url: string,
    dev: DeviceCfg,
    body?: unknown,
  ): Promise<Record<string, unknown>> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await fetch(url, {
        method,
        headers: this.headers(dev, body !== undefined),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
    } catch (e) {
      throw new TetherError(
        ErrorCode.DeviceUnreachable,
        `could not reach device: ${(e as Error).message}`,
      );
    } finally {
      clearTimeout(timer);
    }

    if (resp.status === 401 || resp.status === 403) {
      throw new TetherError(ErrorCode.DeviceAuthFailed, "device rejected our credentials");
    }
    if (!resp.ok) {
      throw new TetherError(ErrorCode.DeviceUnreachable, `device returned HTTP ${resp.status}`);
    }
    return (await resp.json()) as Record<string, unknown>;
  }

  async describe(deviceId: string, dev: DeviceCfg): Promise<DeviceCapabilities> {
    const d = await this.request("GET", `${this.base(dev)}/describe`, dev);
    const sensors: SensorSpec[] = ((d["sensors"] as any[]) ?? []).map((s) => ({
      name: String(s.name),
      type: s.type ?? "number",
      unit: s.unit,
      min: s.min,
      max: s.max,
    }));
    const actuators: ActuatorSpec[] = ((d["actuators"] as any[]) ?? []).map((a) => ({
      name: String(a.name),
      states: a.states ?? [],
    }));
    return {
      deviceId,
      sensors,
      actuators,
      firmware: d["firmware"] as string | undefined,
    };
  }

  async readSensor(deviceId: string, dev: DeviceCfg, sensor: string): Promise<RawReading> {
    const d = await this.request(
      "GET",
      `${this.base(dev)}/sensor/${encodeURIComponent(sensor)}`,
      dev,
    );
    return { value: d["value"], unit: d["unit"] as string | undefined };
  }

  async setActuator(
    deviceId: string,
    dev: DeviceCfg,
    actuator: string,
    state: string,
  ): Promise<RawResult> {
    const d = await this.request(
      "POST",
      `${this.base(dev)}/actuator/${encodeURIComponent(actuator)}`,
      dev,
      { state },
    );
    return { ok: d["ok"] !== false, data: d };
  }

  async rawCommand(deviceId: string, dev: DeviceCfg, command: string): Promise<RawResult> {
    const d = await this.request("POST", `${this.base(dev)}/cmd`, dev, { command });
    return { ok: d["ok"] !== false, data: d, text: d["response"] as string | undefined };
  }

  async close(): Promise<void> {
    // global fetch keeps no pool we own; nothing to close.
  }
}
