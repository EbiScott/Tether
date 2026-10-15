import type { DeviceCfg } from "../config.js";
import type { DeviceCapabilities, RawReading, RawResult } from "../types.js";
import { HttpTransport } from "./http.js";

/**
 * The device transport interface (SPEC.md §5). One interface so the rest of Tether never knows
 * whether a device is reached over HTTP, MQTT, or serial. Everything a transport returns is *raw and
 * untrusted* — the sanitizer (#4) is what makes it safe to hand back to the LLM.
 */
export interface DeviceTransport {
  describe(deviceId: string, dev: DeviceCfg): Promise<DeviceCapabilities>;
  readSensor(deviceId: string, dev: DeviceCfg, sensor: string): Promise<RawReading>;
  setActuator(
    deviceId: string,
    dev: DeviceCfg,
    actuator: string,
    state: string,
  ): Promise<RawResult>;
  rawCommand(deviceId: string, dev: DeviceCfg, command: string): Promise<RawResult>;
  close(): Promise<void>;
}

export function getTransport(kind: string): DeviceTransport {
  switch (kind) {
    case "http":
      return new HttpTransport();
    case "mqtt":
      throw new Error("the MQTT transport is on the roadmap; use kind: http for v1 (SPEC.md §5)");
    default:
      throw new Error(`unknown transport kind: ${kind}`);
  }
}
