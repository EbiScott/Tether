import type { ErrorCode } from "./errors.js";

/**
 * Runtime types shared across the pipeline. Kept dependency-light so config, transports, policy,
 * sanitizer and audit can all import from here without a cycle.
 */

export type RiskTier = "read_only" | "low_risk" | "high_risk";

// ---- device capability description (what a device says it can do) ----

export interface SensorSpec {
  name: string;
  type: "number" | "string" | "bool";
  unit?: string;
  min?: number; // declared valid range for numeric sensors
  max?: number;
}

export interface ActuatorSpec {
  name: string;
  states: string[]; // e.g. ["on","off"]; empty = free-form
}

export interface DeviceCapabilities {
  deviceId: string;
  sensors: SensorSpec[];
  actuators: ActuatorSpec[];
  firmware?: string;
}

// ---- raw transport results (untrusted until the sanitizer has seen them) ----

export interface RawReading {
  value: unknown;
  unit?: string;
}

export interface RawResult {
  ok: boolean;
  data: Record<string, unknown>;
  text?: string;
}

// ---- a policy decision about a single call ----

export interface Decision {
  allowed: boolean;
  tier: RiskTier | null;
  reason: string;
  errorCode?: ErrorCode;
}

/** Identity of the caller, as far as the MCP layer can tell. Best-effort, never trusted. */
export interface Actor {
  host?: string;
  session?: string;
}

/** A call request as it enters the pipeline. */
export interface CallContext {
  requestId: string;
  actor: Actor;
  deviceId: string;
  tool: string;
  args: Record<string, unknown>;
}
