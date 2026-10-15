import { ErrorCode, TetherError } from "./errors.js";
import type { RawReading, SensorSpec } from "./types.js";

/**
 * Sanitizer (feature #4). Everything crossing device -> bridge -> LLM passes through here first.
 * The defence is *structural*, not a blocklist of magic phrases: numeric readings are type- and
 * range-checked, control characters and ANSI escapes are stripped, strings are length-capped, and
 * free text is wrapped in a clearly-delimited "untrusted data" block so the model reads it as data,
 * never as instructions. This is what stops a compromised/spoofed device from prompt-injecting the
 * model (threat model T4).
 */

const MAX_FIELD_LEN = 512;
const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/g;

export interface SanitizedReading {
  value: unknown;
  unit?: string;
  flags: string[];
}

export interface SanitizedText {
  text: string;
  flags: string[];
}

export class Sanitizer {
  private clean(s: string): { out: string; changed: boolean; truncated: boolean } {
    let out = s.replace(ANSI, "").replace(CONTROL, " ");
    const changed = out !== s;
    let truncated = false;
    if (out.length > MAX_FIELD_LEN) {
      out = out.slice(0, MAX_FIELD_LEN) + " …[truncated]";
      truncated = true;
    }
    return { out, changed, truncated };
  }

  wrapUntrusted(deviceId: string, field: string, text: string): string {
    return `<untrusted-device-data device="${deviceId}" field="${field}">\n${text}\n</untrusted-device-data>`;
  }

  /** Validate + neutralize a sensor reading against its declared spec. Throws on hard rejects. */
  sanitizeReading(
    deviceId: string,
    spec: SensorSpec | undefined,
    reading: RawReading,
  ): SanitizedReading {
    const flags: string[] = [];

    let unit = reading.unit;
    if (typeof unit === "string") {
      const u = this.clean(unit);
      if (u.changed) flags.push("sanitizer:unit_neutralized");
      unit = u.out;
    }

    const type = spec?.type ?? "number";

    if (type === "number") {
      const n = typeof reading.value === "number" ? reading.value : Number(reading.value);
      if (!Number.isFinite(n)) {
        throw new TetherError(
          ErrorCode.SanitizerRejected,
          `sensor value is not a finite number (got ${JSON.stringify(reading.value)})`,
        );
      }
      if (spec?.min !== undefined && n < spec.min) {
        throw new TetherError(
          ErrorCode.SanitizerRejected,
          `value ${n} is below declared min ${spec.min} [sanitizer:out_of_range]`,
        );
      }
      if (spec?.max !== undefined && n > spec.max) {
        throw new TetherError(
          ErrorCode.SanitizerRejected,
          `value ${n} is above declared max ${spec.max} [sanitizer:out_of_range]`,
        );
      }
      return { value: n, unit, flags };
    }

    if (type === "bool") {
      return { value: Boolean(reading.value), unit, flags };
    }

    // string sensor: neutralize and wrap as untrusted data
    const s = this.clean(String(reading.value));
    if (s.changed) flags.push("sanitizer:neutralized_text");
    if (s.truncated) flags.push("sanitizer:truncated");
    return { value: this.wrapUntrusted(deviceId, spec?.name ?? "value", s.out), unit, flags };
  }

  /** Neutralize and wrap an arbitrary device text field (e.g. a raw-command response). */
  sanitizeText(deviceId: string, field: string, text: string): SanitizedText {
    const s = this.clean(text);
    const flags: string[] = [];
    if (s.changed) flags.push("sanitizer:neutralized_text");
    if (s.truncated) flags.push("sanitizer:truncated");
    return { text: this.wrapUntrusted(deviceId, field, s.out), flags };
  }
}
