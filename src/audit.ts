import { appendFileSync } from "node:fs";
import type { Actor, RiskTier } from "./types.js";

/**
 * Audit log (feature #5): append-only JSONL, written for *every* call attempt — allow, deny,
 * pending, or error. It wraps the whole pipeline rather than being a final step a failure can skip.
 * `args` are expected to arrive already sanitized and secret-redacted by the bridge.
 *
 * Roadmap: per-line hash chaining for tamper-evidence (threat model §6).
 */

export type DecisionKind = "allow" | "deny" | "pending" | "error";
export type ResultStatus = "ok" | "error" | "pending" | "denied";

export interface AuditRecord {
  ts: string;
  requestId: string;
  actor: Actor;
  deviceId: string;
  tool: string;
  args: Record<string, unknown>;
  tier: RiskTier | null;
  decision: DecisionKind;
  reason: string;
  anomalyFlags: string[];
  resultStatus: ResultStatus;
  latencyMs: number;
  error: string | null;
}

const MEM_CAP = 1000;

export class AuditLog {
  private readonly mem: AuditRecord[] = [];

  /** @param path JSONL file to append to; null keeps records in memory only (tests). */
  constructor(private readonly path: string | null = null) {}

  write(rec: AuditRecord): void {
    this.mem.push(rec);
    if (this.mem.length > MEM_CAP) this.mem.shift();
    if (this.path) {
      try {
        appendFileSync(this.path, JSON.stringify(rec) + "\n");
      } catch (e) {
        console.error(`[audit] failed to persist record: ${(e as Error).message}`);
      }
    }
  }

  query(
    filter: { deviceId?: string; tool?: string; decision?: string; limit?: number } = {},
  ): AuditRecord[] {
    let rows: AuditRecord[] = this.mem;
    if (filter.deviceId) rows = rows.filter((r) => r.deviceId === filter.deviceId);
    if (filter.tool) rows = rows.filter((r) => r.tool === filter.tool);
    if (filter.decision) rows = rows.filter((r) => r.decision === filter.decision);
    const limit = filter.limit ?? 50;
    return rows.slice(-limit).reverse(); // most recent first
  }
}
