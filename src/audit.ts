import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import type { Actor, RiskTier } from "./types.js";

/**
 * Audit log (feature #5): append-only JSONL, written for *every* call attempt — allow, deny,
 * pending, or error. It wraps the whole pipeline rather than being a final step a failure can skip.
 *
 * Tamper-evidence (threat model §6): records form a hash chain. Each record carries a `seq`, the
 * previous record's `hash` (`prevHash`), and its own `hash` = SHA-256 over its content (including
 * seq + prevHash). Editing, reordering, or dropping any record breaks the chain from that point on,
 * which `verifyChain` detects. The chain is seeded from the existing file on startup so it survives
 * restarts. `args` are expected to arrive already sanitized and secret-redacted by the bridge.
 */

export type DecisionKind = "allow" | "deny" | "pending" | "error";
export type ResultStatus = "ok" | "error" | "pending" | "denied";

export interface AuditRecord {
  seq: number;
  prevHash: string;
  hash: string;
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

/** What a caller supplies; the log fills in the chain fields (seq, prevHash, hash). */
export type AuditInput = Omit<AuditRecord, "seq" | "prevHash" | "hash">;

export const GENESIS_HASH = "0".repeat(64);

const MEM_CAP = 1000;

/** Deterministic JSON (recursively sorted keys) so a record always hashes identically. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
}

function hashRecord(recordWithoutHash: Omit<AuditRecord, "hash">): string {
  return createHash("sha256").update(stableStringify(recordWithoutHash)).digest("hex");
}

export class AuditLog {
  private readonly mem: AuditRecord[] = [];
  private lastHash = GENESIS_HASH;
  private seq = 0;

  /** @param path JSONL file to append to; null keeps records in memory only (tests). */
  constructor(private readonly path: string | null = null) {
    if (path && existsSync(path)) this.seed(path);
  }

  /** Resume the chain from the last record already on disk. */
  private seed(path: string): void {
    try {
      const lines = readFileSync(path, "utf8").trim().split("\n").filter(Boolean);
      if (lines.length === 0) return;
      const last = JSON.parse(lines[lines.length - 1]!) as AuditRecord;
      if (typeof last.seq === "number" && typeof last.hash === "string") {
        this.seq = last.seq;
        this.lastHash = last.hash;
      }
    } catch {
      // corrupt/partial tail — leave the chain at genesis rather than crash
    }
  }

  write(input: AuditInput): AuditRecord {
    const withoutHash: Omit<AuditRecord, "hash"> = {
      seq: ++this.seq,
      prevHash: this.lastHash,
      ...input,
    };
    const record: AuditRecord = { ...withoutHash, hash: hashRecord(withoutHash) };
    this.lastHash = record.hash;

    this.mem.push(record);
    if (this.mem.length > MEM_CAP) this.mem.shift();
    if (this.path) {
      try {
        appendFileSync(this.path, JSON.stringify(record) + "\n");
      } catch (e) {
        console.error(`[audit] failed to persist record: ${(e as Error).message}`);
      }
    }
    return record;
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

/**
 * Verify a set of audit records form an intact hash chain. Order-independent (sorts by seq).
 * Returns the seq of the first record whose content hash or back-link doesn't check out.
 */
export function verifyChain(records: AuditRecord[]): { ok: boolean; brokenAt?: number } {
  const sorted = [...records].sort((a, b) => a.seq - b.seq);
  let prev = GENESIS_HASH;
  for (const r of sorted) {
    const { hash, ...withoutHash } = r;
    if (hashRecord(withoutHash) !== hash) return { ok: false, brokenAt: r.seq };
    if (r.prevHash !== prev) return { ok: false, brokenAt: r.seq };
    prev = hash;
  }
  return { ok: true };
}
