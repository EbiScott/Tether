import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

/**
 * Pending high-risk actions (feature #2, the confirmation queue). File-backed JSON so a *separate*
 * `tether approve` operator process can read and update the same queue the server writes to. This is
 * the server-side half of human-in-the-loop: Tether never trusts the MCP client to have asked a
 * human, so a high-risk action waits here until an operator approves it out-of-band.
 */

export type PendingStatus = "pending" | "approved" | "denied" | "executed";

export interface PendingAction {
  actionId: string;
  deviceId: string;
  tool: string;
  args: Record<string, unknown>;
  requestedAt: string;
  expiresAt: string;
  status: PendingStatus;
  result?: unknown;
  resultError?: string | null;
}

export class PendingStore {
  constructor(private readonly path: string = "pending_actions.json") {}

  private load(): Record<string, PendingAction> {
    if (!existsSync(this.path)) return {};
    try {
      return JSON.parse(readFileSync(this.path, "utf8")) as Record<string, PendingAction>;
    } catch {
      return {};
    }
  }

  private save(all: Record<string, PendingAction>): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(all, null, 2));
    renameSync(tmp, this.path); // atomic replace so the operator CLI never reads a half-written file
  }

  /** Flip any pending action past its expiry to denied/expired. Returns whether anything changed. */
  private expireStale(all: Record<string, PendingAction>): boolean {
    const now = Date.now();
    let changed = false;
    for (const a of Object.values(all)) {
      if (a.status === "pending" && Date.parse(a.expiresAt) < now) {
        a.status = "denied";
        a.resultError = "expired";
        changed = true;
      }
    }
    return changed;
  }

  private loadFresh(): Record<string, PendingAction> {
    const all = this.load();
    if (this.expireStale(all)) this.save(all);
    return all;
  }

  create(
    deviceId: string,
    tool: string,
    args: Record<string, unknown>,
    expirySeconds: number,
  ): PendingAction {
    const all = this.loadFresh();
    const now = Date.now();
    const action: PendingAction = {
      actionId: randomUUID().slice(0, 8),
      deviceId,
      tool,
      args,
      requestedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + expirySeconds * 1000).toISOString(),
      status: "pending",
    };
    all[action.actionId] = action;
    this.save(all);
    return action;
  }

  get(actionId: string): PendingAction | null {
    return this.loadFresh()[actionId] ?? null;
  }

  list(): PendingAction[] {
    return Object.values(this.loadFresh()).sort((a, b) =>
      a.requestedAt < b.requestedAt ? 1 : -1,
    );
  }

  approve(actionId: string): PendingAction | null {
    const all = this.loadFresh();
    const a = all[actionId];
    if (!a) return null;
    if (a.status === "pending") {
      a.status = "approved";
      this.save(all);
    }
    return a;
  }

  deny(actionId: string): PendingAction | null {
    const all = this.loadFresh();
    const a = all[actionId];
    if (!a) return null;
    if (a.status === "pending") {
      a.status = "denied";
      a.resultError = "operator_denied";
      this.save(all);
    }
    return a;
  }

  markExecuted(actionId: string, result: unknown, error: string | null): PendingAction | null {
    const all = this.loadFresh();
    const a = all[actionId];
    if (!a) return null;
    a.status = "executed";
    a.result = result;
    a.resultError = error;
    this.save(all);
    return a;
  }
}
