/**
 * Sliding-window counters, shared by the rate limiter (#1) and the anomaly detector (#3).
 * Single-threaded by design — the bridge drives these from one event loop.
 */

export class SlidingWindow {
  private readonly windowMs: number;
  private readonly events = new Map<string, number[]>();

  constructor(windowSeconds: number) {
    this.windowMs = windowSeconds * 1000;
  }

  private prune(key: string, now: number): number[] {
    const cutoff = now - this.windowMs;
    const q = this.events.get(key) ?? [];
    let i = 0;
    while (i < q.length && q[i]! < cutoff) i++;
    const kept = i > 0 ? q.slice(i) : q;
    this.events.set(key, kept);
    return kept;
  }

  /** Current event count for `key` within the window. */
  count(key: string, now: number = Date.now()): number {
    return this.prune(key, now).length;
  }

  /** Record one event and return the new in-window count. */
  record(key: string, now: number = Date.now()): number {
    const q = this.prune(key, now);
    q.push(now);
    return q.length;
  }

  /** True if recording one more event would reach or exceed `limit`. */
  wouldExceed(key: string, limit: number, now: number = Date.now()): boolean {
    return this.count(key, now) >= limit;
  }
}

/** Tracks keys temporarily quarantined until a deadline. */
export class Cooldown {
  private readonly until = new Map<string, number>();

  set(key: string, seconds: number, now: number = Date.now()): void {
    this.until.set(key, now + seconds * 1000);
  }

  active(key: string, now: number = Date.now()): boolean {
    const deadline = this.until.get(key);
    if (deadline === undefined) return false;
    if (now >= deadline) {
      this.until.delete(key);
      return false;
    }
    return true;
  }

  remainingSeconds(key: string, now: number = Date.now()): number {
    const deadline = this.until.get(key);
    if (deadline === undefined) return 0;
    return Math.max(0, (deadline - now) / 1000);
  }
}
