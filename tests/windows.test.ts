import { describe, expect, it } from "vitest";
import { Cooldown, SlidingWindow } from "../src/windows.js";

describe("SlidingWindow", () => {
  it("counts events within the window and prunes old ones", () => {
    const w = new SlidingWindow(1); // 1s = 1000ms
    expect(w.record("k", 0)).toBe(1);
    expect(w.record("k", 100)).toBe(2);
    expect(w.count("k", 1050)).toBe(1); // event at 0 pruned (cutoff 50); event at 100 kept
    expect(w.count("k", 1200)).toBe(0); // both pruned (cutoff 200)
  });

  it("keeps keys independent", () => {
    const w = new SlidingWindow(10);
    w.record("a", 0);
    expect(w.count("b", 0)).toBe(0);
  });

  it("reports wouldExceed against the limit before adding", () => {
    const w = new SlidingWindow(10);
    w.record("k", 0);
    w.record("k", 1);
    expect(w.wouldExceed("k", 2, 2)).toBe(true);
    expect(w.wouldExceed("k", 3, 2)).toBe(false);
  });
});

describe("Cooldown", () => {
  it("stays active until the deadline, then clears", () => {
    const c = new Cooldown();
    c.set("k", 1, 0); // 1s
    expect(c.active("k", 500)).toBe(true);
    expect(c.active("k", 1500)).toBe(false);
  });
});
