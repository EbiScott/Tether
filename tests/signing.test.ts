import { describe, expect, it } from "vitest";
import {
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  NonceCache,
  canonicalRequest,
  signRequest,
  verifySignature,
  type SignInput,
} from "../src/signing.js";

const SECRET = "dev-secret";
const NOW = 1_700_000_000; // fixed unix seconds

function input(over: Partial<SignInput> = {}): SignInput {
  return {
    method: "GET",
    path: "/sensor/temperature",
    body: "",
    timestamp: NOW,
    nonce: "nonce-1",
    ...over,
  };
}

describe("canonicalRequest", () => {
  it("is method, path, timestamp, nonce, and a body hash, newline-separated", () => {
    const lines = canonicalRequest(input()).split("\n");
    expect(lines).toHaveLength(5);
    expect(lines[0]).toBe("GET");
    expect(lines[1]).toBe("/sensor/temperature");
    expect(lines[2]).toBe(String(NOW));
    expect(lines[3]).toBe("nonce-1");
    expect(lines[4]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("upper-cases the method so `get` and `GET` sign identically", () => {
    expect(canonicalRequest(input({ method: "get" }))).toBe(canonicalRequest(input()));
  });

  it("changes when the body changes", () => {
    expect(canonicalRequest(input({ body: "{}" }))).not.toBe(canonicalRequest(input({ body: "" })));
  });
});

describe("signRequest / verifySignature", () => {
  it("is deterministic for identical inputs", () => {
    expect(signRequest(SECRET, input())).toEqual(signRequest(SECRET, input()));
  });

  it("produces a 64-hex signature plus timestamp and nonce headers", () => {
    const h = signRequest(SECRET, input());
    expect(h[HEADER_SIGNATURE]).toMatch(/^[0-9a-f]{64}$/);
    expect(h[HEADER_TIMESTAMP]).toBe(String(NOW));
    expect(h[HEADER_NONCE]).toBe("nonce-1");
  });

  it("changes when path, method, or secret changes", () => {
    const base = signRequest(SECRET, input())[HEADER_SIGNATURE];
    expect(signRequest(SECRET, input({ path: "/actuator/relay1" }))[HEADER_SIGNATURE]).not.toBe(base);
    expect(signRequest(SECRET, input({ method: "POST" }))[HEADER_SIGNATURE]).not.toBe(base);
    expect(signRequest("other-secret", input())[HEADER_SIGNATURE]).not.toBe(base);
  });

  it("accepts a validly signed request", () => {
    const headers = signRequest(SECRET, input());
    const res = verifySignature(SECRET, input(), headers, { now: NOW });
    expect(res.ok).toBe(true);
  });

  it("rejects the wrong secret", () => {
    const headers = signRequest("wrong", input());
    const res = verifySignature(SECRET, input(), headers, { now: NOW });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/signature/);
  });

  it("rejects a tampered body", () => {
    const headers = signRequest(SECRET, input({ method: "POST", body: '{"state":"off"}' }));
    const res = verifySignature(
      SECRET,
      input({ method: "POST", body: '{"state":"on"}' }),
      headers,
      { now: NOW },
    );
    expect(res.ok).toBe(false);
  });

  it("rejects a malformed signature without throwing", () => {
    const headers = signRequest(SECRET, input());
    const res = verifySignature(
      SECRET,
      input(),
      { ...headers, [HEADER_SIGNATURE]: "zzz" },
      { now: NOW },
    );
    expect(res.ok).toBe(false);
  });

  it("rejects a stale timestamp outside the skew window", () => {
    const headers = signRequest(SECRET, input());
    const res = verifySignature(SECRET, input(), headers, { now: NOW + 120, skewSeconds: 60 });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/timestamp/);
  });

  it("rejects a timestamp too far in the future", () => {
    const headers = signRequest(SECRET, input({ timestamp: NOW + 120 }));
    const res = verifySignature(SECRET, input({ timestamp: NOW + 120 }), headers, {
      now: NOW,
      skewSeconds: 60,
    });
    expect(res.ok).toBe(false);
  });

  it("rejects missing signature headers", () => {
    const res = verifySignature(SECRET, input(), {}, { now: NOW });
    expect(res.ok).toBe(false);
  });

  it("looks headers up case-insensitively", () => {
    const h = signRequest(SECRET, input());
    const upper: Record<string, string> = {};
    for (const [k, v] of Object.entries(h)) upper[k.toUpperCase()] = v;
    expect(verifySignature(SECRET, input(), upper, { now: NOW }).ok).toBe(true);
  });
});

describe("NonceCache (replay defence)", () => {
  it("accepts a nonce once, then rejects its reuse", () => {
    const cache = new NonceCache(60);
    expect(cache.checkAndRecord("n1", NOW)).toBe(true);
    expect(cache.checkAndRecord("n1", NOW + 1)).toBe(false);
  });

  it("forgets a nonce after the window", () => {
    const cache = new NonceCache(60);
    cache.checkAndRecord("n1", NOW);
    expect(cache.checkAndRecord("n1", NOW + 61_000)).toBe(true);
  });

  it("keeps distinct nonces independent", () => {
    const cache = new NonceCache(60);
    expect(cache.checkAndRecord("a", NOW)).toBe(true);
    expect(cache.checkAndRecord("b", NOW)).toBe(true);
  });

  it("evicts the oldest entries past its cap", () => {
    const cache = new NonceCache(60, 2);
    cache.checkAndRecord("a", NOW);
    cache.checkAndRecord("b", NOW);
    cache.checkAndRecord("c", NOW); // evicts "a"
    expect(cache.checkAndRecord("a", NOW)).toBe(true); // forgotten, so accepted again
  });
});
