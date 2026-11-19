import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const HEADER_SIGNATURE = "x-tether-signature";
export const HEADER_TIMESTAMP = "x-tether-timestamp";
export const HEADER_NONCE = "x-tether-nonce";

const SIGNATURE_HEX = /^[0-9a-f]{64}$/;
const DEFAULT_SKEW_SECONDS = 300;
const DEFAULT_NONCE_WINDOW_SECONDS = 300;
const DEFAULT_NONCE_CAP = 10_000;

export interface SignInput {
  method: string;
  path: string;
  body: string;
  timestamp: number;
  nonce: string;
}

export interface VerifyOptions {
  now?: number;
  skewSeconds?: number;
}

export type VerifyResult = { ok: true } | { ok: false; reason: string };

function bodyHash(body: string): string {
  return createHash("sha256").update(body).digest("hex");
}

function header(headers: Record<string, string>, name: string): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) return value;
  }
  return undefined;
}

/** The exact string that gets signed: method, path, timestamp, nonce, body hash. */
export function canonicalRequest(input: SignInput): string {
  return [
    input.method.toUpperCase(),
    input.path,
    String(input.timestamp),
    input.nonce,
    bodyHash(input.body),
  ].join("\n");
}

/** Sign a request and return the headers a caller should send. */
export function signRequest(secret: string, input: SignInput): Record<string, string> {
  const signature = createHmac("sha256", secret)
    .update(canonicalRequest(input))
    .digest("hex");

  return {
    [HEADER_SIGNATURE]: signature,
    [HEADER_TIMESTAMP]: String(input.timestamp),
    [HEADER_NONCE]: input.nonce,
  };
}

/** Verify headers against the request. Header names are matched case-insensitively. */
export function verifySignature(
  secret: string,
  input: SignInput,
  headers: Record<string, string>,
  options: VerifyOptions = {},
): VerifyResult {
  const signature = header(headers, HEADER_SIGNATURE);
  const timestamp = header(headers, HEADER_TIMESTAMP);
  const nonce = header(headers, HEADER_NONCE);

  if (!signature || !timestamp || !nonce) {
    return { ok: false, reason: "missing signature headers" };
  }
  if (!SIGNATURE_HEX.test(signature)) {
    return { ok: false, reason: "malformed signature" };
  }

  const signedAt = Number(timestamp);
  if (!Number.isFinite(signedAt)) {
    return { ok: false, reason: "invalid timestamp" };
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.skewSeconds ?? DEFAULT_SKEW_SECONDS;
  if (Math.abs(now - signedAt) > skew) {
    return { ok: false, reason: "timestamp outside allowed skew" };
  }

  const expected = createHmac("sha256", secret)
    .update(
      canonicalRequest({
        ...input,
        timestamp: signedAt,
        nonce,
      }),
    )
    .digest();

  const actual = Buffer.from(signature, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return { ok: false, reason: "signature mismatch" };
  }

  return { ok: true };
}

/** In-memory replay defence: each nonce is accepted once per window. */
export class NonceCache {
  private readonly seen = new Map<string, number>();

  constructor(
    private readonly windowSeconds = DEFAULT_NONCE_WINDOW_SECONDS,
    private readonly maxEntries = DEFAULT_NONCE_CAP,
  ) {}

  checkAndRecord(nonce: string, now: number): boolean {
    for (const [key, seenAt] of this.seen) {
      if (now - seenAt > this.windowSeconds) this.seen.delete(key);
    }

    const seenAt = this.seen.get(nonce);
    if (seenAt !== undefined && now - seenAt <= this.windowSeconds) return false;

    this.seen.delete(nonce);
    this.seen.set(nonce, now);

    while (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next().value;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }

    return true;
  }
}
