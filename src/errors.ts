/**
 * Stable error codes (SPEC.md §10). Every failure the LLM can see maps to one of these strings, so
 * the model can reason about *why* a call failed without ever seeing bridge internals.
 */
export enum ErrorCode {
  NotRegistered = "not_registered", // device/tool not in policy (deny-by-default)
  PolicyDenied = "policy_denied", // explicitly disallowed by policy
  RateLimited = "rate_limited", // over the applicable rate limit
  AnomalyBlocked = "anomaly_blocked", // anomaly detector tripped
  PendingConfirmation = "pending_confirmation", // high-risk, waiting on a human
  ConfirmationDenied = "confirmation_denied", // operator rejected / it expired
  DeviceUnreachable = "device_unreachable", // transport could not reach the device
  DeviceAuthFailed = "device_auth_failed", // device rejected our bearer token
  SanitizerRejected = "sanitizer_rejected", // device response failed validation
  BadRequest = "bad_request", // malformed tool arguments
  NotFound = "not_found", // e.g. unknown action_id
}

/** A tool-result shape the LLM receives on failure: { ok: false, error, message }. */
export interface ErrorResult {
  ok: false;
  error: ErrorCode;
  message: string;
}

/** Raised anywhere in the pipeline; carries a stable code plus a human-readable message. */
export class TetherError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "TetherError";
  }

  asResult(): ErrorResult {
    return { ok: false, error: this.code, message: this.message };
  }
}
