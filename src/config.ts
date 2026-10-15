import { readFileSync } from "node:fs";
import yaml from "js-yaml";
import { z } from "zod";

/**
 * Policy configuration: the security contract (feature #1), parsed from YAML and validated strictly
 * with zod. `.strict()` means a typo'd key is a loud startup error, never a silently-ignored rule.
 * Secrets are never stored here — the file only names the env var that holds a device token.
 */

const rateLimit = z
  .object({
    calls: z.number().int().positive(),
    per_seconds: z.number().positive(),
  })
  .strict();

const auth = z
  .object({
    type: z.enum(["bearer", "none"]).default("none"),
    token_env: z.string().optional(),
  })
  .strict();

const transport = z
  .object({
    kind: z.enum(["http", "mqtt"]).default("http"),
    address: z.string().url(),
    auth: auth.default({}),
  })
  .strict();

const toolCfg = z
  .object({
    tier: z.enum(["read_only", "low_risk", "high_risk"]).default("read_only"),
    allow: z.boolean().default(true),
    sensors: z.array(z.string()).optional(),
    actuators: z.array(z.string()).optional(),
    rate_limit: rateLimit.optional(),
  })
  .strict();

const confirmation = z
  .object({
    mode: z.enum(["queue", "deny", "auto"]).default("queue"),
    expiry_seconds: z.number().positive().default(300),
  })
  .strict();

const defaults = z
  .object({
    rate_limit: rateLimit.default({ calls: 30, per_seconds: 60 }),
    confirmation: confirmation.default({}),
  })
  .strict();

const anomaly = z
  .object({
    repetition: z
      .object({
        max_identical: z.number().int().positive().default(5),
        per_seconds: z.number().positive().default(30),
      })
      .strict()
      .default({}),
    denial_burst: z
      .object({
        max_denials: z.number().int().positive().default(8),
        per_seconds: z.number().positive().default(60),
        cooldown_seconds: z.number().positive().default(120),
      })
      .strict()
      .default({}),
    escalation: z
      .object({
        max_high_risk_attempts: z.number().int().positive().default(3),
        per_seconds: z.number().positive().default(60),
      })
      .strict()
      .default({}),
  })
  .strict();

const device = z
  .object({
    description: z.string().default(""),
    transport,
    tools: z.record(z.string(), toolCfg).default({}),
  })
  .strict();

export const PolicySchema = z
  .object({
    version: z.number().int().default(1),
    defaults: defaults.default({}),
    anomaly: anomaly.default({}),
    devices: z.record(z.string(), device).default({}),
  })
  .strict();

export type Policy = z.infer<typeof PolicySchema>;
export type DeviceCfg = z.infer<typeof device>;
export type ToolCfg = z.infer<typeof toolCfg>;
export type AuthCfg = z.infer<typeof auth>;
export type TransportCfg = z.infer<typeof transport>;
export type RateLimitCfg = z.infer<typeof rateLimit>;
export type ConfirmationCfg = z.infer<typeof confirmation>;
export type AnomalyCfg = z.infer<typeof anomaly>;

/** Load and strictly validate a policy YAML file. Throws a readable error on any violation. */
export function loadPolicy(path: string): Policy {
  const raw = yaml.load(readFileSync(path, "utf8")) ?? {};
  const parsed = PolicySchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    throw new Error(`invalid policy file ${path}:\n${issues}`);
  }
  return parsed.data;
}

/**
 * Resolve a device's bearer token from the environment at call time. The policy file holds only the
 * *name* of the env var; the secret itself never lives on disk in config. Returns null when no auth
 * is configured, throws when auth is configured but the env var is missing.
 */
export function resolveToken(a: AuthCfg): string | null {
  if (a.type !== "bearer" || !a.token_env) return null;
  const token = process.env[a.token_env];
  if (!token) {
    throw new Error(
      `device auth configured with token_env=${a.token_env} but that environment variable is unset`,
    );
  }
  return token;
}
