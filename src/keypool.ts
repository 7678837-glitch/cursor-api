import { createHash } from "node:crypto";
import { GatewayError } from "./errors.js";
import { logInfo } from "./log.js";

/** Auth failures usually mean a revoked key; keep it out much longer than a rate limit. */
export const AUTH_FAILURE_COOLDOWN_MS = 15 * 60 * 1000;

export type CursorKeyFailure = "rate_limit" | "auth";

export interface CursorKeyStatus {
  /** Stable, non-reversible fingerprint (sha256 prefix); the key itself is never exposed. */
  id: string;
  state: "healthy" | "cooling_down";
  cooldown_until: string | null;
  last_failure: CursorKeyFailure | null;
  consecutive_failures: number;
  requests: number;
  failures: number;
}

interface Entry {
  key: string;
  id: string;
  cooldownUntil: number;
  lastFailure: CursorKeyFailure | null;
  consecutiveFailures: number;
  requests: number;
  failures: number;
}

/**
 * Upstream Cursor key pool: round-robin over healthy keys, cool down keys
 * that hit a rate limit or auth failure, and fail over to the next key.
 */
export class CursorKeyPool {
  private readonly entries: Entry[];
  private cursor = 0;

  constructor(
    keys: string[],
    private readonly options: { cooldownMs: number; now?: () => number },
  ) {
    const unique = [...new Set(keys.map((key) => key.trim()).filter((key) => key !== ""))];
    if (unique.length === 0) {
      throw new Error("CursorKeyPool needs at least one key");
    }
    this.entries = unique.map((key) => ({
      key,
      id: fingerprintKey(key),
      cooldownUntil: 0,
      lastFailure: null,
      consecutiveFailures: 0,
      requests: 0,
      failures: 0,
    }));
  }

  get size(): number {
    return this.entries.length;
  }

  /** The first configured key; used where one key is enough (e.g. model catalog cache). */
  get primary(): string {
    return this.entries[0]?.key ?? "";
  }

  /**
   * Next key to use. Healthy keys rotate round-robin; `exclude` skips keys
   * that already failed for this request. When every candidate is cooling
   * down, the one that recovers first is returned so requests still go out.
   */
  pick(exclude: ReadonlySet<string> = new Set()): string | undefined {
    const now = this.now();
    const candidates = this.entries.filter((entry) => !exclude.has(entry.key));
    if (candidates.length === 0) return undefined;
    for (let step = 0; step < this.entries.length; step += 1) {
      const entry = this.entries[(this.cursor + step) % this.entries.length];
      if (!entry || exclude.has(entry.key) || entry.cooldownUntil > now) continue;
      this.cursor = (this.cursor + step + 1) % this.entries.length;
      return entry.key;
    }
    const soonest = [...candidates].sort((a, b) => a.cooldownUntil - b.cooldownUntil)[0];
    return soonest?.key;
  }

  reportSuccess(key: string): void {
    const entry = this.find(key);
    if (!entry) return;
    entry.requests += 1;
    if (entry.consecutiveFailures > 0 || entry.cooldownUntil > 0) {
      logInfo("cursor key recovered", { key_id: entry.id });
    }
    entry.consecutiveFailures = 0;
    entry.cooldownUntil = 0;
  }

  /**
   * Records an upstream failure. Returns true when the error is key-specific
   * (auth / rate limit) and another key may succeed.
   */
  reportFailure(key: string, error: unknown): boolean {
    const entry = this.find(key);
    const failure = classifyKeyFailure(error);
    if (!entry) return failure !== null;
    entry.requests += 1;
    if (failure === null) return false;
    entry.failures += 1;
    entry.consecutiveFailures += 1;
    entry.lastFailure = failure;
    const base = failure === "auth" ? AUTH_FAILURE_COOLDOWN_MS : this.options.cooldownMs;
    // Back off harder on keys that keep failing (x1, x2, x4 … capped at x8).
    const factor = Math.min(8, 2 ** Math.max(0, entry.consecutiveFailures - 1));
    entry.cooldownUntil = this.now() + base * factor;
    logInfo("cursor key cooling down", {
      key_id: entry.id,
      reason: failure,
      cooldown_ms: base * factor,
      pool_size: this.entries.length,
    });
    return true;
  }

  /**
   * Runs `fn` with a pooled key, failing over to other keys on
   * auth / rate-limit errors. Other errors are returned unchanged.
   * `canRetry` lets callers stop failover once output reached the client.
   */
  async run<T>(
    fn: (key: string) => Promise<T>,
    canRetry: (error: unknown) => boolean = () => true,
  ): Promise<T> {
    const tried = new Set<string>();
    let lastError: unknown;
    for (;;) {
      const key = this.pick(tried);
      if (key === undefined) throw lastError;
      tried.add(key);
      try {
        const value = await fn(key);
        this.reportSuccess(key);
        return value;
      } catch (error) {
        lastError = error;
        const keySpecific = this.reportFailure(key, error);
        if (!keySpecific || tried.size >= this.entries.length || !canRetry(error)) {
          throw error;
        }
      }
    }
  }

  snapshot(): CursorKeyStatus[] {
    const now = this.now();
    return this.entries.map((entry) => ({
      id: entry.id,
      state: entry.cooldownUntil > now ? "cooling_down" : "healthy",
      cooldown_until: entry.cooldownUntil > now ? new Date(entry.cooldownUntil).toISOString() : null,
      last_failure: entry.lastFailure,
      consecutive_failures: entry.consecutiveFailures,
      requests: entry.requests,
      failures: entry.failures,
    }));
  }

  private find(key: string): Entry | undefined {
    return this.entries.find((entry) => entry.key === key);
  }

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }
}

export function classifyKeyFailure(error: unknown): CursorKeyFailure | null {
  if (!(error instanceof GatewayError)) return null;
  if (error.code === "upstream_authentication_error") return "auth";
  if (error.code === "rate_limit_error") return "rate_limit";
  return null;
}

export function fingerprintKey(key: string): string {
  return `ck_${createHash("sha256").update(key).digest("hex").slice(0, 10)}`;
}
