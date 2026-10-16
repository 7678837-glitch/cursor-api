import type { IncomingMessage } from "node:http";
import { GatewayError, rateLimitError } from "./errors.js";

/**
 * Per-address limit on failed authentication attempts. Client keys are long random strings, but
 * ADMIN_ACCESS_KEY is chosen by the operator and may be guessable; without a limit the gateway
 * answers wrong guesses as fast as the network allows.
 */
export class AuthFailureThrottle {
  private readonly failures = new Map<string, { count: number; windowStart: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  get enabled(): boolean {
    return this.limit > 0;
  }

  /** Throws 429 while `address` has used up its failures for the current window. */
  check(address: string): void {
    if (!this.enabled) return;
    const entry = this.current(address);
    if (entry && entry.count >= this.limit) {
      const retryAfter = Math.max(1, Math.ceil((entry.windowStart + this.windowMs - this.now()) / 1000));
      throw rateLimitError(`Too many failed authentication attempts; retry in ${retryAfter}s`);
    }
  }

  recordFailure(address: string): void {
    if (!this.enabled) return;
    const entry = this.current(address);
    if (entry) {
      entry.count += 1;
    } else {
      this.failures.set(address, { count: 1, windowStart: this.now() });
      if (this.failures.size > 10_000) this.prune();
    }
  }

  private current(address: string): { count: number; windowStart: number } | undefined {
    const entry = this.failures.get(address);
    if (!entry) return undefined;
    if (this.now() - entry.windowStart >= this.windowMs) {
      this.failures.delete(address);
      return undefined;
    }
    return entry;
  }

  private prune(): void {
    const now = this.now();
    for (const [address, entry] of this.failures) {
      if (now - entry.windowStart >= this.windowMs) this.failures.delete(address);
    }
  }
}

export function clientAddress(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? "unknown";
}

let throttle = new AuthFailureThrottle(0, 60_000);

export function configureAuthThrottle(limit: number, windowMs = 60_000): void {
  throttle = new AuthFailureThrottle(limit, windowMs);
}

/** Runs an authentication check, refusing early for throttled addresses and counting failures. */
export function guardAuth<T>(req: IncomingMessage, check: () => T): T {
  const address = clientAddress(req);
  throttle.check(address);
  try {
    return check();
  } catch (error) {
    if (error instanceof GatewayError && error.httpStatus === 401) throttle.recordFailure(address);
    throw error;
  }
}
