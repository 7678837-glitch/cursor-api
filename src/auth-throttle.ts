import type { IncomingMessage } from "node:http";
import { GatewayError, rateLimitError } from "./errors.js";

export class AuthFailureThrottle {
  private readonly failures = new Map<string, { count: number; windowStart: number }>();

  constructor(private readonly limit: number, private readonly windowMs: number, private readonly now: () => number = Date.now) {}

  get enabled(): boolean {
    return this.limit > 0;
  }

  check(address: string): void {
    const entry = this.current(address);
    if (entry && entry.count >= this.limit) {
      const retryAfter = Math.max(1, Math.ceil((entry.windowStart + this.windowMs - this.now()) / 1000));
      throw rateLimitError(`Too many failed authentication attempts; retry in ${retryAfter}s`, retryAfter);
    }
  }

  recordFailure(address: string): void {
    if (this.limit <= 0) return;
    const entry = this.current(address);
    if (entry) entry.count += 1;
    else this.failures.set(address, { count: 1, windowStart: this.now() });
    if (this.failures.size > 10_000) this.prune();
  }

  private current(address: string): { count: number; windowStart: number } | undefined {
    if (this.limit <= 0) return undefined;
    const entry = this.failures.get(address);
    if (!entry) return undefined;
    if (this.now() - entry.windowStart >= this.windowMs) {
      this.failures.delete(address);
      return undefined;
    }
    return entry;
  }

  private prune(): void {
    for (const [address, entry] of this.failures) if (this.now() - entry.windowStart >= this.windowMs) this.failures.delete(address);
  }
}

let throttle = new AuthFailureThrottle(0, 60_000);

export function configureAuthThrottle(limit: number, windowMs = 60_000): void {
  throttle = new AuthFailureThrottle(limit, windowMs);
}

export function guardAuth<T>(req: IncomingMessage, check: () => T): T {
  const address = req.socket.remoteAddress ?? "unknown";
  throttle.check(address);
  try {
    return check();
  } catch (error) {
    if (error instanceof GatewayError && error.httpStatus === 401) {
      throttle.recordFailure(address);
    }
    throw error;
  }
}
