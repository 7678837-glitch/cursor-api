import { BlockList, isIP } from "node:net";
import type { IncomingMessage } from "node:http";
import { GatewayError, rateLimitError } from "./errors.js";

/** Hard cap on tracked buckets per scope. The least recently failed bucket is evicted first. */
const DEFAULT_MAX_ENTRIES = 10_000;
/** Expired buckets examined per recorded failure (amortized sweep). */
const SWEEP_PER_RECORD = 8;

interface Bucket {
  /** Failure timestamps inside the window, oldest first; never longer than `limit`. */
  times: number[];
}

/**
 * Sliding-window limit on failed authentication attempts, keyed by client address. IPv4-mapped
 * IPv6 addresses are folded into IPv4 and IPv6 addresses are aggregated per /64, because one host
 * usually controls a whole /64.
 *
 * Memory is bounded: at most `maxEntries` buckets (LRU by last failure) of at most `limit`
 * timestamps each. Expired buckets are swept a few at a time on every recorded failure; since the
 * map is ordered by last failure, the oldest buckets are always at the front, so the sweep never
 * scans live entries.
 */
export class AuthFailureThrottle {
  private readonly buckets = new Map<string, Bucket>();
  private readonly maxEntries: number;

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
    options: { maxEntries?: number } = {},
  ) {
    this.maxEntries = Math.max(1, options.maxEntries ?? DEFAULT_MAX_ENTRIES);
  }

  get enabled(): boolean {
    return this.limit > 0;
  }

  /** Number of tracked buckets (for tests and diagnostics). */
  get size(): number {
    return this.buckets.size;
  }

  /** Seconds until `address` may fail again, or 0 when it is under the limit. */
  retryAfterSeconds(address: string): number {
    if (!this.enabled) return 0;
    const bucket = this.live(bucketKey(address));
    if (!bucket || bucket.times.length < this.limit) return 0;
    const oldest = bucket.times[0] ?? this.now();
    return Math.max(1, Math.ceil((oldest + this.windowMs - this.now()) / 1000));
  }

  /** Throws 429 (with `retryAfterSeconds`) while `address` has used up its failures. */
  check(address: string): void {
    const retryAfter = this.retryAfterSeconds(address);
    if (retryAfter > 0) throw throttledError(retryAfter);
  }

  recordFailure(address: string): void {
    if (!this.enabled) return;
    const key = bucketKey(address);
    const now = this.now();
    const bucket = this.live(key) ?? { times: [] };
    bucket.times.push(now);
    if (bucket.times.length > this.limit) bucket.times.splice(0, bucket.times.length - this.limit);
    // Re-insert so the map stays ordered by last failure (LRU order).
    this.buckets.delete(key);
    this.buckets.set(key, bucket);
    this.sweep(now);
    while (this.buckets.size > this.maxEntries) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
  }

  /** Returns the bucket with expired timestamps dropped, or undefined when nothing is left. */
  private live(key: string): Bucket | undefined {
    const bucket = this.buckets.get(key);
    if (!bucket) return undefined;
    const cutoff = this.now() - this.windowMs;
    let drop = 0;
    while (drop < bucket.times.length && (bucket.times[drop] ?? 0) <= cutoff) drop += 1;
    if (drop > 0) bucket.times.splice(0, drop);
    if (bucket.times.length === 0) {
      this.buckets.delete(key);
      return undefined;
    }
    return bucket;
  }

  private sweep(now: number): void {
    const cutoff = now - this.windowMs;
    let examined = 0;
    for (const [key, bucket] of this.buckets) {
      if (examined >= SWEEP_PER_RECORD) break;
      examined += 1;
      const newest = bucket.times[bucket.times.length - 1] ?? 0;
      if (newest > cutoff) break; // ordered by last failure: everything after this is live too
      this.buckets.delete(key);
    }
  }
}

function throttledError(retryAfterSeconds: number): GatewayError {
  const error = rateLimitError(`Too many failed authentication attempts; retry in ${retryAfterSeconds}s`);
  error.retryAfterSeconds = retryAfterSeconds;
  return error;
}

/** Normalizes an address and aggregates IPv6 per /64. Non-IP strings are used as-is. */
export function bucketKey(address: string): string {
  const ip = normalizeIp(address);
  if (isIP(ip) !== 6) return ip;
  const groups = expandIpv6(ip);
  return groups ? `${groups.slice(0, 4).join(":")}::/64` : ip;
}

function normalizeIp(address: string): string {
  let ip = address.trim();
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped?.[1] && isIP(mapped[1]) === 4) return mapped[1];
  return ip.toLowerCase();
}

/** Expands an IPv6 address into 8 lowercase 4-digit groups. */
function expandIpv6(ip: string): string[] | null {
  let text = ip;
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (v4?.[1]) {
    const parts = v4[1].split(".").map(Number);
    const hi = (((parts[0] ?? 0) << 8) | (parts[1] ?? 0)).toString(16);
    const lo = (((parts[2] ?? 0) << 8) | (parts[3] ?? 0)).toString(16);
    text = `${text.slice(0, -v4[1].length)}${hi}:${lo}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  return groups.map((group) => group.padStart(4, "0"));
}

/**
 * Trusted reverse proxies. Empty (the default) means the socket address is the client address and
 * X-Forwarded-For is ignored. When the direct peer is a trusted proxy, the client address is the
 * right-most X-Forwarded-For entry that is not itself a trusted proxy.
 */
export class TrustedProxies {
  private readonly list = new BlockList();
  readonly count: number;

  constructor(entries: readonly string[]) {
    let count = 0;
    for (const raw of entries) {
      const entry = raw.trim();
      if (entry === "") continue;
      const [address = "", prefixText] = entry.split("/");
      const ip = normalizeIp(address);
      const family = isIP(ip);
      if (family === 0) throw new Error(`trusted_proxies: invalid address '${entry}'`);
      const type = family === 4 ? "ipv4" : "ipv6";
      if (prefixText === undefined) {
        this.list.addAddress(ip, type);
      } else {
        const prefix = Number(prefixText);
        const max = family === 4 ? 32 : 128;
        if (!/^\d+$/.test(prefixText) || prefix > max) {
          throw new Error(`trusted_proxies: invalid prefix in '${entry}'`);
        }
        this.list.addSubnet(ip, prefix, type);
      }
      count += 1;
    }
    this.count = count;
  }

  has(address: string): boolean {
    if (this.count === 0) return false;
    const ip = normalizeIp(address);
    const family = isIP(ip);
    if (family === 0) return false;
    return this.list.check(ip, family === 4 ? "ipv4" : "ipv6");
  }
}

let trustedProxies = new TrustedProxies([]);

export function clientAddress(req: IncomingMessage): string {
  const peer = req.socket.remoteAddress ?? "unknown";
  if (!trustedProxies.has(peer)) return peer;
  const header = req.headers["x-forwarded-for"];
  const values = (Array.isArray(header) ? header.join(",") : header ?? "")
    .split(",")
    .map((part) => normalizeIp(part))
    .filter((part) => part !== "");
  for (let i = values.length - 1; i >= 0; i -= 1) {
    const candidate = values[i] ?? "";
    if (isIP(candidate) === 0) return peer; // malformed chain: fall back to the proxy address
    if (!trustedProxies.has(candidate)) return candidate;
  }
  return peer;
}

export type AuthScope = "admin" | "client";

const WINDOW_MS = 60_000;
let throttles: Record<AuthScope, AuthFailureThrottle> = {
  admin: new AuthFailureThrottle(0, WINDOW_MS),
  client: new AuthFailureThrottle(0, WINDOW_MS),
};

export function configureAuthThrottle(
  limit: number,
  options: { windowMs?: number; trustedProxies?: readonly string[]; maxEntries?: number } = {},
): void {
  const windowMs = options.windowMs ?? WINDOW_MS;
  throttles = {
    admin: new AuthFailureThrottle(limit, windowMs, Date.now, { maxEntries: options.maxEntries }),
    client: new AuthFailureThrottle(limit, windowMs, Date.now, { maxEntries: options.maxEntries }),
  };
  trustedProxies = new TrustedProxies(options.trustedProxies ?? []);
}

/**
 * Runs an authentication check with per-scope failure counting.
 *
 * - `admin`: hard limit. A throttled address is refused before the key is checked, so a guess made
 *   while throttled reveals nothing about the operator-chosen ADMIN_ACCESS_KEY.
 * - `client`: back-off only. Client keys are 256-bit random `cgk_` strings, so brute force is not a
 *   realistic threat; a valid key is always accepted. Only failed attempts from an address over
 *   the limit are answered with 429 + Retry-After instead of 401.
 *
 * Requests that carry no credential at all (`hasCredential === false`) are never counted.
 */
export function guardAuth<T>(
  req: IncomingMessage,
  scope: AuthScope,
  hasCredential: boolean,
  check: () => T,
): T {
  const throttle = throttles[scope];
  const address = clientAddress(req);
  if (scope === "admin") throttle.check(address);
  try {
    return check();
  } catch (error) {
    if (hasCredential && error instanceof GatewayError && error.httpStatus === 401) {
      if (scope === "client") throttle.check(address);
      throttle.recordFailure(address);
    }
    throw error;
  }
}
