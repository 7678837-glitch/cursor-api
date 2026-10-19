// Regression tests for the #28 review (round 1). Each one fails on 30fe758 and passes after the rework.
import assert from "node:assert/strict";
import { test } from "node:test";
import { AuthFailureThrottle } from "../dist/auth-throttle.js";
import { CLIENT_KEY, startFakeGateway } from "./fixtures/gateway-harness.mjs";

const ADMIN_KEY = "it-admin-key";
const get = (gateway, path, headers = {}) => fetch(`${gateway.baseUrl}${path}`, { headers });
const bearer = (key, extra = {}) => ({ authorization: `Bearer ${key}`, ...extra });

// High: a lockout must not reject valid keys, and client failures must not lock the admin out.
test("high: bad client keys never block a valid client key or the admin key", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "3" });
  try {
    for (let i = 0; i < 10; i += 1) await get(gateway, "/v1/models", bearer("cgk_wrong"));
    assert.equal((await get(gateway, "/v1/models", bearer(CLIENT_KEY))).status, 200);
    assert.equal((await get(gateway, "/admin/api/overview", bearer(ADMIN_KEY))).status, 200);
  } finally {
    await gateway.stop();
  }
});

test("high: admin lockout is per admin bucket and does not touch client traffic", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "3" });
  try {
    for (let i = 0; i < 3; i += 1) {
      assert.equal((await get(gateway, "/admin/api/overview", bearer("wrong"))).status, 401);
    }
    assert.equal((await get(gateway, "/admin/api/overview", bearer(ADMIN_KEY))).status, 429);
    assert.equal((await get(gateway, "/v1/models", bearer(CLIENT_KEY))).status, 200);
  } finally {
    await gateway.stop();
  }
});

test("high: behind a configured trusted proxy, clients are bucketed by X-Forwarded-For", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "3", TRUSTED_PROXIES: "127.0.0.1" });
  try {
    const a = { "x-forwarded-for": "203.0.113.7" };
    const b = { "x-forwarded-for": "198.51.100.9" };
    for (let i = 0; i < 3; i += 1) await get(gateway, "/admin/api/overview", bearer("wrong", a));
    assert.equal((await get(gateway, "/admin/api/overview", bearer(ADMIN_KEY, a))).status, 429);
    assert.equal((await get(gateway, "/admin/api/overview", bearer(ADMIN_KEY, b))).status, 200);
  } finally {
    await gateway.stop();
  }
});

test("high: without trusted proxies, X-Forwarded-For is ignored", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "3" });
  try {
    for (let i = 0; i < 3; i += 1) {
      await get(gateway, "/admin/api/overview", bearer("wrong", { "x-forwarded-for": `192.0.2.${i}` }));
    }
    const res = await get(gateway, "/admin/api/overview", bearer(ADMIN_KEY, { "x-forwarded-for": "192.0.2.200" }));
    assert.equal(res.status, 429);
  } finally {
    await gateway.stop();
  }
});

// Medium: bounded table, IPv6 /64 aggregation, no O(n) prune on insert.
test("medium: the table has a hard cap (LRU)", () => {
  let now = 0;
  const throttle = new AuthFailureThrottle(20, 60_000, () => now, { maxEntries: 1_000 });
  for (let i = 0; i < 5_000; i += 1) throttle.recordFailure(`10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`);
  assert.equal(typeof throttle.size, "number");
  assert.ok(throttle.size <= 1_000, `size ${throttle.size} exceeds the cap`);
});

test("medium: IPv6 addresses in one /64 share a bucket", () => {
  let now = 0;
  const throttle = new AuthFailureThrottle(3, 60_000, () => now);
  throttle.recordFailure("2001:db8:1:2::1");
  throttle.recordFailure("2001:db8:1:2:aaaa::2");
  throttle.recordFailure("2001:0db8:0001:0002:ffff:ffff:ffff:ffff");
  assert.throws(() => throttle.check("2001:db8:1:2::99"), (error) => error.httpStatus === 429);
  throttle.check("2001:db8:1:3::1");
});

test("medium: inserting 1000 new addresses into a 40k table stays fast", () => {
  let now = 0;
  const throttle = new AuthFailureThrottle(20, 60_000, () => now, { maxEntries: 100_000 });
  const ip = (i) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
  for (let i = 0; i < 40_000; i += 1) throttle.recordFailure(ip(i));
  const started = performance.now();
  for (let i = 40_000; i < 41_000; i += 1) throttle.recordFailure(ip(i));
  const elapsed = performance.now() - started;
  // 30fe758 measured ~280 ms here (full prune per insert past 10k entries).
  assert.ok(elapsed < 50, `1000 inserts took ${elapsed.toFixed(1)} ms`);
});

// Low
test("low: sliding window, no 2x burst across a window boundary", () => {
  let now = 0;
  const throttle = new AuthFailureThrottle(20, 60_000, () => now);
  throttle.recordFailure("192.0.2.1");
  now = 59_000;
  for (let i = 0; i < 19; i += 1) {
    throttle.check("192.0.2.1");
    throttle.recordFailure("192.0.2.1");
  }
  now = 60_000; // the t=0 failure leaves the window; the 19 at t=59s are still in it
  let allowed = 0;
  for (let i = 0; i < 20; i += 1) {
    try {
      throttle.check("192.0.2.1");
      throttle.recordFailure("192.0.2.1");
      allowed += 1;
    } catch {
      break;
    }
  }
  assert.equal(allowed, 1);
});

test("low: 429 carries Retry-After", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "2" });
  try {
    for (let i = 0; i < 2; i += 1) await get(gateway, "/admin/api/overview", bearer("wrong"));
    const res = await get(gateway, "/admin/api/overview", bearer("wrong"));
    assert.equal(res.status, 429);
    const retryAfter = Number(res.headers.get("retry-after"));
    assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60, `retry-after=${res.headers.get("retry-after")}`);
  } finally {
    await gateway.stop();
  }
});

test("low: requests without any key are not counted as failures", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "2" });
  try {
    for (let i = 0; i < 10; i += 1) {
      assert.equal((await get(gateway, "/admin/api/overview")).status, 401);
      assert.equal((await get(gateway, "/v1/models")).status, 401);
    }
    assert.equal((await get(gateway, "/admin/api/overview", bearer(ADMIN_KEY))).status, 200);
  } finally {
    await gateway.stop();
  }
});
