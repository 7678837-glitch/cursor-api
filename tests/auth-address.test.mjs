import assert from "node:assert/strict";
import { test } from "node:test";
import { bucketKey, clientAddress, configureAuthThrottle, TrustedProxies } from "../dist/auth-throttle.js";
import { timingSafeEqualUtf8 } from "../dist/auth.js";

const req = (remoteAddress, xff) => ({ socket: { remoteAddress }, headers: xff === undefined ? {} : { "x-forwarded-for": xff } });

test("bucketKey folds IPv4-mapped IPv6 and aggregates IPv6 per /64", () => {
  assert.equal(bucketKey("::ffff:192.0.2.1"), "192.0.2.1");
  assert.equal(bucketKey("192.0.2.1"), "192.0.2.1");
  assert.equal(bucketKey("2001:db8::1"), "2001:0db8:0000:0000::/64");
  assert.equal(bucketKey("2001:DB8:0:0:ffff::1%eth0"), "2001:0db8:0000:0000::/64");
  assert.equal(bucketKey("::1"), "0000:0000:0000:0000::/64");
  assert.equal(bucketKey("unknown"), "unknown");
});

test("trusted proxies accept IPs and CIDRs and reject garbage", () => {
  const proxies = new TrustedProxies(["10.0.0.0/8", "::1", "172.31.99.20"]);
  assert.equal(proxies.has("10.1.2.3"), true);
  assert.equal(proxies.has("::ffff:10.1.2.3"), true);
  assert.equal(proxies.has("::1"), true);
  assert.equal(proxies.has("172.31.99.21"), false);
  assert.throws(() => new TrustedProxies(["not-an-ip"]), /trusted_proxies/);
  assert.throws(() => new TrustedProxies(["10.0.0.0/33"]), /trusted_proxies/);
});

test("clientAddress uses the right-most untrusted X-Forwarded-For entry only behind a trusted peer", () => {
  try {
    configureAuthThrottle(20, { trustedProxies: [] });
    assert.equal(clientAddress(req("10.0.0.5", "203.0.113.1")), "10.0.0.5");
    configureAuthThrottle(20, { trustedProxies: ["10.0.0.0/8"] });
    assert.equal(clientAddress(req("10.0.0.5", "203.0.113.1")), "203.0.113.1");
    // A client-supplied prefix is ignored; the chain is read from the right.
    assert.equal(clientAddress(req("10.0.0.5", "1.1.1.1, 203.0.113.1, 10.0.0.9")), "203.0.113.1");
    assert.equal(clientAddress(req("10.0.0.5")), "10.0.0.5");
    assert.equal(clientAddress(req("10.0.0.5", "garbage")), "10.0.0.5");
    assert.equal(clientAddress(req("198.51.100.1", "203.0.113.1")), "198.51.100.1");
  } finally {
    configureAuthThrottle(0);
  }
});

test("timingSafeEqualUtf8 compares regardless of length", () => {
  assert.equal(timingSafeEqualUtf8("secret", "secret"), true);
  assert.equal(timingSafeEqualUtf8("secret", "secreT"), false);
  assert.equal(timingSafeEqualUtf8("secret", "secret-longer"), false);
  assert.equal(timingSafeEqualUtf8("", "x"), false);
});
