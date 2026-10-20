import assert from "node:assert/strict";
import { test } from "node:test";
import { AuthFailureThrottle, configureAuthThrottle, guardAuth } from "../dist/auth-throttle.js";
import { authenticationError } from "../dist/errors.js";
import { CLIENT_KEY, startFakeGateway } from "./fixtures/gateway-harness.mjs";

test("exhausted authentication limits reject guesses before checking credentials", () => {
  const req = { socket: { remoteAddress: "192.0.2.1" } };
  configureAuthThrottle(1);
  assert.throws(() => guardAuth(req, () => { throw authenticationError(); }), { httpStatus: 401 });
  let checked = false;
  assert.throws(() => guardAuth(req, () => { checked = true; }), { httpStatus: 429 });
  assert.equal(checked, false);
  configureAuthThrottle(0);
});

test("throttle blocks an address after the limit until the window passes", () => {
  let now = 0;
  const throttle = new AuthFailureThrottle(3, 60_000, () => now);
  for (let i = 0; i < 3; i += 1) {
    throttle.check("1.2.3.4");
    throttle.recordFailure("1.2.3.4");
  }
  assert.throws(() => throttle.check("1.2.3.4"), (error) => error.httpStatus === 429 && /retry in 60s/.test(error.message));
  throttle.check("5.6.7.8");
  now = 60_000;
  throttle.check("1.2.3.4");
  assert.equal(new AuthFailureThrottle(0, 60_000).enabled, false);
});

test("gateway answers 429 after repeated bad keys, for client and admin routes alike", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "3" });
  try {
    const models = (key) => fetch(`${gateway.baseUrl}/v1/models`, { headers: { authorization: `Bearer ${key}` } });
    assert.equal((await models(CLIENT_KEY)).status, 200);
    for (let i = 0; i < 3; i += 1) assert.equal((await models("cgk_wrong")).status, 401);
    const blocked = await models("cgk_wrong");
    assert.equal(blocked.status, 429);
    assert.match((await blocked.json()).error.message, /failed authentication/);
    assert.ok(Number(blocked.headers.get("retry-after")) > 0);
    // A blocked address cannot continue checking guesses, even against valid credentials.
    assert.equal((await models(CLIENT_KEY)).status, 429);
    const admin = await fetch(`${gateway.baseUrl}/admin/api/overview`, { headers: { authorization: "Bearer it-admin-key" } });
    assert.equal(admin.status, 429);
  } finally {
    await gateway.stop();
  }
});

test("good keys are never counted and the limit can be switched off", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ AUTH_FAILURE_LIMIT: "0" });
  try {
    for (let i = 0; i < 30; i += 1) {
      const res = await fetch(`${gateway.baseUrl}/admin/api/overview`, { headers: { authorization: "Bearer nope" } });
      assert.equal(res.status, 401);
    }
  } finally {
    await gateway.stop();
  }
});

test("admin page cannot be framed", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({});
  try {
    const res = await fetch(`${gateway.baseUrl}/admin/`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.match(res.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  } finally {
    await gateway.stop();
  }
});
