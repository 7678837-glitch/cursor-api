import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AgentBusyError,
  AuthenticationError,
  ConfigurationError,
  CursorSdkError,
  NetworkError,
  RateLimitError,
} from "@cursor/sdk";
import { mapCursorError, runFailureError } from "../dist/cursor.js";
import { GatewayError } from "../dist/errors.js";
import { CLIENT_KEY, parseSse, startFakeGateway } from "./fixtures/gateway-harness.mjs";

function expectMapped(error, status, code, message) {
  const mapped = mapCursorError(error);
  assert.ok(mapped instanceof GatewayError);
  assert.equal(mapped.httpStatus, status, `${error?.name}: ${mapped.code}`);
  assert.equal(mapped.code, code);
  if (message) assert.match(mapped.message, message);
  return mapped;
}

test("Cursor SDK errors map to specific gateway statuses", () => {
  expectMapped(new AuthenticationError("bad key"), 502, "upstream_authentication_error");
  expectMapped(new RateLimitError("slow down"), 429, "rate_limit_error", /slow down/);
  expectMapped(new AgentBusyError("busy"), 409, "conversation_busy");
  expectMapped(new ConfigurationError("bad model"), 400, "invalid_request", /bad model/);
  expectMapped(new NetworkError("ECONNRESET"), 503, "upstream_unavailable", /Cannot reach Cursor: ECONNRESET/);
  expectMapped(new CursorSdkError("gateway timeout", { status: 504 }), 504, "upstream_timeout", /gateway timeout/);
  expectMapped(new CursorSdkError("deadline", { status: 408 }), 504, "upstream_timeout");
  expectMapped(new CursorSdkError("boom", { status: 500 }), 503, "upstream_unavailable", /boom/);
  expectMapped(new CursorSdkError("flaky", { isRetryable: true }), 503, "upstream_unavailable");
  expectMapped(new CursorSdkError("forbidden", { status: 403 }), 502, "upstream_authentication_error");
  expectMapped(new CursorSdkError("too many", { status: 429 }), 429, "rate_limit_error");
  expectMapped(new CursorSdkError("weird", { status: 418 }), 502, "upstream_error", /Cursor request failed: weird/);
  expectMapped(new Error("internal secret path /etc/x"), 502, "upstream_error", /^Cursor request failed$/);
  const long = expectMapped(new CursorSdkError("x".repeat(1000), { status: 500 }), 503, "upstream_unavailable");
  assert.ok(long.message.length < 400);
  const passthrough = new GatewayError(418, "teapot", "short and stout", "invalid_request_error");
  assert.equal(mapCursorError(passthrough), passthrough);
});

test("failed Cursor runs keep their message and classify by code", () => {
  const cases = [
    [undefined, 502, "upstream_error", /^Cursor request failed$/],
    [{ message: "You have reached your usage limit", code: "resource_exhausted" }, 429, "rate_limit_error", /usage limit/],
    [{ message: "Too Many Requests" }, 429, "rate_limit_error"],
    [{ message: "token invalid", code: "unauthenticated" }, 502, "upstream_authentication_error"],
    [{ message: "context deadline exceeded" }, 504, "upstream_timeout"],
    [{ message: "backend overloaded", code: "unavailable" }, 503, "upstream_unavailable", /overloaded/],
    [{ message: "tool crashed", code: "internal" }, 502, "upstream_error", /Cursor request failed: tool crashed/],
  ];
  for (const [failure, status, code, message] of cases) {
    const mapped = runFailureError(failure);
    assert.equal(mapped.httpStatus, status, JSON.stringify(failure));
    assert.equal(mapped.code, code);
    if (message) assert.match(mapped.message, message);
  }
});

test("HTTP responses surface mapped upstream failures", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway();
  const post = (path, body) =>
    fetch(`${gateway.baseUrl}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${CLIENT_KEY}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  try {
    const quota = await post("/v1/chat/completions", { model: "fake-model", messages: [{ role: "user", content: "RUN_QUOTA" }] });
    assert.equal(quota.status, 429);
    const quotaBody = await quota.json();
    assert.equal(quotaBody.error.code, "rate_limit_error");
    assert.match(quotaBody.error.message, /usage limit/);

    const network = await post("/v1/chat/completions", { model: "fake-model", messages: [{ role: "user", content: "FAIL_NETWORK" }] });
    assert.equal(network.status, 503);
    assert.equal((await network.json()).error.code, "upstream_unavailable");

    const responses = await post("/v1/responses", { model: "fake-model", input: "UPSTREAM_ERROR" });
    assert.equal(responses.status, 503);
    const responsesBody = await responses.json();
    assert.equal(responsesBody.error.code, "upstream_unavailable");
    assert.match(responsesBody.error.message, /model backend unavailable/);

    const streamed = await post("/v1/chat/completions", {
      model: "fake-model",
      stream: true,
      messages: [{ role: "user", content: "RUN_QUOTA stream" }],
    });
    assert.equal(streamed.status, 200);
    const frames = parseSse(await streamed.text());
    const errorFrame = frames.find((frame) => typeof frame.data === "object" && frame.data.error);
    assert.equal(errorFrame.data.error.code, "rate_limit_error");
    assert.equal(frames.at(-1).data, "[DONE]");

    const output = gateway.output();
    assert.match(output, /"message":"cursor upstream error".*"upstream_request_id":"req-net-1"/);
    assert.match(output, /"message":"cursor run failed".*"upstream_code":"resource_exhausted"/);
  } finally {
    await gateway.stop();
  }
});
