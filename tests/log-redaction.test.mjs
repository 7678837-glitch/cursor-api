import assert from "node:assert/strict";
import { test } from "node:test";
import { sanitizeFields, scrubSecrets } from "../dist/log.js";

test("nested arrays redact both free text secrets and credential fields", () => {
  const out = sanitizeFields({ nested: [{ input_tokens: 5, token: "private" }, "Bearer cgk_abcdefghijklmnop"] });
  assert.deepEqual(out, { nested: [{ input_tokens: 5, token: "[redacted]" }, "Bearer [redacted]"] });
});

test("token counts and ordinary text survive redaction", () => {
  const out = sanitizeFields({
    input_tokens: 120,
    output_tokens: 45,
    max_tokens: 4096,
    total_tokens: 165,
    error: "max_tokens must be a positive integer",
    model: "gpt-5",
    tokens_stored: true,
    api_key_id: "k_123",
    key_prefix: "cgk_abc",
  });
  assert.deepEqual(out, {
    input_tokens: 120,
    output_tokens: 45,
    max_tokens: 4096,
    total_tokens: 165,
    error: "max_tokens must be a positive integer",
    model: "gpt-5",
    tokens_stored: true,
    api_key_id: "k_123",
    key_prefix: "cgk_abc",
  });
});

test("credential fields are redacted whatever their value", () => {
  const out = sanitizeFields({
    api_key: "anything",
    authorization: "Bearer abc",
    "x-api-key": "k",
    admin_access_key: "admin",
    api_key_pepper: "p",
    token: "t",
    refresh_token: "r",
    client_secret: "s",
    password: "pw",
    cookie: "sid=1",
  });
  for (const value of Object.values(out)) assert.equal(value, "[redacted]");
});

test("secrets embedded in free text are masked in place", () => {
  assert.equal(scrubSecrets("auth Bearer cgk_abcdefgh12345 failed"), "auth Bearer [redacted] failed");
  assert.equal(scrubSecrets("key cgk_abcdef123456 disabled"), "key [redacted] disabled");
  assert.equal(scrubSecrets("upstream rejected key_0123456789abcdefghijklmn"), "upstream rejected [redacted]");
  assert.equal(scrubSecrets("bad config api_key=supersecretvalue here"), "bad config api_key=[redacted] here");
  assert.equal(scrubSecrets('{"token": "abcdef123456"}'), '{"token": "[redacted]"}');
  assert.equal(scrubSecrets("request failed after 3 retries"), "request failed after 3 retries");
});
