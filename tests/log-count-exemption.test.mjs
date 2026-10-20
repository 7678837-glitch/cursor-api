// Regression tests for the token-count exemption in log redaction (#27 review round 2, N1-N4).
// Every secret below is a synthetic fake. Only exports that already exist on main are used, so this
// file can be run against main to show the gap.
import assert from "node:assert/strict";
import { test } from "node:test";
import { logError, logInfo, sanitizeFields, scrubSecrets, setSystemLogWriter } from "../dist/log.js";
import { parseChatCompletionsRequest } from "../dist/openai.js";
import { CLIENT_KEY, startFakeGateway } from "./fixtures/gateway-harness.mjs";

const S = "FAKEs3cr3tVALUE9x";
const REDACTED = "[redacted]";

/** Runs one log call and returns both sinks: the stdout/stderr JSON line and the persisted entry. */
function capture(fn) {
  let persisted;
  let line = "";
  const out = process.stdout.write;
  const err = process.stderr.write;
  setSystemLogWriter((entry) => {
    persisted = entry;
  });
  process.stdout.write = (chunk) => ((line += chunk), true);
  process.stderr.write = (chunk) => ((line += chunk), true);
  try {
    fn();
  } finally {
    process.stdout.write = out;
    process.stderr.write = err;
    setSystemLogWriter(undefined);
  }
  return { stdout: JSON.parse(line), persisted };
}

// ---- N1: no super-linear work on long strings ----

const SIZES = [1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576];
/** Generous linear bound: 40 ms fixed + 0.25 ms per KiB (1 MiB -> 296 ms). */
const boundMs = (bytes) => 40 + (bytes / 1024) * 0.25;

const SHAPES = {
  word_run: (n) => "a".repeat(n),
  word_run_tokens: (n) => `${"a".repeat(n - 6)}tokens`,
  base64url: (n) => `upstream returned ${Buffer.alloc(Math.ceil((n * 3) / 4), 7).toString("base64url").slice(0, n)}`,
  digits_commas: (n) => "1,".repeat(n / 2),
  count_phrases: (n) => "max_tokens ".repeat(Math.ceil(n / 11)).slice(0, n),
  bearer_repeat: (n) => "Bearer ".repeat(Math.ceil(n / 7)).slice(0, n),
  dash_run: (n) => `x-${"-".repeat(n - 2)}`,
};

function timeMs(fn) {
  const started = performance.now();
  fn();
  return performance.now() - started;
}

/** Ascending sizes, so a quadratic implementation fails fast on a small input instead of hanging. */
function assertLinear(label, run) {
  for (const size of SIZES) {
    run(size); // warm-up at this size keeps JIT noise out of the measurement
    const ms = timeMs(() => run(size));
    assert.ok(ms <= boundMs(size), `${label} @ ${size} B took ${ms.toFixed(1)} ms (bound ${boundMs(size).toFixed(0)} ms)`);
  }
}

test("sanitizeFields stays within a linear time bound from 1 KiB to 1 MiB", () => {
  for (const [name, make] of Object.entries(SHAPES)) {
    assertLinear(`sanitizeFields ${name}`, (n) => sanitizeFields({ error_message: make(n) }));
  }
});

test("logInfo/logError (stdout and system_logs) stay within a linear time bound", () => {
  for (const [name, make] of Object.entries(SHAPES)) {
    assertLinear(`logError ${name}`, (n) => {
      const value = make(n);
      capture(() => logError(value, { error_message: value }));
    });
  }
});

test("scrubSecrets stays within a linear time bound", () => {
  for (const [name, make] of Object.entries(SHAPES)) {
    assertLinear(`scrubSecrets ${name}`, (n) => scrubSecrets(make(n)));
  }
});

test("long field names stay within a linear time bound and are masked", () => {
  assertLinear("long upper-case key", (n) => sanitizeFields({ ["A".repeat(n)]: S }));
  assert.deepEqual(sanitizeFields({ [`${"a".repeat(300)}_token`]: S }), { [`${"a".repeat(300)}_token`]: REDACTED });
});

test("an echoed unknown request field name is logged within a linear time bound", () => {
  assertLinear("unknown field echo", (n) => {
    let message = "";
    try {
      parseChatCompletionsRequest({ model: "fake-model", messages: [{ role: "user", content: "hi" }], ["a".repeat(n)]: 1 });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    assert.ok(message !== "", "the long unknown field must be rejected");
    capture(() => logInfo("chat completed", { error_message: message }));
  });
});

test("a huge unknown field name does not stall the gateway event loop", { timeout: 120_000 }, async () => {
  const gateway = await startFakeGateway();
  try {
    for (const size of [81_920, 1_048_576]) {
      const started = Date.now();
      const big = fetch(`${gateway.baseUrl}/v1/chat/completions`, {
        method: "POST",
        headers: { authorization: `Bearer ${CLIENT_KEY}`, "content-type": "application/json" },
        body: JSON.stringify({ model: "fake-model", messages: [{ role: "user", content: "hi" }], ["a".repeat(size)]: 1 }),
      }).then((res) => res.status);
      await new Promise((resolve) => setTimeout(resolve, 20));
      const healthStarted = Date.now();
      const health = await fetch(`${gateway.baseUrl}/health`).then((res) => res.status);
      const healthMs = Date.now() - healthStarted;
      assert.equal(health, 200);
      assert.equal(await big, 400);
      const totalMs = Date.now() - started;
      assert.ok(healthMs < 1_000, `/health waited ${healthMs} ms behind a ${size} B field name`);
      assert.ok(totalMs < 3_000, `${size} B field name request took ${totalMs} ms`);
    }
  } finally {
    await gateway.stop();
  }
});

// ---- N2 / N4: plural and variant credential names and phrasing ----

test("plural and variant credential field names are masked whatever the value type", () => {
  const names = [
    "tokens", "access_tokens", "refresh_tokens", "refreshTokens", "RefreshTokens", "REFRESH_TOKENS",
    "device_tokens", "id_tokens", "idTokens", "api_tokens", "x-auth-tokens", "auth-tokens", "session_tokens",
    "access_token_count_secret", "tokensSecret", "secret_tokens", "api_keys", "apiKeys", "client_secrets",
    "passwords", "cookies", "credentials", "x-api-key",
  ];
  for (const value of [S, [S], { value: S }, 12345678, true]) {
    const out = sanitizeFields(Object.fromEntries(names.map((name) => [name, value])));
    for (const name of names) assert.equal(out[name], REDACTED, `${name} = ${JSON.stringify(value)}`);
  }
});

test("count fields are exempt only for numbers and null", () => {
  const counts = {
    input_tokens: 120, output_tokens: 45, total_tokens: 165, prompt_tokens: 1, completion_tokens: 2,
    reasoning_tokens: 3, cache_read_tokens: 4, cache_write_tokens: 5, max_tokens: 4096, maxTokens: 4096,
    inputTokens: 7, maxOutputTokens: 8, max_completion_tokens: 9, prompt_token_count: 10, token_count: 11,
    cache_read_input_tokens: 12, cache_creation_input_tokens: 13, budget_tokens: 14, cached_tokens: null,
  };
  assert.deepEqual(sanitizeFields(counts), counts);
  for (const value of [S, "4096", [S], { nested: S }, true]) {
    for (const name of ["max_tokens", "input_tokens", "token_count", "inputTokens"]) {
      assert.equal(sanitizeFields({ [name]: value })[name], REDACTED, `${name} = ${JSON.stringify(value)}`);
    }
  }
  const usage = sanitizeFields({ prompt_tokens_details: { cached_tokens: 3, refresh_token: S } });
  assert.deepEqual(usage, { prompt_tokens_details: { cached_tokens: 3, refresh_token: REDACTED } });
  assert.equal(sanitizeFields({ prompt_tokens_details: S }).prompt_tokens_details, REDACTED);
});

/** Elliot's r2 matrix: 9 prefixes x 8 count-like cores x 6 separators = 432 field values. */
function leakingVariants(secret) {
  const prefixes = ["", "refresh_", "access-", "api_", "id", "client_secret_", "password_", "api_key_", "Bearer "];
  const cores = ["tokens", "Tokens", "TOKENS", "token count", "token_count", "token-counts", "tokenCount", "max_tokens"];
  const seps = ["=", ": ", " ", '":"', " is ", '\\":\\"'];
  const leaks = [];
  for (const prefix of prefixes) {
    for (const core of cores) {
      for (const sep of seps) {
        const value = `${prefix}${core}${sep}${secret}`;
        if (sanitizeFields({ detail: value }).detail.includes(secret)) leaks.push(value);
      }
    }
  }
  return leaks;
}

test("plural and count-like phrasing never excuses a credential word in a field value", () => {
  assert.deepEqual(leakingVariants(S), [], "secret-shaped value");
  // A short, plain-word secret right after a bare count field name reads like prose
  // ("max_tokens must be ..."), so only that exact form is let through; nothing else.
  const short = "hunter2pw";
  assert.deepEqual(leakingVariants(short), [
    `max_tokens ${short}`,
    `max_tokens is ${short}`,
    `access-max_tokens ${short}`,
    `access-max_tokens is ${short}`,
    `Bearer max_tokens ${short}`,
    `Bearer max_tokens is ${short}`,
  ]);
  for (const value of [`the token is ${short}`, `refresh tokens: ${short}`, `token count ${short}`, `max_tokens=${short}`, `"max_tokens":"${short}"`]) {
    assert.equal(sanitizeFields({ detail: value }).detail, REDACTED, value);
  }
  for (const value of [
    `failed to refresh tokens: ${S}`,
    `401 {"id_tokens":"${S}"}`,
    `Unknown field 'refresh_tokens: ${S}'`,
    `Unknown field 'token count ${S}'`,
    `the token is ${S}`,
    `token ${S}`,
  ]) {
    const { stdout, persisted } = capture(() => logError("upstream failed", { error_message: value }));
    assert.equal(stdout.error_message, REDACTED, value);
    assert.equal(persisted.fields.error_message, REDACTED, value);
  }
});

test("count wording without a secret stays readable", () => {
  for (const value of [
    "max_tokens must be a positive integer",
    "prompt is too long: 210000 tokens > 200000 maximum",
    "max_tokens: 4096",
    "maxOutputTokens 8192 exceeds the limit",
    "used 1,234 tokens",
  ]) {
    assert.equal(sanitizeFields({ error: value }).error, value);
  }
});

// ---- N3: the whole-value check looks at the raw value ----

test("a keyword swallowed by an in-place rule still masks the whole value", () => {
  for (const value of [
    `Bearer token_abcdefgh ${S}`,
    `user_01AB::password ${S}`,
    `key-secret_abcdefghijklmnopqrstuv ${S}`,
    `cgk_token_abcdef ${S}`,
  ]) {
    assert.equal(sanitizeFields({ error_message: value }).error_message, REDACTED, value);
  }
});

// ---- N7: format() fallback and singular token ----

test("format() falls back to a log_format_error line instead of throwing", () => {
  const circular = {};
  circular.self = circular;
  for (const fields of [{ big: 10n }, { get boom() { throw new Error(S); } }, { circular }]) {
    let line = "";
    const out = process.stdout.write;
    process.stdout.write = (chunk) => ((line += chunk), true);
    try {
      assert.doesNotThrow(() => logInfo(`message with ${S}`, fields));
    } finally {
      process.stdout.write = out;
    }
    const parsed = JSON.parse(line);
    assert.equal(parsed.log_format_error, true);
    assert.equal(parsed.message, REDACTED);
    assert.ok(!line.includes(S));
  }
});

test("long values are capped before redaction and a secret at the cut does not survive", () => {
  const head = "x ".repeat(8_191); // 16 382 chars, so the secret straddles the 16 KiB cap
  const out = sanitizeFields({ detail: `${head}Bearer abcdefghijklmnopqrstuvwxyz` }).detail;
  assert.ok(out.length < 16_500, `output length ${out.length}`);
  assert.ok(!/abcd/.test(out), out.slice(-40));
  assert.ok(out.endsWith("…[truncated]"));
});

// ---- r3 review R3-1: a credential word past the 16 KiB cut still masks the whole value ----

test("a credential word after the truncation point still masks the whole value", () => {
  const pad = (n) => "lorem ".repeat(Math.ceil(n / 6)).slice(0, n);
  const big = pad(16_400);
  for (const value of [
    `${S} ${big} password`,
    `user FAKEpw ${big} is the password`,
    `${S} ${big} api_key`,
    `${S} ${big} max_tokens`, // no count-phrase excuse once the value is cut
  ]) {
    assert.ok(value.length > 16_384);
    const { stdout, persisted } = capture(() => logInfo("m", { detail: value, error_message: value }));
    for (const out of [stdout.detail, stdout.error_message, persisted.fields.detail, persisted.fields.error_message]) {
      assert.equal(out, REDACTED, value.slice(-30));
    }
  }
  // A long value with no credential word anywhere is still only truncated, not masked.
  const plain = sanitizeFields({ detail: `${big} done` }).detail;
  assert.ok(plain.endsWith("…[truncated]") && plain.startsWith("lorem"), plain.slice(0, 20));
});

// ---- r3 review R3-4: uncapped scrubSecrets must not throw on multi-MB secret-shaped runs ----

test("scrubSecrets handles 16 MiB secret-shaped runs without RangeError and masks them", () => {
  const n = 16 * 1024 * 1024;
  const shapes = {
    key_dash: "key-".repeat(n / 4),
    long_cgk: `cgk_${"A".repeat(n)}`,
    sk_run: `sk-${"a".repeat(n)}`,
    bearer_run: `Bearer ${"a".repeat(n)}`,
    basic_run: `Basic ${"A".repeat(n)}`,
  };
  for (const [name, text] of Object.entries(shapes)) {
    let out;
    assert.doesNotThrow(() => {
      out = scrubSecrets(text);
    }, name);
    assert.ok(out.length < 64, `${name}: ${out.length} chars left`);
    assert.ok(out.endsWith(REDACTED), `${name}: ${out.slice(0, 40)}`);
  }
});
