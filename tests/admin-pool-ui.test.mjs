import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const html = readFileSync(new URL("../public/admin.html", import.meta.url), "utf8");

function dict(name) {
  const start = html.indexOf(`const ${name} = {`);
  assert.ok(start > 0, `${name} dictionary present`);
  const body = html.slice(start, html.indexOf("\n    };", start));
  return new Set([...body.matchAll(/^\s+"([^"]+)":/gm)].map((m) => m[1]));
}

test("admin console has a Cursor key pool view wired to the status API", () => {
  assert.match(html, /data-view="pool"/);
  assert.match(html, /id="view-pool"/);
  assert.match(html, /\/admin\/api\/cursor-keys/);
  assert.match(html, /if \(name === "pool"\) loadPool\(\)/);
  for (const field of ["active_requests", "successes", "failures", "consecutive_failures", "cooldown_until", "last_used_at"]) {
    assert.ok(html.includes(`row.${field}`), `renders ${field}`);
  }
});

test("every pool label is translated in both languages", () => {
  const used = new Set([...html.matchAll(/t\("(pool\.[a-zA-Z_.]+)"\)/g)].map((m) => m[1]));
  for (const dynamic of ["round_robin", "least_active"]) used.add(`pool.strategy.${dynamic}`);
  for (const dynamic of ["rate_limit", "auth"]) used.add(`pool.failure.${dynamic}`);
  used.add("nav.pool");
  const zh = dict("ZH");
  const en = dict("EN");
  for (const key of used) {
    assert.ok(en.has(key), `EN has ${key}`);
    assert.ok(zh.has(key), `ZH has ${key}`);
  }
});
