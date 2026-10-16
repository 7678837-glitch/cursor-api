import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "../dist/config.js";
import { countConversations, openDb, pruneConversations, upsertConversation } from "../dist/db.js";
import { sessionStats, sweepSessions } from "../dist/session.js";
import { CLIENT_KEY, startFakeGateway } from "./fixtures/gateway-harness.mjs";

test("session limits config defaults and bounds", () => {
  const root = mkdtempSync(join(tmpdir(), "cursor-api-sessions-"));
  mkdirSync(join(root, "data", "config"), { recursive: true });
  writeFileSync(
    join(root, "data", "config", "gateway.toml"),
    ['cursor_api_key = "c"', 'admin_access_key = "a"', 'api_key_pepper = "p"', ""].join("\n"),
  );
  const cfg = loadConfig({ DATA_DIR: "data" }, root);
  assert.equal(cfg.maxLiveSessions, 256);
  assert.equal(cfg.conversationTtlDays, 30);
  const env = loadConfig({ DATA_DIR: "data", MAX_LIVE_SESSIONS: "8", CONVERSATION_TTL_DAYS: "2" }, root);
  assert.equal(env.maxLiveSessions, 8);
  assert.equal(env.conversationTtlDays, 2);
  assert.throws(() => loadConfig({ DATA_DIR: "data", MAX_LIVE_SESSIONS: "0" }, root), /MAX_LIVE_SESSIONS/);
  assert.throws(() => loadConfig({ DATA_DIR: "data", CONVERSATION_TTL_DAYS: "9999" }, root), /CONVERSATION_TTL_DAYS/);
});

test("sweep prunes conversation mappings older than the TTL", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cursor-api-sweep-"));
  const db = openDb(dir, { retentionDays: 7, maxRows: 1000, maxDetailBytes: 1_048_576 });
  upsertConversation(db, "k1", "fresh", "agent-1");
  upsertConversation(db, "k1", "stale", "agent-2");
  db.prepare("UPDATE conversations SET updated_at = ? WHERE conversation_id = 'stale'").run("2000-01-01T00:00:00.000Z");
  assert.equal(countConversations(db), 2);
  const result = await sweepSessions({ db, conversationTtlDays: 30 });
  assert.deepEqual(result, { expired: 0, conversationsPruned: 1 });
  assert.equal(countConversations(db), 1);
  assert.equal(pruneConversations(db, new Date(Date.now() + 1000).toISOString()), 1);
  assert.equal(sessionStats().conversations_pruned_total, 1);
  assert.equal(sessionStats().live, 0);
  db.close();
});

const tools = [{ type: "function", function: { name: "lookup", parameters: { type: "object", properties: {} } } }];

async function chat(baseUrl, body) {
  return fetch(`${baseUrl}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: `Bearer ${CLIENT_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ model: "fake-model", ...body }),
  });
}

async function overview(baseUrl) {
  const res = await fetch(`${baseUrl}/admin/api/overview`, { headers: { authorization: "Bearer it-admin-key" } });
  return (await res.json()).sessions;
}

test("parked sessions beyond max_live_sessions evict the least recently active", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ MAX_LIVE_SESSIONS: "2" });
  try {
    const parked = [];
    for (const name of ["a", "b", "c"]) {
      const messages = [{ role: "user", content: `CALL_TOOL ${name}` }];
      const res = await chat(gateway.baseUrl, { tools, messages, conversation_id: `conv-${name}` });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.choices[0].finish_reason, "tool_calls");
      parked.push({ name, messages, call: body.choices[0].message.tool_calls[0] });
    }
    let stats = await overview(gateway.baseUrl);
    assert.equal(stats.live, 2);
    assert.equal(stats.parked, 2);
    assert.equal(stats.max, 2);
    assert.equal(stats.evicted_total, 1);
    assert.match(gateway.output(), /evicted parked session/);

    // The evicted conversation still completes, via transcript replay on a new agent.
    const [first] = parked;
    const resumed = await chat(gateway.baseUrl, {
      tools,
      conversation_id: "conv-a",
      messages: [
        ...first.messages,
        { role: "assistant", content: null, tool_calls: [first.call] },
        { role: "tool", tool_call_id: first.call.id, content: "42" },
      ],
    });
    assert.equal(resumed.status, 200);
    stats = await overview(gateway.baseUrl);
    assert.ok(stats.live <= 2);
  } finally {
    await gateway.stop();
  }
});

test("when every session is running, new work gets 503 instead of unbounded growth", { timeout: 20_000 }, async () => {
  const gateway = await startFakeGateway({ MAX_LIVE_SESSIONS: "1", FAKE_SDK_DELAY_MS: "400" });
  try {
    const slow = chat(gateway.baseUrl, { messages: [{ role: "user", content: "slow one" }] });
    await new Promise((resolve) => setTimeout(resolve, 150));
    const busy = await chat(gateway.baseUrl, { messages: [{ role: "user", content: "second" }] });
    assert.equal(busy.status, 503);
    assert.equal((await busy.json()).error.code, "too_many_sessions");
    assert.equal((await slow).status, 200);
    const stats = await overview(gateway.baseUrl);
    assert.equal(stats.rejected_total, 1);
    assert.equal(stats.live, 0);
    const after = await chat(gateway.baseUrl, { messages: [{ role: "user", content: "third" }] });
    assert.equal(after.status, 200);
  } finally {
    await gateway.stop();
  }
});
