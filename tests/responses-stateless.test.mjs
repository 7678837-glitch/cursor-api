import assert from "node:assert/strict";
import { test } from "node:test";
import { CLIENT_KEY, startFakeGateway } from "./fixtures/gateway-harness.mjs";

const tool = { type: "function", name: "get_weather", parameters: { type: "object", properties: { query: { type: "string" } } } };

async function responses(gateway, body) {
  const res = await fetch(`${gateway.baseUrl}/v1/responses`, {
    method: "POST",
    headers: { authorization: `Bearer ${CLIENT_KEY}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  assert.equal(res.status, 200);
  return res.json();
}

for (const echoReasoning of [false, true]) {
  test(`stateless Responses tool round continues the parked agent (reasoning echoed: ${echoReasoning})`, { timeout: 20_000 }, async () => {
    const gateway = await startFakeGateway({});
    try {
      const first = await responses(gateway, { model: "fake-model", input: "CALL_TOOL go", tools: [tool] });
      const call = first.output.find((item) => item.type === "function_call");
      assert.ok(call);
      const replayed = echoReasoning ? first.output : [call];
      const second = await responses(gateway, {
        model: "fake-model",
        tools: [tool],
        input: [
          { role: "user", content: "CALL_TOOL go" },
          ...replayed,
          { type: "function_call_output", call_id: call.call_id, output: "rainy" },
        ],
      });
      const text = second.output.find((item) => item.type === "message")?.content?.[0]?.text;
      assert.equal(text, "tool said: rainy");
      assert.doesNotMatch(gateway.output(), /replaying tool results from transcript/);
    } finally {
      await gateway.stop();
    }
  });
}
