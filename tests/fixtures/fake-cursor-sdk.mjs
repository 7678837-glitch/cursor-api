// In-process stand-in for @cursor/sdk used by the HTTP integration tests.
// Behavior is driven by markers in the prompt text so tests need no Cursor credentials.

export class CursorSdkError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = new.target.name;
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId;
    this.isRetryable = options.isRetryable ?? false;
  }
}
export class CursorAgentError extends CursorSdkError {}
export class AuthenticationError extends CursorAgentError {
  constructor(message, options = {}) {
    super(message, { status: 401, ...options });
  }
}
export class RateLimitError extends CursorAgentError {
  constructor(message, options = {}) {
    super(message, { status: 429, ...options });
  }
}
export class NetworkError extends CursorAgentError {}
export class AgentBusyError extends CursorAgentError {
  constructor(message, options = {}) {
    super(message, { status: 409, ...options });
  }
}
export class ConfigurationError extends CursorAgentError {
  constructor(message, options = {}) {
    super(message, { status: 400, ...options });
  }
}

const CATALOG = [
  { id: "fake-model", displayName: "Fake Model", aliases: ["fake-alias"], parameters: [], variants: [] },
  {
    id: "fake-reasoner",
    displayName: "Fake Reasoner",
    parameters: [
      {
        id: "reasoning_effort",
        displayName: "Reasoning effort",
        values: [{ value: "low" }, { value: "medium" }, { value: "high" }],
      },
    ],
    variants: [
      { displayName: "Fake Reasoner", isDefault: true, params: [{ id: "reasoning_effort", value: "medium" }] },
      { displayName: "Fake Reasoner High", params: [{ id: "reasoning_effort", value: "high" }] },
    ],
  },
];

/** Keys starting with these prefixes simulate upstream failures. */
function checkKey(apiKey) {
  if (typeof apiKey !== "string" || apiKey.startsWith("bad-")) {
    throw new AuthenticationError("invalid key");
  }
  if (apiKey.startsWith("limited-")) {
    throw new RateLimitError("usage limit exceeded");
  }
}

export const calls = { create: [], send: [] };
globalThis.__fakeCursorCalls = calls;

export const Cursor = {
  models: {
    async list({ apiKey }) {
      checkKey(apiKey);
      return CATALOG;
    },
  },
  async me({ apiKey }) {
    checkKey(apiKey);
    return { apiKeyName: "fake", createdAt: "2026-01-01T00:00:00Z", userId: "u1" };
  },
};

let agentSeq = 0;

function makeAgent(apiKey, agentId, model) {
  return {
    agentId,
    apiKey,
    async send(message, options = {}) {
      checkKey(apiKey);
      const prompt = typeof message === "string" ? message : message.text;
      calls.send.push({ apiKey, agentId, prompt });
      if (process.env.FAKE_SDK_DELAY_MS) {
        await new Promise((resolve) => setTimeout(resolve, Number(process.env.FAKE_SDK_DELAY_MS)));
      }
      if (prompt.includes("FAIL_RATE_LIMIT")) {
        throw new RateLimitError("usage limit exceeded");
      }
      if (prompt.includes("FAIL_NETWORK")) {
        throw new NetworkError("connect ECONNREFUSED", { isRetryable: true, requestId: "req-net-1" });
      }
      let text = "";
      let status = "finished";
      let runError;
      const emit = async (update) => {
        await options.onDelta?.({ update });
      };
      const work = (async () => {
        await emit({ type: "thinking-delta", text: "pondering" });
        const tools = options.local?.customTools ?? {};
        const names = Object.keys(tools);
        // `CALL_TOOL<<Name|{"json":"args"}>>` calls a specific client tool.
        const named = /CALL_TOOL<<([A-Za-z0-9_.-]+)\|(\{.*?\})>>/s.exec(prompt);
        if (named && tools[named[1]] && !prompt.includes("[tool ")) {
          const result = await tools[named[1]].execute(JSON.parse(named[2]), { toolCallId: `tool-${named[1]}` });
          text = `tool said: ${result}`;
          await emit({ type: "text-delta", text });
          return;
        }
        if (prompt.includes("ECHO_MODEL")) {
          text = JSON.stringify(model ?? null);
          await emit({ type: "text-delta", text });
          return;
        }
        if (prompt.includes("CALL_TOOL") && names.length > 0) {
          const result = await tools[names[0]].execute({ query: "weather" }, { toolCallId: "tool-1" });
          text = `tool said: ${result}`;
          await emit({ type: "text-delta", text });
          return;
        }
        if (prompt.includes("UPSTREAM_ERROR")) {
          status = "error";
          runError = { message: "model backend unavailable", code: "unavailable" };
          return;
        }
        if (prompt.includes("RUN_QUOTA")) {
          status = "error";
          runError = { message: "You have reached your usage limit", code: "resource_exhausted" };
          return;
        }
        for (const part of ["PO", "NG"]) {
          text += part;
          await emit({ type: "text-delta", text: part });
        }
      })();
      return {
        supports: () => true,
        async cancel() {
          status = "cancelled";
        },
        async wait() {
          await work;
          return {
            status,
            result: status === "finished" ? text : undefined,
            ...(runError ? { error: runError } : {}),
            usage: { inputTokens: 11, outputTokens: 2, totalTokens: 13, cacheReadTokens: 3, cacheWriteTokens: 0 },
          };
        },
      };
    },
    async getUsage() {
      return undefined;
    },
    close() {},
    async [Symbol.asyncDispose]() {},
  };
}

export const Agent = {
  async create(options) {
    checkKey(options.apiKey);
    agentSeq += 1;
    calls.create.push({ apiKey: options.apiKey });
    return makeAgent(options.apiKey, `agent-${String(agentSeq)}`, options.model);
  },
  async resume(agentId, options) {
    checkKey(options.apiKey);
    return makeAgent(options.apiKey, agentId, options.model);
  },
};
