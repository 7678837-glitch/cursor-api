import { randomUUID } from "node:crypto";
import type { CursorCost, ModelParam, OpenAiToolCall, ParsedChatRequest, Usage } from "./contracts.js";
import { GatewayError, invalidRequest, serverError } from "./errors.js";
import { parseChatCompletionsRequest } from "./openai.js";

/**
 * Anthropic Messages API (`POST /v1/messages`) adapter.
 *
 * Requests are translated into the Chat Completions shape and validated by
 * `parseChatCompletionsRequest`, so model knobs, tools, images and
 * conversation routing behave exactly like `/v1/chat/completions`.
 */

/** Sampling / beta fields Anthropic clients send by default. Cursor has no equivalent; ignored. */
const IGNORED_FIELDS = new Set([
  "temperature",
  "top_p",
  "top_k",
  "thinking",
  "service_tier",
  "container",
  "context_management",
  "mcp_servers",
  "output_config",
  "betas",
]);

const PASSTHROUGH_FIELDS = [
  "params",
  "variant",
  "reasoning_effort",
  "verbosity",
  "fast",
  "optimize_for",
] as const;

const ACCEPTED_FIELDS = new Set<string>([
  "model",
  "messages",
  "system",
  "max_tokens",
  "stream",
  "stop_sequences",
  "metadata",
  "tools",
  "tool_choice",
  "conversation_id",
  ...PASSTHROUGH_FIELDS,
  ...IGNORED_FIELDS,
]);

const SKIPPED_BLOCK_TYPES = new Set(["thinking", "redacted_thinking"]);

export function parseAnthropicMessagesRequest(body: unknown): ParsedChatRequest {
  if (!isPlainObject(body)) {
    throw invalidRequest("Request body must be a JSON object");
  }
  for (const key of Object.keys(body)) {
    if (!ACCEPTED_FIELDS.has(key)) {
      throw invalidRequest(`Unknown field '${key}'`);
    }
  }
  if ("max_tokens" in body && body.max_tokens !== undefined) {
    if (typeof body.max_tokens !== "number" || !Number.isInteger(body.max_tokens) || body.max_tokens < 1) {
      throw invalidRequest("Field 'max_tokens' must be a positive integer");
    }
  }
  if (body.stop_sequences !== undefined) {
    if (!Array.isArray(body.stop_sequences)) {
      throw invalidRequest("Field 'stop_sequences' must be an array");
    }
    if (body.stop_sequences.length > 0) {
      throw invalidRequest("Field 'stop_sequences' is not supported");
    }
  }
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    throw invalidRequest("Field 'messages' must be a non-empty array");
  }

  const messages: Record<string, unknown>[] = [];
  const system = systemText(body.system);
  if (system !== undefined) {
    messages.push({ role: "system", content: system });
  }
  body.messages.forEach((item, index) => {
    messages.push(...convertMessage(item, index));
  });

  const chatBody: Record<string, unknown> = {
    model: body.model,
    messages,
    stream: body.stream,
    max_tokens: body.max_tokens,
    tools: convertTools(body.tools),
    tool_choice: convertToolChoice(body.tool_choice),
  };
  for (const field of PASSTHROUGH_FIELDS) {
    if (body[field] !== undefined) chatBody[field] = body[field];
  }
  const conversationId = conversationIdOf(body);
  if (conversationId !== undefined) chatBody.conversation_id = conversationId;
  for (const key of Object.keys(chatBody)) {
    if (chatBody[key] === undefined) delete chatBody[key];
  }
  const parsed = parseChatCompletionsRequest(chatBody);
  parsed.includeUsage = true;
  return parsed;
}

function systemText(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "string") return value === "" ? undefined : value;
  if (!Array.isArray(value)) {
    throw invalidRequest("Field 'system' must be a string or an array of text blocks");
  }
  const parts = value.map((block, index) => {
    if (!isPlainObject(block) || block.type !== "text" || typeof block.text !== "string") {
      throw invalidRequest(`system[${String(index)}] must be a text block`);
    }
    return block.text;
  });
  const text = parts.filter((part) => part !== "").join("\n\n");
  return text === "" ? undefined : text;
}

function convertMessage(item: unknown, index: number): Record<string, unknown>[] {
  const label = `messages[${String(index)}]`;
  if (!isPlainObject(item)) {
    throw invalidRequest(`${label} must be an object`);
  }
  if (item.role !== "user" && item.role !== "assistant") {
    throw invalidRequest(`${label}.role must be 'user' or 'assistant'`);
  }
  const blocks = normalizeBlocks(item.content, label);
  return item.role === "assistant"
    ? [convertAssistant(blocks, label)]
    : convertUser(blocks, label);
}

function normalizeBlocks(content: unknown, label: string): Record<string, unknown>[] {
  if (typeof content === "string") {
    return [{ type: "text", text: content }];
  }
  if (!Array.isArray(content)) {
    throw invalidRequest(`${label}.content must be a string or an array of content blocks`);
  }
  return content.map((block, index) => {
    if (!isPlainObject(block) || typeof block.type !== "string") {
      throw invalidRequest(`${label}.content[${String(index)}] must be a typed content block`);
    }
    return block;
  });
}

function convertAssistant(blocks: Record<string, unknown>[], label: string): Record<string, unknown> {
  const text: string[] = [];
  const toolCalls: Record<string, unknown>[] = [];
  blocks.forEach((block, index) => {
    const where = `${label}.content[${String(index)}]`;
    if (SKIPPED_BLOCK_TYPES.has(block.type as string)) return;
    if (block.type === "text") {
      text.push(textOf(block, where));
      return;
    }
    if (block.type === "tool_use") {
      if (typeof block.id !== "string" || block.id === "") {
        throw invalidRequest(`${where}.id must be a non-empty string`);
      }
      if (typeof block.name !== "string" || block.name === "") {
        throw invalidRequest(`${where}.name must be a non-empty string`);
      }
      toolCalls.push({
        id: block.id,
        type: "function",
        function: { name: block.name, arguments: JSON.stringify(block.input ?? {}) },
      });
      return;
    }
    throw invalidRequest(`${where}.type '${String(block.type)}' is not supported in assistant messages`);
  });
  const message: Record<string, unknown> = { role: "assistant", content: text.join("") };
  if (toolCalls.length > 0) message.tool_calls = toolCalls;
  return message;
}

/**
 * A user turn may carry `tool_result` blocks plus extra text (for example
 * client reminders). Results become `tool` messages; leftover text is folded
 * into the last result so the turn still reads as a tool-result round.
 */
function convertUser(blocks: Record<string, unknown>[], label: string): Record<string, unknown>[] {
  const toolMessages: Array<{ role: "tool"; tool_call_id: string; content: string }> = [];
  const parts: Record<string, unknown>[] = [];
  blocks.forEach((block, index) => {
    const where = `${label}.content[${String(index)}]`;
    if (block.type === "tool_result") {
      if (typeof block.tool_use_id !== "string" || block.tool_use_id === "") {
        throw invalidRequest(`${where}.tool_use_id must be a non-empty string`);
      }
      const body = toolResultText(block.content, where);
      toolMessages.push({
        role: "tool",
        tool_call_id: block.tool_use_id,
        content: block.is_error === true ? `[error]\n${body}` : body,
      });
      return;
    }
    if (block.type === "text") {
      parts.push({ type: "text", text: textOf(block, where) });
      return;
    }
    if (block.type === "image") {
      parts.push({ type: "image_url", image_url: { url: imageUrlOf(block, where) } });
      return;
    }
    throw invalidRequest(`${where}.type '${String(block.type)}' is not supported in user messages`);
  });

  if (toolMessages.length === 0) {
    return [{ role: "user", content: parts }];
  }
  const extra = parts
    .filter((part) => part.type === "text")
    .map((part) => part.text as string)
    .filter((text) => text.trim() !== "");
  if (parts.some((part) => part.type === "image_url")) {
    throw invalidRequest(`${label}: images cannot be sent alongside tool_result blocks`);
  }
  if (extra.length > 0) {
    const last = toolMessages[toolMessages.length - 1];
    if (last) last.content = `${last.content}\n\n${extra.join("\n\n")}`;
  }
  return toolMessages;
}

function toolResultText(content: unknown, where: string): string {
  if (content === undefined || content === null) return "";
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) {
    throw invalidRequest(`${where}.content must be a string or an array of text blocks`);
  }
  return content
    .map((block, index) => {
      if (isPlainObject(block) && block.type === "text" && typeof block.text === "string") {
        return block.text;
      }
      if (isPlainObject(block) && block.type === "image") {
        return "[image omitted]";
      }
      throw invalidRequest(`${where}.content[${String(index)}] must be a text block`);
    })
    .join("\n");
}

function textOf(block: Record<string, unknown>, where: string): string {
  if (typeof block.text !== "string") {
    throw invalidRequest(`${where}.text must be a string`);
  }
  return block.text;
}

function imageUrlOf(block: Record<string, unknown>, where: string): string {
  const source = block.source;
  if (!isPlainObject(source)) {
    throw invalidRequest(`${where}.source must be an object`);
  }
  if (source.type === "base64") {
    if (typeof source.media_type !== "string" || !source.media_type.startsWith("image/")) {
      throw invalidRequest(`${where}.source.media_type must be an image MIME type`);
    }
    if (typeof source.data !== "string" || source.data === "") {
      throw invalidRequest(`${where}.source.data must be a non-empty base64 string`);
    }
    return `data:${source.media_type};base64,${source.data}`;
  }
  if (source.type === "url") {
    if (typeof source.url !== "string" || source.url === "") {
      throw invalidRequest(`${where}.source.url must be a non-empty string`);
    }
    return source.url;
  }
  throw invalidRequest(`${where}.source.type must be 'base64' or 'url'`);
}

function convertTools(value: unknown): Record<string, unknown>[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw invalidRequest("Field 'tools' must be an array");
  }
  const tools: Record<string, unknown>[] = [];
  value.forEach((tool, index) => {
    if (!isPlainObject(tool)) {
      throw invalidRequest(`tools[${String(index)}] must be an object`);
    }
    // Server tools (web_search_20250305, bash_20250124, …) carry a versioned type and no schema.
    if (tool.type !== undefined && tool.type !== "custom" && tool.input_schema === undefined) {
      return;
    }
    if (typeof tool.name !== "string" || tool.name === "") {
      throw invalidRequest(`tools[${String(index)}].name must be a non-empty string`);
    }
    if (tool.input_schema !== undefined && !isPlainObject(tool.input_schema)) {
      throw invalidRequest(`tools[${String(index)}].input_schema must be an object`);
    }
    tools.push({
      type: "function",
      function: {
        name: tool.name,
        ...(typeof tool.description === "string" && tool.description !== ""
          ? { description: tool.description }
          : {}),
        parameters: tool.input_schema ?? { type: "object", properties: {} },
      },
    });
  });
  return tools;
}

function convertToolChoice(value: unknown): unknown {
  if (value === undefined) return undefined;
  if (!isPlainObject(value) || typeof value.type !== "string") {
    throw invalidRequest("Field 'tool_choice' must be an object with a 'type'");
  }
  switch (value.type) {
    case "auto":
    // Cursor cannot force a tool call; `any` degrades to `auto`.
    case "any":
      return "auto";
    case "none":
      return "none";
    case "tool":
      if (typeof value.name !== "string" || value.name === "") {
        throw invalidRequest("Field 'tool_choice.name' must be a non-empty string");
      }
      return { type: "function", function: { name: value.name } };
    default:
      throw invalidRequest("Field 'tool_choice.type' must be 'auto', 'any', 'tool', or 'none'");
  }
}

function conversationIdOf(body: Record<string, unknown>): unknown {
  if (body.conversation_id !== undefined) return body.conversation_id;
  const metadata = body.metadata;
  if (metadata === undefined || metadata === null) return undefined;
  if (!isPlainObject(metadata)) {
    throw invalidRequest("Field 'metadata' must be an object");
  }
  return metadata.conversation_id;
}

export type AnthropicStopReason = "end_turn" | "tool_use";

export function anthropicStopReason(finishReason: string | undefined): AnthropicStopReason {
  return finishReason === "tool_calls" ? "tool_use" : "end_turn";
}

export function encodeAnthropicUsage(usage: Usage | null): Record<string, number> {
  return {
    input_tokens: usage?.prompt_tokens ?? 0,
    output_tokens: usage?.completion_tokens ?? 0,
    cache_creation_input_tokens: usage?.cache_write_tokens ?? 0,
    cache_read_input_tokens: usage?.cache_read_tokens ?? 0,
  };
}

function encodeCursorExtra(cost?: CursorCost | null, params?: ModelParam[]): Record<string, unknown> {
  return {
    cost: cost ?? null,
    ...(params && params.length > 0 ? { params } : {}),
  };
}

export function toolInputOf(argumentsJson: string): Record<string, unknown> {
  if (argumentsJson.trim() === "") return {};
  try {
    const parsed: unknown = JSON.parse(argumentsJson);
    return isPlainObject(parsed) ? parsed : { value: parsed };
  } catch {
    return { raw: argumentsJson };
  }
}

export function encodeAnthropicMessage(input: {
  id: string;
  model: string;
  content: string;
  reasoning_content?: string;
  tool_calls?: OpenAiToolCall[];
  finish_reason?: "stop" | "tool_calls";
  usage: Usage | null;
  cost?: CursorCost | null;
  params?: ModelParam[];
}): Record<string, unknown> {
  const content: Record<string, unknown>[] = [];
  if (input.reasoning_content) {
    content.push({ type: "thinking", thinking: input.reasoning_content, signature: "" });
  }
  if (input.content !== "") {
    content.push({ type: "text", text: input.content });
  }
  for (const call of input.tool_calls ?? []) {
    content.push({ type: "tool_use", id: call.id, name: call.name, input: toolInputOf(call.arguments) });
  }
  const finish =
    input.finish_reason ?? (input.tool_calls && input.tool_calls.length > 0 ? "tool_calls" : "stop");
  return {
    id: input.id,
    type: "message",
    role: "assistant",
    model: input.model,
    content,
    stop_reason: anthropicStopReason(finish),
    stop_sequence: null,
    usage: encodeAnthropicUsage(input.usage),
    cursor: encodeCursorExtra(input.cost, input.params),
  };
}

const ERROR_TYPE_BY_STATUS: Record<number, string> = {
  400: "invalid_request_error",
  401: "authentication_error",
  403: "permission_error",
  404: "not_found_error",
  409: "invalid_request_error",
  413: "request_too_large",
  429: "rate_limit_error",
  499: "invalid_request_error",
  529: "overloaded_error",
};

export function anthropicErrorType(error: unknown): string {
  const mapped = error instanceof GatewayError ? error : serverError();
  return ERROR_TYPE_BY_STATUS[mapped.httpStatus] ?? "api_error";
}

export function toAnthropicErrorBody(error: unknown, requestId?: string): Record<string, unknown> {
  const mapped = error instanceof GatewayError ? error : serverError();
  return {
    type: "error",
    error: { type: anthropicErrorType(mapped), message: mapped.message, code: mapped.code },
    ...(requestId ? { request_id: requestId } : {}),
  };
}

type OpenBlock =
  | { kind: "thinking"; index: number }
  | { kind: "text"; index: number };

/** Emits Anthropic Messages SSE events (`message_start` … `message_stop`). */
export class AnthropicStreamWriter {
  private nextIndex = 0;
  private open: OpenBlock | undefined;
  private sentText = false;
  private sentToolIds = new Set<string>();

  constructor(
    private readonly emit: (event: string, data: Record<string, unknown>) => Promise<void>,
    private readonly meta: { id: string; model: string },
  ) {}

  async start(): Promise<void> {
    await this.emit("message_start", {
      type: "message_start",
      message: {
        id: this.meta.id,
        type: "message",
        role: "assistant",
        model: this.meta.model,
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: encodeAnthropicUsage(null),
      },
    });
    await this.emit("ping", { type: "ping" });
  }

  async onThinking(text: string): Promise<void> {
    if (text === "") return;
    if (this.open?.kind !== "thinking") {
      await this.closeBlock();
      this.open = { kind: "thinking", index: this.allocate() };
      await this.emit("content_block_start", {
        type: "content_block_start",
        index: this.open.index,
        content_block: { type: "thinking", thinking: "", signature: "" },
      });
    }
    await this.emit("content_block_delta", {
      type: "content_block_delta",
      index: this.open.index,
      delta: { type: "thinking_delta", thinking: text },
    });
  }

  async onText(text: string): Promise<void> {
    if (text === "") return;
    if (this.open?.kind !== "text") {
      await this.closeBlock();
      this.open = { kind: "text", index: this.allocate() };
      await this.emit("content_block_start", {
        type: "content_block_start",
        index: this.open.index,
        content_block: { type: "text", text: "" },
      });
    }
    this.sentText = true;
    await this.emit("content_block_delta", {
      type: "content_block_delta",
      index: this.open.index,
      delta: { type: "text_delta", text },
    });
  }

  async onToolCalls(calls: OpenAiToolCall[]): Promise<void> {
    await this.closeBlock();
    for (const call of calls) {
      if (this.sentToolIds.has(call.id)) continue;
      this.sentToolIds.add(call.id);
      const index = this.allocate();
      await this.emit("content_block_start", {
        type: "content_block_start",
        index,
        content_block: { type: "tool_use", id: call.id, name: call.name, input: {} },
      });
      const input = JSON.stringify(toolInputOf(call.arguments));
      await this.emit("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "input_json_delta", partial_json: input },
      });
      await this.emit("content_block_stop", { type: "content_block_stop", index });
    }
  }

  async complete(result: {
    content: string;
    tool_calls?: OpenAiToolCall[];
    finish_reason?: "stop" | "tool_calls";
    usage: Usage | null;
  }): Promise<void> {
    if (!this.sentText && result.content !== "") {
      await this.onText(result.content);
    }
    if (result.tool_calls && result.tool_calls.length > 0) {
      await this.onToolCalls(result.tool_calls);
    }
    await this.closeBlock();
    await this.emit("message_delta", {
      type: "message_delta",
      delta: { stop_reason: anthropicStopReason(result.finish_reason), stop_sequence: null },
      usage: encodeAnthropicUsage(result.usage),
    });
    await this.emit("message_stop", { type: "message_stop" });
  }

  async fail(error: unknown): Promise<void> {
    await this.closeBlock();
    const body = toAnthropicErrorBody(error);
    await this.emit("error", body);
  }

  private allocate(): number {
    const index = this.nextIndex;
    this.nextIndex += 1;
    return index;
  }

  private async closeBlock(): Promise<void> {
    if (!this.open) return;
    const index = this.open.index;
    this.open = undefined;
    await this.emit("content_block_stop", { type: "content_block_stop", index });
  }
}

export function newAnthropicMessageId(): string {
  return `msg_${randomUUID().replaceAll("-", "")}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
