/**
 * Field names whose values are credentials. Matched as a substring of the lower-cased name, so
 * camelCase and prefixed forms are covered (`accessToken`, `WorkosCursorSessionToken`, `tokenValue`,
 * `token_hash`, `client_secret_name`). Token *counts* are carved out by COUNT_WORDS below.
 */
const SENSITIVE_KEY = /api[_-]?key|access[_-]?key|private[_-]?key|authorization|cookie|pepper|secret|token|password|passwd|credential|bearer|jwt/i;

/** Count-style names (`input_tokens`, `maxTokens`, `prompt_token_count`) are removed before matching. */
const COUNT_WORDS = /(^|_)([a-z0-9]*tokens|token_counts?)(?=_|$)/g;

/** Names that only identify a credential. Exact names only; no generic suffix exemption. */
const IDENTIFIER_KEYS = new Set(["api_key_id", "api_key_ids", "key_id", "key_prefix", "api_key_prefix", "api_key_name"]);

/** `accessToken` -> `access_token`, `X-Cursor-Token` -> `x_cursor_token`, `APIKey` -> `api_key`. */
function normalizeKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/[\s.-]+/g, "_")
    .toLowerCase();
}

function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (IDENTIFIER_KEYS.has(normalized)) return false;
  return SENSITIVE_KEY.test(normalized.replace(COUNT_WORDS, "$1"));
}

const REDACTED = "[redacted]";

/** Separator after a field-style name: `=`, `:`, with optional (JSON-escaped) quotes. */
const SEP = String.raw`(\\?["']?\s*[:=]\s*\\?["']?)`;
/** A value: anything up to whitespace, a quote, a backslash or a list/query separator. */
const VALUE = String.raw`(?!\[redacted\])(?!(?:null|true|false)\b)(?!\d+\s+tokens\b)[^\s"',;&\\]+`;

type Rule = { pattern: RegExp; replace: (match: string, ...args: string[]) => string };

/**
 * Credential-looking substrings inside free text, masked in place so the rest stays readable.
 * Each rule has its own replacer and only reads its own capture groups, so a pattern without a
 * group can never pick up String.replace's offset/input arguments.
 */
const SECRET_RULES: Rule[] = [
  // `Authorization: Token abc`, `proxy-authorization=Basic abc`: mask the scheme and value.
  {
    pattern: new RegExp(String.raw`\b((?:proxy[_-])?authorization)${SEP}(?!\[redacted\])(?:[A-Za-z]+[ \t]+)?[^\s"',;&\\]+`, "gi"),
    replace: (_match, name, sep) => `${name}${sep}${REDACTED}`,
  },
  // Cursor session token `user_xxx::<jwt>` (also URL-encoded `%3A%3A`): mask the whole thing.
  {
    pattern: /\buser_[A-Za-z0-9]+(?:::|%3A%3A)[A-Za-z0-9._~+/=-]+/gi,
    replace: () => REDACTED,
  },
  // `Bearer <value>` (any 8+ chars) and `Basic <base64>` (needs base64 shape, so prose like
  // "Basic authentication" stays readable).
  {
    pattern: /\b(Bearer)(\s+)(?!\[redacted\])[A-Za-z0-9._~+/=-]{8,}/gi,
    replace: (_match, scheme, space) => `${scheme}${space}${REDACTED}`,
  },
  {
    pattern: /\b(Basic)(\s+)(?!\[redacted\])(?:[A-Za-z0-9+/]{20,}={0,2}|(?=[A-Za-z0-9+/]*[0-9+/])[A-Za-z0-9+/]{4,}={0,2}|[A-Za-z0-9+/]{2,}={1,2})(?![A-Za-z0-9+/=])/g,
    replace: (_match, scheme, space) => `${scheme}${space}${REDACTED}`,
  },
  { pattern: /\bcgk_[A-Za-z0-9_-]{6,}/g, replace: () => REDACTED },
  { pattern: /\b(?:sk|key|crsr|cursor)[-_][A-Za-z0-9_-]{20,}/g, replace: () => REDACTED },
  // `api_key=…`, `access_token=…`, `client_secret: …`, `"refresh_token":"…"`, `password=abc12`.
  // No left word boundary: `_` is a word character, so `\btoken` would miss `access_token`.
  {
    pattern: new RegExp(
      String.raw`(api[_-]?key|access[_-]?key|private[_-]?key|token|secret|password|passwd|pepper|credential|cookie)${SEP}${VALUE}`,
      "gi",
    ),
    replace: (_match, name, sep) => `${name}${sep}${REDACTED}`,
  },
];

export function scrubSecrets(text: string): string {
  let out = text;
  for (const rule of SECRET_RULES) {
    out = out.replace(rule.pattern, rule.replace as (substring: string, ...args: unknown[]) => string);
  }
  return out;
}

/** Same words the pre-#27 sanitizer used to mask whole values, plus `passwd`. */
const VALUE_KEYWORDS = /api[_-]?key|authorization|pepper|secret|token|password|passwd/i;
/** Count wording that mentions `token` without carrying one (`max_tokens`, `inputTokens`, `token count`). */
const COUNT_WORDING = /[A-Za-z0-9_-]*tokens(?![A-Za-z])|token[_\s-]?counts?/gi;

/**
 * String field values: mask known secret shapes in place; if a credential keyword is still left
 * (outside `[redacted]` and count wording), mask the whole value as the old sanitizer did.
 */
function sanitizeString(value: string): string {
  const scrubbed = scrubSecrets(value);
  const residue = scrubbed.split(REDACTED).join(" ").replace(COUNT_WORDING, " ");
  return VALUE_KEYWORDS.test(residue) ? REDACTED : scrubbed;
}

export type SystemLogEntry = {
  level: "info" | "error";
  message: string;
  fields: Record<string, unknown> | null;
};

type SystemLogWriter = (entry: SystemLogEntry) => void;

let writer: SystemLogWriter | undefined;
let writing = false;

export function setSystemLogWriter(next: SystemLogWriter | undefined): void {
  writer = next;
}

export function logInfo(message: string, fields?: Record<string, unknown>): void {
  process.stdout.write(`${format("info", message, fields)}\n`);
  persist("info", message, fields);
}

/** Startup warnings (stderr only; emitted before the SQLite system-log writer exists). */
export function logWarn(message: string, fields?: Record<string, unknown>): void {
  process.stderr.write(`${format("warn", message, fields)}\n`);
}

export function logError(message: string, fields?: Record<string, unknown>): void {
  process.stderr.write(`${format("error", message, fields)}\n`);
  persist("error", message, fields);
}

function persist(level: "info" | "error", message: string, fields?: Record<string, unknown>): void {
  if (!writer || writing) return;
  writing = true;
  try {
    writer({
      level,
      message: scrubSecrets(message),
      fields: fields === undefined ? null : sanitizeFields(fields),
    });
  } catch {
    // SQLite persist must not recurse through logError or break the request.
  } finally {
    writing = false;
  }
}

/** Byte-safe UTF-8 truncation in O(n). Avoid character-by-character rescans. */
export function truncateUtf8(text: string, maxBytes: number): string {
  if (maxBytes < 1) return "";
  const suffix = "\n…[truncated]";
  const suffixBytes = Buffer.byteLength(suffix, "utf8");
  if (maxBytes <= suffixBytes) {
    return Buffer.from(text, "utf8").subarray(0, maxBytes).toString("utf8");
  }
  const buf = Buffer.from(text, "utf8");
  if (buf.byteLength <= maxBytes) return text;
  let cut = maxBytes - suffixBytes;
  while (cut > 0 && (buf[cut] & 0xc0) === 0x80) {
    cut -= 1;
  }
  return buf.subarray(0, cut).toString("utf8") + suffix;
}

export function sanitizeFields(fields: Record<string, unknown>): Record<string, unknown> {
  const safe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (isSensitiveKey(key) && value !== null && value !== undefined) {
      // Any non-empty value, numbers and booleans included (PINs, OTPs).
      safe[key] = REDACTED;
      continue;
    }
    safe[key] = typeof value === "string" ? sanitizeString(value) : value;
  }
  return safe;
}

function format(level: string, message: string, fields?: Record<string, unknown>): string {
  try {
    const safe: Record<string, unknown> = { level, message: scrubSecrets(message), ts: new Date().toISOString() };
    if (fields) Object.assign(safe, sanitizeFields(fields));
    return JSON.stringify(safe);
  } catch {
    // Logging must never throw into the caller; drop the content rather than risk leaking it.
    return JSON.stringify({ level, message: REDACTED, ts: new Date().toISOString(), log_format_error: true });
  }
}
