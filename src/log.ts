/**
 * Field names whose values are credentials. Token *counts* (`input_tokens`, `max_tokens`) are not
 * secrets, so `token` only matches as a whole word or with a credential-style suffix.
 */
const SENSITIVE_KEY =
  /api[_-]?key|access[_-]?key|authorization|cookie|pepper|secret|password|passwd|credential|(^|[_-])token($|[_-](value|secret))|bearer/i;

/** Credential-looking substrings inside free text, masked in place so the rest stays readable. */
const SECRET_PATTERNS: RegExp[] = [
  /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\bcgk_[A-Za-z0-9_-]{6,}/g,
  /\b(sk|key|crsr|cursor|user)[-_][A-Za-z0-9_-]{20,}/g,
  /\b(api[_-]?key|access[_-]?key|token|secret|password|pepper)(["']?\s*[:=]\s*["']?)[^\s"',;&]{6,}/gi,
];

export function scrubSecrets(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match, ...groups) => {
      // Keep the scheme or field name and separator, drop the value.
      if (/^(Bearer|Basic)\s/i.test(match)) return `${String(groups[0])} [redacted]`;
      if (typeof groups[1] === "string" && /[:=]/.test(groups[1])) return `${String(groups[0])}${groups[1]}[redacted]`;
      return "[redacted]";
    });
  }
  return out;
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
    if (SENSITIVE_KEY.test(key) && value !== null && value !== undefined && typeof value !== "number" && typeof value !== "boolean") {
      safe[key] = "[redacted]";
      continue;
    }
    safe[key] = typeof value === "string" ? scrubSecrets(value) : value;
  }
  return safe;
}

function format(level: string, message: string, fields?: Record<string, unknown>): string {
  const safe: Record<string, unknown> = { level, message: scrubSecrets(message), ts: new Date().toISOString() };
  if (fields) Object.assign(safe, sanitizeFields(fields));
  return JSON.stringify(safe);
}
