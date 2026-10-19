import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { DatabaseSync } from "node:sqlite";
import type { ApiKeyRow } from "./contracts.js";
import { authenticationError, permissionError } from "./errors.js";
import { getApiKeyByDigest } from "./db.js";
import { guardAuth } from "./auth-throttle.js";
import { readAdminToken, readClientToken } from "./http.js";

export function generateClientKey(): {
  plaintext: string;
  prefix: string;
  digestPeppered: (pepper: string) => string;
} {
  const plaintext = `cgk_${randomBytes(32).toString("base64url")}`;
  return {
    plaintext,
    prefix: plaintext.slice(0, 12),
    digestPeppered: (pepper: string) => digestClientKey(pepper, plaintext),
  };
}

export function digestClientKey(pepper: string, plaintext: string): string {
  return createHmac("sha256", pepper).update(plaintext).digest("hex");
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length % 2 !== 0) return false;
  if (!/^[0-9a-fA-F]+$/.test(a) || !/^[0-9a-fA-F]+$/.test(b)) return false;
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function requireClientKey(
  req: IncomingMessage,
  db: DatabaseSync,
  pepper: string,
): ApiKeyRow {
  return guardAuth(req, "client", readClientToken(req) !== null, () => checkClientKey(req, db, pepper));
}

function checkClientKey(req: IncomingMessage, db: DatabaseSync, pepper: string): ApiKeyRow {
  const token = readClientToken(req);
  if (token === null) {
    throw authenticationError();
  }
  const digest = digestClientKey(pepper, token);
  const row = getApiKeyByDigest(db, digest);
  if (!row) {
    throw authenticationError();
  }
  if (row.enabled !== 1) {
    throw permissionError("API key is disabled");
  }
  return row;
}

export function requireAdminKey(req: IncomingMessage, adminAccessKey: string): void {
  const presented = (readAdminToken(req) ?? "").trim();
  guardAuth(req, "admin", presented !== "", () => checkAdminKey(req, adminAccessKey));
}

function checkAdminKey(req: IncomingMessage, adminAccessKey: string): void {
  const token = (readAdminToken(req) ?? "").trim();
  const expected = adminAccessKey.trim();
  if (!timingSafeEqualUtf8(token, expected)) {
    throw authenticationError("Invalid ADMIN_ACCESS_KEY");
  }
}

/**
 * Constant-time string comparison. Both sides are hashed to fixed-length SHA-256 digests first, so
 * the comparison takes the same time whatever the lengths are and does not leak the key length.
 */
export function timingSafeEqualUtf8(a: string, b: string): boolean {
  const left = createHash("sha256").update(a, "utf8").digest();
  const right = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(left, right);
}
