import { createHash, randomBytes } from "node:crypto";

const REFRESH_TOKEN_BYTES = 32;

/**
 * Hash a refresh token using SHA-256.
 */
export function hashRefreshToken(token) {
  if (typeof token !== "string" || !token.trim()) {
    throw new TypeError("A valid refresh token is required");
  }

  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Generate a cryptographically secure opaque refresh token.
 *
 * Returns the raw token for the client cookie
 * and its SHA-256 hash for database storage.
 */
export function generateRefreshToken() {
  const token = randomBytes(REFRESH_TOKEN_BYTES).toString("base64url");

  const tokenHash = hashRefreshToken(token);

  return {
    token,
    tokenHash,
  };
}
