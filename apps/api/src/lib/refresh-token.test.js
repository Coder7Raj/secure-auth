import { describe, expect, it } from "vitest";

import { generateRefreshToken, hashRefreshToken } from "./refresh-token.js";

describe("Refresh token utilities", () => {
  describe("generateRefreshToken", () => {
    it("should generate a valid refresh token", () => {
      const result = generateRefreshToken();

      expect(result.token).toEqual(expect.any(String));
      expect(result.tokenHash).toEqual(expect.any(String));
    });

    it("should generate a 43-character Base64URL token", () => {
      const { token } = generateRefreshToken();

      expect(token).toHaveLength(43);
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("should generate a 64-character hexadecimal hash", () => {
      const { tokenHash } = generateRefreshToken();

      expect(tokenHash).toHaveLength(64);
      expect(tokenHash).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should generate unique refresh tokens", () => {
      const first = generateRefreshToken();
      const second = generateRefreshToken();

      expect(first.token).not.toBe(second.token);
      expect(first.tokenHash).not.toBe(second.tokenHash);
    });

    it("should return a hash matching the generated token", () => {
      const { token, tokenHash } = generateRefreshToken();

      expect(hashRefreshToken(token)).toBe(tokenHash);
    });

    it("should not expose the raw token as the hash", () => {
      const { token, tokenHash } = generateRefreshToken();

      expect(tokenHash).not.toBe(token);
    });
  });

  describe("hashRefreshToken", () => {
    it("should generate a deterministic hash", () => {
      const token = "test-refresh-token";

      expect(hashRefreshToken(token)).toBe(hashRefreshToken(token));
    });

    it("should generate different hashes for different tokens", () => {
      const first = hashRefreshToken("first-token");
      const second = hashRefreshToken("second-token");

      expect(first).not.toBe(second);
    });

    it("should reject an empty token", () => {
      expect(() => hashRefreshToken("")).toThrow(
        "A valid refresh token is required",
      );
    });

    it("should reject a non-string token", () => {
      expect(() => hashRefreshToken(null)).toThrow(
        "A valid refresh token is required",
      );
    });
  });
});
