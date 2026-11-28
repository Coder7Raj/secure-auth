import { SignJWT } from "jose";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

process.env.NODE_ENV = "test";
process.env.PORT = "5000";
process.env.CLIENT_URL = "http://localhost:5173";
process.env.DATABASE_URL =
  "postgresql://secureauth:password@localhost:5432/secure_auth";

process.env.JWT_ACCESS_SECRET =
  "test-access-secret-that-is-at-least-32-characters-long";

process.env.JWT_ACCESS_EXPIRES_IN = "15m";
process.env.JWT_ISSUER = "secure-auth-api";
process.env.JWT_AUDIENCE = "secure-auth-api";

const { signAccessToken, verifyAccessToken } = await import("./jwt.js");

const accessSecret = new TextEncoder().encode(process.env.JWT_ACCESS_SECRET);

const testIdentity = {
  userId: "11111111-1111-4111-8111-111111111111",
  sessionId: "22222222-2222-4222-8222-222222222222",
};

async function createTestToken({
  secret = accessSecret,
  issuer = "secure-auth-api",
  audience = "secure-auth-api",
  tokenType = "access",
  expiration = "15m",
  userId = testIdentity.userId,
  sessionId = testIdentity.sessionId,
} = {}) {
  return new SignJWT({
    sid: sessionId,
    tokenType,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(userId)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(expiration)
    .sign(secret);
}

describe("Access JWT utilities", () => {
  it("should generate a valid access token", async () => {
    const token = await signAccessToken(testIdentity);

    expect(token).toEqual(expect.any(String));
    expect(token.split(".")).toHaveLength(3);
  });

  it("should verify a valid access token", async () => {
    const token = await signAccessToken(testIdentity);
    const payload = await verifyAccessToken(token);

    expect(payload.sub).toBe(testIdentity.userId);
    expect(payload.sid).toBe(testIdentity.sessionId);
    expect(payload.tokenType).toBe("access");
    expect(payload.jti).toBeTruthy();
  });

  it("should reject an expired access token", async () => {
    const token = await createTestToken({ expiration: 2 });

    await expect(verifyAccessToken(token)).rejects.toThrow();
  });

  it("should reject an invalid signature", async () => {
    const token = await signAccessToken(testIdentity);
    const parts = token.split(".");

    parts[2] = "invalid-signature";

    await expect(verifyAccessToken(parts.join("."))).rejects.toThrow();
  });

  it("should reject an invalid issuer", async () => {
    const token = await createTestToken({
      issuer: "unexpected-issuer",
    });

    await expect(verifyAccessToken(token)).rejects.toThrow();
  });

  it("should reject an invalid audience", async () => {
    const token = await createTestToken({
      audience: "unexpected-audience",
    });

    await expect(verifyAccessToken(token)).rejects.toThrow();
  });

  it("should reject an incorrect token type", async () => {
    const token = await createTestToken({
      tokenType: "refresh",
    });

    await expect(verifyAccessToken(token)).rejects.toThrow(
      "Invalid JWT claims",
    );
  });

  it("should reject a correctly signed token with an invalid user UUID", async () => {
    const token = await createTestToken({
      userId: "user-123",
    });

    await expect(verifyAccessToken(token)).rejects.toThrow(
      "Invalid JWT claims",
    );
  });

  it("should reject a correctly signed token with an invalid session UUID", async () => {
    const token = await createTestToken({
      sessionId: "session-123",
    });

    await expect(verifyAccessToken(token)).rejects.toThrow(
      "Invalid JWT claims",
    );
  });

  it("should reject a missing userId", async () => {
    await expect(
      signAccessToken({ sessionId: testIdentity.sessionId }),
    ).rejects.toThrow("A valid userId UUID is required");
  });

  it("should reject a missing sessionId", async () => {
    await expect(
      signAccessToken({ userId: testIdentity.userId }),
    ).rejects.toThrow("A valid sessionId UUID is required");
  });

  it("should reject a malformed userId when signing", async () => {
    await expect(
      signAccessToken({
        userId: "user-123",
        sessionId: testIdentity.sessionId,
      }),
    ).rejects.toThrow("A valid userId UUID is required");
  });

  it("should reject a malformed sessionId when signing", async () => {
    await expect(
      signAccessToken({
        userId: testIdentity.userId,
        sessionId: "session-123",
      }),
    ).rejects.toThrow("A valid sessionId UUID is required");
  });

  it("should reject an empty token", async () => {
    await expect(verifyAccessToken("")).rejects.toThrow(
      "A valid JWT is required",
    );
  });

  it("should reject a non-string token", async () => {
    await expect(verifyAccessToken(null)).rejects.toThrow(
      "A valid JWT is required",
    );
  });
});
