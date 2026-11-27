import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

// Fail safely if the test database is not selected.
const databaseUrl = new URL(process.env.DATABASE_URL ?? "");

if (
  databaseUrl.hostname !== "localhost" ||
  databaseUrl.port !== "5433" ||
  databaseUrl.pathname !== "/secure_auth_test"
) {
  throw new Error(
    "Integration tests require secure_auth_test on localhost:5433",
  );
}

// Import database-dependent modules after the database guard.
const { prisma } = await import("../../lib/prisma.js");
const { signAccessToken } = await import("../../lib/jwt.js");
const { createSession } =
  await import("../../modules/session/session.service.js");
const { COOKIE_NAMES } = await import("../../config/cookies.js");
const { requireAuth } = await import("./require-auth.js");

describe("requireAuth integration tests", () => {
  let user;
  let secondUser;
  let session;

  async function createTestUser() {
    return prisma.user.create({
      data: {
        id: randomUUID(),
        email: `auth-test-${randomUUID()}@example.com`,
        passwordHash: "integration-test-password-hash",
        status: "ACTIVE",
      },
      select: {
        id: true,
        status: true,
      },
    });
  }

  async function createRequestToken(userId, sessionId) {
    return signAccessToken({
      userId,
      sessionId,
    });
  }

  async function authenticate(token) {
    const req = {
      cookies: {
        [COOKIE_NAMES.ACCESS_TOKEN]: token,
      },
    };

    const next = vi.fn();

    await requireAuth(req, {}, next);

    return { req, next };
  }

  beforeEach(async () => {
    user = await createTestUser();
    secondUser = await createTestUser();

    const result = await createSession({
      userId: user.id,
      ipAddress: "127.0.0.1",
      userAgent: "SecureAuth Integration Test",
    });

    session = result.session;
  });

  afterAll(async () => {
    await prisma.user.deleteMany({
      where: {
        email: {
          startsWith: "auth-test-",
        },
      },
    });

    await prisma.$disconnect();
  });

  it("should authenticate an active user with a valid session", async () => {
    const token = await createRequestToken(user.id, session.id);

    const { req, next } = await authenticate(token);

    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();

    expect(req.auth).toEqual({
      userId: user.id,
      sessionId: session.id,
    });

    expect(Object.isFrozen(req.auth)).toBe(true);
  });

  it("should reject a revoked session", async () => {
    await prisma.session.update({
      where: {
        id: session.id,
      },
      data: {
        revokedAt: new Date(),
        revokeReason: "USER_LOGOUT",
      },
    });

    const token = await createRequestToken(user.id, session.id);
    const { next } = await authenticate(token);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
    expect(next).toHaveBeenCalledOnce();
  });

  it("should reject an expired session", async () => {
    await prisma.session.update({
      where: {
        id: session.id,
      },
      data: {
        expiresAt: new Date(Date.now() - 60_000),
      },
    });

    const token = await createRequestToken(user.id, session.id);
    const { next } = await authenticate(token);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });

  it.each(["SUSPENDED", "DISABLED", "PENDING_VERIFICATION"])(
    "should reject a user with status %s",
    async (status) => {
      await prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          status,
        },
      });

      const token = await createRequestToken(user.id, session.id);
      const { next } = await authenticate(token);

      expect(next.mock.calls[0][0].statusCode).toBe(401);
    },
  );

  it("should reject a token belonging to another user", async () => {
    const token = await createRequestToken(secondUser.id, session.id);

    const { next } = await authenticate(token);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });

  it("should reject a token referencing a nonexistent session", async () => {
    const token = await createRequestToken(user.id, randomUUID());

    const { next } = await authenticate(token);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });
});
