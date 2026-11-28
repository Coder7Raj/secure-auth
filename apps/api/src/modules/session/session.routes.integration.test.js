import { randomUUID } from "node:crypto";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Protect the dedicated integration-test database.
const databaseUrl = process.env.DATABASE_URL
  ? new URL(process.env.DATABASE_URL)
  : null;

if (
  !databaseUrl ||
  databaseUrl.hostname !== "localhost" ||
  databaseUrl.port !== "5433" ||
  databaseUrl.pathname !== "/secure_auth_test"
) {
  throw new Error(
    "Integration tests require secure_auth_test on localhost:5433",
  );
}

// Import database-dependent modules after the guard.
const { default: app } = await import("../../app.js");
const { prisma } = await import("../../lib/prisma.js");
const { hashPassword } = await import("../auth/services/password.service.js");
const { createSession } = await import("./session.service.js");

const EMAIL_PREFIX = "session-routes-http-test-";
const PASSWORD = "StrongPassword123!";

describe("Session Management API", () => {
  const createdEmails = [];

  beforeAll(async () => {
    await prisma.$connect();
  });

  afterAll(async () => {
    try {
      await prisma.user.deleteMany({
        where: {
          email: {
            startsWith: EMAIL_PREFIX,
          },
        },
      });
    } finally {
      await prisma.$disconnect();
    }
  });

  async function createTestUser() {
    const email = `${EMAIL_PREFIX}${randomUUID()}@example.com`;

    createdEmails.push(email);

    return prisma.user.create({
      data: {
        email,
        passwordHash: await hashPassword(PASSWORD),
        firstName: "Session",
        lastName: "Integration",
        status: "ACTIVE",
      },
    });
  }

  async function loginUser(user) {
    const response = await request(app)
      .post("/api/v1/auth/login")
      .set("User-Agent", "Session Management Integration Test")
      .send({
        email: user.email,
        password: PASSWORD,
      })
      .expect(200);

    const cookies = response.headers["set-cookie"] ?? [];

    const accessCookie = cookies
      .find((cookie) => cookie.startsWith("accessToken="))
      ?.split(";")[0];

    if (!accessCookie) {
      throw new Error("Login did not return an access token cookie.");
    }

    return {
      accessCookie,
      session: response.body.data.session,
    };
  }

  async function createAdditionalSession(userId) {
    const result = await createSession({
      userId,
      ipAddress: "127.0.0.1",
      userAgent: "Additional Integration Test Browser",
      deviceName: "Integration Test Device",
    });

    return result.session;
  }

  describe("GET /api/v1/auth/sessions", () => {
    it("should return the authenticated user's active sessions", async () => {
      const user = await createTestUser();
      const { accessCookie, session } = await loginUser(user);

      const additionalSession = await createAdditionalSession(user.id);

      const response = await request(app)
        .get("/api/v1/auth/sessions")
        .set("Cookie", accessCookie)
        .expect(200);

      expect(response.body.success).toBe(true);

      expect(response.body.data.sessions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: session.id,
          }),
          expect.objectContaining({
            id: additionalSession.id,
          }),
        ]),
      );

      for (const returnedSession of response.body.data.sessions) {
        expect(returnedSession).not.toHaveProperty("refreshToken");
        expect(returnedSession).not.toHaveProperty("tokenHash");
        expect(returnedSession).not.toHaveProperty("familyId");
      }
    });

    it("should reject unauthenticated requests", async () => {
      const response = await request(app)
        .get("/api/v1/auth/sessions")
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe("DELETE /api/v1/auth/sessions/:sessionId", () => {
    it("should revoke one of the authenticated user's sessions", async () => {
      const user = await createTestUser();
      const { accessCookie } = await loginUser(user);

      const targetSession = await createAdditionalSession(user.id);

      const response = await request(app)
        .delete(`/api/v1/auth/sessions/${targetSession.id}`)
        .set("Cookie", accessCookie)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        message: "Session revoked successfully.",
      });

      const storedSession = await prisma.session.findUniqueOrThrow({
        where: {
          id: targetSession.id,
        },
      });

      expect(storedSession.revokedAt).toBeInstanceOf(Date);
      expect(storedSession.revokeReason).toBe("USER_LOGOUT");

      const refreshTokens = await prisma.refreshToken.findMany({
        where: {
          sessionId: targetSession.id,
        },
      });

      expect(refreshTokens.length).toBeGreaterThan(0);

      for (const token of refreshTokens) {
        expect(token.revokedAt).toBeInstanceOf(Date);
      }
    });

    it("should return 404 when attempting to revoke another user's session", async () => {
      const firstUser = await createTestUser();
      const secondUser = await createTestUser();

      const { accessCookie } = await loginUser(firstUser);
      const secondUserSession = await createAdditionalSession(secondUser.id);

      const response = await request(app)
        .delete(`/api/v1/auth/sessions/${secondUserSession.id}`)
        .set("Cookie", accessCookie)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe("Session not found.");

      const storedSession = await prisma.session.findUniqueOrThrow({
        where: {
          id: secondUserSession.id,
        },
      });

      expect(storedSession.revokedAt).toBeNull();
    });

    it("should reject invalid session IDs", async () => {
      const user = await createTestUser();
      const { accessCookie } = await loginUser(user);

      const response = await request(app)
        .delete("/api/v1/auth/sessions/not-a-uuid")
        .set("Cookie", accessCookie)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe("Invalid session ID.");
    });

    it("should clear both authentication cookies when revoking the current session", async () => {
      const user = await createTestUser();
      const { accessCookie, session } = await loginUser(user);

      const response = await request(app)
        .delete(`/api/v1/auth/sessions/${session.id}`)
        .set("Cookie", accessCookie)
        .expect(200);

      const setCookies = response.headers["set-cookie"] ?? [];

      expect(setCookies).toHaveLength(2);

      const accessCookieClear = setCookies.find((cookie) =>
        cookie.startsWith("accessToken="),
      );

      const refreshCookieClear = setCookies.find((cookie) =>
        cookie.startsWith("refreshToken="),
      );

      expect(accessCookieClear).toBeDefined();
      expect(refreshCookieClear).toBeDefined();

      expect(accessCookieClear).toMatch(/HttpOnly/i);
      expect(accessCookieClear).toContain("Path=/api/v1");
      expect(accessCookieClear).toMatch(/Expires=/i);

      expect(refreshCookieClear).toMatch(/HttpOnly/i);
      expect(refreshCookieClear).toContain("Path=/api/v1/auth");
      expect(refreshCookieClear).toMatch(/Expires=/i);

      const storedSession = await prisma.session.findUniqueOrThrow({
        where: {
          id: session.id,
        },
      });

      expect(storedSession.revokedAt).toBeInstanceOf(Date);
    });

    it("should reject unauthenticated requests", async () => {
      const response = await request(app)
        .delete(`/api/v1/auth/sessions/${randomUUID()}`)
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe("DELETE /api/v1/auth/sessions/others", () => {
    it("should revoke all other active sessions and preserve the current session", async () => {
      const user = await createTestUser();
      const { accessCookie, session: currentSession } = await loginUser(user);

      const firstOtherSession = await createAdditionalSession(user.id);
      const secondOtherSession = await createAdditionalSession(user.id);

      const response = await request(app)
        .delete("/api/v1/auth/sessions/others")
        .set("Cookie", accessCookie)
        .expect(200);

      expect(response.body).toEqual({
        success: true,
        message: "Other sessions revoked successfully.",
        data: {
          revokedCount: 2,
        },
      });

      const storedCurrentSession = await prisma.session.findUniqueOrThrow({
        where: {
          id: currentSession.id,
        },
      });

      const storedFirstOtherSession = await prisma.session.findUniqueOrThrow({
        where: {
          id: firstOtherSession.id,
        },
      });

      const storedSecondOtherSession = await prisma.session.findUniqueOrThrow({
        where: {
          id: secondOtherSession.id,
        },
      });

      expect(storedCurrentSession.revokedAt).toBeNull();

      expect(storedFirstOtherSession.revokedAt).toBeInstanceOf(Date);
      expect(storedSecondOtherSession.revokedAt).toBeInstanceOf(Date);

      // The current session must remain usable.
      await request(app)
        .get("/api/v1/auth/sessions")
        .set("Cookie", accessCookie)
        .expect(200);

      // Other sessions' refresh tokens must also be revoked.
      const revokedTokens = await prisma.refreshToken.findMany({
        where: {
          sessionId: {
            in: [firstOtherSession.id, secondOtherSession.id],
          },
        },
      });

      expect(revokedTokens.length).toBeGreaterThan(0);

      for (const token of revokedTokens) {
        expect(token.revokedAt).toBeInstanceOf(Date);
      }
    });

    it("should preserve the current session when there are no other sessions", async () => {
      const user = await createTestUser();
      const { accessCookie, session } = await loginUser(user);

      const response = await request(app)
        .delete("/api/v1/auth/sessions/others")
        .set("Cookie", accessCookie)
        .expect(200);

      expect(response.body.data.revokedCount).toBe(0);

      const storedSession = await prisma.session.findUniqueOrThrow({
        where: {
          id: session.id,
        },
      });

      expect(storedSession.revokedAt).toBeNull();
    });

    it("should reject unauthenticated requests", async () => {
      const response = await request(app)
        .delete("/api/v1/auth/sessions/others")
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });
});
