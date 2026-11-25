import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { hashRefreshToken } from "../../lib/refresh-token.js";

// Fail safely if the test database is not selected.
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

// Import database-dependent modules only after the guard.
const { prisma } = await import("../../lib/prisma.js");
const { createSession, rotateRefreshToken, listActiveSessions } =
  await import("./session.service.js");

describe("Session service integration tests", () => {
  let testUser;

  // Shared test user for all test suites.
  beforeAll(async () => {
    testUser = await prisma.user.create({
      data: {
        id: randomUUID(),
        email: `session-test-${randomUUID()}@example.com`,
        passwordHash: "integration-test-password-hash",
        status: "ACTIVE",
      },
      select: {
        id: true,
      },
    });
  });

  // Clean up only after all nested test suites finish.
  afterAll(async () => {
    try {
      if (testUser) {
        await prisma.user.delete({
          where: { id: testUser.id },
        });
      }
    } finally {
      await prisma.$disconnect();
    }
  });

  // ==========================================
  // SESSION CREATION TESTS
  // ==========================================

  describe("Session creation", () => {
    it("should create a session and its initial refresh token", async () => {
      const result = await createSession({
        userId: testUser.id,
      });

      expect(result.session.userId).toBe(testUser.id);
      expect(result.session.id).toBeTruthy();
      expect(result.refreshToken).toEqual(expect.any(String));

      const storedToken = await prisma.refreshToken.findFirst({
        where: {
          sessionId: result.session.id,
        },
      });

      expect(storedToken).not.toBeNull();

      expect(storedToken.tokenHash).toBe(hashRefreshToken(result.refreshToken));

      expect(storedToken.tokenHash).not.toBe(result.refreshToken);
    });

    it("should create a session with seven-day absolute expiration", async () => {
      const result = await createSession({
        userId: testUser.id,
      });

      const expectedDuration =
        Number(process.env.SESSION_MAX_AGE_DAYS ?? 7) * 24 * 60 * 60 * 1000;

      const actualDuration =
        result.session.expiresAt.getTime() - result.session.createdAt.getTime();

      expect(actualDuration).toBe(expectedDuration);
    });

    it("should use the same expiration for the session and refresh token", async () => {
      const result = await createSession({
        userId: testUser.id,
      });

      const storedToken = await prisma.refreshToken.findFirst({
        where: {
          sessionId: result.session.id,
        },
      });

      expect(storedToken).not.toBeNull();

      expect(storedToken.expiresAt.getTime()).toBe(
        result.session.expiresAt.getTime(),
      );
    });

    it("should persist session metadata", async () => {
      const metadata = {
        ipAddress: "127.0.0.1",
        userAgent: "SecureAuth Integration Test",
        deviceName: "Test Browser",
      };

      const result = await createSession({
        userId: testUser.id,
        ...metadata,
      });

      expect(result.session.ipAddress).toBe(metadata.ipAddress);
      expect(result.session.userAgent).toBe(metadata.userAgent);
      expect(result.session.deviceName).toBe(metadata.deviceName);
    });

    it("should generate a unique refresh-token family for each session", async () => {
      const first = await createSession({
        userId: testUser.id,
      });

      const second = await createSession({
        userId: testUser.id,
      });

      const firstToken = await prisma.refreshToken.findFirst({
        where: {
          sessionId: first.session.id,
        },
      });

      const secondToken = await prisma.refreshToken.findFirst({
        where: {
          sessionId: second.session.id,
        },
      });

      expect(firstToken).not.toBeNull();
      expect(secondToken).not.toBeNull();

      expect(firstToken.familyId).not.toBe(secondToken.familyId);
    });

    it("should reject an invalid user ID", async () => {
      await expect(
        createSession({
          userId: "not-a-uuid",
        }),
      ).rejects.toThrow();
    });

    it("should reject a nonexistent user", async () => {
      await expect(
        createSession({
          userId: randomUUID(),
        }),
      ).rejects.toThrow();
    });

    it("should reject an IP address exceeding the database limit", async () => {
      await expect(
        createSession({
          userId: testUser.id,
          ipAddress: "1".repeat(46),
        }),
      ).rejects.toThrow();
    });

    it("should roll back the session if the transaction fails", async () => {
      const userId = testUser.id;

      const sessionsBefore = await prisma.session.count({
        where: { userId },
      });

      await expect(
        prisma.$transaction(async (tx) => {
          await tx.session.create({
            data: {
              userId,
              expiresAt: new Date(Date.now() + 60_000),
            },
          });

          throw new Error("Simulated refresh-token creation failure");
        }),
      ).rejects.toThrow("Simulated refresh-token creation failure");

      const sessionsAfter = await prisma.session.count({
        where: { userId },
      });

      expect(sessionsAfter).toBe(sessionsBefore);
    });
  });

  // ==========================================
  // REFRESH-TOKEN ROTATION TESTS
  // ==========================================

  describe("Refresh-token rotation", () => {
    it("should rotate a valid refresh token", async () => {
      const initial = await createSession({
        userId: testUser.id,
      });

      const rotated = await rotateRefreshToken({
        token: initial.refreshToken,
      });

      expect(rotated.refreshToken).toEqual(expect.any(String));

      expect(rotated.refreshToken).not.toBe(initial.refreshToken);

      expect(rotated.session.id).toBe(initial.session.id);
      expect(rotated.session.userId).toBe(testUser.id);

      const oldToken = await prisma.refreshToken.findUnique({
        where: {
          tokenHash: hashRefreshToken(initial.refreshToken),
        },
      });

      const newToken = await prisma.refreshToken.findUnique({
        where: {
          tokenHash: hashRefreshToken(rotated.refreshToken),
        },
      });

      expect(oldToken).not.toBeNull();
      expect(oldToken.consumedAt).toBeInstanceOf(Date);

      expect(newToken).not.toBeNull();
      expect(newToken.consumedAt).toBeNull();
      expect(newToken.revokedAt).toBeNull();

      expect(newToken.tokenHash).not.toBe(rotated.refreshToken);
    });

    it("should preserve the original token family and session expiration", async () => {
      const initial = await createSession({
        userId: testUser.id,
      });

      const originalToken = await prisma.refreshToken.findUnique({
        where: {
          tokenHash: hashRefreshToken(initial.refreshToken),
        },
      });

      const rotated = await rotateRefreshToken({
        token: initial.refreshToken,
      });

      const replacementToken = await prisma.refreshToken.findUnique({
        where: {
          tokenHash: hashRefreshToken(rotated.refreshToken),
        },
      });

      expect(replacementToken.familyId).toBe(originalToken.familyId);

      expect(replacementToken.expiresAt.getTime()).toBe(
        initial.session.expiresAt.getTime(),
      );

      expect(rotated.session.expiresAt.getTime()).toBe(
        initial.session.expiresAt.getTime(),
      );
    });

    it("should reject reuse of a consumed refresh token", async () => {
      const initial = await createSession({
        userId: testUser.id,
      });

      const rotated = await rotateRefreshToken({
        token: initial.refreshToken,
      });

      await expect(
        rotateRefreshToken({
          token: initial.refreshToken,
        }),
      ).rejects.toThrow("Refresh token reuse detected");

      const session = await prisma.session.findUnique({
        where: {
          id: initial.session.id,
        },
      });

      const tokens = await prisma.refreshToken.findMany({
        where: {
          sessionId: initial.session.id,
        },
      });

      expect(session.revokedAt).toBeInstanceOf(Date);

      expect(session.revokeReason).toBe("REFRESH_TOKEN_REUSE");

      expect(tokens.length).toBe(2);

      for (const token of tokens) {
        expect(token.revokedAt).toBeInstanceOf(Date);
      }

      expect(
        tokens.some(
          (token) => token.tokenHash === hashRefreshToken(rotated.refreshToken),
        ),
      ).toBe(true);
    });

    it("should reject an unknown refresh token", async () => {
      await expect(
        rotateRefreshToken({
          token: randomUUID(),
        }),
      ).rejects.toThrow("Invalid refresh token");
    });

    it("should reject an expired refresh token", async () => {
      const initial = await createSession({
        userId: testUser.id,
      });

      await prisma.refreshToken.update({
        where: {
          tokenHash: hashRefreshToken(initial.refreshToken),
        },
        data: {
          expiresAt: new Date(Date.now() - 60_000),
        },
      });

      await expect(
        rotateRefreshToken({
          token: initial.refreshToken,
        }),
      ).rejects.toThrow("Invalid refresh token");

      const session = await prisma.session.findUnique({
        where: {
          id: initial.session.id,
        },
      });

      expect(session.revokedAt).toBeNull();
    });

    it("should reject a refresh token belonging to a revoked session", async () => {
      const initial = await createSession({
        userId: testUser.id,
      });

      await prisma.session.update({
        where: {
          id: initial.session.id,
        },
        data: {
          revokedAt: new Date(),
          revokeReason: "USER_LOGOUT",
        },
      });

      await expect(
        rotateRefreshToken({
          token: initial.refreshToken,
        }),
      ).rejects.toThrow("Invalid refresh token");
    });

    it("should reject refresh tokens belonging to an inactive user", async () => {
      const initial = await createSession({
        userId: testUser.id,
      });

      await prisma.user.update({
        where: {
          id: testUser.id,
        },
        data: {
          status: "SUSPENDED",
        },
      });

      try {
        await expect(
          rotateRefreshToken({
            token: initial.refreshToken,
          }),
        ).rejects.toThrow("Invalid refresh token");
      } finally {
        await prisma.user.update({
          where: {
            id: testUser.id,
          },
          data: {
            status: "ACTIVE",
          },
        });
      }
    });
  });

  // ==========================================
  // CONCURRENT REFRESH REQUEST TESTS
  // ==========================================

  describe("Concurrent refresh requests", () => {
    it("should detect reuse when two requests use the same refresh token", async () => {
      const initial = await createSession({
        userId: testUser.id,
      });

      const results = await Promise.allSettled([
        rotateRefreshToken({
          token: initial.refreshToken,
        }),
        rotateRefreshToken({
          token: initial.refreshToken,
        }),
      ]);

      const successfulRequests = results.filter(
        (result) => result.status === "fulfilled",
      );

      const failedRequests = results.filter(
        (result) => result.status === "rejected",
      );

      expect(successfulRequests).toHaveLength(1);
      expect(failedRequests).toHaveLength(1);

      const session = await prisma.session.findUnique({
        where: {
          id: initial.session.id,
        },
      });

      expect(session.revokedAt).toBeInstanceOf(Date);

      expect(session.revokeReason).toBe("REFRESH_TOKEN_REUSE");

      const tokens = await prisma.refreshToken.findMany({
        where: {
          sessionId: initial.session.id,
        },
      });

      for (const token of tokens) {
        expect(token.revokedAt).toBeInstanceOf(Date);
      }
    });
  });
});

describe("Active session listing", () => {
  let testUser;

  // Shared test user for all test suites.
  beforeAll(async () => {
    testUser = await prisma.user.create({
      data: {
        id: randomUUID(),
        email: `session-test-${randomUUID()}@example.com`,
        passwordHash: "integration-test-password-hash",
        status: "ACTIVE",
      },
      select: {
        id: true,
      },
    });
  });

  // Clean up only after all nested test suites finish.
  afterAll(async () => {
    try {
      if (testUser) {
        await prisma.user.delete({
          where: { id: testUser.id },
        });
      }
    } finally {
      await prisma.$disconnect();
    }
  });
  it("should list active sessions belonging to the user", async () => {
    const first = await createSession({
      userId: testUser.id,
      deviceName: "Desktop",
    });

    const second = await createSession({
      userId: testUser.id,
      deviceName: "Mobile",
    });

    const sessions = await listActiveSessions({
      userId: testUser.id,
    });

    expect(sessions).toHaveLength(2);

    expect(sessions.map((session) => session.id)).toEqual(
      expect.arrayContaining([first.session.id, second.session.id]),
    );
  });

  it("should exclude revoked sessions", async () => {
    const initial = await createSession({
      userId: testUser.id,
    });

    await prisma.session.update({
      where: {
        id: initial.session.id,
      },
      data: {
        revokedAt: new Date(),
        revokeReason: "USER_LOGOUT",
      },
    });

    const sessions = await listActiveSessions({
      userId: testUser.id,
    });

    expect(sessions.some((session) => session.id === initial.session.id)).toBe(
      false,
    );
  });

  it("should exclude expired sessions", async () => {
    const initial = await createSession({
      userId: testUser.id,
    });

    await prisma.session.update({
      where: {
        id: initial.session.id,
      },
      data: {
        expiresAt: new Date(Date.now() - 60_000),
      },
    });

    const sessions = await listActiveSessions({
      userId: testUser.id,
    });

    expect(sessions.some((session) => session.id === initial.session.id)).toBe(
      false,
    );
  });

  it("should not expose refresh-token information", async () => {
    await createSession({
      userId: testUser.id,
    });

    const sessions = await listActiveSessions({
      userId: testUser.id,
    });

    expect(sessions.length).toBeGreaterThan(0);

    for (const session of sessions) {
      expect(session).not.toHaveProperty("tokenHash");
      expect(session).not.toHaveProperty("familyId");
      expect(session).not.toHaveProperty("consumedAt");
    }
  });

  it("should reject an invalid user ID", async () => {
    await expect(
      listActiveSessions({
        userId: "invalid-user-id",
      }),
    ).rejects.toThrow();
  });
});
