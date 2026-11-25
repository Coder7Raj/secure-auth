import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { hashRefreshToken } from "../../lib/refresh-token.js";

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

// Import database-dependent modules only after the guard.
const { prisma } = await import("../../lib/prisma.js");
const { createSession } = await import("./session.service.js");

describe("Session service integration tests", () => {
  let testUser;

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

  afterAll(async () => {
    if (testUser) {
      await prisma.user.delete({
        where: { id: testUser.id },
      });
    }

    await prisma.$disconnect();
  });

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

    // Count existing sessions before the transaction.
    const sessionsBefore = await prisma.session.count({
      where: { userId },
    });

    // Simulate a failure inside the transaction.
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

    // Verify that the failed transaction created no additional session.
    const sessionsAfter = await prisma.session.count({
      where: { userId },
    });

    expect(sessionsAfter).toBe(sessionsBefore);
  });
});
