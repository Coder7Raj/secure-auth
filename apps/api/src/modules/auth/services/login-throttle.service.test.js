import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

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
const { prisma } = await import("../../../lib/prisma.js");

const { consumeLoginAttempt, resetAccountThrottle, resetIpThrottle } =
  await import("./login-throttle.service.js");

describe("Login throttle service integration tests", () => {
  const testId = randomUUID();

  const email = `throttle-${testId}@example.com`;
  const ipAddress = "192.0.2.100";

  beforeAll(async () => {
    await prisma.$connect();
  });

  afterAll(async () => {
    try {
      // Remove only records created by this test suite.
      await prisma.loginThrottle.deleteMany({
        where: {
          OR: [
            { key: { startsWith: "account:" } },
            { key: { startsWith: "ip:" } },
          ],
        },
      });
    } finally {
      await prisma.$disconnect();
    }
  });

  beforeEach(async () => {
    // Reset only this test suite's specific keys.
    await resetAccountThrottle(email);
    await resetIpThrottle(ipAddress);
  });

  describe("Account throttling", () => {
    it("should allow the first five attempts", async () => {
      for (let attempt = 1; attempt <= 5; attempt += 1) {
        const result = await consumeLoginAttempt({
          email,
          ipAddress: `${ipAddress.slice(0, -1)}${attempt}`,
        });

        expect(result.allowed).toBe(true);
      }
    });

    it("should block the sixth attempt for the same account", async () => {
      const results = [];

      for (let attempt = 0; attempt < 6; attempt += 1) {
        results.push(
          await consumeLoginAttempt({
            email,
            ipAddress: `${ipAddress.slice(0, -1)}${attempt}`,
          }),
        );
      }

      expect(results.slice(0, 5).every((result) => result.allowed)).toBe(true);

      expect(results[5].allowed).toBe(false);
      expect(results[5].retryAt).toBeInstanceOf(Date);
    });

    it("should normalize account emails", async () => {
      await consumeLoginAttempt({
        email: email.toUpperCase(),
        ipAddress,
      });

      const result = await consumeLoginAttempt({
        email: email.toLowerCase(),
        ipAddress: "192.0.2.101",
      });

      expect(result.allowed).toBe(true);

      const blocked = await consumeLoginAttempt({
        email: `  ${email.toUpperCase()}  `,
        ipAddress: "192.0.2.102",
      });

      expect(blocked.allowed).toBe(true);

      const finalAttempt = await consumeLoginAttempt({
        email,
        ipAddress: "192.0.2.103",
      });

      expect(finalAttempt.allowed).toBe(true);

      const blockedAttempt = await consumeLoginAttempt({
        email,
        ipAddress: "192.0.2.104",
      });

      expect(blockedAttempt.allowed).toBe(true);

      const sixthAttempt = await consumeLoginAttempt({
        email,
        ipAddress: "192.0.2.105",
      });

      expect(sixthAttempt.allowed).toBe(false);
    });

    it("should reset the account counter", async () => {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        await consumeLoginAttempt({
          email,
          ipAddress: `192.0.2.${attempt + 110}`,
        });
      }

      await resetAccountThrottle(email);

      const result = await consumeLoginAttempt({
        email,
        ipAddress: "192.0.2.120",
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe("IP throttling", () => {
    it("should block the twenty-first attempt from the same IP", async () => {
      const results = await Promise.all(
        Array.from({ length: 21 }, (_, index) =>
          consumeLoginAttempt({
            email: `different-${testId}-${index}@example.com`,
            ipAddress,
          }),
        ),
      );

      expect(results.filter((result) => result.allowed)).toHaveLength(20);

      expect(results.filter((result) => !result.allowed)).toHaveLength(1);
    });

    it("should reset the IP counter", async () => {
      for (let attempt = 0; attempt < 20; attempt += 1) {
        await consumeLoginAttempt({
          email: `reset-${testId}-${attempt}@example.com`,
          ipAddress,
        });
      }

      await resetIpThrottle(ipAddress);

      const result = await consumeLoginAttempt({
        email: `reset-final-${testId}@example.com`,
        ipAddress,
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe("Counter independence", () => {
    it("should maintain independent counters for different accounts", async () => {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        await consumeLoginAttempt({
          email,
          ipAddress: `192.0.2.${attempt + 130}`,
        });
      }

      const result = await consumeLoginAttempt({
        email: `different-${testId}@example.com`,
        ipAddress: "192.0.2.140",
      });

      expect(result.allowed).toBe(true);
    });

    it("should maintain independent counters for different IP addresses", async () => {
      const firstIp = "192.0.2.150";
      const secondIp = "192.0.2.151";

      for (let attempt = 0; attempt < 5; attempt += 1) {
        await consumeLoginAttempt({
          email,
          ipAddress: firstIp,
        });
      }

      const result = await consumeLoginAttempt({
        email: `different-${testId}@example.com`,
        ipAddress: secondIp,
      });

      expect(result.allowed).toBe(true);
    });
  });

  describe("Concurrent requests", () => {
    it("should not lose concurrent account counter increments", async () => {
      const concurrentEmail = `concurrent-${testId}@example.com`;

      const results = await Promise.all(
        Array.from({ length: 10 }, (_, index) =>
          consumeLoginAttempt({
            email: concurrentEmail,
            ipAddress: `192.0.2.${160 + index}`,
          }),
        ),
      );

      expect(results.filter((result) => result.allowed)).toHaveLength(5);
      expect(results.filter((result) => !result.allowed)).toHaveLength(5);

      await resetAccountThrottle(concurrentEmail);
    });

    it("should not lose concurrent IP counter increments", async () => {
      const concurrentIp = "192.0.2.200";

      const results = await Promise.all(
        Array.from({ length: 25 }, (_, index) =>
          consumeLoginAttempt({
            email: `concurrent-ip-${testId}-${index}@example.com`,
            ipAddress: concurrentIp,
          }),
        ),
      );

      expect(results.filter((result) => result.allowed)).toHaveLength(20);
      expect(results.filter((result) => !result.allowed)).toHaveLength(5);

      await resetIpThrottle(concurrentIp);
    });
  });
});
