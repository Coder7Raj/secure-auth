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
const { default: app } = await import("../../../app.js");
const { prisma } = await import("../../../lib/prisma.js");
const { hashPassword } = await import("../services/password.service.js");

const EMAIL_PREFIX = "login-http-test-";
const PASSWORD = "StrongPassword123!";

describe("POST /api/v1/auth/login", () => {
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

  async function createTestUser(status = "ACTIVE") {
    const email = `${EMAIL_PREFIX}${randomUUID()}@example.com`;

    createdEmails.push(email);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash: await hashPassword(PASSWORD),
        firstName: "Login",
        lastName: "Integration",
        status,
      },
    });

    return user;
  }

  it("should authenticate an active user successfully", async () => {
    const user = await createTestUser();

    const response = await request(app)
      .post("/api/v1/auth/login")
      .set("User-Agent", "SecureAuth Integration Test")
      .send({
        email: user.email,
        password: PASSWORD,
      })
      .expect(200);

    expect(response.body.success).toBe(true);
    expect(response.body.message).toBe("Login successful.");

    expect(response.body.data.user).toMatchObject({
      id: user.id,
      email: user.email,
      status: "ACTIVE",
    });

    expect(response.body.data.session.userId).toBe(user.id);

    // Tokens must never be exposed in the JSON response.
    expect(response.body.data).not.toHaveProperty("accessToken");
    expect(response.body.data).not.toHaveProperty("refreshToken");

    // Verify both authentication cookies.
    const cookies = response.headers["set-cookie"];

    expect(cookies).toHaveLength(2);

    const accessCookie = cookies.find((cookie) =>
      cookie.startsWith("accessToken="),
    );

    const refreshCookie = cookies.find((cookie) =>
      cookie.startsWith("refreshToken="),
    );

    expect(accessCookie).toBeDefined();
    expect(refreshCookie).toBeDefined();

    expect(accessCookie).toMatch(/HttpOnly/i);
    expect(accessCookie).toContain("Path=/api/v1");

    expect(refreshCookie).toMatch(/HttpOnly/i);
    expect(refreshCookie).toContain("Path=/api/v1/auth");

    // Verify the session was persisted.
    const session = await prisma.session.findUnique({
      where: {
        id: response.body.data.session.id,
      },
    });

    expect(session).not.toBeNull();
    expect(session.userId).toBe(user.id);
    expect(session.revokedAt).toBeNull();

    // Verify the refresh token was persisted as a hash.
    const refreshTokens = await prisma.refreshToken.findMany({
      where: {
        sessionId: session.id,
      },
    });

    expect(refreshTokens).toHaveLength(1);
    expect(refreshTokens[0].tokenHash).toBeTruthy();

    // Verify successful login auditing.
    const loginAttempt = await prisma.loginAttempt.findFirst({
      where: {
        userId: user.id,
        email: user.email,
        success: true,
      },
    });

    expect(loginAttempt).not.toBeNull();
    expect(loginAttempt.failureReason).toBeNull();

    // Verify last login timestamp.
    const updatedUser = await prisma.user.findUniqueOrThrow({
      where: {
        id: user.id,
      },
    });

    expect(updatedUser.lastLoginAt).toBeInstanceOf(Date);
  });

  it("should reject an incorrect password", async () => {
    const user = await createTestUser();

    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: user.email,
        password: "WrongPassword123!",
      })
      .expect(401);

    expect(response.body.success).toBe(false);
    expect(response.body.message).toBe("Invalid email or password.");

    expect(response.headers["set-cookie"]).toBeUndefined();

    const loginAttempt = await prisma.loginAttempt.findFirst({
      where: {
        userId: user.id,
        success: false,
      },
    });

    expect(loginAttempt).not.toBeNull();
    expect(loginAttempt.failureReason).toBe("INVALID_CREDENTIALS");
  });

  it("should reject an unknown email with a generic authentication error", async () => {
    const email = `${EMAIL_PREFIX}${randomUUID()}@example.com`;

    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({
        email,
        password: PASSWORD,
      })
      .expect(401);

    expect(response.body.message).toBe("Invalid email or password.");

    const loginAttempt = await prisma.loginAttempt.findFirst({
      where: {
        email,
        success: false,
      },
    });

    expect(loginAttempt).not.toBeNull();
    expect(loginAttempt.userId).toBeNull();
    expect(loginAttempt.failureReason).toBe("INVALID_CREDENTIALS");
  });

  it("should reject accounts pending email verification", async () => {
    const user = await createTestUser("PENDING_VERIFICATION");

    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: user.email,
        password: PASSWORD,
      })
      .expect(403);

    expect(response.body.message).toBe(
      "Please verify your email before logging in.",
    );

    expect(response.headers["set-cookie"]).toBeUndefined();
  });

  it("should reject suspended accounts", async () => {
    const user = await createTestUser("SUSPENDED");

    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: user.email,
        password: PASSWORD,
      })
      .expect(403);

    expect(response.body.message).toBe(
      "Your account is currently unavailable.",
    );

    expect(response.headers["set-cookie"]).toBeUndefined();
  });

  it("should normalize email addresses before authentication", async () => {
    const user = await createTestUser();

    const response = await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: `  ${user.email.toUpperCase()}  `,
        password: PASSWORD,
      })
      .expect(200);

    expect(response.body.data.user.email).toBe(user.email);
  });

  it("should reject invalid request payloads", async () => {
    await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: "invalid-email",
        password: PASSWORD,
      })
      .expect(400);
  });

  it("should reject attempts to inject additional fields", async () => {
    await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: "user@example.com",
        password: PASSWORD,
        role: "ADMIN",
      })
      .expect(400);
  });
});
