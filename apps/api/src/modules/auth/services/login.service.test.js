import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  verifyPassword: vi.fn(),
  findUnique: vi.fn(),
  createLoginAttempt: vi.fn(),
  updateUser: vi.fn(),
  createSession: vi.fn(),
  consumeLoginAttempt: vi.fn(),
  resetAccountThrottle: vi.fn(),
}));

vi.mock("./password.service.js", () => ({
  hashPassword: vi.fn().mockResolvedValue("dummy-password-hash"),
  verifyPassword: mocks.verifyPassword,
}));

vi.mock("./login-throttle.service.js", () => ({
  consumeLoginAttempt: mocks.consumeLoginAttempt,
  resetAccountThrottle: mocks.resetAccountThrottle,
}));

vi.mock("../../../lib/prisma.js", () => ({
  prisma: {
    user: {
      findUnique: mocks.findUnique,
      update: mocks.updateUser,
    },
    loginAttempt: {
      create: mocks.createLoginAttempt,
    },
  },
}));

vi.mock("../../session/session.service.js", () => ({
  createSession: mocks.createSession,
}));

import { loginUser } from "./login.service.js";

const activeUser = {
  id: "550e8400-e29b-41d4-a716-446655440000",
  email: "user@example.com",
  passwordHash: "stored-password-hash",
  firstName: "Test",
  lastName: "User",
  status: "ACTIVE",
};

const sessionResult = {
  session: {
    id: "650e8400-e29b-41d4-a716-446655440000",
    userId: activeUser.id,
  },
  refreshToken: "test-refresh-token",
};

describe("loginUser", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    mocks.verifyPassword.mockResolvedValue(true);

    mocks.consumeLoginAttempt.mockResolvedValue({
      allowed: true,
      retryAt: new Date(Date.now() + 15 * 60 * 1000),
    });

    mocks.resetAccountThrottle.mockResolvedValue(undefined);

    mocks.findUnique.mockResolvedValue(activeUser);
    mocks.createLoginAttempt.mockResolvedValue({});
    mocks.updateUser.mockResolvedValue({});
    mocks.createSession.mockResolvedValue(sessionResult);
  });

  it("should reject when the user does not exist", async () => {
    mocks.findUnique.mockResolvedValue(null);
    mocks.verifyPassword.mockResolvedValue(false);

    await expect(
      loginUser({
        email: "unknown@example.com",
        password: "ValidPassword123!",
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      message: "Invalid email or password.",
    });

    expect(mocks.verifyPassword).toHaveBeenCalled();
    expect(mocks.createSession).not.toHaveBeenCalled();
  });

  it("should reject when the password is incorrect", async () => {
    mocks.verifyPassword.mockResolvedValue(false);

    await expect(
      loginUser({
        email: activeUser.email,
        password: "WrongPassword123!",
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      message: "Invalid email or password.",
    });

    expect(mocks.createSession).not.toHaveBeenCalled();
  });

  it("should reject accounts pending email verification", async () => {
    mocks.findUnique.mockResolvedValue({
      ...activeUser,
      status: "PENDING_VERIFICATION",
    });

    await expect(
      loginUser({
        email: activeUser.email,
        password: "ValidPassword123!",
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      message: "Please verify your email before logging in.",
    });

    expect(mocks.createSession).not.toHaveBeenCalled();
  });

  it("should reject unavailable accounts", async () => {
    mocks.findUnique.mockResolvedValue({
      ...activeUser,
      status: "SUSPENDED",
    });

    await expect(
      loginUser({
        email: activeUser.email,
        password: "ValidPassword123!",
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      message: "Your account is currently unavailable.",
    });

    expect(mocks.createSession).not.toHaveBeenCalled();
  });

  it("should create a session for valid credentials", async () => {
    const result = await loginUser(
      {
        email: activeUser.email,
        password: "ValidPassword123!",
      },
      {
        ipAddress: "127.0.0.1",
        userAgent: "Vitest",
      },
    );

    expect(mocks.createSession).toHaveBeenCalledWith({
      userId: activeUser.id,
      ipAddress: "127.0.0.1",
      userAgent: "Vitest",
    });

    expect(mocks.updateUser).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: activeUser.id },
        data: { lastLoginAt: expect.any(Date) },
      }),
    );

    expect(result.user).toEqual({
      id: activeUser.id,
      email: activeUser.email,
      firstName: activeUser.firstName,
      lastName: activeUser.lastName,
      status: "ACTIVE",
    });

    expect(result.session).toEqual(sessionResult.session);
    expect(result.refreshToken).toBe(sessionResult.refreshToken);
  });

  it("should normalize email before looking up the user", async () => {
    await loginUser({
      email: "  USER@EXAMPLE.COM  ",
      password: "ValidPassword123!",
    });

    expect(mocks.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { email: "user@example.com" },
      }),
    );
  });
});
