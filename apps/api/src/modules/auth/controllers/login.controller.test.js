import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  loginUser: vi.fn(),
  signAccessToken: vi.fn(),
}));

vi.mock("../services/login.service.js", () => ({
  loginUser: mocks.loginUser,
}));

vi.mock("../../../lib/jwt.js", () => ({
  signAccessToken: mocks.signAccessToken,
}));

import { loginController } from "./login.controller.js";

describe("loginController", () => {
  let req;
  let res;
  let next;

  const user = {
    id: "550e8400-e29b-41d4-a716-446655440000",
    email: "user@example.com",
    firstName: "Test",
    lastName: "User",
    status: "ACTIVE",
  };

  const session = {
    id: "650e8400-e29b-41d4-a716-446655440000",
    userId: user.id,
  };

  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      body: {
        email: "user@example.com",
        password: "ValidPassword123!",
      },
      ip: "127.0.0.1",
      get: vi.fn().mockReturnValue("Vitest"),
    };

    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      cookie: vi.fn().mockReturnThis(),
    };

    next = vi.fn();

    mocks.loginUser.mockResolvedValue({
      user,
      session,
      refreshToken: "test-refresh-token",
    });

    mocks.signAccessToken.mockResolvedValue("test-access-token");
  });

  it("should reject invalid credentials", async () => {
    req.body.email = "invalid-email";

    await loginController(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(mocks.loginUser).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("should authenticate using normalized credentials", async () => {
    req.body.email = " USER@EXAMPLE.COM ";

    await loginController(req, res, next);

    expect(mocks.loginUser).toHaveBeenCalledWith(
      {
        email: "user@example.com",
        password: "ValidPassword123!",
      },
      {
        ipAddress: "127.0.0.1",
        userAgent: "Vitest",
      },
    );
  });

  it("should generate an access token", async () => {
    await loginController(req, res, next);

    expect(mocks.signAccessToken).toHaveBeenCalledWith({
      userId: user.id,
      sessionId: session.id,
    });
  });

  it("should set both authentication cookies", async () => {
    await loginController(req, res, next);

    expect(res.cookie).toHaveBeenCalledTimes(2);

    expect(res.cookie).toHaveBeenCalledWith(
      "accessToken",
      "test-access-token",
      expect.objectContaining({
        httpOnly: true,
        path: "/api/v1",
      }),
    );

    expect(res.cookie).toHaveBeenCalledWith(
      "refreshToken",
      "test-refresh-token",
      expect.objectContaining({
        httpOnly: true,
        path: "/api/v1/auth",
      }),
    );
  });

  it("should return safe user and session information", async () => {
    await loginController(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      message: "Login successful.",
      data: {
        user,
        session,
      },
    });

    const responseBody = res.json.mock.calls[0][0];

    expect(responseBody).not.toHaveProperty("accessToken");
    expect(responseBody).not.toHaveProperty("refreshToken");
  });

  it("should forward authentication errors to Express", async () => {
    const error = new Error("Invalid email or password.");

    mocks.loginUser.mockRejectedValue(error);

    await loginController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
    expect(res.json).not.toHaveBeenCalled();
  });

  it("should forward JWT signing errors to Express", async () => {
    const error = new Error("JWT signing failed");

    mocks.signAccessToken.mockRejectedValue(error);

    await loginController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
    expect(res.json).not.toHaveBeenCalled();
  });
});
