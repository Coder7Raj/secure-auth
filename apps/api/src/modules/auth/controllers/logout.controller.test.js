import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  revokeSession: vi.fn(),
}));

vi.mock("../../session/session.service.js", () => ({
  revokeSession: mocks.revokeSession,
}));

import { logoutController } from "./logout.controller.js";

describe("logoutController", () => {
  let req;
  let res;
  let next;

  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      auth: {
        userId: "550e8400-e29b-41d4-a716-446655440000",
        sessionId: "650e8400-e29b-41d4-a716-446655440000",
      },
    };

    res = {
      clearCookie: vi.fn().mockReturnThis(),
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };

    next = vi.fn();

    mocks.revokeSession.mockResolvedValue({
      success: true,
      alreadyRevoked: false,
    });
  });

  it("should revoke the authenticated user's current session", async () => {
    await logoutController(req, res, next);

    expect(mocks.revokeSession).toHaveBeenCalledWith({
      userId: req.auth.userId,
      sessionId: req.auth.sessionId,
      revokeReason: "USER_LOGOUT",
    });
  });

  it("should clear both authentication cookies", async () => {
    await logoutController(req, res, next);

    expect(res.clearCookie).toHaveBeenCalledTimes(2);

    expect(res.clearCookie).toHaveBeenCalledWith(
      "accessToken",
      expect.objectContaining({
        httpOnly: true,
        path: "/api/v1",
      }),
    );

    expect(res.clearCookie).toHaveBeenCalledWith(
      "refreshToken",
      expect.objectContaining({
        httpOnly: true,
        path: "/api/v1/auth",
      }),
    );
  });

  it("should return a successful logout response", async () => {
    await logoutController(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      message: "Logout successful.",
    });
  });

  it("should clear cookies even if the session was already revoked", async () => {
    mocks.revokeSession.mockResolvedValue({
      success: true,
      alreadyRevoked: true,
    });

    await logoutController(req, res, next);

    expect(res.clearCookie).toHaveBeenCalledTimes(2);

    expect(res.status).toHaveBeenCalledWith(200);
  });

  it("should forward session revocation errors to Express", async () => {
    const error = new Error("Database connection failed");

    mocks.revokeSession.mockRejectedValue(error);

    await logoutController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);

    expect(res.clearCookie).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
  });
});
