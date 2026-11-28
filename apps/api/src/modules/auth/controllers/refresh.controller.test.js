import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  rotateRefreshToken: vi.fn(),
  signAccessToken: vi.fn(),
}));

vi.mock("../../session/session.service.js", () => ({
  rotateRefreshToken: mocks.rotateRefreshToken,
}));

vi.mock("../../../lib/jwt.js", () => ({
  signAccessToken: mocks.signAccessToken,
}));

import {
  ACCESS_COOKIE_CLEAR_OPTIONS,
  REFRESH_COOKIE_CLEAR_OPTIONS,
} from "../../../config/cookies.js";
import { refreshController } from "./refresh.controller.js";

describe("refreshController", () => {
  let req;
  let res;
  let next;

  const session = {
    id: "650e8400-e29b-41d4-a716-446655440000",
    userId: "550e8400-e29b-41d4-a716-446655440000",
    expiresAt: new Date("2027-01-01T00:00:00.000Z"),
  };

  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      cookies: {
        refreshToken: "old-refresh-token",
      },
    };

    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      cookie: vi.fn().mockReturnThis(),
      clearCookie: vi.fn().mockReturnThis(),
    };

    next = vi.fn();

    mocks.rotateRefreshToken.mockResolvedValue({
      refreshToken: "new-refresh-token",
      session,
    });

    mocks.signAccessToken.mockResolvedValue("new-access-token");
  });

  it("should reject requests without a refresh cookie", async () => {
    req.cookies = {};

    await refreshController(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        message: "Authentication required.",
        statusCode: 401,
      }),
    );

    expect(res.clearCookie).toHaveBeenCalledTimes(2);
    expect(mocks.rotateRefreshToken).not.toHaveBeenCalled();
    expect(mocks.signAccessToken).not.toHaveBeenCalled();
  });

  it("should rotate the existing refresh token", async () => {
    await refreshController(req, res, next);

    expect(mocks.rotateRefreshToken).toHaveBeenCalledWith({
      token: "old-refresh-token",
    });
  });

  it("should generate a new access token", async () => {
    await refreshController(req, res, next);

    expect(mocks.signAccessToken).toHaveBeenCalledWith({
      userId: session.userId,
      sessionId: session.id,
    });
  });

  it("should set replacement authentication cookies", async () => {
    await refreshController(req, res, next);

    expect(res.cookie).toHaveBeenCalledTimes(2);

    expect(res.cookie).toHaveBeenCalledWith(
      "accessToken",
      "new-access-token",
      expect.objectContaining({
        httpOnly: true,
        path: "/api/v1",
      }),
    );

    expect(res.cookie).toHaveBeenCalledWith(
      "refreshToken",
      "new-refresh-token",
      expect.objectContaining({
        httpOnly: true,
        path: "/api/v1/auth",
      }),
    );
  });

  it("should return safe session information", async () => {
    await refreshController(req, res, next);

    expect(res.status).toHaveBeenCalledWith(200);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      message: "Token refreshed successfully.",
      data: {
        session,
      },
    });

    const body = res.json.mock.calls[0][0];

    expect(body.data).not.toHaveProperty("refreshToken");
    expect(body.data).not.toHaveProperty("accessToken");
  });

  it.each([
    "Invalid refresh token",
    "Refresh token reuse detected",
    "SESSION_NO_LONGER_ACTIVE",
  ])(
    "should convert expected refresh failure '%s' into a generic 401",
    async (message) => {
      mocks.rotateRefreshToken.mockRejectedValue(new Error(message));

      await refreshController(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "Invalid or expired refresh token.",
          statusCode: 401,
        }),
      );

      expect(res.clearCookie).toHaveBeenCalledTimes(2);
      expect(res.clearCookie).toHaveBeenCalledWith(
        "accessToken",
        ACCESS_COOKIE_CLEAR_OPTIONS,
      );
      expect(res.clearCookie).toHaveBeenCalledWith(
        "refreshToken",
        REFRESH_COOKIE_CLEAR_OPTIONS,
      );

      expect(res.cookie).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(mocks.signAccessToken).not.toHaveBeenCalled();
    },
  );

  it("should forward unexpected refresh-service errors unchanged", async () => {
    const error = new Error("Database connection failed");

    mocks.rotateRefreshToken.mockRejectedValue(error);

    await refreshController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
    expect(res.clearCookie).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
  });

  it("should forward JWT signing errors unchanged", async () => {
    const error = new Error("JWT signing failed");

    mocks.signAccessToken.mockRejectedValue(error);

    await refreshController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
    expect(res.json).not.toHaveBeenCalled();
  });
});
