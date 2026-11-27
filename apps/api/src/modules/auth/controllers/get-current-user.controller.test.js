import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../services/get-current-user.service.js", () => ({
  getCurrentUser: vi.fn(),
}));

import { getCurrentUser } from "../services/get-current-user.service.js";
import { getCurrentUserController } from "./get-current-user.controller.js";

describe("getCurrentUserController", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns the authenticated user's profile", async () => {
    const user = {
      id: "user-123",
      email: "user@example.com",
      roles: ["USER"],
      permissions: ["profile:read:self"],
    };

    getCurrentUser.mockResolvedValue(user);

    const req = {
      auth: {
        userId: "user-123",
      },
    };

    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };

    const next = vi.fn();

    await getCurrentUserController(req, res, next);

    expect(getCurrentUser).toHaveBeenCalledWith("user-123");

    expect(res.status).toHaveBeenCalledWith(200);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: {
        user,
      },
    });

    expect(next).not.toHaveBeenCalled();
  });

  it("forwards service errors to error middleware", async () => {
    const error = new Error("Database failure");

    getCurrentUser.mockRejectedValue(error);

    const req = {
      auth: {
        userId: "user-123",
      },
    };

    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };

    const next = vi.fn();

    await getCurrentUserController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
  });
});
