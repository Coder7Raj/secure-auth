import { beforeEach, describe, expect, it, vi } from "vitest";

const { registerUserMock } = vi.hoisted(() => ({
  registerUserMock: vi.fn(),
}));

vi.mock("../services/register.service.js", () => ({
  registerUser: registerUserMock,
}));

import { AppError } from "../../../common/errors/app-error.js";
import { registerController } from "./register.controller.js";

describe("registerController", () => {
  let req;
  let res;
  let next;

  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      body: {
        email: "  USER@example.com  ",
        password: "StrongPassword123!",
        firstName: "John",
        lastName: "Doe",
      },
    };

    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };

    next = vi.fn();
  });

  it("registers a user and returns HTTP 201", async () => {
    const user = {
      id: "user-uuid",
      email: "user@example.com",
      firstName: "John",
      lastName: "Doe",
      status: "PENDING_VERIFICATION",
      emailVerifiedAt: null,
      createdAt: new Date(),
    };

    registerUserMock.mockResolvedValue(user);

    await registerController(req, res, next);

    expect(registerUserMock).toHaveBeenCalledWith({
      email: "user@example.com",
      password: "StrongPassword123!",
      firstName: "John",
      lastName: "Doe",
    });

    expect(res.status).toHaveBeenCalledWith(201);

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      message: "Registration successful. Please verify your email.",
      data: { user },
    });

    expect(next).not.toHaveBeenCalled();
  });

  it.each([
    [
      "invalid email",
      {
        email: "invalid-email",
        password: "StrongPassword123!",
        firstName: "John",
        lastName: "Doe",
      },
    ],
    [
      "short password",
      {
        email: "user@example.com",
        password: "short",
        firstName: "John",
        lastName: "Doe",
      },
    ],
    [
      "missing email",
      {
        password: "StrongPassword123!",
      },
    ],
    [
      "unknown fields",
      {
        email: "user@example.com",
        password: "StrongPassword123!",
        firstName: "John",
        lastName: "Doe",
        role: "ADMIN",
      },
    ],
  ])("rejects %s with HTTP 400", async (_description, body) => {
    req.body = body;

    await registerController(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        message: "Validation failed.",
        errors: expect.any(Array),
      }),
    );

    expect(registerUserMock).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("forwards duplicate email errors to the error handler", async () => {
    const error = new AppError(
      "An account with this email already exists",
      409,
    );

    registerUserMock.mockRejectedValue(error);

    await registerController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
  });

  it("forwards unexpected service errors to the error handler", async () => {
    const error = new Error("Database connection failed");

    registerUserMock.mockRejectedValue(error);

    await registerController(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
  });
});
