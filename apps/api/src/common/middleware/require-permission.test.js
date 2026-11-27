import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  findMany: vi.fn(),
}));

vi.mock("../../lib/prisma.js", () => ({
  prisma: {
    userRole: {
      findMany: mocks.findMany,
    },
  },
}));

import { requirePermission } from "./require-permission.js";

describe("requirePermission", () => {
  let req;
  let res;
  let next;

  const userId = "550e8400-e29b-41d4-a716-446655440000";

  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      auth: {
        userId,
        sessionId: "650e8400-e29b-41d4-a716-446655440000",
      },
    };

    res = {};

    next = vi.fn();

    mocks.findMany.mockResolvedValue([
      {
        role: {
          permissions: [
            {
              permission: {
                key: "profile:read:self",
              },
            },
            {
              permission: {
                key: "profile:update:self",
              },
            },
            {
              permission: {
                key: "users:read:any",
              },
            },
          ],
        },
      },
    ]);
  });

  it("should reject middleware without required permissions", () => {
    expect(() => requirePermission()).toThrow(
      "At least one valid permission is required",
    );
  });

  it("should reject invalid permission definitions", () => {
    expect(() => requirePermission("")).toThrow(TypeError);
    expect(() => requirePermission(null)).toThrow(TypeError);
  });

  it("should reject unauthenticated requests", async () => {
    req.auth = undefined;

    const middleware = requirePermission("profile:read:self");

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 401,
      }),
    );

    expect(mocks.findMany).not.toHaveBeenCalled();
  });

  it("should allow users with the required permission", async () => {
    const middleware = requirePermission("users:read:any");

    await middleware(req, res, next);

    expect(mocks.findMany).toHaveBeenCalledWith({
      where: {
        userId,
      },
      select: {
        role: {
          select: {
            permissions: {
              select: {
                permission: {
                  select: {
                    key: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    expect(next).toHaveBeenCalledWith();
  });

  it("should allow permissions inherited from multiple roles", async () => {
    mocks.findMany.mockResolvedValue([
      {
        role: {
          permissions: [
            {
              permission: {
                key: "profile:read:self",
              },
            },
          ],
        },
      },
      {
        role: {
          permissions: [
            {
              permission: {
                key: "users:read:any",
              },
            },
          ],
        },
      },
    ]);

    const middleware = requirePermission("profile:read:self", "users:read:any");

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
  });

  it("should reject users without the required permission", async () => {
    const middleware = requirePermission("users:suspend:any");

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 403,
        message: "Insufficient permissions",
      }),
    );
  });

  it("should require all specified permissions", async () => {
    const middleware = requirePermission(
      "profile:read:self",
      "users:suspend:any",
    );

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 403,
      }),
    );
  });

  it("should forward database errors to Express", async () => {
    const error = new Error("Database connection failed");

    mocks.findMany.mockRejectedValue(error);

    const middleware = requirePermission("users:read:any");

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
  });
});
