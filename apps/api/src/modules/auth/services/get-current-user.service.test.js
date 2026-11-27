import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../lib/prisma.js", () => ({
  prisma: {
    user: {
      findUnique: vi.fn(),
    },
  },
}));

import { prisma } from "../../../lib/prisma.js";
import { getCurrentUser } from "./get-current-user.service.js";

describe("getCurrentUser", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns safe user information, roles, and permissions", async () => {
    prisma.user.findUnique.mockResolvedValue({
      id: "user-123",
      email: "user@example.com",
      firstName: "Test",
      lastName: "User",
      status: "ACTIVE",
      emailVerifiedAt: new Date("2026-01-01"),
      createdAt: new Date("2026-01-01"),
      roles: [
        {
          role: {
            name: "USER",
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
            ],
          },
        },
        {
          role: {
            name: "ADMIN",
            permissions: [
              {
                permission: {
                  key: "profile:read:self",
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
      ],
    });

    const result = await getCurrentUser("user-123");

    expect(result.id).toBe("user-123");
    expect(result.email).toBe("user@example.com");

    expect(result.roles).toEqual(["ADMIN", "USER"]);

    expect(result.permissions).toEqual([
      "profile:read:self",
      "profile:update:self",
      "users:read:any",
    ]);

    expect(result).not.toHaveProperty("passwordHash");
    expect(result).not.toHaveProperty("roles.0.permissions");
  });

  it("throws 404 when the user does not exist", async () => {
    prisma.user.findUnique.mockResolvedValue(null);

    await expect(getCurrentUser("missing-user")).rejects.toMatchObject({
      message: "User not found",
      statusCode: 404,
    });
  });

  it("queries the requested user ID", async () => {
    prisma.user.findUnique.mockResolvedValue({
      id: "user-123",
      email: "user@example.com",
      firstName: "Test",
      lastName: "User",
      status: "ACTIVE",
      emailVerifiedAt: null,
      createdAt: new Date(),
      roles: [],
    });

    await getCurrentUser("user-123");

    expect(prisma.user.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: "user-123",
        },
      }),
    );
  });
});
