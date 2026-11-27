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

import { getUserPermissions, getUserRoles } from "./authorization.service.js";

describe("Authorization service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("getUserPermissions", () => {
    it("should return permissions assigned through user roles", async () => {
      mocks.findMany.mockResolvedValue([
        {
          role: {
            permissions: [
              { permission: { key: "profile:read:self" } },
              { permission: { key: "profile:update:self" } },
            ],
          },
        },
        {
          role: {
            permissions: [
              { permission: { key: "users:read:any" } },
              { permission: { key: "profile:read:self" } },
            ],
          },
        },
      ]);

      const permissions = await getUserPermissions(
        "550e8400-e29b-41d4-a716-446655440000",
      );

      expect(permissions).toEqual([
        "profile:read:self",
        "profile:update:self",
        "users:read:any",
      ]);
    });

    it("should return an empty array when the user has no roles", async () => {
      mocks.findMany.mockResolvedValue([]);

      await expect(
        getUserPermissions("550e8400-e29b-41d4-a716-446655440000"),
      ).resolves.toEqual([]);
    });

    it("should filter out inactive users", async () => {
      mocks.findMany.mockResolvedValue([]);

      await getUserPermissions("550e8400-e29b-41d4-a716-446655440000");

      expect(mocks.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            userId: "550e8400-e29b-41d4-a716-446655440000",
            user: {
              is: {
                status: "ACTIVE",
              },
            },
          },
        }),
      );
    });
  });

  describe("getUserRoles", () => {
    it("should return assigned role names", async () => {
      mocks.findMany.mockResolvedValue([
        { role: { name: "USER" } },
        { role: { name: "ADMIN" } },
      ]);

      await expect(
        getUserRoles("550e8400-e29b-41d4-a716-446655440000"),
      ).resolves.toEqual(["USER", "ADMIN"]);
    });

    it("should return an empty array when no roles exist", async () => {
      mocks.findMany.mockResolvedValue([]);

      await expect(
        getUserRoles("550e8400-e29b-41d4-a716-446655440000"),
      ).resolves.toEqual([]);
    });
  });
});
