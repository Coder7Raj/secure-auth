import { describe, expect, it, vi } from "vitest";

import {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  SYSTEM_ROLES,
} from "./rbac.constants.js";

import { seedSystemRbac } from "./rbac-seed.service.js";

function createMockPrisma() {
  const roles = new Map();
  const permissions = new Map();
  const assignments = new Map();

  let nextRoleId = 1;
  let nextPermissionId = 1;

  const tx = {
    role: {
      upsert: vi.fn(async ({ where, create, update }) => {
        const existing = roles.get(where.name);

        if (existing) {
          Object.assign(existing, update);
          return existing;
        }

        const record = {
          id: `role-${nextRoleId++}`,
          ...create,
        };

        roles.set(where.name, record);

        return record;
      }),
    },

    permission: {
      upsert: vi.fn(async ({ where, create, update }) => {
        const existing = permissions.get(where.key);

        if (existing) {
          Object.assign(existing, update);
          return existing;
        }

        const record = {
          id: `permission-${nextPermissionId++}`,
          ...create,
        };

        permissions.set(where.key, record);

        return record;
      }),
    },

    rolePermission: {
      upsert: vi.fn(async ({ where, create }) => {
        const key = `${where.roleId_permissionId.roleId}:${where.roleId_permissionId.permissionId}`;

        if (assignments.has(key)) {
          return assignments.get(key);
        }

        const record = {
          roleId: create.roleId,
          permissionId: create.permissionId,
        };

        assignments.set(key, record);

        return record;
      }),
    },
  };

  const prisma = {
    $transaction: vi.fn(async (callback) => callback(tx)),
  };

  return {
    prisma,
    tx,
    roles,
    permissions,
    assignments,
  };
}

describe("seedSystemRbac", () => {
  it("creates all system roles and permissions", async () => {
    const { prisma, roles, permissions } = createMockPrisma();

    const result = await seedSystemRbac(prisma);

    expect(roles.size).toBe(Object.keys(SYSTEM_ROLES).length);
    expect(permissions.size).toBe(Object.keys(PERMISSIONS).length);

    expect(result.rolesCreatedOrUpdated).toBe(3);
    expect(result.permissionsCreatedOrUpdated).toBe(
      Object.keys(PERMISSIONS).length,
    );
  });

  it("marks all seeded roles as system roles", async () => {
    const { prisma, roles } = createMockPrisma();

    await seedSystemRbac(prisma);

    for (const role of roles.values()) {
      expect(role.isSystem).toBe(true);
    }
  });

  it("creates the expected role-permission assignments", async () => {
    const { prisma, assignments } = createMockPrisma();

    const result = await seedSystemRbac(prisma);

    const expectedAssignmentCount = Object.values(ROLE_PERMISSIONS).reduce(
      (total, permissionKeys) => total + permissionKeys.length,
      0,
    );

    expect(assignments.size).toBe(expectedAssignmentCount);
    expect(result.assignmentsEnsured).toBe(expectedAssignmentCount);
  });

  it("does not duplicate records or assignments when executed twice", async () => {
    const { prisma, roles, permissions, assignments } = createMockPrisma();

    await seedSystemRbac(prisma);

    const firstRoleCount = roles.size;
    const firstPermissionCount = permissions.size;
    const firstAssignmentCount = assignments.size;

    await seedSystemRbac(prisma);

    expect(roles.size).toBe(firstRoleCount);
    expect(permissions.size).toBe(firstPermissionCount);
    expect(assignments.size).toBe(firstAssignmentCount);
  });

  it("runs the operation inside a Prisma transaction", async () => {
    const { prisma } = createMockPrisma();

    await seedSystemRbac(prisma);

    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
  });

  it("rejects an invalid Prisma client", async () => {
    await expect(seedSystemRbac(null)).rejects.toThrow(
      "A valid Prisma client is required",
    );
  });
});
