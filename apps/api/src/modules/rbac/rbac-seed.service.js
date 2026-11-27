import {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  SYSTEM_ROLES,
} from "./rbac.constants.js";

/**
 * Seed system roles, permissions, and their assignments.
 *
 * This operation is additive and idempotent:
 * - Existing records are updated only in seed-owned fields.
 * - Existing assignments are not duplicated.
 * - Obsolete assignments are not automatically deleted.
 *
 * @param {import("@prisma/client").PrismaClient} prismaClient
 */
export async function seedSystemRbac(prismaClient) {
  if (!prismaClient?.$transaction) {
    throw new TypeError("A valid Prisma client is required");
  }

  return prismaClient.$transaction(async (tx) => {
    const roleRecords = {};
    const permissionRecords = {};

    // 1. Create or update system roles.
    for (const role of Object.values(SYSTEM_ROLES)) {
      roleRecords[role.name] = await tx.role.upsert({
        where: {
          name: role.name,
        },
        update: {
          description: role.description,
          isSystem: true,
        },
        create: {
          name: role.name,
          description: role.description,
          isSystem: true,
        },
      });
    }

    // 2. Create or update permissions.
    for (const permission of Object.values(PERMISSIONS)) {
      permissionRecords[permission.key] = await tx.permission.upsert({
        where: {
          key: permission.key,
        },
        update: {
          description: permission.description,
        },
        create: {
          key: permission.key,
          description: permission.description,
        },
      });
    }

    // 3. Create role-permission assignments.
    let assignmentCount = 0;

    for (const [roleName, permissionKeys] of Object.entries(ROLE_PERMISSIONS)) {
      const role = roleRecords[roleName];

      for (const permissionKey of permissionKeys) {
        const permission = permissionRecords[permissionKey];

        await tx.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: role.id,
              permissionId: permission.id,
            },
          },
          update: {},
          create: {
            roleId: role.id,
            permissionId: permission.id,
          },
        });

        assignmentCount += 1;
      }
    }

    return {
      rolesCreatedOrUpdated: Object.keys(roleRecords).length,
      permissionsCreatedOrUpdated: Object.keys(permissionRecords).length,
      assignmentsEnsured: assignmentCount,
    };
  });
}
