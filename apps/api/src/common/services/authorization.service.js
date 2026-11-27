import { prisma } from "../../lib/prisma.js";

/**
 * Retrieve all permission keys assigned to a user
 * through their roles.
 */
export async function getUserPermissions(userId) {
  const userRoles = await prisma.userRole.findMany({
    where: {
      userId,
      user: {
        is: {
          status: "ACTIVE",
        },
      },
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

  // Flatten permissions from all assigned roles.
  // Set removes duplicate permission keys.
  const permissions = new Set();

  for (const userRole of userRoles) {
    for (const rolePermission of userRole.role.permissions) {
      permissions.add(rolePermission.permission.key);
    }
  }

  return [...permissions];
}

/**
 * Retrieve all role names assigned to a user.
 */
export async function getUserRoles(userId) {
  const userRoles = await prisma.userRole.findMany({
    where: {
      userId,
      user: {
        is: {
          status: "ACTIVE",
        },
      },
    },
    select: {
      role: {
        select: {
          name: true,
        },
      },
    },
  });

  return userRoles.map(({ role }) => role.name);
}
