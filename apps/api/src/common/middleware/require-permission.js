import { prisma } from "../../lib/prisma.js";
import { AppError } from "../errors/app-error.js";

/**
 * Require an authenticated user to possess all specified permissions.
 *
 * Must run after requireAuth middleware.
 *
 * @param {...string} requiredPermissions
 * @returns {import("express").RequestHandler}
 */
export function requirePermission(...requiredPermissions) {
  if (
    requiredPermissions.length === 0 ||
    requiredPermissions.some(
      (permission) => typeof permission !== "string" || !permission.trim(),
    )
  ) {
    throw new TypeError("At least one valid permission is required");
  }

  return async function permissionMiddleware(req, res, next) {
    try {
      if (!req.auth?.userId) {
        throw new AppError("Authentication required", 401);
      }

      const userRoles = await prisma.userRole.findMany({
        where: {
          userId: req.auth.userId,
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

      const grantedPermissions = new Set(
        userRoles.flatMap((userRole) =>
          userRole.role.permissions.map(
            (rolePermission) => rolePermission.permission.key,
          ),
        ),
      );

      const hasAllPermissions = requiredPermissions.every((permission) =>
        grantedPermissions.has(permission),
      );

      if (!hasAllPermissions) {
        throw new AppError("Insufficient permissions", 403);
      }

      return next();
    } catch (error) {
      return next(error);
    }
  };
}
