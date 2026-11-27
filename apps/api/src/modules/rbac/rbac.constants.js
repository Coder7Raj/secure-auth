export const SYSTEM_ROLES = Object.freeze({
  USER: Object.freeze({
    name: "USER",
    description: "Standard authenticated user",
  }),

  ADMIN: Object.freeze({
    name: "ADMIN",
    description:
      "Administrator with explicitly defined administrative permissions",
  }),

  SUPER_ADMIN: Object.freeze({
    name: "SUPER_ADMIN",
    description: "Highest-privilege system administrator",
  }),
});

export const PERMISSIONS = Object.freeze({
  PROFILE_READ_SELF: {
    key: "profile:read:self",
    description: "Read the authenticated user's own profile",
  },
  PROFILE_UPDATE_SELF: {
    key: "profile:update:self",
    description: "Update the authenticated user's own profile",
  },
  SESSIONS_READ_SELF: {
    key: "sessions:read:self",
    description: "View the authenticated user's own sessions",
  },
  SESSIONS_REVOKE_SELF: {
    key: "sessions:revoke:self",
    description: "Revoke the authenticated user's own sessions",
  },
  USERS_READ_ANY: {
    key: "users:read:any",
    description: "View user accounts",
  },
  USERS_UPDATE_ANY: {
    key: "users:update:any",
    description: "Update user accounts",
  },
  USERS_SUSPEND_ANY: {
    key: "users:suspend:any",
    description: "Suspend and reactivate user accounts",
  },
  ROLES_READ_ANY: {
    key: "roles:read:any",
    description: "View roles and their assignments",
  },
  ROLES_ASSIGN_ANY: {
    key: "roles:assign:any",
    description: "Assign and revoke roles for users",
  },
  PERMISSIONS_READ_ANY: {
    key: "permissions:read:any",
    description: "View available system permissions",
  },
  AUDIT_LOGS_READ_ANY: {
    key: "audit-logs:read:any",
    description: "View system audit logs",
  },
});

const selfServicePermissions = [
  PERMISSIONS.PROFILE_READ_SELF.key,
  PERMISSIONS.PROFILE_UPDATE_SELF.key,
  PERMISSIONS.SESSIONS_READ_SELF.key,
  PERMISSIONS.SESSIONS_REVOKE_SELF.key,
];

const administrativePermissions = [
  PERMISSIONS.USERS_READ_ANY.key,
  PERMISSIONS.USERS_UPDATE_ANY.key,
  PERMISSIONS.USERS_SUSPEND_ANY.key,
  PERMISSIONS.ROLES_READ_ANY.key,
  PERMISSIONS.ROLES_ASSIGN_ANY.key,
  PERMISSIONS.PERMISSIONS_READ_ANY.key,
  PERMISSIONS.AUDIT_LOGS_READ_ANY.key,
];

export const ROLE_PERMISSIONS = Object.freeze({
  USER: Object.freeze(selfServicePermissions),

  ADMIN: Object.freeze([
    ...selfServicePermissions,
    ...administrativePermissions,
  ]),

  SUPER_ADMIN: Object.freeze(
    Object.values(PERMISSIONS).map((permission) => permission.key),
  ),
});
