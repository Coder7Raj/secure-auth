import { AppError } from "../../../common/errors/app-error.js";
import { prisma } from "../../../lib/prisma.js";
import { createSession } from "../../session/session.service.js";

import {
  consumeLoginAttempt,
  resetAccountThrottle,
} from "./login-throttle.service.js";
import { hashPassword, verifyPassword } from "./password.service.js";

const DUMMY_PASSWORD_HASH = await hashPassword(
  "secure-auth-dummy-password-not-used-for-authentication",
);

function createAuthError(message, statusCode = 401) {
  return new AppError(message, statusCode);
}

async function recordLoginAttempt({
  userId,
  email,
  ipAddress,
  userAgent,
  success,
  failureReason,
}) {
  await prisma.loginAttempt.create({
    data: {
      userId,
      email,
      ipAddress: ipAddress?.slice(0, 45) ?? null,
      userAgent: userAgent?.slice(0, 512) ?? null,
      success,
      failureReason,
    },
  });
}

/**
 * Authenticate a user and create an authenticated session.
 */
export async function loginUser(
  { email, password },
  { ipAddress, userAgent } = {},
) {
  const normalizedEmail = email.trim().toLowerCase();

  // Enforce account-level and IP-level limits before password verification.
  const throttle = await consumeLoginAttempt({
    email: normalizedEmail,
    ipAddress,
  });

  if (!throttle.allowed) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((throttle.retryAt.getTime() - Date.now()) / 1000),
    );

    const error = createAuthError(
      "Too many login attempts. Please try again later.",
      429,
    );

    error.retryAfterSeconds = retryAfterSeconds;

    throw error;
  }

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
    select: {
      id: true,
      email: true,
      passwordHash: true,
      firstName: true,
      lastName: true,
      status: true,
    },
  });

  // Verify against a dummy hash for unknown accounts to reduce
  // timing differences between unknown-email and wrong-password cases.
  const passwordMatches = await verifyPassword(
    password,
    user?.passwordHash ?? DUMMY_PASSWORD_HASH,
  );

  if (!user || !passwordMatches) {
    await recordLoginAttempt({
      userId: user?.id ?? null,
      email: normalizedEmail,
      ipAddress,
      userAgent,
      success: false,
      failureReason: "INVALID_CREDENTIALS",
    });

    throw createAuthError("Invalid email or password.", 401);
  }

  if (user.status === "PENDING_VERIFICATION") {
    await recordLoginAttempt({
      userId: user.id,
      email: normalizedEmail,
      ipAddress,
      userAgent,
      success: false,
      failureReason: "ACCOUNT_UNVERIFIED",
    });

    throw createAuthError("Please verify your email before logging in.", 403);
  }

  if (user.status !== "ACTIVE") {
    await recordLoginAttempt({
      userId: user.id,
      email: normalizedEmail,
      ipAddress,
      userAgent,
      success: false,
      failureReason: "ACCOUNT_UNAVAILABLE",
    });

    throw createAuthError("Your account is currently unavailable.", 403);
  }

  const sessionResult = await createSession({
    userId: user.id,
    ipAddress: ipAddress?.slice(0, 45) ?? null,
    userAgent: userAgent?.slice(0, 512) ?? null,
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await recordLoginAttempt({
    userId: user.id,
    email: normalizedEmail,
    ipAddress,
    userAgent,
    success: true,
    failureReason: null,
  });

  // Clear the account counter after a successful login.
  // Keep the IP counter to prevent switching accounts to bypass IP limits.
  await resetAccountThrottle(normalizedEmail);

  return {
    user: {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      status: user.status,
    },
    session: sessionResult.session,
    refreshToken: sessionResult.refreshToken,
  };
}
