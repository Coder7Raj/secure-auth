import argon2 from "argon2";

import { AppError } from "../../../common/errors/app-error.js";
import { prisma } from "../../../lib/prisma.js";
import { createSession } from "../../session/session.service.js";

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
};

// Generate a dummy hash once to reduce timing differences
// between unknown-email and incorrect-password attempts.
const DUMMY_PASSWORD_HASH = await argon2.hash(
  "secure-auth-dummy-password-not-used-for-authentication",
  ARGON2_OPTIONS,
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

  const user = await prisma.user.findUnique({
    where: {
      email: normalizedEmail,
    },
    select: {
      id: true,
      email: true,
      passwordHash: true,
      firstName: true,
      lastName: true,
      status: true,
    },
  });

  // Always perform an Argon2 verification, including
  // when the requested email does not exist.
  const passwordMatches = await argon2.verify(
    user?.passwordHash ?? DUMMY_PASSWORD_HASH,
    password,
  );

  // Generic response prevents account enumeration.
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

  // Reject unverified accounts.
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

  // Reject suspended and disabled accounts.
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

  // Create a new server-side session.
  const sessionResult = await createSession({
    userId: user.id,
    ipAddress: ipAddress?.slice(0, 45) ?? null,
    userAgent: userAgent?.slice(0, 512) ?? null,
  });

  // Update successful login activity.
  await prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      lastLoginAt: new Date(),
    },
  });

  await recordLoginAttempt({
    userId: user.id,
    email: normalizedEmail,
    ipAddress,
    userAgent,
    success: true,
    failureReason: null,
  });

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
