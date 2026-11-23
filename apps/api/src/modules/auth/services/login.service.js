import { prisma } from "../../../lib/prisma.js";
import { verifyPassword } from "./password.service.js";

const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,t=3,p=1$TjLyNLjZlHP0vD4wyvnIpQ$GhhrAvltsfq4AJNU5X2p8PzHhhmVR4E1H24GNN45PQY";

function createAuthError(message, statusCode = 401) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

async function recordLoginAttempt({
  userId = null,
  email,
  ipAddress = null,
  userAgent = null,
  success,
  failureReason = null,
}) {
  await prisma.loginAttempt.create({
    data: {
      userId,
      email,
      ipAddress,
      userAgent,
      success,
      failureReason,
    },
  });
}

export async function loginUser(data, metadata = {}) {
  const { ipAddress = null, userAgent = null } = metadata;

  const user = await prisma.user.findUnique({
    where: { email: data.email },
    select: {
      id: true,
      email: true,
      passwordHash: true,
      firstName: true,
      lastName: true,
      status: true,
    },
  });

  if (!user) {
    await verifyPassword(data.password, DUMMY_PASSWORD_HASH);

    await recordLoginAttempt({
      email: data.email,
      ipAddress,
      userAgent,
      success: false,
      failureReason: "INVALID_CREDENTIALS",
    });

    throw createAuthError("Invalid email or password.");
  }

  const passwordIsValid = await verifyPassword(
    data.password,
    user.passwordHash,
  );

  if (!passwordIsValid) {
    await recordLoginAttempt({
      userId: user.id,
      email: user.email,
      ipAddress,
      userAgent,
      success: false,
      failureReason: "INVALID_CREDENTIALS",
    });

    throw createAuthError("Invalid email or password.");
  }

  if (user.status !== "ACTIVE") {
    const failureReason =
      user.status === "PENDING_VERIFICATION"
        ? "ACCOUNT_UNVERIFIED"
        : "ACCOUNT_UNAVAILABLE";

    await recordLoginAttempt({
      userId: user.id,
      email: user.email,
      ipAddress,
      userAgent,
      success: false,
      failureReason,
    });

    if (user.status === "PENDING_VERIFICATION") {
      throw createAuthError("Please verify your email before logging in.", 403);
    }

    throw createAuthError("Your account is unavailable.", 403);
  }

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await recordLoginAttempt({
    userId: user.id,
    email: user.email,
    ipAddress,
    userAgent,
    success: true,
  });

  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    status: user.status,
  };
}
