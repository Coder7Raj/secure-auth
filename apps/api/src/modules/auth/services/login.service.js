import { prisma } from "../../../lib/prisma.js";
import { verifyPassword } from "./password.service.js";

function createAuthError(message, statusCode = 401) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

export async function loginUser(data) {
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
    throw createAuthError("Invalid email or password.");
  }

  const passwordIsValid = await verifyPassword(
    data.password,
    user.passwordHash,
  );

  if (!passwordIsValid) {
    throw createAuthError("Invalid email or password.");
  }

  if (user.status !== "ACTIVE") {
    if (user.status === "PENDING_VERIFICATION") {
      throw createAuthError("Please verify your email before logging in.", 403);
    }

    throw createAuthError("Your account is unavailable.", 403);
  }

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    status: user.status,
  };
}
