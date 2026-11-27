import argon2 from "argon2";

import { AppError } from "../../../common/errors/app-error.js";
import { prisma } from "../../../lib/prisma.js";

export async function registerUser(input) {
  const { email, password, firstName, lastName } = input;

  // Hash the password before storing it.
  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
  });

  try {
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName,
        lastName,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        status: true,
        emailVerifiedAt: true,
        createdAt: true,
      },
    });

    return user;
  } catch (error) {
    // Handle duplicate email at the database constraint level.
    // This also handles concurrent registration attempts safely.
    if (error?.code === "P2002") {
      const target = error.meta?.target;

      const emailConflict =
        target === "email" ||
        (Array.isArray(target) && target.includes("email"));

      if (emailConflict) {
        throw new AppError("An account with this email already exists", 409);
      }
    }

    throw error;
  }
}
