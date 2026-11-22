import { prisma } from "../../../lib/prisma.js";
import { hashPassword } from "./password.service.js";

export async function registerUser(data) {
  const email = data.email;

  const existingUser = await prisma.user.findUnique({
    where: { email },
    select: { id: true },
  });

  if (existingUser) {
    const error = new Error("An account with this email already exists.");
    error.statusCode = 409;
    throw error;
  }

  const passwordHash = await hashPassword(data.password);

  try {
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName: data.firstName,
        lastName: data.lastName,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        status: true,
        createdAt: true,
      },
    });

    return user;
  } catch (error) {
    if (error.code === "P2002") {
      const duplicateError = new Error(
        "An account with this email already exists.",
      );

      duplicateError.statusCode = 409;
      throw duplicateError;
    }

    throw error;
  }
}
