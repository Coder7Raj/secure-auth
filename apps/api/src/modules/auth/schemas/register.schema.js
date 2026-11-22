import { z } from "zod";

export const registerSchema = z
  .object({
    email: z
      .string()
      .trim()
      .toLowerCase()
      .email("Please provide a valid email address.")
      .max(254, "Email must not exceed 254 characters."),

    password: z
      .string()
      .min(12, "Password must be at least 12 characters long.")
      .max(128, "Password must not exceed 128 characters."),

    firstName: z
      .string()
      .trim()
      .max(80, "First name must not exceed 80 characters.")
      .optional(),

    lastName: z
      .string()
      .trim()
      .max(80, "Last name must not exceed 80 characters.")
      .optional(),
  })
  .strict();
