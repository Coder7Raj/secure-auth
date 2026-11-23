import { z } from "zod";

export const loginSchema = z
  .object({
    email: z
      .string()
      .trim()
      .toLowerCase()
      .email("Please provide a valid email address.")
      .max(254, "Email must not exceed 254 characters."),

    password: z.string().max(128, "Password must not exceed 128 characters."),
  })
  .strict();
