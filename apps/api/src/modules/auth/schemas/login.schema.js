import { z } from "zod";

export const loginSchema = z
  .object({
    email: z
      .string()
      .trim()
      .toLowerCase()
      .email("Please provide a valid email address.")
      .max(254, "Email address is too long."),

    password: z
      .string()
      .min(1, "Password is required.")
      .max(128, "Password is too long."),
  })
  .strict();
