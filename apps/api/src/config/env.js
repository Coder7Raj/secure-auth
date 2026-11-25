import "dotenv/config";
import { z } from "zod";

const jwtExpiresInSchema = z
  .string()
  .regex(/^[1-9]\d*[smhd]$/, "Invalid JWT expiration format");

const envSchema = z
  .object({
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),

    PORT: z.coerce.number().int().min(1).max(65535).default(5000),

    CLIENT_URL: z
      .string()
      .url()
      .refine(
        (value) => ["http:", "https:"].includes(new URL(value).protocol),
        {
          message: "CLIENT_URL must use HTTP or HTTPS",
        },
      ),

    DATABASE_URL: z
      .string()
      .url()
      .refine(
        (value) =>
          ["postgres:", "postgresql:"].includes(new URL(value).protocol),
        {
          message: "DATABASE_URL must be a PostgreSQL connection URL",
        },
      ),

    JWT_ACCESS_SECRET: z.string().min(32),

    // JWT_REFRESH_SECRET: z.string().min(32),

    JWT_ACCESS_EXPIRES_IN: jwtExpiresInSchema.default("15m"),

    // JWT_REFRESH_EXPIRES_IN: jwtExpiresInSchema.default("7d"),

    JWT_ISSUER: z.string().min(1).default("secure-auth-api"),

    JWT_AUDIENCE: z.string().min(1).default("secure-auth-api"),

    SESSION_MAX_AGE_DAYS: z.coerce.number().int().positive().default(7),
  })
  .superRefine((config, ctx) => {
    if (
      config.NODE_ENV === "production" &&
      new URL(config.CLIENT_URL).protocol !== "https:"
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["CLIENT_URL"],
        message: "CLIENT_URL must use HTTPS in production",
      });
    }

    // if (config.JWT_ACCESS_SECRET === config.JWT_REFRESH_SECRET) {
    //   ctx.addIssue({
    //     code: "custom",
    //     path: ["JWT_REFRESH_SECRET"],
    //     message: "Access and refresh JWT secrets must be different",
    //   });
    // }
  });

const result = envSchema.safeParse(process.env);

if (!result.success) {
  console.error("Invalid environment configuration:");
  console.error(result.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = Object.freeze(result.data);
