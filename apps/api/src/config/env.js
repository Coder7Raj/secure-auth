import "dotenv/config";
import { z } from "zod";

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
  });

const result = envSchema.safeParse(process.env);

if (!result.success) {
  console.error("Invalid environment configuration:");
  console.error(result.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = Object.freeze(result.data);
