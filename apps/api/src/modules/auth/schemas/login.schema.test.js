import { describe, expect, it } from "vitest";

import { loginSchema } from "./login.schema.js";

describe("loginSchema", () => {
  const validInput = {
    email: "user@example.com",
    password: "StrongPassword123!",
  };

  it("should accept valid login credentials", () => {
    expect(loginSchema.safeParse(validInput).success).toBe(true);
  });

  it("should normalize email addresses", () => {
    const result = loginSchema.safeParse({
      ...validInput,
      email: "  USER@EXAMPLE.COM  ",
    });

    expect(result.success).toBe(true);
    expect(result.data.email).toBe("user@example.com");
  });

  it("should reject invalid email addresses", () => {
    const result = loginSchema.safeParse({
      ...validInput,
      email: "invalid-email",
    });

    expect(result.success).toBe(false);
  });

  it("should reject empty passwords", () => {
    const result = loginSchema.safeParse({
      ...validInput,
      password: "",
    });

    expect(result.success).toBe(false);
  });

  it("should reject passwords longer than 128 characters", () => {
    const result = loginSchema.safeParse({
      ...validInput,
      password: "a".repeat(129),
    });

    expect(result.success).toBe(false);
  });

  it("should reject unknown properties", () => {
    const result = loginSchema.safeParse({
      ...validInput,
      role: "ADMIN",
    });

    expect(result.success).toBe(false);
  });
});
