import { beforeEach, describe, expect, it, vi } from "vitest";

const { hash, create } = vi.hoisted(() => ({
  hash: vi.fn(),
  create: vi.fn(),
}));

vi.mock("argon2", () => ({
  default: {
    hash,
    argon2id: 2,
  },
}));

vi.mock("../../../lib/prisma.js", () => ({
  prisma: {
    user: {
      create,
    },
  },
}));

import argon2 from "argon2";
import { registerUser } from "./register.service.js";

describe("Registration service", () => {
  const input = {
    email: "test@example.com",
    password: "StrongPassword123!",
    firstName: "Test",
    lastName: "User",
  };

  const passwordHash = "$argon2id$mocked-password-hash";

  const createdUser = {
    id: "11111111-1111-4111-8111-111111111111",
    email: input.email,
    firstName: input.firstName,
    lastName: input.lastName,
    status: "PENDING_VERIFICATION",
    emailVerifiedAt: null,
    createdAt: new Date(),
  };

  beforeEach(() => {
    vi.clearAllMocks();

    hash.mockResolvedValue(passwordHash);
    create.mockResolvedValue(createdUser);
  });

  it("should successfully register a user", async () => {
    const result = await registerUser(input);

    expect(result).toEqual(createdUser);

    expect(hash).toHaveBeenCalledWith(input.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
    });

    expect(create).toHaveBeenCalledOnce();
  });

  it("should persist the hashed password instead of plaintext", async () => {
    await registerUser(input);

    const createArguments = create.mock.calls[0][0];

    expect(createArguments.data.passwordHash).toBe(passwordHash);
    expect(createArguments.data.passwordHash).not.toBe(input.password);
  });

  it("should never return the password hash", async () => {
    const result = await registerUser(input);

    expect(result).not.toHaveProperty("passwordHash");
    expect(JSON.stringify(result)).not.toContain(passwordHash);
  });

  it("should select only safe user fields", async () => {
    await registerUser(input);

    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          status: true,
          emailVerifiedAt: true,
          createdAt: true,
        },
      }),
    );
  });

  it("should rely on the database default account status", async () => {
    await registerUser(input);

    expect(create.mock.calls[0][0].data).not.toHaveProperty("status");
  });

  it("should reject duplicate email addresses", async () => {
    const duplicateError = Object.assign(
      new Error("Unique constraint failed"),
      {
        code: "P2002",
        meta: {
          target: ["email"],
        },
      },
    );

    create.mockRejectedValue(duplicateError);

    await expect(registerUser(input)).rejects.toMatchObject({
      statusCode: 409,
      message: "An account with this email already exists",
    });
  });

  it("should propagate unexpected database errors", async () => {
    const databaseError = new Error("Database connection failed");

    create.mockRejectedValue(databaseError);

    await expect(registerUser(input)).rejects.toBe(databaseError);
  });

  it("should propagate password hashing failures", async () => {
    const hashingError = new Error("Argon2 hashing failed");

    hash.mockRejectedValue(hashingError);

    await expect(registerUser(input)).rejects.toBe(hashingError);

    expect(create).not.toHaveBeenCalled();
  });

  it("should support optional profile fields", async () => {
    const minimalInput = {
      email: "minimal@example.com",
      password: "StrongPassword123!",
    };

    await registerUser(minimalInput);

    expect(create.mock.calls[0][0].data).toEqual({
      email: minimalInput.email,
      passwordHash,
      firstName: undefined,
      lastName: undefined,
    });
  });
});
