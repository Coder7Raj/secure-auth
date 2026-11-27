import { afterAll, beforeAll, describe, expect, it } from "vitest";

const databaseUrl = new URL(process.env.DATABASE_URL ?? "");

if (
  databaseUrl.hostname !== "localhost" ||
  databaseUrl.port !== "5433" ||
  databaseUrl.pathname !== "/secure_auth_test"
) {
  throw new Error(
    "Integration tests require secure_auth_test on localhost:5433",
  );
}

const testEmailPrefix = "register-integration-";

let prisma;
let registerUser;

const testUsers = [];

function createRegistrationInput(overrides = {}) {
  const email = `${testEmailPrefix}${crypto.randomUUID()}@example.com`;

  return {
    email,
    password: "StrongPassword123!",
    firstName: "Integration",
    lastName: "Test",
    ...overrides,
  };
}

beforeAll(async () => {
  const prismaModule = await import("../../../lib/prisma.js");
  const serviceModule = await import("./register.service.js");

  prisma = prismaModule.prisma;
  registerUser = serviceModule.registerUser;

  await prisma.$connect();
});

afterAll(async () => {
  if (prisma) {
    await prisma.user.deleteMany({
      where: {
        email: {
          startsWith: testEmailPrefix,
        },
      },
    });

    await prisma.$disconnect();
  }
});

describe("registerUser integration", () => {
  it("creates a user with a hashed password", async () => {
    const input = createRegistrationInput();
    testUsers.push(input.email);

    const user = await registerUser(input);

    const storedUser = await prisma.user.findUnique({
      where: { email: input.email },
    });

    expect(user.id).toBeDefined();
    expect(user.email).toBe(input.email);
    expect(user.status).toBe("PENDING_VERIFICATION");

    expect(storedUser).not.toBeNull();
    expect(storedUser.passwordHash).not.toBe(input.password);
  });

  it("stores the password as a valid Argon2id hash", async () => {
    const argon2 = await import("argon2");
    const input = createRegistrationInput();

    testUsers.push(input.email);

    await registerUser(input);

    const storedUser = await prisma.user.findUniqueOrThrow({
      where: { email: input.email },
    });

    expect(
      await argon2.default.verify(storedUser.passwordHash, input.password),
    ).toBe(true);
  });

  it("does not return the password hash", async () => {
    const input = createRegistrationInput();

    testUsers.push(input.email);

    const user = await registerUser(input);

    expect(user).not.toHaveProperty("passwordHash");
    expect(user).not.toHaveProperty("password");
  });

  it("persists optional profile fields", async () => {
    const input = createRegistrationInput({
      firstName: "Secure",
      lastName: "Auth",
    });

    testUsers.push(input.email);

    const user = await registerUser(input);

    expect(user.firstName).toBe("Secure");
    expect(user.lastName).toBe("Auth");
  });

  it("rejects duplicate email addresses", async () => {
    const input = createRegistrationInput();

    testUsers.push(input.email);

    await registerUser(input);

    await expect(registerUser(input)).rejects.toMatchObject({
      statusCode: 409,
      message: "An account with this email already exists",
    });
  });

  it("does not create a second user after a duplicate registration", async () => {
    const input = createRegistrationInput();

    testUsers.push(input.email);

    await registerUser(input);

    await expect(registerUser(input)).rejects.toMatchObject({
      statusCode: 409,
    });

    const count = await prisma.user.count({
      where: { email: input.email },
    });

    expect(count).toBe(1);
  });
});
