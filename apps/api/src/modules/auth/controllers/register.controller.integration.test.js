import argon2 from "argon2";
import { randomUUID } from "node:crypto";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Protect the dedicated integration-test database.
const databaseUrl = new URL(process.env.DATABASE_URL ?? "http://invalid");

if (
  databaseUrl.hostname !== "localhost" ||
  databaseUrl.port !== "5433" ||
  databaseUrl.pathname !== "/secure_auth_test"
) {
  throw new Error(
    "Integration tests require secure_auth_test on localhost:5433",
  );
}

const { default: app } = await import("../../../app.js");
const { prisma } = await import("../../../lib/prisma.js");

const emailPrefix = "register-http-test-";

describe("POST /api/v1/auth/register", () => {
  beforeAll(async () => {
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.user.deleteMany({
      where: {
        email: {
          startsWith: emailPrefix,
        },
      },
    });

    await prisma.$disconnect();
  });

  function createInput(overrides = {}) {
    return {
      email: `${emailPrefix}${randomUUID()}@example.com`,
      password: "StrongPassword123!",
      firstName: "HTTP",
      lastName: "Integration",
      ...overrides,
    };
  }

  it("should register a user successfully", async () => {
    const input = createInput();

    const response = await request(app)
      .post("/api/v1/auth/register")
      .send(input);

    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);

    expect(response.body.data.user).toMatchObject({
      email: input.email,
      firstName: input.firstName,
      lastName: input.lastName,
      status: "PENDING_VERIFICATION",
    });

    expect(response.body.data.user).not.toHaveProperty("passwordHash");
  });

  it("should persist a valid Argon2id password hash", async () => {
    const input = createInput();

    await request(app).post("/api/v1/auth/register").send(input).expect(201);

    const storedUser = await prisma.user.findUniqueOrThrow({
      where: { email: input.email },
    });

    expect(storedUser.passwordHash).not.toBe(input.password);

    expect(await argon2.verify(storedUser.passwordHash, input.password)).toBe(
      true,
    );
  });

  it("should reject duplicate email addresses", async () => {
    const input = createInput();

    await request(app).post("/api/v1/auth/register").send(input).expect(201);

    const response = await request(app)
      .post("/api/v1/auth/register")
      .send(input)
      .expect(409);

    expect(response.body.success).toBe(false);
    expect(response.body.message).toBe(
      "An account with this email already exists",
    );
  });

  it("should reject invalid email addresses", async () => {
    const response = await request(app)
      .post("/api/v1/auth/register")
      .send(createInput({ email: "invalid-email" }))
      .expect(400);

    expect(response.body.success).toBe(false);
  });

  it("should reject short passwords", async () => {
    const response = await request(app)
      .post("/api/v1/auth/register")
      .send(createInput({ password: "short" }))
      .expect(400);

    expect(response.body.success).toBe(false);
  });

  it("should reject attempts to assign privileged roles", async () => {
    const input = createInput();

    await request(app)
      .post("/api/v1/auth/register")
      .send({
        ...input,
        role: "ADMIN",
      })
      .expect(400);

    const storedUser = await prisma.user.findUnique({
      where: { email: input.email },
    });

    expect(storedUser).toBeNull();
  });

  it("should reject requests with missing required fields", async () => {
    await request(app)
      .post("/api/v1/auth/register")
      .send({
        email: "missing-password@example.com",
      })
      .expect(400);
  });
});
