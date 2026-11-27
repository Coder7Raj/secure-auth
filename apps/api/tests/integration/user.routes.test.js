import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  requireAuth: vi.fn(),
  requirePermission: vi.fn(),
}));

let app;

async function loadApp() {
  vi.resetModules();

  vi.doMock("../../src/common/middleware/require-auth.js", () => ({
    requireAuth: mocks.requireAuth,
  }));

  vi.doMock("../../src/common/middleware/require-permission.js", () => ({
    requirePermission: mocks.requirePermission,
  }));

  const module = await import("../../src/app.js");

  app = module.default;
}

describe("GET /api/v1/users/me", () => {
  beforeEach(async () => {
    vi.clearAllMocks();

    mocks.requireAuth.mockImplementation((req, res, next) => {
      req.auth = {
        userId: "11111111-1111-4111-8111-111111111111",
        sessionId: "22222222-2222-4222-8222-222222222222",
      };

      next();
    });

    mocks.requirePermission.mockImplementation(() => {
      return (req, res, next) => next();
    });

    await loadApp();
  });

  it("should return the authenticated user's ID", async () => {
    const response = await request(app).get("/api/v1/users/me").expect(200);

    expect(response.body).toEqual({
      success: true,
      data: {
        userId: "11111111-1111-4111-8111-111111111111",
      },
    });
  });

  it("should require the correct permission", async () => {
    expect(mocks.requirePermission).toHaveBeenCalledWith("profile:read:self");

    await request(app).get("/api/v1/users/me").expect(200);
  });

  it("should reject unauthenticated requests", async () => {
    mocks.requireAuth.mockImplementation((req, res, next) => {
      next({
        name: "AppError",
        message: "Authentication required",
        statusCode: 401,
      });
    });

    const response = await request(app).get("/api/v1/users/me").expect(401);

    expect(response.body.success).toBe(false);
  });

  it("should reject requests without the required permission", async () => {
    // Configure the factory before loading the app.
    mocks.requirePermission.mockImplementation(() => {
      return (req, res, next) => {
        next({
          name: "AppError",
          message: "Insufficient permissions",
          statusCode: 403,
        });
      };
    });

    // Rebuild the route with the rejecting middleware.
    await loadApp();

    const response = await request(app).get("/api/v1/users/me").expect(403);

    expect(response.body.success).toBe(false);
  });
});
