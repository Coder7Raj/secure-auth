import { beforeEach, describe, expect, it, vi } from "vitest";

const { verifyAccessToken, findUnique } = vi.hoisted(() => ({
  verifyAccessToken: vi.fn(),
  findUnique: vi.fn(),
}));

vi.mock("../../lib/jwt.js", () => ({
  verifyAccessToken,
}));

vi.mock("../../lib/prisma.js", () => ({
  prisma: {
    session: {
      findUnique,
    },
  },
}));

import { requireAuth } from "./require-auth.js";

describe("requireAuth middleware", () => {
  let req;
  let next;

  const validPayload = {
    sub: "11111111-1111-4111-8111-111111111111",
    sid: "22222222-2222-4222-8222-222222222222",
  };

  const activeSession = {
    id: validPayload.sid,
    userId: validPayload.sub,
    revokedAt: null,
    expiresAt: new Date(Date.now() + 60_000),
    user: {
      id: validPayload.sub,
      status: "ACTIVE",
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      cookies: {
        accessToken: "valid-access-token",
      },
    };

    next = vi.fn();

    verifyAccessToken.mockResolvedValue(validPayload);
    findUnique.mockResolvedValue(activeSession);
  });

  it("should reject a missing access cookie", async () => {
    req.cookies = {};

    await requireAuth(req, {}, next);

    expect(next).toHaveBeenCalledOnce();
    expect(next.mock.calls[0][0].statusCode).toBe(401);

    expect(verifyAccessToken).not.toHaveBeenCalled();
    expect(findUnique).not.toHaveBeenCalled();
  });

  it("should reject an invalid JWT", async () => {
    verifyAccessToken.mockRejectedValue(new Error("Invalid signature"));

    await requireAuth(req, {}, next);

    expect(next).toHaveBeenCalledOnce();
    expect(next.mock.calls[0][0].statusCode).toBe(401);
    expect(next.mock.calls[0][0].message).toBe(
      "Invalid or expired access token",
    );

    expect(findUnique).not.toHaveBeenCalled();
  });

  it("should reject a nonexistent session", async () => {
    findUnique.mockResolvedValue(null);

    await requireAuth(req, {}, next);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });

  it("should reject a session belonging to another user", async () => {
    findUnique.mockResolvedValue({
      ...activeSession,
      userId: "33333333-3333-4333-8333-333333333333",
    });

    await requireAuth(req, {}, next);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });

  it("should reject a revoked session", async () => {
    findUnique.mockResolvedValue({
      ...activeSession,
      revokedAt: new Date(),
    });

    await requireAuth(req, {}, next);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });

  it("should reject an expired session", async () => {
    findUnique.mockResolvedValue({
      ...activeSession,
      expiresAt: new Date(Date.now() - 60_000),
    });

    await requireAuth(req, {}, next);

    expect(next.mock.calls[0][0].statusCode).toBe(401);
  });

  it.each(["SUSPENDED", "DISABLED", "PENDING_VERIFICATION"])(
    "should reject a user with status %s",
    async (status) => {
      findUnique.mockResolvedValue({
        ...activeSession,
        user: {
          ...activeSession.user,
          status,
        },
      });

      await requireAuth(req, {}, next);

      expect(next.mock.calls[0][0].statusCode).toBe(401);
    },
  );

  it("should authenticate a valid request", async () => {
    await requireAuth(req, {}, next);

    expect(verifyAccessToken).toHaveBeenCalledWith("valid-access-token");

    expect(findUnique).toHaveBeenCalledWith({
      where: {
        id: validPayload.sid,
      },
      select: {
        id: true,
        userId: true,
        revokedAt: true,
        expiresAt: true,
        user: {
          select: {
            id: true,
            status: true,
          },
        },
      },
    });

    expect(req.auth).toEqual({
      userId: validPayload.sub,
      sessionId: validPayload.sid,
    });

    expect(Object.isFrozen(req.auth)).toBe(true);

    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
  });

  it("should propagate database errors without converting them to 401", async () => {
    const databaseError = new Error("Database connection failed");

    findUnique.mockRejectedValue(databaseError);

    await requireAuth(req, {}, next);

    expect(next).toHaveBeenCalledWith(databaseError);
  });
});
