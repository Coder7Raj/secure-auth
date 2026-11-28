import { beforeEach, describe, expect, it, vi } from "vitest";

const { listActiveSessions, revokeSession, revokeOtherSessions } = vi.hoisted(
  () => ({
    listActiveSessions: vi.fn(),
    revokeSession: vi.fn(),
    revokeOtherSessions: vi.fn(),
  }),
);

vi.mock("./session.service.js", () => ({
  listActiveSessions,
  revokeSession,
  revokeOtherSessions,
}));

import {
  ACCESS_COOKIE_CLEAR_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_CLEAR_OPTIONS,
} from "../../config/cookies.js";

import {
  listSessionsController,
  revokeOtherSessionsController,
  revokeSessionController,
} from "./session.controller.js";

function createResponse() {
  const res = {
    status: vi.fn(),
    json: vi.fn(),
    clearCookie: vi.fn(),
  };

  res.status.mockReturnValue(res);
  res.json.mockReturnValue(res);

  return res;
}

function createRequest(overrides = {}) {
  return {
    auth: {
      userId: "11111111-1111-4111-8111-111111111111",
      sessionId: "22222222-2222-4222-8222-222222222222",
    },
    params: {},
    ...overrides,
  };
}

describe("Session controllers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("listSessionsController", () => {
    it("returns the authenticated user's active sessions", async () => {
      const sessions = [
        {
          id: "33333333-3333-4333-8333-333333333333",
          ipAddress: "127.0.0.1",
          userAgent: "Test browser",
          deviceName: "Desktop",
          createdAt: new Date(),
          lastSeenAt: new Date(),
          expiresAt: new Date(),
        },
      ];

      listActiveSessions.mockResolvedValue(sessions);

      const req = createRequest();
      const res = createResponse();
      const next = vi.fn();

      await listSessionsController(req, res, next);

      expect(listActiveSessions).toHaveBeenCalledWith({
        userId: req.auth.userId,
      });

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        data: {
          sessions,
        },
      });

      expect(next).not.toHaveBeenCalled();
    });

    it("forwards service errors to the error handler", async () => {
      const error = new Error("Database failure");

      listActiveSessions.mockRejectedValue(error);

      const req = createRequest();
      const res = createResponse();
      const next = vi.fn();

      await listSessionsController(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
      expect(res.json).not.toHaveBeenCalled();
    });
  });

  describe("revokeSessionController", () => {
    it("revokes a session belonging to the authenticated user", async () => {
      const sessionId = "33333333-3333-4333-8333-333333333333";

      revokeSession.mockResolvedValue({
        success: true,
        alreadyRevoked: false,
      });

      const req = createRequest({
        params: { sessionId },
      });

      const res = createResponse();
      const next = vi.fn();

      await revokeSessionController(req, res, next);

      expect(revokeSession).toHaveBeenCalledWith({
        userId: req.auth.userId,
        sessionId,
        revokeReason: "USER_LOGOUT",
      });

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        message: "Session revoked successfully.",
      });

      // A different session was revoked, so the current
      // authentication cookies must remain untouched.
      expect(res.clearCookie).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it("rejects an invalid session ID", async () => {
      const req = createRequest({
        params: { sessionId: "not-a-uuid" },
      });

      const res = createResponse();
      const next = vi.fn();

      await revokeSessionController(req, res, next);

      expect(revokeSession).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "Invalid session ID.",
          statusCode: 400,
        }),
      );
    });

    it("returns 404 when the session does not belong to the user", async () => {
      revokeSession.mockResolvedValue({
        success: false,
      });

      const req = createRequest({
        params: {
          sessionId: "33333333-3333-4333-8333-333333333333",
        },
      });

      const res = createResponse();
      const next = vi.fn();

      await revokeSessionController(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "Session not found.",
          statusCode: 404,
        }),
      );

      expect(res.json).not.toHaveBeenCalled();
    });

    it("clears both authentication cookies when revoking the current session", async () => {
      revokeSession.mockResolvedValue({
        success: true,
        alreadyRevoked: false,
      });

      const req = createRequest({
        params: {
          sessionId: "22222222-2222-4222-8222-222222222222",
        },
      });

      const res = createResponse();
      const next = vi.fn();

      await revokeSessionController(req, res, next);

      expect(res.clearCookie).toHaveBeenCalledTimes(2);

      expect(res.clearCookie).toHaveBeenCalledWith(
        COOKIE_NAMES.ACCESS_TOKEN,
        ACCESS_COOKIE_CLEAR_OPTIONS,
      );

      expect(res.clearCookie).toHaveBeenCalledWith(
        COOKIE_NAMES.REFRESH_TOKEN,
        REFRESH_COOKIE_CLEAR_OPTIONS,
      );

      expect(res.status).toHaveBeenCalledWith(200);
      expect(next).not.toHaveBeenCalled();
    });

    it("forwards service errors to the error handler", async () => {
      const error = new Error("Database failure");

      revokeSession.mockRejectedValue(error);

      const req = createRequest({
        params: {
          sessionId: "33333333-3333-4333-8333-333333333333",
        },
      });

      const res = createResponse();
      const next = vi.fn();

      await revokeSessionController(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
    });
  });

  describe("revokeOtherSessionsController", () => {
    it("revokes other sessions while preserving the current session", async () => {
      revokeOtherSessions.mockResolvedValue({
        success: true,
        revokedCount: 3,
      });

      const req = createRequest();
      const res = createResponse();
      const next = vi.fn();

      await revokeOtherSessionsController(req, res, next);

      expect(revokeOtherSessions).toHaveBeenCalledWith({
        userId: req.auth.userId,
        currentSessionId: req.auth.sessionId,
      });

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        message: "Other sessions revoked successfully.",
        data: {
          revokedCount: 3,
        },
      });

      expect(res.clearCookie).not.toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it("returns 401 when the current session is no longer active", async () => {
      revokeOtherSessions.mockResolvedValue({
        success: false,
        revokedCount: 0,
      });

      const req = createRequest();
      const res = createResponse();
      const next = vi.fn();

      await revokeOtherSessionsController(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "The current session is no longer active.",
          statusCode: 401,
        }),
      );
    });

    it("forwards service errors to the error handler", async () => {
      const error = new Error("Database failure");

      revokeOtherSessions.mockRejectedValue(error);

      const req = createRequest();
      const res = createResponse();
      const next = vi.fn();

      await revokeOtherSessionsController(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
    });
  });
});
