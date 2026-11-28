import { z } from "zod";

import {
  ACCESS_COOKIE_CLEAR_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_CLEAR_OPTIONS,
} from "../../config/cookies.js";
import {
  listActiveSessions,
  revokeOtherSessions,
  revokeSession,
} from "./session.service.js";

const sessionIdSchema = z.string().uuid();

function createHttpError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;

  return error;
}

/**
 * GET /api/v1/auth/sessions
 *
 * Return the authenticated user's active sessions.
 */
export async function listSessionsController(req, res, next) {
  try {
    const sessions = await listActiveSessions({
      userId: req.auth.userId,
    });

    return res.status(200).json({
      success: true,
      data: {
        sessions,
      },
    });
  } catch (error) {
    return next(error);
  }
}

/**
 * DELETE /api/v1/auth/sessions/:sessionId
 *
 * Revoke one session belonging to the authenticated user.
 */
export async function revokeSessionController(req, res, next) {
  try {
    const validation = sessionIdSchema.safeParse(req.params.sessionId);

    if (!validation.success) {
      throw createHttpError("Invalid session ID.", 400);
    }

    const sessionId = validation.data;

    const result = await revokeSession({
      userId: req.auth.userId,
      sessionId,
      revokeReason: "USER_LOGOUT",
    });

    if (!result.success) {
      throw createHttpError("Session not found.", 404);
    }

    // If the user revoked their current session, clear both cookies.
    if (sessionId === req.auth.sessionId) {
      res.clearCookie(COOKIE_NAMES.ACCESS_TOKEN, ACCESS_COOKIE_CLEAR_OPTIONS);

      res.clearCookie(COOKIE_NAMES.REFRESH_TOKEN, REFRESH_COOKIE_CLEAR_OPTIONS);
    }

    return res.status(200).json({
      success: true,
      message: "Session revoked successfully.",
    });
  } catch (error) {
    return next(error);
  }
}

/**
 * DELETE /api/v1/auth/sessions/others
 *
 * Revoke all active sessions except the current session.
 */
export async function revokeOtherSessionsController(req, res, next) {
  try {
    const result = await revokeOtherSessions({
      userId: req.auth.userId,
      currentSessionId: req.auth.sessionId,
    });

    if (!result.success) {
      throw createHttpError("The current session is no longer active.", 401);
    }

    return res.status(200).json({
      success: true,
      message: "Other sessions revoked successfully.",
      data: {
        revokedCount: result.revokedCount,
      },
    });
  } catch (error) {
    return next(error);
  }
}
