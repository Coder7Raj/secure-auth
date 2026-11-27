import {
  ACCESS_COOKIE_CLEAR_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_CLEAR_OPTIONS,
} from "../../../config/cookies.js";

import { revokeSession } from "../../session/session.service.js";

/**
 * Handle authenticated user logout.
 *
 * Responsibilities:
 * 1. Revoke the current database session.
 * 2. Revoke its associated refresh tokens.
 * 3. Clear authentication cookies.
 * 4. Return a safe response.
 */
export async function logoutController(req, res, next) {
  try {
    const { userId, sessionId } = req.auth;

    await revokeSession({
      userId,
      sessionId,
      revokeReason: "USER_LOGOUT",
    });

    res.clearCookie(COOKIE_NAMES.ACCESS_TOKEN, ACCESS_COOKIE_CLEAR_OPTIONS);

    res.clearCookie(COOKIE_NAMES.REFRESH_TOKEN, REFRESH_COOKIE_CLEAR_OPTIONS);

    return res.status(200).json({
      success: true,
      message: "Logout successful.",
    });
  } catch (error) {
    return next(error);
  }
}
