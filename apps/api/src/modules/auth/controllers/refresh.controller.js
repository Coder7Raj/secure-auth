import {
  ACCESS_COOKIE_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_OPTIONS,
} from "../../../config/cookies.js";

import { AppError } from "../../../common/errors/app-error.js";
import { signAccessToken } from "../../../lib/jwt.js";
import { rotateRefreshToken } from "../../session/session.service.js";

/**
 * Refresh the access token using the HTTP-only refresh token cookie.
 *
 * Responsibilities:
 * 1. Read the refresh token from the cookie.
 * 2. Rotate the refresh token.
 * 3. Generate a new access token.
 * 4. Replace both authentication cookies.
 * 5. Return only safe session information.
 */
export async function refreshController(req, res, next) {
  try {
    const refreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN];

    if (!refreshToken) {
      throw new AppError("Invalid or expired refresh token.", 401);
    }

    let result;

    try {
      result = await rotateRefreshToken({ token: refreshToken });
    } catch (error) {
      if (
        error.message === "Invalid refresh token" ||
        error.message === "Refresh token reuse detected"
      ) {
        throw new AppError("Invalid or expired refresh token.", 401);
      }

      throw error;
    }

    const accessToken = signAccessToken({
      userId: result.session.userId,
      sessionId: result.session.id,
    });

    res.cookie(COOKIE_NAMES.ACCESS_TOKEN, accessToken, ACCESS_COOKIE_OPTIONS);

    res.cookie(
      COOKIE_NAMES.REFRESH_TOKEN,
      result.refreshToken,
      REFRESH_COOKIE_OPTIONS,
    );

    return res.status(200).json({
      success: true,
      message: "Authentication tokens refreshed successfully.",
      data: {
        session: {
          id: result.session.id,
          userId: result.session.userId,
          expiresAt: result.session.expiresAt,
        },
      },
    });
  } catch (error) {
    return next(error);
  }
}
