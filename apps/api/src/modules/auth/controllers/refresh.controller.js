import {
  ACCESS_COOKIE_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_OPTIONS,
} from "../../../config/cookies.js";
import { signAccessToken } from "../../../lib/jwt.js";
import { rotateRefreshToken } from "../../session/session.service.js";

/**
 * Handle refresh-token rotation.
 *
 * Responsibilities:
 * 1. Read the refresh token from its HTTP-only cookie.
 * 2. Rotate the refresh token.
 * 3. Generate a new access JWT.
 * 4. Replace both authentication cookies.
 * 5. Return safe session information.
 */
export async function refreshController(req, res, next) {
  try {
    const refreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN];

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const result = await rotateRefreshToken({
      token: refreshToken,
    });

    const accessToken = await signAccessToken({
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
      message: "Token refreshed successfully.",
      data: {
        session: result.session,
      },
    });
  } catch (error) {
    return next(error);
  }
}
