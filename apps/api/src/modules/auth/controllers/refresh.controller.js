import { AppError } from "../../../common/errors/app-error.js";
import {
  ACCESS_COOKIE_CLEAR_OPTIONS,
  ACCESS_COOKIE_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_CLEAR_OPTIONS,
  REFRESH_COOKIE_OPTIONS,
} from "../../../config/cookies.js";
import { signAccessToken } from "../../../lib/jwt.js";
import { rotateRefreshToken } from "../../session/session.service.js";

const EXPECTED_REFRESH_FAILURES = new Set([
  "Invalid refresh token",
  "Refresh token reuse detected",
  "SESSION_NO_LONGER_ACTIVE",
]);

function clearAuthenticationCookies(res) {
  res.clearCookie(COOKIE_NAMES.ACCESS_TOKEN, ACCESS_COOKIE_CLEAR_OPTIONS);
  res.clearCookie(COOKIE_NAMES.REFRESH_TOKEN, REFRESH_COOKIE_CLEAR_OPTIONS);
}

export async function refreshController(req, res, next) {
  try {
    const refreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN];

    if (!refreshToken) {
      clearAuthenticationCookies(res);
      return next(new AppError("Authentication required.", 401));
    }

    let result;

    try {
      result = await rotateRefreshToken({ token: refreshToken });
    } catch (error) {
      if (EXPECTED_REFRESH_FAILURES.has(error?.message)) {
        clearAuthenticationCookies(res);

        return next(new AppError("Invalid or expired refresh token.", 401));
      }

      throw error;
    }

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
      data: { session: result.session },
    });
  } catch (error) {
    return next(error);
  }
}
