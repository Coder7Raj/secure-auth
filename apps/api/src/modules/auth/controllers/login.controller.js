import {
  ACCESS_COOKIE_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_OPTIONS,
} from "../../../config/cookies.js";
import { signAccessToken } from "../../../lib/jwt.js";

import { loginSchema } from "../schemas/login.schema.js";
import { loginUser } from "../services/login.service.js";

/**
 * Handle user login.
 *
 * Responsibilities:
 * 1. Validate incoming credentials.
 * 2. Authenticate the user.
 * 3. Generate an access JWT.
 * 4. Set access and refresh tokens in HTTP-only cookies.
 * 5. Return safe user and session information.
 */
export async function loginController(req, res, next) {
  try {
    // Validate and sanitize incoming credentials.
    const validation = loginSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        success: false,
        message: "Validation failed.",
        errors: validation.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      });
    }

    // Authenticate user and create an authenticated session.
    const result = await loginUser(validation.data, {
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    // Generate a short-lived access JWT.
    const accessToken = await signAccessToken({
      userId: result.user.id,
      sessionId: result.session.id,
    });

    // Store JWTs exclusively in HTTP-only cookies.
    res.cookie(COOKIE_NAMES.ACCESS_TOKEN, accessToken, ACCESS_COOKIE_OPTIONS);

    res.cookie(
      COOKIE_NAMES.REFRESH_TOKEN,
      result.refreshToken,
      REFRESH_COOKIE_OPTIONS,
    );

    // Return only safe user and session information.
    return res.status(200).json({
      success: true,
      message: "Login successful.",
      data: {
        user: result.user,
        session: result.session,
      },
    });
  } catch (error) {
    return next(error);
  }
}
