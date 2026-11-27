import { loginSchema } from "../schemas/login.schema.js";
import { loginUser } from "../services/login.service.js";

import { signAccessToken } from "../../../lib/jwt.js";

import {
  ACCESS_COOKIE_OPTIONS,
  COOKIE_NAMES,
  REFRESH_COOKIE_OPTIONS,
} from "../../../config/cookies.js";

/**
 * Handle user login.
 */
export async function loginController(req, res, next) {
  try {
    // Validate incoming credentials.
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

    // Authenticate the user and create a server-side session.
    const result = await loginUser(validation.data, {
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    // Generate a short-lived access JWT.
    const accessToken = await signAccessToken({
      userId: result.user.id,
      sessionId: result.session.id,
    });

    // Set the access token in an HTTP-only cookie.
    res.cookie(COOKIE_NAMES.ACCESS_TOKEN, accessToken, ACCESS_COOKIE_OPTIONS);

    // Set the refresh token in a separate HTTP-only cookie.
    res.cookie(
      COOKIE_NAMES.REFRESH_TOKEN,
      result.refreshToken,
      REFRESH_COOKIE_OPTIONS,
    );

    // Never expose either token in the JSON response.
    return res.status(200).json({
      success: true,
      message: "Login successful.",
      data: {
        user: result.user,
        session: {
          id: result.session.id,
          expiresAt: result.session.expiresAt,
        },
      },
    });
  } catch (error) {
    return next(error);
  }
}
