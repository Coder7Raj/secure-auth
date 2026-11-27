import { COOKIE_NAMES } from "../../config/cookies.js";
import { verifyAccessToken } from "../../lib/jwt.js";
import { prisma } from "../../lib/prisma.js";
import { AppError } from "../errors/app-error.js";

export async function requireAuth(req, res, next) {
  try {
    const accessToken = req.cookies?.[COOKIE_NAMES.ACCESS_TOKEN];

    if (!accessToken) {
      throw new AppError("Authentication required", 401);
    }

    let payload;

    // Only JWT verification errors are converted into authentication errors.
    try {
      payload = await verifyAccessToken(accessToken);
    } catch {
      throw new AppError("Invalid or expired access token", 401);
    }

    const session = await prisma.session.findUnique({
      where: {
        id: payload.sid,
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

    if (
      !session ||
      session.userId !== payload.sub ||
      session.revokedAt ||
      session.expiresAt <= new Date() ||
      session.user.status !== "ACTIVE"
    ) {
      throw new AppError("Invalid or expired session", 401);
    }

    req.auth = Object.freeze({
      userId: session.userId,
      sessionId: session.id,
    });

    return next();
  } catch (error) {
    return next(error);
  }
}
