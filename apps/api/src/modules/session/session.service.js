import { randomUUID } from "node:crypto";
import { z } from "zod";

import { env } from "../../config/env.js";
import { prisma } from "../../lib/prisma.js";
import {
  generateRefreshToken,
  hashRefreshToken,
} from "../../lib/refresh-token.js";

const sessionInputSchema = z.object({
  userId: z.string().uuid(),

  ipAddress: z.string().max(45).nullable().optional(),

  userAgent: z.string().max(512).nullable().optional(),

  deviceName: z.string().max(150).nullable().optional(),
});

const listActiveSessionsInputSchema = z.object({
  userId: z.string().uuid(),
});

const revokeSessionInputSchema = z.object({
  userId: z.string().uuid(),
  sessionId: z.string().uuid(),
  revokeReason: z
    .enum(["USER_LOGOUT", "ADMIN_ACTION", "SECURITY_EVENT"])
    .default("USER_LOGOUT"),
});

/**
 * List all currently active sessions belonging to a user.
 *
 * Revoked sessions, expired sessions, and sessions belonging
 * to inactive users are excluded.
 *
 * Refresh tokens and token hashes are never returned.
 */
export async function listActiveSessions(input) {
  const validatedInput = listActiveSessionsInputSchema.parse(input);

  const now = new Date();

  const sessions = await prisma.session.findMany({
    where: {
      userId: validatedInput.userId,
      revokedAt: null,
      expiresAt: {
        gt: now,
      },
      user: {
        is: {
          status: "ACTIVE",
        },
      },
    },

    select: {
      id: true,
      ipAddress: true,
      userAgent: true,
      deviceName: true,
      createdAt: true,
      lastSeenAt: true,
      expiresAt: true,
    },

    orderBy: {
      lastSeenAt: "desc",
    },
  });

  return sessions;
}

/**
 * Revoke a specific session belonging to a user.
 *
 * Session revocation and refresh-token revocation
 * are performed atomically.
 *
 * Repeated revocation is idempotent.
 */
export async function revokeSession(input) {
  const validatedInput = revokeSessionInputSchema.parse(input);

  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const session = await tx.session.findFirst({
      where: {
        id: validatedInput.sessionId,
        userId: validatedInput.userId,
      },
      select: {
        id: true,
        revokedAt: true,
      },
    });

    // Do not reveal whether another user's session exists.
    if (!session) {
      return {
        success: false,
      };
    }

    // Preserve the original revocation information.
    if (session.revokedAt) {
      await tx.refreshToken.updateMany({
        where: {
          sessionId: session.id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
        },
      });

      return {
        success: true,
        alreadyRevoked: true,
      };
    }

    const revoked = await tx.session.updateMany({
      where: {
        id: session.id,
        userId: validatedInput.userId,
        revokedAt: null,
      },
      data: {
        revokedAt: now,
        revokeReason: validatedInput.revokeReason,
      },
    });

    // Another request may have revoked the session first.
    if (revoked.count !== 1) {
      return {
        success: true,
        alreadyRevoked: true,
      };
    }

    await tx.refreshToken.updateMany({
      where: {
        sessionId: session.id,
        revokedAt: null,
      },
      data: {
        revokedAt: now,
      },
    });

    return {
      success: true,
      alreadyRevoked: false,
    };
  });
}

/**
 * Calculate the absolute session expiration.
 */
function calculateSessionExpiration(now) {
  const expiresAt = new Date(now);

  expiresAt.setUTCDate(expiresAt.getUTCDate() + env.SESSION_MAX_AGE_DAYS);

  return expiresAt;
}

/**
 * Create a new authenticated session and its initial refresh token.
 *
 * The session and refresh-token records are created atomically.
 */
export async function createSession(input) {
  const validatedInput = sessionInputSchema.parse(input);

  const now = new Date();
  const sessionId = randomUUID();
  const familyId = randomUUID();

  const expiresAt = calculateSessionExpiration(now);

  const { token, tokenHash } = generateRefreshToken();

  const session = await prisma.$transaction(async (tx) => {
    const createdSession = await tx.session.create({
      data: {
        id: sessionId,
        userId: validatedInput.userId,

        ipAddress: validatedInput.ipAddress ?? null,
        userAgent: validatedInput.userAgent ?? null,
        deviceName: validatedInput.deviceName ?? null,

        createdAt: now,
        lastSeenAt: now,
        expiresAt,
      },
      select: {
        id: true,
        userId: true,
        ipAddress: true,
        userAgent: true,
        deviceName: true,
        createdAt: true,
        lastSeenAt: true,
        expiresAt: true,
        revokedAt: true,
      },
    });

    await tx.refreshToken.create({
      data: {
        sessionId: createdSession.id,
        tokenHash,
        familyId,
        createdAt: now,
        expiresAt,
      },
    });

    return createdSession;
  });

  return {
    session,
    refreshToken: token,
  };
}

/**
 * Rotate an existing refresh token.
 *
 * A consumed token triggers session-wide revocation.
 * A successful rotation preserves the original session
 * expiration and refresh-token family.
 */
export async function rotateRefreshToken({ token }) {
  const tokenHash = hashRefreshToken(token);
  const now = new Date();

  // Find the presented token and its associated records.
  const storedToken = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    include: {
      session: {
        include: {
          user: {
            select: {
              id: true,
              status: true,
            },
          },
        },
      },
    },
  });

  if (!storedToken) {
    throw new Error("Invalid refresh token");
  }

  const session = storedToken.session;

  // Reuse detection: a previously consumed token
  // indicates possible refresh-token compromise.
  if (storedToken.consumedAt) {
    await prisma.$transaction(async (tx) => {
      await tx.session.updateMany({
        where: {
          id: session.id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
          revokeReason: "REFRESH_TOKEN_REUSE",
        },
      });

      await tx.refreshToken.updateMany({
        where: {
          sessionId: session.id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
        },
      });
    });

    throw new Error("Refresh token reuse detected");
  }

  // Reject invalid or inactive sessions.
  if (
    storedToken.revokedAt ||
    storedToken.expiresAt <= now ||
    session.revokedAt ||
    session.expiresAt <= now ||
    session.user.status !== "ACTIVE"
  ) {
    throw new Error("Invalid refresh token");
  }

  // Generate the replacement token before the transaction.
  const replacement = generateRefreshToken();

  const result = await prisma.$transaction(async (tx) => {
    // Atomically consume the existing refresh token.
    const consumed = await tx.refreshToken.updateMany({
      where: {
        id: storedToken.id,
        consumedAt: null,
        revokedAt: null,
        expiresAt: {
          gt: now,
        },
      },
      data: {
        consumedAt: now,
      },
    });

    if (consumed.count !== 1) {
      const currentToken = await tx.refreshToken.findUnique({
        where: {
          id: storedToken.id,
        },
      });

      if (currentToken?.consumedAt) {
        await tx.session.updateMany({
          where: {
            id: session.id,
            revokedAt: null,
          },
          data: {
            revokedAt: now,
            revokeReason: "REFRESH_TOKEN_REUSE",
          },
        });

        await tx.refreshToken.updateMany({
          where: {
            sessionId: session.id,
            revokedAt: null,
          },
          data: {
            revokedAt: now,
          },
        });

        return { status: "reuse" };
      }

      return { status: "invalid" };
    }

    // Confirm that the session is still active.
    const sessionUpdate = await tx.session.updateMany({
      where: {
        id: session.id,
        revokedAt: null,
        expiresAt: {
          gt: now,
        },
      },
      data: {
        lastSeenAt: now,
      },
    });

    if (sessionUpdate.count !== 1) {
      // Throwing rolls back the token consumption too.
      throw new Error("SESSION_NO_LONGER_ACTIVE");
    }

    // Create the replacement using the original
    // session expiration and token family.
    await tx.refreshToken.create({
      data: {
        sessionId: session.id,
        tokenHash: replacement.tokenHash,
        familyId: storedToken.familyId,
        createdAt: now,
        expiresAt: session.expiresAt,
      },
    });

    return { status: "rotated" };
  });

  if (result.status === "reuse") {
    throw new Error("Refresh token reuse detected");
  }

  if (result.status !== "rotated") {
    throw new Error("Invalid refresh token");
  }

  return {
    refreshToken: replacement.token,
    session: {
      id: session.id,
      userId: session.userId,
      expiresAt: session.expiresAt,
    },
  };
}
