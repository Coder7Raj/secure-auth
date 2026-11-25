import { randomUUID } from "node:crypto";
import { z } from "zod";

import { env } from "../../config/env.js";
import { prisma } from "../../lib/prisma.js";
import { generateRefreshToken } from "../../lib/refresh-token.js";

const sessionInputSchema = z.object({
  userId: z.string().uuid(),

  ipAddress: z.string().max(45).nullable().optional(),

  userAgent: z.string().max(512).nullable().optional(),

  deviceName: z.string().max(150).nullable().optional(),
});

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
