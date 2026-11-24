import { createHash, randomUUID } from "node:crypto";

import { prisma } from "../../../lib/prisma.js";

const WINDOW_SECONDS = 15 * 60;

const LIMITS = {
  account: 5,
  ip: 20,
};

function hashKey(value) {
  return createHash("sha256").update(value).digest("hex");
}

function createThrottleKey(type, value) {
  return `${type}:${hashKey(value)}`;
}

async function incrementCounter(tx, key) {
  const id = randomUUID();

  const rows = await tx.$queryRaw`
    INSERT INTO login_throttles (
      id,
      "key",
      attempts,
      "expiresAt",
      "createdAt",
      "updatedAt"
    )
    VALUES (
      ${id}::uuid,
      ${key},
      1,
      NOW() + (${WINDOW_SECONDS} * INTERVAL '1 second'),
      NOW(),
      NOW()
    )
    ON CONFLICT ("key")
    DO UPDATE SET
      attempts = CASE
        WHEN login_throttles."expiresAt" <= NOW() THEN 1
        ELSE login_throttles.attempts + 1
      END,
      "expiresAt" = CASE
        WHEN login_throttles."expiresAt" <= NOW()
        THEN EXCLUDED."expiresAt"
        ELSE login_throttles."expiresAt"
      END,
      "updatedAt" = NOW()
    RETURNING attempts, "expiresAt"
  `;

  return rows[0];
}

export async function consumeLoginAttempt({ email, ipAddress }) {
  if (!email || !ipAddress) {
    throw new Error("Email and IP address are required for throttling.");
  }

  const accountKey = createThrottleKey("account", email.trim().toLowerCase());

  const ipKey = createThrottleKey("ip", ipAddress);

  return prisma.$transaction(async (tx) => {
    const account = await incrementCounter(tx, accountKey);
    const ip = await incrementCounter(tx, ipKey);

    return {
      allowed: account.attempts <= LIMITS.account && ip.attempts <= LIMITS.ip,

      retryAt: new Date(
        Math.max(account.expiresAt.getTime(), ip.expiresAt.getTime()),
      ),
    };
  });
}

export async function resetAccountThrottle(email) {
  const accountKey = createThrottleKey("account", email.trim().toLowerCase());

  await prisma.loginThrottle.deleteMany({
    where: { key: accountKey },
  });
}
