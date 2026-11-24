import { prisma } from "../lib/prisma.js";

import {
  consumeLoginAttempt,
  resetAccountThrottle,
  resetIpThrottle,
} from "../modules/auth/services/login-throttle.service.js";

const email = "expiry.test@example.com";
const ipAddress = "192.0.2.160";

const accountKey = `account:${(await import("node:crypto"))
  .createHash("sha256")
  .update(email)
  .digest("hex")}`;

const ipKey = `ip:${(await import("node:crypto"))
  .createHash("sha256")
  .update(ipAddress)
  .digest("hex")}`;

try {
  await resetAccountThrottle(email);
  await resetIpThrottle(ipAddress);

  console.log("Test 1: Create initial counters");

  for (let i = 0; i < 3; i++) {
    await consumeLoginAttempt({ email, ipAddress });
  }

  let records = await prisma.loginThrottle.findMany({
    where: {
      key: { in: [accountKey, ipKey] },
    },
  });

  console.table(
    records.map(({ key, attempts }) => ({
      type: key.split(":")[0],
      attempts,
    })),
  );

  if (records.some((record) => record.attempts !== 3)) {
    throw new Error("Initial counter creation failed.");
  }

  console.log("\nTest 2: Expire both counters");

  await prisma.loginThrottle.updateMany({
    where: {
      key: { in: [accountKey, ipKey] },
    },
    data: {
      expiresAt: new Date(Date.now() - 1000),
    },
  });

  console.log("Counters manually expired.");

  console.log("\nTest 3: Consume after expiration");

  const result = await consumeLoginAttempt({
    email,
    ipAddress,
  });

  console.log(result);

  records = await prisma.loginThrottle.findMany({
    where: {
      key: { in: [accountKey, ipKey] },
    },
  });

  console.table(
    records.map(({ key, attempts, expiresAt }) => ({
      type: key.split(":")[0],
      attempts,
      expiresAt,
    })),
  );

  if (records.some((record) => record.attempts !== 1)) {
    throw new Error("Expired counters did not reset correctly.");
  }

  console.log("\nCOUNTER EXPIRY TEST PASSED!");
} catch (error) {
  console.error("Expiry test failed:", error);
  process.exitCode = 1;
} finally {
  await resetAccountThrottle(email);
  await resetIpThrottle(ipAddress);
  await prisma.$disconnect();
}
