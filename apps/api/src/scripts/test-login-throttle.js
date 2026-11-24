import {
  consumeLoginAttempt,
  resetIpThrottle,
} from "../modules/auth/services/login-throttle.service.js";

import { prisma } from "../lib/prisma.js";

const ipAddress = "192.0.2.102";

try {
  await resetIpThrottle(ipAddress);

  console.log("Testing IP limit: 20 requests\n");

  for (let i = 1; i <= 21; i++) {
    const email = `ip-test-${i}@example.com`;

    const result = await consumeLoginAttempt({
      email,
      ipAddress,
    });

    console.log({
      request: i,
      allowed: result.allowed,
    });

    if (i <= 20 && !result.allowed) {
      throw new Error(`Request ${i} was unexpectedly blocked.`);
    }

    if (i === 21 && result.allowed) {
      throw new Error("21st request should have been blocked.");
    }
  }

  console.log("\nIP throttle limit test PASSED.");
} catch (error) {
  console.error("IP test failed:", error);
  process.exitCode = 1;
} finally {
  await resetIpThrottle(ipAddress);
  await prisma.$disconnect();
}
