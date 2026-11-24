import {
  consumeLoginAttempt,
  resetAccountThrottle,
  resetIpThrottle,
} from "../modules/auth/services/login-throttle.service.js";

import { prisma } from "../lib/prisma.js";

const accountEmail = "concurrency.test@example.com";
const accountIps = Array.from({ length: 10 }, (_, i) => `198.51.100.${i + 1}`);

const sharedIp = "192.0.2.150";

try {
  console.log("Testing concurrent account throttling...\n");

  await resetAccountThrottle(accountEmail);

  await Promise.all(accountIps.map((ipAddress) => resetIpThrottle(ipAddress)));

  const accountResults = await Promise.all(
    accountIps.map((ipAddress) =>
      consumeLoginAttempt({
        email: accountEmail,
        ipAddress,
      }),
    ),
  );

  const accountAllowed = accountResults.filter(
    (result) => result.allowed,
  ).length;

  console.log({
    totalRequests: accountResults.length,
    allowed: accountAllowed,
    blocked: accountResults.length - accountAllowed,
  });

  if (accountAllowed !== 5) {
    throw new Error("Concurrent account throttle test FAILED.");
  }

  console.log("\nTesting concurrent IP throttling...\n");

  await resetIpThrottle(sharedIp);

  const ipResults = await Promise.all(
    Array.from({ length: 25 }, (_, i) =>
      consumeLoginAttempt({
        email: `concurrent-${i}@example.com`,
        ipAddress: sharedIp,
      }),
    ),
  );

  const ipAllowed = ipResults.filter((result) => result.allowed).length;

  console.log({
    totalRequests: ipResults.length,
    allowed: ipAllowed,
    blocked: ipResults.length - ipAllowed,
  });

  if (ipAllowed !== 20) {
    throw new Error("Concurrent IP throttle test FAILED.");
  }

  console.log("\nALL CONCURRENCY TESTS PASSED!");
} catch (error) {
  console.error("Concurrency test failed:", error);
  process.exitCode = 1;
} finally {
  await resetAccountThrottle(accountEmail);

  await Promise.all(accountIps.map((ipAddress) => resetIpThrottle(ipAddress)));

  await resetIpThrottle(sharedIp);

  await prisma.$disconnect();
}
