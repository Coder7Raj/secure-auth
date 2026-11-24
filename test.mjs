import { prisma } from "./apps/api/src/lib/prisma.js";

const attempt = await prisma.loginAttempt.findFirst({
  where: { email: "raj.test01@example.com" },
  orderBy: { attemptedAt: "desc" },
  select: {
    ipAddress: true,
    userAgent: true,
    success: true,
    failureReason: true,
  },
});

console.log(attempt);

await prisma.$disconnect();
