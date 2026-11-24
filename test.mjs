import { prisma } from "./apps/api/src/lib/prisma.js";

const records = await prisma.loginThrottle.findMany({
  select: {
    key: true,
    attempts: true,
    expiresAt: true,
  },
});

console.table(
  records.map((record) => ({
    keyPrefix: record.key.split(":")[0],
    attempts: record.attempts,
    expiresAt: record.expiresAt,
  })),
);

await prisma.$disconnect();
