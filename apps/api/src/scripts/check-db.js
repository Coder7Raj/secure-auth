import { prisma } from "../lib/prisma.js";

try {
  await prisma.$connect();

  const result = await prisma.$queryRaw`SELECT NOW() AS current_time`;

  console.log("Database connection successful!");
  console.log("Database time:", result[0].current_time);
} catch (error) {
  console.error("Database connection failed:", error);
  process.exitCode = 1;
} finally {
  await prisma.$disconnect();
}
