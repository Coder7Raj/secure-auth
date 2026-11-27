import { prisma } from "../src/lib/prisma.js";
import { seedSystemRbac } from "../src/modules/rbac/rbac-seed.service.js";

try {
  const result = await seedSystemRbac(prisma);

  console.log("RBAC seed completed successfully.");
  console.log(result);
} catch (error) {
  console.error("RBAC seed failed:", error);
  process.exitCode = 1;
} finally {
  await prisma.$disconnect();
}
