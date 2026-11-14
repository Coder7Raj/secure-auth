import app from "./app.js";
import { env } from "./config/env.js";
import { prisma } from "./lib/prisma.js";

await prisma.$connect();

const server = app.listen(env.PORT, () => {
  console.log(`SecureAuth API running on port ${env.PORT} (${env.NODE_ENV})`);
});

function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);

  server.close(async (error) => {
    try {
      await prisma.$disconnect();

      if (error) {
        console.error("HTTP server shutdown failed:", error);
        process.exitCode = 1;
        return;
      }

      console.log("Database disconnected.");
      process.exitCode = 0;
    } catch (disconnectError) {
      console.error("Database shutdown failed:", disconnectError);
      process.exitCode = 1;
    }
  });
}

process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));
