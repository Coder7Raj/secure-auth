import app from "./app.js";
import { env } from "./config/env.js";
import { prisma } from "./lib/prisma.js";

await prisma.$connect();

const server = app.listen(env.PORT);

server.on("listening", () => {
  console.log(`SecureAuth API running on port ${env.PORT} (${env.NODE_ENV})`);
});

// Handle startup/listening errors.
server.once("error", async (error) => {
  console.error("HTTP server startup failed:", error);

  try {
    await prisma.$disconnect();
  } catch (disconnectError) {
    console.error("Database shutdown failed:", disconnectError);
  }

  process.exitCode = 1;
});

let isShuttingDown = false;

function shutdown(signal) {
  if (isShuttingDown) {
    return;
  }

  isShuttingDown = true;

  console.log(`${signal} received. Shutting down...`);

  const shutdownTimer = setTimeout(() => {
    console.error("Graceful shutdown timed out. Forcing exit.");
    process.exit(1);
  }, 10_000);

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
    } finally {
      clearTimeout(shutdownTimer);
    }
  });
}

process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));
