-- CreateTable
CREATE TABLE "login_throttles" (
    "id" UUID NOT NULL,
    "key" VARCHAR(300) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "login_throttles_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "login_throttles_key_key" ON "login_throttles"("key");

-- CreateIndex
CREATE INDEX "login_throttles_expiresAt_idx" ON "login_throttles"("expiresAt");
