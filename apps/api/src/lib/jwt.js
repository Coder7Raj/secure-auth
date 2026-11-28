import { SignJWT, jwtVerify } from "jose";
import { randomUUID } from "node:crypto";
import { env } from "../config/env.js";

const JWT_ALGORITHM = "HS256";
const ACCESS_TOKEN_TYPE = "access";

// PostgreSQL UUID format: 8-4-4-4-12 hexadecimal characters.
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const accessSecret = new TextEncoder().encode(env.JWT_ACCESS_SECRET);

function validateIdentity({ userId, sessionId }) {
  if (typeof userId !== "string" || !UUID_REGEX.test(userId)) {
    throw new TypeError("A valid userId UUID is required");
  }

  if (typeof sessionId !== "string" || !UUID_REGEX.test(sessionId)) {
    throw new TypeError("A valid sessionId UUID is required");
  }
}

export async function signAccessToken({ userId, sessionId }) {
  validateIdentity({ userId, sessionId });

  return new SignJWT({
    sid: sessionId,
    tokenType: ACCESS_TOKEN_TYPE,
  })
    .setProtectedHeader({ alg: JWT_ALGORITHM, typ: "JWT" })
    .setSubject(userId)
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(env.JWT_ACCESS_EXPIRES_IN)
    .sign(accessSecret);
}

export async function verifyAccessToken(token) {
  if (typeof token !== "string" || !token.trim()) {
    throw new TypeError("A valid JWT is required");
  }

  const { payload } = await jwtVerify(token, accessSecret, {
    algorithms: [JWT_ALGORITHM],
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  });

  if (
    typeof payload.sub !== "string" ||
    !UUID_REGEX.test(payload.sub) ||
    typeof payload.sid !== "string" ||
    !UUID_REGEX.test(payload.sid) ||
    typeof payload.jti !== "string" ||
    !payload.jti ||
    typeof payload.iat !== "number" ||
    typeof payload.exp !== "number" ||
    payload.tokenType !== ACCESS_TOKEN_TYPE
  ) {
    throw new Error("Invalid JWT claims");
  }

  return payload;
}
