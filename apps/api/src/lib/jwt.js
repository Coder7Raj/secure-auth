// import { SignJWT, jwtVerify } from "jose";
// import { randomUUID } from "node:crypto";

// import { env } from "../config/env.js";

// const JWT_ALGORITHM = "HS256";

// const ACCESS_TOKEN_TYPE = "access";
// const REFRESH_TOKEN_TYPE = "refresh";

// const accessSecret = new TextEncoder().encode(env.JWT_ACCESS_SECRET);
// const refreshSecret = new TextEncoder().encode(env.JWT_REFRESH_SECRET);

// /**
//  * Validate the identity data required to issue a token.
//  */
// function validateIdentity({ userId, sessionId }) {
//   if (typeof userId !== "string" || !userId.trim()) {
//     throw new TypeError("A valid userId is required");
//   }

//   if (typeof sessionId !== "string" || !sessionId.trim()) {
//     throw new TypeError("A valid sessionId is required");
//   }
// }

// /**
//  * Create a signed JWT.
//  */
// async function createToken({
//   userId,
//   sessionId,
//   tokenType,
//   secret,
//   expiresIn,
// }) {
//   validateIdentity({ userId, sessionId });

//   return new SignJWT({
//     sid: sessionId,
//     tokenType,
//   })
//     .setProtectedHeader({
//       alg: JWT_ALGORITHM,
//       typ: "JWT",
//     })
//     .setSubject(userId)
//     .setIssuer(env.JWT_ISSUER)
//     .setAudience(env.JWT_AUDIENCE)
//     .setIssuedAt()
//     .setJti(randomUUID())
//     .setExpirationTime(expiresIn)
//     .sign(secret);
// }

// /**
//  * Verify a JWT and enforce its expected token type.
//  */
// async function verifyToken(token, expectedType, secret) {
//   if (typeof token !== "string" || !token.trim()) {
//     throw new TypeError("A valid JWT is required");
//   }

//   const { payload } = await jwtVerify(token, secret, {
//     algorithms: [JWT_ALGORITHM],
//     issuer: env.JWT_ISSUER,
//     audience: env.JWT_AUDIENCE,
//   });

//   if (
//     typeof payload.sub !== "string" ||
//     !payload.sub ||
//     typeof payload.sid !== "string" ||
//     !payload.sid ||
//     typeof payload.jti !== "string" ||
//     !payload.jti ||
//     typeof payload.iat !== "number" ||
//     typeof payload.exp !== "number" ||
//     payload.tokenType !== expectedType
//   ) {
//     throw new Error("Invalid JWT claims");
//   }

//   return payload;
// }

// /**
//  * Generate an access token.
//  */
// export function signAccessToken({ userId, sessionId }) {
//   return createToken({
//     userId,
//     sessionId,
//     tokenType: ACCESS_TOKEN_TYPE,
//     secret: accessSecret,
//     expiresIn: env.JWT_ACCESS_EXPIRES_IN,
//   });
// }

// /**
//  * Generate a refresh token.
//  */
// export function signRefreshToken({ userId, sessionId }) {
//   return createToken({
//     userId,
//     sessionId,
//     tokenType: REFRESH_TOKEN_TYPE,
//     secret: refreshSecret,
//     expiresIn: env.JWT_REFRESH_EXPIRES_IN,
//   });
// }

// /**
//  * Verify an access token.
//  */
// export function verifyAccessToken(token) {
//   return verifyToken(token, ACCESS_TOKEN_TYPE, accessSecret);
// }

// /**
//  * Verify a refresh token.
//  */
// export function verifyRefreshToken(token) {
//   return verifyToken(token, REFRESH_TOKEN_TYPE, refreshSecret);
// }

import { SignJWT, jwtVerify } from "jose";
import { randomUUID } from "node:crypto";

import { env } from "../config/env.js";

const JWT_ALGORITHM = "HS256";
const ACCESS_TOKEN_TYPE = "access";

const accessSecret = new TextEncoder().encode(env.JWT_ACCESS_SECRET);

/**
 * Validate the identity data required to issue an access token.
 */
function validateIdentity({ userId, sessionId }) {
  if (typeof userId !== "string" || !userId.trim()) {
    throw new TypeError("A valid userId is required");
  }

  if (typeof sessionId !== "string" || !sessionId.trim()) {
    throw new TypeError("A valid sessionId is required");
  }
}

/**
 * Generate a signed access JWT.
 */
export async function signAccessToken({ userId, sessionId }) {
  validateIdentity({ userId, sessionId });

  return new SignJWT({
    sid: sessionId,
    tokenType: ACCESS_TOKEN_TYPE,
  })
    .setProtectedHeader({
      alg: JWT_ALGORITHM,
      typ: "JWT",
    })
    .setSubject(userId)
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(env.JWT_ACCESS_EXPIRES_IN)
    .sign(accessSecret);
}

/**
 * Verify an access JWT.
 */
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
    !payload.sub ||
    typeof payload.sid !== "string" ||
    !payload.sid ||
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
