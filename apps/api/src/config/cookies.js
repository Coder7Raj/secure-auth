import { env } from "./env.js";

export const COOKIE_NAMES = Object.freeze({
  ACCESS_TOKEN: "accessToken",
  REFRESH_TOKEN: "refreshToken",
});

const secure = env.NODE_ENV === "production";

const sameSite = env.COOKIE_SAME_SITE;

const domain = env.COOKIE_DOMAIN || undefined;

/**
 * Convert supported JWT-style durations into milliseconds.
 */
function durationToMilliseconds(duration) {
  const match = /^([1-9]\d*)([smhd])$/.exec(duration);

  if (!match) {
    throw new TypeError("Invalid cookie duration");
  }

  const value = Number(match[1]);

  const multipliers = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return value * multipliers[match[2]];
}

const baseCookieOptions = Object.freeze({
  httpOnly: true,
  secure,
  sameSite,
  ...(domain ? { domain } : {}),
});

export const ACCESS_COOKIE_OPTIONS = Object.freeze({
  ...baseCookieOptions,
  path: "/api/v1",
  maxAge: durationToMilliseconds(env.JWT_ACCESS_EXPIRES_IN),
});

export const REFRESH_COOKIE_OPTIONS = Object.freeze({
  ...baseCookieOptions,
  path: "/api/v1/auth",
  maxAge: env.SESSION_MAX_AGE_DAYS * 24 * 60 * 60 * 1000,
});

/**
 * Cookie-clearing options must match the original
 * cookie's path and domain.
 */
export const ACCESS_COOKIE_CLEAR_OPTIONS = Object.freeze({
  ...baseCookieOptions,
  path: ACCESS_COOKIE_OPTIONS.path,
});

export const REFRESH_COOKIE_CLEAR_OPTIONS = Object.freeze({
  ...baseCookieOptions,
  path: REFRESH_COOKIE_OPTIONS.path,
});
