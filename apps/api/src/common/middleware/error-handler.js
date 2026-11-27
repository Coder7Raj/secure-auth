export function notFoundHandler(req, res, _next) {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
}

export function errorHandler(err, req, res, _next) {
  // Delegate if response headers have already been sent
  if (res.headersSent) {
    return _next(err);
  }

  const rawStatusCode = err.statusCode ?? err.status;

  const statusCode =
    Number.isInteger(rawStatusCode) &&
    rawStatusCode >= 400 &&
    rawStatusCode <= 599
      ? rawStatusCode
      : 500;

  if (
    statusCode === 429 &&
    Number.isInteger(err.retryAfterSeconds) &&
    err.retryAfterSeconds > 0
  ) {
    res.set("Retry-After", String(err.retryAfterSeconds));
  }

  if (statusCode >= 500) {
    req.log?.error({ err }, "Internal server error");
  }

  res.status(statusCode).json({
    success: false,
    message:
      statusCode >= 500
        ? "Internal server error"
        : err.message || "Something went wrong",
  });
}
