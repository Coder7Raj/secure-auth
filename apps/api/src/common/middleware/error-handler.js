export function errorHandler(err, req, res, _next) {
  const statusCode = err.statusCode || 500;

  if (statusCode >= 500) {
    req.log?.error({ err }, "Internal server error");
  }

  if (statusCode === 429 && err.retryAfterSeconds) {
    res.setHeader("Retry-After", String(err.retryAfterSeconds));
  }

  res.status(statusCode).json({
    success: false,
    message:
      statusCode >= 500
        ? "Internal server error"
        : err.message || "Something went wrong",
  });
}
