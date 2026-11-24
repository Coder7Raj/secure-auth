export function notFoundHandler(req, res, _next) {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
}

export function errorHandler(err, req, res, _next) {
  const statusCode = err.statusCode || 500;

  if (statusCode === 429 && err.retryAfterSeconds) {
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
