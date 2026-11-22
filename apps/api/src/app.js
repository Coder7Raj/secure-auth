import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import helmet from "helmet";
import pinoHttp from "pino-http";

import { env } from "./config/env.js";
import apiRoutes from "./routes/index.js";

import {
  errorHandler,
  notFoundHandler,
} from "./common/middleware/error-handler.js";

const app = express();

app.disable("x-powered-by");

// Request logger — deliberately excludes sensitive request data.
app.use(
  pinoHttp({
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
        };
      },

      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);

app.use(
  helmet({
    hsts:
      env.NODE_ENV === "production"
        ? {
            maxAge: 31536000, // 1 year
            includeSubDomains: false,
          }
        : false,
  }),
);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, false);
      }

      if (origin === env.CLIENT_URL) {
        return callback(null, true);
      }

      return callback(null, false);
    },
    credentials: true,
  }),
);

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

app.use(cookieParser());

app.use("/api/v1", apiRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;
