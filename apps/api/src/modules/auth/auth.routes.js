import { Router } from "express";

import { requireAuth } from "../../common/middleware/require-auth.js";
import { getCurrentUserController } from "../auth/controllers/get-current-user.controller.js";

import { loginController } from "./controllers/login.controller.js";
import { logoutController } from "./controllers/logout.controller.js";
import { refreshController } from "./controllers/refresh.controller.js";
import { registerController } from "./controllers/register.controller.js";

import {
  listSessionsController,
  revokeOtherSessionsController,
  revokeSessionController,
} from "../session/session.controller.js";

const authRouter = Router();

authRouter.post("/register", registerController);
authRouter.post("/login", loginController);
authRouter.post("/refresh", refreshController);

authRouter.get("/me", requireAuth, getCurrentUserController);
authRouter.post("/logout", requireAuth, logoutController);

// Session management
authRouter.get("/sessions", requireAuth, listSessionsController);

// IMPORTANT: Register this before /sessions/:sessionId.
authRouter.delete(
  "/sessions/others",
  requireAuth,
  revokeOtherSessionsController,
);

authRouter.delete("/sessions/:sessionId", requireAuth, revokeSessionController);

export default authRouter;
