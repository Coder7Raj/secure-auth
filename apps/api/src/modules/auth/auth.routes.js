import { Router } from "express";
import { requireAuth } from "../../common/middleware/require-auth.js";
import { getCurrentUserController } from "../auth/controllers/get-current-user.controller.js";
import { loginController } from "./controllers/login.controller.js";
import { logoutController } from "./controllers/logout.controller.js";
import { refreshController } from "./controllers/refresh.controller.js";
import { registerController } from "./controllers/register.controller.js";

const authRouter = Router();

authRouter.post("/register", registerController);
authRouter.post("/login", loginController);
authRouter.get("/me", requireAuth, getCurrentUserController);
authRouter.post("/refresh", refreshController);

authRouter.post("/logout", requireAuth, logoutController);

export default authRouter;
