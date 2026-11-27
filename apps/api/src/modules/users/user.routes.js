import { Router } from "express";

import { requireAuth } from "../../common/middleware/require-auth.js";
import { requirePermission } from "../../common/middleware/require-permission.js";

const router = Router();

router.get(
  "/me",
  requireAuth,
  requirePermission("profile:read:self"),
  (req, res) => {
    res.status(200).json({
      success: true,
      data: {
        userId: req.auth.userId,
      },
    });
  },
);

export default router;
