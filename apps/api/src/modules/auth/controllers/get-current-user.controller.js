import { getCurrentUser } from "../services/get-current-user.service.js";

export async function getCurrentUserController(req, res, next) {
  try {
    const user = await getCurrentUser(req.auth.userId);

    return res.status(200).json({
      success: true,
      data: {
        user,
      },
    });
  } catch (error) {
    return next(error);
  }
}
