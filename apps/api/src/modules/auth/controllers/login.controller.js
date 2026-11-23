import { loginSchema } from "../schemas/login.schema.js";
import { loginUser } from "../services/login.service.js";

export async function loginController(req, res, next) {
  const validation = loginSchema.safeParse(req.body);

  if (!validation.success) {
    return res.status(400).json({
      success: false,
      message: "Validation failed.",
      errors: validation.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  try {
    const user = await loginUser(validation.data);

    return res.status(200).json({
      success: true,
      message: "Login successful.",
      data: { user },
    });
  } catch (error) {
    return next(error);
  }
}
