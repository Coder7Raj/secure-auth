import { registerSchema } from "../schemas/register.schema.js";
import { registerUser } from "../services/register.service.js";

export async function registerController(req, res, next) {
  const validation = registerSchema.safeParse(req.body);

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
    const user = await registerUser(validation.data);

    return res.status(201).json({
      success: true,
      message: "Registration successful. Please verify your email.",
      data: { user },
    });
  } catch (error) {
    return next(error);
  }
}
