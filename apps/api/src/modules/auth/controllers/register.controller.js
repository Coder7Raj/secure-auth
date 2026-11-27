import { registerSchema } from "../schemas/register.schema.js";
import { registerUser } from "../services/register.service.js";

/**
 * Handle user registration.
 *
 * Responsibilities:
 * 1. Validate incoming request data.
 * 2. Pass sanitized data to the registration service.
 * 3. Return a safe HTTP response.
 * 4. Forward unexpected errors to Express error handling.
 */
export async function registerController(req, res, next) {
  try {
    // Validate and sanitize incoming data.
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

    // Execute registration business logic.
    const user = await registerUser(validation.data);

    // Return the safe user representation.
    return res.status(201).json({
      success: true,
      message: "Registration successful. Please verify your email.",
      data: {
        user,
      },
    });
  } catch (error) {
    return next(error);
  }
}
