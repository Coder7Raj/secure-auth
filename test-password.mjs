import {
  hashPassword,
  verifyPassword,
} from "./apps/api/src/modules/auth/services/password.service.js";

const password = "StrongPassword123!";

const hash1 = await hashPassword(password);
const hash2 = await hashPassword(password);

console.log("Hash generated:", hash1.startsWith("$argon2id$"));
console.log("Unique salts produce different hashes:", hash1 !== hash2);
console.log("Correct password:", await verifyPassword(password, hash1));
console.log("Incorrect password:", await verifyPassword("WrongPassword123!", hash1));
console.log("Second hash verifies:", await verifyPassword(password, hash2));
