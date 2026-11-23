import argon2 from "argon2";

const dummyHash = await argon2.hash(
  "SecureAuth-Dummy-Password-Never-Used-For-Login",
  {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
    hashLength: 32,
  },
);

console.log("DUMMY_ARGON2_HASH:");
console.log(dummyHash);
