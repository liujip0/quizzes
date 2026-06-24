import jwt from "jsonwebtoken";

export function generateToken(
  username: string,
  userSecret: string,
  jwtSecret: string,
) {
  return jwt.sign({ user: username, userSecret }, jwtSecret, {
    expiresIn: "7d",
  });
}
