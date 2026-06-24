import jwt from "jsonwebtoken";

export type TokenPayload = { user: string; userSecret: string };

export function generateToken(
  username: string,
  userSecret: string,
  jwtSecret: string,
) {
  return jwt.sign({ user: username, userSecret } as TokenPayload, jwtSecret, {
    expiresIn: "7d",
  });
}
