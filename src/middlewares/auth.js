import { verifyToken } from "../utils/jwt.js";
import { JWT_ACCESS_SECRET } from "../config/env.js";

export const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer "))
    return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  const payload = verifyToken(token, JWT_ACCESS_SECRET);
  if (!payload) return res.status(401).json({ message: "Invalid token" });

  req.user = payload;
  next();
};
