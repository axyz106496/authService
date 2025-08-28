// src/config/env.js
import dotenv from "dotenv";
dotenv.config();

export const {
  PORT,
  NODE_ENV,
  CORS_ORIGIN,
  MONGO_URI,
  REDIS_URL,
  JWT_ACCESS_SECRET,
  JWT_REFRESH_SECRET,
  ADMIN_EMAIL,
  USER_SERVICE_URL,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
} = process.env;
