import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { connectDB } from "./config/db.js";
import "./config/redis.js"; // connect redis
import authRoutes from "./routes/auth.routes.js";
import { PORT, CORS_ORIGIN } from "./config/env.js";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));

app.use("/api/auth", authRoutes);

await connectDB();

app.listen(PORT, () => console.log(`🚀 Auth service running on port ${PORT}`));
