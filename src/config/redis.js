// redis.js
import { createClient } from "redis";
import { REDIS_URL } from "./env.js";

export const redis = createClient({ url: REDIS_URL });
redis.on("error", (err) => console.error("Redis Error:", err));

await redis.connect();
console.log("✅ Redis connected");
