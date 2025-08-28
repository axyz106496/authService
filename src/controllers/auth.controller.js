import User from "../models/User.js";
import { hashPassword, verifyPassword } from "../utils/password.js";
import {
  createAccessToken,
  createRefreshToken,
  verifyToken,
} from "../utils/jwt.js";
import { redis } from "../config/redis.js";
import { sendEmail } from "../utils/mailer.js";
import { ADMIN_EMAIL, USER_SERVICE_URL } from "../config/env.js";
import crypto from "crypto";
import axios from "axios";

// ✅ Register
export const register = async (req, res) => {
  try {
    const { email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "User already exists" });

    // Admin auto-assign
    const isAdmin =
      !(await User.findOne({ is_admin: true })) || email === ADMIN_EMAIL;

    const user = await User.create({
      email,
      password: await hashPassword(password),
      is_admin: isAdmin,
    });

    // 🔹 Call User Service to create empty profile
    try {
      await axios.post(`${USER_SERVICE_URL}/init-profile`, {
        userId: user._id,
      });
    } catch (err) {
      console.error(
        "❌ Failed to create profile in User Service:",
        err.message,
      );
    }

    // OTP -> Redis (5 mins)
    const otp = crypto.randomInt(100000, 999999).toString();
    await redis.setEx(`otp:${user._id}`, 300, otp);

    await sendEmail(email, "Verify OTP", `Your OTP is: ${otp}`);

    return res.status(201).json({
      message: "User registered, OTP sent to email",
      id: user._id,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
};

// ✅ Verify OTP
export const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });

  if (user.is_verified) return res.json({ message: "Already verified" });

  const storedOtp = await redis.get(`otp:${user._id}`);
  if (!storedOtp || storedOtp !== otp)
    return res.status(400).json({ message: "Invalid or expired OTP" });

  user.is_verified = true;
  await user.save();

  await redis.del(`otp:${user._id}`);
  await sendEmail(
    email,
    "Account Verified",
    "Your account has been verified successfully",
  );

  return res.json({ message: "Account verified successfully" });
};

// ✅ Resend OTP
export const resendOtp = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });
  if (user.is_verified) return res.json({ message: "Already verified" });

  const otp = crypto.randomInt(100000, 999999).toString();
  await redis.setEx(`otp:${user._id}`, 300, otp);

  await sendEmail(email, "Resend OTP", `Your OTP is: ${otp}`);
  return res.json({ message: "OTP resent to email" });
};

// ✅ Login
export const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await verifyPassword(password, user.password)))
    return res.status(401).json({ message: "Invalid credentials" });

  if (!user.is_verified)
    return res.status(403).json({ message: "Account not verified" });

  const accessToken = createAccessToken({ sub: user._id });
  const refreshToken = createRefreshToken({ sub: user._id });

  // Save refresh in Redis
  await redis.set(`refresh:${user._id}`, refreshToken, {
    EX: 60 * 60 * 24 * 15,
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 15,
  });

  return res.json({ access_token: accessToken, token_type: "bearer" });
};

// ✅ Refresh token
export const refresh = async (req, res) => {
  const token = req.cookies.refresh_token;
  if (!token) return res.status(401).json({ message: "No refresh token" });

  const payload = verifyToken(token, process.env.JWT_REFRESH_SECRET);
  if (!payload) return res.status(401).json({ message: "Invalid token" });

  const savedToken = await redis.get(`refresh:${payload.sub}`);
  if (savedToken !== token)
    return res.status(401).json({ message: "Refresh token not recognized" });

  const newAccess = createAccessToken({ sub: payload.sub });
  const newRefresh = createRefreshToken({ sub: payload.sub });

  await redis.set(`refresh:${payload.sub}`, newRefresh, {
    EX: 60 * 60 * 24 * 15,
  });

  res.cookie("refresh_token", newRefresh, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 15,
  });

  return res.json({ access_token: newAccess, token_type: "bearer" });
};

// ✅ Logout
export const logout = async (req, res) => {
  const userId = req.user.sub;
  await redis.del(`refresh:${userId}`);
  res.clearCookie("refresh_token");
  return res.json({ message: "Logged out successfully" });
};

// ✅ Get Authenticated User
export const getUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.sub).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });

    return res.json(user);
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Server error", error: err.message });
  }
};
