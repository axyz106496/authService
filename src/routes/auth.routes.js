import { Router } from "express";
import {
  register,
  verifyOtp,
  resendOtp,
  login,
  refresh,
  logout,
  getUser,
} from "../controllers/auth.controller.js";
import { authenticate } from "../middlewares/auth.js";

const router = Router();

router.post("/register", register);
router.post("/verify-otp", verifyOtp);
router.post("/resend-otp", resendOtp);
router.post("/login", login);
router.post("/refresh-token", refresh);
router.post("/logout", authenticate, logout);
router.get("/me", authenticate, getUser);

export default router;
