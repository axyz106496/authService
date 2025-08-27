// src/utils/mailer.js
import nodemailer from "nodemailer";
import { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } from "../config/env.js";

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: false, // true for 465, false for other ports
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

export const sendEmail = async (to, subject, text) => {
  try {
    const info = await transporter.sendMail({
      from: `"Auth Service" <no-reply@auth-service.com>`,
      to,
      subject,
      text,
    });

    console.log(`📧 Email sent: ${info.messageId}`);
  } catch (err) {
    console.error("❌ Email sending failed:", err.message);
  }
};