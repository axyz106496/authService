// mailer.js (simple console log for now)
export const sendEmail = async (to, subject, text) => {
  console.log(`📧 Email sent to ${to}: ${subject} - ${text}`);
  // Use nodemailer if you want real mails
};