const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

const sendVerificationEmail = async (to, code) => {
  return await resend.emails.send({
    from: 'Auth System <onboarding@resend.dev>', // Resend default sender
    to,
    subject: 'Verification Code',
    html: `<h1>Your code: ${code}</h1><p>This code expires in 10 minutes.</p>`
  });
};

module.exports = sendVerificationEmail;
