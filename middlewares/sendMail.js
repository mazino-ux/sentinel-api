const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
    service: 'gmail', // Use your email service provider
    auth: {
        user: process.env.NODE_EMAIL_ADDRESS, // Your email address
        pass: process.env.NODE_EMAIL_PASS  // Your email password 
    },
    secure: true, // Use TLS
});

module.exports = transport;
// This code sets up a Nodemailer transporter for sending emails.
// It uses Gmail as the email service provider and authenticates with the provided email address and password.