const express = require('express');
const authController = require('../controllers/authController');
const { globalLimiter } = require('../middlewares/rateLimiter'); // Importing the global rate limiter middleware
const { identifyUser } = require('../middlewares/identifyUser');

const router = express.Router();

router.use(globalLimiter); // Apply global rate limiting to all routes in this router

router.post('/signup', authController.signup);
router.post('/login', authController.login); 
router.post('/logout', identifyUser, authController.logout); 
router.patch('/send-verification-code', identifyUser, authController.sendVerificationCode); 
router.patch('/verify-email',identifyUser, authController.verifyCode);

module.exports = router;