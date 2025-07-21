const express = require('express');
const authController = require('../controllers/authController');
const { globalLimiter } = require('../middlewares/rateLimiter'); // Importing the global rate limiter middleware

const router = express.Router();

router.use(globalLimiter); // Apply global rate limiting to all routes in this router

router.post('/signup', authController.signup);
router.post('/login', authController.login); 
router.post('/logout', authController.logout); 
router.post('/send-verification-code', authController.sendVerificationCode); 


module.exports = router;