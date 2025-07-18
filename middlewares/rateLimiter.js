const ratelimit = require('express-rate-limit');

exports.createRateLimiter = (windowMinutes, maxRequests) => ({ //creating the rate limiter middleware
    windowMs: windowMinutes * 60 * 1000, //how long the rate limiting window should last, in milliseconds
    max: maxRequests, //max number of requests allowed in the time windowen the limit is exceeded

    handlers: (req, res) => { //if individual request exceeds the limit respond with a 429 status code
        res.status(429).json({
            success: false,
            message: `Too many requests, please try again after ${windowMinutes} minutes.`
        })
    },
    standardHeaders: true, //this is a more modern way to send rate limit information in the headers, so we enable it
    legacyHeaders: false //legacy headers are deprecated, so we disable them, by setting it to false
});

exports.loginLimiter = createRateLimiter( //this helps prevent brute force attacks on the login endpoint
    process.env.LOGIN_RATE_LIMIT_WINDOW || 15, //default to 15 minutes if not set
    process.env.LOGIN_RATE_LIMIT_MAX || 5 //default to 5 requests if not set
)

exports.verificationLimiter = createRateLimiter( //this helps prevent spam attacks on the verification endpoint
    process.env.VERIFICATION_RATE_LIMIT_WINDOW || 60, 
    process.env.VERIFICATION_RATE_LIMIT_MAX || 3
)

exports.globalLimiter = createRateLimiter(15, 100); //this is a general-purpose or global rate limiter for the entire API, it allows about 100 requests every 15 minutes per user/IP address.