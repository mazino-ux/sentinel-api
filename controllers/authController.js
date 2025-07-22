const jwt = require("jsonwebtoken");
const { SignupSchema, LoginSchema, verificationSchema } = require("../middlewares/validator");
const User = require("../models/userModel");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashing");
const sendVerificationEmail = require("../middlewares/sendMail");
const { ROLES, SALT_ROUNDS, TOKEN_EXPIRY_MS } = require("../config/constants");
const { logAndRespond } = require("../utils/errorHandler");
const { loginLimiter, verificationLimiter } = require("../middlewares/rateLimiter");

exports.signup = async(req, res) => {
    const {username, email, password } = req.body; //The request body expected from the client/frontend

    try{
        const {error} = SignupSchema.validate({username, email, password}); //validating the inputs based on the signupSchema rules

        if(error){
            return res.status(400).json({success: false, message: error.details[0].message}); //If there's an error while validating flag this error
        }

        const userExist = await User.findOne({ $or: [{email}, {username}] }); //checking if the user already exists in the database using either the email or username
        if (userExist){
            return res.status(409).json({success:false, message: "User Already Exists"}); //if the user already exists, flag this error
        }

        const hashPassword = await doHash(password, SALT_ROUNDS[process.env.NODE_ENV] || SALT_ROUNDS.development); //hashing the password using the doHash function and the salt rounds based on the environment

        const newUser =  new User({ //creating a new user 
            username,
            email,
            role: ROLES.USER,
            password: hashPassword
        });
        const result = await newUser.save();
        result.password = undefined; 

        res.status(201).json({success:true, message: "User Created Successfully!"})
    }catch(error){
        return logAndRespond(res, error); //if there's an error while creating the user, log the error and respond with a 500 status code
    }
}

exports.login = [ loginLimiter, async(req, res) => {  // applying login limiter middleware to the login staye
    const {username, email, password} = req.body; //The request body expected from the client/frontend

    try{
        const { error } = LoginSchema.validate({username, email, password}); //validating the inputs based on the loginSchema rules

        if (error){
            return res.status(400).json({success:false, message: error.details[0].message}) //if there's an error while validating flag a 400 status code with json message saying false and the error message
        }

        const user  = await User.findOne({ $or: [{email}, {username}]}).select("+password"); //find the user exists using either the email or username plus the password
        if(!user){
            return res.status(404).json({success:false, message: "User Not Found!"}); //if the email isn't found in the database flag 404 error saying user not found!
        }

        const isValid = await doHashValidation(password, user.password); //validating the password
        if(!isValid){
            return res.status(401).json({success:false, message: "Invalid Credentials!"});
        }

        const token = jwt.sign({
            userId: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            verified: user.verified,
        }, process.env.JWT_SECRET, {
            algorithm: 'HS256',
            expiresIn: '8h'  // Token will expire in 8 hours
        } 
        );

        res.cookie("Authorization", `Bearer ${token}`, { //securing cookie settings
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 8 * 60 * 60 * 1000
        }).status(200).json({
            success: true,
            message: "Login Successful!",
            user: {
                username: user.username,
                email: user.email,
                verified: user.verified,
                role: user.role
            }
        })
     
    } catch (error) {
        return logAndRespond(res, error);
      }
      
}];

exports.logout = async(req, res) => {
    res
     .clearCookie('Authorization')
     .status(200)
     .json({success:true, message:'Logged out Successfully!'})
}

exports.sendVerificationCode = [verificationLimiter, async (req, res) =>{
    const {email} = req.body;
    try{
        const user = await User.findOne({email}).select("+verificationToken +verificationTokenValidation");
        if(!user){
            return res.status(404).json({success: false, message: "User Not Found!"});
        }

        if(user.verified){
            return res.status(400).json({success: false, message: "User Already Verified!"});
        }

        // Generate a verification token and validation time
        const codeValue = Math.floor(100000 + Math.random() * 900000).toString();
        const info = await sendVerificationEmail(user.email, codeValue);

        if (info && info.data && info.data.id) {
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_SECRET_CODE);
            user.verificationToken = hashedCodeValue;
            user.verificationTokenValidation = Date.now();
            await user.save();
            return res.status(200).json({ success: true, message: 'Verification code sent successfully!' });
        } else {
            return res.status(502).json({ success: false, message: 'Email delivery failed' });
        }
        
        // res.status(502).json({ success: false, message: 'Email delivery failed' });

    }catch(error){
        console.error(error);
        return res.status(500).json({success: false, message: "Server error, please try again later."});
    }
}];

exports.verifyCode = [
    verificationLimiter, 
    async(req, res) => { // applying verification limiter middleware to the verifyCode state
        const{email, code} = req.body; //The email for verification and the code sent to the user
        try{
            const {error} = verificationSchema.validate({email, code}); //validating the inputs based on the verificationSchema rules
            if(error){
                return res.status(400).json({success:false, message: error.details[0].message}); 
            }

            const codeValue = code.toString().padStart(6, '0'); // Ensure the code is a 6-digit string

            const user = await User.findOne({email}).select("+verificationToken +verificationTokenValidation");
            if (!user)
                return res.status(404).json({success:false, message: "User Not Found"});
            if(user.verified) 
                return res.status(400).json({success: false, message: "User Already Verified!"});

            if(!user.verificationToken || !user.verificationTokenValidation){
                return res.status(400).json({success:false, message: "Verification code not sent!"});
            }

            // Check if the verification code has expired
            if(Date.now() - user.verificationTokenValidation > TOKEN_EXPIRY_MS){ 
                user.verificationToken = undefined; // Clear the token if expired){
                return res.status(400).json({success:false, message: "Verification code expired!"});
            }
            const hashedCode = hmacProcess(codeValue, process.env.HMAC_SECRET_CODE);
            
            if(hashedCode === user.verificationToken){ //if the hashed code matches the verification token
                user.verified = true; //set the user as verified
                user.verificationToken = undefined; //clear the verification token
                user.verificationTokenValidation = undefined; //clear the verification token validation time
                await user.save(); //save the user to the database

                return res.status(200).json({success:true, message: "User Verified Successfully!"});
            }
            return res.status(400).json({success:false, message: "Invalid Verification Code!"}); //if the hashed code doesn't match the verification token, flag this error
            
        }catch(error){
            return logAndRespond(res, error); 
        }
    }
];