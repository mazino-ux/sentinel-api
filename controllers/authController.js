const jwt = require("jsonwebtoken");
const { SignupSchema, LoginSchema } = require("../middlewares/validator");
const User = require("../models/userModel");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashing");
const { transport } = require("../middlewares/sendMail");

exports.signup = async(req, res) => {
    const {username, email, password } = req.body;

    try{
        const {error, value} = SignupSchema.validate({username, email, password});

        if(error){
            return res.status(400).json({success: false, message: error.details[0].message});
        }

        const userExist = await User.findOne({ $or: [{email}, {username}] });
        if (userExist){
            return res.status(409).json({success:false, message: "User Already Exists"});
        }

        const hashPassword = await doHash(password, 12);

        const newUser =  new User({
            username,
            email,
            password: hashPassword
        });
        const result = await newUser.save();
        result.password = undefined;

        res.status(201).json({success:true, message: "User Created Successfully!"})
    }catch(error){
        console.log(error);
        return res.status(500).json({success: false, message: "Server Error, Please try again later!"});
    }
}

exports.login = async(req, res) =>{
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

        const result = await doHashValidation(password, user.password);
        if(!result){
            return res.status(401).json({success:false, message: "Invalid Credentials!"});
        }

        const token = jwt.sign({
            userId: user._id,
            username: user.username,
            email: user.email,
            verified: user.verified,
        }, process.env.JWT_SECRET, {
            expiresIn: '8h'  // Token will expire in 8 hours
        } 
        );

        res.cookie("Authorization", `Bearer ${token}`, {
            httpOnly: process.env.NODE_ENV === "production",
            secure: process.env.NODE_ENV === "production",
            maxAge: 8 * 60 * 60 * 1000
        }).status(200).json({
            success: true,
            message: "User Logged In Successfully!",
            token,
            user: {
                username: user.username,
                email: user.email,
                verified: user.verified
            }
        })
     
    } catch (error) {
        console.error(error);
        return res.status(500).json({
          success: false,
          message: "Server error, please try again later."
        });
      }
      
}

exports.logout = async(req, res) => {
    res
     .clearCookie('Authorization')
     .status(200)
     .json({success:true, message:'Logged out Successfully!'})
}

exports.sendVerificationCode = async (req, res) =>{
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
        let info = await transport({
           from: process.env.NODE_EMAIL_USER,
           to: user.email,
           subject: 'Verification Code',
           html:'<h1> This is your Verification code:' + codeValue + '</h1>'
        });

        if (info.accepted[0] === user.email ){
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_SECRET_CODE)
            user.verificationToken = hashedCodeValue; 
            user.verificationTokenValidation = Date.now();
            await user.save();
            return res.status(200).json({success:true, message: 'Verification code sent successfully!'});
        }
        res.status(400).json({success:false, message: 'Code sent Failed!'});

    }catch(error){
        console.error(error);
        return res.status(500).json({success: false, message: "Server error, please try again later."});
    }
}