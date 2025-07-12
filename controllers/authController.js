const jwt = require("jsonwebtoken");
const { SignupSchema, LoginSchema } = require("../middlewares/validator");
const User = require("../models/userModel");
const { doHash, doHashValidation } = require("../utils/hashing");

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
    const {username, email, password} = req.body;

    try{
        const { error } = LoginSchema.validate({username, email, password});

        if (error){
            return res.status(400).json({success:false, message: error.details[0].message})
        }

        const user  = await User.findOne({ $or: [{email: identifier}, {username: identifier}]}).select("+password");
        if(!user){
            return res.status(404).json({success:false, message: "User Not Found!"});
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
        }, process.env.JWT_SECRET )

        res.cookie('Authorization', 'Bearer ' + token, {
            httpOnly: process.env.NODE_ENV === 'production',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 8 * 60 * 60 * 1000  // 8 hours in milliseconds
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