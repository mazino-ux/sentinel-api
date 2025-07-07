const { SignupSchema } = require("../middlewares/validator");
const User = require("../models/userModel");
const { doHash } = require("../utils/hashing");

exports.Signup = async(req, res) => {
    const {email, password } = req.body;

    try{
        const {error, value} = SignupSchema.validate({email, password});

        if(error){
            return res.status(400).json({success: false, message: error.details[0].message});
        }

        const existingUser = await User.findOne({ email });
        if (existingUser){
            return res.status(409).json({success:false, message: "User Already Exists"});
        }

        const hashPassword = await doHash(password, 12);

        const newUser =  new User({
            email,
            password: hashPassword
        });
        const result = await newUser.save();
        result.password = undefined;

        res.status(201 || 200).json({success:true, message: "User Created Successdully!!"})
    }catch(error){
        console.log(error);
        return res.status(500).json({success: false, message: "Server Error, Please try again later!"});
    }
}