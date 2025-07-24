const jwt = require('jsonwebtoken');
const logAndRespond = require('../utils/errorHandler');

exports.identifyUser = (req, res, next) => {
    let token;
    const isBearerHeader = req.headers.authorization?.startsWith("Bearer "); //this is to get the token from the 'Authorization' header if it's a non-browser request

    if (isBearerHeader) {
        token = req.headers.authorization;
    }else{
        token = req.cookies["Authorization"]; //if not from header, try to get the token from the broswer
    }

    //if no token was found, means the user is unauthorzed and will be denied access
    if (!token) {
        return res
        .status(401)
        .json({success: false, message:"Unathorized acess. No token provided"});
    }

    try{
        const userToken = token.startsWith("Bearer ") ? token.split(" ")[1] : token;
        const decoded = jwt.verify(userToken, process.env.JWT_SECRET);
        if (decoded) {
            req.user = decoded;
            next(); //Move on to the next middleware or route
        }else{
            throw new Error("Invalid Token!"); // If token was decoded but something seems wrong
        }
    }catch(error) {
        return logAndRespond(res, error);
    }
};