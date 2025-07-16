const { hash, compare } = require("bcryptjs");
const { createHmac } = require("crypto");

exports.doHash = async (value, saltRounds) => {
    return await hash(value, saltRounds);
} 

exports.doHashValidation = async(value, hashedValue) => {
    return await compare(value, hashedValue);
}

exports.hmacProcess = (value, key) => {  
    return createHmac('sha256', key).update(value).digest('hex');
  };