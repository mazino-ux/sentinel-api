const { hash, compare } = require("bcryptjs")

exports.doHash = async (value, saltRounds) => {
    return await hash(value, saltRounds);
} 

exports.doHashValidation = async(value, hashedValue) => {
    return await compare(value, hashedValue);
}