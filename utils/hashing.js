const { hash } = require("bcryptjs")

exports.doHash = async (value, saltRounds) => {
    return await hash(value, saltRounds);
} 