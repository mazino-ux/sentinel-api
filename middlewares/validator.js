const Joi = require('joi');

exports.SignupSchema = Joi.objects({
    email: Joi.string()
        .min(5).max(255)
        .required
        .email({
            tlds: {allow : ['com', 'net', 'org', 'edu']}
        }),
    password: Joi.string()
        .min(8).max(1024)
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$'))
})