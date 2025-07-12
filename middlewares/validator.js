const Joi = require('joi');

exports.SignupSchema = Joi.object({
    username: Joi.string().min(3).required(),
    email: Joi.string()
        .min(5).max(255)
        .required()
        .email({
            tlds: {allow : ['com', 'net', 'org', 'edu']}
        }),
        password: Joi.string()
            .min(6).max(1024)
            .required()
            .pattern(new RegExp('^[a-zA-Z0-9@#$%^&*!()_+\\-=\\[\\]{};:\'",.<>/?|`~\\\\]*$'))
            .messages({
            'string.pattern.base': 'Password contains invalid characters.',
            'string.min': 'Password must be at least 6 characters long.',
            'string.max': 'Password must not exceed 1024 characters.',
            'string.empty': 'Password cannot be empty.',
            'any.required': 'Password is required.'
            })      
})

exports.LoginSchema = Joi.object({
    username: Joi.string().min(3),
    email: Joi.string()
        .min(5).max(255)     
        .email({
            tlds: {allow : ['com', 'net', 'org', 'edu']}
        }),
        password: Joi.string()
            .min(6).max(1024)
            .required()
            .messages({
            'string.pattern.base': 'Password contains invalid characters.',
            'string.min': 'Password must be at least 6 characters long.',
            'string.max': 'Password must not exceed 1024 characters.',
            'string.empty': 'Password cannot be empty.',
            'any.required': 'Password is required.'
            })
}).or('username', 'email')