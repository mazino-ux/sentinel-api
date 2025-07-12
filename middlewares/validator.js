const Joi = require('joi');

const passwordSchema = Joi.string()
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

exports.SignupSchema = Joi.object({
    username: Joi.string().min(3).required()
                .pattern(new RegExp('^[a-zA-Z0-9_]+$'))
                .messages({
                    'string.pattern.base': 'Username can only contain letters, numbers, and underscores'
                }),
    email: Joi.string()
        .min(5)
        .max(255)
        .required()
        .email({
            tlds: { allow: ['com', 'net', 'org', 'edu', 'io'] }
        })
        .messages({
            'string.email': 'Please enter a valid email address',
            'string.empty': 'Email cannot be empty',
            'any.required': 'Email is required'
        }),
    password: passwordSchema  
})

exports.LoginSchema = Joi.object({
    username: Joi.string().min(3),
    email: Joi.string()
        .min(5).max(255)     
        .email({
            tlds: {allow : ['com', 'net', 'org', 'edu']}
        }),
        password: passwordSchema
}).or('username', 'email')
  .messages({
    'object.missing': 'Either username or email must be provided'
});