const joi = require('joi');

exports.registerSchema = joi.object({
    email: joi.string().min(4).max(25).email(),
    password: joi.string().min(4).max(25)
})

exports.loginSchema = joi.object({
    email: joi.string().min(4).max(25).email(),
    password: joi.string().min(4).max(25)
})