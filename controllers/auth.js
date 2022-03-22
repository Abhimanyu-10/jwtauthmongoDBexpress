const User = require('../models/User');
const jwt = require('jsonwebtoken');
const validation = require('../helpers/validation');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const moment = require('moment');

exports.login = async (req, res) => {
    try {
        const { error } = validation.loginSchema.validate(req.body);
        if (error) {
            res.status(400).json({
                status: 400,
                message: 'INPUT ERROR',
                errors: error.details,
                original: error._original,
            })
        } else {
            const user = await User.findOne({ email: req.body.email });
            //check if the email is correct
            if (user) {
                const validatePassword = await bcrypt.compare(req.body.password, user.password);
                if (validatePassword) {
                    //Generate access token & refresh token
                    const accessToken = jwt.sign({
                        _id: user.id,
                        email: user.email,
                    }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
                    const refreshToken = jwt.sign({
                        _id: user.id,
                        email: user.email,
                    }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });

                    if (await addRefreshToken(user, refreshToken)) {
                        res.status(200).json({
                            success: {
                                status: {
                                    status: 200,
                                    message: 'LOGIN SUCCESS',
                                    accessToken: accessToken,
                                    refreshToken: refreshToken,
                                }
                            }
                        })
                    } else {
                        res.status(500).json({ error: { status: 500, message: 'SERVER ERROR' } })
                    }
                } else {
                    res.status(403).json({ error: { status: 403, message: 'INVALID PASSWORD' } })
                }
            } else {
                res.status(403).json({ error: { status: 403, message: 'INVALID EMAIL' } })
            }
        }
    } catch (err) {
        console.log(err);
        res.status(400).json({ error: { status: 400, message: 'BAD REQUEST' } });
    }
}

exports.register = async (req, res) => {
    try {
        const { error } = validation.registerSchema.validate(req.body, { abortEarly: false });

        if (error) {
            res.status(400).json({
                status: 400,
                message: 'INPUT ERROR',
                errors: error.details,
                original: error._original,
            })
        } else {
            //Encrypt password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);
            //Create new user instance
            const user = new User({
                email: req.body.email,
                password: hashedPassword,
                emailConfirmed: false,
                emailToken: uuidv4(),
                security: {
                    tokens: [],
                    passwordReset: {
                        token: null,
                        provisionalPassword: null,
                        expiry: null
                    }
                }
            })

            //Attempt to  save data to user DB
            await user.save();

            //Generate access token & refresh token
            const accessToken = jwt.sign({
                _id: user.id,
                email: user.email,
            }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
            const refreshToken = jwt.sign({
                _id: user.id,
                email: user.email,
            }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });

            //Assign the token to user and save
            await User.updateOne({ email: user.email }, {
                $push: {
                    'security.tokens': {
                        refreshToken: refreshToken,
                        createdAt: new Date(),
                    }
                }
            })
            //Send Email Conformation
            await sendEmailConfirmation({ email: user.email, emailToken: user.emailToken });

            res.status(200).header().json({
                success: {
                    status: 200,
                    message: 'REGISTER SUCCESS',
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    user: {
                        id: user.id,
                        email: user.email
                    }
                }
            })
        }

    } catch (err) {

        console.log(err)
        let errorMessage;

        if (err.keyPattern.email === 1) {
            errorMessage = 'EMAIL ALREADY EXISTS';
        } else {
            errorMessage = err;
        }

        res.status(400).json({ error: { status: 400, message: errorMessage } });
    }
}

exports.token = async (req, res) => {
    try {
        const refreshToken = req.body.refreshToken;

        //Verify if the token is valid if not ask to re-authenticate
        try {
            const decodeRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            const user = await User.findOne({ email: decodeRefreshToken.email });
            const existingRefreshToken = user.security.tokens;
            //Check if refresh token is in document
            if (existingRefreshToken.some(token => token.refreshToken === refreshToken)) {
                //Generate access token
                const accessToken = jwt.sign({
                    _id: user.id,
                    email: user.email,
                }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
                //Send new Access token
                res.status(200).json({
                    status: 200,
                    message: 'ACCESS TOKEN GENERATED',
                    accessToken: accessToken
                })
            } else {
                res.status(401).json({ error: { status: 401, message: 'INVALID REFRESH TOKEN ELSE' } })
            }
        } catch (err) {
            res.status(401).json({ error: { status: 401, message: 'INVALID REFRESH TOKEN CATCH' } })
        }
    } catch (err) {
        res.status(400).json({ error: { status: 400, message: 'BAD REQUEST' } })
    }
}

exports.confirmEmailToken = async (req, res) => {
    try {
        const emailToken = req.body.emailToken;
        if (emailToken !== null) {
            const accessToken = req.header('Authorization').split(' ')[1];
            const decodeAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
            //check user exist
            const user = await User.findOne({ email: decodeAccessToken.email })
            //check if email already confirmed
            if (!user.emailConfirmed) {
                //check if provided email token matches users email token
                if (emailToken === user.emailToken) {
                    await User.updateOne({ email: decodeAccessToken.email }, { $set: { emailConfirmed: true, emailToken: null } });
                    res.status(200).json({ success: { success: 200, message: 'EMAIL CONFIRMED' } })
                } else {
                    res.status(401).json({ error: { status: 401, message: 'INVALID EMAIL TOKEN' } })
                }
            } else {
                res.status(401).json({ error: { status: 401, message: 'EMAIL ALREADY CONFIRMED' } })
            }
        } else {
            res.status(400).json({ error: { status: 400, message: 'BAD REQUEST' } })
        }
    } catch (err) {
        res.status(400).json({ error: { status: 400, message: 'BAD REQUEST' } });
    }
}

exports.resetPasswordConfirm = async (req, res)=>{
    try{
        const user = await User.findOne({email: req.body.email});

        //Check if supplied passwordResetToken matches with the users stored one
        if(user.security.passwordReset.token === req.body.passwordResetToken){
            //check if password reset token is expired
            if(new Date().getTime()  <= new Date(user.security.passwordReset.expiry).getTime()){
                await User.updateOne({email:req.body.email},{
                    $set: {
                        'password':user.security.passwordReset.provisionalPassword,
                        'security.passwordReset.token':null,
                        'security.passwordReset.provisionalPassword': null,
                        'security.passwordReset.expiry':null
                    }
                })
                res.status(200).json({success:{status:200,message:'PASSWORD RESET SUCCESS'}})
            } else {
                await User.updateOne({email:req.body.email},{
                    $set:{
                        'security.passwordReset.token':null,
                        'security.passwordReset.provisionalPassword': null,
                        'security.passwordReset.expiry':null
                    }
                })
                res.status(401).json({error:{status:401,message:'PASSWORD RESET TOKEN EXPIRED'}})
            }
        } else {
            res.status(401).json({error:{status:401,message:'INVALID PASSWORD RESET TOKEN'}})
        }
    } catch(err) {
        res.status(400).json({ error: { status: 400, message: 'BAD REQUEST' } });
    }
}

exports.resetPassword = async (req, res) => {
    try {
        if (req.body.provisionalPassword.length >= 4 && req.body.provisionalPassword.length <= 25) {
            //Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(req.body.provisionalPassword, salt);

            //Generate a password reset token
            const passwordResetToken = uuidv4();
            const expiresIn = moment().add(10, 'm').toISOString();
            //Update user with password token
            const user = await User.findOneAndUpdate({ email: req.body.email }, {
                $set: {
                    'security.passwordReset': {
                        token: passwordResetToken,
                        provisionalPassword: hashedPassword,
                        expiry: expiresIn
                    }
                }
            })
            await sendPasswordResetConfirmation({ email: req.body.email, passwordResetToken: passwordResetToken })
            res.status(200).json({ success: { status: 200, message: 'PASSWORD RESET EMAIL SENT' } })
        } else {
            res.status(400).json({ error: { status: 400, message: 'PASSWORD INPUT ERROR' } })
        }
    } catch {
        res.status(400).json({ error: { status: 400, message: 'BAD REQUEST' } });
    }
}

exports.test = async (req, res) => {
    try {
        const newUser = new User({
            email: 'test4@test.com',
            password: 'test4',
            emailConfirmed: false,
            emailToken: 'test',
            security: {
                tokens: null,
                passwordReset: null
            }
        });
        await newUser.save();
        res.send(newUser);
    } catch (err) {
        res.send(err)
    }
}

const addRefreshToken = async (user, refreshToken) => {
    try {
        const existingRefreshToken = user.security.tokens;
        //check if there less than 5
        if (existingRefreshToken.length < 5) {
            await User.updateOne({ email: user.email }, {
                $push: {
                    'security.tokens': {
                        refreshToken: refreshToken,
                        createdAt: new Date(),
                    }
                }
            })
        } else {
            //else remove the last token
            await User.updateOne({ email: user.email }, {
                $pull: {
                    'security.tokens': {
                        _id: existingRefreshToken[0]._id,
                    }
                }
            })
            //Push the new token
            await User.updateOne({ email: user.email }, {
                $push: {
                    'security.tokens': {
                        refreshToken: refreshToken,
                        createdAt: new Date(),
                    }
                }
            })
        }
        return true;
    } catch (err) {
        return false;
    }
}

const sendEmailConfirmation = async (user) => {
    const transport = nodemailer.createTransport({
        host: process.env.NODEMAILER_HOST,
        port: process.env.NODEMAILER_PORT,
        auth: {
            user: process.env.NODEMAILER_USER,
            pass: process.env.NODEMAILER_PASS
        }
    });
    const info = await transport.sendMail({
        from: '"jwtauth" <noreply@jwtauth.com>',
        to: user.email,
        subject: 'Confirm your email',
        text: `click on the link to confirm your email: http://localhost:7000/confirm-email/${user.emailToken}`,

    })
}

const sendPasswordResetConfirmation = async (user) => {
    const transport = nodemailer.createTransport({
        host: process.env.NODEMAILER_HOST,
        port: process.env.NODEMAILER_PORT,
        auth: {
            user: process.env.NODEMAILER_USER,
            pass: process.env.NODEMAILER_PASS
        }
    });
    const info = await transport.sendMail({
        from: '"jwtauth" <noreply@jwtauth.com>',
        to: user.email,
        subject: 'Reset your Password',
        text: `click on the link to confirm your password reset: http://localhost:7000/confirm-password/${user.passwordResetToken}`,

    })
}