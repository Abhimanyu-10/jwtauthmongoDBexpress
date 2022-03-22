const express = require('express');
const authController = require('../controllers/auth');
const rateLimiter = require('../helpers/rateLimiter');
const verifyToken = require('../helpers/verifyToken');

//Router initialisation
const router = express.Router();

//Routes
router.get('/test',[verifyToken],authController.test);

//[POST] login
router.post('/login',authController.login)

//[POST] register
router.post('/register',authController.register);

//[POST] Token
router.post('/token',authController.token);

//[POST] email token
router.post('/confirmEmailToken',verifyToken,authController.confirmEmailToken)

//[POST] Reset Password
router.post('/resetPassword',authController.resetPassword)

//[POST] Reset password Confirm
router.post('/resetPasswordConfirm',authController.resetPasswordConfirm)

module.exports = router;