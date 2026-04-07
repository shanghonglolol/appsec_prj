const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
require("dotenv").config();
const Member = require("../Database/member");

const verifyCaptcha = async (captchaResponse) => {
    if (!captchaResponse) return false;
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captchaResponse}`);
        return response.data.success;
    } catch (error) {
        return false;
    }
};

const createTransporter = () => {
    return nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
};

const memberSignup = async (req, role, res) => {
    try {
        if (role === 'member' && !await verifyCaptcha(req.captcha)) {
            return res.status(400).json({ message: 'CAPTCHA verification failed.' });
        }

        if (await Member.findOne({ name: req.name })) {
            return res.status(400).json({ message: 'Member is already registered.' });
        }
        if (await Member.findOne({ email: req.email })) {
            return res.status(400).json({ message: 'Email is already registered.' });
        }

        const password = await bcrypt.hash(req.password, 12);
        const newMember = new Member({ ...req, password, role });
        await newMember.save();

        return res.status(201).json({ message: "Successfully registered. Please login." });
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
};

const memberLogin = async (req, role, res) => {
    try {
        const member = await Member.findOne({ name: req.name });
        if (!member) {
            return res.status(404).json({ message: "Invalid login credentials" });
        }
        if (member.role !== role) {
            return res.status(401).json({ message: "Wrong portal for your role" });
        }
        if (!await bcrypt.compare(req.password, member.password)) {
            return res.status(403).json({ message: "Incorrect password" });
        }

        //captcha verification
        if (role === 'member' && !await verifyCaptcha(req.captcha)) {
            return res.status(400).json({ message: 'CAPTCHA verification failed.' });
        }

        //2FA
        if (role === 'member') {
            const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString();
            member.twoFactorCode = twoFactorCode;
            member.twoFactorExpires = new Date(Date.now() + 30); //setting to 30 because of demo
            await member.save();

            const transporter = createTransporter();
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: member.email,
                subject: '2FA Verification Code',
                html: `<h2>Your Verification Code</h2><p>Your 6-digit code is: <strong>${twoFactorCode}</strong></p><p>This code expires in 10 minutes.</p>`
            });

            return res.status(200).json({ 
                message: "2FA code sent to your email",
                requiresTwoFactor: true,
                email: member.email
            });
        }

        const token = jwt.sign(
            { role: member.role, name: member.name, email: member.email, id: member.member_id },
            process.env.APP_SECRET,
            { expiresIn: "3 days" }
        );

        return res.status(200).json({
            name: member.name,
            role: member.role,
            email: member.email,
            token: token,
            message: "You are now logged in."
        });
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const member = await Member.findOne({ email: req.email });
        if (!member) {
            return res.status(404).json({ message: "No account found with this email." });
        }
        if (member.role !== 'member') {
            return res.status(403).json({ message: "Password reset only available for members." });
        }

        //generate token
        const resetToken = crypto.randomBytes(32).toString('hex');
        member.resetPasswordToken = resetToken;
        member.resetPasswordExpires = new Date(Date.now() + 60000); 
        await member.save();

        //send email
        const resetURL = `http://localhost:3699/reset-password.html?token=${resetToken}`;
        const transporter = createTransporter();
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: req.email,
            subject: 'Password Reset Request',
            html: `
                <h2>Password Reset Request</h2>
                <p>Hello,</p>
                <p>You requested a password reset for your member account.</p>
                <p>Click the link below to reset your password:</p>
                <a href="${resetURL}" style="background-color: #04AA6D; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">Reset Password</a>
                <p>Or copy this link: ${resetURL}</p>
                <p>This link will expire in 1 minute.</p>
                <p>If you didn't request this reset, please ignore this email.</p>
            `
        });

        return res.status(200).json({ message: "Reset link sent to your email." });
    } catch (error) {
        return res.status(500).json({ message: "Error sending email." });
    }
};

const resetPassword = async (req, res) => {
    try {
        const member = await Member.findOne({
            resetPasswordToken: req.token,
            resetPasswordExpires: { $gt: Date.now() },
            role: 'member'
        });

        if (!member) {
            return res.status(400).json({ message: "Invalid or expired token." });
        }

        //update password
        member.password = await bcrypt.hash(req.newPassword, 12);
        member.resetPasswordToken = null;
        member.resetPasswordExpires = null;
        await member.save();

        return res.status(200).json({ message: "Password reset successfully." });
    } catch (error) {
        return res.status(500).json({ message: "Error resetting password." });
    }
};

const memberAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ message: "Missing Token" });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.APP_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Wrong Token" });
        req.name = decoded.name;
        req.id = decoded.id;
        next();
    });
};

const verify2FA = async (req, res) => {
    try {
        const member = await Member.findOne({
            email: req.email,
            twoFactorCode: req.code,
            twoFactorExpires: { $gt: Date.now() },
            role: 'member'
        });

        if (!member) {
            return res.status(400).json({ message: "Invalid or expired code" });
        }

        member.twoFactorCode = null;
        member.twoFactorExpires = null;
        await member.save();

        const token = jwt.sign(
            { role: member.role, name: member.name, email: member.email, id: member.member_id },
            process.env.APP_SECRET,
            { expiresIn: "3 days" }
        );

        return res.status(200).json({
            name: member.name,
            role: member.role,
            email: member.email,
            token: token,
            message: "Login successful"
        });
    } catch (error) {
        return res.status(500).json({ message: "Verification failed" });
    }
};

const resend2FA = async (req, res) => {
    try {
        const member = await Member.findOne({ email: req.email, role: 'member' });
        if (!member) {
            return res.status(404).json({ message: "User not found" });
        }

        const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString();
        member.twoFactorCode = twoFactorCode;
        member.twoFactorExpires = new Date(Date.now() + 600000);
        await member.save();

        const transporter = createTransporter();
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: member.email,
            subject: '2FA Verification Code',
            html: `<h2>Your Verification Code</h2><p>Your 6-digit code is: <strong>${twoFactorCode}</strong></p><p>This code expires in 10 minutes.</p>`
        });

        return res.status(200).json({ message: "New code sent to your email" });
    } catch (error) {
        return res.status(500).json({ message: "Failed to resend code" });
    }
};

const checkRole = roles => async (req, res, next) => {
    const member = await Member.findOne({ name: req.name });
    !roles.includes(member.role)
        ? res.status(401).json("Access denied")
        : next();
};

module.exports = {
    memberSignup,
    memberLogin,
    checkRole,
    memberAuth,
    forgotPassword,
    resetPassword,
    verify2FA,
    resend2FA,
};