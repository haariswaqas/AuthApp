// authController.js

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

exports.register = async (req, res) => {
    const {email, password} = req.body;
    try {
        const existingUser = await User.findOne({where: {email}});
        if(existingUser) return res.status(400).json({message: 'User already exists'});

        const user = await User.create({email, password});
        const token = jwt.sign({userId: user.id}, process.env.JWT_SECRET, {expiresIn: '1h'});
        res.json({message: 'user successfully registered', token});
    } catch(error) {
        res.status(500).json({message: error.message});
    }
};


exports.login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({where: {email}});
        if(!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({message: 'Invalid credentials'});
        } 
        const token = jwt.sign({userId: user.id}, process.env.JWT_SECRET, {expiresIn: '1h' });
        res.json({message: 'Logged in', token});
    } catch (error) {
        res.status(500).json({message: error.message});
    }
};


