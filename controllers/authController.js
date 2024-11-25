const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');

// Utility function to generate tokens
const generateToken = (user, secret, expiresIn) => {
    return jwt.sign(
        { userId: user.id, email: user.email },  // Include userId and email in the payload
        secret,
        { expiresIn }
    );
};

// Register Controller
exports.register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    try {
        // Check if the email is already taken
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: 'Email is already registered' });
        }

        // Create new user
        const user = await User.create({ email, password });

        // Generate token with email and userId
        const token = generateToken(user, process.env.JWT_SECRET, '1h');
        
        res.json({ message: 'User successfully registered', token });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Login Controller
exports.login = async (req, res) => {
    const { email, password } = req.body;
    try {
        // Find user by email
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Use the validatePassword method to check if the password is correct
        const isPasswordValid = await user.validatePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate access token with userId and email
        const accessToken = generateToken(user, process.env.JWT_SECRET, '1h');

        // Generate refresh token (this could also include email if you wish)
        const refreshToken = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ message: 'Logged in', accessToken, refreshToken });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: error.message });
    }
};
