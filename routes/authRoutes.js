const express = require('express');
const { register, login } = require('../controllers/authController');
const authenticateToken = require('../middleware/authMiddleware');

const router = express.Router();

// Register and Login routes
router.post('/register', register);
router.post('/login', login);

// Protected route with authentication middleware
router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Protected route', user: req.user });
});

module.exports = router;
