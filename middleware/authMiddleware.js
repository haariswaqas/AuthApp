// authMiddleware.js

const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({message: '401 Unauthorized: Access token required'});

    jwt.verify(token, process.env_JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({message: 'Invalid token'});
        req.user = user;
        next();
    });
};

module.exports = authenticateToken;