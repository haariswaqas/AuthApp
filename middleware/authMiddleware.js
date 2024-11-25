const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    try {
        // Extract the token from the Authorization header
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            console.error('Authorization header is missing');
            return res.status(401).json({ message: 'Access token required' });
        }

        if (!authHeader.startsWith('Bearer ')) {
            console.error('Invalid Authorization header format');
            return res.status(401).json({ message: 'Invalid Authorization header format' });
        }

        const token = authHeader.split(' ')[1];
        if (!token) {
            console.error('Token is missing in the Authorization header');
            return res.status(401).json({ message: 'Access token required' });
        }

        // Verify the token
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                console.error('Token verification error:', err);
                return res.status(403).json({ message: 'Invalid or expired token' });
            }

            // Attach decoded user information to the request object
            req.user = decoded;
            next();
        });
    } catch (error) {
        console.error('An error occurred while authenticating the token:', error);
        res.status(500).json({ message: 'An error occurred while authenticating the token' });
    }
};

module.exports = authenticateToken;
