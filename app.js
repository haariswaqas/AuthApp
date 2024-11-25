// app.js
const express = require('express');
const cors = require('cors'); // Import cors package
const dotenv = require('dotenv');
const sequelize = require('./config/database');
const authRoutes = require('./routes/authRoutes');
const noteRoutes = require('./routes/noteRoutes');  // Import noteRoutes

dotenv.config();

const app = express();

// Enable CORS for requests from http://localhost:3001
app.use(cors({ origin: 'http://localhost:3001' }));

// Middleware
app.use(express.json());

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something broke!' });
});

// Routes
app.use('/api', authRoutes);  // Auth routes are prefixed with '/api/auth'
app.use('/api/notes', noteRoutes);  // Notes routes are prefixed with '/api'

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK' });
});

const PORT = process.env.PORT || 3000;

const startServer = async () => {
    try {
        await sequelize.authenticate();
        console.log('Database connected successfully');
        await sequelize.sync({ alter: true }); // `alter: true` updates the schema without dropping data
        await sequelize.sync();
        console.log('Database models synchronized');
        
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
            console.log('JWT_SECRET:', process.env.JWT_SECRET);

        });
    } catch (error) {
        console.error('Unable to start server:', error);
        process.exit(1);
    }
};

startServer();
