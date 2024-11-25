const sequelize = require('./config/database');
const User = require('./models/User');
const Note = require('./models/Note');

// Initialize associations
User.associate({ Note });
Note.associate({ User });

module.exports = { sequelize, User, Note };
