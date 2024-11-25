const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Note = sequelize.define(
    'Note',
    {
        id: {
            type: DataTypes.INTEGER,
            autoIncrement: true,
            primaryKey: true,
        },
        title: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        content: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        userId: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: 'Users', // Matches the table name for the User model
                key: 'id',
            },
        },
    },
    {
        timestamps: true,
    }
);

// Define associations
Note.associate = (models) => {
    Note.belongsTo(models.User, {
        foreignKey: 'userId',
        as: 'user',
    });
};

module.exports = Note;
