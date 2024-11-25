const Note = require('../models/Note');
const { validationResult } = require('express-validator');
const User = require('../models/User');

// Create a new note
const createNote = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { title, content } = req.body;
        const note = await Note.create({
            title,
            content,
            userId: req.user.userId,
        });

        res.status(201).json({
            success: true,
            message: 'Note created successfully',
            note,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error creating note',
            error: error.message,
        });
    }
};

// Get all notes (accessible to any authenticated user)
const getAllNotes = async (req, res) => {
    try {
        const notes = await Note.findAll();

        res.status(200).json({
            success: true,
            message: 'Notes retrieved successfully',
            notes,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error retrieving notes',
            error: error.message,
        });
    }
};

// Get a single note by ID (accessible to any authenticated user)
const getNoteById = async (req, res) => {
    try {
        const note = await Note.findOne({
            where: { id: req.params.id },
        });

        if (!note) {
            return res.status(404).json({
                success: false,
                message: 'Note not found',
            });
        }

        res.status(200).json({
            success: true,
            message: 'Note retrieved successfully',
            note,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error retrieving note',
            error: error.message,
        });
    }
};

// Update a note (only accessible to note owner)
const updateNote = async (req, res) => {
    try {
        const { title, content } = req.body;
        const note = await Note.findOne({ where: { id: req.params.id } });

        if (!note) {
            return res.status(404).json({
                success: false,
                message: 'Note not found',
            });
        }

        if (note.userId !== req.user.userId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized: You can only edit your own notes',
            });
        }

        await note.update({ title, content });

        res.status(200).json({
            success: true,
            message: 'Note updated successfully',
            note,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error updating note',
            error: error.message,
        });
    }
};

// Delete a note (only accessible to note owner)
const deleteNote = async (req, res) => {
    try {
        const note = await Note.findOne({ where: { id: req.params.id } });

        if (!note) {
            return res.status(404).json({
                success: false,
                message: 'Note not found',
            });
        }

        if (note.userId !== req.user.userId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized: You can only delete your own notes',
            });
        }

        await note.destroy();

        res.status(200).json({
            success: true,
            message: 'Note deleted successfully',
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error deleting note',
            error: error.message,
        });
    }
};

module.exports = {
    createNote,
    getAllNotes,
    getNoteById,
    updateNote,
    deleteNote,
};
