const express = require('express');
const { check } = require('express-validator');
const authenticateToken = require('../middleware/authMiddleware');
const noteController = require('../controllers/noteController');

const router = express.Router();

// Validation middleware
const validateNote = [
    check('title').not().isEmpty().withMessage('Title is required'),
    check('content').not().isEmpty().withMessage('Content is required'),
];

// Create a note
router.post(
    '/',  // Changed from '/notes' since we'll mount the router with '/api/notes' prefix
    authenticateToken,
    validateNote,
    noteController.createNote
);

// Get all notes (accessible to all authenticated users)
router.get(
    '/',  // Changed from '/notes'
    
    noteController.getAllNotes  // Changed from getUserNotes to match new controller
);

// Get a single note by ID
router.get(
    '/:id',  // Changed from '/notes/:id'
  
    noteController.getNoteById
);

// Update a note
router.put(
    '/:id',  // Changed from '/notes/:id'
    authenticateToken,
    validateNote,
    noteController.updateNote
);

// Delete a note
router.delete(
    '/:id',  // Changed from '/notes/:id'
    authenticateToken,
    validateNote,
    noteController.deleteNote
);

module.exports = router;