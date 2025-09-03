const express = require('express');
const router = express.Router();
const { createStaff, getAllUsers, getUserById, updateUserById, deleteUserById } = require('../controllers/adminController.js');
const { protect, authorizeAdmin } = require('../middleware/authMiddleware.js');

// Apply middleware to all routes in this file
router.use(protect);
router.use(authorizeAdmin);

// --- Admin Routes ---
router.route('/staff').post(createStaff);

router.route('/users').get(getAllUsers);

router.route('/users/:id')
  .get(getUserById)
  .put(updateUserById)
  .delete(deleteUserById);

module.exports = router;