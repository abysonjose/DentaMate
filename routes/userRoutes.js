const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getUserProfile, updateUserProfile, deleteUserProfile, googleLogin } = require('../controllers/userController.js');
const { protect } = require('../middleware/authMiddleware.js');

// Define the registration route
router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/google-login', googleLogin);


// --- Protected Routes ---
// The 'protect' middleware will run before the controller function for these routes
router.route('/profile')
  .get(protect, getUserProfile)
  .put(protect, updateUserProfile)
  .delete(protect, deleteUserProfile);

module.exports = router;