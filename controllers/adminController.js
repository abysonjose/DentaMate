const User = require('../models/User.js');
const bcrypt = require('bcryptjs');

// @desc    Create a staff user (by an admin)
// @route   POST /api/admin/staff
// @access  Private/Admin
const createStaff = async (req, res) => {
  try {
    const { name, email, password, role, phoneNumber } = req.body;

    // An admin can't create another Central Admin for security
    if (role === 'Central Admin') {
      return res.status(400).json({ message: 'Cannot create another Central Admin.' });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role, // Role is taken from admin's input
      phoneNumber,
    });

    const createdUser = await user.save();
    res.status(201).json({
      _id: createdUser._id,
      name: createdUser.name,
      email: createdUser.email,
      role: createdUser.role,
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Get all users
// @route   GET /api/admin/users
// @access  Private/Admin
const getAllUsers = async (req, res) => {
  try {
    // Find all users but exclude their passwords from the result
    const users = await User.find({}).select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Get user by ID
// @route   GET /api/admin/users/:id
// @access  Private/Admin
const getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Update user by ID
// @route   PUT /api/admin/users/:id
// @access  Private/Admin
const updateUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (user) {
      user.name = req.body.name || user.name;
      user.email = req.body.email || user.email;
      user.role = req.body.role || user.role;
      user.phoneNumber = req.body.phoneNumber || user.phoneNumber;

      const updatedUser = await user.save();
      res.json({
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
      });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Delete user by ID
// @route   DELETE /api/admin/users/:id
// @access  Private/Admin
const deleteUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (user) {
      // Prevent the admin from deleting their own account
      if (user._id.equals(req.user._id)) {
          return res.status(400).json({ message: 'Cannot delete your own admin account.' });
      }
      await user.deleteOne();
      res.json({ message: 'User removed successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  createStaff,
  getAllUsers,
  getUserById,
  updateUserById,
  deleteUserById
};