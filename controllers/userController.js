const User = require('../models/User.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault() // Or use service account JSON
  });
}

const googleLogin = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ message: 'ID token is required' });
    }

    // Verify Firebase ID token
    const decoded = await admin.auth().verifyIdToken(idToken);

    // Check if user exists in DB
    let user = await User.findOne({ email: decoded.email });
    if (!user) {
      // Create a new user (no password since Google handles it)
      user = new User({
        name: decoded.name || 'Google User',
        email: decoded.email,
        password: 'google-auth', // Dummy password to satisfy schema
        role: 'Patient', // Default role
        phoneNumber: '0000000000' // Placeholder, can be updated later
      });

      await user.save();
    }

    // Create JWT for your backend
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token
    });

  } catch (error) {
    console.error(error);
    res.status(401).json({ message: 'Invalid Firebase token', error: error.message });
  }
};


// @desc    Register a new user
// @route   POST /api/users/register
// @access  Public
const registerUser = async (req, res) => {
  try {
    // 1. Get user data from the request body. Notice we don't extract 'role'.
    const { name, email, password, phoneNumber } = req.body;

    // 2. Check if the user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    // 3. Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

 // 4. Create a new user instance, HARDCODING the role to 'Patient'
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: 'Patient', // The role is now hardcoded and not taken from user input
      phoneNumber
    });

    // 5. Save the user to the database
    const createdUser = await user.save();

    // 6. Send a response back
    res.status(201).json({
      _id: createdUser._id,
      name: createdUser.name,
      email: createdUser.email,
      role: createdUser.role,
      message: 'User registered successfully!'
    });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Authenticate a user & get token
// @route   POST /api/users/login
// @access  Public
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check for user by email
    const user = await User.findOne({ email });
 /*    console.log("user:", user); // Debugging line to check if user is found

    console.log("password:", password);
    console.log("hashed password:", user.password);
    console.log("password match:", await bcrypt.compare(password, user.password)); */
    // If user exists and password matches, send back user data and a token
    if (user && (await bcrypt.compare(password, user.password))) {
      res.json({
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        token: jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
          expiresIn: '1d', // Token expires in 1 day
        }),
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Get user profile
// @route   GET /api/users/profile
// @access  Private
const getUserProfile = async (req, res) => {
  try {
    // The 'protect' middleware already found the user and attached it to the request.
    const user = await User.findById(req.user._id);

    if (user) {
      res.json({
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        phoneNumber: user.phoneNumber,
      });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Update user profile
// @route   PUT /api/users/profile
// @access  Private
const updateUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (user) {
      // Update the fields if they are provided in the request body
      user.name = req.body.name || user.name;
      user.phoneNumber = req.body.phoneNumber || user.phoneNumber;

      // Check if a new password is provided and update it
      if (req.body.password) {
        // Note: The pre-save hook in User.js will automatically hash this
        user.password = req.body.password;
      }

      const updatedUser = await user.save();

      res.json({
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        phoneNumber: updatedUser.phoneNumber,
        message: 'Profile updated successfully!'
      });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    // Handle validation errors specifically
    if (error.name === 'ValidationError') {
        return res.status(400).json({ message: error.message });
    }
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Delete user profile
// @route   DELETE /api/users/profile
// @access  Private
const deleteUserProfile = async (req, res) => {
  try {
    // Find the user by the ID from the token
    const user = await User.findById(req.user._id);

    if (user) {
      await user.deleteOne(); // Mongoose 6+ uses deleteOne() on the document
      res.json({ message: 'User account deleted successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  registerUser,
  loginUser,
  googleLogin,
  getUserProfile,
  updateUserProfile,
  deleteUserProfile
};