const jwt = require('jsonwebtoken');
const User = require('../models/User.js');

// Middleware to protect routes by checking for a valid token
const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      // Get token from header (e.g., "Bearer eyJhbGci...")
      token = req.headers.authorization.split(' ')[1];

      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Get user from the token's ID and attach it to the request object
      req.user = await User.findById(decoded.id).select('-password');
      
      next(); // Move on to the next step
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

// Middleware to authorize based on role
const authorizeAdmin = (req, res, next) => {
    // We check the user object that was attached in the 'protect' middleware
    if (req.user && req.user.role === 'Central Admin') {
        next();
    } else {
        res.status(403).json({ message: 'Not authorized as an admin' }); // 403 Forbidden
    }
};

module.exports = { protect, authorizeAdmin };