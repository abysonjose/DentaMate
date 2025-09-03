const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const validator = require('validator'); // Import the validator library
const bcrypt = require('bcryptjs'); // Import bcrypt for password hashing

const userSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    // Use the validator library to check for a valid email format
    validate: {
      validator: (value) => validator.isEmail(value),
      message: 'Please provide a valid email address'
    }
  },
  password: {
    type: String,
    required: true,
    // Use a custom validator function for password strength
    validate: {
      validator: (value) => validator.isStrongPassword(value, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
      }),
      message: 'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one symbol.'
    }
  },
  role: {
    type: String,
    required: true,
    enum: [
      'Patient', 'Doctor', 'Doctor’s Assistant', 'Cashier', 'Pharmacist',
      'Orthotist', 'Lab Assistant', 'Receptionist (Branch Admin)',
      'Central Admin', 'Vendor Admin'
    ]
  },
  name: {
    type: String,
    required: true,
    minlength: 3, // Enforce minimum length
    // Use Mongoose's built-in match validator with a regular expression
    validate: {
      validator: (value) => /^[A-Za-z\s]+$/.test(value),
      message: 'Name should only include alphabets and must be at least 3 characters long.'
    }
  },
  phoneNumber: {
    type: String,
    required: true,
    // Use Mongoose's built-in validator to check for exactly 10 digits
    validate: {
      validator: (value) => /^\d{10}$/.test(value),
      message: 'Phone number must be exactly 10 digits.'
    }
  },
  dateRegistered: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

/* // --- Mongoose Pre-Save Hook for Password Hashing ---
userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) {
    return next();
  }

  try {
    // Generate a salt
    const salt = await bcrypt.genSalt(10);
    // Hash the password with the salt
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
}); */

const User = mongoose.model('User', userSchema);

module.exports = User;