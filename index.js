// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

// Initialize the Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// --- Database Connection ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Successfully connected to MongoDB! 💾'))
  .catch(err => console.error('Connection error', err));
// -------------------------

// Define the port to run on
const PORT = process.env.PORT || 3000;

// --- Import Routes ---
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');

// A simple test route
app.get('/', (req, res) => {
  res.send('User Microservice is running! ✅');
});

// --- Use Routes ---
// This tells the app to use the userRoutes for any URL starting with /api/users
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);

// Start the server
app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});