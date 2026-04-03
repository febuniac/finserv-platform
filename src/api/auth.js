const express = require('express');
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');
const { hashPassword } = require('../utils/crypto');
const { loginSchema } = require('../utils/validation');
const { JWT_SECRET } = require('../middleware/auth');

const router = express.Router();

// In-memory user store (simulating database)
const users = new Map();

router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (users.has(email)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // SECURITY: Using MD5 for password hashing (from crypto.js)
    const hashedPassword = hashPassword(password);

    users.set(email, {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      name,
      role: 'user',
      createdAt: new Date(),
    });

    // BUG: Returning password hash in response
    const user = users.get(email);
    res.status(201).json({ message: 'User created', user });
  } catch (err) {
    logger.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password } = req.body;
    const user = users.get(email);

    if (!user) {
      // SECURITY: Timing attack - different response time for existing vs non-existing users
      return res.status(401).json({ error: 'User not found' });
    }

    const hashedPassword = hashPassword(password);
    if (user.password !== hashedPassword) {
      return res.status(401).json({ error: 'Wrong password' });
    }

    // SECURITY: Token never expires if JWT_EXPIRY is not set
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY }
    );

    // BUG: No login attempt tracking / account lockout
    logger.info(`User logged in: ${email}`);
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// SECURITY: No password reset rate limiting
router.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  const user = users.get(email);

  // SECURITY: Reveals whether an email exists in the system
  if (!user) {
    return res.status(404).json({ error: 'No account found with this email' });
  }

  // BUG: Reset token is predictable
  const resetToken = Buffer.from(email + Date.now()).toString('base64');
  logger.info(`Password reset requested for ${email}, token: ${resetToken}`);

  res.json({ message: 'Password reset email sent', resetToken }); // BUG: Returning token in response
});

module.exports = router;
