const express = require('express');
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');
const { hashPassword, verifyPassword, generateToken } = require('../utils/crypto');
const { loginSchema, userSchema } = require('../utils/validation');
const { JWT_SECRET } = require('../middleware/auth');
const { loginRateLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// In-memory user store (simulating database)
const users = new Map();

// Account lockout tracking (Fixes #27)
const failedAttempts = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

router.post('/register', async (req, res) => {
  try {
    const { error: validationError } = userSchema.validate(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError.details[0].message });
    }

    const { email, password, name } = req.body;

    if (users.has(email)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Fixed: Using scrypt for password hashing (Fixes #3)
    const hashedPassword = hashPassword(password);

    users.set(email, {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      name,
      role: 'user',
      createdAt: new Date(),
    });

    // Fixed: Don't return password hash in response (Fixes #35)
    const user = users.get(email);
    const { password: _, ...safeUser } = user;
    res.status(201).json({ message: 'User created', user: safeUser });
  } catch (err) {
    logger.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', loginRateLimiter, async (req, res) => {
  try {
    const { error: validationError } = loginSchema.validate(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError.details[0].message });
    }

    const { email, password } = req.body;

    // Fixed: Check account lockout (Fixes #27)
    const attempts = failedAttempts.get(email);
    if (attempts && attempts.count >= MAX_FAILED_ATTEMPTS) {
      const elapsed = Date.now() - attempts.lastAttempt;
      if (elapsed < LOCKOUT_DURATION) {
        return res.status(423).json({ error: 'Account locked. Try again later.' });
      }
      failedAttempts.delete(email);
    }

    const user = users.get(email);

    // Fixed: Use generic error message to prevent user enumeration (Fixes #24)
    if (!user) {
      // Hash a dummy password to prevent timing attacks
      hashPassword('dummy-password');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Fixed: Use verifyPassword with timing-safe comparison
    if (!verifyPassword(password, user.password)) {
      // Track failed attempts (Fixes #27)
      const current = failedAttempts.get(email) || { count: 0 };
      failedAttempts.set(email, { count: current.count + 1, lastAttempt: Date.now() });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Clear failed attempts on successful login
    failedAttempts.delete(email);

    // Fixed: Default expiry of 1h if JWT_EXPIRY not set
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY || '1h', algorithm: 'HS256' }
    );

    logger.info(`User logged in: ${email}`);
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Fixed: Rate-limited password reset with generic response (Fixes #14, #24)
router.post('/reset-password', loginRateLimiter, async (req, res) => {
  const { email } = req.body;

  // Fixed: Always return same response regardless of whether email exists (Fixes #24)
  // Fixed: Use cryptographically secure token (Fixes #14)
  const user = users.get(email);
  if (user) {
    const resetToken = generateToken();
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
    logger.info(`Password reset requested for ${email}`);
    // In production, send email here instead of returning token
  }

  // Fixed: Don't return token in response (Fixes #14)
  res.json({ message: 'If an account exists with this email, a password reset link has been sent.' });
});

module.exports = router;
