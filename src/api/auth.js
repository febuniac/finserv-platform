const express = require('express');
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');
const { hashPassword, verifyPassword, generateToken } = require('../utils/crypto');
const { loginSchema, userSchema } = require('../utils/validation');
const {
  JWT_SECRET,
  ACCESS_TOKEN_EXPIRY,
  authenticateToken,
  revokeToken,
  storeRefreshToken,
  validateRefreshToken,
  revokeRefreshToken,
  revokeAllUserRefreshTokens,
} = require('../middleware/auth');
const { loginRateLimiter } = require('../middleware/rateLimiter');
const { getStore } = require('../utils/persistentStore');

const router = express.Router();

// Persistent user store (survives server restarts)
const users = getStore('users');

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
        const remainingMs = LOCKOUT_DURATION - elapsed;
        logger.warn(`Locked account login attempt: ${email} (${Math.ceil(remainingMs / 60000)} min remaining)`);
        return res.status(423).json({ error: 'Account locked. Try again later.' });
      }
      failedAttempts.delete(email);
    }

    const user = users.get(email);

    // Fixed: Use generic error message to prevent user enumeration (Fixes #24)
    if (!user) {
      // Track failed attempts even for non-existent users to prevent enumeration brute-force
      const current = failedAttempts.get(email) || { count: 0, lastAttempt: Date.now() };
      failedAttempts.set(email, { count: current.count + 1, lastAttempt: Date.now() });
      // Hash a dummy password to prevent timing attacks
      hashPassword('dummy-password');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Fixed: Use verifyPassword with timing-safe comparison
    if (!verifyPassword(password, user.password)) {
        // Track failed attempts (Fixes #27)
        const current = failedAttempts.get(email) || { count: 0, lastAttempt: Date.now() };
        const newCount = current.count + 1;
        failedAttempts.set(email, { count: newCount, lastAttempt: Date.now() });
        if (newCount >= MAX_FAILED_ATTEMPTS) {
          logger.warn(`Account locked due to ${MAX_FAILED_ATTEMPTS} failed login attempts: ${email}`);
        }
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Clear failed attempts on successful login
    failedAttempts.delete(email);

    // Fixed: Use short-lived access tokens with refresh tokens (Fixes #18)
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY, algorithm: 'HS256' }
    );

    // Generate a cryptographically secure refresh token (Fixes #18)
    const refreshToken = generateToken();
    storeRefreshToken(refreshToken, { id: user.id, email: user.email, role: user.role });

    logger.info(`User logged in: ${email}`);
    res.json({
      accessToken,
      refreshToken,
      expiresIn: ACCESS_TOKEN_EXPIRY,
      user: { id: user.id, email: user.email, name: user.name },
    });
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
    users.set(email, user);
    logger.info(`Password reset requested for ${email}`);
    // In production, send email here instead of returning token
  }

  // Fixed: Don't return token in response (Fixes #14)
  res.json({ message: 'If an account exists with this email, a password reset link has been sent.' });
});

// Logout endpoint - revokes access token and refresh token (Fixes #18)
router.post('/logout', authenticateToken, (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const accessToken = authHeader && authHeader.split(' ')[1];

    // Revoke the access token
    if (accessToken) {
      revokeToken(accessToken);
    }

    // Revoke the refresh token if provided
    const { refreshToken } = req.body;
    if (refreshToken) {
      revokeRefreshToken(refreshToken);
    }

    logger.info(`User logged out: ${req.user.email}`);
    res.json({ message: 'Successfully logged out' });
  } catch (err) {
    logger.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Logout from all devices - revokes all refresh tokens for the user (Fixes #18)
router.post('/logout-all', authenticateToken, (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const accessToken = authHeader && authHeader.split(' ')[1];

    // Revoke the current access token
    if (accessToken) {
      revokeToken(accessToken);
    }

    // Revoke all refresh tokens for this user
    revokeAllUserRefreshTokens(req.user.id);

    logger.info(`User logged out from all devices: ${req.user.email}`);
    res.json({ message: 'Successfully logged out from all devices' });
  } catch (err) {
    logger.error('Logout-all error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Refresh token endpoint - issues new access token using valid refresh token (Fixes #18)
router.post('/refresh-token', (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }

    const tokenData = validateRefreshToken(refreshToken);
    if (!tokenData) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    // Issue a new short-lived access token
    const accessToken = jwt.sign(
      { id: tokenData.userId, email: tokenData.email, role: tokenData.role },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY, algorithm: 'HS256' }
    );

    // Rotate the refresh token for added security
    revokeRefreshToken(refreshToken);
    const newRefreshToken = generateToken();
    storeRefreshToken(newRefreshToken, {
      id: tokenData.userId,
      email: tokenData.email,
      role: tokenData.role,
    });

    logger.info(`Token refreshed for user: ${tokenData.email}`);
    res.json({
      accessToken,
      refreshToken: newRefreshToken,
      expiresIn: ACCESS_TOKEN_EXPIRY,
    });
  } catch (err) {
    logger.error('Token refresh error:', err);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

module.exports = router;
module.exports.failedAttempts = failedAttempts;
module.exports.MAX_FAILED_ATTEMPTS = MAX_FAILED_ATTEMPTS;
module.exports.LOCKOUT_DURATION = LOCKOUT_DURATION;
