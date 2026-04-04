const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');

// Fixed: Require JWT_SECRET in production, use secure random fallback in dev (Fixes #7)
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET must be set in production');
  }
  logger.warn('Using auto-generated JWT secret - set JWT_SECRET env var for production');
  return crypto.randomBytes(32).toString('hex');
})();

// Short-lived access tokens (15 min) with refresh tokens (7 days) (Fixes #18)
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY_MS = parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS || '7', 10) * 24 * 60 * 60 * 1000;

// Token blacklist for revocation with expiry tracking (Fixes #18)
// Maps token -> expiry timestamp so we can clean up expired entries
const revokedTokens = new Map();

// Refresh token store: maps refreshToken -> { userId, email, role, expiresAt } (Fixes #18)
const refreshTokens = new Map();

// Periodic cleanup of expired entries to prevent memory leaks (Fixes #18)
const CLEANUP_INTERVAL_MS = 60 * 1000; // 1 minute
let _cleanupTimer = null;

function _startCleanupTimer() {
  if (_cleanupTimer) return;
  _cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [token, expiresAt] of revokedTokens.entries()) {
      if (now > expiresAt) {
        revokedTokens.delete(token);
      }
    }
    for (const [token, data] of refreshTokens.entries()) {
      if (now > data.expiresAt) {
        refreshTokens.delete(token);
      }
    }
  }, CLEANUP_INTERVAL_MS);
  // Allow the process to exit without waiting for the timer
  if (_cleanupTimer.unref) _cleanupTimer.unref();
}

_startCleanupTimer();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // Check if token has been revoked (Fixes #18)
  if (revokedTokens.has(token)) {
    logger.warn('Revoked token used in request');
    return res.status(401).json({ error: 'Token has been revoked' });
  }

  try {
    // Fixed: Specify allowed algorithms to prevent algorithm confusion (Fixes #22)
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.user = decoded;
    next();
  } catch (err) {
    // Fixed: Distinguish between expired and invalid tokens
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    logger.warn('Token verification failed', { error: err.message });
    return res.status(403).json({ error: 'Invalid token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Fixed: CSRF protection middleware using double-submit cookie pattern (Fixes #16)
// Generates a cryptographic CSRF token, sets it as a cookie, and validates
// that state-changing requests include the matching token in the X-CSRF-Token header.
// Also validates Origin/Referer headers as a secondary defense layer.

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(pair => {
    const [name, ...rest] = pair.trim().split('=');
    if (name) cookies[name.trim()] = rest.join('=').trim();
  });
  return cookies;
}

function csrfProtection(req, res, next) {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];

  // For safe methods, issue a CSRF token cookie if one is not already present
  if (safeMethods.includes(req.method)) {
    const cookies = parseCookies(req.headers.cookie);
    if (!cookies['_csrf_token']) {
      const token = generateCsrfToken();
      res.cookie('_csrf_token', token, {
        httpOnly: false,   // Client JS needs to read this for the header
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        path: '/',
      });
    }
    return next();
  }

  // --- State-changing request (POST, PUT, DELETE, PATCH) ---

  // 1. Origin / Referer validation
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  const origin = req.headers['origin'];
  const referer = req.headers['referer'];

  if (origin) {
    if (!allowedOrigins.includes(origin)) {
      logger.warn(`CSRF origin mismatch: ${origin}`);
      return res.status(403).json({ error: 'CSRF validation failed: origin not allowed' });
    }
  } else if (referer) {
    // Fall back to Referer when Origin is absent
    try {
      const refererOrigin = new URL(referer).origin;
      if (!allowedOrigins.includes(refererOrigin)) {
        logger.warn(`CSRF referer mismatch: ${referer}`);
        return res.status(403).json({ error: 'CSRF validation failed: referer not allowed' });
      }
    } catch {
      return res.status(403).json({ error: 'CSRF validation failed: invalid referer' });
    }
  } else {
    // Neither Origin nor Referer present – block the request
    logger.warn('CSRF validation failed: no origin or referer header');
    return res.status(403).json({ error: 'CSRF validation failed: missing origin' });
  }

  // 2. Double-submit cookie validation
  const cookies = parseCookies(req.headers.cookie);
  const cookieToken = cookies['_csrf_token'];
  const headerToken = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken) {
    logger.warn('CSRF token missing from cookie or header');
    return res.status(403).json({ error: 'CSRF validation failed: missing token' });
  }

  // Constant-time comparison to prevent timing attacks
  if (cookieToken.length !== headerToken.length ||
      !crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))) {
    logger.warn('CSRF token mismatch');
    return res.status(403).json({ error: 'CSRF validation failed: token mismatch' });
  }

  next();
}

function revokeToken(token) {
  try {
    // Decode (without verifying) to get the expiry so we can auto-clean later
    const decoded = jwt.decode(token);
    const expiresAt = decoded && decoded.exp ? decoded.exp * 1000 : Date.now() + 3600000;
    revokedTokens.set(token, expiresAt);
  } catch {
    // If we can't decode, still blacklist with a 1-hour default TTL
    revokedTokens.set(token, Date.now() + 3600000);
  }
}

function storeRefreshToken(refreshToken, userData) {
  refreshTokens.set(refreshToken, {
    userId: userData.id,
    email: userData.email,
    role: userData.role,
    expiresAt: Date.now() + REFRESH_TOKEN_EXPIRY_MS,
  });
}

function validateRefreshToken(refreshToken) {
  const data = refreshTokens.get(refreshToken);
  if (!data) return null;
  if (Date.now() > data.expiresAt) {
    refreshTokens.delete(refreshToken);
    return null;
  }
  return data;
}

function revokeRefreshToken(refreshToken) {
  return refreshTokens.delete(refreshToken);
}

function revokeAllUserRefreshTokens(userId) {
  for (const [token, data] of refreshTokens.entries()) {
    if (data.userId === userId) {
      refreshTokens.delete(token);
    }
  }
}

// Exposed for testing
function _getRevokedTokens() {
  return revokedTokens;
}

function _getRefreshTokens() {
  return refreshTokens;
}

function _stopCleanupTimer() {
  if (_cleanupTimer) {
    clearInterval(_cleanupTimer);
    _cleanupTimer = null;
  }
}

module.exports = {
  authenticateToken,
  requireRole,
  csrfProtection,
  revokeToken,
  storeRefreshToken,
  validateRefreshToken,
  revokeRefreshToken,
  revokeAllUserRefreshTokens,
  JWT_SECRET,
  ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY_MS,
  _getRevokedTokens,
  _getRefreshTokens,
  _stopCleanupTimer,
};
