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

// Token blacklist for revocation (Fixes #18)
const revokedTokens = new Set();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // Check if token has been revoked (Fixes #18)
  if (revokedTokens.has(token)) {
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
  revokedTokens.add(token);
}

module.exports = { authenticateToken, requireRole, csrfProtection, revokeToken, JWT_SECRET };
