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

// Fixed: CSRF protection middleware (Fixes #16)
function csrfProtection(req, res, next) {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) return next();

  const origin = req.headers['origin'];
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');

  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'CSRF validation failed' });
  }
  next();
}

function revokeToken(token) {
  revokedTokens.add(token);
}

module.exports = { authenticateToken, requireRole, csrfProtection, revokeToken, JWT_SECRET };
