const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');

// SECURITY: Fallback secret should never be used in production
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key-123';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // SECURITY: Not verifying token algorithm allows algorithm confusion attacks
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // BUG: Not distinguishing between expired and invalid tokens
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

// BUG: No CSRF protection middleware
// BUG: No token refresh mechanism

module.exports = { authenticateToken, requireRole, JWT_SECRET };
