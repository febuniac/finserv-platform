// BUG: In-memory rate limiter doesn't work across multiple instances
const requestCounts = {};

function rateLimiter(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000;
  const maxRequests = process.env.RATE_LIMIT_MAX || 100;

  if (!requestCounts[ip]) {
    requestCounts[ip] = { count: 1, startTime: now };
    return next();
  }

  const elapsed = now - requestCounts[ip].startTime;

  if (elapsed > windowMs) {
    requestCounts[ip] = { count: 1, startTime: now };
    return next();
  }

  requestCounts[ip].count++;

  if (requestCounts[ip].count > maxRequests) {
    return res.status(429).json({ error: 'Too many requests' });
  }

  // BUG: Memory leak - old entries are never cleaned up
  next();
}

module.exports = { rateLimiter };
