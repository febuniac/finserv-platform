const requestCounts = new Map();
const loginAttempts = new Map();

// Fixed: Periodic cleanup of expired entries to prevent memory leak (Fixes #12)
setInterval(() => {
  const now = Date.now();
  const windowMs = (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000;
  for (const [ip, data] of requestCounts.entries()) {
    if (now - data.startTime > windowMs) {
      requestCounts.delete(ip);
    }
  }
  for (const [key, data] of loginAttempts.entries()) {
    if (now - data.startTime > LOGIN_RATE_LIMIT_WINDOW_MS) {
      loginAttempts.delete(key);
    }
  }
}, 60 * 1000);

function rateLimiter(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000;
  const maxRequests = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, startTime: now });
    return next();
  }

  const entry = requestCounts.get(ip);
  const elapsed = now - entry.startTime;

  if (elapsed > windowMs) {
    requestCounts.set(ip, { count: 1, startTime: now });
    return next();
  }

  entry.count++;

  if (entry.count > maxRequests) {
    return res.status(429).json({ error: 'Too many requests' });
  }

  next();
}

// Fixed: Stricter rate limiting for login endpoint (Fixes #17)
// Max 5 attempts per minute per IP to prevent brute force attacks
const LOGIN_RATE_LIMIT_WINDOW_MS = parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS || String(60 * 1000), 10); // 1 minute
const LOGIN_RATE_LIMIT_MAX = parseInt(process.env.LOGIN_RATE_LIMIT_MAX || '5', 10);

function loginRateLimiter(req, res, next) {
  const ip = req.ip;
  const now = Date.now();

  const key = `login:${ip}`;
  if (!loginAttempts.has(key)) {
    loginAttempts.set(key, { count: 1, startTime: now });
    return next();
  }

  const entry = loginAttempts.get(key);
  const elapsed = now - entry.startTime;

  if (elapsed > LOGIN_RATE_LIMIT_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, startTime: now });
    return next();
  }

  entry.count++;

  if (entry.count > LOGIN_RATE_LIMIT_MAX) {
    const retryAfterSec = Math.ceil((LOGIN_RATE_LIMIT_WINDOW_MS - elapsed) / 1000);
    res.set('Retry-After', String(retryAfterSec));
    return res.status(429).json({
      error: 'Too many login attempts. Please try again later.',
    });
  }

  next();
}

module.exports = { rateLimiter, loginRateLimiter, loginAttempts, LOGIN_RATE_LIMIT_WINDOW_MS, LOGIN_RATE_LIMIT_MAX };
