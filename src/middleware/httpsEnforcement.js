const { logger } = require('../utils/logger');

/**
 * Middleware to enforce HTTPS in production.
 *
 * Behind a reverse-proxy / load-balancer the original protocol arrives in the
 * `x-forwarded-proto` header.  When the request was made over plain HTTP we
 * respond with a 301 redirect to the HTTPS equivalent and log the event.
 *
 * In non-production environments the middleware is a no-op so that local
 * development over HTTP is not affected.
 */
function httpsEnforcement(req, res, next) {
  if (process.env.NODE_ENV !== 'production') {
    return next();
  }

  const proto = req.headers['x-forwarded-proto'];
  if (proto && proto !== 'https') {
    const host = req.headers.host || '';
    const redirectUrl = `https://${host}${req.url}`;
    logger.warn('Redirecting insecure HTTP request to HTTPS', {
      originalUrl: req.url,
      host,
    });
    return res.redirect(301, redirectUrl);
  }

  next();
}

module.exports = { httpsEnforcement };
