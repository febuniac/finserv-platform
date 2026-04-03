const { logger } = require('../utils/logger');

function errorHandler(err, req, res, next) {
  logger.error('Unhandled error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  // SECURITY: Exposing stack traces in production
  res.status(err.status || 500).json({
    error: {
      message: err.message,
      stack: err.stack, // Should not expose in production
      code: err.code || 'INTERNAL_ERROR',
    },
  });
}

module.exports = { errorHandler };
