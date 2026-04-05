const xss = require('xss');

// Configure xss with strict settings - strip all HTML tags
const xssOptions = {
  whiteList: {},          // No tags allowed
  stripIgnoreTag: true,   // Strip all unrecognized tags
  stripIgnoreTagBody: ['script', 'style'], // Remove script/style content entirely
};

/**
 * Sanitize a single string value to prevent stored XSS.
 * Returns the sanitized string, or the original value if not a string.
 */
function sanitizeString(value) {
  if (typeof value !== 'string') {
    return value;
  }
  return xss(value, xssOptions);
}

/**
 * Sanitize all string values in an object (shallow).
 * Non-string values are left unchanged.
 */
function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    sanitized[key] = sanitizeString(value);
  }
  return sanitized;
}

module.exports = { sanitizeString, sanitizeObject };
