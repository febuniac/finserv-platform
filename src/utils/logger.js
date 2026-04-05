const winston = require('winston');

// Fixed: Redact sensitive data from logs (Fixes #19)
const sensitiveFields = [
  'password', 'token', 'secret', 'api_key', 'apiKey',
  'authorization', 'creditCard', 'credit_card', 'ssn',
  'resetToken', 'reset_token', 'accessToken', 'access_token',
  'refreshToken', 'refresh_token', 'sessionId', 'session_id',
  'cookie', 'pin', 'cvv', 'cardNumber', 'card_number',
];

// Redact email addresses from strings
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

function redactString(str) {
  let result = str;
  // Redact sensitive key-value patterns (supports both quoted and unquoted values)
  sensitiveFields.forEach((field) => {
    // Match quoted values (captures everything inside quotes)
    const quotedRegex = new RegExp(`(${field}["']?\\s*[:=]\\s*["'])([^"']*?)(["'])`, 'gi');
    result = result.replace(quotedRegex, '$1[REDACTED]$3');
    // Match unquoted values (captures the entire remaining value until delimiter)
    const unquotedRegex = new RegExp(`(${field}\\s*[:=]\\s*)([^\\s,;}"']+(?:\\s+[^\\s,;}"']+)*)`, 'gi');
    result = result.replace(unquotedRegex, '$1[REDACTED]');
  });
  // Redact email addresses
  result = result.replace(EMAIL_REGEX, '[REDACTED_EMAIL]');
  return result;
}

function redactObject(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return redactString(obj);
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(redactObject);

  const redacted = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = sensitiveFields.some(
      (field) => lowerKey === field.toLowerCase() || lowerKey.includes(field.toLowerCase())
    );
    if (isSensitive) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'string') {
      redacted[key] = redactString(value);
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redactObject(value);
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}

const redactSensitive = winston.format((info) => {
  const redacted = { ...info };

  // Redact string messages
  if (typeof redacted.message === 'string') {
    redacted.message = redactString(redacted.message);
  }

  // Redact metadata objects (spread properties beyond level/message/timestamp)
  for (const key of Object.keys(redacted)) {
    if (['level', 'message', 'timestamp'].includes(key)) continue;
    const lowerKey = key.toLowerCase();
    const isSensitive = sensitiveFields.some(
      (field) => lowerKey === field.toLowerCase() || lowerKey.includes(field.toLowerCase())
    );
    if (isSensitive) {
      redacted[key] = '[REDACTED]';
    } else if (typeof redacted[key] === 'string') {
      redacted[key] = redactString(redacted[key]);
    } else if (typeof redacted[key] === 'object' && redacted[key] !== null) {
      redacted[key] = redactObject(redacted[key]);
    }
  }

  return redacted;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    redactSensitive(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

module.exports = { logger, redactString, redactObject, sensitiveFields };
