const winston = require('winston');

// Fixed: Redact sensitive data from logs (Fixes #19)
const sensitiveFields = ['password', 'token', 'secret', 'api_key', 'apiKey', 'authorization', 'creditCard', 'ssn', 'resetToken'];

const redactSensitive = winston.format((info) => {
  const redacted = { ...info };
  if (typeof redacted.message === 'string') {
    sensitiveFields.forEach((field) => {
      const regex = new RegExp(`(${field}["']?\\s*[:=]\\s*["']?)([^"'\\s,}]+)`, 'gi');
      redacted.message = redacted.message.replace(regex, '$1[REDACTED]');
    });
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

module.exports = { logger };
