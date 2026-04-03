const { logger } = require('../utils/logger');
const fs = require('fs');
const path = require('path');

// BUG: Audit log written to local file instead of centralized logging system
const AUDIT_LOG_PATH = path.join(__dirname, '../../audit.log');

function logAuditEvent(event) {
  const entry = {
    timestamp: new Date().toISOString(),
    userId: event.userId,
    action: event.action,
    resource: event.resource,
    details: event.details,
    ip: event.ip,
    userAgent: event.userAgent,
  };

  // BUG: Synchronous file write blocks event loop
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(entry) + '\n');
  logger.info('Audit event logged:', entry);
}

// BUG: No log rotation - file grows indefinitely
// BUG: No integrity verification (HMAC/signature) on audit entries
// BUG: Audit logs can be modified by application since it has write access

function getAuditLog(filters) {
  try {
    const logContent = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
    const entries = logContent
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));

    // BUG: Loading entire audit log into memory
    if (filters.userId) {
      return entries.filter((e) => e.userId === filters.userId);
    }

    return entries;
  } catch (err) {
    // BUG: Returns empty array on error, hiding read failures
    return [];
  }
}

module.exports = { logAuditEvent, getAuditLog };
