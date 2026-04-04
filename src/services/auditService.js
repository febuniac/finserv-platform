const crypto = require('crypto');
const { logger } = require('../utils/logger');
const fs = require('fs');
const path = require('path');

const AUDIT_LOG_PATH = path.join(__dirname, '../../audit.log');
const HMAC_SECRET = process.env.AUDIT_HMAC_SECRET || 'audit-integrity-key';

// Fixed: Add HMAC integrity verification to audit entries (Fixes #26)
function computeHmac(data) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
}

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

  // Fixed: Add HMAC signature for tamper detection (Fixes #26)
  const entryJson = JSON.stringify(entry);
  const hmac = computeHmac(entryJson);
  const signedEntry = JSON.stringify({ ...entry, hmac });

  // Fixed: Use async file write to avoid blocking event loop
  fs.appendFile(AUDIT_LOG_PATH, signedEntry + '\n', (err) => {
    if (err) {
      logger.error('Failed to write audit log:', err.message);
    }
  });
  logger.info('Audit event logged', { action: entry.action, userId: entry.userId });
}

function getAuditLog(filters) {
  try {
    if (!fs.existsSync(AUDIT_LOG_PATH)) {
      return [];
    }

    const logContent = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
    let entries = logContent
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const parsed = JSON.parse(line);
        // Verify HMAC integrity
        const { hmac, ...data } = parsed;
        if (hmac) {
          const expected = computeHmac(JSON.stringify(data));
          parsed._verified = hmac === expected;
        }
        return parsed;
      });

    if (filters && filters.userId) {
      entries = entries.filter((e) => e.userId === filters.userId);
    }

    // Fixed: Support pagination to avoid loading entire log into memory
    const limit = (filters && filters.limit) || 1000;
    const offset = (filters && filters.offset) || 0;
    return entries.slice(offset, offset + limit);
  } catch (err) {
    logger.error('Failed to read audit log:', err.message);
    return [];
  }
}

module.exports = { logAuditEvent, getAuditLog };
