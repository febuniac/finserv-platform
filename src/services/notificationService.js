const https = require('https');
const axios = require('axios');
const { logger } = require('../utils/logger');
const { generateSecureResetLink } = require('../utils/crypto');

// Enforce TLS 1.2+ for all outbound HTTPS requests (Fixes #28)
const tlsAgent = new https.Agent({
  minVersion: 'TLSv1.2',
  rejectUnauthorized: true,
});

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000;

/**
 * Retry a function up to maxRetries times with exponential backoff.
 */
async function withRetry(fn, maxRetries = MAX_RETRIES) {
  let lastErr;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt < maxRetries) {
        const delay = RETRY_DELAY_MS * Math.pow(2, attempt - 1);
        logger.warn(`Retry attempt ${attempt}/${maxRetries} after ${delay}ms`);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
  throw lastErr;
}

async function sendEmail(to, subject, body) {
  return withRetry(async () => {
    try {
      const response = await axios.post(
        'https://api.sendgrid.com/v3/mail/send',
        {
          personalizations: [{ to: [{ email: to }] }],
          from: { email: 'noreply@finserv.com' },
          subject,
          content: [{ type: 'text/html', value: body }],
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.SENDGRID_API_KEY}`,
            'Content-Type': 'application/json',
          },
          httpsAgent: tlsAgent,
        }
      );
      return response.data;
    } catch (err) {
      logger.error(`Failed to send email to ${to}:`, err.message);
      throw err;
    }
  });
}

async function sendSlackAlert(channel, message) {
  return withRetry(async () => {
    try {
      logger.info(`Sending Slack alert to ${channel}`);

      await axios.post(
        process.env.SLACK_WEBHOOK_URL,
        { channel, text: message },
        { httpsAgent: tlsAgent }
      );
    } catch (err) {
      logger.error('Slack notification failed:', err.message);
      throw err;
    }
  });
}

/**
 * Send a password reset email with a time-limited, HMAC-signed link
 * instead of exposing the raw reset token. (Fixes #28)
 *
 * @param {string} email - Recipient email address
 * @param {number} [ttlMs] - Optional link TTL in milliseconds
 */
async function sendPasswordResetEmail(email, ttlMs) {
  const { link, expiresAt } = generateSecureResetLink(email, ttlMs);
  const expiryMinutes = Math.round((expiresAt - Date.now()) / 60000);

  const body = [
    '<h2>Password Reset Request</h2>',
    '<p>You requested a password reset for your FinServ account.</p>',
    `<p><a href="${link}">Reset your password</a></p>`,
    `<p>This link expires in ${expiryMinutes} minutes. If you did not request this, ignore this email.</p>`,
    '<p><em>Do not share this link with anyone.</em></p>',
  ].join('');

  await sendEmail(email, 'FinServ Password Reset', body);
  logger.info(`Password reset link sent to ${email} (expires in ${expiryMinutes}m)`);
}

async function sendTransactionAlert(userId, transaction) {
  // Don't include full account IDs in notifications (Fixes #28)
  const maskedFrom = transaction.fromAccountId.slice(-4);
  const message = `Transaction ${transaction.id}: $${transaction.amount} from account ...${maskedFrom}`;

  const results = await Promise.allSettled([
    sendEmail(userId, 'Transaction Alert', message),
    sendSlackAlert('#transactions', message),
  ]);

  const failures = results.filter((r) => r.status === 'rejected');
  if (failures.length > 0) {
    logger.warn(`${failures.length} notification(s) failed for transaction ${transaction.id}`);
  }
}

module.exports = { sendEmail, sendSlackAlert, sendPasswordResetEmail, sendTransactionAlert };
