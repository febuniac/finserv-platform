const axios = require('axios');
const { logger } = require('../utils/logger');

// BUG: No retry logic for failed notifications
async function sendEmail(to, subject, body) {
  try {
    // Fixed: API key in Authorization header instead of URL param (Fixes #28)
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
      }
    );
    return response.data;
  } catch (err) {
    // Fixed: Re-throw so caller knows notification failed
    logger.error(`Failed to send email to ${to}:`, err.message);
    throw err;
  }
}

async function sendSlackAlert(channel, message) {
  try {
    // Fixed: Don't log webhook URL (Fixes #19, #28)
    logger.info(`Sending Slack alert to ${channel}`);

    await axios.post(process.env.SLACK_WEBHOOK_URL, {
      channel,
      text: message,
    });
  } catch (err) {
    logger.error('Slack notification failed:', err.message);
    throw err;
  }
}

async function sendTransactionAlert(userId, transaction) {
  // Fixed: Don't include full account IDs in notifications (Fixes #28)
  const maskedFrom = transaction.fromAccountId.slice(-4);
  const message = `Transaction ${transaction.id}: $${transaction.amount} from account ...${maskedFrom}`;

  // Fixed: Handle errors from each notification independently
  const results = await Promise.allSettled([
    sendEmail(userId, 'Transaction Alert', message),
    sendSlackAlert('#transactions', message),
  ]);

  const failures = results.filter((r) => r.status === 'rejected');
  if (failures.length > 0) {
    logger.warn(`${failures.length} notification(s) failed for transaction ${transaction.id}`);
  }
}

module.exports = { sendEmail, sendSlackAlert, sendTransactionAlert };
