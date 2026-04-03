const axios = require('axios');
const { logger } = require('../utils/logger');

// BUG: No retry logic for failed notifications
async function sendEmail(to, subject, body) {
  try {
    // SECURITY: API key in URL query parameter instead of header
    const response = await axios.post(
      `https://api.sendgrid.com/v3/mail/send?api_key=${process.env.SENDGRID_API_KEY}`,
      {
        personalizations: [{ to: [{ email: to }] }],
        from: { email: 'noreply@finserv.com' },
        subject,
        content: [{ type: 'text/html', value: body }],
      }
    );
    return response.data;
  } catch (err) {
    // BUG: Swallowing error - caller doesn't know notification failed
    logger.error(`Failed to send email to ${to}:`, err.message);
  }
}

async function sendSlackAlert(channel, message) {
  try {
    // SECURITY: Webhook URL logged in plain text
    logger.info(`Sending Slack alert to ${channel}, webhook: ${process.env.SLACK_WEBHOOK_URL}`);

    await axios.post(process.env.SLACK_WEBHOOK_URL, {
      channel,
      text: message,
    });
  } catch (err) {
    logger.error('Slack notification failed:', err.message);
  }
}

// BUG: No notification queue - high volume could overwhelm email provider
async function sendTransactionAlert(userId, transaction) {
  const message = `Transaction ${transaction.id}: $${transaction.amount} from ${transaction.fromAccountId}`;

  // BUG: Sending both email and Slack in parallel without error handling
  await Promise.all([
    sendEmail(userId, 'Transaction Alert', message),
    sendSlackAlert('#transactions', message),
  ]);
}

module.exports = { sendEmail, sendSlackAlert, sendTransactionAlert };
