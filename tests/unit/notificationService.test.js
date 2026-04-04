const https = require('https');
const crypto = require('crypto');

// Mock axios before requiring the module under test
jest.mock('axios');
const axios = require('axios');

// Mock logger to suppress output during tests
jest.mock('../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

const {
  sendEmail,
  sendSlackAlert,
  sendPasswordResetEmail,
  sendTransactionAlert,
} = require('../../src/services/notificationService');

const {
  generateSecureResetLink,
  verifyResetToken,
} = require('../../src/utils/crypto');

describe('notificationService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SENDGRID_API_KEY = 'test-sg-key';
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/test';
  });

  describe('TLS enforcement', () => {
    it('should use TLS 1.2+ httpsAgent for email requests', async () => {
      axios.post.mockResolvedValueOnce({ data: { success: true } });

      await sendEmail('user@test.com', 'Test', '<p>Hello</p>');

      expect(axios.post).toHaveBeenCalledTimes(1);
      const callArgs = axios.post.mock.calls[0];
      const config = callArgs[2];
      expect(config.httpsAgent).toBeDefined();
      expect(config.httpsAgent).toBeInstanceOf(https.Agent);
      expect(config.httpsAgent.options.minVersion).toBe('TLSv1.2');
      expect(config.httpsAgent.options.rejectUnauthorized).toBe(true);
    });

    it('should use TLS 1.2+ httpsAgent for Slack requests', async () => {
      axios.post.mockResolvedValueOnce({ data: 'ok' });

      await sendSlackAlert('#general', 'Test message');

      expect(axios.post).toHaveBeenCalledTimes(1);
      const callArgs = axios.post.mock.calls[0];
      const config = callArgs[2];
      expect(config.httpsAgent).toBeDefined();
      expect(config.httpsAgent.options.minVersion).toBe('TLSv1.2');
    });
  });

  describe('sendEmail', () => {
    it('should send email via SendGrid with proper headers', async () => {
      axios.post.mockResolvedValueOnce({ data: { id: 'msg-1' } });

      const result = await sendEmail('user@test.com', 'Subject', '<p>Body</p>');

      expect(axios.post).toHaveBeenCalledWith(
        'https://api.sendgrid.com/v3/mail/send',
        expect.objectContaining({
          personalizations: [{ to: [{ email: 'user@test.com' }] }],
          subject: 'Subject',
        }),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer test-sg-key',
          }),
        })
      );
      expect(result).toEqual({ id: 'msg-1' });
    });

    it('should retry on failure and succeed on second attempt', async () => {
      axios.post
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({ data: { id: 'msg-2' } });

      const result = await sendEmail('user@test.com', 'Test', '<p>Retry</p>');

      expect(axios.post).toHaveBeenCalledTimes(2);
      expect(result).toEqual({ id: 'msg-2' });
    });

    it('should throw after exhausting all retries', async () => {
      axios.post.mockRejectedValue(new Error('Persistent failure'));

      await expect(
        sendEmail('user@test.com', 'Test', '<p>Fail</p>')
      ).rejects.toThrow('Persistent failure');

      expect(axios.post).toHaveBeenCalledTimes(3);
    });
  });

  describe('sendPasswordResetEmail', () => {
    it('should send a password reset email with a time-limited link', async () => {
      axios.post.mockResolvedValueOnce({ data: { success: true } });

      await sendPasswordResetEmail('user@test.com');

      expect(axios.post).toHaveBeenCalledTimes(1);
      const callArgs = axios.post.mock.calls[0];
      const emailBody = callArgs[1].content[0].value;

      // Should contain a reset link, not a raw token
      expect(emailBody).toContain('Reset your password');
      expect(emailBody).toContain('https://app.finserv.com/reset-password?token=');
      expect(emailBody).toContain('expires in');
      expect(emailBody).not.toMatch(/[a-f0-9]{64}/); // No raw 64-char hex token
    });

    it('should not include raw reset token in the email', async () => {
      axios.post.mockResolvedValueOnce({ data: { success: true } });

      await sendPasswordResetEmail('user@test.com');

      const callArgs = axios.post.mock.calls[0];
      const emailBody = callArgs[1].content[0].value;
      const subject = callArgs[1].subject;

      expect(subject).toBe('FinServ Password Reset');
      // The link should be a base64url-encoded JSON payload, not a raw token
      const linkMatch = emailBody.match(/token=([^"]+)/);
      expect(linkMatch).toBeTruthy();

      // Verify the token is a valid signed payload
      const email = verifyResetToken(linkMatch[1]);
      expect(email).toBe('user@test.com');
    });
  });

  describe('sendTransactionAlert', () => {
    it('should mask account IDs in notifications', async () => {
      axios.post.mockResolvedValue({ data: { success: true } });

      await sendTransactionAlert('user@test.com', {
        id: 'txn-123',
        amount: 500,
        fromAccountId: 'acc-12345678-abcd',
      });

      const emailCallArgs = axios.post.mock.calls[0];
      const emailBody = emailCallArgs[1].content[0].value;

      // Should only show last 4 chars of account ID
      expect(emailBody).toContain('...abcd');
      expect(emailBody).not.toContain('acc-12345678-abcd');
    });
  });
});

describe('crypto - secure reset links', () => {
  describe('generateSecureResetLink', () => {
    it('should generate a link with a signed token', () => {
      const { link, expiresAt } = generateSecureResetLink('user@test.com');

      expect(link).toContain('https://app.finserv.com/reset-password?token=');
      expect(expiresAt).toBeGreaterThan(Date.now());
    });

    it('should respect custom TTL', () => {
      const ttl = 300000; // 5 minutes
      const before = Date.now();
      const { expiresAt } = generateSecureResetLink('user@test.com', ttl);

      expect(expiresAt).toBeGreaterThanOrEqual(before + ttl);
      expect(expiresAt).toBeLessThanOrEqual(Date.now() + ttl);
    });

    it('should generate unique links for different emails', () => {
      const { link: link1 } = generateSecureResetLink('a@test.com');
      const { link: link2 } = generateSecureResetLink('b@test.com');

      expect(link1).not.toBe(link2);
    });
  });

  describe('verifyResetToken', () => {
    it('should verify a valid token and return the email', () => {
      const { link } = generateSecureResetLink('user@test.com');
      const token = link.split('token=')[1];

      const email = verifyResetToken(token);
      expect(email).toBe('user@test.com');
    });

    it('should reject an expired token', () => {
      // Generate a link that expired 1ms ago
      const { link } = generateSecureResetLink('user@test.com', -1);
      const token = link.split('token=')[1];

      const email = verifyResetToken(token);
      expect(email).toBeNull();
    });

    it('should reject a tampered token', () => {
      const { link } = generateSecureResetLink('user@test.com');
      const token = link.split('token=')[1];

      // Tamper with the token by decoding, changing email, re-encoding
      const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());
      decoded.email = 'attacker@evil.com';
      const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString('base64url');

      const email = verifyResetToken(tamperedToken);
      expect(email).toBeNull();
    });

    it('should reject malformed tokens', () => {
      expect(verifyResetToken('not-a-valid-token')).toBeNull();
      expect(verifyResetToken('')).toBeNull();
    });
  });
});
