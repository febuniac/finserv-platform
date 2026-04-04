const request = require('supertest');

// Mock the rate limiter to be a passthrough so it doesn't interfere with lockout tests
jest.mock('../../src/middleware/rateLimiter', () => ({
  rateLimiter: (req, res, next) => next(),
  loginRateLimiter: (req, res, next) => next(),
}));

const app = require('../../src/index');
const { failedAttempts, MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION } = require('../../src/api/auth');

const TEST_USER = {
  email: 'lockout-test@example.com',
  password: 'SecurePass1!@#abc',
  name: 'Lockout Test User',
};

const WRONG_PASSWORD = 'WrongPass1!@#xyz';

// Helper: attempt login
async function attemptLogin(email, password) {
  return request(app).post('/api/auth/login').send({ email, password });
}

describe('Account Lockout (Issue #27)', () => {
  beforeEach(() => {
    // Clear lockout state between tests
    failedAttempts.clear();
  });

  // Register once before all tests in this suite
  beforeAll(async () => {
    await request(app).post('/api/auth/register').send(TEST_USER);
  });

  describe('Failed attempt tracking', () => {
    it('should track failed login attempts for existing users', async () => {
      const res = await attemptLogin(TEST_USER.email, WRONG_PASSWORD);

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid email or password');

      const attempts = failedAttempts.get(TEST_USER.email);
      expect(attempts).toBeDefined();
      expect(attempts.count).toBe(1);
      expect(attempts.lastAttempt).toBeDefined();
    });

    it('should track failed login attempts for non-existent users', async () => {
      const fakeEmail = 'nonexistent@example.com';
      const res = await attemptLogin(fakeEmail, WRONG_PASSWORD);

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid email or password');

      const attempts = failedAttempts.get(fakeEmail);
      expect(attempts).toBeDefined();
      expect(attempts.count).toBe(1);
    });

    it('should increment the counter on each failed attempt', async () => {
      for (let i = 1; i <= 3; i++) {
        await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
        const attempts = failedAttempts.get(TEST_USER.email);
        expect(attempts.count).toBe(i);
      }
    });
  });

  describe('Account locking after MAX_FAILED_ATTEMPTS', () => {
    it('should lock the account after 5 consecutive failed attempts', async () => {
      // Make MAX_FAILED_ATTEMPTS failed login attempts
      for (let i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
        const res = await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
        expect(res.status).toBe(401);
      }

      // The next attempt should return 423 Locked
      const lockedRes = await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
      expect(lockedRes.status).toBe(423);
      expect(lockedRes.body.error).toBe('Account locked. Try again later.');
    });

    it('should reject even correct credentials while account is locked', async () => {
      // Lock the account
      for (let i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
        await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
      }

      // Try with correct password - should still be locked
      const res = await attemptLogin(TEST_USER.email, TEST_USER.password);
      expect(res.status).toBe(423);
      expect(res.body.error).toBe('Account locked. Try again later.');
    });

    it('should lock non-existent user emails after 5 failed attempts', async () => {
      const fakeEmail = 'bruteforce-target@example.com';

      for (let i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
        await attemptLogin(fakeEmail, WRONG_PASSWORD);
      }

      const lockedRes = await attemptLogin(fakeEmail, WRONG_PASSWORD);
      expect(lockedRes.status).toBe(423);
      expect(lockedRes.body.error).toBe('Account locked. Try again later.');
    });
  });

  describe('Lockout expiry', () => {
    it('should unlock the account after the lockout duration expires', async () => {
      // Lock the account
      for (let i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
        await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
      }

      // Verify it is locked
      let res = await attemptLogin(TEST_USER.email, TEST_USER.password);
      expect(res.status).toBe(423);

      // Simulate lockout expiry by backdating the lastAttempt
      const attempts = failedAttempts.get(TEST_USER.email);
      attempts.lastAttempt = Date.now() - LOCKOUT_DURATION - 1000;

      // Should now be able to log in with correct password
      res = await attemptLogin(TEST_USER.email, TEST_USER.password);
      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
    });

    it('should clear failed attempts record after lockout expires and login succeeds', async () => {
      // Lock the account
      for (let i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
        await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
      }

      // Simulate lockout expiry
      const attempts = failedAttempts.get(TEST_USER.email);
      attempts.lastAttempt = Date.now() - LOCKOUT_DURATION - 1000;

      // Login with correct password
      await attemptLogin(TEST_USER.email, TEST_USER.password);

      // Failed attempts should be cleared
      expect(failedAttempts.has(TEST_USER.email)).toBe(false);
    });
  });

  describe('Successful login resets attempts', () => {
    it('should clear failed attempts after a successful login', async () => {
      // Make a few failed attempts (less than lockout threshold)
      for (let i = 0; i < 3; i++) {
        await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
      }

      expect(failedAttempts.get(TEST_USER.email).count).toBe(3);

      // Successful login
      const res = await attemptLogin(TEST_USER.email, TEST_USER.password);
      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();

      // Failed attempts should be cleared
      expect(failedAttempts.has(TEST_USER.email)).toBe(false);
    });

    it('should allow fresh failed attempts after a successful login resets the counter', async () => {
      // Make 3 failed attempts
      for (let i = 0; i < 3; i++) {
        await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
      }

      // Successful login resets counter
      await attemptLogin(TEST_USER.email, TEST_USER.password);

      // Make 4 more failed attempts (should NOT lock since counter was reset)
      for (let i = 1; i <= 4; i++) {
        const res = await attemptLogin(TEST_USER.email, WRONG_PASSWORD);
        expect(res.status).toBe(401);
      }

      expect(failedAttempts.get(TEST_USER.email).count).toBe(4);
    });
  });

  describe('Configuration', () => {
    it('should have MAX_FAILED_ATTEMPTS set to 5', () => {
      expect(MAX_FAILED_ATTEMPTS).toBe(5);
    });

    it('should have LOCKOUT_DURATION set to 15 minutes', () => {
      expect(LOCKOUT_DURATION).toBe(15 * 60 * 1000);
    });
  });
});
