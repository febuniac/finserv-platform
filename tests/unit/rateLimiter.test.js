const request = require('supertest');
const app = require('../../src/index');
const { loginAttempts } = require('../../src/middleware/rateLimiter');
const { getStore } = require('../../src/utils/persistentStore');
const { hashPassword } = require('../../src/utils/crypto');

// Prevent Jest from hanging due to the setInterval in rateLimiter.js
afterAll(() => {
  jest.useRealTimers();
});

describe('Login rate limiting (Fixes #17)', () => {
  const TEST_EMAIL = 'ratelimit@example.com';
  const TEST_PASSWORD = 'SuperSecure1!@#';
  let users;

  beforeAll(() => {
    users = getStore('users');
    const hashed = hashPassword(TEST_PASSWORD);
    users.set(TEST_EMAIL, {
      id: 'rl-test-user',
      email: TEST_EMAIL,
      password: hashed,
      name: 'Rate Limit Test User',
      role: 'user',
      createdAt: new Date(),
    });
  });

  afterAll(() => {
    users.delete(TEST_EMAIL);
  });

  beforeEach(() => {
    // Clear rate limit state between tests
    loginAttempts.clear();
  });

  it('should allow login attempts within the rate limit', async () => {
    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid email or password');
    }
  });

  it('should block the 6th login attempt from the same IP within the window', async () => {
    // Make 5 allowed attempts
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' });
    }

    // 6th attempt should be rate-limited
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' });

    expect(res.status).toBe(429);
    expect(res.body.error).toMatch(/too many login attempts/i);
  });

  it('should include Retry-After header when rate limited', async () => {
    // Exhaust the rate limit
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' });
    }

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' });

    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
    expect(parseInt(res.headers['retry-after'], 10)).toBeGreaterThan(0);
  });

  it('should rate limit even valid credentials after limit is exceeded', async () => {
    // Exhaust rate limit with wrong passwords
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' });
    }

    // Even correct credentials should be blocked
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: TEST_EMAIL, password: TEST_PASSWORD });

    expect(res.status).toBe(429);
    expect(res.body.error).toMatch(/too many login attempts/i);
  });

  it('should allow requests after the rate limit window resets', async () => {
    // Register a separate user for this test to avoid account lockout from other tests
    const freshEmail = 'ratelimit-reset@example.com';
    const freshPassword = 'FreshSecure1!@#';
    const hashed = hashPassword(freshPassword);
    users.set(freshEmail, {
      id: 'rl-reset-user',
      email: freshEmail,
      password: hashed,
      name: 'Reset Test User',
      role: 'user',
      createdAt: new Date(),
    });

    // Manually set an expired rate limit entry
    loginAttempts.set('login:::ffff:127.0.0.1', {
      count: 10,
      startTime: Date.now() - 120 * 1000, // 2 minutes ago (window is 1 minute)
    });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: freshEmail, password: freshPassword });

    // Should be allowed since the window has expired
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();

    users.delete(freshEmail);
  });
});

describe('Account lockout (Fixes #17)', () => {
  const LOCKOUT_EMAIL = 'lockout@example.com';
  const LOCKOUT_PASSWORD = 'SuperSecure1!@#';
  let users;

  beforeAll(() => {
    users = getStore('users');
    const hashed = hashPassword(LOCKOUT_PASSWORD);
    users.set(LOCKOUT_EMAIL, {
      id: 'lockout-test-user',
      email: LOCKOUT_EMAIL,
      password: hashed,
      name: 'Lockout Test User',
      role: 'user',
      createdAt: new Date(),
    });
  });

  afterAll(() => {
    users.delete(LOCKOUT_EMAIL);
  });

  beforeEach(() => {
    // Clear rate limit and lockout state between tests
    loginAttempts.clear();
    // Clear the failedAttempts map in auth.js by sending requests with fresh state
  });

  it('should lock account after 5 failed password attempts', async () => {
    // Make 5 failed login attempts with wrong password
    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: LOCKOUT_EMAIL, password: 'WrongPass1!@#' });

      expect(res.status).toBe(401);
    }

    // Clear rate limiter so we can test account lockout specifically
    loginAttempts.clear();

    // 6th attempt with correct password should fail due to account lockout
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: LOCKOUT_EMAIL, password: LOCKOUT_PASSWORD });

    expect(res.status).toBe(423);
    expect(res.body.error).toMatch(/account locked/i);
  });
});
