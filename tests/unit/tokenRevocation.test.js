const request = require('supertest');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Store original env
const originalEnv = process.env;

const TEST_PASSWORD = 'TestPassword1!@#';

beforeEach(() => {
  jest.resetModules();
  process.env = {
    ...originalEnv,
    JWT_SECRET: 'test-secret-key-for-testing',
    ALLOWED_ORIGINS: 'http://localhost:3000',
    ACCESS_TOKEN_EXPIRY: '15m',
    REFRESH_TOKEN_EXPIRY_DAYS: '7',
  };
});

afterAll(() => {
  process.env = originalEnv;
  // Stop cleanup timers to allow Jest to exit cleanly
  try {
    const authMiddleware = require('../../src/middleware/auth');
    if (authMiddleware._stopCleanupTimer) {
      authMiddleware._stopCleanupTimer();
    }
  } catch {
    // ignore
  }
});

function loadApp() {
  return require('../../src/index');
}

// Helper: obtain a CSRF token cookie from a GET request
async function getCsrfToken(app) {
  const res = await request(app).get('/api/csrf-token');
  const setCookie = res.headers['set-cookie'];
  let token = null;
  let cookieString = '';
  if (setCookie) {
    const cookieArr = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const c of cookieArr) {
      const match = c.match(/_csrf_token=([^;]+)/);
      if (match) {
        token = match[1];
        cookieString = `_csrf_token=${token}`;
        break;
      }
    }
  }
  return { token, cookieString };
}

// Helper: register and login a user, returns { accessToken, refreshToken, user }
async function registerAndLogin(app, csrf) {
  const email = `testuser-${Date.now()}@example.com`;

  await request(app)
    .post('/api/auth/register')
    .set('Origin', 'http://localhost:3000')
    .set('Cookie', csrf.cookieString)
    .set('X-CSRF-Token', csrf.token)
    .send({ email, password: TEST_PASSWORD, name: 'Test User' });

  const loginRes = await request(app)
    .post('/api/auth/login')
    .set('Origin', 'http://localhost:3000')
    .set('Cookie', csrf.cookieString)
    .set('X-CSRF-Token', csrf.token)
    .send({ email, password: TEST_PASSWORD });

  return { ...loginRes.body, email };
}

describe('JWT Token Revocation (Fixes #18)', () => {
  describe('Login response format', () => {
    it('should return accessToken, refreshToken, and expiresIn on login', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const result = await registerAndLogin(app, csrf);

      expect(result.accessToken).toBeDefined();
      expect(typeof result.accessToken).toBe('string');
      expect(result.refreshToken).toBeDefined();
      expect(typeof result.refreshToken).toBe('string');
      expect(result.expiresIn).toBe('15m');
      expect(result.user).toBeDefined();
      expect(result.user.email).toBeDefined();
    });

    it('should issue short-lived access tokens (15 min)', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const result = await registerAndLogin(app, csrf);

      const decoded = jwt.decode(result.accessToken);
      // Token should expire within 15 minutes (900 seconds)
      const ttl = decoded.exp - decoded.iat;
      expect(ttl).toBe(900);
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should successfully logout and revoke the access token', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const { accessToken, refreshToken } = await registerAndLogin(app, csrf);

      // Logout
      const logoutRes = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken });

      expect(logoutRes.status).toBe(200);
      expect(logoutRes.body.message).toBe('Successfully logged out');

      // Access token should now be revoked
      const protectedRes = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(protectedRes.status).toBe(401);
      expect(protectedRes.body.error).toBe('Token has been revoked');
    });

    it('should revoke the refresh token on logout', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const { accessToken, refreshToken } = await registerAndLogin(app, csrf);

      // Logout with refresh token
      await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken });

      // Refresh token should be invalid now
      const refreshRes = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken });

      expect(refreshRes.status).toBe(401);
      expect(refreshRes.body.error).toBe('Invalid or expired refresh token');
    });

    it('should require authentication to logout', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/logout')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({});

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Access token required');
    });

    it('should reject a revoked token on subsequent requests', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const { accessToken } = await registerAndLogin(app, csrf);

      // First request should work
      const firstRes = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${accessToken}`);
      // Should not be 401 (token revoked) - could be 404 or similar depending on route
      expect(firstRes.status).not.toBe(401);

      // Logout
      await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({});

      // Second request should be rejected
      const secondRes = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(secondRes.status).toBe(401);
      expect(secondRes.body.error).toBe('Token has been revoked');
    });
  });

  describe('POST /api/auth/logout-all', () => {
    it('should revoke all refresh tokens for the user', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);

      // Register user
      const email = `multidevice-${Date.now()}@example.com`;
      await request(app)
        .post('/api/auth/register')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ email, password: TEST_PASSWORD, name: 'Multi Device User' });

      // Login from "device 1"
      const login1 = await request(app)
        .post('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ email, password: TEST_PASSWORD });

      // Login from "device 2"
      const login2 = await request(app)
        .post('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ email, password: TEST_PASSWORD });

      // Logout all from device 1
      const logoutAllRes = await request(app)
        .post('/api/auth/logout-all')
        .set('Authorization', `Bearer ${login1.body.accessToken}`)
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({});

      expect(logoutAllRes.status).toBe(200);
      expect(logoutAllRes.body.message).toBe('Successfully logged out from all devices');

      // Both refresh tokens should be invalid
      const refresh1 = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken: login1.body.refreshToken });

      expect(refresh1.status).toBe(401);

      const refresh2 = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken: login2.body.refreshToken });

      expect(refresh2.status).toBe(401);
    });
  });

  describe('POST /api/auth/refresh-token', () => {
    it('should issue a new access token with a valid refresh token', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const { refreshToken, user } = await registerAndLogin(app, csrf);

      const refreshRes = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken });

      expect(refreshRes.status).toBe(200);
      expect(refreshRes.body.accessToken).toBeDefined();
      expect(refreshRes.body.refreshToken).toBeDefined();
      expect(refreshRes.body.expiresIn).toBe('15m');

      // New access token should be different from old one
      expect(refreshRes.body.refreshToken).not.toBe(refreshToken);
    });

    it('should rotate the refresh token on each use', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const { refreshToken: originalRefresh } = await registerAndLogin(app, csrf);

      // Use the refresh token
      const refreshRes = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken: originalRefresh });

      expect(refreshRes.status).toBe(200);
      const newRefresh = refreshRes.body.refreshToken;
      expect(newRefresh).not.toBe(originalRefresh);

      // Original refresh token should no longer work (it was rotated)
      const replayRes = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken: originalRefresh });

      expect(replayRes.status).toBe(401);
      expect(replayRes.body.error).toBe('Invalid or expired refresh token');

      // New refresh token should still work
      const secondRefresh = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken: newRefresh });

      expect(secondRefresh.status).toBe(200);
      expect(secondRefresh.body.accessToken).toBeDefined();
    });

    it('should reject an invalid refresh token', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken: 'invalid-token-value' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid or expired refresh token');
    });

    it('should return 400 when no refresh token is provided', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Refresh token is required');
    });

    it('should issue access tokens that work for authenticated endpoints', async () => {
      const app = loadApp();
      const csrf = await getCsrfToken(app);
      const { refreshToken } = await registerAndLogin(app, csrf);

      // Get a new access token via refresh
      const refreshRes = await request(app)
        .post('/api/auth/refresh-token')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', csrf.cookieString)
        .set('X-CSRF-Token', csrf.token)
        .send({ refreshToken });

      const newAccessToken = refreshRes.body.accessToken;

      // Use the new access token for an authenticated request
      const protectedRes = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${newAccessToken}`);

      // Should not be 401 (token should be valid)
      expect(protectedRes.status).not.toBe(401);
    });
  });

  describe('Token blacklist', () => {
    it('should track revoked tokens with expiry for cleanup', () => {
      jest.resetModules();
      process.env.JWT_SECRET = 'test-secret-key-for-testing';
      const authMiddleware = require('../../src/middleware/auth');

      const token = jwt.sign(
        { id: '1', email: 'test@test.com', role: 'user' },
        'test-secret-key-for-testing',
        { expiresIn: '1h', algorithm: 'HS256' }
      );

      authMiddleware.revokeToken(token);

      const revokedTokens = authMiddleware._getRevokedTokens();
      expect(revokedTokens.has(token)).toBe(true);

      // The stored value should be the expiry timestamp
      const expiresAt = revokedTokens.get(token);
      expect(typeof expiresAt).toBe('number');
      expect(expiresAt).toBeGreaterThan(Date.now());
    });

    it('should handle revoking tokens that cannot be decoded', () => {
      jest.resetModules();
      process.env.JWT_SECRET = 'test-secret-key-for-testing';
      const authMiddleware = require('../../src/middleware/auth');

      const badToken = 'not-a-valid-jwt';
      authMiddleware.revokeToken(badToken);

      const revokedTokens = authMiddleware._getRevokedTokens();
      expect(revokedTokens.has(badToken)).toBe(true);
    });
  });

  describe('Refresh token store', () => {
    it('should store and validate refresh tokens', () => {
      jest.resetModules();
      process.env.JWT_SECRET = 'test-secret-key-for-testing';
      const authMiddleware = require('../../src/middleware/auth');

      const refreshToken = crypto.randomBytes(32).toString('hex');
      const userData = { id: '1', email: 'test@test.com', role: 'user' };

      authMiddleware.storeRefreshToken(refreshToken, userData);

      const data = authMiddleware.validateRefreshToken(refreshToken);
      expect(data).not.toBeNull();
      expect(data.userId).toBe('1');
      expect(data.email).toBe('test@test.com');
      expect(data.role).toBe('user');
    });

    it('should return null for non-existent refresh tokens', () => {
      jest.resetModules();
      process.env.JWT_SECRET = 'test-secret-key-for-testing';
      const authMiddleware = require('../../src/middleware/auth');

      const data = authMiddleware.validateRefreshToken('non-existent-token');
      expect(data).toBeNull();
    });

    it('should revoke individual refresh tokens', () => {
      jest.resetModules();
      process.env.JWT_SECRET = 'test-secret-key-for-testing';
      const authMiddleware = require('../../src/middleware/auth');

      const refreshToken = crypto.randomBytes(32).toString('hex');
      authMiddleware.storeRefreshToken(refreshToken, { id: '1', email: 'a@b.com', role: 'user' });

      expect(authMiddleware.validateRefreshToken(refreshToken)).not.toBeNull();

      authMiddleware.revokeRefreshToken(refreshToken);

      expect(authMiddleware.validateRefreshToken(refreshToken)).toBeNull();
    });

    it('should revoke all refresh tokens for a specific user', () => {
      jest.resetModules();
      process.env.JWT_SECRET = 'test-secret-key-for-testing';
      const authMiddleware = require('../../src/middleware/auth');

      const token1 = crypto.randomBytes(32).toString('hex');
      const token2 = crypto.randomBytes(32).toString('hex');
      const token3 = crypto.randomBytes(32).toString('hex');

      authMiddleware.storeRefreshToken(token1, { id: 'user1', email: 'a@b.com', role: 'user' });
      authMiddleware.storeRefreshToken(token2, { id: 'user1', email: 'a@b.com', role: 'user' });
      authMiddleware.storeRefreshToken(token3, { id: 'user2', email: 'c@d.com', role: 'user' });

      authMiddleware.revokeAllUserRefreshTokens('user1');

      expect(authMiddleware.validateRefreshToken(token1)).toBeNull();
      expect(authMiddleware.validateRefreshToken(token2)).toBeNull();
      // user2's token should still be valid
      expect(authMiddleware.validateRefreshToken(token3)).not.toBeNull();
    });
  });
});
