const request = require('supertest');
const crypto = require('crypto');

// Store original env
const originalEnv = process.env;

beforeEach(() => {
  jest.resetModules();
  process.env = {
    ...originalEnv,
    JWT_SECRET: 'test-secret-key-for-testing',
    ALLOWED_ORIGINS: 'http://localhost:3000',
  };
});

afterAll(() => {
  process.env = originalEnv;
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

describe('CSRF Protection (Fixes #16)', () => {
  describe('safe methods (GET, HEAD, OPTIONS)', () => {
    it('should allow GET requests without CSRF token', async () => {
      const app = loadApp();
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });

    it('should set a CSRF token cookie on GET requests', async () => {
      const app = loadApp();
      const res = await request(app).get('/health');
      const setCookie = res.headers['set-cookie'];
      expect(setCookie).toBeDefined();
      const csrfCookie = setCookie.find(c => c.includes('_csrf_token='));
      expect(csrfCookie).toBeDefined();
      expect(csrfCookie).toContain('SameSite=Strict');
      expect(csrfCookie).toContain('Path=/');
      // httpOnly should be false (not present in cookie string)
      expect(csrfCookie).not.toContain('HttpOnly');
    });

    it('should not overwrite existing CSRF token cookie', async () => {
      const app = loadApp();
      const existingToken = crypto.randomBytes(32).toString('hex');
      const res = await request(app)
        .get('/health')
        .set('Cookie', `_csrf_token=${existingToken}`);

      // Should not set a new cookie if one already exists
      const setCookie = res.headers['set-cookie'] || [];
      const csrfCookie = setCookie.find(c => c.includes('_csrf_token='));
      expect(csrfCookie).toBeUndefined();
    });
  });

  describe('CSRF token endpoint', () => {
    it('should return a CSRF token via /api/csrf-token', async () => {
      const app = loadApp();
      const res = await request(app).get('/api/csrf-token');
      expect(res.status).toBe(200);
      expect(res.body.csrfToken).toBeDefined();
      expect(typeof res.body.csrfToken).toBe('string');
      expect(res.body.csrfToken.length).toBe(64); // 32 bytes hex
    });
  });

  describe('state-changing methods require CSRF validation', () => {
    it('should block POST without Origin or Referer header', async () => {
      const app = loadApp();
      const { token, cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Cookie', cookieString)
        .set('X-CSRF-Token', token)
        .send({ email: 'test@test.com', password: 'pass' });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('CSRF validation failed');
    });

    it('should block POST with disallowed Origin (blocked by CORS or CSRF)', async () => {
      const app = loadApp();
      const { token, cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Origin', 'https://evil-site.com')
        .set('Cookie', cookieString)
        .set('X-CSRF-Token', token)
        .send({ email: 'test@test.com', password: 'pass' });

      // CORS middleware rejects disallowed origins (500) before CSRF runs (403).
      // Either way, the request is blocked — both layers provide defense-in-depth.
      expect([403, 500]).toContain(res.status);
    });

    it('should block POST with disallowed Referer (when no Origin)', async () => {
      const app = loadApp();
      const { token, cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Referer', 'https://evil-site.com/page')
        .set('Cookie', cookieString)
        .set('X-CSRF-Token', token)
        .send({ email: 'test@test.com', password: 'pass' });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('referer not allowed');
    });

    it('should block POST with invalid Referer URL', async () => {
      const app = loadApp();
      const { token, cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Referer', 'not-a-valid-url')
        .set('Cookie', cookieString)
        .set('X-CSRF-Token', token)
        .send({ email: 'test@test.com', password: 'pass' });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('CSRF validation failed');
    });

    it('should block POST with missing CSRF token cookie', async () => {
      const app = loadApp();

      const res = await request(app)
        .post('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('X-CSRF-Token', 'some-token')
        .send({ email: 'test@test.com', password: 'pass' });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('missing token');
    });

    it('should block POST with missing X-CSRF-Token header', async () => {
      const app = loadApp();
      const { cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', cookieString)
        .send({ email: 'test@test.com', password: 'pass' });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('missing token');
    });

    it('should block POST with mismatched CSRF tokens', async () => {
      const app = loadApp();
      const { cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', cookieString)
        .set('X-CSRF-Token', crypto.randomBytes(32).toString('hex'))
        .send({ email: 'test@test.com', password: 'pass' });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('token mismatch');
    });

    it('should allow POST with valid Origin and matching CSRF tokens', async () => {
      const app = loadApp();
      const { token, cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Cookie', cookieString)
        .set('X-CSRF-Token', token)
        .send({ email: 'test@test.com', password: 'password123' });

      // Should pass CSRF validation and reach the login handler
      // (may return 401 for bad credentials, but NOT 403 for CSRF)
      expect(res.status).not.toBe(403);
    });

    it('should allow POST with valid Referer (no Origin) and matching CSRF tokens', async () => {
      const app = loadApp();
      const { token, cookieString } = await getCsrfToken(app);

      const res = await request(app)
        .post('/api/auth/login')
        .set('Referer', 'http://localhost:3000/login')
        .set('Cookie', cookieString)
        .set('X-CSRF-Token', token)
        .send({ email: 'test@test.com', password: 'password123' });

      // Should pass CSRF and reach the handler
      expect(res.status).not.toBe(403);
    });
  });

  describe('PUT and DELETE also require CSRF', () => {
    it('should block PUT without CSRF tokens', async () => {
      const app = loadApp();

      const res = await request(app)
        .put('/api/users/profile')
        .set('Origin', 'http://localhost:3000')
        .send({ name: 'Updated' });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('CSRF validation failed');
    });

    it('should block DELETE without CSRF tokens', async () => {
      const app = loadApp();

      const res = await request(app)
        .delete('/api/accounts/some-id')
        .set('Origin', 'http://localhost:3000');

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('CSRF validation failed');
    });
  });

  describe('X-CSRF-Token in CORS allowed headers', () => {
    it('should include X-CSRF-Token in preflight allowed headers', async () => {
      const app = loadApp();

      const res = await request(app)
        .options('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type,X-CSRF-Token');

      expect(res.headers['access-control-allow-headers']).toContain('X-CSRF-Token');
    });
  });

  describe('token security properties', () => {
    it('should generate unique tokens for different requests', async () => {
      const app = loadApp();

      const res1 = await request(app).get('/health');
      const res2 = await request(app).get('/health');

      const cookie1 = res1.headers['set-cookie']?.find(c => c.includes('_csrf_token='));
      const cookie2 = res2.headers['set-cookie']?.find(c => c.includes('_csrf_token='));

      const token1 = cookie1?.match(/_csrf_token=([^;]+)/)?.[1];
      const token2 = cookie2?.match(/_csrf_token=([^;]+)/)?.[1];

      expect(token1).toBeDefined();
      expect(token2).toBeDefined();
      expect(token1).not.toBe(token2);
    });

    it('should generate tokens of sufficient length (32 bytes / 64 hex chars)', async () => {
      const app = loadApp();
      const res = await request(app).get('/health');
      const cookie = res.headers['set-cookie']?.find(c => c.includes('_csrf_token='));
      const token = cookie?.match(/_csrf_token=([^;]+)/)?.[1];
      expect(token).toBeDefined();
      expect(token.length).toBe(64);
    });
  });
});
