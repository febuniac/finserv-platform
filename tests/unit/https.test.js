const request = require('supertest');

// Store original env
const originalEnv = process.env;

beforeEach(() => {
  jest.resetModules();
  process.env = { ...originalEnv, JWT_SECRET: 'test-secret-key-for-testing' };
});

afterAll(() => {
  process.env = originalEnv;
});

function loadApp(env = {}) {
  Object.assign(process.env, env);
  return require('../../src/index');
}

describe('HTTPS Enforcement (Fixes #25)', () => {
  describe('production environment', () => {
    it('should redirect HTTP requests to HTTPS with 301', async () => {
      const app = loadApp({ NODE_ENV: 'production' });

      const res = await request(app)
        .get('/health')
        .set('X-Forwarded-Proto', 'http')
        .set('Host', 'api.finserv.com');

      expect(res.status).toBe(301);
      expect(res.headers.location).toBe('https://api.finserv.com/health');
    });

    it('should redirect HTTP requests preserving the full URL path and query', async () => {
      const app = loadApp({ NODE_ENV: 'production' });

      const res = await request(app)
        .get('/api/accounts?page=2&limit=10')
        .set('X-Forwarded-Proto', 'http')
        .set('Host', 'api.finserv.com');

      expect(res.status).toBe(301);
      expect(res.headers.location).toBe(
        'https://api.finserv.com/api/accounts?page=2&limit=10'
      );
    });

    it('should allow HTTPS requests through without redirect', async () => {
      const app = loadApp({ NODE_ENV: 'production' });

      const res = await request(app)
        .get('/health')
        .set('X-Forwarded-Proto', 'https')
        .set('Host', 'api.finserv.com');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });

    it('should allow requests with no x-forwarded-proto header', async () => {
      const app = loadApp({ NODE_ENV: 'production' });

      const res = await request(app)
        .get('/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });

    it('should redirect before CORS or other middleware processes the request', async () => {
      const app = loadApp({
        NODE_ENV: 'production',
        ALLOWED_ORIGINS: 'https://app.finserv.com',
      });

      const res = await request(app)
        .get('/health')
        .set('X-Forwarded-Proto', 'http')
        .set('Host', 'api.finserv.com')
        .set('Origin', 'https://evil-site.com');

      // Should get a redirect (301) rather than a CORS error (500),
      // proving HTTPS enforcement runs before CORS.
      expect(res.status).toBe(301);
      expect(res.headers.location).toBe('https://api.finserv.com/health');
    });
  });

  describe('non-production environment', () => {
    it('should not redirect HTTP requests in development', async () => {
      const app = loadApp({ NODE_ENV: 'development' });

      const res = await request(app)
        .get('/health')
        .set('X-Forwarded-Proto', 'http')
        .set('Host', 'localhost:3000');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });

    it('should not redirect HTTP requests in test', async () => {
      const app = loadApp({ NODE_ENV: 'test' });

      const res = await request(app)
        .get('/health')
        .set('X-Forwarded-Proto', 'http')
        .set('Host', 'localhost:3000');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });

    it('should not redirect when NODE_ENV is unset', async () => {
      delete process.env.NODE_ENV;
      const app = loadApp({});

      const res = await request(app)
        .get('/health')
        .set('X-Forwarded-Proto', 'http')
        .set('Host', 'localhost:3000');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });
  });

  describe('HSTS header', () => {
    it('should include Strict-Transport-Security header', async () => {
      const app = loadApp({});

      const res = await request(app)
        .get('/health');

      const hsts = res.headers['strict-transport-security'];
      expect(hsts).toBeDefined();
      expect(hsts).toContain('max-age=31536000');
      expect(hsts).toContain('includeSubDomains');
      expect(hsts).toContain('preload');
    });
  });
});
