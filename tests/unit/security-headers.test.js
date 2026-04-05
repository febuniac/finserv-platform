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

function loadApp() {
  return require('../../src/index');
}

describe('Security Headers - helmet middleware (Fixes #21)', () => {
  describe('Content-Security-Policy', () => {
    it('should set Content-Security-Policy header', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      const csp = res.headers['content-security-policy'];
      expect(csp).toBeDefined();
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("script-src 'self'");
      expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    });
  });

  describe('X-Content-Type-Options', () => {
    it('should set X-Content-Type-Options to nosniff', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });
  });

  describe('X-Frame-Options', () => {
    it('should set X-Frame-Options to prevent clickjacking', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      // helmet v7 sets X-Frame-Options to SAMEORIGIN by default
      expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    });
  });

  describe('Strict-Transport-Security (HSTS)', () => {
    it('should set HSTS header with correct directives', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      const hsts = res.headers['strict-transport-security'];
      expect(hsts).toBeDefined();
      expect(hsts).toContain('max-age=31536000');
      expect(hsts).toContain('includeSubDomains');
      expect(hsts).toContain('preload');
    });
  });

  describe('Referrer-Policy', () => {
    it('should set Referrer-Policy to strict-origin-when-cross-origin', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    });
  });

  describe('X-DNS-Prefetch-Control', () => {
    it('should set X-DNS-Prefetch-Control header', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      expect(res.headers['x-dns-prefetch-control']).toBe('off');
    });
  });

  describe('X-Download-Options', () => {
    it('should set X-Download-Options to noopen', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      expect(res.headers['x-download-options']).toBe('noopen');
    });
  });

  describe('X-Permitted-Cross-Domain-Policies', () => {
    it('should set X-Permitted-Cross-Domain-Policies to none', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      expect(res.headers['x-permitted-cross-domain-policies']).toBe('none');
    });
  });

  describe('Security headers on API routes', () => {
    it('should include security headers on API endpoints (not just /health)', async () => {
      const app = loadApp();

      // Test on a different route to ensure headers are applied globally
      const res = await request(app).get('/api/auth');

      expect(res.headers['content-security-policy']).toBeDefined();
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
      expect(res.headers['strict-transport-security']).toBeDefined();
    });
  });

  describe('Removed insecure headers', () => {
    it('should not expose X-Powered-By header', async () => {
      const app = loadApp();

      const res = await request(app).get('/health');

      // helmet removes X-Powered-By by default
      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });
});
