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

function loadApp(allowedOrigins) {
  if (allowedOrigins !== undefined) {
    process.env.ALLOWED_ORIGINS = allowedOrigins;
  } else {
    delete process.env.ALLOWED_ORIGINS;
  }
  return require('../../src/index');
}

describe('CORS Configuration (Fixes #30)', () => {
  describe('allowed origins', () => {
    it('should allow requests from configured origins', async () => {
      const app = loadApp('https://app.finserv.com,https://admin.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', 'https://app.finserv.com');

      expect(res.headers['access-control-allow-origin']).toBe('https://app.finserv.com');
      expect(res.headers['access-control-allow-credentials']).toBe('true');
      expect(res.status).toBe(200);
    });

    it('should allow requests from second configured origin', async () => {
      const app = loadApp('https://app.finserv.com,https://admin.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', 'https://admin.finserv.com');

      expect(res.headers['access-control-allow-origin']).toBe('https://admin.finserv.com');
      expect(res.status).toBe(200);
    });

    it('should use localhost:3000 as default when ALLOWED_ORIGINS is not set', async () => {
      const app = loadApp(undefined);

      const res = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:3000');

      expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      expect(res.status).toBe(200);
    });
  });

  describe('blocked origins', () => {
    it('should block requests from unauthorized origins', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', 'https://evil-site.com');

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      expect(res.status).toBe(500);
    });

    it('should block requests from similar but different origins', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', 'https://app.finserv.com.evil.com');

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      expect(res.status).toBe(500);
    });

    it('should block wildcard origin with credentials', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', '*');

      expect(res.headers['access-control-allow-origin']).not.toBe('*');
    });
  });

  describe('no origin header', () => {
    it('should allow requests with no origin (server-to-server)', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .get('/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });
  });

  describe('preflight requests', () => {
    it('should respond to preflight with correct headers for allowed origin', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .options('/health')
        .set('Origin', 'https://app.finserv.com')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type,Authorization');

      expect(res.headers['access-control-allow-origin']).toBe('https://app.finserv.com');
      expect(res.headers['access-control-allow-methods']).toContain('GET');
      expect(res.headers['access-control-allow-methods']).toContain('POST');
      expect(res.headers['access-control-allow-methods']).toContain('PUT');
      expect(res.headers['access-control-allow-methods']).toContain('DELETE');
      expect(res.headers['access-control-allow-headers']).toContain('Content-Type');
      expect(res.headers['access-control-allow-headers']).toContain('Authorization');
      expect(res.headers['access-control-allow-credentials']).toBe('true');
    });

    it('should block preflight for unauthorized origins', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .options('/health')
        .set('Origin', 'https://evil-site.com')
        .set('Access-Control-Request-Method', 'POST');

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('origin whitespace handling', () => {
    it('should handle whitespace in ALLOWED_ORIGINS config', async () => {
      const app = loadApp('https://app.finserv.com , https://admin.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', 'https://admin.finserv.com');

      expect(res.headers['access-control-allow-origin']).toBe('https://admin.finserv.com');
      expect(res.status).toBe(200);
    });
  });

  describe('credentials support', () => {
    it('should include credentials header for allowed origins', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', 'https://app.finserv.com');

      expect(res.headers['access-control-allow-credentials']).toBe('true');
    });

    it('should never return wildcard origin with credentials', async () => {
      const app = loadApp('https://app.finserv.com');

      const res = await request(app)
        .get('/health')
        .set('Origin', 'https://app.finserv.com');

      // Verify origin is specific, not wildcard (which is insecure with credentials)
      expect(res.headers['access-control-allow-origin']).not.toBe('*');
      expect(res.headers['access-control-allow-origin']).toBe('https://app.finserv.com');
    });
  });
});
