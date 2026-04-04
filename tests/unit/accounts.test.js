const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');

// Set up test JWT secret before requiring modules that use it
process.env.JWT_SECRET = 'test-secret-key-for-unit-tests';

const accountsRouter = require('../../src/api/accounts');
const { JWT_SECRET } = require('../../src/middleware/auth');

function createApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/accounts', accountsRouter);
  return app;
}

function generateToken(payload) {
  return jwt.sign(
    { id: payload.id || 'user-1', role: payload.role || 'user', email: payload.email || 'test@example.com' },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h' }
  );
}

describe('GET /api/accounts - Pagination (Fixes #39)', () => {
  let app;
  let token;

  beforeAll(async () => {
    app = createApp();
    token = generateToken({ id: 'user-1' });

    // Seed 25 accounts for the test user
    for (let i = 0; i < 25; i++) {
      await request(app)
        .post('/api/accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: `Account ${i + 1}`, type: 'checking', currency: 'USD', initialBalance: 100 });
    }
  });

  it('should return paginated results with default page=1 and limit=20', async () => {
    const res = await request(app)
      .get('/api/accounts')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(20);
    expect(res.body.pagination).toEqual({
      page: 1,
      limit: 20,
      total: 25,
      totalPages: 2,
    });
  });

  it('should return the second page of results', async () => {
    const res = await request(app)
      .get('/api/accounts?page=2')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(5);
    expect(res.body.pagination.page).toBe(2);
    expect(res.body.pagination.total).toBe(25);
  });

  it('should respect custom limit parameter', async () => {
    const res = await request(app)
      .get('/api/accounts?limit=5')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(5);
    expect(res.body.pagination).toEqual({
      page: 1,
      limit: 5,
      total: 25,
      totalPages: 5,
    });
  });

  it('should cap limit at 100', async () => {
    const res = await request(app)
      .get('/api/accounts?limit=500')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.pagination.limit).toBe(100);
  });

  it('should return empty data array for page beyond total pages', async () => {
    const res = await request(app)
      .get('/api/accounts?page=999')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(0);
    expect(res.body.pagination.total).toBe(25);
  });

  it('should default to page=1 for invalid page values', async () => {
    const values = ['0', '-1', 'abc', ''];
    for (const val of values) {
      const res = await request(app)
        .get(`/api/accounts?page=${val}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.pagination.page).toBe(1);
    }
  });

  it('should default to limit=20 for invalid limit values', async () => {
    const values = ['0', '-5', 'abc', ''];
    for (const val of values) {
      const res = await request(app)
        .get(`/api/accounts?limit=${val}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.pagination.limit).toBe(20);
    }
  });

  it('should combine page and limit correctly', async () => {
    const res = await request(app)
      .get('/api/accounts?page=3&limit=10')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(5);
    expect(res.body.pagination).toEqual({
      page: 3,
      limit: 10,
      total: 25,
      totalPages: 3,
    });
  });

  it('should only return accounts for the authenticated user', async () => {
    const otherToken = generateToken({ id: 'user-other' });

    const res = await request(app)
      .get('/api/accounts')
      .set('Authorization', `Bearer ${otherToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(0);
    expect(res.body.pagination.total).toBe(0);
  });

  it('should require authentication', async () => {
    const res = await request(app).get('/api/accounts');

    expect(res.status).toBe(401);
  });
});
