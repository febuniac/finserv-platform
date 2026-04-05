const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');

// Set up test JWT secret before requiring modules that use it
process.env.JWT_SECRET = 'test-secret-key-for-unit-tests';

const accountsRouter = require('../../src/api/accounts');
const transactionsRouter = require('../../src/api/transactions');
const usersRouter = require('../../src/api/users');
const { JWT_SECRET } = require('../../src/middleware/auth');
const { getStore } = require('../../src/utils/persistentStore');

function createApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/accounts', accountsRouter);
  app.use('/api/transactions', transactionsRouter);
  app.use('/api/users', usersRouter);
  return app;
}

function generateToken(payload) {
  return jwt.sign(
    { id: payload.id || 'xss-user-1', role: payload.role || 'user', email: payload.email || 'xss-test@example.com' },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h' }
  );
}

describe('XSS Prevention in API routes (Fixes #20)', () => {
  let app;
  let token;

  beforeAll(() => {
    app = createApp();
    token = generateToken({ id: 'xss-user-1' });

    // Seed a user for profile update tests
    const users = getStore('users');
    users.set('xss-test@example.com', {
      id: 'xss-user-1',
      email: 'xss-test@example.com',
      password: 'hashed',
      name: 'Test User',
      role: 'user',
      createdAt: new Date(),
    });
  });

  describe('POST /api/accounts - account name sanitization', () => {
    it('should strip script tags from account name', async () => {
      const res = await request(app)
        .post('/api/accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: '<script>alert("xss")</script>My Account', type: 'checking' });

      expect(res.status).toBe(201);
      expect(res.body.name).not.toContain('<script>');
      expect(res.body.name).toContain('My Account');
    });

    it('should strip img onerror XSS from account name', async () => {
      const res = await request(app)
        .post('/api/accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: '<img src=x onerror=alert(1)>Account', type: 'savings' });

      expect(res.status).toBe(201);
      expect(res.body.name).not.toContain('onerror');
      expect(res.body.name).not.toContain('alert');
    });

    it('should preserve clean account names', async () => {
      const res = await request(app)
        .post('/api/accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'My Savings Account', type: 'savings' });

      expect(res.status).toBe(201);
      expect(res.body.name).toBe('My Savings Account');
    });
  });

  describe('PUT /api/accounts/:id - account update sanitization', () => {
    let accountId;

    beforeAll(async () => {
      const res = await request(app)
        .post('/api/accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Update Test Account', type: 'checking', initialBalance: 0 });
      accountId = res.body.id;
    });

    it('should strip XSS from updated account name', async () => {
      const res = await request(app)
        .put(`/api/accounts/${accountId}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ name: '<svg onload=alert(1)>Hacked' });

      expect(res.status).toBe(200);
      expect(res.body.name).not.toContain('<svg');
      expect(res.body.name).not.toContain('onload');
    });
  });

  describe('POST /api/transactions/transfer - description sanitization', () => {
    let fromAccountId;
    let toAccountId;

    beforeAll(async () => {
      const from = await request(app)
        .post('/api/accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'XSS From Account', type: 'checking', initialBalance: 1000 });
      fromAccountId = from.body.id;

      const to = await request(app)
        .post('/api/accounts')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'XSS To Account', type: 'checking', initialBalance: 0 });
      toAccountId = to.body.id;
    });

    it('should strip script tags from transaction description', async () => {
      const res = await request(app)
        .post('/api/transactions/transfer')
        .set('Authorization', `Bearer ${token}`)
        .send({
          fromAccountId,
          toAccountId,
          amount: 10,
          description: '<script>document.cookie</script>Payment',
        });

      expect(res.status).toBe(201);
      expect(res.body.description).not.toContain('<script>');
      expect(res.body.description).toContain('Payment');
    });

    it('should strip iframe from transaction description', async () => {
      const res = await request(app)
        .post('/api/transactions/transfer')
        .set('Authorization', `Bearer ${token}`)
        .send({
          fromAccountId,
          toAccountId,
          amount: 10,
          description: '<iframe src="http://evil.com"></iframe>Normal desc',
        });

      expect(res.status).toBe(201);
      expect(res.body.description).not.toContain('<iframe');
      expect(res.body.description).toContain('Normal desc');
    });

    it('should preserve clean transaction descriptions', async () => {
      const res = await request(app)
        .post('/api/transactions/transfer')
        .set('Authorization', `Bearer ${token}`)
        .send({
          fromAccountId,
          toAccountId,
          amount: 10,
          description: 'Rent payment for April 2024',
        });

      expect(res.status).toBe(201);
      expect(res.body.description).toBe('Rent payment for April 2024');
    });
  });

  describe('PUT /api/users/profile - name sanitization', () => {
    it('should strip XSS from user name update', async () => {
      const res = await request(app)
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: '<script>steal()</script>John' });

      expect(res.status).toBe(200);
      expect(res.body.name).not.toContain('<script>');
      expect(res.body.name).toContain('John');
    });

    it('should preserve clean user names', async () => {
      const res = await request(app)
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Jane Doe' });

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('Jane Doe');
    });
  });
});
