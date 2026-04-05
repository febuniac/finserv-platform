const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');

// Set up test JWT secret before requiring modules that use it
process.env.JWT_SECRET = 'test-secret-key-for-unit-tests';

const usersRouter = require('../../src/api/users');
const { JWT_SECRET } = require('../../src/middleware/auth');
const { getStore } = require('../../src/utils/persistentStore');
const { hashPassword } = require('../../src/utils/crypto');

function createApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/users', usersRouter);
  return app;
}

function generateToken(payload) {
  return jwt.sign(
    { id: payload.id || 'user-1', role: payload.role || 'user', email: payload.email || 'test@example.com' },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h' }
  );
}

describe('Role Authorization - Fixes #22', () => {
  let app;
  let users;

  beforeAll(() => {
    app = createApp();
    users = getStore('users');
  });

  beforeEach(() => {
    users.clear();
  });

  describe('requireRole verifies role from database', () => {
    it('should deny access when JWT claims admin but DB has user role', async () => {
      // Create a regular user in the store
      users.set('attacker@example.com', {
        id: 'attacker-1',
        email: 'attacker@example.com',
        password: hashPassword('password123'),
        name: 'Attacker',
        role: 'user',
        createdAt: new Date(),
      });

      // Craft a token with escalated admin role (simulating the attack)
      const maliciousToken = generateToken({
        id: 'attacker-1',
        role: 'admin',
        email: 'attacker@example.com',
      });

      // Attempt to access admin-only endpoint
      const res = await request(app)
        .get('/api/users/all')
        .set('Authorization', `Bearer ${maliciousToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Insufficient permissions');
    });

    it('should allow access when both JWT and DB have admin role', async () => {
      // Create an actual admin user in the store
      users.set('admin@example.com', {
        id: 'admin-1',
        email: 'admin@example.com',
        password: hashPassword('password123'),
        name: 'Admin User',
        role: 'admin',
        createdAt: new Date(),
      });

      const adminToken = generateToken({
        id: 'admin-1',
        role: 'admin',
        email: 'admin@example.com',
      });

      const res = await request(app)
        .get('/api/users/all')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
    });

    it('should deny access when user does not exist in database', async () => {
      // Token for a user that has been deleted from the store
      const deletedUserToken = generateToken({
        id: 'deleted-1',
        role: 'admin',
        email: 'deleted@example.com',
      });

      const res = await request(app)
        .get('/api/users/all')
        .set('Authorization', `Bearer ${deletedUserToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Insufficient permissions');
    });

    it('should deny admin delete when JWT claims admin but DB has user role', async () => {
      // Create target user
      users.set('target@example.com', {
        id: 'target-1',
        email: 'target@example.com',
        password: hashPassword('password123'),
        name: 'Target User',
        role: 'user',
        createdAt: new Date(),
      });

      // Create attacker as regular user in DB
      users.set('attacker@example.com', {
        id: 'attacker-1',
        email: 'attacker@example.com',
        password: hashPassword('password123'),
        name: 'Attacker',
        role: 'user',
        createdAt: new Date(),
      });

      // Craft a token with escalated admin role
      const maliciousToken = generateToken({
        id: 'attacker-1',
        role: 'admin',
        email: 'attacker@example.com',
      });

      // Attempt to delete a user via admin endpoint
      const res = await request(app)
        .delete('/api/users/target-1')
        .set('Authorization', `Bearer ${maliciousToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Insufficient permissions');
    });
  });

  describe('PUT /profile mass-assignment prevention', () => {
    it('should not allow role to be updated via profile update', async () => {
      users.set('user@example.com', {
        id: 'user-1',
        email: 'user@example.com',
        password: hashPassword('password123'),
        name: 'Regular User',
        role: 'user',
        createdAt: new Date(),
      });

      const token = generateToken({
        id: 'user-1',
        role: 'user',
        email: 'user@example.com',
      });

      // Attempt to escalate role via mass assignment
      const res = await request(app)
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Updated Name', role: 'admin' });

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('Updated Name');
      expect(res.body.role).toBe('user'); // Role must NOT change

      // Verify in the store that role was not changed
      const storedUser = users.get('user@example.com');
      expect(storedUser.role).toBe('user');
    });

    it('should not allow email to be updated via profile update', async () => {
      users.set('user@example.com', {
        id: 'user-1',
        email: 'user@example.com',
        password: hashPassword('password123'),
        name: 'Regular User',
        role: 'user',
        createdAt: new Date(),
      });

      const token = generateToken({
        id: 'user-1',
        role: 'user',
        email: 'user@example.com',
      });

      const res = await request(app)
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Updated Name', email: 'hacked@example.com' });

      expect(res.status).toBe(200);
      expect(res.body.email).toBe('user@example.com'); // Email must NOT change
    });

    it('should not allow id to be updated via profile update', async () => {
      users.set('user@example.com', {
        id: 'user-1',
        email: 'user@example.com',
        password: hashPassword('password123'),
        name: 'Regular User',
        role: 'user',
        createdAt: new Date(),
      });

      const token = generateToken({
        id: 'user-1',
        role: 'user',
        email: 'user@example.com',
      });

      const res = await request(app)
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Updated Name', id: 'admin-1' });

      expect(res.status).toBe(200);
      expect(res.body.id).toBe('user-1'); // ID must NOT change
    });

    it('should only update allowed fields (name)', async () => {
      users.set('user@example.com', {
        id: 'user-1',
        email: 'user@example.com',
        password: hashPassword('password123'),
        name: 'Original Name',
        role: 'user',
        createdAt: new Date(),
      });

      const token = generateToken({
        id: 'user-1',
        role: 'user',
        email: 'user@example.com',
      });

      const res = await request(app)
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'New Name' });

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('New Name');
    });
  });
});
