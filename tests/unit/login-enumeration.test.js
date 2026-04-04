const request = require('supertest');
const app = require('../../src/index');
const { getStore } = require('../../src/utils/persistentStore');
const { hashPassword } = require('../../src/utils/crypto');

describe('Login endpoint - User enumeration prevention (Fixes #24)', () => {
  const TEST_EMAIL = 'enumtest@example.com';
  const TEST_PASSWORD = 'SuperSecure1!@#';
  let users;

  beforeAll(() => {
    users = getStore('users');
    const hashed = hashPassword(TEST_PASSWORD);
    users.set(TEST_EMAIL, {
      id: 'test-user-1',
      email: TEST_EMAIL,
      password: hashed,
      name: 'Test User',
      role: 'user',
      createdAt: new Date(),
    });
  });

  afterAll(() => {
    users.delete(TEST_EMAIL);
  });

  it('should return generic error for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nonexistent@example.com', password: 'SomePass1!@#' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password');
    // Must NOT reveal that the user does not exist
    expect(res.body.error).not.toMatch(/not found/i);
    expect(res.body.error).not.toMatch(/no user/i);
    expect(res.body.error).not.toMatch(/does not exist/i);
  });

  it('should return generic error for wrong password on existing user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password');
    // Must NOT reveal that the password specifically was wrong
    expect(res.body.error).not.toMatch(/wrong password/i);
    expect(res.body.error).not.toMatch(/incorrect password/i);
  });

  it('should return identical error messages for both failure cases', async () => {
    const [notFoundRes, wrongPassRes] = await Promise.all([
      request(app)
        .post('/api/auth/login')
        .send({ email: 'unknown@example.com', password: 'SomePass1!@#' }),
      request(app)
        .post('/api/auth/login')
        .send({ email: TEST_EMAIL, password: 'WrongPass1!@#' }),
    ]);

    // Both must return the exact same status code and error message
    expect(notFoundRes.status).toBe(wrongPassRes.status);
    expect(notFoundRes.body.error).toBe(wrongPassRes.body.error);
  });

  it('should return 200 with token for valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: TEST_EMAIL, password: TEST_PASSWORD });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe(TEST_EMAIL);
  });

});
