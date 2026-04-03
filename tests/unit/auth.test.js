const { hashPassword, generateToken } = require('../../src/utils/crypto');

describe('Auth Utils', () => {
  describe('hashPassword', () => {
    it('should hash a password', () => {
      const hash = hashPassword('testpassword');
      expect(hash).toBeDefined();
      expect(hash).not.toBe('testpassword');
    });

    // BUG: Test doesn't verify hash consistency
    it('should produce consistent hashes', () => {
      const hash1 = hashPassword('test');
      const hash2 = hashPassword('test');
      expect(hash1).toBe(hash2);
    });
  });

  describe('generateToken', () => {
    it('should generate a token', () => {
      const token = generateToken();
      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(10);
    });

    // BUG: Test doesn't verify uniqueness
    it('should generate unique tokens', () => {
      const token1 = generateToken();
      const token2 = generateToken();
      // This could fail due to timing - tokens use Date.now()
      expect(token1).not.toBe(token2);
    });
  });
});
