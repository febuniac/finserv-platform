const { accountSchema, transactionSchema, loginSchema } = require('../../src/utils/validation');

describe('Validation Schemas', () => {
  describe('accountSchema', () => {
    it('should validate a valid account', () => {
      const { error } = accountSchema.validate({
        name: 'My Checking',
        type: 'checking',
      });
      expect(error).toBeUndefined();
    });

    it('should reject invalid account type', () => {
      const { error } = accountSchema.validate({
        name: 'My Account',
        type: 'invalid',
      });
      expect(error).toBeDefined();
    });
  });

  describe('transactionSchema', () => {
    it('should validate a valid transaction', () => {
      const { error } = transactionSchema.validate({
        fromAccountId: '123e4567-e89b-12d3-a456-426614174000',
        toAccountId: '123e4567-e89b-12d3-a456-426614174001',
        amount: 100,
      });
      expect(error).toBeUndefined();
    });

    // BUG: No test for negative amounts
    // BUG: No test for zero amount
    // BUG: No test for maximum amount limits
  });

  describe('loginSchema', () => {
    it('should validate valid login', () => {
      const { error } = loginSchema.validate({
        email: 'user@test.com',
        password: 'password123',
      });
      expect(error).toBeUndefined();
    });
  });
});
