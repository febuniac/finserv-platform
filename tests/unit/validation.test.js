const { accountSchema, transactionSchema, loginSchema, userSchema } = require('../../src/utils/validation');

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

  describe('userSchema - password complexity (Fixes #23)', () => {
    const validUser = {
      email: 'test@example.com',
      password: 'StrongP@ss1234',
      name: 'Test User',
    };

    it('should accept a valid password meeting all complexity requirements', () => {
      const { error } = userSchema.validate(validUser);
      expect(error).toBeUndefined();
    });

    it('should reject a single character password like "1"', () => {
      const { error } = userSchema.validate({ ...validUser, password: '1' });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/at least 12 characters/);
    });

    it('should reject an empty password', () => {
      const { error } = userSchema.validate({ ...validUser, password: '' });
      expect(error).toBeDefined();
    });

    it('should reject a password shorter than 12 characters', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'Abcde1!fgh' });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/at least 12 characters/);
    });

    it('should reject a password of exactly 11 characters', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'Abcde1!fghJ' });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/at least 12 characters/);
    });

    it('should accept a password of exactly 12 characters with all requirements', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'Abcde1!fghJk' });
      expect(error).toBeUndefined();
    });

    it('should reject a password exceeding 128 characters', () => {
      const longPassword = 'A1a!' + 'x'.repeat(126);
      const { error } = userSchema.validate({ ...validUser, password: longPassword });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/must not exceed 128 characters/);
    });

    it('should reject a password without uppercase letters', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'alllowercase1!' });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/uppercase letter/);
    });

    it('should reject a password without lowercase letters', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'ALLUPPERCASE1!' });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/lowercase letter/);
    });

    it('should reject a password without numbers', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'NoNumbersHere!' });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/number/);
    });

    it('should reject a password without special characters', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'NoSpecialChar1' });
      expect(error).toBeDefined();
      expect(error.details[0].message).toMatch(/special character/);
    });

    it('should reject a password with only numbers', () => {
      const { error } = userSchema.validate({ ...validUser, password: '123456789012' });
      expect(error).toBeDefined();
    });

    it('should reject a password with only lowercase letters', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'abcdefghijkl' });
      expect(error).toBeDefined();
    });

    it('should accept passwords with various special characters', () => {
      const specialChars = ['@', '$', '!', '%', '*', '?', '&', '#', '^', '-', '_', '='];
      for (const char of specialChars) {
        const { error } = userSchema.validate({
          ...validUser,
          password: `Abcdefghij1${char}`,
        });
        expect(error).toBeUndefined();
      }
    });

    it('should reject a common weak password', () => {
      const { error } = userSchema.validate({ ...validUser, password: 'password' });
      expect(error).toBeDefined();
    });

    it('should require password field to be present', () => {
      const { password, ...noPassword } = validUser;
      const { error } = userSchema.validate(noPassword);
      expect(error).toBeDefined();
    });

    it('should validate all fields together for a complete valid user', () => {
      const { error, value } = userSchema.validate({
        email: 'newuser@finserv.com',
        password: 'MyStr0ng!Pass',
        name: 'Jane Doe',
      });
      expect(error).toBeUndefined();
      expect(value.email).toBe('newuser@finserv.com');
      expect(value.name).toBe('Jane Doe');
    });
  });
});
