const { redactString, redactObject, sensitiveFields } = require('../../src/utils/logger');

describe('Logger Sanitization (Fixes #19)', () => {
  describe('redactString', () => {
    it('should redact email addresses', () => {
      const input = 'User logged in: user@example.com';
      const result = redactString(input);
      expect(result).not.toContain('user@example.com');
      expect(result).toContain('[REDACTED_EMAIL]');
    });

    it('should redact multiple email addresses', () => {
      const input = 'From admin@test.com to user@example.com';
      const result = redactString(input);
      expect(result).not.toContain('admin@test.com');
      expect(result).not.toContain('user@example.com');
      expect(result.match(/\[REDACTED_EMAIL\]/g)).toHaveLength(2);
    });

    it('should redact password key-value patterns', () => {
      const input = 'password: "secret123"';
      const result = redactString(input);
      expect(result).not.toContain('secret123');
      expect(result).toContain('[REDACTED]');
    });

    it('should redact token key-value patterns', () => {
      const input = 'token=abc123xyz';
      const result = redactString(input);
      expect(result).not.toContain('abc123xyz');
      expect(result).toContain('[REDACTED]');
    });

    it('should redact resetToken key-value patterns', () => {
      const input = 'resetToken: "a1b2c3d4e5f6"';
      const result = redactString(input);
      expect(result).not.toContain('a1b2c3d4e5f6');
      expect(result).toContain('[REDACTED]');
    });

    it('should redact authorization headers', () => {
      const input = 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test';
      const result = redactString(input);
      expect(result).not.toContain('eyJhbGciOiJIUzI1NiJ9');
      expect(result).toContain('[REDACTED]');
    });

    it('should redact SSN patterns', () => {
      const input = 'ssn: "123-45-6789"';
      const result = redactString(input);
      expect(result).not.toContain('123-45-6789');
      expect(result).toContain('[REDACTED]');
    });

    it('should redact creditCard patterns', () => {
      const input = 'creditCard: "4111111111111111"';
      const result = redactString(input);
      expect(result).not.toContain('4111111111111111');
      expect(result).toContain('[REDACTED]');
    });

    it('should not redact non-sensitive data', () => {
      const input = 'User with id 12345 performed action';
      const result = redactString(input);
      expect(result).toBe(input);
    });

    it('should handle case-insensitive field names', () => {
      const input = 'PASSWORD: "mypass" and Token: "mytoken"';
      const result = redactString(input);
      expect(result).not.toContain('mypass');
      expect(result).not.toContain('mytoken');
    });
  });

  describe('redactObject', () => {
    it('should redact sensitive keys in objects', () => {
      const input = { username: 'john', password: 'secret123', email: 'john@example.com' };
      const result = redactObject(input);
      expect(result.password).toBe('[REDACTED]');
      expect(result.username).toBe('john');
    });

    it('should redact email addresses in string values', () => {
      const input = { message: 'Sent to user@example.com' };
      const result = redactObject(input);
      expect(result.message).not.toContain('user@example.com');
      expect(result.message).toContain('[REDACTED_EMAIL]');
    });

    it('should redact token fields', () => {
      const input = { resetToken: 'abc123', accessToken: 'xyz789' };
      const result = redactObject(input);
      expect(result.resetToken).toBe('[REDACTED]');
      expect(result.accessToken).toBe('[REDACTED]');
    });

    it('should handle nested objects', () => {
      const input = { user: { name: 'John', password: 'secret', ssn: '123-45-6789' } };
      const result = redactObject(input);
      expect(result.user.password).toBe('[REDACTED]');
      expect(result.user.ssn).toBe('[REDACTED]');
      expect(result.user.name).toBe('John');
    });

    it('should handle arrays', () => {
      const input = [{ password: 'secret' }, { token: 'abc' }];
      const result = redactObject(input);
      expect(result[0].password).toBe('[REDACTED]');
      expect(result[1].token).toBe('[REDACTED]');
    });

    it('should return null/undefined as-is', () => {
      expect(redactObject(null)).toBeNull();
      expect(redactObject(undefined)).toBeUndefined();
    });

    it('should return primitives as-is', () => {
      expect(redactObject(42)).toBe(42);
      expect(redactObject(true)).toBe(true);
    });

    it('should redact authorization field', () => {
      const input = { authorization: 'Bearer eyJhbG...' };
      const result = redactObject(input);
      expect(result.authorization).toBe('[REDACTED]');
    });

    it('should redact cookie field', () => {
      const input = { cookie: 'session=abc123; token=xyz' };
      const result = redactObject(input);
      expect(result.cookie).toBe('[REDACTED]');
    });

    it('should redact credit card fields', () => {
      const input = { creditCard: '4111111111111111', cvv: '123' };
      const result = redactObject(input);
      expect(result.creditCard).toBe('[REDACTED]');
      expect(result.cvv).toBe('[REDACTED]');
    });
  });

  describe('sensitiveFields', () => {
    it('should contain all critical PCI-DSS and GDPR fields', () => {
      const required = ['password', 'token', 'ssn', 'creditCard', 'cvv', 'authorization', 'resetToken'];
      required.forEach((field) => {
        expect(sensitiveFields).toContain(field);
      });
    });
  });
});
