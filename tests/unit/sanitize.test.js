const { sanitizeString, sanitizeObject } = require('../../src/utils/sanitize');

describe('sanitizeString (Fixes #20)', () => {
  it('should strip script tags and their content', () => {
    const input = '<script>alert("xss")</script>';
    expect(sanitizeString(input)).toBe('');
  });

  it('should strip inline event handlers', () => {
    const input = '<img src=x onerror=alert(1)>';
    const result = sanitizeString(input);
    expect(result).not.toContain('onerror');
    expect(result).not.toContain('alert');
  });

  it('should strip anchor tags with javascript: protocol', () => {
    const input = '<a href="javascript:alert(1)">click</a>';
    const result = sanitizeString(input);
    expect(result).not.toContain('javascript:');
    expect(result).not.toContain('<a');
  });

  it('should strip style tags and their content', () => {
    const input = '<style>body{display:none}</style>';
    expect(sanitizeString(input)).toBe('');
  });

  it('should strip all HTML tags', () => {
    const input = '<div><b>bold</b></div>';
    const result = sanitizeString(input);
    expect(result).not.toContain('<');
    expect(result).not.toContain('>');
    expect(result).toContain('bold');
  });

  it('should preserve plain text without HTML', () => {
    expect(sanitizeString('John Doe')).toBe('John Doe');
    expect(sanitizeString('My Checking Account')).toBe('My Checking Account');
    expect(sanitizeString('Payment for invoice #1234')).toBe('Payment for invoice #1234');
  });

  it('should handle empty string', () => {
    expect(sanitizeString('')).toBe('');
  });

  it('should return non-string values unchanged', () => {
    expect(sanitizeString(42)).toBe(42);
    expect(sanitizeString(null)).toBe(null);
    expect(sanitizeString(undefined)).toBe(undefined);
    expect(sanitizeString(true)).toBe(true);
  });

  it('should handle encoded XSS attempts', () => {
    const input = '&lt;script&gt;alert("xss")&lt;/script&gt;';
    const result = sanitizeString(input);
    expect(result).not.toContain('<script>');
  });

  it('should strip nested script tags', () => {
    const input = '<scr<script>ipt>alert(1)</scr</script>ipt>';
    const result = sanitizeString(input);
    expect(result).not.toContain('alert');
  });

  it('should strip SVG-based XSS', () => {
    const input = '<svg onload=alert(1)>';
    const result = sanitizeString(input);
    expect(result).not.toContain('onload');
    expect(result).not.toContain('alert');
  });

  it('should strip iframe tags', () => {
    const input = '<iframe src="http://evil.com"></iframe>';
    const result = sanitizeString(input);
    expect(result).not.toContain('<iframe');
    expect(result).not.toContain('evil.com');
  });
});

describe('sanitizeObject (Fixes #20)', () => {
  it('should sanitize all string values in an object', () => {
    const input = {
      name: '<script>alert("xss")</script>Test',
      description: '<img src=x onerror=alert(1)>',
      amount: 100,
    };
    const result = sanitizeObject(input);
    expect(result.name).not.toContain('<script>');
    expect(result.name).toContain('Test');
    expect(result.description).not.toContain('onerror');
    expect(result.amount).toBe(100);
  });

  it('should return null/undefined unchanged', () => {
    expect(sanitizeObject(null)).toBe(null);
    expect(sanitizeObject(undefined)).toBe(undefined);
  });

  it('should handle empty object', () => {
    expect(sanitizeObject({})).toEqual({});
  });
});
