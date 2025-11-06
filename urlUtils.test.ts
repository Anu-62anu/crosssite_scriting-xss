import { describe, expect, it } from 'vitest';
import { sanitizeAbsoluteUrl, sanitizeUrlOrigin } from './urlUtils';

describe('sanitizeAbsoluteUrl', () => {
  it('returns null for empty or whitespace strings', () => {
    expect(sanitizeAbsoluteUrl('')).toBeNull();
    expect(sanitizeAbsoluteUrl('   ')).toBeNull();
    expect(sanitizeAbsoluteUrl(undefined)).toBeNull();
  });

  it('allows secure absolute URLs', () => {
    expect(sanitizeAbsoluteUrl('https://example.com/path')).toBe(
      'https://example.com/path',
    );
  });

  it('normalizes hostnames without protocol to https', () => {
    expect(sanitizeAbsoluteUrl('example.org/login')).toBe(
      'https://example.org/login',
    );
  });

  it('rejects URLs with dangerous protocols or patterns', () => {
    expect(sanitizeAbsoluteUrl('javascript:alert(1)')).toBeNull();
    expect(sanitizeAbsoluteUrl('SELECT * FROM users; DROP TABLE users;')).toBeNull();
    expect(sanitizeAbsoluteUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==')).toBeNull();
  });
});

describe('sanitizeUrlOrigin', () => {
  it('returns the origin of a sanitized URL', () => {
    expect(sanitizeUrlOrigin('https://example.com/path?q=1')).toBe(
      'https://example.com',
    );
  });

  it('returns null when sanitization fails', () => {
    expect(sanitizeUrlOrigin('javascript:alert(1)')).toBeNull();
  });
});
