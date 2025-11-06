import { describe, expect, it } from 'vitest';
import { sanitizeAbsoluteUrl, sanitizeUrlOrigin, encodeUrlsDeep } from './urlUtils';

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

describe('encodeUrlsDeep', () => {
  it('encodes url-like strings when key hints at a URL', () => {
    const result = encodeUrlsDeep({ profileUrl: 'https://exa mple.com/a b' });
    expect(result).toEqual({ profileUrl: 'https://exa%20mple.com/a%20b' });
  });

  it('encodes bare url strings that look like URLs', () => {
    const result = encodeUrlsDeep({ website: 'www.example.com/some path' });
    expect(result).toEqual({ website: 'www.example.com/some%20path' });
  });

  it('marks dangerous values as removed', () => {
    const payload = {
      link: 'javascript:alert(1)',
      nested: ['https://ok.example', 'data:text/html;base64,PGhlbGxvPg=='],
    };

    const result = encodeUrlsDeep(payload);
    expect(result).toEqual({
      link: '[unsafe-url-removed]',
      nested: ['https://ok.example', '[unsafe-url-removed]'],
    });
  });

  it('handles circular references gracefully', () => {
    const obj: Record<string, unknown> = { self: null };
    obj.self = obj;

    expect(() => encodeUrlsDeep(obj)).not.toThrow();
  });
});
