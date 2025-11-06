import { describe, expect, it } from 'vitest';
import { buildContentSecurityPolicy } from './csp';

describe('buildContentSecurityPolicy', () => {
  it('returns base directives with upgrade-insecure-requests', () => {
    const policy = buildContentSecurityPolicy();

    const directives = policy.split('; ').map(entry => entry.trim());

    expect(directives).toContain("default-src 'self'");
    expect(directives).toContain("script-src 'self' 'unsafe-inline' 'unsafe-eval'");
    expect(directives).toContain('upgrade-insecure-requests');
    expect(directives).toContain("object-src 'none'");
  });

  it('adds supplied hosts to common directives', () => {
    const policy = buildContentSecurityPolicy({
      api: 'https://api.example.com',
      cdn: ['https://cdn.example.com', 'https://assets.example.com'],
    });

    const directives = Object.fromEntries(
      policy
        .split('; ')
        .filter(Boolean)
        .map(entry => {
          const [name, ...values] = entry.split(' ');
          return [name, values];
        }),
    );

    const expectedHosts = [
      'https://api.example.com',
      'https://cdn.example.com',
      'https://assets.example.com',
    ];

    for (const directive of ['script-src', 'connect-src', 'img-src', 'frame-src']) {
      expect(directives[directive]).toEqual(
        expect.arrayContaining(expectedHosts),
      );
    }

    // Ensure other directives remain unchanged
    expect(directives['object-src']).toEqual(["'none'"]);
  });
});
