import { test, expect } from '@playwright/test';
import { buildCorsOrigins, normalizeCorsOrigin, parseCsvList } from '@server/core/SessionService';

test.describe('CORS origin helpers (server)', () => {
  test('parseCsvList normalizes URLs and dedupes', async () => {
    const out = parseCsvList('https://EXAMPLE.com/, https://example.com, https://example.com/path');
    expect(out).toContain('https://example.com');
    expect(out.filter((x) => x === 'https://example.com').length).toBe(1);
    // URL inputs are normalized to scheme + host (+ optional port) only.
    expect(out.some((x) => x.includes('/path'))).toBe(false);
  });

  test('buildCorsOrigins returns "*" when no inputs', async () => {
    const out = buildCorsOrigins(undefined, '');
    expect(out).toBe('*');
  });

  test('buildCorsOrigins merges CSV lists', async () => {
    const out = buildCorsOrigins('https://a.com, https://b.com', 'https://a.com/');
    expect(out).toEqual(['https://a.com', 'https://b.com']);
  });

  test('parseCsvList canonicalizes default ports', async () => {
    const out = parseCsvList(
      'https://wallet.example.localhost:443,https://wallet.example.localhost,http://localhost:80',
    );
    expect(out).toContain('https://wallet.example.localhost');
    expect(out).toContain('http://localhost');
    expect(out).not.toContain('https://wallet.example.localhost:443');
    expect(out).not.toContain('http://localhost:80');
  });

  test('normalizeCorsOrigin canonicalizes default ports', async () => {
    expect(normalizeCorsOrigin('https://wallet.example.localhost:443')).toBe(
      'https://wallet.example.localhost',
    );
    expect(normalizeCorsOrigin('http://localhost:80')).toBe('http://localhost');
    expect(normalizeCorsOrigin('not-a-url')).toBe(null);
  });
});
