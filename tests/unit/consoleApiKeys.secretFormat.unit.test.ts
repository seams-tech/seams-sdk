import { test, expect } from '@playwright/test';
import {
  makeApiKeyLookupPrefix,
  makeApiKeySecret,
  parseApiKeySecret,
} from '@server/console/apiKeys/secret';

test.describe('console API key secret format', () => {
  test('creates short opaque publishable keys', async () => {
    const secret = makeApiKeySecret({ kind: 'publishable_key' });

    expect(secret).toMatch(/^pk_[A-Za-z0-9_-]+$/);
    expect(secret).not.toContain('.');
    expect(secret.length).toBeLessThan(50);
    expect(parseApiKeySecret(secret)).toEqual({ kind: 'publishable_key' });
    expect(makeApiKeyLookupPrefix(secret)).toBe(secret.slice(0, 24));
  });

  test('creates short opaque secret keys', async () => {
    const secret = makeApiKeySecret({ kind: 'secret_key' });

    expect(secret).toMatch(/^sk_[A-Za-z0-9_-]+$/);
    expect(secret).not.toContain('.');
    expect(secret.length).toBeLessThan(50);
    expect(parseApiKeySecret(secret)).toEqual({ kind: 'secret_key' });
  });

  test('rejects legacy dotted token layouts', async () => {
    expect(parseApiKeySecret('pk_org.part.keypart')).toBeNull();
    expect(parseApiKeySecret('sk_org.part.keypart')).toBeNull();
  });
});
