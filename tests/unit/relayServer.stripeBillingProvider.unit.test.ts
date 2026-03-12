import { expect, test } from '@playwright/test';
import {
  createStripeBillingProviderAdapter,
  normalizeOptionalStripePublishableKey,
  normalizeStripeSecretKey,
} from '../../examples/relay-server/src/stripeBillingProvider';

test.describe('relay-server stripe billing provider config', () => {
  test('accepts Stripe secret and restricted keys for server-side billing', async () => {
    expect(normalizeStripeSecretKey('sk_test_123')).toBe('sk_test_123');
    expect(normalizeStripeSecretKey('rk_test_123')).toBe('rk_test_123');
    expect(createStripeBillingProviderAdapter({ secretKey: 'sk_test_123' })).toBeTruthy();
  });

  test('rejects publishable keys in STRIPE_API_SK', async () => {
    expect(() => normalizeStripeSecretKey('pk_test_123')).toThrow(
      'STRIPE_API_SK must be a Stripe secret key (sk_...) or restricted key (rk_...), not a publishable key.',
    );
    expect(() => createStripeBillingProviderAdapter({ secretKey: 'pk_test_123' })).toThrow(
      'STRIPE_API_SK must be a Stripe secret key (sk_...) or restricted key (rk_...), not a publishable key.',
    );
  });

  test('accepts publishable STRIPE_API_PK values and rejects secret keys', async () => {
    expect(normalizeOptionalStripePublishableKey('')).toBe('');
    expect(normalizeOptionalStripePublishableKey('pk_test_123')).toBe('pk_test_123');
    expect(() => normalizeOptionalStripePublishableKey('sk_test_123')).toThrow(
      'STRIPE_API_PK must be a Stripe publishable key (pk_...).',
    );
  });
});
