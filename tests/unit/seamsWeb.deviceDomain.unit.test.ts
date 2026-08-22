import { expect, test } from '@playwright/test';
import { resolveSeamsWebDeviceDomainModeV1 } from '@/SeamsWeb/SeamsWeb';

test('wallet-host SeamsWeb selects direct device linking', () => {
  expect(resolveSeamsWebDeviceDomainModeV1('wallet_host')).toBe('direct');
  expect(resolveSeamsWebDeviceDomainModeV1('application')).toBe('iframe');
});
