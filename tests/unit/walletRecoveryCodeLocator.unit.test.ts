import { expect, test } from '@playwright/test';
import {
  deriveRecoveryCodeLocatorV1,
  deriveRecoveryCodeLocatorV1FromBytes,
} from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeLocator';

test('the code-only locator is stable across recovery-code formatting', async () => {
  const canonical = await deriveRecoveryCodeLocatorV1('ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789');
  const normalized = await deriveRecoveryCodeLocatorV1('abcd efgh jkmn pqrs tvwx yz01 2345 6789');
  expect(normalized).toBe(canonical);
});

test('the locator is code-only and changes when code bytes change', async () => {
  const firstBytes = new Uint8Array(20);
  firstBytes[19] = 3;
  const secondBytes = new Uint8Array(firstBytes);
  secondBytes[19] = 4;
  const first = await deriveRecoveryCodeLocatorV1FromBytes(firstBytes);
  const second = await deriveRecoveryCodeLocatorV1FromBytes(secondBytes);
  expect(second).not.toBe(first);
});
