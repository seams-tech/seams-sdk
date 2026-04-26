import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test.describe('evm signing nonce prefetch hook', () => {
  test('prefetches nonce state as soon as reservation input resolves', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const evmSigningPath = path.join(
      repoRoot,
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
    );
    const source = fs.readFileSync(evmSigningPath, 'utf8');

    expect(
      source.includes('const reservationInputPromise = resolveManagedEvmNonceReservationInput({'),
    ).toBe(true);
    expect(
      source.includes('args.deps.nonceCoordinator.reconcile({'),
    ).toBe(true);
    expect(source.includes('reservationInput: await reservationInputPromise')).toBe(true);
  });
});
