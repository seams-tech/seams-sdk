import { expect, test } from '@playwright/test';
import { walletCustodyCeremonyStepRunner } from '../../packages/wallet/src/core/signingEngine/walletCustody/ceremonyStepRunner';

/**
 * The adapter between the worker transport and the ceremony driver.
 *
 * One property, and it is the whole reason this is a named seam: every step of
 * a run goes to the same channel. The seed and the owner roots live in that
 * worker's wasm state between steps, so a step dispatched anywhere else finds
 * no run to continue — and the failure would surface as a mid-ceremony error
 * with a live seed still held.
 */

test('every step goes to the ceremony channel, shaped as the worker expects', async () => {
  const sent: { kind: string; request: unknown }[] = [];
  const runner = walletCustodyCeremonyStepRunner({
    requestOperation: async (args) => {
      sent.push(args);
      return { yaoExecuteRequestJson: '{}' };
    },
  });

  await runner('beginWalletCustodyKeySetRun', {
    ceremonyId: 'ceremony-1',
    keySet: 'near_ed25519_v1',
    custody: { origin: 'establish', walletId: 'alice.testnet' },
    protocolInputsJson: '{}',
  } as never);
  await runner('discardWalletCustodyCeremony', { ceremonyId: 'ceremony-1' } as never);

  expect(sent.map((entry) => entry.kind)).toEqual([
    'walletCustodyCeremony',
    'walletCustodyCeremony',
  ]);
  expect(sent[0].request).toMatchObject({ type: 'beginWalletCustodyKeySetRun' });
  expect(sent[1].request).toMatchObject({ type: 'discardWalletCustodyCeremony' });
});

test('the worker result is returned unchanged', async () => {
  // The driver reads the run's public protocol messages straight off this.
  const runner = walletCustodyCeremonyStepRunner({
    requestOperation: async () => ({ yaoExecuteRequestJson: '{"execute":true}' }),
  });

  const begun = await runner('beginWalletCustodyKeySetRun', {
    ceremonyId: 'ceremony-1',
    keySet: 'near_ed25519_v1',
    custody: { origin: 'establish', walletId: 'alice.testnet' },
    protocolInputsJson: '{}',
  } as never);

  expect(begun.yaoExecuteRequestJson).toBe('{"execute":true}');
});

test('a transport failure propagates so the driver can discard the run', async () => {
  /* The driver's catch is what discards a run whose protocol round failed —
     swallowing the error here would leave the worker holding a seed. */
  const runner = walletCustodyCeremonyStepRunner({
    requestOperation: async () => {
      throw new Error('worker is gone');
    },
  });

  await expect(
    runner('discardWalletCustodyCeremony', { ceremonyId: 'ceremony-1' } as never),
  ).rejects.toThrow(/worker is gone/);
});
