import { expect, test } from '@playwright/test';
import { ActionType } from '@/core/types/actions';
import { signNearWithUiConfirm } from '@/core/signingEngine/flows/signNear/nearSigningFlow';

test.describe('NEAR transaction signing shape', () => {
  test('rejects multi-transaction signing before signing-session admission', async () => {
    await expect(
      signNearWithUiConfirm({
        chain: 'near',
        kind: 'transactionWithActions',
        payload: {
          nearAccount: { accountId: 'alice.testnet' },
          rpcCall: { nearAccountId: 'alice.testnet' },
          transactions: [
            {
              receiverId: 'contract-a.testnet',
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
            {
              receiverId: 'contract-b.testnet',
              actions: [{ action_type: ActionType.Transfer, deposit: '2' }],
            },
          ],
        },
      } as never),
    ).rejects.toThrow('exactly one NEAR transaction is supported');
  });
});
