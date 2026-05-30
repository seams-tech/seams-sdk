import { expect, test } from '@playwright/test';
import { ActionType, type TransactionInputWasm } from '@/core/types/actions';
import { requiredNearTransactionSignatureUses } from '@/core/signingEngine/flows/signNear/signatureUses';
import {
  requiredEvmFamilyRequestSignatureUses,
  requiredEvmFamilySignatureUses,
} from '@/core/signingEngine/flows/signEvmFamily/signatureUses';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/types';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/types';
import type { SigningIntent } from '@/core/signingEngine/interfaces/signing';

function nearTx(actions: TransactionInputWasm['actions']): TransactionInputWasm {
  return {
    receiverId: 'contract.testnet',
    actions,
  };
}

test.describe('signing signature-use accounting', () => {
  test('counts NEAR signature uses by transaction, not action', () => {
    const oneTransactionWithMultipleActions = [
      nearTx([
        {
          action_type: ActionType.FunctionCall,
          method_name: 'setGreeting',
          args: '{}',
          gas: '30000000000000',
          deposit: '0',
        },
        {
          action_type: ActionType.Transfer,
          deposit: '1',
        },
      ]),
    ];

    expect(requiredNearTransactionSignatureUses(oneTransactionWithMultipleActions)).toBe(1);
    expect(
      requiredNearTransactionSignatureUses([
        ...oneTransactionWithMultipleActions,
        nearTx([{ action_type: ActionType.Transfer, deposit: '2' }]),
      ]),
    ).toBe(2);
  });

  test('counts current EVM and Tempo requests as one threshold signature', () => {
    const evmRequest: EvmSigningRequest = {
      chain: 'evm',
      kind: 'eip1559',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        chainId: 11155111,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 21_000n,
        value: 0n,
      },
    };
    const tempoRequest: TempoSigningRequest = {
      chain: 'tempo',
      kind: 'tempoTransaction',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        chainId: 42431,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 100_000n,
        nonceKey: 1n,
        calls: [
          { to: `0x${'11'.repeat(20)}`, value: 0n },
          { to: `0x${'22'.repeat(20)}`, value: 1n },
        ],
      },
    };

    expect(requiredEvmFamilyRequestSignatureUses(evmRequest)).toBe(1);
    expect(requiredEvmFamilyRequestSignatureUses(tempoRequest)).toBe(1);
  });

  test('counts future EVM-family batch intents by secp256k1 digest request', () => {
    const intent: SigningIntent<unknown, object> = {
      chain: 'evm',
      uiModel: {},
      signRequests: [
        { kind: 'digest', algorithm: 'secp256k1', digest32: new Uint8Array(32) },
        { kind: 'digest', algorithm: 'secp256k1', digest32: new Uint8Array(32).fill(1) },
      ],
      finalize: async () => ({}),
    };

    expect(requiredEvmFamilySignatureUses(intent)).toBe(2);
  });
});
