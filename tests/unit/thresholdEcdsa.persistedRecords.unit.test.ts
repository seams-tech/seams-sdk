import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  parseCurrentRouterAbEcdsaDerivationPoolFillSessionRow,
  parseCurrentThresholdEd25519KeyRecord,
} from '../../packages/wallet-server/src/core/ThresholdService/persistedRecords';

const ed25519AuthorityScope = { kind: 'passkey_rp' as const, rpId: 'example.localhost' };

test.describe('threshold ecdsa persisted records', () => {
  test('parses current Ed25519 records', async () => {
    expect(
      parseCurrentThresholdEd25519KeyRecord({
        kind: 'ready',
        walletId: 'frost-vermillion-k7p9m2',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-frost-vermillion-k7p9m2',
        authorityScope: ed25519AuthorityScope,
        publicKey: 'ed25519:public',
        routerMaterial: {
          signingShareB64u: 'signing-share',
          verifyingShareB64u: 'verifying-share',
        },
        keyVersion: 'key-v1',
        recoveryExportCapable: true,
      }),
    ).toEqual({
      kind: 'ready',
      walletId: 'frost-vermillion-k7p9m2',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-frost-vermillion-k7p9m2',
      authorityScope: ed25519AuthorityScope,
      publicKey: 'ed25519:public',
      routerMaterial: {
        signingShareB64u: 'signing-share',
        verifyingShareB64u: 'verifying-share',
      },
      keyVersion: 'key-v1',
      recoveryExportCapable: true,
    });
    expect(
      parseCurrentThresholdEd25519KeyRecord({
        kind: 'ready',
        walletId: 'frost-vermillion-k7p9m2',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-frost-vermillion-k7p9m2',
        rpId: 'example.localhost',
        publicKey: 'ed25519:public',
        routerMaterial: {
          signingShareB64u: 'signing-share',
          verifyingShareB64u: 'verifying-share',
        },
        keyVersion: 'key-v1',
        recoveryExportCapable: true,
      }),
    ).toBeNull();
  });

  test('rejects obsolete or malformed presign session rows', () => {
    const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
      walletId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'default',
    });
    expect(
      parseCurrentRouterAbEcdsaDerivationPoolFillSessionRow({
        recordJson: {
          expiresAtMs: 999_999,
          walletId: 'alice.testnet',
          evmFamilySigningKeySlotId,
          relayerKeyId: 'relayer-key',
          presignPoolKey: 'keyHandle:threshold-key',
          poolFill: { kind: 'local_threshold_ecdsa_presignature_pool' },
          participantIds: [2, 1],
          clientParticipantId: 1,
          relayerParticipantId: 2,
          stage: 'triples',
          version: 1,
          createdAtMs: 100,
          updatedAtMs: 150,
          signingRootId: 'signing-root',
          signingRootVersion: 'default',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 999_999,
      }),
    ).toBeNull();

    expect(
      parseCurrentRouterAbEcdsaDerivationPoolFillSessionRow({
        recordJson: {
          expiresAtMs: 999_999,
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerKeyId: 'relayer-key',
          presignPoolKey: 'keyHandle:threshold-key',
          participantIds: [1, 2],
          clientParticipantId: 1,
          relayerParticipantId: 2,
          stage: 'triples',
          version: 1,
          createdAtMs: 100,
          updatedAtMs: 99,
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 999_999,
      }),
    ).toBeNull();
  });
});
