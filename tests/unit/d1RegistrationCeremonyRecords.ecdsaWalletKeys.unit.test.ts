import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { buildD1EcdsaWalletKeysFromBootstrap } from '@server/router/cloudflare/d1RegistrationCeremonyRecords';
import type { EcdsaHssServerBootstrapResponse } from '@server/core/types';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@server/core/thresholdEcdsaChainTarget';

const TEMPO_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 42_431,
  networkSlug: 'tempo-moderato',
};
const ARC_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5_042_002,
  networkSlug: 'arc-testnet',
};
const WALLET_ID = 'wallet-registration-ecdsa-targets';
const TEMPO_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: WALLET_ID,
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  chainTargetKey: thresholdEcdsaChainTargetKey(TEMPO_TARGET),
});
const ARC_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: WALLET_ID,
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  chainTargetKey: thresholdEcdsaChainTargetKey(ARC_TARGET),
});

function makeBootstrap(args: {
  readonly targetLabel: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly keyHandle: string;
  readonly ethereumAddress: string;
}): EcdsaHssServerBootstrapResponse {
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: `threshold-key-${args.targetLabel}`,
    relayerKeyId: `relayer-key-${args.targetLabel}`,
    applicationBindingDigestB64u: `application-binding-${args.targetLabel}`,
    contextBinding32B64u: `context-binding-${args.targetLabel}`,
    publicIdentity: {
      hssClientSharePublicKey33B64u: `client-share-${args.targetLabel}`,
      relayerPublicKey33B64u: `relayer-share-${args.targetLabel}`,
      groupPublicKey33B64u: `group-public-${args.targetLabel}`,
      ethereumAddress: args.ethereumAddress,
    },
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 0,
    publicTranscriptDigest32B64u: `transcript-${args.targetLabel}`,
    keyHandle: args.keyHandle,
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    thresholdEcdsaPublicKeyB64u: `group-public-${args.targetLabel}`,
    ethereumAddress: args.ethereumAddress,
    relayerVerifyingShareB64u: `relayer-verifying-${args.targetLabel}`,
    participantIds: [1, 2],
    thresholdSessionId: `threshold-session-${args.targetLabel}`,
    signingGrantId: `signing-grant-${args.targetLabel}`,
    expiresAtMs: 1_800_000_000_000,
    expiresAt: '2027-01-15T08:00:00.000Z',
    remainingUses: 10,
  };
}

test.describe('D1 registration ECDSA wallet keys', () => {
  test('preserves target-specific ECDSA bootstrap facts across Tempo and Arc', () => {
    const result = buildD1EcdsaWalletKeysFromBootstrap({
      bootstraps: [
        {
          chainTarget: TEMPO_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'tempo',
            evmFamilySigningKeySlotId: TEMPO_SLOT_ID,
            keyHandle: 'key-handle-tempo',
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          }),
        },
        {
          chainTarget: ARC_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'arc',
            evmFamilySigningKeySlotId: ARC_SLOT_ID,
            keyHandle: 'key-handle-arc',
            ethereumAddress: '0x2222222222222222222222222222222222222222',
          }),
        },
      ],
      errorContext: 'registration finalize',
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.walletKeys).toHaveLength(2);
    expect(result.walletKeys[0]).toMatchObject({
      chainTarget: TEMPO_TARGET,
      evmFamilySigningKeySlotId: TEMPO_SLOT_ID,
      keyHandle: 'key-handle-tempo',
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
    });
    expect(result.walletKeys[1]).toMatchObject({
      chainTarget: ARC_TARGET,
      evmFamilySigningKeySlotId: ARC_SLOT_ID,
      keyHandle: 'key-handle-arc',
      thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
    });
  });

  test('rejects duplicate target bootstrap material before wallet-key persistence', () => {
    const result = buildD1EcdsaWalletKeysFromBootstrap({
      bootstraps: [
        {
          chainTarget: TEMPO_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'tempo-a',
            evmFamilySigningKeySlotId: TEMPO_SLOT_ID,
            keyHandle: 'key-handle-tempo-a',
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          }),
        },
        {
          chainTarget: TEMPO_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'tempo-b',
            evmFamilySigningKeySlotId: TEMPO_SLOT_ID,
            keyHandle: 'key-handle-tempo-b',
            ethereumAddress: '0x2222222222222222222222222222222222222222',
          }),
        },
      ],
      errorContext: 'registration finalize',
    });

    expect(result).toEqual({
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message:
        'registration finalize returned duplicate ECDSA wallet key material for tempo:42431',
    });
  });
});
