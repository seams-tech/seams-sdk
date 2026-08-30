import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
} from '@server/router/cloudflare/d1/registration/d1RegistrationCeremonyRecords';
import type { EcdsaDerivationServerBootstrapResponse } from '@server/core/types';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@server/core/thresholdEcdsaChainTarget';
import { fixtureEcdsaRoleLocalPublicCapability } from './helpers/ecdsaBootstrap.fixtures';
import { makeRouterAbEcdsaDerivationNormalSigningStateFixture } from './helpers/ecdsaSessionRecordVariants.fixtures';

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
const EVM_FAMILY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: WALLET_ID,
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
});
const SHARED_OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const CLIENT_SHARE_PUBLIC_KEY_33_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const RELAYER_PUBLIC_KEY_33_B64U = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD';
const GROUP_PUBLIC_KEY_33_B64U = CLIENT_SHARE_PUBLIC_KEY_33_B64U;
const PUBLIC_CAPABILITY = fixtureEcdsaRoleLocalPublicCapability({
  walletId: WALLET_ID,
  evmFamilySigningKeySlotId: EVM_FAMILY_SLOT_ID,
  ecdsaThresholdKeyId: 'threshold-key-evm-family',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  clientVerifyingShareB64u: CLIENT_SHARE_PUBLIC_KEY_33_B64U,
  thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
  ethereumAddress: SHARED_OWNER_ADDRESS,
});

function makeBootstrap(args: {
  readonly targetLabel: string;
  readonly evmFamilySigningKeySlotId?: string;
  readonly keyHandle?: string;
  readonly ecdsaThresholdKeyId?: string;
  readonly relayerKeyId?: string;
  readonly ethereumAddress?: string;
}): EcdsaDerivationServerBootstrapResponse {
  const ethereumAddress = args.ethereumAddress || SHARED_OWNER_ADDRESS;
  const ecdsaThresholdKeyId = args.ecdsaThresholdKeyId || 'threshold-key-evm-family';
  const signingRootId = 'project:dev';
  const signingRootVersion = 'default';
  const routerAbEcdsaDerivationNormalSigning = makeRouterAbEcdsaDerivationNormalSigningStateFixture(
    {
      walletId: WALLET_ID,
      walletKeyId: args.evmFamilySigningKeySlotId || EVM_FAMILY_SLOT_ID,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      clientPublicKey33B64u: CLIENT_SHARE_PUBLIC_KEY_33_B64U,
      serverPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
      thresholdPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
      ethereumAddress,
      activationEpoch: `activation-${args.targetLabel}`,
    },
  );
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId || EVM_FAMILY_SLOT_ID,
    ecdsaThresholdKeyId,
    relayerKeyId: args.relayerKeyId || 'relayer-key-evm-family',
    applicationBindingDigestB64u: `application-binding-${args.targetLabel}`,
    contextBinding32B64u:
      routerAbEcdsaDerivationNormalSigning.scope.public_identity.context_binding_b64u,
    publicIdentity: {
      derivationClientSharePublicKey33B64u:
        routerAbEcdsaDerivationNormalSigning.scope.public_identity
          .derivation_client_share_public_key33_b64u,
      relayerPublicKey33B64u:
        routerAbEcdsaDerivationNormalSigning.scope.public_identity.server_public_key33_b64u,
      groupPublicKey33B64u:
        routerAbEcdsaDerivationNormalSigning.scope.public_identity.threshold_public_key33_b64u,
      ethereumAddress,
    },
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 0,
    publicTranscriptDigest32B64u: `transcript-${args.targetLabel}`,
    keyHandle: args.keyHandle || 'key-handle-evm-family',
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
    ethereumAddress,
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
    participantIds: [1, 2],
    thresholdSessionId: `threshold-session-${args.targetLabel}`,
    activationEpoch: routerAbEcdsaDerivationNormalSigning.scope.activation_epoch,
    expiresAtMs: 1_800_000_000_000,
    expiresAt: '2027-01-15T08:00:00.000Z',
    remainingUses: 10,
    routerAbEcdsaDerivationNormalSigning,
  };
}

test.describe('D1 registration ECDSA wallet keys', () => {
  test('preserves concrete targets while requiring shared EVM-family wallet key material', () => {
    const result = buildD1EcdsaWalletKeysFromBootstrap({
      bootstraps: [
        {
          chainTarget: TEMPO_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'tempo',
          }),
        },
        {
          chainTarget: ARC_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'arc',
          }),
        },
      ],
      publicCapability: PUBLIC_CAPABILITY,
      errorContext: 'registration finalize',
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.walletKeys).toHaveLength(2);
    expect(result.walletKeys[0]).toMatchObject({
      chainTarget: TEMPO_TARGET,
      evmFamilySigningKeySlotId: EVM_FAMILY_SLOT_ID,
      keyHandle: 'key-handle-evm-family',
      thresholdOwnerAddress: SHARED_OWNER_ADDRESS,
    });
    expect(result.walletKeys[1]).toMatchObject({
      chainTarget: ARC_TARGET,
      evmFamilySigningKeySlotId: EVM_FAMILY_SLOT_ID,
      keyHandle: 'key-handle-evm-family',
      thresholdOwnerAddress: SHARED_OWNER_ADDRESS,
    });
  });

  test('rejects partitioned EVM-family wallet key material across Tempo and Arc', () => {
    const result = buildD1EcdsaWalletKeysFromBootstrap({
      bootstraps: [
        {
          chainTarget: TEMPO_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'tempo',
          }),
        },
        {
          chainTarget: ARC_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'arc',
            ethereumAddress: '0x2222222222222222222222222222222222222222',
          }),
        },
      ],
      publicCapability: PUBLIC_CAPABILITY,
      errorContext: 'registration finalize',
    });

    expect(result).toEqual({
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message:
        'registration finalize returned partitioned EVM-family wallet key material: thresholdOwnerAddress',
    });
  });

  test('rejects duplicate target bootstrap material before wallet-key persistence', () => {
    const result = buildD1EcdsaWalletKeysFromBootstrap({
      bootstraps: [
        {
          chainTarget: TEMPO_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'tempo-a',
            evmFamilySigningKeySlotId: EVM_FAMILY_SLOT_ID,
            keyHandle: 'key-handle-tempo-a',
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          }),
        },
        {
          chainTarget: TEMPO_TARGET,
          bootstrap: makeBootstrap({
            targetLabel: 'tempo-b',
            evmFamilySigningKeySlotId: EVM_FAMILY_SLOT_ID,
            keyHandle: 'key-handle-tempo-b',
            ethereumAddress: '0x2222222222222222222222222222222222222222',
          }),
        },
      ],
      publicCapability: PUBLIC_CAPABILITY,
      errorContext: 'registration finalize',
    });

    expect(result).toEqual({
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: 'registration finalize returned duplicate ECDSA wallet key material for tempo:42431',
    });
  });
});
