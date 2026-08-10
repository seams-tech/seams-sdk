import { expect, test } from '@playwright/test';
import type {
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
} from '../../packages/sdk-server-ts/src/core/WalletStore';
import {
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
} from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/walletRecoveryKeyManifest';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  deriveWalletRecoveryKeyLifecycleId,
  parseRecoveryCodeReservationId,
} from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeReservation';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import { buildRouterAbEd25519YaoCapabilityReplacementFixture } from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';

const WALLET_ID = walletIdFromString('alice.testnet');

type RecoveryRegistryState = {
  readonly ed25519Signers: readonly WalletEd25519SignerRecord[];
  readonly ecdsaSigners: readonly WalletEcdsaSignerRecord[];
};

function registry(state: RecoveryRegistryState) {
  return {
    listEd25519SignersForWallet: async () => state.ed25519Signers,
    listEcdsaSignersForWallet: async () => state.ecdsaSigners,
  };
}

function recoveredEd25519Signer(lifecycleId?: string): WalletEd25519SignerRecord {
  const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture(lifecycleId);
  const capability = fixture.next;
  if (capability.version !== 'wallet_ed25519_yao_recovery_capability_v1') {
    throw new Error('Ed25519 recovery fixture did not build a recovery capability');
  }
  const application = capability.admissionRequest.application_binding;
  const scope = capability.admissionRequest.scope;
  return buildYaoEd25519WalletSignerRecord({
    walletId: walletIdFromString(fixture.walletId),
    nearAccountId: fixture.nearAccountId,
    nearEd25519SigningKeyId: fixture.nearSigningKeyId,
    thresholdSessionId: scope.threshold_session_id,
    signerSlot: application.key_creation_signer_slot,
    publicKey: ed25519NearPublicKeyFromBytes(
      capability.activationResult.public_receipt.registered_public_key,
    ),
    signingWorkerId: fixture.signingWorkerId,
    keyVersion: 'yao-recovery-key-v1',
    participantIds: capability.admissionRequest.participant_ids,
    signingRootId: application.signing_root_id,
    signingRootVersion: scope.root_share_epoch,
    runtimePolicyScope: capability.runtimePolicyScope,
    activeYaoCapability: capability,
    now: Date.now(),
  });
}

test('the server manifest deduplicates EVM chain targets by exact key handle', async () => {
  const now = Date.now();
  const base = createWalletEcdsaSignerRecord({ walletId: WALLET_ID, now });
  const secondTarget = createWalletEcdsaSignerRecord({
    walletId: WALLET_ID,
    now,
    keyHandle: base.walletKey.keyHandle,
    walletKeyOverrides: {
      chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 42161 },
      publicCapability: base.walletKey.publicCapability,
    },
  });
  const manifest = await resolveWalletRecoveryKeyManifestV1({
    registry: registry({ ed25519Signers: [], ecdsaSigners: [base, secondTarget] }),
    walletId: WALLET_ID,
  });

  expect(manifest.entries).toHaveLength(1);
  expect(manifest.entries[0]).toMatchObject({
    kind: 'evm_family_ecdsa',
    keySetId: `evm_family_ecdsa:${base.walletKey.keyHandle}`,
    chainTargetKeys: [base.chainTargetKey, secondTarget.chainTargetKey].sort(),
  });
});

test('Ed25519 recovery must be the durable capability for this reservation', async () => {
  const preliminarySigner = recoveredEd25519Signer();
  const correlationId = parseRecoveryCodeReservationId('wallet-recovery-reservation-1');
  const lifecycleId = await deriveWalletRecoveryKeyLifecycleId({
    reservationId: correlationId,
    keySetId: `near_ed25519:${preliminarySigner.signerId}`,
  });
  const signer = recoveredEd25519Signer(lifecycleId);
  const authorityRef = await walletAuthAuthorityRef({
    authority: buildEmailOtpWalletAuthAuthority({
      walletId: String(signer.walletId),
      provider: 'email',
      providerUserId: 'wallet-recovery-manifest-user',
      emailHashHex: 'wallet-recovery-manifest-email-hash',
    }),
  });
  const verificationContext = {
    replacementId: 'wallet-recovery-replacement-1',
    authorityRef,
    ecdsaPossessionChallenges: [],
    ecdsaActivationReceipts: [],
    ecdsaMaterialPossessionProofs: [],
    nowMs: Date.now(),
  } as const;
  const accepted = await verifyWalletRecoveryKeyActivationsV1({
    registry: registry({ ed25519Signers: [signer], ecdsaSigners: [] }),
    walletId: signer.walletId,
    recoveryCorrelationId: correlationId,
    ...verificationContext,
  });
  const unrelated = await verifyWalletRecoveryKeyActivationsV1({
    registry: registry({ ed25519Signers: [signer], ecdsaSigners: [] }),
    walletId: signer.walletId,
    recoveryCorrelationId: 'another-wallet-recovery',
    ...verificationContext,
  });

  expect(accepted).toEqual({
    kind: 'verified',
    keySetIds: [`near_ed25519:${signer.signerId}`],
  });
  expect(unrelated).toMatchObject({ kind: 'refused' });
});
