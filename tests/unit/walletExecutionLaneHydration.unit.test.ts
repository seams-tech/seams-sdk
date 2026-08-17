import { expect, test } from '@playwright/test';
import {
  hydrateWalletExecutionLane,
  type WalletExecutionLaneHydrationInput,
} from '../../packages/sdk-web/src/core/signingEngine/session/lanes/walletExecutionLaneHydration';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { ecdsaCapabilityActivationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { nearEd25519YaoCapabilityHydrationFixture } from './helpers/nearEd25519YaoCapabilityHydration.fixtures';

const DIGEST_B64U = Buffer.alloc(32, 7).toString('base64url');
const HPKE_PUBLIC_KEY_B64U = Buffer.alloc(32, 8).toString('base64url');

function laneRaw(args: {
  walletId: string;
  walletKeyId: string;
  laneId: string;
  laneShareEpoch?: string;
  activationReceiptDigestB64u: string;
  laneKind?: 'owner_passkey' | 'linked_device';
  ownerParticipantIds?: readonly [number, number];
  ownerSigningWorkerId?: string;
}): Record<string, unknown> {
  const laneKind = args.laneKind ?? 'owner_passkey';
  const common = {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind,
    laneShareEpoch: args.laneShareEpoch ?? 'epoch:1',
    participantBindingDigestB64u: DIGEST_B64U,
    lifecycle: {
      state: 'active',
      revocationEpoch: 1,
      activatedAtMs: 20,
      activationReceiptDigestB64u: args.activationReceiptDigestB64u,
    },
  };
  if (laneKind === 'linked_device') {
    return {
      ...common,
      linkedDeviceId: 'device:owner',
      holderParticipant: {
        kind: 'lane_holder_participant_v1',
        participantId: 'holder:owner',
        custodyBindingId: 'custody:owner',
        custodyBindingDigestB64u: DIGEST_B64U,
        hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
        hpkePublicKeyDigestB64u: DIGEST_B64U,
        participantBindingDigestB64u: DIGEST_B64U,
      },
      serverParticipant: {
        kind: 'signing_worker_participant_v1',
        participantId: 'worker:owner',
        recipientKeyId: 'recipient:owner',
        hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
        hpkePublicKeyDigestB64u: DIGEST_B64U,
        participantBindingDigestB64u: DIGEST_B64U,
      },
    };
  }
  return {
    ...common,
    walletAuthMethodId: 'passkey:wallet.example.test:credential-owner',
    ownerParticipantContinuity: {
      kind: 'owner_lane_participant_continuity_v1',
      signerId: 'signer:owner',
      participantIds: args.ownerParticipantIds ?? [1, 2],
      signingWorkerId: args.ownerSigningWorkerId ?? 'worker:owner',
      custodyKeyManifestDigestB64u: DIGEST_B64U,
      sourceIdentityDigestB64u: DIGEST_B64U,
    },
  };
}

function ed25519Input(): WalletExecutionLaneHydrationInput {
  const fixture = nearEd25519YaoCapabilityHydrationFixture();
  const walletId = String(fixture.authority.walletId);
  const walletKeyId = 'wallet-key:near-owner';
  const registeredPublicKey = new Uint8Array(32).fill(9);
  const metadata = {
    kind: 'router_ab_ed25519_yao_active_client_v1' as const,
    scope: {
      lifecycle_id: 'lifecycle:near-owner',
      root_share_epoch: 'root:1',
      account_id: walletId,
      threshold_session_id: 'session:near-owner',
      signer_set_id: 'signer-set:near-owner',
      signing_worker_id: String(fixture.materialActivation.signingWorker),
      material_activation: routerAbMpcMaterialActivationRefToWire(fixture.materialActivation),
    },
    applicationBinding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id: 'near-signing-key:owner',
      signing_root_id: 'project:dev',
      key_creation_signer_slot: 1,
    },
    participantIds: [1, 2] as const,
    registeredPublicKey,
    signingWorkerVerifyingShare: new Uint8Array(32).fill(10),
    stateEpoch: 1n,
    transcript: new Uint8Array(32).fill(11),
    activeCapabilityBinding: new Uint8Array(32).fill(12),
    materialActivation: fixture.materialActivation,
  };
  return {
    walletKey: {
      kind: 'wallet_key_record_v1',
      keyFamily: 'ed25519',
      walletId,
      walletKeyId,
      walletKeyVersion: 'version:1',
      nearEd25519SigningKeyId: 'near-signing-key:owner',
      keyCreationSignerSlot: 1,
      registeredPublicKeyB64u: Buffer.from(registeredPublicKey).toString('base64url'),
      lifecycle: { state: 'active', activatedAtMs: 10 },
    },
    lane: laneRaw({
      walletId,
      walletKeyId,
      laneId: 'lane:owner',
      activationReceiptDigestB64u: DIGEST_B64U,
      ownerSigningWorkerId: String(fixture.materialActivation.signingWorker),
    }),
    material: {
      keyFamily: 'ed25519',
      laneShareEpoch: 'epoch:1',
      metadata,
      hydration: {
        publicLocator: fixture.publicLocator,
        sealed: fixture.sealed,
        runtime: fixture.runtime,
        unlockSource: { kind: 'available', authority: fixture.authority },
      },
    },
  };
}

function ecdsaInput(): WalletExecutionLaneHydrationInput {
  const lookup = ecdsaCapabilityActivationLookupFixture();
  const manifest = lookup.manifest;
  const facts = manifest.durableMaterial.roleLocalPublicFacts;
  const walletId = String(manifest.signer.walletId);
  const walletKeyId = 'wallet-key:ecdsa-owner';
  return {
    walletKey: {
      kind: 'wallet_key_record_v1',
      keyFamily: 'ecdsa_secp256k1',
      walletId,
      walletKeyId,
      walletKeyVersion: 'version:1',
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: facts.walletId,
        signingRootId: facts.signingRootId,
        signingRootVersion: facts.signingRootVersion,
      }),
      thresholdPublicKey33B64u: facts.groupPublicKey33B64u,
      evmAddress: facts.ethereumAddress,
      lifecycle: { state: 'active', activatedAtMs: 10 },
    },
    lane: laneRaw({
      walletId,
      walletKeyId,
      laneId: 'lane:owner',
      activationReceiptDigestB64u: String(
        manifest.activation.serverActivation.serverActivationReceipt.activationDigest,
      ),
      ownerSigningWorkerId: String(manifest.activation.materialActivation.signingWorker),
    }),
    material: {
      keyFamily: 'ecdsa_secp256k1',
      laneShareEpoch: 'epoch:1',
      lookup,
      runtime: { kind: 'absent' },
    },
  };
}

test.describe('R101 browser wallet execution lane hydration', () => {
  test('hydrates an active Ed25519 Yao lane with exact public identity and material', () => {
    const result = hydrateWalletExecutionLane(ed25519Input());
    expect(result.kind).toBe('active_wallet_execution_lane_v1');
    if (result.kind !== 'active_wallet_execution_lane_v1') throw new Error('expected active lane');
    expect(result.keyFamily).toBe('ed25519');
    expect(result.lane.laneShareEpoch).toBe('epoch:1');
    expect(result.materialActivation.materialOwner).toBe('wallet-near-hydration');
  });

  test('hydrates an active ECDSA manifest and pins its receipt public identity', () => {
    const result = hydrateWalletExecutionLane(ecdsaInput());
    expect(result.kind).toBe('active_wallet_execution_lane_v1');
    if (result.kind !== 'active_wallet_execution_lane_v1') throw new Error('expected active lane');
    expect(result.keyFamily).toBe('ecdsa_secp256k1');
    expect(result.publicIdentity).toMatchObject({ keyFamily: 'ecdsa_secp256k1' });
  });

  test('refuses linked-device lanes and receipt drift before exposing material', () => {
    const input = ecdsaInput();
    const linkedLane = laneRaw({
      walletId: 'ecdsa-manifest-fixture-wallet',
      walletKeyId: 'wallet-key:ecdsa-owner',
      laneId: 'lane:linked',
      laneKind: 'linked_device',
      activationReceiptDigestB64u: DIGEST_B64U,
    });
    const linked = hydrateWalletExecutionLane({ ...input, lane: linkedLane });
    expect(linked).toMatchObject({
      kind: 'wallet_execution_lane_refused_v1',
      reason: 'unsupported_lane_kind',
    });

    const drifted = hydrateWalletExecutionLane({
      ...input,
      lane: laneRaw({
        walletId: 'ecdsa-manifest-fixture-wallet',
        walletKeyId: 'wallet-key:ecdsa-owner',
        laneId: 'lane:owner',
        activationReceiptDigestB64u: DIGEST_B64U,
        ownerSigningWorkerId: 'signing-worker-fixture',
      }),
    });
    expect(drifted).toMatchObject({
      kind: 'wallet_execution_lane_refused_v1',
      reason: 'activation_receipt_mismatch',
    });
  });

  test('refuses owner lanes when participant continuity drifts or carries HPKE records', () => {
    const input = ed25519Input();
    const participantDrift = hydrateWalletExecutionLane({
      ...input,
      lane: laneRaw({
        walletId: 'wallet-near-hydration',
        walletKeyId: 'wallet-key:near-owner',
        laneId: 'lane:owner',
        activationReceiptDigestB64u: DIGEST_B64U,
        ownerSigningWorkerId: 'worker:near-hydration',
        ownerParticipantIds: [2, 1],
      }),
    });
    expect(participantDrift).toMatchObject({
      kind: 'wallet_execution_lane_refused_v1',
      reason: 'participant_binding_mismatch',
    });

    const hpkeOwnerLane = {
      ...(input.lane as Record<string, unknown>),
      holderParticipant: {
        kind: 'lane_holder_participant_v1',
        participantId: 'holder:owner',
        custodyBindingId: 'custody:owner',
        custodyBindingDigestB64u: DIGEST_B64U,
        hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
        hpkePublicKeyDigestB64u: DIGEST_B64U,
        participantBindingDigestB64u: DIGEST_B64U,
      },
    };
    expect(hydrateWalletExecutionLane({ ...input, lane: hpkeOwnerLane })).toMatchObject({
      kind: 'wallet_execution_lane_refused_v1',
      reason: 'invalid_boundary_record',
    });
  });
});
