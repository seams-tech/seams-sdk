import { expect, test } from '@playwright/test';
import {
  buildActiveSigningLaneLifecycle,
  buildActiveSigningLaneReference,
  buildDelegatedExecutionSigningLaneRecord,
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildLinkedDeviceSigningLaneRecord,
  buildOwnerPasskeySigningLaneRecord,
  buildProvisioningSigningLaneLifecycle,
  parseActiveSigningLaneReference,
  parseSigningLaneLifecycle,
  parseSigningLaneRecord,
  parseWalletKeyRecord,
} from '../../packages/shared-ts/src/signing-lanes/recordParsers';
import {
  parseLaneHolderParticipantRecordV1,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantRecordV1,
} from '../../packages/shared-ts/src/signing-lanes/participants';
import {
  parseLaneShareEpoch,
  parseLinkedDeviceId,
  parseSigningLaneId,
  parseWalletKeyId,
} from '../../packages/shared-ts/src/signing-lanes/ids';
import { requireEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import {
  parseMpcMaterialActivationRef,
  parseMpcSigningWorkerRef,
  parseWalletAuthMethodId,
  parseWalletId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseEd25519PublicKeyB64u,
  parseKeyCreationSignerSlot,
  parseSecp256k1CompressedPublicKeyB64u,
} from '../../packages/shared-ts/src/passkey-custody/primitives';
import { parseNearEd25519SigningKeyId } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  buildOwnerLaneParticipantContinuityV1,
  parseWalletSignerId,
} from '../../packages/shared-ts/src/signing-lanes/ownerContinuity';

const DIGEST_B64U = Buffer.alloc(32, 7).toString('base64url');
const HPKE_PUBLIC_KEY_B64U = Buffer.alloc(32, 8).toString('base64url');
const ED25519_PUBLIC_KEY_B64U = Buffer.alloc(32, 9).toString('base64url');
const SECP256K1_PUBLIC_KEY_B64U = Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 10)]).toString(
  'base64url',
);

function resultValue<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

const walletId = resultValue(parseWalletId('wallet:lane-records'));
const walletKeyId = resultValue(parseWalletKeyId('wallet-key:lane-records'));
const laneId = resultValue(parseSigningLaneId('lane:owner'));
const laneShareEpoch = resultValue(parseLaneShareEpoch('epoch:1'));
const linkedDeviceId = resultValue(parseLinkedDeviceId('device:owner'));
const walletAuthMethodId = resultValue(
  parseWalletAuthMethodId('passkey:wallet.example.test:credential-owner'),
);
const participantBindingDigestB64u = resultValue(
  parseLaneParticipantBindingDigestB64u(DIGEST_B64U),
);
const holderParticipant = parseLaneHolderParticipantRecordV1({
  kind: 'lane_holder_participant_v1',
  participantId: 'holder:owner',
  custodyBindingId: 'custody:owner',
  custodyBindingDigestB64u: DIGEST_B64U,
  hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
  hpkePublicKeyDigestB64u: DIGEST_B64U,
  participantBindingDigestB64u: DIGEST_B64U,
});
const serverParticipant = parseSigningWorkerParticipantRecordV1({
  kind: 'signing_worker_participant_v1',
  participantId: 'worker:owner',
  recipientKeyId: 'recipient:owner',
  hpkePublicKeyB64u: HPKE_PUBLIC_KEY_B64U,
  hpkePublicKeyDigestB64u: DIGEST_B64U,
  participantBindingDigestB64u: DIGEST_B64U,
});
const materialActivation = resultValue(
  parseMpcMaterialActivationRef({
    kind: 'mpc_material_activation_ref',
    activationId: 'activation:owner',
    capability: 'capability:owner',
    materialOwner: 'material-owner:owner',
    keyBinding: 'key-binding:owner',
    lifecycleBinding: 'lifecycle:owner',
    signingWorker: 'signing-worker:owner',
  }),
);
const ownerParticipantContinuity = buildOwnerLaneParticipantContinuityV1({
  signerId: parseWalletSignerId('signer:owner'),
  participantIds: [1, 2],
  signingWorkerId: resultValue(parseMpcSigningWorkerRef('signing-worker:owner')),
  custodyKeyManifestDigestB64u: DIGEST_B64U,
  sourceIdentityDigestB64u: DIGEST_B64U,
});

function activeLaneLifecycle() {
  return buildActiveSigningLaneLifecycle({
    revocationEpoch: 1,
    activatedAtMs: 20,
    activationReceiptDigestB64u: DIGEST_B64U,
  });
}

function laneBase() {
  return {
    walletId,
    walletKeyId,
    laneId,
    laneShareEpoch,
    participantBindingDigestB64u,
    holderParticipant,
    serverParticipant,
    lifecycle: activeLaneLifecycle(),
  } as const;
}

function ownerLaneBase() {
  return {
    walletId,
    walletKeyId,
    laneId,
    laneShareEpoch,
    participantBindingDigestB64u,
    ownerParticipantContinuity,
    lifecycle: activeLaneLifecycle(),
  } as const;
}

function ed25519WalletKeyRaw(): Record<string, unknown> {
  return {
    kind: 'wallet_key_record_v1',
    keyFamily: 'ed25519',
    walletId,
    walletKeyId,
    walletKeyVersion: 'version:1',
    nearEd25519SigningKeyId: 'near-signing-key:owner',
    keyCreationSignerSlot: 1,
    registeredPublicKeyB64u: ED25519_PUBLIC_KEY_B64U,
    lifecycle: { state: 'active', activatedAtMs: 10 },
  };
}

function evmWalletKeyRaw(): Record<string, unknown> {
  return {
    kind: 'wallet_key_record_v1',
    keyFamily: 'ecdsa_secp256k1',
    walletId,
    walletKeyId,
    walletKeyVersion: 'version:1',
    evmFamilySigningKeySlotId: 'wallet-key:evm-family:wallet_lane-records:root:version-1',
    thresholdPublicKey33B64u: SECP256K1_PUBLIC_KEY_B64U,
    evmAddress: '0x1111111111111111111111111111111111111111',
    lifecycle: { state: 'retired', retiredAtMs: 30 },
  };
}

test.describe('R101 signing lane record boundaries', () => {
  test('round-trips both curve-specific wallet-key records through branded parsers', () => {
    const parsedEd25519 = parseWalletKeyRecord(ed25519WalletKeyRaw());
    expect(parsedEd25519).toMatchObject({
      kind: 'wallet_key_record_v1',
      keyFamily: 'ed25519',
      walletId,
      walletKeyId,
      lifecycle: { state: 'active', activatedAtMs: 10 },
    });
    if (parsedEd25519.keyFamily !== 'ed25519') throw new Error('expected Ed25519 wallet key');
    const rebuiltEd25519 = buildEd25519WalletKeyRecord(parsedEd25519);
    expect(rebuiltEd25519).toEqual(parsedEd25519);

    const parsedEvm = parseWalletKeyRecord(evmWalletKeyRaw());
    expect(parsedEvm).toMatchObject({
      kind: 'wallet_key_record_v1',
      keyFamily: 'ecdsa_secp256k1',
      walletId,
      walletKeyId,
      lifecycle: { state: 'retired', retiredAtMs: 30 },
    });
    if (parsedEvm.keyFamily !== 'ecdsa_secp256k1') throw new Error('expected EVM wallet key');
    const rebuiltEvm = buildEvmFamilyWalletKeyRecord(parsedEvm);
    expect(rebuiltEvm).toEqual(parsedEvm);

    expect(parseEd25519PublicKeyB64u(parsedEd25519.registeredPublicKeyB64u)).toBe(
      parsedEd25519.registeredPublicKeyB64u,
    );
    expect(parseKeyCreationSignerSlot(parsedEd25519.keyCreationSignerSlot)).toBe(1);
    expect(parseNearEd25519SigningKeyId(parsedEd25519.nearEd25519SigningKeyId)).toBe(
      parsedEd25519.nearEd25519SigningKeyId,
    );
    expect(requireEvmFamilySigningKeySlotId(parsedEvm.evmFamilySigningKeySlotId)).toBe(
      parsedEvm.evmFamilySigningKeySlotId,
    );
    expect(parseSecp256k1CompressedPublicKeyB64u(parsedEvm.thresholdPublicKey33B64u)).toBe(
      parsedEvm.thresholdPublicKey33B64u,
    );
  });

  test('rejects wallet-key branch mixing, unknown fields, and invalid lifecycle fields', () => {
    expect(() =>
      parseWalletKeyRecord({
        ...ed25519WalletKeyRaw(),
        evmAddress: '0x1111111111111111111111111111111111111111',
      }),
    ).toThrow(/evmAddress/);
    expect(() =>
      parseWalletKeyRecord({ ...ed25519WalletKeyRaw(), agentIdentityKeyId: 'agent:key' }),
    ).toThrow(/agentIdentityKeyId/);
    expect(() =>
      parseWalletKeyRecord({
        ...ed25519WalletKeyRaw(),
        lifecycle: { state: 'active', activatedAtMs: 10, retiredAtMs: 11 },
      }),
    ).toThrow(/cannot be active/);
    expect(() =>
      parseWalletKeyRecord({
        ...ed25519WalletKeyRaw(),
        lifecycle: { state: 'active', activatedAtMs: 10, unexpected: true },
      }),
    ).toThrow(/unexpected/);
    expect(() =>
      parseWalletKeyRecord({ ...evmWalletKeyRaw(), thresholdPublicKey33B64u: 'bad' }),
    ).toThrow(/thresholdPublicKey33B64u/);
  });

  test('parses all lane branches and preserves exact participant/lifecycle bindings', () => {
    const owner = buildOwnerPasskeySigningLaneRecord({ ...ownerLaneBase(), walletAuthMethodId });
    expect(parseSigningLaneRecord(owner)).toEqual(owner);

    const linked = buildLinkedDeviceSigningLaneRecord({
      ...laneBase(),
      linkedDeviceId,
    });
    expect(parseSigningLaneRecord(linked)).toEqual(linked);

    const delegated = parseSigningLaneRecord({
      kind: 'signing_lane_reference_v1',
      ...laneBase(),
      laneKind: 'delegated_execution',
      authorizationId: 'authorization:agent',
      agentIdentityKeyId: 'agent-key:owner',
      custodyBindingId: 'custody-binding:agent',
      authorizationBindingDigestB64u: DIGEST_B64U,
    });
    if (delegated.laneKind !== 'delegated_execution') {
      throw new Error('expected delegated execution lane');
    }
    expect(buildDelegatedExecutionSigningLaneRecord(delegated)).toEqual(delegated);

    expect(parseSigningLaneRecord({ ...owner, laneKind: 'owner_email_otp' })).toMatchObject({
      laneKind: 'owner_email_otp',
    });
    expect(
      parseSigningLaneRecord({
        ...ownerLaneBase(),
        kind: 'signing_lane_reference_v1',
        laneKind: 'recovery',
      }),
    ).toMatchObject({
      laneKind: 'recovery',
    });
    expect(
      parseSigningLaneRecord({
        ...ownerLaneBase(),
        kind: 'signing_lane_reference_v1',
        laneKind: 'break_glass',
      }),
    ).toMatchObject({
      laneKind: 'break_glass',
    });
  });

  test('rejects lane branch mixing and lifecycle states before exposing an active reference', () => {
    const owner = buildOwnerPasskeySigningLaneRecord({ ...ownerLaneBase(), walletAuthMethodId });
    expect(() =>
      parseSigningLaneRecord({ ...owner, authorizationId: 'authorization:wrong-branch' }),
    ).toThrow(/authorizationId/);
    expect(() =>
      parseSigningLaneRecord({ ...owner, linkedDeviceId: 'device:wrong-branch' }),
    ).toThrow(/linkedDeviceId/);

    const delegated = parseSigningLaneRecord({
      kind: 'signing_lane_reference_v1',
      ...laneBase(),
      laneKind: 'delegated_execution',
      authorizationId: 'authorization:agent',
      agentIdentityKeyId: 'agent-key:owner',
      custodyBindingId: 'custody-binding:agent',
      authorizationBindingDigestB64u: DIGEST_B64U,
    });
    expect(() =>
      parseSigningLaneRecord({
        ...delegated,
        mandatePolicy: { kind: 'retired_mandate_policy' },
      }),
    ).toThrow(/mandatePolicy/);

    const activeReference = buildActiveSigningLaneReference({
      walletId,
      walletKeyId,
      laneId,
      laneShareEpoch,
      laneKind: 'owner_passkey',
      participantBindingDigestB64u,
      lifecycle: activeLaneLifecycle(),
      materialActivation,
    });
    expect(parseActiveSigningLaneReference(activeReference)).toEqual(activeReference);
    expect(() =>
      parseActiveSigningLaneReference({
        ...activeReference,
        lifecycle: buildProvisioningSigningLaneLifecycle({ revocationEpoch: 1, startedAtMs: 40 }),
      }),
    ).toThrow(/must be active/);
    expect(() =>
      parseActiveSigningLaneReference({ ...activeReference, holderParticipant }),
    ).toThrow(/holderParticipant/);
  });

  test('enforces lifecycle branch fields and canonical digests', () => {
    const active = activeLaneLifecycle();
    expect(parseSigningLaneLifecycle(active)).toEqual(active);
    expect(() =>
      parseSigningLaneLifecycle({
        state: 'active',
        revocationEpoch: 1,
        activatedAtMs: 20,
        activationReceiptDigestB64u: 'not-base64',
      }),
    ).toThrow(/activationReceiptDigestB64u/);
    expect(() =>
      parseSigningLaneLifecycle({
        state: 'revoked',
        revocationEpoch: 1,
        revokedAtMs: 20,
        revokeReason: 'unknown',
      }),
    ).toThrow(/revokeReason/);
    expect(() =>
      parseSigningLaneLifecycle({
        state: 'provisioning',
        revocationEpoch: -1,
        startedAtMs: 20,
      }),
    ).toThrow(/revocationEpoch/);
  });
});
