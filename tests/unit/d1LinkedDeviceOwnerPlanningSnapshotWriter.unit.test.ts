import { expect, test } from '@playwright/test';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildR102EcdsaLaneJob, buildR102LaneJob } from './helpers/r102LaneGateway.fixtures';
import type { ActiveOwnerWalletExecutionLaneProjection } from '../../packages/wallet-server/src/core/signingLanes/WalletExecutionLaneProjection';
import type { D1LinkedDeviceOwnerPlanningSnapshotInputV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotStore';
import { D1LinkedDeviceOwnerPlanningSnapshotWriterV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotWriter';
import type {
  D1LinkedDeviceOwnerPlanningDeploymentChildV1,
  D1LinkedDeviceOwnerPlanningDeploymentPlanV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotWriter';
import {
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildActiveWalletKeyLifecycle,
  buildOwnerPasskeySigningLaneRecord,
  parseWalletKeyVersion,
} from '../../packages/shared-ts/src/signing-lanes/recordParsers';
import {
  buildOwnerLaneParticipantContinuityV1,
  computeOwnerLaneParticipantBindingDigestV1,
  parseWalletSignerId,
} from '../../packages/shared-ts/src/signing-lanes/ownerContinuity';
import {
  parseEd25519PublicKeyB64u,
  parseKeyCreationSignerSlot,
  parseSecp256k1CompressedPublicKeyB64u,
} from '../../packages/shared-ts/src/passkey-custody/primitives';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  parseLaneShareEpoch,
  parseMpcMaterialActivationRef,
  parseMpcSigningWorkerRef,
  parseSigningLaneId,
  parseWalletAuthMethodId,
  parseWalletId,
  parseWalletKeyId,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseNearEd25519SigningKeyId } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import { parseLinkedDeviceOwnerSourceLaneV1 } from '../../packages/shared-ts/src/device-linking/parsers';

const digest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
const walletId = required(parseWalletId('wallet:writer-mixed'));
const authMethodId = required(
  parseWalletAuthMethodId('passkey:wallet.example.test:credential-writer'),
);
const rpId = required(parseWebAuthnRpId('wallet.example.test'));

function required<T>(
  value:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (value.ok) return value.value;
  throw new Error(value.error.message);
}

function activation(label: string) {
  return required(
    parseMpcMaterialActivationRef({
      kind: 'mpc_material_activation_ref',
      activationId: `activation:writer:${label}`,
      capability: `capability:writer:${label}`,
      materialOwner: `material-owner:writer:${label}`,
      keyBinding: `key-binding:writer:${label}`,
      lifecycleBinding: `lifecycle:writer:${label}`,
      signingWorker: `worker:writer:${label}`,
    }),
  );
}

async function projection(
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  label: string,
): Promise<ActiveOwnerWalletExecutionLaneProjection> {
  const ownerParticipantContinuity = buildOwnerLaneParticipantContinuityV1({
    signerId: parseWalletSignerId(`signer:writer:${label}`),
    participantIds: [1, 2],
    signingWorkerId: required(parseMpcSigningWorkerRef(`worker:writer:${label}`)),
    custodyKeyManifestDigestB64u: digest,
    sourceIdentityDigestB64u: digest,
  });
  const participantBindingDigestB64u = await computeOwnerLaneParticipantBindingDigestV1(
    ownerParticipantContinuity,
  );
  const walletKeyId = required(parseWalletKeyId(`wallet-key:writer:${label}`));
  const lane = buildOwnerPasskeySigningLaneRecord({
    walletId,
    walletKeyId,
    laneId: required(parseSigningLaneId(`lane:owner:writer:${label}`)),
    laneShareEpoch: required(parseLaneShareEpoch(`epoch:writer:${label}`)),
    participantBindingDigestB64u,
    walletAuthMethodId: authMethodId,
    ownerParticipantContinuity,
    lifecycle: {
      state: 'active',
      revocationEpoch: 0,
      activatedAtMs: 1_000,
      activationReceiptDigestB64u: digest,
    },
  });
  const walletKey =
    keyFamily === 'ed25519'
      ? buildEd25519WalletKeyRecord({
          walletId,
          walletKeyId,
          walletKeyVersion: parseWalletKeyVersion(`wallet-key-version:writer:${label}`),
          nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(`ed25519ks_writer_${label}`),
          keyCreationSignerSlot: parseKeyCreationSignerSlot(1),
          registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
            base64UrlEncode(new Uint8Array(32).fill(label === 'ed' ? 1 : 2)),
          ),
          lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: 1_000 }),
        })
      : buildEvmFamilyWalletKeyRecord({
          walletId,
          walletKeyId,
          walletKeyVersion: parseWalletKeyVersion(`wallet-key-version:writer:${label}`),
          evmFamilySigningKeySlotId: required(
            parseEvmFamilySigningKeySlotId(
              `wallet-key:evm-family:${encodeURIComponent(String(walletId))}:root:version-1`,
            ),
          ),
          thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
            base64UrlEncode(Uint8Array.from([2, ...new Uint8Array(32).fill(6)])),
          ),
          evmAddress: '0x' + '2'.repeat(40),
          lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: 1_000 }),
        });
  return {
    kind: 'active_owner_wallet_execution_lane_projection_v1',
    walletKey,
    lane,
    materialActivation: activation(label),
    verifiedActivationReceiptDigestB64u: digest,
  };
}

function ownerContext() {
  return {
    walletId,
    walletSessionId: required(parseWalletSessionId('wallet-session:writer-mixed')),
    authorizationId: required(
      parseWalletSessionAuthorizationId('wallet-authorization:writer-mixed'),
    ),
    expiresAtMs: 10_000,
    curve: 'ed25519' as const,
    authority: buildPasskeyWalletAuthAuthority({
      walletId,
      rpId,
      credentialIdB64u: 'credential-writer',
    }),
    authorityScope: { kind: 'passkey_rp' as const, rpId },
  };
}

function deploymentChild(
  projectionValue: ActiveOwnerWalletExecutionLaneProjection,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  label: string,
): D1LinkedDeviceOwnerPlanningDeploymentChildV1 {
  const targetJob =
    keyFamily === 'ed25519'
      ? buildR102LaneJob(`writer-${label}`)
      : buildR102EcdsaLaneJob(`writer-${label}`);
  const common = {
    keyFamily,
  } as const;
  if (keyFamily === 'ed25519' && targetJob.keyFamily === 'ed25519') {
    return {
      ...common,
      keyFamily,
      stableContextBindingB64u: String(digest),
    };
  }
  if (keyFamily === 'ecdsa_secp256k1' && targetJob.keyFamily === 'ecdsa_secp256k1') {
    return {
      ...common,
      keyFamily,
      sourceCapability: targetJob.sourceCapability,
      sourceHolderVerifyingShare33B64u: targetJob.sourceHolderVerifyingShare33B64u,
      sourceServerVerifyingShare33B64u: targetJob.sourceServerVerifyingShare33B64u,
    };
  }
  throw new Error('deployment child fixture family mismatch');
}

test('projects mixed owner hints through D1 facts before writing the snapshot', async () => {
  const ed = await projection('ed25519', 'ed');
  const ecdsa = await projection('ecdsa_secp256k1', 'ecdsa');
  const base = buildR103DeviceLinkFixture();
  const metadata = {
    walletId,
    policyDigestB64u: String(base.approval.policyDigestB64u),
    operationId: base.approval.operationId,
    idempotencyKey: base.approval.idempotencyKey,
    orderedKeyBindings: [
      {
        walletKeyId: ed.walletKey.walletKeyId,
        keyFamily: 'ed25519' as const,
        sourceKind: 'owner_registration' as const,
        sourceLaneKind: ed.lane.laneKind,
        sourceLaneId: ed.lane.laneId,
        sourceLaneShareEpoch: ed.lane.laneShareEpoch,
        sourceRevocationEpoch: 0,
        ownerParticipantContinuity: ed.lane.ownerParticipantContinuity,
        targetLaneId: required(parseSigningLaneId('lane:target:writer:ed')),
        targetLaneShareEpoch: required(parseLaneShareEpoch('epoch:target:writer:ed')),
      },
      {
        walletKeyId: ecdsa.walletKey.walletKeyId,
        keyFamily: 'ecdsa_secp256k1' as const,
        sourceKind: 'owner_registration' as const,
        sourceLaneKind: ecdsa.lane.laneKind,
        sourceLaneId: ecdsa.lane.laneId,
        sourceLaneShareEpoch: ecdsa.lane.laneShareEpoch,
        sourceRevocationEpoch: 0,
        ownerParticipantContinuity: ecdsa.lane.ownerParticipantContinuity,
        targetLaneId: required(parseSigningLaneId('lane:target:writer:ecdsa')),
        targetLaneShareEpoch: required(parseLaneShareEpoch('epoch:target:writer:ecdsa')),
      },
    ],
    protocolVersions: [
      { keyFamily: 'ed25519' as const, version: 'rotatable_signing_lane_protocol_v1' },
      { keyFamily: 'ecdsa_secp256k1' as const, version: 'rotatable_signing_lane_protocol_v1' },
    ],
    expiresAtMs: 9_000,
  } as const;
  const hints = [
    parseLinkedDeviceOwnerSourceLaneV1({
      kind: 'linked_device_owner_source_lane_v1',
      keyFamily: 'ed25519',
      walletKey: ed.walletKey,
      lane: ed.lane,
      materialActivation: ed.materialActivation,
      verifiedActivationReceiptDigestB64u: digest,
    }),
    parseLinkedDeviceOwnerSourceLaneV1({
      kind: 'linked_device_owner_source_lane_v1',
      keyFamily: 'ecdsa_secp256k1',
      walletKey: ecdsa.walletKey,
      lane: ecdsa.lane,
      materialActivation: ecdsa.materialActivation,
      verifiedActivationReceiptDigestB64u: digest,
      ecdsaSourceManifest: { manifestId: 'manifest:writer', manifestRevision: 1 },
    }),
  ] as const;
  let captured: D1LinkedDeviceOwnerPlanningSnapshotInputV1 | null = null;
  const deploymentPlan: D1LinkedDeviceOwnerPlanningDeploymentPlanV1 = {
    metadata,
    orderedChildren: [
      deploymentChild(ed, 'ed25519', 'ed'),
      deploymentChild(ecdsa, 'ecdsa_secp256k1', 'ecdsa'),
    ],
  };
  const writer = new D1LinkedDeviceOwnerPlanningSnapshotWriterV1({
    walletRegistration: {
      resolveActiveOwnerWalletExecutionLane: async (input) => ({
        kind: 'projected',
        projection:
          String(input.expectedMaterialActivation.activationId) ===
          String(ed.materialActivation.activationId)
            ? ed
            : ecdsa,
      }),
    },
    deployment: {
      planOwnerPlanningV1: async (input) => {
        expect(input.projections.map((value) => value.walletKey.keyFamily)).toEqual([
          'ed25519',
          'ecdsa_secp256k1',
        ]);
        expect(input.orderedOwnerSourceLaneHints.map((value) => value.keyFamily)).toEqual([
          'ed25519',
          'ecdsa_secp256k1',
        ]);
        return deploymentPlan;
      },
    },
    snapshotStore: {
      insertOrReplayV1: async (input) => {
        captured = input;
        return { outcome: 'applied', snapshot: input };
      },
    },
  });
  const result = await writer.writeV1({
    owner: ownerContext(),
    payload: base.payload,
    orderedOwnerSourceLaneHints: hints,
  });
  expect(result.outcome).toBe('applied');
  expect(captured?.sourceChildren.map((child) => child.keyFamily)).toEqual([
    'ed25519',
    'ecdsa_secp256k1',
  ]);
  expect(captured?.sourceChildren[0]?.registeredPublicKeyB64u).toBe(
    ed.walletKey.keyFamily === 'ed25519' ? ed.walletKey.registeredPublicKeyB64u : undefined,
  );
  expect(captured?.sourceChildren[1]?.evmAddress).toBe(
    ecdsa.walletKey.keyFamily === 'ecdsa_secp256k1' ? ecdsa.walletKey.evmAddress : undefined,
  );
});
