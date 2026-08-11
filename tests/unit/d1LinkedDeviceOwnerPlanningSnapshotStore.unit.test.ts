import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
} from '../helpers/sqliteD1';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildR102LaneJob, buildR102EcdsaLaneJob } from './helpers/r102LaneGateway.fixtures';
import { parseRotatableSigningLaneJobV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import type { WalletId } from '../../packages/shared-ts/src/utils/domainIds';
import type { ActiveOwnerWalletExecutionLaneProjection } from '../../packages/sdk-server-ts/src/core/signingLanes/WalletExecutionLaneProjection';
import {
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildActiveWalletKeyLifecycle,
  buildActiveSigningLaneLifecycle,
  buildOwnerPasskeySigningLaneRecord,
  parseWalletKeyVersion,
} from '../../packages/shared-ts/src/signing-lanes/recordParsers';
import {
  buildOwnerLaneParticipantContinuityV1,
  parseWalletSignerId,
  computeOwnerLaneParticipantBindingDigestV1,
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
import type { D1LinkedDeviceOwnerPlanningSnapshotInputV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotStore';
import { D1LinkedDeviceOwnerPlanningSnapshotStoreV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotStore';
import { createD1LinkedDeviceLaneLifecycleAuthorizationV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceLaneLifecycleAuthorization';

const digest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9)));
const walletId = required(parseWalletId('wallet:mixed-planning'));
const authMethodId = required(
  parseWalletAuthMethodId('passkey:wallet.example.test:credential-mixed'),
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
      activationId: `activation:${label}`,
      capability: `capability:${label}`,
      materialOwner: `material-owner:${label}`,
      keyBinding: `key-binding:${label}`,
      lifecycleBinding: `lifecycle:${label}`,
      signingWorker: `worker:${label}`,
    }),
  );
}

async function projection(
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  label: string,
): Promise<ActiveOwnerWalletExecutionLaneProjection> {
  const materialActivation = activation(label);
  const ownerParticipantContinuity = buildOwnerLaneParticipantContinuityV1({
    signerId: parseWalletSignerId(`signer:${label}`),
    participantIds: [1, 2],
    signingWorkerId: required(parseMpcSigningWorkerRef(`worker:${label}`)),
    custodyKeyManifestDigestB64u: digest,
    sourceIdentityDigestB64u: digest,
  });
  const participantBindingDigestB64u = await computeOwnerLaneParticipantBindingDigestV1(
    ownerParticipantContinuity,
  );
  const walletKeyId = required(parseWalletKeyId(`wallet-key:${label}`));
  const lane = buildOwnerPasskeySigningLaneRecord({
    walletId,
    walletKeyId,
    laneId: required(parseSigningLaneId(`lane:owner:${label}`)),
    laneShareEpoch: required(parseLaneShareEpoch(`epoch:${label}`)),
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
          walletKeyVersion: parseWalletKeyVersion(`wallet-key-version:${label}`),
          nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(`ed25519ks_${label}`),
          keyCreationSignerSlot: parseKeyCreationSignerSlot(1),
          registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
            base64UrlEncode(new Uint8Array(32).fill(label === 'ed' ? 3 : 4)),
          ),
          lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: 1_000 }),
        })
      : buildEvmFamilyWalletKeyRecord({
          walletId,
          walletKeyId,
          walletKeyVersion: parseWalletKeyVersion(`wallet-key-version:${label}`),
          evmFamilySigningKeySlotId: required(
            parseEvmFamilySigningKeySlotId(`wallet-key:evm-family:${label}:root:version-1`),
          ),
          thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
            base64UrlEncode(Uint8Array.from([2, ...new Uint8Array(32).fill(5)])),
          ),
          evmAddress: `0x${'1'.repeat(40)}`,
          lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: 1_000 }),
        });
  return {
    kind: 'active_owner_wallet_execution_lane_projection_v1',
    walletKey,
    lane,
    materialActivation,
    verifiedActivationReceiptDigestB64u: digest,
  };
}

function ownerContext() {
  const authority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u: 'credential-mixed',
  });
  return {
    walletId,
    walletSessionId: required(parseWalletSessionId('wallet-session:mixed')),
    authorizationId: required(parseWalletSessionAuthorizationId('wallet-authorization:mixed')),
    expiresAtMs: 10_000,
    curve: 'ed25519' as const,
    authority,
    authorityScope: { kind: 'passkey_rp' as const, rpId },
  };
}

function sourceChild(
  projectionValue: ActiveOwnerWalletExecutionLaneProjection,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  operationId: string,
  idempotencyKey: string,
  policyDigestB64u: string,
  label: string,
) {
  const targetJob =
    keyFamily === 'ed25519'
      ? buildR102LaneJob(`target-${label}`)
      : buildR102EcdsaLaneJob(`target-${label}`);
  const common = {
    walletKeyId: projectionValue.walletKey.walletKeyId,
    source: {
      laneId: projectionValue.lane.laneId,
      laneKind: projectionValue.lane.laneKind,
      laneShareEpoch: projectionValue.lane.laneShareEpoch,
      revocationEpoch: projectionValue.lane.lifecycle.revocationEpoch,
      holderParticipantId: `holder:source:${label}`,
      signingWorkerParticipantId: `worker:source:${label}`,
      signingWorkerRecipientKeyId: `worker-key:source:${label}`,
      participantBindingDigestB64u: projectionValue.lane.participantBindingDigestB64u,
      materialActivation: projectionValue.materialActivation,
    },
    targetHolderParticipantId: targetJob.targetHolder.participantId,
    targetSigningWorker: targetJob.targetSigningWorker,
    authorization: {
      authorizedOperationId: operationId,
      idempotencyKey,
      linkedDevicePermissionDigestB64u: policyDigestB64u,
    },
  };
  if (keyFamily === 'ed25519' && projectionValue.walletKey.keyFamily === 'ed25519')
    return {
      ...common,
      keyFamily,
      registeredPublicKeyB64u: projectionValue.walletKey.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: projectionValue.walletKey.nearEd25519SigningKeyId,
      keyCreationSignerSlot: projectionValue.walletKey.keyCreationSignerSlot,
      stableContextBindingB64u: digest,
      yaoSuiteId: targetJob.yaoSuiteId,
      circuitDigestB64u: digest,
    };
  if (
    keyFamily === 'ecdsa_secp256k1' &&
    projectionValue.walletKey.keyFamily === 'ecdsa_secp256k1' &&
    targetJob.keyFamily === 'ecdsa_secp256k1'
  )
    return {
      ...common,
      keyFamily,
      evmFamilySigningKeySlotId: projectionValue.walletKey.evmFamilySigningKeySlotId,
      thresholdPublicKey33B64u: projectionValue.walletKey.thresholdPublicKey33B64u,
      evmAddress: projectionValue.walletKey.evmAddress,
      sourceCapability: targetJob.sourceCapability,
      targetCapability: targetJob.targetCapability,
      sourceHolderVerifyingShare33B64u: targetJob.sourceHolderVerifyingShare33B64u,
      sourceServerVerifyingShare33B64u: targetJob.sourceServerVerifyingShare33B64u,
      reshareChannelBindingDigestB64u: targetJob.reshareChannelBindingDigestB64u,
    };
  throw new Error('source child family mismatch');
}

async function fixture(): Promise<{
  readonly store: D1LinkedDeviceOwnerPlanningSnapshotStoreV1;
  readonly snapshot: D1LinkedDeviceOwnerPlanningSnapshotInputV1;
  readonly database: ReturnType<typeof createTemporaryD1Database>['database'];
  readonly cleanup: () => void;
}> {
  const ed = await projection('ed25519', 'ed');
  const ecdsa = await projection('ecdsa_secp256k1', 'ecdsa');
  const base = buildR103DeviceLinkFixture();
  const operationId = String(base.approval.operationId);
  const idempotencyKey = String(base.approval.idempotencyKey);
  const policyDigestB64u = String(base.approval.policyDigestB64u);
  const edChild = sourceChild(ed, 'ed25519', operationId, idempotencyKey, policyDigestB64u, 'ed');
  const ecdsaChild = sourceChild(
    ecdsa,
    'ecdsa_secp256k1',
    operationId,
    idempotencyKey,
    policyDigestB64u,
    'ecdsa',
  );
  const metadata = {
    walletId,
    policyDigestB64u,
    operationId,
    idempotencyKey,
    orderedKeyBindings: [
      {
        walletKeyId: ed.walletKey.walletKeyId,
        keyFamily: 'ed25519',
        sourceLaneId: ed.lane.laneId,
        sourceLaneShareEpoch: ed.lane.laneShareEpoch,
        sourceRevocationEpoch: 0,
        sourceHolderParticipantId: edChild.source.holderParticipantId,
        sourceSigningWorkerParticipantId: edChild.source.signingWorkerParticipantId,
        targetLaneId: required(parseSigningLaneId(`lane:target:${'ed'}`)),
        targetLaneShareEpoch: required(parseLaneShareEpoch('epoch:target-ed')),
      },
      {
        walletKeyId: ecdsa.walletKey.walletKeyId,
        keyFamily: 'ecdsa_secp256k1',
        sourceLaneId: ecdsa.lane.laneId,
        sourceLaneShareEpoch: ecdsa.lane.laneShareEpoch,
        sourceRevocationEpoch: 0,
        sourceHolderParticipantId: ecdsaChild.source.holderParticipantId,
        sourceSigningWorkerParticipantId: ecdsaChild.source.signingWorkerParticipantId,
        targetLaneId: required(parseSigningLaneId('lane:target:ecdsa')),
        targetLaneShareEpoch: required(parseLaneShareEpoch('epoch:target-ecdsa')),
      },
    ],
    protocolVersions: [
      { keyFamily: 'ed25519', version: 'rotatable_signing_lane_protocol_v1' },
      { keyFamily: 'ecdsa_secp256k1', version: 'rotatable_signing_lane_protocol_v1' },
    ],
    expiresAtMs: 9_000,
  } as const;
  const database = createTemporaryD1Database();
  await applyD1MigrationFiles(database.database, [
    path.resolve(
      '../packages/sdk-server-ts/migrations/d1-signer/0036_signer_linked_device_owner_planning_snapshots.sql',
    ),
  ]);
  const registrations = new Map([
    [String(ed.materialActivation.activationId), ed],
    [String(ecdsa.materialActivation.activationId), ecdsa],
  ]);
  const store = new D1LinkedDeviceOwnerPlanningSnapshotStoreV1({
    database: database.database,
    scope: { namespace: 'ns', orgId: 'org', projectId: 'project', envId: 'test' },
    walletRegistration: {
      resolveActiveOwnerWalletExecutionLane: async (input) => ({
        kind: 'projected',
        projection: registrations.get(String(input.expectedMaterialActivation.activationId))!,
      }),
    },
  });
  return {
    store,
    database: database.database,
    cleanup: () => cleanupTemporaryD1Database(database.tempDir),
    snapshot: {
      kind: 'linked_device_owner_planning_snapshot_v1',
      linkSessionId: String(base.payload.linkSessionId),
      walletId,
      owner: ownerContext(),
      payload: base.payload,
      metadata,
      sourceChildren: [edChild, ecdsaChild],
      orderedOwnerSourceLaneHints: [
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
          ecdsaSourceManifest: {
            manifestId: ecdsaChild.sourceCapability.manifestId,
            manifestRevision: ecdsaChild.sourceCapability.manifestRevision,
          },
        }),
      ],
    },
  };
}

function ed25519JobForSnapshot(snapshot: D1LinkedDeviceOwnerPlanningSnapshotInputV1) {
  const child = snapshot.sourceChildren[0];
  const binding = snapshot.metadata.orderedKeyBindings[0];
  if (!child || child.keyFamily !== 'ed25519' || !binding || binding.keyFamily !== 'ed25519') {
    throw new Error('mixed planning fixture has no Ed25519 child');
  }
  const template = buildR102LaneJob('snapshot-authorization');
  return parseRotatableSigningLaneJobV1({
    kind: 'ed25519_yao_lane_job_v1',
    keyFamily: 'ed25519',
    operationId: 'operation:snapshot-authorization',
    enrollmentId: 'enrollment:snapshot-authorization',
    idempotencyKey: snapshot.metadata.idempotencyKey,
    walletId: snapshot.walletId,
    walletKeyId: child.walletKeyId,
    source: child.source,
    targetHolder: {
      ...template.targetHolder,
      participantId: child.targetHolderParticipantId,
    },
    targetSigningWorker: child.targetSigningWorker,
    targetMaterialActivationId: template.targetMaterialActivationId,
    protocolVersion: 'rotatable_signing_lane_protocol_v1',
    expiresAtMs: snapshot.metadata.expiresAtMs,
    target: {
      operation: 'create_lane',
      laneId: binding.targetLaneId,
      laneKind: 'linked_device',
      laneShareEpoch: binding.targetLaneShareEpoch,
      expectedTargetState: 'absent',
    },
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: String(snapshot.metadata.operationId),
      linkedDeviceEnrollmentId: 'enrollment:snapshot-authorization',
      linkedDevicePermissionDigestB64u: snapshot.metadata.policyDigestB64u,
    },
    registeredPublicKeyB64u: child.registeredPublicKeyB64u,
    nearEd25519SigningKeyId: child.nearEd25519SigningKeyId,
    keyCreationSignerSlot: child.keyCreationSignerSlot,
    stableContextBindingB64u: child.stableContextBindingB64u,
    yaoSuiteId: child.yaoSuiteId,
    circuitDigestB64u: child.circuitDigestB64u,
    yaoRequestKind: 'lane_provisioning',
  });
}

test('persists mixed-curve owner planning snapshots with replay/conflict and hint tamper fencing', async () => {
  const value = await fixture();
  try {
    const applied = await value.store.insertOrReplayV1(value.snapshot);
    expect(applied.outcome).toBe('applied');
    const replayed = await value.store.insertOrReplayV1(value.snapshot);
    expect(replayed.outcome).toBe('replayed');
    const byOperation = await value.store.getByAuthorizedOperationV1(
      String(value.snapshot.metadata.operationId),
    );
    expect(byOperation?.linkSessionId).toBe(value.snapshot.linkSessionId);
    const lifecycleAuthorization = createD1LinkedDeviceLaneLifecycleAuthorizationV1({
      snapshots: value.store,
      lifecycle: {
        getProductEpoch: async () => null,
        getProtocol: async () => null,
      },
    });
    const job = ed25519JobForSnapshot(value.snapshot);
    await lifecycleAuthorization.authorizeLaneLifecycleV1({
      kind: 'record_lane_protocol_commit_v1',
      curve: 'ed25519_yao',
      job,
      expectedVersion: 1,
    });
    const substitutedJob = parseRotatableSigningLaneJobV1({
      ...job,
      registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(8)),
    });
    await expect(
      lifecycleAuthorization.authorizeLaneLifecycleV1({
        kind: 'record_lane_protocol_commit_v1',
        curve: 'ed25519_yao',
        job: substitutedJob,
        expectedVersion: 1,
      }),
    ).rejects.toThrow('Ed25519 lane job differs');
    const conflictPolicy = base64UrlEncode(new Uint8Array(32).fill(2));
    const conflict = await value.store.insertOrReplayV1({
      ...value.snapshot,
      metadata: {
        ...value.snapshot.metadata,
        policyDigestB64u: conflictPolicy,
      },
      sourceChildren: value.snapshot.sourceChildren.map((child) => ({
        ...child,
        authorization: {
          ...child.authorization,
          linkedDevicePermissionDigestB64u: conflictPolicy,
        },
      })) as typeof value.snapshot.sourceChildren,
    });
    expect(conflict.outcome).toBe('conflict');
    const storedHints = await value.database
      .prepare(
        'SELECT ordered_owner_source_lane_hints_json FROM linked_device_owner_planning_snapshots LIMIT 1',
      )
      .first<{ readonly ordered_owner_source_lane_hints_json?: unknown }>();
    const tamperedHints = JSON.parse(String(storedHints?.ordered_owner_source_lane_hints_json));
    tamperedHints[1].lane.laneShareEpoch = 'epoch:tampered';
    await value.database
      .prepare(
        'UPDATE linked_device_owner_planning_snapshots SET ordered_owner_source_lane_hints_json = ? WHERE link_session_id = ?',
      )
      .bind(JSON.stringify(tamperedHints), value.snapshot.linkSessionId)
      .run();
    await expect(value.store.getV1(value.snapshot.linkSessionId)).rejects.toThrow(
      'source lane hints column',
    );
  } finally {
    value.cleanup();
  }
});
