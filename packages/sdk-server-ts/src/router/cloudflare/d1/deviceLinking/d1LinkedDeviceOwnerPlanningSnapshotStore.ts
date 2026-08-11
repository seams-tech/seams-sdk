import type {
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceOwnerSourceLaneV1,
  LinkedDeviceProtocolVersionV1,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceEnrollmentKeyBindingV1,
  parseLinkedDeviceOwnerSourceLaneV1,
  parseLinkedDeviceProtocolVersionV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking/parsers';
import type { DeviceLinkingOwnerWalletSessionContextV1 } from '../../../../router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletId } from '@shared/utils/domainIds';
import {
  parseMpcMaterialActivationRef,
  parseProviderSubject,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type {
  WalletExecutionLaneAuthSource,
  WalletExecutionLaneProjectionResult,
} from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import { parseThresholdEd25519AuthorityScope } from '../../../../core/ThresholdService/validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import { d1ChangedRows, parseD1JsonColumn } from '../../../../storage/d1Sql';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import type {
  D1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
  D1LinkedDeviceOwnerAuthorizationMetadataV1,
} from './d1LinkedDeviceOwnerAuthorizationProvider';
import type {
  LinkedDeviceOwnerSourceChildResolutionRequestV1,
  LinkedDeviceOwnerSourceChildResolutionV1,
} from './d1LinkedDeviceTargetPlanner';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import { parseLinkedDeviceOwnerSourceChildResolutionV1 } from './d1LinkedDeviceOwnerPlanningSnapshotStoreParser';
import { parseLaneOperationId, parseLaneOperationIdempotencyKey } from '@shared/signing-lanes/ids';

const TABLE = 'linked_device_owner_planning_snapshots';

export type D1LinkedDeviceOwnerPlanningSnapshotV1 = {
  readonly kind: 'linked_device_owner_planning_snapshot_v1';
  readonly linkSessionId: string;
  readonly walletId: WalletId;
  readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
  readonly payload: QrLinkedDeviceSessionPayloadV4;
  readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataV1;
  readonly sourceChildren: readonly [
    LinkedDeviceOwnerSourceChildResolutionV1,
    ...LinkedDeviceOwnerSourceChildResolutionV1[],
  ];
  readonly orderedOwnerSourceLaneHints: readonly [
    LinkedDeviceOwnerSourceLaneV1,
    ...LinkedDeviceOwnerSourceLaneV1[],
  ];
};

export type D1LinkedDeviceOwnerPlanningSnapshotInputV1 = D1LinkedDeviceOwnerPlanningSnapshotV1;

export type D1LinkedDeviceOwnerPlanningSnapshotMutationV1 =
  | { readonly outcome: 'applied'; readonly snapshot: D1LinkedDeviceOwnerPlanningSnapshotV1 }
  | { readonly outcome: 'replayed'; readonly snapshot: D1LinkedDeviceOwnerPlanningSnapshotV1 }
  | {
      readonly outcome: 'conflict';
      readonly snapshot: D1LinkedDeviceOwnerPlanningSnapshotV1;
    };

export type D1LinkedDeviceOwnerPlanningSnapshotStoreOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly nowV1?: () => number;
};

export class D1LinkedDeviceOwnerPlanningSnapshotStoreV1 implements D1LinkedDeviceOwnerAuthorizationMetadataSourceV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly walletRegistration: D1LinkedDeviceOwnerPlanningSnapshotStoreOptionsV1['walletRegistration'];
  private readonly nowV1: () => number;

  constructor(options: D1LinkedDeviceOwnerPlanningSnapshotStoreOptionsV1) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
    this.walletRegistration = options.walletRegistration;
    this.nowV1 = options.nowV1 ?? Date.now;
  }

  async insertOrReplayV1(
    input: D1LinkedDeviceOwnerPlanningSnapshotInputV1,
  ): Promise<D1LinkedDeviceOwnerPlanningSnapshotMutationV1> {
    const normalized = await normalizeSnapshot(input, this.walletRegistration);
    const canonical = alphabetizeStringify(normalized);
    const digest = base64UrlEncode(await sha256BytesUtf8(canonical));
    const now = this.nowV1();
    if (!Number.isSafeInteger(now) || now <= 0) throw new Error('snapshot timestamp is invalid');
    let insertFailed = false;
    let insertError: unknown;
    try {
      const result = await this.database
        .prepare(
          `INSERT INTO ${TABLE} (
             namespace, org_id, project_id, env_id, link_session_id, wallet_id,
             owner_context_json, payload_json, policy_digest_b64u, operation_id,
             idempotency_key, ordered_key_bindings_json, protocol_versions_json,
             expires_at_ms, source_children_json, ordered_owner_source_lane_hints_json,
             snapshot_json, snapshot_digest_b64u,
             created_at_ms, updated_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          ...scopeValues(this.scope),
          normalized.linkSessionId,
          String(normalized.walletId),
          JSON.stringify(normalized.owner),
          JSON.stringify(normalized.payload),
          String(normalized.metadata.policyDigestB64u),
          String(normalized.metadata.operationId),
          String(normalized.metadata.idempotencyKey),
          JSON.stringify(normalized.metadata.orderedKeyBindings),
          JSON.stringify(normalized.metadata.protocolVersions),
          normalized.metadata.expiresAtMs,
          JSON.stringify(normalized.sourceChildren),
          JSON.stringify(normalized.orderedOwnerSourceLaneHints),
          canonical,
          digest,
          now,
          now,
        )
        .run();
      if (d1ChangedRows(result) === 1) return { outcome: 'applied', snapshot: normalized };
    } catch (error: unknown) {
      insertFailed = true;
      insertError = error;
    }
    const existing = await this.getV1(normalized.linkSessionId);
    if (!existing) {
      if (insertFailed) throw insertError;
      throw new Error('owner planning snapshot insert did not persist');
    }
    const existingCanonical = alphabetizeStringify(existing);
    if (existingCanonical === canonical) return { outcome: 'replayed', snapshot: existing };
    return { outcome: 'conflict', snapshot: existing };
  }

  async getV1(linkSessionId: string): Promise<D1LinkedDeviceOwnerPlanningSnapshotV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT link_session_id, wallet_id, owner_context_json, payload_json,
                policy_digest_b64u, operation_id, idempotency_key,
                ordered_key_bindings_json, protocol_versions_json, expires_at_ms,
                source_children_json, ordered_owner_source_lane_hints_json, snapshot_json,
                snapshot_digest_b64u,
                created_at_ms, updated_at_ms
           FROM ${TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), linkSessionId)
      .first<Record<string, unknown>>();
    if (!row) return null;
    const snapshotJson = requiredJson(row.snapshot_json, 'snapshot_json');
    const snapshot = await normalizeSnapshot(snapshotJson, this.walletRegistration);
    const canonical = alphabetizeStringify(snapshot);
    const digest = base64UrlEncode(await sha256BytesUtf8(canonical));
    if (String(row.snapshot_digest_b64u) !== digest) {
      throw new Error('owner planning snapshot digest does not match snapshot_json');
    }
    if (
      String(row.link_session_id) !== snapshot.linkSessionId ||
      String(row.wallet_id) !== snapshot.walletId
    ) {
      throw new Error('owner planning snapshot identity columns do not match snapshot_json');
    }
    if (String(row.owner_context_json) !== JSON.stringify(snapshot.owner)) {
      throw new Error('owner planning snapshot owner context column does not match snapshot_json');
    }
    if (String(row.payload_json) !== JSON.stringify(snapshot.payload)) {
      throw new Error('owner planning snapshot payload column does not match snapshot_json');
    }
    if (
      String(row.ordered_owner_source_lane_hints_json) !==
      JSON.stringify(snapshot.orderedOwnerSourceLaneHints)
    ) {
      throw new Error(
        'owner planning snapshot source lane hints column does not match snapshot_json',
      );
    }
    if (String(row.policy_digest_b64u) !== String(snapshot.metadata.policyDigestB64u)) {
      throw new Error('owner planning snapshot policy column does not match snapshot_json');
    }
    if (String(row.operation_id) !== String(snapshot.metadata.operationId)) {
      throw new Error('owner planning snapshot operation column does not match snapshot_json');
    }
    if (String(row.idempotency_key) !== String(snapshot.metadata.idempotencyKey)) {
      throw new Error('owner planning snapshot idempotency column does not match snapshot_json');
    }
    if (Number(row.expires_at_ms) !== snapshot.metadata.expiresAtMs) {
      throw new Error('owner planning snapshot expiry column does not match snapshot_json');
    }
    return snapshot;
  }

  async getByAuthorizedOperationV1(
    operationId: string,
  ): Promise<D1LinkedDeviceOwnerPlanningSnapshotV1 | null> {
    const normalizedOperationId = parseRequired(parseLaneOperationId(operationId), 'operationId');
    const row = await this.database
      .prepare(
        `SELECT link_session_id
           FROM ${TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND operation_id = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), String(normalizedOperationId))
      .first<{ readonly link_session_id?: unknown }>();
    if (!row) return null;
    return await this.getV1(requiredText(row.link_session_id, 'link_session_id'));
  }

  async readOwnerAuthorizationMetadataV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly payload: QrLinkedDeviceSessionPayloadV4;
  }): Promise<D1LinkedDeviceOwnerAuthorizationMetadataV1 | null> {
    const snapshot = await this.getV1(String(input.payload.linkSessionId));
    if (!snapshot || snapshot.walletId !== input.owner.walletId) return null;
    if (
      alphabetizeStringify(snapshot.owner) !== alphabetizeStringify(input.owner) ||
      alphabetizeStringify(snapshot.payload) !== alphabetizeStringify(input.payload)
    ) {
      return null;
    }
    return snapshot.metadata;
  }

  async readApprovedOwnerContextV1(input: {
    readonly walletId: WalletId;
    readonly linkSessionId: string;
  }): Promise<DeviceLinkingOwnerWalletSessionContextV1 | null> {
    const snapshot = await this.getV1(input.linkSessionId);
    if (!snapshot || snapshot.walletId !== input.walletId) return null;
    if (this.nowV1() >= snapshot.owner.expiresAtMs) return null;
    return snapshot.owner;
  }

  async readOwnerSourceChildV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly request: LinkedDeviceOwnerSourceChildResolutionRequestV1;
  }): Promise<LinkedDeviceOwnerSourceChildResolutionV1 | null> {
    const identity = sourceRequestIdentity(input.request);
    const snapshot = await this.getV1(identity.linkSessionId);
    if (!snapshot || snapshot.walletId !== identity.walletId) return null;
    if (alphabetizeStringify(snapshot.owner) !== alphabetizeStringify(input.owner)) return null;
    const childIndex = input.request.childIndex;
    const child = snapshot.sourceChildren[childIndex];
    if (!child) return null;
    const binding = snapshot.metadata.orderedKeyBindings[childIndex];
    if (!binding) return null;
    assertSourceChildMatchesBinding(child, binding, childIndex);
    assertSourceChildAuthorization(child, snapshot.metadata);
    if (input.request.kind === 'preparation') {
      if (
        input.request.approval.walletId !== snapshot.walletId ||
        input.request.approval.linkSessionId !== snapshot.linkSessionId
      )
        return null;
    } else if (
      input.request.preparation.walletId !== snapshot.walletId ||
      input.request.preparation.linkSessionId !== snapshot.linkSessionId
    ) {
      return null;
    }
    return child;
  }
}

function sourceRequestIdentity(request: LinkedDeviceOwnerSourceChildResolutionRequestV1): {
  readonly walletId: WalletId;
  readonly linkSessionId: string;
} {
  if (request.kind === 'preparation') {
    return {
      walletId: request.approval.walletId,
      linkSessionId: String(request.approval.linkSessionId),
    };
  }
  return {
    walletId: request.preparation.walletId,
    linkSessionId: String(request.preparation.linkSessionId),
  };
}

async function normalizeSnapshot(
  raw: D1LinkedDeviceOwnerPlanningSnapshotV1 | unknown,
  walletRegistration: D1LinkedDeviceOwnerPlanningSnapshotStoreOptionsV1['walletRegistration'],
): Promise<D1LinkedDeviceOwnerPlanningSnapshotV1> {
  const record = requireRecord(raw, 'owner planning snapshot');
  if (record.kind !== 'linked_device_owner_planning_snapshot_v1')
    throw new Error('owner planning snapshot kind is invalid');
  const payload = parseQrLinkedDeviceSessionPayloadV4(record.payload);
  const owner = parseOwnerContext(record.owner);
  const walletId = parseRequired(parseWalletId(record.walletId), 'walletId');
  const linkSessionId = requiredText(record.linkSessionId, 'linkSessionId');
  if (walletId !== owner.walletId || String(payload.linkSessionId) !== linkSessionId)
    throw new Error('owner planning snapshot identity is inconsistent');
  const metadataRecord = requireRecord(record.metadata, 'metadata');
  const metadata = normalizeMetadata(metadataRecord, owner, payload);
  const sourceChildrenRaw = record.sourceChildren;
  if (
    !Array.isArray(sourceChildrenRaw) ||
    sourceChildrenRaw.length !== metadata.orderedKeyBindings.length ||
    sourceChildrenRaw.length === 0
  )
    throw new Error('owner planning snapshot source children are incomplete');
  const sourceChildren = sourceChildrenRaw.map((value, index) =>
    parseLinkedDeviceOwnerSourceChildResolutionV1(value, `sourceChildren[${index}]`),
  );
  const hintsRaw = record.orderedOwnerSourceLaneHints;
  if (
    !Array.isArray(hintsRaw) ||
    hintsRaw.length !== sourceChildren.length ||
    hintsRaw.length === 0
  )
    throw new Error('owner planning snapshot source lane hints are incomplete');
  const orderedOwnerSourceLaneHints = hintsRaw.map((value, index) =>
    parseLinkedDeviceOwnerSourceLaneV1(value, `orderedOwnerSourceLaneHints[${index}]`),
  );
  for (let index = 0; index < sourceChildren.length; index += 1) {
    const child = sourceChildren[index];
    const binding = metadata.orderedKeyBindings[index];
    if (!child || !binding)
      throw new Error(`owner planning snapshot source child ${index} is missing`);
    const hint = orderedOwnerSourceLaneHints[index];
    if (!hint) throw new Error(`owner planning snapshot source lane hint ${index} is missing`);
    if (hint.walletKey.walletId !== owner.walletId)
      throw new Error(
        `owner planning snapshot source lane hint ${index} wallet differs from owner`,
      );
    assertSourceChildMatchesBinding(child, binding, index);
    assertSourceChildAuthorization(child, metadata);
    assertSourceChildMatchesHint(child, hint, index);
    await assertOwnerSourceHintMatchesRegistration(walletRegistration, hint);
    await assertSourceChildMatchesRegistration(walletRegistration, hint, child);
  }
  return {
    kind: 'linked_device_owner_planning_snapshot_v1',
    linkSessionId,
    walletId,
    owner,
    payload,
    metadata,
    sourceChildren: [sourceChildren[0]!, ...sourceChildren.slice(1)],
    orderedOwnerSourceLaneHints: [
      orderedOwnerSourceLaneHints[0]!,
      ...orderedOwnerSourceLaneHints.slice(1),
    ],
  };
}

async function assertOwnerSourceHintMatchesRegistration(
  walletRegistration: D1LinkedDeviceOwnerPlanningSnapshotStoreOptionsV1['walletRegistration'],
  hint: LinkedDeviceOwnerSourceLaneV1,
): Promise<void> {
  const result = await walletRegistration.resolveActiveOwnerWalletExecutionLane({
    walletId: hint.walletKey.walletId,
    authorization: { kind: 'wallet_auth_method', walletAuthMethodId: hint.lane.walletAuthMethodId },
    expectedMaterialActivation: hint.materialActivation,
  });
  if (result.kind !== 'projected')
    throw new Error(`owner source lane hint projection refused: ${result.reason}`);
  if (
    result.projection.walletKey.walletKeyId !== hint.walletKey.walletKeyId ||
    result.projection.walletKey.keyFamily !== hint.keyFamily ||
    result.projection.lane.laneId !== hint.lane.laneId ||
    result.projection.lane.laneShareEpoch !== hint.lane.laneShareEpoch ||
    result.projection.lane.participantBindingDigestB64u !==
      hint.lane.participantBindingDigestB64u ||
    String(result.projection.materialActivation.activationId) !==
      String(hint.materialActivation.activationId) ||
    result.projection.verifiedActivationReceiptDigestB64u !==
      hint.verifiedActivationReceiptDigestB64u
  )
    throw new Error('owner source lane hint does not match active wallet registration projection');
}

function assertSourceChildMatchesHint(
  child: LinkedDeviceOwnerSourceChildResolutionV1,
  hint: LinkedDeviceOwnerSourceLaneV1,
  index: number,
): void {
  if (
    child.keyFamily !== hint.keyFamily ||
    child.walletKeyId !== hint.walletKey.walletKeyId ||
    child.source.laneId !== hint.lane.laneId ||
    child.source.laneShareEpoch !== hint.lane.laneShareEpoch ||
    child.source.participantBindingDigestB64u !== hint.lane.participantBindingDigestB64u ||
    String(child.source.materialActivation.activationId) !==
      String(hint.materialActivation.activationId)
  )
    throw new Error(`owner source lane hint ${index} does not match source child plan`);
}

function normalizeMetadata(
  raw: Record<string, unknown>,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  payload: QrLinkedDeviceSessionPayloadV4,
): D1LinkedDeviceOwnerAuthorizationMetadataV1 {
  const walletId = parseRequired(parseWalletId(raw.walletId), 'metadata.walletId');
  const policyDigestB64u = parseDigestB64u(raw.policyDigestB64u);
  const operationId = parseRequired(parseLaneOperationId(raw.operationId), 'metadata.operationId');
  const idempotencyKey = parseRequired(
    parseLaneOperationIdempotencyKey(raw.idempotencyKey),
    'metadata.idempotencyKey',
  );
  const orderedRaw = raw.orderedKeyBindings;
  const protocolRaw = raw.protocolVersions;
  if (!Array.isArray(orderedRaw) || !Array.isArray(protocolRaw))
    throw new Error('owner planning metadata arrays are invalid');
  const orderedKeyBindings = orderedRaw.map((value, index) =>
    parseLinkedDeviceEnrollmentKeyBindingV1(value, `metadata.orderedKeyBindings[${index}]`),
  );
  const protocolVersions = protocolRaw.map((value, index) =>
    parseLinkedDeviceProtocolVersionV1(value, `metadata.protocolVersions[${index}]`),
  );
  const expiresAtMs = requiredPositiveInteger(raw.expiresAtMs, 'metadata.expiresAtMs');
  if (
    walletId !== owner.walletId ||
    orderedKeyBindings.length === 0 ||
    protocolVersions.length === 0 ||
    expiresAtMs > owner.expiresAtMs ||
    expiresAtMs > payload.expiresAtMs
  )
    throw new Error('owner planning metadata is inconsistent');
  return {
    walletId,
    policyDigestB64u,
    operationId,
    idempotencyKey,
    orderedKeyBindings: [orderedKeyBindings[0]!, ...orderedKeyBindings.slice(1)],
    protocolVersions: [protocolVersions[0]!, ...protocolVersions.slice(1)],
    expiresAtMs,
  };
}

function parseOwnerContext(raw: unknown): DeviceLinkingOwnerWalletSessionContextV1 {
  const record = requireRecord(raw, 'owner context');
  const walletId = parseRequired(parseWalletId(record.walletId), 'owner.walletId');
  const walletSessionId = parseRequired(
    parseWalletSessionId(record.walletSessionId),
    'owner.walletSessionId',
  );
  const authorizationId = parseRequired(
    parseWalletSessionAuthorizationId(record.authorizationId),
    'owner.authorizationId',
  );
  const expiresAtMs = requiredPositiveInteger(record.expiresAtMs, 'owner.expiresAtMs');
  if (record.curve === 'ed25519') {
    const authority = parseWalletAuthAuthority(record.authority);
    const authorityScope = parseThresholdEd25519AuthorityScope(record.authorityScope);
    if (
      !authority ||
      !authorityScope ||
      record.walletAuthAuthorityRef !== undefined ||
      record.authSource !== undefined
    )
      throw new Error('owner ed25519 context is invalid');
    return {
      walletId,
      walletSessionId,
      authorizationId,
      expiresAtMs,
      curve: 'ed25519',
      authority,
      authorityScope,
    };
  }
  if (record.curve === 'ecdsa') {
    const walletAuthAuthorityRef = parseWalletAuthAuthorityRef(record.walletAuthAuthorityRef);
    const authSource = parseAuthSource(record.authSource);
    if (
      !walletAuthAuthorityRef ||
      !authSource ||
      record.authority !== undefined ||
      record.authorityScope !== undefined
    )
      throw new Error('owner ecdsa context is invalid');
    return {
      walletId,
      walletSessionId,
      authorizationId,
      expiresAtMs,
      curve: 'ecdsa',
      walletAuthAuthorityRef,
      authSource,
    };
  }
  throw new Error('owner context curve is invalid');
}

function parseAuthSource(raw: unknown): WalletExecutionLaneAuthSource | null {
  const record =
    raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null;
  if (!record) return null;
  if (record.kind === 'passkey') {
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(record.credentialIdB64u);
    return credentialIdB64u.ok
      ? { kind: 'passkey', credentialIdB64u: credentialIdB64u.value }
      : null;
  }
  if (
    record.kind === 'oidc_provider' &&
    (record.providerId === 'google_oidc' || record.providerId === 'oidc')
  ) {
    const providerSubject = parseProviderSubject(record.providerSubject);
    return providerSubject.ok
      ? {
          kind: 'oidc_provider',
          providerId: record.providerId,
          providerSubject: providerSubject.value,
        }
      : null;
  }
  return null;
}

async function assertSourceChildMatchesRegistration(
  walletRegistration: D1LinkedDeviceOwnerPlanningSnapshotStoreOptionsV1['walletRegistration'],
  hint: LinkedDeviceOwnerSourceLaneV1,
  child: LinkedDeviceOwnerSourceChildResolutionV1,
): Promise<void> {
  const projected: WalletExecutionLaneProjectionResult =
    await walletRegistration.resolveActiveOwnerWalletExecutionLane({
      walletId: hint.walletKey.walletId,
      authorization: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: hint.lane.walletAuthMethodId,
      },
      expectedMaterialActivation: child.source.materialActivation,
    });
  if (projected.kind !== 'projected')
    throw new Error(`active owner source projection refused: ${projected.reason}`);
  const projection = projected.projection;
  if (
    projection.walletKey.walletId !== hint.walletKey.walletId ||
    projection.walletKey.walletKeyId !== child.walletKeyId ||
    projection.walletKey.keyFamily !== child.keyFamily ||
    projection.lane.laneId !== child.source.laneId ||
    projection.lane.laneKind !== child.source.laneKind ||
    projection.lane.laneShareEpoch !== child.source.laneShareEpoch ||
    projection.lane.lifecycle.revocationEpoch !== child.source.revocationEpoch ||
    projection.lane.participantBindingDigestB64u !== child.source.participantBindingDigestB64u
  )
    throw new Error('owner source child does not match active wallet registration projection');
  if (
    child.keyFamily === 'ed25519' &&
    projection.walletKey.keyFamily === 'ed25519' &&
    (projection.walletKey.registeredPublicKeyB64u !== child.registeredPublicKeyB64u ||
      projection.walletKey.nearEd25519SigningKeyId !== child.nearEd25519SigningKeyId ||
      projection.walletKey.keyCreationSignerSlot !== child.keyCreationSignerSlot)
  )
    throw new Error('Ed25519 owner source child identity does not match wallet registration');
  if (
    child.keyFamily === 'ecdsa_secp256k1' &&
    projection.walletKey.keyFamily === 'ecdsa_secp256k1' &&
    (projection.walletKey.thresholdPublicKey33B64u !== child.thresholdPublicKey33B64u ||
      projection.walletKey.evmAddress !== child.evmAddress ||
      projection.walletKey.evmFamilySigningKeySlotId !== child.evmFamilySigningKeySlotId)
  )
    throw new Error('ECDSA owner source child identity does not match wallet registration');
}

function assertSourceChildMatchesBinding(
  child: LinkedDeviceOwnerSourceChildResolutionV1,
  binding: LinkedDeviceEnrollmentKeyBindingV1,
  index: number,
): void {
  if (
    child.walletKeyId !== binding.walletKeyId ||
    child.keyFamily !== binding.keyFamily ||
    child.source.laneId !== binding.sourceLaneId ||
    child.source.laneShareEpoch !== binding.sourceLaneShareEpoch ||
    child.source.revocationEpoch !== binding.sourceRevocationEpoch ||
    child.source.holderParticipantId !== binding.sourceHolderParticipantId ||
    child.source.signingWorkerParticipantId !== binding.sourceSigningWorkerParticipantId
  )
    throw new Error(`owner source child ${index} differs from metadata binding`);
}

function assertSourceChildAuthorization(
  child: LinkedDeviceOwnerSourceChildResolutionV1,
  metadata: D1LinkedDeviceOwnerAuthorizationMetadataV1,
): void {
  if (String(child.authorization.authorizedOperationId) !== String(metadata.operationId)) {
    throw new Error(
      `owner source child operation differs from metadata: ${String(child.authorization.authorizedOperationId)} != ${String(metadata.operationId)}`,
    );
  }
  if (String(child.authorization.idempotencyKey) !== String(metadata.idempotencyKey)) {
    throw new Error(
      `owner source child idempotency differs from metadata: ${String(child.authorization.idempotencyKey)} != ${String(metadata.idempotencyKey)}`,
    );
  }
  if (
    String(child.authorization.linkedDevicePermissionDigestB64u) !==
    String(metadata.policyDigestB64u)
  ) {
    throw new Error(
      `owner source child policy differs from metadata: ${String(child.authorization.linkedDevicePermissionDigestB64u)} != ${String(metadata.policyDigestB64u)}`,
    );
  }
}

function parseRequired<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label}: ${result.error.message}`);
}
function parseRequiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim() || value.trim() !== value)
    throw new Error(`${label} is invalid`);
  return value;
}
function requiredText(value: unknown, label: string): string {
  return parseRequiredString(value, label);
}
function requiredPositiveInteger(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${label} is invalid`);
  return parsed;
}
function requiredJson(value: unknown, label: string): unknown {
  const parsed = parseD1JsonColumn(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    throw new Error(`${label} is invalid`);
  return parsed;
}
function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1LinkedDeviceSessionScopeV1 {
  return {
    namespace: requiredText(scope.namespace, 'namespace'),
    orgId: requiredText(scope.orgId, 'orgId'),
    projectId: requiredText(scope.projectId, 'projectId'),
    envId: requiredText(scope.envId, 'envId'),
  };
}
function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}
