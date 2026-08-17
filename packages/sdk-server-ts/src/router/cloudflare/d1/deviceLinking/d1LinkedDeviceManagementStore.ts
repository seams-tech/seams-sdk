import type {
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LaneEnrollmentId,
} from '@shared/signing-lanes/ids';
import { parseLaneEnrollmentId } from '@shared/signing-lanes/ids';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import type { LaneEnrollmentManifestV1, LaneProductEpochRecordV1 } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { queryD1All, queryD1One } from '../../../../storage/d1Sql';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type {
  LinkedDeviceManagementProjectionPortV1,
  LinkedDeviceManagementTargetV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import { encodeLinkedDeviceListCursorV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type {
  LinkedDeviceListResultV1,
  LinkedDeviceSummaryV1,
} from '@shared/device-linking/contracts';
import { parseLinkedDeviceTargetCredentialRegistrationV1 } from '@shared/device-linking/parsers';
import type {
  LinkedDeviceSessionRecordV1,
  LinkedDeviceSessionListCursorV1,
  LinkedDeviceSessionListPageV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import type { LinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LaneEnrollmentAdmissionRecord } from '../../../../core/signingLanes/LaneLifecycleStore';
import {
  parseEnrollmentRow,
  parseProductEpochRow,
} from '../signingLanes/d1LaneRecords';

const ENROLLMENT_TABLE = 'lane_enrollments';
const TARGET_CREDENTIAL_TABLE = 'linked_device_target_credentials';
const AUTHORIZATION_AUDIT_TABLE = 'authorized_operation_audit_events';

export type D1LinkedDeviceManagementMetadataV1 = {
  readonly label: string;
  readonly platform: string;
};

export type D1LinkedDeviceManagementMetadataPortV1 = {
  readLinkedDeviceMetadataV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<D1LinkedDeviceManagementMetadataV1 | null>;
  readonly readLinkedDeviceMetadataBatchV1: (
    input: ReadonlyArray<{
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
    }>,
  ) => Promise<ReadonlyMap<string, D1LinkedDeviceManagementMetadataV1>>;
};

export class D1LinkedDeviceTargetCredentialMetadataSourceV1 implements D1LinkedDeviceManagementMetadataPortV1 {
  constructor(
    private readonly input: {
      readonly database: D1DatabaseLike;
      readonly scope: D1LinkedDeviceSessionScopeV1;
    },
  ) {}

  async readLinkedDeviceMetadataV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<D1LinkedDeviceManagementMetadataV1 | null> {
    const row = await queryD1One(
      this.input.database,
      `SELECT registration_json
         FROM ${TARGET_CREDENTIAL_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_id = ?5 AND enrollment_id = ?6 AND device_id = ?7
          AND state = 'registered'
        LIMIT 1`,
      [
        ...scopeValues(normalizeScope(this.input.scope)),
        String(input.walletId),
        String(input.enrollmentId),
        String(input.deviceId),
      ],
    );
    if (!row) return null;
    const registrationJson = requiredString(field(row, 'registration_json'), 'registration_json');
    const registration = parseLinkedDeviceTargetCredentialRegistrationV1(
      JSON.parse(registrationJson),
    );
    if (
      registration.walletId !== input.walletId ||
      registration.enrollmentId !== input.enrollmentId ||
      registration.deviceId !== input.deviceId
    ) {
      throw new Error('linked-device target credential metadata identity changed');
    }
    return metadataFromRegistration(registration.webauthnRegistration);
  }

  async readLinkedDeviceMetadataBatchV1(
    inputs: ReadonlyArray<{
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
    }>,
  ): Promise<ReadonlyMap<string, D1LinkedDeviceManagementMetadataV1>> {
    if (inputs.length === 0) return new Map();
    const keySet = new Set(inputs.map(metadataKey));
    const rows = await queryD1All(
      this.input.database,
      `SELECT wallet_id, enrollment_id, device_id, registration_json
         FROM ${TARGET_CREDENTIAL_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND state = 'registered'
          AND wallet_id IN (${inputs.map((_, index) => `?${index + 5}`).join(', ')})`,
      [...scopeValues(normalizeScope(this.input.scope)), ...inputs.map((item) => String(item.walletId))],
    );
    const result = new Map<string, D1LinkedDeviceManagementMetadataV1>();
    for (const row of rows) {
      const walletId = requiredString(field(row, 'wallet_id'), 'wallet_id');
      const enrollmentId = requiredString(field(row, 'enrollment_id'), 'enrollment_id');
      const deviceId = requiredString(field(row, 'device_id'), 'device_id');
      const key = `${walletId}\u0000${enrollmentId}\u0000${deviceId}`;
      if (!keySet.has(key)) continue;
      const registration = parseLinkedDeviceTargetCredentialRegistrationV1(
        JSON.parse(requiredString(field(row, 'registration_json'), 'registration_json')),
      );
      if (
        String(registration.walletId) !== walletId ||
        String(registration.enrollmentId) !== enrollmentId ||
        String(registration.deviceId) !== deviceId ||
        result.has(key)
      ) {
        throw new Error('linked-device target credential metadata identity changed');
      }
      result.set(key, metadataFromRegistration(registration.webauthnRegistration));
    }
    return result;
  }
}

export class D1LinkedDeviceSigningActivitySourceV1 {
  private readonly scope: D1LinkedDeviceSessionScopeV1;

  constructor(
    private readonly input: {
      readonly database: D1DatabaseLike;
      readonly scope: D1LinkedDeviceSessionScopeV1;
    },
  ) {
    this.scope = normalizeScope(input.scope);
  }

  async readLastSigningActivityAtMsV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<number | null> {
    const row = await queryD1One(
      this.input.database,
      `SELECT MAX(COALESCE(completed_at_ms, claimed_at_ms)) AS last_activity_at_ms
         FROM ${AUTHORIZATION_AUDIT_TABLE}
        WHERE namespace = ?1
          AND authorization_grant_kind = 'linked_device_wallet_session_authorization_v1'
          AND linked_scope_org_id = ?2
          AND linked_scope_project_id = ?3
          AND linked_scope_env_id = ?4
          AND linked_wallet_id = ?5
          AND linked_enrollment_id = ?6
          AND linked_device_id = ?7`,
      [
        ...scopeValues(this.scope),
        String(input.walletId),
        String(input.enrollmentId),
        String(input.deviceId),
      ],
    );
    if (!row) return null;
    const timestamp = field(row, 'last_activity_at_ms');
    if (timestamp === null || timestamp === undefined) return null;
    return requiredTimestamp(timestamp, 'linked-device signing last activity');
  }

  async readLastSigningActivityBatchV1(
    inputs: ReadonlyArray<{
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
    }>,
  ): Promise<ReadonlyMap<string, number>> {
    if (inputs.length === 0) return new Map();
    const rows = await queryD1All(
      this.input.database,
      `SELECT linked_wallet_id, linked_enrollment_id, linked_device_id,
              MAX(COALESCE(completed_at_ms, claimed_at_ms)) AS last_activity_at_ms
         FROM ${AUTHORIZATION_AUDIT_TABLE}
        WHERE namespace = ?1 AND linked_scope_org_id = ?2
          AND linked_scope_project_id = ?3 AND linked_scope_env_id = ?4
          AND authorization_grant_kind = 'linked_device_wallet_session_authorization_v1'
          AND linked_wallet_id IN (${inputs.map((_, index) => `?${index + 5}`).join(', ')})
        GROUP BY linked_wallet_id, linked_enrollment_id, linked_device_id`,
      [...scopeValues(this.scope), ...inputs.map((item) => String(item.walletId))],
    );
    const result = new Map<string, number>();
    for (const row of rows) {
      const timestamp = field(row, 'last_activity_at_ms');
      if (timestamp === null || timestamp === undefined) continue;
      result.set(
        `${requiredString(field(row, 'linked_wallet_id'), 'linked_wallet_id')}\u0000${requiredString(field(row, 'linked_enrollment_id'), 'linked_enrollment_id')}\u0000${requiredString(field(row, 'linked_device_id'), 'linked_device_id')}`,
        requiredTimestamp(timestamp, 'linked-device signing last activity'),
      );
    }
    return result;
  }
}

export type D1LinkedDeviceManagementStoreOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly sessionService: Pick<LinkedDeviceSessionServiceV1, 'getSessionV1' | 'listSessionsForWalletV1'>;
  readonly nowV1: () => number;
  readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
};

type ManagementProjectionContextV1 = {
  readonly enrollments: ReadonlyMap<string, {
    readonly admission: LaneEnrollmentAdmissionRecord;
    readonly manifestDigestB64u: string;
    readonly updatedAtMs: number;
  }>;
  readonly products: ReadonlyMap<string, readonly LaneProductEpochRecordV1[]>;
  readonly metadata: ReadonlyMap<string, D1LinkedDeviceManagementMetadataV1>;
  readonly signingActivity: ReadonlyMap<string, number>;
};

type LinkedDeviceManagementIdentityV1 = {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
};

export class D1LinkedDeviceManagementStoreV1 implements LinkedDeviceManagementProjectionPortV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly sessionService: Pick<LinkedDeviceSessionServiceV1, 'getSessionV1' | 'listSessionsForWalletV1'>;
  private readonly nowV1: () => number;
  private readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
  private readonly signingActivity: D1LinkedDeviceSigningActivitySourceV1;

  constructor(options: D1LinkedDeviceManagementStoreOptionsV1) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
    this.sessionService = options.sessionService;
    this.nowV1 = options.nowV1;
    this.metadata = options.metadata;
    this.signingActivity = new D1LinkedDeviceSigningActivitySourceV1({
      database: this.database,
      scope: this.scope,
    });
  }

  async listLinkedDevicesV1(input: {
    readonly walletId: WalletId;
    readonly limit: number;
    readonly cursor: LinkedDeviceSessionListCursorV1 | null;
  }): Promise<LinkedDeviceListResultV1> {
    const sessions = await this.readClaimedSessionsV1({
      walletId: input.walletId,
      deviceId: undefined,
      limit: input.limit,
      cursor: input.cursor,
    });
    const context = await this.buildProjectionContextV1(sessions.records);
    const summaries: LinkedDeviceSummaryV1[] = [];
    for (const session of sessions.records) {
      const target = await this.projectSessionV1(session, context);
      if (!target || target.summary.walletId !== input.walletId) continue;
      summaries.push(target.summary);
    }
    return {
      devices: summaries,
      nextCursor: sessions.nextCursor
        ? encodeLinkedDeviceListCursorV1(sessions.nextCursor)
        : null,
    };
  }

  async getLinkedDeviceV1(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<LinkedDeviceManagementTargetV1 | null> {
    const sessions = await this.readClaimedSessionsV1({
      walletId: input.walletId,
      deviceId: input.deviceId,
    });
    const context = await this.buildProjectionContextV1(sessions.records);
    for (const session of sessions.records) {
      const target = await this.projectSessionV1(session, context);
      if (
        target &&
        target.summary.walletId === input.walletId &&
        target.summary.deviceId === input.deviceId
      ) {
        return target;
      }
    }
    return null;
  }

  private async readClaimedSessionsV1(
    input:
      | {
          readonly walletId: WalletId;
          readonly deviceId: undefined;
          readonly limit: number;
          readonly cursor: LinkedDeviceSessionListCursorV1 | null;
        }
      | {
          readonly walletId: WalletId;
          readonly deviceId: LinkedDeviceId;
        },
  ): Promise<LinkedDeviceSessionListPageV1> {
    if (input.deviceId === undefined) {
      return await this.sessionService.listSessionsForWalletV1({
        walletId: input.walletId,
        nowMs: this.nowV1(),
        limit: input.limit,
        cursor: input.cursor,
      });
    }
    const sessions = await this.sessionService.listSessionsForWalletV1({
      walletId: input.walletId,
      nowMs: this.nowV1(),
      limit: Number.MAX_SAFE_INTEGER - 1,
      cursor: null,
    });
    return {
      records: sessions.records.filter(
        (session) => session.claimTranscript?.value.deviceId === input.deviceId,
      ),
      nextCursor: sessions.nextCursor,
    };
  }

  private async projectSessionV1(
    session: LinkedDeviceSessionRecordV1,
    context: ManagementProjectionContextV1,
  ): Promise<LinkedDeviceManagementTargetV1 | null> {
    const claim = session.claimTranscript?.value;
    const approval = session.approvalTranscript?.value;
    if (!claim || !approval) return null;
    if (
      claim.walletId !== approval.walletId ||
      claim.enrollmentId !== approval.enrollmentId ||
      claim.deviceId !== approval.deviceId ||
      claim.devicePublicKeyB64u !== approval.devicePublicKeyB64u
    ) {
      throw new Error('linked-device session transcripts disagree on identity');
    }
    const laneEnrollmentId = parseRequiredLaneEnrollmentId(claim.enrollmentId);
    const enrollmentContext = context.enrollments.get(String(laneEnrollmentId));
    if (!enrollmentContext) return null;
    const enrollment = enrollmentContext.admission;
    const manifestDigest = parseDigestB64u(
      await computeLaneEnrollmentManifestDigestV1(enrollment.value.manifest),
    );
    if (enrollmentContext.manifestDigestB64u !== manifestDigest) {
      throw new Error('lane enrollment manifest digest does not match its columns');
    }
    assertManifestMatchesIdentity(
      enrollment.value.manifest,
      claim.walletId,
      laneEnrollmentId,
      claim.enrollmentId,
    );
    const products = context.products.get(String(laneEnrollmentId)) ?? [];
    assertProductsMatchManifest(
      products,
      enrollment.value.manifest,
      enrollment.value.lifecycle,
    );
    const metadata = context.metadata.get(metadataKey({
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
    })) ?? null;
    if (!metadata) return null;
    const normalizedMetadata = parseMetadata(metadata);
    const enrollmentUpdatedAtMs = enrollmentContext.updatedAtMs;
    const signingActivityAtMs = context.signingActivity.get(metadataKey({
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
    })) ?? null;
    const lastActivityAtMs = Math.max(
      session.updatedAtMs,
      enrollmentUpdatedAtMs,
      signingActivityAtMs ?? 0,
      ...products.map(productActivityAtMs),
    );
    const summary: LinkedDeviceSummaryV1 = {
      deviceId: claim.deviceId,
      enrollmentId: claim.enrollmentId,
      walletId: claim.walletId,
      label: normalizedMetadata.label,
      platform: normalizedMetadata.platform,
      permission: approval.permission,
      keyManifestDigestB64u: manifestDigest,
      coveredWalletKeys: enrollment.value.manifest.orderedChildren.map(
        (child) => child.walletKeyId,
      ),
      state: projectState(session, enrollment.value.lifecycle),
      createdAtMs: session.createdAtMs,
      lastActivityAtMs,
      revocationEpoch: products.reduce(
        (maximum, product) => Math.max(maximum, product.revocationEpoch),
        0,
      ),
    };
    return { summary, session, enrollment, products };
  }

  private async buildProjectionContextV1(
    sessions: readonly LinkedDeviceSessionRecordV1[],
  ): Promise<ManagementProjectionContextV1> {
    const identities = uniqueSessionIdentities(sessions);
    if (identities.length === 0) {
      return { enrollments: new Map(), products: new Map(), metadata: new Map(), signingActivity: new Map() };
    }
    const enrollmentIds = [...new Set(identities.map((identity) => String(identity.enrollmentId)))];
    const enrollmentRows = await queryD1All(
      this.database,
      `SELECT enrollment_id, wallet_id, manifest_digest_b64u, manifest_json,
              lifecycle_json, version, command_digest_b64u, created_at_ms, updated_at_ms
         FROM ${ENROLLMENT_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND enrollment_id IN (${enrollmentIds.map((_, index) => `?${index + 5}`).join(', ')})`,
      [...scopeValues(this.scope), ...enrollmentIds],
    );
    const enrollments = new Map<string, {
      readonly admission: LaneEnrollmentAdmissionRecord;
      readonly manifestDigestB64u: string;
      readonly updatedAtMs: number;
    }>();
    for (const row of enrollmentRows) {
      const parsed = parseEnrollmentRow(row);
      enrollments.set(parsed.enrollmentId, {
        admission: {
          version: parsed.version,
          commandDigestB64u: parsed.commandDigestB64u,
          value: { manifest: parsed.manifest, lifecycle: parsed.lifecycle },
        },
        manifestDigestB64u: parsed.manifestDigestB64u,
        updatedAtMs: parsed.updatedAtMs,
      });
    }
    const productRows = await queryD1All(
      this.database,
      `SELECT enrollment_id, product_json
         FROM lane_product_epochs
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND enrollment_id IN (${enrollmentIds.map((_, index) => `?${index + 5}`).join(', ')})`,
      [...scopeValues(this.scope), ...enrollmentIds],
    );
    const products = new Map<string, LaneProductEpochRecordV1[]>();
    for (const row of productRows) {
      const enrollmentId = requiredString(field(row, 'enrollment_id'), 'enrollment_id');
      const product = parseProductEpochRow(row);
      const existing = products.get(enrollmentId);
      if (existing) existing.push(product);
      else products.set(enrollmentId, [product]);
    }
    const metadata = await this.metadata.readLinkedDeviceMetadataBatchV1(identities);
    const signingActivity = await this.signingActivity.readLastSigningActivityBatchV1(identities);
    return { enrollments, products, metadata, signingActivity };
  }

}

function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1LinkedDeviceSessionScopeV1 {
  return {
    namespace: requiredScopeString(scope.namespace, 'namespace'),
    orgId: requiredScopeString(scope.orgId, 'orgId'),
    projectId: requiredScopeString(scope.projectId, 'projectId'),
    envId: requiredScopeString(scope.envId, 'envId'),
  };
}

function metadataKey(input: LinkedDeviceManagementIdentityV1): string {
  return `${String(input.walletId)}\u0000${String(input.enrollmentId)}\u0000${String(input.deviceId)}`;
}

function uniqueSessionIdentities(
  sessions: readonly LinkedDeviceSessionRecordV1[],
): readonly LinkedDeviceManagementIdentityV1[] {
  const identities = new Map<string, LinkedDeviceManagementIdentityV1>();
  for (const session of sessions) {
    const claim = session.claimTranscript?.value;
    const approval = session.approvalTranscript?.value;
    if (!claim || !approval) continue;
    const identity = {
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
    } satisfies LinkedDeviceManagementIdentityV1;
    identities.set(metadataKey(identity), identity);
  }
  return [...identities.values()];
}

function requiredScopeString(value: string, field: string): string {
  if (typeof value !== 'string' || !value.trim() || value.trim() !== value) {
    throw new Error(`linked-device management ${field} is invalid`);
  }
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function parseRequiredLaneEnrollmentId(raw: string): LaneEnrollmentId {
  const parsed = parseLaneEnrollmentId(raw);
  if (!parsed.ok) throw new Error('linked-device management enrollment id is invalid');
  return parsed.value;
}

function field(row: Record<string, unknown> | null, name: string): unknown {
  if (!row || !Object.prototype.hasOwnProperty.call(row, name)) {
    throw new Error(`linked-device management row is missing ${name}`);
  }
  return row[name];
}

function requiredString(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || !raw || raw.trim() !== raw) throw new Error(`${field} is invalid`);
  return raw;
}

function requiredTimestamp(raw: unknown, field: string): number {
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} is invalid`);
  return value;
}

function parseMetadata(
  metadata: D1LinkedDeviceManagementMetadataV1,
): D1LinkedDeviceManagementMetadataV1 {
  if (
    typeof metadata.label !== 'string' ||
    !metadata.label ||
    metadata.label.trim() !== metadata.label ||
    typeof metadata.platform !== 'string' ||
    !metadata.platform ||
    metadata.platform.trim() !== metadata.platform
  ) {
    throw new Error('linked-device metadata is invalid');
  }
  return metadata;
}

function metadataFromRegistration(
  registration: ReturnType<
    typeof parseLinkedDeviceTargetCredentialRegistrationV1
  >['webauthnRegistration'],
): D1LinkedDeviceManagementMetadataV1 {
  switch (registration.authenticatorAttachment) {
    case 'platform':
      return { label: 'Platform passkey', platform: 'platform' };
    case 'cross-platform':
      return { label: 'Security key', platform: 'cross-platform' };
    case null: {
      const platform = registration.transports.includes('internal')
        ? 'platform'
        : (registration.transports[0] ?? 'unspecified');
      return { label: 'Passkey', platform };
    }
  }
}

function assertManifestMatchesIdentity(
  manifest: LaneEnrollmentManifestV1,
  walletId: WalletId,
  laneEnrollmentId: LaneEnrollmentId,
  linkedEnrollmentId: LinkedDeviceEnrollmentId,
): void {
  if (
    manifest.walletId !== walletId ||
    String(manifest.enrollmentId) !== String(laneEnrollmentId) ||
    manifest.authorization.kind !== 'linked_device_enrollment' ||
    manifest.authorization.linkedDeviceEnrollmentId !== linkedEnrollmentId
  ) {
    throw new Error('lane enrollment manifest is not bound to the linked device');
  }
}

function assertProductsMatchManifest(
  products: readonly LaneProductEpochRecordV1[],
  manifest: LaneEnrollmentManifestV1,
  lifecycle: LaneEnrollmentAdmissionRecord['value']['lifecycle'],
): void {
  if (
    (lifecycle.state === 'ready_for_visibility' || lifecycle.state === 'active') &&
    products.length !== manifest.orderedChildren.length
  ) {
    throw new Error('lane enrollment products do not match the manifest count');
  }
  const byOperation = new Map(products.map((product) => [String(product.operationId), product]));
  if (byOperation.size !== products.length)
    throw new Error('lane enrollment products are duplicated');
  const childrenByOperation = new Map(
    manifest.orderedChildren.map((child) => [String(child.operationId), child]),
  );
  for (const product of products) {
    const child = childrenByOperation.get(String(product.operationId));
    if (
      !child ||
      product.enrollmentId !== manifest.enrollmentId ||
      product.walletId !== manifest.walletId ||
      product.walletKeyId !== child.walletKeyId ||
      product.laneKind !== 'linked_device' ||
      product.laneId !== child.targetLaneId ||
      product.laneShareEpoch !== child.targetLaneShareEpoch ||
      product.targetMaterialActivationId !== child.targetMaterialActivationId ||
      product.keyFamily !== child.keyFamily ||
      product.holderParticipant.participantBindingDigestB64u !==
        child.holderParticipantBindingDigestB64u ||
      product.signingWorkerParticipant.participantBindingDigestB64u !==
        child.signingWorkerParticipantBindingDigestB64u
    ) {
      throw new Error('lane enrollment product does not match its manifest child');
    }
  }
}

function projectState(
  session: LinkedDeviceSessionRecordV1,
  lifecycle: LaneEnrollmentAdmissionRecord['value']['lifecycle'],
): LinkedDeviceSummaryV1['state'] {
  if (lifecycle.state === 'revoked') return 'revoked';
  if (session.state.state === 'expired_claimed') return 'expired';
  if (
    session.state.state === 'cancelled_claimed_precommit' ||
    session.state.state === 'committed_completion_required' ||
    lifecycle.state === 'revoking_committed_targets'
  ) {
    return 'suspended';
  }
  if (lifecycle.state === 'active' && session.state.state === 'active') return 'active';
  return 'provisioning';
}

function productActivityAtMs(product: LaneProductEpochRecordV1): number {
  switch (product.state) {
    case 'pending_visibility':
      return Math.max(product.createdAtMs, product.pendingSinceMs);
    case 'active':
      return Math.max(product.createdAtMs, product.activatedAtMs);
    case 'retired':
      return Math.max(product.createdAtMs, product.retiredAtMs);
    case 'revocation_pending':
      return Math.max(product.createdAtMs, product.revocationRequestedAtMs);
    case 'revoked':
      return Math.max(product.createdAtMs, product.revokedAtMs);
  }
}
