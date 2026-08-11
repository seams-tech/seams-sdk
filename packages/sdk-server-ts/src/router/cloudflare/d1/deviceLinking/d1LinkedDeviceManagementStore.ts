import type {
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LinkDeviceSessionId,
  LaneEnrollmentId,
} from '@shared/signing-lanes/ids';
import { parseLaneEnrollmentId, parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
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
import type { LinkedDeviceSummaryV1 } from '@shared/device-linking/contracts';
import { parseLinkedDeviceTargetCredentialRegistrationV1 } from '@shared/device-linking/parsers';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import type { LinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';
import type { CloudflareD1LaneScopeV1 } from '../signingLanes/d1LaneRecords';
import type { LaneEnrollmentAdmissionRecord } from '../../../../core/signingLanes/LaneLifecycleStore';

const SESSION_TABLE = 'linked_device_sessions';
const ENROLLMENT_TABLE = 'lane_enrollments';
const TARGET_CREDENTIAL_TABLE = 'linked_device_target_credentials';

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
}

export type D1LinkedDeviceManagementStoreOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly sessionService: Pick<LinkedDeviceSessionServiceV1, 'getSessionV1'>;
  readonly nowV1: () => number;
  readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
};

export class D1LinkedDeviceManagementStoreV1 implements LinkedDeviceManagementProjectionPortV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly sessionService: Pick<LinkedDeviceSessionServiceV1, 'getSessionV1'>;
  private readonly nowV1: () => number;
  private readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
  private readonly lanes: CloudflareD1LaneLifecycleStore;

  constructor(options: D1LinkedDeviceManagementStoreOptionsV1) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
    this.sessionService = options.sessionService;
    this.nowV1 = options.nowV1;
    this.metadata = options.metadata;
    const laneScope: CloudflareD1LaneScopeV1 = {
      namespace: this.scope.namespace,
      orgId: this.scope.orgId,
      projectId: this.scope.projectId,
      envId: this.scope.envId,
    };
    this.lanes = new CloudflareD1LaneLifecycleStore({
      database: this.database,
      scope: laneScope,
    });
  }

  async listLinkedDevicesV1(walletId: WalletId): Promise<readonly LinkedDeviceSummaryV1[]> {
    const sessions = await this.readClaimedSessionsV1();
    const summaries: LinkedDeviceSummaryV1[] = [];
    for (const session of sessions) {
      const target = await this.projectSessionV1(session);
      if (!target || target.summary.walletId !== walletId) continue;
      summaries.push(target.summary);
    }
    return summaries.sort(compareSummaries);
  }

  async getLinkedDeviceV1(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<LinkedDeviceManagementTargetV1 | null> {
    const sessions = await this.readClaimedSessionsV1();
    for (const session of sessions) {
      const target = await this.projectSessionV1(session);
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

  private async readClaimedSessionsV1(): Promise<readonly LinkedDeviceSessionRecordV1[]> {
    const rows = await queryD1All(
      this.database,
      `SELECT link_session_id
         FROM ${SESSION_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
        ORDER BY updated_at_ms DESC, link_session_id ASC`,
      scopeValues(this.scope),
    );
    const records: LinkedDeviceSessionRecordV1[] = [];
    for (const row of rows) {
      const sessionId = parseRequiredSessionId(field(row, 'link_session_id'));
      const session = await this.sessionService.getSessionV1({
        linkSessionId: sessionId,
        nowMs: this.nowV1(),
      });
      if (!session || !session.claimTranscript || !session.approvalTranscript) continue;
      records.push(session);
    }
    return records;
  }

  private async projectSessionV1(
    session: LinkedDeviceSessionRecordV1,
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
    const enrollment = await this.lanes.getEnrollment(laneEnrollmentId);
    if (!enrollment) return null;
    const manifestDigest = parseDigestB64u(
      await computeLaneEnrollmentManifestDigestV1(enrollment.value.manifest),
    );
    await this.assertEnrollmentColumnsV1(laneEnrollmentId, manifestDigest, enrollment);
    assertManifestMatchesIdentity(
      enrollment.value.manifest,
      claim.walletId,
      laneEnrollmentId,
      claim.enrollmentId,
    );
    const products = await this.lanes.listEnrollmentProductEpochs(laneEnrollmentId);
    assertProductsMatchManifest(products, enrollment.value.manifest);
    const metadata = await this.metadata.readLinkedDeviceMetadataV1({
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
    });
    if (!metadata) return null;
    const normalizedMetadata = parseMetadata(metadata);
    const enrollmentUpdatedAtMs = await this.readEnrollmentUpdatedAtMsV1(laneEnrollmentId);
    const lastActivityAtMs = Math.max(
      session.updatedAtMs,
      enrollmentUpdatedAtMs,
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

  private async assertEnrollmentColumnsV1(
    enrollmentId: LaneEnrollmentId,
    manifestDigestB64u: DigestB64u,
    enrollment: LaneEnrollmentAdmissionRecord,
  ): Promise<void> {
    const row = await queryD1One(
      this.database,
      `SELECT manifest_digest_b64u
         FROM ${ENROLLMENT_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND enrollment_id = ?5`,
      [...scopeValues(this.scope), String(enrollmentId)],
    );
    const stored = requiredString(
      field(row, 'manifest_digest_b64u'),
      'lane enrollment manifest_digest_b64u',
    );
    if (
      stored !== manifestDigestB64u ||
      String(enrollment.value.manifest.enrollmentId) !== String(enrollmentId)
    ) {
      throw new Error('lane enrollment manifest digest does not match its columns');
    }
  }

  private async readEnrollmentUpdatedAtMsV1(enrollmentId: LaneEnrollmentId): Promise<number> {
    const row = await queryD1One(
      this.database,
      `SELECT updated_at_ms
         FROM ${ENROLLMENT_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND enrollment_id = ?5`,
      [...scopeValues(this.scope), String(enrollmentId)],
    );
    return requiredTimestamp(field(row, 'updated_at_ms'), 'lane enrollment updated_at_ms');
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

function requiredScopeString(value: string, field: string): string {
  if (typeof value !== 'string' || !value.trim() || value.trim() !== value) {
    throw new Error(`linked-device management ${field} is invalid`);
  }
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function parseRequiredSessionId(raw: unknown): LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(raw);
  if (!parsed.ok) throw new Error('linked-device management session id is invalid');
  return parsed.value;
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
): void {
  if (products.length !== manifest.orderedChildren.length) {
    throw new Error('lane enrollment products do not match the manifest count');
  }
  const byOperation = new Map(products.map((product) => [String(product.operationId), product]));
  if (byOperation.size !== products.length)
    throw new Error('lane enrollment products are duplicated');
  for (const child of manifest.orderedChildren) {
    const product = byOperation.get(String(child.operationId));
    if (
      !product ||
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

function compareSummaries(left: LinkedDeviceSummaryV1, right: LinkedDeviceSummaryV1): number {
  if (left.createdAtMs !== right.createdAtMs) return left.createdAtMs - right.createdAtMs;
  return String(left.deviceId).localeCompare(String(right.deviceId));
}
