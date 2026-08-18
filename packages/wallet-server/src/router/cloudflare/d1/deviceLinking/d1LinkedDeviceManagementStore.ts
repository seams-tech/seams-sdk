import type {
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LaneEnrollmentId,
} from '@shared/signing-lanes/ids';
import { parseLaneEnrollmentId } from '@shared/signing-lanes/ids';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import type { LaneEnrollmentManifestV1, LaneProductEpochRecordV1 } from '@shared/signing-lanes';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import type { WalletId } from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  walletAuthMethodRecordId,
  type WalletAuthMethodRecord,
} from '@shared/utils/registrationIntent';
import { normalizeWalletAuthMethod } from '../../../../core/d1WalletAuthMethodStore';
import { parseWebAuthnAuthenticator, type D1AuthenticatorRow } from '../webauthn/d1WebAuthnRecords';
import { parseD1JsonColumn, queryD1All, queryD1One } from '../../../../storage/d1Sql';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type {
  LinkedDeviceManagementProjectionPortV1,
  LinkedDeviceManagementTargetV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import { encodeLinkedDeviceListCursorV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type {
  LinkedDeviceListResultV1,
  LinkedOwnerCredentialMetadataV1,
  LinkedDeviceSummaryV1,
} from '@shared/device-linking/contracts';
import { D1LinkedDeviceOwnerAuthBindingStoreV1 } from './d1LinkedDeviceOwnerAuthBindingStore';
import type { LinkedDeviceOwnerAuthBindingV1 } from '@shared/device-linking/ownerAuthBinding';
import type {
  LinkedDeviceSessionRecordV1,
  LinkedDeviceSessionListCursorV1,
  LinkedDeviceSessionListPageV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import type { LinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LaneEnrollmentAdmissionRecord } from '../../../../core/signingLanes/LaneLifecycleStore';
import { parseEnrollmentRow, parseProductEpochRow } from '../signingLanes/d1LaneRecords';

const ENROLLMENT_TABLE = 'lane_enrollments';
const WALLET_AUTH_METHOD_TABLE = 'wallet_auth_methods';
const WEBAUTHN_AUTHENTICATOR_TABLE = 'webauthn_authenticators';
const AUTHORIZATION_AUDIT_TABLE = 'authorized_operation_audit_events';

export type D1LinkedDeviceManagementMetadataV1 = LinkedOwnerCredentialMetadataV1;

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

export class D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1 implements D1LinkedDeviceManagementMetadataPortV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly tenantId: TenantId;
  private readonly bindings: D1LinkedDeviceOwnerAuthBindingStoreV1;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
    readonly tenantId: TenantId;
  }) {
    this.database = input.database;
    this.scope = normalizeScope(input.scope);
    this.tenantId = input.tenantId;
    this.bindings = new D1LinkedDeviceOwnerAuthBindingStoreV1({
      database: this.database,
      scope: this.scope,
    });
  }

  async readLinkedDeviceMetadataV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<D1LinkedDeviceManagementMetadataV1 | null> {
    const metadata = await this.readLinkedDeviceMetadataBatchV1([input]);
    return metadata.get(metadataKey(input)) ?? null;
  }

  async readLinkedDeviceMetadataBatchV1(
    inputs: ReadonlyArray<{
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
    }>,
  ): Promise<ReadonlyMap<string, D1LinkedDeviceManagementMetadataV1>> {
    if (inputs.length === 0) return new Map();
    const identities = uniqueMetadataIdentities(inputs);
    const walletIds = [...new Set(identities.map((item) => String(item.walletId)))];
    if (walletIds.length !== 1) {
      throw new Error('linked-device metadata batch must be wallet-scoped');
    }
    const walletId = walletIds[0];
    const firstIdentity = identities[0];
    if (!walletId || !firstIdentity) {
      throw new Error('linked-device metadata batch wallet is missing');
    }
    const bindings = await this.bindings.readBatchForWalletV1(firstIdentity.walletId);
    const selectedBindings = new Map<string, LinkedDeviceOwnerAuthBindingV1>();
    for (const identity of identities) {
      const binding = bindings.get(String(identity.deviceId));
      if (!binding) throw new Error('linked-device owner auth binding is missing');
      assertBindingMatchesIdentity(binding, identity, this.tenantId);
      const key = metadataKey(identity);
      if (selectedBindings.has(key)) {
        throw new Error('linked-device owner auth binding identity is duplicated');
      }
      selectedBindings.set(key, binding);
    }

    const authMethodIds = [
      ...new Set(
        [...selectedBindings.values()].map((binding) => String(binding.walletAuthMethodId)),
      ),
    ];
    const authMethodRows = await queryD1All(
      this.database,
      `SELECT wallet_id, wallet_auth_method_id, record_json
         FROM ${WALLET_AUTH_METHOD_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_id = ?5
          AND wallet_auth_method_id IN (${authMethodIds.map((_, index) => `?${index + 6}`).join(', ')})`,
      [...scopeValues(this.scope), walletId, ...authMethodIds],
    );
    const authMethods = new Map<string, WalletAuthMethodRecord>();
    for (const row of authMethodRows) {
      const authMethodId = requiredString(
        field(row, 'wallet_auth_method_id'),
        'wallet_auth_method_id',
      );
      if (authMethods.has(authMethodId)) {
        throw new Error('linked-device canonical auth method is duplicated');
      }
      const authMethod = normalizeWalletAuthMethod(parseD1JsonColumn(field(row, 'record_json')));
      if (!authMethod || String(authMethod.walletId) !== walletId) {
        throw new Error('linked-device canonical auth method is invalid');
      }
      if (String(walletAuthMethodRecordId(authMethod)) !== authMethodId) {
        throw new Error('linked-device canonical auth method identity changed');
      }
      if (String(field(row, 'wallet_id')) !== walletId) {
        throw new Error('linked-device canonical auth method wallet changed');
      }
      authMethods.set(authMethodId, authMethod);
    }

    const credentialIds = [
      ...new Set(
        [...selectedBindings.values()].flatMap((binding) =>
          binding.factor.kind === 'passkey' ? [String(binding.factor.credentialIdB64u)] : [],
        ),
      ),
    ];
    const authenticators = await this.readCanonicalAuthenticatorsV1({ walletId, credentialIds });
    const result = new Map<string, D1LinkedDeviceManagementMetadataV1>();
    for (const identity of identities) {
      const binding = selectedBindings.get(metadataKey(identity));
      if (!binding) throw new Error('linked-device owner auth binding is missing');
      const authMethod = authMethods.get(String(binding.walletAuthMethodId));
      if (!authMethod) throw new Error('linked-device canonical auth method is missing');
      result.set(
        metadataKey(identity),
        buildCanonicalMetadataV1({ binding, authMethod, authenticators }),
      );
    }
    return result;
  }

  private async readCanonicalAuthenticatorsV1(input: {
    readonly walletId: string;
    readonly credentialIds: readonly string[];
  }): Promise<ReadonlyMap<string, ReturnType<typeof parseWebAuthnAuthenticator>>> {
    if (input.credentialIds.length === 0) return new Map();
    const rows = await queryD1All(
      this.database,
      `SELECT user_id, credential_id_b64u, credential_public_key_b64u, counter,
              created_at_ms, updated_at_ms, device_info_json
         FROM ${WEBAUTHN_AUTHENTICATOR_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND user_id = ?5
          AND credential_id_b64u IN (${input.credentialIds.map((_, index) => `?${index + 6}`).join(', ')})`,
      [...scopeValues(this.scope), input.walletId, ...input.credentialIds],
    );
    const authenticators = new Map<string, ReturnType<typeof parseWebAuthnAuthenticator>>();
    for (const row of rows) {
      const credentialId = requiredString(field(row, 'credential_id_b64u'), 'credential_id_b64u');
      if (authenticators.has(credentialId)) {
        throw new Error('linked-device canonical authenticator is duplicated');
      }
      const userId = requiredString(field(row, 'user_id'), 'user_id');
      if (userId !== input.walletId) {
        throw new Error('linked-device canonical authenticator wallet changed');
      }
      const authenticator = parseWebAuthnAuthenticator(row as D1AuthenticatorRow);
      if (!authenticator) throw new Error('linked-device canonical authenticator is invalid');
      authenticators.set(credentialId, authenticator);
    }
    return authenticators;
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
  readonly sessionService: Pick<
    LinkedDeviceSessionServiceV1,
    'getSessionV1' | 'listSessionsForWalletV1'
  >;
  readonly nowV1: () => number;
  readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
};

type ManagementProjectionContextV1 = {
  readonly enrollments: ReadonlyMap<
    string,
    {
      readonly admission: LaneEnrollmentAdmissionRecord;
      readonly manifestDigestB64u: string;
      readonly updatedAtMs: number;
    }
  >;
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
  private readonly sessionService: Pick<
    LinkedDeviceSessionServiceV1,
    'getSessionV1' | 'listSessionsForWalletV1'
  >;
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
      nextCursor: sessions.nextCursor ? encodeLinkedDeviceListCursorV1(sessions.nextCursor) : null,
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
    assertProductsMatchManifest(products, enrollment.value.manifest, enrollment.value.lifecycle);
    const credential = context.metadata.get(
      metadataKey({
        walletId: claim.walletId,
        enrollmentId: claim.enrollmentId,
        deviceId: claim.deviceId,
      }),
    );
    if (!credential) {
      throw new Error('linked-device owner auth metadata is missing');
    }
    const enrollmentUpdatedAtMs = enrollmentContext.updatedAtMs;
    const signingActivityAtMs =
      context.signingActivity.get(
        metadataKey({
          walletId: claim.walletId,
          enrollmentId: claim.enrollmentId,
          deviceId: claim.deviceId,
        }),
      ) ?? null;
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
      credential,
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
      return {
        enrollments: new Map(),
        products: new Map(),
        metadata: new Map(),
        signingActivity: new Map(),
      };
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
    const enrollments = new Map<
      string,
      {
        readonly admission: LaneEnrollmentAdmissionRecord;
        readonly manifestDigestB64u: string;
        readonly updatedAtMs: number;
      }
    >();
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

function uniqueMetadataIdentities(
  inputs: ReadonlyArray<LinkedDeviceManagementIdentityV1>,
): readonly LinkedDeviceManagementIdentityV1[] {
  const identities = new Map<string, LinkedDeviceManagementIdentityV1>();
  for (const input of inputs) {
    const key = metadataKey(input);
    if (identities.has(key)) {
      throw new Error('linked-device metadata identity is duplicated');
    }
    identities.set(key, input);
  }
  return [...identities.values()];
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

function assertBindingMatchesIdentity(
  binding: LinkedDeviceOwnerAuthBindingV1,
  identity: LinkedDeviceManagementIdentityV1,
  tenantId: TenantId,
): void {
  if (
    binding.tenantId !== tenantId ||
    binding.walletId !== identity.walletId ||
    binding.enrollmentId !== identity.enrollmentId ||
    binding.deviceId !== identity.deviceId
  ) {
    throw new Error('linked-device owner auth binding identity does not match its session');
  }
}

function buildCanonicalMetadataV1(input: {
  readonly binding: LinkedDeviceOwnerAuthBindingV1;
  readonly authMethod: WalletAuthMethodRecord;
  readonly authenticators: ReadonlyMap<string, ReturnType<typeof parseWebAuthnAuthenticator>>;
}): D1LinkedDeviceManagementMetadataV1 {
  const { binding, authMethod } = input;
  const expectedStatus = binding.lifecycle.state === 'revoked' ? 'revoked' : 'active';
  if (authMethod.status !== expectedStatus) {
    throw new Error('linked-device owner auth binding lifecycle disagrees with auth method');
  }
  if (binding.factor.kind === 'passkey') {
    if (
      authMethod.kind !== 'passkey' ||
      authMethod.walletId !== binding.walletId ||
      authMethod.rpId !== binding.factor.rpId ||
      authMethod.credentialIdB64u !== binding.factor.credentialIdB64u ||
      String(walletAuthMethodRecordId(authMethod)) !== String(binding.walletAuthMethodId)
    ) {
      throw new Error('linked-device passkey binding disagrees with canonical auth method');
    }
    const authenticator = input.authenticators.get(String(binding.factor.credentialIdB64u));
    if (!authenticator) {
      throw new Error('linked-device canonical passkey authenticator is missing');
    }
    return {
      kind: 'passkey',
      walletAuthMethodId: binding.walletAuthMethodId,
      credentialIdB64u: binding.factor.credentialIdB64u,
      device: authenticator.deviceInfo,
    };
  }
  if (
    authMethod.kind !== 'email_otp' ||
    authMethod.walletId !== binding.walletId ||
    authMethod.emailHashHex !== binding.factor.emailHashHex ||
    authMethod.registrationAuthorityId !== binding.factor.registrationAuthorityId ||
    String(walletAuthMethodRecordId(authMethod)) !== String(binding.walletAuthMethodId)
  ) {
    throw new Error('linked-device Email OTP binding disagrees with canonical auth method');
  }
  return {
    kind: 'email_otp',
    walletAuthMethodId: binding.walletAuthMethodId,
  };
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
