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
  LinkedDeviceManagementListCursorV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import { encodeLinkedDeviceListCursorV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type {
  LinkedDeviceListResultV1,
  LinkedOwnerCredentialMetadataV1,
  LinkedDeviceSummaryV1,
  OwnerDeviceSummaryV1,
} from '@shared/device-linking/contracts';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { D1LinkedDeviceOwnerAuthBindingStoreV1 } from './d1LinkedDeviceOwnerAuthBindingStore';
import type { LinkedDeviceOwnerAuthBindingV1 } from '@shared/device-linking/ownerAuthBinding';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
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
  /**
   * Active owner passkeys that never enrolled through device linking: the
   * wallet's founding device(s). They have no link session, so the session
   * projection can never surface them; management lists them alongside the
   * linked enrollments.
   */
  readonly listUnlinkedOwnerDeviceSummariesV1: (input: {
    readonly walletId: WalletId;
  }) => Promise<readonly OwnerDeviceSummaryV1[]>;
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
      if (!binding) continue;
      assertBindingMatchesIdentity(binding, identity, this.tenantId);
      const key = metadataKey(identity);
      if (selectedBindings.has(key)) {
        throw new Error('linked-device owner auth binding identity is duplicated');
      }
      selectedBindings.set(key, binding);
    }

    if (selectedBindings.size === 0) return new Map();

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
      if (!binding) continue;
      const authMethod = authMethods.get(String(binding.walletAuthMethodId));
      if (!authMethod) throw new Error('linked-device canonical auth method is missing');
      result.set(
        metadataKey(identity),
        buildCanonicalMetadataV1({ binding, authMethod, authenticators }),
      );
    }
    return result;
  }

  async listUnlinkedOwnerDeviceSummariesV1(input: {
    readonly walletId: WalletId;
  }): Promise<readonly OwnerDeviceSummaryV1[]> {
    const walletId = String(input.walletId);
    const bindings = await this.bindings.readBatchForWalletV1(input.walletId);
    const linkedAuthMethodIds = new Set(
      [...bindings.values()].map((binding) => String(binding.walletAuthMethodId)),
    );
    const rows = await queryD1All(
      this.database,
      `SELECT wallet_id, wallet_auth_method_id, record_json
         FROM ${WALLET_AUTH_METHOD_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_id = ?5`,
      [...scopeValues(this.scope), walletId],
    );
    const ownerPasskeys: Extract<WalletAuthMethodRecord, { kind: 'passkey' }>[] = [];
    for (const row of rows) {
      const authMethodId = requiredString(
        field(row, 'wallet_auth_method_id'),
        'wallet_auth_method_id',
      );
      const authMethod = normalizeWalletAuthMethod(parseD1JsonColumn(field(row, 'record_json')));
      if (!authMethod || String(authMethod.walletId) !== walletId) {
        throw new Error('owner device auth method is invalid');
      }
      if (String(walletAuthMethodRecordId(authMethod)) !== authMethodId) {
        throw new Error('owner device auth method identity changed');
      }
      if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') continue;
      if (linkedAuthMethodIds.has(authMethodId)) continue;
      ownerPasskeys.push(authMethod);
    }
    if (ownerPasskeys.length === 0) return [];
    const authenticators = await this.readCanonicalAuthenticatorsV1({
      walletId,
      credentialIds: ownerPasskeys.map((authMethod) => authMethod.credentialIdB64u),
    });
    const summaries: OwnerDeviceSummaryV1[] = [];
    for (const authMethod of ownerPasskeys) {
      const authenticator = authenticators.get(authMethod.credentialIdB64u);
      if (!authenticator) {
        throw new Error('owner device canonical passkey authenticator is missing');
      }
      summaries.push({
        walletId: authMethod.walletId,
        credential: {
          kind: 'passkey',
          walletAuthMethodId: walletAuthMethodRecordId(authMethod),
          credentialIdB64u: requireParsedCredentialId(authMethod.credentialIdB64u),
          device: authenticator.deviceInfo,
        },
        createdAtMs: authMethod.createdAtMs,
        lastActivityAtMs: Math.max(authMethod.updatedAtMs, authenticator.updatedAtMs),
      });
    }
    return summaries.sort(
      (left, right) =>
        left.createdAtMs - right.createdAtMs ||
        String(left.credential.credentialIdB64u).localeCompare(
          String(right.credential.credentialIdB64u),
        ),
    );
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
  readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
};

type LinkedDeviceManagementIdentityV1 = {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
};

export class D1LinkedDeviceManagementStoreV1 implements LinkedDeviceManagementProjectionPortV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
  private readonly signingActivity: D1LinkedDeviceSigningActivitySourceV1;
  private readonly ownerAuthBindings: D1LinkedDeviceOwnerAuthBindingStoreV1;

  constructor(options: D1LinkedDeviceManagementStoreOptionsV1) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
    this.metadata = options.metadata;
    this.signingActivity = new D1LinkedDeviceSigningActivitySourceV1({
      database: this.database,
      scope: this.scope,
    });
    this.ownerAuthBindings = new D1LinkedDeviceOwnerAuthBindingStoreV1({
      database: this.database,
      scope: this.scope,
    });
  }

  async listLinkedDevicesV1(input: {
    readonly walletId: WalletId;
    readonly limit: number;
    readonly cursor: LinkedDeviceManagementListCursorV1 | null;
  }): Promise<LinkedDeviceListResultV1> {
    const bindings = await this.ownerAuthBindings.listPageForWalletV1({
      walletId: input.walletId,
      limit: input.limit,
      cursor: input.cursor
        ? {
            updatedAtMs: input.cursor.updatedAtMs,
            deviceId: input.cursor.deviceId,
          }
        : null,
    });
    const summaries: LinkedDeviceSummaryV1[] = [];
    for (const binding of bindings.records) {
      const target = await this.projectBindingTargetV1(binding);
      summaries.push(target.summary);
    }
    // Founding owner devices ride the first page only; later pages would
    // otherwise repeat them under every cursor.
    const ownerDevices =
      input.cursor === null
        ? await this.metadata.listUnlinkedOwnerDeviceSummariesV1({ walletId: input.walletId })
        : [];
    return {
      devices: summaries,
      ownerDevices,
      nextCursor: bindings.nextCursor
        ? encodeLinkedDeviceListCursorV1({
            kind: 'owner_binding_v1',
            updatedAtMs: bindings.nextCursor.updatedAtMs,
            deviceId: bindings.nextCursor.deviceId,
          })
        : null,
    };
  }

  /** Projects one device from the durable owner binding and lane inventory. */
  private async projectBindingTargetV1(
    binding: LinkedDeviceOwnerAuthBindingV1,
  ): Promise<LinkedDeviceManagementTargetV1> {
    if (String(binding.walletId).trim().length === 0) {
      throw new Error('linked-device owner auth binding wallet is missing');
    }
    const laneEnrollmentId = parseRequiredLaneEnrollmentId(String(binding.enrollmentId));
    const enrollmentRow = await queryD1One(
      this.database,
      `SELECT enrollment_id, wallet_id, manifest_digest_b64u, manifest_json,
              lifecycle_json, version, command_digest_b64u, created_at_ms, updated_at_ms
         FROM ${ENROLLMENT_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND enrollment_id = ?5`,
      [...scopeValues(this.scope), String(laneEnrollmentId)],
    );
    if (!enrollmentRow) {
      throw new Error('linked-device owner binding enrollment is missing; re-link is required');
    }
    const parsed = parseEnrollmentRow(enrollmentRow);
    if (
      parsed.walletId !== String(binding.walletId) ||
      parsed.enrollmentId !== String(laneEnrollmentId)
    ) {
      throw new Error('linked-device owner binding enrollment identity is invalid');
    }
    assertManifestMatchesIdentity(
      parsed.manifest,
      binding.walletId,
      laneEnrollmentId,
      binding.enrollmentId,
    );
    const manifestDigestB64u = parseDigestB64u(
      await computeLaneEnrollmentManifestDigestV1(parsed.manifest),
    );
    if (
      parsed.manifestDigestB64u !== manifestDigestB64u ||
      String(binding.keyManifestDigestB64u) !== manifestDigestB64u
    ) {
      throw new Error('linked-device owner binding manifest digest disagrees with its enrollment');
    }
    const productRows = await queryD1All(
      this.database,
      `SELECT enrollment_id, product_json
         FROM lane_product_epochs
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND enrollment_id = ?5`,
      [...scopeValues(this.scope), String(laneEnrollmentId)],
    );
    const products: LaneProductEpochRecordV1[] = [];
    for (const row of productRows) products.push(parseProductEpochRow(row));
    assertProductsMatchManifest(products, parsed.manifest, parsed.lifecycle, manifestDigestB64u);
    if (products.length !== parsed.manifest.orderedChildren.length) {
      throw new Error('linked-device owner binding lane product coverage is incomplete');
    }
    const revocationEpoch = requireUniformProductRevocationEpochV1(products);
    if (binding.revocationEpoch !== revocationEpoch) {
      throw new Error(
        'linked-device owner binding revocation epoch disagrees with its lane products',
      );
    }
    const enrollment: LaneEnrollmentAdmissionRecord = {
      version: parsed.version,
      commandDigestB64u: parsed.commandDigestB64u,
      value: { manifest: parsed.manifest, lifecycle: parsed.lifecycle },
    };
    const credential = await this.metadata.readLinkedDeviceMetadataV1({
      walletId: binding.walletId,
      enrollmentId: binding.enrollmentId,
      deviceId: binding.deviceId,
    });
    if (!credential) {
      throw new Error(
        'linked-device owner binding canonical credential metadata is missing; re-link is required',
      );
    }
    const signingActivityAtMs = await this.signingActivity.readLastSigningActivityAtMsV1({
      walletId: binding.walletId,
      enrollmentId: binding.enrollmentId,
      deviceId: binding.deviceId,
    });
    const summary: LinkedDeviceSummaryV1 = {
      deviceId: binding.deviceId,
      enrollmentId: binding.enrollmentId,
      walletId: binding.walletId,
      credential,
      permission: LINKED_OWNER_EXECUTION_PERMISSION_V1,
      keyManifestDigestB64u: manifestDigestB64u,
      coveredWalletKeys: parsed.manifest.orderedChildren.map((child) => child.walletKeyId),
      state: projectBindingState(binding, parsed.lifecycle),
      createdAtMs: binding.createdAtMs,
      lastActivityAtMs: Math.max(
        binding.updatedAtMs,
        parsed.updatedAtMs,
        signingActivityAtMs ?? 0,
        ...products.map(productActivityAtMs),
      ),
      revocationEpoch,
    };
    return { summary, enrollment, products };
  }

  async getLinkedDeviceV1(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<LinkedDeviceManagementTargetV1 | null> {
    const binding = await this.ownerAuthBindings.readByDeviceV1({
      walletId: input.walletId,
      deviceId: input.deviceId,
    });
    if (!binding) return null;
    return await this.projectBindingTargetV1(binding);
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

function requireParsedCredentialId(raw: string) {
  const parsed = parseWebAuthnCredentialIdB64u(raw);
  if (!parsed.ok) throw new Error('owner device credential id is invalid');
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
  manifestDigestB64u: DigestB64u,
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
    if (
      (product.state === 'pending_visibility' || product.state === 'active') &&
      product.aggregateManifestDigestB64u !== manifestDigestB64u
    ) {
      throw new Error('lane enrollment product manifest digest is invalid');
    }
    if (
      lifecycle.state === 'active' &&
      (product.state !== 'active' ||
        product.aggregateActivationReceiptDigestB64u !== lifecycle.aggregateReceiptDigestB64u)
    ) {
      throw new Error('active lane enrollment product activation receipt is invalid');
    }
    if (lifecycle.state === 'ready_for_visibility' && product.state !== 'pending_visibility') {
      throw new Error('ready lane enrollment product visibility state is invalid');
    }
    if (lifecycle.state === 'revoked' && product.state !== 'revoked') {
      throw new Error('revoked lane enrollment has a live product');
    }
  }
}

function requireUniformProductRevocationEpochV1(
  products: readonly LaneProductEpochRecordV1[],
): number {
  const first = products[0];
  if (!first) throw new Error('linked-device owner binding has no lane products');
  if (products.some((product) => product.revocationEpoch !== first.revocationEpoch)) {
    throw new Error('linked-device owner binding lane product revocation epochs disagree');
  }
  return first.revocationEpoch;
}

/**
 * R103C Phase 4: a device whose link-session workflow history has expired or
 * been pruned is still a device. Its state comes from the durable owner
 * binding and lane-enrollment lifecycle alone.
 */
function projectBindingState(
  binding: LinkedDeviceOwnerAuthBindingV1,
  lifecycle: LaneEnrollmentAdmissionRecord['value']['lifecycle'],
): LinkedDeviceSummaryV1['state'] {
  if (binding.lifecycle.state === 'revoked' || lifecycle.state === 'revoked') return 'revoked';
  if (binding.lifecycle.state === 'paused' || lifecycle.state === 'revoking_committed_targets') {
    return 'suspended';
  }
  return lifecycle.state === 'active' ? 'active' : 'provisioning';
}

/** The narrow linked execution grant every Phase 8 linked owner holds. */
const LINKED_OWNER_EXECUTION_PERMISSION_V1: LinkedDeviceSummaryV1['permission'] = {
  kind: 'owner_equivalent_signing',
  administrationScope: 'signing_only',
  localUserPresence: 'required',
};

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
