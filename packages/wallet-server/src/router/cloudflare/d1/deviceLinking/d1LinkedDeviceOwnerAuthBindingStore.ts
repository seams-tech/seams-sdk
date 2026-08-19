import {
  linkedOwnerAuthMethodIdV1,
  parseLinkedDeviceOwnerAuthBindingV1,
  type LinkedDeviceOwnerAuthBindingV1,
} from '@shared/device-linking/ownerAuthBinding';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import { queryD1All, queryD1One } from '../../../../storage/d1Sql';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';

const BINDING_TABLE = 'linked_device_owner_auth_bindings';

/**
 * Writing the binding is the act that makes Device 2 an owner credential, so
 * it can never be a second round-trip after activation: a crash between the
 * two would leave a wallet auth method no device owns, or a device pointing at
 * nothing. Callers hand their own activation statements in and this store
 * appends the binding insert to the same D1 batch.
 */
export type LinkedDeviceOwnerAuthBindingWriteV1 = {
  readonly binding: LinkedDeviceOwnerAuthBindingV1;
  readonly statement: D1PreparedStatementLike;
};

/**
 * The write half alone. The wallet auth-method service depends on this rather
 * than the whole port so it cannot accidentally read bindings during a
 * finalize — it only ever appends one insert to its own batch.
 */
export type LinkedDeviceOwnerAuthBindingWriterV1 = {
  readonly buildInsertV1: (
    binding: LinkedDeviceOwnerAuthBindingV1,
  ) => LinkedDeviceOwnerAuthBindingWriteV1;
};

export type LinkedDeviceOwnerAuthBindingPortV1 = {
  readonly buildInsertV1: (
    binding: LinkedDeviceOwnerAuthBindingV1,
  ) => LinkedDeviceOwnerAuthBindingWriteV1;
  readonly buildLifecycleUpdateV1: (
    binding: LinkedDeviceOwnerAuthBindingV1,
    expectedRevocationEpoch: number,
  ) => LinkedDeviceOwnerAuthBindingWriteV1;
  readonly readByEnrollmentV1: (input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
  }) => Promise<LinkedDeviceOwnerAuthBindingV1 | null>;
  readonly readByDeviceV1: (input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
  }) => Promise<LinkedDeviceOwnerAuthBindingV1 | null>;
  readonly readByAuthMethodV1: (input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }) => Promise<LinkedDeviceOwnerAuthBindingV1 | null>;
  readonly readBatchForWalletV1: (
    walletId: WalletId,
  ) => Promise<ReadonlyMap<string, LinkedDeviceOwnerAuthBindingV1>>;
};

export type LinkedDeviceOwnerAuthBindingPageCursorV1 = {
  readonly updatedAtMs: number;
  readonly deviceId: LinkedDeviceId;
};

export type LinkedDeviceOwnerAuthBindingPageV1 = {
  readonly records: readonly LinkedDeviceOwnerAuthBindingV1[];
  readonly nextCursor: LinkedDeviceOwnerAuthBindingPageCursorV1 | null;
};

export class D1LinkedDeviceOwnerAuthBindingStoreV1 implements LinkedDeviceOwnerAuthBindingPortV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;

  constructor(options: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
  }) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
  }

  buildInsertV1(binding: LinkedDeviceOwnerAuthBindingV1): LinkedDeviceOwnerAuthBindingWriteV1 {
    assertBindingIsSelfConsistent(binding);
    const columns = bindingColumns(binding);
    return {
      binding,
      statement: this.database
        .prepare(
          `INSERT INTO ${BINDING_TABLE} (
             namespace, org_id, project_id, env_id,
             tenant_id, wallet_id, enrollment_id, device_id,
             wallet_auth_method_id, factor_kind,
             rp_id, credential_id_b64u, email_hash_hex, registration_authority_id,
             key_manifest_digest_b64u, lifecycle_state, revocation_epoch,
             record_json, created_at_ms, updated_at_ms
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)`,
        )
        .bind(
          ...scopeValues(this.scope),
          columns.tenantId,
          columns.walletId,
          columns.enrollmentId,
          columns.deviceId,
          columns.walletAuthMethodId,
          columns.factorKind,
          columns.rpId,
          columns.credentialIdB64u,
          columns.emailHashHex,
          columns.registrationAuthorityId,
          columns.keyManifestDigestB64u,
          columns.lifecycleState,
          columns.revocationEpoch,
          columns.recordJson,
          columns.createdAtMs,
          columns.updatedAtMs,
        ),
    };
  }

  /**
   * Lifecycle writes are compare-and-set on the revocation epoch. Two
   * concurrent revocations must not both advance it, and a resume must not
   * overwrite a revocation that landed first.
   */
  buildLifecycleUpdateV1(
    binding: LinkedDeviceOwnerAuthBindingV1,
    expectedRevocationEpoch: number,
  ): LinkedDeviceOwnerAuthBindingWriteV1 {
    assertBindingIsSelfConsistent(binding);
    if (!Number.isSafeInteger(expectedRevocationEpoch) || expectedRevocationEpoch < 0) {
      throw new Error('linked-device owner auth binding expected revocation epoch is invalid');
    }
    const columns = bindingColumns(binding);
    return {
      binding,
      statement: this.database
        .prepare(
          `UPDATE ${BINDING_TABLE}
              SET lifecycle_state = ?6,
                  revocation_epoch = ?7,
                  record_json = ?8,
                  updated_at_ms = ?9
            WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
              AND enrollment_id = ?5
              AND wallet_id = ?10
              AND device_id = ?11
              AND wallet_auth_method_id = ?12
              AND revocation_epoch = ?13`,
        )
        .bind(
          ...scopeValues(this.scope),
          columns.enrollmentId,
          columns.lifecycleState,
          columns.revocationEpoch,
          columns.recordJson,
          columns.updatedAtMs,
          columns.walletId,
          columns.deviceId,
          columns.walletAuthMethodId,
          expectedRevocationEpoch,
        ),
    };
  }

  async readByEnrollmentV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
  }): Promise<LinkedDeviceOwnerAuthBindingV1 | null> {
    const row = await queryD1One(
      this.database,
      `SELECT wallet_id, device_id, wallet_auth_method_id, record_json
         FROM ${BINDING_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_id = ?5 AND enrollment_id = ?6
        LIMIT 1`,
      [...scopeValues(this.scope), String(input.walletId), String(input.enrollmentId)],
    );
    return row ? parseBindingRow(row) : null;
  }

  async readByDeviceV1(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<LinkedDeviceOwnerAuthBindingV1 | null> {
    const row = await queryD1One(
      this.database,
      `SELECT wallet_id, device_id, wallet_auth_method_id, record_json
         FROM ${BINDING_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_id = ?5 AND device_id = ?6
        LIMIT 1`,
      [...scopeValues(this.scope), String(input.walletId), String(input.deviceId)],
    );
    return row ? parseBindingRow(row) : null;
  }

  async readByAuthMethodV1(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<LinkedDeviceOwnerAuthBindingV1 | null> {
    const row = await queryD1One(
      this.database,
      `SELECT wallet_id, device_id, wallet_auth_method_id, record_json
         FROM ${BINDING_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_id = ?5 AND wallet_auth_method_id = ?6
        LIMIT 1`,
      [...scopeValues(this.scope), String(input.walletId), String(input.walletAuthMethodId)],
    );
    return row ? parseBindingRow(row) : null;
  }

  /** Keyed by device id: the list path renders one card per device. */
  async readBatchForWalletV1(
    walletId: WalletId,
  ): Promise<ReadonlyMap<string, LinkedDeviceOwnerAuthBindingV1>> {
    const rows = await queryD1All(
      this.database,
      `SELECT wallet_id, device_id, wallet_auth_method_id, record_json
         FROM ${BINDING_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND wallet_id = ?5`,
      [...scopeValues(this.scope), String(walletId)],
    );
    const bindings = new Map<string, LinkedDeviceOwnerAuthBindingV1>();
    for (const row of rows) {
      const binding = parseBindingRow(row);
      const key = String(binding.deviceId);
      if (bindings.has(key)) {
        throw new Error('linked-device owner auth binding is duplicated for one device');
      }
      bindings.set(key, binding);
    }
    return bindings;
  }

  async listPageForWalletV1(input: {
    readonly walletId: WalletId;
    readonly limit: number;
    readonly cursor: LinkedDeviceOwnerAuthBindingPageCursorV1 | null;
  }): Promise<LinkedDeviceOwnerAuthBindingPageV1> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1) {
      throw new Error('linked-device owner auth binding page limit is invalid');
    }
    const rows =
      input.cursor === null
        ? await queryD1All(
            this.database,
            `SELECT wallet_id, device_id, wallet_auth_method_id, record_json, updated_at_ms
               FROM ${BINDING_TABLE}
              WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
                AND wallet_id = ?5
              ORDER BY updated_at_ms DESC, device_id ASC
              LIMIT ?6`,
            [...scopeValues(this.scope), String(input.walletId), input.limit + 1],
          )
        : await queryD1All(
            this.database,
            `SELECT wallet_id, device_id, wallet_auth_method_id, record_json, updated_at_ms
               FROM ${BINDING_TABLE}
              WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
                AND wallet_id = ?5
                AND (updated_at_ms < ?6 OR (updated_at_ms = ?6 AND device_id > ?7))
              ORDER BY updated_at_ms DESC, device_id ASC
              LIMIT ?8`,
            [
              ...scopeValues(this.scope),
              String(input.walletId),
              input.cursor.updatedAtMs,
              String(input.cursor.deviceId),
              input.limit + 1,
            ],
          );
    const hasNextPage = rows.length > input.limit;
    const pageRows = hasNextPage ? rows.slice(0, input.limit) : rows;
    const records: LinkedDeviceOwnerAuthBindingV1[] = [];
    const seenDevices = new Set<string>();
    for (const row of pageRows) {
      const binding = parseBindingRow(row);
      const updatedAtMs = requiredIntegerColumn(row, 'updated_at_ms');
      if (binding.updatedAtMs !== updatedAtMs) {
        throw new Error('linked-device owner auth binding row timestamp disagrees with its record');
      }
      const deviceId = String(binding.deviceId);
      if (seenDevices.has(deviceId)) {
        throw new Error('linked-device owner auth binding page contains a duplicate device');
      }
      seenDevices.add(deviceId);
      records.push(binding);
    }
    const last = records.at(-1);
    return {
      records,
      nextCursor:
        hasNextPage && last ? { updatedAtMs: last.updatedAtMs, deviceId: last.deviceId } : null,
    };
  }
}

/** Fails the whole batch when any statement did not apply. */
export function assertOwnerAuthBindingBatchApplied(
  results: readonly D1ResultLike[],
  expected: number,
): void {
  if (results.length !== expected) {
    throw new Error('linked-device owner auth binding batch returned an unexpected result count');
  }
  for (const result of results) {
    if (!result.success) {
      throw new Error('linked-device owner auth binding batch did not apply');
    }
  }
}

type BindingColumnsV1 = {
  readonly tenantId: string;
  readonly walletId: string;
  readonly enrollmentId: string;
  readonly deviceId: string;
  readonly walletAuthMethodId: string;
  readonly factorKind: 'passkey' | 'email_otp';
  readonly rpId: string | null;
  readonly credentialIdB64u: string | null;
  readonly emailHashHex: string | null;
  readonly registrationAuthorityId: string | null;
  readonly keyManifestDigestB64u: string;
  readonly lifecycleState: LinkedDeviceOwnerAuthBindingV1['lifecycle']['state'];
  readonly revocationEpoch: number;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

function bindingColumns(binding: LinkedDeviceOwnerAuthBindingV1): BindingColumnsV1 {
  const factor = binding.factor;
  const identity =
    factor.kind === 'passkey'
      ? {
          factorKind: 'passkey' as const,
          rpId: String(factor.rpId),
          credentialIdB64u: String(factor.credentialIdB64u),
          emailHashHex: null,
          registrationAuthorityId: null,
        }
      : {
          factorKind: 'email_otp' as const,
          rpId: null,
          credentialIdB64u: null,
          emailHashHex: factor.emailHashHex,
          registrationAuthorityId: factor.registrationAuthorityId,
        };
  return {
    tenantId: String(binding.tenantId),
    walletId: String(binding.walletId),
    enrollmentId: String(binding.enrollmentId),
    deviceId: String(binding.deviceId),
    walletAuthMethodId: String(binding.walletAuthMethodId),
    factorKind: identity.factorKind,
    rpId: identity.rpId,
    credentialIdB64u: identity.credentialIdB64u,
    emailHashHex: identity.emailHashHex,
    registrationAuthorityId: identity.registrationAuthorityId,
    keyManifestDigestB64u: String(binding.keyManifestDigestB64u),
    lifecycleState: binding.lifecycle.state,
    revocationEpoch: binding.revocationEpoch,
    recordJson: JSON.stringify(binding),
    createdAtMs: binding.createdAtMs,
    updatedAtMs: binding.updatedAtMs,
  };
}

/**
 * The parser already re-derives the auth-method id from the factor. This
 * repeats the check against the indexed columns so a row whose JSON was
 * replaced wholesale — leaving the columns the unique indexes see intact —
 * still fails closed rather than resolving to another credential.
 */
function parseBindingRow(row: Record<string, unknown>): LinkedDeviceOwnerAuthBindingV1 {
  const binding = parseLinkedDeviceOwnerAuthBindingV1(
    JSON.parse(requiredColumn(row, 'record_json')),
  );
  if (
    String(binding.walletId) !== requiredColumn(row, 'wallet_id') ||
    String(binding.deviceId) !== requiredColumn(row, 'device_id') ||
    String(binding.walletAuthMethodId) !== requiredColumn(row, 'wallet_auth_method_id')
  ) {
    throw new Error('linked-device owner auth binding row disagrees with its record');
  }
  return binding;
}

function assertBindingIsSelfConsistent(binding: LinkedDeviceOwnerAuthBindingV1): void {
  const derived = linkedOwnerAuthMethodIdV1({
    walletId: binding.walletId,
    factor: binding.factor,
  });
  if (binding.walletAuthMethodId !== derived) {
    throw new Error('linked-device owner auth binding auth-method id does not match its factor');
  }
}

function requiredColumn(row: Record<string, unknown>, name: string): string {
  const value = row[name];
  if (typeof value !== 'string' || !value) {
    throw new Error(`linked-device owner auth binding row is missing ${name}`);
  }
  return value;
}

function requiredIntegerColumn(row: Record<string, unknown>, name: string): number {
  const value = typeof row[name] === 'number' ? row[name] : Number(row[name]);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`linked-device owner auth binding row ${name} is invalid`);
  }
  return value;
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
    throw new Error(`linked-device owner auth binding ${field} is invalid`);
  }
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}
