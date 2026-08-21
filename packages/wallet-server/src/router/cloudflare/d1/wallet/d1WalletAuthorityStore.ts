import {
  computeWalletAuthorityDigestB64u,
  buildRevokedWalletAuthorityV1,
  parseWalletAuthorityV1,
  parseWalletSignerActivationSetV1,
  walletAuthorityDigestsMatchV1,
  type ActiveWalletAuthorityV1,
  type PendingWalletAuthorityV1,
  type RevokedWalletAuthorityV1,
  type WalletSignerActivationSetV1,
  type WalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { parseDelegatedWalletPermissionSetV1 } from '@shared/authorization/delegatedAuthority';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkDeviceSessionId,
  mpcMaterialActivationRefsEqual,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletAuthorityId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  ensureWalletAuthMethodStoreD1SchemaV2,
  prepareD1WalletAuthMethodV2PutStatement,
} from '../../../../core/d1WalletAuthMethodStore';
import {
  parseWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { d1ChangedRows, formatD1ExecStatement, parseD1JsonColumn } from '../../../../storage/d1Sql';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';

export type D1WalletAuthorityStoreScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

export type WalletAuthorityPageCursorV1 = {
  readonly updatedAtMs: number;
  readonly authorityId: WalletAuthorityId;
};

export type WalletAuthorityPageV1 = {
  readonly records: readonly WalletAuthorityV1[];
  readonly nextCursor: WalletAuthorityPageCursorV1 | null;
};

export type CommittedWalletAuthorityV1 = {
  readonly kind: 'committed_wallet_authority_v1';
  readonly authority: PendingWalletAuthorityV1;
  readonly authMethod: WalletAuthMethodRecordV2;
};

export type WalletAuthorityCommitResultV1 =
  | CommittedWalletAuthorityV1
  | {
      readonly kind: 'replayed';
      readonly authority: PendingWalletAuthorityV1;
      readonly authMethod: WalletAuthMethodRecordV2;
    }
  | {
      readonly kind: 'conflict';
      readonly authorityId: WalletAuthorityId;
    };

export type WalletAuthorityActivationResultV1 =
  | {
      readonly kind: 'activated';
      readonly authority: ActiveWalletAuthorityV1;
      readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
    }
  | {
      readonly kind: 'replayed';
      readonly authority: ActiveWalletAuthorityV1;
      readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
    }
  | {
      readonly kind: 'conflict';
      readonly authorityId: WalletAuthorityId;
    };

export type WalletAuthorityRevocationResultV1 =
  | {
      readonly kind: 'revoked_method';
      readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'revoked' }>;
      readonly authority: WalletAuthorityV1;
    }
  | { readonly kind: 'would_remove_last_wallet_auth_method' }
  | { readonly kind: 'conflict' };

export const WALLET_AUTHORITY_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS wallet_authorities (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      authority_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      provenance_kind TEXT NOT NULL,
      enrollment_id TEXT,
      source_authority_id TEXT,
      link_session_id TEXT,
      lifecycle_state TEXT NOT NULL,
      permissions_json TEXT NOT NULL,
      signer_activations_json TEXT NOT NULL,
      local_install_package_set_digest_b64u TEXT,
      signer_activation_set_digest_b64u TEXT NOT NULL,
      authority_digest_b64u TEXT NOT NULL,
      revocation_epoch INTEGER NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      activated_at_ms INTEGER,
      revoked_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, project_id, env_id, authority_id),
      CHECK (length(authority_id) > 0),
      CHECK (length(wallet_id) > 0),
      CHECK (length(device_id) > 0),
      CHECK (provenance_kind IN ('wallet_registration', 'device_link')),
      CHECK (lifecycle_state IN ('pending_local_install', 'active', 'revoked')),
      CHECK (length(permissions_json) > 0 AND json_valid(permissions_json)),
      CHECK (length(signer_activations_json) > 0 AND json_valid(signer_activations_json)),
      CHECK (length(record_json) > 0 AND json_valid(record_json)),
      CHECK (length(signer_activation_set_digest_b64u) > 0),
      CHECK (length(authority_digest_b64u) > 0),
      CHECK (revocation_epoch >= 0),
      CHECK (created_at_ms >= 0),
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (
        (provenance_kind = 'wallet_registration'
          AND enrollment_id IS NULL
          AND source_authority_id IS NULL
          AND link_session_id IS NULL)
        OR
        (provenance_kind = 'device_link'
          AND enrollment_id IS NOT NULL AND length(enrollment_id) > 0
          AND source_authority_id IS NOT NULL AND length(source_authority_id) > 0
          AND link_session_id IS NOT NULL AND length(link_session_id) > 0)
      ),
      CHECK (
        (lifecycle_state = 'pending_local_install'
          AND local_install_package_set_digest_b64u IS NOT NULL
          AND length(local_install_package_set_digest_b64u) > 0
          AND activated_at_ms IS NULL
          AND revoked_at_ms IS NULL
          AND revocation_epoch = 0)
        OR
        (lifecycle_state = 'active'
          AND local_install_package_set_digest_b64u IS NULL
          AND activated_at_ms IS NOT NULL
          AND revoked_at_ms IS NULL)
        OR
        (lifecycle_state = 'revoked'
          AND local_install_package_set_digest_b64u IS NULL
          AND activated_at_ms IS NOT NULL
          AND revoked_at_ms IS NOT NULL)
      ),
      CHECK (json_extract(record_json, '$.authorityId') = authority_id),
      CHECK (json_extract(record_json, '$.walletId') = wallet_id),
      CHECK (json_extract(record_json, '$.state') = lifecycle_state),
      CHECK (json_extract(record_json, '$.revocationEpoch') = revocation_epoch),
      CHECK (json_extract(record_json, '$.authorityDigestB64u') = authority_digest_b64u),
      CHECK (
        json_extract(record_json, '$.signerActivationSetDigestB64u')
          = signer_activation_set_digest_b64u
      )
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_authorities_active_device_uidx
      ON wallet_authorities (
        namespace, org_id, project_id, env_id, wallet_id, device_id
      )
      WHERE lifecycle_state <> 'revoked'
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_authorities_enrollment_uidx
      ON wallet_authorities (
        namespace, org_id, project_id, env_id, wallet_id, enrollment_id
      )
      WHERE enrollment_id IS NOT NULL
  `,
  `
    CREATE INDEX IF NOT EXISTS wallet_authorities_inventory_idx
      ON wallet_authorities (
        namespace, org_id, project_id, env_id, wallet_id, lifecycle_state,
        updated_at_ms, authority_id
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS wallet_authority_cas_guard (
      guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
    )
  `,
  `
    INSERT OR IGNORE INTO wallet_authority_cas_guard (guard_id) VALUES (1)
  `,
] as const);

type NormalizedScope = D1WalletAuthorityStoreScope;
type AuthorityRow = {
  readonly authority_id?: unknown;
  readonly wallet_id?: unknown;
  readonly device_id?: unknown;
  readonly provenance_kind?: unknown;
  readonly enrollment_id?: unknown;
  readonly source_authority_id?: unknown;
  readonly link_session_id?: unknown;
  readonly lifecycle_state?: unknown;
  readonly permissions_json?: unknown;
  readonly signer_activations_json?: unknown;
  readonly local_install_package_set_digest_b64u?: unknown;
  readonly signer_activation_set_digest_b64u?: unknown;
  readonly authority_digest_b64u?: unknown;
  readonly revocation_epoch?: unknown;
  readonly record_json?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
  readonly activated_at_ms?: unknown;
  readonly revoked_at_ms?: unknown;
};

type AuthMethodRow = {
  readonly record_json?: unknown;
};

function normalizeScope(input: D1WalletAuthorityStoreScope): NormalizedScope {
  return {
    namespace: requireScopeString(input.namespace, 'namespace'),
    orgId: requireScopeString(input.orgId, 'orgId'),
    projectId: requireScopeString(input.projectId, 'projectId'),
    envId: requireScopeString(input.envId, 'envId'),
  };
}

function requireScopeString(value: unknown, field: string): string {
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (!normalized) throw new Error(`${field} is required for D1 wallet authority store`);
  return normalized;
}

function scopeValues(scope: NormalizedScope): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function requireNonNegativeInteger(value: unknown, field: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
  return parsed;
}

function nullableString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const normalized = String(value).trim();
  return normalized || null;
}

function nullableTime(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  return requireNonNegativeInteger(value, 'authority lifecycle timestamp');
}

function requiredId<T>(
  raw: unknown,
  parser: (value: unknown) => { readonly ok: true; readonly value: T } | { readonly ok: false },
  field: string,
): T {
  const parsed = parser(raw);
  if (!parsed.ok) throw new Error(`stored wallet authority ${field} is invalid`);
  return parsed.value;
}

function parseAuthorityRow(row: AuthorityRow): WalletAuthorityV1 {
  const parsed = parseWalletAuthorityV1(parseD1JsonColumn(row.record_json));
  if (!parsed.ok) throw new Error(`stored wallet authority is invalid: ${parsed.error.message}`);
  const authority = parsed.value;
  const authorityId = requiredId(row.authority_id, parseWalletAuthorityId, 'authority_id');
  const walletId = requiredId(row.wallet_id, parseWalletId, 'wallet_id');
  const deviceId = requiredId(row.device_id, parseDeviceIdValue, 'device_id');
  const columns = authorityColumns(authority);
  const permissions = parseDelegatedWalletPermissionSetV1(
    parseD1JsonColumn(row.permissions_json),
  );
  const signerActivations = parseWalletSignerActivationSetV1(
    parseD1JsonColumn(row.signer_activations_json),
  );
  if (
    authority.authorityId !== authorityId ||
    authority.walletId !== walletId ||
    authority.principal.deviceId !== deviceId ||
    authority.state !== String(row.lifecycle_state || '') ||
    authority.revocationEpoch !==
      requireNonNegativeInteger(row.revocation_epoch, 'revocation_epoch') ||
    authority.signerActivationSetDigestB64u !==
      String(row.signer_activation_set_digest_b64u || '') ||
    authority.authorityDigestB64u !== String(row.authority_digest_b64u || '') ||
    columns.provenanceKind !== String(row.provenance_kind || '') ||
    columns.deviceId !== String(deviceId) ||
    !permissions.ok ||
    !permissionSetsEqual(authority.permissions, permissions.value) ||
    !signerActivations.ok ||
    !signerActivationSetsEqual(authority.signerActivations, signerActivations.value) ||
    nullableString(row.local_install_package_set_digest_b64u) !==
      columns.localInstallPackageSetDigestB64u ||
    nullableTime(row.created_at_ms) !== columns.createdAtMs ||
    nullableTime(row.updated_at_ms) !== columns.updatedAtMs ||
    nullableTime(row.activated_at_ms) !== columns.activatedAtMs ||
    nullableTime(row.revoked_at_ms) !== columns.revokedAtMs
  ) {
    throw new Error('stored wallet authority columns disagree with record_json');
  }
  const provenanceKind = columns.provenanceKind;
  if (authority.provenance.kind !== provenanceKind) {
    throw new Error('stored wallet authority provenance disagrees with columns');
  }
  if (authority.provenance.kind === 'device_link') {
    const enrollmentId = requiredId(
      row.enrollment_id,
      parseLinkedDeviceEnrollmentId,
      'enrollment_id',
    );
    const sourceAuthorityId = requiredId(
      row.source_authority_id,
      parseWalletAuthorityId,
      'source_authority_id',
    );
    const linkSessionId = requiredId(
      row.link_session_id,
      parseLinkDeviceSessionId,
      'link_session_id',
    );
    if (
      authority.provenance.enrollmentId !== enrollmentId ||
      authority.provenance.sourceAuthorityId !== sourceAuthorityId ||
      authority.provenance.linkSessionId !== linkSessionId
    ) {
      throw new Error('stored wallet authority provenance columns disagree with record_json');
    }
  } else if (
    nullableString(row.enrollment_id) !== null ||
    nullableString(row.source_authority_id) !== null ||
    nullableString(row.link_session_id) !== null
  ) {
    throw new Error('founding wallet authority has device-link provenance columns');
  }
  return authority;
}

function parseDeviceIdValue(
  value: unknown,
): { readonly ok: true; readonly value: DeviceId } | { readonly ok: false } {
  const parsed = parseDeviceId(value);
  return parsed.ok ? { ok: true, value: parsed.value } : { ok: false };
}

function authorityColumns(authority: WalletAuthorityV1): {
  readonly deviceId: string;
  readonly provenanceKind: WalletAuthorityV1['provenance']['kind'];
  readonly enrollmentId: string | null;
  readonly sourceAuthorityId: string | null;
  readonly linkSessionId: string | null;
  readonly lifecycleState: WalletAuthorityV1['state'];
  readonly permissionsJson: string;
  readonly signerActivationsJson: string;
  readonly localInstallPackageSetDigestB64u: string | null;
  readonly signerActivationSetDigestB64u: string;
  readonly authorityDigestB64u: string;
  readonly revocationEpoch: number;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly activatedAtMs: number | null;
  readonly revokedAtMs: number | null;
} {
  const provenance = authority.provenance;
  return {
    deviceId: String(authority.principal.deviceId),
    provenanceKind: provenance.kind,
    enrollmentId: provenance.kind === 'device_link' ? String(provenance.enrollmentId) : null,
    sourceAuthorityId:
      provenance.kind === 'device_link' ? String(provenance.sourceAuthorityId) : null,
    linkSessionId: provenance.kind === 'device_link' ? String(provenance.linkSessionId) : null,
    lifecycleState: authority.state,
    permissionsJson: JSON.stringify(authority.permissions),
    signerActivationsJson: JSON.stringify(authority.signerActivations),
    localInstallPackageSetDigestB64u:
      authority.state === 'pending_local_install'
        ? String(authority.localInstallPackageSetDigestB64u)
        : null,
    signerActivationSetDigestB64u: String(authority.signerActivationSetDigestB64u),
    authorityDigestB64u: String(authority.authorityDigestB64u),
    revocationEpoch: authority.revocationEpoch,
    recordJson: JSON.stringify(authority),
    createdAtMs: authority.createdAtMs,
    updatedAtMs: authority.updatedAtMs,
    activatedAtMs: authority.state === 'pending_local_install' ? null : authority.activatedAtMs,
    revokedAtMs: authority.state === 'revoked' ? authority.revokedAtMs : null,
  };
}

function assertPendingCommitInput(input: {
  readonly authority: PendingWalletAuthorityV1;
  readonly authMethod: WalletAuthMethodRecordV2;
}): void {
  if (input.authMethod.status !== 'pending_local_install') {
    throw new Error('pending authority commit requires a pending auth method');
  }
  if (
    input.authMethod.walletId !== input.authority.walletId ||
    input.authMethod.walletAuthorityId !== input.authority.authorityId
  ) {
    throw new Error('pending authority and auth method identities do not match');
  }
}

function assertActivationInput(input: {
  readonly pendingAuthority: PendingWalletAuthorityV1;
  readonly activeAuthority: ActiveWalletAuthorityV1;
  readonly pendingAuthMethod: WalletAuthMethodRecordV2;
  readonly activeAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
}): void {
  if (input.pendingAuthMethod.status !== 'pending_local_install') {
    throw new Error('authority activation requires a pending auth method');
  }
  if (
    input.activeAuthority.authorityId !== input.pendingAuthority.authorityId ||
    input.activeAuthority.walletId !== input.pendingAuthority.walletId ||
    input.activeAuthMethod.walletAuthMethodId !== input.pendingAuthMethod.walletAuthMethodId ||
    input.activeAuthMethod.walletAuthorityId !== input.activeAuthority.authorityId ||
    input.activeAuthMethod.walletId !== input.activeAuthority.walletId
  ) {
    throw new Error('authority activation identities do not match');
  }
}

function prepareAuthorityInsertStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: NormalizedScope;
  readonly authority: WalletAuthorityV1;
}): D1PreparedStatementLike {
  const columns = authorityColumns(input.authority);
  return input.database
    .prepare(
      `INSERT INTO wallet_authorities (
        namespace, org_id, project_id, env_id,
        authority_id, wallet_id, device_id, provenance_kind,
        enrollment_id, source_authority_id, link_session_id,
        lifecycle_state, permissions_json, signer_activations_json,
        local_install_package_set_digest_b64u,
        signer_activation_set_digest_b64u, authority_digest_b64u,
        revocation_epoch, record_json, created_at_ms, updated_at_ms,
        activated_at_ms, revoked_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      ...scopeValues(input.scope),
      String(input.authority.authorityId),
      String(input.authority.walletId),
      columns.deviceId,
      columns.provenanceKind,
      columns.enrollmentId,
      columns.sourceAuthorityId,
      columns.linkSessionId,
      columns.lifecycleState,
      columns.permissionsJson,
      columns.signerActivationsJson,
      columns.localInstallPackageSetDigestB64u,
      columns.signerActivationSetDigestB64u,
      columns.authorityDigestB64u,
      columns.revocationEpoch,
      columns.recordJson,
      columns.createdAtMs,
      columns.updatedAtMs,
      columns.activatedAtMs,
      columns.revokedAtMs,
    );
}

export function prepareD1WalletAuthorityPutStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletAuthorityStoreScope;
  readonly authority: WalletAuthorityV1;
}): D1PreparedStatementLike {
  return prepareAuthorityInsertStatement({
    database: input.database,
    scope: normalizeScope(input.scope),
    authority: input.authority,
  });
}

function prepareAuthorityTransitionStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: NormalizedScope;
  readonly expected: PendingWalletAuthorityV1;
  readonly next: ActiveWalletAuthorityV1;
}): D1PreparedStatementLike {
  const columns = authorityColumns(input.next);
  return input.database
    .prepare(
      `UPDATE wallet_authorities
          SET lifecycle_state = ?,
              permissions_json = ?,
              signer_activations_json = ?,
              local_install_package_set_digest_b64u = NULL,
              signer_activation_set_digest_b64u = ?,
              authority_digest_b64u = ?,
              revocation_epoch = ?,
              record_json = ?,
              updated_at_ms = ?,
              activated_at_ms = ?,
              revoked_at_ms = NULL
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND authority_id = ?
          AND wallet_id = ?
          AND lifecycle_state = 'pending_local_install'
          AND authority_digest_b64u = ?
          AND revocation_epoch = ?`,
    )
    .bind(
      columns.lifecycleState,
      columns.permissionsJson,
      columns.signerActivationsJson,
      columns.signerActivationSetDigestB64u,
      columns.authorityDigestB64u,
      columns.revocationEpoch,
      columns.recordJson,
      columns.updatedAtMs,
      columns.activatedAtMs,
      ...scopeValues(input.scope),
      String(input.expected.authorityId),
      String(input.expected.walletId),
      String(input.expected.authorityDigestB64u),
      input.expected.revocationEpoch,
    );
}

function prepareAuthMethodTransitionStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: NormalizedScope;
  readonly expected: WalletAuthMethodRecordV2;
  readonly next: WalletAuthMethodRecordV2;
}): D1PreparedStatementLike {
  if (input.expected.status !== 'pending_local_install' || input.next.status !== 'active') {
    throw new Error('auth method transition must be pending_local_install to active');
  }
  const expected = parseWalletAuthMethodRecordV2(input.expected);
  const next = parseWalletAuthMethodRecordV2(input.next);
  if (!expected || !next) throw new Error('auth method transition contains an invalid record');
  const columns = {
    record: JSON.stringify(next),
    updatedAtMs: next.updatedAtMs,
    activatedAtMs: next.activatedAtMs,
  };
  return input.database
    .prepare(
      `UPDATE wallet_auth_methods
          SET status = 'active',
              record_json = ?,
              updated_at_ms = ?,
              activated_at_ms = ?,
              revoked_at_ms = NULL
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND wallet_auth_method_id = ?
          AND wallet_authority_id = ?
          AND status = 'pending_local_install'
          AND updated_at_ms = ?
          AND record_json = ?`,
    )
    .bind(
      columns.record,
      columns.updatedAtMs,
      columns.activatedAtMs,
      ...scopeValues(input.scope),
      String(input.expected.walletAuthMethodId),
      String(input.expected.walletAuthorityId),
      input.expected.updatedAtMs,
      JSON.stringify(expected),
    );
}

function assertBatchResults(results: readonly D1ResultLike[], expectedCount: number): void {
  if (results.length !== expectedCount || results.some((result) => !result.success)) {
    throw new Error('D1 wallet authority batch returned an incomplete result');
  }
}

function prepareAuthorityCasGuard(database: D1DatabaseLike): D1PreparedStatementLike {
  return database.prepare(`
    INSERT INTO wallet_authority_cas_guard (guard_id)
    SELECT 1
     WHERE changes() = 0
  `);
}

export class WalletAuthorityCommitConflictError extends Error {
  readonly kind = 'wallet_authority_commit_conflict';

  constructor(authorityId: WalletAuthorityId) {
    super(`wallet authority ${String(authorityId)} commit conflicts with an existing record`);
    this.name = 'WalletAuthorityCommitConflictError';
  }
}

export class D1WalletAuthorityStore {
  private readonly database: D1DatabaseLike;
  private readonly scope: NormalizedScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope?: D1WalletAuthorityStoreScope;
    readonly namespace?: string;
    readonly orgId?: string;
    readonly projectId?: string;
    readonly envId?: string;
    readonly ensureSchema?: boolean;
  }) {
    this.database = input.database;
    this.scope = normalizeScope(
      input.scope ?? {
        namespace: input.namespace ?? '',
        orgId: input.orgId ?? '',
        projectId: input.projectId ?? '',
        envId: input.envId ?? '',
      },
    );
    this.ensureSchemaOnUse = input.ensureSchema !== false;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    for (const statement of WALLET_AUTHORITY_STORE_D1_SCHEMA_SQL) {
      await this.database.exec(formatD1ExecStatement(statement));
    }
    await ensureWalletAuthMethodStoreD1SchemaV2({ database: this.database });
    this.schemaReady = true;
  }

  async readById(authorityId: WalletAuthorityId): Promise<WalletAuthorityV1 | null> {
    await this.ensureSchema();
    const row = await this.database
      .prepare(
        `SELECT *
           FROM wallet_authorities
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND authority_id = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), String(authorityId))
      .first<AuthorityRow>();
    if (!row) return null;
    const authority = parseAuthorityRow(row);
    if (!(await walletAuthorityDigestsMatchV1(authority))) {
      throw new Error('stored wallet authority digest does not match its canonical record');
    }
    return authority;
  }

  async readByWalletAndDevice(input: {
    readonly walletId: WalletId;
    readonly deviceId: DeviceId;
  }): Promise<WalletAuthorityV1 | null> {
    await this.ensureSchema();
    const row = await this.database
      .prepare(
        `SELECT *
           FROM wallet_authorities
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND wallet_id = ? AND device_id = ?
            AND lifecycle_state <> 'revoked'
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), String(input.walletId), String(input.deviceId))
      .first<AuthorityRow>();
    if (!row) return null;
    const authority = parseAuthorityRow(row);
    if (!(await walletAuthorityDigestsMatchV1(authority))) {
      throw new Error('stored wallet authority digest does not match its canonical record');
    }
    return authority;
  }

  async commitPendingAuthority(input: {
    readonly authority: PendingWalletAuthorityV1;
    readonly authMethod: WalletAuthMethodRecordV2;
  }): Promise<WalletAuthorityCommitResultV1> {
    await this.ensureSchema();
    assertPendingCommitInput(input);
    if (!(await walletAuthorityDigestsMatchV1(input.authority))) {
      throw new Error('pending wallet authority digest does not match its canonical record');
    }
    const existing = await this.readById(input.authority.authorityId);
    if (existing) {
      const existingMethod = await this.readAuthMethodById(input.authMethod.walletAuthMethodId);
      if (
        existing.state === 'pending_local_install' &&
        existingMethod &&
        recordsEqual(existing, input.authority) &&
        authMethodsEqual(existingMethod, input.authMethod)
      ) {
        return { kind: 'replayed', authority: existing, authMethod: existingMethod };
      }
      return { kind: 'conflict', authorityId: input.authority.authorityId };
    }
    const statements = [
      prepareAuthorityInsertStatement({
        database: this.database,
        scope: this.scope,
        authority: input.authority,
      }),
      prepareD1WalletAuthMethodV2PutStatement({
        database: this.database,
        scope: this.scope,
        record: input.authMethod,
        insertOnly: true,
      }),
    ];
    try {
      const results = await this.database.batch<D1ResultLike>(statements);
      assertBatchResults(results, statements.length);
    } catch (error: unknown) {
      const raced = await this.readById(input.authority.authorityId);
      if (raced) {
        const racedMethod = await this.readAuthMethodById(input.authMethod.walletAuthMethodId);
        if (
          raced.state === 'pending_local_install' &&
          racedMethod &&
          recordsEqual(raced, input.authority) &&
          authMethodsEqual(racedMethod, input.authMethod)
        ) {
          return { kind: 'replayed', authority: raced, authMethod: racedMethod };
        }
        return { kind: 'conflict', authorityId: input.authority.authorityId };
      }
      throw error;
    }
    return {
      kind: 'committed_wallet_authority_v1',
      authority: input.authority,
      authMethod: input.authMethod,
    };
  }

  async activatePendingAuthority(input: {
    readonly pendingAuthority: PendingWalletAuthorityV1;
    readonly activeAuthority: ActiveWalletAuthorityV1;
    readonly pendingAuthMethod: WalletAuthMethodRecordV2;
    readonly activeAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  }): Promise<WalletAuthorityActivationResultV1> {
    await this.ensureSchema();
    assertActivationInput(input);
    if (!(await walletAuthorityDigestsMatchV1(input.activeAuthority))) {
      throw new Error('active wallet authority digest does not match its canonical record');
    }
    const existingAuthority = await this.readById(input.pendingAuthority.authorityId);
    const existingMethod = await this.readAuthMethodById(input.pendingAuthMethod.walletAuthMethodId);
    if (
      existingAuthority?.state === 'active' &&
      existingMethod?.status === 'active' &&
      recordsEqual(existingAuthority, input.activeAuthority) &&
      authMethodsEqual(existingMethod, input.activeAuthMethod)
    ) {
      return {
        kind: 'replayed',
        authority: existingAuthority,
        authMethod: existingMethod,
      };
    }
    const statements = [
      prepareAuthorityTransitionStatement({
        database: this.database,
        scope: this.scope,
        expected: input.pendingAuthority,
        next: input.activeAuthority,
      }),
      prepareAuthorityCasGuard(this.database),
      prepareAuthMethodTransitionStatement({
        database: this.database,
        scope: this.scope,
        expected: input.pendingAuthMethod,
        next: input.activeAuthMethod,
      }),
      prepareAuthorityCasGuard(this.database),
    ];
    let results: readonly D1ResultLike[];
    try {
      results = await this.database.batch<D1ResultLike>(statements);
    } catch (error: unknown) {
      const racedAuthority = await this.readById(input.pendingAuthority.authorityId);
      const racedMethod = await this.readAuthMethodById(input.pendingAuthMethod.walletAuthMethodId);
      if (
        racedAuthority?.state === 'active' &&
        racedMethod?.status === 'active' &&
        recordsEqual(racedAuthority, input.activeAuthority) &&
        authMethodsEqual(racedMethod, input.activeAuthMethod)
      ) {
        return { kind: 'replayed', authority: racedAuthority, authMethod: racedMethod };
      }
      if (racedAuthority || racedMethod) {
        return { kind: 'conflict', authorityId: input.pendingAuthority.authorityId };
      }
      throw error;
    }
    assertBatchResults(results, statements.length);
    const authorityChanged = d1ChangedRows(results[0] || {}) === 1;
    const methodChanged = d1ChangedRows(results[2] || {}) === 1;
    if (authorityChanged && methodChanged) {
      return {
        kind: 'activated',
        authority: input.activeAuthority,
        authMethod: input.activeAuthMethod,
      };
    }
    const storedAuthority = await this.readById(input.pendingAuthority.authorityId);
    const storedMethod = await this.readAuthMethodById(input.pendingAuthMethod.walletAuthMethodId);
    if (
      storedAuthority?.state === 'active' &&
      storedMethod?.status === 'active' &&
      recordsEqual(storedAuthority, input.activeAuthority) &&
      authMethodsEqual(storedMethod, input.activeAuthMethod)
    ) {
      return { kind: 'replayed', authority: storedAuthority, authMethod: storedMethod };
    }
    return { kind: 'conflict', authorityId: input.pendingAuthority.authorityId };
  }

  async listForWallet(input: {
    readonly walletId: WalletId;
    readonly lifecycleState?: WalletAuthorityV1['state'];
    readonly limit: number;
    readonly cursor: WalletAuthorityPageCursorV1 | null;
  }): Promise<WalletAuthorityPageV1> {
    await this.ensureSchema();
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 1000) {
      throw new Error('wallet authority page limit is invalid');
    }
    const state = input.lifecycleState ?? '';
    const cursorTime = input.cursor?.updatedAtMs ?? 0;
    const cursorId = input.cursor ? String(input.cursor.authorityId) : '';
    const rows = await this.database
      .prepare(
        `SELECT *
           FROM wallet_authorities
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND wallet_id = ?
            AND (? = '' OR lifecycle_state = ?)
            AND (
              ? = '' OR updated_at_ms > ? OR (updated_at_ms = ? AND authority_id > ?)
            )
          ORDER BY updated_at_ms ASC, authority_id ASC
          LIMIT ?`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(input.walletId),
        state,
        state,
        cursorId,
        cursorTime,
        cursorTime,
        cursorId,
        input.limit + 1,
      )
      .all<AuthorityRow>();
    const authorities: WalletAuthorityV1[] = [];
    for (const row of rows.results || []) {
      const authority = parseAuthorityRow(row);
      if (!(await walletAuthorityDigestsMatchV1(authority))) {
        throw new Error('stored wallet authority digest does not match its canonical record');
      }
      authorities.push(authority);
    }
    const page = authorities.slice(0, input.limit);
    const last = page.at(-1);
    const nextCursor =
      authorities.length > input.limit && last
        ? { updatedAtMs: last.updatedAtMs, authorityId: last.authorityId }
        : null;
    return { records: page, nextCursor };
  }

  async revokeWalletAuthMethod(input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expectedAuthorityRevocationEpoch: number;
    readonly requestedAtMs: number;
  }): Promise<WalletAuthorityRevocationResultV1> {
    await this.ensureSchema();
    const expectedEpoch = requireNonNegativeInteger(
      input.expectedAuthorityRevocationEpoch,
      'expected authority revocation epoch',
    );
    const requestedAtMs = requireNonNegativeInteger(input.requestedAtMs, 'requestedAtMs');
    const activeCountRow = await this.database
      .prepare(
        `SELECT COUNT(*) AS count
           FROM wallet_auth_methods
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND wallet_id = ? AND status = 'active'`,
      )
      .bind(...scopeValues(this.scope), String(input.walletId))
      .first<{ readonly count?: unknown }>();
    if (Number(activeCountRow?.count || 0) <= 1) {
      return { kind: 'would_remove_last_wallet_auth_method' };
    }
    const authority = await this.readById(input.authorityId);
    if (
      !authority ||
      authority.walletId !== input.walletId ||
      authority.state !== 'active' ||
      authority.revocationEpoch !== expectedEpoch
    ) {
      return { kind: 'conflict' };
    }
    const method = await this.readAuthMethodById(input.walletAuthMethodId);
    if (
      !method ||
      method.status !== 'active' ||
      method.walletId !== input.walletId ||
      method.walletAuthorityId !== authority.authorityId
    ) {
      return { kind: 'conflict' };
    }
    const revokedMethod = buildRevokedAuthMethod(method, requestedAtMs);
    const nextAuthority = await buildRevokedAuthority(authority, requestedAtMs);
    const methodUpdate = this.database
      .prepare(
        `UPDATE wallet_auth_methods
            SET status = 'revoked', record_json = ?, updated_at_ms = ?,
                revoked_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND wallet_auth_method_id = ? AND wallet_authority_id = ?
            AND wallet_id = ? AND status = 'active' AND updated_at_ms = ?
            AND (
              SELECT COUNT(*)
                FROM wallet_auth_methods AS active_method
               WHERE active_method.namespace = ?
                 AND active_method.org_id = ?
                 AND active_method.project_id = ?
                 AND active_method.env_id = ?
                 AND active_method.wallet_id = ?
                 AND active_method.status = 'active'
            ) > 1`,
      )
      .bind(
        JSON.stringify(revokedMethod),
        revokedMethod.updatedAtMs,
        revokedMethod.revokedAtMs,
        ...scopeValues(this.scope),
        String(method.walletAuthMethodId),
        String(authority.authorityId),
        String(input.walletId),
        method.updatedAtMs,
        ...scopeValues(this.scope),
        String(input.walletId),
      );
    const statements: D1PreparedStatementLike[] = [
      methodUpdate,
      prepareAuthorityCasGuard(this.database),
      this.database
        .prepare(
          `UPDATE wallet_authorities
              SET lifecycle_state = 'revoked',
                  authority_digest_b64u = ?, record_json = ?,
                  revocation_epoch = ?, updated_at_ms = ?, revoked_at_ms = ?
            WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
              AND authority_id = ? AND wallet_id = ?
              AND lifecycle_state = 'active' AND revocation_epoch = ?
              AND NOT EXISTS (
                SELECT 1
                  FROM wallet_auth_methods AS remaining_method
                 WHERE remaining_method.namespace = ?
                   AND remaining_method.org_id = ?
                   AND remaining_method.project_id = ?
                   AND remaining_method.env_id = ?
                   AND remaining_method.wallet_authority_id = ?
                   AND remaining_method.status = 'active'
              )`,
        )
        .bind(
          String(nextAuthority.authorityDigestB64u),
          JSON.stringify(nextAuthority),
          nextAuthority.revocationEpoch,
          nextAuthority.updatedAtMs,
          nextAuthority.revokedAtMs,
          ...scopeValues(this.scope),
          String(authority.authorityId),
          String(input.walletId),
          expectedEpoch,
          ...scopeValues(this.scope),
          String(authority.authorityId),
        ),
      this.database.prepare(`
        INSERT INTO wallet_authority_cas_guard (guard_id)
        SELECT 1
         WHERE changes() = 0
           AND NOT EXISTS (
             SELECT 1
               FROM wallet_auth_methods
              WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
                AND wallet_authority_id = ? AND status = 'active'
           )
      `).bind(...scopeValues(this.scope), String(authority.authorityId)),
    ];
    let results: readonly D1ResultLike[];
    try {
      results = await this.database.batch<D1ResultLike>(statements);
    } catch {
      return { kind: 'conflict' };
    }
    assertBatchResults(results, statements.length);
    if (d1ChangedRows(results[0] || {}) !== 1) return { kind: 'conflict' };
    const storedAuthority = await this.readById(authority.authorityId);
    if (!storedAuthority) return { kind: 'conflict' };
    return { kind: 'revoked_method', authMethod: revokedMethod, authority: storedAuthority };
  }

  private async readAuthMethodById(
    walletAuthMethodId: WalletAuthMethodId,
  ): Promise<WalletAuthMethodRecordV2 | null> {
    const row = await this.database
      .prepare(
        `SELECT record_json
           FROM wallet_auth_methods
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND wallet_auth_method_id = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), String(walletAuthMethodId))
      .first<AuthMethodRow>();
    return parseWalletAuthMethodRecordV2(parseD1JsonColumn(row?.record_json));
  }
}

function permissionSetsEqual(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

type Ed25519ActivationSet = Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519'] }
>;
type EcdsaActivationSet = Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
>;
type BothActivationSet = Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
>;

function isEd25519ActivationSet(value: WalletSignerActivationSetV1): value is Ed25519ActivationSet {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ed25519';
}

function isEcdsaActivationSet(value: WalletSignerActivationSetV1): value is EcdsaActivationSet {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ecdsa_secp256k1';
}

function isBothActivationSet(value: WalletSignerActivationSetV1): value is BothActivationSet {
  return value.keyFamilies.length === 2;
}

function signerActivationSetsEqual(
  left: WalletSignerActivationSetV1,
  right: WalletSignerActivationSetV1,
): boolean {
  if (left.kind !== right.kind || left.keyFamilies.length !== right.keyFamilies.length) {
    return false;
  }
  for (let index = 0; index < left.keyFamilies.length; index += 1) {
    if (left.keyFamilies[index] !== right.keyFamilies[index]) return false;
  }
  if (isEd25519ActivationSet(left)) {
    return isEd25519ActivationSet(right) && ed25519ActivationsEqual(left, right);
  }
  if (isEcdsaActivationSet(left)) {
    return isEcdsaActivationSet(right) && ecdsaActivationsEqual(left, right);
  }
  if (isBothActivationSet(left)) {
    return isBothActivationSet(right) &&
      ed25519ActivationsEqual(left, right) &&
      ecdsaActivationsEqual(left, right);
  }
  return false;
}

function ed25519ActivationsEqual(left: Ed25519ActivationSet | BothActivationSet, right: Ed25519ActivationSet | BothActivationSet): boolean {
  return (
    left.ed25519.kind === right.ed25519.kind &&
    left.ed25519.signer.kind === right.ed25519.signer.kind &&
    left.ed25519.signer.keyFamily === right.ed25519.signer.keyFamily &&
    left.ed25519.signer.walletId === right.ed25519.signer.walletId &&
    left.ed25519.signer.walletKeyId === right.ed25519.signer.walletKeyId &&
    left.ed25519.signer.registeredPublicKeyB64u === right.ed25519.signer.registeredPublicKeyB64u &&
    mpcMaterialActivationRefsEqual(
      left.ed25519.materialActivation,
      right.ed25519.materialActivation,
    )
  );
}

function ecdsaActivationsEqual(left: EcdsaActivationSet | BothActivationSet, right: EcdsaActivationSet | BothActivationSet): boolean {
  return (
    left.ecdsa.kind === right.ecdsa.kind &&
    left.ecdsa.signer.kind === right.ecdsa.signer.kind &&
    left.ecdsa.signer.keyFamily === right.ecdsa.signer.keyFamily &&
    left.ecdsa.signer.walletId === right.ecdsa.signer.walletId &&
    left.ecdsa.signer.walletKeyId === right.ecdsa.signer.walletKeyId &&
    left.ecdsa.signer.thresholdPublicKey33B64u === right.ecdsa.signer.thresholdPublicKey33B64u &&
    left.ecdsa.signer.evmAddress === right.ecdsa.signer.evmAddress &&
    mpcMaterialActivationRefsEqual(left.ecdsa.materialActivation, right.ecdsa.materialActivation)
  );
}

function provenanceEqual(
  left: WalletAuthorityV1['provenance'],
  right: WalletAuthorityV1['provenance'],
): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'wallet_registration') return true;
  return (
    right.kind === 'device_link' &&
    left.enrollmentId === right.enrollmentId &&
    left.sourceAuthorityId === right.sourceAuthorityId &&
    left.linkSessionId === right.linkSessionId
  );
}

function recordsEqual(left: WalletAuthorityV1, right: WalletAuthorityV1): boolean {
  if (
    left.kind !== right.kind ||
    left.authorityId !== right.authorityId ||
    left.walletId !== right.walletId ||
    left.principal.kind !== right.principal.kind ||
    left.principal.deviceId !== right.principal.deviceId ||
    !provenanceEqual(left.provenance, right.provenance) ||
    !permissionSetsEqual(left.permissions, right.permissions) ||
    !signerActivationSetsEqual(left.signerActivations, right.signerActivations) ||
    left.signerActivationSetDigestB64u !== right.signerActivationSetDigestB64u ||
    left.authorityDigestB64u !== right.authorityDigestB64u ||
    left.revocationEpoch !== right.revocationEpoch ||
    left.createdAtMs !== right.createdAtMs ||
    left.updatedAtMs !== right.updatedAtMs ||
    left.state !== right.state
  ) {
    return false;
  }
  switch (left.state) {
    case 'pending_local_install':
      return (
        right.state === 'pending_local_install' &&
        left.localInstallPackageSetDigestB64u === right.localInstallPackageSetDigestB64u
      );
    case 'active':
      return right.state === 'active' && left.activatedAtMs === right.activatedAtMs;
    case 'revoked':
      return (
        right.state === 'revoked' &&
        left.activatedAtMs === right.activatedAtMs &&
        left.revokedAtMs === right.revokedAtMs
      );
  }
}

function authMethodsEqual(
  left: WalletAuthMethodRecordV2,
  right: WalletAuthMethodRecordV2,
): boolean {
  if (
    left.version !== right.version ||
    left.walletAuthMethodId !== right.walletAuthMethodId ||
    left.walletId !== right.walletId ||
    left.walletAuthorityId !== right.walletAuthorityId ||
    left.kind !== right.kind ||
    left.status !== right.status ||
    left.createdAtMs !== right.createdAtMs ||
    left.updatedAtMs !== right.updatedAtMs
  ) {
    return false;
  }
  if (left.kind === 'passkey') {
    if (right.kind !== 'passkey') return false;
    if (
      left.rpId !== right.rpId ||
      left.credentialIdB64u !== right.credentialIdB64u ||
      left.credentialPublicKeyB64u !== right.credentialPublicKeyB64u ||
      left.counter !== right.counter
    ) {
      return false;
    }
  } else {
    if (right.kind !== 'email_otp') return false;
    if (
      left.emailHashHex !== right.emailHashHex ||
      left.registrationAuthorityId !== right.registrationAuthorityId
    ) {
      return false;
    }
  }
  switch (left.status) {
    case 'pending_local_install':
      return right.status === 'pending_local_install';
    case 'active':
      return right.status === 'active' && left.activatedAtMs === right.activatedAtMs;
    case 'revoked':
      return (
        right.status === 'revoked' &&
        left.activatedAtMs === right.activatedAtMs &&
        left.revokedAtMs === right.revokedAtMs
      );
  }
}

function buildRevokedAuthMethod(
  method: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
  revokedAtMs: number,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'revoked' }> {
  if (revokedAtMs < method.updatedAtMs) {
    throw new Error('auth method revocation time precedes the current record');
  }
  if (method.kind === 'passkey') {
    return {
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: method.walletAuthMethodId,
      walletId: method.walletId,
      walletAuthorityId: method.walletAuthorityId,
      kind: 'passkey',
      status: 'revoked',
      rpId: method.rpId,
      credentialIdB64u: method.credentialIdB64u,
      credentialPublicKeyB64u: method.credentialPublicKeyB64u,
      counter: method.counter,
      createdAtMs: method.createdAtMs,
      updatedAtMs: revokedAtMs,
      activatedAtMs: method.activatedAtMs,
      revokedAtMs,
    };
  }
  return {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: method.walletAuthMethodId,
    walletId: method.walletId,
    walletAuthorityId: method.walletAuthorityId,
    kind: 'email_otp',
    status: 'revoked',
    emailHashHex: method.emailHashHex,
    registrationAuthorityId: method.registrationAuthorityId,
    createdAtMs: method.createdAtMs,
    updatedAtMs: revokedAtMs,
    activatedAtMs: method.activatedAtMs,
    revokedAtMs,
  };
}

async function buildRevokedAuthority(
  authority: ActiveWalletAuthorityV1,
  revokedAtMs: number,
): Promise<RevokedWalletAuthorityV1> {
  if (revokedAtMs < authority.updatedAtMs) {
    throw new Error('authority revocation time precedes the current record');
  }
  const draft: RevokedWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId: authority.authorityId,
    walletId: authority.walletId,
    principal: authority.principal,
    provenance: authority.provenance,
    permissions: authority.permissions,
    signerActivations: authority.signerActivations,
    signerActivationSetDigestB64u: authority.signerActivationSetDigestB64u,
    authorityDigestB64u: authority.authorityDigestB64u,
    revocationEpoch: authority.revocationEpoch + 1,
    createdAtMs: authority.createdAtMs,
    updatedAtMs: revokedAtMs,
    state: 'revoked',
    activatedAtMs: authority.activatedAtMs,
    revokedAtMs,
  };
  const digest = parseDigestB64u(await computeWalletAuthorityDigestB64u(draft));
  return buildRevokedWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: digest,
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
    revokedAtMs: draft.revokedAtMs,
  });
}

export class D1WalletAuthorityStoreV1 extends D1WalletAuthorityStore {}
export type CloudflareD1WalletAuthorityStore = D1WalletAuthorityStore;
