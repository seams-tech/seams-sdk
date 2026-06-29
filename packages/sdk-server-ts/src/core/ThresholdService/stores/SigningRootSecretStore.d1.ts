import { alphabetizeStringify, sha256Bytes, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { formatD1ExecStatement } from '../../../storage/d1Sql';
import type { D1DatabaseLike } from '../../../storage/tenantRoute';
import { parseCurrentSigningRootSecretShareRecord } from '../persistedRecords';
import type {
  SealedSigningRootSecretShare,
  SigningRootSecretShareId,
} from '../signingRootSecretShareWires';
import {
  cloneRecord,
  normalizePutInput,
  normalizeSigningRootVersionKey,
  requireSigningRootId,
  signingRootVersionFromKey,
  type DeleteSigningRootSecretSharesInput,
  type PutSigningRootSecretShareInput,
  type ResolveSigningRootSecretSharesInput,
  type SigningRootSecretStore,
} from './SigningRootSecretStore.shared';

const DEFAULT_D1_ROTATION_STATE = 'active';

type D1SigningRootSecretShareRow = {
  namespace?: unknown;
  org_id?: unknown;
  project_id?: unknown;
  env_id?: unknown;
  signing_root_id?: unknown;
  signing_root_version?: unknown;
  share_id?: unknown;
  sealed_share_b64u?: unknown;
  storage_id?: unknown;
  kek_id?: unknown;
  envelope_version?: unknown;
  aad_digest_b64u?: unknown;
  ciphertext_digest_b64u?: unknown;
  rotation_state?: unknown;
  last_audit_event_id?: unknown;
  created_at_ms?: unknown;
  updated_at_ms?: unknown;
};

export interface D1SigningRootSecretStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1SigningRootSecretStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly envelopeVersion: string;
  readonly lastAuditEventId: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

type NormalizedD1SigningRootSecretStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly envelopeVersion: string;
  readonly lastAuditEventId: string;
  readonly ensureSchema: boolean;
  readonly now: () => Date;
};

type D1SigningRootSecretShareScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

export const SIGNING_ROOT_SECRET_SHARE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS signing_root_secret_shares (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      signing_root_id TEXT NOT NULL,
      signing_root_version TEXT NOT NULL,
      share_id INTEGER NOT NULL,
      sealed_share_b64u TEXT NOT NULL,
      storage_id TEXT,
      kek_id TEXT NOT NULL,
      envelope_version TEXT NOT NULL,
      aad_digest_b64u TEXT NOT NULL,
      ciphertext_digest_b64u TEXT NOT NULL,
      rotation_state TEXT NOT NULL,
      rotated_from_kek_id TEXT,
      rotated_at_ms INTEGER,
      retired_at_ms INTEGER,
      last_audit_event_id TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (
        namespace,
        org_id,
        project_id,
        env_id,
        signing_root_id,
        signing_root_version,
        share_id
      ),
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(project_id) > 0),
      CHECK (length(env_id) > 0),
      CHECK (length(signing_root_id) > 0),
      CHECK (share_id IN (1, 2, 3)),
      CHECK (length(sealed_share_b64u) > 0),
      CHECK (sealed_share_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
      CHECK (storage_id IS NULL OR length(storage_id) > 0),
      CHECK (length(kek_id) > 0),
      CHECK (length(envelope_version) > 0),
      CHECK (length(aad_digest_b64u) = 43),
      CHECK (aad_digest_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
      CHECK (length(ciphertext_digest_b64u) = 43),
      CHECK (ciphertext_digest_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
      CHECK (rotation_state IN ('active', 'rotation_pending', 'rotated', 'retired')),
      CHECK (rotated_from_kek_id IS NULL OR length(rotated_from_kek_id) > 0),
      CHECK (rotated_at_ms IS NULL OR rotated_at_ms >= created_at_ms),
      CHECK (retired_at_ms IS NULL OR retired_at_ms >= created_at_ms),
      CHECK (length(last_audit_event_id) > 0),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms >= created_at_ms)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS signing_root_secret_shares_scope_idx
      ON signing_root_secret_shares (
        namespace,
        org_id,
        project_id,
        env_id,
        signing_root_id,
        signing_root_version,
        share_id
      )
  `,
] as const);

export async function ensureSigningRootSecretShareD1Schema(
  options: D1SigningRootSecretStoreSchemaOptions,
): Promise<void> {
  for (const statement of SIGNING_ROOT_SECRET_SHARE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 signing-root secret store`);
  return normalized;
}

function normalizeD1SigningRootSecretStoreOptions(
  input: D1SigningRootSecretStoreOptions,
): NormalizedD1SigningRootSecretStoreOptions {
  return {
    database: input.database,
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.orgId, 'orgId'),
    projectId: requireD1ScopeString(input.projectId, 'projectId'),
    envId: requireD1ScopeString(input.envId, 'envId'),
    envelopeVersion: requireD1ScopeString(input.envelopeVersion, 'envelopeVersion'),
    lastAuditEventId: requireD1ScopeString(input.lastAuditEventId, 'lastAuditEventId'),
    ensureSchema: input.ensureSchema !== false,
    now: input.now || (() => new Date()),
  };
}

function d1ScopeMatches(input: {
  readonly row: D1SigningRootSecretShareRow;
  readonly scope: D1SigningRootSecretShareScope;
}): boolean {
  return (
    input.row.namespace === input.scope.namespace &&
    input.row.org_id === input.scope.orgId &&
    input.row.project_id === input.scope.projectId &&
    input.row.env_id === input.scope.envId
  );
}

function parseD1RotationState(input: unknown): typeof DEFAULT_D1_ROTATION_STATE | null {
  return input === DEFAULT_D1_ROTATION_STATE ? DEFAULT_D1_ROTATION_STATE : null;
}

function parseRequiredD1RowString(input: unknown): string | null {
  return toOptionalTrimmedString(input) || null;
}

async function computeD1AadDigestB64u(input: {
  readonly scope: D1SigningRootSecretShareScope;
  readonly signingRootId: string;
  readonly signingRootVersionKey: string;
  readonly shareId: SigningRootSecretShareId;
}): Promise<string> {
  const aadJson = alphabetizeStringify({
    version: 'signing_root_secret_share_d1_aad_v1',
    namespace: input.scope.namespace,
    orgId: input.scope.orgId,
    projectId: input.scope.projectId,
    envId: input.scope.envId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersionKey,
    shareId: input.shareId,
  });
  return base64UrlEncode(await sha256BytesUtf8(aadJson));
}

async function computeD1CiphertextDigestB64u(sealedShare: Uint8Array): Promise<string> {
  return base64UrlEncode(await sha256Bytes(sealedShare));
}

async function parseD1SigningRootSecretShareRow(input: {
  readonly row: D1SigningRootSecretShareRow;
  readonly scope: D1SigningRootSecretShareScope;
}): Promise<SealedSigningRootSecretShare | null> {
  if (!d1ScopeMatches(input)) return null;
  const parsed = parseCurrentSigningRootSecretShareRecord(input.row);
  if (!parsed) return null;
  const envelopeVersion = parseRequiredD1RowString(input.row.envelope_version);
  const aadDigestB64u = parseRequiredD1RowString(input.row.aad_digest_b64u);
  const ciphertextDigestB64u = parseRequiredD1RowString(input.row.ciphertext_digest_b64u);
  const rotationState = parseD1RotationState(input.row.rotation_state);
  const lastAuditEventId = parseRequiredD1RowString(input.row.last_audit_event_id);
  const kekId = parseRequiredD1RowString(input.row.kek_id);
  if (
    !envelopeVersion ||
    !aadDigestB64u ||
    !ciphertextDigestB64u ||
    !rotationState ||
    !lastAuditEventId ||
    !kekId
  ) {
    return null;
  }
  const signingRootVersionKey = normalizeSigningRootVersionKey(parsed.signingRootVersion);
  const expectedAadDigestB64u = await computeD1AadDigestB64u({
    scope: input.scope,
    signingRootId: parsed.signingRootId,
    signingRootVersionKey,
    shareId: parsed.shareId,
  });
  const expectedCiphertextDigestB64u = await computeD1CiphertextDigestB64u(parsed.sealedShare);
  if (aadDigestB64u !== expectedAadDigestB64u) return null;
  if (ciphertextDigestB64u !== expectedCiphertextDigestB64u) return null;
  return cloneRecord({
    signingRootId: parsed.signingRootId,
    shareId: parsed.shareId,
    sealedShare: parsed.sealedShare,
    ...(parsed.signingRootVersion ? { signingRootVersion: parsed.signingRootVersion } : {}),
    ...(parsed.storageId ? { storageId: parsed.storageId } : {}),
    kekId,
  });
}

export class D1SigningRootSecretStore implements SigningRootSecretStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1SigningRootSecretShareScope;
  private readonly envelopeVersion: string;
  private readonly lastAuditEventId: string;
  private readonly ensureSchemaOnUse: boolean;
  private readonly now: () => Date;
  private ensureSchemaPromise: Promise<void> | null = null;

  constructor(input: D1SigningRootSecretStoreOptions) {
    const normalized = normalizeD1SigningRootSecretStoreOptions(input);
    this.database = normalized.database;
    this.scope = {
      namespace: normalized.namespace,
      orgId: normalized.orgId,
      projectId: normalized.projectId,
      envId: normalized.envId,
    };
    this.envelopeVersion = normalized.envelopeVersion;
    this.lastAuditEventId = normalized.lastAuditEventId;
    this.ensureSchemaOnUse = normalized.ensureSchema;
    this.now = normalized.now;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse) return;
    if (!this.ensureSchemaPromise) {
      this.ensureSchemaPromise = ensureSigningRootSecretShareD1Schema({
        database: this.database,
      }).catch((error) => {
        this.ensureSchemaPromise = null;
        throw error;
      });
    }
    await this.ensureSchemaPromise;
  }

  async listSealedSigningRootSecretShares(
    input: ResolveSigningRootSecretSharesInput,
  ): Promise<readonly SealedSigningRootSecretShare[]> {
    await this.ensureSchema();
    const signingRootId = requireSigningRootId(input.signingRootId);
    const signingRootVersionKey = normalizeSigningRootVersionKey(input.signingRootVersion);
    const result = await this.database
      .prepare(
        `SELECT
           namespace,
           org_id,
           project_id,
           env_id,
           signing_root_id,
           signing_root_version,
           share_id,
           sealed_share_b64u,
           storage_id,
           kek_id,
           envelope_version,
           aad_digest_b64u,
           ciphertext_digest_b64u,
           rotation_state,
           last_audit_event_id,
           created_at_ms,
           updated_at_ms
         FROM signing_root_secret_shares
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND signing_root_id = ?
          AND signing_root_version = ?
          AND rotation_state = 'active'
        ORDER BY share_id ASC`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        signingRootId,
        signingRootVersionKey,
      )
      .all<D1SigningRootSecretShareRow>();
    const rows = result.results || [];
    const records: SealedSigningRootSecretShare[] = [];
    for (const row of rows) {
      const parsed = await parseD1SigningRootSecretShareRow({
        row,
        scope: this.scope,
      });
      if (!parsed) {
        await this.deleteSigningRootSecretShares({
          signingRootId,
          signingRootVersion: signingRootVersionFromKey(signingRootVersionKey),
        });
        return [];
      }
      records.push(parsed);
    }
    return records.sort((a, b) => a.shareId - b.shareId).map(cloneRecord);
  }

  async putSealedSigningRootSecretShare(input: PutSigningRootSecretShareInput): Promise<void> {
    await this.ensureSchema();
    const normalized = normalizePutInput(input);
    const kekId = toOptionalTrimmedString(normalized.kekId);
    if (!kekId) {
      throw new Error('kekId is required for D1 signing-root secret shares');
    }
    const nowMs = this.now().getTime();
    const sealedShareB64u = base64UrlEncode(normalized.sealedShare);
    const aadDigestB64u = await computeD1AadDigestB64u({
      scope: this.scope,
      signingRootId: normalized.signingRootId,
      signingRootVersionKey: normalized.signingRootVersionKey,
      shareId: normalized.shareId,
    });
    const ciphertextDigestB64u = await computeD1CiphertextDigestB64u(normalized.sealedShare);
    await this.database
      .prepare(
        `INSERT INTO signing_root_secret_shares (
          namespace,
          org_id,
          project_id,
          env_id,
          signing_root_id,
          signing_root_version,
          share_id,
          sealed_share_b64u,
          storage_id,
          kek_id,
          envelope_version,
          aad_digest_b64u,
          ciphertext_digest_b64u,
          rotation_state,
          rotated_from_kek_id,
          rotated_at_ms,
          retired_at_ms,
          last_audit_event_id,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL, NULL, NULL, ?, ?, ?)
        ON CONFLICT (
          namespace,
          org_id,
          project_id,
          env_id,
          signing_root_id,
          signing_root_version,
          share_id
        )
        DO UPDATE SET
          project_id = EXCLUDED.project_id,
          env_id = EXCLUDED.env_id,
          sealed_share_b64u = EXCLUDED.sealed_share_b64u,
          storage_id = EXCLUDED.storage_id,
          kek_id = EXCLUDED.kek_id,
          envelope_version = EXCLUDED.envelope_version,
          aad_digest_b64u = EXCLUDED.aad_digest_b64u,
          ciphertext_digest_b64u = EXCLUDED.ciphertext_digest_b64u,
          rotation_state = 'active',
          rotated_from_kek_id = NULL,
          rotated_at_ms = NULL,
          retired_at_ms = NULL,
          last_audit_event_id = EXCLUDED.last_audit_event_id,
          updated_at_ms = EXCLUDED.updated_at_ms`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        normalized.signingRootId,
        normalized.signingRootVersionKey,
        normalized.shareId,
        sealedShareB64u,
        normalized.storageId || null,
        kekId,
        this.envelopeVersion,
        aadDigestB64u,
        ciphertextDigestB64u,
        this.lastAuditEventId,
        nowMs,
        nowMs,
      )
      .run();
  }

  async deleteSigningRootSecretShares(input: DeleteSigningRootSecretSharesInput): Promise<void> {
    await this.ensureSchema();
    const signingRootId = requireSigningRootId(input.signingRootId);
    const signingRootVersionKey = normalizeSigningRootVersionKey(input.signingRootVersion);
    await this.database
      .prepare(
        `DELETE FROM signing_root_secret_shares
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND signing_root_id = ?
            AND signing_root_version = ?`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        signingRootId,
        signingRootVersionKey,
      )
      .run();
  }
}
