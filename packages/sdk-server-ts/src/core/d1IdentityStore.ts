import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { d1ChangedRows, formatD1ExecStatement } from '../storage/d1Sql';
import type { D1DatabaseLike } from '../storage/tenantRoute';
import type {
  AppSessionVersionRecord,
  IdentityStore,
  IdentitySubjectRecord,
  LinkIdentityResult,
  UnlinkIdentityResult,
} from './IdentityStore';

export interface D1IdentityStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1IdentityStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

type NormalizedD1IdentityStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
  readonly now: () => Date;
};

type D1IdentityScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1IdentityLinkRow = {
  readonly subject?: unknown;
  readonly user_id?: unknown;
  readonly created_at_ms?: unknown;
  readonly subject_count?: unknown;
};

type D1AppSessionVersionRow = {
  readonly session_version?: unknown;
  readonly created_at_ms?: unknown;
};

export const IDENTITY_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS identity_links (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      user_id TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, subject),
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(project_id) > 0),
      CHECK (length(env_id) > 0),
      CHECK (length(subject) > 0),
      CHECK (length(user_id) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (COALESCE(json_extract(record_json, '$.version') = 'identity_subject_v1', 0)),
      CHECK (COALESCE(json_extract(record_json, '$.subject') = subject, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.userId') = user_id, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS identity_links_user_idx
      ON identity_links (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        created_at_ms
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS app_session_versions (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      session_version TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, user_id),
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(project_id) > 0),
      CHECK (length(env_id) > 0),
      CHECK (length(user_id) > 0),
      CHECK (length(session_version) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (COALESCE(json_extract(record_json, '$.version') = 'app_session_version_v1', 0)),
      CHECK (COALESCE(json_extract(record_json, '$.userId') = user_id, 0)),
      CHECK (
        COALESCE(json_extract(record_json, '$.appSessionVersion') = session_version, 0)
      ),
      CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
      CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
    )
  `,
] as const);

export async function ensureIdentityStoreD1Schema(
  options: D1IdentityStoreSchemaOptions,
): Promise<void> {
  for (const statement of IDENTITY_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

function defaultNow(): Date {
  return new Date();
}

function generateAppSessionVersion(): string {
  return secureRandomBase64Url(32, 'app session versions');
}

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 identity store`);
  return normalized;
}

function normalizeD1IdentityStoreOptions(
  input: D1IdentityStoreOptions,
): NormalizedD1IdentityStoreOptions {
  return {
    database: input.database,
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.orgId, 'orgId'),
    projectId: requireD1ScopeString(input.projectId, 'projectId'),
    envId: requireD1ScopeString(input.envId, 'envId'),
    ensureSchema: input.ensureSchema !== false,
    now: input.now || defaultNow,
  };
}

function parseSubjectCount(raw: unknown): number {
  const count = Number(raw);
  return Number.isFinite(count) && count >= 0 ? Math.floor(count) : 0;
}

function subjectFromIdentityLinkRow(row: D1IdentityLinkRow): string | null {
  return toOptionalTrimmedString(row.subject) || null;
}

function isPresentString(value: string | null): value is string {
  return Boolean(value);
}

function buildIdentitySubjectRecord(input: {
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): IdentitySubjectRecord {
  return {
    version: 'identity_subject_v1',
    subject: input.subject,
    userId: input.userId,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function buildAppSessionVersionRecord(input: {
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): AppSessionVersionRecord {
  return {
    version: 'app_session_version_v1',
    userId: input.userId,
    appSessionVersion: input.appSessionVersion,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

export class D1IdentityStore implements IdentityStore {
  readonly adapterKind = 'd1';
  private readonly database: D1DatabaseLike;
  private readonly scope: D1IdentityScope;
  private readonly ensureSchemaOnUse: boolean;
  private readonly now: () => Date;
  private schemaReady = false;

  constructor(input: D1IdentityStoreOptions) {
    const normalized = normalizeD1IdentityStoreOptions(input);
    this.database = normalized.database;
    this.scope = {
      namespace: normalized.namespace,
      orgId: normalized.orgId,
      projectId: normalized.projectId,
      envId: normalized.envId,
    };
    this.ensureSchemaOnUse = normalized.ensureSchema;
    this.now = normalized.now;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    await ensureIdentityStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  private bindScope(statement: string, values: readonly unknown[] = []) {
    return this.database
      .prepare(statement)
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        ...values,
      );
  }

  async getUserIdBySubject(subject: string): Promise<string | null> {
    await this.ensureSchema();
    const normalizedSubject = toOptionalTrimmedString(subject);
    if (!normalizedSubject) return null;
    const row = await this.bindScope(
      `SELECT user_id
         FROM identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND subject = ?
        LIMIT 1`,
      [normalizedSubject],
    ).first<D1IdentityLinkRow>();
    return toOptionalTrimmedString(row?.user_id) || null;
  }

  async listSubjectsByUserId(userId: string): Promise<string[]> {
    await this.ensureSchema();
    const normalizedUserId = toOptionalTrimmedString(userId);
    if (!normalizedUserId) return [];
    const result = await this.bindScope(
      `SELECT subject
         FROM identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY created_at_ms ASC`,
      [normalizedUserId],
    ).all<D1IdentityLinkRow>();
    return (result.results || [])
      .map(subjectFromIdentityLinkRow)
      .filter(isPresentString);
  }

  async linkSubjectToUserId(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    await this.ensureSchema();
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const now = this.now().getTime();
    const existing = await this.bindScope(
      `SELECT user_id, created_at_ms
         FROM identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND subject = ?
        LIMIT 1`,
      [subject],
    ).first<D1IdentityLinkRow>();
    const existingUserId = toOptionalTrimmedString(existing?.user_id);
    const existingCreatedAtMs = Number(existing?.created_at_ms);
    const createdAtMs =
      Number.isFinite(existingCreatedAtMs) && existingCreatedAtMs > 0
        ? Math.floor(existingCreatedAtMs)
        : now;

    if (existingUserId && existingUserId !== userId) {
      if (!input.allowMoveIfSoleIdentity) {
        return {
          ok: false,
          code: 'already_linked',
          message: 'Subject is already linked to a different user',
        };
      }
      const moved = d1ChangedRows(
        await this.database
          .prepare(
            `UPDATE identity_links
            SET user_id = ?,
                record_json = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND subject = ?
            AND user_id = ?
            AND (
              SELECT COUNT(*)
                FROM identity_links
               WHERE namespace = ?
                 AND org_id = ?
                 AND project_id = ?
                 AND env_id = ?
                 AND user_id = ?
            ) = 1`,
          )
          .bind(
            userId,
            JSON.stringify(
              buildIdentitySubjectRecord({ subject, userId, createdAtMs, updatedAtMs: now }),
            ),
            now,
            this.scope.namespace,
            this.scope.orgId,
            this.scope.projectId,
            this.scope.envId,
            subject,
            existingUserId,
            this.scope.namespace,
            this.scope.orgId,
            this.scope.projectId,
            this.scope.envId,
            existingUserId,
          )
          .run(),
      );
      if (moved > 0) return { ok: true, movedFromUserId: existingUserId };
      const countRow = await this.bindScope(
        `SELECT COUNT(*) AS subject_count
           FROM identity_links
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?`,
        [existingUserId],
      ).first<D1IdentityLinkRow>();
      if (parseSubjectCount(countRow?.subject_count) !== 1) {
        return {
          ok: false,
          code: 'already_linked',
          message:
            'Subject is linked to a different user with other identities; merge is not allowed',
        };
      }
      return {
        ok: false,
        code: 'already_linked',
        message: 'Subject is already linked to a different user',
      };
    }

    await this.bindScope(
      `INSERT INTO identity_links (
        namespace,
        org_id,
        project_id,
        env_id,
        subject,
        user_id,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, subject)
      DO UPDATE SET
        user_id = EXCLUDED.user_id,
        record_json = EXCLUDED.record_json,
        updated_at_ms = EXCLUDED.updated_at_ms
      WHERE identity_links.user_id = EXCLUDED.user_id`,
      [
        subject,
        userId,
        JSON.stringify(
          buildIdentitySubjectRecord({ subject, userId, createdAtMs, updatedAtMs: now }),
        ),
        createdAtMs,
        now,
      ],
    ).run();
    const finalUserId = await this.getUserIdBySubject(subject);
    if (finalUserId === userId) return { ok: true };
    if (finalUserId) {
      return {
        ok: false,
        code: 'already_linked',
        message: 'Subject is already linked to a different user',
      };
    }
    return { ok: false, code: 'internal', message: 'Failed to link identity' };
  }

  async unlinkSubjectFromUserId(input: {
    userId: string;
    subject: string;
  }): Promise<UnlinkIdentityResult> {
    await this.ensureSchema();
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const deleted = d1ChangedRows(
      await this.database
        .prepare(
          `DELETE FROM identity_links
            WHERE namespace = ?
              AND org_id = ?
              AND project_id = ?
              AND env_id = ?
              AND subject = ?
              AND user_id = ?
              AND (
                SELECT COUNT(*)
                  FROM identity_links
                 WHERE namespace = ?
                   AND org_id = ?
                   AND project_id = ?
                   AND env_id = ?
                   AND user_id = ?
              ) > 1`,
        )
        .bind(
          this.scope.namespace,
          this.scope.orgId,
          this.scope.projectId,
          this.scope.envId,
          subject,
          userId,
          this.scope.namespace,
          this.scope.orgId,
          this.scope.projectId,
          this.scope.envId,
          userId,
        )
        .run(),
    );
    if (deleted > 0) return { ok: true };

    const existingUserId = await this.getUserIdBySubject(subject);
    if (existingUserId !== userId) {
      return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
    }
    const countRow = await this.bindScope(
      `SELECT COUNT(*) AS subject_count
         FROM identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?`,
      [userId],
    ).first<D1IdentityLinkRow>();
    if (parseSubjectCount(countRow?.subject_count) <= 1) {
      return {
        ok: false,
        code: 'cannot_unlink_last_identity',
        message: 'Refusing to remove the last remaining identity',
      };
    }
    return { ok: false, code: 'internal', message: 'Failed to unlink identity' };
  }

  async deleteSubjectLinkForDevCleanup(input: {
    userId: string;
    subject: string;
  }): Promise<UnlinkIdentityResult> {
    await this.ensureSchema();
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };
    const deleted = await this.deleteIdentityLink({ userId, subject });
    if (deleted === 0) {
      return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
    }
    return { ok: true };
  }

  async getAppSessionVersionByUserId(userId: string): Promise<string | null> {
    await this.ensureSchema();
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return null;
    const row = await this.bindScope(
      `SELECT session_version
         FROM app_session_versions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        LIMIT 1`,
      [uid],
    ).first<D1AppSessionVersionRow>();
    return toOptionalTrimmedString(row?.session_version) || null;
  }

  async ensureAppSessionVersionByUserId(userId: string): Promise<string> {
    await this.ensureSchema();
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const now = this.now().getTime();
    const next = generateAppSessionVersion();
    await this.bindScope(
      `INSERT INTO app_session_versions (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        session_version,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, user_id) DO NOTHING`,
      [
        uid,
        next,
        JSON.stringify(
          buildAppSessionVersionRecord({
            userId: uid,
            appSessionVersion: next,
            createdAtMs: now,
            updatedAtMs: now,
          }),
        ),
        now,
        now,
      ],
    ).run();
    return (await this.getAppSessionVersionByUserId(uid)) || next;
  }

  async rotateAppSessionVersionByUserId(userId: string): Promise<string> {
    await this.ensureSchema();
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const now = this.now().getTime();
    const existing = await this.bindScope(
      `SELECT created_at_ms
         FROM app_session_versions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        LIMIT 1`,
      [uid],
    ).first<D1AppSessionVersionRow>();
    const existingCreatedAtMs = Number(existing?.created_at_ms);
    const createdAtMs =
      Number.isFinite(existingCreatedAtMs) && existingCreatedAtMs > 0
        ? Math.floor(existingCreatedAtMs)
        : now;
    const next = generateAppSessionVersion();
    await this.bindScope(
      `INSERT INTO app_session_versions (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        session_version,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, user_id)
      DO UPDATE SET
        session_version = EXCLUDED.session_version,
        record_json = EXCLUDED.record_json,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        uid,
        next,
        JSON.stringify(
          buildAppSessionVersionRecord({
            userId: uid,
            appSessionVersion: next,
            createdAtMs,
            updatedAtMs: now,
          }),
        ),
        createdAtMs,
        now,
      ],
    ).run();
    return next;
  }

  private async deleteIdentityLink(input: {
    readonly userId: string;
    readonly subject: string;
  }): Promise<number> {
    const result = await this.bindScope(
      `DELETE FROM identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND subject = ?
          AND user_id = ?`,
      [input.subject, input.userId],
    ).run();
    return d1ChangedRows(result);
  }
}
