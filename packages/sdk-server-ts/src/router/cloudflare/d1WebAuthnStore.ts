import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../storage/tenantRoute';
import {
  parseWebAuthnAuthenticator,
  parseWebAuthnBinding,
  parseWebAuthnLoginChallengeRecord,
  parseWebAuthnSyncChallengeRecord,
  type D1AuthenticatorRow,
  type D1RecordJsonRow,
  type WebAuthnAuthenticatorRecord,
  type WebAuthnCredentialBindingRecord,
  type WebAuthnLoginChallengeRecord,
  type WebAuthnSyncChallengeRecord,
} from './d1WebAuthnRecords';

type WebAuthnChallengeKind = 'login' | 'sync';

export class CloudflareD1WebAuthnStore {
  private readonly database: D1DatabaseLike;
  private readonly namespace: string;
  private readonly orgId: string;
  private readonly projectId: string;
  private readonly envId: string;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly namespace: string;
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  }) {
    this.database = input.database;
    this.namespace = input.namespace;
    this.orgId = input.orgId;
    this.projectId = input.projectId;
    this.envId = input.envId;
  }

  async writeChallenge(input: {
    readonly challengeId: string;
    readonly challengeKind: WebAuthnChallengeKind;
    readonly record: WebAuthnLoginChallengeRecord | WebAuthnSyncChallengeRecord;
    readonly createdAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<void> {
    await this.prepare(
      `INSERT INTO webauthn_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        challenge_kind,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, challenge_id)
      DO UPDATE SET
        challenge_kind = EXCLUDED.challenge_kind,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        input.challengeId,
        input.challengeKind,
        JSON.stringify(input.record),
        input.createdAtMs,
        input.expiresAtMs,
      ],
    ).run();
  }

  async consumeLoginChallenge(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const row = await this.consumeChallenge({
      challengeId,
      challengeKind: 'login',
    });
    return parseWebAuthnLoginChallengeRecord(row?.record_json);
  }

  async consumeSyncChallenge(challengeId: string): Promise<WebAuthnSyncChallengeRecord | null> {
    const row = await this.consumeChallenge({
      challengeId,
      challengeKind: 'sync',
    });
    return parseWebAuthnSyncChallengeRecord(row?.record_json);
  }

  async readAuthenticator(input: {
    readonly userId: string;
    readonly credentialIdB64u: string;
  }): Promise<WebAuthnAuthenticatorRecord | null> {
    const row = await this.prepare(
      `SELECT credential_id_b64u, credential_public_key_b64u, counter, created_at_ms, updated_at_ms
         FROM webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
          AND credential_id_b64u = ?
        LIMIT 1`,
      [input.userId, input.credentialIdB64u],
    ).first<D1AuthenticatorRow>();
    return parseWebAuthnAuthenticator(row);
  }

  async writeAuthenticator(input: {
    readonly userId: string;
    readonly record: WebAuthnAuthenticatorRecord;
  }): Promise<void> {
    await this.prepare(
      `INSERT INTO webauthn_authenticators (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        credential_id_b64u,
        credential_public_key_b64u,
        counter,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, user_id, credential_id_b64u)
      DO UPDATE SET
        credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
        counter = MAX(webauthn_authenticators.counter, EXCLUDED.counter),
        created_at_ms = MIN(webauthn_authenticators.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = MAX(webauthn_authenticators.updated_at_ms, EXCLUDED.updated_at_ms)`,
      [
        input.userId,
        input.record.credentialIdB64u,
        input.record.credentialPublicKeyB64u,
        input.record.counter,
        input.record.createdAtMs,
        input.record.updatedAtMs,
      ],
    ).run();
  }

  async updateAuthenticatorCounter(input: {
    readonly userId: string;
    readonly credentialIdB64u: string;
    readonly newCounter: number;
    readonly updatedAtMs: number;
  }): Promise<void> {
    await this.database
      .prepare(
        `UPDATE webauthn_authenticators
          SET counter = ?,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
          AND credential_id_b64u = ?
          AND counter < ?`,
      )
      .bind(
        input.newCounter,
        input.updatedAtMs,
        this.namespace,
        this.orgId,
        this.projectId,
        this.envId,
        input.userId,
        input.credentialIdB64u,
        input.newCounter,
      )
      .run();
  }

  async readBindingByCredential(input: {
    readonly rpId: string;
    readonly credentialIdB64u: string;
  }): Promise<WebAuthnCredentialBindingRecord | null> {
    const row = await this.prepare(
      `SELECT record_json
         FROM webauthn_credential_bindings
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND rp_id = ?
          AND credential_id_b64u = ?
        LIMIT 1`,
      [input.rpId, input.credentialIdB64u],
    ).first<D1RecordJsonRow>();
    return parseWebAuthnBinding(row || {});
  }

  async readAuthenticatorRows(userId: string): Promise<D1AuthenticatorRow[]> {
    const result = await this.prepare(
      `SELECT credential_id_b64u, created_at_ms, updated_at_ms
         FROM webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY created_at_ms ASC`,
      [userId],
    ).all<D1AuthenticatorRow>();
    return [...(result.results || [])];
  }

  async readBindingRows(input: {
    readonly userId: string;
    readonly rpId?: string;
  }): Promise<WebAuthnCredentialBindingRecord[]> {
    const rpId = toOptionalTrimmedString(input.rpId);
    const sql = rpId
      ? `SELECT record_json
           FROM webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
            AND rp_id = ?
          ORDER BY signer_slot ASC`
      : `SELECT record_json
           FROM webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY signer_slot ASC`;
    const values = rpId ? [input.userId, rpId] : [input.userId];
    const result = await this.prepare(sql, values).all<D1RecordJsonRow>();
    const bindings: WebAuthnCredentialBindingRecord[] = [];
    for (const row of result.results || []) {
      const binding = parseWebAuthnBinding(row);
      if (binding) bindings.push(binding);
    }
    return bindings;
  }

  private async consumeChallenge(input: {
    readonly challengeId: string;
    readonly challengeKind: WebAuthnChallengeKind;
  }): Promise<D1RecordJsonRow | null> {
    return await this.prepare(
      `DELETE FROM webauthn_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
          AND challenge_kind = ?
          AND expires_at_ms > ?
        RETURNING record_json`,
      [input.challengeId, input.challengeKind, Date.now()],
    ).first<D1RecordJsonRow>();
  }

  private prepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.database
      .prepare(sql)
      .bind(this.namespace, this.orgId, this.projectId, this.envId, ...values);
  }
}
