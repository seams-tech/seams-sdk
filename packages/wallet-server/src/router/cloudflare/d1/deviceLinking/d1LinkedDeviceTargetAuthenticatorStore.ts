import type {
  WebAuthnAuthenticatorRecord,
  WebAuthnAuthenticatorStore,
} from '../../../../core/WebAuthnAuthenticatorStore';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import { d1ChangedRows } from '../../../../storage/d1Sql';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';

type TargetAuthenticatorRowV1 = {
  readonly credential_id_b64u?: unknown;
  readonly credential_public_key_b64u?: unknown;
  readonly credential_counter?: unknown;
  readonly registered_at_ms?: unknown;
};

type TargetIdentityV1 = {
  readonly enrollmentId: string;
  readonly deviceId: string;
};

const TARGET_CREDENTIAL_TABLE = 'linked_device_target_credentials';

export class D1LinkedDeviceTargetAuthenticatorStoreV1
  implements WebAuthnAuthenticatorStore
{
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly target: TargetIdentityV1;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
    readonly enrollmentId: string;
    readonly deviceId: string;
  }) {
    this.database = input.database;
    this.scope = input.scope;
    this.target = {
      enrollmentId: requiredText(input.enrollmentId, 'enrollmentId'),
      deviceId: requiredText(input.deviceId, 'deviceId'),
    };
  }

  async get(userId: string, credentialIdB64u: string): Promise<WebAuthnAuthenticatorRecord | null> {
    if (userId !== `linked-device:${this.target.deviceId}`) return null;
    const credentialId = parseWebAuthnCredentialIdB64u(credentialIdB64u);
    if (!credentialId.ok) return null;
    const row = await this.readRegisteredRow({
      walletId: null,
      credentialIdB64u: credentialId.value,
    });
    return row ? parseTargetAuthenticatorRow(row) : null;
  }

  async put(userId: string, record: WebAuthnAuthenticatorRecord): Promise<void> {
    if (userId !== `linked-device:${this.target.deviceId}`) {
      throw new Error('linked-device authenticator user changed');
    }
    const current = await this.get(userId, record.credentialIdB64u);
    if (
      !current ||
      current.credentialPublicKeyB64u !== record.credentialPublicKeyB64u ||
      record.counter < current.counter
    ) {
      throw new Error('linked-device authenticator counter update is invalid');
    }
    if (record.counter === current.counter) return;
    const result = await this.database
      .prepare(
        `UPDATE ${TARGET_CREDENTIAL_TABLE}
            SET credential_counter = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND enrollment_id = ? AND device_id = ? AND state = 'registered'
            AND credential_id_b64u = ? AND credential_public_key_b64u = ?
            AND credential_counter = ?`,
      )
      .bind(
        record.counter,
        ...scopeValues(this.scope),
        this.target.enrollmentId,
        this.target.deviceId,
        record.credentialIdB64u,
        record.credentialPublicKeyB64u,
        current.counter,
      )
      .run();
    if (d1ChangedRows(result) !== 1) {
      throw new Error('linked-device authenticator counter changed concurrently');
    }
  }

  async del(): Promise<void> {
    throw new Error('linked-device authenticators are retired through enrollment revocation');
  }

  private async readRegisteredRow(input: {
    readonly walletId: string | null;
    readonly credentialIdB64u: string | null;
  }): Promise<TargetAuthenticatorRowV1 | null> {
    const walletClause = input.walletId === null ? '' : ' AND wallet_id = ?';
    const credentialClause = input.credentialIdB64u === null ? '' : ' AND credential_id_b64u = ?';
    const bindings: unknown[] = [
      ...scopeValues(this.scope),
      this.target.enrollmentId,
      this.target.deviceId,
    ];
    if (input.walletId !== null) bindings.push(input.walletId);
    if (input.credentialIdB64u !== null) bindings.push(input.credentialIdB64u);
    return await this.database
      .prepare(
        `SELECT credential_id_b64u, credential_public_key_b64u,
                credential_counter, registered_at_ms
           FROM ${TARGET_CREDENTIAL_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND enrollment_id = ? AND device_id = ? AND state = 'registered'
            ${walletClause}${credentialClause}
          LIMIT 1`,
      )
      .bind(...bindings)
      .first<TargetAuthenticatorRowV1>();
  }
}

function parseTargetAuthenticatorRow(row: TargetAuthenticatorRowV1): WebAuthnAuthenticatorRecord {
  const credentialId = parseWebAuthnCredentialIdB64u(row.credential_id_b64u);
  if (!credentialId.ok) throw new Error(credentialId.error.message);
  const publicKey = requiredText(row.credential_public_key_b64u, 'credential public key');
  const counter = requiredNonnegativeInteger(row.credential_counter, 'credential counter');
  const registeredAtMs = requiredPositiveInteger(row.registered_at_ms, 'registeredAtMs');
  return {
    version: 'webauthn_authenticator_v1',
    credentialIdB64u: credentialId.value,
    credentialPublicKeyB64u: publicKey,
    counter,
    createdAtMs: registeredAtMs,
    updatedAtMs: registeredAtMs,
    /* The signing-only target registration captures no server-derived device
       metadata, and Refactor 103B deliberately does not add any to it. */
    deviceInfo: unknownWebAuthnAuthenticatorDeviceInfo(),
  };
}

function requiredText(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  return value.trim();
}

function requiredNonnegativeInteger(value: unknown, label: string): number {
  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(numeric) || numeric < 0) throw new Error(`${label} is invalid`);
  return numeric;
}

function requiredPositiveInteger(value: unknown, label: string): number {
  const numeric = requiredNonnegativeInteger(value, label);
  if (numeric <= 0) throw new Error(`${label} is invalid`);
  return numeric;
}

function scopeValues(
  scope: D1LinkedDeviceSessionScopeV1,
): readonly [string, string, string, string] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}
