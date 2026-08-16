import {
  LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
  linkedDeviceCustodyTransferMatchesRecipientV1,
  parseLinkedDeviceCustodyTransferPackageV1,
  parseLinkedDeviceCustodyTransferRecipientV1,
  type LinkedDeviceCustodyTransferPackageV1,
  type LinkedDeviceCustodyTransferRecipientV1,
} from '@shared/device-linking/custodyTransfer';
import type { LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { queryD1One } from '../../../../storage/d1Sql';
import { d1ChangedRows } from '../../../../storage/d1Sql';
import type { D1DatabaseLike, D1ResultLike } from '../../../../storage/tenantRoute';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';

import type {
  LinkedDeviceCustodyTransferPortV1,
  LinkedDeviceCustodyTransferRecordV1,
  LinkedDeviceCustodyTransferWriteResultV1,
} from '../../../../core/deviceLinking/linkedDeviceCustodyTransfer';

const TRANSFER_TABLE = 'linked_device_custody_transfers';

export class D1LinkedDeviceCustodyTransferStoreV1 implements LinkedDeviceCustodyTransferPortV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;

  constructor(options: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
  }) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
  }

  /**
   * Device 2 publishes the key Device 1 will seal to.
   *
   * The registration is immutable: Device 1 seals to whatever this row says,
   * so a second registration naming a different key would redirect a seed that
   * may already be in flight. An identical repeat is a relay retry and
   * succeeds.
   */
  async registerRecipientV1(input: {
    readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
  }): Promise<LinkedDeviceCustodyTransferWriteResultV1> {
    const recipient = input.recipient;
    const inserted = await this.database
      .prepare(
        `INSERT OR IGNORE INTO ${TRANSFER_TABLE} (
           namespace, org_id, project_id, env_id, link_session_id,
           wallet_id, enrollment_id, device_id, state, transfer_alg,
           recipient_public_key_b64u, recipient_json, registered_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'recipient_registered', ?9, ?10, ?11, ?12)`,
      )
      .bind(
        ...scopeValues(this.scope),
        recipient.linkSessionId,
        String(recipient.walletId),
        String(recipient.enrollmentId),
        String(recipient.deviceId),
        LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
        String(recipient.recipientPublicKeyB64u),
        JSON.stringify(recipient),
        recipient.registeredAtMs,
      )
      .run<D1ResultLike>();
    if (d1ChangedRows(inserted) === 1) return { outcome: 'applied' };

    const existing = await this.readRowV1(recipient.linkSessionId);
    if (!existing) return { outcome: 'conflict', reason: 'recipient_not_registered' };
    return recipientsMatch(existing.recipient, recipient)
      ? { outcome: 'replayed' }
      : { outcome: 'conflict', reason: 'recipient_already_registered_with_another_key' };
  }

  /**
   * Device 1 returns the sealed package.
   *
   * Compare-and-set from `recipient_registered`, so a package cannot land
   * before a recipient exists and two different seals cannot both take effect.
   * The recipient key is matched first so a misaddressed package reports which
   * identity disagreed rather than failing as an opaque constraint violation.
   */
  async submitPackageV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly package: LinkedDeviceCustodyTransferPackageV1;
  }): Promise<LinkedDeviceCustodyTransferWriteResultV1> {
    const existing = await this.readRowV1(String(input.linkSessionId));
    if (!existing) return { outcome: 'conflict', reason: 'recipient_not_registered' };
    if (!linkedDeviceCustodyTransferMatchesRecipientV1(input.package, existing.recipient)) {
      return { outcome: 'conflict', reason: 'package_addressed_to_another_recipient' };
    }
    if (existing.state === 'sealed') {
      return packagesMatch(existing.package, input.package)
        ? { outcome: 'replayed' }
        : { outcome: 'conflict', reason: 'package_already_sealed_differently' };
    }
    const updated = await this.database
      .prepare(
        `UPDATE ${TRANSFER_TABLE}
            SET state = 'sealed',
                package_json = ?6,
                ephemeral_public_key_b64u = ?7,
                ciphertext_digest_b64u = ?8,
                sealed_at_ms = ?9
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND link_session_id = ?5
            AND state = 'recipient_registered'`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(input.linkSessionId),
        JSON.stringify(input.package),
        String(input.package.ephemeralPublicKeyB64u),
        String(input.package.ciphertextDigestB64u),
        input.package.sealedAtMs,
      )
      .run<D1ResultLike>();
    if (d1ChangedRows(updated) === 1) return { outcome: 'applied' };
    // Another seal won the race between the read above and this write.
    const raced = await this.readRowV1(String(input.linkSessionId));
    if (raced?.state === 'sealed' && packagesMatch(raced.package, input.package)) {
      return { outcome: 'replayed' };
    }
    return { outcome: 'conflict', reason: 'package_already_sealed_differently' };
  }

  async readTransferV1(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<LinkedDeviceCustodyTransferRecordV1 | null> {
    return await this.readRowV1(String(linkSessionId));
  }

  private async readRowV1(
    linkSessionId: string,
  ): Promise<LinkedDeviceCustodyTransferRecordV1 | null> {
    const row = await queryD1One(
      this.database,
      `SELECT state, recipient_public_key_b64u, recipient_json, package_json
         FROM ${TRANSFER_TABLE}
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND link_session_id = ?5
        LIMIT 1`,
      [...scopeValues(this.scope), linkSessionId],
    );
    if (!row) return null;
    const recipient = parseLinkedDeviceCustodyTransferRecipientV1(
      JSON.parse(requiredColumn(row, 'recipient_json')),
    );
    if (
      String(recipient.recipientPublicKeyB64u) !==
      requiredColumn(row, 'recipient_public_key_b64u')
    ) {
      throw new Error('linked-device custody transfer row disagrees with its recipient record');
    }
    const state = requiredColumn(row, 'state');
    if (state === 'recipient_registered') return { state: 'recipient_registered', recipient };
    if (state !== 'sealed') {
      throw new Error('linked-device custody transfer row has an unsupported state');
    }
    const transferPackage = parseLinkedDeviceCustodyTransferPackageV1(
      JSON.parse(requiredColumn(row, 'package_json')),
    );
    if (!linkedDeviceCustodyTransferMatchesRecipientV1(transferPackage, recipient)) {
      throw new Error('linked-device custody transfer package is addressed to another recipient');
    }
    return { state: 'sealed', recipient, package: transferPackage };
  }
}

function recipientsMatch(
  left: LinkedDeviceCustodyTransferRecipientV1,
  right: LinkedDeviceCustodyTransferRecipientV1,
): boolean {
  return (
    left.linkSessionId === right.linkSessionId &&
    left.walletId === right.walletId &&
    left.enrollmentId === right.enrollmentId &&
    left.deviceId === right.deviceId &&
    left.recipientPublicKeyB64u === right.recipientPublicKeyB64u
  );
}

function packagesMatch(
  left: LinkedDeviceCustodyTransferPackageV1,
  right: LinkedDeviceCustodyTransferPackageV1,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.enrollmentId === right.enrollmentId &&
    left.deviceId === right.deviceId &&
    left.recipientPublicKeyB64u === right.recipientPublicKeyB64u &&
    left.ephemeralPublicKeyB64u === right.ephemeralPublicKeyB64u &&
    left.nonceB64u === right.nonceB64u &&
    left.sealedCustodySecretB64u === right.sealedCustodySecretB64u &&
    left.aadHashB64u === right.aadHashB64u &&
    left.ciphertextDigestB64u === right.ciphertextDigestB64u
  );
}

function requiredColumn(row: Record<string, unknown>, name: string): string {
  const value = row[name];
  if (typeof value !== 'string' || !value) {
    throw new Error(`linked-device custody transfer row is missing ${name}`);
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
    throw new Error(`linked-device custody transfer ${field} is invalid`);
  }
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}
