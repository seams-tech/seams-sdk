import {
  LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1,
  linkedDeviceEd25519ExportRootMatchesRecipientV1,
  parseLinkedDeviceEd25519ExportRootPackageV1,
  parseLinkedDeviceEd25519ExportRootRecipientV1,
  type LinkedDeviceEd25519ExportRootPackageV1,
  type LinkedDeviceEd25519ExportRootRecipientV1,
} from '@shared/device-linking/ed25519ExportRoot';
import type { LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { queryD1One, d1ChangedRows } from '../../../../storage/d1Sql';
import type { D1DatabaseLike, D1ResultLike } from '../../../../storage/tenantRoute';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import type {
  LinkedDeviceEd25519ExportRootPortV1,
  LinkedDeviceEd25519ExportRootRecordV1,
  LinkedDeviceEd25519ExportRootWriteResultV1,
} from '../../../../core/deviceLinking/linkedDeviceEd25519ExportRoot';

const TRANSFER_TABLE = 'linked_device_ed25519_export_root_transfers';

export class D1LinkedDeviceEd25519ExportRootStoreV1
  implements LinkedDeviceEd25519ExportRootPortV1
{
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;

  constructor(options: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
  }) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
  }

  async registerRecipientV1(input: {
    readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
  }): Promise<LinkedDeviceEd25519ExportRootWriteResultV1> {
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
        String(recipient.linkSessionId),
        String(recipient.walletId),
        String(recipient.enrollmentId),
        String(recipient.deviceId),
        LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1,
        String(recipient.recipientPublicKeyB64u),
        JSON.stringify(recipient),
        recipient.registeredAtMs,
      )
      .run<D1ResultLike>();
    if (d1ChangedRows(inserted) === 1) return { outcome: 'applied' };

    const existing = await this.readRowV1(String(recipient.linkSessionId));
    if (!existing) return { outcome: 'conflict', reason: 'recipient_not_registered' };
    return recipientsMatch(existing.recipient, recipient)
      ? { outcome: 'replayed' }
      : {
          outcome: 'conflict',
          reason: 'recipient_already_registered_with_another_key',
        };
  }

  async submitPackageV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly package: LinkedDeviceEd25519ExportRootPackageV1;
  }): Promise<LinkedDeviceEd25519ExportRootWriteResultV1> {
    const existing = await this.readRowV1(String(input.linkSessionId));
    if (!existing) return { outcome: 'conflict', reason: 'recipient_not_registered' };
    if (!linkedDeviceEd25519ExportRootMatchesRecipientV1(input.package, existing.recipient)) {
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
    const raced = await this.readRowV1(String(input.linkSessionId));
    if (raced?.state === 'sealed' && packagesMatch(raced.package, input.package)) {
      return { outcome: 'replayed' };
    }
    return { outcome: 'conflict', reason: 'package_already_sealed_differently' };
  }

  async readTransferV1(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<LinkedDeviceEd25519ExportRootRecordV1 | null> {
    return await this.readRowV1(String(linkSessionId));
  }

  private async readRowV1(
    linkSessionId: string,
  ): Promise<LinkedDeviceEd25519ExportRootRecordV1 | null> {
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
    const recipient = parseLinkedDeviceEd25519ExportRootRecipientV1(
      JSON.parse(requiredColumn(row, 'recipient_json')),
    );
    if (
      String(recipient.recipientPublicKeyB64u) !==
      requiredColumn(row, 'recipient_public_key_b64u')
    ) {
      throw new Error('linked-device export-root row disagrees with its recipient record');
    }
    const state = requiredColumn(row, 'state');
    if (state === 'recipient_registered') return { state: 'recipient_registered', recipient };
    if (state !== 'sealed') {
      throw new Error('linked-device export-root row has an unsupported state');
    }
    const transferPackage = parseLinkedDeviceEd25519ExportRootPackageV1(
      JSON.parse(requiredColumn(row, 'package_json')),
    );
    if (!linkedDeviceEd25519ExportRootMatchesRecipientV1(transferPackage, recipient)) {
      throw new Error('linked-device export-root package is addressed to another recipient');
    }
    return { state: 'sealed', recipient, package: transferPackage };
  }
}

function recipientsMatch(
  left: LinkedDeviceEd25519ExportRootRecipientV1,
  right: LinkedDeviceEd25519ExportRootRecipientV1,
): boolean {
  return (
    left.linkSessionId === right.linkSessionId &&
    left.walletId === right.walletId &&
    left.walletKeyId === right.walletKeyId &&
    left.enrollmentId === right.enrollmentId &&
    left.deviceId === right.deviceId &&
    left.transferAlg === right.transferAlg &&
    left.applicationBindingDigestB64u === right.applicationBindingDigestB64u &&
    left.registeredPublicKeyB64u === right.registeredPublicKeyB64u &&
    left.targetFactor.kind === right.targetFactor.kind &&
    left.revocationEpoch === right.revocationEpoch &&
    left.recipientPublicKeyB64u === right.recipientPublicKeyB64u
  );
}

function packagesMatch(
  left: LinkedDeviceEd25519ExportRootPackageV1,
  right: LinkedDeviceEd25519ExportRootPackageV1,
): boolean {
  return (
    left.linkSessionId === right.linkSessionId &&
    left.walletId === right.walletId &&
    left.walletKeyId === right.walletKeyId &&
    left.enrollmentId === right.enrollmentId &&
    left.deviceId === right.deviceId &&
    left.applicationBindingDigestB64u === right.applicationBindingDigestB64u &&
    left.registeredPublicKeyB64u === right.registeredPublicKeyB64u &&
    left.targetFactor.kind === right.targetFactor.kind &&
    left.revocationEpoch === right.revocationEpoch &&
    left.recipientPublicKeyB64u === right.recipientPublicKeyB64u &&
    left.ephemeralPublicKeyB64u === right.ephemeralPublicKeyB64u &&
    left.nonceB64u === right.nonceB64u &&
    left.sealedExportRootB64u === right.sealedExportRootB64u &&
    left.bindingDigestB64u === right.bindingDigestB64u &&
    left.ciphertextDigestB64u === right.ciphertextDigestB64u
  );
}

function requiredColumn(row: Record<string, unknown>, name: string): string {
  const value = row[name];
  if (typeof value !== 'string' || !value) {
    throw new Error(`linked-device export-root row is missing ${name}`);
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
    throw new Error(`linked-device export-root ${field} is invalid`);
  }
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}
