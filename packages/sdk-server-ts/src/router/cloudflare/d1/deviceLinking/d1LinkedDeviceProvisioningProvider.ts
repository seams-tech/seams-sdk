import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceProvisioningCommandV1,
  LinkedDeviceProvisioningDeliveriesV1,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceEnrollmentReceiptV1,
  parseLinkedDeviceProvisioningDeliveriesV1,
} from '@shared/device-linking/parsers';
import { alphabetizeStringify } from '@shared/utils/digests';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type { DeviceLinkingProvisioningProviderV1 } from '../../../transport/fetch/routes/deviceLinking';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from './d1LinkedDeviceSessionStore';

type ProvisioningRowV1 = {
  readonly enrollment_id?: unknown;
  readonly wallet_id?: unknown;
  readonly device_id?: unknown;
  readonly manifest_digest_b64u?: unknown;
  readonly deliveries_json?: unknown;
  readonly aggregate_receipt_json?: unknown;
};

type PersistedProvisioningV1 = {
  readonly enrollmentId: string;
  readonly walletId: string;
  readonly deviceId: string;
  readonly manifestDigestB64u: DigestB64u;
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
  readonly receipt: LinkedDeviceEnrollmentReceiptV1 | null;
};

export type LinkedDeviceR102ProvisioningExecutionPortV1 = {
  prepareProvisioningDeliveriesV1(input: {
    readonly command: LinkedDeviceProvisioningCommandV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceProvisioningDeliveriesV1>;
  recordHolderDeliveriesAndActivateV1(input: {
    readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
    readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceEnrollmentReceiptV1>;
};

const PROVISIONING_TABLE = 'linked_device_provisioning_records';

/** Durable replay boundary around the exact R102 protocol/activation coordinator. */
export class D1LinkedDeviceProvisioningProviderV1 implements DeviceLinkingProvisioningProviderV1 {
  private readonly sessionStore: D1LinkedDeviceSessionStoreV1;

  constructor(
    private readonly input: {
      readonly database: D1DatabaseLike;
      readonly scope: D1LinkedDeviceSessionScopeV1;
      readonly execution: LinkedDeviceR102ProvisioningExecutionPortV1;
    },
  ) {
    this.sessionStore = new D1LinkedDeviceSessionStoreV1({
      database: input.database,
      scope: input.scope,
    });
  }

  async provisionLinkedDeviceV1(input: {
    readonly command: LinkedDeviceProvisioningCommandV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceProvisioningDeliveriesV1> {
    let session = await this.sessionStore.reconcileCommittedProvisioningOutputV1({
      record: input.session,
      nowMs: input.requestedAtMs,
    });
    const persisted = await this.readV1(session.linkSessionId);
    if (persisted) {
      assertPersistedIdentity(persisted, session, input.approval);
      return persisted.deliveries;
    }
    const manifestDigestB64u = requireSessionManifestDigest(session);
    const deliveries = parseLinkedDeviceProvisioningDeliveriesV1(
      await this.input.execution.prepareProvisioningDeliveriesV1({ ...input, session }),
    );
    session = await this.sessionStore.reconcileCommittedProvisioningOutputV1({
      record: session,
      nowMs: input.requestedAtMs,
    });
    if (session.state.state !== 'committed_completion_required') {
      throw new Error('linked-device prepared deliveries did not commit their parent session');
    }
    assertDeliveriesIdentity(deliveries, session, input.approval);
    await this.input.database
      .prepare(
        `INSERT OR IGNORE INTO ${PROVISIONING_TABLE} (
           namespace, org_id, project_id, env_id, link_session_id,
           enrollment_id, wallet_id, device_id, manifest_digest_b64u,
           deliveries_json, created_at_ms, updated_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        ...scopeValues(this.input.scope),
        String(session.linkSessionId),
        String(input.approval.enrollmentId),
        String(input.approval.walletId),
        String(input.approval.deviceId),
        manifestDigestB64u,
        JSON.stringify(deliveries),
        input.requestedAtMs,
        input.requestedAtMs,
      )
      .run();
    const stored = await this.readV1(session.linkSessionId);
    if (!stored) throw new Error('linked-device provisioning deliveries did not persist');
    assertPersistedIdentity(stored, session, input.approval);
    if (alphabetizeStringify(stored.deliveries) !== alphabetizeStringify(deliveries)) {
      throw new Error('linked-device provisioning deliveries conflict with durable replay');
    }
    return stored.deliveries;
  }

  async recordHolderDeliveriesV1(input: {
    readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceEnrollmentReceiptV1> {
    const session = await this.sessionStore.reconcileCommittedProvisioningOutputV1({
      record: input.session,
      nowMs: input.requestedAtMs,
    });
    const persisted = await this.readV1(session.linkSessionId);
    if (!persisted) throw new Error('linked-device provisioning deliveries are missing');
    assertPersistedIdentity(persisted, session, input.approval);
    if (persisted.receipt) return persisted.receipt;
    const receipt = parseLinkedDeviceEnrollmentReceiptV1(
      await this.input.execution.recordHolderDeliveriesAndActivateV1({
        ...input,
        session,
        deliveries: persisted.deliveries,
      }),
    );
    assertReceiptIdentity(receipt, persisted, input.approval);
    await this.input.database
      .prepare(
        `UPDATE ${PROVISIONING_TABLE}
            SET aggregate_receipt_json = ?, updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND aggregate_receipt_json IS NULL
            AND manifest_digest_b64u = ?`,
      )
      .bind(
        JSON.stringify(receipt),
        input.requestedAtMs,
        ...scopeValues(this.input.scope),
        String(session.linkSessionId),
        persisted.manifestDigestB64u,
      )
      .run();
    const stored = await this.readV1(session.linkSessionId);
    if (!stored?.receipt) throw new Error('linked-device aggregate receipt did not persist');
    assertReceiptIdentity(stored.receipt, stored, input.approval);
    if (alphabetizeStringify(stored.receipt) !== alphabetizeStringify(receipt)) {
      throw new Error('linked-device aggregate receipt conflicts with durable replay');
    }
    return stored.receipt;
  }

  private async readV1(linkSessionId: string): Promise<PersistedProvisioningV1 | null> {
    const row = await this.input.database
      .prepare(
        `SELECT enrollment_id, wallet_id, device_id, manifest_digest_b64u,
                deliveries_json, aggregate_receipt_json
           FROM ${PROVISIONING_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? LIMIT 1`,
      )
      .bind(...scopeValues(this.input.scope), linkSessionId)
      .first<ProvisioningRowV1>();
    if (!row) return null;
    const enrollmentId = requiredString(row.enrollment_id, 'enrollment_id');
    const walletId = requiredString(row.wallet_id, 'wallet_id');
    const deviceId = requiredString(row.device_id, 'device_id');
    const manifestDigestB64u = parseDigestB64u(row.manifest_digest_b64u);
    const deliveries = parseLinkedDeviceProvisioningDeliveriesV1(
      JSON.parse(requiredString(row.deliveries_json, 'deliveries_json')),
    );
    const receipt =
      row.aggregate_receipt_json === null || row.aggregate_receipt_json === undefined
        ? null
        : parseLinkedDeviceEnrollmentReceiptV1(
            JSON.parse(requiredString(row.aggregate_receipt_json, 'aggregate_receipt_json')),
          );
    return { enrollmentId, walletId, deviceId, manifestDigestB64u, deliveries, receipt };
  }
}

function requireSessionManifestDigest(session: LinkedDeviceSessionRecordV1): DigestB64u {
  switch (session.state.state) {
    case 'provisioning':
    case 'committed_completion_required':
      return parseDigestB64u(session.state.keyManifestDigestB64u);
    default:
      throw new Error('linked-device session has no admitted R102 manifest digest');
  }
}

function assertPersistedIdentity(
  persisted: PersistedProvisioningV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): void {
  if (
    persisted.enrollmentId !== String(approval.enrollmentId) ||
    persisted.walletId !== String(approval.walletId) ||
    persisted.deviceId !== String(approval.deviceId)
  ) {
    throw new Error('linked-device provisioning replay identity changed');
  }
  assertDeliveriesIdentity(persisted.deliveries, session, approval);
  if (
    (session.state.state === 'provisioning' ||
      session.state.state === 'committed_completion_required') &&
    persisted.manifestDigestB64u !== session.state.keyManifestDigestB64u
  ) {
    throw new Error('linked-device provisioning manifest digest changed');
  }
}

function assertDeliveriesIdentity(
  deliveries: LinkedDeviceProvisioningDeliveriesV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): void {
  if (
    deliveries.linkSessionId !== session.linkSessionId ||
    deliveries.linkSessionId !== approval.linkSessionId ||
    deliveries.enrollmentId !== approval.enrollmentId ||
    deliveries.deviceId !== approval.deviceId ||
    deliveries.orderedChildren.length !== approval.orderedKeyBindings.length
  ) {
    throw new Error('linked-device provisioning deliveries changed identity or coverage');
  }
}

function assertReceiptIdentity(
  receipt: LinkedDeviceEnrollmentReceiptV1,
  persisted: PersistedProvisioningV1,
  approval: LinkedDeviceApprovalV1,
): void {
  if (
    receipt.enrollmentId !== approval.enrollmentId ||
    receipt.walletId !== approval.walletId ||
    receipt.deviceId !== approval.deviceId ||
    receipt.manifestDigestB64u !== persisted.manifestDigestB64u ||
    receipt.orderedChildReceipts.length !== persisted.deliveries.orderedChildren.length
  ) {
    throw new Error('linked-device aggregate receipt changed identity, manifest, or coverage');
  }
}

function scopeValues(
  scope: D1LinkedDeviceSessionScopeV1,
): readonly [string, string, string, string] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is invalid`);
  return value;
}
