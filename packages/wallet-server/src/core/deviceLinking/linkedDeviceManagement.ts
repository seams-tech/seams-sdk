import type {
  LinkedDeviceListRequestV1,
  LinkedDeviceListResultV1,
  LinkedDeviceRevokeRequestV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
} from '@shared/device-linking/contracts';
import { computeAggregateLaneRevocationReceiptDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { LaneProductEpochRecordV1 } from '@shared/signing-lanes';
import type { LaneEnrollmentAdmissionRecord } from '../signingLanes/LaneLifecycleStore';
import type { LaneAggregateRevocationRequestV1 } from '../signingLanes/LaneAggregateRevocationApplicationService';
import { parseLinkedDeviceId } from '@shared/signing-lanes/ids';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import type { LaneEnrollmentRevocationResultV1 } from '@shared/signing-lanes';
import type { RevokeLaneEnrollmentV1 } from '@shared/signing-lanes';
import {
  hasDelegatedWalletPermissionV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';

export type LinkedDeviceManagementTargetV1 = {
  readonly summary: LinkedDeviceSummaryV1;
  readonly enrollment: LaneEnrollmentAdmissionRecord;
  readonly products: readonly LaneProductEpochRecordV1[];
};

export type LinkedDeviceManagementListCursorV1 = {
  readonly kind: 'owner_binding_v1';
  readonly updatedAtMs: number;
  readonly deviceId: LinkedDeviceId;
};

export class LinkedDeviceListCursorError extends Error {
  readonly kind = 'linked_device_list_cursor_error_v1';
}

export const MAX_LINKED_DEVICE_LIST_LIMIT_V1 = 50;

/**
 * Owner Wallet Session authentication has already verified the bearer token at
 * the HTTP boundary. Management receives that exact context so it can bind
 * the mutation to the authenticated wallet without a second D1 lookup.
 */
export type LinkedDeviceManagementOwnerV1 = {
  readonly walletId: WalletId;
  readonly expiresAtMs: number;
  readonly permission: DelegatedWalletAuthorityV1;
};

export type LinkedDeviceManagementListPrincipalV1 = Pick<
  LinkedDeviceManagementOwnerV1,
  'walletId' | 'expiresAtMs' | 'permission'
>;

export type LinkedDeviceManagementProjectionPortV1 = {
  listLinkedDevicesV1(input: {
    readonly walletId: WalletId;
    readonly limit: number;
    readonly cursor: LinkedDeviceManagementListCursorV1 | null;
  }): Promise<LinkedDeviceListResultV1>;
  getLinkedDeviceV1(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<LinkedDeviceManagementTargetV1 | null>;
};

export type LinkedDeviceWalletSessionRevocationTargetV1 = {
  readonly tenantId: TenantId;
  readonly deviceId: LinkedDeviceId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

export type LinkedDeviceRevocationPlanV1 = {
  readonly target: LinkedDeviceManagementTargetV1;
  readonly aggregate: LaneAggregateRevocationRequestV1;
  readonly walletSessions: readonly LinkedDeviceWalletSessionRevocationTargetV1[];
  readonly revocationEpoch: number;
};

export type LinkedDeviceRevocationPreparationResultV1 =
  | { readonly kind: 'prepared'; readonly plan: LinkedDeviceRevocationPlanV1 }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'conflict' };

/** Resolves the exact manifest-ordered revoke plan from the persisted target. */
export type LinkedDeviceRevocationPreparationPortV1 = {
  prepareLinkedDeviceRevocationV1(input: {
    readonly target: LinkedDeviceManagementTargetV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceRevocationPreparationResultV1>;
};

export type LinkedDeviceAggregateRevocationPortV1 = {
  /** Persist the enrollment fence before revoking any child authorization. */
  fenceLaneEnrollmentV1(
    input: RevokeLaneEnrollmentV1,
  ): Promise<{ readonly kind: 'applied' | 'replayed' | 'conflict' }>;
  revokeLaneEnrollmentV1(
    input: LaneAggregateRevocationRequestV1,
  ): Promise<LaneEnrollmentRevocationResultV1>;
};

export type LinkedDeviceWalletSessionRevocationPortV1 = {
  revokeLinkedDeviceWalletSessionV1(input: {
    readonly target: LinkedDeviceWalletSessionRevocationTargetV1;
    readonly requestedAtMs: number;
  }): Promise<{ readonly kind: 'applied' | 'replayed' | 'conflict' }>;
};

export type LinkedDeviceLocalStateInvalidationPortV1 = {
  invalidateLinkedDeviceStateV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
    readonly revocationEpoch: number;
    readonly aggregateReceiptDigestB64u: DigestB64u;
    readonly requestedAtMs: number;
  }): Promise<{ readonly kind: 'applied' | 'replayed' | 'conflict' }>;
};

export type LinkedDeviceOwnerCredentialRevocationPortV1 = {
  revokeLinkedDeviceOwnerCredentialV1(input: {
    readonly target: LinkedDeviceManagementTargetV1;
    readonly owner: LinkedDeviceManagementOwnerV1;
    readonly requestedAtMs: number;
  }): Promise<{ readonly kind: 'applied' | 'replayed' | 'conflict' }>;
};

export type LinkedDeviceManagementServiceOptionsV1 = {
  readonly projection: LinkedDeviceManagementProjectionPortV1;
  readonly preparation: LinkedDeviceRevocationPreparationPortV1;
  readonly aggregateRevocation: LinkedDeviceAggregateRevocationPortV1;
  readonly ownerCredentialRevocation: LinkedDeviceOwnerCredentialRevocationPortV1;
  readonly walletSessionRevocation: LinkedDeviceWalletSessionRevocationPortV1;
  readonly localStateInvalidation: LinkedDeviceLocalStateInvalidationPortV1;
};

export type LinkedDeviceManagementListResultV1 =
  | LinkedDeviceListResultV1
  | { readonly kind: 'unauthorized' };

export class LinkedDeviceManagementServiceV1 {
  constructor(private readonly options: LinkedDeviceManagementServiceOptionsV1) {}

  async listLinkedDevicesV1(
    request: LinkedDeviceListRequestV1,
    owner: LinkedDeviceManagementListPrincipalV1,
    requestedAtMs: number,
  ): Promise<LinkedDeviceManagementListResultV1> {
    if (!ownerAuthorizesWalletV1(owner, request.walletId, requestedAtMs)) {
      return { kind: 'unauthorized' };
    }
    if (
      !hasDelegatedWalletPermissionV1(owner.permission, 'link_devices') &&
      !hasDelegatedWalletPermissionV1(owner.permission, 'revoke_devices')
    ) {
      return { kind: 'unauthorized' };
    }
    if (
      !Number.isSafeInteger(request.limit) ||
      request.limit < 1 ||
      request.limit > MAX_LINKED_DEVICE_LIST_LIMIT_V1
    ) {
      throw new Error('linked-device list limit is invalid');
    }
    return await this.options.projection.listLinkedDevicesV1({
      walletId: request.walletId,
      limit: request.limit,
      cursor: decodeLinkedDeviceListCursorV1(request.cursor),
    });
  }

  async revokeLinkedDeviceV1(
    request: LinkedDeviceRevokeRequestV1,
    owner: LinkedDeviceManagementOwnerV1,
  ): Promise<LinkedDeviceRevokeResultV1> {
    if (!ownerAuthorizesWalletV1(owner, request.walletId, request.requestedAtMs)) {
      return { kind: 'unauthorized' };
    }
    if (!hasDelegatedWalletPermissionV1(owner.permission, 'revoke_devices')) {
      return { kind: 'unauthorized' };
    }

    const target = await this.options.projection.getLinkedDeviceV1({
      walletId: request.walletId,
      deviceId: request.deviceId,
    });
    if (!target) return { kind: 'not_found' };
    const prepared = await this.options.preparation.prepareLinkedDeviceRevocationV1({
      target,
      requestedAtMs: request.requestedAtMs,
    });
    if (prepared.kind === 'not_found' || prepared.kind === 'conflict') return prepared;
    assertRevocationPlanMatchesRequest(prepared.plan, request);

    const ownerCredential =
      await this.options.ownerCredentialRevocation.revokeLinkedDeviceOwnerCredentialV1({
        target: prepared.plan.target,
        owner,
        requestedAtMs: request.requestedAtMs,
      });
    if (ownerCredential.kind === 'conflict') return { kind: 'conflict' };

    const fence = await this.options.aggregateRevocation.fenceLaneEnrollmentV1(
      prepared.plan.aggregate.command,
    );
    if (fence.kind === 'conflict') return { kind: 'conflict' };

    for (const target of prepared.plan.walletSessions) {
      const walletSession =
        await this.options.walletSessionRevocation.revokeLinkedDeviceWalletSessionV1({
          target,
          requestedAtMs: request.requestedAtMs,
        });
      if (walletSession.kind === 'conflict') return { kind: 'conflict' };
    }
    const aggregate = await this.options.aggregateRevocation.revokeLaneEnrollmentV1(
      prepared.plan.aggregate,
    );
    if (aggregate.outcome === 'conflict') return { kind: 'conflict' };
    assertAggregateRevocationMatchesPlan(aggregate, prepared.plan, request);
    const aggregateReceiptDigestB64u = parseDigestB64u(
      await computeAggregateLaneRevocationReceiptDigestV1(aggregate.receipt),
    );
    const local = await this.options.localStateInvalidation.invalidateLinkedDeviceStateV1({
      walletId: request.walletId,
      enrollmentId: prepared.plan.target.summary.enrollmentId,
      deviceId: request.deviceId,
      revocationEpoch: prepared.plan.revocationEpoch,
      aggregateReceiptDigestB64u,
      requestedAtMs: request.requestedAtMs,
    });
    if (local.kind === 'conflict') return { kind: 'conflict' };
    return {
      kind: aggregate.outcome === 'applied' ? 'revoked' : 'replayed',
      enrollmentId: prepared.plan.target.summary.enrollmentId,
      revocationEpoch: prepared.plan.revocationEpoch,
      aggregateReceiptDigestB64u,
    };
  }
}

export function encodeLinkedDeviceListCursorV1(cursor: LinkedDeviceManagementListCursorV1): string {
  if (!Number.isSafeInteger(cursor.updatedAtMs) || cursor.updatedAtMs < 0) {
    throw new LinkedDeviceListCursorError('linked-device list cursor timestamp is invalid');
  }
  if (cursor.kind !== 'owner_binding_v1') {
    throw new LinkedDeviceListCursorError('linked-device list cursor kind is invalid');
  }
  const deviceId = parseLinkedDeviceId(String(cursor.deviceId));
  if (!deviceId.ok) {
    throw new LinkedDeviceListCursorError('linked-device list cursor device id is invalid');
  }
  const encoded = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        kind: cursor.kind,
        updatedAtMs: cursor.updatedAtMs,
        deviceId: String(deviceId.value),
      }),
    ),
  );
  return encoded;
}

export function decodeLinkedDeviceListCursorV1(
  raw: string | null,
): LinkedDeviceManagementListCursorV1 | null {
  if (raw === null) return null;
  try {
    const decoded = new TextDecoder().decode(base64UrlDecode(raw));
    const record: unknown = JSON.parse(decoded);
    if (!isLinkedDeviceListCursorRecordV1(record)) {
      throw new Error('invalid cursor shape');
    }
    if (record.kind !== 'owner_binding_v1') {
      throw new Error('invalid cursor kind');
    }
    if (
      typeof record.updatedAtMs !== 'number' ||
      !Number.isSafeInteger(record.updatedAtMs) ||
      record.updatedAtMs < 0
    ) {
      throw new Error('invalid cursor timestamp');
    }
    const deviceId = parseLinkedDeviceId(record.deviceId);
    if (!deviceId.ok) throw new Error('invalid cursor device id');
    const cursor = {
      kind: 'owner_binding_v1',
      updatedAtMs: record.updatedAtMs,
      deviceId: deviceId.value,
    } satisfies LinkedDeviceManagementListCursorV1;
    if (encodeLinkedDeviceListCursorV1(cursor) !== raw) {
      throw new Error('non-canonical cursor');
    }
    return cursor;
  } catch {
    throw new LinkedDeviceListCursorError('linked-device list cursor is invalid');
  }
}

function isLinkedDeviceListCursorRecordV1(
  raw: unknown,
): raw is { readonly kind: unknown; readonly updatedAtMs: unknown; readonly deviceId: unknown } {
  return (
    typeof raw === 'object' &&
    raw !== null &&
    !Array.isArray(raw) &&
    Object.keys(raw).sort().join(',') === 'deviceId,kind,updatedAtMs' &&
    'kind' in raw &&
    'updatedAtMs' in raw &&
    'deviceId' in raw
  );
}

function ownerAuthorizesWalletV1(
  owner: LinkedDeviceManagementListPrincipalV1,
  walletId: WalletId,
  requestedAtMs: number,
): boolean {
  return owner.walletId === walletId && owner.expiresAtMs > requestedAtMs;
}

function assertRevocationPlanMatchesRequest(
  plan: LinkedDeviceRevocationPlanV1,
  request: LinkedDeviceRevokeRequestV1,
): void {
  if (
    plan.target.summary.walletId !== request.walletId ||
    plan.target.summary.deviceId !== request.deviceId ||
    plan.aggregate.command.walletId !== request.walletId ||
    String(plan.aggregate.command.enrollmentId) !== String(plan.target.summary.enrollmentId) ||
    plan.aggregate.command.requestedAtMs !== request.requestedAtMs ||
    plan.walletSessions.some((session) => session.deviceId !== request.deviceId) ||
    plan.revocationEpoch < 1
  ) {
    throw new Error('linked-device revocation plan does not match its target');
  }
}

function assertAggregateRevocationMatchesPlan(
  result: Exclude<LaneEnrollmentRevocationResultV1, { readonly outcome: 'conflict' }>,
  plan: LinkedDeviceRevocationPlanV1,
  request: LinkedDeviceRevokeRequestV1,
): void {
  if (
    String(result.enrollmentId) !== String(plan.target.summary.enrollmentId) ||
    String(result.receipt.enrollmentId) !== String(result.enrollmentId) ||
    result.receipt.walletId !== request.walletId ||
    result.receipt.revokedAtMs !== request.requestedAtMs ||
    result.productEpochs.some((product) => product.revocationEpoch !== plan.revocationEpoch)
  ) {
    throw new Error('linked-device aggregate revocation result does not match its plan');
  }
}
