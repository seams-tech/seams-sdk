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
import type {
  LinkedDeviceOwnerAuthorizationContextV1,
  LinkedDeviceSessionRecordV1,
} from './linkedDeviceSession';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import type {
  LinkedDeviceWalletSessionAuthorizationId,
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import type { LaneEnrollmentRevocationResultV1 } from '@shared/signing-lanes';
import type { RevokeLaneEnrollmentV1 } from '@shared/signing-lanes';

export type LinkedDeviceManagementTargetV1 = {
  readonly summary: LinkedDeviceSummaryV1;
  readonly session: LinkedDeviceSessionRecordV1;
  readonly enrollment: LaneEnrollmentAdmissionRecord;
  readonly products: readonly LaneProductEpochRecordV1[];
};

/**
 * Owner Wallet Session authentication has already verified the bearer token at
 * the HTTP boundary. Management receives that exact context so it can bind
 * the mutation to the authenticated wallet without a second D1 lookup.
 */
export type LinkedDeviceManagementOwnerV1 = Pick<
  LinkedDeviceOwnerAuthorizationContextV1,
  'walletId' | 'expiresAtMs'
>;

export type LinkedDeviceManagementProjectionPortV1 = {
  listLinkedDevicesV1(walletId: WalletId): Promise<readonly LinkedDeviceSummaryV1[]>;
  getLinkedDeviceV1(input: {
    readonly walletId: WalletId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<LinkedDeviceManagementTargetV1 | null>;
};

export type LinkedDeviceWalletSessionRevocationTargetV1 = {
  readonly tenantId: TenantId;
  readonly deviceId: LinkedDeviceId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

export type LinkedDeviceRevocationPlanV1 = {
  readonly target: LinkedDeviceManagementTargetV1;
  readonly aggregate: LaneAggregateRevocationRequestV1;
  readonly walletSessions: readonly [
    LinkedDeviceWalletSessionRevocationTargetV1,
    ...LinkedDeviceWalletSessionRevocationTargetV1[],
  ];
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

export type LinkedDeviceManagementServiceOptionsV1 = {
  readonly projection: LinkedDeviceManagementProjectionPortV1;
  readonly preparation: LinkedDeviceRevocationPreparationPortV1;
  readonly aggregateRevocation: LinkedDeviceAggregateRevocationPortV1;
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
    owner: LinkedDeviceManagementOwnerV1,
    requestedAtMs: number,
  ): Promise<LinkedDeviceManagementListResultV1> {
    if (!ownerAuthorizesWalletV1(owner, request.walletId, requestedAtMs)) {
      return { kind: 'unauthorized' };
    }
    const devices = await this.options.projection.listLinkedDevicesV1(request.walletId);
    return { devices };
  }

  async revokeLinkedDeviceV1(
    request: LinkedDeviceRevokeRequestV1,
    owner: LinkedDeviceManagementOwnerV1,
  ): Promise<LinkedDeviceRevokeResultV1> {
    if (!ownerAuthorizesWalletV1(owner, request.walletId, request.requestedAtMs)) {
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

function ownerAuthorizesWalletV1(
  owner: LinkedDeviceManagementOwnerV1,
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
    plan.walletSessions.length === 0 ||
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
