import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletId } from '@shared/utils/domainIds';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { LinkedDeviceLocalStateInvalidationPortV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type {
  LinkedDeviceManagementProjectionPortV1,
  LinkedDeviceManagementTargetV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';

export type D1LinkedDeviceLocalStateInvalidationOptionsV1 = {
  /** D1-backed projection; reads are authoritative for admission state. */
  readonly projection: Pick<LinkedDeviceManagementProjectionPortV1, 'getLinkedDeviceV1'>;
};

/**
 * Confirms that D1 has durably revoked the exact linked enrollment before
 * acknowledging local-state invalidation. This architecture has no separate
 * server admission cache, so a successful confirmation is an idempotent
 * replay of the already-persisted D1 transition.
 */
export class D1LinkedDeviceLocalStateInvalidationV1 implements LinkedDeviceLocalStateInvalidationPortV1 {
  private readonly projection: D1LinkedDeviceLocalStateInvalidationOptionsV1['projection'];

  constructor(options: D1LinkedDeviceLocalStateInvalidationOptionsV1) {
    this.projection = options.projection;
  }

  async invalidateLinkedDeviceStateV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
    readonly revocationEpoch: number;
    readonly aggregateReceiptDigestB64u: DigestB64u;
    readonly requestedAtMs: number;
  }): Promise<{ readonly kind: 'applied' | 'replayed' | 'conflict' }> {
    const target = await this.projection.getLinkedDeviceV1({
      walletId: input.walletId,
      deviceId: input.deviceId,
    });
    if (!target || !matchesIdentity(target, input)) return { kind: 'conflict' };
    if (!matchesRevokedD1State(target, input)) return { kind: 'conflict' };
    return { kind: 'replayed' };
  }
}

function matchesIdentity(
  target: LinkedDeviceManagementTargetV1,
  input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  },
): boolean {
  return (
    target.summary.walletId === input.walletId &&
    target.summary.deviceId === input.deviceId &&
    String(target.summary.enrollmentId) === String(input.enrollmentId) &&
    target.enrollment.value.manifest.walletId === input.walletId &&
    String(target.enrollment.value.manifest.enrollmentId) === String(input.enrollmentId) &&
    target.products.length > 0
  );
}

function matchesRevokedD1State(
  target: LinkedDeviceManagementTargetV1,
  input: {
    readonly walletId: WalletId;
    readonly revocationEpoch: number;
    readonly aggregateReceiptDigestB64u: DigestB64u;
    readonly requestedAtMs: number;
  },
): boolean {
  const lifecycle = target.enrollment.value.lifecycle;
  if (
    lifecycle.state !== 'revoked' ||
    lifecycle.aggregateRevocationReceiptDigestB64u !== input.aggregateReceiptDigestB64u ||
    lifecycle.revokedAtMs !== input.requestedAtMs
  ) {
    return false;
  }
  return target.products.every(
    (product) =>
      product.state === 'revoked' &&
      product.revocationEpoch === input.revocationEpoch &&
      product.walletId === input.walletId &&
      String(product.enrollmentId) === String(target.summary.enrollmentId) &&
      product.revocationReceiptDigestB64u.length > 0,
  );
}
