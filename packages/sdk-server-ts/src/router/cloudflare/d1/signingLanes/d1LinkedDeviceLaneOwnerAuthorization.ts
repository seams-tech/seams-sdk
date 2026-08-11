import type { RotatableSigningLaneJobV1 } from '@shared/signing-lanes';
import type { PrepareLaneEnrollmentV1 } from '@shared/signing-lanes';
import type {
  DeviceLinkingOwnerWalletSessionContextV1,
} from '../../../transport/fetch/routes/deviceLinkingOwnerAuthorization';

/**
 * D1-owned owner/source projection guard shared by the browser lane route and
 * the in-process R102 provisioning path. The guard has no mutation authority;
 * callers must complete it before invoking a Gateway or protocol committer.
 */
export type D1LinkedDeviceLaneOwnerProjectionGuardV1 = {
  assertActiveOwnerSourceLaneV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly job: RotatableSigningLaneJobV1;
  }): Promise<void>;
};

export function createD1LinkedDeviceLaneOwnerAuthorizationV1(input: {
  readonly projection: D1LinkedDeviceLaneOwnerProjectionGuardV1;
}): D1LinkedDeviceLaneOwnerProjectionGuardV1 & {
  authorizePrepareV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly request: PrepareLaneEnrollmentV1;
  }): Promise<void>;
  authorizeProtocolJobV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly job: RotatableSigningLaneJobV1;
  }): Promise<void>;
} {
  return {
    assertActiveOwnerSourceLaneV1: input.projection.assertActiveOwnerSourceLaneV1,
    async authorizePrepareV1(request) {
      if (request.owner.walletId !== request.request.manifest.walletId) {
        throw new Error('owner Wallet Session walletId does not match enrollment manifest');
      }
      for (const job of request.request.children) {
        await authorizeJobV1(input.projection, request.owner, job);
      }
    },
    async authorizeProtocolJobV1(request) {
      await authorizeJobV1(input.projection, request.owner, request.job);
    },
  };
}

async function authorizeJobV1(
  projection: D1LinkedDeviceLaneOwnerProjectionGuardV1,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  job: RotatableSigningLaneJobV1,
): Promise<void> {
  if (job.walletId !== owner.walletId) {
    throw new Error('owner Wallet Session walletId does not match lane job');
  }
  await projection.assertActiveOwnerSourceLaneV1({ owner, job });
}
