import type { RotatableSigningLaneJobV1 } from '@shared/signing-lanes';
import type { PrepareLaneEnrollmentV1 } from '@shared/signing-lanes';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type {
  DeviceLinkingOwnerWalletSessionContextV1,
} from '../../../transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import type { LaneEnrollmentGatewayV1 } from '@shared/signing-lanes';
import type {
  DeviceLinkingLaneGatewayRequestV1,
  DeviceLinkingLaneGatewayResponseV1,
  DeviceLinkingLaneGatewayRouteServiceV1,
  DeviceLinkingLaneProtocolCommitRequestV1,
  DeviceLinkingLaneProtocolCommitResultV1,
  DeviceLinkingLaneCeremonyBindingResponseV1,
} from '../../../transport/fetch/routes/deviceLinkingLaneGateway';
import type {
  DeviceLinkingOwnerRequestAuthenticationV1,
} from '../../../transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type { DeviceLinkingOwnerRequestInputV1 } from '../../../transport/fetch/routes/deviceLinking';

export type D1LinkedDeviceLaneProtocolCommitterV1 = {
  executeAndRecordEd25519YaoLaneV1(input: {
    readonly job: Extract<RotatableSigningLaneJobV1, { kind: 'ed25519_yao_lane_job_v1' }>;
    readonly requestJson: string;
    readonly expectedVersion: number;
  }): Promise<Extract<DeviceLinkingLaneProtocolCommitResultV1, { curve: 'ed25519_yao' }>>;
  executeAndRecordEcdsaAdditiveLaneV1(input: {
    readonly job: Extract<RotatableSigningLaneJobV1, { kind: 'ecdsa_additive_lane_job_v1' }>;
    readonly holderRound: import('@shared/signing-lanes').EcdsaAdditiveLaneHolderRoundV1;
    readonly holderPackage: Extract<
      import('@shared/signing-lanes').LaneHolderPackageWireV1,
      { readonly kind: 'ecdsa_additive_lane_holder_package_v1' }
    >;
    readonly encryptedDeltaPackageJson: string;
    readonly expectedVersion: number;
  }): Promise<Extract<DeviceLinkingLaneProtocolCommitResultV1, { curve: 'ecdsa_additive' }>>;
};

export type D1LinkedDeviceLaneGatewayRouteOptionsV1 = {
  readonly authenticateOwnerRequestV1: (
    input: DeviceLinkingOwnerRequestInputV1,
  ) => Promise<DeviceLinkingOwnerRequestAuthenticationV1>;
  readonly gateway: LaneEnrollmentGatewayV1;
  readonly protocolCommitter: D1LinkedDeviceLaneProtocolCommitterV1;
  readonly ownerProjection: D1LinkedDeviceLaneOwnerProjectionGuardV1;
  resolveCeremonyBindingV1(input: {
    readonly operationId: import('@shared/signing-lanes/ids').LaneOperationId;
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
  }): Promise<DeviceLinkingLaneCeremonyBindingResponseV1>;
};

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

/**
 * Resolves the active owner lane through the same wallet-registration
 * projection used by normal signing admission, then compares every durable
 * source binding carried by the lane job.
 */
export function createD1LinkedDeviceLaneOwnerProjectionGuardV1(input: {
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
}): D1LinkedDeviceLaneOwnerProjectionGuardV1 {
  return {
    async assertActiveOwnerSourceLaneV1({ owner, job }) {
      const authorization =
        owner.curve === 'ed25519'
          ? ({
              kind: 'wallet_auth_method',
              walletAuthMethodId: owner.authority.bindingId,
            } as const)
          : ({
              kind: 'authority_ref',
              authorityRef: owner.walletAuthAuthorityRef,
              authSource: owner.authSource,
            } as const);
      const result = await input.walletRegistration.resolveActiveOwnerWalletExecutionLane({
        walletId: owner.walletId,
        authorization,
        expectedMaterialActivation: job.source.materialActivation,
      });
      if (result.kind !== 'projected') {
        throw new Error(`active owner source lane projection refused: ${result.reason}`);
      }
      const projection = result.projection;
      const lane = projection.lane;
      if (
        projection.walletKey.walletId !== owner.walletId ||
        projection.walletKey.walletKeyId !== job.walletKeyId ||
        lane.walletId !== owner.walletId ||
        lane.walletKeyId !== job.walletKeyId ||
        lane.laneId !== job.source.laneId ||
        lane.laneKind !== job.source.laneKind ||
        lane.laneShareEpoch !== job.source.laneShareEpoch ||
        lane.participantBindingDigestB64u !== job.source.participantBindingDigestB64u ||
        lane.lifecycle.state !== 'active' ||
        lane.lifecycle.revocationEpoch !== job.source.revocationEpoch ||
        !mpcMaterialActivationRefsEqual(projection.materialActivation, job.source.materialActivation)
      ) {
        throw new Error('lane job source does not match active owner source-lane projection');
      }
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
