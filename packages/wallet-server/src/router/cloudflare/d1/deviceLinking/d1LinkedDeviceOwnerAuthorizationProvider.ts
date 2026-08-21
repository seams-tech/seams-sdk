import type {
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceProtocolVersionV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';
import {
  buildWalletSessionLinkedDeviceOwnerAuthorizationV1,
  parseLinkedDeviceEnrollmentKeyBindingV1,
  parseLinkedDeviceProtocolVersionV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import {
  hasDelegatedWalletPermissionV1,
  validateDelegatedWalletAuthorityAttenuationV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
} from '@shared/signing-lanes/ids';
import type { LaneOperationId, LaneOperationIdempotencyKey } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import type {
  ActiveOwnerWalletExecutionLaneProjection,
  WalletExecutionLaneProjectionResult,
} from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import type {
  LinkedDeviceOwnerAuthorizationContextV1,
  LinkedDeviceOwnerAuthorizationPortV1,
  LinkedDeviceSessionRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  DeviceLinkingOwnerAuthorizationResponseV1,
  DeviceLinkingOwnerAuthorizationRouteServiceV1,
  DeviceLinkingOwnerWalletSessionContextV1,
} from '../../../../router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type {
  LinkedDeviceOwnerSourceChildResolutionRequestV1,
  LinkedDeviceOwnerSourceChildResolutionV1,
  LinkedDeviceOwnerSourceChildResolverV1,
  D1LinkedDeviceTargetPlannerOptionsV1,
  D1LinkedDeviceTargetPlannerV1,
} from './d1LinkedDeviceTargetPlanner';
import type { D1LinkedDeviceOwnerPlanningSnapshotWriterV1 } from './d1LinkedDeviceOwnerPlanningSnapshotWriter';
import { D1LinkedDeviceTargetPlannerV1 as TargetPlanner } from './d1LinkedDeviceTargetPlanner';
import { computeLinkedDevicePublicKeyDigestV1 } from '../../../../core/deviceLinking/requestProof';

const ENROLLMENT_ID_DOMAIN_V1 = 'seams/linked-device/enrollment-identity/v1';

export type D1LinkedDeviceOwnerAuthorizationMetadataV1 = {
  readonly walletId: WalletId;
  readonly policyDigestB64u: DigestB64u;
  readonly operationId: LaneOperationId;
  readonly idempotencyKey: LaneOperationIdempotencyKey;
  readonly orderedKeyBindings: readonly [
    LinkedDeviceEnrollmentKeyBindingV1,
    ...LinkedDeviceEnrollmentKeyBindingV1[],
  ];
  readonly protocolVersions: readonly [
    LinkedDeviceProtocolVersionV1,
    ...LinkedDeviceProtocolVersionV1[],
  ];
  readonly expiresAtMs: number;
};

/**
 * Durable owner metadata and source facts are supplied by D1/registration
 * authority. This provider validates and binds those facts; it never invents
 * lane participants, protocol keys, or owner authorization metadata.
 */
export type D1LinkedDeviceOwnerAuthorizationMetadataSourceV1 = {
  readApprovedOwnerContextV1(input: {
    readonly walletId: WalletId;
    readonly linkSessionId: string;
  }): Promise<DeviceLinkingOwnerWalletSessionContextV1 | null>;
  readOwnerSourceChildV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly request: LinkedDeviceOwnerSourceChildResolutionRequestV1;
  }): Promise<LinkedDeviceOwnerSourceChildResolutionV1 | null>;
};

type D1LinkedDeviceOwnerAuthorizationPlanningWriterV1 = {
  writeV1(input: Parameters<D1LinkedDeviceOwnerPlanningSnapshotWriterV1['writeV1']>[0]): Promise<
    | {
        readonly outcome: 'applied' | 'replayed';
        readonly snapshot: { readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataV1 };
      }
    | { readonly outcome: 'conflict' }
  >;
};

export type D1LinkedDeviceOwnerAuthorizationProviderOptionsV1 = {
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1;
  readonly targetPlanner: Pick<
    D1LinkedDeviceTargetPlannerOptionsV1,
    'preparationTtlMs' | 'targetDeploymentDescriptorProvider'
  >;
  readonly planningWriter: D1LinkedDeviceOwnerAuthorizationPlanningWriterV1;
  readonly nowV1?: () => number;
};

export type D1LinkedDeviceOwnerAuthorizationProviderV1 = {
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  readonly ownerAuthorizationRoute: DeviceLinkingOwnerAuthorizationRouteServiceV1;
  readonly ownerSourceResolver: LinkedDeviceOwnerSourceChildResolverV1;
  readonly targetPlanner: D1LinkedDeviceTargetPlannerV1;
};

export function createD1LinkedDeviceOwnerAuthorizationProviderV1(
  options: D1LinkedDeviceOwnerAuthorizationProviderOptionsV1,
): D1LinkedDeviceOwnerAuthorizationProviderV1 {
  const nowV1 = options.nowV1 ?? Date.now;
  const ownerAuthorization = createOwnerAuthorizationPortV1(nowV1);
  const ownerSourceResolver = createD1LinkedDeviceOwnerSourceResolverV1({
    walletRegistration: options.walletRegistration,
    metadata: options.metadata,
    nowV1,
  });
  const targetPlanner = new TargetPlanner({
    preparationTtlMs: options.targetPlanner.preparationTtlMs,
    targetDeploymentDescriptorProvider: options.targetPlanner.targetDeploymentDescriptorProvider,
    resolveOwnerSourceChildV1: ownerSourceResolver.resolveOwnerSourceChildV1,
  });
  return {
    ownerAuthorization,
    ownerAuthorizationRoute: createOwnerAuthorizationRouteV1({
      planningWriter: options.planningWriter,
      nowV1,
    }),
    ownerSourceResolver,
    targetPlanner,
  };
}

function createOwnerAuthorizationPortV1(nowV1: () => number): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async (input) => {
      const payload = parseQrLinkedDeviceSessionPayloadV5(input.payload);
      const ownerError = validateOwnerContext(input.owner, input.requestedAtMs, nowV1);
      if (ownerError) return ownerError;
      const attenuationError = requestedAuthorityAttenuationError(
        input.owner.permission,
        payload.requestedPermission,
      );
      if (attenuationError) return denied('unauthorized', attenuationError);
      if (input.requestedAtMs < payload.issuedAtMs || input.requestedAtMs >= payload.expiresAtMs) {
        return denied('expired', 'linked-device QR session is outside its lifetime');
      }
      const deviceDigestB64u = await computeLinkedDevicePublicKeyDigestV1(
        payload.devicePublicKeyB64u,
      );
      const enrollmentDigestB64u = parseDigestB64u(
        base64UrlEncode(
          await sha256BytesUtf8(
            `${ENROLLMENT_ID_DOMAIN_V1}\u0000${alphabetizeStringify({
              walletId: input.owner.walletId,
              linkSessionId: payload.linkSessionId,
              linkPublicKeyB64u: payload.linkPublicKeyB64u,
              devicePublicKeyB64u: payload.devicePublicKeyB64u,
            })}`,
          ),
        ),
      );
      const enrollmentId = parseRequired(
        parseLinkedDeviceEnrollmentId(`linked-enrollment:${enrollmentDigestB64u}`),
        'linked-device enrollment identity',
      );
      const deviceId = parseRequired(
        parseLinkedDeviceId(`linked-device:${deviceDigestB64u}`),
        'linked-device device identity',
      );
      const claimExpiresAtMs = Math.min(payload.expiresAtMs, input.owner.expiresAtMs);
      if (claimExpiresAtMs <= input.requestedAtMs) {
        return denied('expired', 'owner Wallet Session expires before the link claim');
      }
      return {
        kind: 'authorized',
        identity: {
          walletId: input.owner.walletId,
          enrollmentId,
          deviceId,
          claimExpiresAtMs,
        },
      };
    },
    authorizeOwnerApprovalV1: async (input) => {
      const ownerError = validateOwnerContext(input.owner, input.requestedAtMs, nowV1);
      if (ownerError) return ownerError;
      const attenuationError = requestedAuthorityAttenuationError(
        input.owner.permission,
        input.approval.permission,
      );
      if (attenuationError) return denied('unauthorized', attenuationError);
      if (!isApprovalSession(input.session)) {
        return denied('invalid', 'linked-device approval session is not owner-claimed');
      }
      if (
        input.session.state.walletId !== input.owner.walletId ||
        input.approval.walletId !== input.owner.walletId ||
        input.approval.linkSessionId !== input.session.linkSessionId ||
        input.approval.enrollmentId !== input.session.state.enrollmentId ||
        input.approval.deviceId !== input.session.claimTranscript.value.deviceId ||
        input.approval.linkPublicKeyB64u !== input.session.qrPayload.linkPublicKeyB64u ||
        input.approval.devicePublicKeyB64u !== input.session.qrPayload.devicePublicKeyB64u ||
        input.requestedAtMs < input.approval.approvedAtMs ||
        input.requestedAtMs >= input.approval.expiresAtMs ||
        input.approval.expiresAtMs > input.session.qrPayload.expiresAtMs
      ) {
        return denied('invalid', 'owner approval identity does not match the claimed session');
      }
      if (!ownerAuthorizationSourceMatchesContext(input.approval.ownerAuthorization, input.owner)) {
        return denied('unauthorized', 'owner approval source does not match the Wallet Session');
      }
      return { kind: 'authorized' };
    },
  };
}

function createOwnerAuthorizationRouteV1(input: {
  readonly planningWriter: D1LinkedDeviceOwnerAuthorizationPlanningWriterV1;
  readonly nowV1: () => number;
}): DeviceLinkingOwnerAuthorizationRouteServiceV1 {
  return {
    authorizeOwnerForLinkingV1: async (request) => {
      const ownerError = validateOwnerContext(request.owner, request.requestedAtMs, input.nowV1);
      if (ownerError) throw new Error(ownerError.message);
      const payload = parseQrLinkedDeviceSessionPayloadV5(request.payload);
      const attenuationError = requestedAuthorityAttenuationError(
        request.owner.permission,
        payload.requestedPermission,
      );
      if (attenuationError) throw new Error(attenuationError);
      const planning = await input.planningWriter.writeV1({
        owner: request.owner,
        payload,
        orderedOwnerSourceLaneHints: request.orderedOwnerSourceLaneHints,
      });
      if (planning.outcome === 'conflict') {
        throw new Error('owner authorization planning snapshot conflicts with this link request');
      }
      const normalized = normalizeOwnerAuthorizationMetadataV1(
        planning.snapshot.metadata,
        request.owner,
        payload,
      );
      return {
        authentication: {
          kind: 'link_session_authenticated_request_v1',
          source: ownerAuthorizationSourceForContext(request.owner),
          proofDigestB64u: request.bodyDigestB64u,
        },
        walletId: normalized.walletId,
        ownerAuthorization: ownerAuthorizationSourceForContext(request.owner),
        policyDigestB64u: normalized.policyDigestB64u,
        operationId: normalized.operationId,
        idempotencyKey: normalized.idempotencyKey,
        orderedKeyBindings: normalized.orderedKeyBindings,
        protocolVersions: normalized.protocolVersions,
        expiresAtMs: normalized.expiresAtMs,
      } satisfies DeviceLinkingOwnerAuthorizationResponseV1;
    },
  };
}

function createD1LinkedDeviceOwnerSourceResolverV1(input: {
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1;
  readonly nowV1: () => number;
}): LinkedDeviceOwnerSourceChildResolverV1 {
  return {
    resolveOwnerSourceChildV1: async (request) => {
      const owner = await resolveApprovedOwnerContextV1(input.metadata, request);
      assertApprovedOwnerContext(request, owner, input.nowV1());
      const resolution = await input.metadata.readOwnerSourceChildV1({ owner, request });
      if (!resolution) throw new Error('authoritative linked-device source facts are unavailable');
      const projection = await projectOwnerLaneV1(input.walletRegistration, owner, resolution);
      assertResolutionMatchesOwnerProjectionV1(resolution, projection);
      return resolution;
    },
  };
}

async function resolveApprovedOwnerContextV1(
  metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
  request: LinkedDeviceOwnerSourceChildResolutionRequestV1,
): Promise<DeviceLinkingOwnerWalletSessionContextV1> {
  const identity = sourceRequestIdentity(request);
  const owner = await metadata.readApprovedOwnerContextV1(identity);
  if (!owner) throw new Error('approved owner Wallet Session context is unavailable');
  return owner;
}

function sourceRequestIdentity(request: LinkedDeviceOwnerSourceChildResolutionRequestV1): {
  readonly walletId: WalletId;
  readonly linkSessionId: string;
} {
  if (request.kind === 'preparation') {
    return {
      walletId: request.approval.walletId,
      linkSessionId: String(request.approval.linkSessionId),
    };
  }
  return {
    walletId: request.preparation.walletId,
    linkSessionId: String(request.preparation.linkSessionId),
  };
}

function assertApprovedOwnerContext(
  request: LinkedDeviceOwnerSourceChildResolutionRequestV1,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  nowMs: number,
): void {
  const identity = sourceRequestIdentity(request);
  if (
    owner.walletId !== identity.walletId ||
    !Number.isSafeInteger(nowMs) ||
    nowMs >= owner.expiresAtMs
  ) {
    throw new Error('approved owner Wallet Session context is expired or mismatched');
  }
  if (!hasDelegatedWalletPermissionV1(owner.permission, 'link_devices')) {
    throw new Error('approved owner Wallet Session authority does not contain link_devices');
  }
  if (request.kind === 'preparation') {
    const attenuationError = requestedAuthorityAttenuationError(
      owner.permission,
      request.approval.permission,
    );
    if (attenuationError) throw new Error(attenuationError);
  }
  if (
    request.kind === 'preparation' &&
    !ownerAuthorizationSourceMatchesContext(request.approval.ownerAuthorization, owner)
  ) {
    throw new Error('approved owner Wallet Session source does not match the approval');
  }
}

async function projectOwnerLaneV1(
  walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
): Promise<ActiveOwnerWalletExecutionLaneProjection> {
  const authorization =
    owner.curve === 'ed25519'
      ? { kind: 'wallet_auth_method' as const, walletAuthMethodId: owner.authority.bindingId }
      : {
          kind: 'authority_ref' as const,
          authorityRef: owner.walletAuthAuthorityRef,
          authSource: owner.authSource,
        };
  const result: WalletExecutionLaneProjectionResult =
    await walletRegistration.resolveActiveOwnerWalletExecutionLane({
      walletId: owner.walletId,
      authorization,
      expectedMaterialActivation: resolution.source.materialActivation,
    });
  if (result.kind !== 'projected') {
    throw new Error(`active owner source lane projection refused: ${result.reason}`);
  }
  return result.projection;
}

function assertResolutionMatchesOwnerProjectionV1(
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
  projection: ActiveOwnerWalletExecutionLaneProjection,
): void {
  const lane = projection.lane;
  if (
    resolution.walletKeyId !== projection.walletKey.walletKeyId ||
    resolution.source.laneId !== lane.laneId ||
    resolution.source.laneKind !== lane.laneKind ||
    resolution.source.laneShareEpoch !== lane.laneShareEpoch ||
    resolution.source.revocationEpoch !== lane.lifecycle.revocationEpoch ||
    resolution.source.participantBindingDigestB64u !== lane.participantBindingDigestB64u
  ) {
    throw new Error('linked-device source facts do not match the active owner projection');
  }
  if (resolution.keyFamily !== projection.walletKey.keyFamily) {
    throw new Error('linked-device source key family does not match the owner projection');
  }
  if (resolution.keyFamily === 'ed25519') {
    if (
      projection.walletKey.keyFamily !== 'ed25519' ||
      resolution.registeredPublicKeyB64u !== projection.walletKey.registeredPublicKeyB64u ||
      resolution.nearEd25519SigningKeyId !== projection.walletKey.nearEd25519SigningKeyId ||
      resolution.keyCreationSignerSlot !== projection.walletKey.keyCreationSignerSlot
    ) {
      throw new Error('Ed25519 linked-device source facts do not match the owner projection');
    }
  }
}

function normalizeOwnerAuthorizationMetadataV1(
  metadata: D1LinkedDeviceOwnerAuthorizationMetadataV1,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  payload: QrLinkedDeviceSessionPayloadV5,
): D1LinkedDeviceOwnerAuthorizationMetadataV1 {
  if (metadata.walletId !== owner.walletId) {
    throw new Error('owner authorization metadata walletId does not match the Wallet Session');
  }
  const policyDigestB64u = parseDigestB64u(metadata.policyDigestB64u);
  const operationId = parseRequired(parseLaneOperationId(metadata.operationId), 'operationId');
  const idempotencyKey = parseRequired(
    parseLaneOperationIdempotencyKey(metadata.idempotencyKey),
    'idempotencyKey',
  );
  const orderedKeyBindings = metadata.orderedKeyBindings.map((value, index) =>
    parseLinkedDeviceEnrollmentKeyBindingV1(value, `orderedKeyBindings[${index}]`),
  );
  const protocolVersions = metadata.protocolVersions.map((value, index) =>
    parseLinkedDeviceProtocolVersionV1(value, `protocolVersions[${index}]`),
  );
  if (
    orderedKeyBindings.length === 0 ||
    protocolVersions.length === 0 ||
    !Number.isSafeInteger(metadata.expiresAtMs) ||
    metadata.expiresAtMs <= 0 ||
    metadata.expiresAtMs > payload.expiresAtMs ||
    metadata.expiresAtMs > owner.expiresAtMs
  ) {
    throw new Error('owner authorization metadata expiry or ordered facts are invalid');
  }
  return {
    walletId: owner.walletId,
    policyDigestB64u,
    operationId,
    idempotencyKey,
    orderedKeyBindings: requireNonEmpty(orderedKeyBindings, 'orderedKeyBindings'),
    protocolVersions: requireNonEmpty(protocolVersions, 'protocolVersions'),
    expiresAtMs: metadata.expiresAtMs,
  };
}

function ownerAuthorizationSourceForContext(
  owner: DeviceLinkingOwnerWalletSessionContextV1,
): LinkedDeviceOwnerAuthorizationSourceV1 {
  return buildWalletSessionLinkedDeviceOwnerAuthorizationV1({
    walletSessionId: owner.walletSessionId,
    authorizationId: owner.authorizationId,
  });
}

function ownerAuthorizationSourceMatchesContext(
  source: LinkedDeviceOwnerAuthorizationSourceV1,
  owner: Pick<LinkedDeviceOwnerAuthorizationContextV1, 'walletSessionId' | 'authorizationId'>,
): boolean {
  return (
    source.kind === 'wallet_session' &&
    String(source.walletSessionId) === String(owner.walletSessionId) &&
    String(source.authorizationId) === String(owner.authorizationId)
  );
}

function validateOwnerContext(
  owner: Pick<
    LinkedDeviceOwnerAuthorizationContextV1,
    'walletId' | 'walletSessionId' | 'authorizationId' | 'expiresAtMs' | 'permission'
  >,
  requestedAtMs: number,
  nowV1: () => number,
): {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid';
  readonly message: string;
} | null {
  if (
    !owner.walletId ||
    !parseWalletSessionId(owner.walletSessionId).ok ||
    !parseWalletSessionAuthorizationId(owner.authorizationId).ok ||
    !Number.isSafeInteger(owner.expiresAtMs) ||
    !Number.isSafeInteger(requestedAtMs) ||
    requestedAtMs < 0 ||
    requestedAtMs >= owner.expiresAtMs ||
    nowV1() >= owner.expiresAtMs ||
    !hasDelegatedWalletPermissionV1(owner.permission, 'link_devices')
  ) {
    return denied('invalid', 'owner Wallet Session context is invalid or expired');
  }
  return null;
}

function requestedAuthorityAttenuationError(
  parent: DelegatedWalletAuthorityV1,
  child: DelegatedWalletAuthorityV1,
): string | null {
  if (!hasDelegatedWalletPermissionV1(parent, 'link_devices')) {
    return 'owner Wallet Session authority does not contain link_devices';
  }
  const result = validateDelegatedWalletAuthorityAttenuationV1({ parent, child });
  return result.ok ? null : result.error.message;
}

function denied(
  code: 'unauthorized' | 'expired' | 'invalid',
  message: string,
): {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid';
  readonly message: string;
} {
  return { kind: 'denied', code, message };
}

function isApprovalSession(
  session: LinkedDeviceSessionRecordV1,
): session is Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'claimed_by_owner' } }
> {
  return session.state.state === 'claimed_by_owner' && session.claimTranscript !== undefined;
}

function requireNonEmpty<T>(values: readonly T[], label: string): readonly [T, ...T[]] {
  const [first, ...rest] = values;
  if (first === undefined) throw new Error(`${label} must not be empty`);
  return [first, ...rest];
}

function parseRequired<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label}: ${result.error.message}`);
}
