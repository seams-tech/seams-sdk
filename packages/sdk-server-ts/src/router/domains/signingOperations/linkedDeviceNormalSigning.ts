import {
  parseAuthorizedOperationId,
  buildAuthorizationGrantRef,
  buildLinkedDeviceWalletSessionAuthorizationRef,
  parseAuthorizationAuditEventId,
  type AuthorizationAuditEventId,
  type CapabilityId,
  type CapabilityOperationId,
  type PrincipalId,
  type TenantId,
  type AuthorizedOperationId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  LaneShareEpoch,
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';
import {
  parseLaneShareEpoch,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseSigningLaneId,
  parseWalletId,
  parseWalletKeyId,
  type MpcMaterialActivationRef,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  parseRouterAbMpcMaterialActivationRef,
  routerAbMpcMaterialActivationRefFromWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  type RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims,
  type RouterAbEd25519LinkedDeviceWalletSessionClaims,
} from '../../../core/ThresholdService/validation';
import type { SessionAdapter } from '../../framework/routerApi';
import {
  buildVerifiedEcdsaWalletSessionAuth,
  buildVerifiedEd25519WalletSessionAuth,
  type VerifiedLinkedDeviceEcdsaWalletSessionAuth,
  type VerifiedLinkedDeviceEd25519WalletSessionAuth,
} from '../../auth/verifiedWalletSessionAuth';
import {
  parseLinkedDeviceLocalPresenceAssertionV1,
  verifyLinkedDeviceLocalPresenceV1,
  type LinkedDeviceLocalPresenceVerifierPortV1,
} from '../../auth/linkedDeviceLocalPresenceVerifier';
import type { LinkedDeviceLocalPresenceEvidenceV1 } from './walletExecutionAdmission';
import type { RouterApiWebAuthnService } from '../../framework/authServicePort';
import type { RouterApiAuthorizedOperationService } from '../../framework/authServicePort';
import type { LinkedDeviceMaterialActivationScopeV1 } from '../../../authorization/service';
import {
  buildCapabilityOperationEnvelope,
  type OperationDigestSet,
} from '@shared/authorization/operationFingerprint';
import type { AuthorizedOperation, AuthorizedOperationInput } from '../../../authorization/domain';
import type { MpcWalletSigningQuotaId } from '@shared/authorization/capabilityKinds';
import type { WebAuthnRpId } from '@shared/utils/domainIds';

export type LinkedDeviceExecutionEnvelopeV1 = {
  readonly kind: 'linked_device_execution_v1';
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
};

export type ParsedLinkedDeviceExecutionEnvelopeV1 = LinkedDeviceExecutionEnvelopeV1 & {
  readonly walletId: WalletId;
  readonly materialActivationValue: MpcMaterialActivationRef;
};

export type LinkedDeviceSessionValidationResultV1 =
  | {
      readonly kind: 'linked_device';
      readonly curve: 'ed25519';
      readonly claims: RouterAbEd25519LinkedDeviceWalletSessionClaims;
      readonly walletSessionAuth: VerifiedLinkedDeviceEd25519WalletSessionAuth;
    }
  | {
      readonly kind: 'linked_device';
      readonly curve: 'ecdsa';
      readonly claims: RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims;
      readonly walletSessionAuth: VerifiedLinkedDeviceEcdsaWalletSessionAuth;
    }
  | { readonly kind: 'not_linked' };

export type LinkedDeviceLocalPresenceResultV1 =
  | { readonly kind: 'verified'; readonly evidence: LinkedDeviceLocalPresenceEvidenceV1 }
  | {
      readonly kind: 'refused';
      readonly reason:
        | 'assertion_malformed'
        | 'assertion_credential_mismatch'
        | 'assertion_time_invalid'
        | 'assertion_invalid'
        | 'assertion_binding_mismatch'
        | 'assertion_expired'
        | 'local_presence_mismatch';
    };

export type LinkedDeviceAuthorizedOperationAdmissionResultV1 =
  | {
      readonly kind: 'claimed';
      readonly operation: AuthorizedOperation;
    }
  | {
      readonly kind: 'operation_in_progress' | 'replayed';
      readonly operation: AuthorizedOperation;
    }
  | {
      readonly kind:
        | 'authorization_grant_rejected'
        | 'verified_step_up_rejected'
        | 'wallet_session_quota_exhausted'
        | 'material_mismatch';
    };

type LinkedDeviceReusableOperationRef = Extract<
  AuthorizedOperationInput,
  {
    readonly authorization: { readonly kind: 'authorization_grant' };
    readonly quota: { readonly kind: 'consume_reusable_wallet_session' };
  }
>['operation']['operation'];

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function exactFields(record: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const fields = [...expected].sort();
  if (actual.length !== fields.length || actual.some((field, index) => field !== fields[index])) {
    throw new Error('linked_device_execution has invalid fields');
  }
}

function requiredDomainId<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label} is invalid`);
  return result.value;
}

export function parseLinkedDeviceExecutionEnvelopeV1(
  value: unknown,
): ParsedLinkedDeviceExecutionEnvelopeV1 {
  if (!isRecord(value)) throw new Error('linked_device_execution is required');
  exactFields(value, [
    'kind',
    'enrollmentId',
    'deviceId',
    'walletKeyId',
    'laneId',
    'laneShareEpoch',
    'materialActivation',
  ]);
  if (value.kind !== 'linked_device_execution_v1') {
    throw new Error('linked_device_execution.kind is invalid');
  }
  const enrollmentId = requiredDomainId(
    parseLinkedDeviceEnrollmentId(value.enrollmentId),
    'linked_device_execution.enrollmentId',
  );
  const deviceId = requiredDomainId(
    parseLinkedDeviceId(value.deviceId),
    'linked_device_execution.deviceId',
  );
  const walletKeyId = requiredDomainId(
    parseWalletKeyId(value.walletKeyId),
    'linked_device_execution.walletKeyId',
  );
  const laneId = requiredDomainId(
    parseSigningLaneId(value.laneId),
    'linked_device_execution.laneId',
  );
  const laneShareEpoch = requiredDomainId(
    parseLaneShareEpoch(value.laneShareEpoch),
    'linked_device_execution.laneShareEpoch',
  );
  const materialActivation = parseRouterAbMpcMaterialActivationRef(value.materialActivation);
  const walletId = requiredDomainId(
    parseWalletId(materialActivation.material_owner),
    'linked_device_execution.materialActivation.material_owner',
  );
  return {
    kind: 'linked_device_execution_v1',
    enrollmentId,
    deviceId,
    walletKeyId,
    laneId,
    laneShareEpoch,
    materialActivation,
    walletId,
    materialActivationValue: routerAbMpcMaterialActivationRefFromWire(materialActivation),
  };
}

export function stripLinkedDeviceNormalSigningBoundaryFields(
  body: Record<string, unknown>,
): Record<string, unknown> {
  const {
    linkedDeviceExecution: _linkedDeviceExecution,
    localPresenceAssertion: _assertion,
    ...rest
  } = body;
  return rest;
}

export function hasLinkedDeviceNormalSigningBoundaryFields(body: Record<string, unknown>): boolean {
  return (
    Object.prototype.hasOwnProperty.call(body, 'linkedDeviceExecution') ||
    Object.prototype.hasOwnProperty.call(body, 'localPresenceAssertion')
  );
}

export async function admitLinkedDeviceAuthorizedOperation(input: {
  readonly authorizedOperations: Pick<
    RouterApiAuthorizedOperationService,
    'admitAuthorizedOperation'
  >;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: LinkedDeviceReusableOperationRef;
  readonly digests: OperationDigestSet;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly authorizationId: Parameters<typeof buildLinkedDeviceWalletSessionAuthorizationRef>[0];
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly material: LinkedDeviceMaterialActivationScopeV1;
  readonly claimedAtMs: number;
}): Promise<LinkedDeviceAuthorizedOperationAdmissionResultV1> {
  const envelope = buildCapabilityOperationEnvelope({
    tenantId: input.tenantId,
    principalId: input.principalId,
    capabilityId: input.capabilityId,
    operationId: input.operationId,
    operation: input.operation,
    digests: input.digests,
  });
  const outcome = await input.authorizedOperations.admitAuthorizedOperation({
    operation: {
      tenantId: input.tenantId,
      authorizedOperationId: input.authorizedOperationId,
      auditEventId: input.auditEventId,
      operation: envelope,
      authorization: {
        kind: 'authorization_grant',
        authorizationGrantRef: buildLinkedDeviceWalletSessionAuthorizationRef(
          input.authorizationId,
        ),
      },
      quota: { kind: 'consume_reusable_wallet_session', quotaId: input.quotaId },
      claimedAtMs: input.claimedAtMs,
    } satisfies AuthorizedOperationInput,
    material: input.material,
  });
  return outcome;
}

export async function parseLinkedDeviceWalletSessionForCurve(input: {
  readonly curve: 'ed25519' | 'ecdsa';
  readonly session: SessionAdapter | null | undefined;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly nowMs?: () => number;
}): Promise<LinkedDeviceSessionValidationResultV1> {
  if (!input.session) return { kind: 'not_linked' };
  let parsed: Awaited<ReturnType<SessionAdapter['parse']>>;
  try {
    parsed = await input.session.parse(input.headers);
  } catch {
    return { kind: 'not_linked' };
  }
  if (!parsed.ok) return { kind: 'not_linked' };
  const nowMs = input.nowMs ? input.nowMs() : Date.now();
  if (input.curve === 'ed25519') {
    const claims = parseRouterAbEd25519WalletSessionClaims(parsed.claims);
    if (!claims || claims.authorizationKind !== 'linked_device_wallet_session') {
      return { kind: 'not_linked' };
    }
    if (claims.expiresAtMs <= nowMs) return { kind: 'not_linked' };
    return {
      kind: 'linked_device',
      curve: 'ed25519',
      claims,
      walletSessionAuth: buildVerifiedEd25519WalletSessionAuth(claims),
    };
  }
  const claims = parseRouterAbEcdsaDerivationWalletSessionClaims(parsed.claims);
  if (!claims || claims.authorizationKind !== 'linked_device_wallet_session') {
    return { kind: 'not_linked' };
  }
  if (claims.expiresAtMs <= nowMs) return { kind: 'not_linked' };
  return {
    kind: 'linked_device',
    curve: 'ecdsa',
    claims,
    walletSessionAuth: buildVerifiedEcdsaWalletSessionAuth(claims),
  };
}

export function buildLinkedDeviceLocalPresenceVerifierPort(input: {
  readonly webAuthn: RouterApiWebAuthnService;
  readonly rpId: WebAuthnRpId;
  readonly expectedOrigin: string;
}): LinkedDeviceLocalPresenceVerifierPortV1 {
  return {
    verify: async (assertion) => {
      const result = await input.webAuthn.verifyWebAuthnAuthenticationLite({
        userId: `linked-device:${String(assertion.deviceId)}`,
        rpId: input.rpId,
        expectedChallenge: String(assertion.challengeDigestB64u),
        expected_origin: input.expectedOrigin,
        webauthn_authentication: assertion.assertion,
      });
      if (result.success && result.verified) {
        return { kind: 'verified', verifiedAtMs: Date.now() };
      }
      return { kind: 'refused', reason: 'assertion_invalid' };
    },
  };
}

export async function verifyLinkedDeviceLocalPresenceForOperation(input: {
  readonly assertion: unknown;
  readonly verifier: LinkedDeviceLocalPresenceVerifierPortV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly intentDigestB64u: DigestB64u;
  readonly nowMs?: () => number;
}): Promise<LinkedDeviceLocalPresenceResultV1> {
  const parsed = parseLinkedDeviceLocalPresenceAssertionV1(input.assertion);
  if (!parsed) return { kind: 'refused', reason: 'assertion_malformed' };
  if (
    parsed.authorizedOperationId !== input.authorizedOperationId ||
    parsed.deviceId !== input.deviceId ||
    parsed.enrollmentId !== input.enrollmentId ||
    String(parsed.intentDigestB64u) !== String(input.intentDigestB64u)
  ) {
    return { kind: 'refused', reason: 'local_presence_mismatch' };
  }
  const verified = await verifyLinkedDeviceLocalPresenceV1({
    assertion: input.assertion,
    verifier: input.verifier,
    nowMs: input.nowMs,
  });
  if (verified.kind === 'refused') return verified;
  return verified;
}
