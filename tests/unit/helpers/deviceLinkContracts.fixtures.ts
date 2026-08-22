import {
  buildLinkedDeviceApprovalV1,
  buildStepUpLinkedDeviceOwnerAuthorizationV1,
  parseLinkedDeviceSessionClaimRequestV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '../../../packages/shared-ts/src/device-linking/parsers';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceTargetFactorV1,
  QrLinkedDeviceSessionPayloadV5,
} from '../../../packages/shared-ts/src/device-linking/contracts';
import {
  parseAuthorizationEvidenceSetId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
} from '../../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLaneShareEpoch,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseSigningLaneId,
  parseWalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import {
  buildOwnerLaneParticipantContinuityV1,
  parseWalletSignerId,
} from '../../../packages/shared-ts/src/signing-lanes/ownerContinuity';
import {
  parseMpcSigningWorkerRef,
  parseWalletId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import {
  parseDigestB64u,
  type DigestB64u,
} from '../../../packages/shared-ts/src/utils/canonicalPrimitives';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

const FIXTURE_DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
const PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(8));

export type R103DeviceLinkFixture = {
  readonly payload: QrLinkedDeviceSessionPayloadV5;
  readonly claimRequest: ReturnType<typeof parseLinkedDeviceSessionClaimRequestV1>;
  readonly approval: LinkedDeviceApprovalV1;
  readonly packageSetDigestB64u: DigestB64u;
};

export function buildR103DeviceLinkFixture(
  input: {
    readonly linkSessionId?: string;
    readonly enrollmentId?: string;
    readonly deviceId?: string;
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
    readonly issuedAtMs?: number;
    readonly expiresAtMs?: number;
  } = {},
): R103DeviceLinkFixture {
  const targetFactor = input.targetFactor ?? ({ kind: 'passkey_prf' } as const);
  const linkSessionId = required(
    parseLinkDeviceSessionId(input.linkSessionId ?? 'link-session:r103'),
  );
  const walletId = required(parseWalletId('wallet:r103'));
  const enrollmentId = required(
    parseLinkedDeviceEnrollmentId(input.enrollmentId ?? 'enrollment:r103'),
  );
  const deviceId = required(parseLinkedDeviceId(input.deviceId ?? 'device:r103'));
  const walletKeyId = required(parseWalletKeyId('wallet-key:r103'));
  const sourceLaneId = required(parseSigningLaneId('lane:owner:r103'));
  const targetLaneId = required(parseSigningLaneId('lane:device:r103'));
  const sourceLaneShareEpoch = required(parseLaneShareEpoch('epoch:owner:r103'));
  const targetLaneShareEpoch = required(parseLaneShareEpoch('epoch:device:r103'));
  const operationId = required(parseLaneOperationId('operation:r103'));
  const idempotencyKey = required(parseLaneOperationIdempotencyKey('idempotency:r103'));
  const ownerParticipantContinuity = buildOwnerLaneParticipantContinuityV1({
    signerId: parseWalletSignerId('owner-signer:r103'),
    participantIds: [1, 2],
    signingWorkerId: required(parseMpcSigningWorkerRef('worker:owner:r103')),
    custodyKeyManifestDigestB64u: FIXTURE_DIGEST,
    sourceIdentityDigestB64u: FIXTURE_DIGEST,
  });
  const payload = parseQrLinkedDeviceSessionPayloadV5({
    version: 'v5',
    purpose: 'linked_device_lane_creation',
    linkSessionId,
    linkPublicKeyB64u: PUBLIC_KEY_B64U,
    devicePublicKeyB64u: PUBLIC_KEY_B64U,
    requestedPermission: buildSigningOnlyDelegatedWalletAuthorityV1(),
    targetFactor,
    issuedAtMs: input.issuedAtMs ?? 1_000,
    expiresAtMs: input.expiresAtMs ?? 10_000,
  });
  const approval = buildLinkedDeviceApprovalV1({
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    linkPublicKeyB64u: payload.linkPublicKeyB64u,
    devicePublicKeyB64u: payload.devicePublicKeyB64u,
    permission: payload.requestedPermission,
    targetFactor,
    ownerAuthorization: buildStepUpLinkedDeviceOwnerAuthorizationV1({
      evidenceSetId: required(parseAuthorizationEvidenceSetId('evidence:r103')),
    }),
    policyDigestB64u: FIXTURE_DIGEST,
    operationId,
    idempotencyKey,
    orderedKeyBindings: [
      {
        walletKeyId,
        keyFamily: 'ed25519',
        sourceLaneId,
        sourceLaneKind: 'owner_passkey',
        sourceKind: 'owner_registration',
        sourceLaneShareEpoch,
        sourceRevocationEpoch: 0,
        ownerParticipantContinuity,
        targetLaneId,
        targetLaneShareEpoch,
      },
    ],
    protocolVersions: [{ keyFamily: 'ed25519', version: 'rotatable_signing_lane_protocol_v1' }],
    approvedAtMs: 2_000,
    expiresAtMs: 9_000,
  });
  const claimRequest = parseLinkedDeviceSessionClaimRequestV1({
    kind: 'linked_device_session_claim_request_v1',
    payload,
  });
  return { payload, claimRequest, approval, packageSetDigestB64u: FIXTURE_DIGEST };
}

export function buildR103OwnerApprovalContextV1(
  approval: LinkedDeviceApprovalV1,
  overrides: { readonly keyManifestDigestB64u?: DigestB64u } = {},
) {
  return {
    walletId: approval.walletId,
    walletSessionId: required(parseWalletSessionId('ws:r103')),
    authorizationId: required(parseWalletSessionAuthorizationId('wsa:r103')),
    expiresAtMs: approval.expiresAtMs,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    curve: 'ed25519' as const,
    keyManifestDigestB64u:
      overrides.keyManifestDigestB64u ??
      parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE'),
  };
}
