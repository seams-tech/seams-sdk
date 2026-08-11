import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceEnrollmentChildReceiptV1,
  buildLinkedDeviceEnrollmentReceiptV1,
  buildLinkedDeviceEnrollmentTranscriptV1,
  buildLinkedDeviceTargetCredentialRegistrationV1,
  buildLinkedDeviceTargetPreparationV1,
  buildQrLinkedDeviceSessionPayloadV4,
  buildStepUpLinkedDeviceOwnerAuthorizationV1,
  parseLinkedDeviceSessionClaimRequestV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '../../../packages/shared-ts/src/device-linking/parsers';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceEnrollmentTranscriptV1,
  QrLinkedDeviceSessionPayloadV4,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
} from '../../../packages/shared-ts/src/device-linking/contracts';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '../../../packages/shared-ts/src/device-linking/digests';
import { parseAuthorizationEvidenceSetId } from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseLaneHolderParticipantId,
  parseSigningWorkerParticipantId,
} from '../../../packages/shared-ts/src/signing-lanes/participants';
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
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import { buildR102LaneJob } from './r102LaneGateway.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

const DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
const PUBLIC_KEY = base64UrlEncode(new Uint8Array(32).fill(8));

export type R103DeviceLinkFixture = {
  readonly payload: QrLinkedDeviceSessionPayloadV4;
  readonly claimRequest: ReturnType<typeof parseLinkedDeviceSessionClaimRequestV1>;
  readonly approval: LinkedDeviceApprovalV1;
  readonly transcript: LinkedDeviceEnrollmentTranscriptV1;
  readonly receipt: LinkedDeviceEnrollmentReceiptV1;
};

export type R103TargetCredentialFixture = {
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
};

export async function buildR103TargetCredentialFixture(
  fixture: R103DeviceLinkFixture,
): Promise<R103TargetCredentialFixture> {
  const binding = fixture.approval.orderedKeyBindings[0];
  const job = buildR102LaneJob('r103-target-credential');
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(
    parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(6))),
  );
  const preparation = buildLinkedDeviceTargetPreparationV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    rpId,
    userHandleB64u: PUBLIC_KEY,
    challengeB64u: fixture.approval.policyDigestB64u,
    orderedChildren: [
      {
        kind: 'linked_device_target_preparation_child_v1',
        operationId: fixture.approval.operationId,
        walletKeyId: binding.walletKeyId,
        keyFamily: binding.keyFamily,
        targetLaneId: binding.targetLaneId,
        targetLaneShareEpoch: binding.targetLaneShareEpoch,
        targetMaterialActivationId:
          fixture.receipt.orderedChildReceipts[0].materialActivation.activationId,
        targetHolderParticipantId: job.targetHolder.participantId,
      },
    ],
    issuedAtMs: 3_003,
    expiresAtMs: 7_000,
  });
  const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    targetPreparationDigestB64u: await computeLinkedDeviceTargetPreparationDigestV1(preparation),
    webauthnRegistration: {
      kind: 'linked_device_webauthn_registration_v1',
      credentialIdB64u,
      authenticatorAttachment: 'platform',
      clientDataJsonB64u: 'AQID',
      attestationObjectB64u: 'BAUG',
      transports: ['internal'],
    },
    orderedHolderRegistrations: [
      {
        kind: 'linked_device_target_holder_registration_v1',
        operationId: preparation.orderedChildren[0].operationId,
        walletKeyId: preparation.orderedChildren[0].walletKeyId,
        keyFamily: preparation.orderedChildren[0].keyFamily,
        targetLaneId: preparation.orderedChildren[0].targetLaneId,
        targetLaneShareEpoch: preparation.orderedChildren[0].targetLaneShareEpoch,
        targetMaterialActivationId: preparation.orderedChildren[0].targetMaterialActivationId,
        holderParticipant: {
          kind: 'lane_holder_participant_v1',
          ...job.targetHolder,
        },
      },
    ],
    registeredAtMs: 3_004,
  });
  return { preparation, registration };
}

export function buildR103DeviceLinkFixture(
  input: {
    readonly linkSessionId?: string;
  } = {},
): R103DeviceLinkFixture {
  const linkSessionId = required(
    parseLinkDeviceSessionId(input.linkSessionId ?? 'link-session:r103'),
  );
  const walletId = required(parseWalletId('wallet:r103'));
  const enrollmentId = required(parseLinkedDeviceEnrollmentId('enrollment:r103'));
  const deviceId = required(parseLinkedDeviceId('device:r103'));
  const walletKeyId = required(parseWalletKeyId('wallet-key:r103'));
  const sourceLaneId = required(parseSigningLaneId('lane:owner:r103'));
  const targetLaneId = required(parseSigningLaneId('lane:device:r103'));
  const sourceLaneShareEpoch = required(parseLaneShareEpoch('epoch:owner:r103'));
  const targetLaneShareEpoch = required(parseLaneShareEpoch('epoch:device:r103'));
  const operationId = required(parseLaneOperationId('operation:r103'));
  const idempotencyKey = required(parseLaneOperationIdempotencyKey('idempotency:r103'));
  const sourceHolderParticipantId = required(parseLaneHolderParticipantId('holder:owner:r103'));
  const sourceSigningWorkerParticipantId = required(
    parseSigningWorkerParticipantId('worker:owner:r103'),
  );
  const payload = parseQrLinkedDeviceSessionPayloadV4({
    version: 'v4',
    purpose: 'linked_device_lane_creation',
    linkSessionId,
    linkPublicKeyB64u: PUBLIC_KEY,
    devicePublicKeyB64u: PUBLIC_KEY,
    requestedPermission: {
      kind: 'owner_equivalent_signing',
      administrationScope: 'signing_only',
      localUserPresence: 'required',
    },
    issuedAtMs: 1_000,
    expiresAtMs: 10_000,
  });
  const activation = buildMpcMaterialActivationRef({
    activationId: required(parseMpcMaterialActivationId('activation:r103')),
    capability: required(parseCapabilityInstanceRef('capability:r103')),
    materialOwner: required(parseMpcMaterialOwnerRef('material-owner:r103')),
    keyBinding: required(parseMpcKeyBindingRef('key-binding:r103')),
    lifecycleBinding: required(parseMpcLifecycleBindingRef('lifecycle:r103')),
    signingWorker: required(parseMpcSigningWorkerRef('worker-signing:r103')),
  });
  const ownerAuthorization = buildStepUpLinkedDeviceOwnerAuthorizationV1({
    evidenceSetId: required(parseAuthorizationEvidenceSetId('evidence:r103')),
  });
  const common = {
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    linkPublicKeyB64u: payload.linkPublicKeyB64u,
    devicePublicKeyB64u: payload.devicePublicKeyB64u,
    permission: payload.requestedPermission,
    ownerAuthorization,
    policyDigestB64u: DIGEST,
    operationId,
    idempotencyKey,
    orderedKeyBindings: [
      {
        walletKeyId,
        keyFamily: 'ed25519' as const,
        sourceLaneId,
        sourceLaneShareEpoch,
        sourceRevocationEpoch: 0,
        sourceHolderParticipantId,
        sourceSigningWorkerParticipantId,
        targetLaneId,
        targetLaneShareEpoch,
      },
    ] as const,
    protocolVersions: [
      { keyFamily: 'ed25519' as const, version: 'rotatable_signing_lane_protocol_v1' as const },
    ] as const,
    approvedAtMs: 2_000,
    expiresAtMs: 20_000,
  };
  const approval = buildLinkedDeviceApprovalV1(common);
  const transcript = buildLinkedDeviceEnrollmentTranscriptV1(common);
  const childReceipt = buildLinkedDeviceEnrollmentChildReceiptV1({
    enrollmentId,
    walletId,
    walletKeyId,
    keyFamily: 'ed25519',
    targetLaneId,
    targetLaneShareEpoch,
    materialActivation: activation,
    receiptDigestB64u: DIGEST,
    transcriptHashB64u: DIGEST,
    deliveredAtMs: 8_000,
  });
  const receipt = buildLinkedDeviceEnrollmentReceiptV1({
    enrollmentId,
    walletId,
    deviceId,
    manifestDigestB64u: DIGEST,
    aggregateReceiptDigestB64u: DIGEST,
    orderedChildReceipts: [childReceipt],
    activatedAtMs: 9_000,
  });
  const claimRequest = parseLinkedDeviceSessionClaimRequestV1({
    kind: 'linked_device_session_claim_request_v1',
    payload: buildQrLinkedDeviceSessionPayloadV4({
      linkSessionId,
      linkPublicKeyB64u: payload.linkPublicKeyB64u,
      devicePublicKeyB64u: payload.devicePublicKeyB64u,
      issuedAtMs: 1_000,
      expiresAtMs: 10_000,
    }),
  });
  return { payload, claimRequest, approval, transcript, receipt };
}

void DIGEST;
void PUBLIC_KEY;
void buildLinkedDeviceEnrollmentReceiptV1;
