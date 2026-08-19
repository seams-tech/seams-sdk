import {
  buildLinkedDeviceApprovalV1,
  parseLinkedDeviceOwnerEnrollmentCeremonyV1,
  buildLinkedDeviceEnrollmentChildReceiptV1,
  buildLinkedDeviceEnrollmentReceiptV1,
  buildLinkedDeviceEnrollmentTranscriptV1,
  buildLinkedDeviceTargetCredentialRegistrationV1,
  buildLinkedDeviceTargetPreparationV1,
  buildLinkedDeviceHolderDeliveryAcknowledgementV1,
  buildLinkedDeviceProvisioningCommandV1,
  buildQrLinkedDeviceSessionPayloadV5,
  buildStepUpLinkedDeviceOwnerAuthorizationV1,
  parseLinkedDeviceSessionClaimRequestV1,
  parseQrLinkedDeviceSessionPayloadV5,
  parseLinkedDeviceProvisioningDeliveriesV1,
  parseLinkedDeviceTargetReadyR102InputV1,
  parseLinkedDeviceWalletSessionDeliveryV1,
} from '../../../packages/shared-ts/src/device-linking/parsers';
import type {
  LinkedDeviceOwnerEnrollmentCeremonyV1,
  LinkedDeviceTargetFactorV1,
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceEnrollmentTranscriptV1,
  QrLinkedDeviceSessionPayloadV5,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceEmailOtpVerificationGrantV1,
  LinkedDeviceTargetPreparationChildV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceTargetHolderRegistrationV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceProvisioningCommandV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceTargetReadyR102InputV1,
  LinkedDeviceWalletSessionDeliveryV1,
} from '../../../packages/shared-ts/src/device-linking/contracts';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '../../../packages/shared-ts/src/device-linking/digests';
import { parseAuthorizationEvidenceSetId } from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseSigningWorkerParticipantId } from '../../../packages/shared-ts/src/signing-lanes/participants';
import {
  buildOwnerLaneParticipantContinuityV1,
  parseWalletSignerId,
} from '../../../packages/shared-ts/src/signing-lanes/ownerContinuity';
import {
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLaneEnrollmentId,
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
} from '../../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '../../../packages/shared-ts/src/utils/sessionTokens';
import { DEFAULT_WALLET_SESSION_REMAINING_USES } from '../../../packages/shared-ts/src/threshold/sessionPolicy';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import type { DigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildR102HolderDeliveryReceipt,
  buildR102LaneJob,
  buildR102EcdsaLaneJob,
  buildR102ProtocolCommitReceipt,
  buildR102ManifestChild,
} from './r102LaneGateway.fixtures';
import {
  buildLaneEnrollmentManifestV1,
  parseRotatableSigningLaneJobV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotationParsers';
import type {
  ActiveLaneProtocolSourceV1,
  RotatableSigningLaneJobV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotation';
import { computeLaneEnrollmentManifestDigestV1 } from '../../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { parseLaneHolderParticipantRecordV1 } from '../../../packages/shared-ts/src/signing-lanes/participants';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

const DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
const R102_RECEIPT_DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32)));
const PUBLIC_KEY = base64UrlEncode(new Uint8Array(32).fill(8));

export type R103DeviceLinkFixture = {
  readonly payload: QrLinkedDeviceSessionPayloadV5;
  readonly claimRequest: ReturnType<typeof parseLinkedDeviceSessionClaimRequestV1>;
  readonly approval: LinkedDeviceApprovalV1;
  readonly transcript: LinkedDeviceEnrollmentTranscriptV1;
  readonly receipt: LinkedDeviceEnrollmentReceiptV1;
};

export type R103TargetCredentialFixture = {
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
};

export type R103ProvisioningFixture = {
  readonly command: LinkedDeviceProvisioningCommandV1;
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
  readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
};

export type R103ActiveExecutionFixture = {
  readonly deviceLink: R103DeviceLinkFixture;
  readonly targetCredential: R103TargetCredentialFixture;
  readonly provisioning: R103ProvisioningFixture;
  readonly walletSession: LinkedDeviceWalletSessionDeliveryV1;
};

export type R103MixedPlannerFixture = {
  readonly deviceLink: R103DeviceLinkFixture;
  readonly targetCredential: R103TargetCredentialFixture;
  readonly sourceJobs: readonly [RotatableSigningLaneJobV1, RotatableSigningLaneJobV1];
};

/**
 * The canonical owner add-auth-method ceremony a linked enrollment finalizes.
 *
 * Built here rather than inline per test so the registration options every
 * fixture carries stay the ones the canonical parser accepts — the preparation
 * digest binds them field by field.
 */
export function buildR103OwnerEnrollmentCeremonyV1(
  overrides: {
    readonly addAuthMethodCeremonyId?: string;
    readonly rpId?: string;
    readonly expiresAtMs?: number;
  } = {},
): LinkedDeviceOwnerEnrollmentCeremonyV1 {
  const rpId = overrides.rpId ?? 'wallet.example.test';
  return parseLinkedDeviceOwnerEnrollmentCeremonyV1({
    kind: 'linked_device_passkey_owner_enrollment_v1',
    targetFactor: { kind: 'passkey_prf' },
    addAuthMethodCeremonyId: overrides.addAuthMethodCeremonyId ?? 'add-auth-method-ceremony:r103p8',
    registration: {
      kind: 'webauthn_add_auth_method_registration_v1',
      challengeId: 'add-auth-method-challenge:r103p8',
      challengeB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
      rpId,
      user: {
        idB64u: base64UrlEncode(new Uint8Array(32).fill(10)),
        name: 'linked-device',
        displayName: 'linked-device',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      timeoutMs: 120_000,
      attestation: 'none',
      extensions: {
        prf: {
          eval: {
            firstB64u: base64UrlEncode(new Uint8Array(32).fill(12)),
            secondB64u: base64UrlEncode(new Uint8Array(32).fill(13)),
          },
        },
      },
      excludeCredentials: [],
    },
    expiresAtMs: overrides.expiresAtMs ?? 9_000_000_000_000,
  });
}

/**
 * The Email OTP branch of the ceremony: the server-resolved base factor and
 * masked destination hint, restating the approval expiry. The base auth-method
 * id follows the canonical wallet-wide `email_otp:<wallet>:<hash>` form so the
 * derived-identity checks exercise real derivations rather than test tokens.
 */
export function buildR103EmailOtpOwnerEnrollmentCeremonyV1(
  overrides: {
    readonly walletId?: string;
    readonly emailHashHex?: string;
    readonly maskedEmailHint?: string;
    readonly expiresAtMs?: number;
  } = {},
): LinkedDeviceOwnerEnrollmentCeremonyV1 {
  const walletId = overrides.walletId ?? 'wallet:r103';
  const emailHashHex = overrides.emailHashHex ?? 'ab'.repeat(32);
  return parseLinkedDeviceOwnerEnrollmentCeremonyV1({
    kind: 'linked_device_email_otp_owner_enrollment_v1',
    targetFactor: { kind: 'email_otp' },
    baseWalletAuthMethodId: `email_otp:${walletId}:${emailHashHex}`,
    maskedEmailHint: overrides.maskedEmailHint ?? 'd***e@e***e.test',
    expiresAtMs: overrides.expiresAtMs ?? 20_000,
  });
}

/** Mixed-curve owner source and target registration facts for R103 planner tests. */
export async function buildR103MixedPlannerFixture(): Promise<R103MixedPlannerFixture> {
  const base = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:r103-mixed' });
  const ed25519 = buildR102LaneJob('r103-mixed-ed25519');
  const ecdsa = buildR102EcdsaLaneJob('r103-mixed-ecdsa');
  const sourceJobs = [ed25519, ecdsa] as const;
  const orderedKeyBindings = [
    buildMixedApprovalBinding(ed25519),
    buildMixedApprovalBinding(ecdsa),
  ] as const;
  const approval = buildLinkedDeviceApprovalV1({
    linkSessionId: base.approval.linkSessionId,
    walletId: base.approval.walletId,
    enrollmentId: base.approval.enrollmentId,
    deviceId: base.approval.deviceId,
    linkPublicKeyB64u: base.approval.linkPublicKeyB64u,
    devicePublicKeyB64u: base.approval.devicePublicKeyB64u,
    permission: base.approval.permission,
    targetFactor: base.approval.targetFactor,
    ownerAuthorization: base.approval.ownerAuthorization,
    ownerEnrollment: base.approval.ownerEnrollment,
    policyDigestB64u: base.approval.policyDigestB64u,
    operationId: base.approval.operationId,
    idempotencyKey: base.approval.idempotencyKey,
    orderedKeyBindings,
    protocolVersions: [
      { keyFamily: 'ed25519', version: 'rotatable_signing_lane_protocol_v1' },
      { keyFamily: 'ecdsa_secp256k1', version: 'rotatable_signing_lane_protocol_v1' },
    ],
    approvedAtMs: base.approval.approvedAtMs,
    expiresAtMs: base.approval.expiresAtMs,
  });
  const transcript = buildLinkedDeviceEnrollmentTranscriptV1({
    linkSessionId: approval.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    linkPublicKeyB64u: approval.linkPublicKeyB64u,
    devicePublicKeyB64u: approval.devicePublicKeyB64u,
    permission: approval.permission,
    targetFactor: approval.targetFactor,
    ownerAuthorization: approval.ownerAuthorization,
    // The transcript is the durable record of the approval, so it carries the
    // same ceremony the approval authorized.
    ownerEnrollment: approval.ownerEnrollment,
    policyDigestB64u: approval.policyDigestB64u,
    operationId: approval.operationId,
    idempotencyKey: approval.idempotencyKey,
    orderedKeyBindings: approval.orderedKeyBindings,
    protocolVersions: approval.protocolVersions,
    approvedAtMs: approval.approvedAtMs,
    expiresAtMs: approval.expiresAtMs,
  });
  const deviceLink = { ...base, approval, transcript };
  const credentialIdB64u = required(
    parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
  );
  const preparation = buildLinkedDeviceTargetPreparationV1({
    linkSessionId: approval.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    targetFactor: approval.targetFactor,
    ownerEnrollment: approval.ownerEnrollment,
    orderedChildren: [
      buildMixedPreparationChild(ed25519),
      buildMixedPreparationChild(ecdsa),
    ] as const,
    issuedAtMs: 3_003,
    expiresAtMs: 7_000,
  });
  const targetPreparationDigestB64u =
    await computeLinkedDeviceTargetPreparationDigestV1(preparation);
  const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
    linkSessionId: approval.linkSessionId,
    walletId: approval.walletId,
    enrollmentId: approval.enrollmentId,
    deviceId: approval.deviceId,
    targetFactor: approval.targetFactor,
    targetPreparationDigestB64u,
    webauthnRegistration: {
      kind: 'linked_device_webauthn_registration_v1',
      credentialIdB64u,
      authenticatorAttachment: 'platform',
      clientDataJsonB64u: 'AQID',
      attestationObjectB64u: 'BAUG',
      transports: ['internal'],
    },
    orderedHolderRegistrations: [
      buildMixedHolderRegistration(ed25519),
      buildMixedHolderRegistration(ecdsa),
    ] as const,
    registeredAtMs: 3_004,
  });
  return { deviceLink, targetCredential: { preparation, registration }, sourceJobs };
}

function buildMixedApprovalBinding(
  job: RotatableSigningLaneJobV1,
): LinkedDeviceEnrollmentKeyBindingV1 {
  const common = {
    walletKeyId: job.walletKeyId,
    keyFamily: job.keyFamily,
    sourceLaneId: job.source.laneId,
    sourceLaneShareEpoch: job.source.laneShareEpoch,
    sourceRevocationEpoch: job.source.revocationEpoch,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
  };
  if (job.source.sourceKind === 'owner_registration') {
    return {
      ...common,
      sourceKind: 'owner_registration',
      sourceLaneKind: job.source.laneKind,
      ownerParticipantContinuity: job.source.ownerParticipantContinuity,
    };
  }
  return {
    ...common,
    sourceKind: 'provisioned_lane',
    sourceLaneKind: job.source.laneKind,
    sourceHolderParticipantId: job.source.holderParticipantId,
    sourceSigningWorkerParticipantId: job.source.signingWorkerParticipantId,
  };
}

function buildR103SourceForBinding(
  source: ActiveLaneProtocolSourceV1,
  binding: LinkedDeviceEnrollmentKeyBindingV1,
  materialActivation: ActiveLaneProtocolSourceV1['materialActivation'],
): ActiveLaneProtocolSourceV1 {
  const common = {
    laneId: binding.sourceLaneId,
    laneShareEpoch: binding.sourceLaneShareEpoch,
    revocationEpoch: binding.sourceRevocationEpoch,
    participantBindingDigestB64u: source.participantBindingDigestB64u,
    materialActivation,
  };
  if (binding.sourceKind === 'owner_registration') {
    if (source.sourceKind !== 'owner_registration') {
      throw new Error('R103 owner fixture binding source kind mismatch');
    }
    return {
      ...common,
      sourceKind: 'owner_registration',
      laneKind: binding.sourceLaneKind,
      ownerParticipantContinuity: binding.ownerParticipantContinuity,
    };
  }
  if (source.sourceKind !== 'provisioned_lane') {
    throw new Error('R103 provisioned fixture binding source kind mismatch');
  }
  return {
    ...common,
    sourceKind: 'provisioned_lane',
    laneKind: binding.sourceLaneKind,
    holderParticipantId: binding.sourceHolderParticipantId,
    signingWorkerParticipantId: binding.sourceSigningWorkerParticipantId,
    signingWorkerRecipientKeyId: source.signingWorkerRecipientKeyId,
  };
}

function buildMixedPreparationChild(
  job: RotatableSigningLaneJobV1,
): LinkedDeviceTargetPreparationChildV1 {
  return {
    kind: 'linked_device_target_preparation_child_v1',
    operationId: job.operationId,
    walletKeyId: job.walletKeyId,
    keyFamily: job.keyFamily,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    targetHolderParticipantId: job.targetHolder.participantId,
  };
}

function buildMixedHolderRegistration(
  job: RotatableSigningLaneJobV1,
): LinkedDeviceTargetHolderRegistrationV1 {
  return {
    kind: 'linked_device_target_holder_registration_v1',
    operationId: job.operationId,
    walletKeyId: job.walletKeyId,
    keyFamily: job.keyFamily,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    holderParticipant: parseLaneHolderParticipantRecordV1({
      kind: 'lane_holder_participant_v1',
      participantId: job.targetHolder.participantId,
      custodyBindingId: job.targetHolder.custodyBindingId,
      custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    }),
  };
}

function buildUnsignedJwt(payload: Readonly<Record<string, unknown>>): string {
  const header = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })),
  );
  const body = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  return `${header}.${body}.signature`;
}

function assertNeverLinkedDeviceKeyFamily(value: never): never {
  throw new Error(`unsupported linked-device key family: ${String(value)}`);
}

export function buildR103LinkedWalletSessionDeliveryFixture(
  fixture: R103DeviceLinkFixture,
  input: { readonly sessionSuffix?: string } = {},
): LinkedDeviceWalletSessionDeliveryV1 {
  const binding = fixture.approval.orderedKeyBindings[0];
  if (!binding) throw new Error('R103 approval fixture has no key binding');
  const issuedAtMs = fixture.receipt.activatedAtMs;
  const expiresAtMs = issuedAtMs + 86_400_000;
  const sessionSuffix = input.sessionSuffix ? `:${input.sessionSuffix}` : '';
  const authorizationId = `linked-authorization-r103-delivery${sessionSuffix}`;
  const walletSessionId = `linked-wallet-session-r103-delivery${sessionSuffix}`;
  const quotaId = `linked-quota-r103-delivery${sessionSuffix}`;
  const walletSessionJwt = buildUnsignedJwt({
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'linked_device_wallet_session',
    sub: `linked-device:${fixture.approval.deviceId}`,
    tenantId: 'tenant-r103-delivery',
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    authorizationId,
    walletSessionId,
    quotaId,
    keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
    permission: fixture.approval.permission,
    revocationEpoch: binding.sourceRevocationEpoch,
    issuedAtMs,
    expiresAtMs,
    walletKeyId: binding.walletKeyId,
    iat: Math.floor(issuedAtMs / 1_000),
    exp: Math.floor(expiresAtMs / 1_000),
  });
  switch (binding.keyFamily) {
    case 'ed25519':
      return parseLinkedDeviceWalletSessionDeliveryV1({
        kind: 'linked_device_wallet_session_delivery_v1',
        tenantId: 'tenant-r103-delivery',
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        authorizationId,
        walletSessionId,
        quotaId,
        keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
        permission: fixture.approval.permission,
        revocationEpoch: binding.sourceRevocationEpoch,
        remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
        issuedAtMs,
        expiresAtMs,
        nearAccountId: 'alice.testnet',
        orderedTokens: [
          {
            kind: 'linked_device_wallet_session_token_v1',
            walletKeyId: binding.walletKeyId,
            keyFamily: 'ed25519',
            walletSessionJwt,
            revocationEpoch: binding.sourceRevocationEpoch,
          },
        ],
      });
    case 'ecdsa_secp256k1':
      return parseLinkedDeviceWalletSessionDeliveryV1({
        kind: 'linked_device_wallet_session_delivery_v1',
        tenantId: 'tenant-r103-delivery',
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        authorizationId,
        walletSessionId,
        quotaId,
        keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
        permission: fixture.approval.permission,
        revocationEpoch: binding.sourceRevocationEpoch,
        remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
        issuedAtMs,
        expiresAtMs,
        orderedTokens: [
          {
            kind: 'linked_device_wallet_session_token_v1',
            walletKeyId: binding.walletKeyId,
            keyFamily: 'ecdsa_secp256k1',
            walletSessionJwt,
            revocationEpoch: binding.sourceRevocationEpoch,
          },
        ],
      });
    default:
      return assertNeverLinkedDeviceKeyFamily(binding.keyFamily);
  }
}

export function buildR103ProvisioningFixture(
  fixture: R103DeviceLinkFixture,
): R103ProvisioningFixture {
  const approved = fixture.approval.orderedKeyBindings[0];
  if (!approved) throw new Error('R103 approval fixture has no child');
  const source = buildR102LaneJob('r103-provisioning');
  const job = parseRotatableSigningLaneJobV1({
    ...source,
    operationId: fixture.approval.operationId,
    enrollmentId: fixture.approval.enrollmentId,
    idempotencyKey: fixture.approval.idempotencyKey,
    walletId: fixture.approval.walletId,
    walletKeyId: approved.walletKeyId,
    source: buildR103SourceForBinding(source.source, approved, {
      ...source.source.materialActivation,
      capability: fixture.receipt.orderedChildReceipts[0].materialActivation.capability,
      materialOwner: fixture.receipt.orderedChildReceipts[0].materialActivation.materialOwner,
      keyBinding: fixture.receipt.orderedChildReceipts[0].materialActivation.keyBinding,
      lifecycleBinding: fixture.receipt.orderedChildReceipts[0].materialActivation.lifecycleBinding,
    }),
    targetSigningWorker: {
      ...source.targetSigningWorker,
      participantId: required(
        parseSigningWorkerParticipantId(
          String(fixture.receipt.orderedChildReceipts[0].materialActivation.signingWorker),
        ),
      ),
    },
    target: {
      ...source.target,
      laneId: approved.targetLaneId,
      laneShareEpoch: approved.targetLaneShareEpoch,
    },
    targetMaterialActivationId:
      fixture.receipt.orderedChildReceipts[0].materialActivation.activationId,
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: fixture.approval.operationId,
      linkedDeviceEnrollmentId: fixture.approval.enrollmentId,
      linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
    },
    expiresAtMs: fixture.approval.expiresAtMs,
  });
  const manifest = buildLaneEnrollmentManifestV1({
    enrollmentId: required(parseLaneEnrollmentId(String(fixture.approval.enrollmentId))),
    walletId: fixture.approval.walletId,
    authorization: job.authorization,
    orderedChildren: [buildR102ManifestChild(job)],
    createdAtMs: fixture.approval.approvedAtMs,
    expiresAtMs: fixture.approval.expiresAtMs,
  });
  const deliveries = parseLinkedDeviceProvisioningDeliveriesV1({
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId: fixture.approval.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    manifest,
    orderedChildren: [
      {
        kind: 'linked_device_provisioning_child_v1',
        job,
        protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
        holderPackage: {
          kind: 'ed25519_yao_lane_holder_package_set_v1',
          deriverAEncryptedPackageJson: '{}',
          deriverBEncryptedPackageJson: '{}',
        },
        expectedVersion: 2,
      },
    ],
  });
  return {
    command: buildLinkedDeviceProvisioningCommandV1({
      linkSessionId: fixture.approval.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      targetFactor: fixture.approval.targetFactor,
    }),
    deliveries,
    acknowledgement: buildLinkedDeviceHolderDeliveryAcknowledgementV1({
      linkSessionId: fixture.approval.linkSessionId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      orderedHolderDeliveryReceipts: [buildR102HolderDeliveryReceipt(job)],
      acknowledgedAtMs: 3_500,
    }),
  };
}

export function buildR103TargetReadySourceFixture(fixture: R103DeviceLinkFixture): {
  readonly targetReady: LinkedDeviceTargetReadyR102InputV1;
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
} {
  const deliveries = buildR103ProvisioningFixture(fixture).deliveries;
  const job = deliveries.orderedChildren[0].job;
  return {
    targetReady: parseLinkedDeviceTargetReadyR102InputV1({
      kind: 'linked_device_target_ready_r102_input_v1',
      linkSessionId: fixture.approval.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      deviceId: fixture.approval.deviceId,
      manifest: deliveries.manifest,
      children: [job],
    }),
    deliveries,
  };
}

export async function buildR103TargetPreparationFixture(
  fixture: R103DeviceLinkFixture,
): Promise<LinkedDeviceTargetPreparationV1> {
  const binding = fixture.approval.orderedKeyBindings[0];
  const job = buildR103ProvisioningFixture(fixture).deliveries.orderedChildren[0].job;
  return buildLinkedDeviceTargetPreparationV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    targetFactor: fixture.approval.targetFactor,
    ownerEnrollment: fixture.approval.ownerEnrollment,
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
}

function buildR103TargetHolderRegistrations(
  fixture: R103DeviceLinkFixture,
  preparation: LinkedDeviceTargetPreparationV1,
): readonly [LinkedDeviceTargetHolderRegistrationV1, ...LinkedDeviceTargetHolderRegistrationV1[]] {
  const job = buildR103ProvisioningFixture(fixture).deliveries.orderedChildren[0].job;
  const child = preparation.orderedChildren[0];
  return [
    {
      kind: 'linked_device_target_holder_registration_v1',
      operationId: child.operationId,
      walletKeyId: child.walletKeyId,
      keyFamily: child.keyFamily,
      targetLaneId: child.targetLaneId,
      targetLaneShareEpoch: child.targetLaneShareEpoch,
      targetMaterialActivationId: child.targetMaterialActivationId,
      holderParticipant: {
        kind: 'lane_holder_participant_v1',
        ...job.targetHolder,
      },
    },
  ];
}

export async function buildR103TargetCredentialFixture(
  fixture: R103DeviceLinkFixture,
): Promise<R103TargetCredentialFixture> {
  if (fixture.approval.targetFactor.kind !== 'passkey_prf') {
    throw new Error('the Passkey target-credential fixture requires a Passkey approval');
  }
  const preparation = await buildR103TargetPreparationFixture(fixture);
  const credentialIdB64u = required(
    parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(6))),
  );
  const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    targetFactor: { kind: 'passkey_prf' },
    targetPreparationDigestB64u: await computeLinkedDeviceTargetPreparationDigestV1(preparation),
    webauthnRegistration: {
      kind: 'linked_device_webauthn_registration_v1',
      credentialIdB64u,
      authenticatorAttachment: 'platform',
      clientDataJsonB64u: 'AQID',
      attestationObjectB64u: 'BAUG',
      transports: ['internal'],
    },
    orderedHolderRegistrations: buildR103TargetHolderRegistrations(fixture, preparation),
    registeredAtMs: 3_004,
  });
  return { preparation, registration };
}

export async function buildR103EmailOtpTargetCredentialFixture(input: {
  readonly fixture: R103DeviceLinkFixture;
  readonly verificationGrant: LinkedDeviceEmailOtpVerificationGrantV1;
  readonly registeredAtMs: number;
}): Promise<R103TargetCredentialFixture> {
  if (input.fixture.approval.targetFactor.kind !== 'email_otp') {
    throw new Error('the Email OTP target-credential fixture requires an Email OTP approval');
  }
  const preparation = await buildR103TargetPreparationFixture(input.fixture);
  const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
    linkSessionId: input.fixture.approval.linkSessionId,
    walletId: input.fixture.approval.walletId,
    enrollmentId: input.fixture.approval.enrollmentId,
    deviceId: input.fixture.approval.deviceId,
    targetFactor: { kind: 'email_otp' },
    targetPreparationDigestB64u: await computeLinkedDeviceTargetPreparationDigestV1(preparation),
    emailOtpVerificationGrant: input.verificationGrant,
    orderedHolderRegistrations: buildR103TargetHolderRegistrations(input.fixture, preparation),
    registeredAtMs: input.registeredAtMs,
  });
  return { preparation, registration };
}

export async function buildR103ActiveExecutionFixture(
  input: { readonly linkSessionId?: string } = {},
): Promise<R103ActiveExecutionFixture> {
  const base = buildR103DeviceLinkFixture(input);
  const provisioning = buildR103ProvisioningFixture(base);
  const manifestDigestB64u = parseDigestB64u(
    await computeLaneEnrollmentManifestDigestV1(provisioning.deliveries.manifest),
  );
  const deviceLink: R103DeviceLinkFixture = {
    ...base,
    receipt: buildLinkedDeviceEnrollmentReceiptV1({
      ...base.receipt,
      manifestDigestB64u,
    }),
  };
  return {
    deviceLink,
    targetCredential: await buildR103TargetCredentialFixture(deviceLink),
    provisioning,
    walletSession: buildR103LinkedWalletSessionDeliveryFixture(deviceLink),
  };
}

export function buildR103DeviceLinkFixture(
  input: {
    readonly linkSessionId?: string;
    readonly enrollmentId?: string;
    readonly deviceId?: string;
    /** The immutable factor branch; defaults to the recommended Passkey. */
    readonly targetFactor?: LinkedDeviceTargetFactorV1;
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
    custodyKeyManifestDigestB64u: DIGEST,
    sourceIdentityDigestB64u: DIGEST,
  });
  const payload = parseQrLinkedDeviceSessionPayloadV5({
    version: 'v5',
    purpose: 'linked_device_lane_creation',
    linkSessionId,
    linkPublicKeyB64u: PUBLIC_KEY,
    devicePublicKeyB64u: PUBLIC_KEY,
    requestedPermission: {
      kind: 'owner_equivalent_signing',
      administrationScope: 'signing_only',
      localUserPresence: 'required',
    },
    targetFactor,
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
    targetFactor,
    ownerAuthorization,
    policyDigestB64u: DIGEST,
    operationId,
    idempotencyKey,
    orderedKeyBindings: [
      {
        walletKeyId,
        keyFamily: 'ed25519' as const,
        sourceLaneId,
        sourceLaneKind: 'owner_passkey' as const,
        sourceKind: 'owner_registration' as const,
        sourceLaneShareEpoch,
        sourceRevocationEpoch: 0,
        ownerParticipantContinuity,
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
  const approval = buildLinkedDeviceApprovalV1({
    ...common,
    ownerEnrollment:
      targetFactor.kind === 'passkey_prf'
        ? buildR103OwnerEnrollmentCeremonyV1()
        : buildR103EmailOtpOwnerEnrollmentCeremonyV1({
            walletId: String(walletId),
            // The email branch restates the approval expiry as its deadline.
            expiresAtMs: common.expiresAtMs,
          }),
  });
  const transcript = buildLinkedDeviceEnrollmentTranscriptV1({
    ...common,
    ownerEnrollment: approval.ownerEnrollment,
  });
  const childReceipt = buildLinkedDeviceEnrollmentChildReceiptV1({
    enrollmentId,
    walletId,
    walletKeyId,
    keyFamily: 'ed25519',
    targetLaneId,
    targetLaneShareEpoch,
    materialActivation: activation,
    receiptDigestB64u: R102_RECEIPT_DIGEST,
    transcriptHashB64u: R102_RECEIPT_DIGEST,
    deliveredAtMs: 8_000,
  });
  const receipt = buildLinkedDeviceEnrollmentReceiptV1({
    enrollmentId,
    walletId,
    deviceId,
    targetFactor,
    manifestDigestB64u: DIGEST,
    aggregateReceiptDigestB64u: DIGEST,
    orderedChildReceipts: [childReceipt],
    activatedAtMs: 9_000,
  });
  const claimRequest = parseLinkedDeviceSessionClaimRequestV1({
    kind: 'linked_device_session_claim_request_v1',
    payload: buildQrLinkedDeviceSessionPayloadV5({
      linkSessionId,
      linkPublicKeyB64u: payload.linkPublicKeyB64u,
      devicePublicKeyB64u: payload.devicePublicKeyB64u,
      targetFactor,
      issuedAtMs: 1_000,
      expiresAtMs: 10_000,
    }),
  });
  return { payload, claimRequest, approval, transcript, receipt };
}

void DIGEST;
void PUBLIC_KEY;
void buildLinkedDeviceEnrollmentReceiptV1;

/**
 * The ceremony reader the session service checks approval provenance against.
 *
 * Returns the ceremony the server would have minted for this exact approval,
 * so a test exercises the provenance check rather than bypassing it. Tests that
 * want a denial pass a mismatched approval instead of stubbing this away.
 */
export function buildR103OwnerEnrollmentCeremonyReaderV1(approval: LinkedDeviceApprovalV1) {
  return {
    getAddAuthMethodCeremony: async (addAuthMethodCeremonyId: string) =>
      addAuthMethodCeremonyId === approval.ownerEnrollment.addAuthMethodCeremonyId
        ? ({
            kind: 'passkey',
            addAuthMethodCeremonyId: approval.ownerEnrollment.addAuthMethodCeremonyId,
            intent: { walletId: approval.walletId },
            digestB64u: 'digest',
            orgId: 'org',
            expiresAtMs: approval.ownerEnrollment.expiresAtMs,
            auth: {
              kind: 'webauthn_assertion',
              rpId: String(approval.ownerEnrollment.registration.rpId),
              credentialIdB64u: 'cred',
            },
            passkeyRegistration: {
              rpId: String(approval.ownerEnrollment.registration.rpId),
              challengeB64u: approval.ownerEnrollment.registration.challengeB64u,
              options: approval.ownerEnrollment.registration,
            },
            custodyEnvelope: {},
          } as never)
        : null,
  };
}

/**
 * The verified owner Wallet Session context an approval is recorded under.
 *
 * Approval reads the source key manifest from here rather than from the
 * approval body, so a call that omits it is not standing in for a real
 * owner-authenticated request.
 */
export function buildR103OwnerApprovalContextV1(
  approval: LinkedDeviceApprovalV1,
  overrides: { readonly keyManifestDigestB64u?: DigestB64u } = {},
) {
  return {
    walletId: approval.walletId,
    walletSessionId: parseWalletSessionId('ws:r103').value!,
    authorizationId: parseWalletSessionAuthorizationId('wsa:r103').value!,
    expiresAtMs: approval.expiresAtMs,
    curve: 'ed25519' as const,
    keyManifestDigestB64u:
      overrides.keyManifestDigestB64u ??
      parseDigestB64u('Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE'),
  };
}
