import {
  buildEvmEcdsaMpcOperationRef,
  buildLinkedDeviceWalletSessionAuthorizationRef,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseAuthorizationAuditEventId,
  parseCapabilityOperationId,
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  parseTenantId,
  parseWalletSessionId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildCapabilityOperationEnvelope } from '../../../packages/shared-ts/src/authorization/operationFingerprint';
import {
  buildLinkedDevicePrincipalId,
  buildLinkedDeviceWalletSessionAuthorization,
  buildAuthorizedOperation,
  type LinkedDeviceWalletSessionAuthorizationV1,
  type AuthorizedOperation,
} from '../../../packages/sdk-server-ts/src/authorization/domain';
import { buildLinkedDeviceSigningLaneRecord } from '../../../packages/shared-ts/src/signing-lanes/recordParsers';
import { parseLinkedDeviceEcdsaNormalSigningScopeV1 } from '../../../packages/shared-ts/src/signing-lanes/linkedEcdsaScope';
import { buildLaneProductEpochActiveV1 } from '../../../packages/shared-ts/src/signing-lanes/rotationParsers';
import type { LaneProductEpochActiveV1 } from '../../../packages/shared-ts/src/signing-lanes/rotation';
import {
  parseLaneHolderParticipantRecordV1,
  parseSigningWorkerParticipantRecordV1,
} from '../../../packages/shared-ts/src/signing-lanes/participants';
import { computeLaneParticipantSetBindingDigestV1 } from '../../../packages/shared-ts/src/signing-lanes/participantDigest';
import {
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneShareEpoch,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseMpcMaterialActivationId,
  parseCapabilityInstanceRef,
  parseMpcMaterialOwnerRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcSigningWorkerRef,
  parseSigningLaneId,
  parseWalletId,
  parseWalletKeyId,
  parseWebAuthnCredentialIdB64u,
  buildMpcMaterialActivationRef,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import type {
  ActiveLinkedDeviceExecutionProjectionV1,
  ActiveLinkedDeviceEnrollmentExecutionRecordV1,
  LinkedDeviceLocalPresenceEvidenceV1,
} from '../../../packages/sdk-server-ts/src/router/domains/signingOperations/walletExecutionAdmission';
import type { WalletId, WalletKeyId } from '../../../packages/shared-ts/src/utils/domainIds';
import { requireEvmFamilySigningKeySlotId } from '../../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import { parseSecp256k1CompressedPublicKeyB64u } from '../../../packages/shared-ts/src/passkey-custody/primitives';
import { parseWalletKeyVersion } from '../../../packages/shared-ts/src/signing-lanes/recordParsers';
import type { RouterAbNormalSigningMaterialSourceV1 } from '../../../packages/sdk-server-ts/src/router/domains/signingOperations/routerAbPrivateSigningWorker';

const FIXTURE_NOW_MS = 1_900_000_000_000;
const DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9)));
const HPKE_KEY = base64UrlEncode(new Uint8Array(32).fill(4));

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

export type LinkedDeviceWalletExecutionFixture = {
  readonly authorizedOperation: AuthorizedOperation;
  readonly authorization: LinkedDeviceWalletSessionAuthorizationV1;
  readonly projection: ActiveLinkedDeviceExecutionProjectionV1;
  readonly localPresence: LinkedDeviceLocalPresenceEvidenceV1;
};

export async function buildLinkedDeviceWalletExecutionFixture(): Promise<LinkedDeviceWalletExecutionFixture> {
  const walletId = required(parseWalletId('wallet-linked-admission'));
  const walletKeyId = required(parseWalletKeyId('wallet-key:evm:linked-admission'));
  const laneId = required(parseSigningLaneId('lane:linked-device:admission'));
  const laneShareEpoch = required(parseLaneShareEpoch('lane-share-epoch:linked-admission'));
  const operationId = required(parseLaneOperationId('operation:linked-admission'));
  const enrollmentId = required(parseLinkedDeviceEnrollmentId('enrollment:linked-admission'));
  const laneEnrollmentId = required(parseLaneEnrollmentId(String(enrollmentId)));
  const deviceId = required(parseLinkedDeviceId('linked-device:admission'));
  const tenantId = required(parseTenantId('tenant-linked-admission'));
  const principalId = buildLinkedDevicePrincipalId(deviceId);
  const capabilityId = required(parseCapabilityId('capability-evm-linked-admission'));
  const authorizedOperationId = required(
    parseAuthorizedOperationId('authorized-operation:linked-admission'),
  );
  const authorizationId = required(
    parseLinkedDeviceWalletSessionAuthorizationId('authorization:linked-admission'),
  );
  const walletSessionId = required(parseWalletSessionId('wallet-session:linked-admission'));
  const quotaId = required(parseMpcWalletSigningQuotaId('wallet-quota:linked-admission'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u('credential-linked-admission'));
  const materialActivation = buildMpcMaterialActivationRef({
    activationId: required(parseMpcMaterialActivationId('activation:linked-admission')),
    capability: required(parseCapabilityInstanceRef('capability-evm-linked-admission')),
    materialOwner: required(parseMpcMaterialOwnerRef(String(walletId))),
    keyBinding: required(parseMpcKeyBindingRef('key-binding:linked-admission')),
    lifecycleBinding: required(parseMpcLifecycleBindingRef('lifecycle:linked-admission')),
    signingWorker: required(parseMpcSigningWorkerRef('worker:linked-admission')),
  });
  const holderParticipant = parseLaneHolderParticipantRecordV1({
    kind: 'lane_holder_participant_v1',
    participantId: 'linked-holder:admission',
    custodyBindingId: 'linked-custody:admission',
    custodyBindingDigestB64u: DIGEST,
    hpkePublicKeyB64u: HPKE_KEY,
    hpkePublicKeyDigestB64u: DIGEST,
    participantBindingDigestB64u: DIGEST,
  });
  const signingWorkerParticipant = parseSigningWorkerParticipantRecordV1({
    kind: 'signing_worker_participant_v1',
    participantId: 'worker:linked-admission',
    recipientKeyId: 'linked-recipient:admission',
    hpkePublicKeyB64u: HPKE_KEY,
    hpkePublicKeyDigestB64u: DIGEST,
    participantBindingDigestB64u: DIGEST,
  });
  const participantBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
    holderParticipant,
    signingWorkerParticipant,
  });
  const lane = buildLinkedDeviceSigningLaneRecord({
    walletId,
    walletKeyId,
    laneId,
    laneShareEpoch,
    participantBindingDigestB64u,
    holderParticipant,
    serverParticipant: signingWorkerParticipant,
    lifecycle: {
      state: 'active',
      revocationEpoch: 0,
      activatedAtMs: FIXTURE_NOW_MS,
      activationReceiptDigestB64u: DIGEST,
    },
    linkedDeviceId: deviceId,
  });
  const product = buildLaneProductEpochActiveV1({
    walletId,
    walletKeyId,
    laneId,
    laneKind: 'linked_device',
    laneShareEpoch,
    keyFamily: 'ecdsa_secp256k1',
    enrollmentId: laneEnrollmentId,
    operationId,
    targetMaterialActivationId: materialActivation.activationId,
    materialActivation,
    publicIdentityDigestB64u: DIGEST,
    holderParticipant,
    signingWorkerParticipant,
    participantSetBindingDigestB64u: participantBindingDigestB64u,
    revocationEpoch: 0,
    createdAtMs: FIXTURE_NOW_MS,
    aggregateManifestDigestB64u: DIGEST,
    aggregateActivationReceiptDigestB64u: DIGEST,
    activatedAtMs: FIXTURE_NOW_MS,
  });
  const authorization = buildLinkedDeviceWalletSessionAuthorization({
    tenantId,
    authorizationGrantRef: buildLinkedDeviceWalletSessionAuthorizationRef(authorizationId),
    walletId,
    enrollmentId,
    deviceId,
    walletSessionId,
    quotaId,
    keyManifestDigestB64u: DIGEST,
    permission: {
      kind: 'owner_equivalent_signing',
      administrationScope: 'signing_only',
      localUserPresence: 'required',
    },
    revocationEpoch: 0,
    issuedAtMs: FIXTURE_NOW_MS,
    expiresAtMs: FIXTURE_NOW_MS + 60_000,
  });
  const operation = buildCapabilityOperationEnvelope({
    tenantId,
    principalId,
    capabilityId,
    operationId: required(parseCapabilityOperationId('capability-operation:linked-admission')),
    operation: buildEvmEcdsaMpcOperationRef('evm.sign_transaction'),
    digests: {
      laneDigest: DIGEST,
      intentDigest: DIGEST,
      displayDigest: DIGEST,
    },
  });
  const authorizedOperation = await buildAuthorizedOperation({
    tenantId,
    authorizedOperationId,
    auditEventId: required(parseAuthorizationAuditEventId('audit-event:linked-admission')),
    operation,
    authorization: {
      kind: 'authorization_grant',
      authorizationGrantRef: authorization.authorizationGrantRef,
    },
    quota: { kind: 'consume_reusable_wallet_session', quotaId },
    claimedAtMs: FIXTURE_NOW_MS + 1,
  });
  const enrollment: ActiveLinkedDeviceEnrollmentExecutionRecordV1 = {
    kind: 'active_linked_device_enrollment_v1',
    walletId,
    enrollmentId,
    deviceId,
    keyManifestDigestB64u: DIGEST,
    credentialIdB64u,
    revocationEpoch: 0,
    lifecycle: { state: 'active', activatedAtMs: FIXTURE_NOW_MS },
  };
  const walletKey = buildWalletKeyFixture(walletId, walletKeyId);
  const materialSource: Extract<
    RouterAbNormalSigningMaterialSourceV1,
    { readonly kind: 'rotatable_lane' }
  > = {
    kind: 'rotatable_lane',
    lookup: {
      identity: {
        operationId,
        enrollmentId: laneEnrollmentId,
        walletId,
        walletKeyId,
        targetLaneId: laneId,
        targetLaneShareEpoch: laneShareEpoch,
        targetMaterialActivationId: materialActivation.activationId,
        keyFamily: 'ecdsa_secp256k1',
        holderParticipantBindingDigestB64u: holderParticipant.participantBindingDigestB64u,
        signingWorkerParticipantBindingDigestB64u:
          signingWorkerParticipant.participantBindingDigestB64u,
        holderRecipientKeyDigestB64u: holderParticipant.hpkePublicKeyDigestB64u,
        serverRecipientKeyDigestB64u: signingWorkerParticipant.hpkePublicKeyDigestB64u,
        transcriptHashB64u: DIGEST,
        protocolCommitReceiptDigestB64u: DIGEST,
      },
      admittedLaneIdentityDigestB64u: DIGEST,
    },
    group_public_key: String(walletKey.thresholdPublicKey33B64u),
  };
  const ecdsaNormalSigningScope = parseLinkedDeviceEcdsaNormalSigningScopeV1({
    kind: 'linked_device_ecdsa_normal_signing_scope_v1',
    keyFamily: 'ecdsa_secp256k1',
    laneKind: 'linked_device',
    walletId,
    walletKeyId,
    enrollmentId: laneEnrollmentId,
    operationId,
    laneId,
    laneShareEpoch,
    revocationEpoch: 0,
    targetMaterialActivationId: materialActivation.activationId,
    materialActivation,
    targetCapability: {
      manifestId: 'manifest:linked-admission',
      manifestRevision: 1,
      ecdsaThresholdKeyId: 'threshold-key:linked-admission',
      orderedThresholdSessions: [
        {
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 1,
            networkSlug: 'mainnet',
          },
          thresholdSessionId: 'threshold-session:linked-admission',
          participantBindingDigestB64u: DIGEST,
        },
      ],
    },
    thresholdPublicKey33B64u: walletKey.thresholdPublicKey33B64u,
    evmAddress: walletKey.evmAddress,
    publicIdentityDigestB64u: DIGEST,
    targetHolderPublicCommitmentB64u: walletKey.thresholdPublicKey33B64u,
    targetServerPublicCommitmentB64u: walletKey.thresholdPublicKey33B64u,
    holderParticipantId: holderParticipant.participantId,
    signingWorkerParticipantId: signingWorkerParticipant.participantId,
    holderParticipantBindingDigestB64u: holderParticipant.participantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u:
      signingWorkerParticipant.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: holderParticipant.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: signingWorkerParticipant.hpkePublicKeyDigestB64u,
    signingWorkerRecipientKeyId: signingWorkerParticipant.recipientKeyId,
    signingWorkerHpkePublicKeyB64u: signingWorkerParticipant.hpkePublicKeyB64u,
    transcriptHashB64u: DIGEST,
    protocolCommitReceiptDigestB64u: DIGEST,
  });
  return {
    authorizedOperation,
    authorization,
    projection: {
      kind: 'active_linked_device_execution_projection_v1',
      authorization,
      enrollment,
      walletKey,
      lane,
      product,
      materialActivation,
      verifiedLaneParticipantBindingDigestB64u: participantBindingDigestB64u,
      verifiedActivationReceiptDigestB64u: DIGEST,
      materialSource,
      ecdsaNormalSigningScope,
    },
    localPresence: {
      kind: 'linked_device_local_presence_evidence_v1',
      authorizedOperationId,
      deviceId,
      enrollmentId,
      credentialIdB64u,
      intentDigestB64u: DIGEST,
      verifiedAtMs: FIXTURE_NOW_MS + 1,
      assertionDigestB64u: DIGEST,
    },
  };
}

function buildWalletKeyFixture(walletId: WalletId, walletKeyId: WalletKeyId) {
  return {
    kind: 'wallet_key_record_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletId,
    walletKeyId,
    walletKeyVersion: parseWalletKeyVersion('wallet-key-version:linked-admission'),
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      'wallet-key:evm-family:linked-admission:root:version-1',
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      base64UrlEncode(Uint8Array.from([2, ...new Uint8Array(32).fill(11)])),
    ),
    evmAddress: '0x1111111111111111111111111111111111111111',
    lifecycle: { state: 'active' as const, activatedAtMs: FIXTURE_NOW_MS },
  };
}

void buildEvmEcdsaMpcOperationRef;
void buildCapabilityOperationEnvelope;
