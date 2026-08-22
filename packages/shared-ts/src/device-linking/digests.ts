import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { alphabetizeStringify, sha256Bytes, sha256BytesUtf8 } from '../utils/digests';
import {
  delegatedWalletPermissionNamesV1,
  type DelegatedWalletAuthorityV1,
  type DelegatedWalletPermissionV1,
} from '../authorization/delegatedAuthority';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceOwnerEnrollmentCeremonyV1,
  LinkedDeviceProtocolVersionV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationChildV1,
  LinkedDeviceEd25519ExportRootPreparationV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceTargetFactorV1,
} from './contracts';
import {
  parseAuthorizedOperationId,
  type AuthorizedOperationId,
  type LinkedDeviceWalletSessionAuthorizationId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '../authorization/capabilityKinds';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '../signing-lanes/ids';
import type { WebAuthnCredentialIdB64u } from '../utils/domainIds';
import { ownerLaneParticipantContinuityCanonicalBytesV1 } from '../signing-lanes/ownerContinuity';

export {
  computeCommittedSignerPackageDigestB64u,
  computeCommittedSignerPackageSetDigestB64u,
} from './committedSignerPackages';

const CLAIM_DOMAIN = 'seams/linked-device/session-claim/v1';
const APPROVAL_DOMAIN = 'seams/linked-device/owner-approval/v1';
const TARGET_PREPARATION_DOMAIN = 'seams/linked-device/target-preparation/v1';
const LOCAL_PRESENCE_DOMAIN = 'seams/linked-device/local-presence/v1';
const WALLET_SESSION_RENEWAL_DOMAIN = 'seams/linked-device/wallet-session-renewal/v1';
const TEXT_ENCODER = new TextEncoder();

export async function computeLinkedDeviceProvisioningDeliveriesDigestV1(
  value: LinkedDeviceProvisioningDeliveriesV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function u32(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`${label} must be a non-negative u32`);
  }
  return Uint8Array.from([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function u64(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  let remaining = BigInt(value);
  const output = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function lp32(value: Uint8Array, label: string): Uint8Array {
  return concat([u32(value.length, `${label}.length`), value]);
}

function text(value: string, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return lp32(TEXT_ENCODER.encode(value), label);
}

function rawDigest(value: DigestB64u, label: string): Uint8Array {
  try {
    const decoded = base64UrlDecode(parseDigestB64u(value));
    if (decoded.length !== 32) throw new Error('must decode to 32 bytes');
    return decoded;
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function rawPublicKey(value: string, label: string): Uint8Array {
  try {
    const decoded = base64UrlDecode(value);
    if (decoded.length === 0 || base64UrlEncode(decoded) !== value) {
      throw new Error('must be canonical base64url');
    }
    return decoded;
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function encodeOwnerAuthorization(value: LinkedDeviceOwnerAuthorizationSourceV1): Uint8Array {
  if (value.kind === 'wallet_session') {
    return concat([
      text(value.kind, 'ownerAuthorization.kind'),
      text(value.walletSessionId, 'ownerAuthorization.walletSessionId'),
      text(value.authorizationId, 'ownerAuthorization.authorizationId'),
    ]);
  }
  return concat([
    text(value.kind, 'ownerAuthorization.kind'),
    text(value.evidenceSetId, 'ownerAuthorization.evidenceSetId'),
  ]);
}

function encodeDelegatedWalletAuthority(value: DelegatedWalletAuthorityV1): Uint8Array {
  const encodedPermissions = delegatedWalletPermissionNamesV1(value).map(
    encodeDelegatedWalletPermission,
  );
  return concat([
    text(value.kind, 'permission.kind'),
    u32(encodedPermissions.length, 'permission.permissions'),
    ...encodedPermissions.map(lengthPrefixedPermission),
  ]);
}

function encodeDelegatedWalletPermission(permission: DelegatedWalletPermissionV1): Uint8Array {
  return text(permission, 'permission.permissions.item');
}

function lengthPrefixedPermission(permission: Uint8Array): Uint8Array {
  return lp32(permission, 'permission.permissions.item');
}

function encodeKeyBinding(value: LinkedDeviceEnrollmentKeyBindingV1): Uint8Array {
  const common = [
    text(value.walletKeyId, 'keyBinding.walletKeyId'),
    text(value.keyFamily, 'keyBinding.keyFamily'),
    text(value.sourceLaneId, 'keyBinding.sourceLaneId'),
    text(value.sourceLaneKind, 'keyBinding.sourceLaneKind'),
    text(value.sourceKind, 'keyBinding.sourceKind'),
    text(value.sourceLaneShareEpoch, 'keyBinding.sourceLaneShareEpoch'),
    u64(value.sourceRevocationEpoch, 'keyBinding.sourceRevocationEpoch'),
    text(value.targetLaneId, 'keyBinding.targetLaneId'),
    text(value.targetLaneShareEpoch, 'keyBinding.targetLaneShareEpoch'),
  ] as const;
  if (value.ownerParticipantContinuity !== undefined) {
    return concat([
      ...common,
      ownerLaneParticipantContinuityCanonicalBytesV1(value.ownerParticipantContinuity),
    ]);
  }
  return concat([
    ...common,
    text(value.sourceHolderParticipantId, 'keyBinding.sourceHolderParticipantId'),
    text(value.sourceSigningWorkerParticipantId, 'keyBinding.sourceSigningWorkerParticipantId'),
  ]);
}

/**
 * The owner ceremony, bound by identity *and* by the exact registration
 * options it minted.
 *
 * Binding the id alone would leave the WebAuthn parameters unbound: a
 * substituted challenge or relying party would produce the same digest, and
 * Device 2 would create a credential against something the approval never
 * covered. Encoding the options field-by-field rather than hashing their JSON
 * keeps the digest independent of key order and of any field a future version
 * adds without meaning to.
 */
function encodeOwnerEnrollmentCeremony(value: LinkedDeviceOwnerEnrollmentCeremonyV1): Uint8Array {
  if (value.kind === 'linked_device_email_otp_owner_enrollment_v1') {
    return concat([
      text(value.kind, 'ownerEnrollment.kind'),
      text(value.targetFactor.kind, 'ownerEnrollment.targetFactor.kind'),
      text(value.baseWalletAuthMethodId, 'ownerEnrollment.baseWalletAuthMethodId'),
      text(value.maskedEmailHint, 'ownerEnrollment.maskedEmailHint'),
      u64(value.expiresAtMs, 'ownerEnrollment.expiresAtMs'),
    ]);
  }
  const registration = value.registration;
  const excludeCredentials = registration.excludeCredentials.map((entry) =>
    concat([text(entry.type, 'excludeCredentials.type'), text(entry.id, 'excludeCredentials.id')]),
  );
  return concat([
    text(value.kind, 'ownerEnrollment.kind'),
    text(value.targetFactor.kind, 'ownerEnrollment.targetFactor.kind'),
    text(value.addAuthMethodCeremonyId, 'ownerEnrollment.addAuthMethodCeremonyId'),
    u64(value.expiresAtMs, 'ownerEnrollment.expiresAtMs'),
    text(registration.kind, 'registration.kind'),
    text(registration.challengeId, 'registration.challengeId'),
    text(registration.challengeB64u, 'registration.challengeB64u'),
    text(registration.rpId, 'registration.rpId'),
    text(registration.user.idB64u, 'registration.user.idB64u'),
    text(registration.user.name, 'registration.user.name'),
    text(registration.user.displayName, 'registration.user.displayName'),
    u32(registration.pubKeyCredParams.length, 'registration.pubKeyCredParams'),
    ...registration.pubKeyCredParams.map((entry) =>
      lp32(
        concat([
          text(entry.type, 'pubKeyCredParams.type'),
          // Two's-complement is irrelevant here: the algorithms are fixed
          // negative COSE identifiers, so their decimal spelling is stable.
          text(String(entry.alg), 'pubKeyCredParams.alg'),
        ]),
        'registration.pubKeyCredParams.item',
      ),
    ),
    text(registration.authenticatorSelection.residentKey, 'registration.residentKey'),
    text(registration.authenticatorSelection.userVerification, 'registration.userVerification'),
    u64(registration.timeoutMs, 'registration.timeoutMs'),
    text(registration.attestation, 'registration.attestation'),
    text(registration.extensions.prf.eval.firstB64u, 'registration.prf.firstB64u'),
    text(registration.extensions.prf.eval.secondB64u, 'registration.prf.secondB64u'),
    u32(excludeCredentials.length, 'registration.excludeCredentials'),
    ...excludeCredentials.map((entry) => lp32(entry, 'registration.excludeCredentials.item')),
  ]);
}

function encodeTargetFactor(value: LinkedDeviceTargetFactorV1): Uint8Array {
  return text(value.kind, 'targetFactor.kind');
}

function encodeProtocolVersion(value: LinkedDeviceProtocolVersionV1): Uint8Array {
  return concat([
    text(value.keyFamily, 'protocolVersion.keyFamily'),
    text(value.version, 'protocolVersion.version'),
  ]);
}

function encodeTargetPreparationChild(value: LinkedDeviceTargetPreparationChildV1): Uint8Array {
  return concat([
    text(value.kind, 'targetPreparationChild.kind'),
    text(value.operationId, 'targetPreparationChild.operationId'),
    text(value.walletKeyId, 'targetPreparationChild.walletKeyId'),
    text(value.keyFamily, 'targetPreparationChild.keyFamily'),
    text(value.targetLaneId, 'targetPreparationChild.targetLaneId'),
    text(value.targetLaneShareEpoch, 'targetPreparationChild.targetLaneShareEpoch'),
    text(value.targetMaterialActivationId, 'targetPreparationChild.targetMaterialActivationId'),
    text(value.targetHolderParticipantId, 'targetPreparationChild.targetHolderParticipantId'),
  ]);
}

function encodeEd25519ExportRootPreparation(
  value: LinkedDeviceEd25519ExportRootPreparationV1 | null,
): Uint8Array {
  if (value === null) return text('none', 'ed25519ExportRoot.kind');
  return concat([
    text(value.kind, 'ed25519ExportRoot.kind'),
    text(value.walletKeyId, 'ed25519ExportRoot.walletKeyId'),
    rawDigest(value.applicationBindingDigestB64u, 'ed25519ExportRoot.applicationBindingDigestB64u'),
    rawPublicKey(value.registeredPublicKeyB64u, 'ed25519ExportRoot.registeredPublicKeyB64u'),
    u64(value.revocationEpoch, 'ed25519ExportRoot.revocationEpoch'),
  ]);
}

export function encodeLinkedDeviceSessionClaimV1(value: LinkedDeviceSessionClaimV1): Uint8Array {
  return concat([
    text(CLAIM_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.linkSessionId, 'linkSessionId'),
    text(value.walletId, 'walletId'),
    text(value.enrollmentId, 'enrollmentId'),
    text(value.deviceId, 'deviceId'),
    lp32(rawPublicKey(value.devicePublicKeyB64u, 'devicePublicKeyB64u'), 'devicePublicKeyB64u'),
    lp32(encodeTargetFactor(value.targetFactor), 'targetFactor'),
    u64(value.claimedAtMs, 'claimedAtMs'),
    u64(value.claimExpiresAtMs, 'claimExpiresAtMs'),
  ]);
}

export async function computeLinkedDeviceSessionClaimDigestV1(
  value: LinkedDeviceSessionClaimV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDeviceSessionClaimV1(value))),
  );
}

export function encodeLinkedDeviceApprovalV1(value: LinkedDeviceApprovalV1): Uint8Array {
  const orderedKeyBindings = value.orderedKeyBindings.map(encodeKeyBinding);
  const protocolVersions = value.protocolVersions.map(encodeProtocolVersion);
  return concat([
    text(APPROVAL_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.linkSessionId, 'linkSessionId'),
    text(value.walletId, 'walletId'),
    text(value.enrollmentId, 'enrollmentId'),
    text(value.deviceId, 'deviceId'),
    lp32(rawPublicKey(value.linkPublicKeyB64u, 'linkPublicKeyB64u'), 'linkPublicKeyB64u'),
    lp32(rawPublicKey(value.devicePublicKeyB64u, 'devicePublicKeyB64u'), 'devicePublicKeyB64u'),
    lp32(encodeDelegatedWalletAuthority(value.permission), 'permission'),
    lp32(encodeTargetFactor(value.targetFactor), 'targetFactor'),
    lp32(encodeOwnerAuthorization(value.ownerAuthorization), 'ownerAuthorization'),
    lp32(encodeOwnerEnrollmentCeremony(value.ownerEnrollment), 'ownerEnrollment'),
    rawDigest(value.policyDigestB64u, 'policyDigestB64u'),
    text(value.operationId, 'operationId'),
    text(value.idempotencyKey, 'idempotencyKey'),
    u32(orderedKeyBindings.length, 'orderedKeyBindings'),
    ...orderedKeyBindings.map((entry) => lp32(entry, 'orderedKeyBindings.item')),
    u32(protocolVersions.length, 'protocolVersions'),
    ...protocolVersions.map((entry) => lp32(entry, 'protocolVersions.item')),
    u64(value.approvedAtMs, 'approvedAtMs'),
    u64(value.expiresAtMs, 'expiresAtMs'),
  ]);
}

export async function computeLinkedDeviceApprovalDigestV1(
  value: LinkedDeviceApprovalV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(encodeLinkedDeviceApprovalV1(value))));
}

export function encodeLinkedDeviceTargetPreparationV1(
  value: LinkedDeviceTargetPreparationV1,
): Uint8Array {
  const children = value.orderedChildren.map(encodeTargetPreparationChild);
  return concat([
    text(TARGET_PREPARATION_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.linkSessionId, 'linkSessionId'),
    text(value.walletId, 'walletId'),
    text(value.enrollmentId, 'enrollmentId'),
    text(value.deviceId, 'deviceId'),
    lp32(encodeEd25519ExportRootPreparation(value.ed25519ExportRoot), 'ed25519ExportRoot'),
    lp32(encodeTargetFactor(value.targetFactor), 'targetFactor'),
    lp32(encodeOwnerEnrollmentCeremony(value.ownerEnrollment), 'ownerEnrollment'),
    u32(children.length, 'orderedChildren'),
    ...children.map((entry) => lp32(entry, 'orderedChildren.item')),
    u64(value.issuedAtMs, 'issuedAtMs'),
    u64(value.expiresAtMs, 'expiresAtMs'),
  ]);
}

export async function computeLinkedDeviceTargetPreparationDigestV1(
  value: LinkedDeviceTargetPreparationV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDeviceTargetPreparationV1(value))),
  );
}

export type LinkedDeviceLocalPresenceChallengeV1 = {
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export function encodeLinkedDeviceLocalPresenceChallengeV1(
  value: LinkedDeviceLocalPresenceChallengeV1,
): Uint8Array {
  if (value.issuedAtMs >= value.expiresAtMs) {
    throw new Error('linked-device local presence must expire after issuance');
  }
  return concat([
    text(LOCAL_PRESENCE_DOMAIN, 'domain'),
    text(value.authorizedOperationId, 'authorizedOperationId'),
    text(value.deviceId, 'deviceId'),
    text(value.enrollmentId, 'enrollmentId'),
    lp32(rawPublicKey(value.credentialIdB64u, 'credentialIdB64u'), 'credentialIdB64u'),
    rawDigest(value.intentDigestB64u, 'intentDigestB64u'),
    u64(value.issuedAtMs, 'issuedAtMs'),
    u64(value.expiresAtMs, 'expiresAtMs'),
  ]);
}

export async function computeLinkedDeviceLocalPresenceChallengeDigestV1(
  value: LinkedDeviceLocalPresenceChallengeV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDeviceLocalPresenceChallengeV1(value))),
  );
}

export function linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1(): AuthorizedOperationId {
  const parsed = parseAuthorizedOperationId('linked-device-wallet-session-renewal-v1');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

export async function computeLinkedDeviceWalletSessionRenewalIntentDigestV1(input: {
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
}): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        [
          WALLET_SESSION_RENEWAL_DOMAIN,
          String(input.authorizationId),
          String(input.walletSessionId),
          String(input.quotaId),
          String(input.deviceId),
          String(input.enrollmentId),
        ].join('\u0000'),
      ),
    ),
  );
}

export async function assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1(input: {
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
}): Promise<void> {
  const { preparation, registration } = input;
  if (
    registration.linkSessionId !== preparation.linkSessionId ||
    registration.walletId !== preparation.walletId ||
    registration.enrollmentId !== preparation.enrollmentId ||
    registration.deviceId !== preparation.deviceId ||
    registration.targetFactor.kind !== preparation.targetFactor.kind ||
    registration.targetPreparationDigestB64u !==
      (await computeLinkedDeviceTargetPreparationDigestV1(preparation)) ||
    registration.orderedHolderRegistrations.length !== preparation.orderedChildren.length
  ) {
    throw new Error('linked-device target registration differs from its preparation');
  }
  for (let index = 0; index < preparation.orderedChildren.length; index += 1) {
    const expected = preparation.orderedChildren[index];
    const actual = registration.orderedHolderRegistrations[index];
    if (
      !expected ||
      !actual ||
      actual.operationId !== expected.operationId ||
      actual.walletKeyId !== expected.walletKeyId ||
      actual.keyFamily !== expected.keyFamily ||
      actual.targetLaneId !== expected.targetLaneId ||
      actual.targetLaneShareEpoch !== expected.targetLaneShareEpoch ||
      actual.targetMaterialActivationId !== expected.targetMaterialActivationId ||
      actual.holderParticipant.participantId !== expected.targetHolderParticipantId
    ) {
      throw new Error(`linked-device holder registration ${index} differs from its R102 child`);
    }
  }
}
