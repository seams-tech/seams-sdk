import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { sha256Bytes } from '../utils/digests';
import {
  delegatedWalletPermissionNamesV1,
  type DelegatedWalletAuthorityV1,
  type DelegatedWalletPermissionV1,
} from '../authorization/delegatedAuthority';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceProtocolVersionV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceEd25519ExportRootPreparationV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDevicePasskeyCreationOptionsV1,
  LinkedDeviceTargetFactorV1,
  OrdinarySignerMaterialRecipientRequirementV1,
} from './contracts';
import { ownerLaneParticipantContinuityCanonicalBytesV1 } from '../signing-lanes/ownerContinuity';

export {
  computeCommittedSignerPackageDigestB64u,
  computeCommittedSignerPackageSetDigestB64u,
} from './committedSignerPackages';

const CLAIM_DOMAIN = 'seams/linked-device/session-claim/v1';
const APPROVAL_DOMAIN = 'seams/linked-device/owner-approval/v1';
const TARGET_PREPARATION_DOMAIN = 'seams/linked-device/target-preparation/v1';
const TEXT_ENCODER = new TextEncoder();

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

function encodeTargetFactor(value: LinkedDeviceTargetFactorV1): Uint8Array {
  return text(value.kind, 'targetFactor.kind');
}

function encodeLinkedDevicePasskeyCreationOptionsV1(
  value: LinkedDevicePasskeyCreationOptionsV1,
): Uint8Array {
  const algorithms = value.pubKeyCredParams.map((entry) =>
    concat([text(entry.type, 'passkeyCreationOptions.pubKeyCredParams.type'), text(String(entry.alg), 'passkeyCreationOptions.pubKeyCredParams.alg')]),
  );
  const excludeCredentials = value.excludeCredentials.map((entry) =>
    concat([
      text(entry.type, 'passkeyCreationOptions.excludeCredentials.type'),
      text(entry.id, 'passkeyCreationOptions.excludeCredentials.id'),
    ]),
  );
  return concat([
    text(value.kind, 'passkeyCreationOptions.kind'),
    text(value.walletAuthMethodId, 'passkeyCreationOptions.walletAuthMethodId'),
    text(value.challengeId, 'passkeyCreationOptions.challengeId'),
    text(value.challengeB64u, 'passkeyCreationOptions.challengeB64u'),
    text(value.rpId, 'passkeyCreationOptions.rpId'),
    text(value.user.idB64u, 'passkeyCreationOptions.user.idB64u'),
    text(value.user.name, 'passkeyCreationOptions.user.name'),
    text(value.user.displayName, 'passkeyCreationOptions.user.displayName'),
    u32(algorithms.length, 'passkeyCreationOptions.pubKeyCredParams'),
    ...algorithms.map((entry) => lp32(entry, 'passkeyCreationOptions.pubKeyCredParams.item')),
    text(
      value.authenticatorSelection.residentKey,
      'passkeyCreationOptions.authenticatorSelection.residentKey',
    ),
    text(
      value.authenticatorSelection.userVerification,
      'passkeyCreationOptions.authenticatorSelection.userVerification',
    ),
    u64(value.timeoutMs, 'passkeyCreationOptions.timeoutMs'),
    text(value.attestation, 'passkeyCreationOptions.attestation'),
    text(value.extensions.prf.eval.firstB64u, 'passkeyCreationOptions.extensions.prf.eval.firstB64u'),
    text(value.extensions.prf.eval.secondB64u, 'passkeyCreationOptions.extensions.prf.eval.secondB64u'),
    u32(excludeCredentials.length, 'passkeyCreationOptions.excludeCredentials'),
    ...excludeCredentials.map((entry) =>
      lp32(entry, 'passkeyCreationOptions.excludeCredentials.item'),
    ),
  ]);
}

function encodeProtocolVersion(value: LinkedDeviceProtocolVersionV1): Uint8Array {
  return concat([
    text(value.keyFamily, 'protocolVersion.keyFamily'),
    text(value.version, 'protocolVersion.version'),
  ]);
}

function encodeRecipientRequirement(value: OrdinarySignerMaterialRecipientRequirementV1): Uint8Array {
  return concat([
    text(value.kind, 'recipientRequirement.kind'),
    text(value.keyFamily, 'recipientRequirement.keyFamily'),
    text(value.walletKeyId, 'recipientRequirement.walletKeyId'),
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
  const requirements = value.ordinarySignerMaterialRecipientRequirements.map(encodeRecipientRequirement);
  const passkeyCreationOptions =
    value.targetFactor.kind === 'passkey_prf' ? value.passkeyCreationOptions : undefined;
  if (value.targetFactor.kind === 'passkey_prf' && !passkeyCreationOptions) {
    throw new Error('passkey target preparation is missing creation options');
  }
  return concat([
    text(TARGET_PREPARATION_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.linkSessionId, 'linkSessionId'),
    text(value.walletId, 'walletId'),
    text(value.enrollmentId, 'enrollmentId'),
    text(value.deviceId, 'deviceId'),
    text(value.walletAuthMethodId, 'walletAuthMethodId'),
    lp32(encodeEd25519ExportRootPreparation(value.ed25519ExportRoot), 'ed25519ExportRoot'),
    lp32(encodeTargetFactor(value.targetFactor), 'targetFactor'),
    ...(passkeyCreationOptions
      ? [lp32(encodeLinkedDevicePasskeyCreationOptionsV1(passkeyCreationOptions), 'passkeyCreationOptions')]
      : []),
    u32(requirements.length, 'ordinarySignerMaterialRecipientRequirements'),
    ...requirements.map((entry) =>
      lp32(entry, 'ordinarySignerMaterialRecipientRequirements.item'),
    ),
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
    registration.walletAuthMethodId !== preparation.walletAuthMethodId ||
    registration.targetFactor.kind !== preparation.targetFactor.kind ||
    registration.targetPreparationDigestB64u !==
      (await computeLinkedDeviceTargetPreparationDigestV1(preparation)) ||
    registration.ordinarySignerMaterialRecipientRequests.length !==
      preparation.ordinarySignerMaterialRecipientRequirements.length
  ) {
    throw new Error('linked-device target registration differs from its preparation');
  }
  for (
    let index = 0;
    index < preparation.ordinarySignerMaterialRecipientRequirements.length;
    index += 1
  ) {
    const expected = preparation.ordinarySignerMaterialRecipientRequirements[index];
    const actual = registration.ordinarySignerMaterialRecipientRequests[index];
    if (
      !expected ||
      !actual ||
      actual.walletKeyId !== expected.walletKeyId ||
      actual.keyFamily !== expected.keyFamily
    ) {
      throw new Error(`linked-device recipient request ${index} differs from its preparation`);
    }
  }
}
