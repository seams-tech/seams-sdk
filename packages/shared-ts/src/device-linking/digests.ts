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
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceEd25519ExportRootPreparationV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDevicePasskeyCreationOptionsV1,
  LinkedDevicePasskeyTargetConfigurationFieldsV1,
  LinkedDeviceTargetFactorV1,
  LinkedDeviceApprovedTargetFactorV1,
  OrdinarySignerMaterialRecipientRequirementV1,
  LocalAuthorityInstallationReceiptV1,
  WalletSessionOperationCredentialV1,
} from './contracts';

export {
  computeCommittedSignerPackageDigestB64u,
  computeCommittedSignerPackageSetDigestB64u,
} from './committedSignerPackages';

const CLAIM_DOMAIN = 'seams/linked-device/session-claim/v1';
const APPROVAL_DOMAIN = 'seams/linked-device/owner-approval/v1';
const TARGET_PREPARATION_DOMAIN = 'seams/linked-device/target-preparation/v1';
const TARGET_PASSKEY_CONFIGURATION_DOMAIN = 'seams/linked-device/passkey-target-configuration/v1';
const LOCAL_AUTHORITY_INSTALLATION_RECEIPT_DOMAIN =
  'seams/linked-device/local-authority-installation-receipt/v1';
const TEXT_ENCODER = new TextEncoder();

/**
 * The server stores this digest alongside the authorization. Hashing the
 * opaque token directly keeps the browser binding identical to that row.
 */
export async function computeWalletSessionOperationCredentialDigestB64u(
  credential: WalletSessionOperationCredentialV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(credential.token)));
}

export function encodeWalletSessionInstallationReceiptV1(
  receipt: LocalAuthorityInstallationReceiptV1,
): string {
  return alphabetizeStringify({
    domain: LOCAL_AUTHORITY_INSTALLATION_RECEIPT_DOMAIN,
    receipt,
  });
}

export async function computeWalletSessionInstallationReceiptDigestB64u(
  receipt: LocalAuthorityInstallationReceiptV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(encodeWalletSessionInstallationReceiptV1(receipt))),
  );
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

function requirePresentString(value: string | undefined, label: string): string {
  if (value === undefined) throw new Error(`${label} is required`);
  return value;
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
  return concat([
    text(value.kind, 'ownerAuthorization.kind'),
    text(value.walletSessionId, 'ownerAuthorization.walletSessionId'),
    text(value.authorizationId, 'ownerAuthorization.authorizationId'),
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

function encodeTargetFactor(value: LinkedDeviceTargetFactorV1): Uint8Array {
  return text(value.kind, 'targetFactor.kind');
}

function encodeApprovedTargetFactor(value: LinkedDeviceApprovedTargetFactorV1): Uint8Array {
  switch (value.kind) {
    case 'passkey_prf':
      return text(value.kind, 'targetFactor.kind');
    case 'email_otp':
      return concat([
        text(value.kind, 'targetFactor.kind'),
        text(value.targetEmail, 'targetFactor.targetEmail'),
        text(value.enrollment.kind, 'targetFactor.enrollment.kind'),
        ...(value.enrollment.kind === 'existing_enrollment'
          ? [
              text(
                requirePresentString(
                  value.baseWalletAuthMethodId,
                  'targetFactor.baseWalletAuthMethodId',
                ),
                'targetFactor.baseWalletAuthMethodId',
              ),
            ]
          : []),
      ]);
  }
}

function encodeLinkedDevicePasskeyCreationOptionsV1(
  value: LinkedDevicePasskeyCreationOptionsV1,
): Uint8Array {
  const algorithms = value.pubKeyCredParams.map((entry) =>
    concat([
      text(entry.type, 'passkeyCreationOptions.pubKeyCredParams.type'),
      text(String(entry.alg), 'passkeyCreationOptions.pubKeyCredParams.alg'),
    ]),
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
    text(
      value.extensions.prf.eval.firstB64u,
      'passkeyCreationOptions.extensions.prf.eval.firstB64u',
    ),
    text(
      value.extensions.prf.eval.secondB64u,
      'passkeyCreationOptions.extensions.prf.eval.secondB64u',
    ),
    u32(excludeCredentials.length, 'passkeyCreationOptions.excludeCredentials'),
    ...excludeCredentials.map((entry) =>
      lp32(entry, 'passkeyCreationOptions.excludeCredentials.item'),
    ),
  ]);
}

export function encodeLinkedDevicePasskeyTargetConfigurationV1(
  value: LinkedDevicePasskeyTargetConfigurationFieldsV1,
): Uint8Array {
  return concat([
    text(TARGET_PASSKEY_CONFIGURATION_DOMAIN, 'domain'),
    text('linked_device_passkey_target_configuration_v1', 'kind'),
    text(value.rpId, 'rpId'),
    text(value.expectedOrigin, 'expectedOrigin'),
  ]);
}

export async function computeLinkedDevicePasskeyTargetConfigurationDigestV1(
  value: LinkedDevicePasskeyTargetConfigurationFieldsV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDevicePasskeyTargetConfigurationV1(value))),
  );
}

function encodeRecipientRequirement(
  value: OrdinarySignerMaterialRecipientRequirementV1,
): Uint8Array {
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
    u64(value.sessionRevision, 'sessionRevision'),
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
    lp32(encodeApprovedTargetFactor(value.targetFactor), 'targetFactor'),
    ...('sourceContribution' in value
      ? [
          lp32(
            TEXT_ENCODER.encode(alphabetizeStringify(value.sourceContribution)),
            'sourceContribution',
          ),
        ]
      : []),
    lp32(encodeOwnerAuthorization(value.ownerAuthorization), 'ownerAuthorization'),
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
  const requirements = value.ordinarySignerMaterialRecipientRequirements.map(
    encodeRecipientRequirement,
  );
  const passkeyPreparation = isPasskeyTargetPreparationV1(value) ? value : undefined;
  const passkeyCreationOptions = passkeyPreparation?.passkeyCreationOptions;
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
    lp32(
      rawPublicKey(value.deliveryRecipientPublicKey65B64u, 'deliveryRecipientPublicKey65B64u'),
      'deliveryRecipientPublicKey65B64u',
    ),
    text(value.walletAuthMethodId, 'walletAuthMethodId'),
    lp32(encodeEd25519ExportRootPreparation(value.ed25519ExportRoot), 'ed25519ExportRoot'),
    lp32(encodeTargetFactor(value.targetFactor), 'targetFactor'),
    ...(passkeyCreationOptions
      ? [
          lp32(
            encodeLinkedDevicePasskeyCreationOptionsV1(passkeyCreationOptions),
            'passkeyCreationOptions',
          ),
          rawDigest(
            passkeyPreparation.passkeyConfigurationDigestB64u,
            'passkeyConfigurationDigestB64u',
          ),
        ]
      : []),
    ...encodeEmailTargetPreparationFactorBindingV1(value),
    u32(requirements.length, 'ordinarySignerMaterialRecipientRequirements'),
    ...requirements.map((entry) => lp32(entry, 'ordinarySignerMaterialRecipientRequirements.item')),
    u64(value.issuedAtMs, 'issuedAtMs'),
    u64(value.expiresAtMs, 'expiresAtMs'),
  ]);
}

function encodeEmailTargetPreparationFactorBindingV1(
  value: LinkedDeviceTargetPreparationV1,
): readonly Uint8Array[] {
  if (isPasskeyTargetPreparationV1(value)) {
    return [];
  }
  return [
    text(value.targetEmail, 'targetEmail'),
    text(value.enrollment.kind, 'enrollment.kind'),
    ...(value.enrollment.kind === 'existing_enrollment'
      ? [
          text(
            requirePresentString(value.baseWalletAuthMethodId, 'baseWalletAuthMethodId'),
            'baseWalletAuthMethodId',
          ),
        ]
      : []),
  ];
}

function isPasskeyTargetPreparationV1(
  value: LinkedDeviceTargetPreparationV1,
): value is Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'passkey_prf' } }
> {
  return value.targetFactor.kind === 'passkey_prf';
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
  if (preparation.targetFactor.kind === 'email_otp') {
    const emailPreparation = preparation;
    const emailRegistration =
      registration.targetFactor.kind === 'email_otp' ? registration : null;
    const grant = emailRegistration?.emailOtpVerificationGrant;
    if (
      !emailRegistration ||
      !grant ||
      !emailPreparation.enrollment ||
      emailRegistration.targetEmail !== emailPreparation.targetEmail ||
      grant.enrollment.kind !== emailPreparation.enrollment.kind
    ) {
      throw new Error('linked-device Email OTP target registration differs from preparation');
    }
    if (emailPreparation.enrollment.kind === 'existing_enrollment') {
      if (
        !grant.baseWalletAuthMethodId ||
        !emailPreparation.baseWalletAuthMethodId ||
        grant.baseWalletAuthMethodId !== emailPreparation.baseWalletAuthMethodId
      ) {
        throw new Error('linked-device Email OTP base factor differs from preparation');
      }
    } else if (emailRegistration.emailOtpEnrollment === undefined) {
      throw new Error('linked-device Email OTP enrollment material is missing');
    }
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
