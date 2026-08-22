import {
  encodeWalletSignerActivationSetV1,
  parseWalletSignerActivationSetV1,
  type WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import type {
  CommittedAuthorityPackagesV1,
  LinkIntegrityFailureV1,
  VerifiedTargetFactorV1,
} from '@shared/device-linking';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseLinkDeviceSessionId,
  parseLinkedDeviceEnrollmentId,
  type LinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
} from '@shared/signing-lanes/ids';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';

export const LINKED_DEVICE_COMMITTED_RESUME_KIND_V1 = 'linked_device_committed_resume_v1' as const;

/**
 * Durable identity for a committed delivery. It contains no key bytes,
 * factor secret, package plaintext, or decrypted signer material.
 */
export type DeviceLinkingCommittedResumeV1 = {
  readonly kind: typeof LINKED_DEVICE_COMMITTED_RESUME_KIND_V1;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly deviceId: DeviceId;
  readonly targetFactorKind: VerifiedTargetFactorV1['kind'];
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly authorityDigestB64u: DigestB64u;
  readonly signerActivationSetDigestB64u: DigestB64u;
  readonly signerActivations: WalletSignerActivationSetV1;
  readonly packageSetDigestB64u: DigestB64u;
  readonly committedAtMs: number;
};

export function committedResumeAppStateKeyV1(authorityId: WalletAuthorityId): string {
  return `device-linking/committed-resume/v1/${String(authorityId)}`;
}

export function buildDeviceLinkingCommittedResumeV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly committedAtMs: number;
}): DeviceLinkingCommittedResumeV1 {
  const authority = input.committed.authority;
  if (authority.provenance.kind !== 'device_link') {
    throw new Error('committed link authority provenance is invalid');
  }
  if (authority.provenance.linkSessionId !== input.linkSessionId) {
    throw new Error('committed link session identity differs from authority provenance');
  }
  if (
    input.committed.authMethod.walletAuthMethodId !==
    input.targetFactor.authMethod.walletAuthMethodId
  ) {
    throw new Error('committed link auth method differs from target factor');
  }
  if (!Number.isSafeInteger(input.committedAtMs) || input.committedAtMs <= 0) {
    throw new Error('committed link resume timestamp is invalid');
  }
  return {
    kind: LINKED_DEVICE_COMMITTED_RESUME_KIND_V1,
    linkSessionId: input.linkSessionId,
    walletId: authority.walletId,
    enrollmentId: authority.provenance.enrollmentId,
    authorityId: authority.authorityId,
    authMethodId: input.committed.authMethod.walletAuthMethodId,
    deviceId: authority.principal.deviceId,
    targetFactorKind: input.targetFactor.kind,
    targetFactorVerificationDigestB64u: input.targetFactor.verificationDigestB64u,
    authorityDigestB64u: authority.authorityDigestB64u,
    signerActivationSetDigestB64u: authority.signerActivationSetDigestB64u,
    signerActivations: authority.signerActivations,
    packageSetDigestB64u: input.committed.packageSetDigestB64u,
    committedAtMs: input.committedAtMs,
  };
}

export function compareDeviceLinkingCommittedResumeV1(input: {
  readonly resume: DeviceLinkingCommittedResumeV1;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly committed: CommittedAuthorityPackagesV1;
  readonly targetFactor: VerifiedTargetFactorV1;
}): LinkIntegrityFailureV1 | null {
  const expected = buildDeviceLinkingCommittedResumeV1({
    linkSessionId: input.linkSessionId,
    committed: input.committed,
    targetFactor: input.targetFactor,
    committedAtMs: input.resume.committedAtMs,
  });
  if (input.resume.authorityId !== expected.authorityId) {
    return {
      kind: 'authority_id_mismatch',
      expectedAuthorityId: input.resume.authorityId,
      actualAuthorityId: expected.authorityId,
    };
  }
  if (
    input.resume.linkSessionId !== expected.linkSessionId ||
    input.resume.enrollmentId !== expected.enrollmentId
  ) {
    return {
      kind: 'package_set_digest_mismatch',
      expectedPackageSetDigestB64u: input.resume.packageSetDigestB64u,
      actualPackageSetDigestB64u: expected.packageSetDigestB64u,
    };
  }
  if (input.resume.walletId !== expected.walletId) {
    return { kind: 'installation_receipt_mismatch', field: 'walletId' };
  }
  if (input.resume.authMethodId !== expected.authMethodId) {
    return { kind: 'installation_receipt_mismatch', field: 'authMethodId' };
  }
  if (input.resume.deviceId !== expected.deviceId) {
    return { kind: 'installation_receipt_mismatch', field: 'deviceId' };
  }
  if (input.resume.targetFactorKind !== expected.targetFactorKind) {
    return {
      kind: 'installation_receipt_mismatch',
      field: 'targetFactorVerificationDigestB64u',
    };
  }
  if (
    input.resume.targetFactorVerificationDigestB64u !== expected.targetFactorVerificationDigestB64u
  ) {
    return {
      kind: 'installation_receipt_mismatch',
      field: 'targetFactorVerificationDigestB64u',
    };
  }
  if (input.resume.signerActivationSetDigestB64u !== expected.signerActivationSetDigestB64u) {
    return { kind: 'installation_receipt_mismatch', field: 'installedActivationRefs' };
  }
  if (input.resume.authorityDigestB64u !== expected.authorityDigestB64u) {
    return {
      kind: 'package_set_digest_mismatch',
      expectedPackageSetDigestB64u: input.resume.packageSetDigestB64u,
      actualPackageSetDigestB64u: expected.packageSetDigestB64u,
    };
  }
  if (input.resume.packageSetDigestB64u !== expected.packageSetDigestB64u) {
    return {
      kind: 'package_set_digest_mismatch',
      expectedPackageSetDigestB64u: input.resume.packageSetDigestB64u,
      actualPackageSetDigestB64u: expected.packageSetDigestB64u,
    };
  }
  if (!sameSignerActivations(input.resume.signerActivations, expected.signerActivations)) {
    return { kind: 'installation_receipt_mismatch', field: 'installedActivationRefs' };
  }
  return null;
}

export function parseDeviceLinkingCommittedResumeV1(
  raw: unknown,
): DeviceLinkingCommittedResumeV1 | null {
  if (!isRecord(raw)) return null;
  const expectedKeys = [
    'kind',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'authorityId',
    'authMethodId',
    'deviceId',
    'targetFactorKind',
    'targetFactorVerificationDigestB64u',
    'authorityDigestB64u',
    'signerActivationSetDigestB64u',
    'signerActivations',
    'packageSetDigestB64u',
    'committedAtMs',
  ] as const;
  if (!hasExactKeys(raw, expectedKeys)) return null;
  if (raw.kind !== LINKED_DEVICE_COMMITTED_RESUME_KIND_V1) return null;
  const linkSessionId = parseLinkDeviceSessionId(raw.linkSessionId);
  const walletId = parseWalletId(raw.walletId);
  const enrollmentId = parseLinkedDeviceEnrollmentId(raw.enrollmentId);
  const authorityId = parseWalletAuthorityId(raw.authorityId);
  const authMethodId = parseWalletAuthMethodId(raw.authMethodId);
  const deviceId = parseDeviceId(raw.deviceId);
  if (
    !linkSessionId.ok ||
    !walletId.ok ||
    !enrollmentId.ok ||
    !authorityId.ok ||
    !authMethodId.ok ||
    !deviceId.ok ||
    (raw.targetFactorKind !== 'verified_passkey_target_v1' &&
      raw.targetFactorKind !== 'verified_email_otp_target_v1')
  ) {
    return null;
  }
  const signerActivations = parseWalletSignerActivationSetV1(raw.signerActivations);
  if (!signerActivations.ok) return null;
  const committedAtMs = raw.committedAtMs;
  if (typeof committedAtMs !== 'number') return null;
  if (!Number.isSafeInteger(committedAtMs) || committedAtMs <= 0) return null;
  try {
    return {
      kind: LINKED_DEVICE_COMMITTED_RESUME_KIND_V1,
      linkSessionId: linkSessionId.value,
      walletId: walletId.value,
      enrollmentId: enrollmentId.value,
      authorityId: authorityId.value,
      authMethodId: authMethodId.value,
      deviceId: deviceId.value,
      targetFactorKind: raw.targetFactorKind,
      targetFactorVerificationDigestB64u: parseDigestB64u(raw.targetFactorVerificationDigestB64u),
      authorityDigestB64u: parseDigestB64u(raw.authorityDigestB64u),
      signerActivationSetDigestB64u: parseDigestB64u(raw.signerActivationSetDigestB64u),
      signerActivations: signerActivations.value,
      packageSetDigestB64u: parseDigestB64u(raw.packageSetDigestB64u),
      committedAtMs,
    };
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function sameSignerActivations(
  left: WalletSignerActivationSetV1,
  right: WalletSignerActivationSetV1,
): boolean {
  const leftBytes = encodeWalletSignerActivationSetV1(left);
  const rightBytes = encodeWalletSignerActivationSetV1(right);
  return (
    leftBytes.length === rightBytes.length &&
    leftBytes.every((value, index) => value === rightBytes[index])
  );
}
