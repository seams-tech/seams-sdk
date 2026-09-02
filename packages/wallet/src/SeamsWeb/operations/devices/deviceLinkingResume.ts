import {
  encodeWalletSignerActivationSetV1,
  parseWalletSignerActivationSetV1,
  type WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import type {
  CommittedAuthorityPackagesV1,
  LinkIntegrityFailureV1,
  LocalAuthorityActivationFinalAckV1,
  VerifiedTargetFactorV1,
  WalletSessionOperationCredentialV1,
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
import { parseLocalAuthorityActivationFinalAckV1 } from '@shared/device-linking/parsers';
import type { DeviceLinkingWalletSessionAcknowledgementReplayPortV1 } from './deviceLinkingPorts';
import type { DeviceLinkingDeliveryResumePortV1 } from './deviceLinkingAuthorityInstallation';

export const LINKED_DEVICE_COMMITTED_RESUME_KIND_V1 = 'linked_device_committed_resume_v1' as const;
export const LINKED_DEVICE_PENDING_ACK_KIND_V1 = 'linked_device_pending_ack_v1' as const;
export const LINKED_DEVICE_COMMITTED_RESUME_APP_STATE_PREFIX_V1 =
  'device-linking/committed-resume/v1/';
export const LINKED_DEVICE_PENDING_ACK_APP_STATE_PREFIX_V1 = 'device-linking/pending-ack/v1/';

export type DeviceLinkingPendingAcknowledgementV1 = {
  readonly kind: typeof LINKED_DEVICE_PENDING_ACK_KIND_V1;
  readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
};

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
  return `${LINKED_DEVICE_COMMITTED_RESUME_APP_STATE_PREFIX_V1}${String(authorityId)}`;
}

export function pendingAcknowledgementAppStateKeyV1(authorityId: WalletAuthorityId): string {
  return `${LINKED_DEVICE_PENDING_ACK_APP_STATE_PREFIX_V1}${String(authorityId)}`;
}

export function buildDeviceLinkingPendingAcknowledgementV1(
  acknowledgement: LocalAuthorityActivationFinalAckV1,
): DeviceLinkingPendingAcknowledgementV1 {
  return {
    kind: LINKED_DEVICE_PENDING_ACK_KIND_V1,
    acknowledgement: parseLocalAuthorityActivationFinalAckV1(acknowledgement),
  };
}

export function parseDeviceLinkingPendingAcknowledgementV1(
  raw: unknown,
): DeviceLinkingPendingAcknowledgementV1 | null {
  if (!isRecord(raw) || !hasExactKeys(raw, ['kind', 'acknowledgement'])) return null;
  if (raw.kind !== LINKED_DEVICE_PENDING_ACK_KIND_V1) return null;
  try {
    return {
      kind: LINKED_DEVICE_PENDING_ACK_KIND_V1,
      acknowledgement: parseLocalAuthorityActivationFinalAckV1(raw.acknowledgement),
    };
  } catch {
    return null;
  }
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

export type DeviceLinkingDurableAcknowledgementReplayResultV1 =
  | { readonly kind: 'none' }
  | { readonly kind: 'replayed'; readonly count: number };

/**
 * Bootstrap recovery for a page reload or a lost recipient worker handle.
 * The exact-method Wallet Session authenticates the already-persisted ack;
 * the sealed credential is never reconstructed here.
 */
export async function replayPendingDeviceLinkingAcknowledgementsV1(input: {
  readonly installation: DeviceLinkingDeliveryResumePortV1;
  readonly transport: DeviceLinkingWalletSessionAcknowledgementReplayPortV1;
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly operationCredential: WalletSessionOperationCredentialV1;
}): Promise<DeviceLinkingDurableAcknowledgementReplayResultV1> {
  const [resumes, acknowledgements] = await Promise.all([
    input.installation.listCommittedDeliveryResumesV1(),
    input.installation.listPendingActivationAcknowledgementsV1(),
  ]);
  const authorityResumes = resumes.filter(
    (resume) => resume.authorityId === input.authorityId,
  );
  const matchingAcknowledgements = acknowledgements.filter(
    (acknowledgement) => acknowledgement.authorityId === input.authorityId,
  );
  if (matchingAcknowledgements.length === 0) return { kind: 'none' };
  for (const acknowledgement of matchingAcknowledgements) {
    const resume = authorityResumes.find(
      (candidate) =>
        candidate.linkSessionId === acknowledgement.linkSessionId &&
        candidate.packageSetDigestB64u === acknowledgement.packageSetDigestB64u,
    );
    if (!resume) {
      throw new Error('durable linked-device acknowledgement has no matching resume');
    }
    if (resume.walletId !== input.walletId || resume.authMethodId !== input.authMethodId) {
      throw new Error('durable linked-device acknowledgement identity changed');
    }
    await input.transport.acknowledgeLocalAuthorityActivationWithWalletSessionV1({
      acknowledgement,
      operationCredential: input.operationCredential,
    });
    await input.installation.clearPendingActivationAcknowledgementV1({
      authorityId: acknowledgement.authorityId,
    });
    await input.installation.clearCommittedDeliveryResumeV1({
      authorityId: acknowledgement.authorityId,
    });
  }
  return { kind: 'replayed', count: matchingAcknowledgements.length };
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
