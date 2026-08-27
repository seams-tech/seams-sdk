/**
 * Refactor 103 Phase 6 — the durable one-time Email OTP verification grant.
 *
 * Verifying the emailed code proves the person holding Device 2 controls the
 * wallet's base Email OTP destination. That proof must authorize exactly one
 * thing: completing this enrollment on this device against this preparation.
 * The grant is the durable record of that proof, bound to every identity the
 * completion will restate, consumed exactly once, and useless for anything
 * else — a login verify, another session, another device, or a second
 * completion.
 *
 * The wire grant (`LinkedDeviceEmailOtpVerificationGrantV1`) hands Device 2 an
 * opaque bearer token. The durable record stores only the token's digest, so a
 * leaked database row cannot be replayed as the token it never contained.
 */
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseVerifiedEmailAddress,
  type WalletAuthMethodId,
  type WalletId,
  type VerifiedEmailAddress,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import {
  parseLinkDeviceSessionId,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  type LinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
} from '@shared/signing-lanes/ids';
import {
  requireRecord,
  rejectUnknownFields,
  parseUnixMs,
} from '@shared/passkey-custody/primitives';
import type { LinkedDeviceEmailOtpEnrollmentSelectionV1 } from '@shared/device-linking/contracts';

const GRANT_TOKEN_DIGEST_DOMAIN = 'seams:linked-device-email-otp-grant-token:v1';
const DESCRIPTOR_CREDENTIAL_DOMAIN = 'seams:linked-device-email-otp-descriptor-credential:v1';
const AUTHORITY_DIGEST_DOMAIN = 'seams:linked-device-email-otp-authority:v1';
const CHALLENGE_BINDING_DOMAIN = 'seams:linked-device-email-otp-challenge-binding:v1';

/**
 * The `ownerProofBindingDigest` a linked-device Email OTP challenge is issued
 * and verified under. It covers the whole device-link context, so a code
 * mailed for this enrollment verifies for nothing else — not a login, not
 * another session, device, enrollment, or preparation — and no other flow's
 * challenge can verify here.
 */
export async function computeLinkedDeviceEmailOtpChallengeBindingDigestV1(input: {
  readonly walletId: WalletId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly targetEmail: VerifiedEmailAddress;
  readonly enrollment: LinkedDeviceEmailOtpEnrollmentSelectionV1;
  readonly baseWalletAuthMethodId?: WalletAuthMethodId;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): Promise<DigestB64u> {
  const baseWalletAuthMethodId =
    input.enrollment.kind === 'existing_enrollment'
      ? requirePresentBaseMethod(input.baseWalletAuthMethodId)
      : '';
  const preimage = [
    CHALLENGE_BINDING_DOMAIN,
    String(input.walletId),
    String(input.linkSessionId),
    String(input.enrollmentId),
    String(input.deviceId),
    'email_otp',
    String(input.targetPreparationDigestB64u),
    input.targetEmail,
    input.enrollment.kind,
    String(baseWalletAuthMethodId),
    String(input.walletAuthMethodId),
  ].join('\\u0000');
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(preimage)));
}

export type LinkedDeviceEmailOtpGrantStateV1 =
  | { readonly kind: 'issued'; readonly consumedAtMs?: never }
  | { readonly kind: 'consumed'; readonly consumedAtMs: number };

export type LinkedDeviceEmailOtpGrantRecordV1 = {
  readonly kind: 'linked_device_email_otp_grant_record_v1';
  readonly grantId: string;
  readonly grantTokenDigestB64u: DigestB64u;
  readonly walletId: WalletId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetFactor: { readonly kind: 'email_otp' };
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly targetEmail: VerifiedEmailAddress;
  readonly enrollment: LinkedDeviceEmailOtpEnrollmentSelectionV1;
  readonly emailHashHex: string;
  readonly registrationAuthorityId: string;
  readonly providerUserId: string;
  readonly baseWalletAuthMethodId?: WalletAuthMethodId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
  readonly challengeId: string;
  readonly state: LinkedDeviceEmailOtpGrantStateV1;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

const GRANT_RECORD_FIELDS = [
  'kind',
  'grantId',
  'grantTokenDigestB64u',
  'walletId',
  'linkSessionId',
  'enrollmentId',
  'deviceId',
  'targetFactor',
  'targetPreparationDigestB64u',
  'targetEmail',
  'enrollment',
  'emailHashHex',
  'registrationAuthorityId',
  'providerUserId',
  'baseWalletAuthMethodId',
  'walletAuthMethodId',
  'authorityDigestB64u',
  'challengeId',
  'state',
  'issuedAtMs',
  'expiresAtMs',
] as const;

export function parseLinkedDeviceEmailOtpGrantRecordV1(
  raw: unknown,
): LinkedDeviceEmailOtpGrantRecordV1 {
  const record = requireRecord(raw, 'LinkedDeviceEmailOtpGrantRecordV1');
  rejectUnknownFields(record, GRANT_RECORD_FIELDS, 'LinkedDeviceEmailOtpGrantRecordV1');
  const enrollment = parseEnrollmentSelection(
    record.enrollment,
    'LinkedDeviceEmailOtpGrantRecordV1.enrollment',
  );
  for (const field of GRANT_RECORD_FIELDS) {
    if (record[field] === undefined && !(field === 'baseWalletAuthMethodId' && enrollment.kind === 'new_enrollment')) {
      throw new Error(`LinkedDeviceEmailOtpGrantRecordV1.${field} is required`);
    }
  }
  if (record.kind !== 'linked_device_email_otp_grant_record_v1') {
    throw new Error('LinkedDeviceEmailOtpGrantRecordV1.kind is invalid');
  }
  const targetFactor = requireRecord(
    record.targetFactor,
    'LinkedDeviceEmailOtpGrantRecordV1.targetFactor',
  );
  rejectUnknownFields(targetFactor, ['kind'], 'LinkedDeviceEmailOtpGrantRecordV1.targetFactor');
  if (targetFactor.kind !== 'email_otp') {
    throw new Error('LinkedDeviceEmailOtpGrantRecordV1.targetFactor must be email_otp');
  }
  const issuedAtMs = parseUnixMs(record.issuedAtMs, 'LinkedDeviceEmailOtpGrantRecordV1.issuedAtMs');
  const expiresAtMs = parseUnixMs(
    record.expiresAtMs,
    'LinkedDeviceEmailOtpGrantRecordV1.expiresAtMs',
  );
  if (expiresAtMs <= issuedAtMs) {
    throw new Error('LinkedDeviceEmailOtpGrantRecordV1.expiresAtMs must follow issuedAtMs');
  }
  const base = {
    kind: 'linked_device_email_otp_grant_record_v1',
    grantId: requireToken(record.grantId, 'LinkedDeviceEmailOtpGrantRecordV1.grantId'),
    grantTokenDigestB64u: requireGrantDigest(
      record.grantTokenDigestB64u,
      'LinkedDeviceEmailOtpGrantRecordV1.grantTokenDigestB64u',
    ),
    walletId: requireParsed(
      parseWalletId(record.walletId),
      'LinkedDeviceEmailOtpGrantRecordV1.walletId',
    ),
    linkSessionId: requireParsed(
      parseLinkDeviceSessionId(record.linkSessionId),
      'LinkedDeviceEmailOtpGrantRecordV1.linkSessionId',
    ),
    enrollmentId: requireParsed(
      parseLinkedDeviceEnrollmentId(record.enrollmentId),
      'LinkedDeviceEmailOtpGrantRecordV1.enrollmentId',
    ),
    deviceId: requireParsed(
      parseLinkedDeviceId(record.deviceId),
      'LinkedDeviceEmailOtpGrantRecordV1.deviceId',
    ),
    targetFactor: { kind: 'email_otp' },
    targetPreparationDigestB64u: requireGrantDigest(
      record.targetPreparationDigestB64u,
      'LinkedDeviceEmailOtpGrantRecordV1.targetPreparationDigestB64u',
    ),
    targetEmail: requireTargetEmail(record.targetEmail),
    enrollment,
    emailHashHex: requireToken(
      record.emailHashHex,
      'LinkedDeviceEmailOtpGrantRecordV1.emailHashHex',
    ),
    registrationAuthorityId: requireToken(
      record.registrationAuthorityId,
      'LinkedDeviceEmailOtpGrantRecordV1.registrationAuthorityId',
    ),
    providerUserId: requireToken(
      record.providerUserId,
      'LinkedDeviceEmailOtpGrantRecordV1.providerUserId',
    ),
    walletAuthMethodId: requireParsed(
      parseWalletAuthMethodId(record.walletAuthMethodId),
      'LinkedDeviceEmailOtpGrantRecordV1.walletAuthMethodId',
    ),
    authorityDigestB64u: requireGrantDigest(
      record.authorityDigestB64u,
      'LinkedDeviceEmailOtpGrantRecordV1.authorityDigestB64u',
    ),
    challengeId: requireToken(record.challengeId, 'LinkedDeviceEmailOtpGrantRecordV1.challengeId'),
    state: parseGrantStateV1(record.state, issuedAtMs),
    issuedAtMs,
    expiresAtMs,
  } as const;
  if (enrollment.kind === 'new_enrollment') {
    return { ...base, enrollment: { kind: 'new_enrollment' } };
  }
  return {
    ...base,
    enrollment: { kind: 'existing_enrollment' },
    baseWalletAuthMethodId: requireParsed(
      parseWalletAuthMethodId(record.baseWalletAuthMethodId),
      'LinkedDeviceEmailOtpGrantRecordV1.baseWalletAuthMethodId',
    ),
  };
}

function parseGrantStateV1(raw: unknown, issuedAtMs: number): LinkedDeviceEmailOtpGrantStateV1 {
  const record = requireRecord(raw, 'LinkedDeviceEmailOtpGrantRecordV1.state');
  switch (record.kind) {
    case 'issued':
      rejectUnknownFields(record, ['kind'], 'LinkedDeviceEmailOtpGrantRecordV1.state', [
        'consumedAtMs',
      ]);
      return { kind: 'issued' };
    case 'consumed': {
      rejectUnknownFields(
        record,
        ['kind', 'consumedAtMs'],
        'LinkedDeviceEmailOtpGrantRecordV1.state',
      );
      const consumedAtMs = parseUnixMs(
        record.consumedAtMs,
        'LinkedDeviceEmailOtpGrantRecordV1.state.consumedAtMs',
      );
      if (consumedAtMs < issuedAtMs) {
        throw new Error('LinkedDeviceEmailOtpGrantRecordV1 consumption precedes issuance');
      }
      return { kind: 'consumed', consumedAtMs };
    }
    default:
      throw new Error('LinkedDeviceEmailOtpGrantRecordV1.state.kind is unsupported');
  }
}

/** True while the grant may authorize exactly one completion. */
export function linkedDeviceEmailOtpGrantAdmitsUseV1(
  record: LinkedDeviceEmailOtpGrantRecordV1,
  nowMs: number,
): boolean {
  return record.state.kind === 'issued' && nowMs < record.expiresAtMs;
}

/**
 * The stored form of the bearer token. Only the digest is durable, so reading
 * every grant row ever written yields nothing that verifies as a token.
 */
export async function computeLinkedDeviceEmailOtpGrantTokenDigestV1(
  grantToken: string,
): Promise<DigestB64u> {
  if (!grantToken || grantToken.trim() !== grantToken) {
    throw new Error('linked-device email OTP grant token is invalid');
  }
  return parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(`${GRANT_TOKEN_DIGEST_DOMAIN}\u0000${grantToken}`)),
  );
}

/**
 * The digest every Wallet Session and admission surface compares to name this
 * one target authority. It covers the full identity chain —
 * wallet, enrollment, device, derived principal, base factor — so two devices
 * sharing an email produce different digests, and a digest computed against a
 * substituted base factor matches nothing.
 */
export async function computeLinkedDeviceEmailOtpAuthorityDigestV1(input: {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly targetEmail: string;
  readonly enrollment: LinkedDeviceEmailOtpEnrollmentSelectionV1;
  readonly baseWalletAuthMethodId?: WalletAuthMethodId;
}): Promise<DigestB64u> {
  const baseWalletAuthMethodId =
    input.enrollment.kind === 'existing_enrollment'
      ? requirePresentBaseMethod(input.baseWalletAuthMethodId)
      : '';
  const preimage = [
    AUTHORITY_DIGEST_DOMAIN,
    String(input.walletId),
    String(input.enrollmentId),
    String(input.deviceId),
    String(input.walletAuthMethodId),
    input.targetEmail,
    input.enrollment.kind,
    String(baseWalletAuthMethodId),
  ].join('\u0000');
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(preimage)));
}

/**
 * The target-deployment descriptor binds each child to the target credential
 * by a credential id. The Email OTP branch creates no WebAuthn credential, so
 * its descriptor binding is a deterministic digest of the target
 * authority — the credential-equivalent principal this enrollment activates.
 * Deterministic, so replays reproduce byte-identical descriptor requests.
 */
export async function linkedDeviceEmailOtpDescriptorCredentialIdV1(
  walletAuthMethodId: WalletAuthMethodId,
): Promise<WebAuthnCredentialIdB64u> {
  const digest = base64UrlEncode(
    await sha256BytesUtf8(`${DESCRIPTOR_CREDENTIAL_DOMAIN}\u0000${String(walletAuthMethodId)}`),
  );
  const parsed = parseWebAuthnCredentialIdB64u(digest);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireToken(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return raw;
}

function requirePresentBaseMethod(value: WalletAuthMethodId | undefined): WalletAuthMethodId {
  if (!value) throw new Error('Email OTP existing enrollment requires a base auth method');
  return value;
}

function requireTargetEmail(raw: unknown): VerifiedEmailAddress {
  const parsed = parseVerifiedEmailAddress(raw);
  if (!parsed.ok) throw new Error(`LinkedDeviceEmailOtpGrantRecordV1.targetEmail ${parsed.error.message}`);
  return parsed.value;
}

function parseEnrollmentSelection(
  raw: unknown,
  label: string,
): LinkedDeviceEmailOtpEnrollmentSelectionV1 {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, ['kind'], label);
  if (record.kind === 'existing_enrollment' || record.kind === 'new_enrollment') {
    return { kind: record.kind };
  }
  throw new Error(`${label}.kind is unsupported`);
}

function requireGrantDigest(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function requireParsed<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}
