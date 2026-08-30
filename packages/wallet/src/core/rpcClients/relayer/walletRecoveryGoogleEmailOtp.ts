import {
  parsePasskeyCustodyEnvelopeRecord,
  rejectUnknownFields,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  parseEmailOtpChallengeId,
  parseEmailOtpProviderUserId,
  parseWalletRecoveryOperationId,
  type EmailOtpChallengeId,
  type WalletId,
  type WalletRecoveryOperationId,
} from '@shared/utils/domainIds';
import type { DeviceId } from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethodId, WalletAuthorityId } from '@shared/utils/domainIds';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import {
  parseWalletRecoveryEcdsaPossessionProofV1,
  type WalletRecoveryEcdsaPossessionProofV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import { parseEmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/challengeDelivery';
import type { EmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { ActiveRecoveredWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseWalletRecoveryCommittedProjectionV1,
  type WalletRecoveryCommittedProjectionExpectationV1,
} from '@shared/wallet-recovery/walletRecoveryCommittedProjection';
import { buildRelayerJsonPostRequestInit, normalizeRelayerBaseUrl } from './relayerHttp';
import type { WalletRecoveryAttemptFailure } from './walletRecoveryPrepare';

const GOOGLE_VERIFY_PATH = '/wallets/recovery/google/verify';
const EMAIL_OTP_VERIFY_PATH = '/wallets/recovery/email-otp/verify';
const GOOGLE_EMAIL_OTP_FINALIZE_PATH = '/wallets/recovery/google-email-otp/finalize';

type RecoveryOperationInput = {
  readonly relayUrl: string;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly fetchImpl?: typeof fetch;
};

export type WalletRecoveryGoogleVerifyResult =
  | {
      readonly kind: 'verified';
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly reservationId: RecoveryCodeReservationId;
      readonly challengeId: EmailOtpChallengeId;
      readonly delivery: EmailOtpChallengeDelivery;
      readonly expiresAtMs: number;
    }
  | WalletRecoveryAttemptFailure;

export type WalletRecoveryEmailOtpVerifyResult =
  | {
      readonly kind: 'verified';
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly reservationId: RecoveryCodeReservationId;
      readonly challengeId: EmailOtpChallengeId;
    }
  | WalletRecoveryAttemptFailure;

export type WalletRecoveryEmailOtpEnrollmentMaterial = {
  readonly enrollmentSealKeyVersion: string;
  readonly clientUnlockPublicKeyB64u: string;
  readonly unlockKeyVersion: string;
  readonly serverSealedFactorCiphertextB64u: string;
};

export type WalletRecoveryGoogleEmailOtpFinalizeResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      readonly authority: ActiveRecoveredWalletAuthorityV1;
      readonly authMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly kind: 'email_otp'; readonly status: 'active' }
      >;
    }
  | WalletRecoveryAttemptFailure;

export async function verifyWalletRecoveryGoogle(
  args: RecoveryOperationInput & { readonly idToken: string },
): Promise<WalletRecoveryGoogleVerifyResult> {
  const response = await postRecoveryJson(args, GOOGLE_VERIFY_PATH, {
    recoveryOperationId: args.recoveryOperationId,
    reservationId: args.reservationId,
    idToken: args.idToken,
  });
  if (!response.ok) return response.failure;
  const body = response.body;
  try {
    rejectUnknownFields(
      body,
      ['ok', 'recoveryOperationId', 'reservationId', 'challengeId', 'delivery', 'expiresAtMs'],
      'walletRecoveryGoogleVerify',
    );
    const identity = parseRecoveryResponseIdentity(body, args);
    const challengeId = requireParsed(parseEmailOtpChallengeId(body.challengeId));
    const expiresAtMs = Number(body.expiresAtMs);
    if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= 0) throw new Error('invalid expiry');
    return {
      kind: 'verified',
      ...identity,
      challengeId,
      delivery: parseEmailOtpChallengeDelivery(
        body.delivery,
        'walletRecoveryGoogleVerify.delivery',
      ),
      expiresAtMs,
    };
  } catch {
    return { kind: 'transport_uncertain' };
  }
}

export async function verifyWalletRecoveryEmailOtp(
  args: RecoveryOperationInput & {
    readonly challengeId: EmailOtpChallengeId;
    readonly otpCode: string;
  },
): Promise<WalletRecoveryEmailOtpVerifyResult> {
  const response = await postRecoveryJson(args, EMAIL_OTP_VERIFY_PATH, {
    recoveryOperationId: args.recoveryOperationId,
    reservationId: args.reservationId,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
  });
  if (!response.ok) return response.failure;
  try {
    rejectUnknownFields(
      response.body,
      ['ok', 'recoveryOperationId', 'reservationId', 'challengeId'],
      'walletRecoveryEmailOtpVerify',
    );
    const identity = parseRecoveryResponseIdentity(response.body, args);
    const challengeId = requireParsed(parseEmailOtpChallengeId(response.body.challengeId));
    if (challengeId !== args.challengeId) throw new Error('challenge changed');
    return { kind: 'verified', ...identity, challengeId };
  } catch {
    return { kind: 'transport_uncertain' };
  }
}

export async function finalizeWalletRecoveryGoogleEmailOtp(
  args: RecoveryOperationInput & {
    readonly walletId: WalletId;
    readonly targetDeviceId: DeviceId;
    readonly targetAuthorityId: WalletAuthorityId;
    readonly targetWalletAuthMethodId: WalletAuthMethodId;
    readonly expectedProviderSubject: string;
    readonly expectedEmailHashHex: string;
    readonly expectedRegistrationAuthorityId: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly ecdsaMaterialPossessionProofs: readonly {
      readonly keySetId: `evm_family_ecdsa:${string}`;
      readonly proof: WalletRecoveryEcdsaPossessionProofV1;
    }[];
    readonly emailOtpEnrollment: {
      readonly kind: 'create';
      readonly material: WalletRecoveryEmailOtpEnrollmentMaterial;
    } | null;
  },
): Promise<WalletRecoveryGoogleEmailOtpFinalizeResult> {
  let replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  let ecdsaMaterialPossessionProofs: readonly {
    readonly keySetId: `evm_family_ecdsa:${string}`;
    readonly proof: WalletRecoveryEcdsaPossessionProofV1;
  }[];
  try {
    replacementEnvelope = parsePasskeyCustodyEnvelopeRecord(
      args.replacementEnvelope,
      'walletRecoveryGoogleEmailOtpFinalize.replacementEnvelope',
    );
    if (replacementEnvelope.factor.kind !== 'email_otp') throw new Error('wrong factor');
    ecdsaMaterialPossessionProofs = args.ecdsaMaterialPossessionProofs.map((entry) => ({
      keySetId: entry.keySetId,
      proof: parseWalletRecoveryEcdsaPossessionProofV1(entry.proof),
    }));
  } catch {
    return { kind: 'refused' };
  }
  const response = await postRecoveryJson(args, GOOGLE_EMAIL_OTP_FINALIZE_PATH, {
    kind: 'finalize',
    recoveryOperationId: args.recoveryOperationId,
    reservationId: args.reservationId,
    replacementEnvelope,
    ecdsaMaterialPossessionProofs,
    ...(args.emailOtpEnrollment ? { emailOtpEnrollment: args.emailOtpEnrollment } : {}),
  });
  if (!response.ok) return response.failure;
  try {
    rejectUnknownFields(
      response.body,
      ['ok', 'projection'],
      'walletRecoveryGoogleEmailOtpFinalize',
    );
    const projection = await parseWalletRecoveryCommittedProjectionV1(
      response.body.projection,
      buildGoogleEmailOtpProjectionExpectation(args, replacementEnvelope),
    );
    if (projection.kind !== 'google_email_otp')
      throw new Error('recovery projection branch changed');
    return {
      kind: 'promoted',
      storeVersion: projection.storeVersion,
      authority: projection.authority,
      authMethod: projection.authMethod,
    };
  } catch {
    return { kind: 'transport_uncertain' };
  }
}

/** Replays an already-committed Email OTP recovery without an OTP or factor. */
export async function replayWalletRecoveryGoogleEmailOtp(args: {
  readonly relayUrl: string;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly walletId: WalletId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly expectedProviderSubject: string;
  readonly expectedEmailHashHex: string;
  readonly expectedRegistrationAuthorityId: string;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryGoogleEmailOtpFinalizeResult> {
  let replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  try {
    replacementEnvelope = parsePasskeyCustodyEnvelopeRecord(
      args.replacementEnvelope,
      'walletRecoveryGoogleEmailOtpReplay.replacementEnvelope',
    );
    if (
      replacementEnvelope.factor.kind !== 'email_otp' ||
      String(replacementEnvelope.walletId) !== String(args.walletId)
    ) {
      throw new Error('recovery replay envelope identity is invalid');
    }
  } catch {
    return { kind: 'refused' };
  }
  const response = await postRecoveryJson(
    args,
    GOOGLE_EMAIL_OTP_FINALIZE_PATH,
    {
      kind: 'replay',
      recoveryOperationId: args.recoveryOperationId,
      reservationId: args.reservationId,
      replacementEnvelope,
    },
  );
  if (!response.ok) return response.failure;
  try {
    rejectUnknownFields(
      response.body,
      ['ok', 'projection'],
      'walletRecoveryGoogleEmailOtpReplay',
    );
    const projection = await parseWalletRecoveryCommittedProjectionV1(
      response.body.projection,
      buildGoogleEmailOtpProjectionExpectation(args, replacementEnvelope),
    );
    if (projection.kind !== 'google_email_otp') {
      throw new Error('recovery projection branch changed');
    }
    return {
      kind: 'promoted',
      storeVersion: projection.storeVersion,
      authority: projection.authority,
      authMethod: projection.authMethod,
    };
  } catch {
    return { kind: 'transport_uncertain' };
  }
}

type RecoveryJsonResponse =
  | { readonly ok: true; readonly body: Record<string, unknown> }
  | { readonly ok: false; readonly failure: WalletRecoveryAttemptFailure };

async function postRecoveryJson(
  args: RecoveryOperationInput,
  path: string,
  body: Record<string, unknown>,
): Promise<RecoveryJsonResponse> {
  let response: Response;
  try {
    response = await (args.fetchImpl ?? fetch)(
      `${normalizeRelayerBaseUrl(args.relayUrl)}${path}`,
      buildRelayerJsonPostRequestInit({ body }),
    );
  } catch {
    return { ok: false, failure: { kind: 'transport_uncertain' } };
  }
  const parsed = await response.json().catch(() => ({}));
  if (response.status === 200 && isRecord(parsed) && parsed.ok === true) {
    return { ok: true, body: parsed };
  }
  if (response.status === 409 || response.status === 429) {
    return { ok: false, failure: { kind: 'retryable_conflict' } };
  }
  if (response.status === 400 || response.status === 401) {
    return { ok: false, failure: { kind: 'refused' } };
  }
  return { ok: false, failure: { kind: 'transport_uncertain' } };
}

function parseRecoveryResponseIdentity(
  body: Record<string, unknown>,
  expected: Pick<RecoveryOperationInput, 'recoveryOperationId' | 'reservationId'>,
): {
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly reservationId: RecoveryCodeReservationId;
} {
  const recoveryOperationId = requireParsed(
    parseWalletRecoveryOperationId(body.recoveryOperationId),
  );
  const reservationId = parseRecoveryCodeReservationId(body.reservationId);
  if (
    recoveryOperationId !== expected.recoveryOperationId ||
    reservationId !== expected.reservationId
  ) {
    throw new Error('recovery operation identity changed');
  }
  return { recoveryOperationId, reservationId };
}

function requireParsed<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false },
): T {
  if (!result.ok) throw new Error('invalid domain identity');
  return result.value;
}

function requireString(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error('value must be a string');
  return value.trim();
}

function buildGoogleEmailOtpProjectionExpectation(
  args: {
    readonly walletId: WalletId;
    readonly recoveryOperationId: WalletRecoveryOperationId;
    readonly targetDeviceId: DeviceId;
    readonly targetAuthorityId: WalletAuthorityId;
    readonly targetWalletAuthMethodId: WalletAuthMethodId;
    readonly expectedProviderSubject: string;
    readonly expectedEmailHashHex: string;
    readonly expectedRegistrationAuthorityId: string;
  },
  replacementEnvelope: PasskeyCustodyEnvelopeRecord,
): WalletRecoveryCommittedProjectionExpectationV1 {
  if (replacementEnvelope.factor.kind !== 'email_otp') {
    throw new Error('replacement envelope is not an Email OTP envelope');
  }
  return {
    kind: 'google_email_otp',
    walletId: args.walletId,
    recoveryOperationId: args.recoveryOperationId,
    targetDeviceId: args.targetDeviceId,
    targetAuthorityId: args.targetAuthorityId,
    targetWalletAuthMethodId: args.targetWalletAuthMethodId,
    providerSubject: requireParsed(parseEmailOtpProviderUserId(args.expectedProviderSubject)),
    emailHashHex: requireEmailHash(args.expectedEmailHashHex),
    registrationAuthorityId: requireString(args.expectedRegistrationAuthorityId),
    enrollment: {
      kind: 'email_otp_enrollment_reference_v1',
      enrollmentId: requireString(replacementEnvelope.factor.enrollmentId),
      enrollmentSealKeyVersion: requireString(replacementEnvelope.factor.enrollmentSealKeyVersion),
    },
  };
}

function requireEmailHash(value: string): string {
  const hash = requireString(value);
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('email hash is invalid');
  return hash;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
