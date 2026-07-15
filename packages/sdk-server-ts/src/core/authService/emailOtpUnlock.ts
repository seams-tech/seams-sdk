import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpUnlockChallengeStore,
  EmailOtpWalletEnrollmentRecord,
} from '../EmailOtpStores';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from '../ThresholdService/ethSignerWasm';
import { parseBoundaryWalletId } from './webauthnWalletBinding';

export type EmailOtpUnlockEnrollmentReadResult =
  | { ok: true; enrollment: EmailOtpWalletEnrollmentRecord }
  | { ok: false; code: string; message: string };

export type CreateEmailOtpUnlockChallengeRequest = {
  walletId?: unknown;
  orgId?: unknown;
  ttlMs?: unknown;
  ttl_ms?: unknown;
};

export type CreateEmailOtpUnlockChallengeResult =
  | {
      ok: true;
      walletId: string;
      challengeId: string;
      challengeB64u: string;
      expiresAtMs: number;
      unlockKeyVersion: string;
    }
  | { ok: false; code: string; message: string; lockedUntilMs?: number };

export type VerifyEmailOtpUnlockProofRequest = {
  walletId?: unknown;
  orgId?: unknown;
  challengeId?: unknown;
  unlockProof?: unknown;
};

export type VerifyEmailOtpUnlockProofResult =
  | {
      ok: true;
      verified: true;
      userId: string;
      walletId: string;
      providerUserId: string;
      orgId: string;
      unlockKeyVersion: string;
    }
  | { ok: false; verified: false; code: string; message: string };

export type CreateEmailOtpUnlockChallengeInput = {
  request: CreateEmailOtpUnlockChallengeRequest;
  unlockChallengeStore: EmailOtpUnlockChallengeStore;
  readActiveEnrollment: (input: {
    walletId: string;
    orgId: string | undefined;
  }) => Promise<EmailOtpUnlockEnrollmentReadResult>;
};

export type VerifyEmailOtpUnlockProofInput = {
  request: VerifyEmailOtpUnlockProofRequest;
  unlockChallengeStore: EmailOtpUnlockChallengeStore;
  readActiveEnrollment: (input: {
    walletId: string;
    orgId: string | undefined;
  }) => Promise<EmailOtpUnlockEnrollmentReadResult>;
  putAuthStateForEnrollment: (
    enrollment: EmailOtpWalletEnrollmentRecord,
    patch: Pick<EmailOtpAuthStateRecord, 'lastEmailOtpLoginAtMs'>,
  ) => Promise<EmailOtpAuthStateRecord>;
};

type ParsedEmailOtpUnlockProof = {
  publicKey: string;
  signatureB64u: string;
};

function parsedUnlockWalletId(raw: unknown): string | null {
  const walletIdRaw = toOptionalTrimmedString(raw);
  if (!walletIdRaw) return null;
  return parseBoundaryWalletId(walletIdRaw);
}

function requestedUnlockTtlMs(raw: unknown): number {
  const numeric = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(numeric) || numeric <= 0) return 5 * 60_000;
  return Math.floor(numeric);
}

function clampedUnlockTtlMs(raw: unknown): number {
  return Math.min(Math.max(requestedUnlockTtlMs(raw), 10_000), 10 * 60_000);
}

function parseUnlockProof(raw: unknown): ParsedEmailOtpUnlockProof | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const signatureB64u = toOptionalTrimmedString(record.signature);
  if (!publicKey || !signatureB64u) return null;
  return { publicKey, signatureB64u };
}

function decodeBase64UrlField(input: {
  value: string;
  missingMessage: string;
  invalidMessage: string;
  expectedLength: number;
  expectedLengthMessage: string;
}): { ok: true; bytes: Uint8Array } | { ok: false; message: string } {
  if (!input.value) return { ok: false, message: input.missingMessage };
  try {
    const bytes = base64UrlDecode(input.value);
    if (bytes.length !== input.expectedLength) {
      return { ok: false, message: input.expectedLengthMessage };
    }
    return { ok: true, bytes };
  } catch {
    return { ok: false, message: input.invalidMessage };
  }
}

function byteArraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return a.every((value, index) => value === b[index]);
}

export async function createEmailOtpUnlockChallenge(
  input: CreateEmailOtpUnlockChallengeInput,
): Promise<CreateEmailOtpUnlockChallengeResult> {
  try {
    const walletId = parsedUnlockWalletId(input.request.walletId);
    const orgId = toOptionalTrimmedString(input.request.orgId) || undefined;
    if (!toOptionalTrimmedString(input.request.walletId)) {
      return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    }
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Invalid walletId' };

    const activeEnrollment = await input.readActiveEnrollment({ walletId, orgId });
    if (!activeEnrollment.ok) return activeEnrollment;
    const enrollment = activeEnrollment.enrollment;

    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }

    const createdAtMs = Date.now();
    const expiresAtMs = createdAtMs + clampedUnlockTtlMs(input.request.ttlMs ?? input.request.ttl_ms);
    const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
    const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
    await input.unlockChallengeStore.put({
      version: 'email_otp_unlock_challenge_v1',
      challengeId,
      walletId: enrollment.walletId,
      userId: enrollment.providerUserId,
      orgId: enrollment.orgId,
      challengeB64u,
      createdAtMs,
      expiresAtMs,
    });

    return {
      ok: true,
      walletId: enrollment.walletId,
      challengeId,
      challengeB64u,
      expiresAtMs,
      unlockKeyVersion: enrollment.unlockKeyVersion,
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to create Email OTP unlock challenge',
    };
  }
}

export async function verifyEmailOtpUnlockProof(
  input: VerifyEmailOtpUnlockProofInput,
): Promise<VerifyEmailOtpUnlockProofResult> {
  try {
    const walletId = parsedUnlockWalletId(input.request.walletId);
    const orgId = toOptionalTrimmedString(input.request.orgId) || undefined;
    const challengeId = toOptionalTrimmedString(input.request.challengeId);
    if (!toOptionalTrimmedString(input.request.walletId)) {
      return { ok: false, verified: false, code: 'invalid_body', message: 'Missing walletId' };
    }
    if (!walletId) {
      return { ok: false, verified: false, code: 'invalid_body', message: 'Invalid walletId' };
    }
    if (!challengeId) {
      return { ok: false, verified: false, code: 'invalid_body', message: 'Missing challengeId' };
    }

    const unlockProof = parseUnlockProof(input.request.unlockProof);
    if (!unlockProof) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'unlockProof is required',
      };
    }

    const challengeRecord = await input.unlockChallengeStore.consume(challengeId);
    if (!challengeRecord || Date.now() > challengeRecord.expiresAtMs) {
      return {
        ok: false,
        verified: false,
        code: 'challenge_expired_or_invalid',
        message: 'Email OTP unlock challenge expired or invalid',
      };
    }
    if (challengeRecord.walletId !== walletId) {
      return {
        ok: false,
        verified: false,
        code: 'challenge_binding_mismatch',
        message: 'Email OTP unlock challenge is not valid for this walletId',
      };
    }

    const activeEnrollment = await input.readActiveEnrollment({ walletId, orgId });
    if (!activeEnrollment.ok) {
      return {
        ok: false,
        verified: false,
        code: activeEnrollment.code,
        message: activeEnrollment.message,
      };
    }
    const enrollment = activeEnrollment.enrollment;
    if (
      challengeRecord.userId !== enrollment.providerUserId ||
      challengeRecord.orgId !== enrollment.orgId
    ) {
      return {
        ok: false,
        verified: false,
        code: 'challenge_binding_mismatch',
        message: 'Email OTP unlock challenge is not valid for this enrollment',
      };
    }

    const publicKeyDecode = decodeBase64UrlField({
      value: unlockProof.publicKey,
      missingMessage: 'unlockProof.publicKey is required',
      invalidMessage: 'unlockProof.publicKey must be valid base64url',
      expectedLength: 33,
      expectedLengthMessage: 'unlockProof.publicKey must decode to 33 bytes',
    });
    if (!publicKeyDecode.ok) {
      return { ok: false, verified: false, code: 'invalid_body', message: publicKeyDecode.message };
    }
    try {
      await validateSecp256k1PublicKey33(publicKeyDecode.bytes);
    } catch {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'unlockProof.publicKey is not a valid secp256k1 public key',
      };
    }

    const signatureDecode = decodeBase64UrlField({
      value: unlockProof.signatureB64u,
      missingMessage: 'unlockProof.signature is required',
      invalidMessage: 'unlockProof.signature must be valid base64url',
      expectedLength: 65,
      expectedLengthMessage: 'unlockProof.signature must decode to 65 bytes',
    });
    if (!signatureDecode.ok) {
      return { ok: false, verified: false, code: 'invalid_body', message: signatureDecode.message };
    }

    const enrolledPublicKey = base64UrlDecode(enrollment.clientUnlockPublicKeyB64u);
    if (!byteArraysEqual(enrolledPublicKey, publicKeyDecode.bytes)) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_unlock_proof',
        message: 'unlockProof.publicKey does not match the enrolled clientUnlockPublicKeyB64u',
      };
    }

    const challengeDigestDecode = decodeBase64UrlField({
      value: challengeRecord.challengeB64u,
      missingMessage: 'Stored unlock challenge digest was invalid',
      invalidMessage: 'Stored unlock challenge digest was invalid',
      expectedLength: 32,
      expectedLengthMessage: 'Stored unlock challenge digest must decode to 32 bytes',
    });
    if (!challengeDigestDecode.ok) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: challengeDigestDecode.message,
      };
    }

    try {
      await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
        challengeDigestDecode.bytes,
        signatureDecode.bytes,
        publicKeyDecode.bytes,
      );
    } catch {
      return {
        ok: false,
        verified: false,
        code: 'invalid_unlock_proof',
        message: 'unlockProof.signature did not verify against unlockProof.publicKey',
      };
    }

    const nowMs = Date.now();
    await input.putAuthStateForEnrollment(enrollment, {
      lastEmailOtpLoginAtMs: nowMs,
    });

    return {
      ok: true,
      verified: true,
      userId: enrollment.walletId,
      walletId: enrollment.walletId,
      providerUserId: enrollment.providerUserId,
      orgId: enrollment.orgId,
      unlockKeyVersion: enrollment.unlockKeyVersion,
    };
  } catch (e: unknown) {
    return {
      ok: false,
      verified: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to verify Email OTP unlock proof',
    };
  }
}
