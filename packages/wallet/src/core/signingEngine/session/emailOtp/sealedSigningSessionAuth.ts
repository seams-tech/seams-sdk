import type {
  CurrentSealedSessionRecord,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ExactEcdsaSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { EmailOtpEcdsaSigningSessionAuthority } from './ecdsaSigningSessionAuthority';

export type SealedEmailOtpEcdsaSigningSessionAuthInput = {
  lane: ExactEcdsaSigningLaneIdentity;
  sealedRecord: SigningSessionSealedStoreRecord;
};

export function emailOtpEcdsaSigningSessionAuthorityFromSealedRecord(
  _input: SealedEmailOtpEcdsaSigningSessionAuthInput,
): EmailOtpEcdsaSigningSessionAuthority | null {
  return null;
}

export function exactEmailOtpEcdsaSigningSessionAuthorityFromSealedRecords(args: {
  lane: ExactEcdsaSigningLaneIdentity;
  sealedRecords: readonly CurrentSealedSessionRecord[];
}): EmailOtpEcdsaSigningSessionAuthority | null {
  const exactAuthorities: EmailOtpEcdsaSigningSessionAuthority[] = [];
  for (const sealedRecord of args.sealedRecords) {
    const authority = emailOtpEcdsaSigningSessionAuthorityFromSealedRecord({
      lane: args.lane,
      sealedRecord,
    });
    if (authority) exactAuthorities.push(authority);
  }
  if (exactAuthorities.length > 1) {
    throw new Error(
      '[SigningEngine][ecdsa] multiple durable Email OTP authorities matched one exact lane',
    );
  }
  return exactAuthorities[0] ?? null;
}
