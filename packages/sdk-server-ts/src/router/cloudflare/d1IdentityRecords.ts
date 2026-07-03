import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { LinkIdentityResult } from '../../core/IdentityStore';
import type {
  RouterApiIdentityService,
} from '../authServicePort';
import { positiveInteger } from './d1RouterApiAuthBoundary';

type ResolveGoogleEmailOtpSessionResult = Awaited<
  ReturnType<RouterApiIdentityService['resolveGoogleEmailOtpSession']>
>;

export type D1IdentityRow = {
  readonly subject?: unknown;
  readonly user_id?: unknown;
  readonly created_at_ms?: unknown;
  readonly subject_count?: unknown;
};

type IdentitySubjectRecord = {
  readonly version: 'identity_subject_v1';
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

export function hasDifferentWalletIdentitySubject(input: {
  readonly subjects: readonly string[];
  readonly expectedIdentitySubject: string;
}): boolean {
  for (const subject of input.subjects) {
    if (subject.startsWith('wallet:') && subject !== input.expectedIdentitySubject) return true;
  }
  return false;
}

export function googleEmailOtpStaleIdentityMapping(input: {
  readonly providerSubject: string;
  readonly linkedWalletId: string;
  readonly email?: string;
}): Extract<ResolveGoogleEmailOtpSessionResult, { readonly ok: false }> {
  const email = toOptionalTrimmedString(input.email);
  return {
    ok: false,
    mode: 'stale_identity_mapping',
    code: 'stale_identity_mapping',
    walletId: input.linkedWalletId,
    providerSubject: input.providerSubject,
    ...(email ? { email } : {}),
    message:
      'Google Email OTP identity mapping is stale. Clear the stale identity mapping with the dev cleanup route before registering this Google account.',
  };
}

export function parseIdentityCreatedAt(input: unknown, fallback: number): number {
  return positiveInteger(input) ?? fallback;
}

export function identitySubjectRecord(input: {
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): IdentitySubjectRecord {
  return {
    version: 'identity_subject_v1',
    subject: input.subject,
    userId: input.userId,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

export function identityAlreadyLinked(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is already linked to a different user',
  };
}

export function identityMoveDisallowed(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is linked to a different user with other identities; merge is not allowed',
  };
}
