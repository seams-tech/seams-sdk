import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpAuthStateStore,
  EmailOtpWalletEnrollmentRecord,
  EmailOtpWalletEnrollmentStore,
} from '../EmailOtpStores';

export type EmailOtpEnrollmentReadResult =
  | {
      ok: true;
      enrollment: EmailOtpWalletEnrollmentRecord;
    }
  | { ok: false; code: string; message: string };

export type EmailOtpAuthStateReadResult =
  | { ok: true; state: EmailOtpAuthStateRecord | null }
  | { ok: false; code: string; message: string };

export type EmailOtpAuthStatePatch = Partial<
  Pick<
    EmailOtpAuthStateRecord,
    | 'otpFailureCount'
    | 'lastOtpFailureAtMs'
    | 'otpLockedUntilMs'
    | 'lastEmailOtpLoginAtMs'
    | 'lastStrongAuthAtMs'
  >
>;

export type EmailOtpStrongAuthRequiredResult =
  | {
      ok: true;
      required: boolean;
      walletId: string;
      lastEmailOtpLoginAtMs?: number;
      lastStrongAuthAtMs?: number;
    }
  | { ok: false; code: string; message: string };

export type EmailOtpStrongAuthSatisfiedResult =
  | { ok: true; walletId: string; lastStrongAuthAtMs?: number }
  | { ok: false; code: string; message: string };

export async function readEmailOtpEnrollmentWithStore(input: {
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly request: { walletId?: unknown; orgId: unknown };
}): Promise<EmailOtpEnrollmentReadResult> {
  const walletId = toOptionalTrimmedString(input.request.walletId);
  const orgId = toOptionalTrimmedString(input.request.orgId);
  if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
  if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
  const enrollment = await input.walletEnrollmentStore.get(walletId);
  if (!enrollment) {
    return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
  }
  if (enrollment.orgId !== orgId) {
    return {
      ok: false,
      code: 'tenant_scope_mismatch',
      message: 'Email OTP enrollment does not match the requested orgId',
    };
  }
  return { ok: true, enrollment };
}

export async function readActiveEmailOtpEnrollmentWithStore(input: {
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly request: {
    walletId?: unknown;
    orgId: unknown;
    providerUserId?: unknown;
  };
}): Promise<EmailOtpEnrollmentReadResult> {
  const result = await readEmailOtpEnrollmentWithStore(input);
  if (!result.ok) return result;
  const providerUserId = toOptionalTrimmedString(input.request.providerUserId);
  if (providerUserId && result.enrollment.providerUserId !== providerUserId) {
    return {
      ok: false,
      code: 'provider_identity_mismatch',
      message: 'Email OTP enrollment does not match the requested provider user',
    };
  }
  return result;
}

export async function readEmailOtpAuthStateForEnrollmentWithStore(input: {
  readonly authStateStore: EmailOtpAuthStateStore;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
}): Promise<EmailOtpAuthStateReadResult> {
  const state = await input.authStateStore.get(input.enrollment.walletId);
  if (!state) return { ok: true, state: null };
  if (
    state.orgId !== input.enrollment.orgId ||
    state.providerUserId !== input.enrollment.providerUserId
  ) {
    return {
      ok: false,
      code: 'auth_state_enrollment_mismatch',
      message: 'Email OTP auth state does not match the active enrollment',
    };
  }
  return { ok: true, state };
}

export async function putEmailOtpAuthStateForEnrollmentWithStore(input: {
  readonly authStateStore: EmailOtpAuthStateStore;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly patch: EmailOtpAuthStatePatch;
  readonly nowMs: number;
}): Promise<EmailOtpAuthStateRecord> {
  const existing = await input.authStateStore.get(input.enrollment.walletId);
  if (
    existing &&
    (existing.orgId !== input.enrollment.orgId ||
      existing.providerUserId !== input.enrollment.providerUserId)
  ) {
    throw new Error('Email OTP auth state does not match the active enrollment');
  }
  const next: EmailOtpAuthStateRecord = {
    version: 'email_otp_auth_state_v1',
    walletId: input.enrollment.walletId,
    providerUserId: input.enrollment.providerUserId,
    orgId: input.enrollment.orgId,
    createdAtMs: existing?.createdAtMs ?? input.nowMs,
    updatedAtMs: input.nowMs,
    ...(existing?.otpFailureCount != null ? { otpFailureCount: existing.otpFailureCount } : {}),
    ...(existing?.lastOtpFailureAtMs ? { lastOtpFailureAtMs: existing.lastOtpFailureAtMs } : {}),
    ...(existing?.otpLockedUntilMs ? { otpLockedUntilMs: existing.otpLockedUntilMs } : {}),
    ...(existing?.lastEmailOtpLoginAtMs
      ? { lastEmailOtpLoginAtMs: existing.lastEmailOtpLoginAtMs }
      : {}),
    ...(existing?.lastStrongAuthAtMs ? { lastStrongAuthAtMs: existing.lastStrongAuthAtMs } : {}),
    ...input.patch,
  };
  await input.authStateStore.put(next);
  return next;
}

export async function isEmailOtpStrongAuthRequiredWithStores(input: {
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly authStateStore: EmailOtpAuthStateStore;
  readonly request: { walletId?: unknown };
}): Promise<EmailOtpStrongAuthRequiredResult> {
  const walletId = toOptionalTrimmedString(input.request.walletId);
  if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
  const enrollment = await input.walletEnrollmentStore.get(walletId);
  if (!enrollment) {
    return { ok: true, required: false, walletId };
  }
  const authState = await readEmailOtpAuthStateForEnrollmentWithStore({
    authStateStore: input.authStateStore,
    enrollment,
  });
  if (!authState.ok) return authState;
  const state = authState.state;
  if (!state) {
    return { ok: true, required: false, walletId };
  }
  const lastEmailOtpLoginAtMs =
    typeof state.lastEmailOtpLoginAtMs === 'number' ? state.lastEmailOtpLoginAtMs : undefined;
  const lastStrongAuthAtMs =
    typeof state.lastStrongAuthAtMs === 'number' ? state.lastStrongAuthAtMs : undefined;
  return {
    ok: true,
    required: Boolean(
      lastEmailOtpLoginAtMs &&
        (!lastStrongAuthAtMs || lastEmailOtpLoginAtMs > lastStrongAuthAtMs),
    ),
    walletId,
    ...(lastEmailOtpLoginAtMs ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs ? { lastStrongAuthAtMs } : {}),
  };
}

export async function markEmailOtpStrongAuthSatisfiedWithStores(input: {
  readonly walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  readonly authStateStore: EmailOtpAuthStateStore;
  readonly request: { walletId?: unknown };
  readonly nowMs: number;
}): Promise<EmailOtpStrongAuthSatisfiedResult> {
  const walletId = toOptionalTrimmedString(input.request.walletId);
  if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
  const enrollment = await input.walletEnrollmentStore.get(walletId);
  if (!enrollment) return { ok: true, walletId };
  await putEmailOtpAuthStateForEnrollmentWithStore({
    authStateStore: input.authStateStore,
    enrollment,
    patch: { lastStrongAuthAtMs: input.nowMs },
    nowMs: input.nowMs,
  });
  return { ok: true, walletId, lastStrongAuthAtMs: input.nowMs };
}
