import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  GoogleEmailOtpRegistrationAttemptRecord,
  GoogleEmailOtpRegistrationOfferCandidateRecord,
  NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
  PendingGoogleEmailOtpRegistrationAttemptRecord,
} from '../../core/EmailOtpStores';
import {
  isB64uString,
  nonNegativeSafeInteger,
  parseJsonObject,
  positiveSafeInteger,
} from './d1RouterApiAuthBoundary';

export type D1EmailOtpRegistrationAttemptRow = {
  readonly attempt_id?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

export type GoogleEmailOtpRegistrationOfferForResponse = {
  readonly offerId: string;
  readonly selectedCandidateId: string;
  readonly candidates: readonly [
    { readonly candidateId: string; readonly walletId: string },
    ...{ readonly candidateId: string; readonly walletId: string }[],
  ];
};

type GoogleEmailOtpRegistrationAttemptParseFields = {
  readonly attemptId: string;
  readonly providerSubject: string;
  readonly email: string;
  readonly walletId: string;
  readonly offerId: string;
  readonly offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  readonly selectedCandidateId: string;
  readonly appSessionVersion: string;
  readonly authProvider: string;
  readonly accountIdSlugVersion: 'hmac_readable_v1';
  readonly walletIdDerivationNonce: string;
  readonly collisionCounter: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly expiresAtMs: number;
  readonly runtimePolicyScope?: RuntimePolicyScope;
};

export function requireRuntimePolicyScope(input: unknown): RuntimePolicyScope {
  const scope = parseRuntimePolicyScope(input);
  if (scope) return scope;
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, runtimePolicyScope.envId, and runtimePolicyScope.signingRootVersion are required for Google Email OTP registration',
  );
}

export function runtimePolicyScopeKey(scope: RuntimePolicyScope | undefined): string {
  if (!scope) return '';
  return `${scope.orgId}\n${scope.projectId}\n${scope.envId}\n${scope.signingRootVersion}`;
}

export function activeGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  const terminal = terminalGoogleEmailOtpRegistrationAttemptRecord({
    fields: {
      ...googleEmailOtpRegistrationAttemptFields(input.record),
      updatedAtMs: input.updatedAtMs,
    },
    state: 'active',
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
  });
  if (!terminal) throw new Error('Failed to build active Google Email OTP registration attempt');
  return terminal;
}

export function expiredGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: GoogleEmailOtpRegistrationAttemptRecord;
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  const terminal = terminalGoogleEmailOtpRegistrationAttemptRecord({
    fields: {
      ...googleEmailOtpRegistrationAttemptFields(input.record),
      updatedAtMs: input.updatedAtMs,
    },
    state: 'expired',
    ...('finalizedPublicKey' in input.record && input.record.finalizedPublicKey
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
    ...('failureCode' in input.record && input.record.failureCode
      ? { failureCode: input.record.failureCode }
      : {}),
  });
  if (!terminal) throw new Error('Failed to build expired Google Email OTP registration attempt');
  return terminal;
}

export function failedGoogleEmailOtpRegistrationAttemptWithCode(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly failureCode: string;
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  const terminal = terminalGoogleEmailOtpRegistrationAttemptRecord({
    fields: {
      ...googleEmailOtpRegistrationAttemptFields(input.record),
      updatedAtMs: input.updatedAtMs,
    },
    state: 'failed',
    failureCode: input.failureCode,
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
  });
  if (!terminal) throw new Error('Failed to build failed Google Email OTP registration attempt');
  return terminal;
}

export function parseGoogleEmailOtpRegistrationAttemptRecord(
  input: unknown,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const attemptId = toOptionalTrimmedString(record.attemptId);
  const providerSubject = toOptionalTrimmedString(record.providerSubject);
  const email = toOptionalTrimmedString(record.email);
  const walletId = toOptionalTrimmedString(record.walletId);
  const offerId = toOptionalTrimmedString(record.offerId);
  const offerCandidates = parseGoogleEmailOtpRegistrationOfferCandidates(record.offerCandidates);
  const selectedCandidateId = toOptionalTrimmedString(record.selectedCandidateId);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
  const authProvider = toOptionalTrimmedString(record.authProvider);
  const accountIdSlugVersion = toOptionalTrimmedString(record.accountIdSlugVersion);
  const walletIdDerivationNonce = toOptionalTrimmedString(record.walletIdDerivationNonce);
  const collisionCounter = nonNegativeSafeInteger(record.collisionCounter);
  const state = googleEmailOtpRegistrationAttemptState(record.state);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const runtimePolicyScope = parseRuntimePolicyScope(record.runtimePolicyScope);
  const finalizedPublicKey = toOptionalTrimmedString(record.finalizedPublicKey);
  const failureCode = toOptionalTrimmedString(record.failureCode);
  if (
    version !== 'google_email_otp_registration_attempt_v1' ||
    !attemptId ||
    !providerSubject ||
    !email ||
    !walletId ||
    !offerId ||
    !offerCandidates ||
    !selectedCandidateId ||
    !googleEmailOtpRegistrationOfferContainsCandidate({
      candidates: offerCandidates,
      candidateId: selectedCandidateId,
    }) ||
    !appSessionVersion ||
    !authProvider ||
    accountIdSlugVersion !== 'hmac_readable_v1' ||
    !walletIdDerivationNonce ||
    !isB64uString(walletIdDerivationNonce) ||
    collisionCounter == null ||
    !state ||
    !createdAtMs ||
    !updatedAtMs ||
    !expiresAtMs ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  if (state === 'key_finalized' && !finalizedPublicKey) return null;
  const fields: GoogleEmailOtpRegistrationAttemptParseFields = {
    attemptId,
    providerSubject,
    email,
    walletId,
    offerId,
    offerCandidates,
    selectedCandidateId,
    appSessionVersion,
    authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce,
    collisionCounter,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
  switch (state) {
    case 'started':
      return startedGoogleEmailOtpRegistrationAttemptRecord(fields);
    case 'key_finalized':
      return keyFinalizedGoogleEmailOtpRegistrationAttemptRecord({
        ...fields,
        finalizedPublicKey: finalizedPublicKey || '',
      });
    case 'active':
    case 'abandoned':
    case 'failed':
    case 'expired':
      return terminalGoogleEmailOtpRegistrationAttemptRecord({
        fields,
        state,
        ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
        ...(failureCode ? { failureCode } : {}),
      });
  }
}

export function parseGoogleEmailOtpRegistrationAttemptRow(
  row: D1EmailOtpRegistrationAttemptRow | null,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  const record = parseGoogleEmailOtpRegistrationAttemptRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !expiresAtMs || !updatedAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

export function registrationAttemptMatchesStartedScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope?: RuntimePolicyScope;
    readonly nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion === input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

export function registrationAttemptMatchesReplacementScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope?: RuntimePolicyScope;
    readonly nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion !== input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

export function googleEmailOtpRegistrationOfferWalletIdsJson(
  candidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
): string {
  const walletIds: string[] = [];
  for (const candidate of candidates) walletIds.push(candidate.walletId);
  return JSON.stringify(walletIds);
}

export function googleEmailOtpRegistrationOfferForResponse(
  input: Pick<
    PendingGoogleEmailOtpRegistrationAttemptRecord,
    'offerId' | 'offerCandidates' | 'selectedCandidateId'
  >,
): GoogleEmailOtpRegistrationOfferForResponse {
  const first = input.offerCandidates[0];
  const candidates: { readonly candidateId: string; readonly walletId: string }[] = [
    { candidateId: first.candidateId, walletId: first.walletId },
  ];
  for (let index = 1; index < input.offerCandidates.length; index += 1) {
    const candidate = input.offerCandidates[index];
    if (!candidate) continue;
    candidates.push({ candidateId: candidate.candidateId, walletId: candidate.walletId });
  }
  return {
    offerId: input.offerId,
    selectedCandidateId: input.selectedCandidateId,
    candidates: [candidates[0], ...candidates.slice(1)],
  };
}

export function pendingGoogleEmailOtpRegistrationAttemptWithUpdatedAt(
  record: PendingGoogleEmailOtpRegistrationAttemptRecord,
  updatedAtMs: number,
): PendingGoogleEmailOtpRegistrationAttemptRecord {
  if (record.state === 'started') {
    return {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: record.attemptId,
      providerSubject: record.providerSubject,
      email: record.email,
      walletId: record.walletId,
      offerId: record.offerId,
      offerCandidates: record.offerCandidates,
      selectedCandidateId: record.selectedCandidateId,
      appSessionVersion: record.appSessionVersion,
      authProvider: record.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: record.walletIdDerivationNonce,
      collisionCounter: record.collisionCounter,
      state: 'started',
      createdAtMs: record.createdAtMs,
      updatedAtMs,
      expiresAtMs: record.expiresAtMs,
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    };
  }
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: record.attemptId,
    providerSubject: record.providerSubject,
    email: record.email,
    walletId: record.walletId,
    offerId: record.offerId,
    offerCandidates: record.offerCandidates,
    selectedCandidateId: record.selectedCandidateId,
    appSessionVersion: record.appSessionVersion,
    authProvider: record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: record.walletIdDerivationNonce,
    collisionCounter: record.collisionCounter,
    state: 'key_finalized',
    finalizedPublicKey: record.finalizedPublicKey,
    createdAtMs: record.createdAtMs,
    updatedAtMs,
    expiresAtMs: record.expiresAtMs,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
  };
}

export function pendingGoogleEmailOtpRegistrationAttemptWithSelectedCandidate(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly candidate: GoogleEmailOtpRegistrationOfferCandidateRecord;
  readonly updatedAtMs: number;
}): PendingGoogleEmailOtpRegistrationAttemptRecord {
  if (input.record.state === 'started') {
    return {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: input.record.attemptId,
      providerSubject: input.record.providerSubject,
      email: input.record.email,
      walletId: input.candidate.walletId,
      offerId: input.record.offerId,
      offerCandidates: input.record.offerCandidates,
      selectedCandidateId: input.candidate.candidateId,
      appSessionVersion: input.record.appSessionVersion,
      authProvider: input.record.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: input.record.walletIdDerivationNonce,
      collisionCounter: input.candidate.collisionCounter,
      state: 'started',
      createdAtMs: input.record.createdAtMs,
      updatedAtMs: input.updatedAtMs,
      expiresAtMs: input.record.expiresAtMs,
      ...(input.record.runtimePolicyScope
        ? { runtimePolicyScope: input.record.runtimePolicyScope }
        : {}),
    };
  }
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.record.attemptId,
    providerSubject: input.record.providerSubject,
    email: input.record.email,
    walletId: input.candidate.walletId,
    offerId: input.record.offerId,
    offerCandidates: input.record.offerCandidates,
    selectedCandidateId: input.candidate.candidateId,
    appSessionVersion: input.record.appSessionVersion,
    authProvider: input.record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.record.walletIdDerivationNonce,
    collisionCounter: input.candidate.collisionCounter,
    state: 'key_finalized',
    finalizedPublicKey: input.record.finalizedPublicKey,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    ...(input.record.runtimePolicyScope
      ? { runtimePolicyScope: input.record.runtimePolicyScope }
      : {}),
  };
}

export function abandonedGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly failureCode: 'app_session_version_replaced' | 'offer_restarted_by_user';
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.record.attemptId,
    providerSubject: input.record.providerSubject,
    email: input.record.email,
    walletId: input.record.walletId,
    offerId: input.record.offerId,
    offerCandidates: input.record.offerCandidates,
    selectedCandidateId: input.record.selectedCandidateId,
    appSessionVersion: input.record.appSessionVersion,
    authProvider: input.record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.record.walletIdDerivationNonce,
    collisionCounter: input.record.collisionCounter,
    state: 'abandoned',
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
    failureCode: input.failureCode,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    ...(input.record.runtimePolicyScope
      ? { runtimePolicyScope: input.record.runtimePolicyScope }
      : {}),
  };
}

function parseRuntimePolicyScope(input: unknown): RuntimePolicyScope | undefined {
  const record = parseJsonObject(input);
  if (!record) return undefined;
  const orgId = toOptionalTrimmedString(record.orgId);
  const projectId = toOptionalTrimmedString(record.projectId);
  const envId = toOptionalTrimmedString(record.envId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return { orgId, projectId, envId, signingRootVersion };
}

function parseGoogleEmailOtpRegistrationOfferCandidate(
  input: unknown,
): GoogleEmailOtpRegistrationOfferCandidateRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const candidateId = toOptionalTrimmedString(record.candidateId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const collisionCounter = nonNegativeSafeInteger(record.collisionCounter);
  if (!candidateId || !walletId || collisionCounter == null) return null;
  return { candidateId, walletId, collisionCounter };
}

function parseGoogleEmailOtpRegistrationOfferCandidates(
  input: unknown,
): NonEmptyGoogleEmailOtpRegistrationOfferCandidates | null {
  if (!Array.isArray(input)) return null;
  const candidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
  for (const item of input) {
    const candidate = parseGoogleEmailOtpRegistrationOfferCandidate(item);
    if (!candidate) return null;
    candidates.push(candidate);
  }
  const first = candidates[0];
  if (!first) return null;
  return [first, ...candidates.slice(1)];
}

function googleEmailOtpRegistrationOfferContainsCandidate(input: {
  readonly candidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  readonly candidateId: string;
}): boolean {
  for (const candidate of input.candidates) {
    if (candidate.candidateId === input.candidateId) return true;
  }
  return false;
}

function googleEmailOtpRegistrationAttemptState(
  input: unknown,
): GoogleEmailOtpRegistrationAttemptRecord['state'] | null {
  const state = toOptionalTrimmedString(input);
  switch (state) {
    case 'started':
    case 'key_finalized':
    case 'active':
    case 'abandoned':
    case 'failed':
    case 'expired':
      return state;
    default:
      return null;
  }
}

function startedGoogleEmailOtpRegistrationAttemptRecord(
  input: GoogleEmailOtpRegistrationAttemptParseFields,
): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.attemptId,
    providerSubject: input.providerSubject,
    email: input.email,
    walletId: input.walletId,
    offerId: input.offerId,
    offerCandidates: input.offerCandidates,
    selectedCandidateId: input.selectedCandidateId,
    appSessionVersion: input.appSessionVersion,
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.walletIdDerivationNonce,
    collisionCounter: input.collisionCounter,
    state: 'started',
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.expiresAtMs,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
}

function keyFinalizedGoogleEmailOtpRegistrationAttemptRecord(
  input: GoogleEmailOtpRegistrationAttemptParseFields & { readonly finalizedPublicKey: string },
): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.attemptId,
    providerSubject: input.providerSubject,
    email: input.email,
    walletId: input.walletId,
    offerId: input.offerId,
    offerCandidates: input.offerCandidates,
    selectedCandidateId: input.selectedCandidateId,
    appSessionVersion: input.appSessionVersion,
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.walletIdDerivationNonce,
    collisionCounter: input.collisionCounter,
    state: 'key_finalized',
    finalizedPublicKey: input.finalizedPublicKey,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.expiresAtMs,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
}

function terminalGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly fields: GoogleEmailOtpRegistrationAttemptParseFields;
  readonly state: 'active' | 'abandoned' | 'failed' | 'expired';
  readonly finalizedPublicKey?: string;
  readonly failureCode?: string;
}): GoogleEmailOtpRegistrationAttemptRecord | null {
  const fields = input.fields;
  switch (input.state) {
    case 'active':
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'active',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
      };
    case 'abandoned':
      if (!input.failureCode) return null;
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'abandoned',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        failureCode: input.failureCode,
      };
    case 'failed':
      if (!input.failureCode) return null;
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'failed',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        failureCode: input.failureCode,
      };
    case 'expired':
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'expired',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        ...(input.failureCode ? { failureCode: input.failureCode } : {}),
      };
  }
}

function googleEmailOtpRegistrationAttemptFields(
  record: GoogleEmailOtpRegistrationAttemptRecord,
): GoogleEmailOtpRegistrationAttemptParseFields {
  return {
    attemptId: record.attemptId,
    providerSubject: record.providerSubject,
    email: record.email,
    walletId: record.walletId,
    offerId: record.offerId,
    offerCandidates: record.offerCandidates,
    selectedCandidateId: record.selectedCandidateId,
    appSessionVersion: record.appSessionVersion,
    authProvider: record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: record.walletIdDerivationNonce,
    collisionCounter: record.collisionCounter,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
    expiresAtMs: record.expiresAtMs,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
  };
}
