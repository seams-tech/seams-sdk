import { EMAIL_OTP_CHANNEL, WALLET_EMAIL_OTP_ACTIONS } from '@shared/utils/emailOtpDomain';
import {
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseOrgId,
  parseWalletId,
} from '@shared/utils/domainIds';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpChallengeAction,
  EmailOtpChallengeOperation,
  EmailOtpChallengeStore,
  EmailOtpWalletEnrollmentRecord,
  EmailOtpWalletEnrollmentStore,
} from '../EmailOtpStores';
import type { NormalizedLogger } from '../logger';
import {
  buildVerifiedEmailOtpRegistrationChallengeProof,
  emailOtpChallengeVerificationIntentFromRequest,
  emailOtpStoredChallengePurposeMatches,
  expectedEmailOtpStoredChallengePurpose,
  readEmailOtpStoredChallengePurpose,
  type EmailOtpChallengeBindingMismatchCode,
  type EmailOtpRegistrationChallengeProof,
  type VerifiedEmailOtpChallengeCodeResult,
  type VerifiedEmailOtpChallengeCodeSuccessBase,
} from './emailOtpChallengeProof';
import { pruneExpiredEmailOtpChallengesWithStore } from './emailOtpChallenges';
import type {
  EmailOtpAuthStatePatch,
  EmailOtpAuthStateReadResult,
  EmailOtpEnrollmentReadResult,
} from './emailOtpEnrollment';
import type { EmailOtpConfig } from './emailOtpConfig';
import type { EmailOtpMemoryOutbox } from './emailOtpDelivery';
import type { RateLimitResult } from './rateLimits';

export type VerifyEmailOtpChallengeCodeRequest = {
  challengeSubjectId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  challengeId?: unknown;
  otpCode?: unknown;
  otpChannel?: unknown;
  sessionHash?: unknown;
  appSessionVersion?: unknown;
  registrationChallengeProof?: EmailOtpRegistrationChallengeProof;
  allowRegistrationChallengeReroll?: boolean;
  clientIp?: unknown;
  expectedAction: EmailOtpChallengeAction;
  expectedOperation?: EmailOtpChallengeOperation;
};

export type EmailOtpVerificationRateLimitConsumer = (input: {
  scope: 'verify';
  action: EmailOtpChallengeAction;
  userId: string;
  walletId: string;
  orgId: string;
  clientIp?: string;
}) => Promise<RateLimitResult>;

export type VerifyEmailOtpChallengeCodeInput = {
  request: VerifyEmailOtpChallengeCodeRequest;
  challengeStore: EmailOtpChallengeStore;
  walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  memoryOutbox: EmailOtpMemoryOutbox;
  logger: NormalizedLogger;
  readActiveEnrollment: (input: {
    walletId: string;
    orgId: string;
  }) => Promise<EmailOtpEnrollmentReadResult>;
  readEnrollmentAuthState: (
    enrollment: EmailOtpWalletEnrollmentRecord,
  ) => Promise<EmailOtpAuthStateReadResult>;
  putEnrollmentAuthState: (
    enrollment: EmailOtpWalletEnrollmentRecord,
    patch: EmailOtpAuthStatePatch,
  ) => Promise<unknown>;
  consumeRateLimit: EmailOtpVerificationRateLimitConsumer;
  resolveConfig: () => EmailOtpConfig;
};

export async function verifyEmailOtpChallengeCode(
  input: VerifyEmailOtpChallengeCodeInput,
): Promise<VerifiedEmailOtpChallengeCodeResult> {
  const request = input.request;
  try {
      const challengeSubjectId = parseChallengeSubjectId(request.challengeSubjectId);
      const walletId = parseWalletId(request.walletId);
      const orgId = parseOrgId(request.orgId);
      const challengeId = parseEmailOtpChallengeId(request.challengeId);
      const otpCode = toOptionalTrimmedString(request.otpCode);
      const otpChannel = toOptionalTrimmedString(request.otpChannel);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      const expectedAction = request.expectedAction;
      const expectedOperation = request.expectedOperation;
      if (
        expectedAction === WALLET_EMAIL_OTP_ACTIONS.registration &&
        !request.registrationChallengeProof
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration verification requires registration challenge proof',
        };
      }
      const verificationIntent = emailOtpChallengeVerificationIntentFromRequest({
        expectedAction,
        ...(expectedOperation ? { expectedOperation } : {}),
        ...(request.registrationChallengeProof
          ? { registrationChallengeProof: request.registrationChallengeProof }
          : {}),
        ...(request.allowRegistrationChallengeReroll
          ? { allowRegistrationChallengeReroll: true }
          : {}),
      });
      const expectedPurpose = expectedEmailOtpStoredChallengePurpose(verificationIntent);
      if (!challengeSubjectId.ok) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeSubjectId' };
      }
      if (!walletId.ok) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId.ok) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId.ok)
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.challengeId !== challengeId.value
      ) {
        return {
          ok: false,
          code: 'challenge_id_mismatch',
          message: 'Email OTP registration proof does not match challengeId',
        };
      }
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.finalWalletId !== walletId.value
      ) {
        return {
          ok: false,
          code: 'challenge_wallet_mismatch',
          message: 'Email OTP registration proof does not match walletId',
        };
      }
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.orgId !== orgId.value
      ) {
        return {
          ok: false,
          code: 'challenge_org_mismatch',
          message: 'Email OTP registration proof does not match orgId',
        };
      }
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.appSessionVersion !== appSessionVersion
      ) {
        return {
          ok: false,
          code: 'challenge_session_mismatch',
          message: 'Email OTP registration proof does not match appSessionVersion',
        };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const rateLimit = await input.consumeRateLimit({
        scope: 'verify',
        action: expectedAction,
        userId: challengeSubjectId.value,
        walletId: walletId.value,
        orgId: orgId.value,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const activeEnrollment =
        expectedAction !== WALLET_EMAIL_OTP_ACTIONS.registration
          ? await input.readActiveEnrollment({
              walletId: walletId.value,
              orgId: orgId.value,
            })
          : null;
      if (activeEnrollment && !activeEnrollment.ok) return activeEnrollment;
      const enrollment = activeEnrollment?.ok
        ? activeEnrollment.enrollment
        : await input.walletEnrollmentStore.get(walletId.value);
      if (enrollment && enrollment.orgId !== orgId.value) {
        return {
          ok: false,
          code: 'tenant_scope_mismatch',
          message: 'Email OTP enrollment does not match the requested orgId',
        };
      }
      const authStateResult = enrollment
        ? await input.readEnrollmentAuthState(enrollment)
        : { ok: true as const, state: null };
      if (!authStateResult.ok) return authStateResult;
      const authState = authStateResult.state;
      const activeLockoutUntilMs =
        authState?.otpLockedUntilMs && authState.otpLockedUntilMs > Date.now()
          ? authState.otpLockedUntilMs
          : undefined;
      if (activeLockoutUntilMs) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: activeLockoutUntilMs,
        };
      }

      const challengeStore = input.challengeStore;
      const nowMs = Date.now();
      await pruneExpiredEmailOtpChallengesWithStore({
        challengeStore,
        memoryOutbox: input.memoryOutbox,
        nowMs,
      });
      let record = await challengeStore.get(challengeId.value);
      if (!record) {
        record = await challengeStore.findActiveByContext({
          challengeSubjectId: challengeSubjectId.value,
          walletId: walletId.value,
          orgId: orgId.value,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action: expectedAction,
          operation: expectedPurpose.operation,
          otpCode,
          nowMs,
        });
        if (!record) {
          input.logger.warn('[email-otp] challenge record not found during verification', {
            challengeId: challengeId.value,
            walletId: walletId.value,
            challengeSubjectId: challengeSubjectId.value,
            otpChannel: EMAIL_OTP_CHANNEL,
            action: expectedAction,
          });
          return {
            ok: false,
            code: 'challenge_expired_or_invalid',
            message: 'Email OTP challenge expired or invalid',
          };
        }
      }

      if (nowMs > record.expiresAtMs) {
        await challengeStore.del(record.challengeId);
        input.memoryOutbox.delete(record.challengeId);
        return {
          ok: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP challenge expired or invalid',
        };
      }

      const storedPurpose = readEmailOtpStoredChallengePurpose(record);
      const purposeMatches = emailOtpStoredChallengePurposeMatches({
        expected: expectedPurpose,
        actual: storedPurpose,
      });
      const verifiedRegistrationChallengeProof =
        verificationIntent.kind === 'registration'
          ? buildVerifiedEmailOtpRegistrationChallengeProof({
              record,
              challengeSubjectId: challengeSubjectId.value,
              proof: verificationIntent.binding,
              storedPurpose,
              allowWalletReroll: verificationIntent.allowWalletReroll,
            })
          : null;
      const registrationChallengeCanFollowReroll = verifiedRegistrationChallengeProof != null;
      const registrationChallengeEmailMatches =
        verificationIntent.kind === 'registration' &&
        toOptionalTrimmedString(record.email)?.toLowerCase() ===
          toOptionalTrimmedString(verificationIntent.binding.proofEmail)?.toLowerCase();
      const registrationRerollDisallowed =
        verificationIntent.kind === 'registration' &&
        storedPurpose?.kind === 'wallet_unlock' &&
        !verificationIntent.allowWalletReroll;
      // Registration name rerolls change only the final wallet id; the OTP
      // remains bound to the same provider subject, email, org, and app session.
      const subjectMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.challengeSubjectId !== challengeSubjectId.value;
      const walletMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.walletId !== walletId.value;
      const actionMismatch = registrationChallengeCanFollowReroll ? false : !purposeMatches;
      const operationMismatch = registrationChallengeCanFollowReroll ? false : !purposeMatches;
      const sessionHashMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.sessionHash !== sessionHash;
      const appSessionVersionMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.appSessionVersion !== appSessionVersion;
      const bindingMismatch =
        subjectMismatch ||
        walletMismatch ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        actionMismatch ||
        operationMismatch ||
        sessionHashMismatch ||
        appSessionVersionMismatch ||
        String(record.orgId || '') !== String(orgId.value || '');
      if (bindingMismatch) {
        const mismatchCode: EmailOtpChallengeBindingMismatchCode =
          record.otpChannel !== EMAIL_OTP_CHANNEL
            ? 'challenge_channel_mismatch'
            : subjectMismatch
              ? 'challenge_subject_mismatch'
              : verificationIntent.kind === 'registration' && !registrationChallengeEmailMatches
                ? 'challenge_email_mismatch'
                : String(record.orgId || '') !== String(orgId.value || '')
                  ? 'challenge_org_mismatch'
                  : registrationRerollDisallowed
                    ? 'registration_reroll_disallowed'
                    : actionMismatch || operationMismatch
                      ? 'challenge_purpose_mismatch'
                      : walletMismatch
                        ? 'challenge_wallet_mismatch'
                        : sessionHashMismatch || appSessionVersionMismatch
                          ? 'challenge_session_mismatch'
                          : 'challenge_org_mismatch';
        input.logger.warn('[email-otp] challenge binding mismatch during verification', {
          challengeId: record.challengeId,
          expectedChallengeId: challengeId.value,
          expectedAction,
          expectedOperation: expectedOperation || null,
          recordAction: record.action,
          recordOperation: record.operation,
          hasRegistrationChallengeProof: request.registrationChallengeProof != null,
          registrationChallengeCanFollowReroll,
          registrationRerollDisallowed,
          registrationChallengeEmailMatches,
          registrationChallengePurpose: verifiedRegistrationChallengeProof?.purpose.kind || null,
          subjectMatches: !subjectMismatch,
          walletMatches: !walletMismatch,
          otpChannelMatches: record.otpChannel === EMAIL_OTP_CHANNEL,
          actionMatches: !actionMismatch,
          operationMatches: !operationMismatch,
          sessionHashMatches: !sessionHashMismatch,
          appSessionVersionMatches: !appSessionVersionMismatch,
          orgMatches: String(record.orgId || '') === String(orgId.value || ''),
          recordWalletId: record.walletId,
          requestWalletId: walletId.value,
          mismatchCode,
          expectedPurpose,
          storedPurpose,
        });
        return {
          ok: false,
          code: mismatchCode,
          message: 'Email OTP challenge is not valid for the current app session',
        };
      }
      if (registrationChallengeCanFollowReroll) {
        input.logger.info('[email-otp] registration reroll challenge validation', {
          challengeId: record.challengeId,
          registrationAttemptId:
            verifiedRegistrationChallengeProof.kind === 'registration_attempt'
              ? verifiedRegistrationChallengeProof.registrationAttemptId
              : null,
          originalWalletId: verifiedRegistrationChallengeProof.originalWalletId,
          finalWalletId: verifiedRegistrationChallengeProof.finalWalletId,
          providerSubject: verifiedRegistrationChallengeProof.providerSubject,
          providerSubjectMatches:
            record.challengeSubjectId === verifiedRegistrationChallengeProof.challengeSubjectId,
          proofEmailMatches: registrationChallengeEmailMatches,
          appSessionVersionMatches:
            record.appSessionVersion === verifiedRegistrationChallengeProof.appSessionVersion,
          orgMatches:
            String(record.orgId || '') === String(verifiedRegistrationChallengeProof.orgId),
          purpose: verifiedRegistrationChallengeProof.purpose,
          expectedPurpose,
          storedPurpose,
        });
      }

      if (record.otpCode !== otpCode) {
        const matchingRecord = await challengeStore.findActiveByContext({
          challengeSubjectId: challengeSubjectId.value,
          walletId: walletId.value,
          orgId: orgId.value,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action: expectedAction,
          operation: expectedOperation || record.operation,
          otpCode,
          nowMs,
        });
        if (matchingRecord) {
          record = matchingRecord;
        }
      }

      if (record.otpCode !== otpCode) {
        const nextAttemptCount = record.attemptCount + 1;
        const otpConfig = input.resolveConfig();
        const nextLockedUntilMs =
          nextAttemptCount >= record.maxAttempts ? Date.now() + otpConfig.lockoutTtlMs : undefined;
        if (enrollment) {
          const nowMsForFailure = Date.now();
          const nextFailureCount = Number(authState?.otpFailureCount || 0) + 1;
          await input.putEnrollmentAuthState(enrollment, {
            otpFailureCount: nextFailureCount,
            lastOtpFailureAtMs: nowMsForFailure,
            ...(nextLockedUntilMs ? { otpLockedUntilMs: nextLockedUntilMs } : {}),
          });
        }
        if (nextAttemptCount >= record.maxAttempts) {
          await challengeStore.del(record.challengeId);
          input.memoryOutbox.delete(record.challengeId);
          return {
            ok: false,
            code: 'otp_attempts_exhausted',
            message: 'Email OTP challenge exceeded the maximum number of attempts',
            attemptsRemaining: 0,
            ...(nextLockedUntilMs ? { lockedUntilMs: nextLockedUntilMs } : {}),
          };
        }

        await challengeStore.put({
          ...record,
          attemptCount: nextAttemptCount,
        });
        return {
          ok: false,
          code: 'invalid_otp',
          message: 'OTP code is invalid',
          attemptsRemaining: record.maxAttempts - nextAttemptCount,
        };
      }

      await challengeStore.del(record.challengeId);
      input.memoryOutbox.delete(record.challengeId);

      if (enrollment) {
        const hadOtpFailureState =
          Number(authState?.otpFailureCount || 0) > 0 ||
          authState?.lastOtpFailureAtMs != null ||
          authState?.otpLockedUntilMs != null;
        if (hadOtpFailureState) {
          await input.putEnrollmentAuthState(enrollment, {
            otpFailureCount: 0,
            lastOtpFailureAtMs: undefined,
            otpLockedUntilMs: undefined,
          });
        }
      }

      const verifiedChallengeId = parseEmailOtpChallengeId(record.challengeId);
      if (!verifiedChallengeId.ok) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email OTP challenge record has an invalid challenge id',
        };
      }
      const successBase: VerifiedEmailOtpChallengeCodeSuccessBase = {
        challengeId: verifiedChallengeId.value,
        challengeSubjectId: challengeSubjectId.value,
        walletId: walletId.value,
        orgId: orgId.value,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
      if (record.email) successBase.email = record.email;
      if (verificationIntent.kind === 'registration') {
        const finalRegistrationChallengeProof = buildVerifiedEmailOtpRegistrationChallengeProof({
          record,
          challengeSubjectId: challengeSubjectId.value,
          proof: verificationIntent.binding,
          storedPurpose: readEmailOtpStoredChallengePurpose(record),
          allowWalletReroll: verificationIntent.allowWalletReroll,
        });
        if (!finalRegistrationChallengeProof) {
          return {
            ok: false,
            code: 'challenge_purpose_mismatch',
            message: 'Email OTP challenge is not valid for registration',
          };
        }
        return {
          ok: true,
          ...successBase,
          intent: 'registration',
          registrationChallengeProof: finalRegistrationChallengeProof,
        };
      }
      return {
        ok: true,
        ...successBase,
        intent: verificationIntent.kind,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to verify Email OTP challenge',
      };
    }

}
