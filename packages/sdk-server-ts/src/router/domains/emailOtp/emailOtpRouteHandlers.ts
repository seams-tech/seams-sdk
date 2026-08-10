import { toOptionalRecordString } from '@shared/utils/validation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { parseOrgId, parseProviderSubject, parseWalletId } from '@shared/utils/domainIds';
import { EMAIL_OTP_CHANNEL, WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpProviderIdentitySubject,
  EmailOtpStrongAuthSubject,
  RouterApiEmailOtpRouteService,
} from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import {
  authorizeEmailOtpExportPolicy,
  emailOtpExportDeniedDecisionFromResult,
  emailOtpExportPolicyWebhookEventDescriptor,
} from './emailOtpExportPolicy';
import { parseWalletEmailOtpLoginOperation } from './emailOtpRequestValidation';
import {
  emailOtpChallengeResponseBody,
  emailOtpEnrollmentFinalizeResponseBody,
  emailOtpEnrolledWebhookEventDescriptor,
  emailOtpFailureWebhookEventDescriptors,
  emailOtpLoginVerifyResponseBody,
  emailOtpResultStatus,
  emailOtpServerSealResponseBody,
  emailOtpStatusCode,
  getSessionWalletId,
  hashEmailOtpAppSessionClaims,
  isGoogleOidcEmailOtpSession,
  validateEmailOtpChannel,
  validateEmailOtpJsonObjectBody,
  validateEmailOtpRequiredString,
  validateEmailOtpWalletId,
  type EmailOtpWebhookEventDescriptor,
} from './emailOtpSessionRouteHelpers';

export type EmailOtpRouteResponse = {
  status: number;
  body: Record<string, unknown>;
};

export type EmitEmailOtpRouteWebhook = (input: {
  descriptor: EmailOtpWebhookEventDescriptor;
  claims?: Record<string, unknown> | null;
  userId: string;
  walletId?: string;
}) => Promise<void>;

const EMAIL_OTP_FACTOR_RELEASE_AAD_DOMAIN = 'seams/email-otp/factor-release/v1';

function emailOtpFactorReleaseAad(input: {
  readonly walletId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly challengeId: string;
}): Uint8Array {
  return new TextEncoder().encode(
    [
      EMAIL_OTP_FACTOR_RELEASE_AAD_DOMAIN,
      input.walletId,
      input.enrollmentId,
      input.enrollmentSealKeyVersion,
      input.challengeId,
    ].join('\0'),
  );
}

async function sealEmailOtpFactorSecretForWorker(input: {
  readonly factorSecret32B64u: string;
  readonly workerEphemeralPublicKey65B64u: string;
  readonly walletId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly challengeId: string;
}): Promise<
  | {
      readonly ok: true;
      readonly serverEphemeralPublicKey65B64u: string;
      readonly nonce12B64u: string;
      readonly ciphertextB64u: string;
    }
  | { readonly ok: false; readonly code: string; readonly message: string }
> {
  let factorSecret32: Uint8Array;
  let workerPublicKey65: Uint8Array;
  try {
    factorSecret32 = base64UrlDecode(input.factorSecret32B64u);
    workerPublicKey65 = base64UrlDecode(input.workerEphemeralPublicKey65B64u);
  } catch {
    return { ok: false, code: 'invalid_body', message: 'Email OTP factor release key is invalid' };
  }
  if (
    factorSecret32.length !== 32 ||
    workerPublicKey65.length !== 65 ||
    workerPublicKey65[0] !== 4
  ) {
    factorSecret32.fill(0);
    return { ok: false, code: 'invalid_body', message: 'Email OTP factor release key is invalid' };
  }
  try {
    const workerPublicKey = await crypto.subtle.importKey(
      'raw',
      workerPublicKey65,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const serverKeyPair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey'],
    )) as CryptoKeyPair;
    const encryptionKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: workerPublicKey },
      serverKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    const nonce12 = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce12,
          additionalData: emailOtpFactorReleaseAad(input),
          tagLength: 128,
        },
        encryptionKey,
        factorSecret32,
      ),
    );
    const serverPublicKey65 = new Uint8Array(
      await crypto.subtle.exportKey('raw', serverKeyPair.publicKey),
    );
    return {
      ok: true,
      serverEphemeralPublicKey65B64u: base64UrlEncode(serverPublicKey65),
      nonce12B64u: base64UrlEncode(nonce12),
      ciphertextB64u: base64UrlEncode(ciphertext),
    };
  } catch {
    return {
      ok: false,
      code: 'factor_release_failed',
      message: 'Email OTP factor release encryption failed',
    };
  } finally {
    factorSecret32.fill(0);
  }
}

function providerEmailOtpGrantSubject(input: {
  readonly orgId: string;
  readonly providerUserId: string;
  readonly walletId: string;
}): EmailOtpProviderIdentitySubject | null {
  const orgId = parseOrgId(input.orgId);
  const providerSubject = parseProviderSubject(input.providerUserId);
  const walletId = parseWalletId(input.walletId);
  if (!orgId.ok || !providerSubject.ok || !walletId.ok) return null;
  return {
    kind: 'provider_identity',
    orgId: orgId.value,
    providerSubject: providerSubject.value,
    walletId: walletId.value,
  };
}

function emailOtpStrongAuthSubject(walletId: string): EmailOtpStrongAuthSubject | null {
  const parsed = parseWalletId(walletId);
  if (!parsed.ok) return null;
  return { kind: 'email_otp_strong_auth', walletId: parsed.value };
}

async function requireEmailOtpEnrollmentMutationAuth(input: {
  service: RouterApiEmailOtpRouteService;
  claims: Record<string, unknown>;
  walletId: string;
}): Promise<EmailOtpRouteResponse | null> {
  if (isGoogleOidcEmailOtpSession(input.claims)) return null;

  const subject = emailOtpStrongAuthSubject(input.walletId);
  if (!subject) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Invalid walletId' },
    };
  }

  const strongAuthGate = await input.service.isEmailOtpStrongAuthRequired({
    subject,
  });
  if (!strongAuthGate.ok) {
    return { status: emailOtpStatusCode(strongAuthGate.code), body: strongAuthGate };
  }
  if (!strongAuthGate.required) return null;

  return {
    status: 403,
    body: {
      ok: false,
      code: 'stronger_auth_required',
      message: 'Passkey authentication is required before modifying Email OTP enrollment',
      ...(strongAuthGate.lastEmailOtpLoginAtMs
        ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
        : {}),
      ...(strongAuthGate.lastStrongAuthAtMs
        ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
        : {}),
    },
  };
}

function resolveEmailOtpProviderUserId(input: {
  claims: Record<string, unknown>;
  userId: string;
}): { ok: true; providerUserId: string } | { ok: false; response: EmailOtpRouteResponse } {
  if (!isGoogleOidcEmailOtpSession(input.claims)) {
    return { ok: true, providerUserId: input.userId };
  }
  const providerSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (!providerSubject) {
    return {
      ok: false,
      response: {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_app_session',
          message: 'Google Email OTP session requires providerSubject',
        },
      },
    };
  }
  return { ok: true, providerUserId: providerSubject };
}

function googleEmailOtpRegistrationCandidateScope(input: {
  claims: Record<string, unknown>;
  walletId: string;
}): {
  registrationAttemptId: string;
  walletId: string;
  appSessionVersion: string;
  providerSubject: string;
} | null {
  if (!isGoogleOidcEmailOtpSession(input.claims)) return null;
  const mode = toOptionalRecordString(input.claims, 'googleEmailOtpResolutionMode');
  const registrationAttemptId = toOptionalRecordString(
    input.claims,
    'googleEmailOtpRegistrationAttemptId',
  );
  const appSessionVersion = toOptionalRecordString(input.claims, 'appSessionVersion');
  const providerSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (
    mode !== 'register_started' ||
    !registrationAttemptId ||
    !appSessionVersion ||
    !providerSubject
  ) {
    return null;
  }
  return {
    registrationAttemptId,
    walletId: input.walletId,
    appSessionVersion,
    providerSubject,
  };
}

async function validateEmailOtpRegistrationWalletId(input: {
  body: Record<string, unknown>;
  claims: Record<string, unknown>;
  userId: string;
  service: RouterApiEmailOtpRouteService;
}): Promise<{ ok: true; walletId: string } | { ok: false; response: EmailOtpRouteResponse }> {
  const walletValidation = validateEmailOtpWalletId({
    body: input.body,
    claims: input.claims,
    userId: input.userId,
  });
  if (walletValidation.ok) return walletValidation;

  const walletId = String(input.body.walletId || '').trim();
  if (!walletId) {
    return {
      ok: false,
      response: { status: walletValidation.status, body: walletValidation.body },
    };
  }
  const candidateScope = googleEmailOtpRegistrationCandidateScope({
    claims: input.claims,
    walletId,
  });
  if (!candidateScope) {
    return {
      ok: false,
      response: { status: walletValidation.status, body: walletValidation.body },
    };
  }

  const result =
    await input.service.validateGoogleEmailOtpRegistrationCandidateWallet(candidateScope);
  if (result.ok) return { ok: true, walletId };
  return {
    ok: false,
    response: {
      status: result.code === 'wallet_identity_mismatch' ? 403 : emailOtpStatusCode(result.code),
      body: result,
    },
  };
}

export async function handleEmailOtpRegistrationChallengeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  requestOrigin: string | null;
  service: RouterApiEmailOtpRouteService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = await validateEmailOtpRegistrationWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
    service: input.service,
  });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const authGate = await requireEmailOtpEnrollmentMutationAuth({
    service: input.service,
    claims: input.claims,
    walletId,
  });
  if (authGate) return authGate;

  const email =
    typeof input.claims.email === 'string' ? input.claims.email.trim().toLowerCase() : '';
  const googleRegistrationSession = isGoogleOidcEmailOtpSession(input.claims);
  const claimProviderSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (googleRegistrationSession && !claimProviderSubject) {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_app_session',
        message: 'Google Email OTP registration requires providerSubject',
      },
    };
  }
  const challengeSubjectId = googleRegistrationSession ? claimProviderSubject : input.userId;
  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const result = await input.service.createEmailOtpEnrollmentChallenge({
    userId: challengeSubjectId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    email,
    otpChannel,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    requestOrigin: input.requestOrigin,
  });
  return {
    status: emailOtpResultStatus(result),
    body: emailOtpChallengeResponseBody(result),
  };
}

export async function handleEmailOtpRegistrationSealRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  service: RouterApiEmailOtpRouteService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = await validateEmailOtpRegistrationWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
    service: input.service,
  });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const wrappedCiphertextValidation = validateEmailOtpRequiredString(body, 'wrappedCiphertext');
  if (!wrappedCiphertextValidation.ok) {
    return {
      status: wrappedCiphertextValidation.status,
      body: wrappedCiphertextValidation.body,
    };
  }

  const authGate = await requireEmailOtpEnrollmentMutationAuth({
    service: input.service,
    claims: input.claims,
    walletId,
  });
  if (authGate) return authGate;

  const result = await input.service.applyEmailOtpServerSeal({
    wrappedCiphertext: wrappedCiphertextValidation.value,
  });
  return {
    status: emailOtpResultStatus(result),
    body: emailOtpServerSealResponseBody(result, walletId),
  };
}

export async function handleEmailOtpRegistrationFinalizeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: RouterApiEmailOtpRouteService;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = await validateEmailOtpRegistrationWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
    service: input.service,
  });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const challengeIdValidation = validateEmailOtpRequiredString(body, 'challengeId');
  if (!challengeIdValidation.ok) {
    return { status: challengeIdValidation.status, body: challengeIdValidation.body };
  }
  const challengeId = challengeIdValidation.value;

  const otpCodeValidation = validateEmailOtpRequiredString(body, 'otpCode');
  if (!otpCodeValidation.ok) {
    return { status: otpCodeValidation.status, body: otpCodeValidation.body };
  }
  const otpCode = otpCodeValidation.value;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const authGate = await requireEmailOtpEnrollmentMutationAuth({
    service: input.service,
    claims: input.claims,
    walletId,
  });
  if (authGate) return authGate;

  const googleRegistrationSession = isGoogleOidcEmailOtpSession(input.claims);
  const claimProviderSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (googleRegistrationSession && !claimProviderSubject) {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_app_session',
        message: 'Google Email OTP registration requires providerSubject',
      },
    };
  }
  const providerSubject = googleRegistrationSession ? claimProviderSubject : input.userId;
  const proofEmail = toOptionalRecordString(input.claims, 'email')?.toLowerCase();
  const bodyGoogleEmailOtpRegistrationAttemptId = toOptionalRecordString(
    body,
    'googleEmailOtpRegistrationAttemptId',
  );
  const claimGoogleEmailOtpRegistrationAttemptId = googleRegistrationSession
    ? toOptionalRecordString(input.claims, 'googleEmailOtpRegistrationAttemptId')
    : undefined;
  const googleEmailOtpRegistrationAttemptId =
    bodyGoogleEmailOtpRegistrationAttemptId || claimGoogleEmailOtpRegistrationAttemptId;
  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const result = await input.service.verifyEmailOtpEnrollment({
    providerSubject,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    challengeId,
    otpCode,
    otpChannel,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    ...(proofEmail ? { proofEmail } : {}),
    clientIp: input.clientIp,
    enrollmentSealKeyVersion: body.enrollmentSealKeyVersion,
    serverSealedFactorCiphertextB64u: body.serverSealedFactorCiphertextB64u,
    clientUnlockPublicKeyB64u: body.clientUnlockPublicKeyB64u,
    unlockKeyVersion: body.unlockKeyVersion,
    ...(googleEmailOtpRegistrationAttemptId ? { googleEmailOtpRegistrationAttemptId } : {}),
  });

  if (result.ok) {
    await input.emitWebhook({
      descriptor: emailOtpEnrolledWebhookEventDescriptor({
        challengeId,
        otpChannel: result.otpChannel,
        enrollmentSealKeyVersion: result.enrollment.enrollmentSealKeyVersion,
        unlockKeyVersion: result.enrollment.unlockKeyVersion,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId: result.walletId,
    });
  } else {
    for (const descriptor of emailOtpFailureWebhookEventDescriptors({
      source: 'registration_finalize',
      code: result.code,
      message: result.message,
      challengeId,
      otpChannel,
      lockedUntilMs:
        typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
          ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
          : undefined,
    })) {
      await input.emitWebhook({
        descriptor,
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
  }

  return {
    status: emailOtpResultStatus(result),
    body: emailOtpEnrollmentFinalizeResponseBody(result),
  };
}

export async function handleEmailOtpLoginChallengeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  requestOrigin: string | null;
  service: RouterApiEmailOtpRouteService;
  opts: RouterApiOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'challenge',
          userId: input.userId,
          walletId,
          orgId: readEmailOtpOrgIdFromClaims(input.claims),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'login_challenge',
        decision: exportPolicy,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: {
        ok: false,
        code: exportPolicy.code,
        message: exportPolicy.message,
      },
    };
  }

  const email = await readServerKnownEmailOtpAddress({
    service: input.service,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    providerUserId: providerUser.providerUserId,
  });
  if (!email.ok) return { status: email.status, body: email.body };

  const result = await input.service.createEmailOtpChallenge({
    userId: providerUser.providerUserId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    email: email.email,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    requestOrigin: input.requestOrigin,
    operation: parsedOperation.operation,
  });

  if (!result.ok && result.code === 'otp_locked_out') {
    for (const descriptor of emailOtpFailureWebhookEventDescriptors({
      source: 'login_challenge',
      code: result.code,
      message: result.message,
      otpChannel,
      operation: parsedOperation.operation,
      lockedUntilMs:
        typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
          ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
          : undefined,
    })) {
      await input.emitWebhook({
        descriptor,
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
  }

  if (result.ok && exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_challenge_issued',
        source: 'login_challenge',
        decision: exportPolicy,
        challengeId: result.challenge.challengeId,
        otpChannel,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return {
    status: emailOtpResultStatus(result),
    body: emailOtpChallengeResponseBody(result),
  };
}

function validateSigningSessionWalletId(input: {
  body: Record<string, unknown>;
  claims: Record<string, unknown>;
  userId: string;
}): { ok: true; walletId: string } | { ok: false; response: EmailOtpRouteResponse } {
  const walletId = String(input.body.walletId || '').trim();
  if (!walletId) {
    return {
      ok: false,
      response: {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: 'walletId is required' },
      },
    };
  }
  if (walletId !== getSessionWalletId(input.claims, input.userId)) {
    return {
      ok: false,
      response: {
        status: 403,
        body: {
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the restored signing-session wallet',
        },
      },
    };
  }
  return { ok: true, walletId };
}

function readEmailOtpOrgIdFromClaims(claims: Record<string, unknown>): string {
  const directOrgId = toOptionalRecordString(claims, 'orgId');
  if (directOrgId) return directOrgId;
  const runtimePolicyScope =
    claims.runtimePolicyScope && typeof claims.runtimePolicyScope === 'object'
      ? (claims.runtimePolicyScope as Record<string, unknown>)
      : null;
  return runtimePolicyScope ? toOptionalRecordString(runtimePolicyScope, 'orgId') || '' : '';
}

async function readServerKnownEmailOtpAddress(input: {
  service: RouterApiEmailOtpRouteService;
  walletId: string;
  orgId?: string;
  providerUserId?: string;
}): Promise<
  | { ok: true; email: string; orgId: string; providerUserId: string }
  | { ok: false; status: number; body: Record<string, unknown> }
> {
  const orgId = String(input.orgId || '').trim();
  if (!orgId) {
    return {
      ok: false,
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Missing orgId' },
    };
  }
  const enrollment = await input.service.readActiveEmailOtpEnrollment({
    walletId: input.walletId,
    orgId,
    providerUserId: input.providerUserId,
  });
  if (!enrollment.ok) {
    return { ok: false, status: emailOtpStatusCode(enrollment.code), body: enrollment };
  }
  if (enrollment.enrollment.walletId !== input.walletId || enrollment.enrollment.orgId !== orgId) {
    return {
      ok: false,
      status: 403,
      body: {
        ok: false,
        code: 'forbidden',
        message: 'Email OTP enrollment does not match the requested wallet',
      },
    };
  }

  return {
    ok: true,
    email: enrollment.enrollment.verifiedEmail,
    orgId: enrollment.enrollment.orgId,
    providerUserId: enrollment.enrollment.providerUserId,
  };
}

export async function handleEmailOtpSigningSessionChallengeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  sessionHash: string;
  clientIp?: string;
  requestOrigin: string | null;
  service: RouterApiEmailOtpRouteService;
  opts: RouterApiOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateSigningSessionWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };

  const email = await readServerKnownEmailOtpAddress({
    service: input.service,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
  });
  if (!email.ok) return { status: email.status, body: email.body };

  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'challenge',
          userId: input.userId,
          walletId,
          ...(email.orgId ? { orgId: email.orgId } : {}),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'signing_session_challenge',
        decision: exportPolicy,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: { ok: false, code: exportPolicy.code, message: exportPolicy.message },
    };
  }

  const result = await input.service.createEmailOtpChallenge({
    userId: email.providerUserId,
    walletId,
    ...(email.orgId ? { orgId: email.orgId } : {}),
    email: email.email,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    requestOrigin: input.requestOrigin,
    operation: parsedOperation.operation,
  });

  if (!result.ok && result.code === 'otp_locked_out') {
    for (const descriptor of emailOtpFailureWebhookEventDescriptors({
      source: 'signing_session_challenge',
      code: result.code,
      message: result.message,
      otpChannel,
      operation: parsedOperation.operation,
      lockedUntilMs:
        typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
          ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
          : undefined,
    })) {
      await input.emitWebhook({
        descriptor,
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
  }

  if (result.ok && exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_challenge_issued',
        source: 'signing_session_challenge',
        decision: exportPolicy,
        challengeId: result.challenge.challengeId,
        otpChannel,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return {
    status: emailOtpResultStatus(result),
    body: emailOtpChallengeResponseBody(result),
  };
}

export async function handleEmailOtpLoginVerifyRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: RouterApiEmailOtpRouteService;
  opts: RouterApiOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const challengeIdValidation = validateEmailOtpRequiredString(body, 'challengeId');
  if (!challengeIdValidation.ok) {
    return { status: challengeIdValidation.status, body: challengeIdValidation.body };
  }
  const challengeId = challengeIdValidation.value;

  const otpCodeValidation = validateEmailOtpRequiredString(body, 'otpCode');
  if (!otpCodeValidation.ok) {
    return { status: otpCodeValidation.status, body: otpCodeValidation.body };
  }
  const otpCode = otpCodeValidation.value;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'verify',
          userId: input.userId,
          walletId,
          orgId: readEmailOtpOrgIdFromClaims(input.claims),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          challengeId,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'login_verify',
        decision: exportPolicy,
        challengeId,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: {
        ok: false,
        code: exportPolicy.code,
        message: exportPolicy.message,
      },
    };
  }

  const result = await input.service.verifyEmailOtpChallenge({
    userId: providerUser.providerUserId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    challengeId,
    otpCode,
    otpChannel,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    operation: parsedOperation.operation,
  });

  if (result.ok) {
    if (exportPolicy) {
      await input.emitWebhook({
        descriptor: emailOtpExportPolicyWebhookEventDescriptor({
          eventType: 'wallet.email_otp.export_approved',
          source: 'login_verify',
          decision: exportPolicy,
          challengeId: result.challengeId,
          otpChannel,
        }),
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
    const enrollment = await input.service.readEmailOtpEnrollment({
      walletId,
      orgId: readEmailOtpOrgIdFromClaims(input.claims),
    });
    if (!enrollment.ok) {
      return { status: emailOtpStatusCode(enrollment.code), body: enrollment };
    }
    return {
      status: 200,
      body: emailOtpLoginVerifyResponseBody({ result, enrollment }),
    };
  }

  for (const descriptor of emailOtpFailureWebhookEventDescriptors({
    source: 'login_verify',
    code: result.code,
    message: result.message,
    challengeId,
    otpChannel,
    operation: parsedOperation.operation,
    lockedUntilMs:
      typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
        ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
        : undefined,
  })) {
    await input.emitWebhook({
      descriptor,
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  if (exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'login_verify',
        decision: emailOtpExportDeniedDecisionFromResult({
          code: result.code,
          message: result.message,
          policySource: exportPolicy.policySource,
          ...(exportPolicy.policyId ? { policyId: exportPolicy.policyId } : {}),
          ...(exportPolicy.approvalId ? { approvalId: exportPolicy.approvalId } : {}),
        }),
        challengeId,
        otpChannel,
        code: result.code,
        message: result.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return { status: emailOtpStatusCode(result.code), body: result };
}

export async function handleEmailOtpSigningSessionVerifyRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  sessionHash: string;
  clientIp?: string;
  service: RouterApiEmailOtpRouteService;
  opts: RouterApiOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateSigningSessionWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const challengeIdValidation = validateEmailOtpRequiredString(body, 'challengeId');
  if (!challengeIdValidation.ok) {
    return { status: challengeIdValidation.status, body: challengeIdValidation.body };
  }
  const challengeId = challengeIdValidation.value;

  const otpCodeValidation = validateEmailOtpRequiredString(body, 'otpCode');
  if (!otpCodeValidation.ok) {
    return { status: otpCodeValidation.status, body: otpCodeValidation.body };
  }
  const otpCode = otpCodeValidation.value;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };

  const email = await readServerKnownEmailOtpAddress({
    service: input.service,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
  });
  if (!email.ok) return { status: email.status, body: email.body };

  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'verify',
          userId: input.userId,
          walletId,
          ...(email.orgId ? { orgId: email.orgId } : {}),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          challengeId,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'signing_session_verify',
        decision: exportPolicy,
        challengeId,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: { ok: false, code: exportPolicy.code, message: exportPolicy.message },
    };
  }

  const result = await input.service.verifyEmailOtpChallenge({
    userId: email.providerUserId,
    walletId,
    ...(email.orgId ? { orgId: email.orgId } : {}),
    challengeId,
    otpCode,
    otpChannel,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    operation: parsedOperation.operation,
  });

  if (result.ok) {
    if (exportPolicy) {
      await input.emitWebhook({
        descriptor: emailOtpExportPolicyWebhookEventDescriptor({
          eventType: 'wallet.email_otp.export_approved',
          source: 'signing_session_verify',
          decision: exportPolicy,
          challengeId: result.challengeId,
          otpChannel,
        }),
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
    const enrollment = await input.service.readEmailOtpEnrollment({
      walletId,
      orgId: readEmailOtpOrgIdFromClaims(input.claims),
    });
    if (!enrollment.ok) {
      return { status: emailOtpStatusCode(enrollment.code), body: enrollment };
    }
    return {
      status: 200,
      body: emailOtpLoginVerifyResponseBody({ result, enrollment }),
    };
  }

  for (const descriptor of emailOtpFailureWebhookEventDescriptors({
    source: 'signing_session_verify',
    code: result.code,
    message: result.message,
    otpChannel,
    operation: parsedOperation.operation,
    lockedUntilMs:
      typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
        ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
        : undefined,
  })) {
    await input.emitWebhook({
      descriptor,
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  if (exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'signing_session_verify',
        decision: emailOtpExportDeniedDecisionFromResult({
          code: result.code,
          message: result.message,
          policySource: exportPolicy.policySource,
          ...(exportPolicy.policyId ? { policyId: exportPolicy.policyId } : {}),
          ...(exportPolicy.approvalId ? { approvalId: exportPolicy.approvalId } : {}),
        }),
        challengeId,
        otpChannel,
        code: result.code,
        message: result.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return { status: emailOtpStatusCode(result.code), body: result };
}

export async function handleEmailOtpFactorReleaseRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: RouterApiEmailOtpRouteService;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletIdValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletIdValidation.ok) {
    return { status: walletIdValidation.status, body: walletIdValidation.body };
  }
  const loginGrantValidation = validateEmailOtpRequiredString(body, 'loginGrant');
  if (!loginGrantValidation.ok) {
    return { status: loginGrantValidation.status, body: loginGrantValidation.body };
  }
  const loginGrant = loginGrantValidation.value;

  const workerPublicKeyValidation = validateEmailOtpRequiredString(
    body,
    'workerEphemeralPublicKey65B64u',
  );
  if (!workerPublicKeyValidation.ok) {
    return {
      status: workerPublicKeyValidation.status,
      body: workerPublicKeyValidation.body,
    };
  }
  try {
    const workerPublicKey65 = base64UrlDecode(workerPublicKeyValidation.value);
    if (workerPublicKey65.length !== 65 || workerPublicKey65[0] !== 4) {
      throw new Error('invalid worker public key');
    }
  } catch {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_body',
        message: 'workerEphemeralPublicKey65B64u is invalid',
      },
    };
  }

  const sessionWalletId = walletIdValidation.walletId;
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;
  const subject = providerEmailOtpGrantSubject({
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    providerUserId: providerUser.providerUserId,
    walletId: sessionWalletId,
  });
  if (!subject) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Invalid OTP subject' },
    };
  }
  const grant = await input.service.consumeEmailOtpGrant({
    subject,
    loginGrant,
    otpChannel: EMAIL_OTP_CHANNEL,
    clientIp: input.clientIp,
  });
  if (!grant.ok) return { status: emailOtpStatusCode(grant.code), body: grant };

  const enrollment = await input.service.readActiveEmailOtpEnrollment({
    walletId: sessionWalletId,
    orgId: subject.orgId,
    providerUserId: subject.providerSubject,
  });
  if (!enrollment.ok) {
    return { status: emailOtpStatusCode(enrollment.code), body: enrollment };
  }
  const result = await input.service.removeEmailOtpServerSeal({
    wrappedCiphertext: enrollment.enrollment.serverSealedFactorCiphertextB64u,
  });
  if (!result.ok) return { status: emailOtpStatusCode(result.code), body: result };
  if (result.enrollmentSealKeyVersion !== enrollment.enrollment.enrollmentSealKeyVersion) {
    return {
      status: 409,
      body: {
        ok: false,
        code: 'scope_mismatch',
        message: 'Email OTP factor release seal key version changed',
      },
    };
  }
  const sealed = await sealEmailOtpFactorSecretForWorker({
    factorSecret32B64u: result.ciphertext,
    workerEphemeralPublicKey65B64u: workerPublicKeyValidation.value,
    walletId: sessionWalletId,
    enrollmentId: enrollment.enrollment.enrollmentId,
    enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
    challengeId: grant.challengeId,
  });
  if (!sealed.ok) return { status: emailOtpStatusCode(sealed.code), body: sealed };

  return {
    status: 200,
    body: {
      ok: true,
      kind: 'email_otp_factor_release_v1',
      challengeId: grant.challengeId,
      enrollmentId: enrollment.enrollment.enrollmentId,
      enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
      serverEphemeralPublicKey65B64u: sealed.serverEphemeralPublicKey65B64u,
      nonce12B64u: sealed.nonce12B64u,
      ciphertextB64u: sealed.ciphertextB64u,
    },
  };
}

export async function handleEmailOtpDevCleanupGoogleRegistrationRoute(input: {
  body: unknown;
  service: RouterApiEmailOtpRouteService;
}): Promise<EmailOtpRouteResponse> {
  const body = input.body && typeof input.body === 'object' ? input.body : {};
  const verified = await input.service.verifyGoogleLogin({
    idToken:
      (body as Record<string, unknown>).idToken ?? (body as Record<string, unknown>).id_token,
  });
  if (!verified.ok || !verified.verified || !verified.userId) {
    const code = verified.code || 'not_verified';
    const status =
      code === 'internal'
        ? 500
        : code === 'not_configured' || code === 'unsupported'
          ? 501
          : code === 'invalid_body'
            ? 400
            : 401;
    return {
      status,
      body: { ok: false, code, message: verified.message || 'Google login failed' },
    };
  }

  const result = await input.service.cleanupGoogleEmailOtpDevRegistrationState({
    providerSubject: verified.providerSubject || verified.userId,
    walletId: (body as Record<string, unknown>).walletId,
    orgId:
      (body as Record<string, unknown>).orgId ??
      ((body as Record<string, unknown>).runtimePolicyScope &&
      typeof (body as Record<string, unknown>).runtimePolicyScope === 'object'
        ? ((body as Record<string, unknown>).runtimePolicyScope as Record<string, unknown>).orgId
        : undefined),
  });
  return { status: result.ok ? 200 : emailOtpStatusCode(result.code), body: result };
}

export async function handleEmailOtpDevOtpOutboxRoute(input: {
  challengeId: string;
  walletId?: string;
  claims: Record<string, unknown>;
  userId: string;
  service: RouterApiEmailOtpRouteService;
}): Promise<EmailOtpRouteResponse> {
  const challengeId = String(input.challengeId || '').trim();
  const sessionWalletId = getSessionWalletId(input.claims, input.userId);
  const walletId = String(input.walletId || sessionWalletId).trim();
  if (walletId !== sessionWalletId) {
    return {
      status: 403,
      body: {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
    };
  }

  let result = await input.service.readEmailOtpOutboxEntry({
    challengeId,
    userId: input.userId,
    walletId,
  });
  const providerSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (
    !result.ok &&
    result.code === 'not_found' &&
    isGoogleOidcEmailOtpSession(input.claims) &&
    providerSubject
  ) {
    result = await input.service.readEmailOtpOutboxEntry({
      challengeId,
      userId: providerSubject,
      walletId,
    });
  }
  if (!result.ok && result.code === 'not_found' && walletId !== input.userId) {
    // Dev-only outbox reads are wallet-scoped after the app-session wallet check above.
    // Signing-session OTP challenges are stored under the wallet id, while Google SSO
    // app sessions use the provider subject as userId.
    result = await input.service.readEmailOtpOutboxEntry({
      challengeId,
      userId: walletId,
      walletId,
    });
  }
  return {
    status: result.ok
      ? 200
      : result.code === 'internal'
        ? 500
        : result.code === 'not_found'
          ? 404
          : 400,
    body: result.ok
      ? {
          ok: true,
          challengeId: result.challengeId,
          walletId: result.walletId,
          userId: result.userId,
          otpChannel: result.otpChannel,
          emailHint: result.emailHint,
          otpCode: result.otpCode,
          expiresAt: new Date(result.expiresAtMs).toISOString(),
        }
      : result,
  };
}
