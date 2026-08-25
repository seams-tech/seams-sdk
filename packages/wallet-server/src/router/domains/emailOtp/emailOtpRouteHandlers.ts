import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import type { RouterApiEmailOtpRouteService } from '../../framework/authServicePort';
import { emailOtpStatusCode } from './emailOtpSessionRouteHelpers';

export type EmailOtpRouteResponse = {
  status: number;
  body: Record<string, unknown>;
};

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

export async function sealEmailOtpFactorSecretForWorker(input: {
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

export async function handleEmailOtpDevCleanupGoogleRegistrationRoute(input: {
  body: unknown;
  service: RouterApiEmailOtpRouteService;
}): Promise<EmailOtpRouteResponse> {
  const body = isPlainObject(input.body) ? input.body : {};
  const verified = await input.service.verifyGoogleLogin({
    idToken: body.idToken ?? body.id_token,
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

  const runtimePolicyScope = isPlainObject(body.runtimePolicyScope)
    ? body.runtimePolicyScope
    : null;
  const result = await input.service.cleanupGoogleEmailOtpDevRegistrationState({
    providerSubject: verified.providerSubject || verified.userId,
    walletId: toOptionalTrimmedString(body.walletId),
    orgId:
      toOptionalTrimmedString(body.orgId) || toOptionalTrimmedString(runtimePolicyScope?.orgId),
  });
  return { status: result.ok ? 200 : emailOtpStatusCode(result.code), body: result };
}

export async function handleEmailOtpRegistrationSealRoute(input: {
  body: unknown;
  service: RouterApiEmailOtpRouteService;
}): Promise<EmailOtpRouteResponse> {
  if (!isPlainObject(input.body)) {
    return { status: 400, body: { ok: false, code: 'invalid_body', message: 'Invalid body' } };
  }
  const allowedFields = new Set(['walletId', 'wrappedCiphertext']);
  for (const field of Object.keys(input.body)) {
    if (!allowedFields.has(field)) {
      return {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: `Unsupported field: ${field}` },
      };
    }
  }
  const walletId = toOptionalTrimmedString(input.body.walletId);
  const wrappedCiphertext = toOptionalTrimmedString(input.body.wrappedCiphertext);
  if (!walletId || !wrappedCiphertext) {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_body',
        message: 'Missing walletId or wrappedCiphertext',
      },
    };
  }
  const result = await input.service.applyEmailOtpServerSeal({ wrappedCiphertext });
  return {
    status: result.ok ? 200 : emailOtpStatusCode(result.code),
    body: result.ok ? { ...result, walletId } : result,
  };
}

export async function handleEmailOtpDevOutboxRoute(input: {
  body: unknown;
  service: RouterApiEmailOtpRouteService;
}): Promise<EmailOtpRouteResponse> {
  if (!isPlainObject(input.body)) {
    return { status: 400, body: { ok: false, code: 'invalid_body', message: 'Invalid body' } };
  }
  const allowedFields = new Set(['idToken', 'walletId', 'challengeId', 'challengeSubjectId']);
  for (const field of Object.keys(input.body)) {
    if (!allowedFields.has(field)) {
      return {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: `Unsupported field: ${field}` },
      };
    }
  }
  const idToken = toOptionalTrimmedString(input.body.idToken);
  const walletId = toOptionalTrimmedString(input.body.walletId);
  const challengeId = toOptionalTrimmedString(input.body.challengeId);
  /* An intended-test affordance, and nothing more. A challenge's subject is not
     always a Google identity — an Email OTP method added by address alone is
     enrolled under that address — so a reader restricted to the token's own
     subject could never see its code.

     Three things keep it from becoming permission to read arbitrary OTPs. The
     store refuses entirely unless the dev outbox is enabled, which requires the
     dev delivery mode and a non-production runtime. The lookup admits only a
     live challenge whose wallet is the one named here and whose subject is the
     one asked for. And an override must name the exact challenge, below: a
     caller can only have that id from the wallet's own flow, so the token says
     which harness is asking rather than whose code it may read. */
  const challengeSubjectId = toOptionalTrimmedString(input.body.challengeSubjectId);
  if (!idToken || !walletId) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Missing idToken or walletId' },
    };
  }
  if (challengeSubjectId && !challengeId) {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_body',
        message: 'challengeSubjectId requires the exact challengeId it belongs to',
      },
    };
  }
  const verified = await input.service.verifyGoogleLogin({ idToken });
  if (!verified.ok || !verified.verified || !verified.userId) {
    const code = verified.code || 'not_verified';
    return {
      status: code === 'internal' ? 500 : code === 'not_configured' ? 501 : 401,
      body: { ok: false, code, message: verified.message || 'Google login failed' },
    };
  }
  const result = await input.service.readEmailOtpOutboxEntry({
    userId: challengeSubjectId || verified.providerSubject || verified.userId,
    walletId,
    ...(challengeId ? { challengeId } : {}),
  });
  return { status: result.ok ? 200 : emailOtpStatusCode(result.code), body: result };
}
