import { createSigningSessionSealShamir3PassCipherAdapter } from '../../threshold/session/signingSessionSeal';
import type { SigningSessionSealCipherAdapter } from '../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import {
  formatSigningSessionSealShamirPrimeB64uForWire,
  formatSigningSessionSealKeyVersionForWire,
  parseSigningSessionSealShamirPrimeB64u,
  parseSigningSessionSealKeyVersion,
} from '../keyMaterialBrands';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type EmailOtpShamirCipherConfig = {
  readonly keyVersionRaw: string;
  readonly shamirPrimeB64u: string;
  readonly serverEncryptExponentB64u: string;
  readonly serverDecryptExponentB64u: string;
};

export type EmailOtpShamirCipherResult =
  | {
      readonly ok: true;
      readonly keyVersion: string;
      readonly cipher: SigningSessionSealCipherAdapter;
    }
  | {
      readonly ok: false;
      readonly code: 'not_configured';
      readonly message: string;
    };

export type EmailOtpServerSealOperation = 'apply-server-seal' | 'remove-server-seal';

export type EmailOtpServerSealRequest = {
  readonly wrappedCiphertext?: unknown;
};

export type EmailOtpServerSealResult =
  | { ok: true; ciphertext: string; enrollmentSealKeyVersion: string }
  | { ok: false; code: string; message: string };

export function createEmailOtpShamirCipherFromConfig(
  input: EmailOtpShamirCipherConfig,
): EmailOtpShamirCipherResult {
  if (
    !input.keyVersionRaw ||
    !input.shamirPrimeB64u ||
    !input.serverEncryptExponentB64u ||
    !input.serverDecryptExponentB64u
  ) {
    return {
      ok: false,
      code: 'not_configured',
      message:
        'Email OTP unseal requires SIGNING_SESSION_SEAL_KEY_VERSION, SIGNING_SESSION_SHAMIR_P_B64U, SIGNING_SESSION_SEAL_E_S_B64U, and SIGNING_SESSION_SEAL_D_S_B64U',
    };
  }
  try {
    const signingSessionSealKeyVersion = parseSigningSessionSealKeyVersion(input.keyVersionRaw);
    const keyVersion = formatSigningSessionSealKeyVersionForWire(signingSessionSealKeyVersion);
    const signingSessionSealShamirPrimeB64u = parseSigningSessionSealShamirPrimeB64u(
      input.shamirPrimeB64u,
    );
    const shamirPrimeB64u = formatSigningSessionSealShamirPrimeB64uForWire(
      signingSessionSealShamirPrimeB64u,
    );
    return {
      ok: true,
      keyVersion,
      cipher: createSigningSessionSealShamir3PassCipherAdapter({
        currentKeyVersion: keyVersion,
        keys: [
          {
            keyVersion,
            shamirPrimeB64u,
            serverEncryptExponentB64u: input.serverEncryptExponentB64u,
            serverDecryptExponentB64u: input.serverDecryptExponentB64u,
          },
        ],
      }),
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'not_configured',
      message: errorMessage(error) || 'Email OTP Shamir configuration is invalid',
    };
  }
}

function emailOtpServerSealThresholdSessionId(operation: EmailOtpServerSealOperation): string {
  switch (operation) {
    case 'apply-server-seal':
      return 'email-otp-enroll';
    case 'remove-server-seal':
      return 'email-otp-unseal';
  }
}

function emailOtpServerSealFailureMessage(operation: EmailOtpServerSealOperation): string {
  switch (operation) {
    case 'apply-server-seal':
      return 'Failed to apply Email OTP server seal';
    case 'remove-server-seal':
      return 'Failed to remove Email OTP server seal';
  }
}

export async function runEmailOtpServerSealOperation(input: {
  readonly operation: EmailOtpServerSealOperation;
  readonly request: EmailOtpServerSealRequest;
  readonly shamir: EmailOtpShamirCipherResult;
}): Promise<EmailOtpServerSealResult> {
  try {
    const wrappedCiphertext = toOptionalTrimmedString(input.request.wrappedCiphertext);
    if (!wrappedCiphertext) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Missing wrappedCiphertext',
      };
    }
    if (!input.shamir.ok) return input.shamir;
    const result = await input.shamir.cipher.run({
      operation: input.operation,
      thresholdSessionId: emailOtpServerSealThresholdSessionId(input.operation),
      ciphertext: wrappedCiphertext,
      keyVersion: input.shamir.keyVersion,
      auth: { userId: 'email_otp', claims: {} },
    });
    if (!result.ok) return result;
    return {
      ok: true,
      ciphertext: result.ciphertext,
      enrollmentSealKeyVersion: result.keyVersion || input.shamir.keyVersion,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || emailOtpServerSealFailureMessage(input.operation),
    };
  }
}
