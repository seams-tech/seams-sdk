import {
  createSigningSessionSealShamir3PassCipherAdapter,
  parseSigningSessionSealRootConfig,
} from '../../threshold/session/signingSessionSeal';
import type { SigningSessionSealCipherAdapter } from '../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type EmailOtpShamirCipherConfig = {
  readonly rootSecretB64u: string;
  readonly currentKeyVersion: string;
  readonly acceptedWarmKeyVersions: readonly string[];
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
  if (!input.rootSecretB64u || !input.currentKeyVersion) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Email OTP unseal requires a signing-session seal root and current key version',
    };
  }
  try {
    const config = parseSigningSessionSealRootConfig({
      rootSecretB64u: input.rootSecretB64u,
      currentKeyVersion: input.currentKeyVersion,
      acceptedWarmKeyVersions: input.acceptedWarmKeyVersions,
    });
    return {
      ok: true,
      keyVersion: config.currentKeyVersion,
      cipher: createSigningSessionSealShamir3PassCipherAdapter({ config }),
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
      auth: { userId: 'email_otp' },
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
