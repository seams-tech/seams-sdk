import { toOptionalTrimmedString } from '@shared/utils/validation';
import { createSigningSessionSealShamir3PassCipherAdapter } from '../../threshold/session/signingSessionSeal/crypto/cipher';
import type { SigningSessionSealCipherAdapter } from '../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import type { EmailOtpServerSealRuntimeConfig } from './d1RouterApiAuthConfig';

type EmailOtpServerSealInput = {
  readonly wrappedCiphertext?: unknown;
};

type EmailOtpServerSealResult =
  | {
      readonly ok: true;
      readonly ciphertext: string;
      readonly enrollmentSealKeyVersion: string;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

type EmailOtpServerSealCipherResult =
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

type EmailOtpServerSealOperation =
  | {
      readonly cipherOperation: 'apply-server-seal';
      readonly thresholdSessionId: 'email-otp-enroll';
      readonly failureMessage: 'Failed to apply Email OTP server seal';
    }
  | {
      readonly cipherOperation: 'remove-server-seal';
      readonly thresholdSessionId: 'email-otp-unseal';
      readonly failureMessage: 'Failed to remove Email OTP server seal';
    };

const applyEmailOtpServerSealOperation: EmailOtpServerSealOperation = {
  cipherOperation: 'apply-server-seal',
  thresholdSessionId: 'email-otp-enroll',
  failureMessage: 'Failed to apply Email OTP server seal',
};

const removeEmailOtpServerSealOperation: EmailOtpServerSealOperation = {
  cipherOperation: 'remove-server-seal',
  thresholdSessionId: 'email-otp-unseal',
  failureMessage: 'Failed to remove Email OTP server seal',
};

export class CloudflareD1EmailOtpServerSealRuntime {
  constructor(private readonly config: EmailOtpServerSealRuntimeConfig) {}

  async removeEmailOtpServerSeal(
    input: EmailOtpServerSealInput,
  ): Promise<EmailOtpServerSealResult> {
    return await this.runServerSealOperation(input, removeEmailOtpServerSealOperation);
  }

  async applyEmailOtpServerSeal(input: EmailOtpServerSealInput): Promise<EmailOtpServerSealResult> {
    return await this.runServerSealOperation(input, applyEmailOtpServerSealOperation);
  }

  private async runServerSealOperation(
    input: EmailOtpServerSealInput,
    operation: EmailOtpServerSealOperation,
  ): Promise<EmailOtpServerSealResult> {
    try {
      const wrappedCiphertext = toOptionalTrimmedString(input.wrappedCiphertext);
      if (!wrappedCiphertext) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing wrappedCiphertext',
        };
      }
      const shamir = this.createCipher();
      if (!shamir.ok) return shamir;
      const result = await shamir.cipher.run({
        operation: operation.cipherOperation,
        thresholdSessionId: operation.thresholdSessionId,
        ciphertext: wrappedCiphertext,
        keyVersion: shamir.keyVersion,
        auth: { userId: 'email_otp', claims: {} },
      });
      if (!result.ok) return result;
      return {
        ok: true,
        ciphertext: result.ciphertext,
        enrollmentSealKeyVersion: result.keyVersion || shamir.keyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: serverSealErrorMessage(error) || operation.failureMessage,
      };
    }
  }

  private createCipher(): EmailOtpServerSealCipherResult {
    if (!this.config.configured) {
      return {
        ok: false,
        code: 'not_configured',
        message: this.config.message,
      };
    }
    try {
      return {
        ok: true,
        keyVersion: this.config.keyVersion,
        cipher: createSigningSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: this.config.keyVersion,
          keys: [
            {
              keyVersion: this.config.keyVersion,
              shamirPrimeB64u: this.config.shamirPrimeB64u,
              serverEncryptExponentB64u: this.config.serverEncryptExponentB64u,
              serverDecryptExponentB64u: this.config.serverDecryptExponentB64u,
            },
          ],
        }),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'not_configured',
        message: serverSealErrorMessage(error) || 'Email OTP Shamir configuration is invalid',
      };
    }
  }
}

function serverSealErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}
