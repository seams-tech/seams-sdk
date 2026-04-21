import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { createSigningSessionSealShamir3PassBigIntRuntime } from '@server/threshold/session/signingSessionSeal';
import { base64UrlEncode } from '@shared/utils/encoders';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const EMAIL_OTP_KEY_VERSION = 'kek-s-email-otp-test';
const SHAMIR_PRIME_B64U = encodePositiveBigIntB64u(257n);
const SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(3n);
const SHAMIR_SERVER_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(171n);
const CLIENT_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(5n);
const CLIENT_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(205n);

function encodePositiveBigIntB64u(value: bigint): string {
  if (value <= 0n) throw new Error('value must be > 0');
  const bytesReversed: number[] = [];
  let cursor = value;
  while (cursor > 0n) {
    bytesReversed.push(Number(cursor & 255n));
    cursor >>= 8n;
  }
  bytesReversed.reverse();
  return base64UrlEncode(Uint8Array.from(bytesReversed));
}

function makeService(): AuthService {
  return new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
    thresholdStore: {
      SIGNING_SESSION_SEAL_KEY_VERSION: EMAIL_OTP_KEY_VERSION,
      SIGNING_SESSION_SHAMIR_P_B64U: SHAMIR_PRIME_B64U,
      SIGNING_SESSION_SEAL_E_S_B64U: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
      SIGNING_SESSION_SEAL_D_S_B64U: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
    },
  });
}

function addClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: CLIENT_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

function removeClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.removeServerSeal({
      ciphertextB64u,
      exponentB64u: CLIENT_DECRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

function addServerSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

test.describe('Email OTP shamir3pass semantics', () => {
  test('enroll seal path transforms E_kc(S) into E_kc(E_ks(S)) and client unseal yields E_ks(S)', async () => {
    const service = makeService();
    const plaintextSecretB64u = encodePositiveBigIntB64u(11n);
    const wrappedCiphertext = addClientSeal(plaintextSecretB64u);

    const applied = await service.applyEmailOtpServerSeal({
      wrappedCiphertext,
    });
    expect(applied.ok).toBe(true);
    if (!applied.ok) return;

    expect(applied.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
    expect(applied.ciphertext).not.toBe(wrappedCiphertext);
    expect(removeClientSeal(applied.ciphertext)).toBe(addServerSeal(plaintextSecretB64u));
  });

  test('unseal path transforms E_kc(E_ks(S)) into E_kc(S) and client unseal yields plaintext S', async () => {
    const service = makeService();
    const plaintextSecretB64u = encodePositiveBigIntB64u(19n);
    const wrappedCiphertext = addClientSeal(addServerSeal(plaintextSecretB64u));

    const removed = await service.removeEmailOtpServerSeal({
      wrappedCiphertext,
    });
    expect(removed.ok).toBe(true);
    if (!removed.ok) return;

    expect(removed.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
    expect(removed.ciphertext).not.toBe(wrappedCiphertext);
    expect(removeClientSeal(removed.ciphertext)).toBe(plaintextSecretB64u);
  });
});
