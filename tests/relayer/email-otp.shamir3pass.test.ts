import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { ensureSigningSessionSealShamir3PassWasm } from '@server/threshold/session/signingSessionSeal/crypto/shamir3PassWasm';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  shamir3pass_add_lock,
  shamir3pass_destroy_lock_key_handle,
  shamir3pass_generate_lock_key_handle,
  shamir3pass_remove_lock,
} from '../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const EMAIL_OTP_KEY_VERSION = 'kek-s-email-otp-test';
const EMAIL_OTP_ROOT_SECRET_B64U = Buffer.alloc(32, 0x42).toString('base64url');

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
      SIGNING_SESSION_SEAL_ROOT_SECRET_B64U: EMAIL_OTP_ROOT_SECRET_B64U,
      SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION: EMAIL_OTP_KEY_VERSION,
      SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS: EMAIL_OTP_KEY_VERSION,
    },
  });
}

class ClientLockFixture {
  constructor(private readonly handle: number) {}

  add(ciphertextB64u: string): string {
    return shamir3pass_add_lock(this.handle, ciphertextB64u);
  }

  remove(ciphertextB64u: string): string {
    return shamir3pass_remove_lock(this.handle, ciphertextB64u);
  }

  destroy(): void {
    shamir3pass_destroy_lock_key_handle(this.handle);
  }
}

async function createClientLock(): Promise<ClientLockFixture> {
  await ensureSigningSessionSealShamir3PassWasm();
  return new ClientLockFixture(shamir3pass_generate_lock_key_handle('rfc2409-group2'));
}

test.describe('Email OTP shamir3pass semantics', () => {
  test('enroll seal path transforms E_kc(S) into E_kc(E_ks(S)) and client unseal yields E_ks(S)', async () => {
    const service = makeService();
    const client = await createClientLock();
    const plaintextSecretB64u = encodePositiveBigIntB64u(11n);
    const wrappedCiphertext = client.add(plaintextSecretB64u);

    const applied = await service.applyEmailOtpServerSeal({
      wrappedCiphertext,
    });
    expect(applied.ok).toBe(true);
    if (!applied.ok) return;

    expect(applied.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
    expect(applied.ciphertext).not.toBe(wrappedCiphertext);
    expect(client.remove(applied.ciphertext)).not.toBe(plaintextSecretB64u);
    client.destroy();
  });

  test('unseal path transforms E_kc(E_ks(S)) into E_kc(S) and client unseal yields plaintext S', async () => {
    const service = makeService();
    const client = await createClientLock();
    const plaintextSecretB64u = encodePositiveBigIntB64u(19n);
    const clientLocked = client.add(plaintextSecretB64u);
    const applied = await service.applyEmailOtpServerSeal({ wrappedCiphertext: clientLocked });
    expect(applied.ok).toBe(true);
    if (!applied.ok) return;
    const serverLocked = client.remove(applied.ciphertext);
    const wrappedCiphertext = client.add(serverLocked);

    const removed = await service.removeEmailOtpServerSeal({
      wrappedCiphertext,
    });
    expect(removed.ok).toBe(true);
    if (!removed.ok) return;

    expect(removed.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
    expect(removed.ciphertext).not.toBe(wrappedCiphertext);
    expect(client.remove(removed.ciphertext)).toBe(plaintextSecretB64u);
    client.destroy();
  });
});
