import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import { base64UrlDecode } from '@shared/utils/encoders';
import {
  parseWebAuthnCredentialIdB64u,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';

export type WalletRecoveryReplacementCredential = {
  readonly registration: WebAuthnRegistrationCredential;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly factorSecret: ArrayBuffer;
};

function recoveryFactorSecret(
  registration: WebAuthnRegistrationCredential,
): ArrayBuffer {
  const first = registration.clientExtensionResults.prf?.results?.first;
  if (typeof first !== 'string' || !first) {
    throw new Error('the replacement passkey returned no wallet-custody PRF output');
  }
  const secret = base64UrlDecode(first);
  if (secret.length !== 32) {
    throw new Error('the replacement passkey returned an invalid wallet-custody PRF output');
  }
  return Uint8Array.from(secret).buffer;
}

export function walletRecoveryReplacementCredentialFromRegistrationV1(
  registration: WebAuthnRegistrationCredential,
): WalletRecoveryReplacementCredential {
  const credentialId = parseWebAuthnCredentialIdB64u(
    String(registration.rawId || registration.id || '').trim(),
  );
  if (!credentialId.ok) {
    throw new Error(`replacement passkey credential id ${credentialId.error.message}`);
  }
  return {
    registration,
    credentialIdB64u: credentialId.value,
    factorSecret: recoveryFactorSecret(registration),
  };
}
