import { base64UrlEncode } from '@shared/utils/base64';
import type { WebAuthnAuthenticationCredential } from '@/core/types';

export function createLocalUnlockChallengeB64u(): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('Secure random is unavailable for passkey wallet unlock');
  }
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  return base64UrlEncode(challenge);
}

export async function collectFreshLocalPasskeyUnlockCredential(args: {
  currentCredential?: WebAuthnAuthenticationCredential;
  collectCredentialForChallenge: (challengeB64u: string) => Promise<WebAuthnAuthenticationCredential>;
}): Promise<WebAuthnAuthenticationCredential | undefined> {
  if (args.currentCredential) return undefined;
  return await args.collectCredentialForChallenge(createLocalUnlockChallengeB64u());
}
