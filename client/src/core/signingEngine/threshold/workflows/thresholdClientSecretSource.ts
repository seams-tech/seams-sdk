import { base64UrlDecode } from '@shared/utils/base64';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../webauthn';

export async function resolveThresholdEcdsaClientRootShare(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  userId: string;
  challengeB64u?: string;
  providedClientRootShare32B64u?: string;
}): Promise<
  | {
      ok: true;
      clientRootShare32B64u: string;
      credential?: Awaited<ReturnType<typeof collectAuthenticationCredentialForChallengeB64u>>;
    }
  | { ok: false; code: string; message: string }
> {
  const providedClientRootShare32B64u = String(args.providedClientRootShare32B64u || '').trim();
  if (providedClientRootShare32B64u) {
    try {
      const decoded = base64UrlDecode(providedClientRootShare32B64u);
      if (decoded.length !== 32) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'threshold-ecdsa clientRootShare32B64u must decode to 32 bytes',
        };
      }
    } catch {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'threshold-ecdsa clientRootShare32B64u must be valid base64url',
      };
    }
    return { ok: true, clientRootShare32B64u: providedClientRootShare32B64u };
  }

  const challengeB64u = String(args.challengeB64u || '').trim();
  if (!challengeB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message:
        'Missing threshold-ecdsa client root share for bootstrap; reconnect with WebAuthn or provide canonical session material',
    };
  }

  const credential = await collectAuthenticationCredentialForChallengeB64u({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    nearAccountId: args.userId,
    challengeB64u,
  });
  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
    };
  }
  return {
    ok: true,
    clientRootShare32B64u: prfFirstB64u,
    credential,
  };
}
