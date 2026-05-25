import { base64UrlDecode } from '@shared/utils/base64';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { collectAuthenticationCredentialForWalletChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../crypto/webauthn';
import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential } from '../../session/passkey/ecdsaClientRoot';
import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';

function cloneFixed32Bytes(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== 32) {
    throw new Error(`${label} must be 32 bytes`);
  }
  return Uint8Array.from(value);
}

export async function resolveThresholdEcdsaClientRootShare(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  walletId: string;
  challengeB64u?: string;
  providedClientRootShare32?: Uint8Array;
  providedClientRootShare32B64u?: string;
  providedCredential?: WebAuthnAuthenticationCredential;
}): Promise<
  | {
      ok: true;
      clientRootShare32: Uint8Array;
      credential?: WebAuthnAuthenticationCredential;
      passkeyPrfFirstB64u?: string;
    }
  | { ok: false; code: string; message: string }
> {
  if (args.providedClientRootShare32 instanceof Uint8Array) {
    try {
      return {
        ok: true,
        clientRootShare32: cloneFixed32Bytes(
          args.providedClientRootShare32,
          'threshold-ecdsa clientRootShare32',
        ),
      };
    } catch (error) {
      return {
        ok: false,
        code: 'invalid_args',
        message:
          error instanceof Error
            ? error.message
            : 'threshold-ecdsa clientRootShare32 must be 32 bytes',
      };
    }
  }

  const providedClientRootShare32B64u = String(args.providedClientRootShare32B64u || '').trim();
  if (providedClientRootShare32B64u) {
    let decoded: Uint8Array | null = null;
    try {
      decoded = base64UrlDecode(providedClientRootShare32B64u);
      return {
        ok: true,
        clientRootShare32: cloneFixed32Bytes(decoded, 'threshold-ecdsa clientRootShare32B64u'),
      };
    } catch {
      return {
        ok: false,
        code: 'invalid_args',
        message:
          'threshold-ecdsa client root share must be 32 bytes supplied as base64url or raw bytes',
      };
    } finally {
      decoded?.fill(0);
    }
  }

  if (args.providedCredential) {
    let decoded: Uint8Array | null = null;
    try {
      const passkeyPrfFirstB64u = String(
        getPrfFirstB64uFromCredential(args.providedCredential) || '',
      ).trim();
      decoded = base64UrlDecode(
        await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(
          args.providedCredential,
        ),
      );
      return {
        ok: true,
        clientRootShare32: cloneFixed32Bytes(
          decoded,
          'threshold-ecdsa passkey client root share',
        ),
        credential: args.providedCredential,
        ...(passkeyPrfFirstB64u ? { passkeyPrfFirstB64u } : {}),
      };
    } catch {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'threshold-ecdsa passkey client root share must decode to 32 bytes',
      };
    } finally {
      decoded?.fill(0);
    }
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

  const credential = await collectAuthenticationCredentialForWalletChallengeB64u({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    walletId: args.walletId,
    challengeB64u,
  });
  const passkeyPrfFirstB64u = String(getPrfFirstB64uFromCredential(credential) || '').trim();
  let clientRootShare32: Uint8Array;
  try {
    clientRootShare32 = base64UrlDecode(
      await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(credential),
    );
  } catch {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
    };
  }
  return {
    ok: true,
    clientRootShare32,
    credential,
    ...(passkeyPrfFirstB64u ? { passkeyPrfFirstB64u } : {}),
  };
}
