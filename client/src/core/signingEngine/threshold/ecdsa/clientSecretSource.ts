import { base64UrlDecode } from '@shared/utils/base64';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { collectAuthenticationCredentialForWalletChallengeB64u } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../crypto/webauthn';
import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst } from '../../session/passkey/ecdsaClientRoot';
import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import {
  buildWebAuthnPrfFirstSecretSource,
  type RequiredPrfAuthenticatorSuccess,
  type WebAuthnPrfFirstSecretSource,
} from '@/core/platform/types';
import { toRpId } from '../../session/identity/evmFamilyEcdsaIdentity';

function cloneFixed32Bytes(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== 32) {
    throw new Error(`${label} must be 32 bytes`);
  }
  return Uint8Array.from(value);
}

type ThresholdEcdsaClientRootShareResolution =
  | {
      ok: true;
      kind: 'provided_client_root_share';
      clientRootShare32: Uint8Array;
      credential?: never;
      passkeyPrfFirstB64u?: never;
      secretSource?: never;
    }
  | {
      ok: true;
      kind: 'webauthn_prf_first';
      clientRootShare32: Uint8Array;
      credential: WebAuthnAuthenticationCredential;
      passkeyPrfFirstB64u: string;
      secretSource: WebAuthnPrfFirstSecretSource;
  }
  | { ok: false; code: string; message: string };

export type ThresholdEcdsaClientRootShareRequest =
  | {
      kind: 'provided_client_root_share_bytes';
      clientRootShare32: Uint8Array;
      clientRootShare32B64u?: never;
      credential?: never;
      indexedDB?: never;
      touchIdPrompt?: never;
      walletId?: never;
      challengeB64u?: never;
      rpId?: never;
    }
  | {
      kind: 'provided_client_root_share_b64u';
      clientRootShare32B64u: string;
      clientRootShare32?: never;
      credential?: never;
      indexedDB?: never;
      touchIdPrompt?: never;
      walletId?: never;
      challengeB64u?: never;
      rpId?: never;
    }
  | {
      kind: 'provided_webauthn_prf_credential';
      credential: WebAuthnAuthenticationCredential;
      rpId: string;
      clientRootShare32?: never;
      clientRootShare32B64u?: never;
      indexedDB?: never;
      touchIdPrompt?: never;
      walletId?: never;
      challengeB64u?: never;
    }
  | {
      kind: 'collect_webauthn_prf_credential';
      indexedDB: ThresholdIndexedDbPort;
      touchIdPrompt: ThresholdWebAuthnPromptPort;
      walletId: string;
      challengeB64u: string;
      rpId: string;
      clientRootShare32?: never;
      clientRootShare32B64u?: never;
      credential?: never;
    };

function assertNeverClientRootShareRequest(value: never): never {
  throw new Error(
    `[threshold-ecdsa] unsupported client-root share request ${String(
      (value as { kind?: unknown })?.kind || '',
    )}`,
  );
}

function buildRequiredPrfAuthenticatorSuccess(args: {
  credential: WebAuthnAuthenticationCredential;
  rpId: string;
}): RequiredPrfAuthenticatorSuccess {
  const passkeyPrfFirstB64u = String(getPrfFirstB64uFromCredential(args.credential) || '').trim();
  if (!passkeyPrfFirstB64u) {
    throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
  }
  return {
    ok: true,
    operation: 'get_passkey',
    requirePrfFirst: true,
    credential: args.credential,
    credentialIdB64u: String(args.credential.rawId || args.credential.id || '').trim(),
    rawIdB64u: String(args.credential.rawId || '').trim(),
    rpId: toRpId(args.rpId),
    prf: {
      kind: 'required',
      prfFirstB64u: passkeyPrfFirstB64u,
    },
  };
}

async function resolveWebAuthnPrfFirstClientRootShare(args: {
  credential: WebAuthnAuthenticationCredential;
  rpId: string;
}): Promise<Extract<ThresholdEcdsaClientRootShareResolution, { kind: 'webauthn_prf_first' }>> {
  const secretSource = buildWebAuthnPrfFirstSecretSource(
    buildRequiredPrfAuthenticatorSuccess(args),
  );
  let decoded: Uint8Array | null = null;
  try {
    decoded = base64UrlDecode(
      await derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst(
        secretSource.prfFirstB64u,
      ),
    );
    return {
      ok: true,
      kind: 'webauthn_prf_first',
      clientRootShare32: cloneFixed32Bytes(
        decoded,
        'threshold-ecdsa passkey client root share',
      ),
      credential: args.credential,
      passkeyPrfFirstB64u: secretSource.prfFirstB64u,
      secretSource,
    };
  } finally {
    decoded?.fill(0);
  }
}

export async function resolveThresholdEcdsaClientRootShare(
  request: ThresholdEcdsaClientRootShareRequest,
): Promise<ThresholdEcdsaClientRootShareResolution> {
  switch (request.kind) {
    case 'provided_client_root_share_bytes':
      try {
        return {
          ok: true,
          kind: 'provided_client_root_share',
          clientRootShare32: cloneFixed32Bytes(
            request.clientRootShare32,
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
    case 'provided_client_root_share_b64u': {
      let decoded: Uint8Array | null = null;
      try {
        decoded = base64UrlDecode(String(request.clientRootShare32B64u || '').trim());
        return {
          ok: true,
          kind: 'provided_client_root_share',
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
    case 'provided_webauthn_prf_credential':
      try {
        return await resolveWebAuthnPrfFirstClientRootShare({
          credential: request.credential,
          rpId: request.rpId,
        });
      } catch {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'threshold-ecdsa passkey client root share must decode to 32 bytes',
        };
      }
    case 'collect_webauthn_prf_credential': {
      const credential = await collectAuthenticationCredentialForWalletChallengeB64u({
        indexedDB: request.indexedDB,
        touchIdPrompt: request.touchIdPrompt,
        walletId: request.walletId,
        challengeB64u: request.challengeB64u,
      });
      try {
        return await resolveWebAuthnPrfFirstClientRootShare({
          credential,
          rpId: request.rpId,
        });
      } catch {
        return {
          ok: false,
          code: 'unsupported',
          message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
        };
      }
    }
    default:
      return assertNeverClientRootShareRequest(request);
  }
}
