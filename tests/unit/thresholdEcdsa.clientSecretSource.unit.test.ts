import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { resolveThresholdEcdsaClientRootShare } from '../../client/src/core/signingEngine/threshold/ecdsa/clientSecretSource';
import type {
  ThresholdIndexedDbPort,
  ThresholdWebAuthnPromptPort,
} from '../../client/src/core/signingEngine/threshold/crypto/webauthn';
import type { WebAuthnAuthenticationCredential } from '../../client/src/core/types/webauthn';

function bytesB64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

const prfFirstB64u = bytesB64u(32, 1);
const credential: WebAuthnAuthenticationCredential = {
  id: 'credential-id',
  rawId: 'credential-raw-id',
  type: 'public-key',
  authenticatorAttachment: undefined,
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: prfFirstB64u,
        second: undefined,
      },
    },
  },
};

const indexedDB: ThresholdIndexedDbPort = {
  async resolveProfileAccountContext() {
    return null;
  },
  async listProfileAuthenticators() {
    return [];
  },
  async listAccountSigners() {
    return [];
  },
  async selectProfileAuthenticatorsForPrompt(args) {
    return { authenticatorsForPrompt: args.authenticators };
  },
};

const touchIdPrompt: ThresholdWebAuthnPromptPort = {
  getRpId() {
    return 'localhost';
  },
  async getAuthenticationCredentialsSerializedForChallengeB64u() {
    return credential;
  },
};

test.describe('threshold ECDSA client secret source boundary', () => {
  test('resolves WebAuthn credentials through the canonical PRF secret source', async () => {
    const result = await resolveThresholdEcdsaClientRootShare({
      kind: 'provided_webauthn_prf_credential',
      credential,
      rpId: 'localhost',
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.kind).toBe('webauthn_prf_first');
    expect(result.clientRootShare32).toHaveLength(32);
    expect(result.passkeyPrfFirstB64u).toBe(prfFirstB64u);
    expect(result.secretSource).toMatchObject({
      kind: 'webauthn_prf_first',
      prfFirstB64u,
      rpId: 'localhost',
      credentialIdB64u: 'credential-raw-id',
    });
  });

  test('keeps raw provided root shares on an explicit transitional branch', async () => {
    const result = await resolveThresholdEcdsaClientRootShare({
      kind: 'provided_client_root_share_bytes',
      clientRootShare32: new Uint8Array(32).fill(7),
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.kind).toBe('provided_client_root_share');
    expect(result.clientRootShare32).toHaveLength(32);
    expect('secretSource' in result).toBe(false);
  });

  test('collects WebAuthn PRF credentials through an exact request branch', async () => {
    await expect(
      resolveThresholdEcdsaClientRootShare({
        kind: 'collect_webauthn_prf_credential',
        indexedDB,
        touchIdPrompt,
        walletId: 'wallet.testnet',
        challengeB64u: bytesB64u(32, 9),
        rpId: 'localhost',
      }),
    ).rejects.toThrow(/no passkeys/i);
  });
});
