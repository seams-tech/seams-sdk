import { expect, test } from '@playwright/test';
import {
  collectAuthenticationCredentialForChallengeB64u,
  collectAuthenticationCredentialForWalletChallengeB64u,
  type WebAuthnAllowCredential,
} from '../../client/src/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';

type Auth = { credentialId: string; signerSlot: number; transports: AuthenticatorTransport[] };

function selectionDb(args: {
  nearAuthenticators?: Auth[];
  walletAuthenticators?: Auth[];
  walletId?: string;
}) {
  const walletId = args.walletId || 'wallet_gorp47';
  return {
    resolveProfileAccountContext: async () => ({
      profileId: 'near-profile:gorp47.w3a-relayer.testnet',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'gorp47.w3a-relayer.testnet',
      },
    }),
    listProfileAuthenticators: async (profileId: string): Promise<Auth[]> => {
      if (profileId === walletId) return args.walletAuthenticators || [];
      return args.nearAuthenticators || [];
    },
    listAccountSigners: async () => [
      {
        signerAuthMethod: 'passkey',
        metadata: {
          walletId,
          passkeyCredentialRawId: 'cred-current',
        },
      },
    ],
    selectProfileAuthenticatorsForPrompt: async (input: {
      authenticators: Auth[];
      selectedCredentialRawId?: string;
    }) => {
      const authenticatorsForPrompt = input.authenticators.filter(
        (auth) => auth.credentialId === 'cred-current',
      );
      if (input.selectedCredentialRawId && input.selectedCredentialRawId !== 'cred-current') {
        return {
          authenticatorsForPrompt,
          wrongPasskeyError: 'wrong passkey',
        };
      }
      return { authenticatorsForPrompt };
    },
  };
}

test('step-up prompt resolves the canonical wallet passkey from the active account signer', async () => {
  let capturedAllowCredentials: WebAuthnAllowCredential[] | undefined;
  const credential = await collectAuthenticationCredentialForChallengeB64u({
    indexedDB: selectionDb({
      nearAuthenticators: [
        { credentialId: 'wrong-near-profile-credential', signerSlot: 1, transports: [] },
      ],
      walletAuthenticators: [
        { credentialId: 'cred-current', signerSlot: 1, transports: ['internal'] },
      ],
    }),
    touchIdPrompt: {
      getAuthenticationCredentialsSerializedForChallengeB64u: async ({ allowCredentials }) => {
        capturedAllowCredentials = allowCredentials;
        return {
          id: 'cred-current',
          rawId: 'cred-current',
          type: 'public-key',
          authenticatorAttachment: undefined,
          response: {
            clientDataJSON: 'client-data',
            authenticatorData: 'auth-data',
            signature: 'signature',
            userHandle: undefined,
          },
          clientExtensionResults: { prf: { results: { first: undefined, second: undefined } } },
        };
      },
    },
    nearAccountId: 'gorp47.w3a-relayer.testnet',
    challengeB64u: 'challenge',
  });

  expect(credential.rawId).toBe('cred-current');
  expect(capturedAllowCredentials).toEqual([
    { id: 'cred-current', type: 'public-key', transports: ['internal'] },
  ]);
});

test('wallet challenge prompt uses canonical wallet passkey directly', async () => {
  let capturedAllowCredentials: WebAuthnAllowCredential[] | undefined;
  await collectAuthenticationCredentialForWalletChallengeB64u({
    indexedDB: selectionDb({
      walletAuthenticators: [
        { credentialId: 'cred-old', signerSlot: 1, transports: [] },
        { credentialId: 'cred-current', signerSlot: 2, transports: ['internal'] },
      ],
    }),
    touchIdPrompt: {
      getAuthenticationCredentialsSerializedForChallengeB64u: async ({ allowCredentials }) => {
        capturedAllowCredentials = allowCredentials;
        return {
          id: 'cred-current',
          rawId: 'cred-current',
          type: 'public-key',
          authenticatorAttachment: undefined,
          response: {
            clientDataJSON: 'client-data',
            authenticatorData: 'auth-data',
            signature: 'signature',
            userHandle: undefined,
          },
          clientExtensionResults: { prf: { results: { first: undefined, second: undefined } } },
        };
      },
    },
    walletId: 'wallet_gorp47',
    challengeB64u: 'challenge',
  });

  expect(capturedAllowCredentials).toEqual([
    { id: 'cred-current', type: 'public-key', transports: ['internal'] },
  ]);
});

test('step-up prompt fails closed when no passkey can be resolved', async () => {
  await expect(
    collectAuthenticationCredentialForChallengeB64u({
      indexedDB: selectionDb({ nearAuthenticators: [], walletAuthenticators: [] }),
      touchIdPrompt: {
        getAuthenticationCredentialsSerializedForChallengeB64u: async () => {
          throw new Error('should not prompt');
        },
      },
      nearAccountId: 'gorp47.w3a-relayer.testnet',
      challengeB64u: 'challenge',
    }),
  ).rejects.toThrow('no passkeys found');
});
