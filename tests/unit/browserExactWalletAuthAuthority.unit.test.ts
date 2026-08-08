import { expect, test } from '@playwright/test';
import { resolveExactWalletAuthAuthority } from '@/SeamsWeb/assembly/browserSigningSurfaceAssembly';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { base64UrlEncode } from '@shared/utils/encoders';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildPasskeyEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

const noEmailOtpSessionResolver = {
  resolveAppSessionJwtForWallet: async () => {
    throw new Error('Email OTP session is not configured for this fixture');
  },
};

function jwtWithPayload(payload: Record<string, unknown>): string {
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'none' })));
  const body = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  return `${header}.${body}.fixture`;
}

test('resolves the exact passkey authority from its sealed ECDSA runtime', async () => {
  const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
  const sealedRecord = buildPasskeyEcdsaSealedRuntimeRecordFixture({
    manifest: fixture.manifest,
  });

  const authority = await resolveExactWalletAuthAuthority(
    fixture.manifest.signer.authority,
    {
      listEcdsaSealedSessionsForWallet: async () => [sealedRecord],
    },
    { listWalletAuthMethodsForWallet: async () => [] },
    { listWalletPasskeyAuthenticators: async () => [] },
    'example.localhost',
    noEmailOtpSessionResolver,
    '',
  );

  expect(authority.factor).toEqual({
    kind: 'passkey',
    credentialIdB64u: sealedRecord.ecdsaRestore.credentialIdB64u,
  });
  expect(authority.verifier).toEqual({
    kind: 'webauthn',
    rpId: sealedRecord.ecdsaRestore.rpId,
  });
  expect(await walletAuthAuthorityRef({ authority })).toEqual(fixture.manifest.signer.authority);
});

test('matches the current verified RP ID with the injected wallet authenticator store', async () => {
  const exactAuthority = buildPasskeyWalletAuthAuthority({
    walletId: 'registered-wallet',
    rpId: 'example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const authority = await resolveExactWalletAuthAuthority(
    authorityRef,
    { listEcdsaSealedSessionsForWallet: async () => [] },
    { listWalletAuthMethodsForWallet: async () => [] },
    {
      listWalletPasskeyAuthenticators: async () => [
        {
          profileId: exactAuthority.walletId,
          signerSlot: 1,
          credentialId: exactAuthority.factor.credentialIdB64u,
          credentialPublicKey: new Uint8Array([1, 2, 3]),
          transports: [],
          name: 'Registered passkey',
          registered: new Date(1).toISOString(),
          syncedAt: new Date(1).toISOString(),
        },
      ],
    },
    'example.localhost',
    noEmailOtpSessionResolver,
    '',
  );
  expect(authority).toEqual(exactAuthority);
});

test('resolves the exact passkey authority from the canonical wallet auth method', async () => {
  const exactAuthority = buildPasskeyWalletAuthAuthority({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const authority = await resolveExactWalletAuthAuthority(
    authorityRef,
    { listEcdsaSealedSessionsForWallet: async () => [] },
    {
      listWalletAuthMethodsForWallet: async () => [
        {
          version: 'wallet_auth_method_v1',
          kind: 'passkey',
          status: 'active',
          localStatus: 'synced',
          walletId: exactAuthority.walletId,
          rpId: exactAuthority.verifier.rpId,
          credentialIdB64u: exactAuthority.factor.credentialIdB64u,
          credentialPublicKeyB64u: 'AQID',
          counter: 0,
          createdAtMs: 1,
          updatedAtMs: 1,
        },
      ],
    },
    { listWalletPasskeyAuthenticators: async () => [] },
    'current.example.localhost',
    noEmailOtpSessionResolver,
    '',
  );

  expect(authority).toEqual(exactAuthority);
});

test('reconstructs the exact Email OTP authority from the active auth row and app session', async () => {
  const exactAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: 'registered-wallet',
    provider: 'email',
    providerUserId: 'email:registered-user',
    emailHashHex: 'email-hash',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    walletId: exactAuthority.walletId,
    provider: exactAuthority.factor.provider,
    providerSubject: exactAuthority.factor.providerUserId,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'oidc',
      providerSubject: exactAuthority.factor.providerUserId,
    },
  });
  const authority = await resolveExactWalletAuthAuthority(
    authorityRef,
    { listEcdsaSealedSessionsForWallet: async () => [] },
    {
      listWalletAuthMethodsForWallet: async () => [
        {
          version: 'wallet_auth_method_v1',
          kind: 'email_otp',
          status: 'active',
          localStatus: 'synced',
          walletId: exactAuthority.walletId,
          emailHashHex: exactAuthority.verifier.emailHashHex,
          registrationAuthorityId: 'registration-authority',
          createdAtMs: 1,
          updatedAtMs: 1,
        },
      ],
    },
    { listWalletPasskeyAuthenticators: async () => [] },
    'current.example.localhost',
    { resolveAppSessionJwtForWallet: async () => appSessionJwt },
    'https://relay.example',
  );

  expect(authority).toEqual(exactAuthority);
  expect(await walletAuthAuthorityRef({ authority })).toEqual(authorityRef);
});

test('reconstructs Google Email OTP authority from the server OIDC app-session claims', async () => {
  const exactAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: 'registered-wallet',
    provider: 'google',
    providerUserId: 'google:registered-user',
    emailHashHex: 'email-hash',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  let appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    walletId: exactAuthority.walletId,
    provider: 'oidc',
    oidcProvider: 'google',
    providerSubject: exactAuthority.factor.providerUserId,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'google_oidc',
      providerSubject: exactAuthority.factor.providerUserId,
    },
  });
  const stores = {
    listEcdsaSealedSessionsForWallet: async () => [],
  };
  const authMethods = {
    listWalletAuthMethodsForWallet: async () => [
      {
        version: 'wallet_auth_method_v1' as const,
        kind: 'email_otp' as const,
        status: 'active' as const,
        localStatus: 'synced' as const,
        walletId: exactAuthority.walletId,
        emailHashHex: exactAuthority.verifier.emailHashHex,
        registrationAuthorityId: 'registration-authority',
        createdAtMs: 1,
        updatedAtMs: 1,
      },
    ],
  };
  const authority = await resolveExactWalletAuthAuthority(
    authorityRef,
    stores,
    authMethods,
    { listWalletPasskeyAuthenticators: async () => [] },
    'current.example.localhost',
    { resolveAppSessionJwtForWallet: async () => appSessionJwt },
    'https://relay.example',
  );

  expect(authority).toEqual(exactAuthority);

  appSessionJwt = jwtWithPayload({
    kind: 'app_session_v1',
    walletId: exactAuthority.walletId,
    provider: 'oidc',
    oidcProvider: 'google',
    providerSubject: 'email:registered-user',
    authSource: {
      kind: 'oidc_provider',
      providerId: 'google_oidc',
      providerSubject: 'email:registered-user',
    },
  });
  await expect(
    resolveExactWalletAuthAuthority(
      authorityRef,
      stores,
      authMethods,
      { listWalletPasskeyAuthenticators: async () => [] },
      'current.example.localhost',
      { resolveAppSessionJwtForWallet: async () => appSessionJwt },
      'https://relay.example',
    ),
  ).rejects.toThrow('Exact wallet authentication authority is unavailable');
});
