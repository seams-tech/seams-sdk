import { expect, test } from '@playwright/test';
import { listWebAuthnAuthenticatorsForUserWithStores } from '../../packages/wallet-server/src/core/authService/webauthn';
import { handleWebAuthnAuthenticators } from '../../packages/wallet-server/src/router/transport/fetch/routes/webauthnAuthenticators';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import type { RouterApiServiceBag } from '../../packages/wallet-server/src/router/framework/authServicePort';
import { coerceRouterLogger } from '../../packages/wallet-server/src/router/framework/logger';
import {
  cleanupTemporaryD1Database,
} from '../helpers/sqliteD1';
import {
  createWebAuthnAuthenticatorListingStores,
  ICLOUD_KEYCHAIN_AAGUID,
  testWebAuthnAuthenticatorRecord,
  testWebAuthnCredentialBindingRecord,
  WEBAUTHN_DEVICE_USER_AGENTS,
  type WebAuthnAuthenticatorListingStores,
} from './helpers/webauthnAuthenticatorListing.fixtures';

const WALLET_ID = 'listing-wallet.testnet';
const RP_ID = 'wallet.example.test';

/**
 * Two owner passkeys with captured metadata, one binding whose authenticator
 * row predates device capture, and one binding with no authenticator row at
 * all — every branch the listing has to describe.
 */
async function seedListingFixture(stores: WebAuthnAuthenticatorListingStores): Promise<void> {
  await stores.authenticatorStore.put(
    WALLET_ID,
    testWebAuthnAuthenticatorRecord({
      credentialIdB64u: 'credential-iphone',
      counter: 4,
      createdAtMs: 1_000,
      updatedAtMs: 2_000,
      userAgent: WEBAUTHN_DEVICE_USER_AGENTS.safariOnIos,
      aaguid: ICLOUD_KEYCHAIN_AAGUID,
      backedUp: true,
      transports: ['internal', 'hybrid'],
    }),
  );
  await stores.credentialBindingStore.put(
    testWebAuthnCredentialBindingRecord({
      credentialIdB64u: 'credential-iphone',
      userId: WALLET_ID,
      rpId: RP_ID,
      signerSlot: 2,
    }),
  );

  await stores.authenticatorStore.put(
    WALLET_ID,
    testWebAuthnAuthenticatorRecord({
      credentialIdB64u: 'credential-macbook',
      createdAtMs: 3_000,
      updatedAtMs: 4_000,
      userAgent: WEBAUTHN_DEVICE_USER_AGENTS.chromeOnMacos,
      transports: ['internal'],
    }),
  );
  await stores.credentialBindingStore.put(
    testWebAuthnCredentialBindingRecord({
      credentialIdB64u: 'credential-macbook',
      userId: WALLET_ID,
      rpId: RP_ID,
      signerSlot: 3,
    }),
  );

  /* A row written before device capture existed: the column carries the '{}'
     default rather than a serialized record. */
  await stores.temporaryDatabase.database
    .prepare(
      `INSERT INTO webauthn_authenticators (
        namespace, org_id, project_id, env_id, user_id, credential_id_b64u,
        credential_public_key_b64u, counter, created_at_ms, updated_at_ms, device_info_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'seams-authenticator-listing-test',
      'org-a',
      'project-a',
      'env-a',
      WALLET_ID,
      'credential-legacy',
      'public-key-legacy',
      0,
      5_000,
      6_000,
      '{}',
    )
    .run();
  await stores.credentialBindingStore.put(
    testWebAuthnCredentialBindingRecord({
      credentialIdB64u: 'credential-legacy',
      userId: WALLET_ID,
      rpId: RP_ID,
      signerSlot: 4,
    }),
  );

  await stores.credentialBindingStore.put(
    testWebAuthnCredentialBindingRecord({
      credentialIdB64u: 'credential-unbacked',
      userId: WALLET_ID,
      rpId: RP_ID,
      signerSlot: 5,
      createdAtMs: 7_000,
      updatedAtMs: 8_000,
    }),
  );
}

test('canonical authenticator listing returns signer binding fields and parsed device metadata together', async () => {
  const stores = createWebAuthnAuthenticatorListingStores();
  try {
    await seedListingFixture(stores);

    const result = await listWebAuthnAuthenticatorsForUserWithStores({
      userId: WALLET_ID,
      rpId: RP_ID,
      authenticatorStore: stores.authenticatorStore,
      credentialBindingStore: stores.credentialBindingStore,
    });

    expect(result.ok).toBe(true);
    expect(result.authenticators).toEqual([
      {
        credentialIdB64u: 'credential-iphone',
        signerSlot: 2,
        publicKey: 'ed25519:public-credential-iphone',
        createdAtMs: 1_000,
        updatedAtMs: 2_000,
        device: {
          label: 'Safari on iOS',
          browser: 'safari',
          os: 'ios',
          synced: true,
          transports: ['internal', 'hybrid'],
          provider: 'icloud-keychain',
          providerLabel: 'iCloud Keychain',
        },
      },
      {
        credentialIdB64u: 'credential-macbook',
        signerSlot: 3,
        publicKey: 'ed25519:public-credential-macbook',
        createdAtMs: 3_000,
        updatedAtMs: 4_000,
        device: {
          label: 'Chrome on macOS',
          browser: 'chrome',
          os: 'macos',
          synced: false,
          transports: ['internal'],
        },
      },
      {
        credentialIdB64u: 'credential-legacy',
        signerSlot: 4,
        publicKey: 'ed25519:public-credential-legacy',
        createdAtMs: 5_000,
        updatedAtMs: 6_000,
        device: {
          label: 'Unknown device',
          browser: 'other',
          os: 'other',
          synced: false,
          transports: [],
        },
      },
      {
        credentialIdB64u: 'credential-unbacked',
        signerSlot: 5,
        publicKey: 'ed25519:public-credential-unbacked',
        createdAtMs: 7_000,
        updatedAtMs: 8_000,
        device: {
          label: 'Unknown device',
          browser: 'other',
          os: 'other',
          synced: false,
          transports: [],
        },
      },
    ]);
  } finally {
    cleanupTemporaryD1Database(stores.temporaryDatabase.tempDir);
  }
});

test('GET /webauthn/authenticators serves the metadata the service contract promises', async () => {
  const stores = createWebAuthnAuthenticatorListingStores();
  try {
    await seedListingFixture(stores);

    const service = {
      authorizationSessions: {
        tenantId: 'tenant-listing',
        async resolveOpaqueWalletSessionToken(input: { readonly curve: string }) {
          if (input.curve !== 'ecdsa') return null;
          return { authorization: { walletId: WALLET_ID } };
        },
      },
      webAuthn: {
        async listWebAuthnAuthenticatorsForUser(input: {
          readonly userId: string;
          readonly rpId?: string;
        }) {
          return await listWebAuthnAuthenticatorsForUserWithStores({
            userId: input.userId,
            rpId: String(input.rpId || ''),
            authenticatorStore: stores.authenticatorStore,
            credentialBindingStore: stores.credentialBindingStore,
          });
        },
      },
    } as unknown as RouterApiServiceBag;

    const url = new URL(`https://router.example.test/webauthn/authenticators?rpId=${RP_ID}`);
    const response = await handleWebAuthnAuthenticators({
      request: new Request(url, {
        method: 'GET',
        headers: { authorization: 'Bearer wallet-session-token' },
      }),
      url,
      pathname: '/webauthn/authenticators',
      method: 'GET',
      runtime: { kind: 'inline' },
      service,
      opts: {} as FetchRouterApiContext['opts'],
      logger: coerceRouterLogger(undefined),
      routeDefinitions: [],
    });

    expect(response?.status).toBe(200);
    const body = (await response?.json()) as {
      readonly ok: boolean;
      readonly authenticators: readonly {
        readonly credentialIdB64u: string;
        readonly signerSlot?: number;
        readonly publicKey?: string;
        readonly device: { readonly label: string; readonly synced: boolean };
      }[];
    };
    expect(body.ok).toBe(true);
    expect(
      body.authenticators.map((entry) => ({
        credentialIdB64u: entry.credentialIdB64u,
        signerSlot: entry.signerSlot,
        publicKey: entry.publicKey,
        label: entry.device.label,
        synced: entry.device.synced,
      })),
    ).toEqual([
      {
        credentialIdB64u: 'credential-iphone',
        signerSlot: 2,
        publicKey: 'ed25519:public-credential-iphone',
        label: 'Safari on iOS',
        synced: true,
      },
      {
        credentialIdB64u: 'credential-macbook',
        signerSlot: 3,
        publicKey: 'ed25519:public-credential-macbook',
        label: 'Chrome on macOS',
        synced: false,
      },
      {
        credentialIdB64u: 'credential-legacy',
        signerSlot: 4,
        publicKey: 'ed25519:public-credential-legacy',
        label: 'Unknown device',
        synced: false,
      },
      {
        credentialIdB64u: 'credential-unbacked',
        signerSlot: 5,
        publicKey: 'ed25519:public-credential-unbacked',
        label: 'Unknown device',
        synced: false,
      },
    ]);
  } finally {
    cleanupTemporaryD1Database(stores.temporaryDatabase.tempDir);
  }
});
