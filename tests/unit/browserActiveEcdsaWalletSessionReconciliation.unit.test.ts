import { expect, test } from '@playwright/test';
import { resolveBrowserActiveEcdsaWalletSessionAuthorization } from '@/SeamsWeb/assembly/browserSigningSurfaceAssembly';
import { createBrowserSigningStores } from '@/SeamsWeb/assembly/createBrowserSigningStores';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { IndexedDBManager } from '@/core/indexedDB';
import { IndexedDbEcdsaCapabilityManifestStore } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ActiveWalletSessionV1 } from '@shared/device-linking';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
} from '@shared/authorization/capabilityKinds';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { ecdsaCapabilityActivationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildPasskeyEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  buildPromotedActiveWalletSessionFixture,
  extendFixtureAuthorityWithEd25519Signer,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function resolvedSelection(input: {
  readonly fixture: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>;
  readonly authority: Awaited<ReturnType<typeof extendFixtureAuthorityWithEd25519Signer>>;
}) {
  return {
    kind: 'resolved' as const,
    selection: input.fixture.selection,
    authMethod: input.fixture.authMethod,
    authority: input.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

async function createResolverHarness() {
  const walletId = walletIdFromString('browser-ecdsa-promotion-wallet');
  const rpId = 'example.localhost';
  const credentialIdB64u = 'credential-passkey-fixture';
  const factorAuthority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u,
  });
  const factorAuthorityRef = await walletAuthAuthorityRef({ authority: factorAuthority });
  const chainTarget = {
    kind: 'evm' as const,
    namespace: 'eip155' as const,
    chainId: 1,
    networkSlug: 'ethereum',
  };
  const manifestLookup = ecdsaCapabilityActivationLookupFixture({
    authority: factorAuthorityRef,
    walletId,
    chainTarget,
  });
  const manifest = manifestLookup.manifest;
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'browser-ecdsa-promotion',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    keyFamily: 'ecdsa_secp256k1',
    materialActivation: manifest.activation.materialActivation,
    ecdsaSigner: {
      walletKeyId: 'wallet-key:browser-ecdsa-promotion',
      thresholdPublicKey33B64u: manifest.signer.registeredPublicFacts.publicKeyB64u,
      evmAddress: manifest.signer.registeredPublicFacts.thresholdOwnerAddress,
    },
    expiresAtMs: Date.now() + 5 * 60_000,
    identity: {
      walletId: String(walletId),
      authorityId: 'authority:browser-ecdsa-promotion',
      walletAuthMethodId: String(factorAuthority.bindingId),
      rpId,
      credentialIdB64u,
    },
  });
  const promotedAuthority = await extendFixtureAuthorityWithEd25519Signer(fixture.authority);
  const serverAuthorization = buildPromotedActiveWalletSessionFixture({
    source: fixture.activeWalletSession,
    authority: promotedAuthority,
  });
  const sealedRecord = buildPasskeyEcdsaSealedRuntimeRecordFixture({ manifest, chainTarget });
  const selected = resolvedSelection({ fixture, authority: promotedAuthority });
  const browserStores = createBrowserSigningStores(IndexedDBManager);
  const unusedPort = undefined as never;
  const context = {
    seamsWebConfigs: buildConfigsFromEnv({
      relayer: { url: 'https://relayer.example.test' },
      iframeWallet: { walletOrigin: 'https://wallet.example.test' },
    }),
    emailOtpSessions: unusedPort,
    touchIdPrompt: unusedPort,
    stores: browserStores.signingEngineStores,
    sealedSigningSessionStore: {
      ...browserStores.sealedSigningSessionStore,
      listExactSealedSessionsForWallet: async () => [sealedRecord],
    },
  } satisfies Parameters<typeof resolveBrowserActiveEcdsaWalletSessionAuthorization>[0];

  const manifestStorePrototype = IndexedDbEcdsaCapabilityManifestStore.prototype;
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalGetWalletAuthMethodV2 = IndexedDBManager.getWalletAuthMethodV2;
  const originalListWalletAuthMethodsForWallet = IndexedDBManager.listWalletAuthMethodsForWallet;
  const originalReadExact = walletSessionAuthorizations.readExactActiveForWallet;
  const originalReplaceExact = walletSessionAuthorizations.replaceExactActive;
  const originalListSubjects = manifestStorePrototype.listActiveWalletCapabilitySubjects;
  const originalLookup = manifestStorePrototype.lookup;
  const originalFetch = globalThis.fetch;
  let observedAuthorization = serverAuthorization;

  IndexedDBManager.resolveSelectedWalletAuthority = async () => selected;
  IndexedDBManager.getWalletAuthMethodV2 = async (walletAuthMethodId) =>
    walletAuthMethodId === fixture.authMethod.walletAuthMethodId ? fixture.authMethod : null;
  IndexedDBManager.listWalletAuthMethodsForWallet = async () => [fixture.authMethod];
  walletSessionAuthorizations.readExactActiveForWallet = async () => ({
    kind: 'found',
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  });
  walletSessionAuthorizations.replaceExactActive = async ({ active }) => active;
  manifestStorePrototype.listActiveWalletCapabilitySubjects = async () => ({
    kind: 'resolved',
    subjects: [
      {
        capability: manifest.signer.capability,
        authority: manifest.signer.authority,
        ecdsaThresholdKeyId: manifest.durableMaterial.roleLocalBinding.ecdsaThresholdKeyId,
      },
    ],
  });
  manifestStorePrototype.lookup = async () => manifestLookup;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        ok: true,
        status: 'active',
        walletSessionId: fixture.operationCredential.walletSessionId,
        quotaId: fixture.activeWalletSession.quotaId,
        remainingUses: 10,
        expiresAtMs: observedAuthorization.expiresAtMs,
        quotaLifecycle: 'active',
        authorization: observedAuthorization,
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );

  return {
    fixture,
    promotedAuthority,
    serverAuthorization,
    chainTarget,
    manifest,
    setObservedAuthorization(authorization: ActiveWalletSessionV1) {
      observedAuthorization = authorization;
    },
    async resolve(materialActivation = manifest.activation.materialActivation) {
      return await resolveBrowserActiveEcdsaWalletSessionAuthorization(context, {
        walletId,
        chainTarget,
        materialActivation,
      });
    },
    restore() {
      IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
      IndexedDBManager.getWalletAuthMethodV2 = originalGetWalletAuthMethodV2;
      IndexedDBManager.listWalletAuthMethodsForWallet = originalListWalletAuthMethodsForWallet;
      walletSessionAuthorizations.readExactActiveForWallet = originalReadExact;
      walletSessionAuthorizations.replaceExactActive = originalReplaceExact;
      manifestStorePrototype.listActiveWalletCapabilitySubjects = originalListSubjects;
      manifestStorePrototype.lookup = originalLookup;
      globalThis.fetch = originalFetch;
    },
  };
}

test('accepts the authenticated promoted server projection for the exact ECDSA resolver', async () => {
  const harness = await createResolverHarness();
  try {
    const result = await harness.resolve();

    if (result.kind !== 'active') {
      throw new Error(`expected promoted ECDSA authorization to be active: ${result.reason}`);
    }
    expect(harness.fixture.activeWalletSession.capabilitySubjects).toContainEqual(
      expect.objectContaining({ kind: 'sign', keyFamily: 'ecdsa_secp256k1' }),
    );
    expect(harness.fixture.activeWalletSession.capabilitySubjects).not.toContainEqual(
      expect.objectContaining({ keyFamily: 'ed25519' }),
    );
    expect(harness.serverAuthorization.capabilitySubjects).toContainEqual(
      expect.objectContaining({ kind: 'sign', keyFamily: 'ed25519' }),
    );
    expect(result.authorization.session).toEqual(harness.serverAuthorization);
    expect(result.authorization.selectedAuthority).toEqual(harness.promotedAuthority);
  } finally {
    harness.restore();
  }
});

test('rejects changed immutable session identity from the authenticated server projection', async () => {
  const harness = await createResolverHarness();
  const cases: readonly ActiveWalletSessionV1[] = [
    {
      ...harness.serverAuthorization,
      walletId: required(parseWalletId('browser-ecdsa-wrong-wallet')),
    },
    {
      ...harness.serverAuthorization,
      authorityId: required(parseWalletAuthorityId('authority:browser-ecdsa-wrong')),
    },
    {
      ...harness.serverAuthorization,
      authorizationId: required(
        parseWalletSessionAuthorizationId('authorization:browser-ecdsa-wrong'),
      ),
    },
    {
      ...harness.serverAuthorization,
      issuedAtMs: harness.serverAuthorization.issuedAtMs + 1,
    },
    {
      ...harness.serverAuthorization,
      expiresAtMs: harness.serverAuthorization.expiresAtMs + 1,
    },
  ];
  try {
    for (const authorization of cases) {
      harness.setObservedAuthorization(authorization);
      await expect(harness.resolve()).resolves.toMatchObject({ kind: 'inactive' });
    }
    harness.setObservedAuthorization({
      ...harness.serverAuthorization,
      quotaId: required(parseMpcWalletSigningQuotaId('wallet-quota:browser-ecdsa-wrong')),
    });
    await expect(harness.resolve()).rejects.toThrow('Wallet Session status response is invalid');
  } finally {
    harness.restore();
  }
});

test('rejects a server projection outside the freshly selected exact method and authority state', async () => {
  const harness = await createResolverHarness();
  const cases: readonly ActiveWalletSessionV1[] = [
    {
      ...harness.serverAuthorization,
      authMethodId: required(parseWalletAuthMethodId('auth-method:browser-ecdsa-wrong')),
    },
    {
      ...harness.serverAuthorization,
      authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(91))),
    },
    {
      ...harness.serverAuthorization,
      authorityRevocationEpoch: harness.promotedAuthority.revocationEpoch + 1,
    },
  ];
  try {
    for (const authorization of cases) {
      harness.setObservedAuthorization(authorization);
      await expect(harness.resolve()).resolves.toMatchObject({ kind: 'inactive' });
    }
  } finally {
    harness.restore();
  }
});

test('rejects an ECDSA activation other than the exact activation requested for signing', async () => {
  const harness = await createResolverHarness();
  try {
    const wrongActivation = buildMpcMaterialActivationRefFixture(
      'browser-ecdsa-wrong-request',
      String(harness.serverAuthorization.walletId),
    );

    await expect(harness.resolve(wrongActivation)).resolves.toMatchObject({ kind: 'inactive' });
  } finally {
    harness.restore();
  }
});
