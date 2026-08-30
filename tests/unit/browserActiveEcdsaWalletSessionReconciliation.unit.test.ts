import { expect, test } from '@playwright/test';
import {
  listBrowserEcdsaSigningCapabilitiesForWallet,
  readBrowserExactNearEd25519WalletSessionAuthorization,
  resolveBrowserActiveEcdsaWalletSessionAuthorization,
} from '@/SeamsWeb/assembly/browserSigningSurfaceAssembly';
import { persistExactWalletSessionAuthorizationFromEcdsaBootstrap } from '@/core/signingEngine/session/persistence/walletSessionAuthorizationProjection';
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
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

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
    context,
    fixture,
    walletId,
    promotedAuthority,
    serverAuthorization,
    chainTarget,
    manifest,
    factorAuthority,
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

test('persists an ECDSA bootstrap session with a promoted full authority', async () => {
  const harness = await createResolverHarness();
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: String(harness.walletId),
    chain: 'evm',
    sessionId: 'browser-ecdsa-promotion-bootstrap',
    expiresAtMs: harness.serverAuthorization.expiresAtMs,
  });
  const promotedBootstrap = {
    ...bootstrap,
    session: {
      ...bootstrap.session,
      authorizationId: harness.serverAuthorization.authorizationId,
      walletSessionId: harness.fixture.operationCredential.walletSessionId,
      quotaId: harness.serverAuthorization.quotaId,
      expiresAtMs: harness.serverAuthorization.expiresAtMs,
      walletSession: harness.serverAuthorization,
      operationCredential: harness.fixture.operationCredential,
    },
  };
  let writes = 0;
  const writer = {
    writeExactWithOperationCredential: async (
      input: Parameters<typeof walletSessionAuthorizations.writeExactWithOperationCredential>[0],
    ) => {
      writes += 1;
      return input.record;
    },
  };

  try {
    expect(harness.serverAuthorization.authorityDigestB64u).not.toBe(
      harness.manifest.signer.authority.authorityDigest,
    );
    await expect(
      persistExactWalletSessionAuthorizationFromEcdsaBootstrap(writer, {
        walletId: harness.walletId,
        authority: harness.manifest.signer.authority,
        bootstrap: {
          ...promotedBootstrap,
          session: {
            ...promotedBootstrap.session,
            operationCredential: {
              ...promotedBootstrap.session.operationCredential,
              walletSessionId: bootstrap.session.walletSessionId,
            },
          },
        },
      }),
    ).rejects.toThrow('ECDSA bootstrap exact Wallet Session authority does not match its request');
    expect(writes).toBe(0);
    await expect(
      persistExactWalletSessionAuthorizationFromEcdsaBootstrap(writer, {
        walletId: harness.walletId,
        authority: harness.manifest.signer.authority,
        bootstrap: promotedBootstrap,
      }),
    ).resolves.toEqual({
      record: harness.serverAuthorization,
      operationCredential: harness.fixture.operationCredential,
    });
    expect(writes).toBe(1);
  } finally {
    harness.restore();
  }
});

test('lists a promoted exact session when the full authority and factor digests differ', async () => {
  const harness = await createResolverHarness();
  try {
    expect(harness.promotedAuthority.authorityDigestB64u).not.toBe(
      harness.manifest.signer.authority.authorityDigest,
    );

    const capabilities = await listBrowserEcdsaSigningCapabilitiesForWallet(harness.context, {
      walletId: String(harness.walletId),
      chainTargets: [harness.chainTarget],
      authMethod: 'passkey',
    });

    expect(capabilities).toHaveLength(1);
    expect(capabilities[0]).toMatchObject({
      kind: 'authorized_evm_family_ecdsa_signing_capability',
    });
  } finally {
    harness.restore();
  }
});

test('resolves the promoted exact NEAR session from the selected factor method', async () => {
  const harness = await createResolverHarness();
  try {
    expect(harness.promotedAuthority.authorityDigestB64u).not.toBe(
      harness.manifest.signer.authority.authorityDigest,
    );

    const result = await readBrowserExactNearEd25519WalletSessionAuthorization(
      harness.walletId,
      'https://relayer.example.test',
    );

    expect(result.kind).toBe('found');
    if (result.kind !== 'found') throw new Error(`expected found, received ${result.kind}`);
    expect(result.authorization.selectedAuthority.authorityId).toBe(
      harness.promotedAuthority.authorityId,
    );
    expect(result.authorization.selectedAuthMethod.walletAuthMethodId).toBe(
      harness.fixture.authMethod.walletAuthMethodId,
    );
    expect(result.authorization.selectedFactorAuthority.bindingId).toBe(
      harness.factorAuthority.bindingId,
    );
    expect(result.authorization.session.authorizationId).toBe(
      harness.serverAuthorization.authorizationId,
    );
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
