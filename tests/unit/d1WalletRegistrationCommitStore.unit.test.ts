import { expect, test } from '@playwright/test';
import { D1WalletStore } from '../../packages/wallet-server/src/core/d1WalletStore';
import type {
  WalletEd25519SignerRecord,
  WalletEcdsaSignerRecord,
  WalletRecord,
} from '../../packages/wallet-server/src/core/WalletStore';
import { CloudflareD1WalletRegistrationCommitStore } from '../../packages/wallet-server/src/router/cloudflare/d1/registration/d1WalletRegistrationCommitStore';
import { CloudflareD1WalletAuthMethodService } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService';
import {
  D1WalletAuthMethodStore,
  prepareD1WalletAuthMethodV2PutStatement,
} from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import type { WalletSessionAuthorizationV2MintLookup } from '../../packages/wallet-server/src/authorization/domain';
import { CloudflareD1WebAuthnStore } from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import { D1WalletAuthorityStore } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { CloudflareD1EmailOtpEnrollmentStore } from '../../packages/wallet-server/src/router/cloudflare/d1/emailOtp/d1EmailOtpEnrollmentStore';
import type { D1EmailOtpRegistrationCommitPlan } from '../../packages/wallet-server/src/router/cloudflare/d1/emailOtp/d1EmailOtpRegistrationEnrollmentFinalizer';
import type { EmailOtpWalletEnrollmentRecord } from '../../packages/wallet-server/src/core/EmailOtpStores';
import type { D1DatabaseLike } from '../../packages/wallet-server/src/storage/tenantRoute';
import {
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionMintId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletKeyId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { buildFullOwnerPermissionsV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '../../packages/shared-ts/src/authorization/walletAuthority';
import { buildExactAdministeredSignerManifestV1 } from '../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
} from '../../packages/shared-ts/src/passkey-custody/primitives';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import {
  walletIdFromString,
  type RegistrationAuthority,
  type WalletId,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';

const TEST_SCOPE = {
  namespace: 'registration-commit-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

function testRpId() {
  const parsed = parseWebAuthnRpId('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function testWalletRecord(walletId: WalletId, now: number): WalletRecord {
  return {
    version: 'wallet_v1',
    walletId,
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function testEd25519Signer(walletId: WalletId, now: number): WalletEd25519SignerRecord {
  const nearAccountId = '0000000000000000000000000000000000000000000000000000000000000001';
  const runtimePolicyScope = {
    orgId: 'org-a',
    projectId: 'project-a',
    envId: 'env-a',
    signingRootVersion: 'root-v1',
  } as const;
  const activeYao = buildEd25519YaoCapabilityFixture({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    thresholdSessionId: 'threshold-session-1',
    signerSlot: 1,
    signingWorkerId: 'yao-signing-worker-a',
    participantIds: [1, 2],
    runtimePolicyScope,
    seed: 61,
  });
  return {
    version: 'wallet_signer_ed25519_v1',
    walletId,
    signerId: `ed25519:${nearAccountId}:1`,
    nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    thresholdSessionId: 'threshold-session-1',
    signerSlot: 1,
    publicKey: activeYao.publicKey,
    signingWorkerId: 'yao-signing-worker-a',
    keyVersion: 'yao-key-v1',
    recoveryExportCapable: true,
    participantIds: [1, 2],
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    runtimePolicyScope,
    activeYaoCapability: activeYao.capability,
    custodyKeyManifestDigestB64u: Buffer.alloc(32, 22).toString('base64url'),
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function testEcdsaSigner(walletId: WalletId, now: number): WalletEcdsaSignerRecord {
  return createWalletEcdsaSignerRecord({ walletId, now });
}

function requireTestParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
  return result.value;
}

async function testFoundingRecords(input: {
  readonly walletId: WalletId;
  readonly signer: WalletEcdsaSignerRecord;
  readonly now: number;
}): Promise<{
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly kind: 'passkey'; readonly status: 'active' }
  >;
}> {
  const walletKeyId = requireTestParsed(
    parseWalletKeyId(`wallet-key:ecdsa:${input.walletId}:ecdsa-slot-1`),
    'wallet key id',
  );
  const manifest = buildExactAdministeredSignerManifestV1([
    {
      kind: 'exact_administered_ecdsa_signer_v1',
      keyFamily: 'ecdsa_secp256k1',
      walletId: input.walletId,
      walletKeyId,
      thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
        input.signer.walletKey.thresholdEcdsaPublicKeyB64u,
      ),
      evmAddress: input.signer.walletKey.thresholdOwnerAddress,
    },
  ]);
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: routerAbMpcMaterialActivationRefFromWire(
        input.signer.walletKey.publicCapability.material_activation,
      ),
    },
  });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const authorityId = requireTestParsed(
    parseWalletAuthorityId('wallet-authority:registration-test'),
    'authority id',
  );
  const deviceId = requireTestParsed(parseDeviceId('device:registration-test'), 'device id');
  const authMethodId = requireTestParsed(
    parseWalletAuthMethodId('wallet-auth-method:registration-test'),
    'auth method id',
  );
  const permissions = buildFullOwnerPermissionsV1();
  const draft: ActiveWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId,
    walletId: input.walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: signerActivationSetDigestB64u,
    revocationEpoch: 0,
    createdAtMs: input.now,
    updatedAtMs: input.now,
    state: 'active',
    activatedAtMs: input.now,
  };
  const authority = buildActiveWalletAuthorityV1({
    ...draft,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authMethodId,
    walletId: input.walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: testRpId(),
    credentialIdB64u: requireTestParsed(
      parseWebAuthnCredentialIdB64u('credential-a'),
      'credential id',
    ),
    credentialPublicKeyB64u: 'credential-public-key-a',
    counter: 0,
    createdAtMs: input.now,
    updatedAtMs: input.now,
    activatedAtMs: input.now,
  });
  if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') {
    throw new Error('test auth method is not active passkey');
  }
  return { authority, authMethod };
}

function testSiblingAuthMethod(
  source: Extract<WalletAuthMethodRecordV2, { readonly kind: 'passkey'; readonly status: 'active' }>,
): Extract<WalletAuthMethodRecordV2, { readonly kind: 'passkey'; readonly status: 'active' }> {
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: requireTestParsed(
      parseWalletAuthMethodId('wallet-auth-method:registration-sibling'),
      'sibling auth method id',
    ),
    walletId: source.walletId,
    walletAuthorityId: source.walletAuthorityId,
    kind: 'passkey',
    status: 'active',
    rpId: source.rpId,
    credentialIdB64u: requireTestParsed(
      parseWebAuthnCredentialIdB64u('credential-sibling'),
      'sibling credential id',
    ),
    credentialPublicKeyB64u: 'credential-public-key-sibling',
    counter: 0,
    createdAtMs: source.createdAtMs,
    updatedAtMs: source.updatedAtMs,
    activatedAtMs: source.activatedAtMs,
  });
  if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') {
    throw new Error('sibling auth method is not active passkey');
  }
  return authMethod;
}

async function testCombinedFoundingAuthority(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly ed25519Signer: WalletEd25519SignerRecord;
  readonly now: number;
}): Promise<ActiveWalletAuthorityV1> {
  const existingEcdsa = input.authority.signerActivations.ecdsa;
  if (!existingEcdsa) throw new Error('test founding authority is missing ECDSA activation');
  const ed25519WalletKeyId = requireTestParsed(
    parseWalletKeyId(
      `wallet-key:ed25519:${input.authority.walletId}:${input.ed25519Signer.nearEd25519SigningKeyId}`,
    ),
    'Ed25519 wallet key id',
  );
  const ed25519SignerManifest = {
    kind: 'exact_administered_ed25519_signer_v1' as const,
    keyFamily: 'ed25519' as const,
    walletId: input.authority.walletId,
    walletKeyId: ed25519WalletKeyId,
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
      base64UrlEncode(
        Uint8Array.from(
          input.ed25519Signer.activeYaoCapability.activationResult.public_receipt
            .registered_public_key,
        ),
      ),
    ),
  };
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: buildExactAdministeredSignerManifestV1([ed25519SignerManifest, existingEcdsa.signer]),
    materialActivations: {
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      ed25519: routerAbMpcMaterialActivationRefFromWire(
        input.ed25519Signer.activeYaoCapability.activationResult.public_receipt.material_activation,
      ),
      ecdsa: existingEcdsa.materialActivation,
    },
  });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const draft: ActiveWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId: input.authority.authorityId,
    walletId: input.authority.walletId,
    principal: input.authority.principal,
    provenance: input.authority.provenance,
    permissions: input.authority.permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: input.authority.authorityDigestB64u,
    revocationEpoch: input.authority.revocationEpoch,
    createdAtMs: input.authority.createdAtMs,
    updatedAtMs: input.now,
    state: 'active',
    activatedAtMs: input.authority.activatedAtMs,
  };
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function testPasskeyAuthority(
  walletId: WalletId,
): Extract<RegistrationAuthority, { readonly kind: 'passkey' }> {
  return {
    kind: 'passkey',
    walletId,
    rpId: testRpId(),
    credentialIdB64u: requireTestParsed(
      parseWebAuthnCredentialIdB64u('credential-a'),
      'credential id',
    ),
    credentialPublicKeyB64u: 'credential-public-key-a',
    counter: 0,
    device: unknownWebAuthnAuthenticatorDeviceInfo(),
    registrationIntentDigestB64u: 'registration-intent-digest-a',
  };
}

class FirstMintReadMissAuthorizationGrantPort extends CloudflareD1AuthorizationStore {
  private firstMintRead = true;

  override async readWalletSessionAuthorizationV2ByMint(
    input: WalletSessionAuthorizationV2MintLookup,
  ) {
    if (this.firstMintRead) {
      this.firstMintRead = false;
      return null;
    }
    return await super.readWalletSessionAuthorizationV2ByMint(input);
  }
}

async function countRows(database: D1DatabaseLike, table: string): Promise<number> {
  const row = await database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{
    readonly count?: unknown;
  }>();
  return Number(row?.count || 0);
}

test('D1 registration commit binds the passkey credential before Ed25519 exists', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    // An ECDSA-only passkey wallet: the Ed25519 Yao ceremony has not settled.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, now),
      walletSigners: [testEcdsaSigner(walletId, now)],
      authority: testPasskeyAuthority(walletId),
      now,
    });

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(1);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(1);
    // The binding must exist, or the next passkey login fails unknown_credential.
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(1);
    const signerRow = await database
      .prepare('SELECT record_json FROM wallet_signers LIMIT 1')
      .first<{ readonly record_json?: unknown }>();
    const persistedSigner = JSON.parse(String(signerRow?.record_json)) as Record<string, unknown>;
    expect(persistedSigner).toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId,
      walletKey: { keyHandle: 'ecdsa-key-handle-1' },
    });
    expect(persistedSigner).not.toHaveProperty('evmFamilySigningKeySlotId');
    expect(persistedSigner).not.toHaveProperty('walletKey.evmFamilySigningKeySlotId');

    const webAuthnStore = new CloudflareD1WebAuthnStore({
      database,
      ...TEST_SCOPE,
    });
    const binding = await webAuthnStore.readBindingByCredential({
      rpId: testRpId(),
      credentialIdB64u: 'credential-a',
    });
    expect(binding).toMatchObject({
      userId: String(walletId),
      credentialIdB64u: 'credential-a',
    });
    // Ed25519 facts are absent as a set, not partially populated.
    expect(binding?.nearAccountId).toBeUndefined();
    expect(binding?.nearEd25519SigningKeyId).toBeUndefined();
    expect(binding?.signerSlot).toBeUndefined();
    expect(binding?.publicKey).toBeUndefined();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit writes the founding authority and V2 method atomically', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const signer = testEcdsaSigner(walletId, now);
    const founding = await testFoundingRecords({ walletId, signer, now });
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });
    const commitInput = () => ({
      kind: 'passkey_wallet_registration_commit_v1' as const,
      wallet: testWalletRecord(walletId, now),
      walletSigners: [signer],
      authority: testPasskeyAuthority(walletId),
      foundingAuthority: founding.authority,
      foundingAuthMethod: founding.authMethod,
      now,
    });

    await store.commit(commitInput());
    await store.commit(commitInput());

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_authorities')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(1);
    const authorityRow = await database
      .prepare('SELECT record_json FROM wallet_authorities LIMIT 1')
      .first<{ readonly record_json?: unknown }>();
    expect(JSON.parse(String(authorityRow?.record_json))).toMatchObject({
      kind: 'wallet_authority_v1',
      authorityId: 'wallet-authority:registration-test',
      state: 'active',
      provenance: { kind: 'wallet_registration' },
      revocationEpoch: 0,
    });
    const authMethodRow = await database
      .prepare('SELECT record_json FROM wallet_auth_methods LIMIT 1')
      .first<{ readonly record_json?: unknown }>();
    expect(JSON.parse(String(authMethodRow?.record_json))).toMatchObject({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: 'wallet-auth-method:registration-test',
      walletAuthorityId: 'wallet-authority:registration-test',
      status: 'active',
    });

    const conflicting = await testFoundingRecords({
      walletId,
      signer,
      now: now + 1,
    });
    await expect(
      store.commit({
        kind: 'passkey_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now + 1),
        walletSigners: [signer],
        authority: testPasskeyAuthority(walletId),
        foundingAuthority: conflicting.authority,
        foundingAuthMethod: conflicting.authMethod,
        now: now + 1,
      }),
    ).rejects.toThrow(/replay conflicts/);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('deferred mixed registration extends the persisted founding authority', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const createdAtMs = 1_900_000_000_000;
    const settledAtMs = createdAtMs + 4_000;
    const ecdsaSigner = testEcdsaSigner(walletId, createdAtMs);
    const founding = await testFoundingRecords({
      walletId,
      signer: ecdsaSigner,
      now: createdAtMs,
    });
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, createdAtMs),
      walletSigners: [ecdsaSigner],
      authority: testPasskeyAuthority(walletId),
      foundingAuthority: founding.authority,
      foundingAuthMethod: founding.authMethod,
      now: createdAtMs,
    });

    const walletAuthMethodStore = new D1WalletAuthMethodStore({
      database,
      ...TEST_SCOPE,
    });
    const walletAuthorityStore = new D1WalletAuthorityStore({
      database,
      ...TEST_SCOPE,
    });
    const walletAuthMethods = new CloudflareD1WalletAuthMethodService({
      getWalletAuthMethodStore: () => walletAuthMethodStore,
      walletAuthorityStore,
    } as never);
    await expect(
      walletAuthMethods.readActiveRegistrationIdentity(testPasskeyAuthority(walletId)),
    ).resolves.toEqual({
      walletAuthorityId: founding.authority.authorityId,
      walletAuthMethodId: founding.authMethod.walletAuthMethodId,
      authority: founding.authority,
      authMethod: founding.authMethod,
    });

    const ed25519Signer = testEd25519Signer(walletId, settledAtMs);
    const combinedAuthority = await testCombinedFoundingAuthority({
      authority: founding.authority,
      ed25519Signer,
      now: settledAtMs,
    });
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, settledAtMs),
      walletSigners: [ed25519Signer],
      authority: testPasskeyAuthority(walletId),
      foundingAuthority: combinedAuthority,
      foundingAuthMethod: founding.authMethod,
      now: settledAtMs,
    });
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, settledAtMs),
      walletSigners: [ed25519Signer],
      authority: testPasskeyAuthority(walletId),
      foundingAuthority: combinedAuthority,
      foundingAuthMethod: founding.authMethod,
      now: settledAtMs,
    });
    await expect(countRows(database, 'wallet_authorities')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(2);
    const persisted = await walletAuthorityStore.readById(combinedAuthority.authorityId);
    expect(persisted).toEqual(combinedAuthority);
    expect(persisted?.signerActivations.keyFamilies).toEqual(['ed25519', 'ecdsa_secp256k1']);
    expect(persisted?.signerActivations.ecdsa).toEqual(founding.authority.signerActivations.ecdsa);
    expect(persisted?.signerActivations.ed25519).toEqual(
      combinedAuthority.signerActivations.ed25519,
    );
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('deferred authority promotion refreshes sibling sessions before fresh issuance', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const createdAtMs = 1_900_000_000_000;
    const settledAtMs = createdAtMs + 4_000;
    const tenantId = requireTestParsed(
      parseTenantId('tenant:registration-promotion'),
      'promotion tenant id',
    );
    const principalId = requireTestParsed(
      parsePrincipalId('principal:registration-promotion'),
      'promotion principal id',
    );
    const ecdsaSigner = testEcdsaSigner(walletId, createdAtMs);
    const founding = await testFoundingRecords({
      walletId,
      signer: ecdsaSigner,
      now: createdAtMs,
    });
    const registrationStore = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });
    await registrationStore.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, createdAtMs),
      walletSigners: [ecdsaSigner],
      authority: testPasskeyAuthority(walletId),
      foundingAuthority: founding.authority,
      foundingAuthMethod: founding.authMethod,
      now: createdAtMs,
    });

    const siblingAuthMethod = testSiblingAuthMethod(founding.authMethod);
    await prepareD1WalletAuthMethodV2PutStatement({
      database,
      scope: TEST_SCOPE,
      record: siblingAuthMethod,
      insertOnly: true,
    }).run();
    const authorizationStore = new CloudflareD1AuthorizationStore({
      database,
      namespace: TEST_SCOPE.namespace,
      walletSignerScope: TEST_SCOPE,
    });
    const authorizationService = new AuthorizationService({
      policy: capabilityPolicyPort,
      sessions: authorizationStore,
      evidence: authorizationStore,
      grants: authorizationStore,
      authorizedOperations: authorizationStore,
      audit: authorizationStore,
    });
    const initiating = await authorizationService.issueDirectWalletSessionAuthorizationV2({
      tenantId,
      principalId,
      walletId,
      authority: founding.authority,
      walletAuthMethodId: founding.authMethod.walletAuthMethodId,
      mintId: requireTestParsed(
        parseWalletSessionMintId('mint:registration-promotion-initiating'),
        'initiating promotion mint id',
      ),
      remainingUses: 3,
      issuedAtMs: createdAtMs + 100,
      expiresAtMs: createdAtMs + 10_000,
    });
    const sibling = await authorizationService.issueDirectWalletSessionAuthorizationV2({
      tenantId,
      principalId,
      walletId,
      authority: founding.authority,
      walletAuthMethodId: siblingAuthMethod.walletAuthMethodId,
      mintId: requireTestParsed(
        parseWalletSessionMintId('mint:registration-promotion-sibling'),
        'sibling promotion mint id',
      ),
      remainingUses: 3,
      issuedAtMs: createdAtMs + 100,
      expiresAtMs: createdAtMs + 10_000,
    });
    if (initiating.kind !== 'issued' || sibling.kind !== 'issued') {
      throw new Error('promotion session fixture did not issue both methods');
    }
    const hashesBefore = await database
      .prepare(
        `SELECT wallet_session_id, authorization_id, quota_id, operation_credential_hash
           FROM wallet_session_authorizations_v2
          WHERE namespace = ?
            AND wallet_session_id IN (?, ?)
          ORDER BY wallet_session_id`,
      )
      .bind(
        TEST_SCOPE.namespace,
        String(initiating.session.walletSessionId),
        String(sibling.session.walletSessionId),
      )
      .all();

    const combinedAuthority = await testCombinedFoundingAuthority({
      authority: founding.authority,
      ed25519Signer: testEd25519Signer(walletId, settledAtMs),
      now: settledAtMs,
    });
    await registrationStore.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, settledAtMs),
      walletSigners: [testEd25519Signer(walletId, settledAtMs)],
      authority: testPasskeyAuthority(walletId),
      foundingAuthority: combinedAuthority,
      foundingAuthMethod: founding.authMethod,
      now: settledAtMs,
    });

    const promotedReplayInput = {
      tenantId,
      principalId,
      walletId,
      authority: combinedAuthority,
      walletAuthMethodId: founding.authMethod.walletAuthMethodId,
      mintId: initiating.session.mintId,
      remainingUses: 99,
      issuedAtMs: settledAtMs + 100,
      expiresAtMs: settledAtMs + 20_000,
    };
    await expect(
      authorizationService.issueDirectWalletSessionAuthorizationV2(promotedReplayInput),
    ).rejects.toThrow('Direct V2 Wallet Session mint replay does not match');
    const promotedReplay =
      await authorizationService.issueDirectRegistrationPromotedWalletSessionAuthorizationV2(
        promotedReplayInput,
      );
    expect(promotedReplay).toEqual({
      kind: 'already_committed',
      walletId: initiating.session.walletId,
      authorityId: initiating.session.authorityId,
      walletAuthMethodId: initiating.session.walletAuthMethodId,
      mintId: initiating.session.mintId,
      authorizationId: initiating.session.authorizationId,
      walletSessionId: initiating.session.walletSessionId,
      quotaId: initiating.session.quotaId,
      next: 'unlock_exact_method',
    });
    expect(promotedReplay).not.toHaveProperty('operationCredential');

    const racedAuthorizationStore = new FirstMintReadMissAuthorizationGrantPort({
      database,
      namespace: TEST_SCOPE.namespace,
      walletSignerScope: TEST_SCOPE,
    });
    const racedReplayService = new AuthorizationService({
      policy: capabilityPolicyPort,
      sessions: racedAuthorizationStore,
      evidence: racedAuthorizationStore,
      grants: racedAuthorizationStore,
      authorizedOperations: racedAuthorizationStore,
      audit: racedAuthorizationStore,
    });
    const racedReplay =
      await racedReplayService.issueDirectRegistrationPromotedWalletSessionAuthorizationV2(
        promotedReplayInput,
      );
    expect(racedReplay).toEqual(promotedReplay);
    expect(racedReplay).not.toHaveProperty('operationCredential');

    const refreshedInitiating =
      await authorizationService.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId,
        token: initiating.operationCredential.token,
        nowMs: settledAtMs + 1,
      });
    const refreshedSibling =
      await authorizationService.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId,
        token: sibling.operationCredential.token,
        nowMs: settledAtMs + 1,
      });
    expect(refreshedInitiating?.session).toMatchObject({
      authorizationId: initiating.session.authorizationId,
      walletSessionId: initiating.session.walletSessionId,
      quotaId: initiating.session.quotaId,
      createdAtMs: initiating.session.createdAtMs,
      expiresAtMs: initiating.session.expiresAtMs,
      authorityDigestB64u: combinedAuthority.authorityDigestB64u,
      authorityRevocationEpoch: combinedAuthority.revocationEpoch,
    });
    expect(refreshedSibling?.session).toMatchObject({
      authorizationId: sibling.session.authorizationId,
      walletSessionId: sibling.session.walletSessionId,
      quotaId: sibling.session.quotaId,
      authorityDigestB64u: combinedAuthority.authorityDigestB64u,
      authorityRevocationEpoch: combinedAuthority.revocationEpoch,
    });
    const hashesAfter = await database
      .prepare(
        `SELECT wallet_session_id, authorization_id, quota_id, operation_credential_hash
           FROM wallet_session_authorizations_v2
          WHERE namespace = ?
            AND wallet_session_id IN (?, ?)
          ORDER BY wallet_session_id`,
      )
      .bind(
        TEST_SCOPE.namespace,
        String(initiating.session.walletSessionId),
        String(sibling.session.walletSessionId),
      )
      .all();
    expect(hashesAfter.results).toEqual(hashesBefore.results);

    const fresh = await authorizationService.issueDirectWalletSessionAuthorizationV2({
      tenantId,
      principalId,
      walletId,
      authority: combinedAuthority,
      walletAuthMethodId: founding.authMethod.walletAuthMethodId,
      mintId: requireTestParsed(
        parseWalletSessionMintId('mint:registration-promotion-fresh'),
        'fresh promotion mint id',
      ),
      remainingUses: 3,
      issuedAtMs: settledAtMs + 1,
      expiresAtMs: settledAtMs + 10_000,
    });
    expect(fresh.kind).toBe('issued');
    const siblingAfterFresh =
      await authorizationService.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId,
        token: sibling.operationCredential.token,
        nowMs: settledAtMs + 2,
      });
    expect(siblingAfterFresh?.session.authorityDigestB64u).toBe(
      combinedAuthority.authorityDigestB64u,
    );
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 founding authority commit rolls back on a signer constraint failure', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('brisk-bloom-abcdef');
    const now = 1_900_000_000_000;
    const signer = testEcdsaSigner(walletId, now);
    const founding = await testFoundingRecords({ walletId, signer, now });
    const invalidSigner = { ...signer, updatedAtMs: now - 1 };
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await expect(
      store.commit({
        kind: 'passkey_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now),
        walletSigners: [invalidSigner],
        authority: testPasskeyAuthority(walletId),
        foundingAuthority: founding.authority,
        foundingAuthMethod: founding.authMethod,
        now,
      }),
    ).rejects.toThrow(/CHECK constraint failed/);
    await expect(countRows(database, 'wallets')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_authorities')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit stores a mixed Ed25519 and ECDSA wallet atomically', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, now),
      walletSigners: [testEd25519Signer(walletId, now), testEcdsaSigner(walletId, now)],
      authority: testPasskeyAuthority(walletId),
      now,
    });

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(2);
    const walletStore = new D1WalletStore({
      database,
      ...TEST_SCOPE,
      ensureSchema: false,
    });
    await expect(walletStore.listEd25519Signers()).resolves.toMatchObject([
      {
        walletId,
        activeYaoCapability: {
          version: 'wallet_ed25519_yao_registration_capability_v1',
          nearAccountId: '0000000000000000000000000000000000000000000000000000000000000001',
        },
      },
    ]);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(1);
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(1);

    const webAuthnStore = new CloudflareD1WebAuthnStore({
      database,
      ...TEST_SCOPE,
    });
    await expect(
      webAuthnStore.readAuthenticator({
        userId: walletId,
        credentialIdB64u: 'credential-a',
      }),
    ).resolves.toMatchObject({
      credentialIdB64u: 'credential-a',
      credentialPublicKeyB64u: 'credential-public-key-a',
      counter: 0,
    });

    const bindingRow = await database
      .prepare('SELECT record_json FROM webauthn_credential_bindings LIMIT 1')
      .first<{ readonly record_json?: unknown }>();
    expect(JSON.parse(String(bindingRow?.record_json))).toMatchObject({
      version: 'webauthn_credential_binding_v1',
      rpId: 'example.com',
      credentialIdB64u: 'credential-a',
      userId: walletId,
      nearEd25519SigningKeyId: 'near-ed25519-key-1',
      signerSlot: 1,
      relayerKeyId: 'yao-signing-worker-a',
      participantIds: [1, 2],
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit rolls back every mixed-wallet record when one signer fails', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('brisk-bloom-abcdef');
    const now = 1_900_000_000_000;
    // Deliberately corrupt valid factory output: updatedAtMs earlier than
    // createdAtMs violates the wallet_signers CHECK (updated_at_ms >= created_at_ms).
    const invalidEcdsaSigner = {
      ...createWalletEcdsaSignerRecord({ walletId, now }),
      updatedAtMs: now - 1,
    };
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await expect(
      store.commit({
        kind: 'passkey_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now),
        walletSigners: [testEd25519Signer(walletId, now), invalidEcdsaSigner],
        authority: testPasskeyAuthority(walletId),
        now,
      }),
    ).rejects.toThrow(/CHECK constraint failed/);

    await expect(countRows(database, 'wallets')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(0);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(0);
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

function testEmailOtpAuthority(
  walletId: WalletId,
): Extract<RegistrationAuthority, { readonly kind: 'email_otp' }> {
  return {
    kind: 'email_otp',
    walletId,
    emailHashHex: 'a'.repeat(64),
    registrationAuthorityId: 'registration-authority-a',
  } as Extract<RegistrationAuthority, { readonly kind: 'email_otp' }>;
}

function testEnrollmentRecord(walletId: WalletId, now: number): EmailOtpWalletEnrollmentRecord {
  return {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: String(walletId),
    providerUserId: 'provider-user-a',
    orgId: TEST_SCOPE.orgId,
    verifiedEmail: 'registrant@example.com',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'v1',
    enrollmentSealKeyVersion: 'seal-v1',
    clientUnlockPublicKeyB64u: 'client-unlock-public-key-a',
    unlockKeyVersion: 'unlock-v1',
    serverSealedFactorCiphertextB64u: 'server-sealed-factor-ciphertext-a',
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function scopedPrepare(database: D1DatabaseLike) {
  return (sql: string, values: readonly unknown[]) =>
    database
      .prepare(sql)
      .bind(
        TEST_SCOPE.namespace,
        TEST_SCOPE.orgId,
        TEST_SCOPE.projectId,
        TEST_SCOPE.envId,
        ...values,
      );
}

function emailOtpCommitPlan(
  database: D1DatabaseLike,
  walletId: WalletId,
  now: number,
): D1EmailOtpRegistrationCommitPlan {
  const enrollments = new CloudflareD1EmailOtpEnrollmentStore({ prepare: scopedPrepare(database) });
  return {
    kind: 'd1_email_otp_registration_commit_plan_v1',
    statements: [enrollments.preparePutEnrollmentStatement(testEnrollmentRecord(walletId, now))],
  };
}

test('D1 registration commit stores the Email OTP enrollment in the wallet batch', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({ database, ...TEST_SCOPE });

    await store.commit({
      kind: 'email_otp_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, now),
      walletSigners: [testEd25519Signer(walletId, now)],
      authority: testEmailOtpAuthority(walletId),
      emailOtp: emailOtpCommitPlan(database, walletId, now),
      now,
    });

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(1);
    await expect(countRows(database, 'email_otp_wallet_enrollments')).resolves.toBe(1);
    const enrollments = new CloudflareD1EmailOtpEnrollmentStore({
      prepare: scopedPrepare(database),
    });
    await expect(enrollments.readEnrollment(String(walletId))).resolves.toMatchObject({
      walletId: String(walletId),
      verifiedEmail: 'registrant@example.com',
      providerUserId: 'provider-user-a',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit rolls back the wallet when the Email OTP statement fails', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({ database, ...TEST_SCOPE });

    await expect(
      store.commit({
        kind: 'email_otp_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now),
        walletSigners: [testEd25519Signer(walletId, now)],
        authority: testEmailOtpAuthority(walletId),
        emailOtp: {
          kind: 'd1_email_otp_registration_commit_plan_v1',
          statements: [
            database
              .prepare('INSERT INTO email_otp_wallet_enrollments (namespace) VALUES (?)')
              .bind('only-namespace'),
          ],
        },
        now,
      }),
    ).rejects.toThrow();

    // A visible wallet without its enrollment is the half-applied state the
    // single batch exists to prevent.
    await expect(countRows(database, 'wallets')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(0);
    await expect(countRows(database, 'email_otp_wallet_enrollments')).resolves.toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('re-running the Email OTP registration commit converges instead of duplicating', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({ database, ...TEST_SCOPE });
    const commitInput = () =>
      ({
        kind: 'email_otp_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now),
        walletSigners: [testEd25519Signer(walletId, now)],
        authority: testEmailOtpAuthority(walletId),
        emailOtp: emailOtpCommitPlan(database, walletId, now),
        now,
      }) as const;

    await store.commit(commitInput());
    // A finalize interrupted after the batch re-runs it on retry; every
    // statement is an upsert, so the retry must converge rather than duplicate.
    await store.commit(commitInput());

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(1);
    await expect(countRows(database, 'email_otp_wallet_enrollments')).resolves.toBe(1);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/*
 * Refactor 94 Phase 4+5. A wallet planned with both signers commits twice: the
 * ECDSA commit makes it usable, the Ed25519 commit lands when the Yao ceremony
 * settles. Both write the credential binding, so the second write must
 * converge the Ed25519 facts onto the first without rewriting its history.
 *
 * Reads parse `record_json`, not the columns, so the upsert has to reconcile
 * the timestamps inside the JSON too — the columns alone being correct is what
 * made this survivable but wrong.
 */
test('the second credential binding write converges without rewriting history', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const createdAtMs = 1_900_000_000_000;
    const settledAtMs = createdAtMs + 4_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });
    const webAuthnStore = new CloudflareD1WebAuthnStore({ database, ...TEST_SCOPE });
    const readBinding = async () =>
      webAuthnStore.readBindingByCredential({
        rpId: testRpId(),
        credentialIdB64u: 'credential-a',
      });

    // Commit #1: ECDSA only. The wallet is usable; Ed25519 has not settled.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, createdAtMs),
      walletSigners: [testEcdsaSigner(walletId, createdAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: createdAtMs,
    });
    const afterEcdsa = await readBinding();
    expect(afterEcdsa?.createdAtMs).toBe(createdAtMs);
    expect(afterEcdsa?.nearAccountId).toBeUndefined();

    // Commit #2: the Ed25519 signer alone, as the deferred finalize sends it.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, settledAtMs),
      walletSigners: [testEd25519Signer(walletId, settledAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: settledAtMs,
    });
    const afterEd25519 = await readBinding();
    // The Ed25519 facts arrive as a set.
    expect(afterEd25519?.nearAccountId).toBe(
      testEd25519Signer(walletId, settledAtMs).nearAccountId,
    );
    expect(afterEd25519?.signerSlot).toBe(testEd25519Signer(walletId, settledAtMs).signerSlot);
    // The wallet's creation history is not rewritten by the later commit.
    expect(afterEd25519?.createdAtMs).toBe(createdAtMs);
    expect(afterEd25519?.updatedAtMs).toBe(settledAtMs);

    // An exact replay of commit #2 changes nothing.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, settledAtMs),
      walletSigners: [testEd25519Signer(walletId, settledAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: settledAtMs,
    });
    await expect(readBinding()).resolves.toEqual(afterEd25519);

    // An out-of-order replay of commit #1 must not regress the update stamp
    // nor drop the Ed25519 facts that commit #2 established.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, createdAtMs),
      walletSigners: [testEcdsaSigner(walletId, createdAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: createdAtMs,
    });
    const afterStaleReplay = await readBinding();
    expect(afterStaleReplay?.createdAtMs).toBe(createdAtMs);
    expect(afterStaleReplay?.updatedAtMs).toBe(settledAtMs);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
