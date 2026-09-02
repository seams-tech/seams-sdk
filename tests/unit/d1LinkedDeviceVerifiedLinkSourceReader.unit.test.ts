import { expect, test } from '@playwright/test';
import type {
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
} from '../../packages/wallet-server/src/core/WalletStore';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '../../packages/shared-ts/src/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  parseDeviceId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletKeyId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { buildExactAdministeredSignerManifestV1 } from '../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
} from '../../packages/wallet-server/src/authorization/domain';
import { createD1LinkedDeviceVerifiedLinkSourceReaderV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceVerifiedLinkSourceReader';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function createWalletEd25519SignerRecord(
  walletId: ActiveWalletAuthorityV1['walletId'],
  now: number,
): WalletEd25519SignerRecord {
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

async function buildCombinedSourceAuthority(input: {
  readonly walletId: ActiveWalletAuthorityV1['walletId'];
  readonly ecdsaSigner: WalletEcdsaSignerRecord;
  readonly ed25519Signer: WalletEd25519SignerRecord;
  readonly now: number;
}): Promise<ActiveWalletAuthorityV1> {
  const ecdsaWalletKeyId = required(
    parseWalletKeyId(
      `wallet-key:ecdsa:${input.walletId}:${deriveEvmFamilySigningKeySlotId({
        walletId: input.ecdsaSigner.walletId,
        signingRootId: input.ecdsaSigner.walletKey.signingRootId,
        signingRootVersion: input.ecdsaSigner.walletKey.signingRootVersion,
      })}`,
    ),
  );
  const ed25519WalletKeyId = required(
    parseWalletKeyId(
      `wallet-key:ed25519:${input.walletId}:${input.ed25519Signer.nearEd25519SigningKeyId}`,
    ),
  );
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: buildExactAdministeredSignerManifestV1([
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: String(input.walletId),
        walletKeyId: ed25519WalletKeyId,
        registeredPublicKeyB64u: base64UrlEncode(
          Uint8Array.from(
            input.ed25519Signer.activeYaoCapability.activationResult.public_receipt
              .registered_public_key,
          ),
        ),
      },
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId: String(input.walletId),
        walletKeyId: ecdsaWalletKeyId,
        thresholdPublicKey33B64u: input.ecdsaSigner.walletKey.thresholdEcdsaPublicKeyB64u,
        evmAddress: input.ecdsaSigner.walletKey.thresholdOwnerAddress,
      },
    ]),
    materialActivations: {
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      ed25519: routerAbMpcMaterialActivationRefFromWire(
        input.ed25519Signer.activeYaoCapability.activationResult.public_receipt.material_activation,
      ),
      ecdsa: routerAbMpcMaterialActivationRefFromWire(
        input.ecdsaSigner.walletKey.publicCapability.material_activation,
      ),
    },
  });
  const signerActivationSetDigestB64u = parseDigestB64u(
    await computeWalletSignerActivationSetDigestB64u(signerActivations),
  );
  const authorityId = required(parseWalletAuthorityId('wallet-authority:source-reader-combined'));
  const deviceId = required(parseDeviceId('device:source-reader-combined'));
  const authorityDraft = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId: input.walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: signerActivationSetDigestB64u,
    revocationEpoch: 0,
    createdAtMs: input.now,
    updatedAtMs: input.now,
    state: 'active',
    activatedAtMs: input.now,
  });
  return buildActiveWalletAuthorityV1({
    kind: authorityDraft.kind,
    authorityId: authorityDraft.authorityId,
    walletId: authorityDraft.walletId,
    principal: authorityDraft.principal,
    provenance: authorityDraft.provenance,
    permissions: authorityDraft.permissions,
    signerActivations: authorityDraft.signerActivations,
    signerActivationSetDigestB64u: authorityDraft.signerActivationSetDigestB64u,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityDraft),
    revocationEpoch: authorityDraft.revocationEpoch,
    createdAtMs: authorityDraft.createdAtMs,
    updatedAtMs: authorityDraft.updatedAtMs,
    state: authorityDraft.state,
    activatedAtMs: authorityDraft.activatedAtMs,
  });
}

test('accepts duplicate ECDSA signer rows for one wallet-wide source identity', async () => {
  const walletId = required(parseWalletId('wallet:source-reader'));
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 100 });
  const tempoSigner = createWalletEcdsaSignerRecord({
    walletId,
    now: 100,
    walletKeyOverrides: {
      chainTarget: { kind: 'tempo', chainId: 42431 },
    },
  });
  const walletKeyId = required(
    parseWalletKeyId(
      `wallet-key:ecdsa:${walletId}:${deriveEvmFamilySigningKeySlotId({
        walletId: signer.walletId,
        signingRootId: signer.walletKey.signingRootId,
        signingRootVersion: signer.walletKey.signingRootVersion,
      })}`,
    ),
  );
  const signerManifest = buildExactAdministeredSignerManifestV1([
    {
      kind: 'exact_administered_ecdsa_signer_v1',
      keyFamily: 'ecdsa_secp256k1',
      walletId: String(walletId),
      walletKeyId,
      thresholdPublicKey33B64u: signer.walletKey.thresholdEcdsaPublicKeyB64u,
      evmAddress: signer.walletKey.thresholdOwnerAddress,
    },
  ]);
  const materialActivation = routerAbMpcMaterialActivationRefFromWire(
    signer.walletKey.publicCapability.material_activation,
  );
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: signerManifest,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: materialActivation,
    },
  });
  const signerActivationSetDigestB64u = parseDigestB64u(
    await computeWalletSignerActivationSetDigestB64u(signerActivations),
  );
  const authorityId = required(parseWalletAuthorityId('wallet-authority:source-reader'));
  const deviceId = required(parseDeviceId('device:source-reader'));
  const authorityDraft = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: signerActivationSetDigestB64u,
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  });
  const authority = buildActiveWalletAuthorityV1({
    kind: authorityDraft.kind,
    authorityId: authorityDraft.authorityId,
    walletId: authorityDraft.walletId,
    principal: authorityDraft.principal,
    provenance: authorityDraft.provenance,
    permissions: authorityDraft.permissions,
    signerActivations: authorityDraft.signerActivations,
    signerActivationSetDigestB64u: authorityDraft.signerActivationSetDigestB64u,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityDraft),
    revocationEpoch: authorityDraft.revocationEpoch,
    createdAtMs: authorityDraft.createdAtMs,
    updatedAtMs: authorityDraft.updatedAtMs,
    state: authorityDraft.state,
    activatedAtMs: authorityDraft.activatedAtMs,
  });
  const walletAuthMethodId = required(parseWalletAuthMethodId('wallet-auth-method:source-reader'));
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: required(parseWebAuthnRpId('source-reader.example.test')),
    credentialIdB64u: required(
      parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(7))),
    ),
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(9)),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
  const tenantId = required(parseTenantId('tenant:source-reader'));
  const principalId = required(parsePrincipalId('principal:source-reader'));
  const walletSessionId = required(parseWalletSessionId('wallet-session:source-reader'));
  const authorizationId = required(
    parseWalletSessionAuthorizationId('wallet-session-authorization:source-reader'),
  );
  const quotaId = required(parseMpcWalletSigningQuotaId('mpc-wallet-signing-quota:source-reader'));
  const mintId = required(parseWalletSessionMintId('wallet-session-mint:source-reader'));
  const session = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId,
    authorityId,
    walletAuthMethodId,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    mintId,
    authorizationId,
    walletSessionId,
    quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    createdAtMs: 300,
    expiresAtMs: 10_000,
  });
  const quota = buildActiveWalletSessionQuota({
    tenantId,
    principalId,
    walletSessionId,
    quotaId,
    remainingUses: 3,
    expiresAtMs: 10_000,
  });
  let exactSessionAvailable = true;
  const reader = createD1LinkedDeviceVerifiedLinkSourceReaderV1({
    authorizationService: {
      readWalletSessionAuthorizationV2ByIdentity: async () =>
        exactSessionAvailable ? { session, quota } : null,
    },
    authorityStore: { readById: async () => authority },
    authMethodStore: { readByIdV2: async () => authMethod },
    walletStore: {
      listEd25519SignersForWallet: async () => [],
      listEcdsaSignersForWallet: async () => [signer, tempoSigner],
    },
    tenantId,
  });

  const sourceRequest = {
    walletId,
    walletSessionId: String(walletSessionId),
    authorizationId: String(authorizationId),
    keyFamily: 'ecdsa_secp256k1' as const,
    requestedAtMs: 4_000,
  };
  const source = await reader.readVerifiedSourceV1(sourceRequest);

  expect(source.keyManifestDigestB64u).toBe(parseDigestB64u(signer.custodyKeyManifestDigestB64u));
  exactSessionAvailable = false;
  await expect(reader.readVerifiedSourceV1(sourceRequest)).rejects.toThrow(
    'source exact Wallet Session is unavailable',
  );
});

test('exposes both exact key families from a combined deferred source authority', async () => {
  const walletId = required(parseWalletId('wallet:source-reader-combined'));
  const now = 100;
  const ecdsaSigner = createWalletEcdsaSignerRecord({ walletId, now });
  const ed25519Signer = createWalletEd25519SignerRecord(walletId, now);
  const authority = await buildCombinedSourceAuthority({
    walletId,
    ecdsaSigner,
    ed25519Signer,
    now,
  });
  const walletAuthMethodId = required(
    parseWalletAuthMethodId('wallet-auth-method:source-reader-combined'),
  );
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId,
    walletAuthorityId: authority.authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: required(parseWebAuthnRpId('source-reader-combined.example.test')),
    credentialIdB64u: required(
      parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(8))),
    ),
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(10)),
    counter: 0,
    createdAtMs: now,
    updatedAtMs: now,
    activatedAtMs: now,
  });
  const tenantId = required(parseTenantId('tenant:source-reader-combined'));
  const principalId = required(parsePrincipalId('principal:source-reader-combined'));
  const walletSessionId = required(parseWalletSessionId('wallet-session:source-reader-combined'));
  const authorizationId = required(
    parseWalletSessionAuthorizationId('wallet-session-authorization:source-reader-combined'),
  );
  const quotaId = required(
    parseMpcWalletSigningQuotaId('mpc-wallet-signing-quota:source-reader-combined'),
  );
  const mintId = required(
    parseWalletSessionMintId('wallet-session-mint:source-reader-combined'),
  );
  const session = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId,
    authorityId: authority.authorityId,
    walletAuthMethodId,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    mintId,
    authorizationId,
    walletSessionId,
    quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    createdAtMs: now + 100,
    expiresAtMs: 10_000,
  });
  const quota = buildActiveWalletSessionQuota({
    tenantId,
    principalId,
    walletSessionId,
    quotaId,
    remainingUses: 3,
    expiresAtMs: 10_000,
  });
  const reader = createD1LinkedDeviceVerifiedLinkSourceReaderV1({
    authorizationService: {
      readWalletSessionAuthorizationV2ByIdentity: async () => ({ session, quota }),
    },
    authorityStore: { readById: async () => authority },
    authMethodStore: { readByIdV2: async () => authMethod },
    walletStore: {
      listEd25519SignersForWallet: async () => [ed25519Signer],
      listEcdsaSignersForWallet: async () => [ecdsaSigner],
    },
    tenantId,
  });

  const [ed25519Source, ecdsaSource] = await Promise.all([
    reader.readVerifiedSourceV1({
      walletId,
      walletSessionId: String(walletSessionId),
      authorizationId: String(authorizationId),
      keyFamily: 'ed25519',
      requestedAtMs: 4_000,
    }),
    reader.readVerifiedSourceV1({
      walletId,
      walletSessionId: String(walletSessionId),
      authorizationId: String(authorizationId),
      keyFamily: 'ecdsa_secp256k1',
      requestedAtMs: 4_000,
    }),
  ]);

  if (
    authority.signerActivations.keyFamilies[0] !== 'ed25519' ||
    authority.signerActivations.keyFamilies[1] !== 'ecdsa_secp256k1'
  ) {
    throw new Error('combined fixture did not build both signer families');
  }
  const expectedManifest = buildExactAdministeredSignerManifestV1([
    authority.signerActivations.ed25519.signer,
    authority.signerActivations.ecdsa.signer,
  ]);
  expect(ed25519Source.signerManifest).toEqual(expectedManifest);
  expect(ecdsaSource.signerManifest).toEqual(expectedManifest);
  expect(ed25519Source.authority.signerActivations.keyFamilies).toEqual([
    'ed25519',
    'ecdsa_secp256k1',
  ]);
  expect(ed25519Source.keyManifestDigestB64u).toBe(
    parseDigestB64u(ed25519Signer.custodyKeyManifestDigestB64u),
  );
  expect(ecdsaSource.keyManifestDigestB64u).toBe(
    parseDigestB64u(ecdsaSigner.custodyKeyManifestDigestB64u),
  );
});
