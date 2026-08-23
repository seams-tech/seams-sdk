import { expect, test } from '@playwright/test';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
} from '../../packages/shared-ts/src/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
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
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
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
  const mintId = required(parseReusableWalletSessionMintId('wallet-session-mint:source-reader'));
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
  const reader = createD1LinkedDeviceVerifiedLinkSourceReaderV1({
    authorizationService: {
      readWalletSessionAuthorizationV2ByIdentity: async () => ({ session, quota }),
    },
    authorityStore: { readById: async () => authority },
    authMethodStore: { readByIdV2: async () => authMethod },
    walletStore: {
      listEd25519SignersForWallet: async () => [],
      listEcdsaSignersForWallet: async () => [signer, tempoSigner],
    },
    tenantId,
  });

  const source = await reader.readVerifiedSourceV1({
    walletId,
    walletSessionId: String(walletSessionId),
    authorizationId: String(authorizationId),
    keyFamily: 'ecdsa_secp256k1',
    requestedAtMs: 4_000,
  });

  expect(source.keyManifestDigestB64u).toBe(parseDigestB64u(signer.custodyKeyManifestDigestB64u));
});
