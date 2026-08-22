import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceApprovalV1,
  buildWalletSessionLinkedDeviceOwnerAuthorizationV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  parsePrincipalId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  parseTenantId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseWalletAuthorityId } from '../../packages/shared-ts/src/utils/domainIds';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../packages/wallet-server/src/core/ThresholdService/validation';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { resolveActiveOwnerWalletExecutionLane } from '../../packages/wallet-server/src/core/signingLanes/WalletExecutionLaneProjection';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import {
  createD1LinkedDeviceOwnerSourceChildReaderV1,
  createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthorizationProvider';
import type { ResolvedOpaqueWalletSessionToken } from '../../packages/wallet-server/src/authorization/service';
import { buildR103AwaitingTargetPasskeySessionRecordV1 } from './helpers/deviceLinkingServer.fixtures';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildRouterAbEd25519WalletSessionClaimsFixture } from './helpers/routerAbEd25519WalletSessionClaims.fixtures';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

test('rebuilds owner context from persisted lane hints and opaque session identity', async () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:owner-metadata' });
  const tenantId = required(parseTenantId('org-owner-metadata'));
  const ownerAuthority = buildPasskeyWalletAuthAuthority({
    walletId: fixture.approval.walletId,
    rpId: 'owner.example.test',
    credentialIdB64u: 'owner-metadata-credential',
  });
  const binding = buildRouterAbEd25519WalletSessionClaimsFixture({
    walletId: String(fixture.approval.walletId),
    nearAccountId: 'owner-metadata.near',
    nearEd25519SigningKeyId: 'ed25519:owner-metadata',
    relayerKeyId: 'owner-metadata-relayer',
    participantIds: [1, 2],
    thresholdExpiresAtMs: 9_000,
    runtimePolicyScope: {
      orgId: 'org-owner-metadata',
      projectId: 'project-owner-metadata',
      envId: 'env-owner-metadata',
      signingRootVersion: 'owner-metadata-root',
    },
    normalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'owner-metadata-worker',
    },
    authority: ownerAuthority,
    walletSessionId: 'wallet-session:owner-metadata',
    authorizationId: 'wallet-session-authorization:owner-metadata',
    quotaId: 'mpc-wallet-signing-quota:owner-metadata',
  });
  const ownerAuthorization = buildWalletSessionLinkedDeviceOwnerAuthorizationV1({
    walletSessionId: binding.walletSessionId,
    authorizationId: binding.authorizationId,
  });
  const approval = buildLinkedDeviceApprovalV1({
    ...fixture.approval,
    ownerAuthorization,
  });
  const linkedFixture = {
    ...fixture,
    approval,
    packageSetDigestB64u: binding.keyManifestDigestB64u,
  };
  const session = await buildR103AwaitingTargetPasskeySessionRecordV1(linkedFixture);
  const lookupCurves: string[] = [];
  const resolved: ResolvedOpaqueWalletSessionToken = {
    kind: 'resolved_opaque_wallet_session_token',
    curve: 'ed25519',
    binding,
    authorization: {
      tenantId,
      principalId: required(parsePrincipalId('principal:owner-metadata')),
      walletId: binding.walletId,
      authorityDigest: binding.keyManifestDigestB64u,
      walletAuthMethodId: null,
      authorizationId: binding.authorizationId,
      walletSessionId: binding.walletSessionId,
      quotaId: binding.quotaId,
      expiresAtMs: binding.thresholdExpiresAtMs,
    },
  };
  const metadata = createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1({
    tenantId,
    sessionStore: {
      getSessionV1: async () => session,
    },
    authorizationStore: {
      readOpaqueWalletSessionTokenByIdentity: async (input) => {
        lookupCurves.push(input.curve);
        return input.curve === 'ed25519' ? resolved : null;
      },
    },
    readOwnerSourceChildV1: async () => null,
    nowV1: () => 4_000,
  });

  const owner = await metadata.readApprovedOwnerContextV1({
    walletId: approval.walletId,
    linkSessionId: String(approval.linkSessionId),
  });

  expect(lookupCurves).toEqual(['ed25519']);
  expect(owner).toEqual({
    walletId: approval.walletId,
    walletSessionId: binding.walletSessionId,
    authorizationId: binding.authorizationId,
    expiresAtMs: binding.thresholdExpiresAtMs,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    keyManifestDigestB64u: binding.keyManifestDigestB64u,
    curve: 'ed25519',
    authority: binding.authority,
    authorityScope: binding.authorityScope,
  });
});

test('resolves the approved Ed25519 source child from the wallet signer projection', async () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:source-child' });
  const walletId = fixture.approval.walletId;
  const authority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId: 'wallet',
    credentialIdB64u: 'r103',
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authority.bindingId,
    walletId,
    walletAuthorityId: required(parseWalletAuthorityId('authority:source-child')),
    kind: 'passkey',
    status: 'active',
    rpId: authority.verifier.rpId,
    credentialIdB64u: authority.factor.credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(9)),
    counter: 0,
    createdAtMs: 1,
    updatedAtMs: 2,
    activatedAtMs: 2,
  });
  const capability = buildEd25519YaoCapabilityFixture({
    walletId,
    nearAccountId: 'owner-source-child.near',
    nearEd25519SigningKeyId: 'near-key:r103',
    thresholdSessionId: 'threshold-session:r103',
    signerSlot: 1,
    signingWorkerId: 'worker:r103',
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org-source-child',
      projectId: 'project-source-child',
      envId: 'env-source-child',
      signingRootVersion: 'version:r103',
    },
    seed: 6,
  });
  const signer = buildYaoEd25519WalletSignerRecord({
    walletId,
    nearAccountId: capability.capability.nearAccountId,
    nearEd25519SigningKeyId:
      capability.capability.admissionRequest.application_binding.near_ed25519_signing_key_id,
    thresholdSessionId: capability.capability.admissionRequest.scope.threshold_session_id,
    signerSlot: capability.capability.admissionRequest.application_binding.key_creation_signer_slot,
    publicKey: ed25519NearPublicKeyFromBytes(
      capability.capability.activationResult.public_receipt.registered_public_key,
    ),
    signingWorkerId: capability.capability.admissionRequest.scope.signing_worker_id,
    keyVersion: 'version:r103',
    participantIds: [1, 2],
    signingRootId: capability.capability.admissionRequest.application_binding.signing_root_id,
    signingRootVersion: capability.capability.admissionRequest.scope.root_share_epoch,
    runtimePolicyScope: capability.capability.runtimePolicyScope,
    activeYaoCapability: capability.capability,
    custodyKeyManifestDigestB64u: fixture.packageSetDigestB64u,
    now: 2_000,
  });
  const sourceStore = {
    listWalletAuthMethods: async () => [authMethod],
    listWalletSigners: async () => [signer],
  };
  const projected = await resolveActiveOwnerWalletExecutionLane({
    source: sourceStore,
    walletId,
    walletAuthMethodId: authMethod.walletAuthMethodId,
    expectedMaterialActivation: routerAbMpcMaterialActivationRefFromWire(
      capability.capability.admissionRequest.scope.material_activation,
    ),
  });
  if (projected.kind !== 'projected')
    throw new Error(`fixture projection refused: ${projected.reason}`);
  const sourceLaneHint = {
    kind: 'linked_device_owner_source_lane_v1' as const,
    keyFamily: 'ed25519' as const,
    walletKey: projected.projection.walletKey,
    lane: projected.projection.lane,
    materialActivation: projected.projection.materialActivation,
    verifiedActivationReceiptDigestB64u: projected.projection.verifiedActivationReceiptDigestB64u,
  };
  const owner = {
    walletId,
    walletSessionId: required(parseWalletSessionId('wallet-session:source-child')),
    authorizationId: required(parseWalletSessionAuthorizationId('authorization:source-child')),
    expiresAtMs: fixture.approval.expiresAtMs,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    keyManifestDigestB64u: fixture.packageSetDigestB64u,
    curve: 'ed25519' as const,
    authority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
  };
  const session = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture);
  const reader = createD1LinkedDeviceOwnerSourceChildReaderV1({
    walletAuthMethodStore: {
      listForWalletV2: async () => [authMethod],
    },
    walletStore: {
      listEd25519SignersForWallet: async () => [signer],
      listEcdsaSignersForWallet: async () => [],
    },
  });

  const resolution = await reader.readOwnerSourceChildV1({
    owner,
    request: {
      kind: 'preparation',
      session,
      approval: fixture.approval,
      sourceLaneHint,
      childIndex: 0,
    },
  });

  expect(resolution).toMatchObject({
    walletKeyId: projected.projection.walletKey.walletKeyId,
    keyFamily: 'ed25519',
    registeredPublicKeyB64u: projected.projection.walletKey.registeredPublicKeyB64u,
    nearEd25519SigningKeyId: projected.projection.walletKey.nearEd25519SigningKeyId,
    keyCreationSignerSlot: projected.projection.walletKey.keyCreationSignerSlot,
  });
});
