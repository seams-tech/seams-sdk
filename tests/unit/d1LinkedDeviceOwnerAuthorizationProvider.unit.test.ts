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
  parseDeviceId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseWalletAuthMethodId, parseWalletAuthorityId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
} from '../../packages/shared-ts/src/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { buildExactAdministeredSignerManifestV1 } from '../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
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
import { sourceKeyManifestDigestForFamilyV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import { parseLinkedDeviceSessionRecordV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
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

test('rebuilds owner context from the approved Wallet Session V2 projection', async () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:owner-metadata' });
  const ownerAuthority = buildPasskeyWalletAuthAuthority({
    walletId: fixture.approval.walletId,
    rpId: 'owner.example.test',
    credentialIdB64u: 'owner-metadata-credential',
  });
  const authorityId = required(parseWalletAuthorityId('authority:owner-metadata'));
  const deviceId = required(parseDeviceId('device:owner-metadata'));
  const sourceHint = fixture.approval.orderedOwnerSourceLaneHints[0];
  if (!sourceHint) throw new Error('owner metadata fixture is missing a source hint');
  const sourceManifest = buildExactAdministeredSignerManifestV1([
    {
      kind: 'exact_administered_ed25519_signer_v1',
      keyFamily: 'ed25519',
      walletId: String(fixture.approval.walletId),
      walletKeyId: String(sourceHint.walletKey.walletKeyId),
      registeredPublicKeyB64u: String(sourceHint.walletKey.registeredPublicKeyB64u),
    },
  ]);
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: sourceManifest,
    materialActivations: {
      keyFamilies: ['ed25519'],
      ed25519: sourceHint.materialActivation,
    },
  });
  const signerActivationSetDigestB64u = parseDigestB64u(
    await computeWalletSignerActivationSetDigestB64u(signerActivations),
  );
  const authorityWithoutDigest = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId: fixture.approval.walletId,
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
    ...authorityWithoutDigest,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityWithoutDigest),
  });
  const opaqueWalletAuthMethodId = required(
    parseWalletAuthMethodId('wallet-auth-method:owner-metadata-opaque'),
  );
  const sourceAuthority = { ...ownerAuthority, bindingId: opaqueWalletAuthMethodId };
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: opaqueWalletAuthMethodId,
    walletId: fixture.approval.walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: ownerAuthority.verifier.rpId,
    credentialIdB64u: ownerAuthority.factor.credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(9)),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
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
    packageSetDigestB64u: fixture.packageSetDigestB64u,
  };
  const session = await buildR103AwaitingTargetPasskeySessionRecordV1(linkedFixture);
  let sourceRequest: {
    walletId: string;
    walletSessionId: string;
    authorizationId: string;
    keyFamily: 'ed25519' | 'ecdsa_secp256k1';
    requestedAtMs: number;
  } | null = null;
  const source = {
    authority,
    authMethod,
    signerManifest: sourceManifest,
    keyManifestDigestB64u: fixture.packageSetDigestB64u,
    principalId: required(parsePrincipalId(String(fixture.approval.walletId))),
    expiresAtMs: 9_000,
    authorityDigestB64u: authority.authorityDigestB64u,
    verifiedRevocationEpoch: 0,
    verifiedAtMs: 4_000,
  };
  const metadata = createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1({
    sessionStore: {
      getSessionV1: async () => session,
    },
    readVerifiedSourceV1: async (input) => {
      sourceRequest = input;
      return source;
    },
    readOwnerSourceChildV1: async () => null,
    nowV1: () => 4_000,
  });

  const owner = await metadata.readApprovedOwnerContextV1({
    walletId: approval.walletId,
    linkSessionId: String(approval.linkSessionId),
    keyFamily: 'ed25519',
  });

  expect(sourceRequest).toEqual({
    walletId: approval.walletId,
    walletSessionId: String(binding.walletSessionId),
    authorizationId: String(binding.authorizationId),
    keyFamily: 'ed25519',
    requestedAtMs: 4_000,
  });
  expect(owner).toEqual({
    walletId: approval.walletId,
    walletSessionId: binding.walletSessionId,
    authorizationId: binding.authorizationId,
    expiresAtMs: 9_000,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    keyManifestDigestB64u: fixture.packageSetDigestB64u,
    curve: 'ed25519',
    authority: sourceAuthority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(sourceAuthority),
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

test('selects distinct custody digests by approved source key family', () => {
  const ed25519 = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(1)));
  const ecdsa = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(2)));
  const digests = { ed25519, ecdsa_secp256k1: ecdsa };

  expect(sourceKeyManifestDigestForFamilyV1(digests, 'ed25519')).toBe(ed25519);
  expect(sourceKeyManifestDigestForFamilyV1(digests, 'ecdsa_secp256k1')).toBe(ecdsa);
});

test('rejects transcript digest families absent from approved source lanes', async () => {
  const fixture = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:digest-family-boundary' });
  const session = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture);
  if (!session.approvalTranscript) throw new Error('fixture approval transcript is missing');
  const ed25519 = fixture.packageSetDigestB64u;
  const ecdsa = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(3)));

  expect(() =>
    parseLinkedDeviceSessionRecordV1({
      ...session,
      approvalTranscript: {
        ...session.approvalTranscript,
        sourceKeyManifestDigestsB64u: { ed25519, ecdsa_secp256k1: ecdsa },
      },
    }),
  ).toThrow(/digest families do not match approved source lanes/);
});
