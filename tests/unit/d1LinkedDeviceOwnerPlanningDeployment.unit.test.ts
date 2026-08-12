import { expect, test } from '@playwright/test';
import { projectActiveOwnerWalletExecutionLane } from '../../packages/sdk-server-ts/src/core/signingLanes/WalletExecutionLaneProjection';
import { normalizeWalletAuthMethod } from '../../packages/sdk-server-ts/src/core/d1WalletAuthMethodStore';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { D1LinkedDeviceOwnerPlanningDeploymentV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerPlanningDeployment';
import { walletAuthMethodRecordId } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWalletId, parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { parseLinkedDeviceOwnerSourceLaneV1 } from '../../packages/shared-ts/src/device-linking/parsers';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import { buildRouterAbEd25519YaoCapabilityReplacementFixture } from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

test('builds replay-stable mixed-curve owner planning facts from D1 signer records', async () => {
  const edFixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
  const walletId = required(parseWalletId(edFixture.walletId));
  const now = 1_900_000_000_000;
  const edCapability = edFixture.next;
  const edApplication = edCapability.admissionRequest.application_binding;
  const edScope = edCapability.admissionRequest.scope;
  const edSigner = buildYaoEd25519WalletSignerRecord({
    walletId,
    nearAccountId: edFixture.nearAccountId,
    nearEd25519SigningKeyId: edFixture.nearSigningKeyId,
    thresholdSessionId: edScope.threshold_session_id,
    signerSlot: edApplication.key_creation_signer_slot,
    publicKey: ed25519NearPublicKeyFromBytes(
      edCapability.activationResult.public_receipt.registered_public_key,
    ),
    signingWorkerId: edFixture.signingWorkerId,
    keyVersion: 'yao-recovery-key-v1',
    participantIds: edCapability.admissionRequest.participant_ids,
    signingRootId: edApplication.signing_root_id,
    signingRootVersion: edScope.root_share_epoch,
    runtimePolicyScope: edCapability.runtimePolicyScope,
    activeYaoCapability: edCapability,
    custodyKeyManifestDigestB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
    now,
  });
  const ecdsaSigner = createWalletEcdsaSignerRecord({ walletId, now });
  const authMethod = normalizeWalletAuthMethod({
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    walletId,
    rpId: 'wallet.example.test',
    credentialIdB64u: 'owner-planning-credential',
    credentialPublicKeyB64u: 'owner-planning-public-key',
    counter: 0,
    createdAtMs: now,
    updatedAtMs: now,
  });
  if (!authMethod) throw new Error('owner planning auth method fixture is invalid');
  const authMethodId = walletAuthMethodRecordId(authMethod);
  const edProjection = await projectActiveOwnerWalletExecutionLane({
    walletId,
    walletAuthMethodId: authMethodId,
    authMethod,
    signers: [edSigner],
    expectedMaterialActivation: routerAbMpcMaterialActivationRefFromWire(
      edCapability.activationResult.public_receipt.material_activation,
    ),
  });
  const ecdsaProjection = await projectActiveOwnerWalletExecutionLane({
    walletId,
    walletAuthMethodId: authMethodId,
    authMethod,
    signers: [ecdsaSigner],
    expectedMaterialActivation: routerAbMpcMaterialActivationRefFromWire(
      ecdsaSigner.walletKey.publicCapability.material_activation,
    ),
  });
  const base = buildR103DeviceLinkFixture({ linkSessionId: 'link-session:owner-planning-adapter' });
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const owner = {
    walletId,
    walletSessionId: required(parseWalletSessionId('wallet-session:owner-planning-adapter')),
    authorizationId: required(
      parseWalletSessionAuthorizationId('wallet-authorization:owner-planning-adapter'),
    ),
    expiresAtMs: base.payload.expiresAtMs,
    curve: 'ed25519' as const,
    authority: buildPasskeyWalletAuthAuthority({
      walletId,
      rpId,
      credentialIdB64u: 'owner-planning-credential',
    }),
    authorityScope: { kind: 'passkey_rp' as const, rpId },
  };
  const digest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
  const hints = [
    parseLinkedDeviceOwnerSourceLaneV1({
      kind: 'linked_device_owner_source_lane_v1',
      keyFamily: 'ed25519',
      walletKey: edProjection.walletKey,
      lane: edProjection.lane,
      materialActivation: edProjection.materialActivation,
      verifiedActivationReceiptDigestB64u: edProjection.verifiedActivationReceiptDigestB64u,
    }),
    parseLinkedDeviceOwnerSourceLaneV1({
      kind: 'linked_device_owner_source_lane_v1',
      keyFamily: 'ecdsa_secp256k1',
      walletKey: ecdsaProjection.walletKey,
      lane: ecdsaProjection.lane,
      materialActivation: ecdsaProjection.materialActivation,
      verifiedActivationReceiptDigestB64u: ecdsaProjection.verifiedActivationReceiptDigestB64u,
      ecdsaSourceManifest: { manifestId: 'manifest:owner-planning', manifestRevision: 1 },
    }),
  ] as const;
  const deployment = new D1LinkedDeviceOwnerPlanningDeploymentV1({
    walletSource: {
      listEd25519SignersForWallet: async () => [edSigner],
      listEcdsaSignersForWallet: async () => [ecdsaSigner],
    },
  });
  const input = {
    owner,
    payload: base.payload,
    orderedOwnerSourceLaneHints: hints,
    projections: [edProjection, ecdsaProjection] as const,
  };
  const first = await deployment.planOwnerPlanningV1(input);
  const second = await deployment.planOwnerPlanningV1(input);
  expect(second).toEqual(first);
  expect(first.metadata.orderedKeyBindings).toHaveLength(2);
  expect(first.orderedChildren.map((child) => child.keyFamily)).toEqual([
    'ed25519',
    'ecdsa_secp256k1',
  ]);
  expect(first.orderedChildren[1]).toMatchObject({
    keyFamily: 'ecdsa_secp256k1',
    sourceHolderVerifyingShare33B64u: ecdsaSigner.walletKey.derivationClientSharePublicKey33B64u,
    sourceServerVerifyingShare33B64u: ecdsaSigner.walletKey.relayerVerifyingShareB64u,
  });
  expect(String(first.metadata.policyDigestB64u)).not.toBe(String(digest));
});
