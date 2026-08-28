import { expect, test } from '@playwright/test';
import { configureIndexedDB, IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  clearLinkedEcdsaHolderRuntimesV1,
  installLinkedEcdsaHolderRuntimeV1,
} from '@/core/signingEngine/session/material/linkedEcdsaHolderRuntime';
import { resolveActiveWalletAuthorityEcdsaRuntimeV1 } from '@/core/signingEngine/session/material/activeWalletAuthorityEcdsaRuntime';
import {
  activeWalletAuthorityAvailableLaneFromProjection,
  ecdsaLaneCandidateFromAvailableLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseRootShareEpoch,
  parseWalletAuthMethodId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { parseWalletSessionId } from '@shared/authorization/capabilityKinds';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { WalletAuthoritySignerMaterialRecordV1 } from '@/core/indexedDB/passkeyClientDB.types';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { computeEcdsaDerivationRoleLocalRelayerKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

configureIndexedDB({ mode: 'disabled' });

function required<T>(result: { readonly ok: true; readonly value: T }): T {
  if (!result.ok) throw new Error('fixture parser rejected a required value');
  return result.value;
}

function normalSigningState(args: {
  readonly walletId: string;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly ecdsaThresholdKeyId: string;
  readonly thresholdPublicKey33B64u: string;
  readonly ethereumAddress20B64u: string;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  return {
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: args.walletId,
      ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
      signing_root_id: 'signing-root:active-authority',
      signing_root_version: 'v1',
      context: { application_binding_digest_b64u: 'active-authority-context' },
      public_identity: {
        context_binding_b64u: 'active-authority-context-binding',
        derivation_client_share_public_key33_b64u: args.thresholdPublicKey33B64u,
        server_public_key33_b64u: args.thresholdPublicKey33B64u,
        threshold_public_key33_b64u: args.thresholdPublicKey33B64u,
        ethereum_address20_b64u: args.ethereumAddress20B64u,
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(args.materialActivation),
      signing_worker: {
        server_id: String(args.materialActivation.signingWorker),
        key_epoch: 'worker-epoch:active-authority',
        recipient_encryption_key: 'recipient-key:active-authority',
      },
      activation_epoch: required(parseRootShareEpoch('epoch:active-authority')),
    },
  };
}

test('active Wallet Authority V2 ECDSA runtime projects to a deferred lane candidate', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('fixture is missing ECDSA authority activation');
  const ecdsaMaterial = fixture.signerMaterials.find(
    (material) => material.keyFamily === 'ecdsa_secp256k1',
  );
  if (!ecdsaMaterial || ecdsaMaterial.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('fixture is missing linked ECDSA material');
  }
  expect(
    new Set([
      ecdsaMaterial.packageSetDigestB64u,
      fixture.authority.signerActivationSetDigestB64u,
      fixture.authority.authorityDigestB64u,
    ]).size,
  ).toBe(3);
  const ethereumAddress20B64u = base64UrlEncode(new Uint8Array(20).fill(0x11));
  const normalSigning = normalSigningState({
    walletId: String(fixture.walletId),
    materialActivation: ecdsaActivation.materialActivation,
    ecdsaThresholdKeyId: String(ecdsaMaterial.ecdsaThresholdKeyId),
    thresholdPublicKey33B64u: ecdsaActivation.signer.thresholdPublicKey33B64u,
    ethereumAddress20B64u,
  });
  const baseReceipt = ecdsaMaterial.publicFacts.activationReceipt;
  const activationReceipt = {
    ...baseReceipt,
    binding: {
      ...baseReceipt.binding,
      source: {
        ...baseReceipt.binding.source,
        thresholdPublicKey33B64u: ecdsaActivation.signer.thresholdPublicKey33B64u,
        thresholdEthereumAddress20B64u: ethereumAddress20B64u,
      },
    },
    thresholdPublicKey33B64u: ecdsaActivation.signer.thresholdPublicKey33B64u,
    thresholdEthereumAddress20B64u: ethereumAddress20B64u,
    normalSigning,
  };
  const signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[] =
    fixture.signerMaterials.map((material) =>
      material.keyFamily === 'ecdsa_secp256k1'
        ? {
            ...material,
            publicFacts: {
              ...material.publicFacts,
              activationReceipt,
            },
          }
        : material,
    );
  const walletSessionId = required(parseWalletSessionId('wallet-session:linked-runtime'));
  const operationCredential = {
    kind: 'opaque_wallet_session_operation_credential_v1' as const,
    token: `wst_${'A'.repeat(43)}`,
    walletSessionId,
  };
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalReadExactWithOperationCredential =
    walletSessionAuthorizations.readExactWithOperationCredential;
  const originalGetWalletPasskeyAuthenticator = IndexedDBManager.getWalletPasskeyAuthenticator;
  const chainTarget = {
    kind: 'evm' as const,
    namespace: 'eip155' as const,
    chainId: 11155111,
    networkSlug: 'sepolia',
  };

  clearLinkedEcdsaHolderRuntimesV1();
  installLinkedEcdsaHolderRuntimeV1({
    kind: 'linked_ecdsa_holder_runtime_v1',
    walletId: fixture.walletId,
    authorityId: fixture.authority.authorityId,
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    factorAuthority: fixture.factorAuthority,
    materialActivation: ecdsaActivation.materialActivation,
    holderHandleId: 'holder:active-authority',
    ecdsaThresholdKeyId: String(ecdsaMaterial.ecdsaThresholdKeyId),
    activationReceipt,
  });
  IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
    kind: 'resolved',
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials,
    exportRoot: null,
  });
  walletSessionAuthorizations.readExactWithOperationCredential = async () => ({
    record: fixture.activeWalletSession,
    operationCredential,
  });
  IndexedDBManager.getWalletPasskeyAuthenticator = async () => {
    throw new Error('ECDSA authority resolution must not read an Ed25519 signer slot');
  };

  try {
    const resolved = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
      walletId: fixture.walletId,
      chainTarget,
    });
    expect(resolved.kind).toBe('resolved');
    if (resolved.kind !== 'resolved' || !resolved.lane) throw new Error('runtime did not resolve');
    expect(resolved.runtime).toMatchObject({
      kind: 'active_wallet_authority_ecdsa_runtime_v1',
      walletId: fixture.walletId,
      authorityId: fixture.authority.authorityId,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      session: fixture.activeWalletSession,
      operationCredential,
      authority: fixture.authority,
      authMethod: fixture.authMethod,
      holderRuntime: expect.objectContaining({
        walletId: fixture.walletId,
        authorityId: fixture.authority.authorityId,
        walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
        materialActivation: ecdsaActivation.materialActivation,
      }),
    });
    const expectedRelayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
      walletId: String(fixture.walletId),
      signingRootId: normalSigning.scope.signing_root_id,
      signingRootVersion: normalSigning.scope.signing_root_version,
    });
    expect(resolved.runtime.relayerKeyId).toBe(expectedRelayerKeyId);
    expect(resolved.runtime.relayerKeyId).not.toBe(normalSigning.scope.signing_worker.server_id);
    const availableLane = activeWalletAuthorityAvailableLaneFromProjection(resolved.lane);
    const candidate = ecdsaLaneCandidateFromAvailableLane({
      walletId: fixture.walletId,
      lane: availableLane,
    });
    expect(candidate).toMatchObject({
      source: 'active_wallet_authority',
      authorizationState: 'authorization_required',
      state: 'deferred',
      chainTarget,
      runtime: {
        authorityId: fixture.authority.authorityId,
        walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
        factorAuthority: {
          bindingId: fixture.authMethod.walletAuthMethodId,
          walletId: fixture.walletId,
          factor: {
            kind: 'passkey',
            credentialIdB64u: fixture.authMethod.credentialIdB64u,
          },
        },
      },
    });

    IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
      kind: 'resolved',
      selection: fixture.selection,
      authMethod: fixture.authMethod,
      authority: fixture.authority,
      signerMaterials: [],
      exportRoot: null,
    });
    const absentMaterial = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
      walletId: fixture.walletId,
      chainTarget,
    });
    expect(absentMaterial).toMatchObject({
      kind: 'blocked',
      reason: 'missing_holder_runtime',
    });
    IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
      kind: 'resolved',
      selection: fixture.selection,
      authMethod: fixture.authMethod,
      authority: fixture.authority,
      signerMaterials,
      exportRoot: null,
    });

    const mismatchedActivation = buildMpcMaterialActivationRefFixture(
      'active-authority-other',
      String(fixture.walletId),
      'worker:linked-runtime',
    );
    const activationMismatch = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
      walletId: fixture.walletId,
      materialActivation: mismatchedActivation,
    });
    expect(activationMismatch).toMatchObject({
      kind: 'blocked',
      reason: 'authority_identity_mismatch',
    });

    const wrongAuthMethodId = required(
      parseWalletAuthMethodId('auth-method:active-authority-other'),
    );
    IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
      kind: 'resolved',
      selection: fixture.selection,
      authMethod: { ...fixture.authMethod, walletAuthMethodId: wrongAuthMethodId },
      authority: fixture.authority,
      signerMaterials,
      exportRoot: null,
    });
    const authMethodMismatch = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
      walletId: fixture.walletId,
    });
    expect(authMethodMismatch).toMatchObject({
      kind: 'blocked',
      reason: 'authority_identity_mismatch',
    });
  } finally {
    clearLinkedEcdsaHolderRuntimesV1();
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    walletSessionAuthorizations.readExactWithOperationCredential =
      originalReadExactWithOperationCredential;
    IndexedDBManager.getWalletPasskeyAuthenticator = originalGetWalletPasskeyAuthenticator;
  }
});
