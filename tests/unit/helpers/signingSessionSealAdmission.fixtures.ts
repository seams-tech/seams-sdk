import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  requireRouterAbEcdsaDerivationNormalSigningStateV1,
  routerAbEcdsaDerivationActiveStateId,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEd25519YaoExportAuthorizationIdentityV1 } from '@shared/utils/routerAbEd25519Yao';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  RouterApiWalletRegistrationService,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
} from '../../../packages/wallet-server/src/router/framework/authServicePort';
import { buildLinkedDeviceManagementAuthorityFixture } from './linkedDeviceManagement.fixtures';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

const PARTICIPANT_IDS = [1, 2] as const;

function bytes(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

export type SigningSessionSealAdmissionFixture = {
  readonly token: string;
  readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
  readonly thresholdSessionId: string;
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveEd25519MaterialActivation' | 'resolveEcdsaMaterialActivation'
  >;
};

export async function buildEd25519SigningSessionSealAdmissionFixture(): Promise<SigningSessionSealAdmissionFixture> {
  const walletId = 'wallet:signing-seal-ed25519';
  const activation = buildMpcMaterialActivationRefFixture(
    'signing-seal-ed25519',
    walletId,
    'worker:signing-seal-ed25519',
  );
  const wireActivation = routerAbMpcMaterialActivationRefToWire(activation);
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'signing-seal-ed25519',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation: activation,
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId,
      authorityId: 'authority:signing-seal-ed25519',
      walletAuthMethodId: 'auth-method:signing-seal-ed25519',
      rpId: 'wallet.example.test',
    },
  });
  const signer = fixture.authority.signerActivations.ed25519?.signer;
  if (!signer) throw new Error('Ed25519 signing-seal fixture is missing its signer');
  const thresholdSessionId = 'threshold-session:signing-seal-ed25519';
  const exportIdentity: RouterAbEd25519YaoExportAuthorizationIdentityV1 = {
    scope: {
      lifecycle_id: 'lifecycle:signing-seal-ed25519',
      root_share_epoch: 'epoch:signing-seal-ed25519',
      account_id: walletId,
      threshold_session_id: thresholdSessionId,
      signer_set_id: 'signer-set:signing-seal-ed25519',
      signing_worker_id: activation.signingWorker,
      material_activation: wireActivation,
    },
    application_binding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id: 'near-key:signing-seal-ed25519',
      signing_root_id: 'signing-root:signing-seal-ed25519',
      key_creation_signer_slot: 1,
    },
    participant_ids: PARTICIPANT_IDS,
    registered_public_key: Array.from(base64UrlDecode(signer.registeredPublicKeyB64u)),
    state_epoch: 1,
    runtime_policy_binding: Array.from(bytes(32, 11)),
  };
  return {
    token: `wso_${'E'.repeat(43)}`,
    context: {
      authorization: fixture.issuedSession,
      authority: fixture.authority,
      authMethod: fixture.authMethod,
      retiredAtMs: null,
    },
    thresholdSessionId,
    walletRegistration: {
      async resolveEd25519MaterialActivation() {
        return {
          ok: true,
          materialActivation: wireActivation,
          nearAccountId: walletId,
          signerSlot: 1,
          signingWorkerId: activation.signingWorker,
          participantIds: PARTICIPANT_IDS,
          runtimePolicyScope: {
            orgId: 'tenant:management',
            projectId: 'project:signing-seal-ed25519',
            envId: 'test',
            signingRootVersion: 'v1',
          },
          exportIdentity,
        };
      },
      async resolveEcdsaMaterialActivation() {
        return { ok: false, code: 'not_found', message: 'ECDSA is not active' };
      },
    },
  };
}

function buildEcdsaNormalSigning(input: {
  readonly walletId: string;
  readonly thresholdPublicKey33B64u: string;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}) {
  return requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: input.walletId,
      ecdsa_threshold_key_id: 'ecdsa-threshold-key:signing-seal',
      signing_root_id: 'signing-root:signing-seal-ecdsa',
      signing_root_version: 'v1',
      context: { application_binding_digest_b64u: base64UrlEncode(bytes(32, 12)) },
      public_identity: {
        context_binding_b64u: base64UrlEncode(bytes(32, 13)),
        derivation_client_share_public_key33_b64u: base64UrlEncode(
          new Uint8Array([2, ...bytes(32, 14)]),
        ),
        server_public_key33_b64u: base64UrlEncode(new Uint8Array([3, ...bytes(32, 15)])),
        threshold_public_key33_b64u: input.thresholdPublicKey33B64u,
        ethereum_address20_b64u: base64UrlEncode(bytes(20, 16)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: input.materialActivation,
      signing_worker: {
        server_id: input.materialActivation.signing_worker,
        key_epoch: 'epoch:signing-seal-ecdsa',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: 'epoch:signing-seal-ecdsa',
    },
  });
}

export async function buildEcdsaSigningSessionSealAdmissionFixture(): Promise<SigningSessionSealAdmissionFixture> {
  const walletId = 'wallet:signing-seal-ecdsa';
  const rpId = 'wallet.example.test';
  const passkeyAuthority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u: base64UrlEncode(bytes(32, 36)),
  });
  const activation = buildMpcMaterialActivationRefFixture(
    'signing-seal-ecdsa',
    walletId,
    'worker:signing-seal-ecdsa',
  );
  const wireActivation = routerAbMpcMaterialActivationRefToWire(activation);
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'signing-seal-ecdsa',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ecdsa_secp256k1',
    materialActivation: activation,
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId,
      authorityId: 'authority:signing-seal-ecdsa',
      walletAuthMethodId: String(passkeyAuthority.bindingId),
      rpId,
    },
  });
  const signer = fixture.authority.signerActivations.ecdsa?.signer;
  if (!signer) throw new Error('ECDSA signing-seal fixture is missing its signer');
  const normalSigning = buildEcdsaNormalSigning({
    walletId,
    thresholdPublicKey33B64u: signer.thresholdPublicKey33B64u,
    materialActivation: wireActivation,
  });
  return {
    token: `wso_${'S'.repeat(43)}`,
    context: {
      authorization: fixture.issuedSession,
      authority: fixture.authority,
      authMethod: fixture.authMethod,
      retiredAtMs: null,
    },
    thresholdSessionId: routerAbEcdsaDerivationActiveStateId(normalSigning),
    walletRegistration: {
      async resolveEd25519MaterialActivation() {
        return { ok: false, code: 'not_found', message: 'Ed25519 is not active' };
      },
      async resolveEcdsaMaterialActivation() {
        return {
          ok: true,
          materialActivation: wireActivation,
          keyHandle: 'ecdsa-key-handle:signing-seal',
          relayerKeyId: activation.signingWorker,
          participantIds: PARTICIPANT_IDS,
          runtimePolicyScope: {
            orgId: 'tenant:management',
            projectId: 'project:signing-seal-ecdsa',
            envId: 'test',
            signingRootVersion: 'v1',
          },
          routerAbEcdsaDerivationNormalSigning: normalSigning,
        };
      },
    },
  };
}
