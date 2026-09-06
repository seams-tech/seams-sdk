import { buildActiveWalletSessionV1 } from '../../../packages/wallet/src/core/indexedDB';
import { base58Encode } from '../../../packages/shared-ts/src/utils/base58';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../../packages/shared-ts/src/utils/signingSessionSeal';
import { routerAbMpcMaterialActivationRefToWire } from '../../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { parseMpcWalletSigningQuotaId } from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefForAuthorityFixture,
} from './ecdsaMaterialRef.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './linkedDeviceManagement.fixtures';
import { rawPasskeyCustodyEnvelope } from './passkeyCustodyEnvelope.fixtures';
export const RP_ID = 'wallet.example.test';

export const DISCOVERED_WALLET_ID = 'discovered-wallet';

export const NEAR_ACCOUNT_ID = 'discovered-wallet.testnet';

export const NEAR_SIGNING_KEY_ID = 'ed25519ks_discovered_wallet';

export const CREDENTIAL_ID = base64UrlEncode(new Uint8Array(32).fill(36));

export const SIGNER_SLOT = 3;

export const THRESHOLD_SESSION_ID = 'threshold-session-sync-1';

export const WALLET_SESSION_ID = 'wallet-session-sync-1';

export const WALLET_SESSION_QUOTA_ID = mpcWalletSigningQuotaId('wallet-session-quota-sync-1');

export const OPERATION_CREDENTIAL_TOKEN = `wst_${base64UrlEncode(new Uint8Array(32).fill(88))}`;

export const SIGNING_WORKER_ID = 'signing-worker-sync-1';

export const ROOT_SHARE_EPOCH = 'root-share-epoch-sync-1';

export const REGISTERED_PUBLIC_KEY = new Uint8Array(32).fill(21);

export const OPERATIONAL_PUBLIC_KEY = `ed25519:${base58Encode(REGISTERED_PUBLIC_KEY)}`;

export const MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'sync-account-yao',
  DISCOVERED_WALLET_ID,
  SIGNING_WORKER_ID,
  NEAR_SIGNING_KEY_ID,
);

export function mpcWalletSigningQuotaId(value: string) {
  const parsed = parseMpcWalletSigningQuotaId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

export function walletBinding(walletId: string): Record<string, unknown> {
  return {
    walletId,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID,
    signerSlot: SIGNER_SLOT,
  };
}

export function registrationAdmissionRequest(walletId: string) {
  return {
    scope: {
      lifecycle_id: 'sync-account-orchestration-lifecycle',
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: walletId,
      threshold_session_id: THRESHOLD_SESSION_ID,
      signer_set_id: 'signer-set-sync-1',
      signing_worker_id: SIGNING_WORKER_ID,
      material_activation: routerAbMpcMaterialActivationRefToWire(MATERIAL_ACTIVATION),
    },
    application_binding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: 'project-sync:test',
      key_creation_signer_slot: SIGNER_SLOT,
    },
    participant_ids: [1, 2] as const,
  };
}

export function registrationAdmissionReceipt(walletId: string) {
  const request = registrationAdmissionRequest(walletId);
  return {
    binding: {
      lifecycle: {
        lifecycle_id: request.scope.lifecycle_id,
        work_kind: 'registration_prepare',
        primitive_request_kind: 'registration',
        root_share_epoch: request.scope.root_share_epoch,
        account_id: request.scope.account_id,
        session_id: request.scope.threshold_session_id,
        signer_set_id: request.scope.signer_set_id,
        selected_server_id: request.scope.signing_worker_id,
      },
      operation: 'registration',
      session_id: new Array<number>(32).fill(8),
      stable_key_context_binding: new Array<number>(32).fill(9),
      material_activation: request.scope.material_activation,
    },
    keyset: {
      deriver_a_input_public_key: new Array<number>(32).fill(1),
      deriver_b_input_public_key: new Array<number>(32).fill(2),
      signing_worker_recipient_public_key: new Array<number>(32).fill(3),
    },
  };
}

export function buildSyncVerifyResponseFixture(input: {
  walletId: string;
  founding: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>;
  walletSession: ReturnType<typeof buildActiveWalletSessionV1>;
  authorityRef: ReturnType<typeof buildWalletAuthAuthorityRefForAuthorityFixture>;
  expiresAtMs: number;
  ecdsaSigners: readonly Record<string, unknown>[];
}): Record<string, unknown> {
  const { walletId, founding, walletSession, authorityRef, expiresAtMs, ecdsaSigners } = input;
  const admissionRequest = registrationAdmissionRequest(walletId);
  const admissionReceipt = registrationAdmissionReceipt(walletId);
  return {
    ok: true,
    verified: true,
    walletId,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    signerSlot: SIGNER_SLOT,
    publicKey: OPERATIONAL_PUBLIC_KEY,
    credentialIdB64u: CREDENTIAL_ID,
    credentialPublicKeyB64u: founding.authMethod.credentialPublicKeyB64u,
    walletBinding: walletBinding(walletId),
    walletAuthMethodId: String(founding.authMethod.walletAuthMethodId),
    walletAuthorityId: String(founding.authority.authorityId),
    foundingAuthority: founding.authority,
    foundingAuthMethod: founding.authMethod,
    thresholdEd25519: {
      relayerKeyId: SIGNING_WORKER_ID,
      keyVersion: 'key-version-sync-1',
      participantIds: [1, 2],
      session: {
        walletId,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        walletSessionId: WALLET_SESSION_ID,
        quotaId: WALLET_SESSION_QUOTA_ID,
        expiresAtMs,
        remainingUses: 4,
        runtimePolicyScope: {
          orgId: 'org-sync',
          projectId: 'project-sync',
          envId: 'test',
          signingRootVersion: ROOT_SHARE_EPOCH,
        },
        routerAbNormalSigning: {
          kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
          signingWorkerId: SIGNING_WORKER_ID,
        },
      },
    },
    walletSession,
    operationCredential: {
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: OPERATION_CREDENTIAL_TOKEN,
      walletSessionId: WALLET_SESSION_ID,
    },
    ed25519YaoRecovery: {
      kind: 'router_ab_ed25519_yao_sync_recovery_v1',
      authorityRef,
      capability: {
        kind: 'router_ab_ed25519_yao_active_capability_v1',
        materialActivation: routerAbMpcMaterialActivationRefToWire(MATERIAL_ACTIVATION),
        activeCapabilityBinding: new Array<number>(32).fill(8),
        registeredPublicKey: [...REGISTERED_PUBLIC_KEY],
        nearAccountId: NEAR_ACCOUNT_ID,
        applicationBinding: {
          wallet_id: walletId,
          near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
          signing_root_id: 'project-sync:test',
          key_creation_signer_slot: SIGNER_SLOT,
        },
        participantIds: [1, 2],
        runtimePolicyScope: {
          orgId: 'org-sync',
          projectId: 'project-sync',
          envId: 'test',
          signingRootVersion: ROOT_SHARE_EPOCH,
        },
        lifecycle: {
          lifecycleId: 'sync-account-orchestration-lifecycle',
          rootShareEpoch: ROOT_SHARE_EPOCH,
          accountId: walletId,
          thresholdSessionId: THRESHOLD_SESSION_ID,
          signerSetId: 'signer-set-sync-1',
          signingWorkerId: SIGNING_WORKER_ID,
        },
        stateEpoch: 1,
        registrationContinuity: {
          kind: 'registration',
          admissionRequest,
          admissionReceipt,
          activationTranscript: new Array<number>(32).fill(11),
        },
      },
    },
    walletCustody: {
      kind: 'wallet_custody_sync_bootstrap_v1',
      envelope: rawPasskeyCustodyEnvelope({
        walletId,
        factor: {
          kind: 'passkey',
          rpId: RP_ID,
          credentialIdB64u: CREDENTIAL_ID,
          kekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
        },
      }),
      storeVersion: 'custody-store-version-1',
    },
    ecdsaCustody: {
      kind: 'wallet_custody_ecdsa_sync_continuity_v1',
      signers: ecdsaSigners,
    },
  };
}
