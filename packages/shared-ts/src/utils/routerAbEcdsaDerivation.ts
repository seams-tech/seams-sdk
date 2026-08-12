import { base64UrlDecode, base64UrlEncode } from './encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from './digests';
import {
  computeSdkEcdsaDerivationApplicationBindingDigestB64u,
  type SdkEcdsaDerivationBindingFacts,
} from '../threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '../threshold/signingRootScope';
import { requireRouterAbX25519PublicKey } from './routerAbPublicKeyset';
import {
  parseEcdsaActiveStateId,
  parseRootShareEpoch,
  parseThresholdEcdsaSessionId,
  type EcdsaActiveStateId,
  type RootShareEpoch,
  type ThresholdEcdsaSessionId,
} from './domainIds';
import {
  parseCorrelationId,
  parseDigestB64u,
  type CorrelationId,
  type DigestB64u,
} from './canonicalPrimitives';
import {
  parseEcdsaServerGeneration,
  type EcdsaServerGeneration,
} from './ecdsaCapabilityActivation';
import {
  canonicalRouterAbMpcMaterialActivationRefBytes,
  canonicalRouterAbNormalSigningAuthorizationBytes,
  parseRouterAbMpcMaterialActivationRef,
  parseRouterAbNormalSigningAuthorization,
  type RouterAbMpcMaterialActivationRefWire,
  type RouterAbNormalSigningAuthorizationWire,
} from './routerAbNormalSigningIdentity';
import {
  EVM_ECDSA_MPC_OPERATION_KINDS,
  parseMpcWalletSigningQuotaId,
  parseReusableWalletSessionMintId,
  parseSeamsSessionId,
  parseWalletSessionId,
  type EvmEcdsaMpcOperationKind,
  type MpcWalletSigningQuotaId,
  type ReusableWalletSessionMintId,
  type SeamsSessionId,
  type WalletSessionId,
} from '../authorization/capabilityKinds';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  parseWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from './walletAuthAuthority';

export const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1 =
  'router_ab_ecdsa_derivation_normal_signing_v1' as const;
export const ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1 = 'evm-family' as const;
export const ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH =
  '/router-ab/ecdsa-derivation/healthz' as const;
export const ROUTER_AB_ECDSA_DERIVATION_BOOTSTRAP_PATH =
  '/router-ab/ecdsa-derivation/bootstrap' as const;
export const ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH = '/router-ab/ecdsa-derivation/export' as const;
export const ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH =
  '/router-ab/ecdsa-derivation/presignature-pool/fill/init' as const;
export const ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH =
  '/router-ab/ecdsa-derivation/presignature-pool/fill/step' as const;
export const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH =
  '/router-ab/ecdsa-derivation/sign/prepare' as const;
export const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH =
  '/router-ab/ecdsa-derivation/sign' as const;
export const ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH =
  '/router-ab/ecdsa-derivation/refresh' as const;
export const ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH =
  '/router-ab/ecdsa-derivation/session/activate' as const;
export const ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH =
  '/router-ab/ecdsa-derivation/operation-step-up' as const;
const ROUTER_AB_ECDSA_OPERATION_STEP_UP_CHALLENGE_DOMAIN_V1 =
  'router-ab-ecdsa-operation-step-up/challenge/v1' as const;
const ECDSA_DERIVATION_CONTEXT_DOMAIN_TAG_V1 = 'router-ab-ecdsa-derivation/context/v1' as const;
const ECDSA_DERIVATION_CONTEXT_BINDING_DOMAIN_V1 =
  'router-ab-ecdsa-derivation/role-local/context-binding/v1' as const;
const ECDSA_DERIVATION_SCHEME_ID_V1 = 'router-ab-ecdsa-derivation-v1' as const;
const ECDSA_DERIVATION_CURVE_V1 = 'secp256k1' as const;
const ECDSA_DERIVATION_CONTEXT_FIELD_BYTES_V1 = 0x01;
const ECDSA_DERIVATION_PARTICIPANT_IDS_V1 = [1, 2] as const;
const ROUTER_AB_ECDSA_DERIVATION_PUBLIC_IDENTITY_VERSION_V1 =
  'router-ab-ecdsa-derivation/public-identity/v1' as const;
const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_SCOPE_VERSION_V1 =
  'router-ab-ecdsa-derivation/normal-signing-scope/v1' as const;
const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_REQUEST_VERSION_V1 =
  'router-ab-ecdsa-derivation/normal-signing-request/v1' as const;
const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1 =
  'router-ab-ecdsa-derivation/normal-signing-finalize-request/v1' as const;
const ROUTER_AB_ECDSA_DERIVATION_CLIENT_RERANDOMIZATION_COMMITMENT_DOMAIN_V1 =
  'router-ab-ecdsa-derivation/client-rerandomization-commitment/v1' as const;

export type RouterAbEcdsaDerivationStableKeyContextV1 = {
  application_binding_digest_b64u: string;
};

export type RouterAbEcdsaDerivationPublicIdentityV1 = {
  context_binding_b64u: string;
  derivation_client_share_public_key33_b64u: string;
  server_public_key33_b64u: string;
  threshold_public_key33_b64u: string;
  ethereum_address20_b64u: string;
  client_share_retry_counter: number;
  server_share_retry_counter: number;
};

export type RouterAbServerIdentityV1 = {
  server_id: string;
  key_epoch: string;
  recipient_encryption_key: string;
};

export type RouterAbEcdsaDerivationPostRegistrationLifecycleScopeV1<
  WorkKind extends 'key_export' | 'recovery' | 'server_share_refresh',
  PrimitiveRequestKind extends 'export' | 'recovery' | 'refresh',
> = {
  lifecycle_id: string;
  work_kind: WorkKind;
  primitive_request_kind: PrimitiveRequestKind;
  root_share_epoch: RootShareEpoch;
  account_id: string;
  session_id: ThresholdEcdsaSessionId;
  signer_set_id: string;
  selected_server_id: string;
};

export type RouterAbEcdsaDerivationExportLifecycleScopeV1 =
  RouterAbEcdsaDerivationPostRegistrationLifecycleScopeV1<'key_export', 'export'>;

export type RouterAbEcdsaDerivationRefreshLifecycleScopeV1 =
  RouterAbEcdsaDerivationPostRegistrationLifecycleScopeV1<'server_share_refresh', 'refresh'>;

export type RouterAbEcdsaDerivationSignerIdentityV1<Role extends 'signer_a' | 'signer_b'> = {
  role: Role;
  signer_id: string;
  key_epoch: string;
};

export type RouterAbEcdsaDerivationSignerSetV1 = {
  signer_set_id: string;
  policy: 'all_2';
  signer_a: RouterAbEcdsaDerivationSignerIdentityV1<'signer_a'>;
  signer_b: RouterAbEcdsaDerivationSignerIdentityV1<'signer_b'>;
  selected_server: RouterAbServerIdentityV1;
};

export type RouterAbEcdsaRegistrationPurposeV1 = 'wallet_registration' | 'wallet_add_signer';

export type RouterAbEcdsaRegistrationLifecycleV1 = {
  lifecycle_id: string;
  work_kind: 'registration_prepare';
  primitive_request_kind: 'registration';
  root_share_epoch: RootShareEpoch;
  account_id: string;
  session_id: string;
  signer_set_id: string;
  selected_server_id: string;
};

export type RouterAbEcdsaRegistrationRecipientKeysV1 = {
  deriver_a: {
    role: 'signer_a';
    key_epoch: string;
    public_key: string;
  };
  deriver_b: {
    role: 'signer_b';
    key_epoch: string;
    public_key: string;
  };
};

export type RouterAbEcdsaRegistrationRequestFactsV1 = {
  registration_purpose: RouterAbEcdsaRegistrationPurposeV1;
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  lifecycle: RouterAbEcdsaRegistrationLifecycleV1;
  signer_set: RouterAbEcdsaDerivationSignerSetV1;
  router_id: string;
  client_id: string;
  replay_nonce: string;
  expires_at_ms: number;
  deriver_recipient_keys: RouterAbEcdsaRegistrationRecipientKeysV1;
};

export type RouterAbEcdsaRegistrationRequestV1 = Omit<
  RouterAbEcdsaRegistrationRequestFactsV1,
  'deriver_recipient_keys'
> & {
  client_ephemeral_public_key: string;
  deriver_a_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  deriver_b_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
};

export type RouterAbEcdsaClientProofBundleV1 = {
  kind: 'recipient_proof_bundle';
  transcriptDigestB64u: string;
  payloadB64u: string;
};

export type RouterAbEcdsaClientProofFinalizationV1 = {
  kind: 'finalize_encrypted_client_proof_bundles_v1';
  bundles: {
    signerA: RouterAbEcdsaClientProofBundleV1;
    signerB: RouterAbEcdsaClientProofBundleV1;
  };
};

export type RouterAbEcdsaRegistrationPublicIdentityV1 = {
  relayerKeyId: string;
  relayerPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: `0x${string}`;
  relayerShareRetryCounter: number;
};

export type RouterAbEcdsaVerifiedClientActivationFactsV1 = {
  registrationRequestDigestB64u: string;
  proofTranscriptDigestB64u: string;
  contextBinding32B64u: string;
  derivationClientSharePublicKey33B64u: string;
  clientShareRetryCounter: number;
  participantId: 1;
};

export type RouterAbEcdsaStrictForwardedRegistrationResponseV1 = {
  result: 'forwarded';
  response: {
    bundles: RouterAbEcdsaClientProofFinalizationV1['bundles'];
  };
};

export type RouterAbEcdsaStrictForwardedProofResponseV1 =
  RouterAbEcdsaStrictForwardedRegistrationResponseV1;

function requireExportShareAuthorizationKind(
  value: unknown,
  label: string,
): 'reusable_wallet_session' | 'verified_step_up' {
  if (value === 'reusable_wallet_session' || value === 'verified_step_up') return value;
  throw new Error(`${label} must be reusable_wallet_session or verified_step_up`);
}

export type RouterAbEcdsaSigningWorkerExportShareBindingV1 = {
  wallet_id: string;
  key_handle: string;
  ecdsa_threshold_key_id: string;
  signing_root_id: string;
  signing_root_version: string;
  activation_epoch: RootShareEpoch;
  signing_worker_id: string;
  context_binding_b64u: string;
  threshold_public_key33_b64u: string;
  export_request_digest_b64u: string;
  export_authorization_digest_b64u: string;
  export_nonce: string;
  authorization_kind: 'reusable_wallet_session' | 'verified_step_up';
  authorization_id: string;
  material_activation: RouterAbMpcMaterialActivationRefWire;
  lifecycle_id: string;
  recipient_identity: string;
  recipient_public_key: string;
  expires_at_ms: number;
};

export type RouterAbEcdsaSigningWorkerExportShareEnvelopeV1 = {
  version: 'router-ab-ecdsa-derivation/signing-worker-export-share-envelope/v1';
  algorithm: 'hpke_x25519_hkdf_sha256_aes256gcm_v1';
  binding: RouterAbEcdsaSigningWorkerExportShareBindingV1;
  ciphertext_and_tag: number[];
};

export type RouterAbEcdsaExplicitExportForwardedResponseV1 = {
  result: 'forwarded';
  response: RouterAbEcdsaStrictForwardedRegistrationResponseV1['response'];
  signing_worker_export: RouterAbEcdsaSigningWorkerExportShareEnvelopeV1;
};

export type RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1 = {
  result: 'forwarded';
  response: RouterAbEcdsaStrictForwardedProofResponseV1['response'];
  signing_worker_activation: RouterAbEcdsaRegistrationActivationReceiptV1;
};

export type RouterAbEcdsaRegistrationActivationRequestV1 = {
  registrationCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_activation_v1';
    activationCorrelationId: CorrelationId;
    publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  };
};

export type RouterAbEcdsaRegistrationActivationReceiptV1 = {
  activation_correlation_id: CorrelationId;
  activation_request_digest: RouterAbPublicDigest32V1Wire;
  server_generation: EcdsaServerGeneration;
  ecdsa_activation: {
    context: RouterAbEcdsaDerivationStableKeyContextV1;
    public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
    signing_worker: RouterAbServerIdentityV1;
    material_activation: RouterAbMpcMaterialActivationRefWire;
    activation_epoch: RootShareEpoch;
    activation_digest_b64u: string;
    activated_at_ms: number;
  };
  lifecycle_id: string;
  transcript_digest: RouterAbPublicDigest32V1Wire;
};

export type RouterAbEcdsaDerivationActivationPrepareResultV1 = {
  activation_correlation_id: CorrelationId;
  activation_request_digest: RouterAbPublicDigest32V1Wire;
};

export type RouterAbEcdsaDerivationActivationCommitQueryResultV1 =
  | {
      kind: 'committed';
      receipt: RouterAbEcdsaRegistrationActivationReceiptV1;
      activation_correlation_id?: never;
      activation_request_digest?: never;
    }
  | {
      kind: 'not_committed';
      activation_correlation_id: CorrelationId;
      activation_request_digest: RouterAbPublicDigest32V1Wire;
      receipt?: never;
    }
  | {
      kind: 'correlation_conflict';
      activation_correlation_id: CorrelationId;
      activation_request_digest: RouterAbPublicDigest32V1Wire;
      receipt?: never;
    };

export type RouterAbEcdsaRegistrationPublicActivationReceiptV1 =
  RouterAbEcdsaRegistrationActivationReceiptV1;

export type RouterAbEcdsaDerivationPublicCapabilityV1 = {
  kind: 'router_ab_ecdsa_derivation_public_capability_v1';
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
  material_activation: RouterAbMpcMaterialActivationRefWire;
  signer_set: RouterAbEcdsaDerivationSignerSetV1;
  deriver_recipient_keys: RouterAbEcdsaRegistrationRecipientKeysV1;
  router_id: string;
  client_id: string;
  activation_epoch: RootShareEpoch;
  registration_request_digest_b64u: string;
  proof_transcript_digest_b64u: string;
};

export type RouterAbEcdsaPostRegistrationSessionPolicyV1 = {
  threshold_session_id: ThresholdEcdsaSessionId;
  wallet_session_mint_id: ReusableWalletSessionMintId;
  ttl_ms: number;
  remaining_uses: number;
  runtime_policy_scope: RuntimePolicyScope;
};

/**
 * Unlock callers select a persisted key by its exact handle and provide only
 * the session budget. The authenticated router resolves the public capability
 * before constructing the canonical activation request.
 */
export type RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 = {
  kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1';
  key_handle: string;
  session_policy: RouterAbEcdsaPostRegistrationSessionPolicyV1;
};

export type RouterAbEcdsaPostRegistrationSessionActivationRequestV1 = {
  kind: 'router_ab_ecdsa_post_registration_session_activation_v1';
  public_capability: RouterAbEcdsaDerivationPublicCapabilityV1;
  session_policy: RouterAbEcdsaPostRegistrationSessionPolicyV1;
};

export type RouterAbEcdsaPostRegistrationSessionActivationResponseV1 = {
  kind: 'router_ab_ecdsa_post_registration_session_activated_v1';
  public_capability: RouterAbEcdsaDerivationPublicCapabilityV1;
  session: {
    authorization_session_id: SeamsSessionId;
    threshold_session_id: ThresholdEcdsaSessionId;
    wallet_session_id: WalletSessionId;
    quota_id: MpcWalletSigningQuotaId;
    expires_at_ms: number;
    remaining_uses: number;
    wallet_session_jwt: string;
  };
  normal_signing: RouterAbEcdsaDerivationNormalSigningStateV1;
};

export type RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<Role extends 'signer_a' | 'signer_b'> = {
  recipient_role: Role;
  header_digest: RouterAbPublicDigest32V1Wire;
  aad_digest: RouterAbPublicDigest32V1Wire;
  ciphertext: { bytes: number[] };
};

export type RouterAbEcdsaDerivationExplicitExportRequestBaseV1 = {
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  lifecycle: RouterAbEcdsaDerivationExportLifecycleScopeV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
  signer_set: RouterAbEcdsaDerivationSignerSetV1;
  router_id: string;
  client_id: string;
  client_ephemeral_public_key: string;
  // The discriminated operation authority and the exact material activation
  // this export binds. Session and grant identifiers never re-enter this
  // request outside the authorization branch.
  material_activation: RouterAbMpcMaterialActivationRefWire;
  export_authorization_digest_b64u: string;
  export_nonce: string;
  expires_at_ms: number;
  deriver_a_export_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  deriver_b_export_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
};

/**
 * Exact explicit-export request carried by the Rust Router A/B protocol.
 * Operation preparation is a Gateway authorization input and never crosses
 * into the protocol request or its canonical digest.
 */
export type RouterAbEcdsaDerivationExplicitExportProtocolRequestV1 =
  RouterAbEcdsaDerivationExplicitExportRequestBaseV1 & {
    authorization: RouterAbNormalSigningAuthorizationWire;
  };

export type RouterAbEcdsaDerivationExplicitExportRequestV1 =
  | (RouterAbEcdsaDerivationExplicitExportRequestBaseV1 & {
      authorization: Extract<
        RouterAbNormalSigningAuthorizationWire,
        { readonly kind: 'reusable_wallet_session' }
      >;
      operation?: never;
    })
  | (RouterAbEcdsaDerivationExplicitExportRequestBaseV1 & {
      authorization: Extract<
        RouterAbNormalSigningAuthorizationWire,
        { readonly kind: 'operation_step_up' }
      >;
      operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
    });

export function projectRouterAbEcdsaDerivationExplicitExportRequestToProtocolV1(
  request: RouterAbEcdsaDerivationExplicitExportRequestV1,
): RouterAbEcdsaDerivationExplicitExportProtocolRequestV1 {
  switch (request.authorization.kind) {
    case 'reusable_wallet_session': {
      const { operation: _operation, ...protocolRequest } = request;
      return protocolRequest;
    }
    case 'operation_step_up': {
      const { operation: _operation, ...protocolRequest } = request;
      return protocolRequest;
    }
  }
}

export type RouterAbEcdsaDerivationActivationRefreshRequestV1 = {
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  lifecycle: RouterAbEcdsaDerivationRefreshLifecycleScopeV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
  signer_set: RouterAbEcdsaDerivationSignerSetV1;
  router_id: string;
  client_id: string;
  signing_worker_ephemeral_public_key: string;
  refresh_authorization_digest_b64u: string;
  refresh_nonce: string;
  previous_activation_epoch: RootShareEpoch;
  next_activation_epoch: RootShareEpoch;
  material_activation: RouterAbMpcMaterialActivationRefWire;
  expires_at_ms: number;
  deriver_a_refresh_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  deriver_b_refresh_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
};

export type RouterAbEcdsaDerivationActivationRefreshCommitRequestV1 = {
  activation_correlation_id: CorrelationId;
  expected_server_generation: EcdsaServerGeneration;
  refresh_request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
};

export type RouterAbEcdsaDerivationActivationRefreshActivationCommittedResponseV1 = {
  result: 'activation_committed';
  signing_worker_activation: RouterAbEcdsaRegistrationActivationReceiptV1;
  response?: never;
  replay?: never;
  lifecycle?: never;
  decision?: never;
};

export type RouterAbEcdsaDerivationActivationRefreshStoppedResponseV1 = {
  result: 'stopped';
  replay: {
    request_id: string;
    reserved: boolean;
  };
  lifecycle: {
    lifecycle_id: string;
    stored: boolean;
  };
  decision:
    | {
        kind: 'accepted';
        request_id: string;
        existing_lifecycle_id?: never;
        reason?: never;
        retry_after_ms?: never;
      }
    | {
        kind: 'reuse_existing';
        request_id: string;
        existing_lifecycle_id: string;
        reason?: never;
        retry_after_ms?: never;
      }
    | {
        kind: 'defer';
        reason: 'short_window_saturated' | 'signer_queue_saturated';
        request_id?: never;
        existing_lifecycle_id?: never;
        retry_after_ms?: never;
      }
    | {
        kind: 'rejected';
        reason: 'rate_limited' | 'abuse_policy';
        retry_after_ms: number;
        request_id?: never;
        existing_lifecycle_id?: never;
      };
  response?: never;
  signing_worker_activation?: never;
};

export type RouterAbEcdsaDerivationActivationRefreshResponseV1 =
  | RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1
  | RouterAbEcdsaDerivationActivationRefreshActivationCommittedResponseV1
  | RouterAbEcdsaDerivationActivationRefreshStoppedResponseV1;

export type RouterAbPublicDigest32V1Wire = {
  bytes: number[];
};

export type RouterAbActiveSigningWorkerStateV1 = {
  account_id: string;
  material_activation: RouterAbMpcMaterialActivationRefWire;
  account_public_key: string;
  signing_worker: RouterAbServerIdentityV1;
  activation_transcript_digest: RouterAbPublicDigest32V1Wire;
  activation_digest: RouterAbPublicDigest32V1Wire;
  signing_worker_material_handle: string;
  activated_at_ms: number;
};

export type RouterAbEcdsaDerivationNormalSigningScopeV1 = {
  wallet_id: string;
  ecdsa_threshold_key_id: string;
  signing_root_id: string;
  signing_root_version: string;
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
  material_activation: RouterAbMpcMaterialActivationRefWire;
  signing_worker: RouterAbServerIdentityV1;
  activation_epoch: RootShareEpoch;
};

export type RouterAbEcdsaDerivationNormalSigningStateV1 = {
  kind: typeof ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
};

export type RouterAbEcdsaDerivationServerPresignatureShareV1 = {
  serverKeyId: string;
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
  createdAtMs: number;
};

export type CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  server_presignature_id: string;
  server_big_r33_b64u: string;
  server_k_share32_b64u: string;
  server_sigma_share32_b64u: string;
  expires_at_ms: number;
};

export type CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire = {
  active_signing_worker_state: RouterAbActiveSigningWorkerStateV1;
  server_presignature_id: string;
  server_big_r33_b64u: string;
  stored: boolean;
};

export type RouterAbEcdsaDerivationSignatureSchemeV1Wire = 'ecdsa_secp256k1_recoverable_v1';

export type RouterAbEcdsaDerivationOperationDigestsV1Wire = {
  lane_digest_b64u: string;
  intent_digest_b64u: string;
  display_digest_b64u: string;
};

type RouterAbEcdsaDerivationEvmDigestSigningRequestBaseV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  request_id: string;
  operation_id: string;
  operation_digests: RouterAbEcdsaDerivationOperationDigestsV1Wire;
  material_activation: RouterAbMpcMaterialActivationRefWire;
  client_presignature_id: string;
  expires_at_ms: number;
  signing_digest_b64u: string;
  client_rerandomization_commitment32_b64u: string;
};

export type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire =
  RouterAbEcdsaDerivationEvmDigestSigningRequestBaseV1Wire & {
    authorization: RouterAbNormalSigningAuthorizationWire;
  };

export type RouterAbEcdsaOperationStepUpWebAuthnCredentialV1Wire = {
  readonly id: string;
  readonly rawId: string;
  readonly type: string;
  readonly authenticatorAttachment: string | null;
  readonly response: {
    readonly clientDataJSON: string;
    readonly authenticatorData: string;
    readonly signature: string;
    readonly userHandle: string | null;
  };
  readonly clientExtensionResults: unknown | null;
};

export type RouterAbEcdsaOperationStepUpPreparationV1Wire = {
  readonly wallet_id: string;
  readonly operation_kind: EvmEcdsaMpcOperationKind;
  readonly operation_id: string;
  readonly operation_digests: RouterAbEcdsaDerivationOperationDigestsV1Wire;
  readonly material_activation: RouterAbMpcMaterialActivationRefWire;
  readonly normal_signing_scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  readonly signing_worker_id: string;
  readonly key_handle: string;
  readonly relayer_key_id: string;
  readonly participant_ids: readonly [number, number];
  readonly expires_at_ms: number;
};

export type RouterAbEcdsaOperationStepUpProofV1Wire =
  | {
      readonly kind: 'passkey';
      readonly authority: PasskeyWalletAuthAuthority;
      readonly webauthn_authentication: RouterAbEcdsaOperationStepUpWebAuthnCredentialV1Wire;
      readonly challenge_id?: never;
      readonly otp_code?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly authority: EmailOtpWalletAuthAuthority;
      readonly challenge_id: string;
      readonly otp_code: string;
      readonly webauthn_authentication?: never;
    };

export type RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire = {
  readonly kind: 'router_ab_ecdsa_operation_step_up_v1';
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  readonly proof: RouterAbEcdsaOperationStepUpProofV1Wire;
};

export type RouterAbEcdsaOperationStepUpUnsealV1Wire =
  | {
      readonly kind: 'not_requested';
    }
  | {
      readonly kind: 'email_otp_grant';
      readonly grant: string;
      readonly challenge_id: string;
    };

export type RouterAbEcdsaOperationStepUpAuthorizationV1Wire = {
  readonly kind: 'operation_step_up';
  readonly evidence_set_digest: DigestB64u;
  readonly unseal: RouterAbEcdsaOperationStepUpUnsealV1Wire;
};

export type RouterAbEcdsaOperationStepUpAuthorizationResponseV1Wire = {
  readonly ok: true;
  readonly kind: 'verified_step_up';
  readonly authorization: RouterAbEcdsaOperationStepUpAuthorizationV1Wire;
  readonly expires_at_ms: number;
};

export function parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1(
  value: unknown,
): RouterAbEcdsaOperationStepUpAuthorizationResponseV1Wire {
  const response = requireRecord(value, 'operationStepUpAuthorizationResponse');
  requireExactKeys(response, 'operationStepUpAuthorizationResponse', [
    'ok',
    'kind',
    'authorization',
    'expires_at_ms',
  ]);
  if (response.ok !== true || response.kind !== 'verified_step_up') {
    throw new Error('operationStepUpAuthorizationResponse is invalid');
  }
  const authorization = requireRecord(
    response.authorization,
    'operationStepUpAuthorizationResponse.authorization',
  );
  requireExactKeys(authorization, 'operationStepUpAuthorizationResponse.authorization', [
    'kind',
    'evidence_set_digest',
    'unseal',
  ]);
  if (authorization.kind !== 'operation_step_up') {
    throw new Error('operationStepUpAuthorizationResponse.authorization.kind is invalid');
  }
  const expiresAtMs = requirePositiveUnixMs(
    response.expires_at_ms,
    'operationStepUpAuthorizationResponse.expires_at_ms',
  );
  if (expiresAtMs <= Date.now()) {
    throw new Error('operationStepUpAuthorizationResponse.expires_at_ms is expired');
  }
  const unseal = requireRecord(
    authorization.unseal,
    'operationStepUpAuthorizationResponse.authorization.unseal',
  );
  const unsealKind = requireAsciiNonEmptyString(
    unseal.kind,
    'operationStepUpAuthorizationResponse.authorization.unseal.kind',
  );
  let parsedUnseal: RouterAbEcdsaOperationStepUpUnsealV1Wire;
  switch (unsealKind) {
    case 'not_requested':
      requireExactKeys(unseal, 'operationStepUpAuthorizationResponse.authorization.unseal', [
        'kind',
      ]);
      parsedUnseal = { kind: 'not_requested' };
      break;
    case 'email_otp_grant':
      requireExactKeys(unseal, 'operationStepUpAuthorizationResponse.authorization.unseal', [
        'kind',
        'grant',
        'challenge_id',
      ]);
      parsedUnseal = {
        kind: 'email_otp_grant',
        grant: requireAsciiNonEmptyString(
          unseal.grant,
          'operationStepUpAuthorizationResponse.authorization.unseal.grant',
        ),
        challenge_id: requireAsciiNonEmptyString(
          unseal.challenge_id,
          'operationStepUpAuthorizationResponse.authorization.unseal.challenge_id',
        ),
      };
      break;
    default:
      throw new Error('operationStepUpAuthorizationResponse.authorization.unseal.kind is invalid');
  }
  const parsedAuthorization = {
    kind: 'operation_step_up' as const,
    evidence_set_digest: parseDigestB64u(authorization.evidence_set_digest),
    unseal: parsedUnseal,
  };
  return {
    ok: true,
    kind: 'verified_step_up',
    authorization: parsedAuthorization,
    expires_at_ms: expiresAtMs,
  };
}

export async function computeRouterAbEcdsaOperationStepUpChallengeB64u(
  value: RouterAbEcdsaOperationStepUpPreparationV1Wire,
): Promise<string> {
  const operation = parseRouterAbEcdsaOperationStepUpPreparationV1(value);
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        domain: ROUTER_AB_ECDSA_OPERATION_STEP_UP_CHALLENGE_DOMAIN_V1,
        operation,
      }),
    ),
  );
}

type RouterAbEcdsaDerivationEvmDigestSigningFinalizeBaseV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  request_id: string;
  operation_id: string;
  operation_digests: RouterAbEcdsaDerivationOperationDigestsV1Wire;
  material_activation: RouterAbMpcMaterialActivationRefWire;
  expires_at_ms: number;
  signing_digest_b64u: string;
  server_presignature_id: string;
  client_signature_share32_b64u: string;
  client_rerandomization_contribution32_b64u: string;
};

export type RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire =
  RouterAbEcdsaDerivationEvmDigestSigningFinalizeBaseV1Wire & {
    authorization: RouterAbNormalSigningAuthorizationWire;
  };

export type RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire =
  RouterAbEcdsaDerivationEvmDigestSigningFinalizeBaseV1Wire & {
    authorization: RouterAbNormalSigningAuthorizationWire;
  };

export type RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  request_id: string;
  request_digest: RouterAbPublicDigest32V1Wire;
  signing_digest: RouterAbPublicDigest32V1Wire;
  server_presignature_id: string;
  server_big_r33_b64u: string;
  signing_worker_rerandomization_contribution32_b64u: string;
  signature_scheme: RouterAbEcdsaDerivationSignatureSchemeV1Wire;
  prepared_at_ms: number;
  expires_at_ms: number;
};

export type RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  request_id: string;
  request_digest: RouterAbPublicDigest32V1Wire;
  signing_digest: RouterAbPublicDigest32V1Wire;
  signature_scheme: RouterAbEcdsaDerivationSignatureSchemeV1Wire;
  signature65_b64u: string;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error(`${label} must be an object`);
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  allowedKeys: readonly string[],
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`${label}.${key} is not a supported field`);
  }
}

function requireAsciiNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const parsed = value.trim();
  if (!parsed) throw new Error(`${label} is required`);
  if (!/^[\x20-\x7e]+$/.test(parsed)) throw new Error(`${label} must be printable ASCII`);
  return parsed;
}

function requireRootShareEpoch(value: unknown, label: string): RootShareEpoch {
  const parsed = parseRootShareEpoch(requireAsciiNonEmptyString(value, label));
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function requireThresholdEcdsaSessionId(value: unknown, label: string): ThresholdEcdsaSessionId {
  const parsed = parseThresholdEcdsaSessionId(requireAsciiNonEmptyString(value, label));
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function requireSeamsSessionId(value: unknown, label: string): SeamsSessionId {
  const parsed = parseSeamsSessionId(value);
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function requireWalletSessionId(value: unknown, label: string): WalletSessionId {
  const parsed = parseWalletSessionId(value);
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function requireMpcWalletSigningQuotaId(value: unknown, label: string): MpcWalletSigningQuotaId {
  const parsed = parseMpcWalletSigningQuotaId(value);
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function requirePositiveUnixMs(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function requirePositiveCounter(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe-integer counter`);
  }
  return value;
}

function requireNonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  const parsed = Math.floor(value);
  if (parsed !== value || parsed < 0) throw new Error(`${label} must be a non-negative integer`);
  return parsed;
}

function requireU32(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  const parsed = Math.floor(value);
  if (parsed !== value || parsed < 0 || parsed > 0xffffffff) {
    throw new Error(`${label} must be a u32 integer`);
  }
  return parsed;
}

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

function requireByte(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  const parsed = Math.floor(value);
  if (parsed !== value || parsed < 0 || parsed > 255) {
    throw new Error(`${label} must be a byte`);
  }
  return parsed;
}

function requireBase64UrlFixed(value: unknown, label: string, byteLength: number): string {
  const parsed = requireAsciiNonEmptyString(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(parsed)) {
    throw new Error(`${label} must be unpadded base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(parsed);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (decoded.length !== byteLength) {
    throw new Error(`${label} must decode to ${byteLength} bytes`);
  }
  return parsed;
}

function requireCompressedSecp256k1PublicKey(value: unknown, label: string): string {
  const parsed = requireBase64UrlFixed(value, label, 33);
  const decoded = base64UrlDecode(parsed);
  if (decoded[0] !== 0x02 && decoded[0] !== 0x03) {
    throw new Error(`${label} must be a compressed secp256k1 public key`);
  }
  return parsed;
}

function requireBase64UrlNonEmpty(value: unknown, label: string): string {
  const parsed = requireAsciiNonEmptyString(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(parsed)) {
    throw new Error(`${label} must be unpadded base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(parsed);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (decoded.length === 0) throw new Error(`${label} must decode to non-empty bytes`);
  return parsed;
}

function requireLowerHexFixed(value: unknown, label: string, byteLength: number): string {
  const parsed = requireAsciiNonEmptyString(value, label);
  if (!new RegExp(`^[0-9a-f]{${byteLength * 2}}$`).test(parsed)) {
    throw new Error(`${label} must contain ${byteLength} lowercase hexadecimal bytes`);
  }
  return parsed;
}

function requireX25519PublicKey(value: unknown, label: string): string {
  const parsed = requireAsciiNonEmptyString(value, label);
  if (!/^x25519:[0-9a-f]{64}$/.test(parsed)) {
    throw new Error(`${label} must use x25519:<64 lowercase hex chars> encoding`);
  }
  return parsed;
}

function requireUint8ArrayFixed(value: unknown, label: string, byteLength: number): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error(`${label} must be a Uint8Array`);
  if (value.length !== byteLength) throw new Error(`${label} must contain ${byteLength} bytes`);
  return value;
}

function requireSignatureScheme(
  value: unknown,
  label: string,
): RouterAbEcdsaDerivationSignatureSchemeV1Wire {
  const parsed = requireAsciiNonEmptyString(value, label);
  if (parsed !== 'ecdsa_secp256k1_recoverable_v1') {
    throw new Error(`${label} must be ecdsa_secp256k1_recoverable_v1`);
  }
  return parsed;
}

function parsePublicDigest32(value: unknown, label: string): RouterAbPublicDigest32V1Wire {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['bytes']);
  if (!Array.isArray(record.bytes)) throw new Error(`${label}.bytes must be an array`);
  if (record.bytes.length !== 32) throw new Error(`${label}.bytes must contain 32 bytes`);
  return {
    bytes: record.bytes.map((entry, index) => requireByte(entry, `${label}.bytes[${index}]`)),
  };
}

function parseStableKeyContext(value: unknown): RouterAbEcdsaDerivationStableKeyContextV1 {
  const record = requireRecord(value, 'scope.context');
  requireExactKeys(record, 'scope.context', ['application_binding_digest_b64u']);
  const digest = base64UrlDecode(
    requireAsciiNonEmptyString(
      record.application_binding_digest_b64u,
      'scope.context.application_binding_digest_b64u',
    ),
  );
  if (digest.length !== 32) {
    throw new Error('scope.context.application_binding_digest_b64u must decode to 32 bytes');
  }
  return {
    application_binding_digest_b64u: base64UrlEncode(digest),
  };
}

function parsePublicIdentity(value: unknown): RouterAbEcdsaDerivationPublicIdentityV1 {
  const record = requireRecord(value, 'scope.public_identity');
  requireExactKeys(record, 'scope.public_identity', [
    'context_binding_b64u',
    'derivation_client_share_public_key33_b64u',
    'server_public_key33_b64u',
    'threshold_public_key33_b64u',
    'ethereum_address20_b64u',
    'client_share_retry_counter',
    'server_share_retry_counter',
  ]);
  return {
    context_binding_b64u: requireBase64UrlFixed(
      record.context_binding_b64u,
      'scope.public_identity.context_binding_b64u',
      32,
    ),
    derivation_client_share_public_key33_b64u: requireCompressedSecp256k1PublicKey(
      record.derivation_client_share_public_key33_b64u,
      'scope.public_identity.derivation_client_share_public_key33_b64u',
    ),
    server_public_key33_b64u: requireCompressedSecp256k1PublicKey(
      record.server_public_key33_b64u,
      'scope.public_identity.server_public_key33_b64u',
    ),
    threshold_public_key33_b64u: requireCompressedSecp256k1PublicKey(
      record.threshold_public_key33_b64u,
      'scope.public_identity.threshold_public_key33_b64u',
    ),
    ethereum_address20_b64u: requireBase64UrlFixed(
      record.ethereum_address20_b64u,
      'scope.public_identity.ethereum_address20_b64u',
      20,
    ),
    client_share_retry_counter: requireU32(
      record.client_share_retry_counter,
      'scope.public_identity.client_share_retry_counter',
    ),
    server_share_retry_counter: requireU32(
      record.server_share_retry_counter,
      'scope.public_identity.server_share_retry_counter',
    ),
  };
}

function parseServerIdentity(value: unknown): RouterAbServerIdentityV1 {
  return parseServerIdentityWithLabel(value, 'scope.signing_worker');
}

function parseServerIdentityWithLabel(value: unknown, label: string): RouterAbServerIdentityV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['server_id', 'key_epoch', 'recipient_encryption_key']);
  return {
    server_id: requireAsciiNonEmptyString(record.server_id, `${label}.server_id`),
    key_epoch: requireAsciiNonEmptyString(record.key_epoch, `${label}.key_epoch`),
    recipient_encryption_key: requireRouterAbX25519PublicKey(
      record.recipient_encryption_key,
      `${label}.recipient_encryption_key`,
    ),
  };
}

function parsePostRegistrationLifecycleScope<
  WorkKind extends 'key_export' | 'recovery' | 'server_share_refresh',
  PrimitiveRequestKind extends 'export' | 'recovery' | 'refresh',
>(
  value: unknown,
  label: string,
  expectedWorkKind: WorkKind,
  expectedPrimitiveRequestKind: PrimitiveRequestKind,
): RouterAbEcdsaDerivationPostRegistrationLifecycleScopeV1<WorkKind, PrimitiveRequestKind> {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'lifecycle_id',
    'work_kind',
    'primitive_request_kind',
    'root_share_epoch',
    'account_id',
    'session_id',
    'signer_set_id',
    'selected_server_id',
  ]);
  const workKind = requireAsciiNonEmptyString(record.work_kind, `${label}.work_kind`);
  if (workKind !== expectedWorkKind) {
    throw new Error(`${label}.work_kind must be ${expectedWorkKind}`);
  }
  const requestKind = requireAsciiNonEmptyString(
    record.primitive_request_kind,
    `${label}.primitive_request_kind`,
  );
  if (requestKind !== expectedPrimitiveRequestKind) {
    throw new Error(`${label}.primitive_request_kind must be ${expectedPrimitiveRequestKind}`);
  }
  return {
    lifecycle_id: requireAsciiNonEmptyString(record.lifecycle_id, `${label}.lifecycle_id`),
    work_kind: expectedWorkKind,
    primitive_request_kind: expectedPrimitiveRequestKind,
    root_share_epoch: requireRootShareEpoch(record.root_share_epoch, `${label}.root_share_epoch`),
    account_id: requireAsciiNonEmptyString(record.account_id, `${label}.account_id`),
    session_id: requireThresholdEcdsaSessionId(record.session_id, `${label}.session_id`),
    signer_set_id: requireAsciiNonEmptyString(record.signer_set_id, `${label}.signer_set_id`),
    selected_server_id: requireAsciiNonEmptyString(
      record.selected_server_id,
      `${label}.selected_server_id`,
    ),
  };
}

function parsePostRegistrationSignerIdentity<Role extends 'signer_a' | 'signer_b'>(
  value: unknown,
  label: string,
  expectedRole: Role,
): RouterAbEcdsaDerivationSignerIdentityV1<Role> {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['role', 'signer_id', 'key_epoch']);
  const role = requireAsciiNonEmptyString(record.role, `${label}.role`);
  if (role !== expectedRole) throw new Error(`${label}.role must be ${expectedRole}`);
  return {
    role: expectedRole,
    signer_id: requireAsciiNonEmptyString(record.signer_id, `${label}.signer_id`),
    key_epoch: requireAsciiNonEmptyString(record.key_epoch, `${label}.key_epoch`),
  };
}

function parsePostRegistrationSignerSet(
  value: unknown,
  label: string,
): RouterAbEcdsaDerivationSignerSetV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'signer_set_id',
    'policy',
    'signer_a',
    'signer_b',
    'selected_server',
  ]);
  const policy = requireAsciiNonEmptyString(record.policy, `${label}.policy`);
  if (policy !== 'all_2') throw new Error(`${label}.policy must be all_2`);
  const signerA = parsePostRegistrationSignerIdentity(
    record.signer_a,
    `${label}.signer_a`,
    'signer_a',
  );
  const signerB = parsePostRegistrationSignerIdentity(
    record.signer_b,
    `${label}.signer_b`,
    'signer_b',
  );
  if (signerA.signer_id === signerB.signer_id) {
    throw new Error(`${label} requires distinct signer ids`);
  }
  return {
    signer_set_id: requireAsciiNonEmptyString(record.signer_set_id, `${label}.signer_set_id`),
    policy,
    signer_a: signerA,
    signer_b: signerB,
    selected_server: parseServerIdentityWithLabel(
      record.selected_server,
      `${label}.selected_server`,
    ),
  };
}

function parsePostRegistrationRoleEnvelope<Role extends 'signer_a' | 'signer_b'>(
  value: unknown,
  label: string,
  expectedRole: Role,
): RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<Role> {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['recipient_role', 'header_digest', 'aad_digest', 'ciphertext']);
  const recipientRole = requireAsciiNonEmptyString(
    record.recipient_role,
    `${label}.recipient_role`,
  );
  if (recipientRole !== expectedRole) {
    throw new Error(`${label}.recipient_role must be ${expectedRole}`);
  }
  const ciphertextRecord = requireRecord(record.ciphertext, `${label}.ciphertext`);
  requireExactKeys(ciphertextRecord, `${label}.ciphertext`, ['bytes']);
  if (!Array.isArray(ciphertextRecord.bytes) || ciphertextRecord.bytes.length === 0) {
    throw new Error(`${label}.ciphertext.bytes must be a non-empty byte array`);
  }
  return {
    recipient_role: expectedRole,
    header_digest: parsePublicDigest32(record.header_digest, `${label}.header_digest`),
    aad_digest: parsePublicDigest32(record.aad_digest, `${label}.aad_digest`),
    ciphertext: {
      bytes: ciphertextRecord.bytes.map((entry, index) =>
        requireByte(entry, `${label}.ciphertext.bytes[${index}]`),
      ),
    },
  };
}

function parseRegistrationLifecycle(value: unknown): RouterAbEcdsaRegistrationLifecycleV1 {
  const label = 'registration.lifecycle';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'lifecycle_id',
    'work_kind',
    'primitive_request_kind',
    'root_share_epoch',
    'account_id',
    'session_id',
    'signer_set_id',
    'selected_server_id',
  ]);
  if (record.work_kind !== 'registration_prepare') {
    throw new Error(`${label}.work_kind must be registration_prepare`);
  }
  if (record.primitive_request_kind !== 'registration') {
    throw new Error(`${label}.primitive_request_kind must be registration`);
  }
  return {
    lifecycle_id: requireAsciiNonEmptyString(record.lifecycle_id, `${label}.lifecycle_id`),
    work_kind: 'registration_prepare',
    primitive_request_kind: 'registration',
    root_share_epoch: requireRootShareEpoch(record.root_share_epoch, `${label}.root_share_epoch`),
    account_id: requireAsciiNonEmptyString(record.account_id, `${label}.account_id`),
    session_id: requireAsciiNonEmptyString(record.session_id, `${label}.session_id`),
    signer_set_id: requireAsciiNonEmptyString(record.signer_set_id, `${label}.signer_set_id`),
    selected_server_id: requireAsciiNonEmptyString(
      record.selected_server_id,
      `${label}.selected_server_id`,
    ),
  };
}

function parseRegistrationRecipientKey<Role extends 'signer_a' | 'signer_b'>(
  value: unknown,
  label: string,
  role: Role,
): { role: Role; key_epoch: string; public_key: string } {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['role', 'key_epoch', 'public_key']);
  if (record.role !== role) {
    throw new Error(`${label}.role must be ${role}`);
  }
  return {
    role,
    key_epoch: requireAsciiNonEmptyString(record.key_epoch, `${label}.key_epoch`),
    public_key: requireRouterAbX25519PublicKey(record.public_key, `${label}.public_key`),
  };
}

function parseRegistrationRecipientKeys(
  value: unknown,
  label = 'registration.deriver_recipient_keys',
): RouterAbEcdsaRegistrationRecipientKeysV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['deriver_a', 'deriver_b']);
  return {
    deriver_a: parseRegistrationRecipientKey(record.deriver_a, `${label}.deriver_a`, 'signer_a'),
    deriver_b: parseRegistrationRecipientKey(record.deriver_b, `${label}.deriver_b`, 'signer_b'),
  };
}

export function parseRouterAbEcdsaRegistrationRequestFactsV1(
  value: unknown,
): RouterAbEcdsaRegistrationRequestFactsV1 {
  const label = 'registration';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'registration_purpose',
    'context',
    'lifecycle',
    'signer_set',
    'router_id',
    'client_id',
    'replay_nonce',
    'expires_at_ms',
    'deriver_recipient_keys',
  ]);
  if (
    record.registration_purpose !== 'wallet_registration' &&
    record.registration_purpose !== 'wallet_add_signer'
  ) {
    throw new Error(`${label}.registration_purpose is invalid`);
  }
  const lifecycle = parseRegistrationLifecycle(record.lifecycle);
  const signerSet = parsePostRegistrationSignerSet(record.signer_set, `${label}.signer_set`);
  if (lifecycle.signer_set_id !== signerSet.signer_set_id) {
    throw new Error(`${label}.lifecycle signer set does not match signer_set`);
  }
  if (lifecycle.selected_server_id !== signerSet.selected_server.server_id) {
    throw new Error(`${label}.lifecycle selected server does not match signer_set`);
  }
  const recipientKeys = parseRegistrationRecipientKeys(record.deriver_recipient_keys);
  if (recipientKeys.deriver_a.key_epoch !== signerSet.signer_a.key_epoch) {
    throw new Error(`${label}.deriver_a recipient key epoch does not match signer_set`);
  }
  if (recipientKeys.deriver_b.key_epoch !== signerSet.signer_b.key_epoch) {
    throw new Error(`${label}.deriver_b recipient key epoch does not match signer_set`);
  }
  return {
    registration_purpose: record.registration_purpose,
    context: parseStableKeyContext(record.context),
    lifecycle,
    signer_set: signerSet,
    router_id: requireAsciiNonEmptyString(record.router_id, `${label}.router_id`),
    client_id: requireAsciiNonEmptyString(record.client_id, `${label}.client_id`),
    replay_nonce: requireAsciiNonEmptyString(record.replay_nonce, `${label}.replay_nonce`),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, `${label}.expires_at_ms`),
    deriver_recipient_keys: recipientKeys,
  };
}

export function parseRouterAbEcdsaRegistrationRequestV1(
  value: unknown,
): RouterAbEcdsaRegistrationRequestV1 {
  const label = 'registration';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'registration_purpose',
    'context',
    'lifecycle',
    'signer_set',
    'router_id',
    'client_id',
    'client_ephemeral_public_key',
    'replay_nonce',
    'expires_at_ms',
    'deriver_a_envelope',
    'deriver_b_envelope',
  ]);
  if (
    record.registration_purpose !== 'wallet_registration' &&
    record.registration_purpose !== 'wallet_add_signer'
  ) {
    throw new Error(`${label}.registration_purpose is invalid`);
  }
  const lifecycle = parseRegistrationLifecycle(record.lifecycle);
  const signerSet = parsePostRegistrationSignerSet(record.signer_set, `${label}.signer_set`);
  if (lifecycle.signer_set_id !== signerSet.signer_set_id) {
    throw new Error(`${label}.lifecycle signer set does not match signer_set`);
  }
  if (lifecycle.selected_server_id !== signerSet.selected_server.server_id) {
    throw new Error(`${label}.lifecycle selected server does not match signer_set`);
  }
  return {
    registration_purpose: record.registration_purpose,
    context: parseStableKeyContext(record.context),
    lifecycle,
    signer_set: signerSet,
    router_id: requireAsciiNonEmptyString(record.router_id, `${label}.router_id`),
    client_id: requireAsciiNonEmptyString(record.client_id, `${label}.client_id`),
    client_ephemeral_public_key: requireX25519PublicKey(
      record.client_ephemeral_public_key,
      `${label}.client_ephemeral_public_key`,
    ),
    replay_nonce: requireAsciiNonEmptyString(record.replay_nonce, `${label}.replay_nonce`),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, `${label}.expires_at_ms`),
    deriver_a_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_a_envelope,
      `${label}.deriver_a_envelope`,
      'signer_a',
    ),
    deriver_b_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_b_envelope,
      `${label}.deriver_b_envelope`,
      'signer_b',
    ),
  };
}

function parseRouterAbEcdsaClientProofBundleV1(
  value: unknown,
  label: string,
): RouterAbEcdsaClientProofBundleV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['kind', 'transcriptDigestB64u', 'payloadB64u']);
  if (record.kind !== 'recipient_proof_bundle') {
    throw new Error(`${label}.kind must be recipient_proof_bundle`);
  }
  return {
    kind: 'recipient_proof_bundle',
    transcriptDigestB64u: requireBase64UrlFixed(
      record.transcriptDigestB64u,
      `${label}.transcriptDigestB64u`,
      32,
    ),
    payloadB64u: requireBase64UrlNonEmpty(record.payloadB64u, `${label}.payloadB64u`),
  };
}

export function parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(
  value: unknown,
): RouterAbEcdsaStrictForwardedRegistrationResponseV1 {
  const label = 'registrationForwarded';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['result', 'response']);
  if (record.result !== 'forwarded') {
    throw new Error(`${label}.result must be forwarded`);
  }
  return {
    result: 'forwarded',
    response: parseRouterAbEcdsaStrictProofResponseV1(record.response, `${label}.response`),
  };
}

export function parseRouterAbEcdsaExplicitExportForwardedResponseV1(
  value: unknown,
): RouterAbEcdsaExplicitExportForwardedResponseV1 {
  const label = 'explicitExportForwarded';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['result', 'response', 'signing_worker_export']);
  if (record.result !== 'forwarded') {
    throw new Error(`${label}.result must be forwarded`);
  }
  return {
    result: 'forwarded',
    response: parseRouterAbEcdsaStrictProofResponseV1(record.response, `${label}.response`),
    signing_worker_export: parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1(
      record.signing_worker_export,
    ),
  };
}

function parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1(
  value: unknown,
): RouterAbEcdsaSigningWorkerExportShareEnvelopeV1 {
  const label = 'signingWorkerExportShare';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['version', 'algorithm', 'binding', 'ciphertext_and_tag']);
  if (record.version !== 'router-ab-ecdsa-derivation/signing-worker-export-share-envelope/v1') {
    throw new Error(`${label}.version is invalid`);
  }
  if (record.algorithm !== 'hpke_x25519_hkdf_sha256_aes256gcm_v1') {
    throw new Error(`${label}.algorithm is invalid`);
  }
  const bindingLabel = `${label}.binding`;
  const binding = requireRecord(record.binding, bindingLabel);
  requireExactKeys(binding, bindingLabel, [
    'wallet_id',
    'key_handle',
    'ecdsa_threshold_key_id',
    'signing_root_id',
    'signing_root_version',
    'activation_epoch',
    'signing_worker_id',
    'context_binding_b64u',
    'threshold_public_key33_b64u',
    'export_request_digest_b64u',
    'export_authorization_digest_b64u',
    'export_nonce',
    'authorization_kind',
    'authorization_id',
    'material_activation',
    'lifecycle_id',
    'recipient_identity',
    'recipient_public_key',
    'expires_at_ms',
  ]);
  if (!Array.isArray(record.ciphertext_and_tag) || record.ciphertext_and_tag.length <= 48) {
    throw new Error(`${label}.ciphertext_and_tag is invalid`);
  }
  const materialActivation = parseRouterAbMpcMaterialActivationRef(binding.material_activation);
  if (
    materialActivation.material_owner !== binding.wallet_id ||
    materialActivation.signing_worker !== binding.signing_worker_id
  ) {
    throw new Error(`${bindingLabel}.material_activation is not bound to wallet and worker`);
  }
  return {
    version: 'router-ab-ecdsa-derivation/signing-worker-export-share-envelope/v1',
    algorithm: 'hpke_x25519_hkdf_sha256_aes256gcm_v1',
    binding: {
      wallet_id: requireAsciiNonEmptyString(binding.wallet_id, `${bindingLabel}.wallet_id`),
      key_handle: requireAsciiNonEmptyString(binding.key_handle, `${bindingLabel}.key_handle`),
      ecdsa_threshold_key_id: requireAsciiNonEmptyString(
        binding.ecdsa_threshold_key_id,
        `${bindingLabel}.ecdsa_threshold_key_id`,
      ),
      signing_root_id: requireAsciiNonEmptyString(
        binding.signing_root_id,
        `${bindingLabel}.signing_root_id`,
      ),
      signing_root_version: requireAsciiNonEmptyString(
        binding.signing_root_version,
        `${bindingLabel}.signing_root_version`,
      ),
      activation_epoch: requireRootShareEpoch(
        binding.activation_epoch,
        `${bindingLabel}.activation_epoch`,
      ),
      signing_worker_id: requireAsciiNonEmptyString(
        binding.signing_worker_id,
        `${bindingLabel}.signing_worker_id`,
      ),
      context_binding_b64u: requireBase64UrlFixed(
        binding.context_binding_b64u,
        `${bindingLabel}.context_binding_b64u`,
        32,
      ),
      threshold_public_key33_b64u: requireCompressedSecp256k1PublicKey(
        binding.threshold_public_key33_b64u,
        `${bindingLabel}.threshold_public_key33_b64u`,
      ),
      export_request_digest_b64u: requireBase64UrlFixed(
        binding.export_request_digest_b64u,
        `${bindingLabel}.export_request_digest_b64u`,
        32,
      ),
      export_authorization_digest_b64u: requireBase64UrlFixed(
        binding.export_authorization_digest_b64u,
        `${bindingLabel}.export_authorization_digest_b64u`,
        32,
      ),
      export_nonce: requireAsciiNonEmptyString(
        binding.export_nonce,
        `${bindingLabel}.export_nonce`,
      ),
      authorization_kind: requireExportShareAuthorizationKind(
        binding.authorization_kind,
        `${bindingLabel}.authorization_kind`,
      ),
      authorization_id: requireAsciiNonEmptyString(
        binding.authorization_id,
        `${bindingLabel}.authorization_id`,
      ),
      material_activation: materialActivation,
      lifecycle_id: requireAsciiNonEmptyString(
        binding.lifecycle_id,
        `${bindingLabel}.lifecycle_id`,
      ),
      recipient_identity: requireAsciiNonEmptyString(
        binding.recipient_identity,
        `${bindingLabel}.recipient_identity`,
      ),
      recipient_public_key: requireX25519PublicKey(
        binding.recipient_public_key,
        `${bindingLabel}.recipient_public_key`,
      ),
      expires_at_ms: requirePositiveUnixMs(binding.expires_at_ms, `${bindingLabel}.expires_at_ms`),
    },
    ciphertext_and_tag: record.ciphertext_and_tag.map((entry, index) =>
      requireByte(entry, `${label}.ciphertext_and_tag[${index}]`),
    ),
  };
}

function parseRouterAbEcdsaStrictProofResponseV1(
  value: unknown,
  label: string,
): RouterAbEcdsaStrictForwardedProofResponseV1['response'] {
  const response = requireRecord(value, label);
  requireExactKeys(response, label, ['bundles']);
  const bundlesLabel = `${label}.bundles`;
  const bundles = requireRecord(response.bundles, bundlesLabel);
  requireExactKeys(bundles, bundlesLabel, ['signerA', 'signerB']);
  return {
    bundles: {
      signerA: parseRouterAbEcdsaClientProofBundleV1(bundles.signerA, `${bundlesLabel}.signerA`),
      signerB: parseRouterAbEcdsaClientProofBundleV1(bundles.signerB, `${bundlesLabel}.signerB`),
    },
  };
}

export function parseRouterAbEcdsaDerivationActivationRefreshResponseV1(
  value: unknown,
): RouterAbEcdsaDerivationActivationRefreshResponseV1 {
  const label = 'activationRefreshResponse';
  const record = requireRecord(value, label);
  switch (record.result) {
    case 'forwarded':
      requireExactKeys(record, label, ['result', 'response', 'signing_worker_activation']);
      return {
        result: 'forwarded',
        response: parseRouterAbEcdsaStrictProofResponseV1(record.response, `${label}.response`),
        signing_worker_activation: parseRouterAbEcdsaRegistrationActivationReceiptV1(
          record.signing_worker_activation,
        ),
      };
    case 'activation_committed':
      requireExactKeys(record, label, ['result', 'signing_worker_activation']);
      return {
        result: 'activation_committed',
        signing_worker_activation: parseRouterAbEcdsaRegistrationActivationReceiptV1(
          record.signing_worker_activation,
        ),
      };
    case 'stopped':
      requireExactKeys(record, label, ['result', 'replay', 'lifecycle', 'decision']);
      return {
        result: 'stopped',
        replay: parseRouterAbReplayReservation(record.replay, `${label}.replay`),
        lifecycle: parseRouterAbLifecycleReceipt(record.lifecycle, `${label}.lifecycle`),
        decision: parseRouterAbExpensiveWorkGateDecision(record.decision, `${label}.decision`),
      };
    default:
      throw new Error(`${label}.result must be forwarded, activation_committed, or stopped`);
  }
}

function parseRouterAbReplayReservation(
  value: unknown,
  label: string,
): RouterAbEcdsaDerivationActivationRefreshStoppedResponseV1['replay'] {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['request_id', 'reserved']);
  if (typeof record.reserved !== 'boolean') {
    throw new Error(`${label}.reserved must be boolean`);
  }
  return {
    request_id: requireAsciiNonEmptyString(record.request_id, `${label}.request_id`),
    reserved: record.reserved,
  };
}

function parseRouterAbLifecycleReceipt(
  value: unknown,
  label: string,
): RouterAbEcdsaDerivationActivationRefreshStoppedResponseV1['lifecycle'] {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['lifecycle_id', 'stored']);
  if (typeof record.stored !== 'boolean') {
    throw new Error(`${label}.stored must be boolean`);
  }
  return {
    lifecycle_id: requireAsciiNonEmptyString(record.lifecycle_id, `${label}.lifecycle_id`),
    stored: record.stored,
  };
}

function parseRouterAbExpensiveWorkGateDecision(
  value: unknown,
  label: string,
): RouterAbEcdsaDerivationActivationRefreshStoppedResponseV1['decision'] {
  const record = requireRecord(value, label);
  switch (record.kind) {
    case 'accepted':
      requireExactKeys(record, label, ['kind', 'request_id']);
      return {
        kind: 'accepted',
        request_id: requireAsciiNonEmptyString(record.request_id, `${label}.request_id`),
      };
    case 'reuse_existing':
      requireExactKeys(record, label, ['kind', 'request_id', 'existing_lifecycle_id']);
      return {
        kind: 'reuse_existing',
        request_id: requireAsciiNonEmptyString(record.request_id, `${label}.request_id`),
        existing_lifecycle_id: requireAsciiNonEmptyString(
          record.existing_lifecycle_id,
          `${label}.existing_lifecycle_id`,
        ),
      };
    case 'defer':
      requireExactKeys(record, label, ['kind', 'reason']);
      if (
        record.reason !== 'short_window_saturated' &&
        record.reason !== 'signer_queue_saturated'
      ) {
        throw new Error(`${label}.reason is invalid`);
      }
      return { kind: 'defer', reason: record.reason };
    case 'rejected':
      requireExactKeys(record, label, ['kind', 'reason', 'retry_after_ms']);
      if (record.reason !== 'rate_limited' && record.reason !== 'abuse_policy') {
        throw new Error(`${label}.reason is invalid`);
      }
      return {
        kind: 'rejected',
        reason: record.reason,
        retry_after_ms: requireNonNegativeInteger(record.retry_after_ms, `${label}.retry_after_ms`),
      };
    default:
      throw new Error(`${label}.kind is invalid`);
  }
}

export function parseRouterAbEcdsaVerifiedClientActivationFactsV1(
  value: unknown,
): RouterAbEcdsaVerifiedClientActivationFactsV1 {
  const label = 'registrationActivation.publicFacts';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'registrationRequestDigestB64u',
    'proofTranscriptDigestB64u',
    'contextBinding32B64u',
    'derivationClientSharePublicKey33B64u',
    'clientShareRetryCounter',
    'participantId',
  ]);
  if (record.participantId !== 1) {
    throw new Error(`${label}.participantId must be 1`);
  }
  return {
    registrationRequestDigestB64u: requireBase64UrlFixed(
      record.registrationRequestDigestB64u,
      `${label}.registrationRequestDigestB64u`,
      32,
    ),
    proofTranscriptDigestB64u: requireBase64UrlFixed(
      record.proofTranscriptDigestB64u,
      `${label}.proofTranscriptDigestB64u`,
      32,
    ),
    contextBinding32B64u: requireBase64UrlFixed(
      record.contextBinding32B64u,
      `${label}.contextBinding32B64u`,
      32,
    ),
    derivationClientSharePublicKey33B64u: requireCompressedSecp256k1PublicKey(
      record.derivationClientSharePublicKey33B64u,
      `${label}.derivationClientSharePublicKey33B64u`,
    ),
    clientShareRetryCounter: requireU32(
      record.clientShareRetryCounter,
      `${label}.clientShareRetryCounter`,
    ),
    participantId: 1,
  };
}

export function parseRouterAbEcdsaRegistrationActivationRequestV1(
  value: unknown,
): RouterAbEcdsaRegistrationActivationRequestV1 {
  const label = 'registrationActivation';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['registrationCeremonyId', 'ecdsa']);
  const ecdsa = requireRecord(record.ecdsa, `${label}.ecdsa`);
  requireExactKeys(ecdsa, `${label}.ecdsa`, ['kind', 'activationCorrelationId', 'publicFacts']);
  if (ecdsa.kind !== 'router_ab_ecdsa_registration_activation_v1') {
    throw new Error(`${label}.ecdsa.kind is invalid`);
  }
  return {
    registrationCeremonyId: requireAsciiNonEmptyString(
      record.registrationCeremonyId,
      `${label}.registrationCeremonyId`,
    ),
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_activation_v1',
      activationCorrelationId: parseCorrelationId(ecdsa.activationCorrelationId),
      publicFacts: parseRouterAbEcdsaVerifiedClientActivationFactsV1(ecdsa.publicFacts),
    },
  };
}

export function parseRouterAbEcdsaRegistrationActivationReceiptV1(
  value: unknown,
): RouterAbEcdsaRegistrationActivationReceiptV1 {
  const label = 'registrationActivationReceipt';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'activation_correlation_id',
    'activation_request_digest',
    'server_generation',
    'ecdsa_activation',
    'lifecycle_id',
    'transcript_digest',
  ]);
  const activationLabel = `${label}.ecdsa_activation`;
  const activation = requireRecord(record.ecdsa_activation, activationLabel);
  requireExactKeys(activation, activationLabel, [
    'context',
    'public_identity',
    'signing_worker',
    'material_activation',
    'activation_epoch',
    'activation_digest_b64u',
    'activated_at_ms',
  ]);
  const signingWorker = parseServerIdentityWithLabel(
    activation.signing_worker,
    `${activationLabel}.signing_worker`,
  );
  const materialActivation = parseRouterAbMpcMaterialActivationRef(activation.material_activation);
  if (materialActivation.signing_worker !== signingWorker.server_id) {
    throw new Error(
      `${activationLabel}.material_activation.signing_worker does not match signing_worker`,
    );
  }
  const activationDigestB64u = requireBase64UrlFixed(
    activation.activation_digest_b64u,
    `${activationLabel}.activation_digest_b64u`,
    32,
  );
  const transcriptDigest = parsePublicDigest32(
    record.transcript_digest,
    `${label}.transcript_digest`,
  );
  return {
    activation_correlation_id: parseCorrelationId(record.activation_correlation_id),
    activation_request_digest: parsePublicDigest32(
      record.activation_request_digest,
      `${label}.activation_request_digest`,
    ),
    server_generation: parseEcdsaServerGeneration(record.server_generation),
    ecdsa_activation: {
      context: parseStableKeyContext(activation.context),
      public_identity: parsePublicIdentity(activation.public_identity),
      signing_worker: signingWorker,
      material_activation: materialActivation,
      activation_epoch: requireRootShareEpoch(
        activation.activation_epoch,
        `${activationLabel}.activation_epoch`,
      ),
      activation_digest_b64u: activationDigestB64u,
      activated_at_ms: requirePositiveUnixMs(
        activation.activated_at_ms,
        `${activationLabel}.activated_at_ms`,
      ),
    },
    lifecycle_id: requireAsciiNonEmptyString(record.lifecycle_id, `${label}.lifecycle_id`),
    transcript_digest: transcriptDigest,
  };
}

export function parseRouterAbEcdsaDerivationActivationPrepareResultV1(
  value: unknown,
): RouterAbEcdsaDerivationActivationPrepareResultV1 {
  const label = 'activationPrepareResult';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['activation_correlation_id', 'activation_request_digest']);
  return {
    activation_correlation_id: parseCorrelationId(record.activation_correlation_id),
    activation_request_digest: parsePublicDigest32(
      record.activation_request_digest,
      `${label}.activation_request_digest`,
    ),
  };
}

export function parseRouterAbEcdsaDerivationActivationCommitQueryResultV1(
  value: unknown,
): RouterAbEcdsaDerivationActivationCommitQueryResultV1 {
  const label = 'activationCommitQueryResult';
  const record = requireRecord(value, label);
  switch (record.kind) {
    case 'committed':
      requireExactKeys(record, label, ['kind', 'receipt']);
      return {
        kind: 'committed',
        receipt: parseRouterAbEcdsaRegistrationActivationReceiptV1(record.receipt),
      };
    case 'not_committed':
    case 'correlation_conflict':
      requireExactKeys(record, label, [
        'kind',
        'activation_correlation_id',
        'activation_request_digest',
      ]);
      return {
        kind: record.kind,
        activation_correlation_id: parseCorrelationId(record.activation_correlation_id),
        activation_request_digest: parsePublicDigest32(
          record.activation_request_digest,
          `${label}.activation_request_digest`,
        ),
      };
    default:
      throw new Error(`${label}.kind must be committed, not_committed, or correlation_conflict`);
  }
}

export function parseRouterAbEcdsaRegistrationPublicActivationReceiptV1(
  value: unknown,
): RouterAbEcdsaRegistrationPublicActivationReceiptV1 {
  return parseRouterAbEcdsaRegistrationActivationReceiptV1(value);
}

function sameServerIdentity(
  left: RouterAbServerIdentityV1,
  right: RouterAbServerIdentityV1,
): boolean {
  return (
    left.server_id === right.server_id &&
    left.key_epoch === right.key_epoch &&
    left.recipient_encryption_key === right.recipient_encryption_key
  );
}

function sameRegistrationSignerSet(
  left: RouterAbEcdsaDerivationSignerSetV1,
  right: RouterAbEcdsaDerivationSignerSetV1,
): boolean {
  return (
    left.signer_set_id === right.signer_set_id &&
    left.policy === right.policy &&
    left.signer_a.role === right.signer_a.role &&
    left.signer_a.signer_id === right.signer_a.signer_id &&
    left.signer_a.key_epoch === right.signer_a.key_epoch &&
    left.signer_b.role === right.signer_b.role &&
    left.signer_b.signer_id === right.signer_b.signer_id &&
    left.signer_b.key_epoch === right.signer_b.key_epoch &&
    sameServerIdentity(left.selected_server, right.selected_server)
  );
}

function sameRegistrationLifecycle(
  left: RouterAbEcdsaRegistrationLifecycleV1,
  right: RouterAbEcdsaRegistrationLifecycleV1,
): boolean {
  return (
    left.lifecycle_id === right.lifecycle_id &&
    left.work_kind === right.work_kind &&
    left.primitive_request_kind === right.primitive_request_kind &&
    left.root_share_epoch === right.root_share_epoch &&
    left.account_id === right.account_id &&
    left.session_id === right.session_id &&
    left.signer_set_id === right.signer_set_id &&
    left.selected_server_id === right.selected_server_id
  );
}

export function assertRouterAbEcdsaRegistrationFactsMatchRequestV1(input: {
  facts: RouterAbEcdsaRegistrationRequestFactsV1;
  request: RouterAbEcdsaRegistrationRequestV1;
}): void {
  const facts = input.facts;
  const request = input.request;
  if (
    facts.registration_purpose !== request.registration_purpose ||
    facts.context.application_binding_digest_b64u !==
      request.context.application_binding_digest_b64u ||
    !sameRegistrationLifecycle(facts.lifecycle, request.lifecycle) ||
    !sameRegistrationSignerSet(facts.signer_set, request.signer_set) ||
    facts.router_id !== request.router_id ||
    facts.client_id !== request.client_id ||
    facts.replay_nonce !== request.replay_nonce ||
    facts.expires_at_ms !== request.expires_at_ms
  ) {
    throw new Error('ECDSA registration facts do not match the sealed registration request');
  }
}

export function parseRouterAbEcdsaDerivationPublicCapabilityV1(
  value: unknown,
): RouterAbEcdsaDerivationPublicCapabilityV1 {
  const label = 'ecdsaPublicCapability';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'kind',
    'context',
    'public_identity',
    'material_activation',
    'signer_set',
    'deriver_recipient_keys',
    'router_id',
    'client_id',
    'activation_epoch',
    'registration_request_digest_b64u',
    'proof_transcript_digest_b64u',
  ]);
  if (record.kind !== 'router_ab_ecdsa_derivation_public_capability_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const signerSet = parsePostRegistrationSignerSet(record.signer_set, `${label}.signer_set`);
  const recipientKeys = parseRegistrationRecipientKeys(
    record.deriver_recipient_keys,
    `${label}.deriver_recipient_keys`,
  );
  if (
    recipientKeys.deriver_a.key_epoch !== signerSet.signer_a.key_epoch ||
    recipientKeys.deriver_b.key_epoch !== signerSet.signer_b.key_epoch
  ) {
    throw new Error(`${label} Deriver recipient key epochs do not match signer_set`);
  }
  return {
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: parseStableKeyContext(record.context),
    public_identity: parsePublicIdentity(record.public_identity),
    material_activation: parseRouterAbMpcMaterialActivationRef(record.material_activation),
    signer_set: signerSet,
    deriver_recipient_keys: recipientKeys,
    router_id: requireAsciiNonEmptyString(record.router_id, `${label}.router_id`),
    client_id: requireAsciiNonEmptyString(record.client_id, `${label}.client_id`),
    activation_epoch: requireRootShareEpoch(record.activation_epoch, `${label}.activation_epoch`),
    registration_request_digest_b64u: requireBase64UrlFixed(
      record.registration_request_digest_b64u,
      `${label}.registration_request_digest_b64u`,
      32,
    ),
    proof_transcript_digest_b64u: requireBase64UrlFixed(
      record.proof_transcript_digest_b64u,
      `${label}.proof_transcript_digest_b64u`,
      32,
    ),
  };
}

function parsePostRegistrationSessionPolicy(
  value: unknown,
): RouterAbEcdsaPostRegistrationSessionPolicyV1 {
  const label = 'postRegistrationSessionActivation.session_policy';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'threshold_session_id',
    'wallet_session_mint_id',
    'ttl_ms',
    'remaining_uses',
    'runtime_policy_scope',
  ]);
  return {
    threshold_session_id: requireThresholdEcdsaSessionId(
      record.threshold_session_id,
      `${label}.threshold_session_id`,
    ),
    wallet_session_mint_id: requireReusableWalletSessionMintId(
      record.wallet_session_mint_id,
      `${label}.wallet_session_mint_id`,
    ),
    ttl_ms: requirePositiveCounter(record.ttl_ms, `${label}.ttl_ms`),
    remaining_uses: requirePositiveCounter(record.remaining_uses, `${label}.remaining_uses`),
    runtime_policy_scope: normalizeRuntimePolicyScope(record.runtime_policy_scope),
  };
}

export function parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
  value: unknown,
): RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 {
  const label = 'postRegistrationSessionActivationPolicy';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['kind', 'key_handle', 'session_policy']);
  if (record.kind !== 'router_ab_ecdsa_post_registration_session_activation_policy_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
    key_handle: requireAsciiNonEmptyString(record.key_handle, `${label}.key_handle`),
    session_policy: parsePostRegistrationSessionPolicy(record.session_policy),
  };
}

function requireReusableWalletSessionMintId(
  value: unknown,
  label: string,
): ReusableWalletSessionMintId {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function publicIdentitiesMatch(
  left: RouterAbEcdsaDerivationPublicIdentityV1,
  right: RouterAbEcdsaDerivationPublicIdentityV1,
): boolean {
  return (
    left.context_binding_b64u === right.context_binding_b64u &&
    left.derivation_client_share_public_key33_b64u ===
      right.derivation_client_share_public_key33_b64u &&
    left.server_public_key33_b64u === right.server_public_key33_b64u &&
    left.threshold_public_key33_b64u === right.threshold_public_key33_b64u &&
    left.ethereum_address20_b64u === right.ethereum_address20_b64u &&
    left.client_share_retry_counter === right.client_share_retry_counter &&
    left.server_share_retry_counter === right.server_share_retry_counter
  );
}

export function parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1(
  value: unknown,
): RouterAbEcdsaPostRegistrationSessionActivationRequestV1 {
  const label = 'postRegistrationSessionActivation';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['kind', 'public_capability', 'session_policy']);
  if (record.kind !== 'router_ab_ecdsa_post_registration_session_activation_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(record.public_capability);
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
    public_capability: publicCapability,
    session_policy: parsePostRegistrationSessionPolicy(record.session_policy),
  };
}

export function parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(
  value: unknown,
): RouterAbEcdsaPostRegistrationSessionActivationResponseV1 {
  const label = 'postRegistrationSessionActivated';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['kind', 'public_capability', 'session', 'normal_signing']);
  if (record.kind !== 'router_ab_ecdsa_post_registration_session_activated_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(record.public_capability);
  const sessionRecord = requireRecord(record.session, `${label}.session`);
  requireExactKeys(sessionRecord, `${label}.session`, [
    'authorization_session_id',
    'threshold_session_id',
    'wallet_session_id',
    'quota_id',
    'expires_at_ms',
    'remaining_uses',
    'wallet_session_jwt',
  ]);
  const normalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1(record.normal_signing);
  if (
    !publicIdentitiesMatch(publicCapability.public_identity, normalSigning.scope.public_identity) ||
    publicCapability.context.application_binding_digest_b64u !==
      normalSigning.scope.context.application_binding_digest_b64u ||
    normalSigning.scope.activation_epoch !== publicCapability.activation_epoch ||
    !sameServerIdentity(
      normalSigning.scope.signing_worker,
      publicCapability.signer_set.selected_server,
    )
  ) {
    throw new Error(`${label} normal-signing state does not match public capability`);
  }
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
    public_capability: publicCapability,
    session: {
      authorization_session_id: requireSeamsSessionId(
        sessionRecord.authorization_session_id,
        `${label}.session.authorization_session_id`,
      ),
      threshold_session_id: requireThresholdEcdsaSessionId(
        sessionRecord.threshold_session_id,
        `${label}.session.threshold_session_id`,
      ),
      wallet_session_id: requireWalletSessionId(
        sessionRecord.wallet_session_id,
        `${label}.session.wallet_session_id`,
      ),
      quota_id: requireMpcWalletSigningQuotaId(sessionRecord.quota_id, `${label}.session.quota_id`),
      expires_at_ms: requirePositiveUnixMs(
        sessionRecord.expires_at_ms,
        `${label}.session.expires_at_ms`,
      ),
      remaining_uses: requirePositiveCounter(
        sessionRecord.remaining_uses,
        `${label}.session.remaining_uses`,
      ),
      wallet_session_jwt: requireAsciiNonEmptyString(
        sessionRecord.wallet_session_jwt,
        `${label}.session.wallet_session_jwt`,
      ),
    },
    normal_signing: normalSigning,
  };
}

export function buildRouterAbEcdsaDerivationPublicCapabilityV1(input: {
  registrationFacts: RouterAbEcdsaRegistrationRequestFactsV1;
  registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
  activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
}): RouterAbEcdsaDerivationPublicCapabilityV1 {
  const facts = parseRouterAbEcdsaRegistrationRequestFactsV1(input.registrationFacts);
  const request = parseRouterAbEcdsaRegistrationRequestV1(input.registrationRequest);
  const clientActivation = parseRouterAbEcdsaVerifiedClientActivationFactsV1(
    input.clientActivation,
  );
  const receipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(input.activationReceipt);
  assertRouterAbEcdsaRegistrationFactsMatchRequestV1({ facts, request });
  const activated = receipt.ecdsa_activation;
  if (
    receipt.lifecycle_id !== request.lifecycle.lifecycle_id ||
    activated.activation_epoch !== request.lifecycle.root_share_epoch ||
    activated.context.application_binding_digest_b64u !==
      request.context.application_binding_digest_b64u ||
    !sameServerIdentity(activated.signing_worker, request.signer_set.selected_server) ||
    activated.public_identity.context_binding_b64u !== clientActivation.contextBinding32B64u ||
    activated.public_identity.derivation_client_share_public_key33_b64u !==
      clientActivation.derivationClientSharePublicKey33B64u ||
    activated.public_identity.client_share_retry_counter !==
      clientActivation.clientShareRetryCounter ||
    base64UrlEncode(new Uint8Array(receipt.transcript_digest.bytes)) !==
      clientActivation.proofTranscriptDigestB64u
  ) {
    throw new Error('ECDSA activation receipt does not match verified registration facts');
  }
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: activated.context,
    public_identity: activated.public_identity,
    material_activation: activated.material_activation,
    signer_set: request.signer_set,
    deriver_recipient_keys: facts.deriver_recipient_keys,
    router_id: request.router_id,
    client_id: request.client_id,
    activation_epoch: activated.activation_epoch,
    registration_request_digest_b64u: clientActivation.registrationRequestDigestB64u,
    proof_transcript_digest_b64u: clientActivation.proofTranscriptDigestB64u,
  });
}

function requirePostRegistrationBindings(
  label: string,
  lifecycle: RouterAbEcdsaDerivationPostRegistrationLifecycleScopeV1<
    'key_export' | 'recovery' | 'server_share_refresh',
    'export' | 'recovery' | 'refresh'
  >,
  signerSet: RouterAbEcdsaDerivationSignerSetV1,
): void {
  if (lifecycle.signer_set_id !== signerSet.signer_set_id) {
    throw new Error(`${label}.lifecycle.signer_set_id must match signer_set.signer_set_id`);
  }
  if (lifecycle.selected_server_id !== signerSet.selected_server.server_id) {
    throw new Error(
      `${label}.lifecycle.selected_server_id must match signer_set.selected_server.server_id`,
    );
  }
}

export function parseRouterAbEcdsaDerivationExplicitExportRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationExplicitExportRequestV1 {
  const label = 'export';
  const record = requireRecord(value, label);
  const authorization = parseRouterAbNormalSigningAuthorization(record.authorization);
  const commonKeys = explicitExportRequestCommonKeys();
  switch (authorization.kind) {
    case 'reusable_wallet_session':
      requireExactKeys(record, label, commonKeys);
      break;
    case 'operation_step_up':
      requireExactKeys(record, label, [...commonKeys, 'operation']);
      break;
  }
  const parsed = parseExplicitExportRequestProtocolFields(record, label, authorization);
  switch (authorization.kind) {
    case 'reusable_wallet_session':
      return { ...parsed, authorization };
    case 'operation_step_up':
      return {
        ...parsed,
        authorization,
        operation: parseRouterAbEcdsaOperationStepUpPreparationV1(record.operation),
      };
  }
}

export function parseRouterAbEcdsaDerivationExplicitExportProtocolRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationExplicitExportProtocolRequestV1 {
  const label = 'export';
  const record = requireRecord(value, label);
  const authorization = parseRouterAbNormalSigningAuthorization(record.authorization);
  requireExactKeys(record, label, explicitExportRequestCommonKeys());
  return parseExplicitExportRequestProtocolFields(record, label, authorization);
}

function explicitExportRequestCommonKeys(): readonly string[] {
  return [
    'context',
    'lifecycle',
    'public_identity',
    'signer_set',
    'router_id',
    'client_id',
    'client_ephemeral_public_key',
    'authorization',
    'material_activation',
    'export_authorization_digest_b64u',
    'export_nonce',
    'expires_at_ms',
    'deriver_a_export_envelope',
    'deriver_b_export_envelope',
  ];
}

function parseExplicitExportRequestProtocolFields(
  record: Record<string, unknown>,
  label: string,
  authorization: RouterAbNormalSigningAuthorizationWire,
): RouterAbEcdsaDerivationExplicitExportProtocolRequestV1 {
  const lifecycle = parsePostRegistrationLifecycleScope(
    record.lifecycle,
    `${label}.lifecycle`,
    'key_export',
    'export',
  );
  const signerSet = parsePostRegistrationSignerSet(record.signer_set, `${label}.signer_set`);
  requirePostRegistrationBindings(label, lifecycle, signerSet);
  const materialActivation = parseRouterAbMpcMaterialActivationRef(record.material_activation);
  if (
    materialActivation.material_owner !== lifecycle.account_id ||
    materialActivation.signing_worker !== lifecycle.selected_server_id
  ) {
    throw new Error(
      `${label}.material_activation is not bound to lifecycle owner and selected server`,
    );
  }
  const parsed = {
    context: parseStableKeyContext(record.context),
    lifecycle,
    public_identity: parsePublicIdentity(record.public_identity),
    signer_set: signerSet,
    router_id: requireAsciiNonEmptyString(record.router_id, `${label}.router_id`),
    client_id: requireAsciiNonEmptyString(record.client_id, `${label}.client_id`),
    client_ephemeral_public_key: requireX25519PublicKey(
      record.client_ephemeral_public_key,
      `${label}.client_ephemeral_public_key`,
    ),
    material_activation: materialActivation,
    export_authorization_digest_b64u: requireBase64UrlFixed(
      record.export_authorization_digest_b64u,
      `${label}.export_authorization_digest_b64u`,
      32,
    ),
    export_nonce: requireAsciiNonEmptyString(record.export_nonce, `${label}.export_nonce`),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, `${label}.expires_at_ms`),
    deriver_a_export_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_a_export_envelope,
      `${label}.deriver_a_export_envelope`,
      'signer_a',
    ),
    deriver_b_export_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_b_export_envelope,
      `${label}.deriver_b_export_envelope`,
      'signer_b',
    ),
    authorization,
  };
  return parsed;
}

export function parseRouterAbEcdsaDerivationActivationRefreshRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationActivationRefreshRequestV1 {
  const label = 'refresh';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'context',
    'lifecycle',
    'public_identity',
    'signer_set',
    'router_id',
    'client_id',
    'signing_worker_ephemeral_public_key',
    'refresh_authorization_digest_b64u',
    'refresh_nonce',
    'previous_activation_epoch',
    'next_activation_epoch',
    'material_activation',
    'expires_at_ms',
    'deriver_a_refresh_envelope',
    'deriver_b_refresh_envelope',
  ]);
  const lifecycle = parsePostRegistrationLifecycleScope(
    record.lifecycle,
    `${label}.lifecycle`,
    'server_share_refresh',
    'refresh',
  );
  const signerSet = parsePostRegistrationSignerSet(record.signer_set, `${label}.signer_set`);
  const previousActivationEpoch = requireRootShareEpoch(
    record.previous_activation_epoch,
    `${label}.previous_activation_epoch`,
  );
  const nextActivationEpoch = requireRootShareEpoch(
    record.next_activation_epoch,
    `${label}.next_activation_epoch`,
  );
  if (previousActivationEpoch === nextActivationEpoch) {
    throw new Error('refresh must advance activation epoch');
  }
  if (lifecycle.root_share_epoch !== nextActivationEpoch) {
    throw new Error('refresh.lifecycle.root_share_epoch must equal next_activation_epoch');
  }
  requirePostRegistrationBindings(label, lifecycle, signerSet);
  const materialActivation = parseRouterAbMpcMaterialActivationRef(record.material_activation);
  if (
    materialActivation.material_owner !== lifecycle.account_id ||
    materialActivation.signing_worker !== signerSet.selected_server.server_id
  ) {
    throw new Error(
      'refresh.material_activation is not bound to lifecycle owner and selected server',
    );
  }
  return {
    context: parseStableKeyContext(record.context),
    lifecycle,
    public_identity: parsePublicIdentity(record.public_identity),
    signer_set: signerSet,
    router_id: requireAsciiNonEmptyString(record.router_id, `${label}.router_id`),
    client_id: requireAsciiNonEmptyString(record.client_id, `${label}.client_id`),
    signing_worker_ephemeral_public_key: requireX25519PublicKey(
      record.signing_worker_ephemeral_public_key,
      `${label}.signing_worker_ephemeral_public_key`,
    ),
    refresh_authorization_digest_b64u: requireBase64UrlFixed(
      record.refresh_authorization_digest_b64u,
      `${label}.refresh_authorization_digest_b64u`,
      32,
    ),
    refresh_nonce: requireAsciiNonEmptyString(record.refresh_nonce, `${label}.refresh_nonce`),
    previous_activation_epoch: previousActivationEpoch,
    next_activation_epoch: nextActivationEpoch,
    material_activation: materialActivation,
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, `${label}.expires_at_ms`),
    deriver_a_refresh_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_a_refresh_envelope,
      `${label}.deriver_a_refresh_envelope`,
      'signer_a',
    ),
    deriver_b_refresh_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_b_refresh_envelope,
      `${label}.deriver_b_refresh_envelope`,
      'signer_b',
    ),
  };
}

export function parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationActivationRefreshCommitRequestV1 {
  const label = 'refreshCommit';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'activation_correlation_id',
    'expected_server_generation',
    'refresh_request',
  ]);
  return {
    activation_correlation_id: parseCorrelationId(record.activation_correlation_id),
    expected_server_generation: parseEcdsaServerGeneration(record.expected_server_generation),
    refresh_request: parseRouterAbEcdsaDerivationActivationRefreshRequestV1(record.refresh_request),
  };
}

function publicDigest32FromBase64Url(
  value: string,
  label = 'signing_digest_b64u',
): RouterAbPublicDigest32V1Wire {
  return {
    bytes: Array.from(base64UrlDecode(requireBase64UrlFixed(value, label, 32))),
  };
}

function samePublicDigest32(
  left: RouterAbPublicDigest32V1Wire,
  right: RouterAbPublicDigest32V1Wire,
): boolean {
  return (
    left.bytes.length === 32 &&
    right.bytes.length === 32 &&
    left.bytes.every((b, i) => b === right.bytes[i])
  );
}

function asciiBytes(value: string): Uint8Array {
  return new TextEncoder().encode(requireAsciiNonEmptyString(value, 'canonical string'));
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function pushBytes(out: number[], bytes: Uint8Array): void {
  for (const byte of bytes) out.push(byte);
}

function pushOperationDigests(
  out: number[],
  digests: RouterAbEcdsaDerivationOperationDigestsV1Wire,
): void {
  pushBytes(out, base64UrlDecode(digests.lane_digest_b64u));
  pushBytes(out, base64UrlDecode(digests.intent_digest_b64u));
  pushBytes(out, base64UrlDecode(digests.display_digest_b64u));
}

function pushU16(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('canonical u16 must be an integer between 0 and 65535');
  }
  out.push((value >>> 8) & 0xff, value & 0xff);
}

function pushU32(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('canonical u32 must be an integer between 0 and 4294967295');
  }
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function pushU64(out: number[], value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('canonical u64 must be a non-negative safe integer');
  }
  const remaining = BigInt(value);
  for (let shift = 56; shift >= 0; shift -= 8) {
    out.push(Number((remaining >> BigInt(shift)) & 0xffn));
  }
}

function pushLen32(out: number[], bytes: Uint8Array): void {
  pushU32(out, bytes.length);
  pushBytes(out, bytes);
}

function pushAsciiU16(out: number[], value: string): void {
  const bytes = asciiBytes(value);
  pushU16(out, bytes.length);
  pushBytes(out, bytes);
}

function pushServerIdentity(out: number[], server: RouterAbServerIdentityV1): void {
  pushLen32(out, asciiBytes(server.server_id));
  pushLen32(out, asciiBytes(server.key_epoch));
  pushLen32(out, asciiBytes(server.recipient_encryption_key));
}

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle)
    throw new Error(
      'crypto.subtle is required for Router A/B ECDSA derivation request digest binding',
    );
  const buffer = new ArrayBuffer(input.byteLength);
  new Uint8Array(buffer).set(input);
  return new Uint8Array(await subtle.digest('SHA-256', buffer));
}

export async function routerAbEcdsaRerandomizationClientCommitmentV1(
  contribution32: Uint8Array,
): Promise<Uint8Array> {
  const contribution = requireUint8ArrayFixed(
    contribution32,
    'clientRerandomizationContribution32',
    32,
  );
  return await sha256Bytes(
    concatBytes([
      asciiBytes(ROUTER_AB_ECDSA_DERIVATION_CLIENT_RERANDOMIZATION_COMMITMENT_DOMAIN_V1),
      contribution,
    ]),
  );
}

function canonicalStableKeyContextBytes(
  context: RouterAbEcdsaDerivationStableKeyContextV1,
): Uint8Array {
  const parsed = parseStableKeyContext(context);
  const out: number[] = [];
  pushBytes(out, asciiBytes(ECDSA_DERIVATION_CONTEXT_DOMAIN_TAG_V1));
  pushAsciiU16(out, ECDSA_DERIVATION_SCHEME_ID_V1);
  pushAsciiU16(out, ECDSA_DERIVATION_CURVE_V1);
  pushBytes(out, base64UrlDecode(parsed.application_binding_digest_b64u));
  out.push(ECDSA_DERIVATION_PARTICIPANT_IDS_V1.length);
  for (const participantId of ECDSA_DERIVATION_PARTICIPANT_IDS_V1) pushU16(out, participantId);
  return new Uint8Array(out);
}

export async function routerAbEcdsaDerivationStableKeyContextFromSdkFactsV1(
  facts: SdkEcdsaDerivationBindingFacts,
): Promise<RouterAbEcdsaDerivationStableKeyContextV1> {
  return {
    application_binding_digest_b64u:
      await computeSdkEcdsaDerivationApplicationBindingDigestB64u(facts),
  };
}

function contextBindingFrame(contextBytes: Uint8Array): Uint8Array {
  const out: number[] = [];
  pushBytes(out, asciiBytes(ECDSA_DERIVATION_CONTEXT_BINDING_DOMAIN_V1));
  out.push(1);
  out.push(ECDSA_DERIVATION_CONTEXT_FIELD_BYTES_V1);
  pushU16(out, contextBytes.length);
  pushBytes(out, contextBytes);
  return new Uint8Array(out);
}

export async function routerAbEcdsaDerivationContextBindingDigestV1(
  context: RouterAbEcdsaDerivationStableKeyContextV1,
): Promise<RouterAbPublicDigest32V1Wire> {
  return publicDigest32FromCanonicalBytes(
    contextBindingFrame(canonicalStableKeyContextBytes(context)),
  );
}

export async function routerAbEcdsaDerivationContextBindingB64uV1(
  context: RouterAbEcdsaDerivationStableKeyContextV1,
): Promise<string> {
  const digest = await routerAbEcdsaDerivationContextBindingDigestV1(context);
  return base64UrlEncode(new Uint8Array(digest.bytes));
}

function canonicalPublicIdentityBytes(
  publicIdentity: RouterAbEcdsaDerivationPublicIdentityV1,
): Uint8Array {
  const parsed = parsePublicIdentity(publicIdentity);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_DERIVATION_PUBLIC_IDENTITY_VERSION_V1));
  pushLen32(out, asciiBytes(parsed.context_binding_b64u));
  pushLen32(out, asciiBytes(parsed.derivation_client_share_public_key33_b64u));
  pushLen32(out, asciiBytes(parsed.server_public_key33_b64u));
  pushLen32(out, asciiBytes(parsed.threshold_public_key33_b64u));
  pushLen32(out, asciiBytes(parsed.ethereum_address20_b64u));
  pushU32(out, parsed.client_share_retry_counter);
  pushU32(out, parsed.server_share_retry_counter);
  return new Uint8Array(out);
}

function canonicalNormalSigningScopeBytes(
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
): Uint8Array {
  const parsed = parseRouterAbEcdsaDerivationNormalSigningScopeV1(scope);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_SCOPE_VERSION_V1));
  pushLen32(out, asciiBytes(parsed.wallet_id));
  pushLen32(out, asciiBytes(parsed.ecdsa_threshold_key_id));
  pushLen32(out, asciiBytes(parsed.signing_root_id));
  pushLen32(out, asciiBytes(parsed.signing_root_version));
  pushLen32(out, canonicalStableKeyContextBytes(parsed.context));
  pushLen32(out, canonicalPublicIdentityBytes(parsed.public_identity));
  out.push(...canonicalRouterAbMpcMaterialActivationRefBytes(parsed.material_activation));
  pushServerIdentity(out, parsed.signing_worker);
  pushLen32(out, asciiBytes(parsed.activation_epoch));
  return new Uint8Array(out);
}

export function routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1(
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
): Uint8Array {
  return canonicalNormalSigningScopeBytes(scope);
}

function sameCanonicalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function sameRouterAbEcdsaDerivationNormalSigningScopeV1(
  left: RouterAbEcdsaDerivationNormalSigningScopeV1,
  right: RouterAbEcdsaDerivationNormalSigningScopeV1,
): boolean {
  try {
    return sameCanonicalBytes(
      routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1(left),
      routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1(right),
    );
  } catch {
    return false;
  }
}

async function publicDigest32FromCanonicalBytes(
  bytes: Uint8Array,
): Promise<RouterAbPublicDigest32V1Wire> {
  return { bytes: Array.from(await sha256Bytes(bytes)) };
}

export async function verifyRouterAbEcdsaDerivationNormalSigningScopeContextBindingV1(
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
): Promise<RouterAbEcdsaDerivationNormalSigningScopeV1> {
  const parsed = parseRouterAbEcdsaDerivationNormalSigningScopeV1(scope);
  const expected = await routerAbEcdsaDerivationContextBindingDigestV1(parsed.context);
  const actual = publicDigest32FromBase64Url(
    parsed.public_identity.context_binding_b64u,
    'scope.public_identity.context_binding_b64u',
  );
  if (!samePublicDigest32(actual, expected)) {
    throw new Error('scope.public_identity.context_binding_b64u does not match scope.context');
  }
  return parsed;
}

export function routerAbEcdsaDerivationEvmDigestSigningRequestCanonicalBytesV1(
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
): Uint8Array {
  const parsed = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(request);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_REQUEST_VERSION_V1));
  pushLen32(out, canonicalNormalSigningScopeBytes(parsed.scope));
  pushLen32(out, asciiBytes(parsed.request_id));
  pushLen32(out, asciiBytes(parsed.operation_id));
  pushOperationDigests(out, parsed.operation_digests);
  out.push(...canonicalRouterAbNormalSigningAuthorizationBytes(parsed.authorization));
  out.push(...canonicalRouterAbMpcMaterialActivationRefBytes(parsed.material_activation));
  pushLen32(out, asciiBytes(parsed.client_presignature_id));
  pushU64(out, parsed.expires_at_ms);
  pushBytes(out, base64UrlDecode(parsed.signing_digest_b64u));
  pushLen32(out, base64UrlDecode(parsed.client_rerandomization_commitment32_b64u));
  return new Uint8Array(out);
}

export async function routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
): Promise<RouterAbPublicDigest32V1Wire> {
  const parsed = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(request);
  await verifyRouterAbEcdsaDerivationNormalSigningScopeContextBindingV1(parsed.scope);
  return publicDigest32FromCanonicalBytes(
    routerAbEcdsaDerivationEvmDigestSigningRequestCanonicalBytesV1(parsed),
  );
}

export function routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestCanonicalBytesV1(
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
): Uint8Array {
  const parsed = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1(request);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1));
  pushLen32(out, canonicalNormalSigningScopeBytes(parsed.scope));
  pushLen32(out, asciiBytes(parsed.request_id));
  pushLen32(out, asciiBytes(parsed.operation_id));
  pushOperationDigests(out, parsed.operation_digests);
  out.push(...canonicalRouterAbNormalSigningAuthorizationBytes(parsed.authorization));
  out.push(...canonicalRouterAbMpcMaterialActivationRefBytes(parsed.material_activation));
  pushU64(out, parsed.expires_at_ms);
  pushBytes(out, base64UrlDecode(parsed.signing_digest_b64u));
  pushLen32(out, asciiBytes(parsed.server_presignature_id));
  pushLen32(out, base64UrlDecode(parsed.client_signature_share32_b64u));
  pushLen32(out, base64UrlDecode(parsed.client_rerandomization_contribution32_b64u));
  return new Uint8Array(out);
}

export async function routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
): Promise<RouterAbPublicDigest32V1Wire> {
  const parsed = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1(request);
  await verifyRouterAbEcdsaDerivationNormalSigningScopeContextBindingV1(parsed.scope);
  return publicDigest32FromCanonicalBytes(
    routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestCanonicalBytesV1(parsed),
  );
}

export function parseRouterAbEcdsaDerivationNormalSigningScopeV1(
  value: unknown,
): RouterAbEcdsaDerivationNormalSigningScopeV1 {
  const record = requireRecord(value, 'scope');
  requireExactKeys(record, 'scope', [
    'wallet_id',
    'ecdsa_threshold_key_id',
    'signing_root_id',
    'signing_root_version',
    'context',
    'public_identity',
    'material_activation',
    'signing_worker',
    'activation_epoch',
  ]);
  return {
    wallet_id: requireAsciiNonEmptyString(record.wallet_id, 'scope.wallet_id'),
    ecdsa_threshold_key_id: requireAsciiNonEmptyString(
      record.ecdsa_threshold_key_id,
      'scope.ecdsa_threshold_key_id',
    ),
    signing_root_id: requireAsciiNonEmptyString(record.signing_root_id, 'scope.signing_root_id'),
    signing_root_version: requireAsciiNonEmptyString(
      record.signing_root_version,
      'scope.signing_root_version',
    ),
    context: parseStableKeyContext(record.context),
    public_identity: parsePublicIdentity(record.public_identity),
    material_activation: parseRouterAbMpcMaterialActivationRef(record.material_activation),
    signing_worker: parseServerIdentity(record.signing_worker),
    activation_epoch: requireRootShareEpoch(record.activation_epoch, 'scope.activation_epoch'),
  };
}

export function parseRouterAbEcdsaDerivationNormalSigningStateV1(
  value: unknown,
): RouterAbEcdsaDerivationNormalSigningStateV1 | null {
  if (value === undefined || value === null) return null;
  const record = requireRecord(value, 'routerAbEcdsaDerivationNormalSigning');
  requireExactKeys(record, 'routerAbEcdsaDerivationNormalSigning', ['kind', 'scope']);
  const kind = requireAsciiNonEmptyString(record.kind, 'routerAbEcdsaDerivationNormalSigning.kind');
  if (kind !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1) {
    throw new Error('routerAbEcdsaDerivationNormalSigning.kind is not supported');
  }
  return {
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
  };
}

export function requireRouterAbEcdsaDerivationNormalSigningStateV1(
  value: unknown,
): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const parsed = parseRouterAbEcdsaDerivationNormalSigningStateV1(value);
  if (!parsed) throw new Error('Router A/B ECDSA derivation normal-signing state is required');
  return parsed;
}

export function buildRouterAbEcdsaDerivationActiveStateIdV1(input: {
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  activationEpoch: RootShareEpoch;
}): EcdsaActiveStateId {
  const ecdsaThresholdKeyId = requireAsciiNonEmptyString(
    input.ecdsaThresholdKeyId,
    'ecdsaThresholdKeyId',
  );
  const signingRootId = requireAsciiNonEmptyString(input.signingRootId, 'signingRootId');
  const signingRootVersion = requireAsciiNonEmptyString(
    input.signingRootVersion,
    'signingRootVersion',
  );
  const activationEpoch = requireRootShareEpoch(input.activationEpoch, 'activationEpoch');
  const activeStateId = [
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    activationEpoch,
  ].join(':');
  const parsed = parseEcdsaActiveStateId(activeStateId);
  if (!parsed.ok) {
    throw new Error(`activeStateId ${parsed.error.message}`);
  }
  return parsed.value;
}

export function routerAbEcdsaDerivationActiveStateId(
  state: RouterAbEcdsaDerivationNormalSigningStateV1,
): EcdsaActiveStateId {
  return buildRouterAbEcdsaDerivationActiveStateIdV1({
    ecdsaThresholdKeyId: state.scope.ecdsa_threshold_key_id,
    signingRootId: state.scope.signing_root_id,
    signingRootVersion: state.scope.signing_root_version,
    activationEpoch: state.scope.activation_epoch,
  });
}

function parseRouterAbEcdsaDerivationOperationDigestsV1(
  value: unknown,
  label: string,
): RouterAbEcdsaDerivationOperationDigestsV1Wire {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'lane_digest_b64u',
    'intent_digest_b64u',
    'display_digest_b64u',
  ]);
  return {
    lane_digest_b64u: requireBase64UrlFixed(
      record.lane_digest_b64u,
      `${label}.lane_digest_b64u`,
      32,
    ),
    intent_digest_b64u: requireBase64UrlFixed(
      record.intent_digest_b64u,
      `${label}.intent_digest_b64u`,
      32,
    ),
    display_digest_b64u: requireBase64UrlFixed(
      record.display_digest_b64u,
      `${label}.display_digest_b64u`,
      32,
    ),
  };
}

export function buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input: {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  requestId: string;
  operationId: string;
  operationDigests: RouterAbEcdsaDerivationOperationDigestsV1Wire;
  authorization: RouterAbNormalSigningAuthorizationWire;
  materialActivation: RouterAbMpcMaterialActivationRefWire;
  clientPresignatureId: string;
  expiresAtMs: number;
  signingDigest32: Uint8Array;
  clientRerandomizationCommitment32: Uint8Array;
}): RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire {
  return parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope: input.scope,
    request_id: input.requestId,
    operation_id: input.operationId,
    operation_digests: input.operationDigests,
    authorization: input.authorization,
    material_activation: input.materialActivation,
    client_presignature_id: input.clientPresignatureId,
    expires_at_ms: input.expiresAtMs,
    signing_digest_b64u: base64UrlEncode(
      requireUint8ArrayFixed(input.signingDigest32, 'signingDigest32', 32),
    ),
    client_rerandomization_commitment32_b64u: base64UrlEncode(
      requireUint8ArrayFixed(
        input.clientRerandomizationCommitment32,
        'clientRerandomizationCommitment32',
        32,
      ),
    ),
  });
}

export function parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire {
  const record = requireRecord(value, 'ecdsaSigningRequest');
  requireExactKeys(record, 'ecdsaSigningRequest', [
    'scope',
    'request_id',
    'operation_id',
    'operation_digests',
    'authorization',
    'material_activation',
    'client_presignature_id',
    'expires_at_ms',
    'signing_digest_b64u',
    'client_rerandomization_commitment32_b64u',
  ]);
  const parsed = {
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaSigningRequest.request_id'),
    operation_id: requireAsciiNonEmptyString(
      record.operation_id,
      'ecdsaSigningRequest.operation_id',
    ),
    operation_digests: parseRouterAbEcdsaDerivationOperationDigestsV1(
      record.operation_digests,
      'ecdsaSigningRequest.operation_digests',
    ),
    authorization: parseRouterAbNormalSigningAuthorization(record.authorization),
    material_activation: parseRouterAbMpcMaterialActivationRef(record.material_activation),
    client_presignature_id: requireAsciiNonEmptyString(
      record.client_presignature_id,
      'ecdsaSigningRequest.client_presignature_id',
    ),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, 'ecdsaSigningRequest.expires_at_ms'),
    signing_digest_b64u: requireBase64UrlFixed(
      record.signing_digest_b64u,
      'ecdsaSigningRequest.signing_digest_b64u',
      32,
    ),
    client_rerandomization_commitment32_b64u: requireBase64UrlFixed(
      record.client_rerandomization_commitment32_b64u,
      'ecdsaSigningRequest.client_rerandomization_commitment32_b64u',
      32,
    ),
  };
  if (parsed.operation_digests.intent_digest_b64u !== parsed.signing_digest_b64u) {
    throw new Error('ecdsaSigningRequest intent digest must equal the admitted signing digest');
  }
  return parsed;
}

function parseRouterAbEcdsaOperationStepUpWebAuthnCredentialV1(
  value: unknown,
): RouterAbEcdsaOperationStepUpWebAuthnCredentialV1Wire {
  const credential = requireRecord(value, 'webauthn_authentication');
  requireExactKeys(credential, 'webauthn_authentication', [
    'id',
    'rawId',
    'type',
    'authenticatorAttachment',
    'response',
    'clientExtensionResults',
  ]);
  const response = requireRecord(credential.response, 'webauthn_authentication.response');
  requireExactKeys(response, 'webauthn_authentication.response', [
    'clientDataJSON',
    'authenticatorData',
    'signature',
    'userHandle',
  ]);
  const authenticatorAttachment =
    credential.authenticatorAttachment === null
      ? null
      : requireAsciiNonEmptyString(
          credential.authenticatorAttachment,
          'webauthn_authentication.authenticatorAttachment',
        );
  const userHandle =
    response.userHandle === null
      ? null
      : requireAsciiNonEmptyString(
          response.userHandle,
          'webauthn_authentication.response.userHandle',
        );
  return {
    id: requireAsciiNonEmptyString(credential.id, 'webauthn_authentication.id'),
    rawId: requireAsciiNonEmptyString(credential.rawId, 'webauthn_authentication.rawId'),
    type: requireAsciiNonEmptyString(credential.type, 'webauthn_authentication.type'),
    authenticatorAttachment,
    response: {
      clientDataJSON: requireAsciiNonEmptyString(
        response.clientDataJSON,
        'webauthn_authentication.response.clientDataJSON',
      ),
      authenticatorData: requireAsciiNonEmptyString(
        response.authenticatorData,
        'webauthn_authentication.response.authenticatorData',
      ),
      signature: requireAsciiNonEmptyString(
        response.signature,
        'webauthn_authentication.response.signature',
      ),
      userHandle,
    },
    clientExtensionResults: credential.clientExtensionResults,
  };
}

export function parseRouterAbEcdsaOperationStepUpAuthorizationRequestV1(
  value: unknown,
): RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire {
  const request = requireRecord(value, 'operationStepUpAuthorizationRequest');
  requireExactKeys(request, 'operationStepUpAuthorizationRequest', ['kind', 'operation', 'proof']);
  if (request.kind !== 'router_ab_ecdsa_operation_step_up_v1') {
    throw new Error(
      'operationStepUpAuthorizationRequest.kind must be router_ab_ecdsa_operation_step_up_v1',
    );
  }
  const operation = parseRouterAbEcdsaOperationStepUpPreparationV1(request.operation);
  const proof = requireRecord(request.proof, 'operationStepUpAuthorizationRequest.proof');
  const authority = parseWalletAuthAuthority(proof.authority);
  let parsedProof: RouterAbEcdsaOperationStepUpProofV1Wire;
  switch (proof.kind) {
    case 'passkey':
      requireExactKeys(proof, 'operationStepUpAuthorizationRequest.proof', [
        'kind',
        'authority',
        'webauthn_authentication',
      ]);
      if (!authority || !isPasskeyWalletAuthAuthority(authority)) {
        throw new Error(
          'operationStepUpAuthorizationRequest.proof requires an exact passkey authority',
        );
      }
      parsedProof = {
        kind: 'passkey',
        authority,
        webauthn_authentication: parseRouterAbEcdsaOperationStepUpWebAuthnCredentialV1(
          proof.webauthn_authentication,
        ),
      };
      break;
    case 'email_otp':
      requireExactKeys(proof, 'operationStepUpAuthorizationRequest.proof', [
        'kind',
        'authority',
        'challenge_id',
        'otp_code',
      ]);
      if (!authority || !isEmailOtpWalletAuthAuthority(authority)) {
        throw new Error(
          'operationStepUpAuthorizationRequest.proof requires an exact Email OTP authority',
        );
      }
      parsedProof = {
        kind: 'email_otp',
        authority,
        challenge_id: requireAsciiNonEmptyString(
          proof.challenge_id,
          'operationStepUpAuthorizationRequest.proof.challenge_id',
        ),
        otp_code: requireAsciiNonEmptyString(
          proof.otp_code,
          'operationStepUpAuthorizationRequest.proof.otp_code',
        ),
      };
      break;
    default:
      throw new Error('operationStepUpAuthorizationRequest.proof.kind is invalid');
  }
  return {
    kind: 'router_ab_ecdsa_operation_step_up_v1',
    operation,
    proof: parsedProof,
  };
}

export function parseRouterAbEcdsaOperationStepUpPreparationV1(
  value: unknown,
): RouterAbEcdsaOperationStepUpPreparationV1Wire {
  const operation = requireRecord(value, 'ecdsaOperationStepUpPreparation');
  requireExactKeys(operation, 'operationStepUpGrantRequest.operation', [
    'wallet_id',
    'operation_kind',
    'operation_id',
    'operation_digests',
    'material_activation',
    'normal_signing_scope',
    'signing_worker_id',
    'key_handle',
    'relayer_key_id',
    'participant_ids',
    'expires_at_ms',
  ]);
  if (
    !Array.isArray(operation.participant_ids) ||
    operation.participant_ids.length !== 2 ||
    !operation.participant_ids.every(
      (participantId) => Number.isSafeInteger(participantId) && participantId > 0,
    )
  ) {
    throw new Error(
      'operationStepUpGrantRequest.operation.participant_ids must contain two positive integers',
    );
  }
  return {
    wallet_id: requireAsciiNonEmptyString(
      operation.wallet_id,
      'operationStepUpGrantRequest.operation.wallet_id',
    ),
    operation_kind: requireEcdsaOperationStepUpKind(operation.operation_kind),
    operation_id: requireAsciiNonEmptyString(
      operation.operation_id,
      'operationStepUpGrantRequest.operation.operation_id',
    ),
    operation_digests: parseRouterAbEcdsaDerivationOperationDigestsV1(
      operation.operation_digests,
      'operationStepUpGrantRequest.operation.operation_digests',
    ),
    material_activation: parseRouterAbMpcMaterialActivationRef(operation.material_activation),
    normal_signing_scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(
      operation.normal_signing_scope,
    ),
    signing_worker_id: requireAsciiNonEmptyString(
      operation.signing_worker_id,
      'operationStepUpGrantRequest.operation.signing_worker_id',
    ),
    key_handle: requireAsciiNonEmptyString(
      operation.key_handle,
      'operationStepUpGrantRequest.operation.key_handle',
    ),
    relayer_key_id: requireAsciiNonEmptyString(
      operation.relayer_key_id,
      'operationStepUpGrantRequest.operation.relayer_key_id',
    ),
    participant_ids: [Number(operation.participant_ids[0]), Number(operation.participant_ids[1])],
    expires_at_ms: requirePositiveUnixMs(
      operation.expires_at_ms,
      'operationStepUpGrantRequest.operation.expires_at_ms',
    ),
  };
}

function requireEcdsaOperationStepUpKind(value: unknown): EvmEcdsaMpcOperationKind {
  switch (value) {
    case EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction:
    case EVM_ECDSA_MPC_OPERATION_KINDS.exportKey:
      return value;
    default:
      throw new Error(
        'operationStepUpGrantRequest.operation.operation_kind must be evm.sign_transaction or evm.export_key',
      );
  }
}

export function buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input: {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  requestId: string;
  operationId: string;
  operationDigests: RouterAbEcdsaDerivationOperationDigestsV1Wire;
  authorization: RouterAbNormalSigningAuthorizationWire;
  materialActivation: RouterAbMpcMaterialActivationRefWire;
  expiresAtMs: number;
  signingDigest32: Uint8Array;
  serverPresignatureId: string;
  clientSignatureShare32: Uint8Array;
  clientRerandomizationContribution32: Uint8Array;
}): RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire {
  return parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1({
    scope: input.scope,
    request_id: input.requestId,
    operation_id: input.operationId,
    operation_digests: input.operationDigests,
    authorization: input.authorization,
    material_activation: input.materialActivation,
    expires_at_ms: input.expiresAtMs,
    signing_digest_b64u: base64UrlEncode(
      requireUint8ArrayFixed(input.signingDigest32, 'signingDigest32', 32),
    ),
    server_presignature_id: input.serverPresignatureId,
    client_signature_share32_b64u: base64UrlEncode(
      requireUint8ArrayFixed(input.clientSignatureShare32, 'clientSignatureShare32', 32),
    ),
    client_rerandomization_contribution32_b64u: base64UrlEncode(
      requireUint8ArrayFixed(
        input.clientRerandomizationContribution32,
        'clientRerandomizationContribution32',
        32,
      ),
    ),
  });
}

export function parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire {
  const record = requireRecord(value, 'ecdsaFinalizeCoreRequest');
  requireExactKeys(record, 'ecdsaFinalizeCoreRequest', [
    'scope',
    'request_id',
    'operation_id',
    'operation_digests',
    'authorization',
    'material_activation',
    'expires_at_ms',
    'signing_digest_b64u',
    'server_presignature_id',
    'client_signature_share32_b64u',
    'client_rerandomization_contribution32_b64u',
  ]);
  return parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFields(record);
}

function parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFields(
  record: Record<string, unknown>,
): RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire {
  const parsed = {
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaFinalizeRequest.request_id'),
    operation_id: requireAsciiNonEmptyString(
      record.operation_id,
      'ecdsaFinalizeRequest.operation_id',
    ),
    operation_digests: parseRouterAbEcdsaDerivationOperationDigestsV1(
      record.operation_digests,
      'ecdsaFinalizeRequest.operation_digests',
    ),
    authorization: parseRouterAbNormalSigningAuthorization(record.authorization),
    material_activation: parseRouterAbMpcMaterialActivationRef(record.material_activation),
    expires_at_ms: requirePositiveUnixMs(
      record.expires_at_ms,
      'ecdsaFinalizeRequest.expires_at_ms',
    ),
    signing_digest_b64u: requireBase64UrlFixed(
      record.signing_digest_b64u,
      'ecdsaFinalizeRequest.signing_digest_b64u',
      32,
    ),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'ecdsaFinalizeRequest.server_presignature_id',
    ),
    client_signature_share32_b64u: requireBase64UrlFixed(
      record.client_signature_share32_b64u,
      'ecdsaFinalizeRequest.client_signature_share32_b64u',
      32,
    ),
    client_rerandomization_contribution32_b64u: requireBase64UrlFixed(
      record.client_rerandomization_contribution32_b64u,
      'ecdsaFinalizeRequest.client_rerandomization_contribution32_b64u',
      32,
    ),
  };
  if (parsed.operation_digests.intent_digest_b64u !== parsed.signing_digest_b64u) {
    throw new Error('ecdsaFinalizeRequest intent digest must equal the admitted signing digest');
  }
  return parsed;
}

export function parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire {
  const record = requireRecord(value, 'ecdsaFinalizeRequest');
  requireExactKeys(record, 'ecdsaFinalizeRequest', [
    'scope',
    'request_id',
    'operation_id',
    'operation_digests',
    'authorization',
    'material_activation',
    'expires_at_ms',
    'signing_digest_b64u',
    'server_presignature_id',
    'client_signature_share32_b64u',
    'client_rerandomization_contribution32_b64u',
  ]);
  return parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFields(record);
}

function parseServerPresignatureShare(
  value: unknown,
): RouterAbEcdsaDerivationServerPresignatureShareV1 {
  const record = requireRecord(value, 'presignature');
  requireExactKeys(record, 'presignature', [
    'serverKeyId',
    'presignatureId',
    'bigRB64u',
    'kShareB64u',
    'sigmaShareB64u',
    'createdAtMs',
  ]);
  return {
    serverKeyId: requireAsciiNonEmptyString(record.serverKeyId, 'presignature.serverKeyId'),
    presignatureId: requireAsciiNonEmptyString(
      record.presignatureId,
      'presignature.presignatureId',
    ),
    bigRB64u: requireBase64UrlFixed(record.bigRB64u, 'presignature.bigRB64u', 33),
    kShareB64u: requireBase64UrlFixed(record.kShareB64u, 'presignature.kShareB64u', 32),
    sigmaShareB64u: requireBase64UrlFixed(record.sigmaShareB64u, 'presignature.sigmaShareB64u', 32),
    createdAtMs: requirePositiveUnixMs(record.createdAtMs, 'presignature.createdAtMs'),
  };
}

export function parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1(
  value: unknown,
): RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire {
  const record = requireRecord(value, 'ecdsaPrepareResponse');
  requireExactKeys(record, 'ecdsaPrepareResponse', [
    'scope',
    'request_id',
    'request_digest',
    'signing_digest',
    'server_presignature_id',
    'server_big_r33_b64u',
    'signing_worker_rerandomization_contribution32_b64u',
    'signature_scheme',
    'prepared_at_ms',
    'expires_at_ms',
  ]);
  return {
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaPrepareResponse.request_id'),
    request_digest: parsePublicDigest32(
      record.request_digest,
      'ecdsaPrepareResponse.request_digest',
    ),
    signing_digest: parsePublicDigest32(
      record.signing_digest,
      'ecdsaPrepareResponse.signing_digest',
    ),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'ecdsaPrepareResponse.server_presignature_id',
    ),
    server_big_r33_b64u: requireBase64UrlFixed(
      record.server_big_r33_b64u,
      'ecdsaPrepareResponse.server_big_r33_b64u',
      33,
    ),
    signing_worker_rerandomization_contribution32_b64u: requireBase64UrlFixed(
      record.signing_worker_rerandomization_contribution32_b64u,
      'ecdsaPrepareResponse.signing_worker_rerandomization_contribution32_b64u',
      32,
    ),
    signature_scheme: requireSignatureScheme(
      record.signature_scheme,
      'ecdsaPrepareResponse.signature_scheme',
    ),
    prepared_at_ms: requirePositiveUnixMs(
      record.prepared_at_ms,
      'ecdsaPrepareResponse.prepared_at_ms',
    ),
    expires_at_ms: requirePositiveUnixMs(
      record.expires_at_ms,
      'ecdsaPrepareResponse.expires_at_ms',
    ),
  };
}

export async function parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1(
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  value: unknown,
): Promise<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire> {
  const parsedRequest = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(request);
  const response = parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1(value);
  if (!sameRouterAbEcdsaDerivationNormalSigningScopeV1(response.scope, parsedRequest.scope)) {
    throw new Error('ecdsaPrepareResponse.scope does not match request');
  }
  if (response.request_id !== parsedRequest.request_id) {
    throw new Error('ecdsaPrepareResponse.request_id does not match request');
  }
  if (response.server_presignature_id !== parsedRequest.client_presignature_id) {
    throw new Error('ecdsaPrepareResponse.server_presignature_id does not match request');
  }
  if (
    !samePublicDigest32(
      response.signing_digest,
      publicDigest32FromBase64Url(parsedRequest.signing_digest_b64u),
    )
  ) {
    throw new Error('ecdsaPrepareResponse.signing_digest does not match request');
  }
  if (response.expires_at_ms !== parsedRequest.expires_at_ms) {
    throw new Error('ecdsaPrepareResponse.expires_at_ms does not match request');
  }
  if (
    !samePublicDigest32(
      response.request_digest,
      await routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(parsedRequest),
    )
  ) {
    throw new Error('ecdsaPrepareResponse.request_digest does not match request');
  }
  return response;
}

export function parseRouterAbEcdsaDerivationEvmDigestSigningResponseV1(
  value: unknown,
): RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire {
  const record = requireRecord(value, 'ecdsaSigningResponse');
  requireExactKeys(record, 'ecdsaSigningResponse', [
    'scope',
    'request_id',
    'request_digest',
    'signing_digest',
    'signature_scheme',
    'signature65_b64u',
  ]);
  return {
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaSigningResponse.request_id'),
    request_digest: parsePublicDigest32(
      record.request_digest,
      'ecdsaSigningResponse.request_digest',
    ),
    signing_digest: parsePublicDigest32(
      record.signing_digest,
      'ecdsaSigningResponse.signing_digest',
    ),
    signature_scheme: requireSignatureScheme(
      record.signature_scheme,
      'ecdsaSigningResponse.signature_scheme',
    ),
    signature65_b64u: requireBase64UrlFixed(
      record.signature65_b64u,
      'ecdsaSigningResponse.signature65_b64u',
      65,
    ),
  };
}

export async function parseRouterAbEcdsaDerivationEvmDigestSigningResponseForCoreRequestV1(
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
  value: unknown,
): Promise<RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire> {
  const parsedRequest = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1(request);
  const response = parseRouterAbEcdsaDerivationEvmDigestSigningResponseV1(value);
  if (!sameRouterAbEcdsaDerivationNormalSigningScopeV1(response.scope, parsedRequest.scope)) {
    throw new Error('ecdsaSigningResponse.scope does not match request');
  }
  if (response.request_id !== parsedRequest.request_id) {
    throw new Error('ecdsaSigningResponse.request_id does not match request');
  }
  if (
    !samePublicDigest32(
      response.signing_digest,
      publicDigest32FromBase64Url(parsedRequest.signing_digest_b64u),
    )
  ) {
    throw new Error('ecdsaSigningResponse.signing_digest does not match request');
  }
  if (
    !samePublicDigest32(
      response.request_digest,
      await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(parsedRequest),
    )
  ) {
    throw new Error('ecdsaSigningResponse.request_digest does not match request');
  }
  return response;
}

function parseActiveSigningWorkerState(value: unknown): RouterAbActiveSigningWorkerStateV1 {
  const record = requireRecord(value, 'receipt.active_signing_worker_state');
  requireExactKeys(record, 'receipt.active_signing_worker_state', [
    'account_id',
    'material_activation',
    'account_public_key',
    'signing_worker',
    'activation_transcript_digest',
    'activation_digest',
    'signing_worker_material_handle',
    'activated_at_ms',
  ]);
  return {
    account_id: requireAsciiNonEmptyString(
      record.account_id,
      'receipt.active_signing_worker_state.account_id',
    ),
    material_activation: parseRouterAbMpcMaterialActivationRef(record.material_activation),
    account_public_key: requireAsciiNonEmptyString(
      record.account_public_key,
      'receipt.active_signing_worker_state.account_public_key',
    ),
    signing_worker: parseServerIdentityWithLabel(
      record.signing_worker,
      'receipt.active_signing_worker_state.signing_worker',
    ),
    activation_transcript_digest: parsePublicDigest32(
      record.activation_transcript_digest,
      'receipt.active_signing_worker_state.activation_transcript_digest',
    ),
    activation_digest: parsePublicDigest32(
      record.activation_digest,
      'receipt.active_signing_worker_state.activation_digest',
    ),
    signing_worker_material_handle: requireAsciiNonEmptyString(
      record.signing_worker_material_handle,
      'receipt.active_signing_worker_state.signing_worker_material_handle',
    ),
    activated_at_ms: requirePositiveUnixMs(
      record.activated_at_ms,
      'receipt.active_signing_worker_state.activated_at_ms',
    ),
  };
}

export function buildCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(input: {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  presignature: RouterAbEcdsaDerivationServerPresignatureShareV1;
  expiresAtMs: number;
}): CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire {
  const scope = parseRouterAbEcdsaDerivationNormalSigningScopeV1(input.scope);
  const presignature = parseServerPresignatureShare(input.presignature);
  const expiresAtMs = requirePositiveUnixMs(input.expiresAtMs, 'expiresAtMs');
  return {
    scope,
    server_presignature_id: presignature.presignatureId,
    server_big_r33_b64u: presignature.bigRB64u,
    server_k_share32_b64u: presignature.kShareB64u,
    server_sigma_share32_b64u: presignature.sigmaShareB64u,
    expires_at_ms: expiresAtMs,
  };
}

export function parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(
  value: unknown,
): CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire {
  const record = requireRecord(value, 'poolFillRequest');
  requireExactKeys(record, 'poolFillRequest', [
    'scope',
    'server_presignature_id',
    'server_big_r33_b64u',
    'server_k_share32_b64u',
    'server_sigma_share32_b64u',
    'expires_at_ms',
  ]);
  return {
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'poolFillRequest.server_presignature_id',
    ),
    server_big_r33_b64u: requireBase64UrlFixed(
      record.server_big_r33_b64u,
      'poolFillRequest.server_big_r33_b64u',
      33,
    ),
    server_k_share32_b64u: requireBase64UrlFixed(
      record.server_k_share32_b64u,
      'poolFillRequest.server_k_share32_b64u',
      32,
    ),
    server_sigma_share32_b64u: requireBase64UrlFixed(
      record.server_sigma_share32_b64u,
      'poolFillRequest.server_sigma_share32_b64u',
      32,
    ),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, 'poolFillRequest.expires_at_ms'),
  };
}

export function parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1(
  value: unknown,
): CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire {
  const record = requireRecord(value, 'receipt');
  requireExactKeys(record, 'receipt', [
    'active_signing_worker_state',
    'server_presignature_id',
    'server_big_r33_b64u',
    'stored',
  ]);
  return {
    active_signing_worker_state: parseActiveSigningWorkerState(record.active_signing_worker_state),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'receipt.server_presignature_id',
    ),
    server_big_r33_b64u: requireBase64UrlFixed(
      record.server_big_r33_b64u,
      'receipt.server_big_r33_b64u',
      33,
    ),
    stored: requireBoolean(record.stored, 'receipt.stored'),
  };
}

export function parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptForRequestV1(
  request: CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire,
  value: unknown,
): CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire {
  const parsedRequest =
    parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(request);
  const receipt = parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1(value);
  if (receipt.server_presignature_id !== parsedRequest.server_presignature_id) {
    throw new Error('receipt.server_presignature_id does not match pool-fill request');
  }
  if (receipt.server_big_r33_b64u !== parsedRequest.server_big_r33_b64u) {
    throw new Error('receipt.server_big_r33_b64u does not match pool-fill request');
  }
  return receipt;
}
