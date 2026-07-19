import { base64UrlDecode, base64UrlEncode } from './encoders';
import {
  computeSdkEcdsaDerivationApplicationBindingDigestB64u,
  type SdkEcdsaDerivationBindingFacts,
} from '../threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  decodeJwtPayloadRecord,
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
} from './sessionTokens';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '../threshold/signingRootScope';
import { requireRouterAbX25519PublicKey } from './routerAbPublicKeyset';
import {
  parseEcdsaActiveStateId,
  parseRootShareEpoch,
  parseSigningGrantId,
  parseThresholdEcdsaSessionId,
  type EcdsaActiveStateId,
  type RootShareEpoch,
  type SigningGrantId,
  type ThresholdEcdsaSessionId,
} from './domainIds';

export const ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1 = 'evm-family' as const;
export const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1 =
  'router_ab_ecdsa_derivation_normal_signing_v1' as const;
export const ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH =
  '/router-ab/ecdsa-derivation/healthz' as const;
export const ROUTER_AB_ECDSA_DERIVATION_BOOTSTRAP_PATH =
  '/router-ab/ecdsa-derivation/bootstrap' as const;
export const ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH = '/router-ab/ecdsa-derivation/export' as const;
export const ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH =
  '/router-ab/ecdsa-derivation/recover' as const;
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

export type RouterAbEcdsaDerivationRecoveryLifecycleScopeV1 =
  RouterAbEcdsaDerivationPostRegistrationLifecycleScopeV1<'recovery', 'recovery'>;

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
    replay: {
      request_id: string;
      reserved: true;
    };
    lifecycle: {
      lifecycle_id: string;
      stored: true;
    };
    bundles: RouterAbEcdsaClientProofFinalizationV1['bundles'];
  };
};

export type RouterAbEcdsaStrictForwardedProofResponseV1 =
  RouterAbEcdsaStrictForwardedRegistrationResponseV1;

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
  threshold_session_id: ThresholdEcdsaSessionId;
  signing_grant_id: SigningGrantId;
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
    publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  };
};

export type RouterAbEcdsaRegistrationActivationReceiptV1 = {
  ecdsa_activation: {
    context: RouterAbEcdsaDerivationStableKeyContextV1;
    public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
    signing_worker: RouterAbServerIdentityV1;
    activation_epoch: RootShareEpoch;
    activation_digest_b64u: string;
    activated_at_ms: number;
  };
  lifecycle_id: string;
  transcript_digest: RouterAbPublicDigest32V1Wire;
  activated: true;
};

export type RouterAbEcdsaRegistrationPublicActivationReceiptV1 =
  RouterAbEcdsaRegistrationActivationReceiptV1;

export type RouterAbEcdsaDerivationPublicCapabilityV1 = {
  kind: 'router_ab_ecdsa_derivation_public_capability_v1';
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
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
  signing_grant_id: SigningGrantId;
  ttl_ms: number;
  remaining_uses: number;
  runtime_policy_scope: RuntimePolicyScope;
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
    threshold_session_id: ThresholdEcdsaSessionId;
    signing_grant_id: SigningGrantId;
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

export type RouterAbEcdsaDerivationExplicitExportRequestV1 = {
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  lifecycle: RouterAbEcdsaDerivationExportLifecycleScopeV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
  signer_set: RouterAbEcdsaDerivationSignerSetV1;
  router_id: string;
  client_id: string;
  client_ephemeral_public_key: string;
  export_authorization_digest_b64u: string;
  export_nonce: string;
  expires_at_ms: number;
  deriver_a_export_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  deriver_b_export_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
};

export type RouterAbEcdsaDerivationRecoveryRequestV1 = {
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  lifecycle: RouterAbEcdsaDerivationRecoveryLifecycleScopeV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
  signer_set: RouterAbEcdsaDerivationSignerSetV1;
  router_id: string;
  client_id: string;
  client_ephemeral_public_key: string;
  recovery_authorization_digest_b64u: string;
  recovery_nonce: string;
  expires_at_ms: number;
  deriver_a_recovery_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  deriver_b_recovery_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
};

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
  expires_at_ms: number;
  deriver_a_refresh_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  deriver_b_refresh_envelope: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
};

export type RouterAbPublicDigest32V1Wire = {
  bytes: number[];
};

export type RouterAbActiveSigningWorkerStateV1 = {
  account_id: string;
  session_id: string;
  account_public_key: string;
  signing_worker: RouterAbServerIdentityV1;
  activation_transcript_digest: RouterAbPublicDigest32V1Wire;
  activation_digest: RouterAbPublicDigest32V1Wire;
  signing_worker_material_handle: string;
  activated_at_ms: number;
};

export type RouterAbEcdsaDerivationNormalSigningScopeV1 = {
  wallet_key_id: string;
  wallet_id: string;
  ecdsa_threshold_key_id: string;
  signing_root_id: string;
  signing_root_version: string;
  context: RouterAbEcdsaDerivationStableKeyContextV1;
  public_identity: RouterAbEcdsaDerivationPublicIdentityV1;
  signing_worker: RouterAbServerIdentityV1;
  activation_epoch: RootShareEpoch;
};

export type RouterAbEcdsaDerivationNormalSigningStateV1 = {
  kind: typeof ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
};

export type RouterAbEcdsaDerivationWalletRegistrationJwtBindingFactsV1 = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  relayerKeyId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdSessionId: string;
  activationEpoch: RootShareEpoch;
  signingGrantId: SigningGrantId;
  expiresAtMs: number;
  participantIds: readonly number[];
  applicationBindingDigestB64u: string;
  contextBinding32B64u: string;
  clientPublicKey33B64u: string;
  serverPublicKey33B64u: string;
  thresholdPublicKey33B64u: string;
  ethereumAddress: string;
  clientShareRetryCounter: number;
  serverShareRetryCounter: number;
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

export type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  request_id: string;
  client_presignature_id: string;
  expires_at_ms: number;
  signing_digest_b64u: string;
  client_rerandomization_commitment32_b64u: string;
};

export type RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  request_id: string;
  expires_at_ms: number;
  signing_digest_b64u: string;
  server_presignature_id: string;
  client_signature_share32_b64u: string;
  client_rerandomization_contribution32_b64u: string;
};

export type RouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1Wire =
  RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire & {
    budget_reservation_id: string;
    budget_operation_id: string;
  };

export type RouterAbEcdsaDerivationBudgetStatusV1Wire = {
  committed_remaining_uses: number;
  reserved_uses: number;
  available_uses: number;
};

export type RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire = {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  request_id: string;
  budget_reservation_id: string;
  budget_operation_id: string;
  budget_status: RouterAbEcdsaDerivationBudgetStatusV1Wire;
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

function requireSigningGrantId(value: unknown, label: string): SigningGrantId {
  const parsed = parseSigningGrantId(requireAsciiNonEmptyString(value, label));
  if (!parsed.ok) throw new Error(`${label} is invalid`);
  return parsed.value;
}

function requireThresholdEcdsaSessionId(value: unknown, label: string): ThresholdEcdsaSessionId {
  const parsed = parseThresholdEcdsaSessionId(requireAsciiNonEmptyString(value, label));
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
    'threshold_session_id',
    'signing_grant_id',
    'lifecycle_id',
    'recipient_identity',
    'recipient_public_key',
    'expires_at_ms',
  ]);
  if (!Array.isArray(record.ciphertext_and_tag) || record.ciphertext_and_tag.length <= 48) {
    throw new Error(`${label}.ciphertext_and_tag is invalid`);
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
      threshold_session_id: requireThresholdEcdsaSessionId(
        binding.threshold_session_id,
        `${bindingLabel}.threshold_session_id`,
      ),
      signing_grant_id: requireSigningGrantId(
        binding.signing_grant_id,
        `${bindingLabel}.signing_grant_id`,
      ),
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
  requireExactKeys(response, label, ['replay', 'lifecycle', 'bundles']);
  const bundlesLabel = `${label}.bundles`;
  const bundles = requireRecord(response.bundles, bundlesLabel);
  requireExactKeys(bundles, bundlesLabel, ['signerA', 'signerB']);
  const replayLabel = `${label}.replay`;
  const replay = requireRecord(response.replay, replayLabel);
  requireExactKeys(replay, replayLabel, ['request_id', 'reserved']);
  if (replay.reserved !== true) {
    throw new Error(`${replayLabel}.reserved must be true for a forwarded response`);
  }
  const lifecycleLabel = `${label}.lifecycle`;
  const lifecycle = requireRecord(response.lifecycle, lifecycleLabel);
  requireExactKeys(lifecycle, lifecycleLabel, ['lifecycle_id', 'stored']);
  if (lifecycle.stored !== true) {
    throw new Error(`${lifecycleLabel}.stored must be true for a forwarded response`);
  }
  return {
    replay: {
      request_id: requireAsciiNonEmptyString(replay.request_id, `${replayLabel}.request_id`),
      reserved: true,
    },
    lifecycle: {
      lifecycle_id: requireAsciiNonEmptyString(
        lifecycle.lifecycle_id,
        `${lifecycleLabel}.lifecycle_id`,
      ),
      stored: true,
    },
    bundles: {
      signerA: parseRouterAbEcdsaClientProofBundleV1(bundles.signerA, `${bundlesLabel}.signerA`),
      signerB: parseRouterAbEcdsaClientProofBundleV1(bundles.signerB, `${bundlesLabel}.signerB`),
    },
  };
}

export function parseRouterAbEcdsaDerivationActivationRefreshForwardedResponseV1(
  value: unknown,
): RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1 {
  const label = 'activationRefreshForwarded';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['result', 'response', 'signing_worker_activation']);
  if (record.result !== 'forwarded') {
    throw new Error(`${label}.result must be forwarded`);
  }
  return {
    result: 'forwarded',
    response: parseRouterAbEcdsaStrictProofResponseV1(record.response, `${label}.response`),
    signing_worker_activation: parseRouterAbEcdsaRegistrationActivationReceiptV1(
      record.signing_worker_activation,
    ),
  };
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
  requireExactKeys(ecdsa, `${label}.ecdsa`, ['kind', 'publicFacts']);
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
    'ecdsa_activation',
    'lifecycle_id',
    'transcript_digest',
    'activated',
  ]);
  const activationLabel = `${label}.ecdsa_activation`;
  const activation = requireRecord(record.ecdsa_activation, activationLabel);
  requireExactKeys(activation, activationLabel, [
    'context',
    'public_identity',
    'signing_worker',
    'activation_epoch',
    'activation_digest_b64u',
    'activated_at_ms',
  ]);
  const signingWorker = parseServerIdentityWithLabel(
    activation.signing_worker,
    `${activationLabel}.signing_worker`,
  );
  const activationDigestB64u = requireBase64UrlFixed(
    activation.activation_digest_b64u,
    `${activationLabel}.activation_digest_b64u`,
    32,
  );
  const transcriptDigest = parsePublicDigest32(
    record.transcript_digest,
    `${label}.transcript_digest`,
  );
  if (record.activated !== true) {
    throw new Error(`${label}.activated must be true`);
  }
  return {
    ecdsa_activation: {
      context: parseStableKeyContext(activation.context),
      public_identity: parsePublicIdentity(activation.public_identity),
      signing_worker: signingWorker,
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
    activated: true,
  };
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

function requireRegistrationFactsMatchRequest(input: {
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
    'signing_grant_id',
    'ttl_ms',
    'remaining_uses',
    'runtime_policy_scope',
  ]);
  return {
    threshold_session_id: requireThresholdEcdsaSessionId(
      record.threshold_session_id,
      `${label}.threshold_session_id`,
    ),
    signing_grant_id: requireSigningGrantId(record.signing_grant_id, `${label}.signing_grant_id`),
    ttl_ms: requirePositiveCounter(record.ttl_ms, `${label}.ttl_ms`),
    remaining_uses: requirePositiveCounter(record.remaining_uses, `${label}.remaining_uses`),
    runtime_policy_scope: normalizeRuntimePolicyScope(record.runtime_policy_scope),
  };
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
    'threshold_session_id',
    'signing_grant_id',
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
      threshold_session_id: requireThresholdEcdsaSessionId(
        sessionRecord.threshold_session_id,
        `${label}.session.threshold_session_id`,
      ),
      signing_grant_id: requireSigningGrantId(
        sessionRecord.signing_grant_id,
        `${label}.session.signing_grant_id`,
      ),
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
  requireRegistrationFactsMatchRequest({ facts, request });
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
  requireExactKeys(record, label, [
    'context',
    'lifecycle',
    'public_identity',
    'signer_set',
    'router_id',
    'client_id',
    'client_ephemeral_public_key',
    'export_authorization_digest_b64u',
    'export_nonce',
    'expires_at_ms',
    'deriver_a_export_envelope',
    'deriver_b_export_envelope',
  ]);
  const lifecycle = parsePostRegistrationLifecycleScope(
    record.lifecycle,
    `${label}.lifecycle`,
    'key_export',
    'export',
  );
  const signerSet = parsePostRegistrationSignerSet(record.signer_set, `${label}.signer_set`);
  requirePostRegistrationBindings(label, lifecycle, signerSet);
  return {
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
  };
}

export function parseRouterAbEcdsaDerivationRecoveryRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationRecoveryRequestV1 {
  const label = 'recovery';
  const record = requireRecord(value, label);
  requireExactKeys(record, label, [
    'context',
    'lifecycle',
    'public_identity',
    'signer_set',
    'router_id',
    'client_id',
    'client_ephemeral_public_key',
    'recovery_authorization_digest_b64u',
    'recovery_nonce',
    'expires_at_ms',
    'deriver_a_recovery_envelope',
    'deriver_b_recovery_envelope',
  ]);
  const lifecycle = parsePostRegistrationLifecycleScope(
    record.lifecycle,
    `${label}.lifecycle`,
    'recovery',
    'recovery',
  );
  const signerSet = parsePostRegistrationSignerSet(record.signer_set, `${label}.signer_set`);
  requirePostRegistrationBindings(label, lifecycle, signerSet);
  return {
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
    recovery_authorization_digest_b64u: requireBase64UrlFixed(
      record.recovery_authorization_digest_b64u,
      `${label}.recovery_authorization_digest_b64u`,
      32,
    ),
    recovery_nonce: requireAsciiNonEmptyString(record.recovery_nonce, `${label}.recovery_nonce`),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, `${label}.expires_at_ms`),
    deriver_a_recovery_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_a_recovery_envelope,
      `${label}.deriver_a_recovery_envelope`,
      'signer_a',
    ),
    deriver_b_recovery_envelope: parsePostRegistrationRoleEnvelope(
      record.deriver_b_recovery_envelope,
      `${label}.deriver_b_recovery_envelope`,
      'signer_b',
    ),
  };
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
  let remaining = BigInt(value);
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
  pushLen32(out, asciiBytes(parsed.wallet_key_id));
  pushLen32(out, asciiBytes(parsed.wallet_id));
  pushLen32(out, asciiBytes(parsed.ecdsa_threshold_key_id));
  pushLen32(out, asciiBytes(parsed.signing_root_id));
  pushLen32(out, asciiBytes(parsed.signing_root_version));
  pushLen32(out, canonicalStableKeyContextBytes(parsed.context));
  pushLen32(out, canonicalPublicIdentityBytes(parsed.public_identity));
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
    'wallet_key_id',
    'wallet_id',
    'ecdsa_threshold_key_id',
    'signing_root_id',
    'signing_root_version',
    'context',
    'public_identity',
    'signing_worker',
    'activation_epoch',
  ]);
  return {
    wallet_key_id: requireAsciiNonEmptyString(record.wallet_key_id, 'scope.wallet_key_id'),
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

function requireWalletRegistrationMatchingString(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): string {
  const expected = String(args.expected || '').trim();
  const actual = String(args.actual || '').trim();
  if (!expected || !actual) {
    throw new Error(`ECDSA registration bootstrap returned incomplete ${args.field}`);
  }
  if (expected !== actual) {
    throw new Error(`ECDSA registration bootstrap ${args.field} mismatch`);
  }
  return actual;
}

function requireWalletRegistrationMatchingNumber(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): number {
  const expected = Math.floor(Number(args.expected));
  const actual = Math.floor(Number(args.actual));
  if (!Number.isSafeInteger(expected) || !Number.isSafeInteger(actual)) {
    throw new Error(`ECDSA registration bootstrap returned incomplete ${args.field}`);
  }
  if (expected !== actual) {
    throw new Error(`ECDSA registration bootstrap ${args.field} mismatch`);
  }
  return actual;
}

function requireWalletRegistrationMatchingParticipantIds(args: {
  expected: readonly unknown[];
  actual: readonly unknown[];
}): number[] {
  const expected = args.expected.map((participantId) => Math.floor(Number(participantId)));
  const actual = args.actual.map((participantId) => Math.floor(Number(participantId)));
  const invalid =
    expected.length === 0 ||
    actual.length === 0 ||
    expected.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0) ||
    actual.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0);
  if (invalid) {
    throw new Error('ECDSA registration bootstrap returned incomplete participantIds');
  }
  if (expected.length !== actual.length || expected.some((id, index) => id !== actual[index])) {
    throw new Error('ECDSA registration bootstrap participantIds mismatch');
  }
  return actual;
}

function ethereumAddress20B64u(address: string): string {
  const normalized = String(address || '').trim();
  const hex = normalized.startsWith('0x') ? normalized.slice(2) : normalized;
  if (!/^[0-9a-fA-F]{40}$/.test(hex)) {
    throw new Error('ECDSA registration bootstrap returned invalid ethereumAddress');
  }
  const bytes = new Uint8Array(20);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return base64UrlEncode(bytes);
}

export function parseRouterAbEcdsaDerivationNormalSigningFromWalletRegistrationJwtV1(args: {
  walletSessionJwt: string;
  expected: RouterAbEcdsaDerivationWalletRegistrationJwtBindingFactsV1;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const payload = decodeJwtPayloadRecord(args.walletSessionJwt);
  if (!payload) {
    throw new Error('ECDSA registration bootstrap returned invalid Wallet Session JWT');
  }
  const expected = args.expected;
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.kind',
    expected: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    actual: payload.kind,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.sub',
    expected: expected.walletId,
    actual: payload.sub,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.walletId',
    expected: expected.walletId,
    actual: payload.walletId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.evmFamilySigningKeySlotId',
    expected: expected.evmFamilySigningKeySlotId,
    actual: payload.evmFamilySigningKeySlotId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.keyScope',
    expected: ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1,
    actual: payload.keyScope,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.keyHandle',
    expected: expected.keyHandle,
    actual: payload.keyHandle,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.relayerKeyId',
    expected: expected.relayerKeyId,
    actual: payload.relayerKeyId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.thresholdSessionId',
    expected: expected.thresholdSessionId,
    actual: payload.thresholdSessionId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.signingGrantId',
    expected: expected.signingGrantId,
    actual: payload.signingGrantId,
  });
  requireWalletRegistrationMatchingNumber({
    field: 'walletSessionJwt.thresholdExpiresAtMs',
    expected: expected.expiresAtMs,
    actual: payload.thresholdExpiresAtMs,
  });
  requireWalletRegistrationMatchingParticipantIds({
    expected: expected.participantIds,
    actual: Array.isArray(payload.participantIds) ? payload.participantIds : [],
  });
  const hasNormalSigning = payload.routerAbEcdsaDerivationNormalSigning !== undefined;
  const hasIssuerBinding = payload.routerAbEcdsaDerivationIssuerBinding !== undefined;
  if (!hasNormalSigning) {
    throw new Error(
      hasIssuerBinding
        ? 'ECDSA registration bootstrap Wallet Session JWT is issuer-binding-only'
        : 'ECDSA registration bootstrap Wallet Session JWT missing routerAbEcdsaDerivationNormalSigning',
    );
  }
  if (hasIssuerBinding) {
    throw new Error(
      'ECDSA registration bootstrap Wallet Session JWT must contain normal-signing state only',
    );
  }
  let normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1 | null = null;
  try {
    normalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1(
      payload.routerAbEcdsaDerivationNormalSigning,
    );
  } catch {
    throw new Error(
      'ECDSA registration bootstrap Wallet Session JWT has invalid routerAbEcdsaDerivationNormalSigning',
    );
  }
  if (!normalSigning) {
    throw new Error(
      'ECDSA registration bootstrap Wallet Session JWT missing routerAbEcdsaDerivationNormalSigning',
    );
  }
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.wallet_id',
    expected: expected.walletId,
    actual: normalSigning.scope.wallet_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.wallet_key_id',
    expected: expected.evmFamilySigningKeySlotId,
    actual: normalSigning.scope.wallet_key_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.ecdsa_threshold_key_id',
    expected: expected.ecdsaThresholdKeyId,
    actual: normalSigning.scope.ecdsa_threshold_key_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.signing_root_id',
    expected: expected.signingRootId,
    actual: normalSigning.scope.signing_root_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.signing_root_version',
    expected: expected.signingRootVersion,
    actual: normalSigning.scope.signing_root_version,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.context.application_binding_digest_b64u',
    expected: expected.applicationBindingDigestB64u,
    actual: normalSigning.scope.context.application_binding_digest_b64u,
  });
  const publicIdentity = normalSigning.scope.public_identity;
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.public_identity.context_binding_b64u',
    expected: expected.contextBinding32B64u,
    actual: publicIdentity.context_binding_b64u,
  });
  requireWalletRegistrationMatchingString({
    field:
      'routerAbEcdsaDerivationNormalSigning.scope.public_identity.derivation_client_share_public_key33_b64u',
    expected: expected.clientPublicKey33B64u,
    actual: publicIdentity.derivation_client_share_public_key33_b64u,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.public_identity.server_public_key33_b64u',
    expected: expected.serverPublicKey33B64u,
    actual: publicIdentity.server_public_key33_b64u,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.public_identity.threshold_public_key33_b64u',
    expected: expected.thresholdPublicKey33B64u,
    actual: publicIdentity.threshold_public_key33_b64u,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.public_identity.ethereum_address20_b64u',
    expected: ethereumAddress20B64u(expected.ethereumAddress),
    actual: publicIdentity.ethereum_address20_b64u,
  });
  requireWalletRegistrationMatchingNumber({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.public_identity.client_share_retry_counter',
    expected: expected.clientShareRetryCounter,
    actual: publicIdentity.client_share_retry_counter,
  });
  requireWalletRegistrationMatchingNumber({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.public_identity.server_share_retry_counter',
    expected: expected.serverShareRetryCounter,
    actual: publicIdentity.server_share_retry_counter,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaDerivationNormalSigning.scope.activation_epoch',
    expected: expected.activationEpoch,
    actual: normalSigning.scope.activation_epoch,
  });
  if (!String(normalSigning.scope.signing_worker.server_id || '').trim()) {
    throw new Error('ECDSA registration bootstrap Wallet Session JWT missing signing worker id');
  }
  return normalSigning;
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

export function buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input: {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  requestId: string;
  clientPresignatureId: string;
  expiresAtMs: number;
  signingDigest32: Uint8Array;
  clientRerandomizationCommitment32: Uint8Array;
}): RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire {
  return parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope: input.scope,
    request_id: input.requestId,
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
    'client_presignature_id',
    'expires_at_ms',
    'signing_digest_b64u',
    'client_rerandomization_commitment32_b64u',
  ]);
  return {
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaSigningRequest.request_id'),
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
}

export function buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1(input: {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  requestId: string;
  budgetReservationId: string;
  budgetOperationId: string;
  expiresAtMs: number;
  signingDigest32: Uint8Array;
  serverPresignatureId: string;
  clientSignatureShare32: Uint8Array;
  clientRerandomizationContribution32: Uint8Array;
}): RouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1Wire {
  return parseRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1({
    scope: input.scope,
    request_id: input.requestId,
    budget_reservation_id: input.budgetReservationId,
    budget_operation_id: input.budgetOperationId,
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
  return {
    scope: parseRouterAbEcdsaDerivationNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaFinalizeRequest.request_id'),
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
}

export function parseRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1(
  value: unknown,
): RouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1Wire {
  const record = requireRecord(value, 'ecdsaFinalizeRequest');
  requireExactKeys(record, 'ecdsaFinalizeRequest', [
    'scope',
    'request_id',
    'budget_reservation_id',
    'budget_operation_id',
    'expires_at_ms',
    'signing_digest_b64u',
    'server_presignature_id',
    'client_signature_share32_b64u',
    'client_rerandomization_contribution32_b64u',
  ]);
  const coreRequest = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFields(record);
  return {
    ...coreRequest,
    budget_reservation_id: requireAsciiNonEmptyString(
      record.budget_reservation_id,
      'ecdsaFinalizeRequest.budget_reservation_id',
    ),
    budget_operation_id: requireAsciiNonEmptyString(
      record.budget_operation_id,
      'ecdsaFinalizeRequest.budget_operation_id',
    ),
  };
}

export function routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFromBudgetedV1(
  request: RouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1Wire,
): RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire {
  const parsed = parseRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1(request);
  return {
    scope: parsed.scope,
    request_id: parsed.request_id,
    expires_at_ms: parsed.expires_at_ms,
    signing_digest_b64u: parsed.signing_digest_b64u,
    server_presignature_id: parsed.server_presignature_id,
    client_signature_share32_b64u: parsed.client_signature_share32_b64u,
    client_rerandomization_contribution32_b64u: parsed.client_rerandomization_contribution32_b64u,
  };
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
    'budget_reservation_id',
    'budget_operation_id',
    'budget_status',
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
    budget_reservation_id: requireAsciiNonEmptyString(
      record.budget_reservation_id,
      'ecdsaPrepareResponse.budget_reservation_id',
    ),
    budget_operation_id: requireAsciiNonEmptyString(
      record.budget_operation_id,
      'ecdsaPrepareResponse.budget_operation_id',
    ),
    budget_status: parseRouterAbEcdsaDerivationBudgetStatusV1(
      record.budget_status,
      'ecdsaPrepareResponse.budget_status',
    ),
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

function parseRouterAbEcdsaDerivationBudgetStatusV1(
  value: unknown,
  label: string,
): RouterAbEcdsaDerivationBudgetStatusV1Wire {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['committed_remaining_uses', 'reserved_uses', 'available_uses']);
  return {
    committed_remaining_uses: requireNonNegativeInteger(
      record.committed_remaining_uses,
      `${label}.committed_remaining_uses`,
    ),
    reserved_uses: requireNonNegativeInteger(record.reserved_uses, `${label}.reserved_uses`),
    available_uses: requireNonNegativeInteger(record.available_uses, `${label}.available_uses`),
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
    'session_id',
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
    session_id: requireAsciiNonEmptyString(
      record.session_id,
      'receipt.active_signing_worker_state.session_id',
    ),
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
