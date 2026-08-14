import type {
  RouterAbNormalSigningFinalizeRequestV2Wire,
  RouterAbNormalSigningPrepareRequestV2Wire,
} from './routerAbNormalSigning';
import type {
  RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
  RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RootShareEpoch } from '@shared/utils/domainIds';

declare const rootShareEpoch: RootShareEpoch;

const scope = {
  request_id: 'router-ab-normal-signing/request-1',
  account_id: 'alice.testnet',
  authorization: {
    kind: 'reusable_wallet_session' as const,
    wallet_session_id: 'wallet-session-1',
  },
  material_activation: {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: 'activation-1',
    capability: 'capability-1',
    material_owner: 'alice.testnet',
    key_binding: 'near-ed25519-key-1',
    lifecycle_binding: 'lifecycle-1',
    signing_worker: 'signing-worker-a',
  },
  signing_worker_id: 'signing-worker-a',
};

const digest32 = {
  bytes: Array.from({ length: 32 }, (_, index) => index),
};

const authorizationClaim = {
  kind: 'reusable_wallet_session_authorized_operation_v1' as const,
  authorized_operation_id: 'authorized-operation-1',
  operation_id: 'operation-1',
  capability_kind: 'near_ed25519_mpc_signing' as const,
  operation_kind: 'near.sign_transaction' as const,
  lane_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  intent_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  display_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  operation_fingerprint_digest: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
};

const prepareRequest = {
  scope,
  expires_at_ms: 1_900_000_000_000,
  display_digest: digest32,
  intent: {
    kind: 'near_transaction_v1' as const,
    operation_id: 'operation-1',
    operation_fingerprint: 'fingerprint-1',
    near_account_id: 'alice.testnet',
    near_network_id: 'testnet' as const,
    transactions: [
      {
        receiver_id: 'contract.testnet',
        action_fingerprint: 'action-fingerprint-1',
      },
    ],
    unsigned_transaction_borsh_b64u: 'unsigned-transaction-borsh',
  },
  signing_payload: {
    kind: 'near_unsigned_transaction_borsh_v1' as const,
    unsigned_transaction_borsh_b64u: 'unsigned-transaction-borsh',
    expected_signing_digest_b64u: 'signing-digest',
  },
} satisfies RouterAbNormalSigningPrepareRequestV2Wire;
void prepareRequest;

const finalizeRequest = {
  scope,
  expires_at_ms: 1_900_000_000_000,
  authorized_operation: authorizationClaim,
  prepare_binding: {
    server_round1_handle: 'round-1-handle',
    round1_binding_digest: digest32,
    intent_digest: digest32,
    signing_payload_digest: digest32,
  },
  protocol: {
    kind: 'ed25519_two_party_frost_finalize_v1' as const,
    client_commitments: {
      hiding: 'client-hiding',
      binding: 'client-binding',
    },
    server_commitments: {
      hiding: 'server-hiding',
      binding: 'server-binding',
    },
    client_verifying_share_b64u: 'client-verifying-share',
    server_verifying_share_b64u: 'server-verifying-share',
    client_signature_share_b64u: 'client-signature-share',
  },
} satisfies RouterAbNormalSigningFinalizeRequestV2Wire;
void finalizeRequest;

const finalizeWithClientGroupPublicKey = {
  scope,
  expires_at_ms: 1_900_000_000_000,
  authorized_operation: finalizeRequest.authorized_operation,
  prepare_binding: finalizeRequest.prepare_binding,
  protocol: {
    kind: 'ed25519_two_party_frost_finalize_v1' as const,
    // @ts-expect-error active SigningWorker state owns the group public key.
    group_public_key: 'ed25519:public-key',
    client_commitments: finalizeRequest.protocol.client_commitments,
    server_commitments: finalizeRequest.protocol.server_commitments,
    client_verifying_share_b64u: 'client-verifying-share',
    server_verifying_share_b64u: 'server-verifying-share',
    client_signature_share_b64u: 'client-signature-share',
  },
} satisfies RouterAbNormalSigningFinalizeRequestV2Wire;
void finalizeWithClientGroupPublicKey;

const missingPrepareBinding = {
  scope,
  expires_at_ms: 1_900_000_000_000,
  protocol: finalizeRequest.protocol,
};

// @ts-expect-error finalize requires the Router-issued prepare binding.
const finalizeWithoutPrepare: RouterAbNormalSigningFinalizeRequestV2Wire = missingPrepareBinding;
void finalizeWithoutPrepare;

const missingSigningWorkerScope = {
  request_id: 'router-ab-normal-signing/request-1',
  account_id: 'alice.testnet',
  authorization: scope.authorization,
  material_activation: scope.material_activation,
};

const prepareWithoutSigningWorker = {
  ...prepareRequest,
  // @ts-expect-error prepare scope requires a SigningWorker id.
  scope: missingSigningWorkerScope,
} satisfies RouterAbNormalSigningPrepareRequestV2Wire;
void prepareWithoutSigningWorker;

const stepUpWithWalletSession = {
  ...prepareRequest,
  scope: {
    ...scope,
    authorization: {
      kind: 'operation_step_up' as const,
      wallet_session_id: 'wallet-session-1',
    },
  },
};
// @ts-expect-error operation step-up authority cannot carry reusable Wallet Session identity.
const invalidStepUpRequest: RouterAbNormalSigningPrepareRequestV2Wire = stepUpWithWalletSession;
void invalidStepUpRequest;

const stepUpFinalizeWithReusableClaim = {
  ...finalizeRequest,
  scope: {
    ...scope,
    authorization: {
      kind: 'operation_step_up' as const,
    },
  },
};
// @ts-expect-error operation step-up finalize requests cannot carry reusable-session claims.
const invalidStepUpFinalize: RouterAbNormalSigningFinalizeRequestV2Wire =
  stepUpFinalizeWithReusableClaim;
void invalidStepUpFinalize;

const stepUpAuthorizationClaim = {
  kind: 'verified_step_up_authorized_operation_v1' as const,
  authorization_session_id: 'authorization-session-1',
  evidence_set_digest: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  authorized_operation_id: 'authorized-operation-2',
  operation_id: 'operation-1',
  capability_kind: 'near_ed25519_mpc_signing' as const,
  operation_kind: 'near.sign_transaction' as const,
  lane_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  intent_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  display_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  operation_fingerprint_digest: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
};

const validStepUpFinalize = {
  ...finalizeRequest,
  scope: stepUpFinalizeWithReusableClaim.scope,
  authorized_operation: stepUpAuthorizationClaim,
} satisfies RouterAbNormalSigningFinalizeRequestV2Wire;
void validStepUpFinalize;

const stepUpFinalizeWithoutClaim = {
  scope: validStepUpFinalize.scope,
  expires_at_ms: validStepUpFinalize.expires_at_ms,
  prepare_binding: validStepUpFinalize.prepare_binding,
  protocol: validStepUpFinalize.protocol,
};
// @ts-expect-error operation step-up finalize requires its exact authorized operation.
const invalidStepUpFinalizeWithoutClaim: RouterAbNormalSigningFinalizeRequestV2Wire =
  stepUpFinalizeWithoutClaim;
void invalidStepUpFinalizeWithoutClaim;

const ecdsaScope = {
  wallet_id: 'wallet-1',
  ecdsa_threshold_key_id: 'ecdsa-threshold-key-1',
  signing_root_id: 'signing-root-1',
  signing_root_version: 'v1',
  context: {
    application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  },
  public_identity: {
    context_binding_b64u: 'context-binding',
    derivation_client_share_public_key33_b64u: 'client-public-key',
    server_public_key33_b64u: 'server-public-key',
    threshold_public_key33_b64u: 'threshold-public-key',
    ethereum_address20_b64u: 'ethereum-address',
    client_share_retry_counter: 0,
    server_share_retry_counter: 0,
  },
  material_activation: {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: 'activation-1',
    capability: 'evm-ecdsa-capability-1',
    material_owner: 'wallet-1',
    key_binding: 'ecdsa-threshold-key-1',
    lifecycle_binding: 'lifecycle-1',
    signing_worker: 'signing-worker-a',
  },
  signing_worker: {
    server_id: 'signing-worker-a',
    key_epoch: 'epoch-1',
    recipient_encryption_key: 'recipient-key',
  },
  activation_epoch: rootShareEpoch,
};

const ecdsaFinalizeCoreRequest = {
  scope: ecdsaScope,
  request_id: 'ecdsa-request-1',
  operation_id: 'ecdsa-operation-1',
  operation_digests: {
    lane_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    intent_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    display_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  },
  authorization: {
    kind: 'reusable_wallet_session' as const,
    wallet_session_id: 'wallet-session-1',
  },
  material_activation: {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: 'activation-1',
    capability: 'evm-ecdsa-capability-1',
    material_owner: 'wallet-1',
    key_binding: 'ecdsa-threshold-key-1',
    lifecycle_binding: 'lifecycle-1',
    signing_worker: 'signing-worker-a',
  },
  expires_at_ms: 1_900_000_000_000,
  signing_digest_b64u: 'signing-digest',
  server_presignature_id: 'server-presignature-1',
  client_signature_share32_b64u: 'client-signature-share',
  client_rerandomization_contribution32_b64u: 'client-rerandomization-contribution',
} satisfies RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
void ecdsaFinalizeCoreRequest;

const ecdsaFinalizeRequest =
  ecdsaFinalizeCoreRequest satisfies RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire;
void ecdsaFinalizeRequest;
