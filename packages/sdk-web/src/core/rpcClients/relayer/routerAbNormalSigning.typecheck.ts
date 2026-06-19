import type {
  RouterAbNormalSigningFinalizeRequestV2Wire,
  RouterAbNormalSigningPrepareRequestV2Wire,
  RouterAbWalletSessionCredential,
} from './routerAbNormalSigning';

const scope = {
  request_id: 'router-ab-normal-signing/request-1',
  account_id: 'alice.testnet',
  session_id: 'wallet-session-1',
  signing_worker_id: 'signing-worker-a',
};

const digest32 = {
  bytes: Array.from({ length: 32 }, (_, index) => index),
};

const prepareRequest = {
  scope,
  expires_at_ms: 1_900_000_000_000,
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
  session_id: 'wallet-session-1',
};

const prepareWithoutSigningWorker = {
  ...prepareRequest,
  // @ts-expect-error prepare scope requires a SigningWorker id.
  scope: missingSigningWorkerScope,
} satisfies RouterAbNormalSigningPrepareRequestV2Wire;
void prepareWithoutSigningWorker;

const jwtCredential = {
  kind: 'jwt' as const,
  walletSessionJwt: 'wallet-session-jwt',
} satisfies RouterAbWalletSessionCredential;
void jwtCredential;

const cookieCredential: RouterAbWalletSessionCredential = {
  // @ts-expect-error Router A/B normal-signing credentials are bearer-only.
  kind: 'cookie',
  walletSessionJwt: 'wallet-session-jwt',
};
void cookieCredential;

// @ts-expect-error JWT Wallet Session credentials require walletSessionJwt.
const missingWalletSessionJwt: RouterAbWalletSessionCredential = { kind: 'jwt' };
void missingWalletSessionJwt;

const mixedWalletCredential: RouterAbWalletSessionCredential = {
  kind: 'jwt',
  walletSessionJwt: 'jwt',
  // @ts-expect-error Router A/B normal-signing credentials reject cookie flags.
  useWalletSessionCookie: true,
};
void mixedWalletCredential;
