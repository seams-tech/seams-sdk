import { alphabetizeStringify } from '@shared/utils/digests';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  routerAbEcdsaHssEvmDigestSigningFinalizeRequestDigestV1,
  routerAbEcdsaHssEvmDigestSigningRequestDigestV1,
  parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseForRequestV1,
  parseRouterAbEcdsaHssEvmDigestSigningResponseForRequestV1,
  type RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningResponseV1Wire,
} from '@shared/utils/routerAbEcdsaHss';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
} from '@/core/signingEngine/session/budget/budget';

const INTENT_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/intent/v2';
const PAYLOAD_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/payload/v2';
const NEP413_PREFIX = 2_147_484_061;

type RouterAbSigningErrorPayload = {
  code: string;
  message: string;
};

export type RouterAbWalletSessionCredential = {
  kind: 'jwt';
  walletSessionJwt: string;
};

export type RouterAbPublicDigest32Wire = {
  bytes: readonly number[];
};

export type RouterAbCanonicalWireBytesV1Wire = {
  bytes: readonly number[];
};

export type RouterAbNormalSigningScopeV1Wire = {
  request_id: string;
  account_id: string;
  session_id: string;
  signing_worker_id: string;
};

export type RouterAbNormalSigningCommitmentsV1Wire = {
  hiding: string;
  binding: string;
};

export type RouterAbServerIdentityV1Wire = {
  server_id: string;
  key_epoch: string;
  recipient_encryption_key: string;
};

export type RouterAbNearNetworkIdV2Wire = 'testnet' | 'mainnet';

export type RouterAbNearTransactionIntentV1Wire = {
  receiver_id: string;
  action_fingerprint: string;
};

export type RouterAbNearDelegateActionIntentV1Wire = {
  sender_id: string;
  receiver_id: string;
  public_key: string;
  nonce: string;
  max_block_height: string;
  action_fingerprint: string;
  canonical_delegate_borsh_b64u: string;
};

export type RouterAbEd25519NormalSigningIntentV2Wire =
  | {
      kind: 'near_transaction_v1';
      operation_id: string;
      operation_fingerprint: string;
      near_account_id: string;
      near_network_id: RouterAbNearNetworkIdV2Wire;
      transactions: readonly RouterAbNearTransactionIntentV1Wire[];
      unsigned_transaction_borsh_b64u: string;
    }
  | {
      kind: 'nep413_v1';
      operation_id: string;
      operation_fingerprint: string;
      near_account_id: string;
      near_network_id: RouterAbNearNetworkIdV2Wire;
      recipient: string;
      message: string;
      nonce_b64u: string;
      callback_url?: string;
    }
  | {
      kind: 'near_delegate_action_v1';
      operation_id: string;
      operation_fingerprint: string;
      near_account_id: string;
      near_network_id: RouterAbNearNetworkIdV2Wire;
      delegate: RouterAbNearDelegateActionIntentV1Wire;
    };

export type RouterAbEd25519SigningPayloadV2Wire =
  | {
      kind: 'near_unsigned_transaction_borsh_v1';
      unsigned_transaction_borsh_b64u: string;
      expected_signing_digest_b64u: string;
    }
  | {
      kind: 'nep413_message_v1';
      canonical_message_b64u: string;
      expected_signing_digest_b64u: string;
    }
  | {
      kind: 'near_delegate_action_v1';
      canonical_delegate_borsh_b64u: string;
      expected_signing_digest_b64u: string;
    };

export type RouterAbNormalSigningPrepareRequestV2Wire = {
  scope: RouterAbNormalSigningScopeV1Wire;
  expires_at_ms: number;
  intent: RouterAbEd25519NormalSigningIntentV2Wire;
  signing_payload: RouterAbEd25519SigningPayloadV2Wire;
};

export type RouterAbEd25519PresignPoolClientOfferV2Wire = {
  client_presign_id: string;
  client_nonce_handle: string;
  client_commitments: RouterAbNormalSigningCommitmentsV1Wire;
  client_verifying_share_b64u: string;
};

export type RouterAbEd25519PresignPoolPrepareRequestV2Wire = {
  scope: RouterAbNormalSigningScopeV1Wire;
  expires_at_ms: number;
  generation: number;
  client_offers: readonly RouterAbEd25519PresignPoolClientOfferV2Wire[];
};

export type RouterAbEd25519PresignPoolAcceptedEntryV2Wire = {
  client_presign_id: string;
  generation: number;
  pool_entry_binding_digest: RouterAbPublicDigest32Wire;
  signing_worker: RouterAbServerIdentityV1Wire;
  server_round1_handle: string;
  server_commitments: RouterAbNormalSigningCommitmentsV1Wire;
  server_verifying_share_b64u: string;
  signature_scheme: 'ed25519_v1';
  prepared_at_ms: number;
  expires_at_ms: number;
};

export type RouterAbEd25519PresignPoolPrepareResponseV2Wire = {
  scope: RouterAbNormalSigningScopeV1Wire;
  generation: number;
  accepted: readonly RouterAbEd25519PresignPoolAcceptedEntryV2Wire[];
  rejected_client_presign_ids: readonly string[];
};

export type RouterAbEd25519NormalSigningPrepareBindingV2Wire = {
  server_round1_handle: string;
  round1_binding_digest: RouterAbPublicDigest32Wire;
  intent_digest: RouterAbPublicDigest32Wire;
  signing_payload_digest: RouterAbPublicDigest32Wire;
};

export type RouterAbEd25519NormalSigningFinalizeProtocolV2Wire = {
  kind: 'ed25519_two_party_frost_finalize_v1';
  client_commitments: RouterAbNormalSigningCommitmentsV1Wire;
  server_commitments: RouterAbNormalSigningCommitmentsV1Wire;
  client_verifying_share_b64u: string;
  server_verifying_share_b64u: string;
  client_signature_share_b64u: string;
};

export type RouterAbNormalSigningFinalizeRequestV2Wire = {
  scope: RouterAbNormalSigningScopeV1Wire;
  expires_at_ms: number;
  budget_reservation_id: string;
  budget_operation_id: string;
  prepare_binding: RouterAbEd25519NormalSigningPrepareBindingV2Wire;
  protocol: RouterAbEd25519NormalSigningFinalizeProtocolV2Wire;
};

export type RouterAbEd25519PresignPoolHitBindingV2Wire = {
  client_presign_id: string;
  client_nonce_handle: string;
  generation: number;
  server_round1_handle: string;
  pool_entry_binding_digest: RouterAbPublicDigest32Wire;
};

export type RouterAbEd25519PresignPoolHitFinalizeRequestV2Wire = {
  scope: RouterAbNormalSigningScopeV1Wire;
  expires_at_ms: number;
  pool_binding: RouterAbEd25519PresignPoolHitBindingV2Wire;
  intent: RouterAbEd25519NormalSigningIntentV2Wire;
  signing_payload: RouterAbEd25519SigningPayloadV2Wire;
  protocol: RouterAbEd25519NormalSigningFinalizeProtocolV2Wire;
};

export type RouterAbNormalSigningBudgetStatusV1Wire = {
  committed_remaining_uses: number;
  reserved_uses: number;
  available_uses: number;
};

export type RouterAbNormalSigningPrepareResponseV1Wire = {
  scope: RouterAbNormalSigningScopeV1Wire;
  budget_reservation_id: string;
  budget_operation_id: string;
  budget_status: RouterAbNormalSigningBudgetStatusV1Wire;
  signing_payload_digest: RouterAbPublicDigest32Wire;
  round1_binding_digest: RouterAbPublicDigest32Wire;
  signing_worker: RouterAbServerIdentityV1Wire;
  server_round1_handle: string;
  server_commitments: RouterAbNormalSigningCommitmentsV1Wire;
  server_verifying_share_b64u: string;
  signature_scheme: 'ed25519_v1';
  prepared_at_ms: number;
  expires_at_ms: number;
};

export type RouterAbNormalSigningResponseV1Wire = {
  scope: RouterAbNormalSigningScopeV1Wire;
  signing_payload_digest: RouterAbPublicDigest32Wire;
  signing_worker: RouterAbServerIdentityV1Wire;
  signature_scheme: 'ed25519_v1';
  signature: RouterAbCanonicalWireBytesV1Wire;
  signed_at_ms: number;
};

export type RouterAbEd25519NormalSigningAdmissionMaterialV2Wire = {
  intentDigest: RouterAbPublicDigest32Wire;
  signingPayloadDigest: RouterAbPublicDigest32Wire;
  admittedSigningDigest: RouterAbPublicDigest32Wire;
};

export type RouterAbNormalSigningPrepareRequestV2BuildResult = {
  request: RouterAbNormalSigningPrepareRequestV2Wire;
  admissionMaterial: RouterAbEd25519NormalSigningAdmissionMaterialV2Wire;
};

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function requireNonNegativeInteger(value: unknown, label: string): number {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return parsed;
}

function requireByteArray(value: unknown, label: string, byteLength?: number): readonly number[] {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be a byte array`);
  }
  const bytes = value.map((entry) => Number(entry));
  if (!bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)) {
    throw new Error(`${label} must contain bytes`);
  }
  if (byteLength !== undefined && bytes.length !== byteLength) {
    throw new Error(`${label} must contain ${byteLength} bytes`);
  }
  return bytes;
}

function requireDigestB64u(value: unknown, label: string): string {
  const normalized = requireNonEmptyString(value, label);
  const bytes = base64UrlDecode(normalized);
  if (bytes.length !== 32) throw new Error(`${label} must decode to 32 bytes`);
  return normalized;
}

function requireBase64UrlNonEmpty(value: unknown, label: string): string {
  const normalized = requireNonEmptyString(value, label);
  if (base64UrlDecode(normalized).length === 0) {
    throw new Error(`${label} must decode to non-empty bytes`);
  }
  return normalized;
}

function normalizeNonceToB64u(value: string, label: string): string {
  const normalized = requireNonEmptyString(value, label);
  let bytes: Uint8Array;
  try {
    bytes = base64Decode(normalized);
  } catch {
    bytes = base64UrlDecode(normalized);
  }
  if (bytes.length !== 32) throw new Error(`${label} must decode to 32 bytes`);
  return base64UrlEncode(bytes);
}

export function routerAbDigest32Wire(bytes: Uint8Array): RouterAbPublicDigest32Wire {
  return { bytes: [...requireByteArray([...bytes], 'digest bytes', 32)] };
}

export function routerAbCanonicalWireBytesToB64u(
  value: RouterAbCanonicalWireBytesV1Wire,
  label: string,
): string {
  return base64UrlEncode(Uint8Array.from(requireByteArray(value.bytes, label)));
}

export async function routerAbNormalSigningActionFingerprint(value: unknown): Promise<string> {
  return base64UrlEncode(await sha256Bytes(new TextEncoder().encode(alphabetizeStringify(value))));
}

export function routerAbEd25519Nep413CanonicalMessageB64uV2(args: {
  message: string;
  recipient: string;
  nonce: string;
  callbackUrl?: string | null;
}): string {
  const message = requireNonEmptyString(args.message, 'nep413.message');
  const recipient = requireNonEmptyString(args.recipient, 'nep413.recipient');
  const nonce = base64UrlDecode(normalizeNonceToB64u(args.nonce, 'nep413.nonce'));
  const callbackUrl =
    args.callbackUrl == null ? undefined : requireNonEmptyString(args.callbackUrl, 'callbackUrl');
  const out: number[] = [];
  pushU32Le(out, NEP413_PREFIX);
  pushBorshString(out, message);
  pushBorshString(out, recipient);
  pushBytes(out, nonce);
  if (callbackUrl) {
    out.push(1);
    pushBorshString(out, callbackUrl);
  } else {
    out.push(0);
  }
  return base64UrlEncode(Uint8Array.from(out));
}

export async function buildRouterAbEd25519NearTransactionPrepareRequestV2(args: {
  scope: RouterAbNormalSigningScopeV1Wire;
  expiresAtMs: number;
  operationId: string;
  operationFingerprint: string;
  nearAccountId: string;
  nearNetworkId: RouterAbNearNetworkIdV2Wire;
  transactions: readonly {
    receiverId: string;
    actionFingerprint: string;
  }[];
  unsignedTransactionBorshB64u: string;
  expectedSigningDigestB64u: string;
}): Promise<RouterAbNormalSigningPrepareRequestV2BuildResult> {
  const request: RouterAbNormalSigningPrepareRequestV2Wire = {
    scope: parseScope(args.scope, 'scope'),
    expires_at_ms: requirePositiveInteger(args.expiresAtMs, 'expiresAtMs'),
    intent: {
      kind: 'near_transaction_v1',
      operation_id: requireNonEmptyString(args.operationId, 'operationId'),
      operation_fingerprint: requireNonEmptyString(
        args.operationFingerprint,
        'operationFingerprint',
      ),
      near_account_id: requireNonEmptyString(args.nearAccountId, 'nearAccountId'),
      near_network_id: args.nearNetworkId,
      transactions: args.transactions.map((transaction, index) => ({
        receiver_id: requireNonEmptyString(
          transaction.receiverId,
          `transactions[${index}].receiverId`,
        ),
        action_fingerprint: requireNonEmptyString(
          transaction.actionFingerprint,
          `transactions[${index}].actionFingerprint`,
        ),
      })),
      unsigned_transaction_borsh_b64u: requireBase64UrlNonEmpty(
        args.unsignedTransactionBorshB64u,
        'unsignedTransactionBorshB64u',
      ),
    },
    signing_payload: {
      kind: 'near_unsigned_transaction_borsh_v1',
      unsigned_transaction_borsh_b64u: requireBase64UrlNonEmpty(
        args.unsignedTransactionBorshB64u,
        'unsignedTransactionBorshB64u',
      ),
      expected_signing_digest_b64u: requireDigestB64u(
        args.expectedSigningDigestB64u,
        'expectedSigningDigestB64u',
      ),
    },
  };
  return {
    request,
    admissionMaterial: await deriveRouterAbNormalSigningAdmissionMaterialV2(request),
  };
}

export async function buildRouterAbEd25519Nep413PrepareRequestV2(args: {
  scope: RouterAbNormalSigningScopeV1Wire;
  expiresAtMs: number;
  operationId: string;
  operationFingerprint: string;
  nearAccountId: string;
  nearNetworkId: RouterAbNearNetworkIdV2Wire;
  message: string;
  recipient: string;
  nonce: string;
  callbackUrl?: string | null;
  expectedSigningDigestB64u: string;
}): Promise<RouterAbNormalSigningPrepareRequestV2BuildResult> {
  const nonceB64u = normalizeNonceToB64u(args.nonce, 'nonce');
  const callbackUrl =
    args.callbackUrl == null ? undefined : requireNonEmptyString(args.callbackUrl, 'callbackUrl');
  const canonicalMessageB64u = routerAbEd25519Nep413CanonicalMessageB64uV2({
    message: args.message,
    recipient: args.recipient,
    nonce: nonceB64u,
    ...(callbackUrl ? { callbackUrl } : {}),
  });
  const request: RouterAbNormalSigningPrepareRequestV2Wire = {
    scope: parseScope(args.scope, 'scope'),
    expires_at_ms: requirePositiveInteger(args.expiresAtMs, 'expiresAtMs'),
    intent: {
      kind: 'nep413_v1',
      operation_id: requireNonEmptyString(args.operationId, 'operationId'),
      operation_fingerprint: requireNonEmptyString(
        args.operationFingerprint,
        'operationFingerprint',
      ),
      near_account_id: requireNonEmptyString(args.nearAccountId, 'nearAccountId'),
      near_network_id: args.nearNetworkId,
      recipient: requireNonEmptyString(args.recipient, 'recipient'),
      message: requireNonEmptyString(args.message, 'message'),
      nonce_b64u: nonceB64u,
      ...(callbackUrl ? { callback_url: callbackUrl } : {}),
    },
    signing_payload: {
      kind: 'nep413_message_v1',
      canonical_message_b64u: canonicalMessageB64u,
      expected_signing_digest_b64u: requireDigestB64u(
        args.expectedSigningDigestB64u,
        'expectedSigningDigestB64u',
      ),
    },
  };
  return {
    request,
    admissionMaterial: await deriveRouterAbNormalSigningAdmissionMaterialV2(request),
  };
}

export async function buildRouterAbEd25519DelegateActionPrepareRequestV2(args: {
  scope: RouterAbNormalSigningScopeV1Wire;
  expiresAtMs: number;
  operationId: string;
  operationFingerprint: string;
  nearAccountId: string;
  nearNetworkId: RouterAbNearNetworkIdV2Wire;
  delegate: {
    senderId: string;
    receiverId: string;
    publicKey: string;
    nonce: string;
    maxBlockHeight: string;
    actionFingerprint: string;
    canonicalDelegateBorshB64u: string;
  };
  expectedSigningDigestB64u: string;
}): Promise<RouterAbNormalSigningPrepareRequestV2BuildResult> {
  const canonicalDelegateBorshB64u = requireBase64UrlNonEmpty(
    args.delegate.canonicalDelegateBorshB64u,
    'canonicalDelegateBorshB64u',
  );
  const request: RouterAbNormalSigningPrepareRequestV2Wire = {
    scope: parseScope(args.scope, 'scope'),
    expires_at_ms: requirePositiveInteger(args.expiresAtMs, 'expiresAtMs'),
    intent: {
      kind: 'near_delegate_action_v1',
      operation_id: requireNonEmptyString(args.operationId, 'operationId'),
      operation_fingerprint: requireNonEmptyString(
        args.operationFingerprint,
        'operationFingerprint',
      ),
      near_account_id: requireNonEmptyString(args.nearAccountId, 'nearAccountId'),
      near_network_id: args.nearNetworkId,
      delegate: {
        sender_id: requireNonEmptyString(args.delegate.senderId, 'delegate.senderId'),
        receiver_id: requireNonEmptyString(args.delegate.receiverId, 'delegate.receiverId'),
        public_key: requireNonEmptyString(args.delegate.publicKey, 'delegate.publicKey'),
        nonce: requireNonEmptyString(args.delegate.nonce, 'delegate.nonce'),
        max_block_height: requireNonEmptyString(
          args.delegate.maxBlockHeight,
          'delegate.maxBlockHeight',
        ),
        action_fingerprint: requireNonEmptyString(
          args.delegate.actionFingerprint,
          'delegate.actionFingerprint',
        ),
        canonical_delegate_borsh_b64u: canonicalDelegateBorshB64u,
      },
    },
    signing_payload: {
      kind: 'near_delegate_action_v1',
      canonical_delegate_borsh_b64u: canonicalDelegateBorshB64u,
      expected_signing_digest_b64u: requireDigestB64u(
        args.expectedSigningDigestB64u,
        'expectedSigningDigestB64u',
      ),
    },
  };
  return {
    request,
    admissionMaterial: await deriveRouterAbNormalSigningAdmissionMaterialV2(request),
  };
}

export function buildRouterAbEd25519PresignPoolPrepareRequestV2(args: {
  scope: RouterAbNormalSigningScopeV1Wire;
  expiresAtMs: number;
  generation: number;
  clientOffers: readonly {
    clientPresignId: string;
    clientNonceHandle: string;
    clientCommitments: RouterAbNormalSigningCommitmentsV1Wire;
    clientVerifyingShareB64u: string;
  }[];
}): RouterAbEd25519PresignPoolPrepareRequestV2Wire {
  return {
    scope: parseScope(args.scope, 'scope'),
    expires_at_ms: requirePositiveInteger(args.expiresAtMs, 'expiresAtMs'),
    generation: requirePositiveInteger(args.generation, 'generation'),
    client_offers: args.clientOffers.map((offer, index) => ({
      client_presign_id: requireNonEmptyString(
        offer.clientPresignId,
        `clientOffers[${index}].clientPresignId`,
      ),
      client_nonce_handle: requireNonEmptyString(
        offer.clientNonceHandle,
        `clientOffers[${index}].clientNonceHandle`,
      ),
      client_commitments: parseCommitments(
        offer.clientCommitments,
        `clientOffers[${index}].clientCommitments`,
      ),
      client_verifying_share_b64u: requireNonEmptyString(
        offer.clientVerifyingShareB64u,
        `clientOffers[${index}].clientVerifyingShareB64u`,
      ),
    })),
  };
}

export function buildRouterAbEd25519NormalSigningFinalizeRequestV2(args: {
  scope: RouterAbNormalSigningScopeV1Wire;
  expiresAtMs: number;
  prepareResponse: RouterAbNormalSigningPrepareResponseV1Wire;
  admissionMaterial: RouterAbEd25519NormalSigningAdmissionMaterialV2Wire;
  clientCommitments: RouterAbNormalSigningCommitmentsV1Wire;
  clientVerifyingShareB64u: string;
  clientSignatureShareB64u: string;
}): RouterAbNormalSigningFinalizeRequestV2Wire {
  return {
    scope: parseScope(args.scope, 'scope'),
    expires_at_ms: requirePositiveInteger(args.expiresAtMs, 'expiresAtMs'),
    budget_reservation_id: requireNonEmptyString(
      args.prepareResponse.budget_reservation_id,
      'budget_reservation_id',
    ),
    budget_operation_id: requireNonEmptyString(
      args.prepareResponse.budget_operation_id,
      'budget_operation_id',
    ),
    prepare_binding: {
      server_round1_handle: requireNonEmptyString(
        args.prepareResponse.server_round1_handle,
        'server_round1_handle',
      ),
      round1_binding_digest: parseDigest32(
        args.prepareResponse.round1_binding_digest,
        'round1_binding_digest',
      ),
      intent_digest: parseDigest32(args.admissionMaterial.intentDigest, 'intent_digest'),
      signing_payload_digest: parseDigest32(
        args.admissionMaterial.signingPayloadDigest,
        'signing_payload_digest',
      ),
    },
    protocol: {
      kind: 'ed25519_two_party_frost_finalize_v1',
      client_commitments: parseCommitments(args.clientCommitments, 'clientCommitments'),
      server_commitments: parseCommitments(
        args.prepareResponse.server_commitments,
        'serverCommitments',
      ),
      client_verifying_share_b64u: requireNonEmptyString(
        args.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      server_verifying_share_b64u: requireNonEmptyString(
        args.prepareResponse.server_verifying_share_b64u,
        'serverVerifyingShareB64u',
      ),
      client_signature_share_b64u: requireNonEmptyString(
        args.clientSignatureShareB64u,
        'clientSignatureShareB64u',
      ),
    },
  };
}

export function buildRouterAbEd25519PresignPoolHitFinalizeRequestV2(args: {
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
  clientPresignId: string;
  clientNonceHandle: string;
  generation: number;
  serverRound1Handle: string;
  poolEntryBindingDigest: RouterAbPublicDigest32Wire;
  clientCommitments: RouterAbNormalSigningCommitmentsV1Wire;
  serverCommitments: RouterAbNormalSigningCommitmentsV1Wire;
  clientVerifyingShareB64u: string;
  serverVerifyingShareB64u: string;
  clientSignatureShareB64u: string;
}): RouterAbEd25519PresignPoolHitFinalizeRequestV2Wire {
  return {
    scope: parseScope(args.prepare.request.scope, 'scope'),
    expires_at_ms: requirePositiveInteger(args.prepare.request.expires_at_ms, 'expiresAtMs'),
    pool_binding: {
      client_presign_id: requireNonEmptyString(args.clientPresignId, 'clientPresignId'),
      client_nonce_handle: requireNonEmptyString(args.clientNonceHandle, 'clientNonceHandle'),
      generation: requirePositiveInteger(args.generation, 'generation'),
      server_round1_handle: requireNonEmptyString(args.serverRound1Handle, 'serverRound1Handle'),
      pool_entry_binding_digest: parseDigest32(
        args.poolEntryBindingDigest,
        'poolEntryBindingDigest',
      ),
    },
    intent: args.prepare.request.intent,
    signing_payload: args.prepare.request.signing_payload,
    protocol: {
      kind: 'ed25519_two_party_frost_finalize_v1',
      client_commitments: parseCommitments(args.clientCommitments, 'clientCommitments'),
      server_commitments: parseCommitments(args.serverCommitments, 'serverCommitments'),
      client_verifying_share_b64u: requireNonEmptyString(
        args.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      server_verifying_share_b64u: requireNonEmptyString(
        args.serverVerifyingShareB64u,
        'serverVerifyingShareB64u',
      ),
      client_signature_share_b64u: requireNonEmptyString(
        args.clientSignatureShareB64u,
        'clientSignatureShareB64u',
      ),
    },
  };
}

export async function deriveRouterAbNormalSigningAdmissionMaterialV2(
  request: RouterAbNormalSigningPrepareRequestV2Wire,
): Promise<RouterAbEd25519NormalSigningAdmissionMaterialV2Wire> {
  const intentDigest = routerAbDigest32Wire(
    await sha256Bytes(canonicalIntentBytes(request.intent)),
  );
  const signingPayloadDigest = routerAbDigest32Wire(
    await sha256Bytes(canonicalSigningPayloadBytes(request.signing_payload)),
  );
  const admittedSigningDigest = routerAbDigest32Wire(
    await sha256Bytes(signingPayloadPreimageBytes(request.signing_payload)),
  );
  const expected = base64UrlDecode(expectedSigningDigestB64u(request.signing_payload));
  if (!sameBytes(admittedSigningDigest.bytes, expected)) {
    throw new Error('Router A/B normal-signing expected signing digest drift');
  }
  return { intentDigest, signingPayloadDigest, admittedSigningDigest };
}

function parseScope(value: unknown, label: string): RouterAbNormalSigningScopeV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  return {
    request_id: requireNonEmptyString(record.request_id, `${label}.request_id`),
    account_id: requireNonEmptyString(record.account_id, `${label}.account_id`),
    session_id: requireNonEmptyString(record.session_id, `${label}.session_id`),
    signing_worker_id: requireNonEmptyString(
      record.signing_worker_id,
      `${label}.signing_worker_id`,
    ),
  };
}

function parseDigest32(value: unknown, label: string): RouterAbPublicDigest32Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  return { bytes: requireByteArray(record.bytes, `${label}.bytes`, 32) };
}

function parseCanonicalWireBytes(value: unknown, label: string): RouterAbCanonicalWireBytesV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  const bytes = requireByteArray(record.bytes, `${label}.bytes`);
  if (bytes.length === 0) throw new Error(`${label}.bytes must be non-empty`);
  return { bytes };
}

function parseCommitments(value: unknown, label: string): RouterAbNormalSigningCommitmentsV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  return {
    hiding: requireNonEmptyString(record.hiding, `${label}.hiding`),
    binding: requireNonEmptyString(record.binding, `${label}.binding`),
  };
}

function parseServerIdentity(value: unknown, label: string): RouterAbServerIdentityV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  return {
    server_id: requireNonEmptyString(record.server_id, `${label}.server_id`),
    key_epoch: requireNonEmptyString(record.key_epoch, `${label}.key_epoch`),
    recipient_encryption_key: requireNonEmptyString(
      record.recipient_encryption_key,
      `${label}.recipient_encryption_key`,
    ),
  };
}

function parseBudgetStatus(value: unknown, label: string): RouterAbNormalSigningBudgetStatusV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  return {
    committed_remaining_uses: requireNonNegativeInteger(
      record.committed_remaining_uses,
      `${label}.committed_remaining_uses`,
    ),
    reserved_uses: requireNonNegativeInteger(record.reserved_uses, `${label}.reserved_uses`),
    available_uses: requireNonNegativeInteger(record.available_uses, `${label}.available_uses`),
  };
}

function parsePrepareResponse(value: unknown): RouterAbNormalSigningPrepareResponseV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error('Router A/B normal-signing prepare response must be an object');
  const signatureScheme = requireNonEmptyString(record.signature_scheme, 'signature_scheme');
  if (signatureScheme !== 'ed25519_v1') {
    throw new Error(`Unsupported Router A/B normal-signing signature scheme: ${signatureScheme}`);
  }
  return {
    scope: parseScope(record.scope, 'scope'),
    budget_reservation_id: requireNonEmptyString(
      record.budget_reservation_id,
      'budget_reservation_id',
    ),
    budget_operation_id: requireNonEmptyString(
      record.budget_operation_id,
      'budget_operation_id',
    ),
    budget_status: parseBudgetStatus(record.budget_status, 'budget_status'),
    signing_payload_digest: parseDigest32(record.signing_payload_digest, 'signing_payload_digest'),
    round1_binding_digest: parseDigest32(record.round1_binding_digest, 'round1_binding_digest'),
    signing_worker: parseServerIdentity(record.signing_worker, 'signing_worker'),
    server_round1_handle: requireNonEmptyString(
      record.server_round1_handle,
      'server_round1_handle',
    ),
    server_commitments: parseCommitments(record.server_commitments, 'server_commitments'),
    server_verifying_share_b64u: requireNonEmptyString(
      record.server_verifying_share_b64u,
      'server_verifying_share_b64u',
    ),
    signature_scheme: 'ed25519_v1',
    prepared_at_ms: requirePositiveInteger(record.prepared_at_ms, 'prepared_at_ms'),
    expires_at_ms: requirePositiveInteger(record.expires_at_ms, 'expires_at_ms'),
  };
}

function parsePresignPoolAcceptedEntry(
  value: unknown,
  label: string,
): RouterAbEd25519PresignPoolAcceptedEntryV2Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  const signatureScheme = requireNonEmptyString(
    record.signature_scheme,
    `${label}.signature_scheme`,
  );
  if (signatureScheme !== 'ed25519_v1') {
    throw new Error(`Unsupported Router A/B presign-pool signature scheme: ${signatureScheme}`);
  }
  return {
    client_presign_id: requireNonEmptyString(
      record.client_presign_id,
      `${label}.client_presign_id`,
    ),
    generation: requirePositiveInteger(record.generation, `${label}.generation`),
    pool_entry_binding_digest: parseDigest32(
      record.pool_entry_binding_digest,
      `${label}.pool_entry_binding_digest`,
    ),
    signing_worker: parseServerIdentity(record.signing_worker, `${label}.signing_worker`),
    server_round1_handle: requireNonEmptyString(
      record.server_round1_handle,
      `${label}.server_round1_handle`,
    ),
    server_commitments: parseCommitments(record.server_commitments, `${label}.server_commitments`),
    server_verifying_share_b64u: requireNonEmptyString(
      record.server_verifying_share_b64u,
      `${label}.server_verifying_share_b64u`,
    ),
    signature_scheme: 'ed25519_v1',
    prepared_at_ms: requirePositiveInteger(record.prepared_at_ms, `${label}.prepared_at_ms`),
    expires_at_ms: requirePositiveInteger(record.expires_at_ms, `${label}.expires_at_ms`),
  };
}

function parsePresignPoolPrepareResponse(
  value: unknown,
): RouterAbEd25519PresignPoolPrepareResponseV2Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) {
    throw new Error('Router A/B normal-signing presign-pool response must be an object');
  }
  const accepted = Array.isArray(record.accepted) ? record.accepted : [];
  const rejected = Array.isArray(record.rejected_client_presign_ids)
    ? record.rejected_client_presign_ids
    : [];
  return {
    scope: parseScope(record.scope, 'scope'),
    generation: requirePositiveInteger(record.generation, 'generation'),
    accepted: accepted.map((entry, index) =>
      parsePresignPoolAcceptedEntry(entry, `accepted[${index}]`),
    ),
    rejected_client_presign_ids: rejected.map((entry, index) =>
      requireNonEmptyString(entry, `rejected_client_presign_ids[${index}]`),
    ),
  };
}

function sameScope(
  left: RouterAbNormalSigningScopeV1Wire,
  right: RouterAbNormalSigningScopeV1Wire,
): boolean {
  return (
    left.request_id === right.request_id &&
    left.account_id === right.account_id &&
    left.session_id === right.session_id &&
    left.signing_worker_id === right.signing_worker_id
  );
}

function requirePresignPoolResponseMatchesRequest(args: {
  request: RouterAbEd25519PresignPoolPrepareRequestV2Wire;
  response: RouterAbEd25519PresignPoolPrepareResponseV2Wire;
}): void {
  if (!sameScope(args.response.scope, args.request.scope)) {
    throw new Error('Router A/B presign-pool response scope does not match request');
  }
  if (args.response.generation !== args.request.generation) {
    throw new Error('Router A/B presign-pool response generation does not match request');
  }

  const offeredIds = new Set<string>();
  args.request.client_offers.forEach((offer, index) => {
    if (offeredIds.has(offer.client_presign_id)) {
      throw new Error(`request.client_offers[${index}].client_presign_id is duplicated`);
    }
    offeredIds.add(offer.client_presign_id);
  });

  const acceptedIds = new Set<string>();
  args.response.accepted.forEach((entry, index) => {
    if (entry.generation !== args.request.generation) {
      throw new Error(`accepted[${index}].generation does not match request`);
    }
    if (!offeredIds.has(entry.client_presign_id)) {
      throw new Error(`accepted[${index}].client_presign_id is not in request.client_offers`);
    }
    if (acceptedIds.has(entry.client_presign_id)) {
      throw new Error(`accepted[${index}].client_presign_id is duplicated`);
    }
    acceptedIds.add(entry.client_presign_id);
  });

  const rejectedIds = new Set<string>();
  args.response.rejected_client_presign_ids.forEach((clientPresignId, index) => {
    if (!offeredIds.has(clientPresignId)) {
      throw new Error(
        `rejected_client_presign_ids[${index}] is not in request.client_offers`,
      );
    }
    if (acceptedIds.has(clientPresignId)) {
      throw new Error(`rejected_client_presign_ids[${index}] was already accepted`);
    }
    if (rejectedIds.has(clientPresignId)) {
      throw new Error(`rejected_client_presign_ids[${index}] is duplicated`);
    }
    rejectedIds.add(clientPresignId);
  });
}

function parsePresignPoolPrepareResponseForRequest(
  request: RouterAbEd25519PresignPoolPrepareRequestV2Wire,
  value: unknown,
): RouterAbEd25519PresignPoolPrepareResponseV2Wire {
  const response = parsePresignPoolPrepareResponse(value);
  requirePresignPoolResponseMatchesRequest({ request, response });
  return response;
}

function parseNormalSigningResponse(value: unknown): RouterAbNormalSigningResponseV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error('Router A/B normal-signing response must be an object');
  const signatureScheme = requireNonEmptyString(record.signature_scheme, 'signature_scheme');
  if (signatureScheme !== 'ed25519_v1') {
    throw new Error(`Unsupported Router A/B normal-signing signature scheme: ${signatureScheme}`);
  }
  return {
    scope: parseScope(record.scope, 'scope'),
    signing_payload_digest: parseDigest32(record.signing_payload_digest, 'signing_payload_digest'),
    signing_worker: parseServerIdentity(record.signing_worker, 'signing_worker'),
    signature_scheme: 'ed25519_v1',
    signature: parseCanonicalWireBytes(record.signature, 'signature'),
    signed_at_ms: requirePositiveInteger(record.signed_at_ms, 'signed_at_ms'),
  };
}

function buildRouterAbRequestInit(args: {
  credential: RouterAbWalletSessionCredential;
  body: unknown;
}): RequestInit {
  return buildRelayerJsonPostRequestInit({
    headers: buildBearerAuthorizationHeader({
      token: args.credential.walletSessionJwt,
      missingMessage: 'walletSessionJwt is required',
    }),
    body: args.body,
  });
}

function parseRouterAbSigningErrorPayload(bodyText: string): RouterAbSigningErrorPayload | null {
  if (!bodyText.trim()) return null;
  try {
    const parsed = JSON.parse(bodyText) as unknown;
    const record = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
    if (!record) return null;
    const code = String(record.code || '').trim();
    const message = String(record.message || '').trim();
    if (!code) return null;
    return { code, message };
  } catch {
    return null;
  }
}

function routerAbSigningBudgetErrorPrefix(code: string): string | null {
  switch (code) {
    case 'wallet_budget_exhausted':
      return SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR;
    case 'wallet_budget_in_flight':
    case 'wallet_budget_reserved':
      return SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR;
    default:
      return null;
  }
}

function routerAbSigningHttpError(args: {
  path: string;
  status: number;
  bodyText: string;
}): Error {
  const payload = parseRouterAbSigningErrorPayload(args.bodyText);
  const budgetPrefix = payload ? routerAbSigningBudgetErrorPrefix(payload.code) : null;
  if (payload && budgetPrefix) {
    const detail = payload.message || payload.code;
    return new Error(
      `${budgetPrefix}: Router A/B signing ${args.path} returned HTTP ${args.status}: ${detail}`,
    );
  }
  return new Error(
    `Router A/B signing ${args.path} returned HTTP ${args.status}${
      args.bodyText ? `: ${args.bodyText}` : ''
    }`,
  );
}

async function postRouterAbNormalSigningJson<T>(args: {
  relayServerUrl: string;
  path:
    | '/v2/router-ab/ed25519/sign/prepare'
    | '/v2/router-ab/ed25519/sign/presign-pool/prepare'
    | '/v2/router-ab/ed25519/sign'
    | '/v1/hss/ecdsa/sign/prepare'
    | '/v1/hss/ecdsa/sign';
  credential: RouterAbWalletSessionCredential;
  body: unknown;
  parse: (value: unknown) => T | Promise<T>;
}): Promise<T> {
  if (typeof fetch !== 'function') {
    throw new Error('fetch is not available for Router A/B normal-signing request');
  }
  const base = normalizeRelayerBaseUrl(requireNonEmptyString(args.relayServerUrl, 'relayServerUrl'));
  const response = await fetch(
    `${base}${args.path}`,
    buildRouterAbRequestInit({ credential: args.credential, body: args.body }),
  );
  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw routerAbSigningHttpError({
      path: args.path,
      status: response.status,
      bodyText: errorText,
    });
  }
  return args.parse(await response.json());
}

export async function prepareRouterAbNormalSigningV2(args: {
  relayServerUrl: string;
  credential: RouterAbWalletSessionCredential;
  request: RouterAbNormalSigningPrepareRequestV2Wire;
}): Promise<RouterAbNormalSigningPrepareResponseV1Wire> {
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/v2/router-ab/ed25519/sign/prepare',
    credential: args.credential,
    body: args.request,
    parse: parsePrepareResponse,
  });
}

export async function prepareRouterAbEcdsaHssEvmDigestSigningV1(args: {
  relayServerUrl: string;
  credential: RouterAbWalletSessionCredential;
  request: RouterAbEcdsaHssEvmDigestSigningRequestV1Wire;
}): Promise<RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1Wire> {
  await routerAbEcdsaHssEvmDigestSigningRequestDigestV1(args.request);
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/v1/hss/ecdsa/sign/prepare',
    credential: args.credential,
    body: args.request,
    parse: (value) =>
      parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseForRequestV1(args.request, value),
  });
}

export async function prepareRouterAbNormalSigningPresignPoolV2(args: {
  relayServerUrl: string;
  credential: RouterAbWalletSessionCredential;
  request: RouterAbEd25519PresignPoolPrepareRequestV2Wire;
}): Promise<RouterAbEd25519PresignPoolPrepareResponseV2Wire> {
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/v2/router-ab/ed25519/sign/presign-pool/prepare',
    credential: args.credential,
    body: args.request,
    parse: (value) => parsePresignPoolPrepareResponseForRequest(args.request, value),
  });
}

export async function finalizeRouterAbNormalSigningV2(args: {
  relayServerUrl: string;
  credential: RouterAbWalletSessionCredential;
  request: RouterAbNormalSigningFinalizeRequestV2Wire;
}): Promise<RouterAbNormalSigningResponseV1Wire> {
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/v2/router-ab/ed25519/sign',
    credential: args.credential,
    body: args.request,
    parse: parseNormalSigningResponse,
  });
}

export async function finalizeRouterAbEcdsaHssEvmDigestSigningV1(args: {
  relayServerUrl: string;
  credential: RouterAbWalletSessionCredential;
  request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1Wire;
}): Promise<RouterAbEcdsaHssEvmDigestSigningResponseV1Wire> {
  await routerAbEcdsaHssEvmDigestSigningFinalizeRequestDigestV1(args.request);
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/v1/hss/ecdsa/sign',
    credential: args.credential,
    body: args.request,
    parse: (value) =>
      parseRouterAbEcdsaHssEvmDigestSigningResponseForRequestV1(args.request, value),
  });
}

export async function finalizeRouterAbNormalSigningPresignPoolHitV2(args: {
  relayServerUrl: string;
  credential: RouterAbWalletSessionCredential;
  request: RouterAbEd25519PresignPoolHitFinalizeRequestV2Wire;
}): Promise<RouterAbNormalSigningResponseV1Wire> {
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/v2/router-ab/ed25519/sign',
    credential: args.credential,
    body: args.request,
    parse: parseNormalSigningResponse,
  });
}

function canonicalIntentBytes(intent: RouterAbEd25519NormalSigningIntentV2Wire): Uint8Array {
  const out: number[] = [];
  pushLen32(out, textBytes(INTENT_VERSION_V2));
  switch (intent.kind) {
    case 'near_transaction_v1':
      pushLen32(out, textBytes('near_transaction_v1'));
      pushIntentCommon(out, intent);
      pushU32Be(out, intent.transactions.length);
      for (const transaction of intent.transactions) {
        pushLen32(out, textBytes(transaction.receiver_id));
        pushLen32(out, textBytes(transaction.action_fingerprint));
      }
      pushLen32(out, textBytes(intent.unsigned_transaction_borsh_b64u));
      return Uint8Array.from(out);
    case 'nep413_v1':
      pushLen32(out, textBytes('nep413_v1'));
      pushIntentCommon(out, intent);
      pushLen32(out, textBytes(intent.recipient));
      pushLen32(out, textBytes(intent.message));
      pushLen32(out, textBytes(intent.nonce_b64u));
      pushOptionalString(out, intent.callback_url);
      return Uint8Array.from(out);
    case 'near_delegate_action_v1':
      pushLen32(out, textBytes('near_delegate_action_v1'));
      pushIntentCommon(out, intent);
      pushLen32(out, textBytes(intent.delegate.sender_id));
      pushLen32(out, textBytes(intent.delegate.receiver_id));
      pushLen32(out, textBytes(intent.delegate.public_key));
      pushLen32(out, textBytes(intent.delegate.nonce));
      pushLen32(out, textBytes(intent.delegate.max_block_height));
      pushLen32(out, textBytes(intent.delegate.action_fingerprint));
      pushLen32(out, textBytes(intent.delegate.canonical_delegate_borsh_b64u));
      return Uint8Array.from(out);
  }
}

function canonicalSigningPayloadBytes(payload: RouterAbEd25519SigningPayloadV2Wire): Uint8Array {
  const out: number[] = [];
  pushLen32(out, textBytes(PAYLOAD_VERSION_V2));
  switch (payload.kind) {
    case 'near_unsigned_transaction_borsh_v1':
      pushLen32(out, textBytes('near_unsigned_transaction_borsh_v1'));
      pushLen32(out, textBytes(payload.unsigned_transaction_borsh_b64u));
      pushLen32(out, textBytes(payload.expected_signing_digest_b64u));
      return Uint8Array.from(out);
    case 'nep413_message_v1':
      pushLen32(out, textBytes('nep413_message_v1'));
      pushLen32(out, textBytes(payload.canonical_message_b64u));
      pushLen32(out, textBytes(payload.expected_signing_digest_b64u));
      return Uint8Array.from(out);
    case 'near_delegate_action_v1':
      pushLen32(out, textBytes('near_delegate_action_v1'));
      pushLen32(out, textBytes(payload.canonical_delegate_borsh_b64u));
      pushLen32(out, textBytes(payload.expected_signing_digest_b64u));
      return Uint8Array.from(out);
  }
}

function signingPayloadPreimageBytes(payload: RouterAbEd25519SigningPayloadV2Wire): Uint8Array {
  switch (payload.kind) {
    case 'near_unsigned_transaction_borsh_v1':
      return base64UrlDecode(payload.unsigned_transaction_borsh_b64u);
    case 'nep413_message_v1':
      return base64UrlDecode(payload.canonical_message_b64u);
    case 'near_delegate_action_v1':
      return base64UrlDecode(payload.canonical_delegate_borsh_b64u);
  }
}

function expectedSigningDigestB64u(payload: RouterAbEd25519SigningPayloadV2Wire): string {
  switch (payload.kind) {
    case 'near_unsigned_transaction_borsh_v1':
    case 'nep413_message_v1':
    case 'near_delegate_action_v1':
      return payload.expected_signing_digest_b64u;
  }
}

function pushIntentCommon(
  out: number[],
  intent: {
    operation_id: string;
    operation_fingerprint: string;
    near_account_id: string;
    near_network_id: RouterAbNearNetworkIdV2Wire;
  },
): void {
  pushLen32(out, textBytes(intent.operation_id));
  pushLen32(out, textBytes(intent.operation_fingerprint));
  pushLen32(out, textBytes(intent.near_account_id));
  pushLen32(out, textBytes(intent.near_network_id));
}

function pushOptionalString(out: number[], value: string | undefined): void {
  if (value) {
    out.push(1);
    pushLen32(out, textBytes(value));
  } else {
    out.push(0);
  }
}

function pushBorshString(out: number[], value: string): void {
  const bytes = textBytes(value);
  pushU32Le(out, bytes.length);
  pushBytes(out, bytes);
}

function pushLen32(out: number[], bytes: Uint8Array): void {
  pushU32Be(out, bytes.length);
  pushBytes(out, bytes);
}

function pushBytes(out: number[], bytes: Uint8Array): void {
  for (const byte of bytes) out.push(byte);
}

function pushU32Be(out: number[], value: number): void {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function pushU32Le(out: number[], value: number): void {
  out.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('Web Crypto SHA-256 is unavailable for Router A/B normal signing');
  const bytes = new Uint8Array(input.length);
  bytes.set(input);
  return new Uint8Array(await subtle.digest('SHA-256', bytes.buffer));
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function sameBytes(left: readonly number[], right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
