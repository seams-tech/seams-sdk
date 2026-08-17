import { alphabetizeStringify } from '@shared/utils/digests';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningResponseForCoreRequestV1,
  parseRouterAbEcdsaOperationStepUpPreparationV1,
  type RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire,
  type RouterAbOwnerOperationAuthorizationDecisionV1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire,
  RouterAbEd25519OperationStepUpPreparationV1Wire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import { WalletSessionQuotaAdmissionError } from '@/core/signingEngine/session/operationState/authorizationAdmission';
import { walletSessionFailureErrorFromPayload } from '@/core/signingEngine/session/lifecycle/walletSessionFailure';
import {
  parseRouterAbMpcMaterialActivationRef,
  parseRouterAbNormalSigningAuthorization,
  type RouterAbMpcMaterialActivationRefWire,
  type RouterAbNormalSigningAuthorizationWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type { LinkedDeviceWalletSessionCredential } from '@/core/signingEngine/session/lanes/linkedDeviceWalletSessionCredential';
import {
  isLinkedDeviceWalletSessionCredential,
  linkedDeviceWalletSessionBearer,
} from '@/core/signingEngine/session/lanes/linkedDeviceWalletSessionCredential';

const INTENT_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/intent/v2';
const PAYLOAD_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/payload/v2';
const NEP413_PREFIX = 2_147_484_061;

type RouterAbSigningErrorPayload = {
  code: string;
  message: string;
  authorizationDecision?:
    | RouterAbOwnerOperationAuthorizationDecisionV1Wire
    | RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire;
};

export function routerAbNormalSigningAdmissionErrorFromPayload(args: {
  code: string;
  message: string;
  path: string;
  status: number;
  authorizationDecision?:
    | RouterAbOwnerOperationAuthorizationDecisionV1Wire
    | RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire;
}): WalletSessionQuotaAdmissionError | null {
  const code = String(args.code || '').trim();
  const detail = `Router A/B signing ${args.path} returned HTTP ${args.status}: ${
    args.message || code || 'unknown admission failure'
  }`;
  if (args.authorizationDecision?.kind === 'step_up_required') {
    return new WalletSessionQuotaAdmissionError(
      {
        kind: 'exhausted',
        source: 'server_prepare',
        detail,
      },
      args.authorizationDecision,
    );
  }
  switch (code) {
    case 'wallet_budget_exhausted':
      return new WalletSessionQuotaAdmissionError({
        kind: 'exhausted',
        source: 'server_prepare',
        detail,
      }, args.authorizationDecision);
    case 'wallet_budget_in_flight':
    case 'wallet_budget_reserved':
      return new WalletSessionQuotaAdmissionError({
        kind: 'in_flight',
        source: 'server_prepare',
        detail,
        retryAfterMs: 150,
      });
    default:
      return null;
  }
}

export type RouterAbOpaqueWalletSessionCredential = {
  kind: 'wallet_session_opaque';
  walletSessionToken: string;
};

export type RouterAbWalletSessionCredential =
  | RouterAbOpaqueWalletSessionCredential
  | LinkedDeviceWalletSessionCredential;

export type RouterAbEd25519NormalSigningCredential =
  | RouterAbWalletSessionCredential
  | {
      kind: 'operation_step_up';
    };

export type RouterAbOwnerNormalSigningCredential =
  | RouterAbOpaqueWalletSessionCredential
  | { kind: 'operation_step_up' };

export type RouterAbPublicDigest32Wire = {
  bytes: readonly number[];
};

export type RouterAbCanonicalWireBytesV1Wire = {
  bytes: readonly number[];
};

export type RouterAbNormalSigningScopeV2Wire = {
  request_id: string;
  account_id: string;
  authorization: RouterAbNormalSigningAuthorizationWire;
  material_activation: RouterAbMpcMaterialActivationRefWire;
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
  scope: RouterAbNormalSigningScopeV2Wire;
  expires_at_ms: number;
  display_digest: RouterAbPublicDigest32Wire;
  intent: RouterAbEd25519NormalSigningIntentV2Wire;
  signing_payload: RouterAbEd25519SigningPayloadV2Wire;
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

export type RouterAbReusableWalletSessionAuthorizedOperationV1Wire = {
  kind: 'reusable_wallet_session_authorized_operation_v1';
  authorized_operation_id: string;
  operation_id: string;
  capability_kind: 'near_ed25519_mpc_signing';
  operation_kind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
  lane_digest_b64u: string;
  intent_digest_b64u: string;
  display_digest_b64u: string;
  operation_fingerprint_digest: string;
};

export type RouterAbVerifiedStepUpAuthorizedOperationV1Wire = {
  kind: 'verified_step_up_authorized_operation_v1';
  authorization_session_id: string;
  evidence_set_digest: string;
  authorized_operation_id: string;
  operation_id: string;
  capability_kind: 'near_ed25519_mpc_signing';
  operation_kind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
  lane_digest_b64u: string;
  intent_digest_b64u: string;
  display_digest_b64u: string;
  operation_fingerprint_digest: string;
};

type RouterAbNormalSigningFinalizeRequestV2BaseWire = {
  scope: RouterAbNormalSigningScopeV2Wire;
  expires_at_ms: number;
  prepare_binding: RouterAbEd25519NormalSigningPrepareBindingV2Wire;
  protocol: RouterAbEd25519NormalSigningFinalizeProtocolV2Wire;
};

export type RouterAbNormalSigningFinalizeRequestV2Wire =
  | (RouterAbNormalSigningFinalizeRequestV2BaseWire & {
      scope: RouterAbNormalSigningScopeV2Wire & {
        authorization: Extract<
          RouterAbNormalSigningAuthorizationWire,
          { kind: 'reusable_wallet_session' }
        >;
      };
      authorized_operation: RouterAbReusableWalletSessionAuthorizedOperationV1Wire;
    })
  | (RouterAbNormalSigningFinalizeRequestV2BaseWire & {
      scope: RouterAbNormalSigningScopeV2Wire & {
        authorization: Extract<
          RouterAbNormalSigningAuthorizationWire,
          { kind: 'operation_step_up' }
        >;
      };
      authorized_operation: RouterAbVerifiedStepUpAuthorizedOperationV1Wire;
    });

type RouterAbNormalSigningPrepareResponseV1BaseWire = {
  scope: RouterAbNormalSigningScopeV2Wire;
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

export type RouterAbNormalSigningPrepareResponseV1Wire =
  | (RouterAbNormalSigningPrepareResponseV1BaseWire & {
      scope: RouterAbNormalSigningScopeV2Wire & {
        authorization: Extract<
          RouterAbNormalSigningAuthorizationWire,
          { kind: 'reusable_wallet_session' }
        >;
      };
      authorized_operation: RouterAbReusableWalletSessionAuthorizedOperationV1Wire;
    })
  | (RouterAbNormalSigningPrepareResponseV1BaseWire & {
      scope: RouterAbNormalSigningScopeV2Wire & {
        authorization: Extract<
          RouterAbNormalSigningAuthorizationWire,
          { kind: 'operation_step_up' }
        >;
      };
      authorized_operation: RouterAbVerifiedStepUpAuthorizedOperationV1Wire;
    });

export type RouterAbNormalSigningResponseV1Wire = {
  scope: RouterAbNormalSigningScopeV2Wire;
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
  scope: RouterAbNormalSigningScopeV2Wire;
  expiresAtMs: number;
  operationId: string;
  operationFingerprint: string;
  displayDigestB64u: string;
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
    display_digest: routerAbDigest32Wire(
      base64UrlDecode(requireDigestB64u(args.displayDigestB64u, 'displayDigestB64u')),
    ),
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
  scope: RouterAbNormalSigningScopeV2Wire;
  expiresAtMs: number;
  operationId: string;
  operationFingerprint: string;
  displayDigestB64u: string;
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
    display_digest: routerAbDigest32Wire(
      base64UrlDecode(requireDigestB64u(args.displayDigestB64u, 'displayDigestB64u')),
    ),
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
  scope: RouterAbNormalSigningScopeV2Wire;
  expiresAtMs: number;
  operationId: string;
  operationFingerprint: string;
  displayDigestB64u: string;
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
    display_digest: routerAbDigest32Wire(
      base64UrlDecode(requireDigestB64u(args.displayDigestB64u, 'displayDigestB64u')),
    ),
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

export function buildRouterAbEd25519NormalSigningFinalizeRequestV2(args: {
  scope: RouterAbNormalSigningScopeV2Wire;
  expiresAtMs: number;
  prepareResponse: RouterAbNormalSigningPrepareResponseV1Wire;
  admissionMaterial: RouterAbEd25519NormalSigningAdmissionMaterialV2Wire;
  clientCommitments: RouterAbNormalSigningCommitmentsV1Wire;
  clientVerifyingShareB64u: string;
  clientSignatureShareB64u: string;
}): RouterAbNormalSigningFinalizeRequestV2Wire {
  const scope = parseScope(args.scope, 'scope');
  const base: RouterAbNormalSigningFinalizeRequestV2BaseWire = {
    scope,
    expires_at_ms: requirePositiveInteger(args.expiresAtMs, 'expiresAtMs'),
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
  if (
    scope.authorization.kind === 'reusable_wallet_session' &&
    args.prepareResponse.scope.authorization.kind === 'reusable_wallet_session'
  ) {
    return {
      ...base,
      scope: {
        ...scope,
        authorization: scope.authorization,
      },
      authorized_operation: parseReusableWalletSessionAuthorizedOperation(
        args.prepareResponse.authorized_operation,
        'authorized_operation',
      ),
    };
  }
  if (
    scope.authorization.kind === 'operation_step_up' &&
    args.prepareResponse.scope.authorization.kind === 'operation_step_up'
  ) {
    return {
      ...base,
      scope: {
        ...scope,
        authorization: scope.authorization,
      },
      authorized_operation: parseVerifiedStepUpAuthorizedOperation(
        args.prepareResponse.authorized_operation,
        'authorized_operation',
      ),
    };
  }
  throw new Error('Router A/B normal-signing authorization changed after prepare');
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

function requireExactFields(
  record: Record<string, unknown>,
  expectedFields: readonly string[],
  label: string,
): void {
  const actualFields = Object.keys(record).sort();
  const expected = [...expectedFields].sort();
  if (
    actualFields.length !== expected.length ||
    actualFields.some((field, index) => field !== expected[index])
  ) {
    throw new Error(`${label} has invalid fields`);
  }
}

function parseScope(value: unknown, label: string): RouterAbNormalSigningScopeV2Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  requireExactFields(
    record,
    ['request_id', 'account_id', 'authorization', 'material_activation', 'signing_worker_id'],
    label,
  );
  const scope = {
    request_id: requireNonEmptyString(record.request_id, `${label}.request_id`),
    account_id: requireNonEmptyString(record.account_id, `${label}.account_id`),
    authorization: parseRouterAbNormalSigningAuthorization(record.authorization),
    material_activation: parseRouterAbMpcMaterialActivationRef(record.material_activation),
    signing_worker_id: requireNonEmptyString(
      record.signing_worker_id,
      `${label}.signing_worker_id`,
    ),
  };
  if (scope.material_activation.signing_worker !== scope.signing_worker_id) {
    throw new Error(`${label} material activation SigningWorker mismatch`);
  }
  return scope;
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

function parseReusableWalletSessionAuthorizedOperation(
  value: unknown,
  label: string,
): RouterAbReusableWalletSessionAuthorizedOperationV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  requireExactFields(
    record,
    [
      'kind',
      'authorized_operation_id',
      'operation_id',
      'capability_kind',
      'operation_kind',
      'lane_digest_b64u',
      'intent_digest_b64u',
      'display_digest_b64u',
      'operation_fingerprint_digest',
    ],
    label,
  );
  const kind = requireNonEmptyString(record.kind, `${label}.kind`);
  if (kind !== 'reusable_wallet_session_authorized_operation_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const capabilityKind = requireNonEmptyString(
    record.capability_kind,
    `${label}.capability_kind`,
  );
  if (capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error(`${label}.capability_kind is invalid`);
  }
  const operationKind = requireNonEmptyString(record.operation_kind, `${label}.operation_kind`);
  if (
    operationKind !== 'near.sign_transaction' &&
    operationKind !== 'near.sign_delegate_action' &&
    operationKind !== 'near.sign_nep413_message'
  ) {
    throw new Error(`${label}.operation_kind is invalid`);
  }
  return {
    kind,
    authorized_operation_id: requireNonEmptyString(
      record.authorized_operation_id,
      `${label}.authorized_operation_id`,
    ),
    operation_id: requireNonEmptyString(record.operation_id, `${label}.operation_id`),
    capability_kind: capabilityKind,
    operation_kind: operationKind,
    lane_digest_b64u: requireDigestB64u(
      record.lane_digest_b64u,
      `${label}.lane_digest_b64u`,
    ),
    intent_digest_b64u: requireDigestB64u(
      record.intent_digest_b64u,
      `${label}.intent_digest_b64u`,
    ),
    display_digest_b64u: requireDigestB64u(
      record.display_digest_b64u,
      `${label}.display_digest_b64u`,
    ),
    operation_fingerprint_digest: requireDigestB64u(
      record.operation_fingerprint_digest,
      `${label}.operation_fingerprint_digest`,
    ),
  };
}

function parseVerifiedStepUpAuthorizedOperation(
  value: unknown,
  label: string,
): RouterAbVerifiedStepUpAuthorizedOperationV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error(`${label} must be an object`);
  requireExactFields(
    record,
    [
      'kind',
      'authorization_session_id',
      'evidence_set_digest',
      'authorized_operation_id',
      'operation_id',
      'capability_kind',
      'operation_kind',
      'lane_digest_b64u',
      'intent_digest_b64u',
      'display_digest_b64u',
      'operation_fingerprint_digest',
    ],
    label,
  );
  const kind = requireNonEmptyString(record.kind, `${label}.kind`);
  if (kind !== 'verified_step_up_authorized_operation_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const capabilityKind = requireNonEmptyString(
    record.capability_kind,
    `${label}.capability_kind`,
  );
  if (capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error(`${label}.capability_kind is invalid`);
  }
  const operationKind = requireNonEmptyString(record.operation_kind, `${label}.operation_kind`);
  if (
    operationKind !== 'near.sign_transaction' &&
    operationKind !== 'near.sign_delegate_action' &&
    operationKind !== 'near.sign_nep413_message'
  ) {
    throw new Error(`${label}.operation_kind is invalid`);
  }
  return {
    kind: 'verified_step_up_authorized_operation_v1',
    authorization_session_id: requireNonEmptyString(
      record.authorization_session_id,
      `${label}.authorization_session_id`,
    ),
    evidence_set_digest: requireDigestB64u(
      record.evidence_set_digest,
      `${label}.evidence_set_digest`,
    ),
    authorized_operation_id: requireNonEmptyString(
      record.authorized_operation_id,
      `${label}.authorized_operation_id`,
    ),
    operation_id: requireNonEmptyString(record.operation_id, `${label}.operation_id`),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operationKind,
    lane_digest_b64u: requireDigestB64u(
      record.lane_digest_b64u,
      `${label}.lane_digest_b64u`,
    ),
    intent_digest_b64u: requireDigestB64u(
      record.intent_digest_b64u,
      `${label}.intent_digest_b64u`,
    ),
    display_digest_b64u: requireDigestB64u(
      record.display_digest_b64u,
      `${label}.display_digest_b64u`,
    ),
    operation_fingerprint_digest: requireDigestB64u(
      record.operation_fingerprint_digest,
      `${label}.operation_fingerprint_digest`,
    ),
  };
}

function parsePrepareResponse(value: unknown): RouterAbNormalSigningPrepareResponseV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error('Router A/B normal-signing prepare response must be an object');
  const signatureScheme = requireNonEmptyString(record.signature_scheme, 'signature_scheme');
  if (signatureScheme !== 'ed25519_v1') {
    throw new Error(`Unsupported Router A/B normal-signing signature scheme: ${signatureScheme}`);
  }
  const scope = parseScope(record.scope, 'scope');
  const base: RouterAbNormalSigningPrepareResponseV1BaseWire = {
    scope,
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
  switch (scope.authorization.kind) {
    case 'reusable_wallet_session':
      requireExactFields(
        record,
        [
          'scope',
          'signing_payload_digest',
          'round1_binding_digest',
          'signing_worker',
          'server_round1_handle',
          'server_commitments',
          'server_verifying_share_b64u',
          'signature_scheme',
          'prepared_at_ms',
          'expires_at_ms',
          'authorized_operation',
        ],
        'Router A/B reusable Wallet Session prepare response',
      );
      return {
        ...base,
        scope: { ...scope, authorization: scope.authorization },
        authorized_operation: parseReusableWalletSessionAuthorizedOperation(
          record.authorized_operation,
          'authorized_operation',
        ),
      };
    case 'operation_step_up':
      requireExactFields(
        record,
        [
          'scope',
          'signing_payload_digest',
          'round1_binding_digest',
          'signing_worker',
          'server_round1_handle',
          'server_commitments',
          'server_verifying_share_b64u',
          'signature_scheme',
          'prepared_at_ms',
          'expires_at_ms',
          'authorized_operation',
        ],
        'Router A/B operation step-up prepare response',
      );
      return {
        ...base,
        scope: { ...scope, authorization: scope.authorization },
        authorized_operation: parseVerifiedStepUpAuthorizedOperation(
          record.authorized_operation,
          'authorized_operation',
        ),
      };
  }
}

function parseNormalSigningResponse(value: unknown): RouterAbNormalSigningResponseV1Wire {
  const record = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!record) throw new Error('Router A/B normal-signing response must be an object');
  requireExactFields(
    record,
    [
      'scope',
      'signing_payload_digest',
      'signing_worker',
      'signature_scheme',
      'signature',
      'signed_at_ms',
    ],
    'Router A/B normal-signing response',
  );
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
  credential: RouterAbEd25519NormalSigningCredential;
  body: unknown;
}): RequestInit {
  const bearer =
    isLinkedDeviceWalletSessionCredential(args.credential)
      ? {
          token: linkedDeviceWalletSessionBearer(args.credential),
          missingMessage: 'linked-device Wallet Session JWT is required',
        }
        : args.credential.kind === 'wallet_session_opaque'
        ? {
            token: args.credential.walletSessionToken,
            missingMessage: 'walletSessionToken is required',
          }
        : null;
  const init = buildRelayerJsonPostRequestInit({
    ...(bearer ? { headers: buildBearerAuthorizationHeader(bearer) } : {}),
    body: args.body,
  });
  return init;
}

function parseRouterAbSigningErrorPayload(bodyText: string): RouterAbSigningErrorPayload | null {
  if (!bodyText.trim()) return null;
  try {
    const parsed = JSON.parse(bodyText) as unknown;
    const record =
      parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
    if (!record) return null;
    const code = String(record.code || '').trim();
    const message = String(record.message || '').trim();
    if (!code) return null;
    const authorizationDecision =
      record.authorization_decision === undefined
        ? undefined
        : parseRouterAbOwnerOperationAuthorizationDecision(record.authorization_decision);
    return { code, message, ...(authorizationDecision ? { authorizationDecision } : {}) };
  } catch {
    return null;
  }
}

function parseRouterAbOwnerOperationAuthorizationDecision(
  value: unknown,
):
  | RouterAbOwnerOperationAuthorizationDecisionV1Wire
  | RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Router A/B owner-operation authorization decision is invalid');
  }
  const record = value as Record<string, unknown>;
  const kind = record.kind;
  if (kind === 'step_up_required') {
    requireExactRecordFields(
      record,
      ['kind', 'reason', 'step_up'],
      'owner-operation step-up decision',
    );
    const reason = record.reason;
    if (
      reason !== 'wallet_session_missing' &&
      reason !== 'wallet_session_expired' &&
      reason !== 'wallet_session_exhausted' &&
      reason !== 'wallet_session_ended' &&
      reason !== 'wallet_session_superseded'
    ) {
      throw new Error('owner-operation step-up decision reason is invalid');
    }
    const stepUp = record.step_up;
    if (
      stepUp &&
      typeof stepUp === 'object' &&
      !Array.isArray(stepUp) &&
      'operation_digests' in stepUp
    ) {
      return { kind, reason, step_up: parseRouterAbEcdsaOperationStepUpPreparationV1(stepUp) };
    }
    return { kind, reason, step_up: parseRouterAbEd25519OperationStepUpPreparation(stepUp) };
  }
  if (kind === 'denied') {
    requireExactRecordFields(record, ['kind', 'denial'], 'owner-operation denial decision');
    if (!record.denial || typeof record.denial !== 'object' || Array.isArray(record.denial)) {
      throw new Error('owner-operation denial is invalid');
    }
    const denial = record.denial as Record<string, unknown>;
    requireExactRecordFields(denial, ['code', 'message'], 'owner-operation denial');
    const code = denial.code;
    if (
      code !== 'invalid_identity' &&
      code !== 'invalid_authority' &&
      code !== 'invalid_operation' &&
      code !== 'inactive_material' &&
      code !== 'replayed_step_up' &&
      code !== 'authorization_unavailable'
    ) {
      throw new Error('owner-operation denial code is invalid');
    }
    if (typeof denial.message !== 'string' || denial.message.trim() !== denial.message) {
      throw new Error('owner-operation denial message is invalid');
    }
    return { kind, denial: { code, message: denial.message } };
  }
  if (kind === 'authorized') {
    requireExactRecordFields(record, ['kind', 'operation', 'source'], 'owner-operation decision');
    if (!record.operation || typeof record.operation !== 'object' || Array.isArray(record.operation)) {
      throw new Error('owner-operation authorized operation is invalid');
    }
    const operation = record.operation as Record<string, unknown>;
    requireExactRecordFields(
      operation,
      ['kind', 'operation_id', 'authorized_operation_id', 'operation_fingerprint_digest'],
      'owner-operation authorized operation',
    );
    if (
      operation.kind !== 'authorized_operation' ||
      typeof operation.operation_id !== 'string' ||
      typeof operation.authorized_operation_id !== 'string' ||
      typeof operation.operation_fingerprint_digest !== 'string'
    ) {
      throw new Error('owner-operation authorized operation is invalid');
    }
    if (!record.source || typeof record.source !== 'object' || Array.isArray(record.source)) {
      throw new Error('owner-operation authorized source is invalid');
    }
    const source = record.source as Record<string, unknown>;
    requireExactRecordFields(
      source,
      ['kind', 'wallet_session_id', 'quota_id'],
      'owner-operation authorized source',
    );
    if (
      source.kind !== 'reusable_wallet_session' ||
      typeof source.wallet_session_id !== 'string' ||
      typeof source.quota_id !== 'string'
    ) {
      throw new Error('owner-operation authorized source is invalid');
    }
    return {
      kind,
      operation: {
        kind: 'authorized_operation',
        operation_id: operation.operation_id,
        authorized_operation_id: operation.authorized_operation_id,
        operation_fingerprint_digest: operation.operation_fingerprint_digest,
      },
      source: {
        kind: 'reusable_wallet_session',
        wallet_session_id: source.wallet_session_id,
        quota_id: source.quota_id,
      },
    };
  }
  throw new Error('owner-operation authorization decision kind is invalid');
}

function parseRouterAbEd25519OperationStepUpPreparation(
  value: unknown,
): RouterAbEd25519OperationStepUpPreparationV1Wire {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Ed25519 operation step-up preparation is invalid');
  }
  const record = value as Record<string, unknown>;
  requireExactRecordFields(
    record,
    [
      'wallet_id',
      'operation_kind',
      'operation_id',
      'request_id',
      'account_id',
      'material_activation',
      'signing_worker_id',
      'near_account_id',
      'signer_slot',
      'participant_ids',
      'expires_at_ms',
    ],
    'Ed25519 owner-operation step-up preparation',
  );
  const operationKind = record.operation_kind;
  if (
    operationKind !== 'near.sign_transaction' &&
    operationKind !== 'near.sign_delegate_action' &&
    operationKind !== 'near.sign_nep413_message'
  ) {
    throw new Error('Ed25519 operation step-up kind is invalid');
  }
  if (
    typeof record.wallet_id !== 'string' ||
    typeof record.operation_id !== 'string' ||
    typeof record.request_id !== 'string' ||
    typeof record.account_id !== 'string' ||
    typeof record.signing_worker_id !== 'string' ||
    typeof record.near_account_id !== 'string' ||
    !Number.isSafeInteger(record.signer_slot) ||
    !Number.isSafeInteger(record.expires_at_ms) ||
    !Array.isArray(record.participant_ids) ||
    record.participant_ids.length !== 2 ||
    !record.participant_ids.every(
      (participantId) => Number.isSafeInteger(participantId) && Number(participantId) > 0,
    )
  ) {
    throw new Error('Ed25519 operation step-up preparation fields are invalid');
  }
  const [firstParticipantId, secondParticipantId] = record.participant_ids;
  const signerSlot = record.signer_slot;
  const expiresAtMs = record.expires_at_ms;
  if (
    typeof firstParticipantId !== 'number' ||
    typeof secondParticipantId !== 'number' ||
    typeof signerSlot !== 'number' ||
    typeof expiresAtMs !== 'number'
  ) {
    throw new Error('Ed25519 operation step-up participants are invalid');
  }
  return {
    wallet_id: record.wallet_id,
    operation_kind: operationKind,
    operation_id: record.operation_id,
    request_id: record.request_id,
    account_id: record.account_id,
    material_activation: parseRouterAbMpcMaterialActivationRef(record.material_activation),
    signing_worker_id: record.signing_worker_id,
    near_account_id: record.near_account_id,
    signer_slot: signerSlot,
    participant_ids: [firstParticipantId, secondParticipantId],
    expires_at_ms: expiresAtMs,
  };
}

function requireExactRecordFields(
  record: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  const expected = new Set(fields);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) throw new Error(`${label} contains unsupported field ${key}`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) throw new Error(`${label} is missing ${field}`);
  }
}

function routerAbSigningHttpError(args: { path: string; status: number; bodyText: string }): Error {
  const payload = parseRouterAbSigningErrorPayload(args.bodyText);
  if (payload) {
    const admissionError = routerAbNormalSigningAdmissionErrorFromPayload({
      code: payload.code,
      message: payload.message,
      path: args.path,
      status: args.status,
      authorizationDecision: payload.authorizationDecision,
    });
    if (admissionError) return admissionError;
    const walletSessionError = walletSessionFailureErrorFromPayload({
      code: payload.code,
      message: `Router A/B signing ${args.path} returned HTTP ${args.status}: ${payload.message}`,
    });
    if (walletSessionError) return walletSessionError;
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
    | '/router-ab/ed25519/sign/prepare'
    | '/router-ab/ed25519/sign'
    | '/router-ab/ecdsa-derivation/sign/prepare'
    | '/router-ab/ecdsa-derivation/sign';
  credential: RouterAbEd25519NormalSigningCredential;
  body: unknown;
  parse: (value: unknown) => T | Promise<T>;
}): Promise<T> {
  if (typeof fetch !== 'function') {
    throw new Error('fetch is not available for Router A/B normal-signing request');
  }
  const base = normalizeRelayerBaseUrl(
    requireNonEmptyString(args.relayServerUrl, 'relayServerUrl'),
  );
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
  credential: RouterAbEd25519NormalSigningCredential;
  request: RouterAbNormalSigningPrepareRequestV2Wire;
}): Promise<RouterAbNormalSigningPrepareResponseV1Wire> {
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/router-ab/ed25519/sign/prepare',
    credential: args.credential,
    body: args.request,
    parse: parsePrepareResponse,
  });
}

export async function prepareRouterAbEcdsaDerivationEvmDigestSigningV1(args: {
  relayServerUrl: string;
  credential: RouterAbEd25519NormalSigningCredential;
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
}): Promise<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire> {
  await routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(args.request);
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/router-ab/ecdsa-derivation/sign/prepare',
    credential: args.credential,
    body: args.request,
    parse: (value) =>
      parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1(args.request, value),
  });
}

export async function finalizeRouterAbNormalSigningV2(args: {
  relayServerUrl: string;
  credential: RouterAbEd25519NormalSigningCredential;
  request: RouterAbNormalSigningFinalizeRequestV2Wire;
}): Promise<RouterAbNormalSigningResponseV1Wire> {
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/router-ab/ed25519/sign',
    credential: args.credential,
    body: args.request,
    parse: parseNormalSigningResponse,
  });
}

export async function finalizeRouterAbEcdsaDerivationEvmDigestSigningV1(args: {
  relayServerUrl: string;
  credential: RouterAbEd25519NormalSigningCredential;
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire;
}): Promise<RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire> {
  await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(args.request);
  return postRouterAbNormalSigningJson({
    relayServerUrl: args.relayServerUrl,
    path: '/router-ab/ecdsa-derivation/sign',
    credential: args.credential,
    body: args.request,
    parse: (value) =>
      parseRouterAbEcdsaDerivationEvmDigestSigningResponseForCoreRequestV1(args.request, value),
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
