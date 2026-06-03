import { errorMessage } from '@shared/utils/errors';
import { normalizeJwtCookieSessionKind, stripTrailingSlashes } from '@shared/utils/normalize';
import type {
  ThresholdEd25519NearAction,
  ThresholdEd25519NearTransaction,
} from '@shared/threshold/ed25519OperationFingerprint';
import type {
  PrepareThresholdEd25519PresignPoolPayload,
  PrepareThresholdEd25519PresignPoolResult,
  ThresholdEd25519PresignCommitmentsWire,
  ThresholdEd25519PresignPoolAcceptedPair,
  ThresholdEd25519PresignPoolRouteAuth,
} from '@/core/types/signer-worker';

export type ThresholdEd25519SigningOperationWire = {
  kind: 'threshold_ed25519_signing_operation_v1';
  operationId: string;
  operationFingerprint: string;
  purpose: 'near_transaction' | 'nep413_message' | 'delegate_action';
};

export type ThresholdEd25519FinalizeNep413IntentWire = {
  kind: 'nep413_message_v1';
  message: string;
  recipient: string;
  nonce: string;
  state?: string;
};

export type ThresholdEd25519FinalizeDelegateActionIntentWire = {
  kind: 'near_delegate_action_v1';
  delegate: {
    senderId: string;
    receiverId: string;
    actions: readonly ThresholdEd25519NearAction[];
    nonce: string;
    maxBlockHeight: string;
    publicKey: string;
  };
};

export type ThresholdEd25519FinalizeSignatureOnlyIntentWire =
  | ThresholdEd25519FinalizeNep413IntentWire
  | ThresholdEd25519FinalizeDelegateActionIntentWire;

export type ThresholdEd25519FinalizeSignatureOnlyRequestWire = {
  kind: 'threshold_ed25519_finalize_signature_only_v1';
  operation: ThresholdEd25519SigningOperationWire;
  requestIntegrityHash: string;
  presignId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  expectedSignerPublicKey: string;
  intent: ThresholdEd25519FinalizeSignatureOnlyIntentWire;
  clientSignatureShareB64u: string;
};

export type ThresholdEd25519FinalizeAndDispatchNearTxRequestWire = {
  kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1';
  operation: ThresholdEd25519SigningOperationWire;
  requestIntegrityHash: string;
  presignId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  expectedSignerPublicKey: string;
  transactions: readonly ThresholdEd25519NearTransaction[];
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
  clientSignatureShareB64u: string;
  dispatch: {
    kind: 'near_rpc_configured_default_v1';
  };
};

export type ThresholdEd25519FinalizeAndDispatchRequestWire =
  | ThresholdEd25519FinalizeSignatureOnlyRequestWire
  | ThresholdEd25519FinalizeAndDispatchNearTxRequestWire;

export type ThresholdEd25519FinalizeAndDispatchResponseWire =
  | {
      ok: true;
      kind: 'threshold_ed25519_signature_only_result_v1';
      operationId: string;
      budgetState: 'consumed' | 'already_consumed';
      remainingSigningUses: number;
      signatureB64u: string;
      signerPublicKey: string;
    }
  | {
      ok: true;
      kind: 'threshold_ed25519_dispatched_near_tx_result_v1';
      operationId: string;
      budgetState: 'consumed' | 'already_consumed';
      remainingSigningUses: number;
      signatureB64u: string;
      signerPublicKey: string;
      signedTransactionBorshB64u: string;
      transactionHash: string;
      rpcResult: unknown;
    }
  | {
      ok: false;
      kind:
        | 'threshold_ed25519_finalize_rejected_without_operation_v1'
        | 'threshold_ed25519_finalize_rejected_for_operation_v1';
      code: string;
      message: string;
      operationId?: string;
      budgetState: 'not_consumed' | 'consumed' | 'already_consumed';
      presignConsumed: boolean;
      dispatchState: 'not_attempted' | 'attempted' | 'unknown';
    };

type ThresholdEd25519PresignRefillResponseWire =
  | {
      ok: true;
      kind: 'threshold_ed25519_presign_refill_response_v1';
      accepted: readonly ThresholdEd25519PresignPairWire[];
      rejectedClientPresignIds: readonly string[];
      serverTimeMs: number;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

type ThresholdEd25519PresignPairWire = ThresholdEd25519PresignPoolAcceptedPair & {
  signerPublicKey: string;
  nearNetworkId: string;
  participantIds: readonly number[];
};

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function buildThresholdEd25519RequestInit(args: {
  auth: ThresholdEd25519PresignPoolRouteAuth;
  body: unknown;
}): RequestInit {
  const sessionKind = normalizeJwtCookieSessionKind(args.auth.sessionKind);
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (sessionKind === 'jwt') {
    headers.Authorization = `Bearer ${requireNonEmptyString(
      args.auth.thresholdSessionAuthToken,
      'thresholdSessionAuthToken',
    )}`;
  }
  return {
    method: 'POST',
    headers,
    credentials: sessionKind === 'cookie' ? 'include' : 'omit',
    body: JSON.stringify(args.body),
  };
}

async function postThresholdEd25519Json<T>(args: {
  relayServerUrl: string;
  path: string;
  auth: ThresholdEd25519PresignPoolRouteAuth;
  body: unknown;
}): Promise<T> {
  if (typeof fetch !== 'function') {
    throw new Error('fetch is not available for threshold-ed25519 relayer request');
  }
  const base = stripTrailingSlashes(requireNonEmptyString(args.relayServerUrl, 'relayServerUrl'));
  const response = await fetch(
    `${base}${args.path}`,
    buildThresholdEd25519RequestInit({ auth: args.auth, body: args.body }),
  );
  return (await response.json()) as T;
}

function presignRefillBodyFromPoolPayload(payload: PrepareThresholdEd25519PresignPoolPayload): {
  kind: 'threshold_ed25519_presign_refill_v1';
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  expectedSignerPublicKey: string;
  participantIds: readonly number[];
  clientPresigns: readonly {
    clientPresignId: string;
    clientVerifyingShareB64u: string;
    clientCommitments: ThresholdEd25519PresignCommitmentsWire;
  }[];
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
} {
  return {
    kind: 'threshold_ed25519_presign_refill_v1',
    relayerKeyId: requireNonEmptyString(payload.relayerKeyId, 'relayerKeyId'),
    nearAccountId: requireNonEmptyString(payload.nearAccountId, 'nearAccountId'),
    nearNetworkId: requireNonEmptyString(payload.nearNetworkId, 'nearNetworkId'),
    expectedSignerPublicKey: requireNonEmptyString(payload.signerPublicKey, 'signerPublicKey'),
    participantIds: payload.participantIds,
    clientPresigns: payload.clientPresigns.map((offer) => ({
      clientPresignId: requireNonEmptyString(offer.clientPresignId, 'clientPresignId'),
      clientVerifyingShareB64u: requireNonEmptyString(
        offer.clientVerifyingShareB64u,
        'clientVerifyingShareB64u',
      ),
      clientCommitments: offer.clientCommitments,
    })),
    requestTag: payload.requestTag,
  };
}

function poolResultFromPresignRefillResponse(args: {
  payload: PrepareThresholdEd25519PresignPoolPayload;
  response: ThresholdEd25519PresignRefillResponseWire;
}): PrepareThresholdEd25519PresignPoolResult {
  if (!args.response.ok) {
    return {
      ok: false,
      kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
      code: args.response.code,
      message: args.response.message,
      generation: args.payload.generation,
    };
  }
  const accepted = args.response.accepted.map(
    (pair): ThresholdEd25519PresignPoolAcceptedPair => ({
      presignId: pair.presignId,
      clientPresignId: pair.clientPresignId,
      relayerCommitments: pair.relayerCommitments,
      relayerVerifyingShareB64u: pair.relayerVerifyingShareB64u,
      expiresAtMs: pair.expiresAtMs,
    }),
  );
  const expiresAtMs =
    accepted.length > 0
      ? Math.min(...accepted.map((pair) => Math.max(0, Math.floor(Number(pair.expiresAtMs) || 0))))
      : Math.max(0, Math.floor(Number(args.response.serverTimeMs) || Date.now()));
  return {
    ok: true,
    kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
    generation: args.payload.generation,
    accepted,
    rejectedClientPresignIds: args.response.rejectedClientPresignIds,
    expiresAtMs,
  };
}

export async function refillThresholdEd25519PresignPool(
  payload: PrepareThresholdEd25519PresignPoolPayload,
): Promise<PrepareThresholdEd25519PresignPoolResult> {
  try {
    const response = await postThresholdEd25519Json<ThresholdEd25519PresignRefillResponseWire>({
      relayServerUrl: payload.relayUrl,
      path: '/threshold-ed25519/presign/refill',
      auth: payload,
      body: presignRefillBodyFromPoolPayload(payload),
    });
    return poolResultFromPresignRefillResponse({ payload, response });
  } catch (error) {
    return {
      ok: false,
      kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
      code: 'relayer_request_failed',
      message: errorMessage(error) || 'threshold-ed25519 presign refill failed',
      generation: payload.generation,
    };
  }
}

export async function finalizeThresholdEd25519Presign(args: {
  relayServerUrl: string;
  auth: ThresholdEd25519PresignPoolRouteAuth;
  request: ThresholdEd25519FinalizeAndDispatchRequestWire;
}): Promise<ThresholdEd25519FinalizeAndDispatchResponseWire> {
  return await postThresholdEd25519Json<ThresholdEd25519FinalizeAndDispatchResponseWire>({
    relayServerUrl: args.relayServerUrl,
    path: '/threshold-ed25519/sign/finalize-and-dispatch',
    auth: args.auth,
    body: args.request,
  });
}
