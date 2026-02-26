import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { TransactionInputWasm, validateActionArgsWasm } from '@/core/types/actions';
import { type onProgressEvents } from '@/core/types/sdkSentEvents';
import {
  WorkerRequestType,
  TransactionPayload,
  type WasmSignTransactionsWithActionsRequest,
  isSignTransactionsWithActionsSuccess,
  isWorkerError,
  type ConfirmationConfig,
  type RpcCallPayload,
  type SignerMode,
  type TransactionResponse,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import { AccountId } from '@/core/types/accountIds';
import type { SigningRuntimeDeps } from '../../interfaces/runtime';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { toAccountId } from '@/core/types/accountIds';
import { WebAuthnAuthenticationCredential } from '@/core/types';
import type { TransactionContext } from '@/core/types/rpc';
import type {
  LocalNearSkV3Material,
  ThresholdEd25519_2p_V1Material,
} from '@/core/indexedDB/passkeyNearKeysDB.types';
import {
  clearCachedEd25519AuthSession,
  getCachedEd25519AuthSessionJwt,
  getCachedEd25519AuthSessionJwtBySessionId,
  makeEd25519AuthSessionCacheKey,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';
import {
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  clearSigningSessionPrfFirstBestEffort,
} from '@/core/signingEngine/api/session/signingSessionState';
import {
  generateSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import { assertThresholdSigningSessionReady } from '@/core/signingEngine/orchestration/shared/thresholdSigningSessionPlanner';
import { buildNearWorkerSigningEnvelope } from './shared/workerRequestAssembly';

function normalizeTransactionSigningRequest(args: {
  nearAccountId: string;
  tx: TransactionInputWasm;
  txIndex: number;
}): TransactionPayload {
  const receiverId = String(args.tx?.receiverId || '').trim();
  if (!receiverId) {
    throw new Error(`[SigningEngine] transactions[${args.txIndex}].receiverId is required`);
  }

  const actions = Array.isArray(args.tx?.actions) ? args.tx.actions : [];
  if (actions.length === 0) {
    throw new Error(`[SigningEngine] transactions[${args.txIndex}].actions must be non-empty`);
  }
  for (let i = 0; i < actions.length; i++) {
    validateActionArgsWasm(actions[i]);
  }

  return {
    nearAccountId: args.nearAccountId,
    receiverId,
    actions,
  };
}

/**
 * Sign multiple transactions with a shared WebAuthn credential.
 * Efficiently processes multiple transactions with one PRF-backed signing session.
 */

export async function signTransactionsWithActions({
  ctx,
  sessionId: providedSessionId,
  transactions,
  rpcCall,
  signerMode,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  deviceNumber,
}: {
  ctx: SigningRuntimeDeps;
  sessionId?: string;
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  signerMode: SignerMode;
  onEvent?: (update: onProgressEvents) => void;
  // Allow callers to pass a partial override (e.g., { uiMode: 'drawer' })
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  deviceNumber?: number;
}): Promise<
  Array<{
    signedTransaction: SignedTransaction;
    nearAccountId: AccountId;
    logs?: string[];
  }>
> {
  const sessionId = providedSessionId ?? generateSessionId();
  const nearAccountId = toAccountId(rpcCall.nearAccountId);
  const relayerUrl = ctx.relayerUrl;

  const warnings: string[] = [];
  const {
    resolvedSignerMode,
    localKeyMaterial,
    thresholdKeyMaterial,
    localWrapKeySalt,
    thresholdWrapKeySalt,
  } = await resolveNearSigningMaterials({
    ctx,
    nearAccountId,
    signerMode,
    deviceNumber,
    operationLabel: 'signing',
    warnings,
    allowThresholdOnlyUpgrade: true,
  });

  console.debug('[signTransactionsWithActions] resolvedSignerMode', {
    nearAccountId,
    resolvedSignerMode,
    warnings,
  });

  const signingContext = validateAndPrepareSigningContext({
    nearAccountId,
    resolvedSignerMode,
    relayerUrl,
    rpId: ctx.touchIdPrompt.getRpId(),
    localKeyMaterial,
    thresholdKeyMaterial,
  });

  // Ensure nonce/block context is fetched for the same access key that will sign.
  // Threshold signing MUST use the threshold/group public key (relayer access key) for:
  // - correct nonce reservation
  // - relayer scope checks (/authorize expects signingPayload.transactionContext.nearPublicKeyStr == relayer key)
  ctx.nonceManager.initializeUser(
    toAccountId(nearAccountId),
    signingContext.signingNearPublicKeyStr,
  );

  // Normalize rpcCall to ensure required fields are present.
  const resolvedRpcCall = {
    nearRpcUrl: rpcCall.nearRpcUrl || resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.chains),
    nearAccountId: rpcCall.nearAccountId,
  } as RpcCallPayload;
  const normalizedInputTransactions = Array.isArray(transactions) ? transactions : [];
  if (normalizedInputTransactions.length === 0) {
    throw new Error('[SigningEngine] transactions must be non-empty');
  }
  const txSigningRequests: TransactionPayload[] = normalizedInputTransactions.map((tx, txIndex) =>
    normalizeTransactionSigningRequest({
      nearAccountId: String(resolvedRpcCall.nearAccountId),
      tx,
      txIndex,
    }),
  );
  const normalizedTransactions: TransactionInputWasm[] = txSigningRequests.map((tx) => ({
    receiverId: tx.receiverId,
    actions: tx.actions,
  }));

  // UserConfirm before sending anything to the signer worker.
  // WebAuthn uses a challenge digest (threshold sessions use `sessionPolicyDigest32`).
  if (!ctx.touchConfirm) {
    throw new Error('TouchConfirm bridge not available for signing');
  }
  const touchConfirm = ctx.touchConfirm;
  const usesNeeded = Math.max(1, txSigningRequests.length);
  const signingAuthMode = signingContext.threshold
    ? await (async () => {
        await assertThresholdSigningSessionReady({
          touchConfirm,
          sessionId,
          usesNeeded,
        });
        return 'warmSession' as const;
      })()
    : undefined;
  const confirmation = await ctx.touchConfirm.orchestrateSigningConfirmation({
    ctx: { touchConfirm },
    sessionId,
    chain: 'near',
    kind: 'transaction',
    ...(signingAuthMode ? { signingAuthMode } : {}),
    txSigningRequests: normalizedTransactions,
    rpcCall: resolvedRpcCall,
    confirmationConfigOverride,
    title,
    body,
  });

  const intentDigest = confirmation.intentDigest;
  const transactionContext = confirmation.transactionContext;

  const credentialWithPrf: WebAuthnAuthenticationCredential | undefined = confirmation.credential as
    | WebAuthnAuthenticationCredential
    | undefined;

  const credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

  const prfFirstB64u = signingContext.threshold
    ? await (async () => {
        const delivered = await touchConfirm.dispensePrfFirstForThresholdSession({
          sessionId,
          uses: usesNeeded,
        });
        if (!delivered.ok) {
          clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          await clearSigningSessionPrfFirstBestEffort(touchConfirm, sessionId);
          throw new Error(
            `[chains] threshold signingSession is ${delivered.code}; reconnect threshold session before signing`,
          );
        }
        return delivered.prfFirstB64u;
      })()
    : requirePrfFirstFromCredential(credentialWithPrf);

  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output for signing');
  }

  // Threshold signer: authorize with relayer and pass threshold config into the signer worker.
  if (signingContext.threshold) {
    if (!signingContext.threshold.thresholdSessionJwt) {
      signingContext.threshold.thresholdSessionJwt =
        getCachedEd25519AuthSessionJwtBySessionId(sessionId)
        || signingContext.threshold.thresholdSessionJwt;
    }
    if (!signingContext.threshold.thresholdSessionJwt) {
      clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
      throw new Error('[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing');
    }
    const requestPayload: Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'> = {
      rpcCall: resolvedRpcCall,
      createdAt: Date.now(),
      ...buildNearWorkerSigningEnvelope({
        signerMode: signingContext.resolvedSignerMode,
        prfFirstB64u,
        wrapKeySalt: thresholdWrapKeySalt,
        threshold: {
          relayerUrl: signingContext.threshold.relayerUrl,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
        },
      }),
      txSigningRequests,
      intentDigest,
      transactionContext,
      credential: credentialForRelayJson,
    };

    try {
      const response = await executeWorkerOperation({
        ctx,
        kind: 'nearSigner',
        request: {
          sessionId,
          type: WorkerRequestType.SignTransactionsWithActions,
          payload: requestPayload,
          onEvent,
        },
      });
      const okResponse = requireOkSignTransactionsWithActionsResponse(response);
      return toSignedTransactionResults({
        okResponse,
        expectedTransactionCount: transactions.length,
        nearAccountId,
        warnings,
      });
    } catch (e: unknown) {
      const err = e instanceof Error ? e : new Error(String(e));

      if (isThresholdSignerMissingKeyError(err)) {
        const msg =
          '[SigningEngine] threshold-signer requested but the relayer is missing the signing share; local fallback is disabled';
        console.warn(msg);
        warnings.push(msg);
        clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
        signingContext.threshold.thresholdSessionJwt = undefined;
        throw new Error(msg);
      }

      if (isThresholdSessionAuthUnavailableError(err)) {
        clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
        await clearSigningSessionPrfFirstBestEffort(touchConfirm, sessionId);
        signingContext.threshold.thresholdSessionJwt = undefined;
        throw new Error(
          '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
        );
      }

      throw err;
    }
  }

  return await signTransactionsWithActionsLocally({
    ctx,
    sessionId,
    onEvent,
    resolvedRpcCall,
    localKeyMaterial: (() => {
      if (!localKeyMaterial)
        throw new Error(`No local key material found for account: ${nearAccountId}`);
      return localKeyMaterial;
    })(),
    txSigningRequests,
    intentDigest,
    transactionContext,
    credential: credentialForRelayJson,
    prfFirstB64u,
    wrapKeySalt: localWrapKeySalt,
    expectedTransactionCount: transactions.length,
    warnings,
  });
}

async function signTransactionsWithActionsLocally(args: {
  ctx: SigningRuntimeDeps;
  sessionId: string;
  onEvent?: (update: onProgressEvents) => void;
  resolvedRpcCall: RpcCallPayload;
  localKeyMaterial: LocalNearSkV3Material;
  txSigningRequests: TransactionPayload[];
  intentDigest: string;
  transactionContext: TransactionContext;
  credential: string | undefined;
  prfFirstB64u: string | undefined;
  wrapKeySalt: string;
  expectedTransactionCount: number;
  warnings: string[];
}): Promise<
  Array<{
    signedTransaction: SignedTransaction;
    nearAccountId: AccountId;
    logs?: string[];
  }>
> {
  const localRequestPayload: Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'> = {
    rpcCall: args.resolvedRpcCall,
    createdAt: Date.now(),
    ...buildNearWorkerSigningEnvelope({
      signerMode: 'local-signer',
      prfFirstB64u: args.prfFirstB64u,
      wrapKeySalt: args.wrapKeySalt,
      localKeyMaterial: args.localKeyMaterial,
    }),
    txSigningRequests: args.txSigningRequests,
    intentDigest: args.intentDigest,
    transactionContext: args.transactionContext,
    credential: args.credential,
  };

  const response = await executeWorkerOperation({
    ctx: args.ctx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: WorkerRequestType.SignTransactionsWithActions,
      payload: localRequestPayload,
      onEvent: args.onEvent,
    },
  });

  const okResponse = requireOkSignTransactionsWithActionsResponse(response);
  return toSignedTransactionResults({
    okResponse,
    expectedTransactionCount: args.expectedTransactionCount,
    nearAccountId: args.resolvedRpcCall.nearAccountId,
    warnings: args.warnings,
  });
}

function toSignedTransactionResults(args: {
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  expectedTransactionCount: number;
  nearAccountId: string;
  warnings: string[];
}): Array<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  const signedTransactions = args.okResponse.payload.signedTransactions || [];
  if (signedTransactions.length !== args.expectedTransactionCount) {
    throw new Error(
      `Expected ${args.expectedTransactionCount} signed transactions but received ${signedTransactions.length}`,
    );
  }

  return signedTransactions.map((signedTx, index) => {
    if (!signedTx || !signedTx.transaction || !signedTx.signature) {
      throw new Error(`Incomplete signed transaction data received for transaction ${index + 1}`);
    }
    return {
      signedTransaction: new SignedTransaction({
        transaction: signedTx.transaction,
        signature: signedTx.signature,
        borsh_bytes: Array.from(signedTx.borshBytes || []),
      }),
      nearAccountId: toAccountId(args.nearAccountId),
      logs: [...(args.okResponse.payload.logs || []), ...args.warnings],
    };
  });
}

type ThresholdSigningContext = {
  resolvedSignerMode: 'threshold-signer';
  signingNearPublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
    thresholdSessionCacheKey: string;
    thresholdSessionJwt: string | undefined;
  };
};

type LocalSigningContext = {
  resolvedSignerMode: 'local-signer';
  signingNearPublicKeyStr: string;
  threshold: null;
};

type SigningContext = ThresholdSigningContext | LocalSigningContext;

function validateAndPrepareSigningContext(args: {
  nearAccountId: string;
  resolvedSignerMode: SignerMode['mode'];
  relayerUrl: string;
  rpId: string | null;
  localKeyMaterial: LocalNearSkV3Material | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material | null;
}): SigningContext {
  if (args.resolvedSignerMode !== 'threshold-signer') {
    if (!args.localKeyMaterial) {
      throw new Error(`No local key material found for account: ${args.nearAccountId}`);
    }
    const localPublicKey = String(args.localKeyMaterial.publicKey || '').trim();
    if (!localPublicKey) {
      throw new Error(`Missing local signing public key for ${args.nearAccountId}`);
    }
    return {
      resolvedSignerMode: 'local-signer',
      signingNearPublicKeyStr: localPublicKey,
      threshold: null,
    };
  }

  const thresholdKeyMaterial = args.thresholdKeyMaterial;
  if (!thresholdKeyMaterial) {
    throw new Error(`Missing threshold key material for ${args.nearAccountId}`);
  }

  const thresholdPublicKey = String(thresholdKeyMaterial.publicKey || '').trim();
  if (!thresholdPublicKey) {
    throw new Error(`Missing threshold signing public key for ${args.nearAccountId}`);
  }

  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayerUrl (required for threshold-signer)');
  }

  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold signing');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(
    thresholdKeyMaterial.participants.map((p) => p.id),
  );
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`,
    );
  }

  const thresholdSessionCacheKey = makeEd25519AuthSessionCacheKey({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId: thresholdKeyMaterial.relayerKeyId,
    participantIds,
  });

  return {
    resolvedSignerMode: 'threshold-signer',
    signingNearPublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionJwt: getCachedEd25519AuthSessionJwt(thresholdSessionCacheKey),
    },
  };
}

function requireOkSignTransactionsWithActionsResponse(
  response: TransactionResponse,
): WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions> {
  if (!isSignTransactionsWithActionsSuccess(response)) {
    if (isWorkerError(response)) {
      throw new Error(response.payload.error || 'Batch transaction signing failed');
    }
    throw new Error('Batch transaction signing failed');
  }

  if (!response.payload.success) {
    throw new Error(response.payload.error || 'Batch transaction signing failed');
  }
  return response;
}
