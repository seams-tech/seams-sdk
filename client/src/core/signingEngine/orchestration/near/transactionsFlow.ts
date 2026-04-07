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
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import {
  clearCachedEd25519AuthSession,
  getCachedEd25519AuthSession,
  getCachedEd25519AuthSessionJwt,
  makeEd25519AuthSessionCacheKey,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';
import {
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { executeWorkerOperation } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { clearSigningSessionPrfFirstBestEffort } from '@/core/signingEngine/api/session/signingSessionState';
import { getStoredThresholdEd25519SessionRecordByThresholdSessionId } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  generateSessionId,
  requirePrfFirstFromCredential,
  resolveNearSigningMaterials,
  toCredentialForRelayJson,
} from './shared/signingMaterials';
import {
  resolveCanonicalThresholdSessionId,
  resolveThresholdSessionAuth,
} from './shared/thresholdSessionAuth';
import { buildNearWorkerSigningEnvelope } from './shared/workerRequestAssembly';
import { resolveNearThresholdSigningAuthPlan } from './shared/thresholdAuthMode';
import { ensureThresholdEd25519HssClientBase } from './shared/ensureThresholdEd25519HssClientBase';
import { repairThresholdEd25519MissingRelayerKey } from './shared/repairThresholdEd25519MissingRelayerKey';
import { ActionPhase, ActionStatus } from '@/core/types/sdkSentEvents';

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
  const signingStartedAt = performance.now();
  onEvent?.({
    step: 2,
    phase: ActionPhase.STEP_2_USER_CONFIRMATION,
    status: ActionStatus.PROGRESS,
    message: 'Loading threshold signing state...',
  });
  const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
    ctx,
    nearAccountId,
    deviceNumber,
    operationLabel: 'signing',
    warnings,
  });
  console.debug('[SigningEngine][near][transactions] signing materials resolved', {
    nearAccountId,
    durationMs: Math.round(performance.now() - signingStartedAt),
  });
  console.debug('[signTransactionsWithActions] threshold signing', {
    nearAccountId,
    warnings,
  });

  const signingContext = validateAndPrepareSigningContext({
    nearAccountId,
    relayerUrl,
    rpId: ctx.touchIdPrompt.getRpId(),
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
    nearRpcUrl:
      rpcCall.nearRpcUrl ||
      resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains),
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
  const thresholdAuthPlan = signingContext.threshold
    ? await resolveNearThresholdSigningAuthPlan({
        touchConfirm,
        sessionId,
        usesNeeded,
        nearAccountId,
        operationLabel: 'transaction signing',
      })
    : null;
  onEvent?.({
    step: 2,
    phase: ActionPhase.STEP_2_USER_CONFIRMATION,
    status: ActionStatus.PROGRESS,
    message: 'Opening confirmation prompt...',
  });
  const signingAuthMode = thresholdAuthPlan?.signingAuthMode;
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

  const credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
    confirmation.credential as WebAuthnAuthenticationCredential | undefined;

  const credentialForRelayJson = toCredentialForRelayJson(credentialWithPrf);

  const prfFirstB64u = signingContext.threshold
    ? thresholdAuthPlan?.warmSessionReady
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
      : requirePrfFirstFromCredential(credentialWithPrf)
    : requirePrfFirstFromCredential(credentialWithPrf);

  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output for signing');
  }

  // Threshold signer: authorize with relayer and pass threshold config into the signer worker.
  const canonicalThresholdSessionId = resolveCanonicalThresholdSessionId({
    thresholdSessionCacheKey: signingContext.threshold.thresholdSessionCacheKey,
    fallbackSessionId: sessionId,
  });
  if (
    (signingContext.threshold.thresholdSessionKind === 'jwt' &&
      !signingContext.threshold.thresholdSessionJwt) ||
    signingContext.threshold.thresholdSessionKind === 'cookie'
  ) {
    const auth = await resolveThresholdSessionAuth({
      thresholdSessionCacheKey: signingContext.threshold.thresholdSessionCacheKey,
      thresholdSessionId: canonicalThresholdSessionId,
    });
    if (auth) {
      signingContext.threshold.thresholdSessionKind = auth.sessionKind;
      signingContext.threshold.thresholdSessionJwt = auth.thresholdSessionJwt;
    }
  }
  if (
    signingContext.threshold.thresholdSessionKind === 'jwt' &&
    !signingContext.threshold.thresholdSessionJwt
  ) {
    clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
    throw new Error(
      '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
    );
  }
  const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
    ...(onEvent
      ? {
          onProgress: (message: string) => {
            onEvent({
              step: 4,
              phase: ActionPhase.STEP_4_AUTHENTICATION_COMPLETE,
              status: ActionStatus.PROGRESS,
              message,
            });
          },
        }
      : {}),
    ctx,
    thresholdSessionId: canonicalThresholdSessionId,
    thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
    relayerUrl: signingContext.threshold.relayerUrl,
    relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
    nearAccountId,
    keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
    participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
    prfFirstB64u,
  });
  console.debug('[SigningEngine][near][transactions] threshold client base ready', {
    nearAccountId,
    thresholdSessionId: canonicalThresholdSessionId,
    durationMs: Math.round(performance.now() - signingStartedAt),
  });
  const buildRequestPayload = (
    xClientBaseOverride?: string,
  ): Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'> => ({
    rpcCall: resolvedRpcCall,
    createdAt: Date.now(),
    ...buildNearWorkerSigningEnvelope({
      threshold: {
        relayerUrl: signingContext.threshold.relayerUrl,
        thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
        xClientBaseB64u:
          xClientBaseOverride ||
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(canonicalThresholdSessionId)
            ?.xClientBaseB64u,
        thresholdSessionKind: signingContext.threshold.thresholdSessionKind,
        thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
      },
    }),
    txSigningRequests,
    intentDigest,
    transactionContext,
    credential: credentialForRelayJson,
  });
  let requestPayload = buildRequestPayload(xClientBaseB64u);

  const executeSignRequest = async (
    payload: Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'>,
  ) => {
    const response = await executeWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.SignTransactionsWithActions,
        payload,
        onEvent,
      },
    });
    return requireOkSignTransactionsWithActionsResponse(response);
  };

  try {
    const okResponse = await executeSignRequest(requestPayload);
    return toSignedTransactionResults({
      okResponse,
      expectedTransactionCount: transactions.length,
      nearAccountId,
      warnings,
    });
  } catch (e: unknown) {
    const err = e instanceof Error ? e : new Error(String(e));

    if (isThresholdSignerMissingKeyError(err)) {
      try {
        const repairedXClientBaseB64u = await repairThresholdEd25519MissingRelayerKey({
          ctx,
          operationLabel: 'transactions',
          thresholdSessionId: canonicalThresholdSessionId,
          thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
          relayerUrl: signingContext.threshold.relayerUrl,
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          nearAccountId,
          keyVersion: signingContext.threshold.thresholdKeyMaterial.keyVersion,
          participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
            (p) => p.id,
          ),
          prfFirstB64u,
          ...(onEvent
            ? {
                onProgress: (message: string) => {
                  onEvent({
                    step: 4,
                    phase: ActionPhase.STEP_4_AUTHENTICATION_COMPLETE,
                    status: ActionStatus.PROGRESS,
                    message,
                  });
                },
              }
            : {}),
        });
        requestPayload = buildRequestPayload(repairedXClientBaseB64u);
        const okResponse = await executeSignRequest(requestPayload);
        return toSignedTransactionResults({
          okResponse,
          expectedTransactionCount: transactions.length,
          nearAccountId,
          warnings,
        });
      } catch (repairError: unknown) {
        const repairErr =
          repairError instanceof Error ? repairError : new Error(String(repairError));
        if (isThresholdSignerMissingKeyError(repairErr)) {
          const msg =
            '[SigningEngine] threshold-signer requested but the relayer signing share could not be repaired from the active HSS session';
          console.warn(msg);
          warnings.push(msg);
          clearCachedEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          signingContext.threshold.thresholdSessionJwt = undefined;
          throw new Error(msg);
        }
        throw repairErr;
      }
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
  signingNearPublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
    thresholdSessionCacheKey: string;
    thresholdSessionKind: 'jwt' | 'cookie';
    thresholdSessionJwt: string | undefined;
  };
};

function validateAndPrepareSigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
  rpId: string | null;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
}): ThresholdSigningContext {
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
  const cachedAuthSession = getCachedEd25519AuthSession(thresholdSessionCacheKey);
  const thresholdSessionKind: 'jwt' | 'cookie' =
    cachedAuthSession?.sessionKind === 'cookie' ? 'cookie' : 'jwt';

  return {
    signingNearPublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionKind,
      thresholdSessionJwt:
        thresholdSessionKind === 'jwt'
          ? getCachedEd25519AuthSessionJwt(thresholdSessionCacheKey)
          : undefined,
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
