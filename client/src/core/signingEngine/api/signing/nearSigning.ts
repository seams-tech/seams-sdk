import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { onProgressEvents } from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  SignerMode,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { SignTransactionResult } from '@/core/types/tatchi';
import type { TransactionInputWasm } from '@/core/types/actions';
import type {
  NearIntentResult,
  NearSigningRequest,
} from '../../interfaces/near';
import type { SignerWorkerManagerContext } from '../../workers/signerWorkerManager';

export type ResolveSigningSessionPolicyArgs = { ttlMs?: number; remainingUses?: number };
export type ResolveSigningSessionPolicyResult = { ttlMs: number; remainingUses: number };

export type SignDelegateActionResult = {
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
};

export type SignNep413MessagePayload = {
  message: string;
  recipient: string;
  nonce: string;
  state: string | null;
  accountId: AccountId;
  signerMode: SignerMode;
  deviceNumber?: number;
  title?: string;
  body?: string;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type SignNep413MessageResult = {
  success: boolean;
  accountId: string;
  publicKey: string;
  signature: string;
  state?: string;
  error?: string;
};

export type NearSigningApiDeps = {
  contractId: string;
  nearRpcUrl: string;
  resolveSigningSessionPolicy: (
    args: ResolveSigningSessionPolicyArgs,
  ) => ResolveSigningSessionPolicyResult;
  getOrCreateActiveSigningSessionId: (nearAccountId: AccountId) => string;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  signNearWithIntent: <TRequest extends NearSigningRequest>(
    request: TRequest,
  ) => Promise<NearIntentResult<TRequest>>;
};

export async function signTransactionsWithActions(
  deps: NearSigningApiDeps,
  args: {
    transactions: TransactionInputWasm[];
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
    signerMode: SignerMode;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
    sessionId?: string;
  },
): Promise<SignTransactionResult[]> {
  const signingSessionPolicy = deps.resolveSigningSessionPolicy({});
  const resolvedSessionId =
    String(args.sessionId || '').trim() ||
    deps.getOrCreateActiveSigningSessionId(toAccountId(args.rpcCall.nearAccountId));
  const ctx = deps.getSignerWorkerContext();
  return await deps.signNearWithIntent({
    chain: 'near',
    kind: 'transactionsWithActions',
    payload: {
      ctx,
      transactions: args.transactions,
      rpcCall: args.rpcCall,
      deviceNumber: args.deviceNumber,
      signerMode: args.signerMode,
      confirmationConfigOverride: args.confirmationConfigOverride,
      title: args.title,
      body: args.body,
      onEvent: args.onEvent,
      signingSessionTtlMs: signingSessionPolicy.ttlMs,
      signingSessionRemainingUses: signingSessionPolicy.remainingUses,
      sessionId: resolvedSessionId,
    },
  }) as unknown as SignTransactionResult[];
}

export async function signDelegateAction(
  deps: NearSigningApiDeps,
  args: {
    delegate: DelegateActionInput;
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
    signerMode: SignerMode;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
  },
): Promise<SignDelegateActionResult> {
  const nearAccountId = toAccountId(args.rpcCall.nearAccountId || args.delegate.senderId);
  const signingSessionPolicy = deps.resolveSigningSessionPolicy({});
  const normalizedRpcCall: RpcCallPayload = {
    contractId: args.rpcCall.contractId || deps.contractId,
    nearRpcUrl: args.rpcCall.nearRpcUrl || deps.nearRpcUrl,
    nearAccountId,
  };

  try {
    const activeSessionId = deps.getOrCreateActiveSigningSessionId(nearAccountId);
    console.debug('[SigningEngine][delegate] session created', { sessionId: activeSessionId });
    const ctx = deps.getSignerWorkerContext();
    return await deps.signNearWithIntent({
      chain: 'near',
      kind: 'delegateAction',
      payload: {
        ctx,
        delegate: args.delegate,
        rpcCall: normalizedRpcCall,
        deviceNumber: args.deviceNumber,
        signerMode: args.signerMode,
        confirmationConfigOverride: args.confirmationConfigOverride,
        title: args.title,
        body: args.body,
        onEvent: args.onEvent,
        signingSessionTtlMs: signingSessionPolicy.ttlMs,
        signingSessionRemainingUses: signingSessionPolicy.remainingUses,
        sessionId: activeSessionId,
      },
    }) as unknown as SignDelegateActionResult;
  } catch (err) {
    console.error('[SigningEngine][delegate] failed', err);
    throw err;
  }
}

export async function signNEP413Message(
  deps: NearSigningApiDeps,
  payload: SignNep413MessagePayload,
): Promise<SignNep413MessageResult> {
  try {
    const activeSessionId = deps.getOrCreateActiveSigningSessionId(payload.accountId);
    const signingSessionPolicy = deps.resolveSigningSessionPolicy({});
    const nearRpcUrl = deps.nearRpcUrl.split(',')[0] || deps.nearRpcUrl;
    const ctx = deps.getSignerWorkerContext();
    const result = await deps.signNearWithIntent({
      chain: 'near',
      kind: 'nep413',
      payload: {
        ctx,
        payload: {
          ...payload,
          sessionId: activeSessionId,
          contractId: deps.contractId,
          nearRpcUrl,
          signingSessionTtlMs: signingSessionPolicy.ttlMs,
          signingSessionRemainingUses: signingSessionPolicy.remainingUses,
        },
      },
    }) as unknown as SignNep413MessageResult;
    if (result.success) {
      return result;
    }
    throw new Error(`NEP-413 signing failed: ${result.error || 'Unknown error'}`);
  } catch (error: unknown) {
    console.error('SigningEngine: NEP-413 signing error:', error);
    const message = error instanceof Error ? error.message : String(error || 'Unknown error');
    return {
      success: false,
      accountId: '',
      publicKey: '',
      signature: '',
      error: message,
    };
  }
}
