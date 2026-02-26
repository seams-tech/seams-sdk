import type { PasskeyManagerContext } from '../index';
import type { DelegateActionInput, SignedDelegate } from '../../types/delegate';
import type {
  ActionSSEEvent,
  DelegateActionSSEEvent,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
} from '../../types/sdkSentEvents';
import type { DelegateRelayResult, SignDelegateActionResult } from '../../types/tatchi';
import type { AccountId } from '../../types/accountIds';
import { ActionPhase, ActionStatus } from '../../types/sdkSentEvents';
import { toAccountId } from '../../types/accountIds';
import { toError } from '@shared/utils/errors';
import { mergeSignerMode, type WasmSignedDelegate } from '../../types/signer-worker';
import { isObject } from '@shared/utils/validation';
import { resolvePrimaryNearRpcUrl } from '../../config/chains';

export interface RelayDelegateRequest {
  hash: string;
  signedDelegate: SignedDelegate | WasmSignedDelegate;
}


export async function signDelegateAction(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
  delegate: DelegateActionInput;
  options: DelegateActionHooksOptions;
}): Promise<SignDelegateActionResult> {
  const { context, delegate, options } = args;
  const nearAccountId = toAccountId(String(args.nearAccountId));
  const title = options?.confirmerText?.title;
  const body = options?.confirmerText?.body;
  const base = context.signingEngine.getUserPreferences().getSignerMode();
  const signerMode = mergeSignerMode(base, options.signerMode);

  const resolvedDelegate: DelegateActionInput = {
    ...delegate,
    senderId: delegate.senderId || String(nearAccountId),
  };

  options?.onEvent?.({
    step: 1,
    phase: ActionPhase.STEP_1_PREPARATION,
    status: ActionStatus.PROGRESS,
    message: 'Preparing delegate action inputs',
  });

  // Emit a user-confirmation phase before kicking off the UserConfirm-driven
  // confirmation flow so the wallet-iframe overlay can expand and allow
  // the TxConfirmer modal to capture activation.
  options?.onEvent?.({
    step: 2,
    phase: ActionPhase.STEP_2_USER_CONFIRMATION,
    status: ActionStatus.PROGRESS,
    message: 'Requesting delegate action confirmation…',
  });

  try {
    const coreResult = await context.signingEngine.signNear({
      chain: 'near',
      kind: 'delegateAction',
      args: {
        delegate: resolvedDelegate,
        rpcCall: {
          nearRpcUrl: resolvePrimaryNearRpcUrl(context.configs.chains),
          nearAccountId: String(nearAccountId),
        },
        signerMode,
        deviceNumber: options?.deviceNumber,
        confirmationConfigOverride: options?.confirmationConfig,
        title,
        body,
        onEvent: options?.onEvent
          ? (ev) => options.onEvent?.(ev as DelegateActionSSEEvent)
          : undefined,
      },
    });

    const result: SignDelegateActionResult = {
      hash: coreResult.hash,
      signedDelegate: coreResult.signedDelegate,
      nearAccountId: String(nearAccountId),
      logs: coreResult.logs,
    };

    options?.onEvent?.({
      step: 8,
      phase: ActionPhase.STEP_8_ACTION_COMPLETE,
      status: ActionStatus.SUCCESS,
      message: 'Delegate action signed',
      data: { hash: result.hash },
    });

    await options?.afterCall?.(true, result);

    return result;
  } catch (error: unknown) {
    const e = toError(error);
    options?.onError?.(e);
    await options?.afterCall?.(false);
    options?.onEvent?.({
      step: 0,
      phase: ActionPhase.ACTION_ERROR,
      status: ActionStatus.ERROR,
      message: e.message,
      error: e.message,
    });
    throw e;
  }
}

const toNumberArray = (value: number[] | Uint8Array): number[] =>
  Array.isArray(value) ? value : Array.from(value);

const normalizeSignedDelegateForRelay = (
  signedDelegate: SignedDelegate | WasmSignedDelegate,
): SignedDelegate => {
  const delegateAction = signedDelegate.delegateAction as SignedDelegate['delegateAction'] & {
    publicKey: { keyType: number; keyData: number[] | Uint8Array };
  };
  const signature = signedDelegate.signature as SignedDelegate['signature'] & {
    keyType: number;
    signatureData: number[] | Uint8Array;
  };

  return {
    delegateAction: {
      ...delegateAction,
      publicKey: {
        ...delegateAction.publicKey,
        keyData: toNumberArray(delegateAction.publicKey.keyData),
      },
    },
    signature: {
      ...signature,
      signatureData: toNumberArray(signature.signatureData),
    },
  };
};

export async function sendDelegateActionViaRelayer(args: {
  url: string;
  payload: RelayDelegateRequest;
  signal?: AbortSignal;
  options?: DelegateRelayHooksOptions;
}): Promise<DelegateRelayResult> {
  const { url, payload, signal, options } = args;
  const normalizedPayload: RelayDelegateRequest = {
    ...payload,
    signedDelegate: normalizeSignedDelegateForRelay(payload.signedDelegate),
  };

  const emit = (event: ActionSSEEvent) => options?.onEvent?.(event);
  const emitError = (message: string) => {
    emit({
      step: 0,
      phase: ActionPhase.ACTION_ERROR,
      status: ActionStatus.ERROR,
      message,
      error: message,
    });
  };

  emit({
    step: 7,
    phase: ActionPhase.STEP_7_BROADCASTING,
    status: ActionStatus.PROGRESS,
    message: 'Submitting delegate to relayer...',
  });

  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(normalizedPayload),
      signal,
    });
  } catch (err: unknown) {
    const error = err instanceof Error ? err : new Error(String(err));
    options?.onError?.(error);
    emitError(error.message);
    await options?.afterCall?.(false);
    throw error;
  }

  if (!res.ok) {
    const response: DelegateRelayResult = {
      ok: false,
      error: `Relayer HTTP ${res.status}`,
    };
    options?.onError?.(new Error(response.error));
    emitError(response.error!);
    await options?.afterCall?.(false);
    return response;
  }

  let json: Record<string, unknown>;
  try {
    const parsed: unknown = await res.json();
    json = isObject(parsed) ? parsed : {};
  } catch (err: unknown) {
    const response: DelegateRelayResult = {
      ok: false,
      error: 'Relayer returned non-JSON response',
    };
    const error = err instanceof Error ? err : new Error(String(err));
    options?.onError?.(error);
    emitError(response.error!);
    await options?.afterCall?.(false);
    return response;
  }

  const response: DelegateRelayResult = {
    ok: Boolean(json.ok ?? true),
    relayerTxHash: typeof json.relayerTxHash === 'string'
      ? json.relayerTxHash
      : (typeof json.transactionId === 'string'
        ? json.transactionId
        : (typeof json.txHash === 'string' ? json.txHash : undefined)),
    status: typeof json.status === 'string' ? json.status : undefined,
    outcome: json.outcome,
    error: typeof json.error === 'string' ? json.error : undefined,
  };

  const success = response.ok !== false;
  if (success) {
    emit({
      step: 8,
      phase: ActionPhase.STEP_8_ACTION_COMPLETE,
      status: ActionStatus.SUCCESS,
      message: 'Delegate relayed successfully',
    });
    await options?.afterCall?.(true, response);
  } else {
    const message = response.error || 'Relayer execution failed';
    options?.onError?.(new Error(message));
    emitError(message);
    await options?.afterCall?.(false);
  }

  return response;
}
