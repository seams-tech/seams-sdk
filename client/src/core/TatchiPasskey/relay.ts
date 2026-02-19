import { ActionPhase, ActionStatus, type ActionSSEEvent, type DelegateRelayHooksOptions } from '../types/sdkSentEvents';
import type { DelegateRelayResult } from '../types/tatchi';
import type { SignedDelegate } from '../types/delegate';
import type { WasmSignedDelegate } from '../types/signer-worker';
import { isObject } from '@shared/utils/validation';

export interface RelayDelegateRequest {
  hash: string;
  signedDelegate: SignedDelegate | WasmSignedDelegate;
}

const toNumberArray = (value: number[] | Uint8Array): number[] =>
  Array.isArray(value) ? value : Array.from(value);

const normalizeSignedDelegateForRelay = (
  signedDelegate: SignedDelegate | WasmSignedDelegate
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
