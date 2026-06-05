import type { NearSigningWebContext } from '@/web/SeamsWeb/signingSurface/types';
import type { DelegateActionInput, SignedDelegate } from '@/core/types/delegate';
import type {
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
} from '@/core/types/sdkSentEvents';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { DelegateRelayResult, SignDelegateActionResult } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { toError } from '@shared/utils/errors';
import type { WasmSignedDelegate } from '@/core/types/signer-worker';
import { isObject } from '@shared/utils/validation';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { nearAccountRefFromAccountId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { emitNearSigningEvent } from './signingEventHelpers';

async function yieldForUiPaint(): Promise<void> {
  if (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function') {
    await new Promise<void>((resolve) => {
      window.requestAnimationFrame(() => resolve());
    });
    return;
  }
  await Promise.resolve();
}

export interface RelayDelegateRequest {
  hash: string;
  signedDelegate: SignedDelegate | WasmSignedDelegate;
}

export async function signDelegateAction(args: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  delegate: DelegateActionInput;
  options: DelegateActionHooksOptions;
}): Promise<SignDelegateActionResult> {
  const { context, delegate, options } = args;
  const nearAccountId = toAccountId(String(args.nearAccountId));
  const title = options?.confirmerText?.title;
  const body = options?.confirmerText?.body;

  const resolvedDelegate: DelegateActionInput = {
    ...delegate,
    senderId: delegate.senderId || String(nearAccountId),
  };

  emitNearSigningEvent(options?.onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_01_STARTED,
    status: 'started',
    message: 'Preparing delegate action inputs',
    interaction: { kind: 'none', overlay: 'none' },
  });

  // Emit the v2 confirmation-display event before kicking off the UserConfirm-driven
  // flow so the wallet-iframe overlay can expand and allow the TxConfirmer modal
  // to capture activation.
  emitNearSigningEvent(options?.onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
    status: 'waiting_for_user',
    message: 'Requesting delegate action confirmation',
    interaction: { kind: 'transaction_confirmation', overlay: 'show' },
  });
  await yieldForUiPaint();

  try {
    const coreResult = await context.signingEngine.signNear({
      chain: 'near',
      kind: 'delegateAction',
      args: {
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        delegate: resolvedDelegate,
        rpcCall: {
          nearRpcUrl: resolvePrimaryNearRpcUrl(context.configs.network.chains),
          nearAccountId: String(nearAccountId),
        },
        signerSlot: options?.signerSlot,
        confirmationConfigOverride: options?.confirmationConfig,
        title,
        body,
        onEvent: options?.onEvent,
      },
    });

    const result: SignDelegateActionResult = {
      hash: coreResult.hash,
      signedDelegate: coreResult.signedDelegate,
      nearAccountId: String(nearAccountId),
      logs: coreResult.logs,
    };

    emitNearSigningEvent(options?.onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_15_COMPLETED,
      status: 'succeeded',
      message: 'Delegate action signed',
      interaction: { kind: 'none', overlay: 'none' },
      data: { hash: result.hash },
    });

    await options?.afterCall?.(true, result);

    return result;
  } catch (error: unknown) {
    const e = toError(error);
    options?.onError?.(e);
    await options?.afterCall?.(false);
    emitNearSigningEvent(options?.onEvent, nearAccountId, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      message: e.message,
      interaction: { kind: 'none', overlay: 'hide' },
      error: { message: e.message },
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

  const emitError = (message: string) => {
    emitNearSigningEvent(options?.onEvent, 'delegate', {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      message,
      interaction: { kind: 'none', overlay: 'hide' },
      error: { message },
    });
  };

  emitNearSigningEvent(options?.onEvent, 'delegate', {
    phase: SigningEventPhase.STEP_12_BROADCAST_STARTED,
    status: 'running',
    message: 'Submitting delegate to relayer',
    interaction: { kind: 'none', overlay: 'none' },
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
    relayerTxHash:
      typeof json.relayerTxHash === 'string'
        ? json.relayerTxHash
        : typeof json.transactionId === 'string'
          ? json.transactionId
          : typeof json.txHash === 'string'
            ? json.txHash
            : undefined,
    status: typeof json.status === 'string' ? json.status : undefined,
    outcome: json.outcome,
    error: typeof json.error === 'string' ? json.error : undefined,
  };

  const success = response.ok !== false;
  if (success) {
    emitNearSigningEvent(options?.onEvent, 'delegate', {
      phase: SigningEventPhase.STEP_15_COMPLETED,
      status: 'succeeded',
      message: 'Delegate relayed successfully',
      interaction: { kind: 'none', overlay: 'none' },
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
