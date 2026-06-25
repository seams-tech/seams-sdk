import { ActionType, toActionArgsWasm } from '@/core/types/actions';
import type {
  ActionHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignTransactionHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { ActionResult, SignTransactionResult } from '@/core/types/seams';
import type { FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import type { ActionArgs, TransactionInput, TransactionInputWasm } from '@/core/types/actions';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import type { NearSigningWebContext } from '@/SeamsWeb/signingSurface/types';
import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { toError, getNearShortErrorMessage } from '@shared/utils/errors';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { emitNearSigningEvent } from './signingEventHelpers';
import { resolveNearCommandSubject } from './commandSubject';

function signedTransactionSignerId(signedTransaction: SignedTransaction): string {
  const tx = signedTransaction.transaction as { signerId?: unknown };
  const signerId = String(tx.signerId || '').trim();
  if (!signerId) {
    throw new Error('Signed transaction is missing signerId');
  }
  return signerId;
}

function assertSignedTransactionSubject(args: {
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
}): void {
  const signerId = signedTransactionSignerId(args.signedTransaction);
  if (signerId !== String(args.nearAccountId)) {
    throw new Error(
      `Signed transaction signerId ${signerId} does not match NEAR account ${String(args.nearAccountId)}`,
    );
  }
}

function assertSignedTransactionReadiness(signedTransaction: SignedTransaction): void {
  if (signedTransaction.serverDispatch || signedTransaction.nonceLease) return;
  throw new Error(
    'near.sendTransaction requires an SDK-produced signed transaction with nonce readiness',
  );
}

async function yieldForUiPaint(): Promise<void> {
  if (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function') {
    await new Promise<void>((resolve) => {
      window.requestAnimationFrame(() => resolve());
    });
    return;
  }
  await Promise.resolve();
}

/**
 * executeAction signs one transaction with actions[] to one receiver.
 *
 * @param context - SeamsWeb context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function executeAction(args: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  walletSession: WalletSessionRef;
  receiverId: AccountId;
  actionArgs: ActionArgs | ActionArgs[];
  options: ActionHooksOptions;
}): Promise<ActionResult> {
  try {
    // Thread optional per-call confirmation override when provided; otherwise
    // user preferences determine the confirmation behavior.
    return executeActionInternal({
      context: args.context,
      nearAccountId: args.nearAccountId,
      walletSession: args.walletSession,
      receiverId: args.receiverId,
      actionArgs: args.actionArgs,
      options: args.options,
      confirmationConfigOverride: args.options.confirmationConfig,
    });
  } catch (error: unknown) {
    throw toError(error);
  }
}

/**
 * Signs one transaction with actions, and broadcasts it.
 *
 * @param context - SeamsWeb context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param transactionInput - Transaction input to sign
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function signAndSendTransaction(args: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  walletSession: WalletSessionRef;
  transactionInput: TransactionInput;
  options: SignAndSendTransactionHooksOptions;
}): Promise<ActionResult> {
  return signAndSendTransactionInternal({
    context: args.context,
    nearAccountId: args.nearAccountId,
    walletSession: args.walletSession,
    transactionInput: args.transactionInput,
    options: args.options,
    confirmationConfigOverride: args.options.confirmationConfig,
  });
}

/**
 * Signs one transaction with actions, without broadcasting it.
 *
 * @param context - SeamsWeb context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function signTransactionWithActions(args: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  walletSession: WalletSessionRef;
  transactionInput: TransactionInput;
  options: SignTransactionHooksOptions;
}): Promise<SignTransactionResult> {
  try {
    return signTransactionWithActionsInternal({
      context: args.context,
      nearAccountId: args.nearAccountId,
      walletSession: args.walletSession,
      transactionInput: args.transactionInput,
      options: args.options,
      confirmationConfigOverride: args.options.confirmationConfig,
      // Public API always uses undefined override (respects user settings)
    });
  } catch (error: unknown) {
    throw toError(error);
  }
}

/**
 * 3. Transaction Broadcasting - Broadcasts the signed transaction to NEAR network
 * This method broadcasts a previously signed transaction and waits for execution
 *
 * @param context - SeamsWeb context
 * @param signedTransaction - The signed transaction to broadcast
 * @param waitUntil - The execution status to wait for (defaults to FINAL)
 * @returns Promise resolving to the transaction execution outcome
 *
 * @example
 * ```typescript
 * // Sign a transaction first
 * const signedTransaction = await signTransactionWithActions(context, 'alice.near', {
 *   transaction: {
 *     receiverId: 'bob.near',
 *     actions: [{
 *       type: ActionType.Transfer,
 *       amount: '1000000000000000000000000'
 *     }],
 *   }
 * });
 *
 * // Then broadcast it
 * const result = await sendTransaction(
 *   context,
 *   signedTransaction.signedTransaction,
 *   TxExecutionStatus.FINAL
 * );
 * ```
 *
 * sendTransaction centrally reports nonce lifecycle for transactions produced by
 * the coordinator-backed signing flow. Direct broadcast requires the nonce lease
 * created during confirmation; server-dispatched results are returned without
 * rebroadcasting.
 */
export async function sendTransaction({
  context,
  nearAccountId,
  walletSession,
  signedTransaction,
  options,
}: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  walletSession: WalletSessionRef;
  signedTransaction: SignedTransaction;
  options?: SendTransactionHooksOptions;
}): Promise<ActionResult> {
  const commandSubject = resolveNearCommandSubject({ nearAccountId, walletSession });
  const accountId = commandSubject.nearAccount.accountId;
  assertSignedTransactionSubject({ signedTransaction, nearAccountId: accountId });
  assertSignedTransactionReadiness(signedTransaction);
  const nonceLease = signedTransaction.nonceLease;
  emitNearSigningEvent(options?.onEvent, accountId, {
    phase: SigningEventPhase.STEP_12_BROADCAST_STARTED,
    status: 'running',
    interaction: { kind: 'none', overlay: 'none' },
  });

  let transactionResult;
  let txId;
  try {
    if (signedTransaction.serverDispatch) {
      transactionResult = signedTransaction.serverDispatch.rpcResult as FinalExecutionOutcome;
      txId = signedTransaction.serverDispatch.transactionHash;
      if (nonceLease) {
        await context.signingEngine.getNonceCoordinator().markBroadcastAccepted({
          leaseId: nonceLease.leaseId,
          operationId: nonceLease.operationId,
          operationFingerprint: nonceLease.operationFingerprint,
          txHash: txId,
        });
        await context.signingEngine.getNonceCoordinator().markFinalized({
          leaseId: nonceLease.leaseId,
          operationId: nonceLease.operationId,
          operationFingerprint: nonceLease.operationFingerprint,
          txHash: txId,
        });
      }
      emitNearSigningEvent(options?.onEvent, accountId, {
        phase: SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
        status: 'succeeded',
        message: `Transaction ${txId} sent successfully`,
        interaction: { kind: 'none', overlay: 'none' },
        data: { txId },
      });
      emitNearSigningEvent(options?.onEvent, accountId, {
        phase: SigningEventPhase.STEP_15_COMPLETED,
        status: 'succeeded',
        message: `Transaction ${txId} completed`,
        interaction: { kind: 'none', overlay: 'none' },
        data: { txId },
      });
      return {
        success: true,
        transactionId: txId,
        result: transactionResult,
      };
    }

    // Debug snapshot of the signed transaction shape to aid integration debugging.
    try {
      const st: unknown = signedTransaction;
      const stObj = st && typeof st === 'object' ? (st as Record<string, unknown>) : null;
      const snapshot = {
        type: typeof st,
        keys: stObj ? Object.keys(stObj) : null,
        hasBase64Encode: typeof stObj?.base64Encode === 'function',
        hasEncode: typeof stObj?.encode === 'function',
        hasSnakeBytes: !!stObj?.borsh_bytes,
        hasCamelBytes: !!stObj?.borshBytes,
      };
      console.debug('[sendTransaction] signedTransaction snapshot', snapshot);
    } catch {
      // best-effort logging only
    }

    transactionResult = await context.nearClient.sendTransaction(
      signedTransaction,
      options?.waitUntil,
    );
    txId = transactionResult.transaction?.hash || transactionResult.transaction?.id;

    if (nonceLease) {
      await context.signingEngine.getNonceCoordinator().markBroadcastAccepted({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        operationFingerprint: nonceLease.operationFingerprint,
        ...(txId ? { txHash: txId } : {}),
      });
      await context.signingEngine.getNonceCoordinator().markFinalized({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        operationFingerprint: nonceLease.operationFingerprint,
        ...(txId ? { txHash: txId } : {}),
      });
    }

    emitNearSigningEvent(options?.onEvent, accountId, {
      phase: SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
      status: 'succeeded',
      message: `Transaction ${txId} sent successfully`,
      interaction: { kind: 'none', overlay: 'none' },
      ...(txId ? { data: { txId } } : {}),
    });
    emitNearSigningEvent(options?.onEvent, accountId, {
      phase: SigningEventPhase.STEP_15_COMPLETED,
      status: 'succeeded',
      message: `Transaction ${txId} completed`,
      interaction: { kind: 'none', overlay: 'none' },
      ...(txId ? { data: { txId } } : {}),
    });
  } catch (error: unknown) {
    const e = toError(error);
    console.error('[sendTransaction] failed:', e);
    const details = (e as { details?: unknown }).details;
    if (details) {
      // Surface full details at error level for visibility during debugging
      console.error('[sendTransaction] RPC error details:', details);
    }
    try {
      if (nonceLease) {
        await context.signingEngine.getNonceCoordinator().markBroadcastRejected({
          leaseId: nonceLease.leaseId,
          operationId: nonceLease.operationId,
          operationFingerprint: nonceLease.operationFingerprint,
          error: e,
        });
      }
    } catch (nonceError) {
      console.warn('[sendTransaction]: Failed to release nonce after failure:', nonceError);
    }
    emitNearSigningEvent(options?.onEvent, accountId, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      interaction: { kind: 'none', overlay: 'hide' },
      error: { message: e.message },
    });
    throw e;
  }

  return {
    success: true,
    transactionId: txId,
    result: transactionResult,
  };
}

//////////////////////////////
// === INTERNAL API ===
//////////////////////////////

/**
 * Internal API for executing actions with optional confirmation override
 * @internal - Only used by internal SDK components like SecureTxConfirmButton
 *
 * @param context - SeamsWeb context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function executeActionInternal({
  context,
  nearAccountId,
  walletSession,
  receiverId,
  actionArgs,
  options,
  confirmationConfigOverride,
}: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  walletSession: WalletSessionRef;
  receiverId: AccountId;
  actionArgs: ActionArgs | ActionArgs[];
  options?: ActionHooksOptions;
  // Accept partial override and merge later in confirm flow
  confirmationConfigOverride?: Partial<ConfirmationConfig> | undefined;
}): Promise<ActionResult> {
  const { onEvent, onError, afterCall, waitUntil } = options || {};
  const confirmerText = options?.confirmerText;
  const actions = Array.isArray(actionArgs) ? actionArgs : [actionArgs];

  try {
    const signedTx = await signTransactionWithActionsInternal({
      context,
      nearAccountId,
      walletSession,
      transactionInput: {
        receiverId,
        actions,
      },
      options: { onEvent, onError, waitUntil, confirmerText },
      confirmationConfigOverride,
    });

    const txResult = await sendTransaction({
      context,
      nearAccountId,
      walletSession,
      signedTransaction: signedTx.signedTransaction,
      options: { onEvent, onError, waitUntil },
    });
    afterCall?.(true, txResult);
    return txResult;
  } catch (error: unknown) {
    console.error('[executeAction] Error during execution:', error);
    const e = toError(error);
    const details = (e as { details?: unknown }).details;
    const short = (e as { short?: string }).short || getNearShortErrorMessage(e);
    onError?.(e);
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      message: `Action failed: ${short || e.message}`,
      interaction: { kind: 'none', overlay: 'hide' },
      error: { message: short || e.message },
    });
    const result: ActionResult = {
      success: false,
      error: e.message,
      // propagate structured RPC details when present so UIs can render helpful errors
      errorDetails: details,
    };
    afterCall?.(false, undefined, e);
    return result;
  }
}

export async function signAndSendTransactionInternal({
  context,
  nearAccountId,
  walletSession,
  transactionInput,
  options,
  confirmationConfigOverride,
}: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  walletSession: WalletSessionRef;
  transactionInput: TransactionInput;
  options?: SignAndSendTransactionHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig> | undefined;
}): Promise<ActionResult> {
  try {
    const signedTx = await signTransactionWithActionsInternal({
      context,
      nearAccountId,
      walletSession,
      transactionInput,
      options,
      confirmationConfigOverride,
    });

    const txResult = await sendTransaction({
      context,
      nearAccountId,
      walletSession,
      signedTransaction: signedTx.signedTransaction,
      options: {
        onEvent: options?.onEvent,
        waitUntil: options?.waitUntil,
      },
    });
    return txResult;
  } catch (error: unknown) {
    const e = toError(error);
    const short = (e as { short?: string }).short || getNearShortErrorMessage(e) || e.message;
    emitNearSigningEvent(options?.onEvent, nearAccountId, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      message: `Action failed: ${short}`,
      interaction: { kind: 'none', overlay: 'hide' },
      error: { message: short },
    });
    options?.onError?.(e);
    throw e;
  }
}

/**
 * Internal API for signing transactions with actions
 * @internal - Only used by internal SDK components with confirmationConfigOverride
 *
 * @param context - SeamsWeb context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function signTransactionWithActionsInternal({
  context,
  nearAccountId,
  walletSession,
  transactionInput,
  options,
  confirmationConfigOverride,
}: {
  context: NearSigningWebContext;
  nearAccountId: AccountId;
  walletSession: WalletSessionRef;
  transactionInput: TransactionInput;
  options?: Omit<ActionHooksOptions, 'afterCall'>;
  confirmationConfigOverride?: Partial<ConfirmationConfig> | undefined;
}): Promise<SignTransactionResult> {
  const { onEvent, onError, waitUntil, confirmerText, signerSlot } = options || {};

  try {
    // Emit started event
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_01_STARTED,
      status: 'started',
      message: `Starting ${transactionInput.actions[0].type} action`,
      interaction: { kind: 'none', overlay: 'none' },
    });

    // 1. Basic validation (NEAR data fetching moved to confirmation flow)
    await validateInputsOnly(nearAccountId, [transactionInput], {
      onEvent,
      onError,
      waitUntil,
    });

    // 2. Transaction signing. The signing engine owns confirmation/auth events.
    await yieldForUiPaint();

    const transactionInputWasm: TransactionInputWasm = {
      receiverId: transactionInput.receiverId,
      actions: transactionInput.actions.map((action) => toActionArgsWasm(action)),
    };

    // WebAuthn challenge digest and NEAR data are computed in the confirmation flow
    // - Nonce will be fetched within the confirmation flow
    // This eliminates the ~500ms blocking operations before modal display
    const results = (await context.signingEngine.signNear({
      chain: 'near',
      kind: 'transactionWithActions',
      args: {
        commandSubject: resolveNearCommandSubject({ nearAccountId, walletSession }),
        transaction: transactionInputWasm,
        rpcCall: {
          nearRpcUrl: resolvePrimaryNearRpcUrl(context.configs.network.chains),
          nearAccountId: nearAccountId, // caller account
        },
        signerSlot,
        confirmationConfigOverride: confirmationConfigOverride,
        title: confirmerText?.title,
        body: confirmerText?.body,
        onEvent,
      },
    })) as SignTransactionResult;
    if (!results?.signedTransaction) {
      throw new Error('NEAR signing returned no signed transaction');
    }
    return results;
  } catch (error: unknown) {
    console.error('[signTransactionWithActions] Error during execution:', error);
    const e = toError(error);
    const short = (e as { short?: string }).short || getNearShortErrorMessage(e) || e.message;
    onError?.(e);
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      message: `Action failed: ${short}`,
      interaction: { kind: 'none', overlay: 'hide' },
      error: { message: short },
    });
    throw e;
  }
}

async function validateInputsOnly(
  nearAccountId: AccountId,
  transactionInputs: TransactionInput[],
  options?: Omit<ActionHooksOptions, 'afterCall'>,
): Promise<void> {
  const { onEvent } = options || {};

  // Basic validation
  if (!nearAccountId) {
    throw new Error('User not logged in or NEAR account ID not set for direct action.');
  }

  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_02_REQUEST_PREPARED,
    status: 'running',
    message: 'Validating inputs',
    interaction: { kind: 'none', overlay: 'none' },
  });

  if (transactionInputs.length === 0) {
    throw new Error('No payloads provided for signing');
  }
  if (transactionInputs.length !== 1) {
    throw new Error(
      `NEAR signing supports exactly one transaction per operation; received ${transactionInputs.length}`,
    );
  }

  for (const transactionInput of transactionInputs) {
    if (!transactionInput.receiverId) {
      throw new Error('Missing required parameter: receiverId');
    }
    for (const action of transactionInput.actions) {
      if (
        action.type === ActionType.FunctionCall &&
        (!action.methodName || action.args === undefined)
      ) {
        throw new Error('Missing required parameters for function call: methodName or args');
      }
      if (action.type === ActionType.Transfer && !action.amount) {
        throw new Error('Missing required parameter for transfer: amount');
      }
    }
  }
}
