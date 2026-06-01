import { ActionType, toActionArgsWasm } from '../../types/actions';
import type {
  ActionHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignTransactionHooksOptions,
} from '../../types/sdkSentEvents';
import type { ActionResult, SignTransactionResult } from '../../types/seams';
import type { TxExecutionStatus } from '@near-js/types';
import type { ActionArgs, TransactionInput, TransactionInputWasm } from '../../types/actions';
import { type ConfirmationConfig } from '../../types/signer-worker';
import type { PasskeyManagerContext } from '../index';
import type { SignedTransaction } from '../../rpcClients/near/NearClient';
import type { AccountId } from '../../types/accountIds';
import {
  SigningEventPhase,
} from '../../types/sdkSentEvents';
import { toError, getNearShortErrorMessage } from '@shared/utils/errors';
import { resolvePrimaryNearRpcUrl } from '../../config/chains';
import { nearAccountRefFromAccountId } from '../../signingEngine/interfaces/ecdsaChainTarget';
import { emitNearSigningEvent } from './signingEventHelpers';

function resolveSignedTransactionAccountId(signedTransaction: SignedTransaction): string {
  const tx = signedTransaction.transaction as { signerId?: unknown };
  return String(tx.signerId || 'unknown');
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
 * executeAction signs a single transaction (with actions[]) to a single receiver.
 * If you want to sign multiple transactions to different receivers,
 * use signTransactionsWithActions() instead.
 *
 * @param context - SeamsPasskey context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function executeAction(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
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
      receiverId: args.receiverId,
      actionArgs: args.actionArgs,
      options: args.options,
      confirmationConfigOverride: args.options.confirmationConfig,
    });
  } catch (error: unknown) {
    throw toError(error);
  }
}

// Execution plan types for broadcasting multiple transactions
// Helper: parse executionWait (only sequential for now)
function parseExecutionWait(options?: SignAndSendTransactionHooksOptions): {
  waitUntil?: TxExecutionStatus;
} {
  return { waitUntil: options?.waitUntil };
}

/**
 * Signs multiple transactions with actions, and broadcasts them
 *
 * @param context - SeamsPasskey context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param transactionInput - Transaction input to sign
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function signAndSendTransactions(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
  transactionInputs: TransactionInput[];
  options: SignAndSendTransactionHooksOptions;
}): Promise<ActionResult[]> {
  return signAndSendTransactionsInternal({
    context: args.context,
    nearAccountId: args.nearAccountId,
    transactionInputs: args.transactionInputs,
    options: args.options,
    confirmationConfigOverride: args.options.confirmationConfig,
  });
}

/**
 * Signs transactions with actions, without broadcasting them
 *
 * @param context - SeamsPasskey context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function signTransactionsWithActions(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
  transactionInputs: TransactionInput[];
  options: SignTransactionHooksOptions;
}): Promise<SignTransactionResult[]> {
  try {
    return signTransactionsWithActionsInternal({
      context: args.context,
      nearAccountId: args.nearAccountId,
      transactionInputs: args.transactionInputs,
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
 * @param context - SeamsPasskey context
 * @param signedTransaction - The signed transaction to broadcast
 * @param waitUntil - The execution status to wait for (defaults to FINAL)
 * @returns Promise resolving to the transaction execution outcome
 *
 * @example
 * ```typescript
 * // Sign a transaction first
 * const signedTransactions = await signTransactionsWithActions(context, 'alice.near', {
 *   transactions: [{
 *     nearAccountId: 'alice.near',
 *     receiverId: 'bob.near',
 *     actions: [{
 *       action_type: ActionType.Transfer,
 *       deposit: '1000000000000000000000000'
 *     }],
 *     nonce: '123'
 *   }]
 * });
 *
 * // Then broadcast it
 * const result = await sendTransaction(
 *   context,
 *   signedTransactions[0].signedTransaction,
 *   TxExecutionStatus.FINAL
 * );
 * ```
 *
 * sendTransaction centrally reports nonce lifecycle for transactions produced by
 * the coordinator-backed signing flow. Transactions without a nonce lease are
 * treated as externally managed; there is no local reservation to reconcile.
 */
export async function sendTransaction({
  context,
  signedTransaction,
  options,
}: {
  context: PasskeyManagerContext;
  signedTransaction: SignedTransaction;
  options?: SendTransactionHooksOptions;
}): Promise<ActionResult> {
  const accountId = resolveSignedTransactionAccountId(signedTransaction);
  const nonceLease = signedTransaction.nonceLease;
  emitNearSigningEvent(options?.onEvent, accountId, {
    phase: SigningEventPhase.STEP_12_BROADCAST_STARTED,
    status: 'running',
    interaction: { kind: 'none', overlay: 'none' },
  });

  let transactionResult;
  let txId;
  try {
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
 * @param context - SeamsPasskey context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function executeActionInternal({
  context,
  nearAccountId,
  receiverId,
  actionArgs,
  options,
  confirmationConfigOverride,
}: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
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
    const signedTxs = await signTransactionsWithActionsInternal({
      context,
      nearAccountId,
      transactionInputs: [
        {
          receiverId: receiverId,
          actions: actions,
        },
      ],
      options: { onEvent, onError, waitUntil, confirmerText },
      confirmationConfigOverride,
    });

    const txResult = await sendTransaction({
      context,
      signedTransaction: signedTxs[0].signedTransaction,
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
      transactionId: undefined,
    };
    afterCall?.(false);
    return result;
  }
}

export async function signAndSendTransactionsInternal({
  context,
  nearAccountId,
  transactionInputs,
  options,
  confirmationConfigOverride,
}: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
  transactionInputs: TransactionInput[];
  options?: SignAndSendTransactionHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig> | undefined;
}): Promise<ActionResult[]> {
  try {
    const signedTxs = await signTransactionsWithActionsInternal({
      context,
      nearAccountId,
      transactionInputs,
      options,
      confirmationConfigOverride,
    });

    const plan = parseExecutionWait(options);
    const txResults: ActionResult[] = [];
    for (let i = 0; i < signedTxs.length; i++) {
      const tx = signedTxs[i];
      const txResult = await sendTransaction({
        context,
        signedTransaction: tx.signedTransaction,
        options: {
          onEvent: options?.onEvent,
          waitUntil: plan.waitUntil ?? options?.waitUntil,
        },
      });
      txResults.push(txResult);
    }
    return txResults;
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
 * @param context - SeamsPasskey context
 * @param nearAccountId - NEAR account ID to sign transactions with
 * @param actionArgs - Action arguments to sign transactions with
 * @param options - Options for the action
 * @returns Promise resolving to the action result
 */
export async function signTransactionsWithActionsInternal({
  context,
  nearAccountId,
  transactionInputs,
  options,
  confirmationConfigOverride,
}: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
  transactionInputs: TransactionInput[];
  options?: Omit<ActionHooksOptions, 'afterCall'>;
  confirmationConfigOverride?: Partial<ConfirmationConfig> | undefined;
}): Promise<SignTransactionResult[]> {
  const { onEvent, onError, waitUntil, confirmerText, signerSlot } = options || {};

  try {
    // Emit started event
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_01_STARTED,
      status: 'started',
      message:
        transactionInputs.length > 1
          ? `Starting batched transaction with ${transactionInputs.length} actions`
          : `Starting ${transactionInputs[0].actions[0].type} action`,
      interaction: { kind: 'none', overlay: 'none' },
    });

    // 1. Basic validation (NEAR data fetching moved to confirmation flow)
    await validateInputsOnly(nearAccountId, transactionInputs, { onEvent, onError, waitUntil });

    // 2. UserConfirm/WebAuthn + transaction signing (NEAR data fetched in confirmation flow)
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      message: 'Requesting user confirmation',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
    });
    await yieldForUiPaint();

    // Convert all actions to ActionArgsWasm format for batched transaction
    const transactionInputsWasm: TransactionInputWasm[] = transactionInputs.map((tx) => {
      return {
        receiverId: tx.receiverId,
        actions: tx.actions.map((action) => toActionArgsWasm(action)),
      };
    });

    // WebAuthn challenge digest and NEAR data are computed in the confirmation flow
    // - Nonce will be fetched within the confirmation flow
    // This eliminates the ~500ms blocking operations before modal display
    return (await context.signingEngine.signNear({
      chain: 'near',
      kind: 'transactionsWithActions',
      args: {
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        transactions: transactionInputsWasm,
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
    })) as SignTransactionResult[];
  } catch (error: unknown) {
    console.error('[signTransactionsWithActions] Error during execution:', error);
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
