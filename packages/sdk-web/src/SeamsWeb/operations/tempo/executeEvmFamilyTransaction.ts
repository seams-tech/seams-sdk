import { chainFamilyFromNetwork } from '@/core/config/chains';
import { createEvmClient, type EvmTransactionByHash } from '@/core/rpcClients/evm/EvmClient';
import type { SeamsChainConfig } from '@/core/types/seams';
import {
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ExecuteEvmFamilyTransactionArgs,
  ExecuteEvmFamilyTransactionResult,
  FinalizedEvmEip1559PayloadExpectation,
  FinalizedTempoEip2718PayloadExpectation,
  FinalizedEvmTxPayloadExpectation,
  FinalizedEvmTxPayloadObservation,
  FinalizedEvmTxPayloadVerification,
  ReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs,
  SignTempoArgs,
  TempoNonceLifecycleEvent,
} from '@/SeamsWeb/signingSurface/types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
} from '@/core/types/sdkSentEvents';

type TempoLifecycleDeps = {
  signTempo(args: SignTempoArgs): Promise<TempoSignedResult | EvmSignedResult>;
  reportBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void>;
  reportBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void>;
  reportFinalized(args: ReportTempoFinalizedArgs): Promise<void>;
  reportDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void>;
  reconcileNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<unknown>;
};

const DEFAULT_FINALIZATION_TIMEOUT_MS = 90_000;
const DEFAULT_FINALIZATION_POLL_INTERVAL_MS = 1_250;
const DEFAULT_FINALIZATION_CONFIRMATIONS = 1;
const BEST_EFFORT_NONCE_CLEANUP_TIMEOUT_MS = 5_000;
const MIN_BEST_EFFORT_NONCE_CLEANUP_TIMEOUT_MS = 250;
const FINALIZATION_WATCHDOG_GRACE_MS = 2_000;

function emitLifecycleEvent(
  onEvent: ((event: TempoNonceLifecycleEvent) => void) | undefined,
  accountId: string,
  event: Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId'>,
): void {
  try {
    onEvent?.(
      createSigningFlowEvent({
        ...event,
        flowId: `signing:evm_family:${accountId}:${event.phase}`,
        accountId,
      }),
    );
  } catch {}
}

function createCancelledError(): Error & { code: string } {
  const err = new Error('Request cancelled') as Error & { code: string };
  err.code = 'cancelled';
  return err;
}

function createLifecycleTimeoutError(message: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = 'timeout';
  return error;
}

async function withLifecycleTimeout<T>(args: {
  promise: Promise<T>;
  timeoutMs: number;
  message: string;
  onTimeout?: () => void;
}): Promise<T> {
  const timeoutMs = Math.max(1, Math.floor(Number(args.timeoutMs) || 0));
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let settled = false;
  try {
    return await new Promise<T>((resolve, reject) => {
      timeoutId = setTimeout(() => {
        if (settled) return;
        settled = true;
        try {
          args.onTimeout?.();
        } catch {}
        reject(createLifecycleTimeoutError(args.message));
      }, timeoutMs);
      args.promise.then(
        (value) => {
          if (settled) return;
          settled = true;
          if (timeoutId) clearTimeout(timeoutId);
          resolve(value);
        },
        (error: unknown) => {
          if (settled) return;
          settled = true;
          if (timeoutId) clearTimeout(timeoutId);
          reject(error);
        },
      );
    });
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

function resolveBestEffortCleanupTimeoutMs(finalizationTimeoutMs: unknown): number {
  const parsed = Math.floor(Number(finalizationTimeoutMs));
  if (!Number.isFinite(parsed) || parsed <= 0) return BEST_EFFORT_NONCE_CLEANUP_TIMEOUT_MS;
  return Math.min(
    BEST_EFFORT_NONCE_CLEANUP_TIMEOUT_MS,
    Math.max(MIN_BEST_EFFORT_NONCE_CLEANUP_TIMEOUT_MS, parsed),
  );
}

function throwIfCancelled(shouldAbort?: () => boolean): void {
  if (typeof shouldAbort === 'function' && shouldAbort()) {
    throw createCancelledError();
  }
}

function normalizeToken(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

function hasErrorCode(error: unknown, expected: string): boolean {
  if (!error || typeof error !== 'object') return false;
  const normalized = normalizeToken((error as { code?: unknown }).code);
  return normalized === normalizeToken(expected);
}

function errorDiagnostic(error: unknown): { code?: string; message: string; details?: unknown } {
  if (error instanceof Error) {
    const code = String((error as { code?: unknown }).code || '').trim();
    const details = 'details' in error ? (error as { details?: unknown }).details : undefined;
    return {
      ...(code ? { code } : {}),
      message: error.message,
      ...(details !== undefined ? { details } : {}),
    };
  }
  if (error && typeof error === 'object') {
    const value = error as { code?: unknown; message?: unknown; details?: unknown };
    const code = String(value.code || '').trim();
    const message = String(value.message || '').trim();
    return {
      ...(code ? { code } : {}),
      message: message || String(error),
      ...(value.details !== undefined ? { details: value.details } : {}),
    };
  }
  return { message: String(error || 'unknown error') };
}

function messageIncludesNonceLaneBlocked(error: unknown): boolean {
  const message = normalizeToken(
    error instanceof Error
      ? error.message
      : error && typeof error === 'object' && 'message' in error
        ? (error as { message?: unknown }).message
        : error,
  );
  return message.includes('nonce_lane_blocked') || message.includes('nonce lane blocked');
}

function extractDroppedOrReplacedReason(error: unknown): 'dropped' | 'replaced' | null {
  if (!error || typeof error !== 'object') return null;
  if (!hasErrorCode(error, 'tx_dropped_or_replaced')) return null;
  const reason = normalizeToken((error as { reason?: unknown }).reason);
  if (reason === 'replaced') return 'replaced';
  return 'dropped';
}

function normalizeHexData(value: unknown): `0x${string}` | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]*$/.test(normalized)) return null;
  return normalized as `0x${string}`;
}

function trimmedStringOrNull(value: unknown): string | null {
  const trimmed = String(value ?? '').trim();
  return trimmed || null;
}

function normalizePayloadAddress(value: unknown): string | null {
  const trimmed = trimmedStringOrNull(value);
  return trimmed ? trimmed.toLowerCase() : null;
}

function assertNeverFinalizedPayload(value: never): never {
  throw new Error(`[Tempo capability] unhandled finalized payload branch: ${String(value)}`);
}

function requireHexData(value: unknown, label: string): `0x${string}` {
  const normalized = normalizeHexData(value);
  if (!normalized) throw new Error(`[Tempo capability] invalid ${label} payload input`);
  return normalized;
}

function eip1559PayloadExpectationFromRequest(
  request: Extract<ExecuteEvmFamilyTransactionArgs['request'], { chain: 'evm' }>,
): FinalizedEvmEip1559PayloadExpectation {
  return {
    kind: 'evm_eip1559',
    to: request.tx.to ?? null,
    input: requireHexData(request.tx.data || '0x', 'EVM'),
  };
}

function tempoCallPayloadExpectationFromRequestCall(
  call: Extract<ExecuteEvmFamilyTransactionArgs['request'], { chain: 'tempo' }>['tx']['calls'][number],
): FinalizedTempoEip2718PayloadExpectation['calls'][number] {
  return {
    to: call.to,
    input: requireHexData(call.input || '0x', 'Tempo call'),
  };
}

function tempoPayloadExpectationFromRequest(
  request: Extract<ExecuteEvmFamilyTransactionArgs['request'], { chain: 'tempo' }>,
): FinalizedTempoEip2718PayloadExpectation {
  const [firstCall, ...remainingCalls] = request.tx.calls;
  if (!firstCall) throw new Error('[Tempo capability] Tempo transaction has no calls');
  const firstExpectation = tempoCallPayloadExpectationFromRequestCall(firstCall);
  const remainingExpectations = remainingCalls.map(tempoCallPayloadExpectationFromRequestCall);
  const calls: FinalizedTempoEip2718PayloadExpectation['calls'] = [
    firstExpectation,
    ...remainingExpectations,
  ];
  return {
    kind: 'tempo_eip2718_calls',
    calls,
  };
}

function payloadExpectationFromRequest(
  request: ExecuteEvmFamilyTransactionArgs['request'],
): FinalizedEvmTxPayloadExpectation {
  switch (request.chain) {
    case 'evm':
      return eip1559PayloadExpectationFromRequest(request);
    case 'tempo':
      return tempoPayloadExpectationFromRequest(request);
    default:
      return assertNeverFinalizedPayload(request);
  }
}

function observedCallInput(call: { input?: string | null; data?: string | null }): string | null {
  return call.input ?? call.data ?? null;
}

function observedPayloadFromTx(tx: EvmTransactionByHash): FinalizedEvmTxPayloadObservation {
  if (Array.isArray(tx.calls)) {
    return {
      kind: 'tempo_eip2718_calls',
      calls: tx.calls.map((call) => ({
        to: call?.to ?? null,
        input: call ? observedCallInput(call) : null,
        data: call?.data ?? null,
      })),
    };
  }
  return {
    kind: 'evm_eip1559',
    to: tx.to ?? null,
    input: tx.input ?? null,
  };
}

function eip1559PayloadMatches(args: {
  expected: FinalizedEvmEip1559PayloadExpectation;
  observed: Extract<FinalizedEvmTxPayloadObservation, { kind: 'evm_eip1559' }>;
}): boolean {
  return (
    normalizePayloadAddress(args.observed.to) === normalizePayloadAddress(args.expected.to) &&
    normalizeHexData(args.observed.input) === normalizeHexData(args.expected.input)
  );
}

function tempoCallPayloadMatches(args: {
  expected: FinalizedTempoEip2718PayloadExpectation['calls'][number];
  observed: Extract<
    FinalizedEvmTxPayloadObservation,
    { kind: 'tempo_eip2718_calls' }
  >['calls'][number];
}): boolean {
  return (
    normalizePayloadAddress(args.observed.to) === normalizePayloadAddress(args.expected.to) &&
    normalizeHexData(observedCallInput(args.observed)) === normalizeHexData(args.expected.input)
  );
}

function tempoPayloadMatches(args: {
  expected: FinalizedTempoEip2718PayloadExpectation;
  observed: Extract<FinalizedEvmTxPayloadObservation, { kind: 'tempo_eip2718_calls' }>;
}): boolean {
  if (args.observed.calls.length !== args.expected.calls.length) return false;
  return args.expected.calls.every((expected, index) => {
    const observed = args.observed.calls[index];
    return observed ? tempoCallPayloadMatches({ expected, observed }) : false;
  });
}

function payloadExpectationMatchesObservation(args: {
  expected: FinalizedEvmTxPayloadExpectation;
  observed: FinalizedEvmTxPayloadObservation;
}): boolean {
  switch (args.expected.kind) {
    case 'evm_eip1559':
      return args.observed.kind === 'evm_eip1559'
        ? eip1559PayloadMatches({ expected: args.expected, observed: args.observed })
        : false;
    case 'tempo_eip2718_calls':
      return args.observed.kind === 'tempo_eip2718_calls'
        ? tempoPayloadMatches({ expected: args.expected, observed: args.observed })
        : false;
    default:
      return assertNeverFinalizedPayload(args.expected);
  }
}

function resolveRpcUrlForRequest(args: {
  chains: readonly SeamsChainConfig[];
  chainTarget: ExecuteEvmFamilyTransactionArgs['chainTarget'];
}): string {
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const compatible = args.chains.filter((chain) => {
    const family = chainFamilyFromNetwork(chain.network);
    if (family !== 'evm' && family !== 'tempo') return false;
    return thresholdEcdsaChainTargetKey(thresholdEcdsaChainTargetFromConfig(chain)) === targetKey;
  });
  if (compatible.length === 1) {
    const rpcUrl = String(compatible[0]!.rpcUrl || '').trim();
    if (!rpcUrl) {
      throw new Error(
        `[Tempo capability] missing rpcUrl for ${compatible[0]!.network} ${targetKey}`,
      );
    }
    return rpcUrl;
  }
  if (compatible.length > 1) {
    const candidates = compatible.map((chain) => chain.network).join(', ');
    throw new Error(
      `[Tempo capability] ambiguous RPC routing for ${targetKey} across [${candidates}]`,
    );
  }
  throw new Error(`[Tempo capability] unable to resolve RPC URL for ${targetKey}`);
}

function extractManagedNonceReceiptWaitIdentity(
  signedResult: TempoSignedResult | EvmSignedResult,
): {
  managedNonceSenderAddress?: `0x${string}`;
  nonceHint?: bigint;
} {
  const senderRaw = String(signedResult?.managedNonce?.sender || '').trim();
  const managedNonceSenderAddress = /^0x[0-9a-fA-F]{40}$/.test(senderRaw)
    ? (senderRaw as `0x${string}`)
    : undefined;
  let nonceHint: bigint | undefined;
  try {
    const nonceRaw = String(signedResult?.managedNonce?.nonce || '').trim();
    if (nonceRaw) {
      const parsed = BigInt(nonceRaw);
      if (parsed >= 0n) nonceHint = parsed;
    }
  } catch {}
  return {
    ...(managedNonceSenderAddress ? { managedNonceSenderAddress } : {}),
    ...(typeof nonceHint === 'bigint' ? { nonceHint } : {}),
  };
}

async function verifyFinalizedPayload(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
  expected: FinalizedEvmTxPayloadExpectation;
}): Promise<FinalizedEvmTxPayloadVerification> {
  const client = createEvmClient({ rpcUrl: args.rpcUrl });
  const tx = await client
    .getTransactionByHash({
      txHash: args.txHash,
    })
    .catch(() => null);
  if (!tx) {
    return {
      kind: 'tx_unavailable',
      expected: args.expected,
    };
  }

  const observed = observedPayloadFromTx(tx);
  if (
    payloadExpectationMatchesObservation({
      expected: args.expected,
      observed,
    })
  ) {
    return {
      kind: 'matched',
      expected: args.expected,
      observed,
    };
  }
  return {
    kind: 'mismatch',
    expected: args.expected,
    observed,
  };
}

async function reportBroadcastFailure(args: {
  lifecycle: TempoLifecycleDeps;
  walletSession: ExecuteEvmFamilyTransactionArgs['walletSession'];
  signedResult: TempoSignedResult | EvmSignedResult;
  error: unknown;
  broadcastAccepted: boolean;
  txHash?: `0x${string}`;
  onEvent?: (event: TempoNonceLifecycleEvent) => void;
}): Promise<void> {
  if (!args.broadcastAccepted) {
    await args.lifecycle.reportBroadcastRejected({
      walletSession: args.walletSession,
      signedResult: args.signedResult,
      error: args.error,
      options: { onEvent: args.onEvent },
    });
    return;
  }

  const droppedOrReplacedReason = extractDroppedOrReplacedReason(args.error);
  if (droppedOrReplacedReason) {
    await args.lifecycle.reportDroppedOrReplaced({
      walletSession: args.walletSession,
      signedResult: args.signedResult,
      reason: droppedOrReplacedReason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      options: { onEvent: args.onEvent },
    });
    return;
  }

  try {
    await args.lifecycle.reconcileNonceLane({
      walletSession: args.walletSession,
      signedResult: args.signedResult,
      options: { onEvent: args.onEvent },
    });
  } catch (reconcileError: unknown) {
    if (
      hasErrorCode(reconcileError, 'nonce_lane_blocked') ||
      messageIncludesNonceLaneBlocked(reconcileError)
    ) {
      await args.lifecycle.reportDroppedOrReplaced({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        reason: 'dropped',
        ...(args.txHash ? { txHash: args.txHash } : {}),
        options: { onEvent: args.onEvent },
      });
      return;
    }
    throw reconcileError;
  }
}

function normalizeTxHashOrThrow(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error(
      `[Tempo capability] invalid transaction hash from broadcast: ${normalized || 'empty'}`,
    );
  }
  return normalized as `0x${string}`;
}

function assertRawTxHexOrThrow(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error('[Tempo capability] signed rawTxHex is missing or invalid');
  }
  return normalized as `0x${string}`;
}

function ensurePayloadExpectation(
  args: ExecuteEvmFamilyTransactionArgs,
): FinalizedEvmTxPayloadExpectation {
  return args.payloadExpectation ?? payloadExpectationFromRequest(args.request);
}

export async function executeEvmFamilyTransactionLifecycle(args: {
  lifecycle: TempoLifecycleDeps;
  chains: readonly SeamsChainConfig[];
  input: ExecuteEvmFamilyTransactionArgs;
}): Promise<ExecuteEvmFamilyTransactionResult> {
  const onEvent = args.input.options?.onEvent;
  const walletId = toWalletId(args.input.walletSession.walletId);
  throwIfCancelled(args.input.options?.shouldAbort);

  let signedResult: TempoSignedResult | EvmSignedResult | null = null;
  let txHash: `0x${string}` | undefined;
  let broadcastAccepted = false;
  let finalizedReported = false;
  const emit = (event: Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId'>): void =>
    emitLifecycleEvent(onEvent, walletId, event);
  const forwardSigningEvent = (event: TempoNonceLifecycleEvent): void => {
    if (event.phase === SigningEventPhase.STEP_15_COMPLETED) return;
    try {
      onEvent?.(event);
    } catch {}
  };

  try {
    const request = args.input.request;
    const rpcUrl = resolveRpcUrlForRequest({
      chains: args.chains,
      chainTarget: args.input.chainTarget,
    });
    const client = createEvmClient({ rpcUrl });

    signedResult = await args.lifecycle.signTempo({
      walletSession: args.input.walletSession,
      request,
      chainTarget: args.input.chainTarget,
      options: args.input.options
        ? {
            ...(args.input.options.confirmationConfig
              ? { confirmationConfig: args.input.options.confirmationConfig }
              : {}),
            ...(args.input.options.shouldAbort
              ? { shouldAbort: args.input.options.shouldAbort }
              : {}),
            ...(onEvent ? { onEvent: forwardSigningEvent } : {}),
          }
        : undefined,
    });
    throwIfCancelled(args.input.options?.shouldAbort);

    emit({
      phase: SigningEventPhase.STEP_12_BROADCAST_STARTED,
      status: 'running',
      interaction: { kind: 'none', overlay: 'none' },
    });
    const rawTxHex = assertRawTxHexOrThrow(signedResult.rawTxHex);
    txHash = normalizeTxHashOrThrow(
      await client.request<string>({
        method: 'eth_sendRawTransaction',
        params: [rawTxHex],
      }),
    );
    await args.lifecycle.reportBroadcastAccepted({
      walletSession: args.input.walletSession,
      signedResult,
      txHash,
      options: { ...(onEvent ? { onEvent } : {}) },
    });
    broadcastAccepted = true;

    emit({
      phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
      status: 'running',
      message: 'Waiting for transaction finalization',
      interaction: { kind: 'none', overlay: 'none' },
      data: { txHash },
    });
    const abortController = new AbortController();
    let abortInterval: ReturnType<typeof setInterval> | null = null;
    if (typeof args.input.options?.shouldAbort === 'function') {
      abortInterval = setInterval(() => {
        if (!args.input.options?.shouldAbort?.()) return;
        abortController.abort(createCancelledError());
      }, 100);
    }
    const finalizationTimeoutMs = Math.max(
      1,
      Math.floor(
        Number(args.input.finalization?.timeoutMs ?? DEFAULT_FINALIZATION_TIMEOUT_MS) || 0,
      ),
    );
    const finalizationPollIntervalMs = Math.max(
      1,
      Math.floor(
        Number(args.input.finalization?.pollIntervalMs ?? DEFAULT_FINALIZATION_POLL_INTERVAL_MS) ||
          0,
      ),
    );
    const finalizationConfirmations = Math.max(
      1,
      Math.floor(
        Number(args.input.finalization?.confirmations ?? DEFAULT_FINALIZATION_CONFIRMATIONS) || 0,
      ),
    );
    const receiptWaitIdentity = extractManagedNonceReceiptWaitIdentity(signedResult);
    const receipt = await withLifecycleTimeout({
      promise: client
        .waitForTransactionReceipt({
          txHash,
          timeoutMs: finalizationTimeoutMs,
          pollIntervalMs: finalizationPollIntervalMs,
          confirmations: finalizationConfirmations,
          maxFeePerGasHint: request.tx.maxFeePerGas,
          signal: abortController.signal,
          ...(receiptWaitIdentity.managedNonceSenderAddress
            ? { transactionSenderAddress: receiptWaitIdentity.managedNonceSenderAddress }
            : {}),
          ...(typeof receiptWaitIdentity.nonceHint === 'bigint'
            ? { nonceHint: receiptWaitIdentity.nonceHint }
            : {}),
        })
        .finally(() => {
          if (abortInterval) {
            clearInterval(abortInterval);
            abortInterval = null;
          }
          abortController.abort(new Error('finalization wait settled'));
        }),
      timeoutMs: finalizationTimeoutMs + FINALIZATION_WATCHDOG_GRACE_MS,
      message: `Timed out waiting for transaction finalization after ${finalizationTimeoutMs.toString()}ms`,
      onTimeout: () => {
        abortController.abort(
          createLifecycleTimeoutError('Transaction finalization watchdog timed out'),
        );
      },
    });

    const status = normalizeToken(receipt.status);
    if (status && status !== '0x1' && status !== '0x01') {
      await args.lifecycle.reportFinalized({
        walletSession: args.input.walletSession,
        signedResult,
        txHash,
        receiptStatus: 'reverted',
        options: { ...(onEvent ? { onEvent } : {}) },
      });
      finalizedReported = true;
      const reverted = new Error(
        `Transaction reverted with receipt status ${String(receipt.status || 'unknown')}`,
      ) as Error & { code?: string; txHash?: `0x${string}` };
      reverted.code = 'tx_reverted';
      reverted.txHash = txHash;
      throw reverted;
    }

    const payloadExpectation = ensurePayloadExpectation(args.input);
    const payloadVerification = await verifyFinalizedPayload({
      rpcUrl,
      txHash,
      expected: payloadExpectation,
    });
    if (payloadVerification.kind === 'mismatch') {
      const mismatchError = new Error(
        `Finalized transaction payload mismatch for ${txHash}.`,
      ) as Error & { code?: string; details?: unknown };
      mismatchError.code = 'tx_payload_mismatch';
      mismatchError.details = payloadVerification;
      throw mismatchError;
    }

    await args.lifecycle.reportFinalized({
      walletSession: args.input.walletSession,
      signedResult,
      txHash,
      receiptStatus: 'success',
      options: { ...(onEvent ? { onEvent } : {}) },
    });
    finalizedReported = true;

    emit({
      phase: SigningEventPhase.STEP_13_RECEIPT_FINALIZED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: { txHash },
    });

    if (typeof args.input.postFinalizationCheck === 'function') {
      emit({
        phase: SigningEventPhase.STEP_14_APP_STATE_SYNC_STARTED,
        status: 'running',
        interaction: { kind: 'none', overlay: 'none' },
        data: { txHash },
      });
      try {
        await args.input.postFinalizationCheck();
      } catch (postFinalizationError: unknown) {
        const reason =
          postFinalizationError instanceof Error
            ? postFinalizationError.message
            : String(postFinalizationError || '');
        const normalized = new Error(
          `Post-finalization state verification failed for ${txHash}: ${reason || 'unknown error'}`,
        ) as Error & {
          code?: string;
          txHash?: `0x${string}`;
          details?: unknown;
        };
        normalized.code = 'post_finalization_state_mismatch';
        normalized.txHash = txHash;
        normalized.details = {
          ...(postFinalizationError instanceof Error && postFinalizationError.message
            ? { message: postFinalizationError.message }
            : {}),
          originalError: postFinalizationError,
        };
        throw normalized;
      }
      emit({
        phase: SigningEventPhase.STEP_14_APP_STATE_SYNC_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        data: { txHash },
      });
    }

    emit({
      phase: SigningEventPhase.STEP_15_COMPLETED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: { operation: 'execute', txHash },
    });
    return {
      txHash,
      signedResult,
      payloadVerification,
    };
  } catch (error: unknown) {
    try {
      const stage = !signedResult
        ? 'sign'
        : !broadcastAccepted
          ? 'broadcast'
          : finalizedReported
            ? 'post_finalization'
            : 'finalization';
      console.warn('[EvmFamilyLifecycle][failure]', {
        stage,
        walletId,
        requestChain: args.input.request.chain,
        requestKind: args.input.request.kind,
        requestChainId: args.input.request.tx.chainId,
        chainTarget: args.input.chainTarget,
        signed: Boolean(signedResult),
        ...(signedResult?.managedNonce
          ? {
              managedNonce: {
                chain: signedResult.managedNonce.chainTarget.kind,
                networkKey: signedResult.managedNonce.chainTarget.networkSlug,
                chainId: signedResult.managedNonce.chainTarget.chainId,
                sender: signedResult.managedNonce.sender,
                nonce: signedResult.managedNonce.nonce.toString(),
                ...(signedResult.managedNonce.nonceKey != null
                  ? { nonceKey: signedResult.managedNonce.nonceKey.toString() }
                  : {}),
              },
            }
          : {}),
        broadcastAccepted,
        finalizedReported,
        ...(txHash ? { txHash } : {}),
        error: errorDiagnostic(error),
      });
    } catch {}
    if (!finalizedReported && signedResult) {
      await withLifecycleTimeout({
        promise: reportBroadcastFailure({
          lifecycle: args.lifecycle,
          walletSession: args.input.walletSession,
          signedResult,
          error,
          broadcastAccepted,
          ...(txHash ? { txHash } : {}),
          ...(onEvent ? { onEvent } : {}),
        }),
        timeoutMs: resolveBestEffortCleanupTimeoutMs(args.input.finalization?.timeoutMs),
        message: 'Timed out during best-effort nonce cleanup after EVM-family signing failure',
      }).catch(() => null);
    }
    throw error;
  }
}
