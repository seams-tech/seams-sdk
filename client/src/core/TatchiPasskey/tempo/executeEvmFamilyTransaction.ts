import { chainFamilyFromNetwork } from '@/core/config/chains';
import { createEvmPublicClient } from '@/core/rpcClients/evm/publicClient';
import type { TatchiChainConfig } from '@/core/types/tatchi';
import type {
  ExecuteEvmFamilyTransactionArgs,
  ExecuteEvmFamilyTransactionResult,
  FinalizedEvmTxPayloadVerification,
  ReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs,
  SignTempoArgs,
  TempoNonceLifecycleEvent,
} from '../interfaces';
import type { EvmSignedResult } from '@/core/signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chainAdaptors/tempo/tempoAdapter';

type TempoLifecycleCapability = {
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

function emitLifecycleEvent(
  onEvent: ((event: TempoNonceLifecycleEvent) => void) | undefined,
  event: TempoNonceLifecycleEvent,
): void {
  try {
    onEvent?.(event);
  } catch {}
}

function createCancelledError(): Error & { code: string } {
  const err = new Error('Request cancelled') as Error & { code: string };
  err.code = 'cancelled';
  return err;
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

function resolveRpcUrlForRequest(args: {
  chains: readonly TatchiChainConfig[];
  request: ExecuteEvmFamilyTransactionArgs['request'];
}): string {
  const targetChainId = Number(args.request.tx.chainId);
  if (!Number.isSafeInteger(targetChainId) || targetChainId <= 0) {
    throw new Error(`[TempoSigner] invalid request chainId: ${String(args.request.tx.chainId)}`);
  }
  const withChainId = args.chains.filter(
    (chain): chain is TatchiChainConfig & { chainId: number } =>
      'chainId' in chain && typeof chain.chainId === 'number' && chain.chainId === targetChainId,
  );
  const compatible = withChainId.filter((chain) => {
    const family = chainFamilyFromNetwork(chain.network);
    if (args.request.chain === 'tempo') return family === 'tempo';
    return family === 'evm' || family === 'tempo';
  });
  if (compatible.length === 1) {
    const rpcUrl = String(compatible[0]!.rpcUrl || '').trim();
    if (!rpcUrl) {
      throw new Error(
        `[TempoSigner] missing rpcUrl for ${compatible[0]!.network} chainId=${String(targetChainId)}`,
      );
    }
    return rpcUrl;
  }
  if (compatible.length > 1 && args.request.chain === 'evm') {
    const evmOnly = compatible.filter((chain) => chainFamilyFromNetwork(chain.network) === 'evm');
    if (evmOnly.length === 1) {
      const rpcUrl = String(evmOnly[0]!.rpcUrl || '').trim();
      if (rpcUrl) return rpcUrl;
    }
  }
  if (compatible.length > 1) {
    const candidates = compatible.map((chain) => chain.network).join(', ');
    throw new Error(
      `[TempoSigner] ambiguous RPC routing for ${args.request.chain} chainId=${String(targetChainId)} across [${candidates}]`,
    );
  }
  throw new Error(
    `[TempoSigner] unable to resolve RPC URL for ${args.request.chain} chainId=${String(targetChainId)}`,
  );
}

function extractManagedNonceHints(
  signedResult: TempoSignedResult | EvmSignedResult,
): { senderHint?: `0x${string}`; nonceHint?: bigint } {
  const senderRaw = String(signedResult?.managedNonce?.sender || '').trim();
  const senderHint = /^0x[0-9a-fA-F]{40}$/.test(senderRaw) ? (senderRaw as `0x${string}`) : undefined;
  let nonceHint: bigint | undefined;
  try {
    const nonceRaw = String(signedResult?.managedNonce?.nonce || '').trim();
    if (nonceRaw) {
      const parsed = BigInt(nonceRaw);
      if (parsed >= 0n) nonceHint = parsed;
    }
  } catch {}
  return {
    ...(senderHint ? { senderHint } : {}),
    ...(typeof nonceHint === 'bigint' ? { nonceHint } : {}),
  };
}

function inferPayloadExpectation(
  request: ExecuteEvmFamilyTransactionArgs['request'],
): { to?: `0x${string}`; input?: `0x${string}` } {
  if (request.chain === 'evm') {
    const to = request.tx.to || undefined;
    const input = normalizeHexData(request.tx.data || '0x') || undefined;
    return {
      ...(to ? { to } : {}),
      ...(input ? { input } : {}),
    };
  }
  if (request.tx.calls.length === 1) {
    const call = request.tx.calls[0]!;
    const input = normalizeHexData(call.input || '0x') || undefined;
    return {
      to: call.to,
      ...(input ? { input } : {}),
    };
  }
  return {};
}

async function verifyFinalizedPayload(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
  expectedTo?: `0x${string}`;
  expectedInput?: `0x${string}`;
}): Promise<FinalizedEvmTxPayloadVerification> {
  const client = createEvmPublicClient({ rpcUrl: args.rpcUrl });
  const tx = await client
    .getTransactionByHash({
      txHash: args.txHash,
    })
    .catch(() => null);
  if (!tx) {
    return {
      verified: false,
      reason: 'tx_unavailable',
    };
  }

  const expectedTo = String(args.expectedTo || '')
    .trim()
    .toLowerCase();
  const expectedInput = normalizeHexData(args.expectedInput);
  const observedTo = String(tx.to || '')
    .trim()
    .toLowerCase();
  const observedInput = normalizeHexData(tx.input);
  const toMismatch = expectedTo ? observedTo !== expectedTo : false;
  const inputMismatch = expectedInput ? observedInput !== expectedInput : false;
  if (!toMismatch && !inputMismatch) {
    return {
      verified: true,
      reason: 'matched',
      observedTo: tx.to ?? null,
      observedInput: tx.input ?? null,
    };
  }
  return {
    verified: false,
    reason: 'mismatch',
    observedTo: tx.to ?? null,
    observedInput: tx.input ?? null,
  };
}

async function reportBroadcastFailure(args: {
  capability: TempoLifecycleCapability;
  nearAccountId: string;
  signedResult: TempoSignedResult | EvmSignedResult;
  error: unknown;
  broadcastAccepted: boolean;
  txHash?: `0x${string}`;
  onEvent?: (event: TempoNonceLifecycleEvent) => void;
}): Promise<void> {
  if (!args.broadcastAccepted) {
    await args.capability.reportBroadcastRejected({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      error: args.error,
      options: { onEvent: args.onEvent },
    });
    return;
  }

  const droppedOrReplacedReason = extractDroppedOrReplacedReason(args.error);
  if (droppedOrReplacedReason) {
    await args.capability.reportDroppedOrReplaced({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      reason: droppedOrReplacedReason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      options: { onEvent: args.onEvent },
    });
    return;
  }

  try {
    await args.capability.reconcileNonceLane({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      options: { onEvent: args.onEvent },
    });
  } catch (reconcileError: unknown) {
    if (hasErrorCode(reconcileError, 'nonce_lane_blocked') || messageIncludesNonceLaneBlocked(reconcileError)) {
      await args.capability.reportDroppedOrReplaced({
        nearAccountId: args.nearAccountId,
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
    throw new Error(`[TempoSigner] invalid transaction hash from broadcast: ${normalized || 'empty'}`);
  }
  return normalized as `0x${string}`;
}

function assertRawTxHexOrThrow(value: unknown): `0x${string}` {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error('[TempoSigner] signed rawTxHex is missing or invalid');
  }
  return normalized as `0x${string}`;
}

function ensurePayloadExpectation(
  args: ExecuteEvmFamilyTransactionArgs,
): { to?: `0x${string}`; input?: `0x${string}` } {
  const inferred = inferPayloadExpectation(args.request);
  return {
    ...(inferred.to ? { to: inferred.to } : {}),
    ...(inferred.input ? { input: inferred.input } : {}),
    ...(args.payloadExpectation?.to ? { to: args.payloadExpectation.to } : {}),
    ...(args.payloadExpectation?.input ? { input: args.payloadExpectation.input } : {}),
  };
}

export async function executeEvmFamilyTransactionLifecycle(args: {
  capability: TempoLifecycleCapability;
  chains: readonly TatchiChainConfig[];
  input: ExecuteEvmFamilyTransactionArgs;
}): Promise<ExecuteEvmFamilyTransactionResult> {
  const onEvent = args.input.options?.onEvent;
  throwIfCancelled(args.input.options?.shouldAbort);

  let signedResult: TempoSignedResult | EvmSignedResult | null = null;
  let txHash: `0x${string}` | undefined;
  let broadcastAccepted = false;
  let finalizedReported = false;

  try {
    const request = args.input.request;
    const rpcUrl = resolveRpcUrlForRequest({
      chains: args.chains,
      request,
    });
    const client = createEvmPublicClient({ rpcUrl });

    emitLifecycleEvent(onEvent, {
      step: 7,
      phase: 'tx-sign',
      status: 'progress',
      message: 'Signing EVM-family transaction',
    });
    signedResult = await args.capability.signTempo({
      nearAccountId: args.input.nearAccountId,
      request,
      options: args.input.options
        ? {
            ...(args.input.options.confirmationConfig
              ? { confirmationConfig: args.input.options.confirmationConfig }
              : {}),
            ...(args.input.options.shouldAbort
              ? { shouldAbort: args.input.options.shouldAbort }
              : {}),
            ...(onEvent ? { onEvent } : {}),
          }
        : undefined,
    });
    throwIfCancelled(args.input.options?.shouldAbort);

    emitLifecycleEvent(onEvent, {
      step: 7,
      phase: 'tx-broadcast',
      status: 'progress',
      message: 'Broadcasting raw transaction',
    });
    const rawTxHex = assertRawTxHexOrThrow(signedResult.rawTxHex);
    txHash = normalizeTxHashOrThrow(
      await client.request<string>({
        method: 'eth_sendRawTransaction',
        params: [rawTxHex],
      }),
    );
    await args.capability.reportBroadcastAccepted({
      nearAccountId: args.input.nearAccountId,
      signedResult,
      txHash,
      options: { ...(onEvent ? { onEvent } : {}) },
    });
    broadcastAccepted = true;

    emitLifecycleEvent(onEvent, {
      step: 7,
      phase: 'tx-finalization-wait',
      status: 'progress',
      message: 'Waiting for transaction finalization',
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
    const receipt = await client
      .waitForTransactionReceipt({
        txHash,
        timeoutMs: Math.max(
          1,
          Math.floor(Number(args.input.finalization?.timeoutMs ?? DEFAULT_FINALIZATION_TIMEOUT_MS) || 0),
        ),
        pollIntervalMs: Math.max(
          1,
          Math.floor(
            Number(args.input.finalization?.pollIntervalMs ?? DEFAULT_FINALIZATION_POLL_INTERVAL_MS) ||
              0,
          ),
        ),
        confirmations: Math.max(
          1,
          Math.floor(
            Number(args.input.finalization?.confirmations ?? DEFAULT_FINALIZATION_CONFIRMATIONS) || 0,
          ),
        ),
        maxFeePerGasHint: request.tx.maxFeePerGas,
        signal: abortController.signal,
        ...extractManagedNonceHints(signedResult),
      })
      .finally(() => {
        if (abortInterval) {
          clearInterval(abortInterval);
          abortInterval = null;
        }
        abortController.abort(new Error('finalization wait settled'));
      });

    const status = normalizeToken(receipt.status);
    if (status && status !== '0x1' && status !== '0x01') {
      await args.capability.reportFinalized({
        nearAccountId: args.input.nearAccountId,
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
      expectedTo: payloadExpectation.to,
      expectedInput: payloadExpectation.input,
    });
    if (!payloadVerification.verified && payloadVerification.reason === 'mismatch') {
      const mismatchError = new Error(
        `Finalized transaction payload mismatch for ${txHash}.`,
      ) as Error & { code?: string; details?: unknown };
      mismatchError.code = 'tx_payload_mismatch';
      mismatchError.details = payloadVerification;
      throw mismatchError;
    }

    await args.capability.reportFinalized({
      nearAccountId: args.input.nearAccountId,
      signedResult,
      txHash,
      receiptStatus: 'success',
      options: { ...(onEvent ? { onEvent } : {}) },
    });
    finalizedReported = true;

    if (typeof args.input.postFinalizationCheck === 'function') {
      emitLifecycleEvent(onEvent, {
        step: 8,
        phase: 'post-finalization-check',
        status: 'progress',
        message: 'Running post-finalization check',
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
    }

    emitLifecycleEvent(onEvent, {
      step: 8,
      phase: 'tx-finalized',
      status: 'success',
      message: 'EVM-family transaction finalized',
      data: { txHash },
    });
    return {
      txHash,
      signedResult,
      payloadVerification,
    };
  } catch (error: unknown) {
    if (!finalizedReported && signedResult) {
      await reportBroadcastFailure({
        capability: args.capability,
        nearAccountId: args.input.nearAccountId,
        signedResult,
        error,
        broadcastAccepted,
        ...(txHash ? { txHash } : {}),
        ...(onEvent ? { onEvent } : {}),
      }).catch(() => null);
    }
    throw error;
  }
}
