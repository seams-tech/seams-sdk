import type { useTatchi } from '@tatchi-xyz/sdk/react';

import {
  EVM_RPC_REQUEST_TIMEOUT_MS,
  EVM_TX_FINALITY_TIMEOUT_MS,
  resolveEip1559FeeCaps,
  waitForEvmTransactionFinalization,
  withPromiseTimeout,
  type Eip1559FeeCaps,
  type ManagedNonceHints,
} from '../demoEvmHelpers';
import { reportEvmFinalizationDebugEvent } from './reportEvmFinalizationDebugEvent';
import { reportTempoBroadcastFailure } from './reportTempoBroadcastFailure';

const DEFAULT_CONFIRMATION_TIMEOUT_PADDING_MS = EVM_RPC_REQUEST_TIMEOUT_MS + 5_000;

type TempoSignedResult = Awaited<
  ReturnType<ReturnType<typeof useTatchi>['tatchi']['tempo']['signTempo']>
>;

export async function resolveClickTimeEip1559FeeCaps(args: {
  rpcUrl: string;
  fallbackFeeCaps: Eip1559FeeCaps;
}): Promise<Eip1559FeeCaps> {
  return await resolveEip1559FeeCaps(args.rpcUrl).catch(() => args.fallbackFeeCaps);
}

export async function waitForDemoEvmFinalization(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
  flowLabel: string;
  timeoutLabel: string;
  chain: 'tempo' | 'evm';
  chainId: number;
  nonceHints?: ManagedNonceHints;
  gasLimitHint?: bigint;
  maxFeePerGasHint?: bigint;
  finalizationTimeoutMs?: number;
  pollIntervalMs?: number;
  confirmationTimeoutPaddingMs?: number;
}): Promise<void> {
  const finalizationTimeoutMs = args.finalizationTimeoutMs ?? EVM_TX_FINALITY_TIMEOUT_MS;
  const confirmationTimeoutPaddingMs =
    args.confirmationTimeoutPaddingMs ?? DEFAULT_CONFIRMATION_TIMEOUT_PADDING_MS;
  const confirmationAbort = new AbortController();

  try {
    await withPromiseTimeout({
      promise: waitForEvmTransactionFinalization({
        rpcUrl: args.rpcUrl,
        txHash: args.txHash,
        chain: args.chain,
        chainId: args.chainId,
        signal: confirmationAbort.signal,
        ...(typeof args.gasLimitHint === 'bigint' ? { gasLimitHint: args.gasLimitHint } : {}),
        ...(typeof args.maxFeePerGasHint === 'bigint'
          ? { maxFeePerGasHint: args.maxFeePerGasHint }
          : {}),
        ...(args.nonceHints || {}),
        ...(args.pollIntervalMs != null ? { pollIntervalMs: args.pollIntervalMs } : {}),
        ...(args.finalizationTimeoutMs != null
          ? { timeoutMs: args.finalizationTimeoutMs }
          : {}),
        onFinalizationDebugEvent: (event) => {
          reportEvmFinalizationDebugEvent({
            flowLabel: args.flowLabel,
            event,
          });
        },
      }),
      timeoutMs: finalizationTimeoutMs + confirmationTimeoutPaddingMs,
      label: args.timeoutLabel,
      onTimeout: () => {
        confirmationAbort.abort(new Error(`${args.flowLabel} receipt finalization timed out`));
      },
    });
  } finally {
    confirmationAbort.abort(new Error(`${args.flowLabel} finalization confirmation settled`));
  }
}

export function reportDemoEvmBroadcastFailure(args: {
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  nearAccountId?: string | null;
  signedResult: TempoSignedResult | null;
  error: unknown;
  flow: string;
  broadcastAccepted?: boolean;
  txHash?: `0x${string}`;
}): void {
  void reportTempoBroadcastFailure(args);
}
