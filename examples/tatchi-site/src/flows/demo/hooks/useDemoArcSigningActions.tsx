import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  EVM_RPC_REQUEST_TIMEOUT_MS,
  EVM_TX_FINALITY_TIMEOUT_MS,
  assertRawTxTypePrefix,
  buildDemoEip1559Request,
  compactHex,
  extractManagedNonceHints,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  sendRawEvmTransaction,
  waitForEvmTransactionFinalization,
  withPromiseTimeout,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import { reportTempoBroadcastFailure } from './reportTempoBroadcastFailure';

const CONFIRMATION_TIMEOUT_PADDING_MS = EVM_RPC_REQUEST_TIMEOUT_MS + 5_000;

type UseDemoArcSigningActionsArgs = {
  canSignEvm: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  arcGreetingInput: string;
  arcEip1559FeeCaps: Eip1559FeeCaps;
  fetchArcGreeting: (opts?: { silent?: boolean }) => Promise<string | null>;
  refreshThresholdEvmFundingAddress: () => Promise<string | null>;
};

export function useDemoArcSigningActions(args: UseDemoArcSigningActionsArgs) {
  const {
    canSignEvm,
    nearAccountId,
    tatchi,
    arcGreetingInput,
    arcEip1559FeeCaps,
    fetchArcGreeting,
    refreshThresholdEvmFundingAddress,
  } = args;

  const [evmThresholdSignLoading, setEvmThresholdSignLoading] = useState(false);

  const handleSignEvmThresholdTx = useCallback(async () => {
    if (!canSignEvm || !nearAccountId) return;
    const toastId = 'evm-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setEvmThresholdSignLoading(true);
    toast.loading('Signing EVM transaction…', { id: toastId, description: null });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    let broadcastAccepted = false;
    let broadcastTxHash: `0x${string}` | undefined;
    let finalizedReported = false;
    try {
      const requestedGreeting = arcGreetingInput.trim();
      const request = buildDemoEip1559Request(requestedGreeting, arcEip1559FeeCaps);
      const signed = await tatchi.tempo.signTempo({
        nearAccountId,
        request,
      });
      signedResultForBroadcast = signed;
      const nonceHints = extractManagedNonceHints(signed);

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

      toast.loading('Dispatching EVM transaction…', { id: toastId, description: null });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        rawTxHex: signed.rawTxHex,
      });
      broadcastTxHash = txHash;
      await tatchi.tempo.reportBroadcastAccepted({
        nearAccountId,
        signedResult: signedResultForBroadcast,
        txHash,
      });
      broadcastAccepted = true;

      toast.loading('EVM transaction broadcasted, waiting for finalization…', {
        id: toastId,
        description: null,
      });
      const confirmationAbort = new AbortController();
      try {
        await withPromiseTimeout({
          promise: waitForEvmTransactionFinalization({
            rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
            txHash,
            gasLimitHint: request.tx.gasLimit,
            maxFeePerGasHint: request.tx.maxFeePerGas,
            signal: confirmationAbort.signal,
            ...nonceHints,
          }),
          timeoutMs: EVM_TX_FINALITY_TIMEOUT_MS + CONFIRMATION_TIMEOUT_PADDING_MS,
          label: 'EVM receipt finalization confirmation',
          onTimeout: () => {
            confirmationAbort.abort(new Error('EVM receipt finalization timed out'));
          },
        });
      } finally {
        confirmationAbort.abort(new Error('EVM finalization confirmation settled'));
      }
      await tatchi.tempo.reportFinalized({
        nearAccountId,
        signedResult: signed,
        txHash,
        receiptStatus: 'success',
      });
      finalizedReported = true;
      await fetchArcGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success('EVM transaction finalized', {
        id: toastId,
        description: (
          <span>
            Tx hash:&nbsp;
            <code>{compactHex(txHash)}</code>
          </span>
        ),
      });
    } catch (error: unknown) {
      const resolvedError: unknown = error;
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      if (!finalizedReported) {
        await reportTempoBroadcastFailure({
          tatchi,
          nearAccountId,
          signedResult: signedResultForBroadcast,
          error: resolvedError,
          flow: 'evm-sign',
          broadcastAccepted,
          txHash: broadcastTxHash,
        });
        if (isUserCancellationError(resolvedError)) {
          toast.error('EVM transaction cancelled by user.', { id: toastId, description: null });
          return;
        }
      } else {
        toast.error(`EVM transaction finalized, but post-finalization refresh failed: ${message}`, {
          id: toastId,
          description: null,
        });
        console.error('[DemoPage][ArcPostFinalizationSyncError]', {
          atIso: new Date().toISOString(),
          message,
          error: resolvedError,
          txHash: broadcastTxHash,
        });
        return;
      }
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `ARC sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId, description: null },
        );
      } else {
        toast.error(`EVM transaction failed: ${message}`, { id: toastId, description: null });
      }
    } finally {
      setEvmThresholdSignLoading(false);
    }
  }, [
    arcEip1559FeeCaps,
    arcGreetingInput,
    canSignEvm,
    fetchArcGreeting,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    tatchi,
  ]);

  return {
    evmThresholdSignLoading,
    handleSignEvmThresholdTx,
  };
}
