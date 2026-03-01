import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  assertRawTxTypePrefix,
  buildEvmExplorerTxUrl,
  buildDemoEip1559Request,
  compactHex,
  extractManagedNonceHints,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  sendRawEvmTransaction,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import {
  reportDemoEvmBroadcastFailure,
  resolveClickTimeEip1559FeeCaps,
  waitForDemoEvmFinalization,
} from './demoEvmTransactionHandling';

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
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        fallbackFeeCaps: arcEip1559FeeCaps,
      });
      const request = buildDemoEip1559Request(requestedGreeting, feeCaps);
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
      await waitForDemoEvmFinalization({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        txHash,
        flowLabel: 'ARC greeting',
        timeoutLabel: 'EVM receipt finalization confirmation',
        chain: 'evm',
        chainId: request.tx.chainId,
        gasLimitHint: request.tx.gasLimit,
        maxFeePerGasHint: request.tx.maxFeePerGas,
        nonceHints,
      });
      await tatchi.tempo.reportFinalized({
        nearAccountId,
        signedResult: signed,
        txHash,
        receiptStatus: 'success',
      });
      finalizedReported = true;
      await fetchArcGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();
      const txUrl = buildEvmExplorerTxUrl({
        explorerBaseUrl: FRONTEND_CONFIG.arcExplorerUrl,
        txHash,
      });
      const txLabel = compactHex(txHash);

      toast.success('EVM transaction finalized', {
        id: toastId,
        description: (
          <span>
            Tx hash:&nbsp;
            {txUrl ? (
              <a href={txUrl} target="_blank" rel="noopener noreferrer">
                <code>{txLabel}</code>
              </a>
            ) : (
              <code>{txLabel}</code>
            )}
          </span>
        ),
      });
    } catch (error: unknown) {
      const resolvedError: unknown = error;
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      if (!finalizedReported) {
        reportDemoEvmBroadcastFailure({
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
