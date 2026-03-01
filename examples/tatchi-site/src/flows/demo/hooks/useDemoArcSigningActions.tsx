import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  buildEvmExplorerTxUrl,
  buildDemoEip1559Request,
  compactHex,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  resolveClickTimeEip1559FeeCaps,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';

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
    try {
      const requestedGreeting = arcGreetingInput.trim();
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        fallbackFeeCaps: arcEip1559FeeCaps,
      });
      const request = buildDemoEip1559Request(requestedGreeting, feeCaps);
      const execution = await tatchi.tempo.executeEvmFamilyTransaction({
        nearAccountId,
        request,
        payloadExpectation: {
          to: request.tx.to,
          input: request.tx.data || '0x',
        },
        postFinalizationCheck: async () => {
          await fetchArcGreeting({ silent: true });
          await refreshThresholdEvmFundingAddress();
        },
      });
      const txUrl = buildEvmExplorerTxUrl({
        explorerBaseUrl: FRONTEND_CONFIG.arcExplorerUrl,
        txHash: execution.txHash,
      });
      const txLabel = compactHex(execution.txHash);

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
      const errorCode =
        resolvedError && typeof resolvedError === 'object' && 'code' in resolvedError
          ? String((resolvedError as { code?: unknown }).code || '')
          : '';
      if (errorCode === 'post_finalization_state_mismatch') {
        toast.error(`EVM transaction finalized, but post-finalization refresh failed: ${message}`, {
          id: toastId,
          description: null,
        });
        console.error('[DemoPage][ArcPostFinalizationSyncError]', {
          atIso: new Date().toISOString(),
          message,
          error: resolvedError,
        });
        return;
      }
      if (isUserCancellationError(resolvedError)) {
        toast.error('EVM transaction cancelled by user.', { id: toastId, description: null });
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
