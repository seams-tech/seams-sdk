import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  assertRawTxTypePrefix,
  buildDemoEip1559Request,
  compactHex,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  sendRawEvmTransaction,
  waitForEvmTransactionFinalization,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import { reportTempoBroadcastFailure } from './reportTempoBroadcastFailure';

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
    toast.loading('Signing EVM transaction…', { id: toastId });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    try {
      const request = buildDemoEip1559Request(arcGreetingInput.trim(), arcEip1559FeeCaps);
      const signed = await tatchi.tempo.signTempo({
        nearAccountId,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

      toast.loading('Dispatching EVM transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        rawTxHex: signed.rawTxHex,
      });
      await tatchi.tempo.reportBroadcastResult({
        nearAccountId,
        signedResult: signedResultForBroadcast,
        status: 'success',
        txHash,
      });

      toast.loading('EVM transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
        maxFeePerGasHint: request.tx.maxFeePerGas,
      });
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
      await reportTempoBroadcastFailure({
        tatchi,
        nearAccountId,
        signedResult: signedResultForBroadcast,
        error: resolvedError,
        flow: 'evm-sign',
      });

      if (isUserCancellationError(resolvedError)) {
        toast.error('EVM transaction cancelled by user.', { id: toastId });
        return;
      }
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `ARC sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`EVM transaction failed: ${message}`, { id: toastId });
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
