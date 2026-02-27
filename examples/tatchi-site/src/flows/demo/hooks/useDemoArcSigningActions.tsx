import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  ARC_GREET_SELECTOR,
  ARC_TESTNET_GREETING_CONTRACT,
  EVM_RPC_REQUEST_TIMEOUT_MS,
  EVM_TX_FINALITY_TIMEOUT_MS,
  assertRawTxTypePrefix,
  buildDemoEip1559Request,
  compactHex,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  sendRawEvmTransaction,
  waitForEvmGreetingMatch,
  waitForEvmTransactionFinalization,
  withPromiseTimeout,
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
      const requestedGreeting = arcGreetingInput.trim();
      const request = buildDemoEip1559Request(requestedGreeting, arcEip1559FeeCaps);
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
      const confirmationAbort = new AbortController();
      let confirmationMode: 'receipt' | 'greeting';
      try {
        const receiptConfirmationResultPromise = waitForEvmTransactionFinalization({
          rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
          txHash,
          gasLimitHint: request.tx.gasLimit,
          maxFeePerGasHint: request.tx.maxFeePerGas,
          signal: confirmationAbort.signal,
        })
          .then(
            () =>
              ({
                ok: true as const,
                mode: 'receipt' as const,
              }) as const,
          )
          .catch(
            (error: unknown) =>
              ({
                ok: false as const,
                source: 'receipt' as const,
                error,
              }) as const,
          );
        const greetingConfirmationResultPromise = waitForEvmGreetingMatch({
          rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
          contract: ARC_TESTNET_GREETING_CONTRACT,
          selector: ARC_GREET_SELECTOR,
          expectedGreeting: requestedGreeting,
          signal: confirmationAbort.signal,
        })
          .then(
            () =>
              ({
                ok: true as const,
                mode: 'greeting' as const,
              }) as const,
          )
          .catch(
            (error: unknown) =>
              ({
                ok: false as const,
                source: 'greeting' as const,
                error,
              }) as const,
          );
        const firstConfirmationResult = await withPromiseTimeout({
          promise: Promise.race([
            receiptConfirmationResultPromise,
            greetingConfirmationResultPromise,
          ]),
          timeoutMs: EVM_TX_FINALITY_TIMEOUT_MS + EVM_RPC_REQUEST_TIMEOUT_MS + 5_000,
          label: 'EVM greeting finalization confirmation',
        });
        if (firstConfirmationResult.ok) {
          confirmationMode = firstConfirmationResult.mode;
        } else {
          const secondConfirmationResult =
            firstConfirmationResult.source === 'receipt'
              ? await greetingConfirmationResultPromise
              : await receiptConfirmationResultPromise;
          if (secondConfirmationResult.ok) {
            confirmationMode = secondConfirmationResult.mode;
          } else {
            const receiptError =
              firstConfirmationResult.source === 'receipt'
                ? firstConfirmationResult.error
                : secondConfirmationResult.error;
            const greetingError =
              firstConfirmationResult.source === 'greeting'
                ? firstConfirmationResult.error
                : secondConfirmationResult.error;
            const receiptErrorMessage =
              receiptError instanceof Error ? receiptError.message : String(receiptError);
            const greetingErrorMessage =
              greetingError instanceof Error ? greetingError.message : String(greetingError);
            throw new Error(
              `Unable to confirm EVM transaction finalization. Receipt check failed: ${receiptErrorMessage}. Greeting check failed: ${greetingErrorMessage}. Tx hash: ${txHash}`,
            );
          }
        }
      } finally {
        confirmationAbort.abort(new Error('EVM finalization confirmation settled'));
      }
      await fetchArcGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success(
        confirmationMode === 'greeting'
          ? 'EVM transaction confirmed (via greeting update)'
          : 'EVM transaction finalized',
        {
          id: toastId,
          description: (
            <span>
              Tx hash:&nbsp;
              <code>{compactHex(txHash)}</code>
            </span>
          ),
        },
      );
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
