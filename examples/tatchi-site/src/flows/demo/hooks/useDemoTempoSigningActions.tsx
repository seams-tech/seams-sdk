import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  EVM_RPC_REQUEST_TIMEOUT_MS,
  EVM_TX_FINALITY_TIMEOUT_MS,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_GREETING_CONTRACT,
  TEMPO_GREETING_SELECTOR,
  assertRawTxTypePrefix,
  buildTempoEip1559DripRequest,
  buildTempoEip1559GreetingRequest,
  compactHex,
  formatWeiToEth,
  isEvmAddress,
  isUserCancellationError,
  parseInsufficientFundsError,
  readEvmNativeBalance,
  sendRawEvmTransaction,
  waitForEvmGreetingMatch,
  waitForEvmTransactionFinalization,
  withPromiseTimeout,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';
import { reportTempoBroadcastFailure } from './reportTempoBroadcastFailure';

type UseDemoTempoSigningActionsArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  canSignTempo: boolean;
  tempoGreetingInput: string;
  tempoEip1559FeeCaps: Eip1559FeeCaps;
  tempoUserFeeToken: EvmAddress | null;
  resolveThresholdSenderForEvmFamily: () => Promise<EvmAddress>;
  refreshTempoUserFeeTokenBalance: (opts?: {
    silent?: boolean;
    userAddress?: EvmAddress | null;
    feeToken?: EvmAddress | null;
  }) => Promise<bigint | null>;
  fetchTempoGreeting: (opts?: { silent?: boolean }) => Promise<string | null>;
  refreshThresholdEvmFundingAddress: () => Promise<string | null>;
};

export function useDemoTempoSigningActions(args: UseDemoTempoSigningActionsArgs) {
  const {
    isLoggedIn,
    nearAccountId,
    tatchi,
    canSignTempo,
    tempoGreetingInput,
    tempoEip1559FeeCaps,
    tempoUserFeeToken,
    resolveThresholdSenderForEvmFamily,
    refreshTempoUserFeeTokenBalance,
    fetchTempoGreeting,
    refreshThresholdEvmFundingAddress,
  } = args;

  const [tempoThresholdSignLoading, setTempoThresholdSignLoading] = useState(false);
  const [tempoDripLoading, setTempoDripLoading] = useState(false);

  const handleTempoDripToken = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) return;
    const toastId = 'tempo-drip-token';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoDripLoading(true);
    toast.loading('Requesting Tempo token drip…', { id: toastId });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    let dripTokensForAttempt: EvmAddress[] = [];
    let senderNativeBalanceRaw: bigint | null = null;
    try {
      const configuredTokenRaw = String(tempoUserFeeToken || '').trim();
      const dripToken = isEvmAddress(configuredTokenRaw)
        ? configuredTokenRaw
        : TEMPO_ALPHA_USD_FEE_TOKEN;
      dripTokensForAttempt = [dripToken];
      const thresholdSenderPromise = resolveThresholdSenderForEvmFamily().catch(() => null);
      const senderNativeBalancePromise = thresholdSenderPromise.then(async (thresholdSender) => {
        if (!thresholdSender) return null;
        return await readEvmNativeBalance({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          address: thresholdSender,
          blockTag: 'latest',
        }).catch(() => null);
      });
      const request = buildTempoEip1559DripRequest({
        feeCaps: tempoEip1559FeeCaps,
        tokenAddresses: dripTokensForAttempt,
      });
      const signed = await tatchi.tempo.signTempo({
        nearAccountId,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

      toast.loading('Dispatching Tempo drip transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        rawTxHex: signed.rawTxHex,
      });
      await tatchi.tempo.reportBroadcastResult({
        nearAccountId,
        signedResult: signed,
        status: 'success',
        txHash,
      });

      toast.loading('Tempo drip transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
        maxFeePerGasHint: request.tx.maxFeePerGas,
      });
      const thresholdSender = await thresholdSenderPromise;
      if (thresholdSender) {
        await refreshTempoUserFeeTokenBalance({
          silent: true,
          userAddress: thresholdSender,
          feeToken: dripToken,
        });
      }
      senderNativeBalanceRaw = await senderNativeBalancePromise;

      toast.success('Tempo drip finalized', {
        id: toastId,
        description: (
          <span>
            Token:&nbsp;
            <code>{compactHex(dripToken)}</code>
            <br />
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
        flow: 'tempo-drip-token',
      });
      if (isUserCancellationError(resolvedError)) {
        toast.error('Tempo drip cancelled by user.', { id: toastId });
        return;
      }
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `Tempo sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`Tempo drip failed: ${message}`, { id: toastId });
      }
      console.error('[DemoPage][TempoDripError]', {
        atIso: new Date().toISOString(),
        error: resolvedError,
        message,
        senderNativeBalanceRaw,
        dripTokensForAttempt,
      });
    } finally {
      setTempoDripLoading(false);
    }
  }, [
    isLoggedIn,
    nearAccountId,
    refreshTempoUserFeeTokenBalance,
    resolveThresholdSenderForEvmFamily,
    tatchi,
    tempoEip1559FeeCaps,
    tempoUserFeeToken,
  ]);

  const handleSignTempoThresholdTx = useCallback(async () => {
    if (!canSignTempo || !nearAccountId) return;
    const toastId = 'tempo-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoThresholdSignLoading(true);
    toast.loading('Signing Tempo transaction…', { id: toastId });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    try {
      const requestedGreeting = tempoGreetingInput.trim();
      const request = buildTempoEip1559GreetingRequest(requestedGreeting, tempoEip1559FeeCaps);

      const signed = await tatchi.tempo.signTempo({
        nearAccountId,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

      toast.loading('Dispatching Tempo transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        rawTxHex: signed.rawTxHex,
      });
      await tatchi.tempo.reportBroadcastResult({
        nearAccountId,
        signedResult: signedResultForBroadcast,
        status: 'success',
        txHash,
      });

      toast.loading('Tempo transaction broadcasted, waiting for finalization…', { id: toastId });
      const receiptConfirmationResultPromise = waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
        maxFeePerGasHint: request.tx.maxFeePerGas,
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
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        contract: TEMPO_GREETING_CONTRACT,
        selector: TEMPO_GREETING_SELECTOR,
        expectedGreeting: requestedGreeting,
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
        label: 'Tempo greeting finalization confirmation',
      });
      let confirmationMode: 'receipt' | 'greeting';
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
            `Unable to confirm Tempo transaction finalization. Receipt check failed: ${receiptErrorMessage}. Greeting check failed: ${greetingErrorMessage}. Tx hash: ${txHash}`,
          );
        }
      }
      await fetchTempoGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success(
        confirmationMode === 'greeting'
          ? 'Tempo transaction confirmed (via greeting update)'
          : 'Tempo transaction finalized',
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
        flow: 'tempo-sign',
      });

      if (isUserCancellationError(resolvedError)) {
        toast.error('Tempo transaction cancelled by user.', { id: toastId });
        return;
      }
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      console.error('[DemoPage][TempoSignError]', {
        atIso: new Date().toISOString(),
        message,
        error: resolvedError,
      });
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `Tempo sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`Tempo transaction failed: ${message}`, { id: toastId });
      }
    } finally {
      setTempoThresholdSignLoading(false);
    }
  }, [
    canSignTempo,
    fetchTempoGreeting,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    tatchi,
    tempoEip1559FeeCaps,
    tempoGreetingInput,
  ]);

  return {
    tempoThresholdSignLoading,
    tempoDripLoading,
    handleTempoDripToken,
    handleSignTempoThresholdTx,
  };
}
