import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  EVM_RPC_REQUEST_TIMEOUT_MS,
  EVM_TX_FINALITY_TIMEOUT_MS,
  TEMPO_ALPHA_USD_FEE_TOKEN,
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
  waitForEvmTransactionFinalization,
  withPromiseTimeout,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';
import { reportTempoBroadcastFailure } from './reportTempoBroadcastFailure';

const CONFIRMATION_TIMEOUT_PADDING_MS = EVM_RPC_REQUEST_TIMEOUT_MS + 5_000;

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
    let broadcastAccepted = false;
    let broadcastTxHash: `0x${string}` | undefined;
    let finalizedReported = false;
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
      broadcastTxHash = txHash;
      await tatchi.tempo.reportBroadcastAccepted({
        nearAccountId,
        signedResult: signed,
        txHash,
      });
      broadcastAccepted = true;

      toast.loading('Tempo drip transaction broadcasted, waiting for finalization…', { id: toastId });
      await withPromiseTimeout({
        promise: waitForEvmTransactionFinalization({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          txHash,
          gasLimitHint: request.tx.gasLimit,
          maxFeePerGasHint: request.tx.maxFeePerGas,
        }),
        timeoutMs: EVM_TX_FINALITY_TIMEOUT_MS + CONFIRMATION_TIMEOUT_PADDING_MS,
        label: 'Tempo drip finalization confirmation',
      });
      await tatchi.tempo.reportFinalized({
        nearAccountId,
        signedResult: signed,
        txHash,
        receiptStatus: 'success',
      });
      finalizedReported = true;
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
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      if (!finalizedReported) {
        await reportTempoBroadcastFailure({
          tatchi,
          nearAccountId,
          signedResult: signedResultForBroadcast,
          error: resolvedError,
          flow: 'tempo-drip-token',
          broadcastAccepted,
          txHash: broadcastTxHash,
        });
        if (isUserCancellationError(resolvedError)) {
          toast.error('Tempo drip cancelled by user.', { id: toastId });
          return;
        }
      } else {
        toast.error(`Tempo drip finalized, but post-finalization refresh failed: ${message}`, {
          id: toastId,
        });
        console.error('[DemoPage][TempoDripPostFinalizationSyncError]', {
          atIso: new Date().toISOString(),
          error: resolvedError,
          message,
          senderNativeBalanceRaw,
          dripTokensForAttempt,
          txHash: broadcastTxHash,
        });
        return;
      }
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
    let broadcastAccepted = false;
    let broadcastTxHash: `0x${string}` | undefined;
    let finalizedReported = false;
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
      broadcastTxHash = txHash;
      await tatchi.tempo.reportBroadcastAccepted({
        nearAccountId,
        signedResult: signedResultForBroadcast,
        txHash,
      });
      broadcastAccepted = true;

      toast.loading('Tempo transaction broadcasted, waiting for finalization…', { id: toastId });
      const confirmationAbort = new AbortController();
      try {
        await withPromiseTimeout({
          promise: waitForEvmTransactionFinalization({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            txHash,
            gasLimitHint: request.tx.gasLimit,
            maxFeePerGasHint: request.tx.maxFeePerGas,
            signal: confirmationAbort.signal,
          }),
          timeoutMs: EVM_TX_FINALITY_TIMEOUT_MS + CONFIRMATION_TIMEOUT_PADDING_MS,
          label: 'Tempo receipt finalization confirmation',
          onTimeout: () => {
            confirmationAbort.abort(new Error('Tempo receipt finalization timed out'));
          },
        });
      } finally {
        confirmationAbort.abort(new Error('Tempo finalization confirmation settled'));
      }
      await tatchi.tempo.reportFinalized({
        nearAccountId,
        signedResult: signed,
        txHash,
        receiptStatus: 'success',
      });
      finalizedReported = true;
      await fetchTempoGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success('Tempo transaction finalized', {
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
          flow: 'tempo-sign',
          broadcastAccepted,
          txHash: broadcastTxHash,
        });

        if (isUserCancellationError(resolvedError)) {
          toast.error('Tempo transaction cancelled by user.', { id: toastId });
          return;
        }
      } else {
        toast.error(`Tempo transaction finalized, but post-finalization refresh failed: ${message}`, {
          id: toastId,
        });
        console.error('[DemoPage][TempoPostFinalizationSyncError]', {
          atIso: new Date().toISOString(),
          message,
          error: resolvedError,
          txHash: broadcastTxHash,
        });
        return;
      }
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
