import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  TEMPO_ALPHA_USD_FEE_TOKEN,
  buildEvmExplorerTxUrl,
  buildTempoDripRequest,
  buildTempoEip1559GreetingRequest,
  compactHex,
  formatWeiToEth,
  isEvmAddress,
  isUserCancellationError,
  parseInsufficientFundsError,
  readEvmNativeBalance,
  resolveClickTimeEip1559FeeCaps,
  waitForExpectedGreeting,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';

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
    toast.loading('Requesting Tempo token drip…', { id: toastId, description: null });
    let executedTxHash: `0x${string}` | undefined;
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
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        fallbackFeeCaps: tempoEip1559FeeCaps,
      });
      const request = buildTempoDripRequest({
        feeCaps,
        tokenAddresses: dripTokensForAttempt,
      });
      const firstCall = request.tx.calls[0];
      const execution = await tatchi.tempo.executeEvmFamilyTransaction({
        nearAccountId,
        request,
        payloadExpectation: {
          to: firstCall?.to,
          input: firstCall?.input || '0x',
        },
        postFinalizationCheck: async () => {
          const thresholdSender = await thresholdSenderPromise;
          if (thresholdSender) {
            await refreshTempoUserFeeTokenBalance({
              silent: true,
              userAddress: thresholdSender,
              feeToken: dripToken,
            });
          }
        },
      });
      executedTxHash = execution.txHash;
      senderNativeBalanceRaw = await senderNativeBalancePromise;
      const txUrl = buildEvmExplorerTxUrl({
        explorerBaseUrl: FRONTEND_CONFIG.tempoExplorerUrl,
        txHash: execution.txHash,
      });
      const txLabel = compactHex(execution.txHash);

      toast.success('Tempo drip finalized', {
        id: toastId,
        description: (
          <span>
            Token:&nbsp;
            <code>{compactHex(dripToken)}</code>
            <br />
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
        toast.error(`Tempo drip finalized, but post-finalization refresh failed: ${message}`, {
          id: toastId,
          description: null,
        });
        console.error('[DemoPage][TempoDripPostFinalizationSyncError]', {
          atIso: new Date().toISOString(),
          error: resolvedError,
          message,
          senderNativeBalanceRaw,
          dripTokensForAttempt,
          txHash: executedTxHash,
        });
        return;
      }
      if (isUserCancellationError(resolvedError)) {
        toast.error('Tempo drip cancelled by user.', { id: toastId, description: null });
        return;
      }
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `Tempo sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId, description: null },
        );
      } else {
        toast.error(`Tempo drip failed: ${message}`, { id: toastId, description: null });
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
    toast.loading('Signing Tempo transaction…', { id: toastId, description: null });
    try {
      const requestedGreeting = tempoGreetingInput.trim();
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        fallbackFeeCaps: tempoEip1559FeeCaps,
      });
      const request = buildTempoEip1559GreetingRequest(requestedGreeting, feeCaps);
      const execution = await tatchi.tempo.executeEvmFamilyTransaction({
        nearAccountId,
        request,
        payloadExpectation: {
          to: request.tx.to,
          input: request.tx.data || '0x',
        },
        postFinalizationCheck: async () => {
          await waitForExpectedGreeting({
            fetchGreeting: fetchTempoGreeting,
            expectedGreeting: requestedGreeting,
          });
          await refreshThresholdEvmFundingAddress();
        },
      });
      const txUrl = buildEvmExplorerTxUrl({
        explorerBaseUrl: FRONTEND_CONFIG.tempoExplorerUrl,
        txHash: execution.txHash,
      });
      const txLabel = compactHex(execution.txHash);

      toast.success('Tempo transaction finalized', {
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
        toast.error(`Tempo transaction finalized, but post-finalization refresh failed: ${message}`, {
          id: toastId,
          description: null,
        });
        console.error('[DemoPage][TempoPostFinalizationSyncError]', {
          atIso: new Date().toISOString(),
          message,
          error: resolvedError,
        });
        return;
      }
      if (isUserCancellationError(resolvedError)) {
        toast.error('Tempo transaction cancelled by user.', { id: toastId, description: null });
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
          { id: toastId, description: null },
        );
      } else {
        toast.error(`Tempo transaction failed: ${message}`, { id: toastId, description: null });
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
