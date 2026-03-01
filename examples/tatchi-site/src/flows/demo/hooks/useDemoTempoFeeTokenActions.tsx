import { useCallback, useState } from 'react';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  EVM_RPC_REQUEST_TIMEOUT_MS,
  EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
  EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  assertRawTxTypePrefix,
  buildEvmExplorerTxUrl,
  buildEip1559SetUserTokenRequest,
  compactHex,
  extractManagedNonceHints,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  readEvmNativeBalance,
  readTempoTokenBalanceRaw,
  sendRawEvmTransaction,
  waitForEvmTransactionFinalization,
  withPromiseTimeout,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import type { EvmAddress, TempoFeeTokenConfigTarget } from './demoThresholdTypes';
import { reportEvmFinalizationDebugEvent } from './reportEvmFinalizationDebugEvent';
import { reportTempoBroadcastFailure } from './reportTempoBroadcastFailure';

const CONFIRMATION_TIMEOUT_PADDING_MS = EVM_RPC_REQUEST_TIMEOUT_MS + 5_000;

type UseDemoTempoFeeTokenActionsArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  tempoEip1559FeeCaps: Eip1559FeeCaps;
  resolveThresholdSenderForEvmFamily: () => Promise<EvmAddress>;
  refreshTempoUserFeeToken: (opts?: {
    silent?: boolean;
    userAddress?: EvmAddress | null;
  }) => Promise<EvmAddress | null>;
  refreshTempoUserFeeTokenBalance: (opts?: {
    silent?: boolean;
    userAddress?: EvmAddress | null;
    feeToken?: EvmAddress | null;
  }) => Promise<bigint | null>;
};

export function useDemoTempoFeeTokenActions(args: UseDemoTempoFeeTokenActionsArgs) {
  const {
    isLoggedIn,
    nearAccountId,
    tatchi,
    tempoEip1559FeeCaps,
    resolveThresholdSenderForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  } = args;

  const [tempoFeeTokenConfigLoading, setTempoFeeTokenConfigLoading] = useState(false);
  const [tempoFeeTokenConfigTarget, setTempoFeeTokenConfigTarget] =
    useState<TempoFeeTokenConfigTarget>(null);

  const configureTempoFeeToken = useCallback(
    async (config: { token: EvmAddress; label: string; target: 'alpha' }) => {
      if (!isLoggedIn || !nearAccountId) return;
      const toastId = 'tempo-set-fee-token';
      try {
        toast.dismiss(toastId);
      } catch {}
      setTempoFeeTokenConfigLoading(true);
      setTempoFeeTokenConfigTarget(config.target);
      toast.loading(`Configuring Tempo fee token to ${config.label}…`, {
        id: toastId,
        description: null,
      });
      let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null =
        null;
      let broadcastAccepted = false;
      let broadcastTxHash: `0x${string}` | undefined;
      let finalizedReported = false;
      let thresholdSenderForAttempt: EvmAddress | null = null;
      let selectedFeeTokenBalanceRaw: bigint | null = null;
      let senderNativeBalanceRaw: bigint | null = null;
      try {
        const tempoFeeToken = config.token;
        const request = buildEip1559SetUserTokenRequest({
          feeCaps: tempoEip1559FeeCaps,
          feeToken: tempoFeeToken,
        });
        const thresholdSenderPromise = resolveThresholdSenderForEvmFamily()
          .then((sender) => {
            thresholdSenderForAttempt = sender;
            return sender;
          })
          .catch(() => null);
        const diagnosticsPromise = (async () => {
          const thresholdSender = await thresholdSenderPromise;
          if (!thresholdSender) return;
          selectedFeeTokenBalanceRaw = await readTempoTokenBalanceRaw({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            userAddress: thresholdSender,
            tokenAddress: tempoFeeToken,
          }).catch(() => null);
          senderNativeBalanceRaw = await readEvmNativeBalance({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            address: thresholdSender,
            blockTag: 'latest',
          }).catch(() => null);
        })().catch(() => undefined);

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

        toast.loading('Dispatching setUserToken transaction…', { id: toastId, description: null });
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

        toast.loading('Waiting for setUserToken finalization…', {
          id: toastId,
          description: null,
        });
        const thresholdSender = await thresholdSenderPromise;
        const confirmationAbort = new AbortController();
        try {
          await withPromiseTimeout({
            promise: waitForEvmTransactionFinalization({
              rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
              txHash,
              gasLimitHint: request.tx.gasLimit,
              maxFeePerGasHint: request.tx.maxFeePerGas,
              timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
              pollIntervalMs: EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
              signal: confirmationAbort.signal,
              onFinalizationDebugEvent: (event) => {
                reportEvmFinalizationDebugEvent({
                  flowLabel: 'Tempo setUserToken',
                  event,
                });
              },
              ...nonceHints,
            }),
            timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS + CONFIRMATION_TIMEOUT_PADDING_MS,
            label: 'setUserToken receipt finalization confirmation',
            onTimeout: () => {
              confirmationAbort.abort(new Error('setUserToken receipt finalization timed out'));
            },
          });
        } finally {
          confirmationAbort.abort(new Error('setUserToken finalization confirmation settled'));
        }
        await tatchi.tempo.reportFinalized({
          nearAccountId,
          signedResult: signed,
          txHash,
          receiptStatus: 'success',
        });
        finalizedReported = true;
        const refreshedFeeToken = thresholdSender
          ? await refreshTempoUserFeeToken({
              silent: true,
              userAddress: thresholdSender,
            })
          : null;
        if (thresholdSender) {
          await refreshTempoUserFeeTokenBalance({
            silent: true,
            userAddress: thresholdSender,
            feeToken: tempoFeeToken,
          });
        }
        const refreshedMatchesTarget =
          !!refreshedFeeToken &&
          refreshedFeeToken.toLowerCase() === tempoFeeToken.toLowerCase();
        if (thresholdSender && !refreshedMatchesTarget) {
          throw new Error(
            `setUserToken transaction finalized, but refreshed userTokens(address) reports ${refreshedFeeToken ? compactHex(refreshedFeeToken) : 'not set'} instead of ${compactHex(tempoFeeToken)}. Tx hash: ${txHash}`,
          );
        }
        await diagnosticsPromise;
        const txUrl = buildEvmExplorerTxUrl({
          explorerBaseUrl: FRONTEND_CONFIG.tempoExplorerUrl,
          txHash,
        });
        const txLabel = compactHex(txHash);

        toast.success('Tempo fee token configured', {
          id: toastId,
          description: (
            <span>
              Token:&nbsp;
              <code>{config.label}</code>&nbsp;
              <code>{compactHex(tempoFeeToken)}</code>
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
        if (!finalizedReported) {
          await reportTempoBroadcastFailure({
            tatchi,
            nearAccountId,
            signedResult: signedResultForBroadcast,
            error: resolvedError,
            flow: 'tempo-set-fee-token',
            broadcastAccepted,
            txHash: broadcastTxHash,
          });
          if (isUserCancellationError(resolvedError)) {
            toast.error('Tempo fee token update cancelled by user.', {
              id: toastId,
              description: null,
            });
            return;
          }
        } else {
          toast.error(
            `Tempo fee-token transaction finalized, but post-finalization refresh failed: ${message}`,
            { id: toastId, description: null },
          );
          console.error('[DemoPage][TempoSetUserTokenPostFinalizationSyncError]', {
            atIso: new Date().toISOString(),
            error: resolvedError,
            message,
            thresholdSenderForAttempt,
            selectedFeeTokenBalanceRaw,
            senderNativeBalanceRaw,
            txHash: broadcastTxHash,
          });
          return;
        }
        const insufficient = parseInsufficientFundsError(message);
        if (insufficient) {
          toast.error(
            `Tempo sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
            { id: toastId, description: null },
          );
        } else {
          toast.error(`Tempo fee token update failed: ${message}`, {
            id: toastId,
            description: null,
          });
        }
        console.error('[DemoPage][TempoSetUserTokenError]', {
          atIso: new Date().toISOString(),
          error: resolvedError,
          message,
          thresholdSenderForAttempt,
          selectedFeeTokenBalanceRaw,
          senderNativeBalanceRaw,
        });
      } finally {
        setTempoFeeTokenConfigLoading(false);
        setTempoFeeTokenConfigTarget(null);
      }
    },
    [
      isLoggedIn,
      nearAccountId,
      refreshTempoUserFeeToken,
      refreshTempoUserFeeTokenBalance,
      resolveThresholdSenderForEvmFamily,
      tatchi,
      tempoEip1559FeeCaps,
    ],
  );

  const handleSetTempoFeeTokenAlphaUsd = useCallback(
    async () =>
      await configureTempoFeeToken({
        token: TEMPO_ALPHA_USD_FEE_TOKEN,
        label: 'AlphaUSD',
        target: 'alpha',
      }),
    [configureTempoFeeToken],
  );

  return {
    tempoFeeTokenConfigLoading,
    tempoFeeTokenConfigTarget,
    handleSetTempoFeeTokenAlphaUsd,
  };
}
