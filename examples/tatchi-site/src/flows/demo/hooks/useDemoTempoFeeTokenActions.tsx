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
  buildEip1559SetUserTokenRequest,
  compactHex,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  readEvmNativeBalance,
  readTempoTokenBalanceRaw,
  sendRawEvmTransaction,
  waitForEvmTransactionFinalization,
  waitForTempoUserTokenMatch,
  withPromiseTimeout,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import type { EvmAddress, TempoFeeTokenConfigTarget } from './demoThresholdTypes';
import { reportTempoBroadcastFailure } from './reportTempoBroadcastFailure';

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
      toast.loading(`Configuring Tempo fee token to ${config.label}…`, { id: toastId });
      let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null =
        null;
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
        if (signed.kind !== 'eip1559') {
          throw new Error(`Unexpected signing result kind: ${signed.kind}`);
        }
        assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

        toast.loading('Dispatching setUserToken transaction…', { id: toastId });
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

        toast.loading('Waiting for setUserToken finalization…', { id: toastId });
        const thresholdSender = await thresholdSenderPromise;
        const confirmationAbort = new AbortController();
        let confirmationMode: 'receipt' | 'userToken';
        try {
          const receiptConfirmationResultPromise = waitForEvmTransactionFinalization({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            txHash,
            gasLimitHint: request.tx.gasLimit,
            maxFeePerGasHint: request.tx.maxFeePerGas,
            timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
            pollIntervalMs: EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
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
          const tokenConfirmationResultPromise = thresholdSender
            ? waitForTempoUserTokenMatch({
                rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
                userAddress: thresholdSender,
                expectedToken: tempoFeeToken,
                timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
                pollIntervalMs: EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
                signal: confirmationAbort.signal,
              })
                .then(
                  () =>
                    ({
                      ok: true as const,
                      mode: 'userToken' as const,
                    }) as const,
                )
                .catch(
                  (error: unknown) =>
                    ({
                      ok: false as const,
                      source: 'userToken' as const,
                      error,
                    }) as const,
                )
            : Promise.resolve({
                ok: false as const,
                source: 'userToken' as const,
                error: new Error('Threshold EVM sender unavailable for userTokens confirmation'),
              });
          const firstConfirmationResult = await withPromiseTimeout({
            promise: Promise.race([
              receiptConfirmationResultPromise,
              tokenConfirmationResultPromise,
            ]),
            timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS + EVM_RPC_REQUEST_TIMEOUT_MS + 5_000,
            label: 'setUserToken finalization confirmation',
          });
          if (firstConfirmationResult.ok) {
            confirmationMode = firstConfirmationResult.mode;
          } else {
            const secondConfirmationResult =
              firstConfirmationResult.source === 'receipt'
                ? await tokenConfirmationResultPromise
                : await receiptConfirmationResultPromise;
            if (secondConfirmationResult.ok) {
              confirmationMode = secondConfirmationResult.mode;
            } else {
              const receiptError =
                firstConfirmationResult.source === 'receipt'
                  ? firstConfirmationResult.error
                  : secondConfirmationResult.error;
              const userTokenError =
                firstConfirmationResult.source === 'userToken'
                  ? firstConfirmationResult.error
                  : secondConfirmationResult.error;
              const receiptErrorMessage =
                receiptError instanceof Error ? receiptError.message : String(receiptError);
              const userTokenErrorMessage =
                userTokenError instanceof Error ? userTokenError.message : String(userTokenError);
              throw new Error(
                `Unable to confirm setUserToken to ${config.label}. Receipt check failed: ${receiptErrorMessage}. userTokens(address) check failed: ${userTokenErrorMessage}.`,
              );
            }
          }
        } finally {
          confirmationAbort.abort(new Error('setUserToken finalization confirmation settled'));
        }
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
            `setUserToken confirmation (${confirmationMode}) completed, but refreshed userTokens(address) reports ${refreshedFeeToken ? compactHex(refreshedFeeToken) : 'not set'} instead of ${compactHex(tempoFeeToken)}. Tx hash: ${txHash}`,
          );
        }
        await diagnosticsPromise;

        toast.success(
          confirmationMode === 'userToken'
            ? 'Tempo fee token configured (confirmed via userTokens)'
            : 'Tempo fee token configured',
          {
            id: toastId,
            description: (
              <span>
                Token:&nbsp;
                <code>{config.label}</code>&nbsp;
                <code>{compactHex(tempoFeeToken)}</code>
                <br />
                Tx hash:&nbsp;
                <code>{compactHex(txHash)}</code>
                {confirmationMode === 'userToken' ? (
                  <>
                    <br />
                    Confirmed from `userTokens(address)` before receipt finalization.
                  </>
                ) : null}
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
          flow: 'tempo-set-fee-token',
        });
        if (isUserCancellationError(resolvedError)) {
          toast.error('Tempo fee token update cancelled by user.', { id: toastId });
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
          toast.error(`Tempo fee token update failed: ${message}`, { id: toastId });
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
