import { useCallback, useState } from 'react';
import { walletSessionRefFromSession } from '@seams/sdk/advanced';
import { type SigningFlowEvent, useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
  EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  buildEvmExplorerTxUrl,
  buildTempoSetUserTokenRequest,
  compactHex,
  isUserCancellationError,
  parseInsufficientFundsError,
  readEvmNativeBalance,
  readTempoTokenBalanceRaw,
  resolveClickTimeEip1559FeeCaps,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import { resolveDemoThresholdEcdsaChainTarget } from '../demoChainTargets';
import type { EvmAddress } from './demoThresholdTypes';
import { handleSigningToastEvent } from './signingToast';

type UseDemoTempoFeeTokenActionsArgs = {
  isLoggedIn: boolean;
  walletId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  tempoEip1559FeeCaps: Eip1559FeeCaps;
  resolveThresholdOwnerAddressForEvmFamily: () => Promise<EvmAddress>;
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
    walletId,
    seams,
    tempoEip1559FeeCaps,
    resolveThresholdOwnerAddressForEvmFamily,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
  } = args;

  const [tempoFeeTokenConfigLoading, setTempoFeeTokenConfigLoading] = useState(false);

  const configureTempoFeeToken = useCallback(
    async (config: { token: EvmAddress; label: string }) => {
      if (!isLoggedIn || !walletId) return false;
      const toastId = 'tempo-set-fee-token';
      try {
        toast.dismiss(toastId);
      } catch {}
      setTempoFeeTokenConfigLoading(true);
      toast.loading(`Configuring Tempo fee token to ${config.label}…`, {
        id: toastId,
        description: null,
      });
      let executedTxHash: `0x${string}` | undefined;
      let thresholdOwnerAddressForAttempt: EvmAddress | null = null;
      let selectedFeeTokenBalanceRaw: bigint | null = null;
      let thresholdOwnerNativeBalanceRaw: bigint | null = null;
      try {
        const tempoFeeToken = config.token;
        const feeCaps = await resolveClickTimeEip1559FeeCaps({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          fallbackFeeCaps: tempoEip1559FeeCaps,
        });
        const request = buildTempoSetUserTokenRequest({
          feeCaps,
          feeToken: tempoFeeToken,
        });
        const payloadExpectation = {
          to: request.tx.to,
          input: request.tx.data || '0x',
        };
        const thresholdOwnerAddressPromise = resolveThresholdOwnerAddressForEvmFamily()
          .then((ownerAddress) => {
            thresholdOwnerAddressForAttempt = ownerAddress;
            return ownerAddress;
          })
          .catch(() => null);
        const diagnosticsPromise = (async () => {
          const thresholdOwnerAddress = await thresholdOwnerAddressPromise;
          if (!thresholdOwnerAddress) return;
          selectedFeeTokenBalanceRaw = await readTempoTokenBalanceRaw({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            userAddress: thresholdOwnerAddress,
            tokenAddress: tempoFeeToken,
          }).catch(() => null);
          thresholdOwnerNativeBalanceRaw = await readEvmNativeBalance({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            address: thresholdOwnerAddress,
            blockTag: 'latest',
          }).catch(() => null);
        })().catch(() => undefined);
        const execution = await seams.tempo.executeEvmFamilyTransaction({
          walletSession: walletSessionRefFromSession({
            walletId,
            walletSessionUserId: walletId,
          }),
          request,
          chainTarget: resolveDemoThresholdEcdsaChainTarget('tempo', FRONTEND_CONFIG.chains),
          finalization: {
            timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
            pollIntervalMs: EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
          },
          payloadExpectation,
          options: {
            onEvent: (event: SigningFlowEvent) =>
              handleSigningToastEvent(event, {
                toastId,
                chainLabel: 'Tempo',
                successMessage: 'Tempo fee-token transaction complete',
              }),
          },
          postFinalizationCheck: async () => {
            const thresholdOwnerAddress = await thresholdOwnerAddressPromise;
            const refreshedFeeToken = thresholdOwnerAddress
              ? await refreshTempoUserFeeToken({
                  silent: true,
                  userAddress: thresholdOwnerAddress,
                })
              : null;
            if (thresholdOwnerAddress) {
              await refreshTempoUserFeeTokenBalance({
                silent: true,
                userAddress: thresholdOwnerAddress,
                feeToken: tempoFeeToken,
              });
            }
            const refreshedMatchesTarget =
              !!refreshedFeeToken &&
              refreshedFeeToken.toLowerCase() === tempoFeeToken.toLowerCase();
            if (thresholdOwnerAddress && !refreshedMatchesTarget) {
              throw new Error(
                `setUserToken transaction finalized, but refreshed userTokens(address) reports ${refreshedFeeToken ? compactHex(refreshedFeeToken) : 'not set'} instead of ${compactHex(tempoFeeToken)}.`,
              );
            }
          },
        });
        executedTxHash = execution.txHash;
        await diagnosticsPromise;
        const txUrl = buildEvmExplorerTxUrl({
          explorerBaseUrl: FRONTEND_CONFIG.tempoExplorerUrl,
          txHash: execution.txHash,
        });
        const txLabel = compactHex(execution.txHash);

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
        return true;
      } catch (error: unknown) {
        const resolvedError: unknown = error;
        const message =
          resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
        const errorCode =
          resolvedError && typeof resolvedError === 'object' && 'code' in resolvedError
            ? String((resolvedError as { code?: unknown }).code || '')
            : '';
        if (errorCode === 'post_finalization_state_mismatch') {
          toast.error(
            `Tempo fee-token transaction finalized, but post-finalization refresh failed: ${message}`,
            { id: toastId, description: null },
          );
          console.error('[DemoPage][TempoSetUserTokenPostFinalizationSyncError]', {
            atIso: new Date().toISOString(),
            error: resolvedError,
            message,
            thresholdOwnerAddressForAttempt,
            selectedFeeTokenBalanceRaw,
            thresholdOwnerNativeBalanceRaw,
            txHash: executedTxHash,
          });
          return false;
        }
        if (isUserCancellationError(resolvedError)) {
          toast.error('Tempo fee token update cancelled by user.', {
            id: toastId,
            description: null,
          });
          return false;
        }
        const insufficient = parseInsufficientFundsError(message);
        if (insufficient) {
          toast.error(
            `Tempo fee-token setup has insufficient fee funds (raw have ${insufficient.haveWei.toString()}, need ${insufficient.wantWei.toString()}). Run Prepare Tempo Fee Token, then retry.`,
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
          thresholdOwnerAddressForAttempt,
          selectedFeeTokenBalanceRaw,
          thresholdOwnerNativeBalanceRaw,
        });
        return false;
      } finally {
        setTempoFeeTokenConfigLoading(false);
      }
    },
    [
      isLoggedIn,
      refreshTempoUserFeeToken,
      refreshTempoUserFeeTokenBalance,
      resolveThresholdOwnerAddressForEvmFamily,
      seams,
      tempoEip1559FeeCaps,
      walletId,
    ],
  );

  const handleSetTempoFeeTokenAlphaUsd = useCallback(
    async () =>
      await configureTempoFeeToken({
        token: TEMPO_ALPHA_USD_FEE_TOKEN,
        label: 'AlphaUSD',
      }),
    [configureTempoFeeToken],
  );

  return {
    tempoFeeTokenConfigLoading,
    handleSetTempoFeeTokenAlphaUsd,
  };
}
