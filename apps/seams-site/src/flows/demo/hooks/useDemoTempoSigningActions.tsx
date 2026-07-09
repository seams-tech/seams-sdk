import { useCallback, useState } from 'react';
import { walletSessionRefFromSession } from '@seams/sdk/advanced';
import { type SigningFlowEvent, useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG, type FrontendConfig } from '@/config';
import {
  EVM_GREETING_FINALITY_POLL_INTERVAL_MS,
  EVM_GREETING_FINALITY_TIMEOUT_MS,
  buildEvmExplorerTxUrl,
  buildTempoTransactionGreetingRequest,
  compactHex,
  fundTempoTestnetAddress,
  isTempoAlphaUsdFeeToken,
  isUserCancellationError,
  parseInsufficientFundsError,
  resolveClickTimeEip1559FeeCaps,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  waitForExpectedGreeting,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import { resolveDemoThresholdEcdsaChainTarget } from '../demoChainTargets';
import type { EvmAddress } from './demoThresholdTypes';
import { handleSigningToastEvent } from './signingToast';

type TempoSigningFrontendConfig = Pick<
  FrontendConfig,
  'chains' | 'tempoExplorerUrl' | 'tempoRpcUrl'
>;

async function refreshTempoFaucetBalance(input: {
  readonly refreshTempoUserFeeTokenBalance: UseDemoTempoSigningActionsArgs['refreshTempoUserFeeTokenBalance'];
  readonly thresholdOwnerAddress: EvmAddress;
  readonly tokenAddress: EvmAddress;
}): Promise<void> {
  await input.refreshTempoUserFeeTokenBalance({
    silent: true,
    userAddress: input.thresholdOwnerAddress,
    feeToken: input.tokenAddress,
  });
}

type UseDemoTempoSigningActionsArgs = {
  isLoggedIn: boolean;
  walletId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  frontendConfig?: TempoSigningFrontendConfig;
  canSignTempo: boolean;
  tempoGreetingInput: string;
  tempoEip1559FeeCaps: Eip1559FeeCaps;
  resolveThresholdOwnerAddressForEvmFamily: () => Promise<EvmAddress>;
  refreshTempoUserFeeTokenBalance: (opts?: {
    silent?: boolean;
    userAddress?: EvmAddress | null;
    feeToken?: EvmAddress | null;
  }) => Promise<bigint | null>;
  refreshTempoUserFeeToken: (opts?: {
    silent?: boolean;
    userAddress?: EvmAddress | null;
  }) => Promise<EvmAddress | null>;
  fetchTempoGreeting: (opts?: { silent?: boolean }) => Promise<string | null>;
  refreshThresholdOwnerAddress: () => Promise<string | null>;
};

export function useDemoTempoSigningActions(args: UseDemoTempoSigningActionsArgs) {
  const {
    isLoggedIn,
    walletId,
    seams,
    frontendConfig = FRONTEND_CONFIG,
    canSignTempo,
    tempoGreetingInput,
    tempoEip1559FeeCaps,
    refreshTempoUserFeeTokenBalance,
    refreshTempoUserFeeToken,
    resolveThresholdOwnerAddressForEvmFamily,
    fetchTempoGreeting,
    refreshThresholdOwnerAddress,
  } = args;

  const [tempoThresholdSignLoading, setTempoThresholdSignLoading] = useState(false);
  const [tempoFaucetFundingLoading, setTempoFaucetFundingLoading] = useState(false);
  const tempoPreparationUnavailableReason = frontendConfig.tempoRpcUrl
    ? null
    : 'Tempo faucet requires VITE_TEMPO_RPC_URL.';

  const handleFundTempoFeeTokens = useCallback(async () => {
    if (!isLoggedIn || !walletId || tempoFaucetFundingLoading) return false;
    const toastId = 'tempo-faucet-fund';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoFaucetFundingLoading(true);
    toast.loading('Requesting Tempo testnet fee tokens…', { id: toastId, description: null });
    try {
      const thresholdOwnerAddress = await resolveThresholdOwnerAddressForEvmFamily();
      const txHashes = await fundTempoTestnetAddress({
        rpcUrl: frontendConfig.tempoRpcUrl,
        address: thresholdOwnerAddress,
      });
      await refreshTempoFaucetBalance({
        refreshTempoUserFeeTokenBalance,
        thresholdOwnerAddress,
        tokenAddress: TEMPO_ALPHA_USD_FEE_TOKEN,
      });
      const txHash = txHashes[0] || null;
      const txUrl = txHash
        ? buildEvmExplorerTxUrl({
            explorerBaseUrl: frontendConfig.tempoExplorerUrl,
            txHash,
          })
        : null;
      toast.success('Tempo testnet fee tokens funded', {
        id: toastId,
        description: (
          <span>
            Recipient:&nbsp;
            <code>{compactHex(thresholdOwnerAddress)}</code>
            {txHash ? (
              <>
                <br />
                First tx:&nbsp;
              </>
            ) : null}
            {txHash && txUrl ? (
              <a href={txUrl} target="_blank" rel="noopener noreferrer">
                <code>{compactHex(txHash)}</code>
              </a>
            ) : txHash ? (
              <code>{compactHex(txHash)}</code>
            ) : null}
          </span>
        ),
      });
      return true;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('[DemoPage][TempoFaucetError]', {
        atIso: new Date().toISOString(),
        error,
        message,
      });
      toast.error(`Tempo faucet funding failed: ${message}`, {
        id: toastId,
        description: null,
      });
      return false;
    } finally {
      setTempoFaucetFundingLoading(false);
    }
  }, [
    frontendConfig,
    isLoggedIn,
    refreshTempoUserFeeTokenBalance,
    resolveThresholdOwnerAddressForEvmFamily,
    tempoFaucetFundingLoading,
    walletId,
  ]);

  const handleSignTempoThresholdTx = useCallback(async () => {
    if (!canSignTempo || !walletId) return;
    const toastId = 'tempo-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoThresholdSignLoading(true);
    toast.loading('Signing Tempo EIP-2718 transaction…', { id: toastId, description: null });
    try {
      const requestedGreeting = tempoGreetingInput.trim();
      const thresholdOwnerAddress = await resolveThresholdOwnerAddressForEvmFamily();
      const configuredFeeToken = await refreshTempoUserFeeToken({
        silent: true,
        userAddress: thresholdOwnerAddress,
      });
      if (!isTempoAlphaUsdFeeToken(configuredFeeToken)) {
        toast.error(
          'Tempo threshold owner is not configured to pay fees with AlphaUSD. Run Prepare Tempo Fee Token, then retry.',
          { id: toastId, description: null },
        );
        return;
      }
      const alphaUsdBalance = await refreshTempoUserFeeTokenBalance({
        silent: true,
        userAddress: thresholdOwnerAddress,
        feeToken: TEMPO_ALPHA_USD_FEE_TOKEN,
      });
      if (alphaUsdBalance === null) {
        toast.error(
          'Tempo AlphaUSD balance check failed. Run Prepare Tempo Fee Token, then retry.',
          { id: toastId, description: null },
        );
        return;
      }
      if (alphaUsdBalance === 0n) {
        toast.error(
          'Tempo threshold owner has no AlphaUSD fee-token balance. Run Prepare Tempo Fee Token, then retry.',
          { id: toastId, description: null },
        );
        return;
      }
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: frontendConfig.tempoRpcUrl,
        fallbackFeeCaps: tempoEip1559FeeCaps,
      });
      const request = buildTempoTransactionGreetingRequest(requestedGreeting, feeCaps);
      const greetingCall = request.tx.calls[0]!;
      const execution = await seams.tempo.executeEvmFamilyTransaction({
        walletSession: walletSessionRefFromSession({
          walletId,
          walletSessionUserId: walletId,
        }),
        request,
        chainTarget: resolveDemoThresholdEcdsaChainTarget('tempo', frontendConfig.chains),
        finalization: {
          timeoutMs: EVM_GREETING_FINALITY_TIMEOUT_MS,
          pollIntervalMs: EVM_GREETING_FINALITY_POLL_INTERVAL_MS,
        },
        payloadExpectation: {
          kind: 'tempo_eip2718_calls',
          calls: [
            {
              to: greetingCall.to,
              input: greetingCall.input || '0x',
            },
          ],
        },
        options: {
          onEvent: (event: SigningFlowEvent) =>
            handleSigningToastEvent(event, {
              toastId,
              chainLabel: 'Tempo',
              successMessage: 'Tempo EIP-2718 transaction complete',
            }),
        },
        postFinalizationCheck: async () => {
          await waitForExpectedGreeting({
            fetchGreeting: fetchTempoGreeting,
            expectedGreeting: requestedGreeting,
          });
          await refreshThresholdOwnerAddress();
        },
      });
      const txUrl = buildEvmExplorerTxUrl({
        explorerBaseUrl: frontendConfig.tempoExplorerUrl,
        txHash: execution.txHash,
      });
      const txLabel = compactHex(execution.txHash);

      toast.success('Tempo EIP-2718 transaction finalized', {
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
        toast.error(
          `Tempo transaction finalized, but post-finalization refresh failed: ${message}`,
          {
            id: toastId,
            description: null,
          },
        );
        console.error('[DemoPage][TempoPostFinalizationSyncError]', {
          atIso: new Date().toISOString(),
          message,
          error: resolvedError,
        });
        return;
      }
      if (isUserCancellationError(resolvedError)) {
        toast.error('Tempo EIP-2718 transaction cancelled by user.', {
          id: toastId,
          description: null,
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
          `Tempo broadcast rejected fee payment (raw have ${insufficient.haveWei.toString()}, need ${insufficient.wantWei.toString()}). Run Prepare Tempo Fee Token, then retry.`,
          { id: toastId, description: null },
        );
      } else {
        toast.error(`Tempo EIP-2718 transaction failed: ${message}`, {
          id: toastId,
          description: null,
        });
      }
    } finally {
      setTempoThresholdSignLoading(false);
    }
  }, [
    canSignTempo,
    fetchTempoGreeting,
    frontendConfig,
    refreshTempoUserFeeToken,
    refreshTempoUserFeeTokenBalance,
    refreshThresholdOwnerAddress,
    resolveThresholdOwnerAddressForEvmFamily,
    seams,
    tempoEip1559FeeCaps,
    tempoGreetingInput,
    walletId,
  ]);

  return {
    tempoThresholdSignLoading,
    tempoFeeTokenFundingLoading: tempoFaucetFundingLoading,
    tempoPreparationUnavailableReason,
    handleFundTempoFeeTokens,
    handleSignTempoThresholdTx,
  };
}
