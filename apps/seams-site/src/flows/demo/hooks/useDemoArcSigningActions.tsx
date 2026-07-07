import { useCallback, useState } from 'react';
import { walletSessionRefFromSession } from '@seams/sdk/advanced';
import { type SigningFlowEvent, useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG } from '@/config';
import {
  EVM_GREETING_FINALITY_POLL_INTERVAL_MS,
  EVM_GREETING_FINALITY_TIMEOUT_MS,
  buildEvmExplorerTxUrl,
  buildDemoEip1559Request,
  compactHex,
  formatWeiToEth,
  isUserCancellationError,
  parseInsufficientFundsError,
  readEvmNativeBalance,
  resolveClickTimeEip1559FeeCaps,
  waitForExpectedGreeting,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import { resolveDemoThresholdEcdsaChainTarget } from '../demoChainTargets';
import { handleSigningToastEvent } from './signingToast';
import type { EvmAddress } from './demoThresholdTypes';

type UseDemoArcSigningActionsArgs = {
  canSignEvm: boolean;
  walletId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  arcGreetingInput: string;
  arcEip1559FeeCaps: Eip1559FeeCaps;
  fetchArcGreeting: (opts?: { silent?: boolean }) => Promise<string | null>;
  refreshThresholdOwnerAddress: () => Promise<string | null>;
  resolveThresholdOwnerAddressForEvmFamily: () => Promise<EvmAddress>;
};

type ArcNativeGasPreflightFailure = Error & {
  code: 'arc_native_gas_insufficient';
  details: {
    thresholdOwnerAddress: EvmAddress;
    rpcUrl: string;
    balanceWei: bigint;
    requiredWei: bigint;
  };
};

function createArcNativeGasPreflightFailure(args: {
  thresholdOwnerAddress: EvmAddress;
  rpcUrl: string;
  balanceWei: bigint;
  requiredWei: bigint;
}): ArcNativeGasPreflightFailure {
  const error = new Error(
    `ARC threshold owner ${args.thresholdOwnerAddress} has insufficient native gas balance (have ${formatWeiToEth(args.balanceWei)}, need ${formatWeiToEth(args.requiredWei)} native tokens).`,
  ) as ArcNativeGasPreflightFailure;
  error.code = 'arc_native_gas_insufficient';
  error.details = {
    thresholdOwnerAddress: args.thresholdOwnerAddress,
    rpcUrl: args.rpcUrl,
    balanceWei: args.balanceWei,
    requiredWei: args.requiredWei,
  };
  return error;
}

function isArcNativeGasPreflightFailure(error: unknown): error is ArcNativeGasPreflightFailure {
  return (
    Boolean(error) &&
    typeof error === 'object' &&
    (error as { code?: unknown }).code === 'arc_native_gas_insufficient'
  );
}

export function useDemoArcSigningActions(args: UseDemoArcSigningActionsArgs) {
  const {
    canSignEvm,
    walletId,
    seams,
    arcGreetingInput,
    arcEip1559FeeCaps,
    fetchArcGreeting,
    refreshThresholdOwnerAddress,
    resolveThresholdOwnerAddressForEvmFamily,
  } = args;

  const [evmThresholdSignLoading, setEvmThresholdSignLoading] = useState(false);

  const handleSignEvmThresholdTx = useCallback(async () => {
    if (!canSignEvm || !walletId) return;
    const toastId = 'evm-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setEvmThresholdSignLoading(true);
    toast.loading('Signing EVM transaction…', { id: toastId, description: null });
    let arcThresholdOwnerAddressForAttempt: EvmAddress | null = null;
    let arcNativeBalanceWeiForAttempt: bigint | null = null;
    let requiredNativeWeiForAttempt: bigint | null = null;
    try {
      const requestedGreeting = arcGreetingInput.trim();
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        fallbackFeeCaps: arcEip1559FeeCaps,
      });
      const request = buildDemoEip1559Request(requestedGreeting, feeCaps);
      const arcThresholdOwnerAddress = await resolveThresholdOwnerAddressForEvmFamily();
      arcThresholdOwnerAddressForAttempt = arcThresholdOwnerAddress;
      const requiredNativeWei = request.tx.gasLimit * request.tx.maxFeePerGas + request.tx.value;
      requiredNativeWeiForAttempt = requiredNativeWei;
      const arcNativeBalanceWei = await readEvmNativeBalance({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        address: arcThresholdOwnerAddress,
        blockTag: 'pending',
      });
      arcNativeBalanceWeiForAttempt = arcNativeBalanceWei;
      if (arcNativeBalanceWei < requiredNativeWei) {
        throw createArcNativeGasPreflightFailure({
          thresholdOwnerAddress: arcThresholdOwnerAddress,
          rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
          balanceWei: arcNativeBalanceWei,
          requiredWei: requiredNativeWei,
        });
      }
      const execution = await seams.tempo.executeEvmFamilyTransaction({
        walletSession: walletSessionRefFromSession({
          walletId,
          walletSessionUserId: walletId,
        }),
        request,
        chainTarget: resolveDemoThresholdEcdsaChainTarget('evm', FRONTEND_CONFIG.chains),
        finalization: {
          timeoutMs: EVM_GREETING_FINALITY_TIMEOUT_MS,
          pollIntervalMs: EVM_GREETING_FINALITY_POLL_INTERVAL_MS,
        },
        payloadExpectation: {
          to: request.tx.to,
          input: request.tx.data || '0x',
        },
        options: {
          onEvent: (event: SigningFlowEvent) =>
            handleSigningToastEvent(event, {
              toastId,
              chainLabel: 'EVM',
              successMessage: 'EVM transaction complete',
            }),
        },
        postFinalizationCheck: async () => {
          await waitForExpectedGreeting({
            fetchGreeting: fetchArcGreeting,
            expectedGreeting: requestedGreeting,
          });
          await refreshThresholdOwnerAddress();
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
      if (isArcNativeGasPreflightFailure(resolvedError)) {
        toast.error(resolvedError.message, { id: toastId, description: null });
        console.error('[DemoPage][ArcNativeGasPreflightFailure]', {
          atIso: new Date().toISOString(),
          rpcUrl: resolvedError.details.rpcUrl,
          thresholdOwnerAddress: resolvedError.details.thresholdOwnerAddress,
          balanceWei: resolvedError.details.balanceWei.toString(),
          requiredWei: resolvedError.details.requiredWei.toString(),
        });
        return;
      }
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        const preflightSawEnoughGas =
          arcNativeBalanceWeiForAttempt !== null &&
          requiredNativeWeiForAttempt !== null &&
          arcNativeBalanceWeiForAttempt >= requiredNativeWeiForAttempt;
        let toastMessage: string;
        if (preflightSawEnoughGas && arcNativeBalanceWeiForAttempt !== null) {
          toastMessage = `ARC broadcast reported insufficient funds, but preflight saw ${formatWeiToEth(
            arcNativeBalanceWeiForAttempt,
          )} native tokens for ${arcThresholdOwnerAddressForAttempt || 'the threshold owner'}. Refresh the wallet session and retry.`;
        } else {
          toastMessage = `ARC threshold owner${arcThresholdOwnerAddressForAttempt ? ` ${arcThresholdOwnerAddressForAttempt}` : ''} has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`;
        }
        toast.error(toastMessage, { id: toastId, description: null });
        console.error('[DemoPage][ArcBroadcastInsufficientFunds]', {
          atIso: new Date().toISOString(),
          rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
          thresholdOwnerAddress: arcThresholdOwnerAddressForAttempt,
          preflightBalanceWei:
            arcNativeBalanceWeiForAttempt !== null ? arcNativeBalanceWeiForAttempt.toString() : null,
          preflightRequiredWei:
            requiredNativeWeiForAttempt !== null ? requiredNativeWeiForAttempt.toString() : null,
          preflightSawEnoughGas,
          haveWei: insufficient.haveWei.toString(),
          wantWei: insufficient.wantWei.toString(),
          error: resolvedError,
        });
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
    refreshThresholdOwnerAddress,
    resolveThresholdOwnerAddressForEvmFamily,
    seams,
    walletId,
  ]);

  return {
    evmThresholdSignLoading,
    handleSignEvmThresholdTx,
  };
}
