import { useCallback, useState } from 'react';
import { walletSessionRefFromSession, walletSubjectIdFromWalletProfile } from '@seams/sdk';
import { useSeams } from '@seams/sdk/react';
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
  nearAccountId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  arcGreetingInput: string;
  arcEip1559FeeCaps: Eip1559FeeCaps;
  fetchArcGreeting: (opts?: { silent?: boolean }) => Promise<string | null>;
  refreshThresholdEvmFundingAddress: () => Promise<string | null>;
  resolveThresholdSenderForEvmFamily: (opts?: {
    chain?: 'tempo' | 'evm';
    bootstrapIfMissing?: boolean;
  }) => Promise<EvmAddress>;
};

type ArcNativeGasPreflightFailure = Error & {
  code: 'arc_native_gas_insufficient';
  details: {
    sender: EvmAddress;
    balanceWei: bigint;
    requiredWei: bigint;
  };
};

function createArcNativeGasPreflightFailure(args: {
  sender: EvmAddress;
  balanceWei: bigint;
  requiredWei: bigint;
}): ArcNativeGasPreflightFailure {
  const error = new Error(
    `ARC sender ${args.sender} has insufficient native gas balance (have ${formatWeiToEth(args.balanceWei)}, need ${formatWeiToEth(args.requiredWei)} native tokens).`,
  ) as ArcNativeGasPreflightFailure;
  error.code = 'arc_native_gas_insufficient';
  error.details = {
    sender: args.sender,
    balanceWei: args.balanceWei,
    requiredWei: args.requiredWei,
  };
  return error;
}

function isArcNativeGasPreflightFailure(
  error: unknown,
): error is ArcNativeGasPreflightFailure {
  return (
    Boolean(error) &&
    typeof error === 'object' &&
    (error as { code?: unknown }).code === 'arc_native_gas_insufficient'
  );
}

export function useDemoArcSigningActions(args: UseDemoArcSigningActionsArgs) {
  const {
    canSignEvm,
    nearAccountId,
    seams,
    arcGreetingInput,
    arcEip1559FeeCaps,
    fetchArcGreeting,
    refreshThresholdEvmFundingAddress,
    resolveThresholdSenderForEvmFamily,
  } = args;

  const [evmThresholdSignLoading, setEvmThresholdSignLoading] = useState(false);

  const handleSignEvmThresholdTx = useCallback(async () => {
    if (!canSignEvm || !nearAccountId) return;
    const toastId = 'evm-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setEvmThresholdSignLoading(true);
    toast.loading('Signing EVM transaction…', { id: toastId, description: null });
    let arcSenderForAttempt: EvmAddress | null = null;
    try {
      const requestedGreeting = arcGreetingInput.trim();
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        fallbackFeeCaps: arcEip1559FeeCaps,
      });
      const request = buildDemoEip1559Request(requestedGreeting, feeCaps);
      const arcSender = await resolveThresholdSenderForEvmFamily({
        chain: 'evm',
        bootstrapIfMissing: true,
      });
      arcSenderForAttempt = arcSender;
      const requiredNativeWei = request.tx.gasLimit * request.tx.maxFeePerGas + request.tx.value;
      const arcNativeBalanceWei = await readEvmNativeBalance({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        address: arcSender,
        blockTag: 'pending',
      });
      if (arcNativeBalanceWei < requiredNativeWei) {
        throw createArcNativeGasPreflightFailure({
          sender: arcSender,
          balanceWei: arcNativeBalanceWei,
          requiredWei: requiredNativeWei,
        });
      }
      const execution = await seams.tempo.executeEvmFamilyTransaction({
        walletSession: walletSessionRefFromSession({
          walletId: nearAccountId,
          userId: nearAccountId,
        }),
        subjectId: walletSubjectIdFromWalletProfile({ walletId: nearAccountId }),
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
          onEvent: (event) =>
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
          await refreshThresholdEvmFundingAddress();
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
          sender: resolvedError.details.sender,
          balanceWei: resolvedError.details.balanceWei.toString(),
          requiredWei: resolvedError.details.requiredWei.toString(),
        });
        return;
      }
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `ARC sender${arcSenderForAttempt ? ` ${arcSenderForAttempt}` : ''} has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId, description: null },
        );
        console.error('[DemoPage][ArcBroadcastInsufficientFunds]', {
          atIso: new Date().toISOString(),
          sender: arcSenderForAttempt,
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
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    resolveThresholdSenderForEvmFamily,
    seams,
  ]);

  return {
    evmThresholdSignLoading,
    handleSignEvmThresholdTx,
  };
}
