import { useCallback, useState } from 'react';
import { walletSessionRefFromSession } from '@seams/sdk/advanced';
import { SigningEventPhase, type SigningFlowEvent, useSeams } from '@seams/sdk/react';
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

    const requestedGreeting = arcGreetingInput.trim();
    /* Cached caps (interval-refreshed by useDemoEip1559FeeCaps) keep the click
       path free of RPC latency so the signing modal opens immediately. */
    const request = buildDemoEip1559Request(requestedGreeting, arcEip1559FeeCaps);
    const requiredNativeWei = request.tx.gasLimit * request.tx.maxFeePerGas + request.tx.value;

    /* The native-gas preflight runs concurrently with the signing flow instead
       of gating the modal. A failure flips shouldAbort so the lifecycle
       cancels before broadcast; once the broadcast starts, the (now stale)
       preflight result can no longer abort the transaction. The outcome lands
       in a holder read synchronously at error time, so a still-pending
       preflight never delays error reporting. */
    type ArcPreflightOutcome =
      | { ok: true; thresholdOwnerAddress: EvmAddress; balanceWei: bigint }
      | { ok: false; error: Error };
    const preflightState: { outcome: ArcPreflightOutcome | null } = { outcome: null };
    let broadcastStarted = false;
    void (async (): Promise<ArcPreflightOutcome> => {
      const thresholdOwnerAddress = await resolveThresholdOwnerAddressForEvmFamily();
      const balanceWei = await readEvmNativeBalance({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        address: thresholdOwnerAddress,
        blockTag: 'pending',
      });
      if (balanceWei < requiredNativeWei) {
        throw createArcNativeGasPreflightFailure({
          thresholdOwnerAddress,
          rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
          balanceWei,
          requiredWei: requiredNativeWei,
        });
      }
      return { ok: true, thresholdOwnerAddress, balanceWei };
    })()
      .catch(
        (error: unknown): ArcPreflightOutcome => ({
          ok: false,
          error: error instanceof Error ? error : new Error(String(error)),
        }),
      )
      .then((outcome) => {
        preflightState.outcome = outcome;
      });

    try {
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
          kind: 'evm_eip1559',
          to: request.tx.to ?? null,
          input: request.tx.data || '0x',
        },
        options: {
          shouldAbort: () => !broadcastStarted && preflightState.outcome?.ok === false,
          onEvent: (event: SigningFlowEvent) => {
            if (event.phase === SigningEventPhase.STEP_12_BROADCAST_STARTED) {
              broadcastStarted = true;
            }
            handleSigningToastEvent(event, {
              toastId,
              chainLabel: 'EVM',
              successMessage: 'EVM transaction complete',
            });
          },
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
      /* A preflight failure trips shouldAbort, which surfaces here as a
         cancellation — report the preflight error instead of "cancelled". */
      const preflight = preflightState.outcome;
      const resolvedError: unknown =
        preflight && !preflight.ok && isUserCancellationError(error) ? preflight.error : error;
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
        /* preflight.ok means the concurrent balance check saw enough gas
           (it rejects otherwise), so a broadcast-side failure is a surprise.
           A failed gas preflight still carries the observed address/balance. */
        const preflightGasFailure =
          preflight && !preflight.ok && isArcNativeGasPreflightFailure(preflight.error)
            ? preflight.error
            : null;
        const preflightOwnerAddress = preflight?.ok
          ? preflight.thresholdOwnerAddress
          : (preflightGasFailure?.details.thresholdOwnerAddress ?? null);
        const preflightBalanceWei = preflight?.ok
          ? preflight.balanceWei
          : (preflightGasFailure?.details.balanceWei ?? null);
        let toastMessage: string;
        if (preflight?.ok) {
          toastMessage = `ARC broadcast reported insufficient funds, but preflight saw ${formatWeiToEth(
            preflight.balanceWei,
          )} native tokens for ${preflight.thresholdOwnerAddress}. Refresh the wallet session and retry.`;
        } else {
          toastMessage = `ARC threshold owner${preflightOwnerAddress ? ` ${preflightOwnerAddress}` : ''} has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`;
        }
        toast.error(toastMessage, { id: toastId, description: null });
        console.error('[DemoPage][ArcBroadcastInsufficientFunds]', {
          atIso: new Date().toISOString(),
          rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
          thresholdOwnerAddress: preflightOwnerAddress,
          preflightBalanceWei: preflightBalanceWei !== null ? preflightBalanceWei.toString() : null,
          preflightRequiredWei: requiredNativeWei.toString(),
          preflightSawEnoughGas: preflight?.ok ?? false,
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
