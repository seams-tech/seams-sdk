import { useCallback, useState } from 'react';
import { walletSessionRefFromSession } from '@seams/sdk/advanced';
import { type SigningFlowEvent, useSeams } from '@seams/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG, type FrontendConfig } from '@/config';
import {
  EVM_GREETING_FINALITY_POLL_INTERVAL_MS,
  EVM_GREETING_FINALITY_TIMEOUT_MS,
  buildEvmExplorerTxUrl,
  buildTempoDripRequest,
  buildTempoEip1559GreetingRequest,
  compactHex,
  formatWeiToEth,
  isEvmAddress,
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
  | 'chains'
  | 'managedRegistration'
  | 'relayerUrl'
  | 'tempoExplorerUrl'
  | 'tempoFeeToken'
  | 'tempoRpcUrl'
>;

type JsonRecord = Record<string, unknown>;

function stripTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function requireTempoSponsorshipRouteUrl(frontendConfig: TempoSigningFrontendConfig): string {
  const relayerUrl = String(frontendConfig.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Tempo sponsorship requires VITE_RELAYER_URL');
  }
  return `${stripTrailingSlash(relayerUrl)}/sponsorships/evm/call`;
}

function requireTempoManagedRegistration(frontendConfig: TempoSigningFrontendConfig): {
  readonly environmentId: string;
  readonly publishableKey: string;
} {
  const managedRegistration = frontendConfig.managedRegistration;
  if (!managedRegistration) {
    throw new Error('Tempo sponsorship requires managed registration config');
  }
  return {
    environmentId: managedRegistration.environmentId,
    publishableKey: managedRegistration.publishableKey,
  };
}

function resolveTempoDripToken(frontendConfig: TempoSigningFrontendConfig): EvmAddress {
  const token = String(frontendConfig.tempoFeeToken || TEMPO_ALPHA_USD_FEE_TOKEN).trim();
  if (!isEvmAddress(token)) {
    throw new Error(`Invalid Tempo drip token address: ${token || 'empty'}`);
  }
  return token;
}

function randomBrowserNonce(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function buildTempoDripIdempotencyKey(input: {
  readonly walletId: string;
  readonly recipient: EvmAddress;
}): string {
  return `tempo-drip:${input.walletId}:${input.recipient.toLowerCase()}:${randomBrowserNonce()}`;
}

function parseJsonRecord(text: string): JsonRecord {
  try {
    const parsed = text ? JSON.parse(text) : {};
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as JsonRecord)
      : {};
  } catch {
    return {};
  }
}

async function readJsonRecord(response: Response): Promise<JsonRecord> {
  return parseJsonRecord(await response.text());
}

function responseMessage(body: JsonRecord, fallback: string): string {
  return String(body.message || body.code || fallback).trim() || fallback;
}

function normalizeTxHash(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{64}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

async function requestSponsoredTempoDrip(input: {
  readonly frontendConfig: TempoSigningFrontendConfig;
  readonly walletId: string;
  readonly thresholdOwnerAddress: EvmAddress;
  readonly tokenAddress: EvmAddress;
  readonly feeCaps: Eip1559FeeCaps;
}): Promise<`0x${string}`> {
  const routeUrl = requireTempoSponsorshipRouteUrl(input.frontendConfig);
  const managedRegistration = requireTempoManagedRegistration(input.frontendConfig);
  const request = buildTempoDripRequest({
    feeCaps: input.feeCaps,
    recipient: input.thresholdOwnerAddress,
    tokenAddresses: [input.tokenAddress],
  });
  const call = request.tx.calls[0];
  if (!call) {
    throw new Error('Tempo drip request did not include a call');
  }
  const response = await fetch(routeUrl, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${managedRegistration.publishableKey}`,
      'content-type': 'application/json',
      'x-seams-environment-id': managedRegistration.environmentId,
    },
    body: JSON.stringify({
      environmentId: managedRegistration.environmentId,
      walletId: input.walletId,
      walletAddress: input.thresholdOwnerAddress,
      chainId: request.tx.chainId,
      call: {
        to: call.to,
        data: call.input,
        gasLimit: request.tx.gasLimit.toString(10),
        value: call.value.toString(10),
      },
      idempotencyKey: buildTempoDripIdempotencyKey({
        walletId: input.walletId,
        recipient: input.thresholdOwnerAddress,
      }),
    }),
  });
  const body = await readJsonRecord(response);
  if (!response.ok || body.ok !== true) {
    throw new Error(responseMessage(body, `Tempo sponsorship failed with HTTP ${response.status}`));
  }
  const txHash = normalizeTxHash(body.txHash);
  if (!txHash) {
    throw new Error('Relay did not return a valid Tempo transaction hash.');
  }
  return txHash;
}

type UseDemoTempoSigningActionsArgs = {
  isLoggedIn: boolean;
  walletId?: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  frontendConfig?: TempoSigningFrontendConfig;
  canSignTempo: boolean;
  tempoGreetingInput: string;
  tempoEip1559FeeCaps: Eip1559FeeCaps;
  tempoUserFeeToken: EvmAddress | null;
  resolveThresholdOwnerAddressForEvmFamily: () => Promise<EvmAddress>;
  refreshTempoUserFeeTokenBalance: (opts?: {
    silent?: boolean;
    userAddress?: EvmAddress | null;
    feeToken?: EvmAddress | null;
  }) => Promise<bigint | null>;
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
    resolveThresholdOwnerAddressForEvmFamily,
    fetchTempoGreeting,
    refreshThresholdOwnerAddress,
  } = args;

  const [tempoThresholdSignLoading, setTempoThresholdSignLoading] = useState(false);
  const [tempoDripLoading, setTempoDripLoading] = useState(false);
  const tempoSponsorshipUnavailableReason =
    frontendConfig.managedRegistration && frontendConfig.relayerUrl
      ? null
      : 'Tempo sponsorship requires managed demo configuration.';

  const handleTempoDripToken = useCallback(async () => {
    if (!isLoggedIn || !walletId || tempoDripLoading) return;
    const toastId = 'tempo-drip-token';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoDripLoading(true);
    toast.loading('Dripping Tempo fee tokens…', { id: toastId, description: null });
    try {
      const thresholdOwnerAddress = await resolveThresholdOwnerAddressForEvmFamily();
      const tokenAddress = resolveTempoDripToken(frontendConfig);
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: frontendConfig.tempoRpcUrl,
        fallbackFeeCaps: tempoEip1559FeeCaps,
      });
      const txHash = await requestSponsoredTempoDrip({
        frontendConfig,
        walletId,
        thresholdOwnerAddress,
        tokenAddress,
        feeCaps,
      });
      await refreshTempoUserFeeTokenBalance({
        silent: true,
        userAddress: thresholdOwnerAddress,
        feeToken: tokenAddress,
      });
      const txUrl = buildEvmExplorerTxUrl({
        explorerBaseUrl: frontendConfig.tempoExplorerUrl,
        txHash,
      });
      toast.success('Tempo fee tokens dripped', {
        id: toastId,
        description: (
          <span>
            Tx hash:&nbsp;
            {txUrl ? (
              <a href={txUrl} target="_blank" rel="noopener noreferrer">
                <code>{compactHex(txHash)}</code>
              </a>
            ) : (
              <code>{compactHex(txHash)}</code>
            )}
          </span>
        ),
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('[DemoPage][TempoDripError]', {
        atIso: new Date().toISOString(),
        error,
        message,
      });
      toast.error(`Tempo drip failed: ${message}`, {
        id: toastId,
        description: null,
      });
    } finally {
      setTempoDripLoading(false);
    }
  }, [
    frontendConfig,
    isLoggedIn,
    refreshTempoUserFeeTokenBalance,
    resolveThresholdOwnerAddressForEvmFamily,
    tempoEip1559FeeCaps,
    tempoDripLoading,
    walletId,
  ]);

  const handleSignTempoThresholdTx = useCallback(async () => {
    if (!canSignTempo || !walletId) return;
    const toastId = 'tempo-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoThresholdSignLoading(true);
    toast.loading('Signing Tempo transaction…', { id: toastId, description: null });
    try {
      const requestedGreeting = tempoGreetingInput.trim();
      const feeCaps = await resolveClickTimeEip1559FeeCaps({
        rpcUrl: frontendConfig.tempoRpcUrl,
        fallbackFeeCaps: tempoEip1559FeeCaps,
      });
      const request = buildTempoEip1559GreetingRequest(requestedGreeting, feeCaps);
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
          to: request.tx.to,
          input: request.tx.data || '0x',
        },
        options: {
          onEvent: (event: SigningFlowEvent) =>
            handleSigningToastEvent(event, {
              toastId,
              chainLabel: 'Tempo',
              successMessage: 'Tempo transaction complete',
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
          `Tempo threshold owner has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
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
    frontendConfig,
    refreshThresholdOwnerAddress,
    seams,
    tempoEip1559FeeCaps,
    tempoGreetingInput,
    walletId,
  ]);

  return {
    tempoThresholdSignLoading,
    tempoDripLoading,
    tempoSponsorshipUnavailableReason,
    handleTempoDripToken,
    handleSignTempoThresholdTx,
  };
}
