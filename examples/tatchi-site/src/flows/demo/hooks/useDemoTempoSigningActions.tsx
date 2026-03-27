import { useCallback, useState } from 'react';
import { createIntentId } from '@tatchi-xyz/sdk';
import { useTatchi } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

import { FRONTEND_CONFIG, type FrontendConfig } from '@/config';
import {
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_DRIP_GAS_LIMIT,
  TEMPO_GREETING_CONTRACT,
  buildEvmExplorerTxUrl,
  buildTempoEip1559GreetingRequest,
  compactHex,
  encodeTempoDripToInput,
  formatWeiToEth,
  isEvmAddress,
  isUserCancellationError,
  parseInsufficientFundsError,
  resolveClickTimeEip1559FeeCaps,
  readTempoFaucetHasDripped,
  waitForExpectedGreeting,
  type Eip1559FeeCaps,
} from '../demoEvmHelpers';
import type { EvmAddress } from './demoThresholdTypes';

type TempoSponsoredCallResponse = {
  ok: boolean;
  txHash?: string;
  policyId?: string;
  message?: string;
  code?: string;
};

const TEMPO_FEE_TOKEN_DECIMALS = 6n;

function formatTempoFeeTokenAmount(raw: bigint | null): string {
  if (raw == null) return 'unknown';
  const negative = raw < 0n;
  const abs = negative ? -raw : raw;
  const scale = 10n ** TEMPO_FEE_TOKEN_DECIMALS;
  const whole = abs / scale;
  const fraction = (abs % scale).toString().padStart(Number(TEMPO_FEE_TOKEN_DECIMALS), '0');
  const trimmedFraction = fraction.replace(/0+$/, '');
  const value = trimmedFraction ? `${whole}.${trimmedFraction}` : `${whole}`;
  return negative ? `-${value}` : value;
}

function buildTempoSponsoredCallUrl(relayerUrl: string): string {
  const trimmed = String(relayerUrl || '').trim();
  return `${trimmed.replace(/\/$/, '')}/sponsorships/evm/call`;
}

type UseDemoTempoSigningActionsArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  frontendConfig?: Pick<
    FrontendConfig,
    'managedRegistration' | 'relayerUrl' | 'tempoExplorerUrl' | 'tempoRpcUrl'
  >;
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
    frontendConfig = FRONTEND_CONFIG,
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
    let thresholdSenderForAttempt: EvmAddress | null = null;
    let dripTokensForAttempt: EvmAddress[] = [];
    try {
      const managedRegistration = frontendConfig.managedRegistration;
      const relayerUrl = String(frontendConfig.relayerUrl || '').trim();
      if (!managedRegistration?.environmentId || !managedRegistration.publishableKey) {
        throw new Error('Managed registration is not configured for Tempo sponsorship.');
      }
      if (!relayerUrl) {
        throw new Error('Relay URL is not configured for Tempo sponsorship.');
      }
      const configuredTokenRaw = String(tempoUserFeeToken || '').trim();
      const dripToken = isEvmAddress(configuredTokenRaw)
        ? configuredTokenRaw
        : TEMPO_ALPHA_USD_FEE_TOKEN;
      dripTokensForAttempt = [dripToken];
      const thresholdSender = await resolveThresholdSenderForEvmFamily();
      if (!isEvmAddress(thresholdSender)) {
        throw new Error('Unable to resolve the Tempo threshold sender address.');
      }
      thresholdSenderForAttempt = thresholdSender;
      const alreadyDripped = await readTempoFaucetHasDripped({
        rpcUrl: frontendConfig.tempoRpcUrl,
        contract: TEMPO_GREETING_CONTRACT,
        account: thresholdSender,
      });
      if (alreadyDripped) {
        const tokenBalance = await refreshTempoUserFeeTokenBalance({
          silent: true,
          userAddress: thresholdSender,
          feeToken: dripToken,
        });
        toast.success('Tempo drip already claimed for this wallet', {
          id: toastId,
          description: (
            <span>
              Wallet:&nbsp;
              <code>{compactHex(thresholdSender)}</code>
              <br />
              Token:&nbsp;
              <code>{compactHex(dripToken)}</code>
              <br />
              Balance:&nbsp;
              <code>{formatTempoFeeTokenAmount(tokenBalance)} AlphaUSD</code>
            </span>
          ),
        });
        return;
      }
      const idempotencyKey = createIntentId('tempo_drip_click');
      const response = await fetch(buildTempoSponsoredCallUrl(relayerUrl), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${managedRegistration.publishableKey}`,
          'content-type': 'application/json',
          'x-tatchi-environment-id': managedRegistration.environmentId,
        },
        body: JSON.stringify({
          environmentId: managedRegistration.environmentId,
          nearAccountId,
          walletAddress: thresholdSender,
          chainId: 42_431,
          call: {
            to: TEMPO_GREETING_CONTRACT,
            data: encodeTempoDripToInput(thresholdSender, dripTokensForAttempt),
            gasLimit: TEMPO_DRIP_GAS_LIMIT.toString(10),
            value: '0',
          },
          idempotencyKey,
        }),
      });
      let payload: TempoSponsoredCallResponse | null = null;
      try {
        payload = (await response.json()) as TempoSponsoredCallResponse;
      } catch {
        payload = null;
      }
      if (!response.ok || !payload?.ok) {
        const reason =
          String(payload?.message || '').trim() ||
          `Relay returned ${response.status} ${response.statusText || 'request failed'}`;
        const failure = new Error(reason) as Error & { code?: string; txHash?: `0x${string}` };
        failure.code = String(payload?.code || '').trim() || undefined;
        const payloadTxHash = String(payload?.txHash || '').trim();
        if (/^0x[0-9a-fA-F]{64}$/.test(payloadTxHash)) {
          failure.txHash = payloadTxHash as `0x${string}`;
        }
        throw failure;
      }
      const txHash = String(payload.txHash || '').trim();
      if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
        throw new Error('Relay did not return a valid Tempo transaction hash.');
      }
      executedTxHash = txHash as `0x${string}`;
      await refreshTempoUserFeeTokenBalance({
        silent: true,
        userAddress: thresholdSender,
        feeToken: dripToken,
      });
      const txUrl = buildEvmExplorerTxUrl({
        explorerBaseUrl: frontendConfig.tempoExplorerUrl,
        txHash: executedTxHash,
      });
      const txLabel = compactHex(executedTxHash);

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
      const errorTxHash =
        resolvedError &&
        typeof resolvedError === 'object' &&
        'txHash' in resolvedError &&
        /^0x[0-9a-fA-F]{64}$/.test(String((resolvedError as { txHash?: unknown }).txHash || '').trim())
          ? (String((resolvedError as { txHash?: unknown }).txHash || '').trim() as `0x${string}`)
          : undefined;
      let resolvedMessage = message;
      if (errorCode === 'tx_reverted' && thresholdSenderForAttempt) {
        try {
          const alreadyDripped = await readTempoFaucetHasDripped({
            rpcUrl: frontendConfig.tempoRpcUrl,
            contract: TEMPO_GREETING_CONTRACT,
            account: thresholdSenderForAttempt,
          });
          if (alreadyDripped) {
            const tokenBalance = await refreshTempoUserFeeTokenBalance({
              silent: true,
              userAddress: thresholdSenderForAttempt,
              feeToken: dripTokensForAttempt[0] || TEMPO_ALPHA_USD_FEE_TOKEN,
            });
            resolvedMessage = `Faucet already claimed for ${compactHex(thresholdSenderForAttempt)} (balance ${formatTempoFeeTokenAmount(tokenBalance)} AlphaUSD).`;
          }
        } catch {}
      }
      const unavailable =
        errorCode === 'sponsored_evm_call_disabled' ||
        errorCode === 'runtime_snapshot_not_found' ||
        errorCode === 'publishable_key_auth_unavailable';
      toast.error(
        unavailable
          ? `Tempo sponsorship unavailable: ${resolvedMessage}`
          : `Tempo drip failed: ${resolvedMessage}`,
        { id: toastId, description: null },
      );
      console.error('[DemoPage][TempoDripError]', {
        atIso: new Date().toISOString(),
        error: resolvedError,
        message: resolvedMessage,
        dripTokensForAttempt,
        txHash: executedTxHash || errorTxHash,
      });
    } finally {
      setTempoDripLoading(false);
    }
  }, [
    frontendConfig,
    isLoggedIn,
    nearAccountId,
    refreshTempoUserFeeTokenBalance,
    resolveThresholdSenderForEvmFamily,
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
        rpcUrl: frontendConfig.tempoRpcUrl,
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
    frontendConfig,
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
