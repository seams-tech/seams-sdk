import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';

import {
  ActionPhase,
  ActionResult,
  ActionType,
  TxExecutionStatus,
  useTatchi,
} from '@tatchi-xyz/sdk/react';
import type { ActionArgs, FunctionCallAction } from '@tatchi-xyz/sdk/react';

import { LoadingButton } from './LoadingButton';
import Refresh from './icons/Refresh';
import { useSetGreeting } from '../hooks/useSetGreeting';
import { NEAR_EXPLORER_BASE_URL, WEBAUTHN_CONTRACT_ID } from '../types';
import {
  readCachedThresholdKeyRef,
  type ThresholdEcdsaChain,
  type ThresholdEcdsaKeyRef,
} from '../utils/thresholdSigners';
import './DemoPage.css';

function shortenHex(value: string, size = 24): string {
  if (!value) return '—';
  return value.length <= size ? value : `${value.slice(0, size)}…`;
}

function buildDemoTempoTransactionRequest() {
  const to = `0x${'11'.repeat(20)}` as `0x${string}`;
  const input = '0x' as `0x${string}`;
  return {
    chain: 'tempo' as const,
    kind: 'tempoTransaction' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 42431n,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 2n,
      gasLimit: 21_000n,
      calls: [{ to, value: 0n, input }],
      accessList: [],
      nonceKey: 0n,
      nonce: 1n,
      validBefore: null,
      validAfter: null,
      feePayerSignature: { kind: 'none' as const },
      aaAuthorizationList: [],
    },
  };
}

function buildDemoEip1559Request() {
  const to = `0x${'22'.repeat(20)}` as `0x${string}`;
  const data = '0x' as `0x${string}`;
  return {
    chain: 'evm' as const,
    kind: 'eip1559' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 11155111n,
      nonce: 7n,
      maxPriorityFeePerGas: 1_500_000_000n,
      maxFeePerGas: 3_000_000_000n,
      gasLimit: 21_000n,
      to,
      value: 12_345n,
      data,
      accessList: [],
    },
  };
}

type LastTempoSigned = {
  senderHashHex: string;
  rawTxHex: string;
};

type LastEvmSigned = {
  txHashHex: string;
  rawTxHex: string;
};

type DemoPageTestOverrides = {
  useTatchiHook?: typeof useTatchi;
  useSetGreetingHook?: typeof useSetGreeting;
  readCachedThresholdKeyRef?: typeof readCachedThresholdKeyRef;
};

type DemoPageProps = {
  __testOverrides?: DemoPageTestOverrides;
};

export const DemoPage: React.FC<DemoPageProps> = (props) => {
  const useTatchiHook = props.__testOverrides?.useTatchiHook || useTatchi;
  const useSetGreetingHook = props.__testOverrides?.useSetGreetingHook || useSetGreeting;
  const readCachedKeyRef =
    props.__testOverrides?.readCachedThresholdKeyRef || readCachedThresholdKeyRef;

  const [clockMs, setClockMs] = useState(() => Date.now());

  // Lightweight clock for TTL countdown display
  useEffect(() => {
    const id = window.setInterval(() => setClockMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const {
    loginState: { isLoggedIn, nearAccountId },
    tatchi,
  } = useTatchiHook();

  const { onchainGreeting, isLoading, fetchGreeting, error } = useSetGreetingHook();

  const [greetingInput, setGreetingInput] = useState('Hello from Tatchi!');
  const [txLoading, setTxLoading] = useState(false);
  const [delegateLoading, setDelegateLoading] = useState(false);
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [sessionRemainingUsesInput, setSessionRemainingUsesInput] = useState(3);
  const [sessionTtlSecondsInput, setSessionTtlSecondsInput] = useState(300);
  const [sessionStatus, setSessionStatus] = useState<{
    sessionId: string;
    status: 'active' | 'exhausted' | 'expired' | 'not_found';
    remainingUses?: number;
    expiresAtMs?: number;
    createdAtMs?: number;
  } | null>(null);

  const [tempoThresholdSignLoading, setTempoThresholdSignLoading] = useState(false);
  const [evmThresholdSignLoading, setEvmThresholdSignLoading] = useState(false);
  const [thresholdKeyRefs, setThresholdKeyRefs] = useState<{
    evm: ThresholdEcdsaKeyRef | null;
    tempo: ThresholdEcdsaKeyRef | null;
  }>({
    evm: null,
    tempo: null,
  });
  const [lastTempoSigned, setLastTempoSigned] = useState<LastTempoSigned | null>(null);
  const [lastEvmSigned, setLastEvmSigned] = useState<LastEvmSigned | null>(null);

  useEffect(() => {
    if (!nearAccountId) {
      setThresholdKeyRefs({ evm: null, tempo: null });
      setLastTempoSigned(null);
      setLastEvmSigned(null);
      return;
    }

    setThresholdKeyRefs({
      evm: readCachedKeyRef(nearAccountId, 'evm'),
      tempo: readCachedKeyRef(nearAccountId, 'tempo'),
    });
    setLastTempoSigned(null);
    setLastEvmSigned(null);
  }, [nearAccountId, readCachedKeyRef]);

  const setThresholdKeyRefForChain = useCallback(
    (chain: ThresholdEcdsaChain, keyRef: ThresholdEcdsaKeyRef) => {
      setThresholdKeyRefs((prev) => ({ ...prev, [chain]: keyRef }));
    },
    [],
  );

  const refreshSessionStatus = useCallback(async () => {
    if (!nearAccountId) return;
    try {
      const sess = await tatchi.auth.getSession(nearAccountId);
      setSessionStatus(sess?.signingSession || null);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`Failed to fetch session status: ${message}`, { id: 'session-status' });
    }
  }, [nearAccountId, tatchi]);

  // Fetch session status on mount/account change (best-effort; errors are toast-only)
  useEffect(() => {
    if (!isLoggedIn || !nearAccountId) return;
    void refreshSessionStatus();
  }, [isLoggedIn, nearAccountId, refreshSessionStatus]);

  const handleUnlockSession = useCallback(async () => {
    if (!nearAccountId) return;

    const remainingUses = Number.isFinite(sessionRemainingUsesInput)
      ? Math.max(0, Math.floor(sessionRemainingUsesInput))
      : undefined;
    const ttlSeconds = Number.isFinite(sessionTtlSecondsInput)
      ? Math.max(0, Math.floor(sessionTtlSecondsInput))
      : undefined;
    const ttlMs = typeof ttlSeconds === 'number' ? ttlSeconds * 1000 : undefined;

    setUnlockLoading(true);
    toast.loading('Logging in & creating session…', { id: 'unlock-session' });
    try {
      await tatchi.auth.login(nearAccountId, {
        signingSession: { ttlMs, remainingUses },
      });
      await refreshSessionStatus();
      toast.success('Session ready', { id: 'unlock-session' });
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`Failed to create session: ${message}`, { id: 'unlock-session' });
    } finally {
      setUnlockLoading(false);
    }
  }, [
    nearAccountId,
    refreshSessionStatus,
    sessionRemainingUsesInput,
    sessionTtlSecondsInput,
    tatchi,
  ]);

  const canExecuteGreeting = useCallback(
    (val: string, loggedIn: boolean, accountId?: string | null) =>
      Boolean(val?.trim()) && loggedIn && Boolean(accountId),
    [],
  );

  const handleRefreshGreeting = async () => {
    await fetchGreeting();
  };

  const createGreetingAction = useCallback(
    (greeting: string, opts?: { postfix?: string }): ActionArgs => {
      const base = greeting.trim();
      const parts = [base];
      if (opts?.postfix && opts.postfix.trim()) parts.push(`[${opts.postfix.trim()}]`);
      parts.push(`[${new Date().toLocaleTimeString()}]`);
      const message = parts.join(' ');
      return {
        type: ActionType.FunctionCall,
        methodName: 'set_greeting',
        args: { greeting: message },
        gas: '30000000000000',
        deposit: '0',
      };
    },
    [],
  );

  const handleSetGreeting = useCallback(async () => {
    if (!canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId)) return;
    const actionToExecute: FunctionCallAction = createGreetingAction(
      greetingInput,
    ) as FunctionCallAction;

    setTxLoading(true);
    try {
      await tatchi.near.executeAction({
        nearAccountId: nearAccountId!,
        receiverId: WEBAUTHN_CONTRACT_ID,
        actionArgs: actionToExecute,
        options: {
          onEvent: (event) => {
            switch (event.phase) {
              case ActionPhase.STEP_1_PREPARATION:
              case ActionPhase.STEP_3_WEBAUTHN_AUTHENTICATION:
              case ActionPhase.STEP_4_AUTHENTICATION_COMPLETE:
              case ActionPhase.STEP_5_TRANSACTION_SIGNING_PROGRESS:
              case ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE:
                toast.loading(event.message, { id: 'greeting' });
                break;
              case ActionPhase.STEP_7_BROADCASTING:
                toast.loading(event.message, { id: 'greeting' });
                break;
              case ActionPhase.ACTION_ERROR:
              case ActionPhase.WASM_ERROR:
                toast.error(`Transaction failed: ${event.error}`, { id: 'greeting' });
                break;
            }
          },
          waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
          afterCall: (success: boolean, result?: ActionResult) => {
            try {
              toast.dismiss('greeting');
            } catch {}
            const txId = result?.transactionId;
            const isSuccess = success && result?.success !== false;
            if (isSuccess && txId) {
              const txLink = `${NEAR_EXPLORER_BASE_URL}/transactions/${txId}`;
              toast.success('Greeting updated on-chain', {
                description: (
                  <a href={txLink} target="_blank" rel="noopener noreferrer">
                    View transaction on NearBlocks
                  </a>
                ),
              });
              setGreetingInput('');
              setTimeout(() => fetchGreeting(), 1000);
            } else {
              const message =
                result?.error || (isSuccess ? 'Missing transaction ID' : 'Unknown error');
              toast.error(`Greeting update failed: ${message}`);
            }
            setTxLoading(false);
          },
        },
      });
    } catch {
      setTxLoading(false);
    }
  }, [
    canExecuteGreeting,
    createGreetingAction,
    fetchGreeting,
    greetingInput,
    isLoggedIn,
    nearAccountId,
    tatchi,
  ]);

  const handleSignDelegateGreeting = useCallback(async () => {
    if (!canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId)) return;

    const { login: loginState } = await tatchi.auth.getSession();

    setDelegateLoading(true);
    try {
      const relayerUrl = tatchi.configs.relayer?.url;
      if (!relayerUrl) {
        toast.error('Relayer URL is not configured: VITE_RELAYER_URL', {
          id: 'delegate-greeting',
        });
        return;
      }

      const delegateAction = createGreetingAction(greetingInput, { postfix: 'Delegate' });
      const result = await tatchi.near.signDelegateAction({
        nearAccountId: nearAccountId!,
        delegate: {
          senderId: nearAccountId!,
          receiverId: WEBAUTHN_CONTRACT_ID,
          actions: [delegateAction],
          nonce: Date.now(),
          maxBlockHeight: 0,
          publicKey: loginState.publicKey!,
        },
        options: {
          onEvent: (event) => {
            switch (event.phase) {
              case ActionPhase.STEP_1_PREPARATION:
              case ActionPhase.STEP_2_USER_CONFIRMATION:
              case ActionPhase.STEP_5_TRANSACTION_SIGNING_PROGRESS:
                toast.loading(event.message, { id: 'delegate-greeting' });
                break;
              case ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE:
                toast.success('Delegate action signed', { id: 'delegate-greeting' });
                break;
              case ActionPhase.ACTION_ERROR:
              case ActionPhase.WASM_ERROR:
                toast.error(`Delegate signing failed: ${event.error}`, { id: 'delegate-greeting' });
                break;
            }
          },
        },
      });

      toast.success('Signed delegate for set_greeting', {
        description: (
          <span>
            Delegate hash:&nbsp;
            <code>{result.hash.slice(0, 16)}…</code>
          </span>
        ),
      });

      toast.loading('Submitting delegate to relayer…', { id: 'delegate-relay' });
      const relayResult = await tatchi.near.sendDelegateActionViaRelayer({
        relayerUrl,
        hash: result.hash,
        signedDelegate: result.signedDelegate as unknown as Record<string, unknown>,
        options: {
          afterCall: (success: boolean, res?: { ok?: boolean }) => {
            if (success && res?.ok !== false) {
              setTimeout(() => fetchGreeting(), 1000);
            }
          },
        },
      });

      toast.dismiss('delegate-relay');

      if (!relayResult.ok) {
        toast.error(`Relayer execution failed: ${relayResult.error || 'Unknown error'}`, {
          id: 'delegate-greeting',
        });
        return;
      }

      const txId = relayResult.relayerTxHash;
      if (txId) {
        const txLink = `${NEAR_EXPLORER_BASE_URL}/transactions/${txId}`;
        toast.success('Delegate executed via relayer', {
          description: (
            <a href={txLink} target="_blank" rel="noopener noreferrer">
              View transaction on NearBlocks
            </a>
          ),
          id: 'delegate-greeting',
        });
      } else {
        toast.success('Delegate submitted via relayer (no TxID)', { id: 'delegate-greeting' });
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`Delegate signing failed: ${message}`, { id: 'delegate-greeting' });
    } finally {
      setDelegateLoading(false);
    }
  }, [
    canExecuteGreeting,
    createGreetingAction,
    fetchGreeting,
    greetingInput,
    isLoggedIn,
    nearAccountId,
    tatchi,
  ]);

  const getKeyRefForChain = useCallback(
    (chain: ThresholdEcdsaChain): ThresholdEcdsaKeyRef => {
      if (!nearAccountId) throw new Error('Missing nearAccountId');

      const cached = readCachedKeyRef(nearAccountId, chain);
      if (cached) {
        const inMemory = thresholdKeyRefs[chain];
        if (inMemory !== cached) {
          setThresholdKeyRefForChain(chain, cached);
        }
        return cached;
      }

      const inMemory = thresholdKeyRefs[chain];
      if (inMemory) return inMemory;

      const chainLabel = chain === 'evm' ? 'EVM' : 'Tempo';
      throw new Error(
        `${chainLabel} threshold signer is not provisioned. Log out and log in again to provision threshold signers.`,
      );
    },
    [nearAccountId, readCachedKeyRef, setThresholdKeyRefForChain, thresholdKeyRefs],
  );

  const handleSignTempoThresholdTx = useCallback(async () => {
    if (!nearAccountId) return;
    const toastId = 'tempo-threshold-sign';
    setTempoThresholdSignLoading(true);
    toast.loading('Signing Tempo transaction with threshold signer…', { id: toastId });
    try {
      const request = buildDemoTempoTransactionRequest();
      const thresholdEcdsaKeyRef = getKeyRefForChain('tempo');
      const signed = await tatchi.tempo.signTempo({
        nearAccountId,
        request,
        options: { thresholdEcdsaKeyRef },
      });

      if (signed.kind !== 'tempoTransaction') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }

      setLastTempoSigned({
        senderHashHex: signed.senderHashHex,
        rawTxHex: signed.rawTxHex,
      });
      toast.success('Tempo threshold signature ready', { id: toastId });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`Tempo threshold signing failed: ${message}`, { id: toastId });
    } finally {
      setTempoThresholdSignLoading(false);
    }
  }, [getKeyRefForChain, nearAccountId, tatchi]);

  const handleSignEvmThresholdTx = useCallback(async () => {
    if (!nearAccountId) return;
    const toastId = 'evm-threshold-sign';
    setEvmThresholdSignLoading(true);
    toast.loading('Signing EIP-1559 transaction with threshold signer…', { id: toastId });
    try {
      const request = buildDemoEip1559Request();
      const thresholdEcdsaKeyRef = getKeyRefForChain('evm');
      const signed = await tatchi.tempo.signTempoWithThresholdEcdsa({
        nearAccountId,
        request,
        thresholdEcdsaKeyRef,
      });

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }

      setLastEvmSigned({
        txHashHex: signed.txHashHex,
        rawTxHex: signed.rawTxHex,
      });
      toast.success('EVM threshold signature ready', { id: toastId });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`EVM threshold signing failed: ${message}`, { id: toastId });
    } finally {
      setEvmThresholdSignLoading(false);
    }
  }, [getKeyRefForChain, nearAccountId, tatchi]);

  if (!isLoggedIn || !nearAccountId) {
    return null;
  }

  const accountName = nearAccountId.split('.')?.[0];
  const expiresInSec =
    sessionStatus?.expiresAtMs != null
      ? Math.max(0, Math.ceil((sessionStatus.expiresAtMs - clockMs) / 1000))
      : null;

  return (
    <div>
      <div className="action-section">
        <div className="demo-page-header">
          <h2 className="demo-title">Welcome, {accountName}</h2>
        </div>
      </div>

      <div className="action-section">
        <h2 className="demo-subtitle">Sign Transactions with TouchId</h2>
        <div className="action-text">Sign transactions securely in an cross-origin iframe.</div>

        <div className="greeting-controls-box">
          <div className="on-chain-greeting-box">
            <button
              onClick={handleRefreshGreeting}
              disabled={isLoading}
              title="Refresh Greeting"
              className="refresh-icon-button"
              aria-busy={isLoading}
            >
              <Refresh size={22} strokeWidth={2} />
            </button>
            <p>
              <strong>{onchainGreeting ?? '...'}</strong>
            </p>
          </div>

          <div className="greeting-input-group">
            <input
              type="text"
              name="greeting"
              value={greetingInput}
              onChange={(e) => setGreetingInput(e.target.value)}
              placeholder="Enter new greeting"
            />
          </div>
          <LoadingButton
            onClick={handleSetGreeting}
            loading={txLoading}
            loadingText="Processing..."
            variant="primary"
            size="medium"
            className="greeting-btn"
            disabled={!canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId) || txLoading}
            style={{ width: 200 }}
          >
            Set Greeting
          </LoadingButton>
          <LoadingButton
            onClick={handleSignDelegateGreeting}
            loading={delegateLoading}
            loadingText="Signing delegate..."
            variant="secondary"
            size="medium"
            className="greeting-btn"
            disabled={
              !canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId) || delegateLoading
            }
            style={{ width: 200, marginTop: '0.5rem' }}
          >
            Send Delegate Action
          </LoadingButton>

          {error && <div className="error-message">Error: {error}</div>}
        </div>
      </div>

      <div className="action-section">
        <div className="demo-divider" aria-hidden="true" />
        <h2 className="demo-subtitle">Tempo + EVM Threshold Signers</h2>
        <div className="action-text">
          Login provisions shared Tempo + EVM threshold signers, then caches them for follow-up
          signatures.
        </div>

        <div
          style={{
            marginTop: 12,
            background: 'var(--fe-bg-secondary)',
            border: '1px solid var(--fe-border)',
            borderRadius: 'var(--fe-radius-lg)',
            padding: 'var(--fe-gap-3)',
            fontSize: '0.9rem',
            color: 'var(--fe-text)',
          }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16 }}>
            <div>
              <strong>EVM signer:</strong>&nbsp;
              {thresholdKeyRefs.evm
                ? `ready (${shortenHex(thresholdKeyRefs.evm.relayerKeyId)})`
                : 'not provisioned'}
            </div>
            <div>
              <strong>Tempo signer:</strong>&nbsp;
              {thresholdKeyRefs.tempo
                ? `ready (${shortenHex(thresholdKeyRefs.tempo.relayerKeyId)})`
                : 'not provisioned'}
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
          <LoadingButton
            onClick={handleSignTempoThresholdTx}
            loading={tempoThresholdSignLoading}
            loadingText="Signing..."
            variant="primary"
            size="medium"
            style={{ width: '100%' }}
          >
            Sign Tempo Threshold Transaction
          </LoadingButton>
          <LoadingButton
            onClick={handleSignEvmThresholdTx}
            loading={evmThresholdSignLoading}
            loadingText="Signing..."
            variant="primary"
            size="medium"
            style={{ width: '100%' }}
          >
            Sign EVM Threshold EIP-1559 Transaction
          </LoadingButton>
        </div>

        {lastTempoSigned ? (
          <div
            style={{
              marginTop: 12,
              background: 'var(--fe-bg-secondary)',
              border: '1px solid var(--fe-border)',
              borderRadius: 'var(--fe-radius-lg)',
              padding: 'var(--fe-gap-3)',
              fontSize: '0.85rem',
              color: 'var(--fe-text)',
            }}
          >
            <div>
              <strong>Tempo sender hash:</strong>{' '}
              <code>{shortenHex(lastTempoSigned.senderHashHex, 42)}</code>
            </div>
            <div style={{ marginTop: 6 }}>
              <strong>Tempo raw tx:</strong> <code>{shortenHex(lastTempoSigned.rawTxHex, 42)}</code>
            </div>
          </div>
        ) : null}

        {lastEvmSigned ? (
          <div
            style={{
              marginTop: 10,
              background: 'var(--fe-bg-secondary)',
              border: '1px solid var(--fe-border)',
              borderRadius: 'var(--fe-radius-lg)',
              padding: 'var(--fe-gap-3)',
              fontSize: '0.85rem',
              color: 'var(--fe-text)',
            }}
          >
            <div>
              <strong>EIP-1559 tx hash:</strong>{' '}
              <code>{shortenHex(lastEvmSigned.txHashHex, 42)}</code>
            </div>
            <div style={{ marginTop: 6 }}>
              <strong>EIP-1559 raw tx:</strong>{' '}
              <code>{shortenHex(lastEvmSigned.rawTxHex, 42)}</code>
            </div>
          </div>
        ) : null}
      </div>

      <div className="action-section">
        <div className="demo-divider" aria-hidden="true" />
        <h2 className="demo-subtitle">Signing Session</h2>
        <div className="action-text">
          Create a warm signing session with configurable <code>remaining_uses</code> and TTL. Touch
          once, then sign multiple times while the session is active.
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 180, flex: 1 }}>
            <label style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>
              Remaining uses
            </label>
            <input
              type="number"
              min={0}
              step={1}
              value={sessionRemainingUsesInput}
              onChange={(e) => setSessionRemainingUsesInput(parseInt(e.target.value || '0', 10))}
              style={{
                height: 44,
                padding: '0 12px',
                backgroundColor: 'var(--w3a-colors-surface2)',
                border: '1px solid var(--fe-border)',
                borderRadius: 'var(--fe-radius-lg)',
                color: 'var(--fe-input-text)',
                fontSize: '0.9rem',
              }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 180, flex: 1 }}>
            <label style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>
              TTL (seconds)
            </label>
            <input
              type="number"
              min={0}
              step={1}
              value={sessionTtlSecondsInput}
              onChange={(e) => setSessionTtlSecondsInput(parseInt(e.target.value || '0', 10))}
              style={{
                height: 44,
                padding: '0 12px',
                backgroundColor: 'var(--w3a-colors-surface2)',
                border: '1px solid var(--fe-border)',
                borderRadius: 'var(--fe-radius-lg)',
                color: 'var(--fe-input-text)',
                fontSize: '0.9rem',
              }}
            />
          </div>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <LoadingButton
              onClick={handleUnlockSession}
              loading={unlockLoading}
              loadingText="Creating..."
              variant="primary"
              size="medium"
              style={{ width: 180 }}
            >
              Create Session
            </LoadingButton>
          </div>
        </div>

        <div
          style={{
            marginTop: 12,
            background: 'var(--fe-bg-secondary)',
            border: '1px solid var(--fe-border)',
            borderRadius: 'var(--fe-radius-lg)',
            padding: 'var(--fe-gap-3)',
            fontSize: '0.9rem',
            color: 'var(--fe-text)',
          }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <strong>Status:</strong>&nbsp;{sessionStatus?.status ?? '…'}
            </div>
            <div>
              <strong>Remaining uses:</strong>&nbsp;
              {typeof sessionStatus?.remainingUses === 'number' ? sessionStatus.remainingUses : '—'}
            </div>
            <div>
              <strong>TTL:</strong>&nbsp;
              {expiresInSec == null
                ? '—'
                : sessionStatus?.status === 'active'
                  ? `${expiresInSec}s remaining`
                  : `${expiresInSec}s`}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DemoPage;
