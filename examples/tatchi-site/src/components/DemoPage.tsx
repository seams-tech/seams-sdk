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
import { CopyButton } from './CopyButton';
import { useSetGreeting } from '../hooks/useSetGreeting';
import { DEMO_CONTRACT_ID, NEAR_EXPLORER_BASE_URL } from '../types';
import { FRONTEND_CONFIG } from '../config';
import './DemoPage.css';

const TEMPO_GREETING_CONTRACT = '0x96cFE92241481954AdA6410409a86AcB6E76a00e' as `0x${string}`;
const ARC_TESTNET_GREETING_CONTRACT = '0xeB7aB5A6F761072C96147A54B8a15F012e836691' as `0x${string}`;
const SET_GREETING_SELECTOR = '0xa4136862';
const GREET_SELECTOR = '0xcfae3217';
const EVM_TX_FINALITY_TIMEOUT_MS = 90_000;
const EVM_TX_RECEIPT_POLL_INTERVAL_MS = 1_250;
const DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS = 2_000_000_000n; // 2 gwei
const DEFAULT_DEMO_MAX_FEE_PER_GAS = 40_000_000_000n; // 40 gwei

type Eip1559FeeCaps = {
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
};

function utf8ToHex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function hexToUtf8(value: string): string {
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (hex.length === 0) return '';
  if (hex.length % 2 !== 0) throw new Error('Invalid hex payload length');

  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

function encodeSetGreetingInput(greeting: string): `0x${string}` {
  const messageHex = utf8ToHex(greeting);
  const messageBytesLength = messageHex.length / 2;
  const dataWordLength = Math.ceil(messageBytesLength / 32) * 64;
  const offsetHex = (32).toString(16).padStart(64, '0');
  const lengthHex = messageBytesLength.toString(16).padStart(64, '0');
  const dataHex = messageHex.padEnd(dataWordLength, '0');
  return `0x${SET_GREETING_SELECTOR.slice(2)}${offsetHex}${lengthHex}${dataHex}` as `0x${string}`;
}

function decodeStringResultData(rawHex: string): string {
  const resultHex = rawHex.startsWith('0x') ? rawHex.slice(2) : rawHex;
  if (resultHex.length < 128) {
    throw new Error('Invalid RPC result payload');
  }

  const dataOffsetBytes = Number.parseInt(resultHex.slice(0, 64), 16);
  if (!Number.isFinite(dataOffsetBytes) || dataOffsetBytes < 0) {
    throw new Error('Invalid ABI offset');
  }

  const dataOffsetHex = dataOffsetBytes * 2;
  const lengthStart = dataOffsetHex;
  const lengthEnd = lengthStart + 64;
  if (lengthEnd > resultHex.length) {
    throw new Error('Invalid ABI string length offset');
  }

  const stringLengthBytes = Number.parseInt(resultHex.slice(lengthStart, lengthEnd), 16);
  if (!Number.isFinite(stringLengthBytes) || stringLengthBytes < 0) {
    throw new Error('Invalid ABI string length');
  }

  const dataStart = lengthEnd;
  const dataEnd = dataStart + stringLengthBytes * 2;
  if (dataEnd > resultHex.length) {
    throw new Error('Invalid ABI string data');
  }

  return hexToUtf8(resultHex.slice(dataStart, dataEnd));
}

type EvmJsonRpcError = {
  message?: string;
};

type EvmTransactionReceipt = {
  blockNumber?: string | null;
  status?: string | null;
};

async function callEvmJsonRpc<T>(args: {
  rpcUrl: string;
  method: string;
  params: unknown[];
}): Promise<T> {
  const { rpcUrl, method, params } = args;
  if (!rpcUrl) {
    throw new Error('RPC URL is not configured');
  }

  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method,
      params,
    }),
  });

  if (!response.ok) {
    throw new Error(`RPC HTTP ${response.status}`);
  }

  const payload = (await response.json()) as {
    error?: EvmJsonRpcError;
    result?: T;
  };
  if (payload.error) {
    throw new Error(payload.error.message || `${method} failed`);
  }
  if (!('result' in payload)) {
    throw new Error(`Invalid ${method} response`);
  }

  return payload.result as T;
}

async function readEvmGreeting(params: {
  rpcUrl: string;
  contract: `0x${string}`;
}): Promise<string> {
  const { rpcUrl, contract } = params;
  const result = await callEvmJsonRpc<string>({
    rpcUrl,
    method: 'eth_call',
    params: [{ to: contract, data: GREET_SELECTOR }, 'latest'],
  });

  if (typeof result !== 'string' || !result.startsWith('0x')) {
    throw new Error('Invalid eth_call response');
  }

  return decodeStringResultData(result);
}

async function sendRawEvmTransaction(args: {
  rpcUrl: string;
  rawTxHex: string;
}): Promise<`0x${string}`> {
  const txHash = await callEvmJsonRpc<string>({
    rpcUrl: args.rpcUrl,
    method: 'eth_sendRawTransaction',
    params: [args.rawTxHex],
  });
  if (typeof txHash !== 'string' || !txHash.startsWith('0x')) {
    throw new Error('Invalid eth_sendRawTransaction response');
  }
  return txHash as `0x${string}`;
}

async function waitForEvmTransactionFinalization(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
  timeoutMs?: number;
  pollIntervalMs?: number;
}): Promise<EvmTransactionReceipt> {
  const timeoutMs = args.timeoutMs ?? EVM_TX_FINALITY_TIMEOUT_MS;
  const pollIntervalMs = args.pollIntervalMs ?? EVM_TX_RECEIPT_POLL_INTERVAL_MS;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const receipt = await callEvmJsonRpc<EvmTransactionReceipt | null>({
      rpcUrl: args.rpcUrl,
      method: 'eth_getTransactionReceipt',
      params: [args.txHash],
    });
    if (receipt && typeof receipt === 'object' && typeof receipt.blockNumber === 'string') {
      const status = String(receipt.status || '').toLowerCase();
      if (status && status !== '0x1' && status !== '0x01') {
        throw new Error(`Transaction reverted with status ${receipt.status}`);
      }
      return receipt;
    }

    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, pollIntervalMs);
    });
  }

  throw new Error(`Timed out waiting for tx finalization after ${timeoutMs}ms`);
}

function parseRpcHexQuantity(value: string, label: string): bigint {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error(`Invalid ${label} quantity`);
  }
  return BigInt(normalized);
}

async function resolveEip1559FeeCaps(rpcUrl: string): Promise<Eip1559FeeCaps> {
  try {
    const gasPriceHex = await callEvmJsonRpc<string>({
      rpcUrl,
      method: 'eth_gasPrice',
      params: [],
    });
    const gasPrice = parseRpcHexQuantity(gasPriceHex, 'eth_gasPrice');
    if (gasPrice <= 0n) {
      throw new Error('eth_gasPrice returned non-positive value');
    }

    const maxFeePerGas =
      gasPrice * 2n > DEFAULT_DEMO_MAX_FEE_PER_GAS ? gasPrice * 2n : DEFAULT_DEMO_MAX_FEE_PER_GAS;
    const suggestedPriority =
      gasPrice / 10n > DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS
        ? gasPrice / 10n
        : DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS;
    const maxPriorityFeePerGas =
      suggestedPriority < maxFeePerGas ? suggestedPriority : maxFeePerGas / 2n;
    return {
      maxPriorityFeePerGas,
      maxFeePerGas,
    };
  } catch {
    return {
      maxPriorityFeePerGas: DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS,
      maxFeePerGas: DEFAULT_DEMO_MAX_FEE_PER_GAS,
    };
  }
}

function buildDemoTempoTransactionRequest(greeting: string, feeCaps: Eip1559FeeCaps) {
  const setGreetingInput = encodeSetGreetingInput(greeting);
  return {
    chain: 'tempo' as const,
    kind: 'tempoTransaction' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 42431n,
      maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
      maxFeePerGas: feeCaps.maxFeePerGas,
      gasLimit: 200_000n,
      calls: [{ to: TEMPO_GREETING_CONTRACT, value: 0n, input: setGreetingInput }],
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

function buildDemoEip1559Request(greeting: string, feeCaps: Eip1559FeeCaps) {
  const data = encodeSetGreetingInput(greeting);
  return {
    chain: 'evm' as const,
    kind: 'eip1559' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 5042002n,
      nonce: 7n,
      maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
      maxFeePerGas: feeCaps.maxFeePerGas,
      gasLimit: 200_000n,
      to: ARC_TESTNET_GREETING_CONTRACT,
      value: 0n,
      data,
      accessList: [],
    },
  };
}

function createChainDefaultGreeting(chainLabel: string): string {
  return `Hello ${chainLabel} [${new Date().toLocaleTimeString()}]`;
}

function compactHex(value: string): string {
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function parseInsufficientFundsError(message: string): {
  haveWei: bigint;
  wantWei: bigint;
} | null {
  const match = /insufficient funds.*have\s+(\d+)\s+want\s+(\d+)/i.exec(message);
  if (!match) return null;
  try {
    return {
      haveWei: BigInt(match[1]!),
      wantWei: BigInt(match[2]!),
    };
  } catch {
    return null;
  }
}

function formatWeiToEth(wei: bigint, precision = 6): string {
  const base = 10n ** 18n;
  const whole = wei / base;
  const fraction = wei % base;
  if (fraction === 0n) return whole.toString();
  const fractionRaw = fraction.toString().padStart(18, '0').slice(0, precision);
  const fractionTrimmed = fractionRaw.replace(/0+$/, '');
  return fractionTrimmed ? `${whole.toString()}.${fractionTrimmed}` : whole.toString();
}

type DemoPageTestOverrides = {
  useTatchiHook?: typeof useTatchi;
  useSetGreetingHook?: typeof useSetGreeting;
};

type DemoPageProps = {
  __testOverrides?: DemoPageTestOverrides;
};

export const DemoPage: React.FC<DemoPageProps> = (props) => {
  const useTatchiHook = props.__testOverrides?.useTatchiHook || useTatchi;
  const useSetGreetingHook = props.__testOverrides?.useSetGreetingHook || useSetGreeting;

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
  const [tempoGreetingInput, setTempoGreetingInput] = useState(() => createChainDefaultGreeting('Tempo'));
  const [arcGreetingInput, setArcGreetingInput] = useState(() => createChainDefaultGreeting('Arc'));
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
  const [tempoGreeting, setTempoGreeting] = useState<string | null>(null);
  const [arcGreeting, setArcGreeting] = useState<string | null>(null);
  const [tempoGreetingLoading, setTempoGreetingLoading] = useState(false);
  const [arcGreetingLoading, setArcGreetingLoading] = useState(false);
  const [tempoGreetingError, setTempoGreetingError] = useState<string | null>(null);
  const [arcGreetingError, setArcGreetingError] = useState<string | null>(null);
  const [thresholdEvmFundingAddress, setThresholdEvmFundingAddress] = useState<string | null>(null);

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
    const secondActionToExecute: FunctionCallAction = createGreetingAction(
      greetingInput,
      { postfix: 'Tx 2' },
    ) as FunctionCallAction;

    setTxLoading(true);
    try {
      await tatchi.near.signAndSendTransactions({
        nearAccountId: nearAccountId!,
        transactions: [
          {
            receiverId: DEMO_CONTRACT_ID,
            actions: [actionToExecute, actionToExecute],
          },
          {
            receiverId: DEMO_CONTRACT_ID,
            actions: [secondActionToExecute],
          },
        ],
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
          afterCall: (success: boolean, results?: ActionResult[]) => {
            try {
              toast.dismiss('greeting');
            } catch {}
            const normalizedResults = Array.isArray(results) ? results : [];
            const successfulResults = normalizedResults.filter((item) => item?.success !== false);
            const latestTxId =
              successfulResults.at(-1)?.transactionId
              || normalizedResults.at(-1)?.transactionId;
            const isSuccess = success && successfulResults.length > 0;
            if (isSuccess && latestTxId) {
              const txLink = `${NEAR_EXPLORER_BASE_URL}/transactions/${latestTxId}`;
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
              const message = normalizedResults.find((item) => item?.error)?.error
                || (isSuccess ? 'Missing transaction ID' : 'Unknown error');
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
          receiverId: DEMO_CONTRACT_ID,
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

  const fetchTempoGreeting = useCallback(async (opts?: { silent?: boolean }) => {
    setTempoGreetingLoading(true);
    setTempoGreetingError(null);
    try {
      const greeting = await readEvmGreeting({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        contract: TEMPO_GREETING_CONTRACT,
      });
      setTempoGreeting(greeting);
      return greeting;
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setTempoGreetingError(message);
      if (!opts?.silent) {
        toast.error(`Tempo greeting fetch failed: ${message}`);
      }
      return null;
    } finally {
      setTempoGreetingLoading(false);
    }
  }, []);

  const fetchArcGreeting = useCallback(async (opts?: { silent?: boolean }) => {
    setArcGreetingLoading(true);
    setArcGreetingError(null);
    try {
      const greeting = await readEvmGreeting({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        contract: ARC_TESTNET_GREETING_CONTRACT,
      });
      setArcGreeting(greeting);
      return greeting;
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setArcGreetingError(message);
      if (!opts?.silent) {
        toast.error(`Arc greeting fetch failed: ${message}`);
      }
      return null;
    } finally {
      setArcGreetingLoading(false);
    }
  }, []);

  const refreshThresholdEvmFundingAddress = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) {
      setThresholdEvmFundingAddress(null);
      return null;
    }
    try {
      const session = await tatchi.auth.getSession(nearAccountId);
      const address = String(session.login.thresholdEcdsaEthereumAddress || '').trim();
      setThresholdEvmFundingAddress(address || null);
      return address || null;
    } catch {
      setThresholdEvmFundingAddress(null);
      return null;
    }
  }, [isLoggedIn, nearAccountId, tatchi]);

  const handleSignTempoThresholdTx = useCallback(async () => {
    if (!canExecuteGreeting(tempoGreetingInput, isLoggedIn, nearAccountId)) return;
    const toastId = 'tempo-threshold-sign';
    setTempoThresholdSignLoading(true);
    toast.loading('Signing Tempo transaction…', { id: toastId });
    try {
      const feeCaps = await resolveEip1559FeeCaps(FRONTEND_CONFIG.tempoRpcUrl);
      const request = buildDemoTempoTransactionRequest(tempoGreetingInput.trim(), feeCaps);
      const signed = await tatchi.tempo.signTempo({
        nearAccountId: nearAccountId!,
        request,
      });

      if (signed.kind !== 'tempoTransaction') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }

      toast.loading('Dispatching Tempo transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        rawTxHex: signed.rawTxHex,
      });

      toast.loading('Tempo transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        txHash,
      });
      await fetchTempoGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success('Tempo transaction finalized', {
        id: toastId,
        description: (
          <span>
            Tx hash:&nbsp;
            <code>{compactHex(txHash)}</code>
          </span>
        ),
      });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `Tempo sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`Tempo transaction failed: ${message}`, { id: toastId });
      }
    } finally {
      setTempoThresholdSignLoading(false);
    }
  }, [
    canExecuteGreeting,
    fetchTempoGreeting,
    isLoggedIn,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    tatchi,
    tempoGreetingInput,
  ]);

  const handleSignEvmThresholdTx = useCallback(async () => {
    if (!canExecuteGreeting(arcGreetingInput, isLoggedIn, nearAccountId)) return;
    const toastId = 'evm-threshold-sign';
    setEvmThresholdSignLoading(true);
    toast.loading('Signing EVM transaction…', { id: toastId });
    try {
      const feeCaps = await resolveEip1559FeeCaps(FRONTEND_CONFIG.arcRpcUrl);
      const request = buildDemoEip1559Request(arcGreetingInput.trim(), feeCaps);
      const signed = await tatchi.tempo.signTempo({
        nearAccountId: nearAccountId!,
        request,
      });

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }

      toast.loading('Dispatching EVM transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        rawTxHex: signed.rawTxHex,
      });

      toast.loading('EVM transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        txHash,
      });
      await fetchArcGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success('EVM transaction finalized', {
        id: toastId,
        description: (
          <span>
            Tx hash:&nbsp;
            <code>{compactHex(txHash)}</code>
          </span>
        ),
      });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `ARC sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`EVM transaction failed: ${message}`, { id: toastId });
      }
    } finally {
      setEvmThresholdSignLoading(false);
    }
  }, [
    arcGreetingInput,
    canExecuteGreeting,
    fetchArcGreeting,
    isLoggedIn,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    tatchi,
  ]);

  useEffect(() => {
    if (!isLoggedIn || !nearAccountId) return;
    void fetchTempoGreeting({ silent: true });
    void fetchArcGreeting({ silent: true });
    void refreshThresholdEvmFundingAddress();
  }, [
    fetchArcGreeting,
    fetchTempoGreeting,
    isLoggedIn,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
  ]);

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
        <div className="action-text funding-instructions">
          <span>Fund this threshold EVM signer address with native gas tokens (Tempo + Arc):</span>
          <div className="funding-address-row">
            <span className="funding-address-text">
              {thresholdEvmFundingAddress || 'Address unavailable. Sign once to bootstrap threshold ECDSA.'}
            </span>
            {thresholdEvmFundingAddress ? (
              <CopyButton
                text={thresholdEvmFundingAddress}
                ariaLabel="Copy funding address"
                className="funding-address-copy"
                size={18}
                onCopy={() => {
                  toast.success('Address copied');
                }}
              />
            ) : (
              <span className="funding-address-copy-placeholder" aria-hidden="true" />
            )}
          </div>
        </div>

        <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
          <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
            <div style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>Tempo Greeting</div>
            <div className="on-chain-greeting-box">
              <button
                onClick={() => void fetchTempoGreeting()}
                disabled={tempoGreetingLoading}
                title="Refresh Tempo Greeting"
                className="refresh-icon-button"
                aria-busy={tempoGreetingLoading}
              >
                <Refresh size={22} strokeWidth={2} />
              </button>
              <p>
                <strong>{tempoGreeting ?? '...'}</strong>
              </p>
            </div>
            <div className="greeting-input-group" style={{ marginBottom: 0 }}>
              <input
                type="text"
                name="tempo-greeting"
                value={tempoGreetingInput}
                onChange={(event) => setTempoGreetingInput(event.target.value)}
                placeholder="Enter Tempo greeting"
              />
            </div>
          </div>
          {tempoGreetingError ? (
            <div className="error-message">Tempo greeting error: {tempoGreetingError}</div>
          ) : null}
          <LoadingButton
            onClick={handleSignTempoThresholdTx}
            loading={tempoThresholdSignLoading}
            loadingText="Signing..."
            variant="primary"
            size="medium"
            style={{ width: '100%' }}
            disabled={
              !canExecuteGreeting(tempoGreetingInput, isLoggedIn, nearAccountId)
              || tempoThresholdSignLoading
            }
          >
            Sign Tempo Transaction
          </LoadingButton>

          <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
            <div style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>Arc Greeting</div>
            <div className="on-chain-greeting-box">
              <button
                onClick={() => void fetchArcGreeting()}
                disabled={arcGreetingLoading}
                title="Refresh Arc Greeting"
                className="refresh-icon-button"
                aria-busy={arcGreetingLoading}
              >
                <Refresh size={22} strokeWidth={2} />
              </button>
              <p>
                <strong>{arcGreeting ?? '...'}</strong>
              </p>
            </div>
            <div className="greeting-input-group" style={{ marginBottom: 0 }}>
              <input
                type="text"
                name="arc-greeting"
                value={arcGreetingInput}
                onChange={(event) => setArcGreetingInput(event.target.value)}
                placeholder="Enter Arc greeting"
              />
            </div>
          </div>
          {arcGreetingError ? <div className="error-message">Arc greeting error: {arcGreetingError}</div> : null}

          <LoadingButton
            onClick={handleSignEvmThresholdTx}
            loading={evmThresholdSignLoading}
            loadingText="Signing..."
            variant="primary"
            size="medium"
            style={{ width: '100%' }}
            disabled={
              !canExecuteGreeting(arcGreetingInput, isLoggedIn, nearAccountId)
              || evmThresholdSignLoading
            }
          >
            Sign EVM Transaction
          </LoadingButton>
        </div>
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
