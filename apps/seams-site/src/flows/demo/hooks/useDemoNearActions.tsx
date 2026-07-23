import { useCallback, useState } from 'react';
import { toast } from 'sonner';

import {
  ActionResult,
  ActionType,
  TxExecutionStatus,
  useSeams,
  type SigningFlowEvent,
} from '@seams/sdk/react';
import { nearAccountRefFromAccountId, walletSessionRefFromSession } from '@seams/sdk/advanced';
import type { ActionArgs, FunctionCallAction } from '@seams/sdk/react';

import { FRONTEND_CONFIG } from '@/config';
import { DEMO_CONTRACT_ID, NEAR_EXPLORER_BASE_URL } from '@/shared/types';
import { friendlySigningErrorMessage, handleSigningToastEvent } from './signingToast';

const SET_GREETING_GAS = '10000000000000';

/* Blocks of validity granted to a signed delegate. A SignedDelegate is signed
   client-side, so its nonce and maxBlockHeight are covered by the signature and
   cannot be filled in later by the relayer — they must be correct at sign time.
   ~1s/block on NEAR, so ~1000 blocks ≈ 16 minutes of relay window. */
const DELEGATE_MAX_BLOCK_HEIGHT_BUFFER = 1000;

interface NearAccessKeyState {
  /** Next usable nonce for the sender's access key (current nonce + 1). */
  nextNonce: bigint;
  /** Current final block height, used to bound the delegate's maxBlockHeight. */
  blockHeight: number;
}

/* A single view_access_key query returns both the access key's current nonce
   and the block height it was resolved against — everything a delegate needs. */
async function fetchNearAccessKeyState(params: {
  nearRpcUrl: string;
  accountId: string;
  publicKey: string;
}): Promise<NearAccessKeyState> {
  const response = await fetch(params.nearRpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'seams-demo-delegate-access-key',
      method: 'query',
      params: {
        request_type: 'view_access_key',
        finality: 'final',
        account_id: params.accountId,
        public_key: params.publicKey,
      },
    }),
  });
  const json = (await response.json()) as {
    error?: { message?: string; data?: string };
    result?: { nonce?: number | string; block_height?: number };
  };
  if (json.error || !json.result || typeof json.result.block_height !== 'number') {
    const message =
      json.error?.data || json.error?.message || `NEAR RPC returned HTTP ${response.status}`;
    throw new Error(message);
  }
  return {
    nextNonce: BigInt(json.result.nonce ?? 0) + 1n,
    blockHeight: json.result.block_height,
  };
}

type UseDemoNearActionsArgs = {
  isLoggedIn: boolean;
  canStartNearTransaction: boolean;
  canSignDelegate: boolean;
  walletId: string | null;
  nearAccountId: string | null;
  nearPublicKey: string | null;
  seams: ReturnType<typeof useSeams>['seams'];
  fetchGreeting: () => unknown | Promise<unknown>;
};

export function useDemoNearActions(args: UseDemoNearActionsArgs) {
  const {
    isLoggedIn,
    canStartNearTransaction,
    canSignDelegate,
    walletId,
    nearAccountId,
    nearPublicKey,
    seams,
    fetchGreeting,
  } = args;

  const [greetingInput, setGreetingInput] = useState('Hello from Seams!');
  const [txLoading, setTxLoading] = useState(false);
  const [delegateLoading, setDelegateLoading] = useState(false);

  const canExecuteGreeting = useCallback(
    (
      val: string,
      loggedIn: boolean,
      funded: boolean,
      wallet: string | null,
      accountId: string | null,
    ) => Boolean(val?.trim()) && loggedIn && funded && Boolean(wallet) && Boolean(accountId),
    [],
  );

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
        gas: SET_GREETING_GAS,
        deposit: '0',
      };
    },
    [],
  );

  const handleSetGreeting = useCallback(async () => {
    if (
      !canExecuteGreeting(
        greetingInput,
        isLoggedIn,
        canStartNearTransaction,
        walletId,
        nearAccountId,
      )
    ) {
      return;
    }
    const actionToExecute: FunctionCallAction = createGreetingAction(
      greetingInput,
    ) as FunctionCallAction;

    setTxLoading(true);
    let signingFailureMessage: string | null = null;
    try {
      await seams.near.signAndSendTransaction({
        walletSession: walletSessionRefFromSession({
          walletId,
          walletSessionUserId: walletId,
        }),
        nearAccount: nearAccountRefFromAccountId(nearAccountId!),
        receiverId: DEMO_CONTRACT_ID,
        actions: [actionToExecute],
        options: {
          onEvent: (event: SigningFlowEvent) => {
            const result = handleSigningToastEvent(event, {
              toastId: 'greeting',
              chainLabel: 'NEAR',
              successMessage: 'Transaction complete',
            });
            if (result.status === 'failed' || result.status === 'cancelled') {
              const message = result.message;
              signingFailureMessage = message;
            }
          },
          onError: (error: unknown) => {
            const message = String((error as { message?: unknown })?.message || error || '').trim();
            if (message) signingFailureMessage = message;
          },
          waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
          afterCall: (success: boolean, result?: ActionResult | ActionResult[], error?: Error) => {
            try {
              toast.dismiss('greeting');
            } catch {}
            const normalizedResults = Array.isArray(result) ? result : result ? [result] : [];
            const successfulResults = normalizedResults.filter((item) => item?.success !== false);
            const latestTxId =
              successfulResults.at(-1)?.transactionId || normalizedResults.at(-1)?.transactionId;
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
              setTimeout(() => {
                void fetchGreeting();
              }, 1000);
            } else {
              const callbackErrorMessage = String(error?.message || '').trim();
              const message = friendlySigningErrorMessage(
                normalizedResults.find((item) => item?.error)?.error ||
                  callbackErrorMessage ||
                  signingFailureMessage ||
                  (isSuccess ? 'Missing transaction ID' : 'Unknown error'),
              );
              toast.error(`Greeting update failed: ${message}`);
            }
            setTxLoading(false);
          },
        },
      });
    } catch (error: unknown) {
      if (!signingFailureMessage) {
        const fallbackMessage = friendlySigningErrorMessage(
          String((error as { message?: unknown })?.message || error || 'Unknown error'),
        );
        toast.error(`Greeting update failed: ${fallbackMessage}`);
      }
      setTxLoading(false);
    }
  }, [
    canExecuteGreeting,
    canStartNearTransaction,
    createGreetingAction,
    fetchGreeting,
    greetingInput,
    isLoggedIn,
    nearAccountId,
    seams,
    walletId,
  ]);

  const handleSignDelegateGreeting = useCallback(async () => {
    if (!canExecuteGreeting(greetingInput, isLoggedIn, canSignDelegate, walletId, nearAccountId)) {
      return;
    }

    const { login: loginState } = await seams.auth.getWalletSession(walletId!);

    setDelegateLoading(true);
    try {
      const relayerUrl = seams.configs.network?.relayer?.url;
      if (!relayerUrl) {
        toast.error('Relayer URL is not configured: VITE_RELAYER_URL', {
          id: 'delegate-greeting',
        });
        return;
      }

      const delegatePublicKey = loginState.publicKey || nearPublicKey || '';
      if (!delegatePublicKey) {
        toast.error('No NEAR public key available to sign the delegate action', {
          id: 'delegate-greeting',
        });
        return;
      }

      // The delegate's nonce and maxBlockHeight are covered by the client-side
      // signature, so they must reflect real chain state at sign time. A stale
      // nonce or an already-passed maxBlockHeight signs cleanly and relays, but
      // the on-chain meta-transaction then fails (InvalidNonce / expired), so
      // the greeting silently never updates.
      const accessKeyState = await fetchNearAccessKeyState({
        nearRpcUrl: FRONTEND_CONFIG.nearRpcUrl,
        accountId: nearAccountId!,
        publicKey: delegatePublicKey,
      });

      const delegateAction = createGreetingAction(greetingInput, { postfix: 'Delegate' });
      const result = await seams.near.signDelegateAction({
        walletSession: walletSessionRefFromSession({
          walletId,
          walletSessionUserId: walletId,
        }),
        nearAccount: nearAccountRefFromAccountId(nearAccountId!),
        delegate: {
          senderId: nearAccountId!,
          receiverId: DEMO_CONTRACT_ID,
          actions: [delegateAction],
          nonce: accessKeyState.nextNonce.toString(),
          maxBlockHeight: accessKeyState.blockHeight + DELEGATE_MAX_BLOCK_HEIGHT_BUFFER,
          publicKey: delegatePublicKey,
        },
        options: {
          onEvent: (event: SigningFlowEvent) => {
            handleSigningToastEvent(event, {
              toastId: 'delegate-greeting',
              chainLabel: 'NEAR',
              successMessage: 'Delegate action signed',
            });
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
      const relayResult = await seams.near.sendDelegateActionViaRelayer({
        relayerUrl,
        hash: result.hash,
        signedDelegate: result.signedDelegate as unknown as Record<string, unknown>,
        options: {
          afterCall: (success: boolean, res?: { ok?: boolean }) => {
            if (success && res?.ok !== false) {
              setTimeout(() => {
                void fetchGreeting();
              }, 1000);
            }
          },
        },
      });

      toast.dismiss('delegate-relay');

      if (!relayResult.ok) {
        toast.error(
          `Relayer execution failed: ${friendlySigningErrorMessage(
            relayResult.error || 'Unknown error',
          )}`,
          { id: 'delegate-greeting' },
        );
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
    } catch (error: unknown) {
      const message = friendlySigningErrorMessage(
        error instanceof Error ? error.message : String(error),
      );
      toast.error(`Delegate signing failed: ${message}`, { id: 'delegate-greeting' });
    } finally {
      setDelegateLoading(false);
    }
  }, [
    canExecuteGreeting,
    canSignDelegate,
    createGreetingAction,
    fetchGreeting,
    greetingInput,
    isLoggedIn,
    nearAccountId,
    nearPublicKey,
    seams,
    walletId,
  ]);

  return {
    greetingInput,
    setGreetingInput,
    txLoading,
    delegateLoading,
    handleSetGreeting,
    handleSignDelegateGreeting,
    canSetGreeting: canExecuteGreeting(
      greetingInput,
      isLoggedIn,
      canStartNearTransaction,
      walletId,
      nearAccountId,
    ),
    canSignDelegate: canExecuteGreeting(
      greetingInput,
      isLoggedIn,
      canSignDelegate,
      walletId,
      nearAccountId,
    ),
  };
}
