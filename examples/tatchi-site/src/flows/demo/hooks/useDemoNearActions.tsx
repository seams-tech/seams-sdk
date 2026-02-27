import { useCallback, useState } from 'react';
import { toast } from 'sonner';

import {
  ActionPhase,
  ActionResult,
  ActionType,
  TxExecutionStatus,
  useTatchi,
} from '@tatchi-xyz/sdk/react';
import type { ActionArgs, FunctionCallAction } from '@tatchi-xyz/sdk/react';

import { DEMO_CONTRACT_ID, NEAR_EXPLORER_BASE_URL } from '@/shared/types';

type UseDemoNearActionsArgs = {
  isLoggedIn: boolean;
  nearAccountId?: string | null;
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  fetchGreeting: () => unknown | Promise<unknown>;
};

export function useDemoNearActions(args: UseDemoNearActionsArgs) {
  const { isLoggedIn, nearAccountId, tatchi, fetchGreeting } = args;

  const [greetingInput, setGreetingInput] = useState('Hello from Tatchi!');
  const [txLoading, setTxLoading] = useState(false);
  const [delegateLoading, setDelegateLoading] = useState(false);

  const canExecuteGreeting = useCallback(
    (val: string, loggedIn: boolean, accountId?: string | null) =>
      Boolean(val?.trim()) && loggedIn && Boolean(accountId),
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
    const secondActionToExecute: FunctionCallAction = createGreetingAction(greetingInput, {
      postfix: 'Tx 2',
    }) as FunctionCallAction;

    setTxLoading(true);
    let signingFailureMessage: string | null = null;
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
          onError: (error: unknown) => {
            const message = String((error as { message?: unknown })?.message || error || '').trim();
            if (message) signingFailureMessage = message;
          },
          waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
          afterCall: (success: boolean, results?: ActionResult[], error?: Error) => {
            try {
              toast.dismiss('greeting');
            } catch {}
            const normalizedResults = Array.isArray(results) ? results : [];
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
              const message =
                normalizedResults.find((item) => item?.error)?.error ||
                callbackErrorMessage ||
                signingFailureMessage ||
                (isSuccess ? 'Missing transaction ID' : 'Unknown error');
              toast.error(`Greeting update failed: ${message}`);
            }
            setTxLoading(false);
          },
        },
      });
    } catch (error: unknown) {
      if (!signingFailureMessage) {
        const fallbackMessage = String(
          (error as { message?: unknown })?.message || error || 'Unknown error',
        );
        toast.error(`Greeting update failed: ${fallbackMessage}`);
      }
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
      const relayerUrl = tatchi.configs.network?.relayer?.url;
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
              setTimeout(() => {
                void fetchGreeting();
              }, 1000);
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
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
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

  return {
    greetingInput,
    setGreetingInput,
    txLoading,
    delegateLoading,
    handleSetGreeting,
    handleSignDelegateGreeting,
    canSubmit: canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId),
  };
}
