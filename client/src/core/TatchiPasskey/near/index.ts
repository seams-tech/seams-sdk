import {
  executeAction,
  sendTransaction,
  signAndSendTransactions,
  signTransactionsWithActions,
} from './actions';
import { toAccountId } from '../../types/accountIds';
import type { SignedTransaction } from '../../rpcClients/near/NearClient';
import type {
  ActionResult,
  DelegateRelayResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SignTransactionResult,
} from '../../types/tatchi';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
} from '../../types/sdkSentEvents';
import type { ActionArgs, TransactionInput } from '../../types/actions';
import type { DelegateActionInput, SignedDelegate } from '../../types/delegate';
import type { WasmSignedDelegate } from '../../types/signer-worker';
import type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
import { toError } from '@shared/utils/errors';
import type { NearSignerCapability } from '..';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';
import {
  signDelegateAction as signDelegateActionCore,
  sendDelegateActionViaRelayer as sendDelegateActionViaRelayerCore,
} from './delegateAction';
import { signNEP413Message as signNEP413MessageCore } from './signNEP413';

type ChainSignerDeps = {
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: WalletIframeRouteDeps;
};

/**
 * NEAR signing call graph:
 * - NEAR tx/delegate/nep413 -> wallet iframe router OR app-origin signing modules
 */
export class NearSigner implements NearSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];
  private readonly walletIframe: ChainSignerDeps['walletIframe'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async executeAction(args: {
    nearAccountId: string;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        const res = await router.executeAction({
          nearAccountId: args.nearAccountId,
          receiverId: args.receiverId,
          actionArgs: args.actionArgs,
          options: args.options,
        });
        await args.options?.afterCall?.(true, res);
        return res;
      },
      onRemoteError: async (error) => {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      },
      local: async () => {
        return await executeAction({
          context: this.getContext(),
          nearAccountId: toAccountId(args.nearAccountId),
          receiverId: toAccountId(args.receiverId),
          actionArgs: args.actionArgs,
          options: args.options,
        });
      },
    });
  }

  async signAndSendTransactions(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]> {
    const { nearAccountId, transactions, options } = args;

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId,
      remote: async (router) => {
        const routerOptions: SignAndSendTransactionHooksOptions = {
          ...options,
          executionWait: options?.executionWait ?? {
            mode: 'sequential',
            waitUntil: options?.waitUntil,
          },
        };
        const res = await router.signAndSendTransactions({
          nearAccountId,
          transactions: transactions.map((t) => ({
            receiverId: t.receiverId,
            actions: t.actions,
          })),
          options: routerOptions,
        });
        await options?.afterCall?.(true, res);
        return res;
      },
      onRemoteError: async (error) => {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      },
      local: async () => {
        try {
          const txResults = await signAndSendTransactions({
            context: this.getContext(),
            nearAccountId: toAccountId(nearAccountId),
            transactionInputs: transactions,
            options,
          });

          return txResults;
        } catch (error: unknown) {
          const e = toError(error);
          await options?.afterCall?.(false, undefined, e);
          throw e;
        }
      },
    });
  }

  async signAndSendTransaction(args: {
    nearAccountId: string;
    receiverId: string;
    actions: ActionArgs[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult> {
    const results = await this.signAndSendTransactions({
      nearAccountId: args.nearAccountId,
      transactions: [
        {
          receiverId: args.receiverId,
          actions: args.actions,
        },
      ],
      options: args.options,
    });
    return results[0] as ActionResult;
  }

  async signTransactionsWithActions(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult[]> {
    const { nearAccountId, transactions, options } = args;

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId,
      remote: async (router) => {
        const txs = transactions.map((t) => ({
          receiverId: t.receiverId,
          actions: t.actions,
        }));
        const result = await router.signTransactionsWithActions({
          nearAccountId,
          transactions: txs,
          options: {
            signerSlot: options.signerSlot,
            onEvent: options.onEvent,
            confirmationConfig: options.confirmationConfig,
            confirmerText: options.confirmerText,
          },
        });
        const arr: SignTransactionResult[] = Array.isArray(result) ? result : [];
        await options?.afterCall?.(true, arr);
        return arr;
      },
      onRemoteError: async (error) => {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      },
      local: async () => {
        try {
          return await signTransactionsWithActions({
            context: this.getContext(),
            nearAccountId: toAccountId(nearAccountId),
            transactionInputs: transactions,
            options,
          });
        } catch (error: unknown) {
          const e = toError(error);
          await options?.afterCall?.(false, undefined, e);
          throw e;
        }
      },
    });
  }

  async sendTransaction(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult> {
    const { signedTransaction, options } = args;

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      remote: async (router) => {
        const res = await router.sendTransaction({
          signedTransaction,
          options: {
            onEvent: options?.onEvent,
            ...(options && 'waitUntil' in options ? { waitUntil: options.waitUntil } : {}),
          },
        });
        await options?.afterCall?.(true, res);
        return res;
      },
      onRemoteError: async (error) => {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      },
      local: async () => {
        const txResult = await sendTransaction({
          context: this.getContext(),
          signedTransaction,
          options,
        });
        return txResult;
      },
    });
  }

  async signDelegateAction(args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    options: DelegateActionHooksOptions;
  }): Promise<SignDelegateActionResult> {
    const { nearAccountId, delegate, options } = args;

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId,
      remote: async (router) => {
        const result = await router.signDelegateAction({
          nearAccountId,
          delegate,
          options: {
            signerSlot: options.signerSlot,
            onEvent: options.onEvent,
            confirmationConfig: options.confirmationConfig,
            confirmerText: options.confirmerText,
          },
        });
        await options?.afterCall?.(true, result);
        return result;
      },
      onRemoteError: async (error) => {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      },
      local: async () => {
        return await signDelegateActionCore({
          context: this.getContext(),
          nearAccountId: toAccountId(nearAccountId),
          delegate,
          options,
        });
      },
    });
  }

  async sendDelegateActionViaRelayer(args: {
    relayerUrl: string;
    signedDelegate: SignedDelegate | WasmSignedDelegate;
    hash: string;
    signal?: AbortSignal;
    options?: DelegateRelayHooksOptions;
  }): Promise<DelegateRelayResult> {
    const base = args.relayerUrl.replace(/\/+$/, '');
    const route = (
      this.getContext().configs.network.relayer?.routes?.delegateAction || '/signed-delegate'
    ).replace(/^\/?/, '/');
    const endpoint = `${base}${route}`;
    return await sendDelegateActionViaRelayerCore({
      url: endpoint,
      payload: {
        hash: args.hash,
        signedDelegate: args.signedDelegate,
      },
      signal: args.signal,
      options: args.options,
    });
  }

  async signAndSendDelegateAction(args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult> {
    const { nearAccountId, delegate, relayerUrl, signal, options } = args;

    const signOptions: DelegateActionHooksOptions | undefined = options
      ? {
          signerSlot: options.signerSlot,
          onEvent: options.onEvent,
          onError: options.onError,
          waitUntil: options.waitUntil,
          confirmationConfig: options.confirmationConfig,
          confirmerText: options.confirmerText,
          // Suppress nested afterCall so lifecycle settles once at the end.
          afterCall: () => {},
        }
      : undefined;

    let signResult: SignDelegateActionResult;
    try {
      signResult = await this.signDelegateAction({
        nearAccountId,
        delegate,
        options: signOptions as DelegateActionHooksOptions,
      });
    } catch (error) {
      const e = toError(error);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }

    const relayOptions: DelegateRelayHooksOptions | undefined = options
      ? {
          onEvent: options.onEvent,
          onError: options.onError,
        }
      : undefined;

    let relayResult: DelegateRelayResult;
    try {
      relayResult = await this.sendDelegateActionViaRelayer({
        relayerUrl,
        hash: signResult.hash,
        signedDelegate: signResult.signedDelegate,
        signal,
        options: relayOptions,
      });
    } catch (error) {
      const e = toError(error);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }

    const combined: SignAndSendDelegateActionResult = {
      signResult,
      relayResult,
    };

    const success = relayResult.ok !== false;
    if (success) {
      await options?.afterCall?.(true, combined);
    } else {
      const relayError = toError(relayResult.error || 'Delegate relay failed');
      await options?.afterCall?.(false, undefined, relayError);
    }

    return combined;
  }

  async signNEP413Message(args: {
    nearAccountId: string;
    params: SignNEP413MessageParams;
    options: SignNEP413HooksOptions;
  }): Promise<SignNEP413MessageResult> {
    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        const result = await router.signNep413Message({
          nearAccountId: args.nearAccountId,
          message: args.params.message,
          recipient: args.params.recipient,
          state: args.params.state,
          options: {
            signerSlot: args.options.signerSlot,
            onEvent: args.options.onEvent,
            confirmerText: args.options.confirmerText,
            confirmationConfig: args.options.confirmationConfig,
          },
        });
        await args.options?.afterCall?.(true, result);
        return result;
      },
      onRemoteError: async (error) => {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      },
      local: async () => {
        const res = await signNEP413MessageCore({
          context: this.getContext(),
          nearAccountId: toAccountId(args.nearAccountId),
          params: args.params,
          options: args.options,
        });

        if (res?.success) {
          await args.options?.afterCall?.(true, res);
        } else {
          const signingError = toError(res?.error || 'NEP-413 signing failed');
          await args.options?.afterCall?.(false, undefined, signingError);
        }
        return res;
      },
    });
  }
}

export { signDelegateAction } from './delegateAction';
export { sendDelegateActionViaRelayer } from './delegateAction';
export type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
