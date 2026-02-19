import {
  executeAction,
  sendTransaction,
  signAndSendTransactions,
  signTransactionsWithActions,
} from '../actions';
import { toAccountId } from '../../types/accountIds';
import type { SignedTransaction } from '../../near/NearClient';
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
import { ActionPhase, ActionStatus } from '../../types/sdkSentEvents';
import type { ActionArgs, TransactionInput } from '../../types/actions';
import type { DelegateActionInput, SignedDelegate } from '../../types/delegate';
import type { WasmSignedDelegate } from '../../types/signer-worker';
import type {
  SignNEP413MessageParams,
  SignNEP413MessageResult,
} from '../signNEP413';
import { toError } from '@shared/utils/errors';
import type { NearSignerCapability } from '../capabilities';
import type { ChainSignerDeps } from './shared';
import { signDelegateAction as signDelegateActionCore } from '../delegateAction';
import { sendDelegateActionViaRelayer as sendDelegateActionViaRelayerCore } from '../relay';
import { signNEP413Message as signNEP413MessageCore } from '../signNEP413';

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
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const res = await router.executeAction({
          nearAccountId: args.nearAccountId,
          receiverId: args.receiverId,
          actionArgs: args.actionArgs,
          options: args.options,
        });
        await args.options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false);
        throw e;
      }
    }

    return await executeAction({
      context: this.getContext(),
      nearAccountId: toAccountId(args.nearAccountId),
      receiverId: toAccountId(args.receiverId),
      actionArgs: args.actionArgs,
      options: args.options,
    });
  }

  async signAndSendTransactions(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]> {
    const { nearAccountId, transactions, options } = args;

    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(nearAccountId);
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
        const txIds = (res || [])
          .map((r) => r?.transactionId)
          .filter(Boolean)
          .join(', ');
        options?.onEvent?.({
          step: 8,
          phase: ActionPhase.STEP_8_ACTION_COMPLETE,
          status: ActionStatus.SUCCESS,
          message: `All transactions sent: ${txIds}`,
        });
        await options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false);
        throw e;
      }
    }

    const txResults = await signAndSendTransactions({
      context: this.getContext(),
      nearAccountId: toAccountId(nearAccountId),
      transactionInputs: transactions,
      options,
    });

    const txIds = txResults.map((txResult) => txResult.transactionId).join(', ');
    options?.onEvent?.({
      step: 8,
      phase: ActionPhase.STEP_8_ACTION_COMPLETE,
      status: ActionStatus.SUCCESS,
      message: `All transactions sent: ${txIds}`,
    });
    return txResults;
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

    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(nearAccountId);
        const txs = transactions.map((t) => ({
          receiverId: t.receiverId,
          actions: t.actions,
        }));
        const result = await router.signTransactionsWithActions({
          nearAccountId,
          transactions: txs,
          options: {
            signerMode: options.signerMode,
            deviceNumber: options.deviceNumber,
            onEvent: options.onEvent,
            confirmationConfig: options.confirmationConfig,
            confirmerText: options.confirmerText,
          },
        });
        const arr: SignTransactionResult[] = Array.isArray(result) ? result : [];
        await options?.afterCall?.(true, arr);
        return arr;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false);
        throw e;
      }
    }

    return await signTransactionsWithActions({
      context: this.getContext(),
      nearAccountId: toAccountId(nearAccountId),
      transactionInputs: transactions,
      options,
    });
  }

  async sendTransaction(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult> {
    const { signedTransaction, options } = args;

    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter();
        const res = await router.sendTransaction({
          signedTransaction,
          options: {
            onEvent: options?.onEvent,
            ...(options && 'waitUntil' in options
              ? { waitUntil: options.waitUntil }
              : {}),
          },
        });
        await options?.afterCall?.(true, res);
        options?.onEvent?.({
          step: 8,
          phase: ActionPhase.STEP_8_ACTION_COMPLETE,
          status: ActionStatus.SUCCESS,
          message: `Transaction ${res?.transactionId} broadcasted`,
        });
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false);
        throw e;
      }
    }

    const txResult = await sendTransaction({
      context: this.getContext(),
      signedTransaction,
      options,
    });
    options?.onEvent?.({
      step: 8,
      phase: ActionPhase.STEP_8_ACTION_COMPLETE,
      status: ActionStatus.SUCCESS,
      message: `Transaction ${txResult.transactionId} broadcasted`,
    });
    return txResult;
  }

  async signDelegateAction(args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    options: DelegateActionHooksOptions;
  }): Promise<SignDelegateActionResult> {
    const { nearAccountId, delegate, options } = args;

    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(nearAccountId);
        const result = await router.signDelegateAction({
          nearAccountId,
          delegate,
          options: {
            signerMode: options.signerMode,
            deviceNumber: options.deviceNumber,
            onEvent: options.onEvent,
            confirmationConfig: options.confirmationConfig,
            confirmerText: options.confirmerText,
          },
        });
        await options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false);
        throw e;
      }
    }

    return await signDelegateActionCore({
      context: this.getContext(),
      nearAccountId: toAccountId(nearAccountId),
      delegate,
      options,
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
      this.getContext().configs.relayer?.delegateActionRoute || '/signed-delegate'
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
          signerMode: options.signerMode,
          deviceNumber: options.deviceNumber,
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
      await options?.afterCall?.(false);
      throw error;
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
      await options?.afterCall?.(false);
      throw error;
    }

    const combined: SignAndSendDelegateActionResult = {
      signResult,
      relayResult,
    };

    const success = relayResult.ok !== false;
    if (success) {
      await options?.afterCall?.(true, combined);
    } else {
      await options?.afterCall?.(false);
    }

    return combined;
  }

  async signNEP413Message(args: {
    nearAccountId: string;
    params: SignNEP413MessageParams;
    options: SignNEP413HooksOptions;
  }): Promise<SignNEP413MessageResult> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const result = await router.signNep413Message({
          nearAccountId: args.nearAccountId,
          message: args.params.message,
          recipient: args.params.recipient,
          state: args.params.state,
          options: {
            signerMode: args.options.signerMode,
            deviceNumber: args.options.deviceNumber,
            onEvent: args.options.onEvent,
            confirmerText: args.options.confirmerText,
            confirmationConfig: args.options.confirmationConfig,
          },
        });
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false);
        throw e;
      }
    }

    const res = await signNEP413MessageCore({
      context: this.getContext(),
      nearAccountId: toAccountId(args.nearAccountId),
      params: args.params,
      options: args.options,
    });

    if (res?.success) {
      await args.options?.afterCall?.(true, res);
    } else {
      await args.options?.afterCall?.(false);
    }
    return res;
  }
}
