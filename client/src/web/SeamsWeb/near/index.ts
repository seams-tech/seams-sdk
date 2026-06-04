import {
  executeAction,
  sendTransaction,
  signAndSendTransactions,
  signTransactionsWithActions,
} from './actions';
import { toAccountId } from '@/core/types/accountIds';
import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type {
  ActionResult,
  DelegateRelayResult,
  RegistrationResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SignTransactionResult,
} from '@/core/types/seams';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { ActionArgs, TransactionInput } from '@/core/types/actions';
import type { DelegateActionInput, SignedDelegate } from '@/core/types/delegate';
import type { WasmSignedDelegate } from '@/core/types/signer-worker';
import type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
import { toError } from '@shared/utils/errors';
import type { NearSignerCapability } from '..';
import { type NearAccountRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  signDelegateAction as signDelegateActionCore,
  sendDelegateActionViaRelayer as sendDelegateActionViaRelayerCore,
} from './delegateAction';
import { signNEP413Message as signNEP413MessageCore } from './signNEP413';
import { registerWallet as registerWalletWithUnifiedCeremony } from '../registration';
import type { RegistrationCapability } from '../interfaces';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { buildPasskeyNearWalletRegistrationSignerSelection } from '../registrationSignerSelection';

type ChainSignerDeps = {
  getContext: () => import('../index').SeamsWebContext;
};

type NearWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0] & {
  options: NonNullable<Parameters<RegistrationCapability['registerWallet']>[0]['options']>;
};

export function buildNearWalletRegistrationArgs(
  context: import('../index').SeamsWebContext,
  args: Parameters<NearSignerCapability['registerNearWallet']>[0],
): NearWalletRegistrationArgs {
  const accountId = toAccountId(args.nearAccountId);
  const rpId = context.signingEngine.getRpId();
  if (!rpId) {
    throw new Error('[SeamsWeb][near] registerNearWallet requires rpId');
  }
  const authMethod = args.authMethod || { kind: 'passkey' as const };
  return {
    wallet: {
      kind: 'provided',
      walletId: walletIdFromString(String(accountId)),
    },
    rpId,
    authMethod,
    signerSelection: buildPasskeyNearWalletRegistrationSignerSelection({
      configs: context.configs,
      nearAccountId: String(accountId),
      options: args.options || {},
    }),
    options: args.options || {},
  };
}

export class NearSigner implements NearSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
  }

  async registerNearWallet(
    args: Parameters<NearSignerCapability['registerNearWallet']>[0],
  ): Promise<RegistrationResult> {
    const context = this.getContext();
    const registerWalletArgs = buildNearWalletRegistrationArgs(context, args);
    return await registerWalletWithUnifiedCeremony({
      context,
      ...registerWalletArgs,
      authenticatorOptions: cloneAuthenticatorOptions(
        context.configs.webauthn.authenticatorOptions,
      ),
    });
  }

  async executeAction(args: {
    nearAccount: NearAccountRef;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    const nearAccountId = args.nearAccount.accountId;
    return await executeAction({
      context: this.getContext(),
      nearAccountId,
      receiverId: toAccountId(args.receiverId),
      actionArgs: args.actionArgs,
      options: args.options,
    });
  }

  async signAndSendTransactions(args: {
    nearAccount: NearAccountRef;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]> {
    const nearAccountId = args.nearAccount.accountId;
    const { transactions, options } = args;

    try {
      return await signAndSendTransactions({
        context: this.getContext(),
        nearAccountId,
        transactionInputs: transactions,
        options,
      });
    } catch (error: unknown) {
      const e = toError(error);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  async signAndSendTransaction(args: {
    nearAccount: NearAccountRef;
    receiverId: string;
    actions: ActionArgs[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult> {
    const results = await this.signAndSendTransactions({
      nearAccount: args.nearAccount,
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
    nearAccount: NearAccountRef;
    transactions: TransactionInput[];
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult[]> {
    const nearAccountId = args.nearAccount.accountId;
    const { transactions, options } = args;

    try {
      return await signTransactionsWithActions({
        context: this.getContext(),
        nearAccountId,
        transactionInputs: transactions,
        options,
      });
    } catch (error: unknown) {
      const e = toError(error);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  async sendTransaction(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult> {
    const { signedTransaction, options } = args;

    return await sendTransaction({
      context: this.getContext(),
      signedTransaction,
      options,
    });
  }

  async signDelegateAction(args: {
    nearAccount: NearAccountRef;
    delegate: DelegateActionInput;
    options: DelegateActionHooksOptions;
  }): Promise<SignDelegateActionResult> {
    const nearAccountId = args.nearAccount.accountId;
    const { delegate, options } = args;

    return await signDelegateActionCore({
      context: this.getContext(),
      nearAccountId,
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
    nearAccount: NearAccountRef;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult> {
    const nearAccountId = args.nearAccount.accountId;
    const { delegate, relayerUrl, signal, options } = args;

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
        nearAccount: args.nearAccount,
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
    nearAccount: NearAccountRef;
    params: SignNEP413MessageParams;
    options: SignNEP413HooksOptions;
  }): Promise<SignNEP413MessageResult> {
    const nearAccountId = args.nearAccount.accountId;
    const res = await signNEP413MessageCore({
      context: this.getContext(),
      nearAccountId,
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
  }
}

export { signDelegateAction } from './delegateAction';
export { sendDelegateActionViaRelayer } from './delegateAction';
export type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
