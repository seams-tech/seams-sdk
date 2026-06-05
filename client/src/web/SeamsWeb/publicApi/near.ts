import type { ActionResult } from '@/core/types/seams';
import type {
  NearSignerCapability,
  NearSigningSurface,
  NearSigningWebContext,
  RegistrationSigningSurface,
  RegistrationWebContext,
  SeamsWebContext,
  UserAccountLookupSurface,
} from '@/web/SeamsWeb/signingSurface/types';
import { toError } from '@shared/utils/errors';
import { toAccountId } from '@/core/types/accountIds';
import type { WalletIframeCoordinator } from '@/web/SeamsWeb/walletIframe/coordinator';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import {
  executeAction,
  sendTransaction,
  signAndSendTransactions,
  signTransactionsWithActions,
} from '@/web/SeamsWeb/operations/near/actions';
import {
  sendDelegateActionViaRelayer as sendDelegateActionViaRelayerCore,
  signDelegateAction as signDelegateActionCore,
} from '@/web/SeamsWeb/operations/near/delegateAction';
import { signNEP413Message as signNEP413MessageCore } from '@/web/SeamsWeb/operations/near/signNEP413';
import { buildNearWalletRegistrationArgs } from '@/web/SeamsWeb/operations/near';
import { registerWallet as registerWalletWithUnifiedCeremony } from '@/web/SeamsWeb/operations/registration/registration';

export function createNearSignerCapability(deps: {
  signingEngine: RegistrationSigningSurface & NearSigningSurface & UserAccountLookupSurface;
  nearClient: SeamsWebContext['nearClient'];
  configs: SeamsWebContext['configs'];
  getTheme: () => SeamsWebContext['theme'];
  getWalletIframe: () => WalletIframeCoordinator;
}): NearSignerCapability {
  const getContext = (): NearSigningWebContext => ({
    signingEngine: deps.signingEngine,
    nearClient: deps.nearClient,
    configs: deps.configs,
    theme: deps.getTheme(),
  });
  const nearCapability: NearSignerCapability = {
    registerNearWallet: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const context = getContext();
      const accountId = toAccountId(args.nearAccountId);
      const registerWalletArgs = buildNearWalletRegistrationArgs(context, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        const registrationContext: RegistrationWebContext = {
          signingEngine: deps.signingEngine,
          nearClient: deps.nearClient,
          configs: deps.configs,
          theme: deps.getTheme(),
        };
        return await registerWalletWithUnifiedCeremony({
          context: registrationContext,
          ...registerWalletArgs,
          authenticatorOptions: cloneAuthenticatorOptions(
            deps.configs.webauthn.authenticatorOptions,
          ),
        });
      }
      try {
        const router = await walletIframe.requireRouter(String(accountId));
        const result = await router.registerWallet(registerWalletArgs);
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    executeAction: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      if (!walletIframe.shouldUseWalletIframe()) {
        return await executeAction({
          context: getContext(),
          nearAccountId,
          receiverId: toAccountId(args.receiverId),
          actionArgs: args.actionArgs,
          options: args.options,
        });
      }
      try {
        const router = await walletIframe.requireRouter(nearAccountId);
        const result = await router.executeAction({
          nearAccountId,
          receiverId: args.receiverId,
          actionArgs: args.actionArgs,
          options: args.options,
        });
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    signAndSendTransactions: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const { transactions, options } = args;
      if (!walletIframe.shouldUseWalletIframe()) {
        try {
          return await signAndSendTransactions({
            context: getContext(),
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
      try {
        const router = await walletIframe.requireRouter(nearAccountId);
        const routerOptions = {
          ...options,
          executionWait: options?.executionWait ?? {
            mode: 'sequential' as const,
            waitUntil: options?.waitUntil,
          },
        };
        const result = await router.signAndSendTransactions({
          nearAccountId,
          transactions: transactions.map((transaction) => ({
            receiverId: transaction.receiverId,
            actions: transaction.actions,
          })),
          options: routerOptions,
        });
        await options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    signAndSendTransaction: async (args) => {
      const results = await nearCapability.signAndSendTransactions({
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
    },
    signTransactionsWithActions: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const { transactions, options } = args;
      if (!walletIframe.shouldUseWalletIframe()) {
        try {
          return await signTransactionsWithActions({
            context: getContext(),
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
      try {
        const router = await walletIframe.requireRouter(nearAccountId);
        const result = await router.signTransactionsWithActions({
          nearAccountId,
          transactions: transactions.map((transaction) => ({
            receiverId: transaction.receiverId,
            actions: transaction.actions,
          })),
          options: {
            signerSlot: options.signerSlot,
            onEvent: options.onEvent,
            confirmationConfig: options.confirmationConfig,
            confirmerText: options.confirmerText,
          },
        });
        const signedTransactions = Array.isArray(result) ? result : [];
        await options?.afterCall?.(true, signedTransactions);
        return signedTransactions;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    sendTransaction: async (args) => {
      const walletIframe = deps.getWalletIframe();
      if (!walletIframe.shouldUseWalletIframe()) {
        return await sendTransaction({
          context: getContext(),
          signedTransaction: args.signedTransaction,
          options: args.options,
        });
      }
      try {
        const router = await walletIframe.requireRouter();
        const result = await router.sendTransaction({
          signedTransaction: args.signedTransaction,
          options: {
            onEvent: args.options?.onEvent,
            ...(args.options && 'waitUntil' in args.options
              ? { waitUntil: args.options.waitUntil }
              : {}),
          },
        });
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    signDelegateAction: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const { delegate, options } = args;
      if (!walletIframe.shouldUseWalletIframe()) {
        return await signDelegateActionCore({
          context: getContext(),
          nearAccountId,
          delegate,
          options,
        });
      }
      try {
        const router = await walletIframe.requireRouter(nearAccountId);
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
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    sendDelegateActionViaRelayer: async (args) => {
      const base = args.relayerUrl.replace(/\/+$/, '');
      const route = (
        deps.configs.network.relayer?.routes?.delegateAction || '/signed-delegate'
      ).replace(/^\/?/, '/');
      return await sendDelegateActionViaRelayerCore({
        url: `${base}${route}`,
        payload: {
          hash: args.hash,
          signedDelegate: args.signedDelegate,
        },
        signal: args.signal,
        options: args.options,
      });
    },
    signAndSendDelegateAction: async (args) => {
      const signOptions = {
        signerSlot: args.options.signerSlot,
        onEvent: args.options.onEvent,
        onError: args.options.onError,
        waitUntil: args.options.waitUntil,
        confirmationConfig: args.options.confirmationConfig,
        confirmerText: args.options.confirmerText,
        afterCall: () => {},
      };

      let signResult;
      try {
        signResult = await nearCapability.signDelegateAction({
          nearAccount: args.nearAccount,
          delegate: args.delegate,
          options: signOptions,
        });
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }

      const relayOptions = {
        onEvent: args.options.onEvent,
        onError: args.options.onError,
      };

      let relayResult;
      try {
        relayResult = await nearCapability.sendDelegateActionViaRelayer({
          relayerUrl: args.relayerUrl,
          hash: signResult.hash,
          signedDelegate: signResult.signedDelegate,
          signal: args.signal,
          options: relayOptions,
        });
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }

      const combined = {
        signResult,
        relayResult,
      };
      if (relayResult.ok !== false) {
        await args.options?.afterCall?.(true, combined);
      } else {
        const relayError = toError(relayResult.error || 'Delegate relay failed');
        await args.options?.afterCall?.(false, undefined, relayError);
      }
      return combined;
    },
    signNEP413Message: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      if (!walletIframe.shouldUseWalletIframe()) {
        const result = await signNEP413MessageCore({
          context: getContext(),
          nearAccountId,
          params: args.params,
          options: args.options,
        });
        if (result?.success) {
          await args.options?.afterCall?.(true, result);
        } else {
          const signingError = toError(result?.error || 'NEP-413 signing failed');
          await args.options?.afterCall?.(false, undefined, signingError);
        }
        return result;
      }
      try {
        const router = await walletIframe.requireRouter(nearAccountId);
        const result = await router.signNep413Message({
          nearAccountId,
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
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
  };
  return nearCapability;
}
