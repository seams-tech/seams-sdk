import type { ActionResult } from '@/core/types/seams';
import type { NearSignerCapability } from '../interfaces';
import { toError } from '@shared/utils/errors';
import { toAccountId } from '@/core/types/accountIds';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';
import { buildNearWalletRegistrationArgs, NearSigner } from '../near';

export function createNearSignerCapability(deps: {
  getContext: () => import('../index').SeamsWebContext;
  getWalletIframe: () => WalletIframeCoordinator;
}): NearSignerCapability {
  const nearSigner = new NearSigner({ getContext: deps.getContext });
  const nearCapability: NearSignerCapability = {
    registerNearWallet: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const context = deps.getContext();
      const accountId = toAccountId(args.nearAccountId);
      const registerWalletArgs = buildNearWalletRegistrationArgs(context, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await nearSigner.registerNearWallet(args);
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
        return await nearSigner.executeAction(args);
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
        return await nearSigner.signAndSendTransactions(args);
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
        return await nearSigner.signTransactionsWithActions(args);
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
        return await nearSigner.sendTransaction(args);
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
        return await nearSigner.signDelegateAction(args);
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
    sendDelegateActionViaRelayer: async (args) =>
      await nearSigner.sendDelegateActionViaRelayer(args),
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
        return await nearSigner.signNEP413Message(args);
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
