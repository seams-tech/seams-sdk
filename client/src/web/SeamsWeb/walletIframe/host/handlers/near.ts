import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  RegistrationHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { RegistrationResult } from '@/core/types/seams';
import type { PMExecuteActionPayload } from '../../shared/messages';
import { nearAccountRefFromAccountId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { NonceLeaseRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  extractBorshBytesFromPlainSignedTx,
  isPlainSignedTransactionLike,
  type PlainSignedTransactionLike,
} from '@shared/utils/validation';
import type { ActionArgs } from '@/core/types';
import type { HandlerDeps, HandlerMap, Req } from './types';
import { respondOk, respondOkResult, withProgress } from './shared';

function normalizeSignedTransaction(
  candidate: SignedTransaction | PlainSignedTransactionLike | undefined,
): SignedTransaction | PlainSignedTransactionLike | undefined {
  if (candidate && isPlainSignedTransactionLike(candidate)) {
    try {
      const borsh = extractBorshBytesFromPlainSignedTx(candidate);
      const nonceLease = (candidate as { nonceLease?: NonceLeaseRef }).nonceLease;
      return SignedTransaction.fromPlain({
        transaction: candidate.transaction,
        signature: candidate.signature,
        borsh_bytes: borsh,
        ...(nonceLease ? { nonceLease } : {}),
      });
    } catch {
      return candidate;
    }
  }
  return candidate;
}

export function createNearWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REGISTER: async (req: Req<'PM_REGISTER'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, options, confirmationConfig } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;

      const hooksOptions = withProgress(deps, req.requestId, options) as RegistrationHooksOptions;
      const result: RegistrationResult = await pm.registration.registerPasskey(nearAccountId, {
        ...hooksOptions,
        ...(confirmationConfig ? { confirmationConfig } : {}),
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_REGISTER_WALLET: async (req: Req<'PM_REGISTER_WALLET'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const hooksOptions = withProgress(
        deps,
        req.requestId,
        payload.options || {},
      ) as RegistrationHooksOptions;
      const result = await pm.registration.registerWallet({
        authMethod: payload.authMethod,
        wallet: payload.wallet,
        rpId: payload.rpId,
        signerSelection: payload.signerSelection,
        options: {
          ...hooksOptions,
          ...(payload.confirmationConfig ? { confirmationConfig: payload.confirmationConfig } : {}),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_ADD_WALLET_SIGNER: async (req: Req<'PM_ADD_WALLET_SIGNER'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const hooksOptions = withProgress(
        deps,
        req.requestId,
        payload.options || {},
      ) as RegistrationHooksOptions;
      const result = await pm.registration.addWalletSigner({
        walletId: payload.walletId,
        rpId: payload.rpId,
        signerSelection: payload.signerSelection,
        options: {
          ...hooksOptions,
          ...(payload.confirmationConfig ? { confirmationConfig: payload.confirmationConfig } : {}),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_PREFETCH_BLOCKHEIGHT: async (req: Req<'PM_PREFETCH_BLOCKHEIGHT'>) => {
      const pm = deps.getSeamsWeb();
      await pm.prefetchBlockheight().catch(() => undefined);
      respondOk(deps, req.requestId);
    },

    PM_SIGN_TXS_WITH_ACTIONS: async (req: Req<'PM_SIGN_TXS_WITH_ACTIONS'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, transactions, options } = req.payload!;
      const results = await pm.near.signTransactionsWithActions({
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        transactions,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as SignTransactionHooksOptions,
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, results);
    },

    PM_SIGN_AND_SEND_TXS: async (req: Req<'PM_SIGN_AND_SEND_TXS'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, transactions, options } = req.payload || {};
      const results = await pm.near.signAndSendTransactions({
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        transactions: transactions || [],
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as SignAndSendTransactionHooksOptions,
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, results);
    },

    PM_SEND_TRANSACTION: async (req: Req<'PM_SEND_TRANSACTION'>) => {
      const pm = deps.getSeamsWeb();
      const { signedTransaction, options } = req.payload || {};
      const result = await pm.near.sendTransaction({
        signedTransaction: normalizeSignedTransaction(signedTransaction) as SignedTransaction,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as SendTransactionHooksOptions,
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_EXECUTE_ACTION: async (req: Req<'PM_EXECUTE_ACTION'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, receiverId, actionArgs, options } =
        req.payload || ({} as Partial<PMExecuteActionPayload>);
      const result = await pm.near.executeAction({
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        receiverId: receiverId as string,
        actionArgs: (actionArgs as ActionArgs | ActionArgs[])!,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as ActionHooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SIGN_DELEGATE_ACTION: async (req: Req<'PM_SIGN_DELEGATE_ACTION'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, delegate, options } = req.payload!;
      const result = await pm.near.signDelegateAction({
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        delegate,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as DelegateActionHooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SIGN_NEP413: async (req: Req<'PM_SIGN_NEP413'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, params, options } = req.payload!;
      const result = await pm.near.signNEP413Message({
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        params,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as SignNEP413HooksOptions,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },
  };
}
