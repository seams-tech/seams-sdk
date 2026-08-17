import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  RegistrationHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { AddPasskeyHooksOptions } from '@/SeamsWeb/operations/authMethods/passkey/addPasskey';
import {
  type PMExecuteActionPayload,
  type PMFundImplicitNearAccountForTestingPayload,
  type PMRegisterWalletPayload,
  type PMRegistrationAuthMethodInput,
  type PMSendTxPayload,
} from '../../shared/messages';
import {
  nearAccountRefFromAccountId,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { NonceLeaseRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  extractBorshBytesFromPlainSignedTx,
  isPlainObject,
  isPlainSignedTransactionLike,
  type PlainSignedTransactionLike,
} from '@shared/utils/validation';
import type { ActionArgs } from '@/core/types';
import type { RegistrationAuthMethodInput } from '@shared/utils/registrationIntent';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress, withRegistrationProgress } from './shared';

function walletSessionFromWalletId(walletIdRaw: unknown) {
  const walletId = toWalletId(walletIdRaw);
  return {
    walletId,
    walletSessionUserId: String(walletId),
  };
}

function normalizeSignedTransaction(
  candidate: SignedTransaction | PlainSignedTransactionLike | undefined,
): SignedTransaction | PlainSignedTransactionLike | undefined {
  if (candidate && isPlainSignedTransactionLike(candidate)) {
    try {
      const borsh = extractBorshBytesFromPlainSignedTx(candidate);
      const nonceLease = (candidate as { nonceLease?: NonceLeaseRef }).nonceLease;
      const serverDispatch = (candidate as { serverDispatch?: SignedTransaction['serverDispatch'] })
        .serverDispatch;
      return SignedTransaction.fromPlain({
        transaction: candidate.transaction,
        signature: candidate.signature,
        borsh_bytes: borsh,
        ...(nonceLease ? { nonceLease } : {}),
        ...(serverDispatch ? { serverDispatch } : {}),
      });
    } catch {
      return candidate;
    }
  }
  return candidate;
}

function assertNeverRegistrationAuthMethod(value: never): never {
  throw new Error(`Unsupported registration auth method: ${String(value)}`);
}

function walletOriginRegistrationAuthMethod(
  authMethod: PMRegistrationAuthMethodInput,
): RegistrationAuthMethodInput {
  switch (authMethod.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: authMethod.rpId,
        ...(authMethod.authenticatorOptions === undefined
          ? {}
          : { authenticatorOptions: authMethod.authenticatorOptions }),
      };
    case 'email_otp': {
      switch (authMethod.proofKind) {
        case 'otp_challenge':
          return {
            kind: 'email_otp',
            proofKind: 'otp_challenge',
            email: authMethod.email,
            providerSubject: authMethod.providerSubject,
            otpCode: authMethod.otpCode,
            ...(authMethod.challengeId === undefined
              ? {}
              : { challengeId: authMethod.challengeId }),
          };
        case 'google_sso_registration':
          return {
            kind: 'email_otp',
            proofKind: 'google_sso_registration',
            email: authMethod.email,
            providerSubject: authMethod.providerSubject,
            googleEmailOtpRegistrationAttemptId: authMethod.googleEmailOtpRegistrationAttemptId,
            googleEmailOtpRegistrationOfferId: authMethod.googleEmailOtpRegistrationOfferId,
            googleEmailOtpRegistrationCandidateId: authMethod.googleEmailOtpRegistrationCandidateId,
          };
        default:
          return assertNeverRegistrationAuthMethod(authMethod);
      }
    }
    default:
      return assertNeverRegistrationAuthMethod(authMethod);
  }
}

export function createNearWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REGISTER_WALLET: async (req: Req<'PM_REGISTER_WALLET'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const hooksOptions = withRegistrationProgress(
        deps,
        req.requestId,
        payload.options || {},
      ) as RegistrationHooksOptions;
      const result = await pm.registration.registerWallet({
        authMethod: walletOriginRegistrationAuthMethod(
          payload.authMethod,
        ),
        wallet: payload.wallet,
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

    PM_ADD_PASSKEY: async (req: Req<'PM_ADD_PASSKEY'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      const hooksOptions = withProgress(
        deps,
        req.requestId,
        payload.options || {},
      ) as AddPasskeyHooksOptions;
      const result = await pm.registration.addPasskey({
        walletId: payload.walletId,
        rpId: payload.rpId,
        authorization: payload.authorization,
        options: {
          ...hooksOptions,
          ...(payload.confirmationConfig ? { confirmationConfig: payload.confirmationConfig } : {}),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_GET_NEAR_PROVISIONING_STATE: async (req: Req<'PM_GET_NEAR_PROVISIONING_STATE'>) => {
      const pm = deps.getSeamsWeb();
      const walletId = toWalletId(req.payload?.walletId);
      const result = await pm.registration.getNearProvisioningState({ walletId });
      respondOkResult(deps, req.requestId, result);
    },

    PM_PREFETCH_BLOCKHEIGHT: async (req: Req<'PM_PREFETCH_BLOCKHEIGHT'>) => {
      const pm = deps.getSeamsWeb();
      await pm.prefetchBlockheight().catch(() => undefined);
      respondOk(deps, req.requestId);
    },

    PM_SIGN_TX_WITH_ACTIONS: async (req: Req<'PM_SIGN_TX_WITH_ACTIONS'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId, nearAccountId, transaction, options } = req.payload!;
      const result = await pm.near.signTransactionWithActions({
        walletSession: walletSessionFromWalletId(walletId),
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        transaction,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as SignTransactionHooksOptions,
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SIGN_AND_SEND_TX: async (req: Req<'PM_SIGN_AND_SEND_TX'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId, nearAccountId, transaction, options } = req.payload!;
      const result = await pm.near.signAndSendTransaction({
        walletSession: walletSessionFromWalletId(walletId),
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        receiverId: transaction.receiverId,
        actions: transaction.actions,
        options: {
          ...withProgress(deps, req.requestId, options || {}),
        } as SignAndSendTransactionHooksOptions,
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_FUND_IMPLICIT_NEAR_ACCOUNT_FOR_TESTING: async (
      req: Req<'PM_FUND_IMPLICIT_NEAR_ACCOUNT_FOR_TESTING'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const { walletId, nearAccountId, nearPublicKey } =
        req.payload || ({} as Partial<PMFundImplicitNearAccountForTestingPayload>);
      const result = await pm.near.fundImplicitNearAccountForTesting({
        walletSession: walletSessionFromWalletId(walletId),
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
        nearPublicKey: String(nearPublicKey || ''),
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_SEND_TRANSACTION: async (req: Req<'PM_SEND_TRANSACTION'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId, nearAccountId, signedTransaction, options } =
        req.payload || ({} as Partial<PMSendTxPayload>);
      const result = await pm.near.sendTransaction({
        walletSession: walletSessionFromWalletId(walletId),
        nearAccount: nearAccountRefFromAccountId(nearAccountId),
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
      const { walletId, nearAccountId, receiverId, actionArgs, options } =
        req.payload || ({} as Partial<PMExecuteActionPayload>);
      const result = await pm.near.executeAction({
        walletSession: walletSessionFromWalletId(walletId),
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
      const { walletId, nearAccountId, delegate, options } = req.payload!;
      const result = await pm.near.signDelegateAction({
        walletSession: walletSessionFromWalletId(walletId),
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
      const { walletId, nearAccountId, params, options } = req.payload!;
      const result = await pm.near.signNEP413Message({
        walletSession: walletSessionFromWalletId(walletId),
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
