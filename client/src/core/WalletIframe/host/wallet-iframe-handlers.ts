import type {
  ParentToChildEnvelope,
  ParentToChildType,
  ChildToParentEnvelope,
  ProgressPayload,
  PMExecuteActionPayload,
} from '../shared/messages';
import type { TatchiPasskey } from '../../TatchiPasskey';
import { errorMessage, isTouchIdCancellationError } from '@shared/utils/errors';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
  SyncAccountHooksOptions,
} from '../../types/sdkSentEvents';
import type { WalletSession, RegistrationResult } from '../../types/tatchi';
import type { ConfirmationConfig } from '../../types/signer-worker';
import { toAccountId } from '../../types/accountIds';
import { SignedTransaction } from '../../rpcClients/near/NearClient';
import {
  isPlainSignedTransactionLike,
  extractBorshBytesFromPlainSignedTx,
  PlainSignedTransactionLike,
} from '@shared/utils/validation';
import type { ActionArgs } from '../../types';

type Req<T extends ParentToChildType> = Extract<ParentToChildEnvelope, { type: T }>;
type HandlerMap = Partial<{
  [K in ParentToChildType]: (req: Extract<ParentToChildEnvelope, { type: K }>) => Promise<void>;
}>;

export interface HandlerDeps {
  getTatchiPasskey(): TatchiPasskey;
  post(msg: ChildToParentEnvelope): void;
  postProgress(requestId: string | undefined, payload: ProgressPayload): void;
  postToParent?(msg: unknown): void;
  isCancelled(requestId: string | undefined): boolean;
  respondIfCancelled(requestId: string | undefined): boolean;
}

export function createWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  const { getTatchiPasskey, post, postProgress, postToParent, isCancelled, respondIfCancelled } =
    deps;

  const respondOk = (requestId: string | undefined): void => {
    post({ type: 'PM_RESULT', requestId, payload: { ok: true } });
  };

  const respondOkResult = (requestId: string | undefined, result: unknown): void => {
    post({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
  };

  const withProgress = <T extends object>(
    requestId: string | undefined,
    options?: T,
  ): T & { onEvent: (payload: ProgressPayload) => void } => {
    return {
      ...(options || {}),
      onEvent: (ev: ProgressPayload) => postProgress(requestId, ev),
    } as T & { onEvent: (payload: ProgressPayload) => void };
  };

  const normalizeSignedTransaction = (
    candidate: SignedTransaction | PlainSignedTransactionLike | undefined,
  ): SignedTransaction | PlainSignedTransactionLike | undefined => {
    if (candidate && isPlainSignedTransactionLike(candidate)) {
      try {
        const borsh = extractBorshBytesFromPlainSignedTx(candidate);
        return SignedTransaction.fromPlain({
          transaction: candidate.transaction,
          signature: candidate.signature,
          borsh_bytes: borsh,
        });
      } catch {
        return candidate;
      }
    }
    return candidate;
  };

  const handlers = {
    PM_UNLOCK: async (req: Req<'PM_UNLOCK'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.unlock(
        nearAccountId,
        withProgress(req.requestId, options) as LoginHooksOptions,
      );
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_LOCK: async (req: Req<'PM_LOCK'>) => {
      const pm = getTatchiPasskey();
      await pm.auth.lock();
      respondOk(req.requestId);
    },

    PM_GET_WALLET_SESSION: async (req: Req<'PM_GET_WALLET_SESSION'>) => {
      const pm = getTatchiPasskey();
      const result: WalletSession = await pm.auth.getWalletSession(req.payload?.nearAccountId);
      respondOkResult(req.requestId, result);
    },

    PM_REGISTER: async (req: Req<'PM_REGISTER'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options, confirmationConfig } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;

      const hooksOptions = withProgress(req.requestId, options) as RegistrationHooksOptions;

      const result: RegistrationResult = !confirmationConfig
        ? await pm.registration.registerPasskey(nearAccountId, hooksOptions)
        : await pm.registration.registerPasskeyInternal(
            nearAccountId,
            hooksOptions,
            confirmationConfig as unknown as ConfirmationConfig,
          );

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION: async (
      req: Req<'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION'>,
    ) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;

      const chain = options?.chain;
      const result =
        chain === 'evm'
          ? await pm.evm.bootstrapEcdsaSession({
              nearAccountId,
              options: options || {},
            })
          : await pm.tempo.bootstrapEcdsaSession({
              nearAccountId,
              options: options || {},
            });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SIGN_TXS_WITH_ACTIONS: async (req: Req<'PM_SIGN_TXS_WITH_ACTIONS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, transactions, options } = req.payload!;

      const results = await pm.near.signTransactionsWithActions({
        nearAccountId,
        transactions: transactions,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SignTransactionHooksOptions,
      });

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, results);
    },

    PM_SIGN_AND_SEND_TXS: async (req: Req<'PM_SIGN_AND_SEND_TXS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, transactions, options } = req.payload || {};

      const results = await pm.near.signAndSendTransactions({
        nearAccountId: nearAccountId as string,
        transactions: transactions || [],
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SignAndSendTransactionHooksOptions,
      });

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, results);
    },

    PM_SEND_TRANSACTION: async (req: Req<'PM_SEND_TRANSACTION'>) => {
      const pm = getTatchiPasskey();
      const { signedTransaction, options } = req.payload || {};
      const st = normalizeSignedTransaction(signedTransaction);
      const result = await pm.near.sendTransaction({
        signedTransaction: st as SignedTransaction,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SendTransactionHooksOptions,
      });

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_EXECUTE_ACTION: async (req: Req<'PM_EXECUTE_ACTION'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, receiverId, actionArgs, options } =
        req.payload || ({} as Partial<PMExecuteActionPayload>);
      const result = await pm.near.executeAction({
        nearAccountId: nearAccountId as string,
        receiverId: receiverId as string,
        actionArgs: (actionArgs as ActionArgs | ActionArgs[])!,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as ActionHooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SIGN_DELEGATE_ACTION: async (req: Req<'PM_SIGN_DELEGATE_ACTION'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, delegate, options } = req.payload!;
      const result = await pm.near.signDelegateAction({
        nearAccountId: nearAccountId,
        delegate,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as DelegateActionHooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SIGN_NEP413: async (req: Req<'PM_SIGN_NEP413'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, params, options } = req.payload!;
      const result = await pm.near.signNEP413Message({
        nearAccountId,
        params,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SignNEP413HooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SIGN_TEMPO: async (req: Req<'PM_SIGN_TEMPO'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, request, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.tempo.signTempo({
        nearAccountId,
        request,
        options: {
          confirmationConfig: options?.confirmationConfig,
          shouldAbort: () => isCancelled(req.requestId),
          onEvent: (ev) => {
            postProgress(req.requestId, ev as unknown as ProgressPayload);
          },
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_REPORT_TEMPO_BROADCAST_ACCEPTED: async (req: Req<'PM_REPORT_TEMPO_BROADCAST_ACCEPTED'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, signedResult, txHash } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportBroadcastAccepted({
        nearAccountId,
        signedResult,
        ...(txHash ? { txHash } : {}),
        options: {
          onEvent: (ev) => {
            postProgress(req.requestId, ev as unknown as ProgressPayload);
          },
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_REPORT_TEMPO_BROADCAST_REJECTED: async (req: Req<'PM_REPORT_TEMPO_BROADCAST_REJECTED'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, signedResult, error } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportBroadcastRejected({
        nearAccountId,
        signedResult,
        ...(error ? { error } : {}),
        options: {
          onEvent: (ev) => {
            postProgress(req.requestId, ev as unknown as ProgressPayload);
          },
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_REPORT_TEMPO_FINALIZED: async (req: Req<'PM_REPORT_TEMPO_FINALIZED'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, signedResult, txHash, receiptStatus } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportFinalized({
        nearAccountId,
        signedResult,
        ...(txHash ? { txHash } : {}),
        ...(receiptStatus ? { receiptStatus } : {}),
        options: {
          onEvent: (ev) => {
            postProgress(req.requestId, ev as unknown as ProgressPayload);
          },
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_REPORT_TEMPO_DROPPED_OR_REPLACED: async (
      req: Req<'PM_REPORT_TEMPO_DROPPED_OR_REPLACED'>,
    ) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, signedResult, reason, txHash } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      await pm.tempo.reportDroppedOrReplaced({
        nearAccountId,
        signedResult,
        reason,
        ...(txHash ? { txHash } : {}),
        options: {
          onEvent: (ev) => {
            postProgress(req.requestId, ev as unknown as ProgressPayload);
          },
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_RECONCILE_TEMPO_NONCE_LANE: async (req: Req<'PM_RECONCILE_TEMPO_NONCE_LANE'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, signedResult } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.tempo.reconcileNonceLane({
        nearAccountId,
        signedResult,
        options: {
          onEvent: (ev) => {
            postProgress(req.requestId, ev as unknown as ProgressPayload);
          },
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_EXPORT_KEYPAIR_UI: async (req: Req<'PM_EXPORT_KEYPAIR_UI'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, chain, variant, theme } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      try {
        await pm.keys.exportKeypairWithUI(nearAccountId, { chain, variant, theme });
      } catch (err: unknown) {
        if (isTouchIdCancellationError(err)) {
          postToParent?.({ type: 'EXPORT_KEYPAIR_CANCELLED', nearAccountId, chain });
          postToParent?.({ type: 'WALLET_UI_CLOSED' });
          if (respondIfCancelled(req.requestId)) return;
          respondOk(req.requestId);
          return;
        }
        postToParent?.({ type: 'WALLET_UI_CLOSED', error: errorMessage(err) });
        throw err;
      }
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI: async (
      req: Req<'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI'>,
    ) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, preparedSession, finalizedReport, expectedPublicKey, variant, theme } =
        req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      try {
        await pm.keys.exportThresholdEd25519SeedFromHssReport({
          nearAccountId,
          preparedSession,
          finalizedReport,
          expectedPublicKey,
          options: { variant, theme },
        });
      } catch (err: unknown) {
        if (isTouchIdCancellationError(err)) {
          postToParent?.({ type: 'EXPORT_KEYPAIR_CANCELLED', nearAccountId, chain: 'near' });
          postToParent?.({ type: 'WALLET_UI_CLOSED' });
          if (respondIfCancelled(req.requestId)) return;
          respondOk(req.requestId);
          return;
        }
        postToParent?.({ type: 'WALLET_UI_CLOSED', error: errorMessage(err) });
        throw err;
      }
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_GET_RECENT_UNLOCKS: async (req: Req<'PM_GET_RECENT_UNLOCKS'>) => {
      const pm = getTatchiPasskey();
      const result = await pm.auth.getRecentUnlocks();
      respondOkResult(req.requestId, result);
    },

    PM_PREFETCH_BLOCKHEIGHT: async (req: Req<'PM_PREFETCH_BLOCKHEIGHT'>) => {
      const pm = getTatchiPasskey();
      await pm.prefetchBlockheight().catch(() => undefined);
      respondOk(req.requestId);
    },

    PM_PREFILL_THRESHOLD_ECDSA_PRESIGN_POOL: async (
      req: Req<'PM_PREFILL_THRESHOLD_ECDSA_PRESIGN_POOL'>,
    ) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.auth.prefillThresholdEcdsaPresignPool({
        nearAccountId,
        ...(options?.chain ? { chain: options.chain } : {}),
        ...(typeof options?.waitForPoolReady === 'boolean'
          ? { waitForPoolReady: options.waitForPoolReady }
          : {}),
        ...(typeof options?.poolReadyTimeoutMs === 'number'
          ? { poolReadyTimeoutMs: options.poolReadyTimeoutMs }
          : {}),
        ...(typeof options?.poolReadyPollIntervalMs === 'number'
          ? { poolReadyPollIntervalMs: options.poolReadyPollIntervalMs }
          : {}),
        ...(typeof options?.minRemainingUsesBeforePrefill === 'number'
          ? { minRemainingUsesBeforePrefill: options.minRemainingUsesBeforePrefill }
          : {}),
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_GET_RECOVERY_EMAILS: async (req: Req<'PM_GET_RECOVERY_EMAILS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.getRecoveryEmails(nearAccountId);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SET_RECOVERY_EMAILS: async (req: Req<'PM_SET_RECOVERY_EMAILS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, recoveryEmails, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.setRecoveryEmails({
        accountId: nearAccountId,
        recoveryEmails: Array.isArray(recoveryEmails) ? recoveryEmails : [],
        options: {
          ...withProgress(req.requestId, options || {}),
        } as ActionHooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SYNC_ACCOUNT_FLOW: async (req: Req<'PM_SYNC_ACCOUNT_FLOW'>) => {
      const pm = getTatchiPasskey();
      const { accountId } = req.payload || {};
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.syncAccount({
        ...(accountId ? { accountId } : {}),
        options: {
          ...withProgress(req.requestId, {}),
        } as SyncAccountHooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_START_EMAIL_RECOVERY: async (req: Req<'PM_START_EMAIL_RECOVERY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.startEmailRecovery({
        accountId,
        options: {
          ...withProgress(req.requestId, options || {}),
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_FINALIZE_EMAIL_RECOVERY: async (req: Req<'PM_FINALIZE_EMAIL_RECOVERY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, nearPublicKey } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      await pm.recovery.finalizeEmailRecovery({
        accountId,
        ...(nearPublicKey ? { nearPublicKey } : {}),
        options: {
          ...withProgress(req.requestId, {}),
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_STOP_EMAIL_RECOVERY: async (req: Req<'PM_STOP_EMAIL_RECOVERY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, nearPublicKey } = req.payload || {};
      if (respondIfCancelled(req.requestId)) return;
      await pm.recovery.cancelEmailRecovery({
        ...(accountId ? { accountId } : {}),
        ...(nearPublicKey ? { nearPublicKey } : {}),
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_START_DEVICE2_LINKING_FLOW: async (req: Req<'PM_START_DEVICE2_LINKING_FLOW'>) => {
      const pm = getTatchiPasskey();
      const { ui, cameraId, accountId, deviceNumber, options } = req.payload || {};
      const accountIdValue = accountId ? toAccountId(accountId) : undefined;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.startDevice2LinkingFlow({
        ...(ui ? { ui } : {}),
        ...(cameraId ? { cameraId } : {}),
        ...(accountIdValue ? { accountId: accountIdValue } : {}),
        ...(typeof deviceNumber === 'number' ? { deviceNumber } : {}),
        options: {
          ...withProgress(req.requestId, options || {}),
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_STOP_DEVICE2_LINKING_FLOW: async (req: Req<'PM_STOP_DEVICE2_LINKING_FLOW'>) => {
      const pm = getTatchiPasskey();
      if (respondIfCancelled(req.requestId)) return;
      await pm.recovery.stopDevice2LinkingFlow();
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_LINK_DEVICE_WITH_SCANNED_QR_DATA: async (
      req: Req<'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA'>,
    ) => {
      const pm = getTatchiPasskey();
      const { qrData, fundingAmount, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.recovery.linkDeviceWithScannedQRData(qrData, {
        fundingAmount: String(fundingAmount || ''),
        ...withProgress(req.requestId, options || {}),
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SET_CONFIRM_BEHAVIOR: async (req: Req<'PM_SET_CONFIRM_BEHAVIOR'>) => {
      const pm = getTatchiPasskey();
      const { behavior } = req.payload!;
      pm.setConfirmBehavior(behavior);
      respondOk(req.requestId);
    },

    PM_SET_CONFIRMATION_CONFIG: async (req: Req<'PM_SET_CONFIRMATION_CONFIG'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId } = req.payload || {};
      const incoming = (req.payload?.config || {}) as Record<string, unknown>;
      let patch: Record<string, unknown> = { ...incoming };
      if (nearAccountId) {
        await pm.auth
          .getWalletSession(nearAccountId)
          .then(({ login }) => {
            const existing = (login?.userData?.preferences?.confirmationConfig || {}) as Record<
              string,
              unknown
            >;
            patch = { ...existing, ...incoming };
          })
          .catch(() => undefined);
      }
      const base: ConfirmationConfig = pm.getConfirmationConfig();
      pm.setConfirmationConfig({ ...base, ...patch });
      respondOk(req.requestId);
    },

    PM_GET_CONFIRMATION_CONFIG: async (req: Req<'PM_GET_CONFIRMATION_CONFIG'>) => {
      const pm = getTatchiPasskey();
      const result = pm.getConfirmationConfig();
      respondOkResult(req.requestId, result);
    },

    PM_SET_THEME: async (req: Req<'PM_SET_THEME'>) => {
      const pm = getTatchiPasskey();
      const { theme } = req.payload!;
      try {
        pm.setTheme(theme);
      } catch {}
      try {
        if (theme === 'light' || theme === 'dark') {
          document.documentElement.setAttribute('data-w3a-theme', theme);
        }
      } catch {}
      respondOk(req.requestId);
    },

    PM_HAS_PASSKEY: async (req: Req<'PM_HAS_PASSKEY'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId } = req.payload!;
      // Soft probe to warm caches in some environments (optional)
      const ctx = pm.getContext();
      const web = ctx?.signingEngine;
      if (web) {
        await web.getLastUser().catch(() => undefined);
        await web.getAuthenticatorsByUser(toAccountId(nearAccountId)).catch(() => undefined);
      }
      const result = await pm.auth.hasPasskeyCredential(toAccountId(nearAccountId));
      respondOkResult(req.requestId, result);
    },

    PM_VIEW_ACCESS_KEYS: async (req: Req<'PM_VIEW_ACCESS_KEYS'>) => {
      const pm = getTatchiPasskey();
      const { accountId } = req.payload!;
      const result = await pm.viewAccessKeyList(accountId);
      respondOkResult(req.requestId, result);
    },

    PM_DELETE_DEVICE_KEY: async (req: Req<'PM_DELETE_DEVICE_KEY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, publicKeyToDelete, options } = req.payload!;
      const result = await pm.deleteDeviceKey(accountId, publicKeyToDelete, {
        ...withProgress(req.requestId, options || {}),
      } as ActionHooksOptions);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },
  } satisfies HandlerMap;

  return handlers;
}
