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
import type {
  PMExecuteActionPayload,
  PMRegistrationActivationPreparePayload,
} from '../../shared/messages';
import { nearAccountRefFromAccountId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { NonceLeaseRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  extractBorshBytesFromPlainSignedTx,
  isObject,
  isPlainSignedTransactionLike,
  type PlainSignedTransactionLike,
} from '@shared/utils/validation';
import type { ActionArgs } from '@/core/types';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
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

type RegistrationActivationRecord = {
  activationId: string;
  requestId: string | undefined;
  container: HTMLElement;
  reject(error: Error): void;
  cancelled: boolean;
  started: boolean;
};

const registrationActivationRecords = new Map<string, RegistrationActivationRecord>();

function registrationOptionsWithoutActivation(options: unknown): Record<string, unknown> {
  const out = isObject(options) ? { ...(options as Record<string, unknown>) } : {};
  delete out.walletIframeActivation;
  return out;
}

function removeRegistrationActivationRecord(activationId: string): void {
  const record = registrationActivationRecords.get(activationId);
  registrationActivationRecords.delete(activationId);
  try {
    record?.container.remove();
  } catch {}
}

function registrationActivationCancelledError(): Error & { code: string } {
  const error = new Error('Registration activation cancelled') as Error & { code: string };
  error.code = 'cancelled';
  return error;
}

function renderRegistrationActivationButton(args: {
  payload: PMRegistrationActivationPreparePayload;
  onStart(): void;
  onCancel(): void;
}): HTMLElement {
  const container = document.createElement('section');
  container.setAttribute('data-w3a-registration-activation-id', args.payload.activationId);
  Object.assign(container.style, {
    minHeight: '100vh',
    display: 'grid',
    placeItems: 'center',
    padding: '24px',
    boxSizing: 'border-box',
    background: 'var(--w3a-colors-surface, #111318)',
    color: 'var(--w3a-colors-text, #fff)',
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  });

  const panel = document.createElement('div');
  Object.assign(panel.style, {
    width: 'min(420px, 100%)',
    display: 'grid',
    gap: '16px',
  });

  const title = document.createElement('div');
  title.textContent = args.payload.nearAccountId;
  Object.assign(title.style, {
    fontSize: '16px',
    fontWeight: '700',
    lineHeight: '1.35',
    wordBreak: 'break-word',
    color: 'var(--w3a-colors-text, #fff)',
  });

  const button = document.createElement('button');
  button.type = 'button';
  button.setAttribute('data-w3a-registration-activation-start', 'true');
  button.textContent = args.payload.button?.label || 'Create passkey';
  Object.assign(button.style, {
    width: '100%',
    minHeight: '52px',
    border: '0',
    borderRadius: '8px',
    padding: '0 18px',
    background: 'var(--w3a-colors-buttonBackground, #4daffe)',
    color: 'var(--w3a-colors-buttonText, #fff)',
    fontSize: '16px',
    fontWeight: '700',
    cursor: 'pointer',
  });
  button.addEventListener('click', () => {
    button.disabled = true;
    button.textContent = args.payload.button?.busyLabel || 'Creating passkey...';
    button.style.cursor = 'default';
    args.onStart();
  });

  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.textContent = 'Cancel';
  Object.assign(cancel.style, {
    width: '100%',
    minHeight: '44px',
    border: '1px solid var(--w3a-colors-border, rgba(255,255,255,0.22))',
    borderRadius: '8px',
    padding: '0 18px',
    background: 'transparent',
    color: 'var(--w3a-colors-textMuted, rgba(255,255,255,0.75))',
    fontSize: '15px',
    fontWeight: '600',
    cursor: 'pointer',
  });
  cancel.addEventListener('click', args.onCancel);

  panel.append(title, button, cancel);
  container.appendChild(panel);
  document.body.appendChild(container);
  return container;
}

export function createNearWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REGISTER: async (req: Req<'PM_REGISTER'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, options, confirmationConfig } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;

      const hooksOptions = withProgress(
        deps,
        req.requestId,
        registrationOptionsWithoutActivation(options),
      ) as RegistrationHooksOptions;
      const result: RegistrationResult = await pm.registration.registerPasskey(nearAccountId, {
        ...hooksOptions,
        ...(confirmationConfig ? { confirmationConfig } : {}),
      });

      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_REGISTRATION_ACTIVATION_PREPARE: async (
      req: Req<'PM_REGISTRATION_ACTIVATION_PREPARE'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      if (Date.now() >= payload.expiresAtMs) {
        throw new Error('Registration activation expired');
      }

      removeRegistrationActivationRecord(payload.activationId);
      let startRegistration!: () => void;
      let rejectRegistration!: (error: Error) => void;
      const resultPromise = new Promise<RegistrationResult>((resolve, reject) => {
        rejectRegistration = reject;
        startRegistration = () => {
          void (async () => {
            const record = registrationActivationRecords.get(payload.activationId);
            if (!record || record.cancelled) {
              reject(new Error('Registration activation cancelled'));
              return;
            }
            if (record.started) return;
            if (Date.now() >= payload.expiresAtMs) {
              reject(new Error('Registration activation expired'));
              return;
            }
            record.started = true;
            deps.post({
              type: 'PM_REGISTRATION_ACTIVATION_STARTED',
              requestId: req.requestId,
              payload: { activationId: payload.activationId },
            });
            try {
              const hooksOptions = withProgress(
                deps,
                req.requestId,
                registrationOptionsWithoutActivation(payload.options),
              ) as RegistrationHooksOptions;
              const result = await pm.registration.registerPasskey(payload.nearAccountId, {
                ...hooksOptions,
                confirmationConfig: {
                  ...(payload.confirmationConfig || {}),
                  uiMode: 'none',
                  behavior: 'skipClick',
                  autoProceedDelay: 0,
                },
                walletIframeActivation: {
                  kind: 'wallet_iframe_registration_activation_v1',
                  activationId: payload.activationId,
                  activatedAtMs: Date.now(),
                },
              });
              resolve(result);
            } catch (error) {
              reject(error);
            }
          })();
        };
      });

      const expiryTimer = window.setTimeout(() => {
        const record = registrationActivationRecords.get(payload.activationId);
        if (!record || record.started) return;
        record.reject(new Error('Registration activation expired'));
        removeRegistrationActivationRecord(payload.activationId);
      }, Math.max(1, payload.expiresAtMs - Date.now()));

      const container = renderRegistrationActivationButton({
        payload,
        onStart: () => startRegistration(),
        onCancel: () => {
          const record = registrationActivationRecords.get(payload.activationId);
          if (record) record.cancelled = true;
          rejectRegistration(registrationActivationCancelledError());
          removeRegistrationActivationRecord(payload.activationId);
        },
      });
      registrationActivationRecords.set(payload.activationId, {
        activationId: payload.activationId,
        requestId: req.requestId,
        container,
        reject: rejectRegistration,
        cancelled: false,
        started: false,
      });
      deps.post({
        type: 'PM_REGISTRATION_ACTIVATION_READY',
        requestId: req.requestId,
        payload: { activationId: payload.activationId, expiresAtMs: payload.expiresAtMs },
      });

      try {
        const result = await resultPromise;
        if (deps.respondIfCancelled(req.requestId)) return;
        respondOkResult(deps, req.requestId, result);
      } finally {
        window.clearTimeout(expiryTimer);
        removeRegistrationActivationRecord(payload.activationId);
      }
    },

    PM_REGISTRATION_ACTIVATION_CANCEL: async (
      req: Req<'PM_REGISTRATION_ACTIVATION_CANCEL'>,
    ) => {
      const payload = req.payload!;
      const record = registrationActivationRecords.get(payload.activationId);
      if (record) {
        record.cancelled = true;
        record.reject(registrationActivationCancelledError());
        removeRegistrationActivationRecord(payload.activationId);
      }
      respondOk(deps, req.requestId);
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

    PM_SIGN_TX_WITH_ACTIONS: async (req: Req<'PM_SIGN_TX_WITH_ACTIONS'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, transaction, options } = req.payload!;
      const result = await pm.near.signTransactionWithActions({
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
      const { nearAccountId, transaction, options } = req.payload!;
      const result = await pm.near.signAndSendTransaction({
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
