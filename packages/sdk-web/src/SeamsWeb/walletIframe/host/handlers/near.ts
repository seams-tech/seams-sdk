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
import {
  isRegistrationActivationButtonInteractionState,
  type PMExecuteActionPayload,
  type PMSendTxPayload,
  type RegistrationActivationButtonInteractionState,
  type PMRegistrationActivationPreparePayload,
} from '../../shared/messages';
import type {
  RegistrationActivationButtonCss,
  RegistrationActivationButtonCssProperty,
  RegistrationActivationButtonPresentation,
} from '@/SeamsWeb/publicApi/types';
import {
  nearAccountRefFromAccountId,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { SEAMS_PASSKEY_REGISTRATION_BTN_ID } from '@/core/signingEngine/uiConfirm/ui/registry';
import type { NonceLeaseRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  extractBorshBytesFromPlainSignedTx,
  isObject,
  isPlainObject,
  isPlainSignedTransactionLike,
  type PlainSignedTransactionLike,
} from '@shared/utils/validation';
import { type RegisterWalletInput, walletIdFromString } from '@shared/utils/registrationIntent';
import type { ActionArgs } from '@/core/types';
import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';

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

type RegistrationActivationRecord = {
  activationId: string;
  requestId: string | undefined;
  container: HTMLElement;
  reject(error: Error): void;
  cancelled: boolean;
  started: boolean;
};

const registrationActivationRecords = new Map<string, RegistrationActivationRecord>();
const REGISTRATION_ACTIVATION_START_EVENT = 'seams-registration-activation-start';
const REGISTRATION_ACTIVATION_STATE_EVENT = 'seams-registration-activation-state';
const ALLOWED_REGISTRATION_BUTTON_CSS_PROPERTIES = new Set<RegistrationActivationButtonCssProperty>(
  [
    'width',
    'height',
    'minWidth',
    'minHeight',
    'maxWidth',
    'maxHeight',
    'padding',
    'border',
    'borderColor',
    'borderRadius',
    'background',
    'backgroundColor',
    'color',
    'boxShadow',
    'fontFamily',
    'fontSize',
    'fontWeight',
    'lineHeight',
    'letterSpacing',
    'textAlign',
    'cursor',
    'outline',
    'outlineColor',
    'outlineOffset',
    'outlineWidth',
  ],
);

function registrationOptionsWithoutActivation(options: unknown): Record<string, unknown> {
  const out = isObject(options) ? { ...(options as Record<string, unknown>) } : {};
  delete out.walletIframeActivation;
  return out;
}

function parseRegistrationActivationProvidedWallet(
  payload: PMRegistrationActivationPreparePayload,
): Extract<RegisterWalletInput, { kind: 'provided' }> {
  const wallet = payload.wallet;
  if (!isPlainObject(wallet)) {
    throw new Error('Registration activation requires a provided wallet');
  }
  if (wallet.kind !== 'provided') {
    throw new Error('Registration activation requires a provided wallet');
  }
  const walletIdRaw = wallet.walletId;
  if (typeof walletIdRaw !== 'string') {
    throw new Error('Registration activation walletId is invalid');
  }
  return {
    kind: 'provided',
    walletId: walletIdFromString(walletIdRaw.trim()),
  };
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

type RegistrationActivationButtonElement = HTMLElement & {
  activationId?: string;
  label?: string;
  busyLabel?: string;
  accessibleLabel?: string;
  mode?: RegistrationActivationButtonPresentation['kind'];
  buttonStyle?: RegistrationActivationButtonCss;
  shadowPaddingPx?: number;
  focusButton?(): void;
};

function normalizeRequiredPresentationString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Invalid registration activation presentation: ${field} is required`);
  }
  return value.trim();
}

function rejectRegistrationActivationPresentationFields(
  record: Record<string, unknown>,
  kind: RegistrationActivationButtonPresentation['kind'],
  fields: readonly string[],
): void {
  for (const field of fields) {
    if (record[field] === undefined) continue;
    throw new Error(
      `Invalid registration activation presentation: ${field} is not allowed for ${kind}`,
    );
  }
}

function normalizeRegistrationButtonCss(
  input: unknown,
  field: string,
): RegistrationActivationButtonCss {
  if (input === undefined) return {};
  if (!isObject(input)) {
    throw new Error(`Invalid registration activation presentation: ${field} must be an object`);
  }
  const normalized: RegistrationActivationButtonCss = {};
  for (const [property, value] of Object.entries(input)) {
    if (
      !ALLOWED_REGISTRATION_BUTTON_CSS_PROPERTIES.has(
        property as RegistrationActivationButtonCssProperty,
      )
    ) {
      throw new Error(
        `Invalid registration activation presentation: unsupported CSS property ${property}`,
      );
    }
    if (typeof value !== 'string') {
      throw new Error(
        `Invalid registration activation presentation: CSS property ${property} must be a string`,
      );
    }
    if (/\burl\s*\(/i.test(value)) {
      throw new Error(
        `Invalid registration activation presentation: CSS property ${property} cannot use url(...)`,
      );
    }
    normalized[property as RegistrationActivationButtonCssProperty] = value;
  }
  return normalized;
}

function normalizeRequiredRegistrationButtonCss(
  input: unknown,
  field: string,
): RegistrationActivationButtonCss {
  if (input === undefined) {
    throw new Error(`Invalid registration activation presentation: ${field} is required`);
  }
  return normalizeRegistrationButtonCss(input, field);
}

function normalizeRegistrationActivationShadowPaddingPx(input: unknown): number {
  if (typeof input !== 'number' || !Number.isFinite(input) || input < 0) {
    throw new Error(
      'Invalid registration activation presentation: shadowPaddingPx must be a non-negative number',
    );
  }
  return input;
}

function normalizeRegistrationActivationPresentation(
  input: unknown,
): RegistrationActivationButtonPresentation {
  if (!isObject(input)) {
    throw new Error('Invalid registration activation presentation');
  }
  const record = input as Record<string, unknown>;
  const label = normalizeRequiredPresentationString(record.label, 'label');
  const busyLabel = normalizeRequiredPresentationString(record.busyLabel, 'busyLabel');
  const accessibleLabel = normalizeRequiredPresentationString(
    record.accessibleLabel,
    'accessibleLabel',
  );
  switch (record.kind) {
    case 'outline_overlay':
      rejectRegistrationActivationPresentationFields(record, 'outline_overlay', [
        'iframeVisualStyle',
        'shadowPaddingPx',
      ]);
      return {
        kind: 'outline_overlay',
        label,
        busyLabel,
        accessibleLabel,
        iframeButtonStyle: normalizeRegistrationButtonCss(
          record.iframeButtonStyle,
          'iframeButtonStyle',
        ),
      };
    case 'iframe_button':
      rejectRegistrationActivationPresentationFields(record, 'iframe_button', [
        'iframeButtonStyle',
      ]);
      return {
        kind: 'iframe_button',
        label,
        busyLabel,
        accessibleLabel,
        iframeVisualStyle: normalizeRequiredRegistrationButtonCss(
          record.iframeVisualStyle,
          'iframeVisualStyle',
        ),
        shadowPaddingPx: normalizeRegistrationActivationShadowPaddingPx(record.shadowPaddingPx),
      };
    default:
      throw new Error('Invalid registration activation presentation kind');
  }
}

function registrationButtonStyleForPresentation(
  presentation: RegistrationActivationButtonPresentation,
): RegistrationActivationButtonCss {
  switch (presentation.kind) {
    case 'outline_overlay':
      return presentation.iframeButtonStyle ?? {};
    case 'iframe_button':
      return presentation.iframeVisualStyle;
  }
}

function cssPropertyName(property: string): string {
  return property.replace(/[A-Z]/g, (match) => `-${match.toLowerCase()}`);
}

function applyRegistrationButtonStyle(args: {
  button: HTMLElement;
  style: RegistrationActivationButtonCss;
}): void {
  for (const [property, value] of Object.entries(args.style)) {
    if (typeof value !== 'string') continue;
    const styleDeclaration = args.button.style as CSSStyleDeclaration & Record<string, string>;
    if (typeof styleDeclaration.setProperty === 'function') {
      styleDeclaration.setProperty(cssPropertyName(property), value);
    } else {
      styleDeclaration[property] = value;
    }
  }
}

function applyFallbackRegistrationButtonInset(args: {
  button: HTMLElement;
  presentation: RegistrationActivationButtonPresentation;
}): void {
  const shadowPaddingPx =
    args.presentation.kind === 'iframe_button' ? args.presentation.shadowPaddingPx : 0;
  args.button.style.margin = `${shadowPaddingPx}px`;
  args.button.style.width = shadowPaddingPx > 0 ? `calc(100% - ${shadowPaddingPx * 2}px)` : '100%';
  args.button.style.height = shadowPaddingPx > 0 ? `calc(100% - ${shadowPaddingPx * 2}px)` : '100%';
}

async function ensureRegistrationActivationButtonElementDefined(): Promise<void> {
  if (typeof customElements === 'undefined') return;
  if (!customElements.get(SEAMS_PASSKEY_REGISTRATION_BTN_ID)) {
    await import('@/core/signingEngine/uiConfirm/ui/lit-components/passkey-registration-btn/entrypoints/seams-passkey-registration-btn');
  }
  await customElements.whenDefined(SEAMS_PASSKEY_REGISTRATION_BTN_ID);
}

function postRegistrationActivationButtonState(args: {
  deps: HandlerDeps;
  requestId: string | undefined;
  activationId: string;
  state: RegistrationActivationButtonInteractionState;
}): void {
  args.deps.post({
    type: 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE',
    requestId: args.requestId,
    payload: {
      activationId: args.activationId,
      state: args.state,
    },
  });
}

function configureRegistrationActivationElement(args: {
  element: RegistrationActivationButtonElement;
  payload: PMRegistrationActivationPreparePayload;
  presentation: RegistrationActivationButtonPresentation;
  onStart(): void;
  onState(state: RegistrationActivationButtonInteractionState): void;
}): void {
  args.element.activationId = args.payload.activationId;
  args.element.label = args.presentation.label;
  args.element.busyLabel = args.presentation.busyLabel;
  args.element.accessibleLabel = args.presentation.accessibleLabel;
  args.element.mode = args.presentation.kind;
  args.element.buttonStyle = registrationButtonStyleForPresentation(args.presentation);
  args.element.shadowPaddingPx =
    args.presentation.kind === 'iframe_button' ? args.presentation.shadowPaddingPx : 0;
  args.element.addEventListener(REGISTRATION_ACTIVATION_START_EVENT, args.onStart, { once: true });
  args.element.addEventListener(REGISTRATION_ACTIVATION_STATE_EVENT, (event) => {
    const state = (event as CustomEvent<unknown>).detail;
    if (!isRegistrationActivationButtonInteractionState(state)) return;
    args.onState(state);
  });
}

function renderFallbackRegistrationActivationButton(args: {
  payload: PMRegistrationActivationPreparePayload;
  presentation: RegistrationActivationButtonPresentation;
  onStart(): void;
}): HTMLElement {
  const container = document.createElement('section');
  container.setAttribute('data-seams-registration-activation-id', args.payload.activationId);
  Object.assign(container.style, {
    width: '100%',
    height: '100%',
    boxSizing: 'border-box',
    background: 'transparent',
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  });

  const button = document.createElement('button');
  button.type = 'button';
  button.setAttribute('data-seams-registration-activation-start', 'true');
  button.setAttribute('aria-label', args.presentation.accessibleLabel);
  button.textContent = args.presentation.label;
  Object.assign(button.style, {
    width: '100%',
    height: '100%',
    minHeight: '0',
    border: '0',
    padding: '0',
    background: 'transparent',
    color: 'transparent',
    cursor: 'pointer',
  });
  applyRegistrationButtonStyle({
    button,
    style: registrationButtonStyleForPresentation(args.presentation),
  });
  applyFallbackRegistrationButtonInset({ button, presentation: args.presentation });
  button.addEventListener('click', () => {
    button.disabled = true;
    button.textContent = args.presentation.busyLabel;
    button.style.cursor = 'default';
    args.onStart();
  });
  container.appendChild(button);
  document.body.appendChild(container);
  return container;
}

async function renderRegistrationActivationButton(args: {
  payload: PMRegistrationActivationPreparePayload;
  presentation: RegistrationActivationButtonPresentation;
  onStart(): void;
  onState(state: RegistrationActivationButtonInteractionState): void;
}): Promise<HTMLElement> {
  if (typeof customElements === 'undefined') {
    return renderFallbackRegistrationActivationButton(args);
  }
  await ensureRegistrationActivationButtonElementDefined();
  const container = document.createElement('section');
  container.setAttribute('data-seams-registration-activation-id', args.payload.activationId);
  Object.assign(container.style, {
    width: '100%',
    height: '100%',
    boxSizing: 'border-box',
    background: 'transparent',
  });
  const element = document.createElement(
    SEAMS_PASSKEY_REGISTRATION_BTN_ID,
  ) as RegistrationActivationButtonElement;
  configureRegistrationActivationElement({ ...args, element });
  container.appendChild(element);
  document.body.appendChild(container);
  return container;
}

function focusRegistrationActivationButton(container: HTMLElement): void {
  const element = container.querySelector(
    SEAMS_PASSKEY_REGISTRATION_BTN_ID,
  ) as RegistrationActivationButtonElement | null;
  if (element?.focusButton) {
    element.focusButton();
    return;
  }
  const fallback = container.querySelector(
    '[data-seams-registration-activation-start="true"]',
  ) as HTMLElement | null;
  fallback?.focus?.({ preventScroll: true });
}

export function createNearWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REGISTRATION_ACTIVATION_PREPARE: async (req: Req<'PM_REGISTRATION_ACTIVATION_PREPARE'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      if (Date.now() >= payload.expiresAtMs) {
        throw new Error('Registration activation expired');
      }
      const wallet = parseRegistrationActivationProvidedWallet(payload);
      const presentation = normalizeRegistrationActivationPresentation(payload.presentation);

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
              const result = await pm.registration.registerPasskey({
                wallet,
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

      const expiryTimer = window.setTimeout(
        () => {
          const record = registrationActivationRecords.get(payload.activationId);
          if (!record || record.started) return;
          record.reject(new Error('Registration activation expired'));
          removeRegistrationActivationRecord(payload.activationId);
        },
        Math.max(1, payload.expiresAtMs - Date.now()),
      );

      const container = await renderRegistrationActivationButton({
        payload,
        presentation,
        onStart: () => startRegistration(),
        onState: (state) =>
          postRegistrationActivationButtonState({
            deps,
            requestId: req.requestId,
            activationId: payload.activationId,
            state,
          }),
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

    PM_REGISTRATION_ACTIVATION_CANCEL: async (req: Req<'PM_REGISTRATION_ACTIVATION_CANCEL'>) => {
      const payload = req.payload!;
      const record = registrationActivationRecords.get(payload.activationId);
      if (record) {
        record.cancelled = true;
        record.reject(registrationActivationCancelledError());
        removeRegistrationActivationRecord(payload.activationId);
      }
      respondOk(deps, req.requestId);
    },

    PM_REGISTRATION_ACTIVATION_FOCUS: async (req: Req<'PM_REGISTRATION_ACTIVATION_FOCUS'>) => {
      const payload = req.payload!;
      const record = registrationActivationRecords.get(payload.activationId);
      if (record) {
        focusRegistrationActivationButton(record.container);
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
