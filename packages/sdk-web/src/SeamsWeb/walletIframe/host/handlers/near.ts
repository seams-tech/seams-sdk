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
  ActivatedPreparedIframePasskeyRegistration,
  PreparedIframePasskeyRegistration,
  RegistrationActivationWebAuthnPromptOwner,
} from '@/SeamsWeb/SeamsWeb';
import { activatePreparedIframePasskeyRegistration } from '@/SeamsWeb/SeamsWeb';
import {
  isRegistrationActivationButtonInteractionState,
  parseRegistrationActivationMessageIdentity,
  type PMExecuteActionPayload,
  type PMFundImplicitNearAccountForTestingPayload,
  type PMSendTxPayload,
  type RegistrationActivationButtonInteractionState,
  type PMRegistrationActivationPreparePayload,
} from '../../shared/messages';
import type {
  RegistrationActivationButtonPresentation,
  RegistrationActivationMessageIdentity,
} from '@/SeamsWeb/publicApi/types';
import {
  nearAccountRefFromAccountId,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { SEAMS_PASSKEY_REGISTRATION_BTN_ID } from '@/core/signingEngine/uiConfirm/ui/registry';
import { ensureExternalStyles } from '@/core/signingEngine/uiConfirm/ui/lit-components/css/css-loader';
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
import {
  webAuthnPromptCoordinator,
  type ReservedRegistrationWebAuthnPrompt,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
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

type RegistrationActivationDeferred = {
  promise: Promise<RegistrationResult>;
  resolve(result: RegistrationResult): void;
  reject(error: Error): void;
};

type RegistrationActivationRecordBase = {
  identity: RegistrationActivationMessageIdentity;
  deferred: RegistrationActivationDeferred;
  cancellation: { kind: 'abort_signal'; signal: AbortSignal };
  abortOperation(): void;
};

type RegistrationActivationRecord =
  | (RegistrationActivationRecordBase & {
      kind: 'preparing';
      container?: never;
      prepared?: never;
      reservation?: never;
      owner?: never;
      disposePrepared?: never;
    })
  | (RegistrationActivationRecordBase & {
      kind: 'ready';
      container: HTMLElement;
      prepared: PreparedIframePasskeyRegistration;
      reservation: ReservedRegistrationWebAuthnPrompt<RegistrationActivationWebAuthnPromptOwner>;
      owner: RegistrationActivationWebAuthnPromptOwner;
      disposePrepared(): void;
    })
  | (RegistrationActivationRecordBase & {
      kind: 'started';
      container?: never;
      prepared: PreparedIframePasskeyRegistration;
      reservation: ReservedRegistrationWebAuthnPrompt<RegistrationActivationWebAuthnPromptOwner>;
      owner: RegistrationActivationWebAuthnPromptOwner;
      disposePrepared(): void;
    });

type RegistrationActivationRecordWithContainer = Extract<
  RegistrationActivationRecord,
  { kind: 'ready' }
>;

type RegistrationActivationCancelErrorCode = 'cancelled' | 'registration_activation_expired';

type RegistrationActivationCancelError = Error & {
  code: RegistrationActivationCancelErrorCode;
};

type RegistrationActivationStartResult =
  | { kind: 'missing' }
  | { kind: 'already_started' }
  | { kind: 'expired'; record: RegistrationActivationRecord }
  | {
      kind: 'started';
      record: Extract<RegistrationActivationRecord, { kind: 'started' }>;
      activationContainer: HTMLElement;
    };

type RegistrationActivationRenderResult =
  | { kind: 'cancelled_during_render' }
  | { kind: 'ready'; record: Extract<RegistrationActivationRecord, { kind: 'ready' }> };

type RegistrationActivationFocusTarget =
  | { kind: 'available'; container: HTMLElement }
  | { kind: 'unavailable' };

const registrationActivationRecords = new Map<string, RegistrationActivationRecord>();
const REGISTRATION_ACTIVATION_START_EVENT = 'seams-registration-activation-start';
const REGISTRATION_ACTIVATION_STATE_EVENT = 'seams-registration-activation-state';
const REGISTRATION_ACTIVATION_FOCUS_EXIT_EVENT = 'seams-registration-activation-focus-exit';

function registrationActivationIdentitiesEqual(
  left: RegistrationActivationMessageIdentity,
  right: RegistrationActivationMessageIdentity,
): boolean {
  return (
    left.surfaceId === right.surfaceId &&
    left.activationId === right.activationId &&
    left.requestId === right.requestId
  );
}

function createRegistrationActivationDeferred(): RegistrationActivationDeferred {
  let resolveDeferred!: (result: RegistrationResult) => void;
  let rejectDeferred!: (error: Error) => void;
  const promise = new Promise<RegistrationResult>((resolve, reject) => {
    resolveDeferred = resolve;
    rejectDeferred = reject;
  });
  void promise.catch(() => undefined);
  return {
    promise,
    resolve: resolveDeferred,
    reject: rejectDeferred,
  };
}

function createPreparingRegistrationActivationRecord(args: {
  identity: RegistrationActivationMessageIdentity;
  deferred: RegistrationActivationDeferred;
  cancellation: { kind: 'abort_signal'; signal: AbortSignal };
  abortOperation(): void;
}): RegistrationActivationRecord {
  return {
    kind: 'preparing',
    identity: args.identity,
    deferred: args.deferred,
    cancellation: args.cancellation,
    abortOperation: args.abortOperation,
  };
}

function registrationActivationRecordWithContainer(
  record: RegistrationActivationRecord,
): RegistrationActivationRecordWithContainer | null {
  switch (record.kind) {
    case 'ready':
      return record;
    case 'started':
    case 'preparing':
      return null;
  }
}

function createReadyRegistrationActivationRecord(args: {
  record: RegistrationActivationRecord;
  container: HTMLElement;
  prepared: PreparedIframePasskeyRegistration;
  reservation: ReservedRegistrationWebAuthnPrompt<RegistrationActivationWebAuthnPromptOwner>;
  owner: RegistrationActivationWebAuthnPromptOwner;
  disposePrepared(): void;
}): Extract<RegistrationActivationRecord, { kind: 'ready' }> {
  return {
    kind: 'ready',
    identity: args.record.identity,
    deferred: args.record.deferred,
    cancellation: args.record.cancellation,
    abortOperation: args.record.abortOperation,
    container: args.container,
    prepared: args.prepared,
    reservation: args.reservation,
    owner: args.owner,
    disposePrepared: args.disposePrepared,
  };
}

function createStartedRegistrationActivationRecord(
  record: Extract<RegistrationActivationRecord, { kind: 'ready' }>,
): Extract<RegistrationActivationRecord, { kind: 'started' }> {
  return {
    kind: 'started',
    identity: record.identity,
    deferred: record.deferred,
    cancellation: record.cancellation,
    abortOperation: record.abortOperation,
    prepared: record.prepared,
    reservation: record.reservation,
    owner: record.owner,
    disposePrepared: record.disposePrepared,
  };
}

function markRegistrationActivationReady(args: {
  activationId: string;
  container: HTMLElement;
  prepared: PreparedIframePasskeyRegistration;
  reservation: ReservedRegistrationWebAuthnPrompt<RegistrationActivationWebAuthnPromptOwner>;
  owner: RegistrationActivationWebAuthnPromptOwner;
  disposePrepared(): void;
}): RegistrationActivationRenderResult {
  const record = registrationActivationRecords.get(args.activationId);
  if (!record) {
    args.container.remove();
    return { kind: 'cancelled_during_render' };
  }
  const readyRecord = createReadyRegistrationActivationRecord({
    record,
    container: args.container,
    prepared: args.prepared,
    reservation: args.reservation,
    owner: args.owner,
    disposePrepared: args.disposePrepared,
  });
  registrationActivationRecords.set(args.activationId, readyRecord);
  return { kind: 'ready', record: readyRecord };
}

function markRegistrationActivationStarted(args: {
  identity: RegistrationActivationMessageIdentity;
  expiresAtMs: number;
}): RegistrationActivationStartResult {
  const record = registrationActivationRecords.get(args.identity.activationId);
  if (!record) return { kind: 'missing' };
  if (!registrationActivationIdentitiesEqual(record.identity, args.identity)) {
    return { kind: 'missing' };
  }
  switch (record.kind) {
    case 'preparing':
      return { kind: 'missing' };
    case 'started':
      return { kind: 'already_started' };
    case 'ready': {
      if (Date.now() >= args.expiresAtMs) return { kind: 'expired', record };
      const startedRecord = createStartedRegistrationActivationRecord(record);
      registrationActivationRecords.set(args.identity.activationId, startedRecord);
      return { kind: 'started', record: startedRecord, activationContainer: record.container };
    }
  }
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
  record?.abortOperation();
  if (record?.kind === 'ready') {
    webAuthnPromptCoordinator.releaseReservation(record.reservation);
    record.disposePrepared();
  }
  const recordWithContainer = record ? registrationActivationRecordWithContainer(record) : null;
  try {
    recordWithContainer?.container.remove();
  } catch {}
}

function registrationActivationCancelledError(): RegistrationActivationCancelError {
  const error = new Error('Registration activation cancelled') as RegistrationActivationCancelError;
  error.code = 'cancelled';
  return error;
}

function registrationActivationExpiredError(): RegistrationActivationCancelError {
  const error = new Error('Registration activation expired') as RegistrationActivationCancelError;
  error.code = 'registration_activation_expired';
  return error;
}

function throwIfRegistrationActivationCancelled(signal: AbortSignal): void {
  if (signal.aborted) throw registrationActivationCancelledError();
}

function rejectRegistrationActivationRecord(
  record: RegistrationActivationRecord,
  error: Error,
): void {
  record.deferred.reject(error);
}

function registrationActivationFocusTarget(
  identity: RegistrationActivationMessageIdentity,
): RegistrationActivationFocusTarget {
  const record = registrationActivationRecords.get(identity.activationId);
  if (!record || !registrationActivationIdentitiesEqual(record.identity, identity)) {
    return { kind: 'unavailable' };
  }
  const recordWithContainer = registrationActivationRecordWithContainer(record);
  if (!recordWithContainer) return { kind: 'unavailable' };
  return { kind: 'available', container: recordWithContainer.container };
}

type RegistrationActivationButtonElement = HTMLElement & {
  activationId?: string;
  label?: string;
  busyLabel?: string;
  accessibleLabel?: string;
  focusButton?(): void;
  activationReady?(): Promise<void>;
};

function normalizeRequiredPresentationString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Invalid registration activation presentation: ${field} is required`);
  }
  return value.trim();
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
  if (record.kind !== 'outline_overlay') {
    throw new Error('Invalid registration activation presentation kind');
  }
  for (const forbiddenField of ['iframeButtonStyle', 'iframeVisualStyle', 'shadowPaddingPx']) {
    if (record[forbiddenField] !== undefined) {
      throw new Error(
        `Invalid registration activation presentation: ${forbiddenField} is not allowed`,
      );
    }
  }
  return { kind: 'outline_overlay', label, busyLabel, accessibleLabel };
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
  identity: RegistrationActivationMessageIdentity;
  state: RegistrationActivationButtonInteractionState;
}): void {
  args.deps.post({
    type: 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE',
    requestId: args.identity.requestId,
    payload: {
      ...args.identity,
      state: args.state,
    },
  });
}

function postRegistrationActivationFocusExit(args: {
  deps: HandlerDeps;
  identity: RegistrationActivationMessageIdentity;
  direction: 'forward' | 'backward';
}): void {
  args.deps.post({
    type: 'PM_REGISTRATION_ACTIVATION_FOCUS_EXIT',
    requestId: args.identity.requestId,
    payload: {
      ...args.identity,
      direction: args.direction,
    },
  });
}

function configureRegistrationActivationElement(args: {
  element: RegistrationActivationButtonElement;
  payload: PMRegistrationActivationPreparePayload;
  presentation: RegistrationActivationButtonPresentation;
  onStart(): void;
  onState(state: RegistrationActivationButtonInteractionState): void;
  onFocusExit(direction: 'forward' | 'backward'): void;
}): void {
  args.element.activationId = args.payload.activationId;
  args.element.label = args.presentation.label;
  args.element.busyLabel = args.presentation.busyLabel;
  args.element.accessibleLabel = args.presentation.accessibleLabel;
  args.element.addEventListener(REGISTRATION_ACTIVATION_START_EVENT, args.onStart, { once: true });
  args.element.addEventListener(REGISTRATION_ACTIVATION_STATE_EVENT, (event) => {
    const state = (event as CustomEvent<unknown>).detail;
    if (!isRegistrationActivationButtonInteractionState(state)) return;
    args.onState(state);
  });
  args.element.addEventListener(REGISTRATION_ACTIVATION_FOCUS_EXIT_EVENT, (event) => {
    const direction = (event as CustomEvent<{ direction?: unknown }>).detail?.direction;
    if (direction !== 'forward' && direction !== 'backward') return;
    args.onFocusExit(direction);
  });
}

async function renderFallbackRegistrationActivationButton(args: {
  payload: PMRegistrationActivationPreparePayload;
  presentation: RegistrationActivationButtonPresentation;
  cancellation: { kind: 'abort_signal'; signal: AbortSignal };
  onStart(): void;
  onFocusExit(direction: 'forward' | 'backward'): void;
}): Promise<HTMLElement> {
  throwIfRegistrationActivationCancelled(args.cancellation.signal);
  const container = document.createElement('section');
  container.setAttribute('data-seams-registration-activation-id', args.payload.activationId);
  container.className = 'seams-passkey-registration-surface';

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'seams-passkey-registration-fallback__button';
  button.setAttribute('data-seams-registration-activation-start', 'true');
  button.setAttribute('aria-label', args.presentation.accessibleLabel);
  button.textContent = args.presentation.label;
  button.addEventListener('click', () => {
    button.disabled = true;
    button.textContent = args.presentation.busyLabel;
    args.onStart();
  });
  button.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    event.preventDefault();
    args.onFocusExit(event.shiftKey ? 'backward' : 'forward');
  });
  container.appendChild(button);
  await ensureExternalStyles(
    container,
    'seams-passkey-registration-btn.css',
    'data-seams-passkey-registration-btn-css',
  );
  throwIfRegistrationActivationCancelled(args.cancellation.signal);
  document.body.appendChild(container);
  return container;
}

async function renderRegistrationActivationButton(args: {
  payload: PMRegistrationActivationPreparePayload;
  presentation: RegistrationActivationButtonPresentation;
  cancellation: { kind: 'abort_signal'; signal: AbortSignal };
  onStart(): void;
  onState(state: RegistrationActivationButtonInteractionState): void;
  onFocusExit(direction: 'forward' | 'backward'): void;
}): Promise<HTMLElement> {
  if (typeof customElements === 'undefined') {
    return renderFallbackRegistrationActivationButton(args);
  }
  await ensureRegistrationActivationButtonElementDefined();
  throwIfRegistrationActivationCancelled(args.cancellation.signal);
  const container = document.createElement('section');
  container.setAttribute('data-seams-registration-activation-id', args.payload.activationId);
  container.className = 'seams-passkey-registration-surface';
  const element = document.createElement(
    SEAMS_PASSKEY_REGISTRATION_BTN_ID,
  ) as RegistrationActivationButtonElement;
  configureRegistrationActivationElement({ ...args, element });
  container.appendChild(element);
  document.body.appendChild(container);
  if (!element.activationReady) {
    container.remove();
    throw new Error('Passkey registration activation element has no readiness contract');
  }
  try {
    await element.activationReady();
    throwIfRegistrationActivationCancelled(args.cancellation.signal);
    return container;
  } catch (error) {
    container.remove();
    throw error;
  }
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

function startRegistrationActivation(args: {
  pm: ReturnType<HandlerDeps['getSeamsWeb']>;
  deps: HandlerDeps;
  payload: PMRegistrationActivationPreparePayload;
}): void {
  const startResult = markRegistrationActivationStarted({
    identity: args.payload,
    expiresAtMs: args.payload.expiresAtMs,
  });
  switch (startResult.kind) {
    case 'missing':
    case 'already_started':
      return;
    case 'expired':
      rejectRegistrationActivationRecord(startResult.record, registrationActivationExpiredError());
      removeRegistrationActivationRecord(args.payload.activationId);
      return;
    case 'started': {
      args.deps.post({
        type: 'PM_REGISTRATION_ACTIVATION_STARTED',
        requestId: args.payload.requestId,
        payload: {
          surfaceId: args.payload.surfaceId,
          activationId: args.payload.activationId,
          requestId: args.payload.requestId,
        },
      });
      let activated: ActivatedPreparedIframePasskeyRegistration;
      try {
        activated = activatePreparedIframePasskeyRegistration({
          prepared: startResult.record.prepared,
          identity: startResult.record.identity,
          reservation: startResult.record.reservation,
          cancellation: startResult.record.cancellation,
          activatedAtMs: Date.now(),
        });
      } catch (error) {
        webAuthnPromptCoordinator.releaseReservation(startResult.record.reservation);
        args.pm.disposePreparedIframePasskeyRegistration(startResult.record.prepared);
        startResult.record.deferred.reject(
          error instanceof Error ? error : new Error(String(error)),
        );
        startResult.activationContainer.remove();
        return;
      }
      let registration: Promise<RegistrationResult>;
      try {
        registration = args.pm.continuePreparedIframePasskeyRegistration(activated);
      } catch (error) {
        webAuthnPromptCoordinator.releaseReservation(startResult.record.reservation);
        args.pm.disposePreparedIframePasskeyRegistration(startResult.record.prepared);
        startResult.record.deferred.reject(
          error instanceof Error ? error : new Error(String(error)),
        );
        startResult.activationContainer.remove();
        return;
      }
      startResult.activationContainer.remove();
      void registration.then(
        startResult.record.deferred.resolve,
        startResult.record.deferred.reject,
      );
      return;
    }
  }
}

function expireRegistrationActivationBeforeStart(activationId: string): void {
  const record = registrationActivationRecords.get(activationId);
  if (!record || record.kind === 'started') return;
  rejectRegistrationActivationRecord(record, registrationActivationExpiredError());
  removeRegistrationActivationRecord(activationId);
}

export function createNearWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REGISTRATION_ACTIVATION_PREPARE: async (req: Req<'PM_REGISTRATION_ACTIVATION_PREPARE'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload!;
      const identity = parseRegistrationActivationMessageIdentity(payload);
      if (!identity || req.requestId !== identity.requestId) {
        throw new Error('Registration activation identity is invalid');
      }
      if (deps.respondIfCancelled(req.requestId)) return;
      if (Date.now() >= payload.expiresAtMs) {
        throw new Error('Registration activation expired');
      }
      const wallet = parseRegistrationActivationProvidedWallet(payload);
      const presentation = normalizeRegistrationActivationPresentation(payload.presentation);

      removeRegistrationActivationRecord(payload.activationId);
      const deferred = createRegistrationActivationDeferred();
      const preparationAbortController = new AbortController();
      registrationActivationRecords.set(
        payload.activationId,
        createPreparingRegistrationActivationRecord({
          identity,
          deferred,
          cancellation: { kind: 'abort_signal', signal: preparationAbortController.signal },
          abortOperation: preparationAbortController.abort.bind(preparationAbortController),
        }),
      );

      const expiryTimer = window.setTimeout(
        () => expireRegistrationActivationBeforeStart(payload.activationId),
        Math.max(1, payload.expiresAtMs - Date.now()),
      );
      let prepared: PreparedIframePasskeyRegistration | null = null;
      let reservation: ReservedRegistrationWebAuthnPrompt<RegistrationActivationWebAuthnPromptOwner> | null =
        null;

      try {
        const hooksOptions = withProgress(deps, payload.requestId, {}) as RegistrationHooksOptions;
        prepared = await pm.prepareIframePasskeyRegistration({
          wallet,
          options: hooksOptions,
          expiresAtMs: payload.expiresAtMs,
        });
        const owner: RegistrationActivationWebAuthnPromptOwner = {
          kind: 'registration_activation',
          identity,
        };
        reservation = await webAuthnPromptCoordinator.reserveRegistrationPrompt({
          owner,
          expiresAtMs: payload.expiresAtMs,
          cancellation: {
            kind: 'abort_signal',
            signal: preparationAbortController.signal,
          },
        });
        const container = await renderRegistrationActivationButton({
          payload,
          presentation,
          cancellation: {
            kind: 'abort_signal',
            signal: preparationAbortController.signal,
          },
          onStart: () =>
            startRegistrationActivation({
              pm,
              deps,
              payload,
            }),
          onState: (state) =>
            postRegistrationActivationButtonState({
              deps,
              identity,
              state,
            }),
          onFocusExit: (direction) =>
            postRegistrationActivationFocusExit({
              deps,
              identity,
              direction,
            }),
        });
        if (!webAuthnPromptCoordinator.isLiveReservation({ reservation, owner })) {
          container.remove();
          throw new Error('Registration activation WebAuthn reservation expired before ready');
        }
        const renderResult = markRegistrationActivationReady({
          activationId: payload.activationId,
          container,
          prepared,
          reservation,
          owner,
          disposePrepared: pm.disposePreparedIframePasskeyRegistration.bind(pm, prepared),
        });
        if (renderResult.kind === 'ready') {
          deps.post({
            type: 'PM_REGISTRATION_ACTIVATION_READY',
            requestId: identity.requestId,
            payload: { ...identity, expiresAtMs: payload.expiresAtMs },
          });
        }

        const result = await deferred.promise;
        if (deps.respondIfCancelled(req.requestId)) return;
        respondOkResult(deps, req.requestId, result);
      } finally {
        window.clearTimeout(expiryTimer);
        const activeRecord = registrationActivationRecords.get(payload.activationId);
        if (!activeRecord || activeRecord.kind === 'preparing') {
          if (reservation) webAuthnPromptCoordinator.releaseReservation(reservation);
          if (prepared) pm.disposePreparedIframePasskeyRegistration(prepared);
        }
        removeRegistrationActivationRecord(payload.activationId);
      }
    },

    PM_REGISTRATION_ACTIVATION_CANCEL: async (req: Req<'PM_REGISTRATION_ACTIVATION_CANCEL'>) => {
      const payload = req.payload!;
      const identity = parseRegistrationActivationMessageIdentity(payload);
      if (!identity) {
        throw new Error('Registration activation cancellation identity is invalid');
      }
      const record = registrationActivationRecords.get(payload.activationId);
      if (record && registrationActivationIdentitiesEqual(record.identity, identity)) {
        rejectRegistrationActivationRecord(record, registrationActivationCancelledError());
        removeRegistrationActivationRecord(payload.activationId);
      }
      respondOk(deps, req.requestId);
    },

    PM_REGISTRATION_ACTIVATION_FOCUS: async (req: Req<'PM_REGISTRATION_ACTIVATION_FOCUS'>) => {
      const payload = req.payload!;
      const identity = parseRegistrationActivationMessageIdentity(payload);
      if (!identity) {
        throw new Error('Registration activation focus identity is invalid');
      }
      const focusTarget = registrationActivationFocusTarget(identity);
      if (focusTarget.kind === 'available') {
        focusRegistrationActivationButton(focusTarget.container);
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
