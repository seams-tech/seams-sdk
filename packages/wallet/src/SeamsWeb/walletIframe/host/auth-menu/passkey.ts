import type { LoginAndCreateSessionResult } from '@/core/types/seams';
import type { LoginHooksOptions, SyncAccountHooksOptions } from '@/core/types/sdkSentEvents';
import { UnlockEventPhase } from '@/core/types/sdkSentEvents';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type {
  AccountSyncSigningSurface,
  LoginUnlockSigningSurface,
  SeamsWebBaseContext,
} from '@/SeamsWeb/signingSurface/ports';
import {
  resolveLinkedDevicePasskeyAuthoritySelection,
  resolveLinkedDeviceUnlockSubjectSet,
  unlockLinkedDevicePasskey,
  unlockResolvedWalletSubjectSet,
  type LinkedDevicePasskeyAuthoritySelection,
} from '@/SeamsWeb/operations/auth/login';
import { clearHostedWalletSessions } from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import {
  resolveWalletUnlockSubjectSet,
  type WalletUnlockSubjectSet,
} from '@/SeamsWeb/operations/auth/walletUnlockSubject';
import {
  prepareSyncAccountChallenge,
  syncAccountWithPreparedCredential,
  type PreparedSyncAccountChallenge,
} from '@/SeamsWeb/operations/recovery/syncAccount';
import type { SyncAccountResult } from '@/core/types/sdkPublicResults';
import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import type { HostedAuthMenuSessionId } from '../../shared/messages';
import type { WalletIframeRequestId } from '@/core/types/walletIframeIdentity';
import type { WebAuthnPromptCancellation } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';

const hostedPasskeyLoginPreparedBrand: unique symbol = Symbol('hostedPasskeyLoginPrepared');
const hostedPasskeyAccountSyncPreparedBrand: unique symbol = Symbol(
  'hostedPasskeyAccountSyncPrepared',
);

const HOSTED_PASSKEY_PREPARATION_TTL_MS = 5 * 60 * 1000;

type HostedPasskeyPreparationCancellation = Extract<
  WebAuthnPromptCancellation,
  { kind: 'abort_signal' }
>;

type HostedPasskeySigningSurface = LoginUnlockSigningSurface & AccountSyncSigningSurface;

export type HostedPasskeyContext = SeamsWebBaseContext<HostedPasskeySigningSurface>;
export type HostedPasskeyContextInput = Pick<
  HostedPasskeyContext,
  'signingEngine' | 'nearClient' | 'configs' | 'theme'
>;

export function createHostedPasskeyContext(input: HostedPasskeyContextInput): HostedPasskeyContext {
  return {
    signingEngine: input.signingEngine,
    nearClient: input.nearClient,
    configs: input.configs,
    theme: input.theme,
  };
}

type HostedPasskeyLoginPreparedBase = Readonly<{
  readonly authMenuSessionId: HostedAuthMenuSessionId;
  readonly requestId: WalletIframeRequestId;
  readonly walletId: WalletId;
  readonly expiresAtMs: number;
  readonly cancellation: HostedPasskeyPreparationCancellation;
  readonly [hostedPasskeyLoginPreparedBrand]: true;
}>;

export type HostedPasskeyLoginPrepared =
  | (HostedPasskeyLoginPreparedBase & {
      readonly kind: 'hosted_passkey_owner_login_prepared_v1';
      readonly subjectSet: WalletUnlockSubjectSet;
      readonly selection?: never;
    })
  | (HostedPasskeyLoginPreparedBase & {
      readonly kind: 'hosted_passkey_linked_authority_login_prepared_v1';
      readonly selection: LinkedDevicePasskeyAuthoritySelection;
      readonly subjectSet?: never;
    });

export type HostedPasskeyAccountSyncPrepared = Readonly<{
  readonly kind: 'hosted_passkey_account_sync_prepared_v1';
  readonly authMenuSessionId: HostedAuthMenuSessionId;
  readonly requestId: WalletIframeRequestId;
  readonly challenge: PreparedSyncAccountChallenge;
  readonly expiresAtMs: number;
  readonly cancellation: HostedPasskeyPreparationCancellation;
  readonly [hostedPasskeyAccountSyncPreparedBrand]: true;
}>;

export type HostedPasskeyPrepared = HostedPasskeyLoginPrepared | HostedPasskeyAccountSyncPrepared;

type HostedPasskeyPreparationState = {
  readonly context: HostedPasskeyContext;
  readonly loginOptions: LoginHooksOptions;
  readonly syncOptions: SyncAccountHooksOptions;
  lifecycle: 'ready' | 'consuming' | 'consumed' | 'completing' | 'finished' | 'cancelled';
  authority: Promise<WebAuthnAuthenticationCredential> | null;
};

const hostedPasskeyPreparationStates = new WeakMap<
  HostedPasskeyPrepared,
  HostedPasskeyPreparationState
>();

function cancellationSignal(cancellation: HostedPasskeyPreparationCancellation): AbortSignal {
  return cancellation.signal;
}

function throwIfCancelled(cancellation: HostedPasskeyPreparationCancellation): void {
  if (cancellationSignal(cancellation).aborted) {
    throw new Error('Hosted auth-menu passkey preparation was cancelled');
  }
}

function throwIfExpired(prepared: HostedPasskeyPrepared): void {
  if (Date.now() >= prepared.expiresAtMs) {
    cancelHostedPasskeyPreparation(prepared);
    throw new Error('Hosted auth-menu passkey preparation expired');
  }
}

function requireLivePreparation(prepared: HostedPasskeyPrepared): HostedPasskeyPreparationState {
  const state = hostedPasskeyPreparationStates.get(prepared);
  if (!state) throw new Error('Hosted auth-menu passkey preparation is unknown');
  if (state.lifecycle !== 'ready') {
    throw new Error('Hosted auth-menu passkey preparation is no longer usable');
  }
  if (Date.now() >= prepared.expiresAtMs) {
    cancelHostedPasskeyPreparation(prepared);
    throw new Error('Hosted auth-menu passkey preparation expired');
  }
  throwIfCancelled(prepared.cancellation);
  return state;
}

function passkeyAllowCredential(input: {
  credentialId: string;
  transports?: readonly string[];
}): WebAuthnAllowCredential {
  return {
    id: String(input.credentialId || '').trim(),
    type: 'public-key',
    transports: Array.isArray(input.transports)
      ? (input.transports as AuthenticatorTransport[])
      : [],
  };
}

function preparationIdentity(args: {
  authMenuSessionId: HostedAuthMenuSessionId;
  requestId: WalletIframeRequestId;
}): Pick<HostedPasskeyLoginPrepared, 'authMenuSessionId' | 'requestId'> {
  return {
    authMenuSessionId: args.authMenuSessionId,
    requestId: args.requestId,
  };
}

export async function prepareHostedPasskeyLogin(args: {
  context: HostedPasskeyContext;
  walletId: string;
  authMenuSessionId: HostedAuthMenuSessionId;
  requestId: WalletIframeRequestId;
  cancellation: HostedPasskeyPreparationCancellation;
}): Promise<HostedPasskeyPrepared> {
  throwIfCancelled(args.cancellation);
  const walletId = walletIdFromString(args.walletId);
  const linkedSelection = await resolveLinkedDevicePasskeyAuthoritySelection(String(walletId));
  if (linkedSelection) {
    throwIfCancelled(args.cancellation);
    const prepared: HostedPasskeyLoginPrepared = Object.freeze({
      kind: 'hosted_passkey_linked_authority_login_prepared_v1',
      ...preparationIdentity(args),
      walletId,
      selection: linkedSelection,
      expiresAtMs: Date.now() + HOSTED_PASSKEY_PREPARATION_TTL_MS,
      cancellation: args.cancellation,
      [hostedPasskeyLoginPreparedBrand]: true as const,
    });
    hostedPasskeyPreparationStates.set(prepared, {
      context: args.context,
      loginOptions: {},
      syncOptions: {},
      lifecycle: 'ready',
      authority: null,
    });
    return prepared;
  }
  const resolution = await resolveWalletUnlockSubjectSet({
    walletId: String(walletId),
    requestedCapabilityFamilies: { kind: 'all_registered_mpc' },
  });
  const subjectSet =
    resolution.kind === 'resolved'
      ? resolution.subjectSet
      : await resolveLinkedDeviceUnlockSubjectSet(String(walletId));
  if (!subjectSet) {
    return await prepareHostedPasskeyAccountSync({
      context: args.context,
      walletId: null,
      authMenuSessionId: args.authMenuSessionId,
      requestId: args.requestId,
      cancellation: args.cancellation,
    });
  }
  throwIfCancelled(args.cancellation);
  const prepared: HostedPasskeyLoginPrepared = Object.freeze({
    kind: 'hosted_passkey_owner_login_prepared_v1',
    ...preparationIdentity(args),
    walletId,
    subjectSet,
    expiresAtMs: Date.now() + HOSTED_PASSKEY_PREPARATION_TTL_MS,
    cancellation: args.cancellation,
    [hostedPasskeyLoginPreparedBrand]: true as const,
  });
  hostedPasskeyPreparationStates.set(prepared, {
    context: args.context,
    loginOptions: {},
    syncOptions: {},
    lifecycle: 'ready',
    authority: null,
  });
  return prepared;
}

export async function prepareHostedPasskeyAccountSync(args: {
  context: HostedPasskeyContext;
  walletId: string | null;
  authMenuSessionId: HostedAuthMenuSessionId;
  requestId: WalletIframeRequestId;
  cancellation: HostedPasskeyPreparationCancellation;
}): Promise<HostedPasskeyAccountSyncPrepared> {
  throwIfCancelled(args.cancellation);
  const challenge = await prepareSyncAccountChallenge(args.context, args.walletId);
  throwIfCancelled(args.cancellation);
  const prepared: HostedPasskeyAccountSyncPrepared = Object.freeze({
    kind: 'hosted_passkey_account_sync_prepared_v1',
    authMenuSessionId: args.authMenuSessionId,
    requestId: args.requestId,
    challenge,
    expiresAtMs: Date.now() + HOSTED_PASSKEY_PREPARATION_TTL_MS,
    cancellation: args.cancellation,
    [hostedPasskeyAccountSyncPreparedBrand]: true as const,
  });
  hostedPasskeyPreparationStates.set(prepared, {
    context: args.context,
    loginOptions: {},
    syncOptions: {},
    lifecycle: 'ready',
    authority: null,
  });
  return prepared;
}

function startCredential(
  prepared: HostedPasskeyAccountSyncPrepared,
): Promise<WebAuthnAuthenticationCredential> {
  const state = requireLivePreparation(prepared);
  state.lifecycle = 'consuming';
  const args = {
    subjectId: prepared.challenge.walletId || 'account-sync',
    challengeB64u: prepared.challenge.syncOptions.challengeB64u,
    allowCredentials: prepared.challenge.syncOptions.credentialIds.map((credentialId) =>
      passkeyAllowCredential({ credentialId }),
    ),
  };
  let authority: Promise<WebAuthnAuthenticationCredential>;
  try {
    // Keep this call on the CTA stack. The signing surface invokes
    // navigator.credentials.get() before this function returns its promise.
    authority = state.context.signingEngine.getAuthenticationCredentialsSerialized({
      ...args,
      includeSecondPrfOutput: false,
    });
  } catch (error) {
    state.lifecycle = 'cancelled';
    throw error;
  }
  state.authority = authority;
  void authority.then(
    () => {
      if (state.lifecycle === 'consuming') state.lifecycle = 'consumed';
    },
    () => {
      if (state.lifecycle === 'consuming') state.lifecycle = 'cancelled';
    },
  );
  return authority;
}

export function startHostedPasskeyAccountSyncCredential(
  prepared: HostedPasskeyAccountSyncPrepared,
): Promise<WebAuthnAuthenticationCredential> {
  return startCredential(prepared);
}

function requireContinuationState(prepared: HostedPasskeyPrepared): HostedPasskeyPreparationState {
  const state = hostedPasskeyPreparationStates.get(prepared);
  if (!state) throw new Error('Hosted auth-menu passkey preparation is unknown');
  if ((state.lifecycle !== 'consuming' && state.lifecycle !== 'consumed') || !state.authority) {
    throw new Error('Hosted auth-menu passkey credential must be started by its CTA');
  }
  state.lifecycle = 'completing';
  return state;
}

/**
 * The unlock pipeline flattens a thrown WebAuthn rejection into
 * `{ success: false, error: <message> }`, which loses the DOMException name the
 * caller needs to tell "the user dismissed the sheet" from "the unlock failed".
 * It does classify the cause while the structure still exists, and reports it
 * on the unlock event stream, so latch that instead of re-deriving it from the
 * message text downstream.
 */
export type HostedPasskeyLoginOutcome = {
  readonly result: LoginAndCreateSessionResult;
  readonly cancelledByUser: boolean;
};

export async function completeHostedPasskeyLogin(
  prepared: HostedPasskeyLoginPrepared,
): Promise<HostedPasskeyLoginOutcome> {
  const state = requireLivePreparation(prepared);
  state.lifecycle = 'completing';
  let cancelledByUser = false;
  const recordUnlockEvent = (event: { phase: UnlockEventPhase }): void => {
    if (event.phase === UnlockEventPhase.CANCELLED) cancelledByUser = true;
  };
  try {
    const callerOnEvent = state.loginOptions.onEvent;
    const loginOptions: LoginHooksOptions = {
      ...state.loginOptions,
      onEvent: (event) => {
        recordUnlockEvent(event);
        callerOnEvent?.(event);
      },
    };
    const result =
      prepared.kind === 'hosted_passkey_linked_authority_login_prepared_v1'
        ? await unlockLinkedDevicePasskey(
            state.context,
            String(prepared.walletId),
            loginOptions,
          )
        : await unlockResolvedWalletSubjectSet(state.context, prepared.subjectSet, loginOptions);
    if (!result.success) clearHostedWalletSessions();
    return { result, cancelledByUser };
  } finally {
    state.lifecycle = 'finished';
  }
}

export async function completeHostedPasskeyAccountSync(
  prepared: HostedPasskeyAccountSyncPrepared,
): Promise<SyncAccountResult> {
  const state = requireContinuationState(prepared);
  const authority = state.authority;
  if (!authority) throw new Error('Hosted auth-menu passkey credential is missing');
  try {
    const credential = await authority;
    throwIfExpired(prepared);
    throwIfCancelled(prepared.cancellation);
    return await syncAccountWithPreparedCredential(
      state.context,
      prepared.challenge,
      credential,
      state.syncOptions,
    );
  } finally {
    state.lifecycle = 'finished';
  }
}

export function cancelHostedPasskeyPreparation(prepared: HostedPasskeyPrepared): void {
  const state = hostedPasskeyPreparationStates.get(prepared);
  if (!state || state.lifecycle === 'finished' || state.lifecycle === 'cancelled') return;
  state.lifecycle = 'cancelled';
}
