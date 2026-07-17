import type {
  RegistrationActivationButtonPresentation,
} from '@/SeamsWeb/publicApi/types';
import {
  registrationActivationIdFromBoundary,
  walletIframeRequestIdFromBoundary,
  walletIframeSurfaceIdFromBoundary,
  type RegistrationActivationId,
  type RegistrationActivationMessageIdentity,
  type WalletIframeRequestId,
  type WalletIframeSurfaceId,
} from '@/core/types/registrationActivationIdentity';
import type { DOMRectLike } from '../overlay/overlay-controller';
import type { RegisterWalletInput } from '@shared/utils/registrationIntent';

export type WalletIframeConnectionId = string & {
  readonly __walletIframeConnectionId: unique symbol;
};

export type RegistrationActivationTargetRect = Readonly<DOMRectLike> & {
  readonly __registrationActivationTargetRect: unique symbol;
};

export type RequestSurfaceIdentity = {
  kind: 'request_surface_identity_v1';
  surfaceId: WalletIframeSurfaceId;
  requestId: WalletIframeRequestId;
  activationId?: never;
};

export type RegistrationActivationSurfaceIdentity = {
  kind: 'registration_activation_surface_identity_v1';
  surfaceId: WalletIframeSurfaceId;
  requestId: WalletIframeRequestId;
  activationId: RegistrationActivationId;
};

export type WalletIframeWireMessageIdentity =
  | RequestSurfaceIdentity
  | RegistrationActivationSurfaceIdentity;

export type TrustedWalletIframeInboundIdentity<
  Identity extends WalletIframeWireMessageIdentity = WalletIframeWireMessageIdentity,
> = {
  kind: 'trusted_wallet_iframe_inbound_identity_v1';
  connectionId: WalletIframeConnectionId;
  wireIdentity: Identity;
};

export type ProvidedPasskeyRegistrationWallet = Extract<RegisterWalletInput, { kind: 'provided' }>;

export type PasskeyRegistrationPreparationReceipt = {
  kind: 'passkey_registration_preparation_receipt_v1';
  expiresAtMs: number;
};

export type AnchoredRegistrationPlacement =
  | { kind: 'interactive'; targetRect: RegistrationActivationTargetRect }
  | {
      kind: 'suspended';
      reason: 'ancestor_clipped';
      lastTargetRect: RegistrationActivationTargetRect;
    };

export type AnchoredRegistrationFocusOwner =
  | { kind: 'outside' }
  | { kind: 'proxy' }
  | { kind: 'iframe_button' };

export type HiddenWalletIframeSurface = {
  kind: 'hidden';
  identity?: never;
  connectionId?: never;
};

type OwnedWalletIframeSurface = {
  connectionId: WalletIframeConnectionId;
};

export type AnchoredRegistrationActivationSurface = OwnedWalletIframeSurface & {
  kind: 'anchored_registration_activation';
  identity: RegistrationActivationSurfaceIdentity;
  wallet: ProvidedPasskeyRegistrationWallet;
  preparation: PasskeyRegistrationPreparationReceipt;
  presentation: RegistrationActivationButtonPresentation;
  placement: AnchoredRegistrationPlacement;
  focusOwner: AnchoredRegistrationFocusOwner;
};

export type ModalRegistrationConfirmSurface = OwnedWalletIframeSurface & {
  kind: 'modal_registration_confirm';
  identity: RequestSurfaceIdentity;
  preparation: PasskeyRegistrationPreparationReceipt;
  userActivation: 'wallet_confirm_button_required';
};

export type ModalTransactionConfirmSurface = OwnedWalletIframeSurface & {
  kind: 'modal_transaction_confirm';
  identity: RequestSurfaceIdentity;
  userActivation: 'wallet_confirm_button_required';
};

export type ModalKeyExportConfirmSurface = OwnedWalletIframeSurface & {
  kind: 'modal_key_export_confirm';
  identity: RequestSurfaceIdentity;
  exportKind: 'near_keypair' | 'threshold_ed25519_seed_from_yao';
  userActivation: 'wallet_confirm_button_required';
};

export type ModalUnlockConfirmSurface = OwnedWalletIframeSurface & {
  kind: 'modal_unlock_confirm';
  identity: RequestSurfaceIdentity;
  unlockKind: 'passkey' | 'device_link';
  userActivation: 'wallet_confirm_button_required';
};

export type ModalRecoveryCodesSurface = OwnedWalletIframeSurface & {
  kind: 'modal_recovery_codes';
  identity: RequestSurfaceIdentity;
  operation: 'show' | 'rotate';
  userActivation: 'wallet_confirm_button_required';
};

export type ModalDeviceLinkQrSurface = OwnedWalletIframeSurface & {
  kind: 'modal_device_link_qr';
  identity: RequestSurfaceIdentity;
};

export type WalletIframeSurface =
  | HiddenWalletIframeSurface
  | AnchoredRegistrationActivationSurface
  | ModalRegistrationConfirmSurface
  | ModalTransactionConfirmSurface
  | ModalKeyExportConfirmSurface
  | ModalUnlockConfirmSurface
  | ModalRecoveryCodesSurface
  | ModalDeviceLinkQrSurface;

export type ForegroundWalletIframeSurface = Exclude<WalletIframeSurface, HiddenWalletIframeSurface>;

export type WalletIframeSurfaceBusyError = {
  kind: 'wallet_iframe_surface_busy';
  activeSurfaceKind: ForegroundWalletIframeSurface['kind'];
  attemptedSurfaceKind: ForegroundWalletIframeSurface['kind'];
  retry: 'after_active_surface_finishes';
};

export type BeginForegroundWalletIframeSurfaceResult =
  | { kind: 'started'; surface: ForegroundWalletIframeSurface }
  | { kind: 'idempotent'; surface: ForegroundWalletIframeSurface }
  | { kind: 'rejected'; error: WalletIframeSurfaceBusyError };

type RegistrationActivationOwnedEvent = {
  connectionId: WalletIframeConnectionId;
  identity: RegistrationActivationSurfaceIdentity;
};

type RequestOwnedEvent = {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
};

export type WalletIframeSurfaceEvent =
  | (RegistrationActivationOwnedEvent & {
      kind: 'registration_activation_prepared';
      wallet: ProvidedPasskeyRegistrationWallet;
      preparation: PasskeyRegistrationPreparationReceipt;
      presentation: RegistrationActivationButtonPresentation;
      placement: AnchoredRegistrationPlacement;
    })
  | (RegistrationActivationOwnedEvent & {
      kind: 'registration_activation_placement_changed';
      placement: AnchoredRegistrationPlacement;
    })
  | (RegistrationActivationOwnedEvent & {
      kind: 'registration_activation_focus_owner_changed';
      focusOwner: AnchoredRegistrationFocusOwner;
    })
  | (RegistrationActivationOwnedEvent & {
      kind: 'registration_activation_cancelled';
      reason: 'user_cancelled' | 'expired' | 'disposed' | 'target_unavailable';
    })
  | (RegistrationActivationOwnedEvent & {
      kind: 'registration_activation_finished';
    })
  | (RequestOwnedEvent & {
      kind: 'registration_modal_request_started';
      preparation: PasskeyRegistrationPreparationReceipt;
    })
  | (RequestOwnedEvent & {
      kind: 'transaction_modal_request_started';
    })
  | (RequestOwnedEvent & {
      kind: 'key_export_modal_request_started';
      exportKind: ModalKeyExportConfirmSurface['exportKind'];
    })
  | (RequestOwnedEvent & {
      kind: 'unlock_modal_request_started';
      unlockKind: ModalUnlockConfirmSurface['unlockKind'];
    })
  | (RequestOwnedEvent & {
      kind: 'recovery_codes_modal_request_started';
      operation: ModalRecoveryCodesSurface['operation'];
    })
  | (RequestOwnedEvent & { kind: 'device_link_qr_modal_request_started' })
  | (RequestOwnedEvent & { kind: 'request_finished' })
  | (RequestOwnedEvent & { kind: 'request_cancelled' })
  | { kind: 'connection_closed'; connectionId: WalletIframeConnectionId };

export type ReduceWalletIframeSurfaceResult =
  | { kind: 'applied'; surface: WalletIframeSurface }
  | { kind: 'ignored'; surface: WalletIframeSurface }
  | { kind: 'rejected'; surface: WalletIframeSurface; error: WalletIframeSurfaceBusyError };

function parseNonEmptyBoundaryString(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value.trim();
}

export function walletIframeConnectionIdFromBoundary(value: unknown): WalletIframeConnectionId {
  return parseNonEmptyBoundaryString(value, 'connectionId') as WalletIframeConnectionId;
}

function boundaryRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function parseRegistrationActivationSurfaceIdentity(
  value: unknown,
): RegistrationActivationSurfaceIdentity | null {
  const record = boundaryRecord(value);
  if (!record) return null;
  try {
    return {
      kind: 'registration_activation_surface_identity_v1',
      surfaceId: walletIframeSurfaceIdFromBoundary(record.surfaceId),
      requestId: walletIframeRequestIdFromBoundary(record.requestId),
      activationId: registrationActivationIdFromBoundary(record.activationId),
    };
  } catch {
    return null;
  }
}

export function parseRequestSurfaceIdentity(value: unknown): RequestSurfaceIdentity | null {
  const record = boundaryRecord(value);
  if (!record || record.activationId !== undefined) return null;
  try {
    return {
      kind: 'request_surface_identity_v1',
      surfaceId: walletIframeSurfaceIdFromBoundary(record.surfaceId),
      requestId: walletIframeRequestIdFromBoundary(record.requestId),
    };
  } catch {
    return null;
  }
}

export function registrationActivationTargetRectFromBoundary(
  rect: DOMRectLike,
): RegistrationActivationTargetRect {
  const values = [rect.top, rect.left, rect.width, rect.height];
  if (!values.every(Number.isFinite) || rect.width < 44 || rect.height < 44) {
    throw new Error('Registration activation target rect must be finite and at least 44px square');
  }
  return Object.freeze({ ...rect }) as RegistrationActivationTargetRect;
}

export function registrationActivationSurfaceIdentity(
  identity: RegistrationActivationMessageIdentity,
): RegistrationActivationSurfaceIdentity {
  return Object.freeze({
    kind: 'registration_activation_surface_identity_v1',
    surfaceId: identity.surfaceId,
    requestId: identity.requestId,
    activationId: identity.activationId,
  });
}

export function requestSurfaceIdentity(args: {
  surfaceId: WalletIframeSurfaceId;
  requestId: WalletIframeRequestId;
}): RequestSurfaceIdentity {
  return Object.freeze({ kind: 'request_surface_identity_v1', ...args });
}

export function trustedWalletIframeInboundIdentity<
  Identity extends WalletIframeWireMessageIdentity,
>(
  connectionId: WalletIframeConnectionId,
  wireIdentity: Identity,
): TrustedWalletIframeInboundIdentity<Identity> {
  return Object.freeze({
    kind: 'trusted_wallet_iframe_inbound_identity_v1',
    connectionId,
    wireIdentity,
  });
}

export function passkeyRegistrationPreparationReceipt(
  expiresAtMs: number,
): PasskeyRegistrationPreparationReceipt {
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('Registration preparation expiry must be a positive safe integer');
  }
  return Object.freeze({ kind: 'passkey_registration_preparation_receipt_v1', expiresAtMs });
}

export function interactiveRegistrationPlacement(rect: DOMRectLike): AnchoredRegistrationPlacement {
  return { kind: 'interactive', targetRect: registrationActivationTargetRectFromBoundary(rect) };
}

export function suspendedRegistrationPlacement(rect: DOMRectLike): AnchoredRegistrationPlacement {
  return {
    kind: 'suspended',
    reason: 'ancestor_clipped',
    lastTargetRect: registrationActivationTargetRectFromBoundary(rect),
  };
}

export function hiddenWalletIframeSurface(): HiddenWalletIframeSurface {
  return { kind: 'hidden' };
}

export function anchoredRegistrationActivationSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RegistrationActivationSurfaceIdentity;
  wallet: ProvidedPasskeyRegistrationWallet;
  preparation: PasskeyRegistrationPreparationReceipt;
  presentation: RegistrationActivationButtonPresentation;
  placement: AnchoredRegistrationPlacement;
  focusOwner: AnchoredRegistrationFocusOwner;
}): AnchoredRegistrationActivationSurface {
  return { kind: 'anchored_registration_activation', ...args };
}

export function modalRegistrationConfirmSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  preparation: PasskeyRegistrationPreparationReceipt;
}): ModalRegistrationConfirmSurface {
  return {
    kind: 'modal_registration_confirm',
    ...args,
    userActivation: 'wallet_confirm_button_required',
  };
}

export function modalTransactionConfirmSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
}): ModalTransactionConfirmSurface {
  return {
    kind: 'modal_transaction_confirm',
    ...args,
    userActivation: 'wallet_confirm_button_required',
  };
}

export function modalKeyExportConfirmSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  exportKind: ModalKeyExportConfirmSurface['exportKind'];
}): ModalKeyExportConfirmSurface {
  return {
    kind: 'modal_key_export_confirm',
    ...args,
    userActivation: 'wallet_confirm_button_required',
  };
}

export function modalUnlockConfirmSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  unlockKind: ModalUnlockConfirmSurface['unlockKind'];
}): ModalUnlockConfirmSurface {
  return {
    kind: 'modal_unlock_confirm',
    ...args,
    userActivation: 'wallet_confirm_button_required',
  };
}

export function modalRecoveryCodesSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  operation: ModalRecoveryCodesSurface['operation'];
}): ModalRecoveryCodesSurface {
  return {
    kind: 'modal_recovery_codes',
    ...args,
    userActivation: 'wallet_confirm_button_required',
  };
}

export function modalDeviceLinkQrSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
}): ModalDeviceLinkQrSurface {
  return { kind: 'modal_device_link_qr', ...args };
}

function requestIdentitiesEqual(
  left: RequestSurfaceIdentity,
  right: RequestSurfaceIdentity,
): boolean {
  return left.surfaceId === right.surfaceId && left.requestId === right.requestId;
}

export function registrationActivationSurfaceIdentitiesEqual(
  left: RegistrationActivationSurfaceIdentity,
  right: RegistrationActivationSurfaceIdentity,
): boolean {
  return (
    left.surfaceId === right.surfaceId &&
    left.requestId === right.requestId &&
    left.activationId === right.activationId
  );
}

function foregroundSurfaceIdentitiesEqual(
  left: ForegroundWalletIframeSurface,
  right: ForegroundWalletIframeSurface,
): boolean {
  if (left.kind !== right.kind || left.connectionId !== right.connectionId) return false;
  if (
    left.kind === 'anchored_registration_activation' &&
    right.kind === 'anchored_registration_activation'
  ) {
    return registrationActivationSurfaceIdentitiesEqual(left.identity, right.identity);
  }
  if (
    left.kind === 'anchored_registration_activation' ||
    right.kind === 'anchored_registration_activation'
  ) {
    return false;
  }
  return requestIdentitiesEqual(left.identity, right.identity);
}

export function beginForegroundWalletIframeSurface(
  current: WalletIframeSurface,
  attempted: ForegroundWalletIframeSurface,
): BeginForegroundWalletIframeSurfaceResult {
  if (current.kind === 'hidden') return { kind: 'started', surface: attempted };
  if (foregroundSurfaceIdentitiesEqual(current, attempted)) {
    return { kind: 'idempotent', surface: current };
  }
  return {
    kind: 'rejected',
    error: {
      kind: 'wallet_iframe_surface_busy',
      activeSurfaceKind: current.kind,
      attemptedSurfaceKind: attempted.kind,
      retry: 'after_active_surface_finishes',
    },
  };
}

function registrationEventOwnsSurface(
  surface: WalletIframeSurface,
  event: RegistrationActivationOwnedEvent,
): surface is AnchoredRegistrationActivationSurface {
  return (
    surface.kind === 'anchored_registration_activation' &&
    surface.connectionId === event.connectionId &&
    registrationActivationSurfaceIdentitiesEqual(surface.identity, event.identity)
  );
}

function requestEventOwnsSurface(
  surface: WalletIframeSurface,
  event: RequestOwnedEvent,
): surface is Exclude<ForegroundWalletIframeSurface, AnchoredRegistrationActivationSurface> {
  return (
    surface.kind !== 'hidden' &&
    surface.kind !== 'anchored_registration_activation' &&
    surface.connectionId === event.connectionId &&
    requestIdentitiesEqual(surface.identity, event.identity)
  );
}

function reduceStartResult(
  current: WalletIframeSurface,
  result: BeginForegroundWalletIframeSurfaceResult,
): ReduceWalletIframeSurfaceResult {
  switch (result.kind) {
    case 'started':
      return { kind: 'applied', surface: result.surface };
    case 'idempotent':
      return { kind: 'ignored', surface: result.surface };
    case 'rejected':
      return { kind: 'rejected', surface: current, error: result.error };
    default:
      return assertNever(result);
  }
}

export function reduceWalletIframeSurface(
  current: WalletIframeSurface,
  event: WalletIframeSurfaceEvent,
): ReduceWalletIframeSurfaceResult {
  switch (event.kind) {
    case 'registration_activation_prepared':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          anchoredRegistrationActivationSurface({
            connectionId: event.connectionId,
            identity: event.identity,
            wallet: event.wallet,
            preparation: event.preparation,
            presentation: event.presentation,
            placement: event.placement,
            focusOwner: { kind: 'outside' },
          }),
        ),
      );
    case 'registration_activation_placement_changed':
      if (!registrationEventOwnsSurface(current, event))
        return { kind: 'ignored', surface: current };
      return { kind: 'applied', surface: { ...current, placement: event.placement } };
    case 'registration_activation_focus_owner_changed':
      if (!registrationEventOwnsSurface(current, event))
        return { kind: 'ignored', surface: current };
      return { kind: 'applied', surface: { ...current, focusOwner: event.focusOwner } };
    case 'registration_activation_cancelled':
    case 'registration_activation_finished':
      return registrationEventOwnsSurface(current, event)
        ? { kind: 'applied', surface: hiddenWalletIframeSurface() }
        : { kind: 'ignored', surface: current };
    case 'registration_modal_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalRegistrationConfirmSurface({
            connectionId: event.connectionId,
            identity: event.identity,
            preparation: event.preparation,
          }),
        ),
      );
    case 'transaction_modal_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalTransactionConfirmSurface({
            connectionId: event.connectionId,
            identity: event.identity,
          }),
        ),
      );
    case 'key_export_modal_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalKeyExportConfirmSurface({
            connectionId: event.connectionId,
            identity: event.identity,
            exportKind: event.exportKind,
          }),
        ),
      );
    case 'unlock_modal_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalUnlockConfirmSurface({
            connectionId: event.connectionId,
            identity: event.identity,
            unlockKind: event.unlockKind,
          }),
        ),
      );
    case 'recovery_codes_modal_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalRecoveryCodesSurface({
            connectionId: event.connectionId,
            identity: event.identity,
            operation: event.operation,
          }),
        ),
      );
    case 'device_link_qr_modal_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalDeviceLinkQrSurface({
            connectionId: event.connectionId,
            identity: event.identity,
          }),
        ),
      );
    case 'request_finished':
    case 'request_cancelled':
      return requestEventOwnsSurface(current, event)
        ? { kind: 'applied', surface: hiddenWalletIframeSurface() }
        : { kind: 'ignored', surface: current };
    case 'connection_closed':
      return current.kind !== 'hidden' && current.connectionId === event.connectionId
        ? { kind: 'applied', surface: hiddenWalletIframeSurface() }
        : { kind: 'ignored', surface: current };
    default:
      return assertNever(event);
  }
}

export function assertNever(value: never): never {
  throw new Error(`Unhandled wallet iframe surface variant: ${JSON.stringify(value)}`);
}
