import {
  walletIframeRequestIdFromBoundary,
  walletIframeSurfaceIdFromBoundary,
  type WalletIframeRequestId,
  type WalletIframeSurfaceId,
} from '@/core/types/walletIframeIdentity';
import type {
  HostedAuthMenuSessionId,
  WalletIframeSurfaceMeasurement,
} from '../../shared/messages';

export type WalletIframeConnectionId = string & {
  readonly __walletIframeConnectionId: unique symbol;
};

export type RequestSurfaceIdentity = {
  kind: 'request_surface_identity_v1';
  surfaceId: WalletIframeSurfaceId;
  requestId: WalletIframeRequestId;
  activationId?: never;
};

export type WalletIframeWireMessageIdentity = RequestSurfaceIdentity;

export type TrustedWalletIframeInboundIdentity<
  Identity extends WalletIframeWireMessageIdentity = WalletIframeWireMessageIdentity,
> = {
  kind: 'trusted_wallet_iframe_inbound_identity_v1';
  connectionId: WalletIframeConnectionId;
  wireIdentity: Identity;
};

export type PasskeyRegistrationPreparationReceipt = {
  kind: 'passkey_registration_preparation_receipt_v1';
  expiresAtMs: number;
};

export type WalletIframeTrustedSurfaceMeasurement =
  | {
      kind: 'measured_v1';
      connectionId: WalletIframeConnectionId;
      identity: RequestSurfaceIdentity;
      authMenuSessionId?: never;
      sequence: number;
      widthCssPx: number;
      heightCssPx: number;
    }
  | {
      kind: 'measured_auth_menu_v1';
      connectionId: WalletIframeConnectionId;
      identity: RequestSurfaceIdentity;
      authMenuSessionId: HostedAuthMenuSessionId;
      sequence: number;
      widthCssPx: number;
      heightCssPx: number;
    };

export type WalletIframeSurfacePresentation =
  | { kind: 'modal'; title: string }
  | { kind: 'drawer'; title: string; edge: 'bottom' }
  | { kind: 'auth_menu_modal'; title: string };

export type WalletIframeRequestSurfacePresentation = Exclude<
  WalletIframeSurfacePresentation,
  { kind: 'auth_menu_modal' }
>;

export type WalletIframeModalPresentation = Extract<
  WalletIframeSurfacePresentation,
  { kind: 'modal' }
>;

export type WalletIframeDrawerPresentation = Extract<
  WalletIframeSurfacePresentation,
  { kind: 'drawer' }
>;

export type WalletIframeAuthMenuPresentation = Extract<
  WalletIframeSurfacePresentation,
  { kind: 'auth_menu_modal' }
>;

function requiredPresentationTitle(title: string): string {
  const normalized = title.trim();
  if (!normalized) throw new Error('Wallet iframe surface presentation title is required');
  return normalized;
}

export function modalWalletIframeSurfacePresentation(title: string): WalletIframeModalPresentation {
  return { kind: 'modal', title: requiredPresentationTitle(title) };
}

export function drawerWalletIframeSurfacePresentation(
  title: string,
): WalletIframeDrawerPresentation {
  return { kind: 'drawer', title: requiredPresentationTitle(title), edge: 'bottom' };
}

export function authMenuWalletIframeSurfacePresentation(
  title: string,
): WalletIframeAuthMenuPresentation {
  return { kind: 'auth_menu_modal', title: requiredPresentationTitle(title) };
}

export type HiddenWalletIframeSurface = {
  kind: 'hidden';
  identity?: never;
  connectionId?: never;
  presentation?: never;
};

type OwnedWalletIframeSurface = {
  connectionId: WalletIframeConnectionId;
  presentation: WalletIframeRequestSurfacePresentation;
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

export type ModalAuthMenuSurface = {
  kind: 'modal_auth_menu';
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  presentation: WalletIframeAuthMenuPresentation;
  authMenuSessionId: HostedAuthMenuSessionId;
};

export type WalletIframeSurface =
  | HiddenWalletIframeSurface
  | ModalRegistrationConfirmSurface
  | ModalTransactionConfirmSurface
  | ModalKeyExportConfirmSurface
  | ModalUnlockConfirmSurface
  | ModalRecoveryCodesSurface
  | ModalDeviceLinkQrSurface
  | ModalAuthMenuSurface;

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

type RequestOwnedEvent = {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
};

type RequestPresentationEvent = RequestOwnedEvent & {
  presentation: WalletIframeRequestSurfacePresentation;
};

export type WalletIframeSurfaceEvent =
  | (RequestPresentationEvent & {
      kind: 'registration_modal_request_started';
      preparation: PasskeyRegistrationPreparationReceipt;
    })
  | (RequestPresentationEvent & {
      kind: 'transaction_modal_request_started';
    })
  | (RequestPresentationEvent & {
      kind: 'key_export_modal_request_started';
      exportKind: ModalKeyExportConfirmSurface['exportKind'];
    })
  | (RequestPresentationEvent & {
      kind: 'unlock_modal_request_started';
      unlockKind: ModalUnlockConfirmSurface['unlockKind'];
    })
  | (RequestPresentationEvent & {
      kind: 'recovery_codes_modal_request_started';
      operation: ModalRecoveryCodesSurface['operation'];
    })
  | (RequestPresentationEvent & { kind: 'device_link_qr_modal_request_started' })
  | (RequestOwnedEvent & {
      kind: 'auth_menu_request_started';
      presentation: WalletIframeAuthMenuPresentation;
      authMenuSessionId: HostedAuthMenuSessionId;
    })
  | (RequestOwnedEvent & {
      kind: 'auth_menu_request_completed';
      presentation?: never;
      authMenuSessionId: HostedAuthMenuSessionId;
    })
  | (RequestOwnedEvent & {
      kind: 'auth_menu_request_closed';
      presentation?: never;
      authMenuSessionId: HostedAuthMenuSessionId;
    })
  | (RequestOwnedEvent & {
      kind: 'auth_menu_request_cancelled';
      presentation?: never;
      authMenuSessionId: HostedAuthMenuSessionId;
    })
  | (RequestOwnedEvent & { kind: 'request_surface_hidden'; presentation?: never })
  | (RequestOwnedEvent & { kind: 'request_finished'; presentation?: never })
  | (RequestOwnedEvent & { kind: 'request_cancelled'; presentation?: never })
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

export function trustedWalletIframeSurfaceMeasurementFromWire(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  measurement: WalletIframeSurfaceMeasurement;
}): WalletIframeTrustedSurfaceMeasurement | null {
  if (args.measurement.requestId !== args.identity.requestId) return null;
  switch (args.measurement.kind) {
    case 'measured_v1':
      return {
        kind: 'measured_v1',
        connectionId: args.connectionId,
        identity: args.identity,
        sequence: args.measurement.sequence,
        widthCssPx: args.measurement.widthCssPx,
        heightCssPx: args.measurement.heightCssPx,
      };
    case 'measured_auth_menu_v1':
      return {
        kind: 'measured_auth_menu_v1',
        connectionId: args.connectionId,
        identity: args.identity,
        authMenuSessionId: args.measurement.authMenuSessionId,
        sequence: args.measurement.sequence,
        widthCssPx: args.measurement.widthCssPx,
        heightCssPx: args.measurement.heightCssPx,
      };
    default:
      return assertNever(args.measurement);
  }
}

export function passkeyRegistrationPreparationReceipt(
  expiresAtMs: number,
): PasskeyRegistrationPreparationReceipt {
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('Registration preparation expiry must be a positive safe integer');
  }
  return Object.freeze({ kind: 'passkey_registration_preparation_receipt_v1', expiresAtMs });
}

export function hiddenWalletIframeSurface(): HiddenWalletIframeSurface {
  return { kind: 'hidden' };
}

export function modalRegistrationConfirmSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  presentation: WalletIframeRequestSurfacePresentation;
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
  presentation: WalletIframeRequestSurfacePresentation;
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
  presentation: WalletIframeRequestSurfacePresentation;
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
  presentation: WalletIframeRequestSurfacePresentation;
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
  presentation: WalletIframeRequestSurfacePresentation;
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
  presentation: WalletIframeRequestSurfacePresentation;
}): ModalDeviceLinkQrSurface {
  return { kind: 'modal_device_link_qr', ...args };
}

export function modalAuthMenuSurface(args: {
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  presentation: WalletIframeAuthMenuPresentation;
  authMenuSessionId: HostedAuthMenuSessionId;
}): ModalAuthMenuSurface {
  return {
    kind: 'modal_auth_menu',
    connectionId: args.connectionId,
    identity: args.identity,
    presentation: args.presentation,
    authMenuSessionId: args.authMenuSessionId,
  };
}

function requestIdentitiesEqual(
  left: RequestSurfaceIdentity,
  right: RequestSurfaceIdentity,
): boolean {
  return left.surfaceId === right.surfaceId && left.requestId === right.requestId;
}

function foregroundSurfaceIdentitiesEqual(
  left: ForegroundWalletIframeSurface,
  right: ForegroundWalletIframeSurface,
): boolean {
  if (left.kind !== right.kind || left.connectionId !== right.connectionId) return false;
  if (
    left.kind === 'modal_auth_menu' &&
    right.kind === 'modal_auth_menu' &&
    left.authMenuSessionId !== right.authMenuSessionId
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

function requestEventOwnsSurface(
  surface: WalletIframeSurface,
  event: RequestOwnedEvent,
): surface is ForegroundWalletIframeSurface {
  return (
    surface.kind !== 'hidden' &&
    surface.connectionId === event.connectionId &&
    requestIdentitiesEqual(surface.identity, event.identity)
  );
}

function authMenuEventOwnsSurface(
  surface: WalletIframeSurface,
  event: RequestOwnedEvent & { authMenuSessionId: HostedAuthMenuSessionId },
): surface is ModalAuthMenuSurface {
  return (
    surface.kind === 'modal_auth_menu' &&
    surface.connectionId === event.connectionId &&
    requestIdentitiesEqual(surface.identity, event.identity) &&
    surface.authMenuSessionId === event.authMenuSessionId
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
    case 'registration_modal_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalRegistrationConfirmSurface({
            connectionId: event.connectionId,
            identity: event.identity,
            presentation: event.presentation,
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
            presentation: event.presentation,
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
            presentation: event.presentation,
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
            presentation: event.presentation,
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
            presentation: event.presentation,
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
            presentation: event.presentation,
          }),
        ),
      );
    case 'auth_menu_request_started':
      return reduceStartResult(
        current,
        beginForegroundWalletIframeSurface(
          current,
          modalAuthMenuSurface({
            connectionId: event.connectionId,
            identity: event.identity,
            presentation: event.presentation,
            authMenuSessionId: event.authMenuSessionId,
          }),
        ),
      );
    case 'auth_menu_request_completed':
    case 'auth_menu_request_closed':
    case 'auth_menu_request_cancelled':
      return authMenuEventOwnsSurface(current, event)
        ? { kind: 'applied', surface: hiddenWalletIframeSurface() }
        : { kind: 'ignored', surface: current };
    case 'request_surface_hidden':
      return requestEventOwnsSurface(current, event)
        ? { kind: 'applied', surface: hiddenWalletIframeSurface() }
        : { kind: 'ignored', surface: current };
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
