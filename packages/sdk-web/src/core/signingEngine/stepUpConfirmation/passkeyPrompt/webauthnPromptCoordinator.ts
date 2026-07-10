import type {
  RegistrationActivationMessageIdentity,
  WalletIframeRequestId,
} from '@/SeamsWeb/publicApi/types';
import { secureRandomBase36 } from '@shared/utils/secureRandomId';

export type WebAuthnPromptReservationId = string & {
  readonly __webAuthnPromptReservationId: unique symbol;
};

export type WebAuthnPromptOperationId = string & {
  readonly __webAuthnPromptOperationId: unique symbol;
};

export type RegistrationWebAuthnPromptOwner =
  | {
      kind: 'registration_activation';
      identity: RegistrationActivationMessageIdentity;
    }
  | {
      kind: 'registration_modal';
      requestId: WalletIframeRequestId;
    };

export type WebAuthnPromptOwner =
  | RegistrationWebAuthnPromptOwner
  | {
      kind: 'wallet_request';
      requestId: string;
      operation: 'authentication' | 'registration';
    };

export type ReservedRegistrationWebAuthnPrompt<
  Owner extends RegistrationWebAuthnPromptOwner = RegistrationWebAuthnPromptOwner,
> = {
  kind: 'reserved_registration_webauthn_prompt_v1';
  reservationId: WebAuthnPromptReservationId;
  owner: Owner;
  expiresAtMs: number;
};

export type WebAuthnPromptCoordinatorState =
  | {
      kind: 'idle';
      reservation?: never;
      operationId?: never;
      owner?: never;
    }
  | {
      kind: 'reserved';
      reservation: ReservedRegistrationWebAuthnPrompt;
      operationId?: never;
      owner?: never;
    }
  | {
      kind: 'running';
      operationId: WebAuthnPromptOperationId;
      owner: WebAuthnPromptOwner;
      reservation?: never;
    };

export type WebAuthnPromptCoordinatorErrorCode =
  | 'webauthn_prompt_busy'
  | 'webauthn_prompt_reservation_expired'
  | 'webauthn_prompt_reservation_owner_mismatch'
  | 'webauthn_prompt_reservation_reused';

export class WebAuthnPromptCoordinatorError extends Error {
  readonly code: WebAuthnPromptCoordinatorErrorCode;

  constructor(code: WebAuthnPromptCoordinatorErrorCode, message: string) {
    super(message);
    this.name = 'WebAuthnPromptCoordinatorError';
    this.code = code;
  }
}

type IdleWaiter = {
  resolve(): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout>;
  signal: AbortSignal | null;
  onAbort: (() => void) | null;
};

export type WebAuthnPromptCancellation =
  | { kind: 'none'; signal?: never }
  | { kind: 'abort_signal'; signal: AbortSignal };

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

function registrationPromptOwnersEqual(
  left: RegistrationWebAuthnPromptOwner,
  right: RegistrationWebAuthnPromptOwner,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'registration_activation':
      return (
        right.kind === 'registration_activation' &&
        registrationActivationIdentitiesEqual(left.identity, right.identity)
      );
    case 'registration_modal':
      return right.kind === 'registration_modal' && left.requestId === right.requestId;
  }
}

function createReservationId(): WebAuthnPromptReservationId {
  return `webauthn-reservation-${secureRandomBase36(18, 'WebAuthn reservation IDs')}` as WebAuthnPromptReservationId;
}

function createOperationId(): WebAuthnPromptOperationId {
  return `webauthn-operation-${secureRandomBase36(18, 'WebAuthn operation IDs')}` as WebAuthnPromptOperationId;
}

export class WebAuthnPromptCoordinator {
  private state: WebAuthnPromptCoordinatorState = { kind: 'idle' };
  private idleWaiters = new Set<IdleWaiter>();
  private reservationExpiryTimer: ReturnType<typeof setTimeout> | null = null;
  private consumedReservationIds = new Set<WebAuthnPromptReservationId>();

  snapshot(): WebAuthnPromptCoordinatorState {
    return this.state;
  }

  async reserveRegistrationPrompt<Owner extends RegistrationWebAuthnPromptOwner>(args: {
    owner: Owner;
    expiresAtMs: number;
    cancellation: WebAuthnPromptCancellation;
  }): Promise<ReservedRegistrationWebAuthnPrompt<Owner>> {
    this.throwIfReservationCancelled(args.cancellation);
    if (Date.now() >= args.expiresAtMs) {
      throw new WebAuthnPromptCoordinatorError(
        'webauthn_prompt_reservation_expired',
        'WebAuthn prompt reservation expired before acquisition',
      );
    }
    while (this.state.kind !== 'idle') {
      await this.waitUntilIdle(args.expiresAtMs, args.cancellation);
      this.throwIfReservationCancelled(args.cancellation);
    }
    const reservation: ReservedRegistrationWebAuthnPrompt<Owner> = {
      kind: 'reserved_registration_webauthn_prompt_v1',
      reservationId: createReservationId(),
      owner: args.owner,
      expiresAtMs: args.expiresAtMs,
    };
    this.state = { kind: 'reserved', reservation };
    this.armReservationExpiry(reservation);
    return reservation;
  }

  releaseReservation(reservation: ReservedRegistrationWebAuthnPrompt): void {
    if (this.state.kind !== 'reserved') return;
    if (this.state.reservation.reservationId !== reservation.reservationId) return;
    this.clearReservationExpiry();
    this.state = { kind: 'idle' };
    this.notifyIdle();
  }

  isLiveReservation(args: {
    reservation: ReservedRegistrationWebAuthnPrompt;
    owner: RegistrationWebAuthnPromptOwner;
  }): boolean {
    return (
      Date.now() < args.reservation.expiresAtMs &&
      this.state.kind === 'reserved' &&
      this.state.reservation.reservationId === args.reservation.reservationId &&
      registrationPromptOwnersEqual(args.reservation.owner, args.owner)
    );
  }

  runReserved<T>(args: {
    reservation: ReservedRegistrationWebAuthnPrompt;
    owner: RegistrationWebAuthnPromptOwner;
    operation(): Promise<T>;
  }): Promise<T> {
    this.assertLiveReservation(args.reservation, args.owner);
    const operationId = createOperationId();
    this.consumedReservationIds.add(args.reservation.reservationId);
    this.clearReservationExpiry();
    this.state = { kind: 'running', operationId, owner: args.owner };
    return this.startOperation(operationId, args.operation);
  }

  runImmediate<T>(args: { owner: WebAuthnPromptOwner; operation(): Promise<T> }): Promise<T> {
    if (this.state.kind !== 'idle') {
      throw new WebAuthnPromptCoordinatorError(
        'webauthn_prompt_busy',
        'Another WebAuthn prompt owns the coordinator',
      );
    }
    const operationId = createOperationId();
    this.state = { kind: 'running', operationId, owner: args.owner };
    return this.startOperation(operationId, args.operation);
  }

  private startOperation<T>(
    operationId: WebAuthnPromptOperationId,
    operation: () => Promise<T>,
  ): Promise<T> {
    let result: Promise<T>;
    try {
      result = operation();
    } catch (error) {
      this.finishOperation(operationId);
      throw error;
    }
    const finish = this.finishOperation.bind(this, operationId);
    void result.then(finish, finish);
    return result;
  }

  private assertLiveReservation(
    reservation: ReservedRegistrationWebAuthnPrompt,
    owner: RegistrationWebAuthnPromptOwner,
  ): void {
    if (this.consumedReservationIds.has(reservation.reservationId)) {
      throw new WebAuthnPromptCoordinatorError(
        'webauthn_prompt_reservation_reused',
        'WebAuthn prompt reservation was already consumed',
      );
    }
    if (Date.now() >= reservation.expiresAtMs) {
      this.releaseReservation(reservation);
      throw new WebAuthnPromptCoordinatorError(
        'webauthn_prompt_reservation_expired',
        'WebAuthn prompt reservation expired',
      );
    }
    if (
      this.state.kind !== 'reserved' ||
      this.state.reservation.reservationId !== reservation.reservationId
    ) {
      throw new WebAuthnPromptCoordinatorError(
        'webauthn_prompt_reservation_reused',
        'WebAuthn prompt reservation is no longer active',
      );
    }
    if (!registrationPromptOwnersEqual(reservation.owner, owner)) {
      throw new WebAuthnPromptCoordinatorError(
        'webauthn_prompt_reservation_owner_mismatch',
        'WebAuthn prompt reservation owner does not match',
      );
    }
  }

  private finishOperation(operationId: WebAuthnPromptOperationId): void {
    if (this.state.kind !== 'running' || this.state.operationId !== operationId) return;
    this.state = { kind: 'idle' };
    this.notifyIdle();
  }

  private waitUntilIdle(
    expiresAtMs: number,
    cancellation: WebAuthnPromptCancellation,
  ): Promise<void> {
    const timeoutMs = Math.max(1, expiresAtMs - Date.now());
    return new Promise<void>((resolve, reject) => {
      const waiter: IdleWaiter = {
        resolve,
        reject,
        signal: cancellation.kind === 'abort_signal' ? cancellation.signal : null,
        onAbort: null,
        timer: setTimeout(() => {
          this.idleWaiters.delete(waiter);
          this.removeWaiterAbortListener(waiter);
          reject(
            new WebAuthnPromptCoordinatorError(
              'webauthn_prompt_reservation_expired',
              'WebAuthn prompt reservation expired while waiting for the coordinator',
            ),
          );
        }, timeoutMs),
      };
      if (waiter.signal) {
        waiter.onAbort = () => {
          this.idleWaiters.delete(waiter);
          clearTimeout(waiter.timer);
          this.removeWaiterAbortListener(waiter);
          reject(new Error('WebAuthn prompt reservation acquisition cancelled'));
        };
        waiter.signal.addEventListener('abort', waiter.onAbort, { once: true });
      }
      this.idleWaiters.add(waiter);
    });
  }

  private notifyIdle(): void {
    for (const waiter of this.idleWaiters) {
      clearTimeout(waiter.timer);
      this.removeWaiterAbortListener(waiter);
      waiter.resolve();
    }
    this.idleWaiters.clear();
  }

  private armReservationExpiry(reservation: ReservedRegistrationWebAuthnPrompt): void {
    this.clearReservationExpiry();
    this.reservationExpiryTimer = setTimeout(
      this.releaseReservation.bind(this, reservation),
      Math.max(1, reservation.expiresAtMs - Date.now()),
    );
  }

  private clearReservationExpiry(): void {
    if (this.reservationExpiryTimer === null) return;
    clearTimeout(this.reservationExpiryTimer);
    this.reservationExpiryTimer = null;
  }

  private throwIfReservationCancelled(cancellation: WebAuthnPromptCancellation): void {
    if (cancellation.kind === 'abort_signal' && cancellation.signal.aborted) {
      throw new Error('WebAuthn prompt reservation acquisition cancelled');
    }
  }

  private removeWaiterAbortListener(waiter: IdleWaiter): void {
    if (!waiter.signal || !waiter.onAbort) return;
    waiter.signal.removeEventListener('abort', waiter.onAbort);
    waiter.onAbort = null;
  }
}

export const webAuthnPromptCoordinator = new WebAuthnPromptCoordinator();
