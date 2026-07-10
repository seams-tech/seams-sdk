import type {
  WebAuthnPromptCoordinatorState,
  WebAuthnPromptOperationId,
  WebAuthnPromptReservationId,
  ReservedRegistrationWebAuthnPrompt,
} from './webauthnPromptCoordinator';
import type { RegistrationActivationMessageIdentity } from '@/SeamsWeb/publicApi/types';

declare const identity: RegistrationActivationMessageIdentity;
declare const reservationId: WebAuthnPromptReservationId;
declare const operationId: WebAuthnPromptOperationId;

const reservation: ReservedRegistrationWebAuthnPrompt = {
  kind: 'reserved_registration_webauthn_prompt_v1',
  reservationId,
  owner: { kind: 'registration_activation', identity },
  expiresAtMs: 1_900_000_000_000,
};

const validReservedState: WebAuthnPromptCoordinatorState = {
  kind: 'reserved',
  reservation,
};
void validReservedState;

// @ts-expect-error reserved state cannot also carry a running operation.
const invalidReservedState: WebAuthnPromptCoordinatorState = {
  kind: 'reserved',
  reservation,
  operationId,
};
void invalidReservedState;

// @ts-expect-error running state cannot retain a reservation.
const invalidRunningState: WebAuthnPromptCoordinatorState = {
  kind: 'running',
  operationId,
  owner: { kind: 'registration_activation', identity },
  reservation,
};
void invalidRunningState;

export {};
