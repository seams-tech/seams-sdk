import type { SigningOperationId } from '../../session/signingSession/types';
import type { SelectedLane } from '../../session/identity/laneIdentity';

export type OperationIntent =
  | {
      kind: 'transaction_sign';
      reason: string;
    }
  | {
      kind: 'key_export';
      reason: string;
      freshAuthRequired: true;
    };

export type SigningReadyState = {
  status: 'ready';
  remainingUses: number;
  expiresAtMs: number;
};

export type OperationAuthPlan =
  | { kind: 'not_required' }
  | { kind: 'passkey_reauth'; reason: string }
  | { kind: 'email_otp_reauth'; reason: string }
  | { kind: 'unavailable'; reason: string };

export type ReadyLane<TLane extends SelectedLane = SelectedLane> = {
  kind: 'ready_lane';
  lane: TLane;
  readiness: SigningReadyState;
};

export type ReauthRequired<TLane extends SelectedLane = SelectedLane> = {
  kind: 'reauth_required';
  lane: TLane;
  plan: Exclude<OperationAuthPlan, { kind: 'not_required' }>;
};

export type LaneReadiness<TLane extends SelectedLane = SelectedLane> =
  | ReadyLane<TLane>
  | ReauthRequired<TLane>;

export type PreparedOperation<TLane extends SelectedLane = SelectedLane> = {
  kind: 'prepared_operation';
  operationId: SigningOperationId;
  intent: OperationIntent;
  lane: TLane;
  readiness: LaneReadiness<TLane>;
  authPlan: OperationAuthPlan;
  availableLanesGeneration: number;
};
