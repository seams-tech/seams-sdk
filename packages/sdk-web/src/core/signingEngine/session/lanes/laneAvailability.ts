import type { SigningLaneReference } from '@shared/signing-lanes';

export type SigningLaneAvailability =
  | {
      state: 'available';
      lane: SigningLaneReference;
      unavailableReason?: never;
    }
  | {
      state: 'unavailable';
      lane: SigningLaneReference;
      unavailableReason:
        | 'missing_holder_share'
        | 'missing_server_share'
        | 'revoked'
        | 'expired'
        | 'pending_rotation';
    };
