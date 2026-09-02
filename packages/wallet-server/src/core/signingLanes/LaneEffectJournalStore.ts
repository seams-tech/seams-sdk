import type {
  LaneEnrollmentId,
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

export type LaneEffectKind =
  | 'activate_server_material'
  | 'retire_server_material'
  | 'invalidate_holder_material';

export type LaneEffectStatus = 'recorded' | 'confirmed';

type LaneEffectRecordBaseV1 = {
  readonly kind: 'lane_effect_record_v1';
  readonly effectId: string;
  readonly enrollmentId: LaneEnrollmentId;
  readonly operationId: LaneOperationId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly effectKind: LaneEffectKind;
  readonly requestDigestB64u: string;
  readonly recordedAtMs: number;
};

/** Effect metadata only. Ciphertexts and private material never cross this port. */
export type LaneEffectRecordV1 =
  | (LaneEffectRecordBaseV1 & {
      readonly status: 'recorded';
      readonly responseDigestB64u?: never;
      readonly confirmedAtMs?: never;
    })
  | (LaneEffectRecordBaseV1 & {
      readonly status: 'confirmed';
      readonly responseDigestB64u: string;
      readonly confirmedAtMs: number;
    });

export type LaneEffectMutation = {
  readonly record: LaneEffectRecordV1;
  readonly commandDigestB64u: string;
};

export type LaneEffectMutationResult =
  | {
      readonly outcome: 'applied' | 'replayed';
      readonly version: number;
      readonly commandDigestB64u: string;
      readonly record: LaneEffectRecordV1;
    }
  | {
      readonly outcome: 'conflict';
      readonly expectedVersion: number | null;
      readonly actualVersion: number;
      readonly requestedCommandDigestB64u: string;
      readonly storedCommandDigestB64u: string;
    };

export type LaneEffectLookup = {
  readonly effectId: string;
};

export interface LaneEffectJournalStore {
  getEffect(lookup: LaneEffectLookup): Promise<{
    readonly version: number;
    readonly commandDigestB64u: string;
    readonly record: LaneEffectRecordV1;
  } | null>;
  recordEffect(input: LaneEffectMutation): Promise<LaneEffectMutationResult>;
  confirmEffect(input: {
    readonly effectId: string;
    readonly expectedVersion: number;
    readonly commandDigestB64u: string;
    readonly responseDigestB64u: string;
    readonly confirmedAtMs: number;
  }): Promise<LaneEffectMutationResult>;
}
