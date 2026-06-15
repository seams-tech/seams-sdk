import type {
  DelegatedIdempotencyKey,
  DelegatedIntentDigest,
  LaneShareEpoch,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';

export type DelegatedBudgetReservationRecord = {
  kind: 'delegated_budget_reservation_v1';
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  idempotencyKey: DelegatedIdempotencyKey;
  intentDigest: DelegatedIntentDigest;
  amountAtomic: string;
  assetId: string;
  status: 'reserved' | 'committed' | 'released';
  createdAtMs: number;
  updatedAtMs: number;
};

export interface DelegatedBudgetReservationStore {
  getReservation(args: {
    walletKeyId: WalletKeyId;
    laneId: SigningLaneId;
    idempotencyKey: DelegatedIdempotencyKey;
  }): Promise<DelegatedBudgetReservationRecord | null>;
  putReservation(record: DelegatedBudgetReservationRecord): Promise<void>;
}
