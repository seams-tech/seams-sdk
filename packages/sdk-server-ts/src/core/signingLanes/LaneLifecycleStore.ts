import type {
  AggregateLaneActivationReceiptV1,
  AggregateLaneRevocationReceiptV1,
  CommitLaneEnrollmentActivationV1,
  LaneEnrollmentLifecycleV1,
  LaneEnrollmentManifestV1,
  LaneProductEpochRecordV1,
  LaneProtocolLifecycle,
  LaneProtocolRecordV1,
  LaneProtocolCasResultV1,
  RevokeLaneEnrollmentV1,
  LaneProtocolCommitReceiptV1,
  LaneHolderDeliveryReceiptV1,
  LaneServerActivationReceiptV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import type {
  LaneEnrollmentId,
  LaneOperationId,
  LaneShareEpoch,
  SigningLaneId,
  WalletKeyId,
} from '@shared/signing-lanes';
import type { MpcMaterialActivationRef, WalletId } from '@shared/utils/domainIds';

/** A version is monotonic inside one immutable protocol or enrollment row. */
export type LaneVersionedRecord<T> = {
  readonly version: number;
  readonly commandDigestB64u: string;
  readonly value: T;
};

export type LaneEnrollmentAdmissionRecord = LaneVersionedRecord<{
  readonly manifest: LaneEnrollmentManifestV1;
  readonly lifecycle: LaneEnrollmentLifecycleV1;
}>;

export type LaneProtocolAdmissionRecord = LaneVersionedRecord<LaneProtocolRecordV1>;

export type LaneAdmissionMutationResult<T> =
  | {
      readonly outcome: 'applied';
      readonly version: number;
      readonly commandDigestB64u: string;
      readonly value: T;
    }
  | {
      readonly outcome: 'replayed';
      readonly version: number;
      readonly commandDigestB64u: string;
      readonly value: T;
    }
  | {
      readonly outcome: 'conflict';
      readonly expectedVersion: number | null;
      readonly actualVersion: number;
      readonly requestedCommandDigestB64u: string;
      readonly storedCommandDigestB64u: string;
    };

export type LaneEnrollmentAdmissionInput = {
  readonly manifest: LaneEnrollmentManifestV1;
  readonly children: readonly LaneProtocolRecordV1[];
  readonly commandDigestB64u: string;
  readonly lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'preparing' }>;
};

export type LaneProtocolAdmissionInput = {
  readonly record: LaneProtocolRecordV1;
  readonly commandDigestB64u: string;
};

export type LaneProtocolLifecycleCasInput = {
  readonly operationId: LaneOperationId;
  readonly expectedVersion: number;
  readonly commandDigestB64u: string;
  readonly lifecycle: LaneProtocolLifecycle;
};

export type LaneEnrollmentLifecycleCasInput = {
  readonly enrollmentId: LaneEnrollmentId;
  readonly expectedVersion: number;
  readonly commandDigestB64u: string;
  readonly lifecycle: LaneEnrollmentLifecycleV1;
};

export type LaneEnrollmentVisibilityCommitResult =
  | {
      readonly outcome: 'applied' | 'replayed';
      readonly version: number;
      readonly commandDigestB64u: string;
      readonly receipt: AggregateLaneActivationReceiptV1;
      readonly lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'active' }>;
      readonly productEpochs: readonly [LaneProductEpochRecordV1, ...LaneProductEpochRecordV1[]];
    }
  | {
      readonly outcome: 'conflict';
      readonly enrollmentId: LaneEnrollmentId;
      readonly expectedVersion: number;
      readonly actualVersion: number;
      readonly requestedCommandDigestB64u: string;
      readonly storedCommandDigestB64u: string;
    };

export type LaneEnrollmentRevocationCommitResult =
  | {
      readonly outcome: 'applied' | 'replayed';
      readonly version: number;
      readonly commandDigestB64u: string;
      readonly receipt: AggregateLaneRevocationReceiptV1;
      readonly lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'revoked' }>;
      readonly productEpochs: readonly [LaneProductEpochRecordV1, ...LaneProductEpochRecordV1[]];
    }
  | {
      readonly outcome: 'conflict';
      readonly enrollmentId: LaneEnrollmentId;
      readonly expectedVersion: number;
      readonly actualVersion: number;
      readonly requestedCommandDigestB64u: string;
      readonly storedCommandDigestB64u: string;
    };

export type LaneProductEpochLookup = {
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
};

export type LaneActiveProductEpochLookup = LaneProductEpochLookup & {
  readonly materialActivation: MpcMaterialActivationRef;
};

export type LaneLock =
  | {
      readonly lockKey: string;
      readonly lockKind: 'wallet_key';
      readonly walletKeyId: WalletKeyId;
      readonly enrollmentId?: never;
      readonly laneId?: never;
      readonly lockId: string;
      readonly acquiredAtMs: number;
      readonly expiresAtMs: number;
    }
  | {
      readonly lockKey: string;
      readonly lockKind: 'enrollment';
      readonly enrollmentId: LaneEnrollmentId;
      readonly walletKeyId?: never;
      readonly laneId?: never;
      readonly lockId: string;
      readonly acquiredAtMs: number;
      readonly expiresAtMs: number;
    };

export type LaneLockResult =
  | { readonly outcome: 'applied'; readonly lock: LaneLock }
  | { readonly outcome: 'replayed'; readonly lock: LaneLock }
  | { readonly outcome: 'conflict'; readonly actual: LaneLock | null };

export interface LaneLockStore {
  acquireWalletKeyLock(input: {
    readonly walletKeyId: WalletKeyId;
    readonly lockId: string;
    readonly ttlMs: number;
    readonly nowMs: number;
  }): Promise<LaneLockResult>;
  acquireEnrollmentLock(input: {
    readonly enrollmentId: LaneEnrollmentId;
    readonly lockId: string;
    readonly ttlMs: number;
    readonly nowMs: number;
  }): Promise<LaneLockResult>;
  releaseLock(input: { readonly lockKey: string; readonly lockId: string }): Promise<boolean>;
}

/**
 * Gateway-owned lane lifecycle persistence. Implementations must perform
 * compare-and-set writes in the database transaction itself; callers cannot
 * turn a read into an authorization decision.
 */
export interface LaneLifecycleStore {
  getEnrollment(enrollmentId: LaneEnrollmentId): Promise<LaneEnrollmentAdmissionRecord | null>;
  getProtocol(operationId: LaneOperationId): Promise<LaneProtocolAdmissionRecord | null>;
  putEnrollmentAdmission(
    input: LaneEnrollmentAdmissionInput,
  ): Promise<LaneAdmissionMutationResult<LaneEnrollmentAdmissionRecord['value']>>;
  putProtocolAdmission(
    input: LaneProtocolAdmissionInput,
  ): Promise<LaneAdmissionMutationResult<LaneProtocolRecordV1>>;
  compareAndSetProtocolLifecycle(
    input: LaneProtocolLifecycleCasInput,
  ): Promise<LaneProtocolCasResultV1>;
  putProtocolCommitReceipt(
    receipt: LaneProtocolCommitReceiptV1,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneProtocolCommitReceiptV1>>;
  putHolderDeliveryReceipt(
    receipt: LaneHolderDeliveryReceiptV1,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneHolderDeliveryReceiptV1>>;
  putServerActivationReceipt(
    receipt: LaneServerActivationReceiptV1,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneServerActivationReceiptV1>>;
  putProductEpochPending(
    productEpoch: Extract<LaneProductEpochRecordV1, { state: 'pending_visibility' }>,
    commandDigestB64u: string,
  ): Promise<LaneAdmissionMutationResult<LaneProductEpochRecordV1>>;
  compareAndSetEnrollmentLifecycle(
    input: LaneEnrollmentLifecycleCasInput,
  ): Promise<LaneAdmissionMutationResult<LaneEnrollmentAdmissionRecord['value']>>;
  getProductEpoch(lookup: LaneProductEpochLookup): Promise<LaneProductEpochRecordV1 | null>;
  getActiveProductEpoch(
    lookup: LaneActiveProductEpochLookup,
  ): Promise<Extract<LaneProductEpochRecordV1, { state: 'active' }> | null>;
  listEnrollmentProductEpochs(
    enrollmentId: LaneEnrollmentId,
  ): Promise<readonly LaneProductEpochRecordV1[]>;
  commitEnrollmentVisibility(
    input: CommitLaneEnrollmentActivationV1,
  ): Promise<LaneEnrollmentVisibilityCommitResult>;
  fenceLaneRevocation(input: RevokeSigningLaneV1): Promise<LaneSigningLaneRevocationMutationResult>;
  fenceEnrollmentRevocation(
    input: RevokeLaneEnrollmentV1,
  ): Promise<LaneAdmissionMutationResult<LaneEnrollmentAdmissionRecord['value']>>;
  commitEnrollmentRevocation(
    input: LaneEnrollmentRevocationCommitInput,
  ): Promise<LaneEnrollmentRevocationCommitResult>;
  commitLaneRevocation(
    input: LaneSigningLaneRevocationCommitInput,
  ): Promise<LaneSigningLaneRevocationMutationResult>;
}

export type LaneSigningLaneRevocationMutationResult =
  | {
      readonly outcome: 'applied' | 'replayed';
      readonly version: number;
      readonly commandDigestB64u: string;
      readonly productEpoch: Extract<LaneProductEpochRecordV1, { state: 'revoked' }>;
    }
  | {
      readonly outcome: 'conflict';
      readonly expectedVersion: number;
      readonly actualVersion: number;
      readonly requestedCommandDigestB64u: string;
      readonly storedCommandDigestB64u: string;
    };

export type LaneSigningLaneRevocationCommitInput = {
  readonly command: RevokeSigningLaneV1;
  readonly expectedVersion: number;
  readonly commandDigestB64u: string;
};

export type LaneEnrollmentRevocationCommitInput = {
  readonly command: {
    readonly kind: 'commit_lane_enrollment_revocation_v1';
    readonly enrollmentId: LaneEnrollmentId;
    readonly walletId: WalletId;
    readonly manifestDigestB64u: string;
    readonly receipt: AggregateLaneRevocationReceiptV1;
    readonly revokedAtMs: number;
  };
  readonly expectedVersion: number;
  readonly commandDigestB64u: string;
};

export function protocolCasResultToAdmissionResult(
  result: LaneProtocolCasResultV1,
): LaneAdmissionMutationResult<LaneProtocolRecordV1> {
  if (result.outcome === 'conflict') {
    return {
      outcome: 'conflict',
      expectedVersion: result.expectedVersion,
      actualVersion: result.actualVersion,
      requestedCommandDigestB64u: result.requestedCommandDigestB64u,
      storedCommandDigestB64u: result.storedCommandDigestB64u,
    };
  }
  return {
    outcome: result.outcome,
    version: result.version,
    commandDigestB64u: result.commandDigestB64u,
    value: result.record,
  };
}

export function assertNonEmptyVersion(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}
