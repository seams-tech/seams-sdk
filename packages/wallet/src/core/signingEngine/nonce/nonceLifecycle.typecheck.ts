import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SigningSessionIds } from '../session/operationState/types';
import {
  NonceLeaseState,
  type EvmNonceLease,
  type NonceCoordinator,
} from './nonceTypes';
import { tryReduceNonceLeaseState, type NonceLeaseTransition } from './nonceLeaseState';
import type { NearNonceLaneLifecycle } from './nearNonceLane';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
});
const walletId = toWalletId('frost-vermillion-k7p9m2');
const operationId = SigningSessionIds.signingOperation('nonce-lifecycle-operation');
const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
  'nonce-lifecycle-fingerprint',
);

const reservedEvmLease: EvmNonceLease = {
  leaseId: 'lease-reserved',
  operationId,
  operationFingerprint,
  reservedAtMs: 1,
  expiresAtMs: 2,
  lane: {
    family: 'evm',
    chainTarget,
    subjectId: walletId,
    sender: `0x${'11'.repeat(20)}`,
  },
  nonce: 7n,
  state: NonceLeaseState.Reserved,
};
void reservedEvmLease;

const acceptedTransition = tryReduceNonceLeaseState(NonceLeaseState.Reserved, 'mark_signed');
if (acceptedTransition.ok) {
  const acceptedState: NonceLeaseState = acceptedTransition.state;
  void acceptedState;
}

const rejectedTransition = tryReduceNonceLeaseState(
  NonceLeaseState.Reserved,
  'broadcast_accepted',
);
if (!rejectedTransition.ok) {
  const reason: 'illegal_transition' = rejectedTransition.reason;
  void reason;
}

// @ts-expect-error unknown transitions cannot enter nonce lifecycle reducers.
const invalidTransition: NonceLeaseTransition = 'broadcast_pending';
void invalidTransition;

const invalidLeaseState: EvmNonceLease = {
  ...reservedEvmLease,
  // @ts-expect-error nonce lease lifecycle state is a closed union.
  state: 'pending',
};
void invalidLeaseState;

// @ts-expect-error Broadcast acceptance always carries the chain transaction identity.
const broadcastAcceptanceWithoutTxHash: Parameters<
  NonceCoordinator['markBroadcastAccepted']
>[0] = {
  leaseId: 'lease-without-tx-hash',
  operationId,
  operationFingerprint,
};
void broadcastAcceptanceWithoutTxHash;

const uninitializedNearLane: NearNonceLaneLifecycle = {
  kind: 'uninitialized',
};
void uninitializedNearLane;

const accessKeyBoundNearLane: NearNonceLaneLifecycle = {
  kind: 'access_key_bound',
  subject: {
    walletId: 'frost-vermillion-k7p9m2',
    nearAccountId: 'a'.repeat(64),
    publicKey: 'ed25519:public-key',
  },
  context: { kind: 'missing' },
};
void accessKeyBoundNearLane;

const invalidUninitializedNearLane: NearNonceLaneLifecycle = {
  kind: 'uninitialized',
  // @ts-expect-error uninitialized NEAR lanes cannot carry access-key identity.
  subject: {
    walletId: 'frost-vermillion-k7p9m2',
    nearAccountId: 'a'.repeat(64),
    publicKey: 'ed25519:public-key',
  },
};
void invalidUninitializedNearLane;

const invalidImplicitNearLane: NearNonceLaneLifecycle = {
  kind: 'implicit_unfunded',
  subject: {
    walletId: 'frost-vermillion-k7p9m2',
    nearAccountId: 'a'.repeat(64),
    publicKey: 'ed25519:public-key',
  },
  readiness: {
    kind: 'implicit_unfunded',
    walletId: 'frost-vermillion-k7p9m2',
    nearAccountId: 'a'.repeat(64),
    nearPublicKeyStr: 'ed25519:public-key',
  },
  // @ts-expect-error implicit-unfunded lanes cannot carry a ready transaction context.
  context: { kind: 'missing' },
};
void invalidImplicitNearLane;
