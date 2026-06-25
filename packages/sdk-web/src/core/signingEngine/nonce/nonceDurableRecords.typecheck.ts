import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SigningSessionIds } from '../session/operationState/types';
import {
  NonceDurableLeaseState,
  NonceLeaseState,
  type EvmNonceLease,
  type NearNonceLease,
  type NonceLaneCoordinationRecord,
} from './nonceTypes';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
});
const walletId = toWalletId('wallet.testnet');
const operationId = SigningSessionIds.signingOperation('nonce-typecheck-operation');
const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
  'nonce-typecheck-fingerprint',
);

const validEvmRecord: NonceLaneCoordinationRecord = {
  v: 1,
  laneKey: 'evm|tempo|42431|wallet.testnet|0x1111111111111111111111111111111111111111',
  leaseId: 'lease-1',
  networkKey: 'tempo-moderato',
  nonce: 7n,
  state: NonceDurableLeaseState.Reserved,
  operationId,
  operationFingerprint,
  reservedAtMs: 1,
  expiresAtMs: 2,
  updatedAtMs: 1,
  family: 'evm',
  chainTarget,
  accountId: walletId,
  sender: `0x${'11'.repeat(20)}`,
};
void validEvmRecord;

// @ts-expect-error EVM durable records require the concrete threshold chain target.
const evmRecordWithoutChainTarget: NonceLaneCoordinationRecord = {
  v: 1,
  laneKey: 'evm|tempo|42431|wallet.testnet|0x1111111111111111111111111111111111111111',
  leaseId: 'lease-2',
  networkKey: 'tempo-moderato',
  nonce: 7n,
  state: NonceDurableLeaseState.Reserved,
  operationId,
  operationFingerprint,
  reservedAtMs: 1,
  expiresAtMs: 2,
  updatedAtMs: 1,
  family: 'evm',
  accountId: walletId,
  sender: `0x${'11'.repeat(20)}`,
};
void evmRecordWithoutChainTarget;

const durableRecordWithStringNonce: NonceLaneCoordinationRecord = {
  v: 1,
  laneKey: 'evm|tempo|42431|wallet.testnet|0x1111111111111111111111111111111111111111',
  leaseId: 'lease-3',
  networkKey: 'tempo-moderato',
  // @ts-expect-error internal durable records carry parsed bigint nonces.
  nonce: '7',
  state: NonceDurableLeaseState.Reserved,
  operationId,
  operationFingerprint,
  reservedAtMs: 1,
  expiresAtMs: 2,
  updatedAtMs: 1,
  family: 'evm',
  chainTarget,
  accountId: walletId,
  sender: `0x${'11'.repeat(20)}`,
};
void durableRecordWithStringNonce;

const nearRecordWithNonceKey: NonceLaneCoordinationRecord = {
  v: 1,
  laneKey: 'near|testnet|wallet.testnet|a'.repeat(64) + '|ed25519:public-key',
  leaseId: 'lease-4',
  networkKey: 'testnet',
  nonce: 7n,
  state: NonceDurableLeaseState.Reserved,
  operationId,
  operationFingerprint,
  reservedAtMs: 1,
  expiresAtMs: 2,
  updatedAtMs: 1,
  family: 'near',
  walletId: 'wallet.testnet',
  nearAccountId: 'a'.repeat(64),
  publicKey: 'ed25519:public-key',
  // @ts-expect-error NEAR durable records do not carry EVM nonce keys.
  nonceKey: 7n,
};
void nearRecordWithNonceKey;

const evmLeaseWithStringNonce: EvmNonceLease = {
  leaseId: 'lease-5',
  operationId,
  operationFingerprint,
  state: NonceLeaseState.Reserved,
  reservedAtMs: 1,
  expiresAtMs: 2,
  lane: {
    family: 'evm',
    chainTarget,
    subjectId: walletId,
    sender: `0x${'11'.repeat(20)}`,
  },
  // @ts-expect-error EVM leases carry bigint nonces.
  nonce: '7',
};
void evmLeaseWithStringNonce;

const nearLeaseWithBigintNonce: NearNonceLease = {
  leaseId: 'lease-6',
  operationId,
  operationFingerprint,
  state: NonceLeaseState.Reserved,
  reservedAtMs: 1,
  expiresAtMs: 2,
	  lane: {
	    family: 'near',
	    networkKey: 'testnet',
	    walletId: 'wallet.testnet',
	    nearAccountId: 'a'.repeat(64),
	    publicKey: 'ed25519:public-key',
	  },
  // @ts-expect-error NEAR leases carry RPC string nonces.
  nonce: 7n,
};
void nearLeaseWithBigintNonce;
