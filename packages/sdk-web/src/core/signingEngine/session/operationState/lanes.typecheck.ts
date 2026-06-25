import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningCapabilityReaderDeps, SigningCapabilityResult } from './lanes';

declare const deps: SigningCapabilityReaderDeps;
declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;

deps.readEmailOtpEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
  signingGrantId: 'signing-grant-id',
});

deps.readPasskeyEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  storageSource: 'login',
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
  signingGrantId: 'signing-grant-id',
});

// @ts-expect-error keyHandle is required for Email OTP ECDSA session reads.
deps.readEmailOtpEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  thresholdSessionId: 'threshold-session-id',
  signingGrantId: 'signing-grant-id',
});

// @ts-expect-error signingGrantId is required for passkey ECDSA session reads.
deps.readPasskeyEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  storageSource: 'manual-bootstrap',
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
});

type EcdsaCapabilitySuccessResult = Extract<
  SigningCapabilityResult,
  { ok: true; capability: { curve: 'ecdsa' } }
>;
type Ed25519CapabilitySuccessResult = Extract<
  SigningCapabilityResult,
  { ok: true; capability: { curve: 'ed25519' } }
>;

declare const ecdsaLane: EcdsaCapabilitySuccessResult['lane'];
declare const ecdsaRecord: EcdsaCapabilitySuccessResult['capability']['record'];
declare const ed25519Lane: Ed25519CapabilitySuccessResult['lane'];
declare const ed25519Record: Ed25519CapabilitySuccessResult['capability']['record'];

const validEcdsaCapabilityResult = {
  ok: true,
  lane: ecdsaLane,
  capability: {
    curve: 'ecdsa',
    record: ecdsaRecord,
  },
} satisfies EcdsaCapabilitySuccessResult;
void validEcdsaCapabilityResult;

const invalidEcdsaCapabilityResultWithKeyRef = {
  ok: true,
  lane: ecdsaLane,
  capability: {
    curve: 'ecdsa',
    record: ecdsaRecord,
  },
  // @ts-expect-error ECDSA capability success rejects key refs.
  keyRef: {},
} satisfies EcdsaCapabilitySuccessResult;
void invalidEcdsaCapabilityResultWithKeyRef;

const invalidEd25519CapabilityResultWithKeyRef = {
  ok: true,
  lane: ed25519Lane,
  capability: {
    curve: 'ed25519',
    record: ed25519Record,
  },
  // @ts-expect-error Ed25519 capability success rejects keyRef.
  keyRef: {},
} satisfies Ed25519CapabilitySuccessResult;
void invalidEd25519CapabilityResultWithKeyRef;
