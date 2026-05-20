import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { SigningCapabilityReaderDeps, SigningCapabilityResult } from './lanes';

declare const deps: SigningCapabilityReaderDeps;
declare const walletId: AccountId;
declare const chainTarget: ThresholdEcdsaChainTarget;

deps.readEmailOtpEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
});

deps.readPasskeyEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  storageSource: 'login',
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
});

deps.readEmailOtpEcdsaKeyRef?.({
  walletId,
  chainTarget,
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
});

deps.readPasskeyEcdsaKeyRef?.({
  walletId,
  chainTarget,
  storageSource: 'registration',
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
});

// @ts-expect-error keyHandle is required for Email OTP ECDSA session reads.
deps.readEmailOtpEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
});

// @ts-expect-error walletSigningSessionId is required for passkey ECDSA key-ref reads.
deps.readPasskeyEcdsaKeyRef?.({
  walletId,
  chainTarget,
  storageSource: 'manual-bootstrap',
  keyHandle: 'key-handle-1',
  thresholdSessionId: 'threshold-session-id',
});

declare const ecdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
type EcdsaCapabilitySuccessResult = Extract<
  SigningCapabilityResult,
  { ok: true; capability: { curve: 'ecdsa' } }
>;
type Ed25519CapabilitySuccessResult = Extract<
  SigningCapabilityResult,
  { ok: true; capability: { curve: 'ed25519' } }
>;

const validEcdsaCapabilityResult = {
  ok: true,
  lane: {} as any,
  capability: {
    curve: 'ecdsa',
    record: {} as any,
  },
  keyRef: ecdsaKeyRef,
} satisfies EcdsaCapabilitySuccessResult;
void validEcdsaCapabilityResult;

const invalidEcdsaCapabilityResultWithoutKeyRef = {
  ok: true,
  lane: {} as any,
  capability: {
    curve: 'ecdsa',
    record: {} as any,
  },
} as const;
// @ts-expect-error ECDSA capability success requires keyRef.
const typedInvalidEcdsaCapabilityResultWithoutKeyRef: EcdsaCapabilitySuccessResult =
  invalidEcdsaCapabilityResultWithoutKeyRef;
void typedInvalidEcdsaCapabilityResultWithoutKeyRef;
void invalidEcdsaCapabilityResultWithoutKeyRef;

const invalidEd25519CapabilityResultWithKeyRef = {
  ok: true,
  lane: {} as any,
  capability: {
    curve: 'ed25519',
    record: {} as any,
  },
  // @ts-expect-error Ed25519 capability success rejects keyRef.
  keyRef: ecdsaKeyRef,
} satisfies Ed25519CapabilitySuccessResult;
void invalidEd25519CapabilityResultWithKeyRef;
