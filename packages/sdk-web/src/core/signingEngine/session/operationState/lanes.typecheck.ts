import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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

// @ts-expect-error keyHandle is required for Email OTP ECDSA session reads.
deps.readEmailOtpEcdsaSessionRecord?.({
  walletId,
  chainTarget,
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
});

// @ts-expect-error walletSigningSessionId is required for passkey ECDSA session reads.
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

const validEcdsaCapabilityResult = {
  ok: true,
  lane: {} as any,
  capability: {
    curve: 'ecdsa',
    record: {} as any,
  },
} satisfies EcdsaCapabilitySuccessResult;
void validEcdsaCapabilityResult;

const invalidEcdsaCapabilityResultWithKeyRef = {
  ok: true,
  lane: {} as any,
  capability: {
    curve: 'ecdsa',
    record: {} as any,
  },
  // @ts-expect-error ECDSA capability success rejects key refs.
  keyRef: {},
} satisfies EcdsaCapabilitySuccessResult;
void invalidEcdsaCapabilityResultWithKeyRef;

const invalidEd25519CapabilityResultWithKeyRef = {
  ok: true,
  lane: {} as any,
  capability: {
    curve: 'ed25519',
    record: {} as any,
  },
  // @ts-expect-error Ed25519 capability success rejects keyRef.
  keyRef: {},
} satisfies Ed25519CapabilitySuccessResult;
void invalidEd25519CapabilityResultWithKeyRef;
