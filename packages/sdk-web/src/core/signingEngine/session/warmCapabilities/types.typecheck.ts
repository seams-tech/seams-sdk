import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaSessionProvisionPlan } from './ecdsaProvisionPlan';
import type {
  ApplyWarmEcdsaPostSignPolicyArgs,
  AssertWarmEcdsaOperationAllowedArgs,
  EnsureWarmEcdsaProvisionPlanReadyArgs,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionEcdsaCapabilityRef,
  WarmSessionPrfClaim,
} from './types';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';

type FreshEcdsaSessionProvisionPlan = Extract<
  EcdsaSessionProvisionPlan,
  { kind: 'passkey_ecdsa_session_provision' | 'email_otp_ecdsa_session_provision' }
>;
type PasskeyEcdsaSessionProvisionPlan = Extract<
  EcdsaSessionProvisionPlan,
  { kind: 'passkey_ecdsa_session_provision' }
>;
type EmailOtpEcdsaSessionProvisionPlan = Extract<
  EcdsaSessionProvisionPlan,
  { kind: 'email_otp_ecdsa_session_provision' }
>;
type ReconnectEcdsaSessionProvisionPlan = Extract<
  EcdsaSessionProvisionPlan,
  { kind: 'wallet_session_ecdsa_reconnect' }
>;
type PresentWarmSessionEcdsaCapabilityState = Exclude<
  WarmSessionEcdsaCapabilityState,
  { state: 'missing' }
>;
type WarmPrfClaim = Extract<WarmSessionPrfClaim, { state: 'warm' }>;
type UnavailablePrfClaim = Extract<WarmSessionPrfClaim, { state: 'unavailable' }>;

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const freshPlan: FreshEcdsaSessionProvisionPlan;
declare const passkeyFreshPlan: PasskeyEcdsaSessionProvisionPlan;
declare const emailOtpFreshPlan: EmailOtpEcdsaSessionProvisionPlan;
declare const reconnectPlan: ReconnectEcdsaSessionProvisionPlan;
declare const selectedRecord: ThresholdEcdsaSessionRecord;
declare const selectedEd25519Record: ThresholdEd25519SessionRecord;
declare const keyRef: ThresholdEcdsaSecp256k1KeyRef;
declare const exactEcdsaLane: ExactEcdsaSigningLaneIdentity;
declare const ecdsaCapabilityKey: PresentWarmSessionEcdsaCapabilityState['key'];
declare const ecdsaCapabilityLane: PresentWarmSessionEcdsaCapabilityState['lane'];
declare const warmPrfClaim: WarmPrfClaim;
declare const unavailablePrfClaim: UnavailablePrfClaim;

const validEnsureWarmEcdsaProvisionPlanReadyArgs = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  record: selectedRecord,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void validEnsureWarmEcdsaProvisionPlanReadyArgs;

const validEnsureWarmEcdsaProvisionPlanReadyArgsWithFreshPlan = {
  walletId,
  chainTarget,
  plan: emailOtpFreshPlan,
  record: null,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void validEnsureWarmEcdsaProvisionPlanReadyArgsWithFreshPlan;

const validEnsureWarmEcdsaProvisionPlanReadyArgsWithPasskeyPlan = {
  walletId,
  chainTarget,
  plan: passkeyFreshPlan,
  record: selectedRecord,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void validEnsureWarmEcdsaProvisionPlanReadyArgsWithPasskeyPlan;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithPasskeyNullRecord = {
  walletId,
  chainTarget,
  plan: passkeyFreshPlan,
  record: null,
  source: 'login',
  sessionBudgetUses: 1,
  // @ts-expect-error passkey ECDSA readiness requires an exact ECDSA record.
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithPasskeyNullRecord;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithReconnectNullRecord = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  record: null,
  source: 'login',
  sessionBudgetUses: 1,
  // @ts-expect-error reconnect readiness requires an exact ECDSA record.
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithReconnectNullRecord;

void freshPlan;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithSubjectId = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  record: selectedRecord,
  source: 'login',
  sessionBudgetUses: 1,
  // @ts-expect-error base-ECDSA provision readiness derives subject from shared key identity.
  subjectId: 'wallet',
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithSubjectId;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithRawWalletId = {
  // @ts-expect-error ECDSA provision readiness requires a normalized WalletId.
  walletId: 'wallet.testnet',
  chainTarget,
  plan: reconnectPlan,
  record: selectedRecord,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithRawWalletId;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithKeyRef = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  record: selectedRecord,
  source: 'login',
  sessionBudgetUses: 1,
  // @ts-expect-error ECDSA provision readiness derives key refs from the selected record.
  keyRef,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithKeyRef;

const validWarmSessionEcdsaCapabilityRef = {
  walletId,
  chainTarget,
  thresholdSessionId: 'threshold-session-id',
} satisfies WarmSessionEcdsaCapabilityRef;
void validWarmSessionEcdsaCapabilityRef;

const invalidWarmSessionEcdsaCapabilityRefWithRawWalletId = {
  // @ts-expect-error ECDSA capability refs require a normalized WalletId.
  walletId: 'wallet.testnet',
  chainTarget,
  thresholdSessionId: 'threshold-session-id',
} satisfies WarmSessionEcdsaCapabilityRef;
void invalidWarmSessionEcdsaCapabilityRefWithRawWalletId;

const validApplyWarmEcdsaPostSignPolicyArgs = {
  lane: exactEcdsaLane,
  selectedRecord,
} satisfies ApplyWarmEcdsaPostSignPolicyArgs;
void validApplyWarmEcdsaPostSignPolicyArgs;

const invalidApplyWarmEcdsaPostSignPolicyArgsWithRawWalletId = {
  lane: exactEcdsaLane,
  selectedRecord,
  // @ts-expect-error ECDSA post-sign policy receives exact lane identity only.
  walletId,
} satisfies ApplyWarmEcdsaPostSignPolicyArgs;
void invalidApplyWarmEcdsaPostSignPolicyArgsWithRawWalletId;

const validAssertWarmEcdsaOperationAllowedArgs = {
  lane: exactEcdsaLane,
  operationLabel: 'threshold-ecdsa sign',
  source: 'login',
} satisfies AssertWarmEcdsaOperationAllowedArgs;
void validAssertWarmEcdsaOperationAllowedArgs;

const invalidAssertWarmEcdsaOperationAllowedArgsWithRawWalletId = {
  lane: exactEcdsaLane,
  operationLabel: 'threshold-ecdsa sign',
  source: 'login',
  // @ts-expect-error ECDSA operation checks receive exact lane identity only.
  walletId,
} satisfies AssertWarmEcdsaOperationAllowedArgs;
void invalidAssertWarmEcdsaOperationAllowedArgsWithRawWalletId;

const invalidReadyEd25519CapabilityWithoutJwt = {
  capability: 'ed25519',
  record: selectedEd25519Record,
  auth: {
    capability: 'ed25519',
    record: selectedEd25519Record,
    walletSessionJwtSource: 'none',
  },
  prfClaim: warmPrfClaim,
  state: 'ready',
  // @ts-expect-error ready Ed25519 warm-session capability requires bearer Wallet Session auth.
} satisfies WarmSessionEd25519CapabilityState;
void invalidReadyEd25519CapabilityWithoutJwt;

const invalidEcdsaCapabilityInvalidState = {
  capability: 'ecdsa',
  record: selectedRecord,
  key: ecdsaCapabilityKey,
  lane: ecdsaCapabilityLane,
  auth: {
    capability: 'ecdsa',
    state: 'ready',
    record: selectedRecord,
    walletSessionJwt: 'wallet-session-jwt',
    walletSessionJwtSource: 'ecdsa_record',
  },
  prfClaim: warmPrfClaim,
  // @ts-expect-error ECDSA warm-session capability states do not have an invalid branch.
  state: 'invalid',
} satisfies WarmSessionEcdsaCapabilityState;
void invalidEcdsaCapabilityInvalidState;

const invalidReadyEcdsaCapabilityWithoutWarmPrf = {
  capability: 'ecdsa',
  record: selectedRecord,
  key: ecdsaCapabilityKey,
  lane: ecdsaCapabilityLane,
  auth: {
    capability: 'ecdsa',
    state: 'ready',
    record: selectedRecord,
    walletSessionJwt: 'wallet-session-jwt',
    walletSessionJwtSource: 'ecdsa_record',
  },
  prfClaim: unavailablePrfClaim,
  state: 'ready',
  // @ts-expect-error ready ECDSA warm-session capability requires a warm PRF claim.
} satisfies WarmSessionEcdsaCapabilityState;
void invalidReadyEcdsaCapabilityWithoutWarmPrf;
