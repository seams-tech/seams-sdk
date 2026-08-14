import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaSessionProvisionPlan } from './ecdsaProvisionPlan';
import type {
  EnsureWarmEcdsaProvisionPlanReadyArgs,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionPrfClaim,
} from './types';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ExactEd25519SealedSessionRuntime } from './ed25519SealedSessionRuntime';

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
declare const exactEd25519Runtime: ExactEd25519SealedSessionRuntime;
declare const keyRef: ThresholdEcdsaSecp256k1KeyRef;
declare const presentEcdsaCapability: PresentWarmSessionEcdsaCapabilityState;
declare const activeEcdsaManifest: NonNullable<PresentWarmSessionEcdsaCapabilityState['manifest']>;
declare const exactEcdsaRuntime: NonNullable<PresentWarmSessionEcdsaCapabilityState['runtime']>;
declare const activeEcdsaAuthorization: NonNullable<
  Extract<WarmSessionEcdsaCapabilityState, { state: 'ready' }>['auth']
>;
declare const missingEcdsaCapability: Extract<WarmSessionEcdsaCapabilityState, { state: 'missing' }>;
declare const ecdsaCapabilityKey: NonNullable<PresentWarmSessionEcdsaCapabilityState['key']>;
declare const ecdsaCapabilityLane: NonNullable<PresentWarmSessionEcdsaCapabilityState['lane']>;
declare const warmPrfClaim: WarmPrfClaim;
declare const unavailablePrfClaim: UnavailablePrfClaim;

// @ts-expect-error material key references never carry session transport kind.
keyRef.thresholdSessionKind;
// @ts-expect-error material key references never carry an MPC session alias.
keyRef.mpcSessionId;
// @ts-expect-error material key references never carry threshold-session identity.
keyRef.thresholdSessionId;

const validEnsureWarmEcdsaProvisionPlanReadyArgs = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  capability: presentEcdsaCapability,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void validEnsureWarmEcdsaProvisionPlanReadyArgs;

const validEnsureWarmEcdsaProvisionPlanReadyArgsWithFreshPlan = {
  walletId,
  chainTarget,
  plan: emailOtpFreshPlan,
  capability: presentEcdsaCapability,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void validEnsureWarmEcdsaProvisionPlanReadyArgsWithFreshPlan;

const validEnsureWarmEcdsaProvisionPlanReadyArgsWithPasskeyPlan = {
  walletId,
  chainTarget,
  plan: passkeyFreshPlan,
  capability: presentEcdsaCapability,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void validEnsureWarmEcdsaProvisionPlanReadyArgsWithPasskeyPlan;

// Material presence is now the capability state's own discriminant, so a
// missing capability cannot be passed where readiness expects resolved material.
const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithMissingCapability = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  capability: missingEcdsaCapability,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithMissingCapability;

void freshPlan;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithSubjectId = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  capability: presentEcdsaCapability,
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
  capability: presentEcdsaCapability,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithRawWalletId;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithKeyRef = {
  walletId,
  chainTarget,
  plan: reconnectPlan,
  capability: presentEcdsaCapability,
  source: 'login',
  sessionBudgetUses: 1,
  // @ts-expect-error ECDSA provision readiness derives key refs from the selected record.
  keyRef,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithKeyRef;

const invalidReadyEd25519CapabilityWithoutJwt = {
  capability: 'ed25519',
  runtime: exactEd25519Runtime,
  auth: null,
  prfClaim: warmPrfClaim,
  state: 'ready',
  // @ts-expect-error ready Ed25519 warm-session capability requires active authorization.
} satisfies WarmSessionEd25519CapabilityState;
void invalidReadyEd25519CapabilityWithoutJwt;

// The four canonical ECDSA read-model outcomes, pinned at compile time.

const missingEcdsaCapabilityState = {
  capability: 'ecdsa',
  manifest: null,
  runtime: null,
  key: null,
  lane: null,
  auth: null,
  prfClaim: null,
  state: 'missing',
} satisfies WarmSessionEcdsaCapabilityState;
void missingEcdsaCapabilityState;

// A manifest and a sealed record that disagree is present-but-unusable, and
// carries the typed correlation reason rather than collapsing into 'missing'.
const invalidEcdsaCapabilityState = {
  capability: 'ecdsa',
  manifest: null,
  runtime: null,
  key: null,
  lane: null,
  auth: null,
  prfClaim: null,
  invalidReason: 'binding_mismatch',
  state: 'invalid',
} satisfies WarmSessionEcdsaCapabilityState;
void invalidEcdsaCapabilityState;

const invalidStateWithoutReason = {
  capability: 'ecdsa',
  manifest: null,
  runtime: null,
  key: null,
  lane: null,
  auth: null,
  prfClaim: null,
  state: 'invalid',
  // @ts-expect-error an invalid ECDSA capability must carry its correlation reason.
} satisfies WarmSessionEcdsaCapabilityState;
void invalidStateWithoutReason;

const authorizationRequiredEcdsaCapabilityState = {
  capability: 'ecdsa',
  manifest: activeEcdsaManifest,
  runtime: exactEcdsaRuntime,
  key: ecdsaCapabilityKey,
  lane: null,
  auth: null,
  prfClaim: warmPrfClaim,
  emailOtpAuthContext: null,
  state: 'authorization_required',
} satisfies WarmSessionEcdsaCapabilityState;
void authorizationRequiredEcdsaCapabilityState;

// A SelectedEcdsaLane embeds the reusable Wallet Session authorization, so an
// unauthorized capability cannot carry one.
const invalidAuthorizationRequiredWithLane = {
  capability: 'ecdsa',
  manifest: activeEcdsaManifest,
  runtime: exactEcdsaRuntime,
  key: ecdsaCapabilityKey,
  lane: ecdsaCapabilityLane,
  auth: null,
  prfClaim: warmPrfClaim,
  emailOtpAuthContext: null,
  state: 'authorization_required',
  // @ts-expect-error authorization_required cannot carry a selected lane.
} satisfies WarmSessionEcdsaCapabilityState;
void invalidAuthorizationRequiredWithLane;

const readyEcdsaCapabilityState = {
  capability: 'ecdsa',
  manifest: activeEcdsaManifest,
  runtime: exactEcdsaRuntime,
  key: ecdsaCapabilityKey,
  lane: ecdsaCapabilityLane,
  auth: activeEcdsaAuthorization,
  prfClaim: warmPrfClaim,
  state: 'ready',
} satisfies WarmSessionEcdsaCapabilityState;
void readyEcdsaCapabilityState;

const invalidReadyEcdsaCapabilityWithoutWarmPrf = {
  capability: 'ecdsa',
  manifest: activeEcdsaManifest,
  runtime: exactEcdsaRuntime,
  key: ecdsaCapabilityKey,
  lane: ecdsaCapabilityLane,
  auth: activeEcdsaAuthorization,
  prfClaim: unavailablePrfClaim,
  state: 'ready',
  // @ts-expect-error ready ECDSA warm-session capability requires a warm PRF claim.
} satisfies WarmSessionEcdsaCapabilityState;
void invalidReadyEcdsaCapabilityWithoutWarmPrf;
