import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaSessionProvisionPlan } from './ecdsaProvisionPlan';
import type {
  ApplyWarmEcdsaPostSignPolicyArgs,
  AssertWarmEcdsaOperationAllowedArgs,
  EnsureWarmEcdsaProvisionPlanReadyArgs,
  WarmSessionEcdsaCapabilityRef,
} from './types';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
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
  { kind: 'threshold_session_auth_ecdsa_reconnect' | 'cookie_ecdsa_reconnect' }
>;

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const freshPlan: FreshEcdsaSessionProvisionPlan;
declare const passkeyFreshPlan: PasskeyEcdsaSessionProvisionPlan;
declare const emailOtpFreshPlan: EmailOtpEcdsaSessionProvisionPlan;
declare const reconnectPlan: ReconnectEcdsaSessionProvisionPlan;
declare const selectedRecord: ThresholdEcdsaSessionRecord;
declare const keyRef: ThresholdEcdsaSecp256k1KeyRef;

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
  walletId,
  chainTarget,
  thresholdSessionId: 'threshold-session-id',
  selectedRecord,
} satisfies ApplyWarmEcdsaPostSignPolicyArgs;
void validApplyWarmEcdsaPostSignPolicyArgs;

const invalidApplyWarmEcdsaPostSignPolicyArgsWithRawWalletId = {
  // @ts-expect-error ECDSA post-sign policy requires a normalized WalletId.
  walletId: 'wallet.testnet',
  chainTarget,
  thresholdSessionId: 'threshold-session-id',
  selectedRecord,
} satisfies ApplyWarmEcdsaPostSignPolicyArgs;
void invalidApplyWarmEcdsaPostSignPolicyArgsWithRawWalletId;

const validAssertWarmEcdsaOperationAllowedArgs = {
  walletId,
  chainTarget,
  operationLabel: 'threshold-ecdsa sign',
  thresholdSessionId: 'threshold-session-id',
  source: 'login',
} satisfies AssertWarmEcdsaOperationAllowedArgs;
void validAssertWarmEcdsaOperationAllowedArgs;

const invalidAssertWarmEcdsaOperationAllowedArgsWithRawWalletId = {
  // @ts-expect-error ECDSA operation checks require a normalized WalletId.
  walletId: 'wallet.testnet',
  chainTarget,
  operationLabel: 'threshold-ecdsa sign',
  thresholdSessionId: 'threshold-session-id',
  source: 'login',
} satisfies AssertWarmEcdsaOperationAllowedArgs;
void invalidAssertWarmEcdsaOperationAllowedArgsWithRawWalletId;
