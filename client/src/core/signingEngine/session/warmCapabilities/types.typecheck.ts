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

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const plan: EcdsaSessionProvisionPlan;
declare const selectedRecord: ThresholdEcdsaSessionRecord;
declare const keyRef: ThresholdEcdsaSecp256k1KeyRef;

const validEnsureWarmEcdsaProvisionPlanReadyArgs = {
  walletId,
  chainTarget,
  plan,
  record: selectedRecord,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void validEnsureWarmEcdsaProvisionPlanReadyArgs;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithSubjectId = {
  walletId,
  chainTarget,
  plan,
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
  plan,
  record: selectedRecord,
  source: 'login',
  sessionBudgetUses: 1,
} satisfies EnsureWarmEcdsaProvisionPlanReadyArgs;
void invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithRawWalletId;

const invalidEnsureWarmEcdsaProvisionPlanReadyArgsWithKeyRef = {
  walletId,
  chainTarget,
  plan,
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
