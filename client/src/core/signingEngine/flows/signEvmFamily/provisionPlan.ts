import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContext,
  buildEmailOtpEcdsaSessionProvision,
  buildPasskeyEcdsaSessionProvision,
  buildThresholdSessionAuthEcdsaReconnect,
  type CookieEcdsaReconnect,
  type EmailOtpEcdsaSessionProvision,
  type PasskeyEcdsaSessionProvision,
  type ThresholdSessionAuthEcdsaReconnect,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type {
  EvmFamilyEcdsaEmailOtpStepUpAuthorization,
  EvmFamilyEcdsaPasskeyStepUpAuthorization,
  EvmFamilyEcdsaWarmSessionStepUpAuthorization,
} from './stepUpAuthorization';

export type EvmFamilyWarmSessionReconnectPlan =
  | ThresholdSessionAuthEcdsaReconnect
  | CookieEcdsaReconnect;

export function buildEvmFamilyWarmSessionReconnectPlan(args: {
  authorization: EvmFamilyEcdsaWarmSessionStepUpAuthorization;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  record?: ThresholdEcdsaSessionRecord | null;
  sessionBudgetUses: number;
}): EvmFamilyWarmSessionReconnectPlan {
  return buildThresholdSessionAuthEcdsaReconnect({
    subjectId: args.lane.subjectId,
    chainTarget: args.lane.chainTarget,
    existingSessionIdentity: buildEcdsaSessionIdentity({
      thresholdSessionId: args.lane.thresholdSessionId,
      walletSigningSessionId: args.lane.walletSigningSessionId,
    }),
    signingKeyContext: buildEcdsaSigningKeyContext({
      keyRef: args.keyRef,
      record: args.record,
    }),
    sessionBudgetUses: args.sessionBudgetUses,
    reconnectMaterial: buildEcdsaReconnectMaterial({
      keyRef: args.keyRef,
      record: args.record,
    }),
  });
}

export function buildEvmFamilyPasskeyEcdsaProvisionPlan(args: {
  authorization: EvmFamilyEcdsaPasskeyStepUpAuthorization;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  record?: ThresholdEcdsaSessionRecord | null;
  sessionBudgetUses: number;
}): PasskeyEcdsaSessionProvision {
  if (!args.authorization.plannedPasskeyReconnect) {
    throw new Error(
      '[SigningEngine][ecdsa] passkey ECDSA provision requires planned reconnect identity',
    );
  }
  const clientRootShare32B64u = getPrfFirstB64uFromCredential(args.authorization.credential);
  if (!clientRootShare32B64u) {
    throw new Error('[SigningEngine][ecdsa] missing PRF.first for passkey ECDSA provision');
  }
  const baseArgs = {
    subjectId: args.lane.subjectId,
    chainTarget: args.lane.chainTarget,
    newSessionIdentity: buildEcdsaSessionIdentity({
      thresholdSessionId: args.authorization.plannedPasskeyReconnect.sessionId,
      walletSigningSessionId: args.authorization.plannedPasskeyReconnect.walletSigningSessionId,
    }),
    signingKeyContext: buildEcdsaSigningKeyContext({
      keyRef: args.keyRef,
      record: args.record,
    }),
    sessionKind: args.record?.thresholdSessionKind || args.keyRef?.thresholdSessionKind || 'jwt',
    sessionBudgetUses: args.sessionBudgetUses,
    clientRootShare32B64u,
    webauthnAuthentication: args.authorization.credential,
  };
  if (args.record?.runtimePolicyScope) {
    return buildPasskeyEcdsaSessionProvision({
      subjectId: baseArgs.subjectId,
      chainTarget: baseArgs.chainTarget,
      newSessionIdentity: baseArgs.newSessionIdentity,
      signingKeyContext: baseArgs.signingKeyContext,
      sessionKind: baseArgs.sessionKind,
      sessionBudgetUses: baseArgs.sessionBudgetUses,
      clientRootShare32B64u: baseArgs.clientRootShare32B64u,
      webauthnAuthentication: baseArgs.webauthnAuthentication,
      runtimePolicyScope: args.record.runtimePolicyScope,
    });
  }
  return buildPasskeyEcdsaSessionProvision(baseArgs);
}

export function buildEvmFamilyEmailOtpEcdsaProvisionPlan(args: {
  authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  record: ThresholdEcdsaSessionRecord;
  chainTarget: ThresholdEcdsaChainTarget;
  clientRootShare32B64u: string;
  sessionBudgetUses: number;
}): EmailOtpEcdsaSessionProvision {
  if (args.record.source !== 'email_otp' || !args.record.emailOtpAuthContext) {
    throw new Error(
      '[SigningEngine][ecdsa] Email OTP provision requires email OTP-authenticated ECDSA state',
    );
  }
  const baseArgs = {
    subjectId: args.record.subjectId,
    chainTarget: args.chainTarget,
    newSessionIdentity: buildEcdsaSessionIdentity({
      thresholdSessionId: args.keyRef.thresholdSessionId,
      walletSigningSessionId: args.keyRef.walletSigningSessionId,
    }),
    signingKeyContext: buildEcdsaSigningKeyContext({
      keyRef: args.keyRef,
      record: args.record,
    }),
    sessionKind: args.record.thresholdSessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    emailOtpAuthContext: args.record.emailOtpAuthContext,
    clientRootShare32B64u: args.clientRootShare32B64u,
  };
  if (args.record.runtimePolicyScope) {
    return buildEmailOtpEcdsaSessionProvision({
      subjectId: baseArgs.subjectId,
      chainTarget: baseArgs.chainTarget,
      newSessionIdentity: baseArgs.newSessionIdentity,
      signingKeyContext: baseArgs.signingKeyContext,
      sessionKind: baseArgs.sessionKind,
      sessionBudgetUses: baseArgs.sessionBudgetUses,
      emailOtpAuthContext: baseArgs.emailOtpAuthContext,
      clientRootShare32B64u: baseArgs.clientRootShare32B64u,
      runtimePolicyScope: args.record.runtimePolicyScope,
    });
  }
  return buildEmailOtpEcdsaSessionProvision(baseArgs);
}
