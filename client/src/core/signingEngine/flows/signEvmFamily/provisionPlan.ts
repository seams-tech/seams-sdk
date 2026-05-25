import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential } from '../../session/passkey/ecdsaClientRoot';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContextFromRecord,
  buildEmailOtpEcdsaSessionProvision,
  buildPasskeyEcdsaSessionProvision,
  buildThresholdSessionAuthEcdsaReconnect,
  type CookieEcdsaReconnect,
  type EmailOtpEcdsaSessionProvision,
  type PasskeyEcdsaSessionProvision,
  type ThresholdSessionAuthEcdsaReconnect,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type { ReadyEvmFamilyEcdsaMaterial } from '../../session/identity/evmFamilyEcdsaIdentity';
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
  material: ReadyEvmFamilyEcdsaMaterial;
  sessionBudgetUses: number;
}): EvmFamilyWarmSessionReconnectPlan {
  return buildThresholdSessionAuthEcdsaReconnect({
    chainTarget: args.material.lane.chainTarget,
    existingSessionIdentity: buildEcdsaSessionIdentity({
      thresholdSessionId: args.material.lane.thresholdSessionId,
      walletSigningSessionId: args.material.lane.walletSigningSessionId,
    }),
    sessionBudgetUses: args.sessionBudgetUses,
    reconnectMaterial: buildEcdsaReconnectMaterial({
      record: args.material.record,
    }),
  });
}

export async function buildEvmFamilyPasskeyEcdsaProvisionPlan(args: {
  authorization: EvmFamilyEcdsaPasskeyStepUpAuthorization;
  material: ReadyEvmFamilyEcdsaMaterial;
  sessionBudgetUses: number;
}): Promise<PasskeyEcdsaSessionProvision> {
  if (!args.authorization.plannedPasskeyReconnect) {
    throw new Error(
      '[SigningEngine][ecdsa] passkey ECDSA provision requires planned reconnect identity',
    );
  }
  const clientRootShare32B64u =
    await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(
      args.authorization.credential,
    );
  const baseArgs = {
    key: args.material.lane.key,
    chainTarget: args.material.lane.chainTarget,
    newSessionIdentity: buildEcdsaSessionIdentity({
      thresholdSessionId:
        args.authorization.plannedPasskeyReconnect.webauthnChallenge.thresholdSessionId,
      walletSigningSessionId:
        args.authorization.plannedPasskeyReconnect.webauthnChallenge.walletSigningSessionId,
    }),
    signingKeyContext: buildEcdsaSigningKeyContextFromRecord(args.material.record),
    sessionKind: args.material.record.thresholdSessionKind || 'jwt',
    sessionBudgetUses: args.sessionBudgetUses,
    requestId: args.authorization.plannedPasskeyReconnect.webauthnChallenge.requestId,
    clientRootShare32B64u,
    webauthnAuthentication: args.authorization.credential,
  };
  if (args.material.record.runtimePolicyScope) {
    return buildPasskeyEcdsaSessionProvision({
      key: baseArgs.key,
      chainTarget: baseArgs.chainTarget,
      newSessionIdentity: baseArgs.newSessionIdentity,
      signingKeyContext: baseArgs.signingKeyContext,
      sessionKind: baseArgs.sessionKind,
      sessionBudgetUses: baseArgs.sessionBudgetUses,
      requestId: baseArgs.requestId,
      clientRootShare32B64u: baseArgs.clientRootShare32B64u,
      webauthnAuthentication: baseArgs.webauthnAuthentication,
      runtimePolicyScope: args.material.record.runtimePolicyScope,
    });
  }
  return buildPasskeyEcdsaSessionProvision(baseArgs);
}

export function buildEvmFamilyEmailOtpEcdsaProvisionPlan(args: {
  authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization;
  material: ReadyEvmFamilyEcdsaMaterial;
  chainTarget: ThresholdEcdsaChainTarget;
  clientRootShare32B64u: string;
  sessionBudgetUses: number;
}): EmailOtpEcdsaSessionProvision {
  const record = args.material.record;
  if (record.source !== 'email_otp' || !record.emailOtpAuthContext) {
    throw new Error(
      '[SigningEngine][ecdsa] Email OTP provision requires email OTP-authenticated ECDSA state',
    );
  }
  const baseArgs = {
    key: args.material.lane.key,
    chainTarget: args.chainTarget,
    newSessionIdentity: buildEcdsaSessionIdentity({
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: record.walletSigningSessionId,
    }),
    signingKeyContext: buildEcdsaSigningKeyContextFromRecord(record),
    sessionKind: record.thresholdSessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    emailOtpAuthContext: record.emailOtpAuthContext,
    clientRootShare32B64u: args.clientRootShare32B64u,
  };
  if (record.runtimePolicyScope) {
    return buildEmailOtpEcdsaSessionProvision({
      key: baseArgs.key,
      chainTarget: baseArgs.chainTarget,
      newSessionIdentity: baseArgs.newSessionIdentity,
      signingKeyContext: baseArgs.signingKeyContext,
      sessionKind: baseArgs.sessionKind,
      sessionBudgetUses: baseArgs.sessionBudgetUses,
      emailOtpAuthContext: baseArgs.emailOtpAuthContext,
      clientRootShare32B64u: baseArgs.clientRootShare32B64u,
      runtimePolicyScope: record.runtimePolicyScope,
    });
  }
  return buildEmailOtpEcdsaSessionProvision(baseArgs);
}
