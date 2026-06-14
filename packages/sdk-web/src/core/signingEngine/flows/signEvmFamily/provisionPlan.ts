import { getPrfFirstB64uFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import { type ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContextFromRecord,
  buildPasskeyEcdsaSessionProvision,
  buildPasskeyEcdsaProvisionSecretSource,
  buildThresholdSessionAuthEcdsaReconnect,
  type CookieEcdsaReconnect,
  type PasskeyEcdsaSessionProvision,
  type ThresholdSessionAuthEcdsaReconnect,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type {
  EvmFamilyEcdsaPasskeyStepUpAuthorization,
  EvmFamilyEcdsaWarmSessionStepUpAuthorization,
} from './stepUpAuthorization';

type PasskeyEcdsaProvisionMaterial = {
  kind: 'session_record';
  lane: Pick<ResolvedEvmFamilyEcdsaSigningLane, 'key' | 'keyHandle' | 'chainTarget'>;
  record: ThresholdEcdsaSessionRecord;
};

export type EvmFamilyWarmSessionReconnectPlan =
  | ThresholdSessionAuthEcdsaReconnect
  | CookieEcdsaReconnect;

export function buildEvmFamilyWarmSessionReconnectPlan(args: {
  authorization: EvmFamilyEcdsaWarmSessionStepUpAuthorization;
  material: {
    lane: Pick<
      ResolvedEvmFamilyEcdsaSigningLane,
      'chainTarget' | 'thresholdSessionId' | 'walletSigningSessionId'
    >;
    record: ThresholdEcdsaSessionRecord;
  };
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
  material: PasskeyEcdsaProvisionMaterial;
  sessionBudgetUses: number;
}): Promise<PasskeyEcdsaSessionProvision> {
  if (!args.authorization.plannedPasskeyReconnect) {
    throw new Error(
      '[SigningEngine][ecdsa] passkey ECDSA provision requires planned reconnect identity',
    );
  }
  const passkeyPrfFirstB64u = String(
    getPrfFirstB64uFromCredential(args.authorization.credential) || '',
  ).trim();
  if (!passkeyPrfFirstB64u) {
    throw new Error(
      '[SigningEngine][ecdsa] passkey ECDSA provision requires PRF.first from WebAuthn',
    );
  }
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
    provisionSecretSource: buildPasskeyEcdsaProvisionSecretSource({
      passkeyPrfFirstB64u,
      webauthnAuthentication: args.authorization.credential,
    }),
    activationMaterial: { kind: 'session_record' } as const,
  };
  const runtimePolicyScope = args.material.record.runtimePolicyScope;
  if (runtimePolicyScope) {
    return buildPasskeyEcdsaSessionProvision({
      key: baseArgs.key,
      chainTarget: baseArgs.chainTarget,
      newSessionIdentity: baseArgs.newSessionIdentity,
      signingKeyContext: baseArgs.signingKeyContext,
      sessionKind: baseArgs.sessionKind,
      sessionBudgetUses: baseArgs.sessionBudgetUses,
      requestId: baseArgs.requestId,
      provisionSecretSource: baseArgs.provisionSecretSource,
      activationMaterial: baseArgs.activationMaterial,
      runtimePolicyScope,
    });
  }
  return buildPasskeyEcdsaSessionProvision(baseArgs);
}
