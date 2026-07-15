import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import {
  THRESHOLD_SESSION_POLICY_VERSION,
  generateSigningGrantId,
  generateThresholdSessionId,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import { resolveThresholdWarmSessionDefaults } from './thresholdWarmSessionDefaults';

export type ThresholdWarmSessionPolicyDraft = {
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds?: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type ThresholdWarmSessionPolicyDraftInput =
  | {
      kind: 'generated_signing_grant';
      sessionId?: string;
      participantIds?: number[];
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      signingGrantId?: never;
      ttlMs?: never;
      remainingUses?: never;
    }
  | {
      kind: 'shared_signing_grant';
      signingGrantId: string;
      ttlMs: number;
      remainingUses: number;
      sessionId?: string;
      participantIds?: number[];
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
    };

export type ThresholdWarmSessionRequestEnvelope = {
  session_policy: {
    version: typeof THRESHOLD_SESSION_POLICY_VERSION;
    walletId?: string;
    nearAccountId?: string;
    nearEd25519SigningKeyId?: string;
    authority: WalletAuthAuthority;
    relayerKeyId?: string;
    thresholdSessionId: string;
    signingGrantId: string;
    participantIds?: number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    routerAbNormalSigning: RouterAbEd25519NormalSigningState;
    ttlMs: number;
    remainingUses: number;
  };
  session_kind: 'jwt';
};

export type ThresholdWarmSessionContext = {
  configs: SeamsConfigsReadonly;
};

type WarmSessionBudget = {
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
};

function assertNeverNormalSigning(value: never): never {
  throw new Error(`Unexpected Router A/B normal-signing config branch: ${String(value)}`);
}

function assertNeverPolicyInput(value: never): never {
  throw new Error(`Unexpected threshold warm-session policy input: ${String(value)}`);
}

function parsePositiveInt(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return Math.floor(parsed);
}

function parseSharedSigningGrantId(value: unknown): string {
  const signingGrantId = String(value ?? '').trim();
  if (!signingGrantId) {
    throw new Error('Threshold warm-session shared signing grant is missing signingGrantId');
  }
  return signingGrantId;
}

function generatedBudget(args: { ttlMs: number; remainingUses: number }): WarmSessionBudget {
  return {
    signingGrantId: generateSigningGrantId(),
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  };
}

function sharedBudget(
  input: Extract<ThresholdWarmSessionPolicyDraftInput, { kind: 'shared_signing_grant' }>,
): WarmSessionBudget {
  const budget = {
    signingGrantId: parseSharedSigningGrantId(input.signingGrantId),
    ttlMs: parsePositiveInt(input.ttlMs),
    remainingUses: parsePositiveInt(input.remainingUses),
  };
  if (!budget.ttlMs || !budget.remainingUses) {
    throw new Error('Threshold warm-session shared signing grant has invalid policy limits');
  }
  return budget;
}

function policyBudget(args: {
  input: ThresholdWarmSessionPolicyDraftInput;
  ttlMs: number;
  remainingUses: number;
}): WarmSessionBudget {
  switch (args.input.kind) {
    case 'generated_signing_grant':
      return generatedBudget({ ttlMs: args.ttlMs, remainingUses: args.remainingUses });
    case 'shared_signing_grant':
      return sharedBudget(args.input);
    default:
      return assertNeverPolicyInput(args.input);
  }
}

export function createRouterAbNormalSigningPolicy(
  configs: SeamsConfigsReadonly,
): RouterAbEd25519NormalSigningState {
  const normalSigning = configs.signing.routerAb.normalSigning;
  switch (normalSigning.mode) {
    case 'disabled':
      throw new Error(
        '[threshold-warm-session] Router A/B normal signing must be enabled for Ed25519 sessions',
      );
    case 'enabled':
      return {
        kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
        signingWorkerId: normalSigning.signingWorkerId,
      };
    default:
      return assertNeverNormalSigning(normalSigning);
  }
}

export function createThresholdWarmSessionPolicyDraft(
  context: ThresholdWarmSessionContext,
  input: ThresholdWarmSessionPolicyDraftInput,
): ThresholdWarmSessionPolicyDraft | null {
  const defaults = resolveThresholdWarmSessionDefaults(context);
  if (!defaults) return null;
  const sessionId = String(input.sessionId ?? '').trim() || generateThresholdSessionId();
  const budget = policyBudget({
    input,
    ttlMs: defaults.ttlMs,
    remainingUses: defaults.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
  return {
    sessionId,
    signingGrantId: budget.signingGrantId,
    ttlMs: budget.ttlMs,
    remainingUses: budget.remainingUses,
    ...(participantIds ? { participantIds } : {}),
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    routerAbNormalSigning: createRouterAbNormalSigningPolicy(context.configs),
  };
}

export function buildThresholdWarmSessionRequestEnvelope(args: {
  authority: WalletAuthAuthority;
  requestedPolicy: ThresholdWarmSessionPolicyDraft;
  walletId?: string;
  nearAccountId?: string;
  nearEd25519SigningKeyId?: string;
  relayerKeyId?: string;
}): ThresholdWarmSessionRequestEnvelope {
  const thresholdSessionId = String(args.requestedPolicy.sessionId).trim();
  const signingGrantId = String(args.requestedPolicy.signingGrantId).trim();
  if (!thresholdSessionId || !signingGrantId) {
    throw new Error(
      'Threshold warm-session request is missing thresholdSessionId or signingGrantId',
    );
  }
  return {
    session_policy: {
      version: THRESHOLD_SESSION_POLICY_VERSION,
      ...(args.walletId ? { walletId: String(args.walletId).trim() } : {}),
      ...(args.nearAccountId ? { nearAccountId: String(args.nearAccountId).trim() } : {}),
      ...(args.nearEd25519SigningKeyId
        ? { nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId).trim() }
        : {}),
      authority: args.authority,
      ...(args.relayerKeyId ? { relayerKeyId: String(args.relayerKeyId).trim() } : {}),
      thresholdSessionId,
      signingGrantId,
      ...(args.requestedPolicy.participantIds
        ? { participantIds: args.requestedPolicy.participantIds }
        : {}),
      ...(args.requestedPolicy.runtimePolicyScope
        ? { runtimePolicyScope: args.requestedPolicy.runtimePolicyScope }
        : {}),
      routerAbNormalSigning: args.requestedPolicy.routerAbNormalSigning,
      ttlMs: args.requestedPolicy.ttlMs,
      remainingUses: args.requestedPolicy.remainingUses,
    },
    session_kind: 'jwt',
  };
}
