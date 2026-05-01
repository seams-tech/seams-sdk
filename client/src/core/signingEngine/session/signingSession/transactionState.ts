import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  ConcreteSigningSessionSnapshotLane,
  SigningSessionSnapshot,
  SigningSessionSnapshotEd25519Lane,
} from '../snapshotReader';
import {
  compareSnapshotCandidates,
  isConcreteSigningSessionSnapshotLane,
} from '../snapshotReader';
import {
  SigningSessionIds,
  type SigningAuthMethod,
  type SigningOperationId,
  type ThresholdEd25519SessionId,
  type WalletSigningSessionId,
} from './types';

export type TransactionSigningIntent = {
  operationId?: SigningOperationId;
  walletId: AccountId | string;
  curve: 'ed25519' | 'ecdsa';
  chain: 'near' | 'tempo' | 'evm';
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
};

export type TransactionAuthSelectionPolicy =
  | { kind: 'explicit'; authMethod: SigningAuthMethod }
  | { kind: 'account_class'; authMethod: SigningAuthMethod }
  | { kind: 'current_lane'; authMethod: SigningAuthMethod };

export type NearEd25519TransactionLane = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: 'ed25519';
  chain: 'near';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEd25519SessionId;
};

export type TransactionLane = NearEd25519TransactionLane;

export type TransactionReadiness =
  | { status: 'ready'; remainingUses: number; expiresAtMs: number }
  | { status: 'missing_hot_material' }
  | { status: 'expired' }
  | { status: 'exhausted' }
  | { status: 'restore_failed'; reason: string }
  | { status: 'budget_unknown'; reason: string }
  | { status: 'policy_blocked'; reason: string };

export type PreparedTransactionOperation<TLane extends TransactionLane = TransactionLane> = {
  intent: TransactionSigningIntent;
  lane: TLane;
  readiness: TransactionReadiness;
};

export type BudgetAdmittedOperation<TLane extends TransactionLane = TransactionLane> =
  PreparedTransactionOperation<TLane> & {
    budgetAdmission: unknown;
  };

export type SignedTransactionOperation<TLane extends TransactionLane = TransactionLane> =
  BudgetAdmittedOperation<TLane> & {
    result: unknown;
  };

export type TransactionLaneSelectionFailure =
  | { kind: 'unsupported_intent'; curve: string; chain: string }
  | { kind: 'no_candidate'; authMethod?: SigningAuthMethod }
  | { kind: 'ambiguous_candidates'; allowedAuthMethods: readonly SigningAuthMethod[] }
  | { kind: 'incomplete_candidate'; missing: readonly string[] }
  | { kind: 'policy_blocked'; reason: string };

export type NearEd25519ConcreteSnapshotLane = SigningSessionSnapshotEd25519Lane &
  ConcreteSigningSessionSnapshotLane & {
    curve: 'ed25519';
    chain: 'near';
  };

export type TransactionLaneSelectionResult =
  | {
      ok: true;
      lane: NearEd25519TransactionLane;
      snapshotLane: NearEd25519ConcreteSnapshotLane;
    }
  | { ok: false; failure: TransactionLaneSelectionFailure };

export type SelectTransactionLaneInput = {
  intent: TransactionSigningIntent;
  snapshot: SigningSessionSnapshot | null;
  currentRuntimeLane?: SigningSessionSnapshotEd25519Lane | null;
};

function isConcreteNearEd25519Lane(
  lane: SigningSessionSnapshotEd25519Lane | null | undefined,
): lane is NearEd25519ConcreteSnapshotLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ed25519' &&
    lane!.chain === 'near' &&
    isConcreteSigningSessionSnapshotLane(lane!)
  );
}

function missingConcreteFields(
  lane: SigningSessionSnapshotEd25519Lane | null | undefined,
): string[] {
  if (!lane) return ['lane'];
  const missing: string[] = [];
  if (lane.authMethod !== 'email_otp' && lane.authMethod !== 'passkey') {
    missing.push('authMethod');
  }
  if (!String(lane.walletSigningSessionId || '').trim()) {
    missing.push('walletSigningSessionId');
  }
  if (!String(lane.thresholdSessionId || '').trim()) {
    missing.push('thresholdSessionId');
  }
  return missing;
}

function buildNearEd25519TransactionLane(args: {
  walletId: AccountId | string;
  lane: NearEd25519ConcreteSnapshotLane;
}): NearEd25519TransactionLane {
  return {
    accountId: toAccountId(args.walletId),
    authMethod: args.lane.authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      args.lane.walletSigningSessionId,
    ),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args.lane.thresholdSessionId,
    ),
  };
}

function allowedAuthMethods(
  candidates: readonly NearEd25519ConcreteSnapshotLane[],
): SigningAuthMethod[] {
  return [...new Set(candidates.map((candidate) => candidate.authMethod))].sort();
}

export function selectTransactionLane(
  input: SelectTransactionLaneInput,
): TransactionLaneSelectionResult {
  const intent = input.intent;
  if (intent.curve !== 'ed25519' || intent.chain !== 'near') {
    return {
      ok: false,
      failure: {
        kind: 'unsupported_intent',
        curve: intent.curve,
        chain: intent.chain,
      },
    };
  }

  const runtimeLane = input.currentRuntimeLane || null;
  if (runtimeLane && !isConcreteNearEd25519Lane(runtimeLane)) {
    return {
      ok: false,
      failure: {
        kind: 'incomplete_candidate',
        missing: missingConcreteFields(runtimeLane),
      },
    };
  }

  // Current-lane and account-class policy are hints below a verified runtime
  // lane. Only an explicit user choice may reject a different hot lane.
  if (runtimeLane) {
    if (
      intent.authSelectionPolicy.kind === 'explicit' &&
      runtimeLane.authMethod !== intent.authSelectionPolicy.authMethod
    ) {
      return {
        ok: false,
        failure: {
          kind: 'policy_blocked',
          reason: 'explicit auth method does not match current runtime lane',
        },
      };
    }
    return {
      ok: true,
      lane: buildNearEd25519TransactionLane({
        walletId: intent.walletId,
        lane: runtimeLane,
      }),
      snapshotLane: runtimeLane,
    };
  }

  const concreteCandidates =
    input.snapshot?.candidates.ed25519.near.filter(isConcreteNearEd25519Lane) || [];
  const policyAuthMethod = intent.authSelectionPolicy.authMethod;
  const candidates = concreteCandidates
    .filter((candidate) => candidate.authMethod === policyAuthMethod)
    .sort((left, right) => compareSnapshotCandidates(left, right, policyAuthMethod));

  if (!candidates.length) {
    return {
      ok: false,
      failure: { kind: 'no_candidate', authMethod: policyAuthMethod },
    };
  }
  const authMethods = allowedAuthMethods(candidates);
  if (authMethods.length > 1) {
    return {
      ok: false,
      failure: { kind: 'ambiguous_candidates', allowedAuthMethods: authMethods },
    };
  }

  const selected = candidates[0];
  if (!selected) {
    return {
      ok: false,
      failure: { kind: 'no_candidate', authMethod: policyAuthMethod },
    };
  }
  return {
    ok: true,
    lane: buildNearEd25519TransactionLane({
      walletId: intent.walletId,
      lane: selected,
    }),
    snapshotLane: selected,
  };
}
