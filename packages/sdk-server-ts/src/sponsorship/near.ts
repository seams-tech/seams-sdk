import { ActionType } from '@shared/near/actions';
import type { DelegateActionPolicy } from '../delegateAction';
import type { ResolvedGasSponsorshipNearPolicy } from '../console/gasSponsorship/types';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export type ResolvedSponsoredNearDelegatePolicy = ResolvedGasSponsorshipNearPolicy;

export type SponsoredNearDelegateSummary = {
  receiverId: string;
  methods: string[];
  totalDepositYocto: bigint;
  hasTransfer: boolean;
  unsupportedActionKinds: string[];
};

function parseActions(rawDelegateAction: Record<string, unknown>): unknown[] {
  if (Array.isArray(rawDelegateAction.actions)) {
    return rawDelegateAction.actions;
  }
  const actionsJson = String(rawDelegateAction.actionsJson || '').trim();
  if (!actionsJson) return [];
  try {
    const parsed = JSON.parse(actionsJson);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function summarizeSignedDelegateForSponsorship(
  signedDelegateRaw: unknown,
): SponsoredNearDelegateSummary {
  const signedDelegate =
    signedDelegateRaw && typeof signedDelegateRaw === 'object' && !Array.isArray(signedDelegateRaw)
      ? (signedDelegateRaw as Record<string, unknown>)
      : {};
  const rawDelegateAction =
    signedDelegate.delegateAction &&
    typeof signedDelegate.delegateAction === 'object' &&
    !Array.isArray(signedDelegate.delegateAction)
      ? (signedDelegate.delegateAction as Record<string, unknown>)
      : null;
  if (!rawDelegateAction) {
    throw new Error('invalid_signed_delegate: missing delegateAction');
  }
  const receiverId = String(rawDelegateAction.receiverId || '').trim();
  if (!receiverId) {
    throw new Error('invalid_signed_delegate: missing delegateAction.receiverId');
  }
  const methods: string[] = [];
  const seenMethods = new Set<string>();
  const unsupportedActionKinds = new Set<string>();
  let totalDepositYocto = 0n;
  let hasTransfer = false;

  for (const action of parseActions(rawDelegateAction)) {
    if (!isObject(action)) continue;
    const kind = String(action.type || '').trim();
    if (kind === ActionType.FunctionCall) {
      const methodName = String(action.methodName || '').trim();
      if (methodName && !seenMethods.has(methodName)) {
        seenMethods.add(methodName);
        methods.push(methodName);
      }
      try {
        totalDepositYocto += BigInt(String(action.deposit || '0').trim() || '0');
      } catch {}
      continue;
    }
    if (kind === ActionType.Transfer) {
      hasTransfer = true;
      try {
        totalDepositYocto += BigInt(String(action.amount || '0').trim() || '0');
      } catch {}
      continue;
    }
    if (kind) unsupportedActionKinds.add(kind);
  }

  return {
    receiverId,
    methods,
    totalDepositYocto,
    hasTransfer,
    unsupportedActionKinds: [...unsupportedActionKinds],
  };
}

function parseResolvedSpendCap(raw: unknown): ResolvedSponsoredNearDelegatePolicy['spendCap'] {
  const row =
    raw && typeof raw === 'object' && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  const modeRaw = String(row.mode || '').trim().toUpperCase();
  const periodRaw = String(row.period || '').trim().toUpperCase();
  const capsByChainRaw = Array.isArray(row.capsByChain) ? row.capsByChain : [];
  return {
    mode:
      modeRaw === 'CHAIN_TOTAL' || modeRaw === 'WALLET_CHAIN_TOTAL'
        ? modeRaw
        : 'NONE',
    period: periodRaw === 'WEEKLY' ? 'WEEKLY' : 'MONTHLY',
    capsByChain: capsByChainRaw
      .map((entry) => {
        if (!isObject(entry)) return null;
        const chainId = Number(entry.chainId);
        const capMinor = Number(entry.capMinor);
        if (!Number.isFinite(chainId) || chainId <= 0) return null;
        if (!Number.isFinite(capMinor) || capMinor < 0) return null;
        return {
          chainId: Math.floor(chainId),
          capMinor: Math.floor(capMinor),
        };
      })
      .filter(
        (entry): entry is ResolvedSponsoredNearDelegatePolicy['spendCap']['capsByChain'][number] =>
          Boolean(entry),
      ),
  };
}

export function parseResolvedSponsoredNearDelegatePolicies(
  snapshot: unknown,
): ResolvedSponsoredNearDelegatePolicy[] {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return [];
  const payload = snapshot as Record<string, unknown>;
  const gasSponsorship = payload.gasSponsorship;
  if (!gasSponsorship || typeof gasSponsorship !== 'object' || Array.isArray(gasSponsorship)) {
    return [];
  }
  const policiesRaw = (gasSponsorship as Record<string, unknown>).resolvedPolicies;
  if (!Array.isArray(policiesRaw)) return [];
  const out: ResolvedSponsoredNearDelegatePolicy[] = [];
  for (const entry of policiesRaw) {
    if (!isObject(entry)) continue;
    if (String(entry.kind || '').trim().toLowerCase() !== 'near_delegate') continue;
    const policyId = String(entry.policyId || '').trim();
    const policyName = String(entry.policyName || '').trim() || policyId;
    if (!policyId) continue;
    const allowedDelegateActionsRaw = Array.isArray(entry.allowedDelegateActions)
      ? entry.allowedDelegateActions
      : [];
    const allowedDelegateActions = allowedDelegateActionsRaw
      .map((allowedAction) => {
        if (!isObject(allowedAction)) return null;
        const receiverId = String(allowedAction.receiverId || '').trim();
        const methods = Array.isArray(allowedAction.methods)
          ? allowedAction.methods
              .map((method) => String(method || '').trim())
              .filter((method) => Boolean(method))
          : [];
        const maxDepositYocto = String(allowedAction.maxDepositYocto || '').trim();
        const allowTransfers = Boolean(allowedAction.allowTransfers);
        if (!receiverId || !maxDepositYocto) return null;
        return {
          receiverId,
          methods,
          maxDepositYocto,
          allowTransfers,
        };
      })
      .filter(
        (
          allowedAction,
        ): allowedAction is ResolvedSponsoredNearDelegatePolicy['allowedDelegateActions'][number] =>
          Boolean(allowedAction),
      );
    if (allowedDelegateActions.length === 0) continue;
    out.push({
      kind: 'near_delegate',
      policyId,
      policyName,
      scopePolicyId: String(entry.scopePolicyId || '').trim() || null,
      scopePolicyName: String(entry.scopePolicyName || '').trim() || null,
      templateId: String(entry.templateId || '').trim() || null,
      networkClass:
        String(entry.networkClass || '').trim().toUpperCase() === 'MAINNET'
          ? 'MAINNET'
          : String(entry.networkClass || '').trim().toUpperCase() === 'TESTNET'
            ? 'TESTNET'
            : 'ANY',
      executionMode: 'near_delegate',
      allowedDelegateActions,
      spendCap: parseResolvedSpendCap(entry.spendCap),
      scopeType: 'ENVIRONMENT',
      projectId: String(entry.projectId || '').trim() || null,
      environmentId: String(entry.environmentId || '').trim() || null,
    });
  }
  return out;
}

export function matchResolvedSponsoredNearDelegatePolicy(input: {
  policies: readonly ResolvedSponsoredNearDelegatePolicy[];
  signedDelegate: unknown;
}): {
  policy: ResolvedSponsoredNearDelegatePolicy;
  allowedDelegateAction: ResolvedSponsoredNearDelegatePolicy['allowedDelegateActions'][number];
  summary: SponsoredNearDelegateSummary;
} | null {
  const summary = summarizeSignedDelegateForSponsorship(input.signedDelegate);
  if (summary.unsupportedActionKinds.length > 0) return null;
  for (const policy of input.policies) {
    for (const allowedDelegateAction of policy.allowedDelegateActions) {
      if (
        summary.receiverId.toLowerCase() !== allowedDelegateAction.receiverId.toLowerCase()
      ) {
        continue;
      }
      if (summary.hasTransfer && !allowedDelegateAction.allowTransfers) continue;
      if (summary.totalDepositYocto > BigInt(allowedDelegateAction.maxDepositYocto)) continue;
      if (
        allowedDelegateAction.methods.length > 0 &&
        summary.methods.some((method) => !allowedDelegateAction.methods.includes(method))
      ) {
        continue;
      }
      return {
        policy,
        allowedDelegateAction,
        summary,
      };
    }
  }
  return null;
}

export function buildDelegateActionPolicyFromResolvedRule(input: {
  allowedDelegateAction: ResolvedSponsoredNearDelegatePolicy['allowedDelegateActions'][number];
}): DelegateActionPolicy {
  return {
    allowedReceivers: [input.allowedDelegateAction.receiverId],
    ...(input.allowedDelegateAction.methods.length > 0
      ? { allowedMethods: [...input.allowedDelegateAction.methods] }
      : {}),
    maxTotalDepositYocto: input.allowedDelegateAction.maxDepositYocto,
  };
}
