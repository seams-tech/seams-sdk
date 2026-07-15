import type { StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch } from '../../core/RegistrationCeremonyStore';
import type { WalletSigningBudgetSessionStatus } from '../../core/ThresholdService/stores/WalletSessionStore';
import { thresholdEcdsaChainTargetKey } from '../../core/thresholdEcdsaChainTarget';

export type D1RegistrationSharedSigningBudget = {
  readonly kind: 'registration_shared_signing_budget';
  readonly signingGrantId: string;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
};

type D1RegistrationSharedSigningBudgetResult =
  | { readonly ok: true; readonly budget: D1RegistrationSharedSigningBudget }
  | {
      readonly ok: false;
      readonly code: 'invalid_state';
      readonly message: string;
    };

type WalletBudgetStatusReader = (
  signingGrantId: string,
) => Promise<WalletSigningBudgetSessionStatus | null>;

function invalidSharedSigningBudget(
  message: string,
): Extract<D1RegistrationSharedSigningBudgetResult, { ok: false }> {
  return { ok: false, code: 'invalid_state', message };
}

function participantIdsEqual(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function findBootstrapForTarget(
  state: StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch,
  targetKey: string,
) {
  for (const entry of state.responded.bootstraps) {
    if (thresholdEcdsaChainTargetKey(entry.chainTarget) === targetKey) return entry.bootstrap;
  }
  return null;
}

function hasExactEcdsaBudgetBinding(args: {
  readonly status: WalletSigningBudgetSessionStatus;
  readonly thresholdSessionId: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly participantIds: readonly number[];
}): boolean {
  const bindings = args.status.record.bindings;
  if (bindings.kind === 'ed25519_only') return false;
  for (const binding of bindings.ecdsa) {
    if (
      binding.thresholdSessionId === args.thresholdSessionId &&
      binding.evmFamilySigningKeySlotId === args.evmFamilySigningKeySlotId &&
      participantIdsEqual(binding.participantIds, args.participantIds)
    ) {
      return true;
    }
  }
  return false;
}

export async function resolveD1RegistrationSharedSigningBudget(input: {
  readonly walletId: string;
  readonly ecdsaState: StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch;
  readonly getWalletBudgetStatus: WalletBudgetStatusReader;
}): Promise<D1RegistrationSharedSigningBudgetResult> {
  if (
    input.ecdsaState.targets.length === 0 ||
    input.ecdsaState.targets.length !== input.ecdsaState.responded.bootstraps.length
  ) {
    return invalidSharedSigningBudget(
      'Mixed registration requires complete ECDSA signing-budget target coverage',
    );
  }

  let signingGrantId = '';
  let remainingUses = 0;
  let expiresAtMs = 0;
  let ecdsaParticipantIds: readonly number[] | null = null;
  for (const target of input.ecdsaState.targets) {
    const prepare = target.prepare;
    const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
    const bootstrap = findBootstrapForTarget(input.ecdsaState, targetKey);
    if (!bootstrap) {
      return invalidSharedSigningBudget(
        `Mixed registration is missing ECDSA signing-budget bootstrap for ${targetKey}`,
      );
    }
    const targetSigningGrantId = String(prepare.signingGrantId || '').trim();
    const targetRemainingUses = Math.floor(Number(prepare.remainingUses));
    const targetExpiresAtMs = Math.floor(Number(bootstrap.expiresAtMs));
    if (
      !targetSigningGrantId ||
      !Number.isSafeInteger(targetRemainingUses) ||
      targetRemainingUses <= 0 ||
      !Number.isSafeInteger(targetExpiresAtMs) ||
      targetExpiresAtMs <= 0 ||
      bootstrap.walletId !== input.walletId ||
      bootstrap.signingGrantId !== targetSigningGrantId ||
      bootstrap.thresholdSessionId !== prepare.thresholdSessionId ||
      bootstrap.evmFamilySigningKeySlotId !== prepare.evmFamilySigningKeySlotId ||
      bootstrap.remainingUses !== targetRemainingUses ||
      !participantIdsEqual(prepare.participantIds, bootstrap.participantIds)
    ) {
      return invalidSharedSigningBudget(
        `Mixed registration ECDSA signing-budget policy mismatch for ${targetKey}`,
      );
    }
    if (!signingGrantId) {
      signingGrantId = targetSigningGrantId;
      remainingUses = targetRemainingUses;
      expiresAtMs = targetExpiresAtMs;
      ecdsaParticipantIds = prepare.participantIds;
      continue;
    }
    if (
      signingGrantId !== targetSigningGrantId ||
      remainingUses !== targetRemainingUses ||
      expiresAtMs !== targetExpiresAtMs ||
      !ecdsaParticipantIds ||
      !participantIdsEqual(ecdsaParticipantIds, prepare.participantIds)
    ) {
      return invalidSharedSigningBudget(
        'Mixed registration ECDSA targets do not share one signing-budget policy',
      );
    }
  }

  const status = await input.getWalletBudgetStatus(signingGrantId);
  if (
    !status ||
    status.record.walletId !== input.walletId ||
    status.record.expiresAtMs !== expiresAtMs ||
    status.committedRemainingUses !== remainingUses ||
    status.availableUses !== remainingUses ||
    status.reservedUses !== 0
  ) {
    return invalidSharedSigningBudget(
      'Mixed registration ECDSA signing budget is unavailable or has unexpected state',
    );
  }
  for (const target of input.ecdsaState.targets) {
    if (
      !hasExactEcdsaBudgetBinding({
        status,
        thresholdSessionId: target.prepare.thresholdSessionId,
        evmFamilySigningKeySlotId: target.prepare.evmFamilySigningKeySlotId,
        participantIds: target.prepare.participantIds,
      })
    ) {
      return invalidSharedSigningBudget(
        'Mixed registration ECDSA signing budget is missing a threshold-session binding',
      );
    }
  }

  return {
    ok: true,
    budget: {
      kind: 'registration_shared_signing_budget',
      signingGrantId,
      expiresAtMs,
      remainingUses,
    },
  };
}
