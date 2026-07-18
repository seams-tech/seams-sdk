import type { StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch } from '../../core/RegistrationCeremonyStore';
import type { WalletSigningBudgetSessionStatus } from '../../core/ThresholdService/stores/WalletSessionStore';

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
  readonly ecdsaState: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch;
  readonly getWalletBudgetStatus: WalletBudgetStatusReader;
}): Promise<D1RegistrationSharedSigningBudgetResult> {
  if (input.ecdsaState.chainTargets.length === 0) {
    return invalidSharedSigningBudget(
      'Mixed registration requires one activated ECDSA family projection',
    );
  }
  const prepare = input.ecdsaState.prepare;
  const bootstrap = input.ecdsaState.bootstrap;
  const signingGrantId = String(prepare.signingGrantId || '').trim();
  const remainingUses = Math.floor(Number(bootstrap.remainingUses));
  const expiresAtMs = Math.floor(Number(bootstrap.expiresAtMs));
  if (
    !signingGrantId ||
    !Number.isSafeInteger(remainingUses) ||
    remainingUses <= 0 ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0 ||
    bootstrap.walletId !== input.walletId ||
    bootstrap.signingGrantId !== signingGrantId ||
    bootstrap.thresholdSessionId !== prepare.thresholdSessionId ||
    bootstrap.evmFamilySigningKeySlotId !== prepare.evmFamilySigningKeySlotId ||
    !participantIdsEqual(prepare.participantIds, bootstrap.participantIds)
  ) {
    return invalidSharedSigningBudget(
      'Mixed registration ECDSA signing-budget policy does not match its activation',
    );
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
  if (
    !hasExactEcdsaBudgetBinding({
      status,
      thresholdSessionId: prepare.thresholdSessionId,
      evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
      participantIds: prepare.participantIds,
    })
  ) {
    return invalidSharedSigningBudget(
      'Mixed registration ECDSA signing budget is missing its family-session binding',
    );
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
