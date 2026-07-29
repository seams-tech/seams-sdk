import type { StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch } from '../../core/RegistrationCeremonyStore';

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

export async function resolveD1RegistrationSharedSigningBudget(input: {
  readonly walletId: string;
  readonly ecdsaState: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch;
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
