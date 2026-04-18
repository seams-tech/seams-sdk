import type { SignerAuthMethod, SignerKind, SignerSource } from '@shared/utils';
import { normalizeFiniteNumber, toTrimmedString } from '@shared/utils';
import type { AccountSignerRecord, SignerMutationOptions } from './passkeyClientDB.types';

export type { SignerAuthMethod, SignerKind, SignerSource } from '@shared/utils';

export const SIGNER_MATERIAL_FINGERPRINT_METADATA_KEY = 'signerMaterialFingerprint';

export type SignerActivationPolicy =
  | { mode: 'reuse_existing'; signerId: string; materialFingerprint: string }
  | { mode: 'allocate_next_free' }
  | { mode: 'fail_if_occupied'; signerSlot: number };

export type PlanAccountSignerActivationInput = {
  activeSigners: readonly (Pick<
    AccountSignerRecord,
    | 'signerId'
    | 'signerSlot'
    | 'signerType'
    | 'signerKind'
    | 'signerAuthMethod'
    | 'signerSource'
    | 'metadata'
  >)[];
  signer: {
    signerId: string;
    signerKind: SignerKind;
    signerAuthMethod: SignerAuthMethod;
    signerSource: SignerSource;
  };
  activationPolicy: SignerActivationPolicy;
  preferredSlot?: number;
};

export type AccountSignerActivationPlan = {
  signerSlot: number;
};

export type ActivateAccountSignerInput = {
  account: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
    accountModel: string;
  };
  signer: {
    signerId: string;
    signerType: string;
    signerKind: SignerKind;
    signerAuthMethod: SignerAuthMethod;
    signerSource: SignerSource;
    metadata?: Record<string, unknown>;
  };
  activationPolicy: SignerActivationPolicy;
  preferredSlot?: number;
  selectAsActive?: boolean;
  mutation?: SignerMutationOptions;
};

export type ActivateAccountSignerResult = {
  signer: AccountSignerRecord;
  signerSlot: number;
};

export type StageAccountSignerInput = {
  account: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
    accountModel: string;
  };
  signer: {
    signerId: string;
    signerSlot: number;
    signerType: string;
    signerKind: SignerKind;
    signerAuthMethod: SignerAuthMethod;
    signerSource: SignerSource;
    metadata?: Record<string, unknown>;
  };
  mutation?: SignerMutationOptions;
};

export type StageAccountSignerResult = {
  signer: AccountSignerRecord;
  signerSlot: number;
};

function normalizeNonEmpty(value: unknown, label: string): string {
  const normalized = toTrimmedString(value);
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function normalizeOptionalPositiveInteger(value: unknown, label: string): number | undefined {
  if (value == null) return undefined;
  const normalized = normalizeFiniteNumber(value);
  if (normalized == null || !Number.isSafeInteger(normalized) || normalized < 1) {
    throw new Error(`${label} must be an integer >= 1`);
  }
  return normalized;
}

function normalizeRequiredPositiveInteger(value: unknown, label: string): number {
  const normalized = normalizeOptionalPositiveInteger(value, label);
  if (normalized == null) throw new Error(`${label} is required`);
  return normalized;
}

function firstFreeSlot(reservedSlots: ReadonlySet<number>): number {
  for (let slot = 1; slot < 1000; slot += 1) {
    if (!reservedSlots.has(slot)) return slot;
  }
  throw new Error('No available account signer slot');
}

function getSignerMaterialFingerprint(signer: { metadata?: Record<string, unknown> }): string {
  const value = signer.metadata?.[SIGNER_MATERIAL_FINGERPRINT_METADATA_KEY];
  return typeof value === 'string' ? value.trim() : '';
}

function assertExistingSignerMaterialMatches(args: {
  existingSigner: Pick<AccountSignerRecord, 'signerId' | 'metadata'>;
  expectedFingerprint: string;
}): void {
  const expectedFingerprint = normalizeNonEmpty(
    args.expectedFingerprint,
    'activationPolicy.materialFingerprint',
  );
  const existingFingerprint = getSignerMaterialFingerprint(args.existingSigner);
  if (!existingFingerprint) {
    throw new Error(
      `Existing signer ${args.existingSigner.signerId} is missing signer material fingerprint`,
    );
  }
  if (existingFingerprint !== expectedFingerprint) {
    throw new Error(`Existing signer material mismatch for ${args.existingSigner.signerId}`);
  }
}

export function planAccountSignerActivation(
  input: PlanAccountSignerActivationInput,
): AccountSignerActivationPlan {
  const signerId = normalizeNonEmpty(input.signer.signerId, 'signerId');
  const signerKind = normalizeNonEmpty(input.signer.signerKind, 'signerKind') as SignerKind;
  normalizeNonEmpty(input.signer.signerAuthMethod, 'signerAuthMethod');
  normalizeNonEmpty(input.signer.signerSource, 'signerSource');
  const activeSigners = Array.isArray(input.activeSigners) ? input.activeSigners : [];
  const existingSigner = activeSigners.find((signer) => signer.signerId === signerId);
  const preferredSlot = normalizeOptionalPositiveInteger(input.preferredSlot, 'preferredSlot');

  if (input.activationPolicy.mode === 'reuse_existing') {
    normalizeNonEmpty(input.activationPolicy.signerId, 'activationPolicy.signerId');
    if (input.activationPolicy.signerId !== signerId) {
      throw new Error('reuse_existing activation policy signerId must match signer.signerId');
    }
    normalizeNonEmpty(
      input.activationPolicy.materialFingerprint,
      'activationPolicy.materialFingerprint',
    );
  }

  if (existingSigner) {
    if (input.activationPolicy.mode === 'reuse_existing') {
      assertExistingSignerMaterialMatches({
        existingSigner,
        expectedFingerprint: input.activationPolicy.materialFingerprint,
      });
    }
    const signerSlot = normalizeRequiredPositiveInteger(existingSigner.signerSlot, 'signerSlot');
    return {
      signerSlot,
    };
  }

  if (input.activationPolicy.mode === 'reuse_existing') {
    const conflictingSigner = activeSigners.find((signer) => signer.signerKind === signerKind);
    if (conflictingSigner) {
      throw new Error(
        `Duplicate account registration for ${signerKind}: existing signer ${conflictingSigner.signerId} differs from ${signerId}`,
      );
    }
  }

  if (input.activationPolicy.mode === 'fail_if_occupied') {
    const signerSlot = normalizeRequiredPositiveInteger(
      input.activationPolicy.signerSlot,
      'signerSlot',
    );
    const occupant = activeSigners.find((signer) => signer.signerSlot === signerSlot);
    if (occupant) {
      throw new Error(`Active signer slot ${signerSlot} is already occupied`);
    }
    return {
      signerSlot,
    };
  }

  const reservedSlots = new Set(activeSigners.map((signer) => signer.signerSlot));
  const signerSlot =
    preferredSlot && !reservedSlots.has(preferredSlot)
      ? preferredSlot
      : firstFreeSlot(reservedSlots);
  return {
    signerSlot,
  };
}
