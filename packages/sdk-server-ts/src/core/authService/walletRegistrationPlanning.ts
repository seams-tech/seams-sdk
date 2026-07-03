import { computeSdkEd25519HssApplicationBindingDigestB64u } from '@shared/threshold/ed25519HssBinding';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import {
  computeRegistrationNearEd25519SigningKeyId,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  nearEd25519SigningKeyIdFromString,
  parseServerAllocatedWalletId,
  registrationEd25519AuthorityScope,
  registrationSignerPlanFromSelection,
  type AddSignerIntentV1,
  type NearEd25519SigningKeyId,
  type RegistrationEvmFamilyEcdsaSignerPlan,
  type RegistrationIntentV1,
  type RegistrationNearEd25519SignerPlan,
  type RegistrationNearAccountProvisioning,
  type RegistrationSignerPlan,
  type ResolvedRegistrationNearAccount,
  type ThresholdEd25519RegistrationSpec,
  type RegisterWalletInput,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  thresholdEcdsaChainTargetFromValue,
  type ThresholdEcdsaChainTarget,
} from '../thresholdEcdsaChainTarget';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519RegistrationAccountScope,
  ThresholdRuntimePolicyScope,
} from '../types';
import { normalizeThresholdRuntimePolicyScope } from './thresholdRuntimePolicy';
import { isObject } from './record';
import type { WalletId } from '@shared/utils/domainIds';
import { createWalletId, type RegistrationCeremonyStore } from '../RegistrationCeremonyStore';
import type { WalletStore } from '../WalletStore';

export type RegistrationIntentWalletResolution =
  | {
      ok: true;
      walletId: WalletId;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      code: 'invalid_body' | 'wallet_id_collision';
      message: string;
      walletId?: never;
    };

export async function createAvailableServerAllocatedWalletId(input: {
  readonly walletStore: WalletStore;
  readonly registrationCeremonyStore: RegistrationCeremonyStore;
  readonly expiresAtMs: number;
}): Promise<RegistrationIntentWalletResolution> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const walletId = createWalletId();
    const existing = await input.walletStore.getWallet({ walletId });
    if (existing) continue;
    const reserved = await input.registrationCeremonyStore.reserveServerAllocatedWalletId({
      walletId,
      expiresAtMs: input.expiresAtMs,
    });
    if (reserved) {
      return { ok: true, walletId };
    }
  }
  return {
    ok: false,
    code: 'wallet_id_collision',
    message: 'Unable to allocate an unused server-allocated walletId',
  };
}

export async function reserveProvidedImplicitWalletId(input: {
  readonly walletStore: WalletStore;
  readonly registrationCeremonyStore: RegistrationCeremonyStore;
  readonly walletId: unknown;
  readonly expiresAtMs: number;
}): Promise<RegistrationIntentWalletResolution> {
  const parsed = parseServerAllocatedWalletId(input.walletId);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'implicit account registration requires a generated readable walletId',
    };
  }
  const existing = await input.walletStore.getWallet({ walletId: parsed.value });
  if (existing) {
    return {
      ok: false,
      code: 'wallet_id_collision',
      message: 'walletId is already registered',
    };
  }
  const reserved = await input.registrationCeremonyStore.reserveServerAllocatedWalletId({
    walletId: parsed.value,
    expiresAtMs: input.expiresAtMs,
  });
  if (!reserved) {
    return {
      ok: false,
      code: 'wallet_id_collision',
      message: 'walletId is already reserved',
    };
  }
  return { ok: true, walletId: parsed.value };
}

export async function resolveGenericRegistrationWalletId(input: {
  readonly walletStore: WalletStore;
  readonly registrationCeremonyStore: RegistrationCeremonyStore;
  readonly wallet: RegisterWalletInput | undefined;
  readonly expiresAtMs: number;
}): Promise<RegistrationIntentWalletResolution> {
  if (!input.wallet || input.wallet.kind === 'server_allocated') {
    return await createAvailableServerAllocatedWalletId(input);
  }
  if (input.wallet.kind === 'provided') {
    try {
      return {
        ok: true,
        walletId: walletIdFromString(String(input.wallet.walletId || '').trim()),
      };
    } catch {
      return { ok: false, code: 'invalid_body', message: 'walletId is required' };
    }
  }
  return { ok: false, code: 'invalid_body', message: 'wallet.kind is unsupported' };
}

export async function resolveRegistrationIntentWalletId(input: {
  readonly walletStore: WalletStore;
  readonly registrationCeremonyStore: RegistrationCeremonyStore;
  readonly wallet: RegisterWalletInput | undefined;
  readonly signerPlan: RegistrationSignerPlan;
  readonly expiresAtMs: number;
}): Promise<RegistrationIntentWalletResolution> {
  const nearEd25519Branch = findRegistrationSignerPlanNearEd25519Branch(input.signerPlan);
  if (!nearEd25519Branch) {
    return await resolveGenericRegistrationWalletId(input);
  }
  const provisioning = nearEd25519Branch.accountProvisioning;
  switch (provisioning.kind) {
    case 'implicit_account': {
      if (input.wallet?.kind === 'provided') {
        return await reserveProvidedImplicitWalletId({
          walletStore: input.walletStore,
          registrationCeremonyStore: input.registrationCeremonyStore,
          walletId: input.wallet.walletId,
          expiresAtMs: input.expiresAtMs,
        });
      }
      return await createAvailableServerAllocatedWalletId(input);
    }
    case 'sponsored_named_account': {
      if (input.wallet?.kind !== 'provided') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'sponsored named registration requires a provided walletId',
        };
      }
      const walletId = String(input.wallet.walletId || '').trim();
      if (!walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'walletId is required',
        };
      }
      return { ok: true, walletId: walletIdFromString(walletId) };
    }
    default:
      return assertNever(provisioning);
  }
}

type RegistrationIntentSignerBranches = {
  nearEd25519: RegistrationNearEd25519SignerPlan | null;
  evmFamilyEcdsa: RegistrationEvmFamilyEcdsaSignerPlan | null;
};

type AdjacentFlowEcdsaPrepareSpec = {
  chainTargets: ThresholdEcdsaChainTarget[];
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signingRootId?: string;
  signingRootVersion?: string;
};

function assertNever(value: never): never {
  throw new Error(`Unexpected variant: ${JSON.stringify(value)}`);
}

function knownAccountNearEd25519SigningKeyIdFromNearAccountId(
  nearAccountId: string,
): NearEd25519SigningKeyId {
  return nearEd25519SigningKeyIdFromString(nearAccountId);
}

export function sponsoredNamedRegistrationAccountId(
  provisioning: RegistrationNearAccountProvisioning,
): string | null {
  switch (provisioning.kind) {
    case 'implicit_account':
      return null;
    case 'sponsored_named_account':
      return String(provisioning.requestedAccountId);
    default:
      return assertNever(provisioning);
  }
}

export function resolvedRegistrationNearAccount(input: {
  accountProvisioning: RegistrationNearAccountProvisioning;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  sponsoredTransactionHash?: string;
}):
  | { ok: true; value: ResolvedRegistrationNearAccount }
  | { ok: false; code: string; message: string } {
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(input.nearEd25519SigningKeyId);
  switch (input.accountProvisioning.kind) {
    case 'implicit_account': {
      const parsed = parseImplicitNearAccountId(input.nearAccountId);
      if (!parsed.ok) {
        return { ok: false, code: 'internal', message: parsed.message };
      }
      return {
        ok: true,
        value: {
          kind: 'implicit_account',
          nearAccountId: parsed.value,
          nearEd25519SigningKeyId,
        },
      };
    }
    case 'sponsored_named_account': {
      const parsed = parseNamedNearAccountId(input.nearAccountId);
      if (!parsed.ok) {
        return { ok: false, code: 'internal', message: parsed.message };
      }
      const transactionHash = toOptionalTrimmedString(input.sponsoredTransactionHash);
      if (!transactionHash) {
        return {
          ok: false,
          code: 'internal',
          message: 'Sponsored named registration missing account creation transaction hash',
        };
      }
      return {
        ok: true,
        value: {
          kind: 'sponsored_named_account',
          nearAccountId: parsed.value,
          nearEd25519SigningKeyId,
          transactionHash,
        },
      };
    }
    default:
      return assertNever(input.accountProvisioning);
  }
}

export function thresholdEd25519RegistrationAccountScope(input: {
  walletId: WalletId;
  intentDigestB64u: string;
  signingRootId: string;
  signingRootVersion: string;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
  participantIds: number[];
  accountProvisioning: RegistrationNearAccountProvisioning;
}): ThresholdEd25519RegistrationAccountScope {
  const common = {
    walletId: String(input.walletId),
    intentDigestB64u: input.intentDigestB64u,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    signerSlot: input.signerSlot,
    keyPurpose: input.keyPurpose,
    keyVersion: input.keyVersion,
    derivationVersion: input.derivationVersion,
    participantIds: [...input.participantIds],
  };
  switch (input.accountProvisioning.kind) {
    case 'implicit_account':
      return {
        kind: 'generated_implicit_registration_scope',
        ...common,
      };
    case 'sponsored_named_account':
      return {
        kind: 'sponsored_named_registration_scope',
        ...common,
        requestedAccountId: String(input.accountProvisioning.requestedAccountId),
      };
    default:
      return assertNever(input.accountProvisioning);
  }
}

export function thresholdEd25519KnownAccountRegistrationScope(input: {
  walletId: WalletId;
  intentDigestB64u: string;
  signingRootId: string;
  signingRootVersion: string;
  nearAccountId: string;
  signerSlot: number;
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
  participantIds: number[];
}): Extract<
  ThresholdEd25519RegistrationAccountScope,
  { kind: 'known_account_registration_scope' }
> {
  const nearAccountId = String(input.nearAccountId);
  const nearEd25519SigningKeyId =
    knownAccountNearEd25519SigningKeyIdFromNearAccountId(nearAccountId);
  return {
    kind: 'known_account_registration_scope',
    walletId: String(input.walletId),
    intentDigestB64u: input.intentDigestB64u,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    nearEd25519SigningKeyId,
    signerSlot: input.signerSlot,
    keyPurpose: input.keyPurpose,
    keyVersion: input.keyVersion,
    derivationVersion: input.derivationVersion,
    participantIds: [...input.participantIds],
    nearAccountId,
  };
}

export async function thresholdEd25519HssContextFromRegistrationAccountScope(
  scope: ThresholdEd25519RegistrationAccountScope,
): Promise<ThresholdEd25519HssCanonicalContext> {
  return {
    applicationBindingDigestB64u: await computeSdkEd25519HssApplicationBindingDigestB64u({
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(scope.nearEd25519SigningKeyId),
      signingRootId: parseSdkEcdsaHssSigningRootId(scope.signingRootId),
      signingRootVersion: parseSdkEcdsaHssSigningRootVersion(scope.signingRootVersion),
    }),
    participantIds: [...scope.participantIds],
  };
}

export function registrationIntentSigningRootId(input: {
  signingRootId?: string;
  intent: RegistrationIntentV1;
}): string {
  return (
    toOptionalTrimmedString(input.signingRootId) ||
    (input.intent.runtimePolicyScope ? deriveSigningRootId(input.intent.runtimePolicyScope) : '')
  );
}

export function registrationIntentSigningRootVersion(input: {
  signingRootVersion?: string;
  intent: RegistrationIntentV1;
}): string {
  return (
    toOptionalTrimmedString(input.signingRootVersion) ||
    toOptionalTrimmedString(input.intent.runtimePolicyScope?.signingRootVersion) ||
    'default'
  );
}

function registrationIntentSignerPlan(intent: RegistrationIntentV1): RegistrationSignerPlan {
  const plan = registrationSignerPlanFromSelection(intent.signerSelection);
  if (!plan.ok) {
    throw new Error(plan.message || 'registration signer plan is invalid');
  }
  return plan.value;
}

export function registrationIntentSignerBranches(
  intent: RegistrationIntentV1,
): RegistrationIntentSignerBranches {
  const plan = registrationIntentSignerPlan(intent);
  return {
    nearEd25519: findRegistrationSignerPlanNearEd25519Branch(plan),
    evmFamilyEcdsa: findRegistrationSignerPlanEvmFamilyEcdsaBranch(plan),
  };
}

function requireRegistrationIntentNearEd25519Branch(
  intent: RegistrationIntentV1,
): RegistrationNearEd25519SignerPlan {
  const branch = registrationIntentSignerBranches(intent).nearEd25519;
  if (!branch) {
    throw new Error('Ed25519 registration key scope requires an Ed25519 signer selection');
  }
  return branch;
}

export function registrationEd25519SpecFromPlanBranch(
  branch: RegistrationNearEd25519SignerPlan,
): ThresholdEd25519RegistrationSpec {
  return {
    accountProvisioning: branch.accountProvisioning,
    signerSlot: branch.signerSlot,
    participantIds: [...branch.participantIds],
    keyPurpose: branch.keyPurpose,
    keyVersion: branch.keyVersion,
    derivationVersion: branch.derivationVersion,
  };
}

export function normalizeRegistrationEcdsaChainTargets(
  branch: RegistrationEvmFamilyEcdsaSignerPlan | null,
): { ok: true; chainTargets: ThresholdEcdsaChainTarget[] } | { ok: false; message: string } {
  if (!branch) return { ok: true, chainTargets: [] };
  const chainTargets: ThresholdEcdsaChainTarget[] = [];
  for (const target of branch.chainTargets) {
    const chainTarget = thresholdEcdsaChainTargetFromValue(target);
    if (!chainTarget) {
      return { ok: false, message: 'ECDSA registration contains an invalid chain target' };
    }
    chainTargets.push(chainTarget);
  }
  return { ok: true, chainTargets };
}

export async function registrationIntentNearEd25519SigningKeyId(input: {
  signingRootId?: string;
  signingRootVersion?: string;
  intent: RegistrationIntentV1;
}): Promise<NearEd25519SigningKeyId> {
  const ed25519 = registrationEd25519SpecFromPlanBranch(
    requireRegistrationIntentNearEd25519Branch(input.intent),
  );
  return await computeRegistrationNearEd25519SigningKeyId({
    walletId: input.intent.walletId,
    authorityScope: registrationEd25519AuthorityScope(input.intent.authMethod),
    signingRootId: registrationIntentSigningRootId({
      signingRootId: input.signingRootId,
      intent: input.intent,
    }),
    signingRootVersion: registrationIntentSigningRootVersion({
      signingRootVersion: input.signingRootVersion,
      intent: input.intent,
    }),
    ed25519,
  });
}

export function addSignerIntentSigningRootId(input: {
  signingRootId?: string;
  intent: AddSignerIntentV1;
}): string {
  return (
    toOptionalTrimmedString(input.signingRootId) ||
    (input.intent.runtimePolicyScope ? deriveSigningRootId(input.intent.runtimePolicyScope) : '')
  );
}

export function normalizeAdjacentFlowEcdsaPrepareSpec(
  raw: unknown,
):
  | { ok: true; value: AdjacentFlowEcdsaPrepareSpec | null }
  | { ok: false; code: string; message: string } {
  if (raw == null) return { ok: true, value: null };
  if (!isObject(raw)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ecdsa_prepare must be an object',
    };
  }
  const chainTargetRaw = raw.chainTargets ?? raw.chain_targets;
  const participantIdRaw = raw.participantIds ?? raw.participant_ids;
  const chainTargets = Array.isArray(chainTargetRaw)
    ? chainTargetRaw.map((target) => thresholdEcdsaChainTargetFromValue(target))
    : [];
  const normalizedChainTargets = chainTargets.filter(
    (target): target is ThresholdEcdsaChainTarget => Boolean(target),
  );
  if (
    normalizedChainTargets.length === 0 ||
    normalizedChainTargets.length !== chainTargets.length
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ecdsa_prepare.chainTargets must contain valid chain targets',
    };
  }
  const participantIds = Array.isArray(participantIdRaw)
    ? participantIdRaw.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)
    : [];
  if (participantIds.length === 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'threshold_ecdsa_prepare.participantIds must contain positive integers',
    };
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    raw.runtimePolicyScope ?? raw.runtime_policy_scope,
  );
  const signingRootId = toOptionalTrimmedString(raw.signingRootId ?? raw.signing_root_id);
  const signingRootVersion = toOptionalTrimmedString(
    raw.signingRootVersion ?? raw.signing_root_version,
  );
  return {
    ok: true,
    value: {
      chainTargets: normalizedChainTargets,
      participantIds: Array.from(new Set(participantIds)).sort((a, b) => a - b),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(signingRootId ? { signingRootId } : {}),
      ...(signingRootVersion ? { signingRootVersion } : {}),
    },
  };
}
