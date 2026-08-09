import type {
  CloudflareDurableObjectNamespaceLike,
  EcdsaDerivationServerBootstrapResponse,
} from './types';
import type {
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentGrant,
  AddSignerIntentV1,
  RegistrationIntentV1,
  WalletAddSignerStartResponse,
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddAuthMethodRegistrationOptions,
  WalletRegistrationStartResponse,
  WalletId,
} from './registrationContracts';
import type {
  RegistrationAuthority,
  RegistrationSignerPlanBranch,
  RegistrationSignerRequest,
  RegistrationSignerPlan,
  RegistrationSignerBranchKey,
} from '@shared/utils/registrationIntent';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  addAuthMethodIntentGrantFromString,
  normalizeAddAuthMethodInput,
  normalizeRegistrationSignerPlan,
  registrationSignerPlanFromSelection,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseEmailOtpProviderUserId,
  parseOrgId,
  parseProviderSubject,
  parseWalletId,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  parseWebAuthnAuthenticatorDeviceInfo,
  unknownWebAuthnAuthenticatorDeviceInfo,
} from '@shared/utils/webauthnDeviceInfo';
import type { NormalizedLogger } from './logger';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from './defaultConfigsServer';
import { base64UrlDecode } from '@shared/utils/encoders';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  parseThresholdEd25519AuthorityScope,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  thresholdEd25519AuthorityScopesMatch,
} from './ThresholdService/validation';
import { parseWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from './thresholdEcdsaChainTarget';
import type {
  RouterAbEd25519YaoActivationAdmissionReceiptV1,
  RouterAbEd25519YaoActivationResultV1,
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaRegistrationRequestV1,
  RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEcdsaPendingActivationV1 } from '../router/domains/ecdsa/routerAbEcdsaStrictRegistration';
import type { WalletEd25519SignerRecord } from './WalletStore';

export type StoredAddSignerIntent = {
  kind: 'add_signer_intent_allocated';
  grant: AddSignerIntentGrant;
  intent: AddSignerIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  consumedAtMs?: never;
};

export type ConsumedAddSignerIntent = Omit<StoredAddSignerIntent, 'kind' | 'consumedAtMs'> & {
  kind: 'add_signer_intent_consumed';
  consumedAtMs: number;
};

export type StoredAddAuthMethodIntent = {
  kind: 'add_auth_method_intent_allocated';
  grant: AddAuthMethodIntentGrant;
  intent: AddAuthMethodIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  consumedAtMs?: never;
};

export type ConsumedAddAuthMethodIntent = Omit<
  StoredAddAuthMethodIntent,
  'kind' | 'consumedAtMs'
> & {
  kind: 'add_auth_method_intent_consumed';
  consumedAtMs: number;
};

export type StoredRegistrationWebAuthnCredential = {
  credentialIdB64u: string;
  credentialPublicKeyB64u: string;
  counter: number;
};

export type StoredRegistrationAuthority = RegistrationAuthority;

type WalletRegistrationEcdsaStartPayload = NonNullable<
  Extract<WalletRegistrationStartResponse, { ok: true }>['ecdsa']
>;

type WalletAddSignerEcdsaStartPayload = Omit<
  NonNullable<Extract<WalletAddSignerStartResponse, { ok: true }>['ecdsa']>,
  'custodyEnvelope'
>;

export type StoredWalletRegistrationRuntimePolicyContext =
  | {
      kind: 'runtime_policy_scope';
      scope: RuntimePolicyScope;
    }
  | {
      kind: 'signing_root_only';
      scope?: never;
    };

export type StoredWalletRegistrationEcdsaPreparedContext =
  | {
      kind: 'evm_family_ecdsa_requested';
      chainTargets: readonly ThresholdEcdsaChainTarget[];
    }
  | {
      kind: 'evm_family_ecdsa_absent';
      chainTargets?: never;
    };

export type StoredWalletRegistrationPreparedContext = {
  kind: 'wallet_registration_prepared_context_v1';
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicy: StoredWalletRegistrationRuntimePolicyContext;
  ecdsa: StoredWalletRegistrationEcdsaPreparedContext;
};

export function buildStoredWalletRegistrationPreparedContext(input: {
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: RuntimePolicyScope | null;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[] | null;
}): StoredWalletRegistrationPreparedContext {
  const signingRootId = String(input.signingRootId || '').trim();
  const signingRootVersion = String(input.signingRootVersion || '').trim();
  if (!signingRootId || !signingRootVersion) {
    throw new Error('registration prepared context requires signing-root scope');
  }
  return {
    kind: 'wallet_registration_prepared_context_v1',
    signingRootId,
    signingRootVersion,
    runtimePolicy: input.runtimePolicyScope
      ? {
          kind: 'runtime_policy_scope',
          scope: {
            orgId: input.runtimePolicyScope.orgId,
            projectId: input.runtimePolicyScope.projectId,
            envId: input.runtimePolicyScope.envId,
            signingRootVersion: input.runtimePolicyScope.signingRootVersion,
          },
        }
      : { kind: 'signing_root_only' },
    ecdsa:
      input.ecdsaChainTargets && input.ecdsaChainTargets.length > 0
        ? {
            kind: 'evm_family_ecdsa_requested',
            chainTargets: input.ecdsaChainTargets.map((target) => ({ ...target })),
          }
        : { kind: 'evm_family_ecdsa_absent' },
  };
}

export function storedWalletRegistrationPreparedContextsMatch(
  left: StoredWalletRegistrationPreparedContext,
  right: StoredWalletRegistrationPreparedContext,
): boolean {
  if (
    left.kind !== right.kind ||
    left.signingRootId !== right.signingRootId ||
    left.signingRootVersion !== right.signingRootVersion ||
    left.runtimePolicy.kind !== right.runtimePolicy.kind ||
    left.ecdsa.kind !== right.ecdsa.kind
  ) {
    return false;
  }
  if (
    left.runtimePolicy.kind === 'runtime_policy_scope' &&
    right.runtimePolicy.kind === 'runtime_policy_scope' &&
    (left.runtimePolicy.scope.orgId !== right.runtimePolicy.scope.orgId ||
      left.runtimePolicy.scope.projectId !== right.runtimePolicy.scope.projectId ||
      left.runtimePolicy.scope.envId !== right.runtimePolicy.scope.envId ||
      left.runtimePolicy.scope.signingRootVersion !== right.runtimePolicy.scope.signingRootVersion)
  ) {
    return false;
  }
  if (
    left.ecdsa.kind === 'evm_family_ecdsa_requested' &&
    right.ecdsa.kind === 'evm_family_ecdsa_requested'
  ) {
    const leftTargets = left.ecdsa.chainTargets;
    const rightTargets = right.ecdsa.chainTargets;
    if (leftTargets.length !== rightTargets.length) return false;
    return leftTargets.every(
      (target, index) =>
        thresholdEcdsaChainTargetKey(target) === thresholdEcdsaChainTargetKey(rightTargets[index]),
    );
  }
  return true;
}

export function storedRegistrationAuthoritiesMatch(
  left: StoredRegistrationAuthority,
  right: StoredRegistrationAuthority,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      return (
        right.kind === 'passkey' &&
        left.walletId === right.walletId &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u &&
        left.credentialPublicKeyB64u === right.credentialPublicKeyB64u &&
        left.registrationIntentDigestB64u === right.registrationIntentDigestB64u
      );
    case 'email_otp':
      return (
        right.kind === 'email_otp' &&
        left.proofKind === right.proofKind &&
        left.walletId === right.walletId &&
        left.providerSubject === right.providerSubject &&
        left.emailHashHex === right.emailHashHex &&
        left.registrationAuthorityId === right.registrationAuthorityId &&
        left.finalWalletId === right.finalWalletId &&
        left.orgId === right.orgId &&
        left.registrationIntentDigestB64u === right.registrationIntentDigestB64u
      );
    default: {
      const exhaustive: never = left;
      return exhaustive;
    }
  }
}

type StoredEcdsaRegistrationBase = Omit<WalletRegistrationEcdsaStartPayload, 'kind'> & {
  derivationKind: WalletRegistrationEcdsaStartPayload['kind'];
  strictRegistrationBindingJson: string;
};

export type StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch = StoredEcdsaRegistrationBase & {
  kind: 'evm_family_ecdsa_prepared';
  branchKey: RegistrationSignerBranchKey;
};

export type StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch =
  StoredEcdsaRegistrationBase & {
    kind: 'evm_family_ecdsa_pending_activation';
    branchKey: RegistrationSignerBranchKey;
    registrationRequest: RouterAbEcdsaRegistrationRequestV1;
    pendingActivation: RouterAbEcdsaPendingActivationV1;
    publicResponse: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
  };

export type StoredWalletRegistrationEvmFamilyEcdsaResponseClaimedBranch =
  StoredEcdsaRegistrationBase & {
    kind: 'evm_family_ecdsa_response_claimed';
    branchKey: RegistrationSignerBranchKey;
    registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  };

export type StoredWalletRegistrationEvmFamilyEcdsaActivationClaimedBranch =
  StoredEcdsaRegistrationBase & {
    kind: 'evm_family_ecdsa_activation_claimed';
    branchKey: RegistrationSignerBranchKey;
    registrationRequest: RouterAbEcdsaRegistrationRequestV1;
    pendingActivation: RouterAbEcdsaPendingActivationV1;
    publicResponse: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
    publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
    activationRequestDigestB64u: string;
    /**
     * The activate operation (idempotency key) that claimed this activation.
     * One owner per ceremony: only the claiming operation may resume the
     * claim or read its result, so a second activate with a different key
     * cannot adopt the claim and re-run custody. Empty only on rows written
     * before this field existed.
     */
    activationOwner: string;
  };

export type StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch = StoredEcdsaRegistrationBase & {
  kind: 'evm_family_ecdsa_activated';
  branchKey: RegistrationSignerBranchKey;
  registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  activation: RouterAbEcdsaRegistrationActivationReceiptV1;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  bootstrap: EcdsaDerivationServerBootstrapResponse;
  /** Carried from the claim: only the owning operation may read this result back. */
  activationOwner: string;
};

/**
 * The ECDSA signer is durable and the wallet is usable. Reached only on a plan
 * that also has an Ed25519 branch: registration returns ECDSA-ready here and
 * the ceremony stays open for the Ed25519 finalize (Refactor 94 Phase 4+5).
 * On an ECDSA-only plan the ceremony is deleted instead, so this state never
 * appears.
 */
export type StoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch = StoredEcdsaRegistrationBase & {
  kind: 'evm_family_ecdsa_finalized';
  branchKey: RegistrationSignerBranchKey;
  registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  activation: RouterAbEcdsaRegistrationActivationReceiptV1;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  bootstrap: EcdsaDerivationServerBootstrapResponse;
  finalizedAtMs: number;
};

export type StoredWalletRegistrationNearEd25519YaoAuthorizedBranch = {
  kind: 'near_ed25519_yao_authorized';
  branchKey: RegistrationSignerBranchKey;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
};

export type StoredWalletRegistrationSignerBranch =
  | StoredWalletRegistrationNearEd25519YaoAuthorizedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaResponseClaimedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch
  | StoredWalletRegistrationEvmFamilyEcdsaActivationClaimedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch;

export type StoredWalletRegistrationSignerSetState = {
  kind: 'signer_set_registration';
  branches: readonly StoredWalletRegistrationSignerBranch[];
};

export type StoredWalletRegistrationEvmFamilyEcdsaBranch =
  | StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaResponseClaimedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch
  | StoredWalletRegistrationEvmFamilyEcdsaActivationClaimedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch
  | StoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch;

export function buildStoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch(input: {
  readonly activated: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch;
  readonly finalizedAtMs: number;
}): StoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch {
  /* The finalized branch is terminal: the activation owner has read its
     result, so the ownership field does not survive into it. */
  const { activationOwner: _activationOwner, ...activated } = input.activated;
  return { ...activated, kind: 'evm_family_ecdsa_finalized', finalizedAtMs: input.finalizedAtMs };
}

export function buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch(input: {
  readonly branchKey: RegistrationSignerBranchKey;
  readonly ecdsa: {
    readonly kind: StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch['derivationKind'];
    readonly chainTargets: StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch['chainTargets'];
    readonly prepare: StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch['prepare'];
    readonly strictRegistration: StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch['strictRegistration'];
    readonly strictRegistrationBindingJson: string;
  };
}): StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch {
  return {
    kind: 'evm_family_ecdsa_prepared',
    branchKey: input.branchKey,
    derivationKind: input.ecdsa.kind,
    chainTargets: input.ecdsa.chainTargets,
    prepare: input.ecdsa.prepare,
    strictRegistration: input.ecdsa.strictRegistration,
    strictRegistrationBindingJson: input.ecdsa.strictRegistrationBindingJson,
  };
}

export function buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch(input: {
  readonly branchKey: RegistrationSignerBranchKey;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
}): StoredWalletRegistrationNearEd25519YaoAuthorizedBranch {
  return {
    kind: 'near_ed25519_yao_authorized',
    branchKey: input.branchKey,
    admissionRequest: input.admissionRequest,
    admissionReceipt: input.admissionReceipt,
  };
}

export function findStoredWalletRegistrationNearEd25519YaoBranch(
  state: StoredWalletRegistrationSignerSetState,
): StoredWalletRegistrationNearEd25519YaoAuthorizedBranch | null {
  for (const branch of state.branches) {
    if (branch.kind === 'near_ed25519_yao_authorized') return branch;
  }
  return null;
}

export function findStoredWalletRegistrationEvmFamilyEcdsaBranch(
  state: StoredWalletRegistrationSignerSetState,
): StoredWalletRegistrationEvmFamilyEcdsaBranch | null {
  for (const branch of state.branches) {
    if (
      branch.kind === 'evm_family_ecdsa_prepared' ||
      branch.kind === 'evm_family_ecdsa_response_claimed' ||
      branch.kind === 'evm_family_ecdsa_pending_activation' ||
      branch.kind === 'evm_family_ecdsa_activation_claimed' ||
      branch.kind === 'evm_family_ecdsa_activated' ||
      branch.kind === 'evm_family_ecdsa_finalized'
    ) {
      return branch;
    }
  }
  return null;
}

export function replaceStoredWalletRegistrationSignerBranch(input: {
  readonly state: StoredWalletRegistrationSignerSetState;
  readonly replacement: StoredWalletRegistrationSignerBranch;
}): StoredWalletRegistrationSignerSetState {
  return {
    kind: 'signer_set_registration',
    branches: input.state.branches.map((branch) =>
      branch.branchKey === input.replacement.branchKey ? input.replacement : branch,
    ),
  };
}

export type StoredWalletRegistrationFailed = {
  kind: 'registration_failed';
  failedAtMs: number;
  failure: {
    code: string;
    message: string;
  };
  ceremonyHandle?: never;
  preparedSession?: never;
  clientOtOfferMessageB64u?: never;
  prepare?: never;
  walletKeys?: never;
  responded?: never;
  completed?: never;
};

export type StoredWalletRegistrationSignerState =
  | StoredWalletRegistrationSignerSetState
  | StoredWalletRegistrationFailed;

/**
 * Refactor 94C. A registration ceremony now exists before its authority proof
 * does.
 *
 * `/wallets/register/setup` issues the challenge the client's WebAuthn create
 * must sign, so the ceremony — and the Router preparation work bound to it —
 * is necessarily created *before* the user has touched the sensor. The proof
 * arrives one leg later, on `/wallets/register/respond`, which binds it.
 *
 * This is a union rather than an optional field so that no reader can consume
 * an authority that has not been verified: the awaiting arm carries only the
 * requested auth method, which is public intent data, and offers no
 * `authority` to read.
 */
export type StoredWalletRegistrationCeremonyAuthorityState =
  | {
      kind: 'awaiting_proof';
      /** The requested method, echoed from the intent; not evidence of anything. */
      authMethod: RegistrationIntentV1['authMethod'];
      authority?: never;
    }
  | {
      kind: 'verified';
      authority: StoredRegistrationAuthority;
      authMethod?: never;
    };

type StoredWalletRegistrationCeremonyBase = {
  registrationCeremonyId: string;
  intent: RegistrationIntentV1;
  digestB64u: string;
  signerPlan: RegistrationSignerPlan;
  preparedContext: StoredWalletRegistrationPreparedContext;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  authorityState: StoredWalletRegistrationCeremonyAuthorityState;
};

export type StoredWalletRegistrationCeremony = StoredWalletRegistrationCeremonyBase & {
  signerState: StoredWalletRegistrationSignerState;
};

/**
 * The verified authority, or `null` while the ceremony is still awaiting its
 * proof. Legs downstream of respond (activation, finalization, persistence)
 * require a verified authority and treat `null` as an invalid state rather
 * than a missing field.
 */
export function verifiedRegistrationCeremonyAuthority(ceremony: {
  readonly authorityState: StoredWalletRegistrationCeremonyAuthorityState;
}): StoredRegistrationAuthority | null {
  return ceremony.authorityState.kind === 'verified' ? ceremony.authorityState.authority : null;
}

export function registrationCeremonyAuthorityRpId(
  authorityState: StoredWalletRegistrationCeremonyAuthorityState,
): string | null {
  switch (authorityState.kind) {
    case 'awaiting_proof':
      return authorityState.authMethod.kind === 'passkey'
        ? String(authorityState.authMethod.rpId)
        : null;
    case 'verified':
      return authorityState.authority.kind === 'passkey'
        ? String(authorityState.authority.rpId)
        : null;
    default: {
      const exhaustive: never = authorityState;
      return exhaustive;
    }
  }
}

export type TerminalRegistrationCeremonyCancellationResult =
  | {
      kind: 'cancelled';
      ceremonyDeleted: true;
    }
  | {
      kind: 'not_found';
      ceremonyDeleted: false;
    };

export function parseTerminalRegistrationCeremonyCancellationResult(
  value: unknown,
): TerminalRegistrationCeremonyCancellationResult | null {
  if (!isRecord(value)) return null;
  switch (value.kind) {
    case 'cancelled':
      return value.ceremonyDeleted === true
        ? { kind: 'cancelled', ceremonyDeleted: true }
        : null;
    case 'not_found':
      return value.ceremonyDeleted === false
        ? { kind: 'not_found', ceremonyDeleted: false }
        : null;
    default:
      return null;
  }
}

type StoredEcdsaAddSignerBase = Omit<WalletAddSignerEcdsaStartPayload, 'kind'> & {
  derivationKind: WalletAddSignerEcdsaStartPayload['kind'];
};

export type StoredEcdsaAddSignerPrepared = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_prepared';
  pendingActivation?: never;
  publicResponse?: never;
  publicFacts?: never;
  activation?: never;
  bootstrap?: never;
};

export type StoredEcdsaAddSignerPendingActivation = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_pending_activation';
  registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  pendingActivation: RouterAbEcdsaPendingActivationV1;
  publicResponse: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
  publicFacts?: never;
  activation?: never;
  bootstrap?: never;
};

/**
 * The prepared activation coordinates, recorded before any Router custody work
 * runs. The client computed the activation request digest from the canonical
 * add-signer activation command; a retry after a crash between the Router
 * commit and the store update finds this claim, must present the exact same
 * coordinates, and replays the canonical Router activation to completion.
 */
export type StoredEcdsaAddSignerActivationClaimed = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_activation_claimed';
  registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  pendingActivation: RouterAbEcdsaPendingActivationV1;
  publicResponse: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  activationRequestDigestB64u: string;
  activation?: never;
  bootstrap?: never;
};

export type StoredEcdsaAddSignerActivated = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_activated';
  pendingActivation?: never;
  publicResponse?: never;
  registrationRequest: RouterAbEcdsaRegistrationRequestV1;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  /** Carried from the claim so a replay is judged against what this server
   * committed to, not against what the Router echoed back. */
  activationRequestDigestB64u: string;
  activation: RouterAbEcdsaRegistrationActivationReceiptV1;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  bootstrap: EcdsaDerivationServerBootstrapResponse;
};

export type StoredEd25519YaoAddSignerAuthorized = {
  kind: 'near_ed25519_yao_add_signer_authorized';
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
};

export type StoredEd25519YaoAddSignerActivation = {
  finalizeRequest: Extract<StoredWalletAddSignerFinalizeRequest, { kind: 'near_ed25519' }>;
  activation: {
    admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
    result: RouterAbEd25519YaoActivationResultV1<'registration'>;
  };
};

export type StoredEd25519YaoAddSignerActivated = StoredEd25519YaoAddSignerActivation & {
  kind: 'near_ed25519_yao_add_signer_activated';
};

export type StoredEd25519YaoAddSignerFinalizing = StoredEd25519YaoAddSignerActivation & {
  kind: 'near_ed25519_yao_add_signer_finalizing';
  response: Extract<
    Extract<WalletAddSignerFinalizeResponse, { ok: true }>,
    { kind: 'near_ed25519' }
  >;
  signer: WalletEd25519SignerRecord;
  finalizingAtMs: number;
};

export type StoredWalletAddSignerSignerState =
  | StoredEcdsaAddSignerPrepared
  | StoredEcdsaAddSignerPendingActivation
  | StoredEcdsaAddSignerActivationClaimed
  | StoredEcdsaAddSignerActivated
  | StoredEd25519YaoAddSignerAuthorized
  | StoredEd25519YaoAddSignerActivated
  | StoredEd25519YaoAddSignerFinalizing;

export type StoredWalletAddSignerCeremony = {
  addSignerCeremonyId: string;
  intent: AddSignerIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  auth:
    | {
        kind: 'webauthn_assertion';
        rpId: string;
        credentialIdB64u: string;
      }
    | {
        kind: 'app_session';
      };
  signerState: StoredWalletAddSignerSignerState;
};

export type StoredWalletAddSignerFinalizeReplay = {
  kind: 'wallet_add_signer_finalize_replay_v1';
  addSignerCeremonyId: string;
  idempotencyKey: string;
  request: StoredWalletAddSignerFinalizeRequest;
  response: Extract<WalletAddSignerFinalizeResponse, { ok: true }>;
  createdAtMs: number;
  expiresAtMs: number;
};

export type StoredWalletAddSignerFinalizeRequest =
  | {
      kind: 'near_ed25519';
      addSignerCeremonyId: string;
      idempotencyKey: string;
      custodyKeySet: Extract<
        WalletAddSignerFinalizeRequest,
        { readonly kind: 'near_ed25519' }
      >['custodyKeySet'];
      activationReference: {
        lifecycleId: string;
        sessionId: RouterAbEd25519YaoBytes32V1;
      };
      expectedKeyHandles?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      addSignerCeremonyId: string;
      idempotencyKey: string;
      custodyKeySet: Extract<
        WalletAddSignerFinalizeRequest,
        { readonly kind: 'evm_family_ecdsa' }
      >['custodyKeySet'];
      expectedKeyHandles: readonly [string];
      activationReference?: never;
    };

type StoredWalletAddAuthMethodCeremonyBase = {
  addAuthMethodCeremonyId: string;
  intent: AddAuthMethodIntentV1;
  digestB64u: string;
  orgId: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  auth:
    | {
        kind: 'webauthn_assertion';
        rpId: string;
        credentialIdB64u: string;
      }
    | {
      kind: 'app_session';
    };
};

export type StoredWalletAddAuthMethodCeremony =
  | (StoredWalletAddAuthMethodCeremonyBase & {
      kind: 'email_otp';
      authority: Extract<StoredRegistrationAuthority, { kind: 'email_otp' }>;
      passkeyRegistration?: never;
      custodyEnvelope?: never;
    })
  | (StoredWalletAddAuthMethodCeremonyBase & {
      kind: 'passkey';
      authority?: never;
      passkeyRegistration: {
        readonly rpId: string;
        readonly challengeB64u: string;
        readonly options: WalletAddAuthMethodRegistrationOptions;
      };
      custodyEnvelope: PasskeyCustodyEnvelopeRecord;
    });

export interface RegistrationCeremonyStore {
  putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void>;
  getAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<StoredAddAuthMethodIntent | null>;
  takeAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<ConsumedAddAuthMethodIntent | null>;
  putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void>;
  getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null>;
  takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null>;
  putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void>;
  getCeremony(registrationCeremonyId: string): Promise<StoredWalletRegistrationCeremony | null>;
  updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void>;
  takeCeremony(registrationCeremonyId: string): Promise<StoredWalletRegistrationCeremony | null>;
  cancelTerminalCeremony(input: {
    registrationCeremonyId: string;
    walletId: WalletId;
  }): Promise<TerminalRegistrationCeremonyCancellationResult>;
  putAddSignerFinalizeReplay(replay: StoredWalletAddSignerFinalizeReplay): Promise<void>;
  getAddSignerFinalizeReplay(input: {
    addSignerCeremonyId: string;
    idempotencyKey: string;
  }): Promise<StoredWalletAddSignerFinalizeReplay | null>;
  getAddSignerFinalizeReplayForCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerFinalizeReplay | null>;
  putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void>;
  getAddSignerCeremony(addSignerCeremonyId: string): Promise<StoredWalletAddSignerCeremony | null>;
  updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void>;
  takeAddSignerCeremony(addSignerCeremonyId: string): Promise<StoredWalletAddSignerCeremony | null>;
  putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void>;
  getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null>;
  updateAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void>;
  takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null>;
}

export class MemoryRegistrationCeremonyStore implements RegistrationCeremonyStore {
  private readonly addAuthMethodIntents = new Map<string, StoredAddAuthMethodIntent>();
  private readonly addSignerIntents = new Map<string, StoredAddSignerIntent>();
  private readonly ceremonies = new Map<string, StoredWalletRegistrationCeremony>();
  private readonly addSignerFinalizeReplays = new Map<
    string,
    StoredWalletAddSignerFinalizeReplay
  >();
  private readonly addSignerFinalizeReplayClaims = new Map<
    string,
    StoredWalletAddSignerFinalizeReplay
  >();
  private readonly addAuthMethodCeremonies = new Map<string, StoredWalletAddAuthMethodCeremony>();
  private readonly addSignerCeremonies = new Map<string, StoredWalletAddSignerCeremony>();

  async putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void> {
    this.pruneExpired();
    this.addAuthMethodIntents.set(intent.grant, intent);
  }

  async getAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<StoredAddAuthMethodIntent | null> {
    this.pruneExpired();
    const intent = this.addAuthMethodIntents.get(String(grant || '').trim()) || null;
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<ConsumedAddAuthMethodIntent | null> {
    this.pruneExpired();
    const key = String(grant || '').trim();
    const intent = this.addAuthMethodIntents.get(key) || null;
    if (!intent) return null;
    this.addAuthMethodIntents.delete(key);
    if (intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_auth_method_intent_consumed', consumedAtMs: Date.now() };
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    this.pruneExpired();
    this.addSignerIntents.set(intent.grant, intent);
  }

  async getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null> {
    this.pruneExpired();
    const intent = this.addSignerIntents.get(String(grant || '').trim()) || null;
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null> {
    this.pruneExpired();
    const key = String(grant || '').trim();
    const intent = this.addSignerIntents.get(key) || null;
    if (!intent) return null;
    this.addSignerIntents.delete(key);
    if (intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_signer_intent_consumed', consumedAtMs: Date.now() };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    this.pruneExpired();
    this.ceremonies.set(ceremony.registrationCeremonyId, ceremony);
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    this.pruneExpired();
    const ceremony = this.ceremonies.get(String(registrationCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.ceremonies.set(ceremony.registrationCeremonyId, ceremony);
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    this.pruneExpired();
    const key = String(registrationCeremonyId || '').trim();
    const ceremony = this.ceremonies.get(key) || null;
    this.ceremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async cancelTerminalCeremony(input: {
    registrationCeremonyId: string;
    walletId: WalletId;
  }): Promise<TerminalRegistrationCeremonyCancellationResult> {
    this.pruneExpired();
    const registrationCeremonyId = trimString(input.registrationCeremonyId);
    const ceremony = this.ceremonies.get(registrationCeremonyId);
    if (!ceremony) {
      return {
        kind: 'not_found',
        ceremonyDeleted: false,
      };
    }
    if (ceremony.intent.walletId !== input.walletId) {
      throw new Error('Terminal registration cancellation walletId mismatch');
    }
    this.ceremonies.delete(registrationCeremonyId);
    return {
      kind: 'cancelled',
      ceremonyDeleted: true,
    };
  }

  async putAddSignerFinalizeReplay(replay: StoredWalletAddSignerFinalizeReplay): Promise<void> {
    this.pruneExpired();
    this.addSignerFinalizeReplays.set(addSignerFinalizeReplayKey(replay), replay);
    this.addSignerFinalizeReplayClaims.set(replay.addSignerCeremonyId, replay);
  }

  async getAddSignerFinalizeReplay(input: {
    addSignerCeremonyId: string;
    idempotencyKey: string;
  }): Promise<StoredWalletAddSignerFinalizeReplay | null> {
    this.pruneExpired();
    const replay = this.addSignerFinalizeReplays.get(addSignerFinalizeReplayKey(input)) || null;
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async getAddSignerFinalizeReplayForCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerFinalizeReplay | null> {
    this.pruneExpired();
    const replay = this.addSignerFinalizeReplayClaims.get(trimString(addSignerCeremonyId)) || null;
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    this.pruneExpired();
    this.addAuthMethodCeremonies.set(ceremony.addAuthMethodCeremonyId, ceremony);
  }

  async getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    this.pruneExpired();
    const ceremony =
      this.addAuthMethodCeremonies.get(String(addAuthMethodCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.addAuthMethodCeremonies.set(ceremony.addAuthMethodCeremonyId, ceremony);
  }

  async takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    this.pruneExpired();
    const key = String(addAuthMethodCeremonyId || '').trim();
    const ceremony = this.addAuthMethodCeremonies.get(key) || null;
    this.addAuthMethodCeremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    this.pruneExpired();
    this.addSignerCeremonies.set(ceremony.addSignerCeremonyId, ceremony);
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    this.pruneExpired();
    const ceremony = this.addSignerCeremonies.get(String(addSignerCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.addSignerCeremonies.set(ceremony.addSignerCeremonyId, ceremony);
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    this.pruneExpired();
    const key = String(addSignerCeremonyId || '').trim();
    const ceremony = this.addSignerCeremonies.get(key) || null;
    this.addSignerCeremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, intent] of this.addAuthMethodIntents) {
      if (intent.expiresAtMs <= now) this.addAuthMethodIntents.delete(key);
    }
    for (const [key, intent] of this.addSignerIntents) {
      if (intent.expiresAtMs <= now) this.addSignerIntents.delete(key);
    }
    for (const [key, ceremony] of this.ceremonies) {
      if (ceremony.expiresAtMs <= now) this.ceremonies.delete(key);
    }
    for (const [key, replay] of this.addSignerFinalizeReplays) {
      if (replay.expiresAtMs <= now) this.addSignerFinalizeReplays.delete(key);
    }
    for (const [key, replay] of this.addSignerFinalizeReplayClaims) {
      if (replay.expiresAtMs <= now) this.addSignerFinalizeReplayClaims.delete(key);
    }
    for (const [key, ceremony] of this.addAuthMethodCeremonies) {
      if (ceremony.expiresAtMs <= now) this.addAuthMethodCeremonies.delete(key);
    }
    for (const [key, ceremony] of this.addSignerCeremonies) {
      if (ceremony.expiresAtMs <= now) this.addSignerCeremonies.delete(key);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function assertNever(value: never): never {
  throw new Error(`Unexpected registration ceremony store branch: ${String(value)}`);
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function addSignerFinalizeReplayKey(input: {
  addSignerCeremonyId: string;
  idempotencyKey: string;
}): string {
  return `${trimString(input.addSignerCeremonyId)}:${trimString(input.idempotencyKey)}`;
}

function parseJsonValue(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function isStoredWalletAddSignerFinalizeSuccess(
  value: unknown,
): value is Extract<WalletAddSignerFinalizeResponse, { ok: true }> {
  if (!isRecord(value) || value.ok !== true || !trimString(value.walletId)) return false;
  if (value.kind === 'near_ed25519') {
    if (
      !trimString(value.rpId) ||
      !trimString(value.credentialIdB64u) ||
      !isRecord(value.ed25519) ||
      !trimString(value.ed25519.nearAccountId) ||
      !trimString(value.ed25519.nearEd25519SigningKeyId) ||
      !trimString(value.ed25519.publicKey) ||
      !trimString(value.ed25519.relayerKeyId)
    ) {
      return false;
    }
    return true;
  }
  return (
    value.kind === 'evm_family_ecdsa' &&
    isRecord(value.ecdsa) &&
    Array.isArray(value.ecdsa.walletKeys)
  );
}

function parseStoredWalletAddSignerFinalizeReplay(
  value: unknown,
): StoredWalletAddSignerFinalizeReplay | null {
  value = parseJsonValue(value);
  if (!isRecord(value) || value.kind !== 'wallet_add_signer_finalize_replay_v1') return null;
  const addSignerCeremonyId = trimString(value.addSignerCeremonyId);
  const idempotencyKey = trimString(value.idempotencyKey);
  const createdAtMs = Number(value.createdAtMs);
  const expiresAtMs = Number(value.expiresAtMs);
  const request = parseStoredWalletAddSignerFinalizeRequest(value.request);
  if (
    !addSignerCeremonyId ||
    !idempotencyKey ||
    !request ||
    request.addSignerCeremonyId !== addSignerCeremonyId ||
    request.idempotencyKey !== idempotencyKey ||
    !isStoredWalletAddSignerFinalizeSuccess(value.response) ||
    request.kind !== value.response.kind ||
    !Number.isSafeInteger(createdAtMs) ||
    createdAtMs <= 0 ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    return null;
  }
  return {
    kind: 'wallet_add_signer_finalize_replay_v1',
    addSignerCeremonyId,
    idempotencyKey,
    request,
    response: value.response,
    createdAtMs,
    expiresAtMs,
  };
}

function parseStoredWalletAddSignerFinalizeRequest(
  value: unknown,
): StoredWalletAddSignerFinalizeRequest | null {
  if (!isRecord(value)) return null;
  const addSignerCeremonyId = trimString(value.addSignerCeremonyId);
  const idempotencyKey = trimString(value.idempotencyKey);
  if (!addSignerCeremonyId || !idempotencyKey) return null;
  if (value.kind === 'near_ed25519') {
    if (!isRecord(value.activationReference)) return null;
    const lifecycleId = trimString(value.activationReference.lifecycleId);
    const sessionId = parseStoredBytes32(value.activationReference.sessionId);
    if (!lifecycleId || !sessionId) return null;
    return {
      kind: 'near_ed25519',
      addSignerCeremonyId,
      idempotencyKey,
      activationReference: { lifecycleId, sessionId },
    };
  }
  if (
    value.kind !== 'evm_family_ecdsa' ||
    !Array.isArray(value.expectedKeyHandles) ||
    value.expectedKeyHandles.length !== 1
  ) {
    return null;
  }
  const expectedKeyHandle = trimString(value.expectedKeyHandles[0]);
  if (!expectedKeyHandle) return null;
  return {
    kind: 'evm_family_ecdsa',
    addSignerCeremonyId,
    idempotencyKey,
    expectedKeyHandles: [expectedKeyHandle],
  };
}

function parseStoredBytes32(value: unknown): number[] | null {
  if (!Array.isArray(value) || value.length !== 32) return null;
  const bytes: number[] = [];
  for (const byte of value) {
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) return null;
    bytes.push(byte);
  }
  return bytes;
}

export function parseStoredRegistrationSignerPlan(value: unknown): RegistrationSignerPlan | null {
  const parsed = normalizeRegistrationSignerPlan(value);
  if (parsed.ok) return parsed.value;
  const record = parseJsonValue(value);
  if (!isRecord(record) || record.kind !== 'signer_set' || !Array.isArray(record.branches)) {
    return null;
  }
  const branches: RegistrationSignerPlanBranch[] = [];
  const signers: RegistrationSignerRequest[] = [];
  for (const rawBranch of record.branches) {
    const branch = parseStoredRegistrationSignerPlanBranch(rawBranch);
    if (!branch) return null;
    branches.push(branch.branch);
    signers.push(branch.signer);
  }
  const recomputed = registrationSignerPlanFromSelection({
    kind: 'signer_set',
    signers,
  });
  if (!recomputed.ok) return null;
  const storedPlan: RegistrationSignerPlan = {
    kind: 'signer_set',
    branches,
  };
  if (!storedRegistrationSignerPlansMatch(storedPlan, recomputed.value)) return null;
  return recomputed.value;
}

export function parseStoredWalletRegistrationPreparedContext(
  value: unknown,
): StoredWalletRegistrationPreparedContext | null {
  const record = parseJsonValue(value);
  if (
    !isRecord(record) ||
    record.kind !== 'wallet_registration_prepared_context_v1' ||
    !isRecord(record.runtimePolicy) ||
    !isRecord(record.ecdsa)
  ) {
    return null;
  }
  const signingRootId = trimString(record.signingRootId);
  const signingRootVersion = trimString(record.signingRootVersion);
  if (!signingRootId || !signingRootVersion) return null;
  const runtimePolicy = parseStoredWalletRegistrationRuntimePolicyContext(record.runtimePolicy);
  const ecdsa = parseStoredWalletRegistrationEcdsaPreparedContext(record.ecdsa);
  if (!runtimePolicy || !ecdsa) return null;
  return {
    kind: 'wallet_registration_prepared_context_v1',
    signingRootId,
    signingRootVersion,
    runtimePolicy,
    ecdsa,
  };
}

function parseStoredWalletRegistrationRuntimePolicyContext(
  value: Record<string, unknown>,
): StoredWalletRegistrationRuntimePolicyContext | null {
  switch (value.kind) {
    case 'runtime_policy_scope': {
      const scope = parseStoredRuntimePolicyScope(value.scope);
      return scope ? { kind: 'runtime_policy_scope', scope } : null;
    }
    case 'signing_root_only':
      return hasDefinedField(value, 'scope') ? null : { kind: 'signing_root_only' };
    default:
      return null;
  }
}

function parseStoredRuntimePolicyScope(value: unknown): RuntimePolicyScope | null {
  const scope = parseRuntimePolicyScopeLike(value);
  if (!scope?.signingRootVersion) return null;
  return {
    orgId: scope.orgId,
    projectId: scope.projectId,
    envId: scope.envId,
    signingRootVersion: scope.signingRootVersion,
  };
}

function parseStoredWalletRegistrationEcdsaPreparedContext(
  value: Record<string, unknown>,
): StoredWalletRegistrationEcdsaPreparedContext | null {
  switch (value.kind) {
    case 'evm_family_ecdsa_requested': {
      if (!Array.isArray(value.chainTargets) || value.chainTargets.length === 0) return null;
      const chainTargets: ThresholdEcdsaChainTarget[] = [];
      for (const rawTarget of value.chainTargets) {
        const chainTarget = thresholdEcdsaChainTargetFromValue(rawTarget);
        if (!chainTarget) return null;
        chainTargets.push(chainTarget);
      }
      return { kind: 'evm_family_ecdsa_requested', chainTargets };
    }
    case 'evm_family_ecdsa_absent':
      return hasDefinedField(value, 'chainTargets') ? null : { kind: 'evm_family_ecdsa_absent' };
    default:
      return null;
  }
}

function parseStoredRegistrationSignerPlanBranch(
  value: unknown,
): { branch: RegistrationSignerPlanBranch; signer: RegistrationSignerRequest } | null {
  if (!isRecord(value)) return null;
  const signerCandidate = storedRegistrationSignerRequestCandidateFromPlanBranch(value);
  if (!signerCandidate) return null;
  const singleBranchPlan = normalizeRegistrationSignerPlan({
    kind: 'signer_set',
    signers: [signerCandidate],
  });
  if (!singleBranchPlan.ok || singleBranchPlan.value.branches.length !== 1) return null;
  const branch = singleBranchPlan.value.branches[0];
  if (!branch || trimString(value.branchKey) !== branch.branchKey) return null;
  switch (branch.kind) {
    case 'near_ed25519': {
      if (
        trimString(value.keyPurpose) !== branch.keyPurpose ||
        trimString(value.keyVersion) !== branch.keyVersion ||
        hasDefinedField(value, 'chainTargets')
      ) {
        return null;
      }
      return {
        branch,
        signer: {
          kind: 'near_ed25519',
          accountProvisioning: branch.accountProvisioning,
          signerSlot: branch.signerSlot,
          participantIds: [...branch.participantIds],
          derivationVersion: branch.derivationVersion,
        },
      };
    }
    case 'evm_family_ecdsa': {
      if (
        hasDefinedField(value, 'accountProvisioning') ||
        hasDefinedField(value, 'signerSlot') ||
        hasDefinedField(value, 'keyPurpose') ||
        hasDefinedField(value, 'keyVersion') ||
        hasDefinedField(value, 'derivationVersion')
      ) {
        return null;
      }
      return {
        branch,
        signer: {
          kind: 'evm_family_ecdsa',
          participantIds: [...branch.participantIds],
          chainTargets: [...branch.chainTargets],
        },
      };
    }
    default:
      return assertNever(branch);
  }
}

function storedRegistrationSignerRequestCandidateFromPlanBranch(
  value: Record<string, unknown>,
): Record<string, unknown> | null {
  switch (value.kind) {
    case 'near_ed25519':
      return {
        kind: 'near_ed25519',
        accountProvisioning: value.accountProvisioning,
        signerSlot: Number(value.signerSlot),
        participantIds: Array.isArray(value.participantIds) ? [...value.participantIds] : [],
        derivationVersion: Number(value.derivationVersion),
      };
    case 'evm_family_ecdsa':
      return {
        kind: 'evm_family_ecdsa',
        participantIds: Array.isArray(value.participantIds) ? [...value.participantIds] : [],
        chainTargets: Array.isArray(value.chainTargets) ? [...value.chainTargets] : [],
      };
    default:
      return null;
  }
}

export function storedRegistrationSignerPlansMatch(
  left: RegistrationSignerPlan,
  right: RegistrationSignerPlan,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function parseStoredAddSignerIntent(value: unknown): StoredAddSignerIntent | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (value.kind !== 'add_signer_intent_allocated') return null;
  if (typeof value.grant !== 'string' || !value.grant.trim()) return null;
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  return value as StoredAddSignerIntent;
}

function parseStoredAddAuthMethodIntent(value: unknown): StoredAddAuthMethodIntent | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (value.kind !== 'add_auth_method_intent_allocated') return null;
  const grant = trimString(value.grant);
  const digestB64u = trimString(value.digestB64u);
  const orgId = typeof value.orgId === 'string' ? value.orgId : null;
  const expiresAtMs = Number(value.expiresAtMs);
  if (!grant || !digestB64u || orgId === null || !Number.isFinite(expiresAtMs)) return null;
  const intent = isRecord(value.intent) ? value.intent : null;
  if (!intent) return null;
  const version = trimString(intent.version);
  const walletId = walletIdFromString(trimString(intent.walletId));
  const authMethod = normalizeAddAuthMethodInput(intent.authMethod);
  const nonceB64u = trimString(intent.nonceB64u);
  if (version !== 'add_auth_method_intent_v1' || !walletId || !authMethod || !nonceB64u) {
    return null;
  }
  const parsedIntent: AddAuthMethodIntentV1 = {
    version: 'add_auth_method_intent_v1',
    walletId,
    authMethod,
    nonceB64u,
  };
  if (Object.prototype.hasOwnProperty.call(intent, 'runtimePolicyScope')) {
    const runtimePolicyScope = parseRuntimePolicyScopeLike(intent.runtimePolicyScope);
    if (!runtimePolicyScope) return null;
    parsedIntent.runtimePolicyScope = runtimePolicyScope;
  }
  const normalizedGrant = addAuthMethodIntentGrantFromString(grant);
  if (!normalizedGrant) {
    return null;
  }
  return {
    kind: 'add_auth_method_intent_allocated',
    grant: normalizedGrant,
    intent: parsedIntent,
    digestB64u,
    orgId,
    expiresAtMs: Math.floor(expiresAtMs),
    ...(trimString(value.signingRootId) ? { signingRootId: trimString(value.signingRootId) } : {}),
    ...(trimString(value.signingRootVersion)
      ? { signingRootVersion: trimString(value.signingRootVersion) }
      : {}),
    ...(trimString(value.expectedOrigin)
      ? { expectedOrigin: trimString(value.expectedOrigin) }
      : {}),
  };
}

function hasDefinedField(obj: Record<string, unknown>, field: string): boolean {
  return field in obj && obj[field] !== undefined;
}

function parseRuntimePolicyScopeLike(
  value: unknown,
): AddAuthMethodIntentV1['runtimePolicyScope'] | null {
  if (!isRecord(value)) return null;
  const orgId = trimString(value.orgId);
  const projectId = trimString(value.projectId);
  const envId = trimString(value.envId);
  const signingRootVersion = trimString(value.signingRootVersion);
  if (!orgId || !projectId || !envId) return null;
  if (hasDefinedField(value, 'signingRootVersion') && !signingRootVersion) return null;
  return signingRootVersion
    ? { orgId, projectId, envId, signingRootVersion }
    : { orgId, projectId, envId };
}

function parseStoredRegistrationAuthority(value: unknown): StoredRegistrationAuthority | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  const walletId = parseWalletId(value.walletId);
  const registrationIntentDigestB64u =
    typeof value.registrationIntentDigestB64u === 'string' &&
    value.registrationIntentDigestB64u.trim()
      ? value.registrationIntentDigestB64u
      : null;
  if (!walletId.ok || !registrationIntentDigestB64u) return null;

  switch (value.kind) {
    case 'passkey': {
      if (hasDefinedField(value, 'emailHashHex') || hasDefinedField(value, 'challengeId')) {
        return null;
      }
      const rpId = parseWebAuthnRpId(value.rpId);
      if (!rpId.ok) return null;
      const credentialIdB64u =
        typeof value.credentialIdB64u === 'string' && value.credentialIdB64u.trim()
          ? value.credentialIdB64u
          : null;
      const credentialPublicKeyB64u =
        typeof value.credentialPublicKeyB64u === 'string' && value.credentialPublicKeyB64u.trim()
          ? value.credentialPublicKeyB64u
          : null;
      const counter = Number(value.counter);
      if (!credentialIdB64u || !credentialPublicKeyB64u || !Number.isSafeInteger(counter)) {
        return null;
      }
      /* legacy stored authorities predate device capture: synthesize instead
         of failing the parse */
      const device =
        parseWebAuthnAuthenticatorDeviceInfo(value.device) ??
        unknownWebAuthnAuthenticatorDeviceInfo();
      return {
        kind: 'passkey',
        walletId: walletId.value,
        rpId: rpId.value,
        credentialIdB64u,
        credentialPublicKeyB64u,
        counter,
        device,
        registrationIntentDigestB64u,
      };
    }
    case 'email_otp': {
      if (
        hasDefinedField(value, 'rpId') ||
        hasDefinedField(value, 'credentialIdB64u') ||
        hasDefinedField(value, 'credentialPublicKeyB64u') ||
        hasDefinedField(value, 'counter')
      ) {
        return null;
      }
      const emailHashHex =
        typeof value.emailHashHex === 'string' && value.emailHashHex.trim()
          ? value.emailHashHex
          : null;
      const proofKind = typeof value.proofKind === 'string' ? value.proofKind.trim() : '';
      const providerSubject =
        typeof value.providerSubject === 'string' && value.providerSubject.trim()
          ? value.providerSubject
          : null;
      const email =
        typeof value.email === 'string' && value.email.trim() ? value.email.toLowerCase() : null;
      const parsedProviderSubject = parseProviderSubject(providerSubject);
      const finalWalletId = parseWalletId(value.finalWalletId);
      const orgId = parseOrgId(value.orgId);
      const appSessionVersion = parseAppSessionVersion(value.appSessionVersion);
      if (
        !providerSubject ||
        !email ||
        !emailHashHex ||
        !parsedProviderSubject.ok ||
        !finalWalletId.ok ||
        !orgId.ok ||
        !appSessionVersion.ok
      ) {
        return null;
      }
      if (proofKind === 'otp_challenge') {
        const challengeId =
          typeof value.challengeId === 'string' && value.challengeId.trim()
            ? value.challengeId
            : null;
        const challengeSubjectId = parseChallengeSubjectId(value.challengeSubjectId);
        const parsedChallengeId = parseEmailOtpChallengeId(challengeId);
        const originalWalletId = parseWalletId(value.originalWalletId);
        const challengePurpose =
          value.challengePurpose === 'registration' ||
          value.challengePurpose === 'registration_reroll'
            ? value.challengePurpose
            : null;
        if (
          !challengeId ||
          !challengeSubjectId.ok ||
          !parsedChallengeId.ok ||
          !originalWalletId.ok ||
          !challengePurpose
        ) {
          return null;
        }
        return {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          walletId: walletId.value,
          providerSubject: parsedProviderSubject.value,
          challengeSubjectId: challengeSubjectId.value,
          email,
          emailHashHex,
          challengeId: parsedChallengeId.value,
          registrationAuthorityId: parsedChallengeId.value,
          originalWalletId: originalWalletId.value,
          finalWalletId: finalWalletId.value,
          orgId: orgId.value,
          appSessionVersion: appSessionVersion.value,
          challengePurpose,
          registrationIntentDigestB64u,
        };
      }
      if (proofKind === 'google_sso_registration') {
        const registrationAttemptId =
          typeof value.googleEmailOtpRegistrationAttemptId === 'string' &&
          value.googleEmailOtpRegistrationAttemptId.trim()
            ? value.googleEmailOtpRegistrationAttemptId.trim()
            : '';
        const registrationOfferId =
          typeof value.googleEmailOtpRegistrationOfferId === 'string' &&
          value.googleEmailOtpRegistrationOfferId.trim()
            ? value.googleEmailOtpRegistrationOfferId.trim()
            : '';
        const registrationCandidateId =
          typeof value.googleEmailOtpRegistrationCandidateId === 'string' &&
          value.googleEmailOtpRegistrationCandidateId.trim()
            ? value.googleEmailOtpRegistrationCandidateId.trim()
            : '';
        if (
          !registrationAttemptId ||
          !registrationOfferId ||
          !registrationCandidateId ||
          hasDefinedField(value, 'challengeId') ||
          hasDefinedField(value, 'challengeSubjectId') ||
          hasDefinedField(value, 'originalWalletId') ||
          hasDefinedField(value, 'challengePurpose')
        ) {
          return null;
        }
        return {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          walletId: walletId.value,
          providerSubject: parsedProviderSubject.value,
          email,
          emailHashHex,
          googleEmailOtpRegistrationAttemptId: registrationAttemptId,
          googleEmailOtpRegistrationOfferId: registrationOfferId,
          googleEmailOtpRegistrationCandidateId: registrationCandidateId,
          registrationAuthorityId: registrationAttemptId,
          finalWalletId: finalWalletId.value,
          orgId: orgId.value,
          appSessionVersion: appSessionVersion.value,
          registrationIntentDigestB64u,
        };
      }
      return null;
    }
  }
  return null;
}

function parseStoredWalletRegistrationCeremony(
  value: unknown,
): StoredWalletRegistrationCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (typeof value.registrationCeremonyId !== 'string' || !value.registrationCeremonyId.trim()) {
    return null;
  }
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  const authorityState = parseStoredWalletRegistrationCeremonyAuthorityState(value.authorityState);
  const signerPlan = parseStoredRegistrationSignerPlan(value.signerPlan);
  const preparedContext = parseStoredWalletRegistrationPreparedContext(value.preparedContext);
  const intentSignerPlan = isRecord(value.intent)
    ? parseStoredRegistrationSignerPlan(value.intent.signerSelection)
    : null;
  if (
    !authorityState ||
    !signerPlan ||
    !preparedContext ||
    !intentSignerPlan ||
    !storedRegistrationSignerPlansMatch(signerPlan, intentSignerPlan) ||
    (trimString(value.signingRootId) &&
      preparedContext.signingRootId !== trimString(value.signingRootId)) ||
    (trimString(value.signingRootVersion) &&
      preparedContext.signingRootVersion !== trimString(value.signingRootVersion)) ||
    !isRecord(value.signerState)
  ) {
    return null;
  }
  return {
    ...(value as Omit<
      StoredWalletRegistrationCeremony,
      'authorityState' | 'signerPlan' | 'preparedContext'
    >),
    authorityState,
    signerPlan,
    preparedContext,
  };
}

function parseStoredWalletRegistrationCeremonyAuthorityState(
  value: unknown,
): StoredWalletRegistrationCeremonyAuthorityState | null {
  if (!isRecord(value)) return null;
  switch (value.kind) {
    case 'awaiting_proof': {
      const authMethod = parseStoredRegistrationCeremonyAuthMethod(value.authMethod);
      return authMethod ? { kind: 'awaiting_proof', authMethod } : null;
    }
    case 'verified': {
      const authority = parseStoredRegistrationAuthority(value.authority);
      return authority ? { kind: 'verified', authority } : null;
    }
    default:
      return null;
  }
}

function parseStoredRegistrationCeremonyAuthMethod(
  value: unknown,
): RegistrationIntentV1['authMethod'] | null {
  if (!isRecord(value)) return null;
  if (value.kind === 'passkey') {
    const rpId = trimString(value.rpId);
    return rpId ? ({ ...value, kind: 'passkey' } as RegistrationIntentV1['authMethod']) : null;
  }
  if (value.kind === 'email_otp') {
    const email = trimString(value.email);
    return email ? ({ ...value, kind: 'email_otp' } as RegistrationIntentV1['authMethod']) : null;
  }
  return null;
}

function parseStoredWalletAddSignerCeremony(value: unknown): StoredWalletAddSignerCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (typeof value.addSignerCeremonyId !== 'string' || !value.addSignerCeremonyId.trim()) {
    return null;
  }
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  if (!isRecord(value.auth) || !isRecord(value.signerState)) return null;
  return value as StoredWalletAddSignerCeremony;
}

function parseAddAuthMethodCeremonyAuth(
  value: unknown,
): StoredWalletAddAuthMethodCeremony['auth'] | null {
  if (!isRecord(value)) return null;
  if (value.kind === 'app_session') {
    return { kind: 'app_session' };
  }
  if (value.kind !== 'webauthn_assertion') return null;
  const rpId = trimString(value.rpId);
  const credentialIdB64u = trimString(value.credentialIdB64u);
  if (!rpId || !credentialIdB64u) return null;
  return {
    kind: 'webauthn_assertion',
    rpId,
    credentialIdB64u,
  };
}

function parseStoredWalletAddAuthMethodRegistrationOptions(
  value: unknown,
): WalletAddAuthMethodRegistrationOptions | null {
  if (!isRecord(value) || value.kind !== 'webauthn_add_auth_method_registration_v1') {
    return null;
  }
  const challengeId = trimString(value.challengeId);
  const challengeB64u = trimString(value.challengeB64u);
  const rpId = trimString(value.rpId);
  const user = isRecord(value.user) ? value.user : null;
  const userIdB64u = trimString(user?.idB64u);
  const userName = trimString(user?.name);
  const userDisplayName = trimString(user?.displayName);
  const parameters = Array.isArray(value.pubKeyCredParams) ? value.pubKeyCredParams : null;
  const firstParameter = parameters && isRecord(parameters[0]) ? parameters[0] : null;
  const secondParameter = parameters && isRecord(parameters[1]) ? parameters[1] : null;
  const selection = isRecord(value.authenticatorSelection)
    ? value.authenticatorSelection
    : null;
  const extensions = isRecord(value.extensions) ? value.extensions : null;
  const prf = isRecord(extensions?.prf) ? extensions.prf : null;
  const evalRecord = isRecord(prf?.eval) ? prf.eval : null;
  const excludeCredentials = Array.isArray(value.excludeCredentials)
    ? value.excludeCredentials
        .map((entry) => {
          if (!isRecord(entry) || entry.type !== 'public-key') return null;
          const id = trimString(entry.id);
          return id ? { type: 'public-key' as const, id } : null;
        })
        .filter((entry): entry is { readonly type: 'public-key'; readonly id: string } => entry !== null)
    : null;
  const timeoutMs = Number(value.timeoutMs);
  if (
    !challengeId ||
    !challengeB64u ||
    !rpId ||
    !userIdB64u ||
    !userName ||
    !userDisplayName ||
    !parameters ||
    parameters.length !== 2 ||
    firstParameter?.type !== 'public-key' ||
    Number(firstParameter.alg) !== -7 ||
    secondParameter?.type !== 'public-key' ||
    Number(secondParameter.alg) !== -257 ||
    selection?.residentKey !== 'required' ||
    selection?.userVerification !== 'preferred' ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    value.attestation !== 'none' ||
    typeof evalRecord?.firstB64u !== 'string' ||
    !evalRecord.firstB64u.trim() ||
    typeof evalRecord?.secondB64u !== 'string' ||
    !evalRecord.secondB64u.trim() ||
    !excludeCredentials
  ) {
    return null;
  }
  return {
    kind: 'webauthn_add_auth_method_registration_v1',
    challengeId,
    challengeB64u,
    rpId,
    user: { idB64u: userIdB64u, name: userName, displayName: userDisplayName },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    timeoutMs,
    attestation: 'none',
    extensions: {
      prf: {
        eval: {
          firstB64u: evalRecord.firstB64u,
          secondB64u: evalRecord.secondB64u,
        },
      },
    },
    excludeCredentials,
  };
}

function parseStoredWalletAddAuthMethodCeremony(
  value: unknown,
): StoredWalletAddAuthMethodCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  const addAuthMethodCeremonyId = trimString(value.addAuthMethodCeremonyId);
  const digestB64u = trimString(value.digestB64u);
  const orgId = typeof value.orgId === 'string' ? value.orgId : null;
  const expiresAtMs = Number(value.expiresAtMs);
  if (!addAuthMethodCeremonyId || !digestB64u || orgId === null || !Number.isFinite(expiresAtMs)) {
    return null;
  }
  const auth = parseAddAuthMethodCeremonyAuth(value.auth);
  const intentRecord = parseStoredAddAuthMethodIntent({
    kind: 'add_auth_method_intent_allocated',
    grant: 'ignored',
    intent: value.intent,
    digestB64u,
    orgId,
    expiresAtMs,
  });
  if (!auth || !intentRecord) return null;
  const kind = value.kind;
  if (kind === 'email_otp') {
    const authority = parseStoredRegistrationAuthority(value.authority);
    if (!authority || authority.kind !== 'email_otp') return null;
    return {
      kind: 'email_otp',
      addAuthMethodCeremonyId,
      intent: intentRecord.intent,
      digestB64u,
      orgId,
      expiresAtMs: Math.floor(expiresAtMs),
      auth,
      authority,
      ...(trimString(value.expectedOrigin)
        ? { expectedOrigin: trimString(value.expectedOrigin) }
        : {}),
    };
  }
  if (kind !== 'passkey' || !isRecord(value.passkeyRegistration)) return null;
  const rpId = parseWebAuthnRpId(value.passkeyRegistration.rpId);
  const challengeB64u = trimString(value.passkeyRegistration.challengeB64u);
  const options = parseStoredWalletAddAuthMethodRegistrationOptions(
    value.passkeyRegistration.options,
  );
  let custodyEnvelope: PasskeyCustodyEnvelopeRecord;
  try {
    custodyEnvelope = parsePasskeyCustodyEnvelopeRecord(value.custodyEnvelope);
  } catch {
    return null;
  }
  if (
    !rpId.ok ||
    !challengeB64u ||
    !options ||
    options.rpId !== rpId.value ||
    options.challengeB64u !== challengeB64u ||
    intentRecord.intent.authMethod.kind !== 'passkey' ||
    intentRecord.intent.authMethod.rpId !== rpId.value ||
    custodyEnvelope.walletId !== intentRecord.intent.walletId ||
    custodyEnvelope.factor.kind !== 'passkey' ||
    custodyEnvelope.factor.rpId !== rpId.value ||
    custodyEnvelope.lifecycle.state !== 'active'
  ) {
    return null;
  }
  return {
    kind: 'passkey',
    addAuthMethodCeremonyId,
    intent: intentRecord.intent,
    digestB64u,
    orgId,
    expiresAtMs: Math.floor(expiresAtMs),
    auth,
    passkeyRegistration: { rpId: rpId.value, challengeB64u, options },
    custodyEnvelope,
    ...(trimString(value.expectedOrigin)
      ? { expectedOrigin: trimString(value.expectedOrigin) }
      : {}),
  };
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoRequest =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'del'; key: string }
  | { op: 'getdel'; key: string }
  | {
      op: 'registrationCancelTerminal';
      ceremonyKey: string;
      registrationCeremonyId: string;
      walletId: string;
    }
  | {
      op: 'getdelIfRelatedMatches';
      key: string;
      relatedKey: string;
      expectedRelated: unknown;
    };

type DoConditionalGetDelResponse = {
  matched: boolean;
  value: unknown | null;
};

function isDurableObjectNamespaceLike(
  value: unknown,
): value is CloudflareDurableObjectNamespaceLike {
  return (
    isRecord(value) && typeof value.idFromName === 'function' && typeof value.get === 'function'
  );
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const direct = config.namespace;
  if (isDurableObjectNamespaceLike(direct)) return direct;

  const durableObjectNamespace = config.durableObjectNamespace;
  if (isDurableObjectNamespaceLike(durableObjectNamespace)) return durableObjectNamespace;

  const envStyle = config.THRESHOLD_DO_NAMESPACE;
  if (isDurableObjectNamespaceLike(envStyle)) return envStyle;

  return null;
}

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as unknown as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, request: DoRequest): Promise<DoResp<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Registration ceremony DO store HTTP ${response.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(
      `Registration ceremony DO store returned non-JSON response: ${text.slice(0, 200)}`,
    );
  }
  if (!isRecord(json)) {
    throw new Error('Registration ceremony DO store returned invalid JSON shape');
  }
  if (json.ok === true) return json as DoOk<T>;
  const code = trimString(json.code);
  const message = trimString(json.message);
  return {
    ok: false,
    code: code || 'internal',
    message: message || 'Registration ceremony DO store error',
  };
}

class CloudflareDurableObjectRegistrationCeremonyStore implements RegistrationCeremonyStore {
  private readonly stub: DurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.prefix = input.prefix;
  }

  private key(
    scope:
      | 'add-auth-method-intent'
      | 'add-signer-intent'
      | 'ceremony'
      | 'add-signer-finalize-replay'
      | 'add-signer-finalize-claim'
      | 'add-auth-method'
      | 'add-signer',
    id: string,
  ): string {
    return `${this.prefix}${scope}:${id}`;
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    const parsed = parseStoredAddSignerIntent(intent);
    if (!parsed) throw new Error('Invalid add-signer intent record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer-intent', parsed.grant),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddSignerIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-signer-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddSignerIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_signer_intent_consumed', consumedAtMs: Date.now() };
  }

  async putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void> {
    const parsed = parseStoredAddAuthMethodIntent(intent);
    if (!parsed) throw new Error('Invalid add-auth-method intent record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-auth-method-intent', parsed.grant),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<StoredAddAuthMethodIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-auth-method-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddAuthMethodIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddAuthMethodIntent(
    grant: AddAuthMethodIntentGrant,
  ): Promise<ConsumedAddAuthMethodIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-auth-method-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddAuthMethodIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_auth_method_intent_consumed', consumedAtMs: Date.now() };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const parsed = parseStoredWalletRegistrationCeremony(ceremony);
    if (!parsed) throw new Error('Invalid registration ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('ceremony', parsed.registrationCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const key = trimString(registrationCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('ceremony', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletRegistrationCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const parsed = parseStoredWalletRegistrationCeremony(ceremony);
    if (!parsed) throw new Error('Invalid registration ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('ceremony', parsed.registrationCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const key = trimString(registrationCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('ceremony', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletRegistrationCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async cancelTerminalCeremony(input: {
    registrationCeremonyId: string;
    walletId: WalletId;
  }): Promise<TerminalRegistrationCeremonyCancellationResult> {
    const registrationCeremonyId = trimString(input.registrationCeremonyId);
    const walletId = trimString(input.walletId);
    if (!registrationCeremonyId || !walletId) {
      throw new Error('Terminal registration cancellation requires ceremony and wallet IDs');
    }
    const response = await callDo<unknown>(this.stub, {
      op: 'registrationCancelTerminal',
      ceremonyKey: this.key('ceremony', registrationCeremonyId),
      registrationCeremonyId,
      walletId,
    });
    if (!response.ok) throw new Error(response.message);
    const result = parseTerminalRegistrationCeremonyCancellationResult(response.value);
    if (!result) throw new Error('Terminal registration cancellation returned an invalid result');
    return result;
  }

  async putAddSignerFinalizeReplay(replay: StoredWalletAddSignerFinalizeReplay): Promise<void> {
    const parsed = parseStoredWalletAddSignerFinalizeReplay(replay);
    if (!parsed) throw new Error('Invalid wallet add-signer finalize replay record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer-finalize-replay', addSignerFinalizeReplayKey(parsed)),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
    const claimResponse = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer-finalize-claim', parsed.addSignerCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!claimResponse.ok) throw new Error(claimResponse.message);
  }

  async getAddSignerFinalizeReplay(input: {
    addSignerCeremonyId: string;
    idempotencyKey: string;
  }): Promise<StoredWalletAddSignerFinalizeReplay | null> {
    if (!trimString(input.addSignerCeremonyId) || !trimString(input.idempotencyKey)) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer-finalize-replay', addSignerFinalizeReplayKey(input)),
    });
    if (!response.ok) return null;
    const replay = parseStoredWalletAddSignerFinalizeReplay(response.value);
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async getAddSignerFinalizeReplayForCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerFinalizeReplay | null> {
    const ceremonyId = trimString(addSignerCeremonyId);
    if (!ceremonyId) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer-finalize-claim', ceremonyId),
    });
    if (!response.ok) return null;
    const replay = parseStoredWalletAddSignerFinalizeReplay(response.value);
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    const parsed = parseStoredWalletAddAuthMethodCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-auth-method ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-auth-method', parsed.addAuthMethodCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const key = trimString(addAuthMethodCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-auth-method', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddAuthMethodCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    const parsed = parseStoredWalletAddAuthMethodCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-auth-method ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-auth-method', parsed.addAuthMethodCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const key = trimString(addAuthMethodCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-auth-method', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddAuthMethodCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const parsed = parseStoredWalletAddSignerCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-signer ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer', parsed.addSignerCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const key = trimString(addSignerCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddSignerCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const parsed = parseStoredWalletAddSignerCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-signer ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer', parsed.addSignerCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const key = trimString(addSignerCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-signer', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddSignerCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }
}

function resolveRegistrationDoPrefix(config: Record<string, unknown>): string {
  const explicit =
    trimString(config.WALLET_REGISTRATION_PREFIX) || trimString(config.walletRegistrationPrefix);
  const base = explicit || trimString(config.keyPrefix) || trimString(config.THRESHOLD_PREFIX);
  if (!base) return 'wallet-registration:';
  return base.endsWith(':') ? `${base}wallet-registration:` : `${base}:wallet-registration:`;
}

export function createRegistrationCeremonyStore(
  input: {
    config?: unknown;
    logger?: NormalizedLogger;
    isNode?: boolean;
  } = {},
): RegistrationCeremonyStore {
  const config = (input.config || {}) as Record<string, unknown>;
  const kind = typeof config.kind === 'string' ? config.kind.trim() : '';
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do registration ceremony store selected but no Durable Object namespace was provided (expected config.namespace)',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger?.info(
      '[wallet-registration] Using Cloudflare Durable Object store for registration ceremonies',
    );
    return new CloudflareDurableObjectRegistrationCeremonyStore({
      namespace,
      objectName,
      prefix: resolveRegistrationDoPrefix(config),
    });
  }
  if (kind && kind !== 'memory' && kind !== 'in-memory') {
    throw new Error(`[wallet-registration] Unknown registration ceremony store kind: ${kind}`);
  }
  input.logger?.warn?.(
    '[wallet-registration] Using in-memory registration ceremony store; configure Cloudflare Durable Object storage for durable registration ceremonies',
  );
  return new MemoryRegistrationCeremonyStore();
}
