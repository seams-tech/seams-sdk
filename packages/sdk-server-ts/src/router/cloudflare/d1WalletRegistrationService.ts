import {
  computeRegistrationIntentDigestB64u,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  nearEd25519SigningKeyIdFromString,
  registrationIntentGrantFromString,
  registrationNearEd25519BranchKey,
  registrationSignerPlanFromSelection,
  walletIdFromString,
  type RegistrationEvmFamilyEcdsaSignerPlan,
  type RegistrationIntentV1,
  type RegistrationNearAccountProvisioning,
  type RegistrationNearEd25519SignerPlan,
  type RegistrationSignerPlan,
  type ResolvedRegistrationNearAccount,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  deriveSigningRootId,
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  AccountCreationResult,
  type EcdsaDerivationServerBootstrapResponse,
} from '../../core/types';
import {
  buildRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationRecoveryRequestV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../../core/thresholdEcdsaChainTarget';
import {
  registrationPreparationIdFromString,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationEcdsaActivationRequest,
  WalletRegistrationEcdsaActivationResponse,
  WalletRegistrationEcdsaDerivationRespondRequest,
  WalletRegistrationEcdsaDerivationRespondResponse,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEd25519YaoStart,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEd25519YaoPublicResult,
  type WalletRegistrationFinalizeSuccess,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
} from '../../core/registrationContracts';
import type { RouterAbNormalSigningRuntime } from '../../core/routerAbSigning/RouterAbNormalSigningRuntime';
import { parseEcdsaDerivationPublicIdentity } from '../../core/ThresholdService/validation';
import {
  routerAbEcdsaStrictRegistrationRequestMatchesFacts,
  type RouterAbEcdsaStrictRegistrationPort,
} from '../routerAbEcdsaStrictRegistration';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import {
  listThresholdEcdsaKeyIdentityTargetsForUser,
  type ThresholdEcdsaKeyInventoryDiagnostics,
  type ThresholdEcdsaKeyInventoryRecord,
} from '../../core/authService/thresholdEcdsaKeyInventory';
import {
  buildStoredWalletRegistrationPreparedContext,
  buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch,
  buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch,
  findStoredWalletRegistrationEvmFamilyEcdsaBranch,
  findStoredWalletRegistrationNearEd25519YaoBranch,
  replaceStoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch,
  type StoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationPreparedContext,
  type StoredRegistrationAuthority,
} from '../../core/RegistrationCeremonyStore';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  buildD1WalletRecord,
  normalizeThresholdEcdsaChainTargets,
  parseD1RegistrationIntent,
  parseD1RuntimePolicyScope,
} from './d1RegistrationCeremonyRecords';
import {
  walletAuthAuthorityFromRegistrationAuthority,
  walletRegistrationFinalizeAuthMethodFromAuthority,
} from './d1WalletAuthMethodBoundary';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from './d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import type { D1WalletRegistrationCommitStore } from './d1WalletRegistrationCommitStore';
import { buildD1EvmFamilyEcdsaRegistrationPrepare } from './d1EvmFamilyEcdsaRegistrationBranch';
import {
  resolveD1RegistrationSharedSigningBudget,
  type D1RegistrationSharedSigningBudget,
} from './d1RegistrationSharedSigningBudget';
import { sha256BytesPortable } from './d1RouterApiAuthBoundary';
import { alphabetizeStringify } from '@shared/utils/digests';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  type WalletEcdsaPendingSessionActivationRecord,
  type WalletEd25519SignerRecord,
  type WalletSignerRecord,
} from '../../core/WalletStore';
import type { D1WalletStore } from '../../core/d1WalletStore';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../core/ThresholdService/validation';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  buildRouterAbEd25519YaoProductAdmissionRequestV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
} from '../routerAbEd25519YaoProductRegistration';
import {
  buildRouterAbEd25519YaoRegistrationCapabilityRecordV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
} from '../routerAbEd25519YaoRecovery';
import type {
  RouterAbEd25519YaoBudgetRefreshRequestV1,
  RouterAbEd25519YaoBudgetRefreshResponseV1,
  RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1,
  RouterAbEd25519YaoEmailOtpRecoverySessionResponseV1,
} from '../routerAbEd25519YaoWalletSession';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
  implicitNearAccountIdFromEd25519PublicKeyBytes,
} from './d1Ed25519YaoWalletSigner';

type StartWalletRegistrationInput = WalletRegistrationStartRequest;
type RespondWalletRegistrationDerivationInput = WalletRegistrationEcdsaDerivationRespondRequest;
type ActivateWalletRegistrationEcdsaInput = WalletRegistrationEcdsaActivationRequest;
type FinalizeWalletRegistrationInput = WalletRegistrationFinalizeRequest;

type D1RegistrationEd25519SigningBudgetPlan =
  | { readonly kind: 'generated_registration_signing_budget' }
  | {
      readonly kind: 'shared_registration_signing_budget';
      readonly budget: D1RegistrationSharedSigningBudget;
    };

type D1RegistrationEcdsaFinalizeState =
  | { readonly kind: 'ecdsa_registration_disabled' }
  | {
      readonly kind: 'ecdsa_registration_responded';
      readonly state: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch;
    };

type D1RegistrationEd25519WalletSessionIdentity = {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authority: WalletAuthAuthority;
  readonly thresholdSessionId: string;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: RuntimePolicyScope;
};

function assertNeverD1RegistrationEd25519SigningBudgetPlan(value: never): never {
  throw new Error(`Unexpected registration signing-budget plan: ${String(value)}`);
}

function assertNeverD1RegistrationEcdsaFinalizeState(value: never): never {
  throw new Error(`Unexpected registration ECDSA finalize state: ${String(value)}`);
}

async function mintD1RegistrationEd25519WalletSession(input: {
  readonly runtime: RouterAbEd25519YaoProductRegistrationRuntimeV1;
  readonly identity: D1RegistrationEd25519WalletSessionIdentity;
  readonly signingBudget: D1RegistrationEd25519SigningBudgetPlan;
}) {
  switch (input.signingBudget.kind) {
    case 'generated_registration_signing_budget':
      return await input.runtime.mintWalletSession({
        kind: 'registration_wallet_session_v1',
        walletId: input.identity.walletId,
        nearAccountId: input.identity.nearAccountId,
        nearEd25519SigningKeyId: input.identity.nearEd25519SigningKeyId,
        authority: input.identity.authority,
        thresholdSessionId: input.identity.thresholdSessionId,
        participantIds: input.identity.participantIds,
        runtimePolicyScope: input.identity.runtimePolicyScope,
      });
    case 'shared_registration_signing_budget':
      return await input.runtime.mintWalletSession({
        kind: 'shared_registration_wallet_session_v1',
        walletId: input.identity.walletId,
        nearAccountId: input.identity.nearAccountId,
        nearEd25519SigningKeyId: input.identity.nearEd25519SigningKeyId,
        authority: input.identity.authority,
        thresholdSessionId: input.identity.thresholdSessionId,
        participantIds: input.identity.participantIds,
        runtimePolicyScope: input.identity.runtimePolicyScope,
        signingGrantId: input.signingBudget.budget.signingGrantId,
        expiresAtMs: input.signingBudget.budget.expiresAtMs,
        remainingUses: input.signingBudget.budget.remainingUses,
      });
    default:
      return assertNeverD1RegistrationEd25519SigningBudgetPlan(input.signingBudget);
  }
}

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type RouterAbNormalSigningRuntimeProvider = () => RouterAbNormalSigningRuntime | null;
type WalletStoreProvider = () => D1WalletStore;
type Ed25519YaoProductRegistrationProvider =
  () => RouterAbEd25519YaoProductRegistrationRuntimeV1 | null;
type SponsoredNamedNearAccountCreator = (input: {
  readonly accountId: string;
  readonly publicKey: string;
}) => Promise<AccountCreationResult>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

async function cleanupFinalizedRegistrationCeremony(input: {
  readonly store: CloudflareD1RegistrationCeremonyIntentStore;
  readonly registrationCeremonyId: string;
}): Promise<void> {
  try {
    await input.store.deleteCeremony(input.registrationCeremonyId);
  } catch {
    // The replay record remains authoritative until the ceremony TTL expires.
  }
}

type D1RegistrationRouteTimingMark = {
  readonly name: WalletRegistrationRouteTimingName;
  readonly startedAtMs: number;
};

type D1RegistrationRouteTimingRecorder = {
  readonly route: WalletRegistrationRouteDiagnostics['route'];
  readonly entries: WalletRegistrationRouteDiagnostics['entries'];
};

function createD1RegistrationRouteTimingRecorder(
  route: WalletRegistrationRouteDiagnostics['route'],
): D1RegistrationRouteTimingRecorder {
  return {
    route,
    entries: [],
  };
}

function startD1RegistrationRouteTiming(
  name: WalletRegistrationRouteTimingName,
): D1RegistrationRouteTimingMark {
  return {
    name,
    startedAtMs: Date.now(),
  };
}

function finishD1RegistrationRouteTiming(
  recorder: D1RegistrationRouteTimingRecorder,
  mark: D1RegistrationRouteTimingMark,
): void {
  recorder.entries.push({
    name: mark.name,
    durationMs: Math.max(0, Date.now() - mark.startedAtMs),
  });
}

function appendD1RegistrationRouteTiming(
  recorder: D1RegistrationRouteTimingRecorder,
  name: WalletRegistrationRouteTimingName,
  durationMs: number,
): void {
  recorder.entries.push({
    name,
    durationMs: Math.max(0, Math.round(durationMs)),
  });
}

function d1RegistrationRouteDiagnostics(
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationRouteDiagnostics {
  const diagnostics: WalletRegistrationRouteDiagnostics = {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: recorder.route,
    entries: recorder.entries.map((entry) => ({
      name: entry.name,
      durationMs: entry.durationMs,
    })),
  };
  return diagnostics;
}

function withD1RegistrationRouteDiagnostics(
  response: WalletRegistrationFinalizeResponse,
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationFinalizeResponse {
  if (!response.ok) return response;
  return {
    ...response,
    registrationDiagnostics: d1RegistrationRouteDiagnostics(recorder),
  };
}

function withD1RegistrationStartDiagnostics(
  response: WalletRegistrationStartResponse,
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationStartResponse {
  if (!response.ok) return response;
  return {
    ...response,
    registrationDiagnostics: d1RegistrationRouteDiagnostics(recorder),
  };
}

function normalizedKeyHandleSet(keyHandles: readonly string[]): Set<string> {
  const normalized = new Set<string>();
  for (const keyHandle of keyHandles) {
    const value = String(keyHandle || '').trim();
    if (value) normalized.add(value);
  }
  return normalized;
}

export function hasEcdsaKeyHandleSetMismatch(
  expectedKeyHandles: readonly string[],
  actualKeyHandles: readonly string[],
): boolean {
  if (expectedKeyHandles.length === 0) return false;
  const expected = normalizedKeyHandleSet(expectedKeyHandles);
  const actual = normalizedKeyHandleSet(actualKeyHandles);
  if (expected.size !== actual.size) return true;
  for (const keyHandle of expected) {
    if (!actual.has(keyHandle)) return true;
  }
  return false;
}

type RegistrationIntentSignerBranches = {
  readonly plan: RegistrationSignerPlan;
  readonly nearEd25519: RegistrationNearEd25519SignerPlan | null;
  readonly evmFamilyEcdsa: RegistrationEvmFamilyEcdsaSignerPlan | null;
};

type RegistrationIntentSignerBranchesResult =
  | { ok: true; value: RegistrationIntentSignerBranches }
  | { ok: false; code: string; message: string };

function registrationIntentSignerBranches(
  intent: RegistrationIntentV1,
): RegistrationIntentSignerBranchesResult {
  const plan = registrationSignerPlanFromSelection(intent.signerSelection);
  if (!plan.ok) return plan;
  return { ok: true, value: registrationSignerBranchesFromPlan(plan.value) };
}

function registrationSignerBranchesFromPlan(
  plan: RegistrationSignerPlan,
): RegistrationIntentSignerBranches {
  return {
    plan,
    nearEd25519: findRegistrationSignerPlanNearEd25519Branch(plan),
    evmFamilyEcdsa: findRegistrationSignerPlanEvmFamilyEcdsaBranch(plan),
  };
}

type RegistrationPreparedContextResolution =
  | {
      ok: true;
      preparedContext: StoredWalletRegistrationPreparedContext;
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[] | null;
    }
  | {
      ok: false;
      code: 'invalid_body';
      message: string;
    };

function resolveRegistrationPreparedContextFromPlan(input: {
  readonly signerPlan: RegistrationSignerPlan;
  readonly runtimePolicyScope: RuntimePolicyScope | undefined;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): RegistrationPreparedContextResolution {
  const branches = registrationSignerBranchesFromPlan(input.signerPlan);
  const ecdsaChainTargets = branches.evmFamilyEcdsa
    ? normalizeThresholdEcdsaChainTargets(branches.evmFamilyEcdsa.chainTargets)
    : null;
  if (branches.evmFamilyEcdsa && !ecdsaChainTargets) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration contains an invalid chain target',
    };
  }
  try {
    return {
      ok: true,
      preparedContext: buildStoredWalletRegistrationPreparedContext({
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        runtimePolicyScope: input.runtimePolicyScope || null,
        ecdsaChainTargets,
      }),
      ecdsaChainTargets,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: errorMessage(error) || 'registration prepared context is invalid',
    };
  }
}

function registrationPreparedContextRuntimePolicyScope(
  preparedContext: StoredWalletRegistrationPreparedContext,
): RuntimePolicyScope | undefined {
  return preparedContext.runtimePolicy.kind === 'runtime_policy_scope'
    ? preparedContext.runtimePolicy.scope
    : undefined;
}

function registrationPreparedContextEcdsaChainTargets(
  preparedContext: StoredWalletRegistrationPreparedContext,
): readonly ThresholdEcdsaChainTarget[] | null {
  return preparedContext.ecdsa.kind === 'evm_family_ecdsa_requested'
    ? preparedContext.ecdsa.chainTargets
    : null;
}

function registrationIntentResponseRpId(intent: RegistrationIntentV1): string | undefined {
  return intent.authMethod.kind === 'passkey' ? intent.authMethod.rpId : undefined;
}

function registrationIntentWalletsMatch(input: {
  readonly requestIntent: RegistrationIntentV1;
  readonly storedIntent: RegistrationIntentV1;
}): boolean {
  return input.requestIntent.walletId === input.storedIntent.walletId;
}

function registrationPreparationWalletsMatch(input: {
  readonly expectedWalletId: string;
  readonly preparation: {
    readonly intent: RegistrationIntentV1;
    readonly authority: { readonly walletId: string };
    readonly ed25519Scope: { readonly walletId: string };
  };
}): boolean {
  return (
    input.preparation.intent.walletId === input.expectedWalletId &&
    input.preparation.authority.walletId === input.expectedWalletId &&
    input.preparation.ed25519Scope.walletId === input.expectedWalletId
  );
}

function registrationCeremonyWalletsMatch(input: {
  readonly ceremony: {
    readonly intent: RegistrationIntentV1;
    readonly authority: { readonly walletId: string };
  };
}): boolean {
  return input.ceremony.authority.walletId === input.ceremony.intent.walletId;
}

function resolvedRegistrationNearAccount(input: {
  readonly accountProvisioning: RegistrationNearAccountProvisioning;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly sponsoredTransactionHash?: string;
}):
  | { ok: true; value: ResolvedRegistrationNearAccount }
  | { ok: false; code: string; message: string } {
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(input.nearEd25519SigningKeyId);
  switch (input.accountProvisioning.kind) {
    case 'implicit_account': {
      const parsed = parseImplicitNearAccountId(input.nearAccountId);
      if (!parsed.ok) return { ok: false, code: 'internal', message: parsed.message };
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
      if (!parsed.ok) return { ok: false, code: 'internal', message: parsed.message };
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
  }
}

function sponsoredNamedRegistrationAccountId(
  provisioning: RegistrationNearAccountProvisioning,
): string | null {
  switch (provisioning.kind) {
    case 'implicit_account':
      return null;
    case 'sponsored_named_account':
      return String(provisioning.requestedAccountId);
  }
}

function finalizeSignerWorkMatchesPlan(input: {
  readonly request: FinalizeWalletRegistrationInput;
  readonly hasNearEd25519: boolean;
  readonly hasEvmFamilyEcdsa: boolean;
}): boolean {
  switch (input.request.kind) {
    case 'near_ed25519':
      return input.hasNearEd25519 && !input.hasEvmFamilyEcdsa;
    case 'evm_family_ecdsa':
      return !input.hasNearEd25519 && input.hasEvmFamilyEcdsa;
    case 'near_ed25519_and_evm_family_ecdsa':
      return input.hasNearEd25519 && input.hasEvmFamilyEcdsa;
  }
}

function finalizePasskeyRpId(authority: StoredRegistrationAuthority): string {
  if (authority.kind !== 'passkey') {
    throw new Error('passkey finalize auth method requires a passkey registration authority');
  }
  return authority.rpId;
}

export function ecdsaStrictRegistrationAuthority(
  facts: RouterAbEcdsaRegistrationRequestFactsV1,
): {
  readonly subjectId: string;
  readonly sessionId: string;
  readonly accountId: string;
  readonly expiresAtMs: number;
} {
  return {
    subjectId: facts.client_id,
    sessionId: facts.lifecycle.session_id,
    accountId: facts.lifecycle.account_id,
    expiresAtMs: facts.expires_at_ms,
  };
}

export function exactEcdsaParticipantPair(
  participantIds: readonly number[],
): readonly [1, 2] {
  if (participantIds.length !== 2 || participantIds[0] !== 1 || participantIds[1] !== 2) {
    throw new Error('ECDSA registration requires participant pair [1, 2]');
  }
  return [1, 2];
}

function ethereumAddressHexFromBase64Url(value: string): string {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) {
    throw new Error('ECDSA activation Ethereum address must contain 20 bytes');
  }
  let hex = '0x';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

type D1PendingEcdsaFamilyActivation = {
  readonly prepare: StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch['prepare'];
  readonly strictRegistration:
    StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch['strictRegistration'];
};

function requireActivatedEcdsaIdentity(input: {
  readonly branch: D1PendingEcdsaFamilyActivation;
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly activation: RouterAbEcdsaRegistrationActivationReceiptV1;
}): void {
  const registration = input.branch.strictRegistration;
  const receipt = input.activation.ecdsa_activation;
  const identity = receipt.public_identity;
  if (
    receipt.context.application_binding_digest_b64u !==
      registration.context.application_binding_digest_b64u ||
    identity.context_binding_b64u !== input.publicFacts.contextBinding32B64u ||
    identity.derivation_client_share_public_key33_b64u !==
      input.publicFacts.derivationClientSharePublicKey33B64u ||
    identity.client_share_retry_counter !== input.publicFacts.clientShareRetryCounter ||
    input.activation.lifecycle_id !== registration.lifecycle.lifecycle_id ||
    base64UrlEncode(Uint8Array.from(input.activation.transcript_digest.bytes)) !==
      input.publicFacts.proofTranscriptDigestB64u ||
    input.activation.activated !== true ||
    receipt.signing_worker.server_id !== registration.lifecycle.selected_server_id
  ) {
    throw new Error('ECDSA activation receipt does not match the admitted registration identity');
  }
}

export async function buildActivatedEcdsaFamilyBootstrap(input: {
  readonly branch: D1PendingEcdsaFamilyActivation;
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly activation: RouterAbEcdsaRegistrationActivationReceiptV1;
}): Promise<EcdsaDerivationServerBootstrapResponse> {
  requireActivatedEcdsaIdentity(input);
  const prepare = input.branch.prepare;
  const identity = input.activation.ecdsa_activation.public_identity;
  const expiresAtMs = input.branch.strictRegistration.expires_at_ms;
  const ethereumAddress = ethereumAddressHexFromBase64Url(
    identity.ethereum_address20_b64u,
  );
  const publicIdentity = parseEcdsaDerivationPublicIdentity({
    derivationClientSharePublicKey33B64u:
      input.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: identity.server_public_key33_b64u,
    groupPublicKey33B64u: identity.threshold_public_key33_b64u,
    ethereumAddress,
  });
  if (!publicIdentity) {
    throw new Error('ECDSA activation receipt contains an invalid public identity');
  }
  const keyHandle = await deriveThresholdEcdsaKeyHandle({
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
  });
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: String(prepare.walletId),
    evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    relayerKeyId: prepare.relayerKeyId,
    applicationBindingDigestB64u:
      input.branch.strictRegistration.context.application_binding_digest_b64u,
    contextBinding32B64u: input.publicFacts.contextBinding32B64u,
    publicIdentity,
    clientShareRetryCounter: input.publicFacts.clientShareRetryCounter,
    relayerShareRetryCounter: identity.server_share_retry_counter,
    publicTranscriptDigest32B64u: input.publicFacts.proofTranscriptDigestB64u,
    keyHandle,
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: identity.threshold_public_key33_b64u,
    ethereumAddress,
    relayerVerifyingShareB64u: identity.server_public_key33_b64u,
    participantIds: [...exactEcdsaParticipantPair(prepare.participantIds)],
    thresholdSessionId: prepare.thresholdSessionId,
    signingGrantId: prepare.signingGrantId,
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: prepare.remainingUses,
  };
}

type EcdsaPostRegistrationProofInput =
  | {
      readonly operation: 'recovery';
      readonly request: RouterAbEcdsaDerivationRecoveryRequestV1;
      readonly response: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
    }
  | {
      readonly operation: 'refresh';
      readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
      readonly response: RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1;
    };

function postRegistrationProofResponse(
  input: EcdsaPostRegistrationProofInput,
): RouterAbEcdsaStrictForwardedRegistrationResponseV1['response'] {
  switch (input.operation) {
    case 'recovery':
      return input.response.response;
    case 'refresh':
      return input.response.response;
  }
}

function postRegistrationProofMatchesRequest(
  input: EcdsaPostRegistrationProofInput,
): boolean {
  const response = postRegistrationProofResponse(input);
  return (
    response.lifecycle.lifecycle_id === input.request.lifecycle.lifecycle_id &&
    response.bundles.signerA.transcriptDigestB64u ===
      response.bundles.signerB.transcriptDigestB64u
  );
}

function pendingEcdsaSessionActivationRecord(input: {
  readonly proof: EcdsaPostRegistrationProofInput;
  readonly walletId: WalletId;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly nowMs: number;
}): WalletEcdsaPendingSessionActivationRecord {
  const response = postRegistrationProofResponse(input.proof);
  const base = {
    version: 'wallet_ecdsa_pending_session_activation_v1',
    walletId: input.walletId,
    lifecycleId: response.lifecycle.lifecycle_id,
    requestId: response.replay.request_id,
    publicCapability: input.publicCapability,
    createdAtMs: input.nowMs,
    expiresAtMs: input.proof.request.expires_at_ms,
  } as const;
  switch (input.proof.operation) {
    case 'recovery':
      return {
        ...base,
        operation: 'recovery',
        request: input.proof.request,
        response: input.proof.response,
      };
    case 'refresh':
      return {
        ...base,
        operation: 'refresh',
        request: input.proof.request,
        response: input.proof.response,
      };
  }
}

function refreshedActivationMatchesCapability(input: {
  readonly activation: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly refreshRequest: RouterAbEcdsaDerivationActivationRefreshRequestV1;
  readonly refreshResponse: RouterAbEcdsaDerivationActivationRefreshForwardedResponseV1;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
}): boolean {
  const activation = input.activation.ecdsa_activation;
  const bundles = input.refreshResponse.response.bundles;
  return (
    input.refreshRequest.previous_activation_epoch ===
      input.publicCapability.activation_epoch &&
    input.refreshRequest.next_activation_epoch === activation.activation_epoch &&
    input.refreshRequest.lifecycle.lifecycle_id === input.activation.lifecycle_id &&
    alphabetizeStringify(activation.context) ===
      alphabetizeStringify(input.publicCapability.context) &&
    alphabetizeStringify(activation.public_identity) ===
      alphabetizeStringify(input.publicCapability.public_identity) &&
    alphabetizeStringify(activation.signing_worker) ===
      alphabetizeStringify(input.publicCapability.signer_set.selected_server) &&
    base64UrlEncode(Uint8Array.from(input.activation.transcript_digest.bytes)) ===
      bundles.signerA.transcriptDigestB64u &&
    bundles.signerA.transcriptDigestB64u ===
      bundles.signerB.transcriptDigestB64u
  );
}

function buildPostRegistrationEcdsaNormalSigningState(input: {
  readonly walletKey: WalletRegistrationEcdsaWalletKey;
  readonly activation: RouterAbEcdsaRegistrationActivationReceiptV1;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const activation = input.activation.ecdsa_activation;
  const state = parseRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_key_id: input.walletKey.evmFamilySigningKeySlotId,
      wallet_id: input.walletKey.walletId,
      ecdsa_threshold_key_id: input.walletKey.ecdsaThresholdKeyId,
      signing_root_id: input.walletKey.signingRootId,
      signing_root_version: input.walletKey.signingRootVersion,
      context: activation.context,
      public_identity: activation.public_identity,
      signing_worker: activation.signing_worker,
      activation_epoch: activation.activation_epoch,
    },
  });
  if (!state) {
    throw new Error('refreshed ECDSA normal-signing state is invalid');
  }
  return state;
}

export class CloudflareD1WalletRegistrationService {
  private readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
  private readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
  private readonly getRouterAbNormalSigningRuntime: RouterAbNormalSigningRuntimeProvider;
  private readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly walletRegistrationCommitStore: D1WalletRegistrationCommitStore;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
    readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
    readonly getRouterAbNormalSigningRuntime: RouterAbNormalSigningRuntimeProvider;
    readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
    readonly getWalletStore: WalletStoreProvider;
    readonly walletRegistrationCommitStore: D1WalletRegistrationCommitStore;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.createSponsoredNamedNearAccount = input.createSponsoredNamedNearAccount;
    this.emailOtpRegistrationEnrollmentFinalizer = input.emailOtpRegistrationEnrollmentFinalizer;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getEd25519YaoProductRegistration = input.getEd25519YaoProductRegistration;
    this.getRouterAbNormalSigningRuntime = input.getRouterAbNormalSigningRuntime;
    this.ecdsaStrictRegistration = input.ecdsaStrictRegistration;
    this.getWalletStore = input.getWalletStore;
    this.walletRegistrationCommitStore = input.walletRegistrationCommitStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async getWalletRegistrationRuntimePolicyScope(
    registrationCeremonyId: string,
  ): Promise<RuntimePolicyScope | undefined> {
    const store = this.getRegistrationCeremonyIntentStore();
    if (!store) return undefined;
    const ceremony = await store.getCeremony(registrationCeremonyId);
    if (!ceremony) return undefined;
    return registrationPreparedContextRuntimePolicyScope(ceremony.preparedContext);
  }

  async listWalletEcdsaKeyFactsInventory(input: {
    readonly walletId: string;
    readonly rpId: string;
    readonly keyTargets: readonly unknown[];
  }): Promise<{
    readonly records: ThresholdEcdsaKeyInventoryRecord[];
    readonly diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
  }> {
    const store = this.getWalletStore();
    return await listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: input.walletId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
      getEcdsaSignerByKeyHandle: store.getEcdsaSignerByKeyHandle.bind(store),
    });
  }

  async recordEcdsaPostRegistrationProof(
    input: EcdsaPostRegistrationProofInput,
  ): Promise<
    | { readonly ok: true }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    try {
      const nowMs = Date.now();
      if (
        input.request.expires_at_ms <= nowMs ||
        !postRegistrationProofMatchesRequest(input)
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA post-registration proof does not match its admitted request',
        };
      }
      const walletId = walletIdFromString(input.request.lifecycle.account_id);
      if (
        input.request.client_id !== walletId ||
        input.request.lifecycle.root_share_epoch === ''
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA post-registration proof has an invalid wallet identity',
        };
      }
      const store = this.getWalletStore();
      const signer = await store.getEcdsaSignerByPostRegistrationRequest({
        walletId,
        request: input.request,
      });
      if (!signer) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA post-registration public capability is not registered',
        };
      }
      if (
        (input.operation === 'recovery' &&
          input.request.lifecycle.root_share_epoch !==
            signer.walletKey.publicCapability.activation_epoch) ||
        (input.operation === 'refresh' &&
          input.request.previous_activation_epoch !==
            signer.walletKey.publicCapability.activation_epoch)
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA post-registration request uses a stale activation epoch',
        };
      }
      await store.putEcdsaPendingSessionActivation(
        pendingEcdsaSessionActivationRecord({
          proof: input,
          walletId,
          publicCapability: signer.walletKey.publicCapability,
          nowMs,
        }),
      );
      return { ok: true };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to persist ECDSA post-registration proof',
      };
    }
  }

  async activateEcdsaPostRegistrationSession(
    input: RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  ): Promise<
    | {
        readonly ok: true;
        readonly walletKey: WalletRegistrationEcdsaWalletKey;
        readonly session: {
          readonly thresholdSessionId: string;
          readonly signingGrantId: string;
          readonly expiresAtMs: number;
          readonly remainingUses: number;
        };
        readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
        readonly signingWorkerActivation: RouterAbEcdsaRegistrationActivationReceiptV1;
      }
    | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    try {
      const nowMs = Date.now();
      const walletId = walletIdFromString(input.public_capability.client_id);
      const store = this.getWalletStore();
      const signer = await store.getEcdsaSignerByPublicCapability({
        walletId,
        publicCapability: input.public_capability,
      });
      if (!signer) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA public capability is not registered for this wallet',
        };
      }
      const walletKey = signer.walletKey;
      const signingRootScope = signingRootScopeFromRuntimePolicyScope(
        input.session_policy.runtime_policy_scope,
      );
      if (
        signingRootScope.signingRootId !== walletKey.signingRootId ||
        signingRootScope.signingRootVersion !== walletKey.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA session policy is outside the registered signing-root scope',
        };
      }
      const pending = await store.takeEcdsaPendingSessionActivationPair({
        walletId,
        recovery: {
          lifecycleId: input.recovery_binding.lifecycle_id,
          requestId: input.recovery_binding.request_id,
        },
        refresh: {
          lifecycleId: input.refresh_binding.lifecycle_id,
          requestId: input.refresh_binding.request_id,
        },
      });
      if (
        !pending ||
        alphabetizeStringify(pending.recovery.publicCapability) !==
          alphabetizeStringify(input.public_capability) ||
        alphabetizeStringify(pending.refresh.publicCapability) !==
          alphabetizeStringify(input.public_capability)
      ) {
        return {
          ok: false,
          code: 'proof_not_found',
          message: 'Exact one-time ECDSA recovery and refresh proofs are required',
        };
      }
      const signingWorkerActivation =
        pending.refresh.response.signing_worker_activation;
      if (
        !refreshedActivationMatchesCapability({
          activation: signingWorkerActivation,
          refreshRequest: pending.refresh.request,
          refreshResponse: pending.refresh.response,
          publicCapability: input.public_capability,
        }) ||
        input.session_policy.threshold_session_id !==
          signingWorkerActivation.ecdsa_activation.activation_epoch
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA refreshed activation does not match the registered public capability',
        };
      }
      const normalSigning = buildPostRegistrationEcdsaNormalSigningState({
        walletKey,
        activation: signingWorkerActivation,
      });
      const expiresAtMs = nowMs + input.session_policy.ttl_ms;
      const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
      if (!normalSigningRuntime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Router A/B normal signing is not configured',
        };
      }
      const provisioned =
        await normalSigningRuntime.provisionRouterAbEcdsaNormalSigningSession({
          kind: 'router_ab_ecdsa_normal_signing_session_v1',
          walletId,
          evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
          relayerKeyId: walletKey.relayerKeyId,
          thresholdSessionId: input.session_policy.threshold_session_id,
          signingGrantId: input.session_policy.signing_grant_id,
          signingRootId: walletKey.signingRootId,
          signingRootVersion: walletKey.signingRootVersion,
          participantIds: walletKey.participantIds,
          expiresAtMs,
          remainingUses: input.session_policy.remaining_uses,
        });
      if (!provisioned.ok) {
        return {
          ok: false,
          code: provisioned.code,
          message: provisioned.message,
        };
      }
      return {
        ok: true,
        walletKey,
        session: {
          thresholdSessionId: provisioned.thresholdSessionId,
          signingGrantId: input.session_policy.signing_grant_id,
          expiresAtMs: provisioned.expiresAtMs,
          remainingUses: provisioned.remainingUses,
        },
        normalSigning,
        signingWorkerActivation,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to activate ECDSA post-registration session',
      };
    }
  }

  async refreshEd25519YaoWalletSession(
    request: RouterAbEd25519YaoBudgetRefreshRequestV1,
  ): Promise<RouterAbEd25519YaoBudgetRefreshResponseV1> {
    try {
      const policy = request.sessionPolicy;
      const authorization = request.authorization;
      const authority = policy.authority;
      const runtimePolicyScope = policy.runtimePolicyScope;
      const routerAbNormalSigning = policy.routerAbNormalSigning;
      const participantIds = normalizeThresholdEd25519ParticipantIds(policy.participantIds);
      if (
        request.kind !== 'router_ab_ed25519_yao_budget_refresh_v1' ||
        !runtimePolicyScope ||
        !routerAbNormalSigning ||
        !participantIds ||
        participantIds.length !== 2 ||
        !walletAuthAuthoritiesMatch(authority, authorization.authority)
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao budget refresh policy is invalid',
        };
      }
      switch (authorization.kind) {
        case 'verified_passkey_router_ab_ed25519_yao_budget_refresh_v1':
          if (!isPasskeyWalletAuthAuthority(authority)) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'Ed25519 Yao passkey budget refresh requires passkey authority',
            };
          }
          break;
        case 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1':
          if (
            !isEmailOtpWalletAuthAuthority(authority) ||
            !Number.isSafeInteger(authorization.signerSlot) ||
            authorization.signerSlot < 1 ||
            !authorization.verifiedChallengeId.trim() ||
            authorization.verifiedProviderUserId !== authority.factor.providerUserId ||
            authorization.verifiedOrgId !== runtimePolicyScope.orgId
          ) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'Ed25519 Yao Email OTP budget refresh authorization is invalid',
            };
          }
          break;
      }
      const firstParticipantId = participantIds[0];
      const secondParticipantId = participantIds[1];
      if (firstParticipantId === undefined || secondParticipantId === undefined) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao budget refresh requires exactly two participants',
        };
      }
      const exactParticipantIds: readonly [number, number] = [
        firstParticipantId,
        secondParticipantId,
      ];
      const yaoRuntime = this.getEd25519YaoProductRegistration();
      const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
      if (!yaoRuntime || !normalSigningRuntime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Ed25519 Yao Wallet Session refresh is not configured',
        };
      }
      const current =
        authorization.kind === 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1'
          ? authorization.currentSession
          : null;
      if (
        policy.relayerKeyId !== yaoRuntime.signingWorkerId ||
        routerAbNormalSigning.signingWorkerId !== yaoRuntime.signingWorkerId ||
        (current !== null &&
          (current.walletId !== authority.walletId ||
            current.nearAccountId !== policy.nearAccountId ||
            current.nearEd25519SigningKeyId !== policy.nearEd25519SigningKeyId ||
            current.thresholdSessionId !== policy.thresholdSessionId ||
            current.signingGrantId !== policy.signingGrantId ||
            current.relayerKeyId !== policy.relayerKeyId ||
            !walletAuthAuthoritiesMatch(authority, current.authority) ||
            alphabetizeStringify(current.participantIds) !==
              alphabetizeStringify(exactParticipantIds) ||
            alphabetizeStringify(current.runtimePolicyScope) !==
              alphabetizeStringify(runtimePolicyScope) ||
            alphabetizeStringify(current.routerAbNormalSigning) !==
              alphabetizeStringify(routerAbNormalSigning)))
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'Ed25519 Yao budget refresh does not match the active Wallet Session',
        };
      }
      const activeAuthority =
        authorization.kind === 'verified_passkey_router_ab_ed25519_yao_budget_refresh_v1'
          ? await this.walletAuthMethods.verifyActivePasskeyAuthority(authorization.authority)
          : await this.walletAuthMethods.verifyActiveEmailOtpAuthority(authorization.authority);
      if (!activeAuthority.ok) return activeAuthority;
      const signingRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
      const signingRootVersion = toOptionalTrimmedString(signingRoot.signingRootVersion);
      if (!signingRootVersion) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao budget refresh requires a signing-root version',
        };
      }
      const signer = await this.getWalletStore().getEd25519Signer({
        walletId: authority.walletId,
        nearAccountId: policy.nearAccountId,
        nearEd25519SigningKeyId: policy.nearEd25519SigningKeyId,
      });
      if (
        !signer ||
        (authorization.kind === 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1' &&
          signer.signerSlot !== authorization.signerSlot) ||
        signer.signingWorkerId !== yaoRuntime.signingWorkerId ||
        signer.thresholdSessionId !== policy.thresholdSessionId ||
        alphabetizeStringify(signer.participantIds) !== alphabetizeStringify(exactParticipantIds) ||
        signer.signingRootId !== signingRoot.signingRootId ||
        signer.signingRootVersion !== signingRootVersion ||
        alphabetizeStringify(signer.runtimePolicyScope) !== alphabetizeStringify(runtimePolicyScope)
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Registered Ed25519 Yao signer does not match the refresh policy',
        };
      }
      const refreshed = await normalSigningRuntime.refreshRouterAbEd25519YaoNormalSigningBudget({
        kind: 'router_ab_ed25519_yao_normal_signing_budget_refresh_v1',
        walletId: authority.walletId,
        nearAccountId: policy.nearAccountId,
        nearEd25519SigningKeyId: policy.nearEd25519SigningKeyId,
        authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
        thresholdSessionId: policy.thresholdSessionId,
        signingGrantId: policy.signingGrantId,
        signingWorkerId: yaoRuntime.signingWorkerId,
        participantIds: exactParticipantIds,
        ttlMs: policy.ttlMs,
        remainingUses: policy.remainingUses,
      });
      if (!refreshed.ok) return refreshed;
      const minted = await yaoRuntime.mintWalletSession({
        kind: 'same_identity_budget_refresh_v1',
        walletId: authority.walletId,
        nearAccountId: policy.nearAccountId,
        nearEd25519SigningKeyId: policy.nearEd25519SigningKeyId,
        authority,
        thresholdSessionId: refreshed.thresholdSessionId,
        signingGrantId: refreshed.signingGrantId,
        expiresAtMs: refreshed.expiresAtMs,
        remainingUses: refreshed.remainingUses,
        participantIds: exactParticipantIds,
        runtimePolicyScope,
      });
      if (!minted.ok) return minted;
      const session = minted.session;
      return {
        ok: true,
        walletId: session.walletId,
        nearAccountId: session.nearAccountId,
        nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
        authorityScope: session.authorityScope,
        thresholdSessionId: session.thresholdSessionId,
        signingGrantId: session.signingGrantId,
        expiresAtMs: session.expiresAtMs,
        expiresAt: new Date(session.expiresAtMs).toISOString(),
        participantIds: exactParticipantIds,
        remainingUses: session.remainingUses,
        runtimePolicyScope,
        routerAbNormalSigning,
        jwt: session.walletSessionJwt,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Ed25519 Yao Wallet Session refresh failed',
      };
    }
  }

  async recoverEd25519YaoEmailOtpWalletSession(
    request: RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1,
  ): Promise<RouterAbEd25519YaoEmailOtpRecoverySessionResponseV1> {
    try {
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId);
      const providerUserId = toOptionalTrimmedString(request.verifiedProviderUserId);
      const verifiedChallengeId = toOptionalTrimmedString(request.verifiedChallengeId);
      const signerSlot = Math.floor(Number(request.signerSlot));
      const remainingUses = Math.floor(Number(request.remainingUses));
      if (
        request.kind !== 'router_ab_ed25519_yao_email_otp_recovery_session_v1' ||
        !walletId ||
        !orgId ||
        !providerUserId ||
        !verifiedChallengeId ||
        !Number.isSafeInteger(signerSlot) ||
        signerSlot < 1 ||
        !Number.isSafeInteger(remainingUses) ||
        remainingUses < 1
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP Ed25519 Yao recovery request is invalid',
        };
      }
      const yaoRuntime = this.getEd25519YaoProductRegistration();
      const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
      if (!yaoRuntime || !normalSigningRuntime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Email OTP Ed25519 Yao recovery is not configured',
        };
      }
      const authorityResult =
        await this.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject({
          walletId,
          providerUserId,
        });
      if (!authorityResult.ok) return authorityResult;
      const authority = authorityResult.authority;
      if (
        String(authority.walletId) !== walletId ||
        String(authority.factor.providerUserId) !== providerUserId
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'Verified Email OTP subject does not match the wallet authority',
        };
      }
      const signer = await this.getWalletStore().getEd25519SignerBySlot({
        walletId: walletIdFromString(walletId),
        signerSlot,
      });
      const firstParticipantId = signer?.participantIds[0];
      const secondParticipantId = signer?.participantIds[1];
      if (
        !signer ||
        signer.walletId !== walletId ||
        signer.signerSlot !== signerSlot ||
        signer.signingWorkerId !== yaoRuntime.signingWorkerId ||
        signer.runtimePolicyScope.orgId !== orgId ||
        firstParticipantId === undefined ||
        secondParticipantId === undefined
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Registered Ed25519 Yao signer is unavailable for Email OTP recovery',
        };
      }
      const participantIds: readonly [number, number] = [firstParticipantId, secondParticipantId];
      const signingRoot = signingRootScopeFromRuntimePolicyScope(signer.runtimePolicyScope);
      if (
        signingRoot.signingRootId !== signer.signingRootId ||
        signingRoot.signingRootVersion !== signer.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Registered Ed25519 Yao signer has inconsistent signing-root scope',
        };
      }
      const capability = await yaoRuntime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId,
        nearAccountId: signer.nearAccountId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        signerSlot,
        signingWorkerId: signer.signingWorkerId,
        participantIds,
      });
      if (!capability.ok) return capability;
      const descriptor = capability.capability;
      if (
        descriptor.applicationBinding.wallet_id !== walletId ||
        descriptor.applicationBinding.near_ed25519_signing_key_id !==
          signer.nearEd25519SigningKeyId ||
        descriptor.applicationBinding.key_creation_signer_slot !== signerSlot ||
        descriptor.applicationBinding.signing_root_id !== signer.signingRootId ||
        descriptor.nearAccountId !== signer.nearAccountId ||
        descriptor.lifecycle.accountId !== walletId ||
        descriptor.lifecycle.signerSetId !== String(registrationNearEd25519BranchKey(signerSlot)) ||
        descriptor.lifecycle.signingWorkerId !== signer.signingWorkerId ||
        descriptor.lifecycle.rootShareEpoch !== signer.signingRootVersion ||
        ed25519NearPublicKeyFromBytes(descriptor.registeredPublicKey) !== signer.publicKey ||
        alphabetizeStringify(descriptor.participantIds) !== alphabetizeStringify(participantIds) ||
        alphabetizeStringify(descriptor.runtimePolicyScope) !==
          alphabetizeStringify(signer.runtimePolicyScope)
      ) {
        return {
          ok: false,
          code: 'capability_conflict',
          message: 'Active Ed25519 Yao capability does not match the registered signer',
        };
      }
      const minted = await yaoRuntime.mintWalletSession({
        kind: 'shared_email_otp_recovery_wallet_session_v1',
        walletId: walletIdFromString(walletId),
        nearAccountId: signer.nearAccountId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        authority,
        thresholdSessionId: descriptor.lifecycle.walletSessionId,
        participantIds,
        runtimePolicyScope: signer.runtimePolicyScope,
        remainingUses,
      });
      if (!minted.ok) return minted;
      const session = minted.session;
      const provisioned =
        await normalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession({
          kind: 'router_ab_ed25519_yao_normal_signing_session_v1',
          walletId,
          nearAccountId: signer.nearAccountId,
          nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
          authorityScope: session.authorityScope,
          thresholdSessionId: session.thresholdSessionId,
          signingGrantId: session.signingGrantId,
          signingWorkerId: signer.signingWorkerId,
          expiresAtMs: session.expiresAtMs,
          participantIds,
          remainingUses: session.remainingUses,
        });
      if (!provisioned.ok) return provisioned;
      return { ok: true, session, capability: descriptor };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Email OTP Ed25519 Yao recovery failed',
      };
    }
  }

  async startWalletRegistration(
    request: StartWalletRegistrationInput,
    context?: { readonly userAgent?: string },
  ): Promise<WalletRegistrationStartResponse> {
    const timing = createD1RegistrationRouteTimingRecorder('wallets_register_start');
    const total = startD1RegistrationRouteTiming('registerStartTotalMs');
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const grant = registrationIntentGrantFromString(
        toOptionalTrimmedString(request.registrationIntentGrant) || '',
      );
      if (!grant) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'registration intent grant is required',
        };
      }
      const preview = await store.getIntent(grant);
      if (!preview) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      const requestIntent = parseD1RegistrationIntent(request.intent);
      if (!requestIntent) {
        return { ok: false, code: 'invalid_body', message: 'registration intent is invalid' };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      const requestDigest = await computeRegistrationIntentDigestB64u(requestIntent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== preview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'registration intent digest mismatch' };
      }
      if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: preview.intent })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent walletId mismatch',
        };
      }
      const branches = registrationIntentSignerBranches(preview.intent);
      if (!branches.ok) return branches;
      const nearEd25519Branch = branches.value.nearEd25519;
      const ecdsaBranch = branches.value.evmFamilyEcdsa;
      if (!nearEd25519Branch && !ecdsaBranch) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration signer branch is required',
        };
      }
      if (!request.authority) {
        return { ok: false, code: 'invalid_body', message: 'registration authority is required' };
      }
      const expectedOrigin = toOptionalTrimmedString(preview.expectedOrigin);
      const verifiedAuthority = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
        orgId: preview.orgId,
        authority: request.authority,
        expectedDigestB64u: preview.digestB64u,
        expectedOrigin: expectedOrigin || '',
        intent: preview.intent,
        userAgent: context?.userAgent,
      });
      if (!verifiedAuthority.ok) return verifiedAuthority;
      const runtimePolicyScope = parseD1RuntimePolicyScope(preview.intent.runtimePolicyScope);
      const signingRootId =
        preview.signingRootId ||
        (runtimePolicyScope ? deriveSigningRootId(runtimePolicyScope) : '');
      const signingRootVersion =
        toOptionalTrimmedString(preview.signingRootVersion) ||
        runtimePolicyScope?.signingRootVersion ||
        'default';
      if (!signingRootId) {
        return { ok: false, code: 'invalid_body', message: 'registration requires a signing root' };
      }
      const preparedContext = resolveRegistrationPreparedContextFromPlan({
        signerPlan: branches.value.plan,
        runtimePolicyScope,
        signingRootId,
        signingRootVersion,
      });
      if (!preparedContext.ok) return preparedContext;
      const storedIntent = await store.takeIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      const registrationCeremonyId = `wrc_${secureRandomBase64Url(24)}`;
      const expiresAtMs = Math.min(storedIntent.expiresAtMs, Date.now() + 10 * 60_000);
      const storedBranches: StoredWalletRegistrationSignerBranch[] = [];
      let ed25519Start: WalletRegistrationEd25519YaoStart | null = null;
      if (nearEd25519Branch) {
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        if (!yaoRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao product registration is not configured',
          };
        }
        const admissionRequest = await buildRouterAbEd25519YaoProductAdmissionRequestV1({
          registrationCeremonyId,
          walletId: storedIntent.intent.walletId,
          signingRootId,
          signingRootVersion,
          authority: verifiedAuthority.authority,
          branch: nearEd25519Branch,
          signingWorkerId: yaoRuntime.signingWorkerId,
        });
        const bound = await yaoRuntime.bindVerifiedIntent({
          kind: 'verified_registration_intent',
          registrationIntentGrant: storedIntent.grant,
          intent: storedIntent.intent,
          admissionRequest,
          expiresAtMs,
        });
        if (!bound.ok) return bound;
        ed25519Start = { admissionRequest };
        storedBranches.push(
          buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch({
            branchKey: nearEd25519Branch.branchKey,
            admissionRequest,
          }),
        );
      }
      let ecdsaStart: WalletRegistrationEcdsaPreparePayload | null = null;
      if (ecdsaBranch) {
        if (!runtimePolicyScope) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ECDSA registration requires an exact runtime policy scope',
          };
        }
        const chainTargets = registrationPreparedContextEcdsaChainTargets(
          preparedContext.preparedContext,
        );
        if (!chainTargets) {
          return { ok: false, code: 'invalid_body', message: 'ECDSA chain targets are required' };
        }
        const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
          registrationCeremonyId,
          registrationPreparationId:
            request.registrationPreparationId ||
            registrationPreparationIdFromString(`regprep_${secureRandomBase64Url(24)}`),
          walletId: storedIntent.intent.walletId,
          signingRootId,
          signingRootVersion,
          chainTargets,
          participantIds: [...ecdsaBranch.participantIds],
          strictRegistration: this.ecdsaStrictRegistration,
          runtimePolicyScope,
        });
        if (!prepared.ok) return prepared;
        ecdsaStart = prepared.ecdsa;
        storedBranches.push(
          buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch({
            branchKey: ecdsaBranch.branchKey,
            ecdsa: prepared.ecdsa,
          }),
        );
      }
      await store.putCeremony({
        registrationCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        signerPlan: branches.value.plan,
        preparedContext: preparedContext.preparedContext,
        orgId: storedIntent.orgId,
        signingRootId,
        signingRootVersion,
        ...(expectedOrigin ? { expectedOrigin } : {}),
        expiresAtMs,
        authority: verifiedAuthority.authority,
        signerState: {
          kind: 'signer_set_registration',
          branches: storedBranches,
        },
      });
      finishD1RegistrationRouteTiming(timing, total);
      if (ed25519Start && ecdsaStart) {
        return withD1RegistrationStartDiagnostics(
          {
            ok: true,
            kind: 'near_ed25519_and_evm_family_ecdsa',
            registrationCeremonyId,
            intent: storedIntent.intent,
            ed25519: ed25519Start,
            ecdsa: ecdsaStart,
          },
          timing,
        );
      }
      if (ed25519Start) {
        return withD1RegistrationStartDiagnostics(
          {
            ok: true,
            kind: 'near_ed25519',
            registrationCeremonyId,
            intent: storedIntent.intent,
            ed25519: ed25519Start,
          },
          timing,
        );
      }
      if (!ecdsaStart) throw new Error('registration produced no signer work');
      return withD1RegistrationStartDiagnostics(
        {
          ok: true,
          kind: 'evm_family_ecdsa',
          registrationCeremonyId,
          intent: storedIntent.intent,
          ecdsa: ecdsaStart,
        },
        timing,
      );
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet registration ceremony',
      };
    }
  }

  async respondWalletRegistrationEcdsaDerivation(
    request: RespondWalletRegistrationDerivationInput,
  ): Promise<WalletRegistrationEcdsaDerivationRespondResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getCeremony(request.registrationCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (!registrationCeremonyWalletsMatch({ ceremony })) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration ceremony walletId mismatch',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const signerBranches = registrationSignerBranchesFromPlan(ceremony.signerPlan);
      if (!signerBranches.evmFamilyEcdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration signer set does not accept ECDSA registration input',
        };
      }
      const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
      if (ecdsaBranch?.kind === 'evm_family_ecdsa_pending_activation') {
        if (
          !routerAbEcdsaStrictRegistrationRequestMatchesFacts({
            request: request.ecdsa.strictRegistration,
            facts: ecdsaBranch.strictRegistration,
          })
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA registration replay changed the admitted ceremony facts',
          };
        }
        return {
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_forwarded_v1',
            strictResult: ecdsaBranch.publicResponse,
          },
        };
      }
      if (!ecdsaBranch || ecdsaBranch.kind !== 'evm_family_ecdsa_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'one prepared ECDSA family registration is required',
        };
      }
      if (
        !routerAbEcdsaStrictRegistrationRequestMatchesFacts({
          request: request.ecdsa.strictRegistration,
          facts: ecdsaBranch.strictRegistration,
        })
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA registration request does not match the admitted ceremony facts',
        };
      }
      const strictResult = await this.ecdsaStrictRegistration.register({
        request: request.ecdsa.strictRegistration,
        authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
      });
      if (!strictResult.ok) {
        if (!strictResult.retryable) {
          await store.cancelTerminalCeremony({
            registrationCeremonyId: ceremony.registrationCeremonyId,
            walletId: ceremony.intent.walletId,
          });
        }
        return {
          ok: false,
          code: strictResult.code,
          message: strictResult.message,
        };
      }
      const nextSignerState = replaceStoredWalletRegistrationSignerBranch({
        state: ceremony.signerState,
        replacement: {
          kind: 'evm_family_ecdsa_pending_activation',
          branchKey: ecdsaBranch.branchKey,
          derivationKind: ecdsaBranch.derivationKind,
          chainTargets: ecdsaBranch.chainTargets,
          prepare: ecdsaBranch.prepare,
          strictRegistration: ecdsaBranch.strictRegistration,
          registrationRequest: request.ecdsa.strictRegistration,
          pendingActivation: strictResult.value.pendingActivation,
          publicResponse: strictResult.value.publicResponse,
        },
      });
      await store.updateCeremony({
        ...ceremony,
        signerState: nextSignerState,
      });
      return {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_forwarded_v1',
          strictResult: strictResult.value.publicResponse,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to respond to wallet registration ceremony',
      };
    }
  }

  async activateWalletRegistrationEcdsa(
    request: ActivateWalletRegistrationEcdsaInput,
  ): Promise<WalletRegistrationEcdsaActivationResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getCeremony(request.registrationCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (
        !registrationCeremonyWalletsMatch({ ceremony }) ||
        ceremony.signerState.kind !== 'signer_set_registration'
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
      if (ecdsaBranch?.kind === 'evm_family_ecdsa_activated') {
        if (
          alphabetizeStringify(ecdsaBranch.publicFacts) !==
          alphabetizeStringify(request.ecdsa.publicFacts)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA activation replay changed the verified client facts',
          };
        }
        return {
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activated_v1',
            activation: ecdsaBranch.activation,
            bootstrap: ecdsaBranch.bootstrap,
          },
        };
      }
      if (!ecdsaBranch || ecdsaBranch.kind !== 'evm_family_ecdsa_pending_activation') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'one pending ECDSA family activation is required',
        };
      }
      const activated = await this.ecdsaStrictRegistration.activate({
        pendingActivation: ecdsaBranch.pendingActivation,
        clientActivation: request.ecdsa.publicFacts,
        authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
      });
      if (!activated.ok) {
        if (!activated.retryable) {
          await store.updateCeremony({
            ...ceremony,
            signerState: {
              kind: 'registration_failed',
              failedAtMs: Date.now(),
              failure: {
                code: activated.code,
                message: activated.message,
              },
            },
          });
        }
        return {
          ok: false,
          code: activated.code,
          message: activated.message,
        };
      }
      try {
        const bootstrap = await buildActivatedEcdsaFamilyBootstrap({
          branch: ecdsaBranch,
          publicFacts: request.ecdsa.publicFacts,
          activation: activated.value,
        });
        const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
        if (!normalSigningRuntime) {
          throw new Error('Router A/B normal signing is not configured');
        }
        const provisioned = await normalSigningRuntime.provisionRouterAbEcdsaNormalSigningSession({
          kind: 'router_ab_ecdsa_normal_signing_session_v1',
          walletId: bootstrap.walletId,
          evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
          relayerKeyId: bootstrap.relayerKeyId,
          thresholdSessionId: bootstrap.thresholdSessionId,
          signingGrantId: bootstrap.signingGrantId,
          signingRootId: bootstrap.signingRootId,
          signingRootVersion: bootstrap.signingRootVersion,
          participantIds: exactEcdsaParticipantPair(bootstrap.participantIds),
          expiresAtMs: bootstrap.expiresAtMs,
          remainingUses: bootstrap.remainingUses,
        });
        if (!provisioned.ok) {
          throw new Error(provisioned.message);
        }
        const activatedBranch: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch = {
        kind: 'evm_family_ecdsa_activated',
        branchKey: ecdsaBranch.branchKey,
        derivationKind: ecdsaBranch.derivationKind,
        chainTargets: ecdsaBranch.chainTargets,
        prepare: ecdsaBranch.prepare,
        strictRegistration: ecdsaBranch.strictRegistration,
        registrationRequest: ecdsaBranch.registrationRequest,
        publicFacts: request.ecdsa.publicFacts,
        activation: activated.value,
        publicCapability: buildRouterAbEcdsaDerivationPublicCapabilityV1({
          registrationFacts: ecdsaBranch.strictRegistration,
          registrationRequest: ecdsaBranch.registrationRequest,
          clientActivation: request.ecdsa.publicFacts,
          activationReceipt: activated.value,
        }),
        bootstrap: {
          formatVersion: bootstrap.formatVersion,
          walletId: bootstrap.walletId,
          evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
          relayerKeyId: bootstrap.relayerKeyId,
          applicationBindingDigestB64u: bootstrap.applicationBindingDigestB64u,
          contextBinding32B64u: bootstrap.contextBinding32B64u,
          publicIdentity: bootstrap.publicIdentity,
          clientShareRetryCounter: bootstrap.clientShareRetryCounter,
          relayerShareRetryCounter: bootstrap.relayerShareRetryCounter,
          publicTranscriptDigest32B64u: bootstrap.publicTranscriptDigest32B64u,
          keyHandle: bootstrap.keyHandle,
          signingRootId: bootstrap.signingRootId,
          signingRootVersion: bootstrap.signingRootVersion,
          thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
          ethereumAddress: bootstrap.ethereumAddress,
          relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
          thresholdSessionId: bootstrap.thresholdSessionId,
          signingGrantId: bootstrap.signingGrantId,
          expiresAtMs: provisioned.expiresAtMs,
          expiresAt: new Date(provisioned.expiresAtMs).toISOString(),
          remainingUses: provisioned.remainingUses,
          participantIds: [...provisioned.participantIds],
        },
        };
        await store.updateCeremony({
          ...ceremony,
          signerState: replaceStoredWalletRegistrationSignerBranch({
            state: ceremony.signerState,
            replacement: activatedBranch,
          }),
        });
        return {
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activated_v1',
            activation: activated.value,
            bootstrap: activatedBranch.bootstrap,
          },
        };
      } catch (error: unknown) {
        const message =
          errorMessage(error) || 'ECDSA activation could not establish normal signing';
        await store.updateCeremony({
          ...ceremony,
          signerState: {
            kind: 'registration_failed',
            failedAtMs: Date.now(),
            failure: {
              code: 'ecdsa_activation_terminal_failure',
              message,
            },
          },
        });
        return {
          ok: false,
          code: 'ecdsa_activation_terminal_failure',
          message,
        };
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to activate ECDSA wallet registration',
      };
    }
  }

  async finalizeWalletRegistration(
    request: FinalizeWalletRegistrationInput,
  ): Promise<WalletRegistrationFinalizeResponse> {
    const finalizeTiming = createD1RegistrationRouteTimingRecorder('wallets_register_finalize');
    const totalTiming = startD1RegistrationRouteTiming('registerFinalizeTotalMs');
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (idempotencyKey) {
        const replayTiming = startD1RegistrationRouteTiming('registrationFinalizeReplayLoadMs');
        let replay: Awaited<ReturnType<typeof store.getFinalizeReplay>>;
        try {
          replay = await store.getFinalizeReplay({
            registrationCeremonyId: request.registrationCeremonyId,
            idempotencyKey,
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, replayTiming);
        }
        if (replay) {
          await cleanupFinalizedRegistrationCeremony({
            store,
            registrationCeremonyId: request.registrationCeremonyId,
          });
          finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
          return withD1RegistrationRouteDiagnostics(replay.response, finalizeTiming);
        }
      }
      const ceremonyLoadTiming = startD1RegistrationRouteTiming('registrationCeremonyLoadMs');
      let ceremony: Awaited<ReturnType<typeof store.getCeremony>>;
      try {
        ceremony = await store.getCeremony(request.registrationCeremonyId);
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, ceremonyLoadTiming);
      }
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (!registrationCeremonyWalletsMatch({ ceremony })) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration ceremony walletId mismatch',
        };
      }
      const signerBranches = registrationSignerBranchesFromPlan(ceremony.signerPlan);
      const requestedNearEd25519 = signerBranches.nearEd25519;
      const requestedEvmFamilyEcdsa = signerBranches.evmFamilyEcdsa;
      if (!requestedNearEd25519 && !requestedEvmFamilyEcdsa) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'registration signer set requires a signer branch',
        };
      }
      if (
        !finalizeSignerWorkMatchesPlan({
          request,
          hasNearEd25519: requestedNearEd25519 !== null,
          hasEvmFamilyEcdsa: requestedEvmFamilyEcdsa !== null,
        })
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration finalize signer work does not match the admitted signer plan',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const ecdsaWalletKeys: WalletRegistrationEcdsaWalletKey[] = [];
      let ecdsaFinalizeState: D1RegistrationEcdsaFinalizeState = {
        kind: 'ecdsa_registration_disabled',
      };
      if (requestedEvmFamilyEcdsa) {
        const ecdsaState = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
        if (!ecdsaState || ecdsaState.kind !== 'evm_family_ecdsa_activated') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA family activation is required before finalize',
          };
        }
        if (!request.ecdsa) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ECDSA finalize requires the activated family key handle',
          };
        }
        const expectedKeyHandles = request.ecdsa.expectedKeyHandles;
        const actualKeyHandles = [ecdsaState.bootstrap.keyHandle];
        if (hasEcdsaKeyHandleSetMismatch(expectedKeyHandles, actualKeyHandles)) {
          return {
            ok: false,
            code: 'key_handle_mismatch',
            message: 'ECDSA finalize expected key handle mismatch',
          };
        }
        const ecdsaVerifyTiming = startD1RegistrationRouteTiming(
          'registrationEcdsaBootstrapVerifyMs',
        );
        let walletKeyResult: ReturnType<typeof buildD1EcdsaWalletKeysFromBootstrap>;
        try {
          walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
            bootstraps: ecdsaState.chainTargets.map((chainTarget) => ({
              chainTarget,
              bootstrap: ecdsaState.bootstrap,
            })),
            publicCapability: ecdsaState.publicCapability,
            errorContext: 'ECDSA registration finalize',
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, ecdsaVerifyTiming);
        }
        if (!walletKeyResult.ok) return walletKeyResult;
        ecdsaWalletKeys.push(...walletKeyResult.walletKeys);
        ecdsaFinalizeState = {
          kind: 'ecdsa_registration_responded',
          state: ecdsaState,
        };
      }

      const now = Date.now();
      const emailOtpEnrollmentTiming = startD1RegistrationRouteTiming(
        'registrationEmailOtpEnrollmentPlanMs',
      );
      let emailOtpEnrollment: Awaited<
        ReturnType<typeof this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize>
      >;
      try {
        emailOtpEnrollment =
          await this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize({
            authority: ceremony.authority,
            request,
            walletId: ceremony.intent.walletId,
            orgId: ceremony.orgId,
            nowMs: now,
          });
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, emailOtpEnrollmentTiming);
      }
      if (!emailOtpEnrollment.ok) return emailOtpEnrollment;

      const walletAuthAuthority = walletAuthAuthorityFromRegistrationAuthority(ceremony.authority);
      let ed25519PublicResult: WalletRegistrationEd25519YaoPublicResult | null = null;
      let resolvedNearAccount: ResolvedRegistrationNearAccount | null = null;
      let ed25519SignerRecord: WalletEd25519SignerRecord | null = null;
      let ed25519CapabilityInstallation: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1 | null =
        null;
      if (requestedNearEd25519) {
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        if (!yaoRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao product registration is not configured',
          };
        }
        const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
        if (!normalSigningRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Router A/B normal signing is not configured',
          };
        }
        const storedYao = findStoredWalletRegistrationNearEd25519YaoBranch(ceremony.signerState);
        if (!storedYao || !request.ed25519) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'authorized Ed25519 Yao registration is required before finalize',
          };
        }
        if (ceremony.preparedContext.runtimePolicy.kind !== 'runtime_policy_scope') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 Yao wallet session requires a runtime policy scope',
          };
        }
        const runtimePolicyScope = ceremony.preparedContext.runtimePolicy.scope;
        const activationReference = request.ed25519.activationReference;
        const consumed = await yaoRuntime.consumeActivated({
          reference: {
            lifecycleId: activationReference.lifecycle_id,
            sessionId: activationReference.session_id,
          },
          consumerBinding: alphabetizeStringify(request),
        });
        if (!consumed.ok) {
          return { ok: false, code: consumed.code, message: consumed.message };
        }
        if (
          alphabetizeStringify(consumed.activation.admissionRequest) !==
          alphabetizeStringify(storedYao.admissionRequest)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'activated Ed25519 Yao registration does not match the stored signer branch',
          };
        }
        const firstParticipantId = requestedNearEd25519.participantIds[0];
        const secondParticipantId = requestedNearEd25519.participantIds[1];
        if (
          requestedNearEd25519.participantIds.length !== 2 ||
          firstParticipantId === undefined ||
          secondParticipantId === undefined
        ) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 Yao registration requires exactly two participants',
          };
        }
        const participantIds: readonly [number, number] = [firstParticipantId, secondParticipantId];
        const publicKeyBytes = consumed.activation.result.public_receipt.registered_public_key;
        const publicKey = ed25519NearPublicKeyFromBytes(publicKeyBytes);
        let nearAccountId = implicitNearAccountIdFromEd25519PublicKeyBytes(publicKeyBytes);
        let sponsoredTransactionHash: string | undefined;
        const sponsoredAccountId = sponsoredNamedRegistrationAccountId(
          requestedNearEd25519.accountProvisioning,
        );
        if (sponsoredAccountId) {
          const created = await this.createSponsoredNamedNearAccount({
            accountId: sponsoredAccountId,
            publicKey,
          });
          if (!created.success) {
            return {
              ok: false,
              code: 'account_creation_failed',
              message:
                created.message || created.error || 'Failed to create sponsored NEAR account',
            };
          }
          nearAccountId = created.accountId || sponsoredAccountId;
          sponsoredTransactionHash = created.transactionHash;
        }
        const resolved = resolvedRegistrationNearAccount({
          accountProvisioning: requestedNearEd25519.accountProvisioning,
          nearAccountId,
          nearEd25519SigningKeyId:
            consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
          ...(sponsoredTransactionHash ? { sponsoredTransactionHash } : {}),
        });
        if (!resolved.ok) return resolved;
        resolvedNearAccount = resolved.value;
        ed25519CapabilityInstallation = {
          kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
          activeCapabilityBinding: consumed.activation.result.binding.session_id,
          nearAccountId,
          registrationAdmissionRequest: consumed.activation.admissionRequest,
          registrationResult: consumed.activation.result,
          runtimePolicyScope,
        };
        const activeYaoCapability =
          buildRouterAbEd25519YaoRegistrationCapabilityRecordV1(
            ed25519CapabilityInstallation,
          );
        if (!activeYaoCapability.ok) {
          return {
            ok: false,
            code: activeYaoCapability.code,
            message: activeYaoCapability.message,
          };
        }
        let signingBudget: D1RegistrationEd25519SigningBudgetPlan;
        switch (ecdsaFinalizeState.kind) {
          case 'ecdsa_registration_disabled':
            signingBudget = { kind: 'generated_registration_signing_budget' };
            break;
          case 'ecdsa_registration_responded': {
            const resolvedSigningBudget = await resolveD1RegistrationSharedSigningBudget({
              walletId: ceremony.intent.walletId,
              ecdsaState: ecdsaFinalizeState.state,
              getWalletBudgetStatus:
                normalSigningRuntime.getSigningGrantBudgetStatus.bind(normalSigningRuntime),
            });
            if (!resolvedSigningBudget.ok) return resolvedSigningBudget;
            signingBudget = {
              kind: 'shared_registration_signing_budget',
              budget: resolvedSigningBudget.budget,
            };
            break;
          }
          default:
            signingBudget = assertNeverD1RegistrationEcdsaFinalizeState(ecdsaFinalizeState);
        }
        const session = await mintD1RegistrationEd25519WalletSession({
          runtime: yaoRuntime,
          identity: {
            walletId: ceremony.intent.walletId,
            nearAccountId,
            nearEd25519SigningKeyId:
              consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
            authority: walletAuthAuthority,
            thresholdSessionId: consumed.activation.admissionRequest.scope.wallet_session_id,
            participantIds,
            runtimePolicyScope,
          },
          signingBudget,
        });
        if (!session.ok) return session;
        const provisioned =
          await normalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession({
            kind: 'router_ab_ed25519_yao_normal_signing_session_v1',
            walletId: ceremony.intent.walletId,
            nearAccountId,
            nearEd25519SigningKeyId:
              consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
            authorityScope: session.session.authorityScope,
            thresholdSessionId: session.session.thresholdSessionId,
            signingGrantId: session.session.signingGrantId,
            signingWorkerId: yaoRuntime.signingWorkerId,
            expiresAtMs: session.session.expiresAtMs,
            participantIds,
            remainingUses: session.session.remainingUses,
          });
        if (!provisioned.ok) return provisioned;
        ed25519PublicResult = {
          signerSlot: requestedNearEd25519.signerSlot,
          nearAccountId,
          nearEd25519SigningKeyId:
            consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
          publicKey,
          relayerKeyId: yaoRuntime.signingWorkerId,
          keyVersion: requestedNearEd25519.keyVersion,
          recoveryExportCapable: true,
          participantIds,
          session: session.session,
        };
        ed25519SignerRecord = buildYaoEd25519WalletSignerRecord({
          walletId: ceremony.intent.walletId,
          nearAccountId,
          nearEd25519SigningKeyId: ed25519PublicResult.nearEd25519SigningKeyId,
          thresholdSessionId: session.session.thresholdSessionId,
          signerSlot: requestedNearEd25519.signerSlot,
          publicKey,
          signingWorkerId: yaoRuntime.signingWorkerId,
          keyVersion: requestedNearEd25519.keyVersion,
          participantIds,
          signingRootId: ceremony.preparedContext.signingRootId,
          signingRootVersion: ceremony.preparedContext.signingRootVersion,
          runtimePolicyScope,
          activeYaoCapability: activeYaoCapability.record,
          now,
        });
      }

      const wallet = buildD1WalletRecord({
        walletId: ceremony.intent.walletId,
        now,
      });
      const walletSigners: WalletSignerRecord[] = buildD1WalletEcdsaSignerRecords({
        walletId: ceremony.intent.walletId,
        walletKeys: ecdsaWalletKeys,
        now,
      });
      if (ed25519SignerRecord) walletSigners.push(ed25519SignerRecord);
      const persistenceTiming = startD1RegistrationRouteTiming('relayPersistenceMs');
      try {
        if (emailOtpEnrollment.persistence) {
          const persisted = await this.emailOtpRegistrationEnrollmentFinalizer.persistPrepared(
            emailOtpEnrollment.persistence,
          );
          if (!persisted.ok) return persisted;
        }
        await this.walletRegistrationCommitStore.commit({
          wallet,
          walletSigners,
          authority: ceremony.authority,
          now,
        });
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, persistenceTiming);
      }
      if (ed25519CapabilityInstallation) {
        const yaoRuntime = this.getEd25519YaoProductRegistration();
        if (!yaoRuntime) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'Ed25519 Yao product registration is not configured',
          };
        }
        const installed = await yaoRuntime.installRegistrationFinalizeCapability(
          ed25519CapabilityInstallation,
        );
        if (!installed.ok) {
          return {
            ok: false,
            code: installed.code,
            message: installed.message,
          };
        }
      }
      const authMethod = walletRegistrationFinalizeAuthMethodFromAuthority(ceremony.authority);
      let response: WalletRegistrationFinalizeSuccess;
      if (ed25519PublicResult && requestedNearEd25519 && resolvedNearAccount) {
        const authorityScope =
          thresholdEd25519AuthorityScopeFromWalletAuthAuthority(walletAuthAuthority);
        if (requestedEvmFamilyEcdsa) {
          response =
            authMethod.kind === 'passkey'
              ? {
                  ok: true,
                  kind: 'near_ed25519_and_evm_family_ecdsa',
                  walletId: ceremony.intent.walletId,
                  authority: walletAuthAuthority,
                  rpId: finalizePasskeyRpId(ceremony.authority),
                  authMethod,
                  authorityScope,
                  accountProvisioning: requestedNearEd25519.accountProvisioning,
                  resolvedAccount: resolvedNearAccount,
                  ed25519: ed25519PublicResult,
                  ecdsa: { walletKeys: ecdsaWalletKeys },
                }
              : {
                  ok: true,
                  kind: 'near_ed25519_and_evm_family_ecdsa',
                  walletId: ceremony.intent.walletId,
                  authority: walletAuthAuthority,
                  authMethod,
                  authorityScope,
                  accountProvisioning: requestedNearEd25519.accountProvisioning,
                  resolvedAccount: resolvedNearAccount,
                  ed25519: ed25519PublicResult,
                  ecdsa: { walletKeys: ecdsaWalletKeys },
                };
        } else {
          response =
            authMethod.kind === 'passkey'
              ? {
                  ok: true,
                  kind: 'near_ed25519',
                  walletId: ceremony.intent.walletId,
                  authority: walletAuthAuthority,
                  rpId: finalizePasskeyRpId(ceremony.authority),
                  authMethod,
                  authorityScope,
                  accountProvisioning: requestedNearEd25519.accountProvisioning,
                  resolvedAccount: resolvedNearAccount,
                  ed25519: ed25519PublicResult,
                }
              : {
                  ok: true,
                  kind: 'near_ed25519',
                  walletId: ceremony.intent.walletId,
                  authority: walletAuthAuthority,
                  authMethod,
                  authorityScope,
                  accountProvisioning: requestedNearEd25519.accountProvisioning,
                  resolvedAccount: resolvedNearAccount,
                  ed25519: ed25519PublicResult,
                };
        }
      } else {
        response =
          authMethod.kind === 'passkey'
            ? {
                ok: true,
                kind: 'evm_family_ecdsa',
                walletId: ceremony.intent.walletId,
                authority: walletAuthAuthority,
                rpId: finalizePasskeyRpId(ceremony.authority),
                authMethod,
                ecdsa: { walletKeys: ecdsaWalletKeys },
              }
            : {
                ok: true,
                kind: 'evm_family_ecdsa',
                walletId: ceremony.intent.walletId,
                authority: walletAuthAuthority,
                authMethod,
                ecdsa: { walletKeys: ecdsaWalletKeys },
              };
      }
      if (idempotencyKey) {
        const replayCacheTiming = startD1RegistrationRouteTiming(
          'registrationFinalizeReplayCacheMs',
        );
        try {
          await store.putFinalizeReplay({
            kind: 'wallet_registration_finalize_replay_v1',
            registrationCeremonyId: ceremony.registrationCeremonyId,
            idempotencyKey,
            response,
            createdAtMs: now,
            expiresAtMs: ceremony.expiresAtMs,
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, replayCacheTiming);
        }
      }
      let deleted = false;
      try {
        deleted = await store.deleteCeremony(ceremony.registrationCeremonyId);
      } catch (error: unknown) {
        if (!idempotencyKey) throw error;
      }
      if (!deleted && !idempotencyKey) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
      return withD1RegistrationRouteDiagnostics(response, finalizeTiming);
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet registration ceremony',
      };
    }
  }
}
