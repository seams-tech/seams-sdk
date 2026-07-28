import {
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type TenantId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
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
import type { RouterAbTraceContextV1 } from '@shared/utils/routerAbTraceContext';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  deriveSigningRootId,
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import { type EcdsaDerivationServerBootstrapResponse } from '../../core/types';
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
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../../core/thresholdEcdsaChainTarget';
import {
  registrationPreparationIdFromString,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationEcdsaActivationPrepareRequest,
  WalletRegistrationEcdsaActivationPrepareResponse,
  WalletRegistrationEcdsaActivationQueryRequest,
  WalletRegistrationEcdsaActivationQueryResponse,
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
import type { AuthorizationService } from '../../authorization/service';
import { parseEcdsaDerivationPublicIdentity } from '../../core/ThresholdService/validation';
import {
  routerAbEcdsaStrictRegistrationFactsBindingJson,
  routerAbEcdsaStrictRegistrationRequestBindingJson,
  routerAbEcdsaStrictRegistrationRequestMatchesFacts,
  type RouterAbEcdsaStrictRegistrationPort,
} from '../routerAbEcdsaStrictRegistration';
import { CloudflareD1RegistrationCeremonyIntentStore } from './d1RegistrationCeremonyStore';
import {
  listThresholdEcdsaKeyIdentityTargetsForUser,
  type ThresholdEcdsaKeyInventoryDiagnostics,
  type ThresholdEcdsaKeyInventoryRecord,
} from '../../core/authService/thresholdEcdsaKeyInventory';
import {
  buildStoredWalletRegistrationPreparedContext,
  buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch,
  buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch,
  buildStoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch,
  findStoredWalletRegistrationEvmFamilyEcdsaBranch,
  findStoredWalletRegistrationNearEd25519YaoBranch,
  replaceStoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch,
  type StoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationPreparedContext,
  type StoredRegistrationAuthority,
  type StoredRegistrationIntent,
  type StoredWalletRegistrationCeremony,
} from '../../core/RegistrationCeremonyStore';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1WalletEcdsaSignerRecords,
  buildD1WalletRecord,
  normalizeThresholdEcdsaChainTargets,
  parseD1RegistrationIntent,
  parseD1RegistrationAuthority,
  parseD1RuntimePolicyScope,
  parseD1StoredRegistrationIntent,
  parseD1StoredWalletRegistrationCeremony,
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
import { alphabetizeStringify, bytesToUnprefixedHex, sha256BytesUtf8 } from '@shared/utils/digests';
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
  walletAuthAuthorityRef,
  walletAuthAuthoritiesMatch,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  buildRouterAbEd25519YaoProductAdmissionRequestV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
} from '../routerAbEd25519YaoProductRegistration';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import {
  buildRouterAbEd25519YaoRegistrationCapabilityRecordV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
} from '../routerAbEd25519YaoRecovery';
import type {
  RouterAbEd25519YaoBudgetRefreshRequestV1,
  RouterAbEd25519YaoBudgetRefreshResponseV1,
  RouterAbEd25519YaoEmailOtpSessionRequestV1,
  RouterAbEd25519YaoEmailOtpSessionResponseV1,
} from '../routerAbEd25519YaoWalletSession';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
  implicitNearAccountIdFromEd25519PublicKeyBytes,
} from './d1Ed25519YaoWalletSigner';
import {
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  parseRouterAbEd25519YaoRegistrationSideEffectRecordV1,
  throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  type RouterAbEd25519YaoRegistrationSideEffectStoreV1,
} from '../routerAbEd25519YaoRegistrationSideEffectBoundary';

type StartWalletRegistrationInput = WalletRegistrationStartRequest;
type RespondWalletRegistrationDerivationInput = WalletRegistrationEcdsaDerivationRespondRequest;
type PrepareWalletRegistrationEcdsaActivationInput =
  WalletRegistrationEcdsaActivationPrepareRequest;
type ActivateWalletRegistrationEcdsaInput = WalletRegistrationEcdsaActivationRequest;
type QueryWalletRegistrationEcdsaActivationInput = WalletRegistrationEcdsaActivationQueryRequest;
type FinalizeWalletRegistrationInput = WalletRegistrationFinalizeRequest;

const WALLET_REGISTRATION_START_RESUME_AFTER_MS = 30_000;

function requireReusableWalletSessionPrincipalId(value: string): PrincipalId {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok) {
    throw new Error(`Reusable Wallet Session principal is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

function requireReusableWalletSessionMintId(value: string): ReusableWalletSessionMintId {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) {
    throw new Error(`Reusable Wallet Session mint identity is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

function reusableWalletSessionPrincipalId(authority: WalletAuthAuthority): PrincipalId {
  return requireReusableWalletSessionPrincipalId(
    isEmailOtpWalletAuthAuthority(authority)
      ? String(authority.factor.providerUserId)
      : String(authority.walletId),
  );
}

async function walletRegistrationFinalizeRequestFingerprint(
  request: FinalizeWalletRegistrationInput,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(request)));
}

export type D1WalletRegistrationFinalizePreparedV1 = {
  readonly kind: 'd1_wallet_registration_finalize_prepared_v1';
};

export type D1WalletRegistrationFinalizeSideEffectStore =
  RouterAbEd25519YaoRegistrationSideEffectStoreV1<
    WalletRegistrationFinalizeResponse,
    D1WalletRegistrationFinalizePreparedV1
  >;

export type D1WalletRegistrationFinalizeSideEffectRecord =
  RouterAbEd25519YaoRegistrationSideEffectRecordV1<
    WalletRegistrationFinalizeResponse,
    D1WalletRegistrationFinalizePreparedV1
  >;

export type D1WalletRegistrationStartPreparedV1 = {
  readonly kind: 'd1_wallet_registration_start_prepared_v1';
  readonly registrationCeremonyId: string;
  readonly registrationPreparationId: string;
  readonly expiresAtMs: number;
  readonly storedIntent: StoredRegistrationIntent;
  readonly authority: StoredRegistrationAuthority;
};

export type D1WalletRegistrationStartTerminalV1 =
  | {
      readonly kind: 'd1_wallet_registration_start_succeeded_v1';
      readonly ceremony: StoredWalletRegistrationCeremony;
      readonly response: Extract<WalletRegistrationStartResponse, { readonly ok: true }>;
    }
  | {
      readonly kind: 'd1_wallet_registration_start_rejected_v1';
      readonly response: Extract<WalletRegistrationStartResponse, { readonly ok: false }>;
    };

export type D1WalletRegistrationStartSideEffectStore =
  RouterAbEd25519YaoRegistrationSideEffectStoreV1<
    D1WalletRegistrationStartTerminalV1,
    D1WalletRegistrationStartPreparedV1
  >;

export type D1WalletRegistrationStartSideEffectRecord =
  RouterAbEd25519YaoRegistrationSideEffectRecordV1<
    D1WalletRegistrationStartTerminalV1,
    D1WalletRegistrationStartPreparedV1
  >;

function recordValue(value: unknown): Record<string, unknown> | null {
  return isPlainObject(value) ? value : null;
}

function parseWalletRegistrationStartDiagnostics(
  raw: unknown,
): WalletRegistrationRouteDiagnostics | null {
  const record = recordValue(raw);
  if (
    !record ||
    record.kind !== 'wallet_registration_route_diagnostics_v1' ||
    record.route !== 'wallets_register_start' ||
    !Array.isArray(record.entries) ||
    record.entries.length !== 1
  ) {
    return null;
  }
  const entry = recordValue(record.entries[0]);
  if (
    !entry ||
    entry.name !== 'registerStartTotalMs' ||
    typeof entry.durationMs !== 'number' ||
    !Number.isSafeInteger(entry.durationMs) ||
    entry.durationMs < 0
  ) {
    return null;
  }
  return {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: 'wallets_register_start',
    entries: [{ name: 'registerStartTotalMs', durationMs: entry.durationMs }],
  };
}

function walletRegistrationStartResponseFromCeremony(
  ceremony: StoredWalletRegistrationCeremony,
  diagnostics?: WalletRegistrationRouteDiagnostics,
): Extract<WalletRegistrationStartResponse, { readonly ok: true }> | null {
  if (ceremony.signerState.kind !== 'signer_set_registration') return null;
  const nearBranch = findStoredWalletRegistrationNearEd25519YaoBranch(ceremony.signerState);
  const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
  if (ecdsaBranch && ecdsaBranch.kind !== 'evm_family_ecdsa_prepared') return null;
  const base = {
    ok: true as const,
    registrationCeremonyId: ceremony.registrationCeremonyId,
    intent: ceremony.intent,
    ...(diagnostics ? { registrationDiagnostics: diagnostics } : {}),
  };
  const ed25519 = nearBranch
    ? {
        admissionRequest: nearBranch.admissionRequest,
        admissionReceipt: nearBranch.admissionReceipt,
      }
    : null;
  const ecdsa = ecdsaBranch
    ? {
        kind: ecdsaBranch.derivationKind,
        chainTargets: ecdsaBranch.chainTargets,
        prepare: ecdsaBranch.prepare,
        strictRegistration: ecdsaBranch.strictRegistration,
      }
    : null;
  if (ed25519 && ecdsa) {
    return { ...base, kind: 'near_ed25519_and_evm_family_ecdsa', ed25519, ecdsa };
  }
  if (ed25519) return { ...base, kind: 'near_ed25519', ed25519 };
  if (ecdsa) return { ...base, kind: 'evm_family_ecdsa', ecdsa };
  return null;
}

function parseWalletRegistrationStartPrepared(
  raw: unknown,
): D1WalletRegistrationStartPreparedV1 | null {
  const record = recordValue(raw);
  if (!record || record.kind !== 'd1_wallet_registration_start_prepared_v1') return null;
  const registrationCeremonyId = toOptionalTrimmedString(record.registrationCeremonyId);
  const registrationPreparationId = toOptionalTrimmedString(record.registrationPreparationId);
  const expiresAtMs = record.expiresAtMs;
  const storedIntent = parseD1StoredRegistrationIntent(record.storedIntent);
  const authority = parseD1RegistrationAuthority(record.authority);
  if (
    !registrationCeremonyId ||
    !registrationPreparationId ||
    typeof expiresAtMs !== 'number' ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0 ||
    !storedIntent ||
    !authority
  ) {
    return null;
  }
  return {
    kind: 'd1_wallet_registration_start_prepared_v1',
    registrationCeremonyId,
    registrationPreparationId,
    expiresAtMs,
    storedIntent,
    authority,
  };
}

function parseWalletRegistrationStartTerminal(
  raw: unknown,
): D1WalletRegistrationStartTerminalV1 | null {
  const record = recordValue(raw);
  if (!record) return null;
  if (record.kind === 'd1_wallet_registration_start_rejected_v1') {
    const response = recordValue(record.response);
    const code = toOptionalTrimmedString(response?.code);
    const message = toOptionalTrimmedString(response?.message);
    return response?.ok === false && code && message
      ? {
          kind: 'd1_wallet_registration_start_rejected_v1',
          response: { ok: false, code, message },
        }
      : null;
  }
  if (record.kind !== 'd1_wallet_registration_start_succeeded_v1') return null;
  const ceremony = parseD1StoredWalletRegistrationCeremony(record.ceremony);
  const response = recordValue(record.response);
  const diagnostics = parseWalletRegistrationStartDiagnostics(response?.registrationDiagnostics);
  if (!ceremony || !response || response.ok !== true || !diagnostics) return null;
  const parsedResponse = walletRegistrationStartResponseFromCeremony(ceremony, diagnostics);
  if (!parsedResponse || alphabetizeStringify(parsedResponse) !== alphabetizeStringify(response)) {
    return null;
  }
  return {
    kind: 'd1_wallet_registration_start_succeeded_v1',
    ceremony,
    response: parsedResponse,
  };
}

export function parseD1WalletRegistrationStartSideEffectRecord(
  raw: unknown,
): D1WalletRegistrationStartSideEffectRecord | null {
  return parseRouterAbEd25519YaoRegistrationSideEffectRecordV1(raw, {
    operation: 'registration_start',
    parsePrepared: parseWalletRegistrationStartPrepared,
    parseResponse: parseWalletRegistrationStartTerminal,
  });
}

async function walletRegistrationStartFingerprint(input: {
  readonly request: StartWalletRegistrationInput;
  readonly userAgent?: string;
}): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input)));
}

async function walletRegistrationStartStableToken(grant: string, domain: string): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(`${domain}\u0000${grant}`));
}

async function buildD1WalletRegistrationStartPrepared(input: {
  readonly storedIntent: StoredRegistrationIntent;
  readonly authority: StoredRegistrationAuthority;
}): Promise<D1WalletRegistrationStartPreparedV1> {
  return {
    kind: 'd1_wallet_registration_start_prepared_v1',
    registrationCeremonyId: `wrc_${await walletRegistrationStartStableToken(
      input.storedIntent.grant,
      'wallet-registration-ceremony-v1',
    )}`,
    registrationPreparationId: `regprep_${await walletRegistrationStartStableToken(
      input.storedIntent.grant,
      'wallet-registration-preparation-v1',
    )}`,
    expiresAtMs: Math.min(input.storedIntent.expiresAtMs, Date.now() + 10 * 60_000),
    storedIntent: input.storedIntent,
    authority: input.authority,
  };
}

async function returnD1WalletRegistrationStartPrepared(
  prepared: D1WalletRegistrationStartPreparedV1,
): Promise<D1WalletRegistrationStartPreparedV1> {
  return prepared;
}

async function fingerprintD1WalletRegistrationStartPrepared(
  prepared: D1WalletRegistrationStartPreparedV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(prepared)));
}

async function rejectUnexpectedWalletRegistrationStartPreparation(): Promise<never> {
  throw new Error('persisted registration start claim disappeared during reconciliation');
}

function rejectedWalletRegistrationStartTerminal(
  code: string,
  message: string,
): D1WalletRegistrationStartTerminalV1 {
  return {
    kind: 'd1_wallet_registration_start_rejected_v1',
    response: { ok: false, code, message },
  };
}

function rejectedWalletRegistrationStartResult(input: {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
}): D1WalletRegistrationStartTerminalV1 {
  return rejectedWalletRegistrationStartTerminal(input.code, input.message);
}

function successfulWalletRegistrationStartTerminal(input: {
  readonly ceremony: StoredWalletRegistrationCeremony;
  readonly timing: D1RegistrationRouteTimingRecorder;
  readonly total: D1RegistrationRouteTimingMark;
}): D1WalletRegistrationStartTerminalV1 {
  const response = walletRegistrationStartResponseFromCeremony(input.ceremony);
  if (!response) throw new Error('registration start ceremony cannot produce a start response');
  finishD1RegistrationRouteTiming(input.timing, input.total);
  const diagnosed = withD1RegistrationStartDiagnostics(response, input.timing);
  if (!diagnosed.ok) throw new Error('registration start success diagnostics are invalid');
  return {
    kind: 'd1_wallet_registration_start_succeeded_v1',
    ceremony: input.ceremony,
    response: diagnosed,
  };
}

function assertNeverWalletRegistrationStartRun(value: never): never {
  throw new Error(`Unhandled wallet registration start result: ${String(value)}`);
}

async function prepareD1WalletRegistrationFinalize(): Promise<D1WalletRegistrationFinalizePreparedV1> {
  return { kind: 'd1_wallet_registration_finalize_prepared_v1' };
}

async function fingerprintD1WalletRegistrationFinalizePrepared(
  prepared: D1WalletRegistrationFinalizePreparedV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(prepared)));
}

const D1_WALLET_REGISTRATION_FINALIZE_RESUME_AFTER_MS = 30_000;

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
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: RuntimePolicyScope;
};

function assertNeverD1RegistrationEd25519SigningBudgetPlan(value: never): never {
  throw new Error(`Unexpected registration signing-budget plan: ${String(value)}`);
}

function assertNeverD1RegistrationEcdsaFinalizeState(value: never): never {
  throw new Error(`Unexpected registration ECDSA finalize state: ${String(value)}`);
}

function registrationReusableWalletSessionTerms(input: {
  readonly signingBudget: D1RegistrationEd25519SigningBudgetPlan;
  readonly issuedAtMs: number;
}): { readonly expiresAtMs: number; readonly remainingUses: number } {
  switch (input.signingBudget.kind) {
    case 'generated_registration_signing_budget':
      return {
        expiresAtMs: input.issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
        remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
      };
    case 'shared_registration_signing_budget':
      return {
        expiresAtMs: input.signingBudget.budget.expiresAtMs,
        remainingUses: input.signingBudget.budget.remainingUses,
      };
    default:
      return assertNeverD1RegistrationEd25519SigningBudgetPlan(input.signingBudget);
  }
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
        walletSessionId: input.identity.walletSessionId,
        quotaId: input.identity.quotaId,
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
        walletSessionId: input.identity.walletSessionId,
        quotaId: input.identity.quotaId,
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

type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore;
type RouterAbNormalSigningRuntimeProvider = () => RouterAbNormalSigningRuntime | null;
type WalletStoreProvider = () => D1WalletStore;
type Ed25519YaoProductRegistrationProvider =
  () => RouterAbEd25519YaoProductRegistrationRuntimeV1 | null;
export type SponsoredNamedNearAccountCreationResult =
  | {
      readonly kind: 'created';
      readonly accountId: string;
      readonly transactionHash: string;
    }
  | {
      readonly kind: 'rejected';
      readonly message: string;
    }
  | {
      readonly kind: 'retryable';
      readonly message: string;
      readonly retryAfterMs: number;
    };
type SponsoredNamedNearAccountCreator = (input: {
  readonly accountId: string;
  readonly publicKey: string;
  /**
   * Registration-scoped key. The provisioning boundary persists the signed
   * transaction under this key before broadcasting, so a retry replays those
   * exact bytes instead of building a second transaction.
   */
  readonly idempotencyKey: string;
}) => Promise<SponsoredNamedNearAccountCreationResult>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function publicDigest32Matches(
  left: RouterAbPublicDigest32V1Wire,
  right: RouterAbPublicDigest32V1Wire,
): boolean {
  return (
    left.bytes.length === 32 &&
    right.bytes.length === 32 &&
    left.bytes.every((value, index) => value === right.bytes[index])
  );
}

function assertNeverSponsoredNamedNearAccountCreationResult(value: never): never {
  throw new Error(`Unexpected sponsored NEAR account creation result: ${String(value)}`);
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

/**
 * A mixed plan finalizes in two calls: `evm_family_ecdsa` first, which returns
 * the wallet ECDSA-ready and leaves the ceremony open, then `near_ed25519`
 * once the Yao ceremony settles (Refactor 94 Phase 4+5). Single-signer plans
 * still finalize in one call.
 *
 * The requested kind must name only branches the plan admitted, and must be
 * legal for the progress those branches have made — a `near_ed25519` call on a
 * mixed plan before the ECDSA commit is durable would return a NEAR-ready
 * wallet whose ECDSA signer does not exist.
 */
function finalizeSignerWorkSequenceFailure(input: {
  readonly request: FinalizeWalletRegistrationInput;
  readonly hasNearEd25519: boolean;
  readonly hasEvmFamilyEcdsa: boolean;
  readonly ecdsaFinalized: boolean;
}): { readonly code: 'invalid_body' | 'invalid_state'; readonly message: string } | null {
  switch (input.request.kind) {
    case 'near_ed25519':
      if (!input.hasNearEd25519) {
        return {
          code: 'invalid_body',
          message: 'registration plan has no Ed25519 signer to finalize',
        };
      }
      if (input.hasEvmFamilyEcdsa && !input.ecdsaFinalized) {
        return {
          code: 'invalid_state',
          message: 'ECDSA finalize must complete before the Ed25519 finalize',
        };
      }
      return null;
    case 'evm_family_ecdsa':
      if (!input.hasEvmFamilyEcdsa) {
        return {
          code: 'invalid_body',
          message: 'registration plan has no ECDSA signer to finalize',
        };
      }
      if (input.ecdsaFinalized) {
        return {
          code: 'invalid_state',
          message: 'ECDSA finalize has already completed for this ceremony',
        };
      }
      return null;
  }
}

function finalizePasskeyRpId(authority: StoredRegistrationAuthority): string {
  if (authority.kind !== 'passkey') {
    throw new Error('passkey finalize auth method requires a passkey registration authority');
  }
  return authority.rpId;
}

export function ecdsaStrictRegistrationAuthority(facts: RouterAbEcdsaRegistrationRequestFactsV1): {
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

export function exactEcdsaParticipantPair(participantIds: readonly number[]): readonly [1, 2] {
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
  readonly strictRegistration: StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch['strictRegistration'];
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
  const ethereumAddress = ethereumAddressHexFromBase64Url(identity.ethereum_address20_b64u);
  const publicIdentity = parseEcdsaDerivationPublicIdentity({
    derivationClientSharePublicKey33B64u: input.publicFacts.derivationClientSharePublicKey33B64u,
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
    activationEpoch: input.activation.ecdsa_activation.activation_epoch,
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

function postRegistrationProofMatchesRequest(input: EcdsaPostRegistrationProofInput): boolean {
  const response = postRegistrationProofResponse(input);
  return (
    response.lifecycle.lifecycle_id === input.request.lifecycle.lifecycle_id &&
    response.bundles.signerA.transcriptDigestB64u === response.bundles.signerB.transcriptDigestB64u
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

function buildPostRegistrationEcdsaNormalSigningState(input: {
  readonly walletKey: WalletRegistrationEcdsaWalletKey;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const capability = input.publicCapability;
  const state = parseRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: input.walletKey.walletId,
      ecdsa_threshold_key_id: input.walletKey.ecdsaThresholdKeyId,
      signing_root_id: input.walletKey.signingRootId,
      signing_root_version: input.walletKey.signingRootVersion,
      context: capability.context,
      public_identity: capability.public_identity,
      signing_worker: capability.signer_set.selected_server,
      activation_epoch: capability.activation_epoch,
    },
  });
  if (!state) {
    throw new Error('registered ECDSA normal-signing state is invalid');
  }
  return state;
}

/**
 * Upper bound on Router metrics folded into one Gateway header. The Router is
 * ours, but a merged header grows at every hop, so the fold is bounded rather
 * than trusting the peer to stay terse.
 */
const ROUTER_SERVER_TIMING_MERGE_LIMIT = 32;

/** Metric names the Gateway is willing to re-emit in its own header. */
const ROUTER_SERVER_TIMING_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Folds the Router's own `Server-Timing` header into the Gateway's span list
 * (Refactor 94B Phase 0), so the Router and role-worker breakdown reaches the
 * browser on the same header as the Gateway's own boundaries.
 *
 * Entries without a finite non-negative `dur` are dropped, which also discards
 * Cloudflare's descriptive metrics, and names are restricted to a token
 * charset so a metric name can never forge extra entries downstream.
 */
export function mergeRouterServerTiming(
  target: Array<readonly [string, number]>,
  header: string,
): void {
  let merged = 0;
  for (const entry of header.split(',')) {
    if (merged >= ROUTER_SERVER_TIMING_MERGE_LIMIT) return;
    const parts = entry.split(';');
    const name = String(parts[0] || '').trim();
    if (!ROUTER_SERVER_TIMING_NAME_PATTERN.test(name)) continue;
    for (const part of parts.slice(1)) {
      const [key, rawValue] = part.split('=');
      if (String(key || '').trim() !== 'dur') continue;
      const duration = Number(String(rawValue || '').trim());
      if (!Number.isFinite(duration) || duration < 0) break;
      target.push([name, duration]);
      merged += 1;
      break;
    }
  }
}

export class CloudflareD1WalletRegistrationService {
  private readonly authorizationService: AuthorizationService;
  private readonly authorizationTenantId: TenantId;
  private readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
  private readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
  private readonly getRouterAbNormalSigningRuntime: RouterAbNormalSigningRuntimeProvider;
  private readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly startSideEffects: D1WalletRegistrationStartSideEffectStore;
  private readonly finalizeSideEffects: D1WalletRegistrationFinalizeSideEffectStore;
  private readonly walletRegistrationCommitStore: D1WalletRegistrationCommitStore;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly authorizationService: AuthorizationService;
    readonly authorizationTenantId: TenantId;
    readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
    readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getEd25519YaoProductRegistration: Ed25519YaoProductRegistrationProvider;
    readonly getRouterAbNormalSigningRuntime: RouterAbNormalSigningRuntimeProvider;
    readonly ecdsaStrictRegistration: RouterAbEcdsaStrictRegistrationPort;
    readonly getWalletStore: WalletStoreProvider;
    readonly startSideEffects: D1WalletRegistrationStartSideEffectStore;
    readonly finalizeSideEffects: D1WalletRegistrationFinalizeSideEffectStore;
    readonly walletRegistrationCommitStore: D1WalletRegistrationCommitStore;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.authorizationService = input.authorizationService;
    this.authorizationTenantId = input.authorizationTenantId;
    this.createSponsoredNamedNearAccount = input.createSponsoredNamedNearAccount;
    this.emailOtpRegistrationEnrollmentFinalizer = input.emailOtpRegistrationEnrollmentFinalizer;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getEd25519YaoProductRegistration = input.getEd25519YaoProductRegistration;
    this.getRouterAbNormalSigningRuntime = input.getRouterAbNormalSigningRuntime;
    this.ecdsaStrictRegistration = input.ecdsaStrictRegistration;
    this.getWalletStore = input.getWalletStore;
    this.startSideEffects = input.startSideEffects;
    this.finalizeSideEffects = input.finalizeSideEffects;
    this.walletRegistrationCommitStore = input.walletRegistrationCommitStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async getWalletRegistrationRuntimePolicyScope(
    registrationCeremonyId: string,
  ): Promise<RuntimePolicyScope | undefined> {
    const store = this.getRegistrationCeremonyIntentStore();
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
    { readonly ok: true } | { readonly ok: false; readonly code: string; readonly message: string }
  > {
    try {
      const nowMs = Date.now();
      if (input.request.expires_at_ms <= nowMs || !postRegistrationProofMatchesRequest(input)) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA post-registration proof does not match its admitted request',
        };
      }
      const walletId = walletIdFromString(input.request.lifecycle.account_id);
      if (input.request.client_id !== walletId || input.request.lifecycle.root_share_epoch === '') {
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
      const normalSigning = buildPostRegistrationEcdsaNormalSigningState({
        walletKey,
        publicCapability: input.public_capability,
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
      const provisioned = await normalSigningRuntime.provisionRouterAbEcdsaNormalSigningSession({
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
        case 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1':
          if (!isPasskeyWalletAuthAuthority(authority)) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'Ed25519 Yao passkey budget refresh requires passkey authority',
            };
          }
          break;
        case 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1': {
          if (!isPasskeyWalletAuthAuthority(authority)) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'Ed25519 Yao passkey app-session refresh requires passkey authority',
            };
          }
          const expectedAuthorityRef = await walletAuthAuthorityRef({ authority });
          if (
            authorization.authorityRef.walletId !== expectedAuthorityRef.walletId ||
            authorization.authorityRef.authorityDigest !== expectedAuthorityRef.authorityDigest ||
            alphabetizeStringify(authorization.runtimePolicyScope) !==
              alphabetizeStringify(runtimePolicyScope)
          ) {
            return {
              ok: false,
              code: 'scope_mismatch',
              message: 'Ed25519 Yao passkey app-session authorization is out of scope',
            };
          }
          return {
            ok: false,
            code: 'explicit_unlock_required',
            message: 'A signed app session cannot mint a reusable Wallet Session',
          };
        }
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
        authorization.kind === 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1'
          ? await this.walletAuthMethods.verifyActiveEmailOtpAuthority(authorization.authority)
          : await this.walletAuthMethods.verifyActivePasskeyAuthority(authorization.authority);
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
      const issuedAtMs = refreshed.expiresAtMs - policy.ttlMs;
      const reusableWalletSession = await this.authorizationService.issueReusableWalletSession({
        tenantId: this.authorizationTenantId,
        principalId: reusableWalletSessionPrincipalId(authority),
        walletId: authority.walletId,
        authority: await walletAuthAuthorityRef({ authority }),
        mintId: requireReusableWalletSessionMintId(authorization.verifiedChallengeId),
        remainingUses: refreshed.remainingUses,
        issuedAtMs,
        expiresAtMs: refreshed.expiresAtMs,
      });
      const minted = await yaoRuntime.mintWalletSession({
        kind: 'same_identity_budget_refresh_v1',
        walletId: authority.walletId,
        nearAccountId: policy.nearAccountId,
        nearEd25519SigningKeyId: policy.nearEd25519SigningKeyId,
        authority,
        thresholdSessionId: refreshed.thresholdSessionId,
        walletSessionId: reusableWalletSession.session.walletSessionId,
        quotaId: reusableWalletSession.quota.quotaId,
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
        walletSessionId: session.walletSessionId,
        quotaId: session.quotaId,
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
    request: RouterAbEd25519YaoEmailOtpSessionRequestV1,
  ): Promise<RouterAbEd25519YaoEmailOtpSessionResponseV1> {
    return await this.provisionEd25519YaoEmailOtpWalletSession(request);
  }

  private async provisionEd25519YaoEmailOtpWalletSession(
    request: RouterAbEd25519YaoEmailOtpSessionRequestV1,
  ): Promise<RouterAbEd25519YaoEmailOtpSessionResponseV1> {
    try {
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId);
      const providerUserId = toOptionalTrimmedString(request.verifiedProviderUserId);
      const verifiedChallengeId = toOptionalTrimmedString(request.verifiedChallengeId);
      const signerSlot = Math.floor(Number(request.signerSlot));
      const remainingUses = Math.floor(Number(request.remainingUses));
      if (
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
          message: 'Email OTP Ed25519 Wallet Session request is invalid',
        };
      }
      const yaoRuntime = this.getEd25519YaoProductRegistration();
      const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
      if (!yaoRuntime || !normalSigningRuntime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Email OTP Ed25519 Wallet Session provisioning is not configured',
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
          message: 'Registered Ed25519 Yao signer is unavailable for Email OTP unlock',
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
      const issuedAtMs = Date.now();
      const reusableRemainingUses = Math.min(
        DEFAULT_WALLET_SESSION_REMAINING_USES,
        remainingUses,
      );
      const expiresAtMs = issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
      const reusableWalletSession = await this.authorizationService.issueReusableWalletSession({
        tenantId: this.authorizationTenantId,
        principalId: reusableWalletSessionPrincipalId(authority),
        walletId: walletIdFromString(walletId),
        authority: await walletAuthAuthorityRef({ authority }),
        mintId: requireReusableWalletSessionMintId(verifiedChallengeId),
        remainingUses: reusableRemainingUses,
        issuedAtMs,
        expiresAtMs,
      });
      const minted = await yaoRuntime.mintWalletSession({
        kind: 'shared_email_otp_recovery_wallet_session_v1',
        walletId: walletIdFromString(walletId),
        nearAccountId: signer.nearAccountId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        authority,
        thresholdSessionId: descriptor.lifecycle.walletSessionId,
        walletSessionId: reusableWalletSession.session.walletSessionId,
        quotaId: reusableWalletSession.quota.quotaId,
        participantIds,
        runtimePolicyScope: signer.runtimePolicyScope,
        expiresAtMs,
        remainingUses: reusableRemainingUses,
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
        message: errorMessage(error) || 'Email OTP Ed25519 Wallet Session provisioning failed',
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
      const requestIntent = parseD1RegistrationIntent(request.intent);
      if (!requestIntent) {
        return { ok: false, code: 'invalid_body', message: 'registration intent is invalid' };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      const requestDigest = await computeRegistrationIntentDigestB64u(requestIntent);
      if (!digestB64u || digestB64u !== requestDigest) {
        return { ok: false, code: 'invalid_body', message: 'registration intent digest mismatch' };
      }
      const requestFingerprint = await walletRegistrationStartFingerprint({
        request,
        ...(context?.userAgent ? { userAgent: context.userAgent } : {}),
      });
      const startKey = `registration:${await walletRegistrationStartStableToken(
        grant,
        'wallet-registration-start-claim-v1',
      )}`;
      const existing = await this.startSideEffects.read(startKey);
      let prepared: D1WalletRegistrationStartPreparedV1 | null = null;
      if (existing.kind === 'missing') {
        const preview = await store.getIntent(grant);
        if (!preview) {
          return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
        }
        if (digestB64u !== preview.digestB64u) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration intent digest mismatch',
          };
        }
        if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: preview.intent })) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration intent walletId mismatch',
          };
        }
        if (!request.authority) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration authority is required',
          };
        }
        const expectedOrigin = toOptionalTrimmedString(preview.expectedOrigin);
        const verifiedAuthority = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent(
          {
            orgId: preview.orgId,
            authority: request.authority,
            expectedDigestB64u: preview.digestB64u,
            expectedOrigin: expectedOrigin || '',
            intent: preview.intent,
            verificationOperationId: startKey,
            verificationReceiptExpiresAtMs: preview.expiresAtMs,
            userAgent: context?.userAgent,
          },
        );
        if (!verifiedAuthority.ok) return verifiedAuthority;
        prepared = await buildD1WalletRegistrationStartPrepared({
          storedIntent: preview,
          authority: verifiedAuthority.authority,
        });
      }
      const run = await runRouterAbEd25519YaoRegistrationSideEffectV1(this.startSideEffects, {
        kind: 'prepared_resumable',
        operation: 'registration_start',
        key: startKey,
        requestFingerprint,
        resumeAfterMs: WALLET_REGISTRATION_START_RESUME_AFTER_MS,
        nowMs: Date.now,
        prepare: prepared
          ? returnD1WalletRegistrationStartPrepared.bind(null, prepared)
          : rejectUnexpectedWalletRegistrationStartPreparation,
        derivePreparedArtifactFingerprint: fingerprintD1WalletRegistrationStartPrepared,
        execute: this.executeWalletRegistrationStartSideEffect.bind(this, {
          request,
          store,
          timing,
          total,
        }),
      });
      switch (run.kind) {
        case 'executed':
        case 'exact_replay':
          return run.value.response;
        case 'request_conflict':
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'registration intent grant belongs to a different start request',
          };
        case 'in_progress':
          return {
            ok: false,
            code: 'conflict',
            message: 'registration start is already in progress; retry later',
          };
        case 'uncertain':
          return {
            ok: false,
            code: 'internal',
            message: run.message || 'Failed to reconcile wallet registration start',
          };
        default:
          return assertNeverWalletRegistrationStartRun(run);
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet registration ceremony',
      };
    }
  }

  private async executeWalletRegistrationStartSideEffect(
    input: {
      readonly request: StartWalletRegistrationInput;
      readonly store: CloudflareD1RegistrationCeremonyIntentStore;
      readonly timing: D1RegistrationRouteTimingRecorder;
      readonly total: D1RegistrationRouteTimingMark;
    },
    prepared: D1WalletRegistrationStartPreparedV1,
    attempt: 'fresh' | 'resumed',
  ): Promise<D1WalletRegistrationStartTerminalV1> {
    const terminal = await this.executeWalletRegistrationStart(input, prepared, attempt);
    if (terminal.kind === 'd1_wallet_registration_start_rejected_v1') {
      throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(terminal.response);
    }
    return terminal;
  }

  private async executeWalletRegistrationStart(
    input: {
      readonly request: StartWalletRegistrationInput;
      readonly store: CloudflareD1RegistrationCeremonyIntentStore;
      readonly timing: D1RegistrationRouteTimingRecorder;
      readonly total: D1RegistrationRouteTimingMark;
    },
    prepared: D1WalletRegistrationStartPreparedV1,
    attempt: 'fresh' | 'resumed',
  ): Promise<D1WalletRegistrationStartTerminalV1> {
    const existingCeremony = await input.store.getCeremony(prepared.registrationCeremonyId);
    if (existingCeremony) {
      if (
        existingCeremony.digestB64u !== prepared.storedIntent.digestB64u ||
        alphabetizeStringify(existingCeremony.intent) !==
          alphabetizeStringify(prepared.storedIntent.intent)
      ) {
        throw new Error('registration start ceremony conflicts with its durable claim');
      }
      return successfulWalletRegistrationStartTerminal({
        ceremony: existingCeremony,
        timing: input.timing,
        total: input.total,
      });
    }
    const requestIntent = parseD1RegistrationIntent(input.request.intent);
    if (!requestIntent) {
      return rejectedWalletRegistrationStartTerminal(
        'invalid_body',
        'registration intent is invalid',
      );
    }
    if (input.request.registrationIntentDigestB64u !== prepared.storedIntent.digestB64u) {
      return rejectedWalletRegistrationStartTerminal(
        'invalid_body',
        'registration intent digest mismatch',
      );
    }
    if (
      !registrationIntentWalletsMatch({
        requestIntent,
        storedIntent: prepared.storedIntent.intent,
      })
    ) {
      return rejectedWalletRegistrationStartTerminal(
        'invalid_body',
        'registration intent walletId mismatch',
      );
    }
    const branches = registrationIntentSignerBranches(prepared.storedIntent.intent);
    if (!branches.ok) return rejectedWalletRegistrationStartResult(branches);
    const nearEd25519Branch = branches.value.nearEd25519;
    const ecdsaBranch = branches.value.evmFamilyEcdsa;
    if (!nearEd25519Branch && !ecdsaBranch) {
      return rejectedWalletRegistrationStartTerminal(
        'invalid_body',
        'registration signer branch is required',
      );
    }
    const expectedOrigin = toOptionalTrimmedString(prepared.storedIntent.expectedOrigin);
    const runtimePolicyScope = parseD1RuntimePolicyScope(
      prepared.storedIntent.intent.runtimePolicyScope,
    );
    const signingRootId =
      prepared.storedIntent.signingRootId ||
      (runtimePolicyScope ? deriveSigningRootId(runtimePolicyScope) : '');
    const signingRootVersion =
      toOptionalTrimmedString(prepared.storedIntent.signingRootVersion) ||
      runtimePolicyScope?.signingRootVersion ||
      'default';
    if (!signingRootId) {
      return rejectedWalletRegistrationStartTerminal(
        'invalid_body',
        'registration requires a signing root',
      );
    }
    const preparedContext = resolveRegistrationPreparedContextFromPlan({
      signerPlan: branches.value.plan,
      runtimePolicyScope,
      signingRootId,
      signingRootVersion,
    });
    if (!preparedContext.ok) return rejectedWalletRegistrationStartResult(preparedContext);
    const yaoRuntime = nearEd25519Branch ? this.getEd25519YaoProductRegistration() : null;
    if (nearEd25519Branch && !yaoRuntime) {
      return rejectedWalletRegistrationStartTerminal(
        'not_configured',
        'Ed25519 Yao product registration is not configured',
      );
    }
    const consumedIntent = await input.store.takeIntent(prepared.storedIntent.grant);
    if (!consumedIntent && attempt === 'fresh') {
      return rejectedWalletRegistrationStartTerminal(
        'invalid_grant',
        'registration intent grant expired',
      );
    }
    if (
      consumedIntent &&
      alphabetizeStringify(consumedIntent) !== alphabetizeStringify(prepared.storedIntent)
    ) {
      throw new Error('consumed registration intent conflicts with its durable claim');
    }
    const storedIntent = consumedIntent || prepared.storedIntent;
    const storedBranches: StoredWalletRegistrationSignerBranch[] = [];
    if (nearEd25519Branch && yaoRuntime) {
      const admissionRequest = await buildRouterAbEd25519YaoProductAdmissionRequestV1({
        registrationCeremonyId: prepared.registrationCeremonyId,
        walletId: storedIntent.intent.walletId,
        signingRootId,
        signingRootVersion,
        authority: prepared.authority,
        branch: nearEd25519Branch,
        signingWorkerId: yaoRuntime.signingWorkerId,
      });
      const admitted = await yaoRuntime.bindAndAdmitVerifiedRegistration({
        kind: 'verified_registration_intent',
        registrationIntentGrant: storedIntent.grant,
        intent: storedIntent.intent,
        admissionRequest,
        expiresAtMs: prepared.expiresAtMs,
      });
      if (!admitted.ok) return rejectedWalletRegistrationStartResult(admitted);
      storedBranches.push(
        buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch({
          branchKey: nearEd25519Branch.branchKey,
          admissionRequest,
          admissionReceipt: admitted.value,
        }),
      );
    }
    if (ecdsaBranch) {
      if (!runtimePolicyScope) {
        return rejectedWalletRegistrationStartTerminal(
          'invalid_body',
          'ECDSA registration requires an exact runtime policy scope',
        );
      }
      const chainTargets = registrationPreparedContextEcdsaChainTargets(
        preparedContext.preparedContext,
      );
      if (!chainTargets) {
        return rejectedWalletRegistrationStartTerminal(
          'invalid_body',
          'ECDSA chain targets are required',
        );
      }
      const ecdsaPrepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
        registrationPurpose: 'wallet_registration',
        registrationCeremonyId: prepared.registrationCeremonyId,
        registrationPreparationId:
          input.request.registrationPreparationId ||
          registrationPreparationIdFromString(prepared.registrationPreparationId),
        walletId: storedIntent.intent.walletId,
        signingRootId,
        signingRootVersion,
        chainTargets,
        participantIds: [...ecdsaBranch.participantIds],
        strictRegistration: this.ecdsaStrictRegistration,
        runtimePolicyScope,
      });
      if (!ecdsaPrepared.ok) return rejectedWalletRegistrationStartResult(ecdsaPrepared);
      storedBranches.push(
        buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch({
          branchKey: ecdsaBranch.branchKey,
          ecdsa: {
            kind: ecdsaPrepared.ecdsa.kind,
            chainTargets: ecdsaPrepared.ecdsa.chainTargets,
            prepare: ecdsaPrepared.ecdsa.prepare,
            strictRegistration: ecdsaPrepared.ecdsa.strictRegistration,
            strictRegistrationBindingJson:
              routerAbEcdsaStrictRegistrationFactsBindingJson(
                ecdsaPrepared.ecdsa.strictRegistration,
              ),
          },
        }),
      );
    }
    const ceremony: StoredWalletRegistrationCeremony = {
      registrationCeremonyId: prepared.registrationCeremonyId,
      intent: storedIntent.intent,
      digestB64u: storedIntent.digestB64u,
      signerPlan: branches.value.plan,
      preparedContext: preparedContext.preparedContext,
      orgId: storedIntent.orgId,
      signingRootId,
      signingRootVersion,
      ...(expectedOrigin ? { expectedOrigin } : {}),
      expiresAtMs: prepared.expiresAtMs,
      authority: prepared.authority,
      signerState: {
        kind: 'signer_set_registration',
        branches: storedBranches,
      },
    };
    await input.store.putCeremony(ceremony);
    return successfulWalletRegistrationStartTerminal({
      ceremony,
      timing: input.timing,
      total: input.total,
    });
  }

  async respondWalletRegistrationEcdsaDerivation(
    request: RespondWalletRegistrationDerivationInput,
    traceContext?: RouterAbTraceContextV1,
  ): Promise<WalletRegistrationEcdsaDerivationRespondResponse> {
    /* Gateway boundary timings; the route strips these into a Server-Timing
       header, so nothing here reaches the wire body. Fixed names + numeric
       durations only. */
    const serverTiming: Array<readonly [string, number]> = [];
    const totalStartedAtMs = Date.now();
    const markServerTiming = (name: string, startedAtMs: number): void => {
      serverTiming.push([name, Math.max(0, Date.now() - startedAtMs)]);
    };
    const withServerTiming = <T extends { ok: true }>(response: T): T => {
      markServerTiming('ecdsa_respond_total', totalStartedAtMs);
      return { ...response, gatewayServerTiming: serverTiming };
    };
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const strictRegistrationBindingJson =
        routerAbEcdsaStrictRegistrationRequestBindingJson(request.ecdsa.strictRegistration);
      const claimStartedAtMs = Date.now();
      let claimed = await store.claimEcdsaRespond({
        registrationCeremonyId: request.registrationCeremonyId,
        strictRegistrationBindingJson,
        registrationRequest: request.ecdsa.strictRegistration,
      });
      markServerTiming('ecdsa_respond_d1_claim', claimStartedAtMs);
      if (!claimed) {
        const reconcileStartedAtMs = Date.now();
        const existing = await store.getCeremonySnapshot(request.registrationCeremonyId);
        markServerTiming('ecdsa_respond_reconcile', reconcileStartedAtMs);
        if (!existing) {
          return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
        }
        const ceremony = existing.ceremony;
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
        const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
          ceremony.signerState,
        );
        if (ecdsaBranch?.kind === 'evm_family_ecdsa_pending_activation') {
          if (
            alphabetizeStringify(ecdsaBranch.registrationRequest) !==
            alphabetizeStringify(request.ecdsa.strictRegistration)
          ) {
            return {
              ok: false,
              code: 'scope_mismatch',
              message: 'ECDSA registration replay changed the exact request',
            };
          }
          return withServerTiming({
            ok: true,
            registrationCeremonyId: ceremony.registrationCeremonyId,
            ecdsa: {
              kind: 'router_ab_ecdsa_registration_forwarded_v1',
              strictResult: ecdsaBranch.publicResponse,
            },
          } as const);
        }
        if (ecdsaBranch?.kind !== 'evm_family_ecdsa_response_claimed') {
          const bindingMatches =
            ecdsaBranch?.strictRegistrationBindingJson === strictRegistrationBindingJson;
          return {
            ok: false,
            code: bindingMatches ? 'invalid_state' : 'scope_mismatch',
            message: bindingMatches
              ? 'ECDSA registration response is not claimable'
              : 'ECDSA registration request does not match the admitted ceremony facts',
          };
        }
        if (
          alphabetizeStringify(ecdsaBranch.registrationRequest) !==
          alphabetizeStringify(request.ecdsa.strictRegistration)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA registration claim belongs to a different exact request',
          };
        }
        claimed = existing;
      }
      const ceremony = claimed.ceremony;
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        throw new Error('Claimed ECDSA registration ceremony has an invalid signer state');
      }
      const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
        ceremony.signerState,
      );
      if (!ecdsaBranch || ecdsaBranch.kind !== 'evm_family_ecdsa_response_claimed') {
        throw new Error('Claimed ECDSA registration branch is invalid');
      }
      const routerStartedAtMs = Date.now();
      const strictResult = await this.ecdsaStrictRegistration.register({
        request: ecdsaBranch.registrationRequest,
        authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
        traceContext,
        onServerTiming: (header) => mergeRouterServerTiming(serverTiming, header),
        /* Presence only: a fixed metric name, never the header contents. */
        onHeaderPresence: (presence) =>
          serverTiming.push([`ecdsa_role_timing_${presence.serverTiming}`, 1]),
      });
      markServerTiming('ecdsa_respond_router', routerStartedAtMs);
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
          strictRegistrationBindingJson: ecdsaBranch.strictRegistrationBindingJson,
          registrationRequest: ecdsaBranch.registrationRequest,
          pendingActivation: strictResult.value.pendingActivation,
          publicResponse: strictResult.value.publicResponse,
        },
      });
      const commitStartedAtMs = Date.now();
      try {
        await store.commitEcdsaClaim({
          expected: claimed,
          next: {
            ...ceremony,
            signerState: nextSignerState,
          },
        });
      } catch (error: unknown) {
        const reconciled = await store.getCeremony(request.registrationCeremonyId);
        const reconciledBranch =
          reconciled?.signerState.kind === 'signer_set_registration'
            ? findStoredWalletRegistrationEvmFamilyEcdsaBranch(reconciled.signerState)
            : null;
        if (
          reconciledBranch?.kind !== 'evm_family_ecdsa_pending_activation' ||
          alphabetizeStringify(reconciledBranch.registrationRequest) !==
            alphabetizeStringify(ecdsaBranch.registrationRequest) ||
          alphabetizeStringify(reconciledBranch.pendingActivation) !==
            alphabetizeStringify(strictResult.value.pendingActivation) ||
          alphabetizeStringify(reconciledBranch.publicResponse) !==
            alphabetizeStringify(strictResult.value.publicResponse)
        ) {
          throw error;
        }
      } finally {
        markServerTiming('ecdsa_respond_d1_commit', commitStartedAtMs);
      }
      return withServerTiming({
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_forwarded_v1',
          strictResult: strictResult.value.publicResponse,
        },
      } as const);
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
    traceContext?: RouterAbTraceContextV1,
  ): Promise<WalletRegistrationEcdsaActivationResponse> {
    /* Same contract as respondWalletRegistrationEcdsaDerivation: stripped into
       a Server-Timing header at the route, never serialized to the wire. */
    const serverTiming: Array<readonly [string, number]> = [];
    const totalStartedAtMs = Date.now();
    const markServerTiming = (name: string, startedAtMs: number): void => {
      serverTiming.push([name, Math.max(0, Date.now() - startedAtMs)]);
    };
    const withServerTiming = <T extends { ok: true }>(response: T): T => {
      markServerTiming('ecdsa_activate_total', totalStartedAtMs);
      return { ...response, gatewayServerTiming: serverTiming };
    };
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const preflight = await store.getCeremonySnapshot(request.registrationCeremonyId);
      const preflightBranch =
        preflight?.ceremony.signerState.kind === 'signer_set_registration'
          ? findStoredWalletRegistrationEvmFamilyEcdsaBranch(preflight.ceremony.signerState)
          : null;
      if (
        preflightBranch?.kind === 'evm_family_ecdsa_pending_activation' ||
        preflightBranch?.kind === 'evm_family_ecdsa_activation_claimed'
      ) {
        if (
          preflightBranch.kind === 'evm_family_ecdsa_activation_claimed' &&
          (preflightBranch.activation.activation_correlation_id !==
            request.ecdsa.activationCorrelationId ||
            !publicDigest32Matches(
              preflightBranch.activation.activation_request_digest,
              request.ecdsa.expectedActivationRequestDigest,
            ) ||
            alphabetizeStringify(preflightBranch.publicFacts) !==
              alphabetizeStringify(request.ecdsa.publicFacts))
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA activation claim belongs to different verified client facts',
          };
        }
        const preparedActivation = await this.ecdsaStrictRegistration.prepareActivation({
          activationCorrelationId: request.ecdsa.activationCorrelationId,
          pendingActivation: preflightBranch.pendingActivation,
          clientActivation: request.ecdsa.publicFacts,
          authority: ecdsaStrictRegistrationAuthority(preflightBranch.strictRegistration),
        });
        if (!preparedActivation.ok) {
          return {
            ok: false,
            code: preparedActivation.code,
            message: preparedActivation.message,
          };
        }
        if (
          !publicDigest32Matches(
            preparedActivation.value.activation_request_digest,
            request.ecdsa.expectedActivationRequestDigest,
          )
        ) {
          return {
            ok: false,
            code: 'activation_digest_mismatch',
            message: 'ECDSA activation request digest does not match prepared activation',
          };
        }
      }
      const claimStartedAtMs = Date.now();
      let claimed = await store.claimEcdsaActivation({
        registrationCeremonyId: request.registrationCeremonyId,
        publicFacts: request.ecdsa.publicFacts,
        activation: {
          activation_correlation_id: request.ecdsa.activationCorrelationId,
          activation_request_digest: request.ecdsa.expectedActivationRequestDigest,
        },
      });
      markServerTiming('ecdsa_activate_d1_claim', claimStartedAtMs);
      if (!claimed) {
        const reconcileStartedAtMs = Date.now();
        const existing = await store.getCeremonySnapshot(request.registrationCeremonyId);
        markServerTiming('ecdsa_activate_reconcile', reconcileStartedAtMs);
        if (!existing) {
          return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
        }
        const ceremony = existing.ceremony;
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
        const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
          ceremony.signerState,
        );
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
          return withServerTiming({
            ok: true,
            registrationCeremonyId: ceremony.registrationCeremonyId,
            ecdsa: {
              kind: 'router_ab_ecdsa_registration_activated_v1',
              activation: ecdsaBranch.activation,
              bootstrap: ecdsaBranch.bootstrap,
            },
          } as const);
        }
        if (ecdsaBranch?.kind !== 'evm_family_ecdsa_activation_claimed') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA registration activation is not claimable',
          };
        }
        if (
          ecdsaBranch.activation.activation_correlation_id !==
            request.ecdsa.activationCorrelationId ||
          !publicDigest32Matches(
            ecdsaBranch.activation.activation_request_digest,
            request.ecdsa.expectedActivationRequestDigest,
          ) ||
          alphabetizeStringify(ecdsaBranch.publicFacts) !==
            alphabetizeStringify(request.ecdsa.publicFacts)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA activation claim belongs to different verified client facts',
          };
        }
        claimed = existing;
      }
      const ceremony = claimed.ceremony;
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        throw new Error('Claimed ECDSA activation ceremony has an invalid signer state');
      }
      const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
        ceremony.signerState,
      );
      if (!ecdsaBranch || ecdsaBranch.kind !== 'evm_family_ecdsa_activation_claimed') {
        throw new Error('Claimed ECDSA activation branch is invalid');
      }
      const routerStartedAtMs = Date.now();
      const activationInput = {
        activationCorrelationId: request.ecdsa.activationCorrelationId,
        pendingActivation: ecdsaBranch.pendingActivation,
        clientActivation: ecdsaBranch.publicFacts,
        authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
      };
      const activated = await this.ecdsaStrictRegistration.activate({
        ...activationInput,
        expectedActivationRequestDigest: request.ecdsa.expectedActivationRequestDigest,
        traceContext,
        onServerTiming: (header) => mergeRouterServerTiming(serverTiming, header),
        /* Presence only: a fixed metric name, never the header contents. */
        onHeaderPresence: (presence) =>
          serverTiming.push([`ecdsa_role_timing_${presence.serverTiming}`, 1]),
      });
      markServerTiming('ecdsa_activate_router', routerStartedAtMs);
      if (!activated.ok) {
        return {
          ok: false,
          code: activated.code,
          message: activated.message,
        };
      }
      try {
        const bootstrapStartedAtMs = Date.now();
        const bootstrap = await buildActivatedEcdsaFamilyBootstrap({
          branch: ecdsaBranch,
          publicFacts: ecdsaBranch.publicFacts,
          activation: activated.value,
        });
        markServerTiming('ecdsa_activate_bootstrap', bootstrapStartedAtMs);
        const normalSigningRuntime = this.getRouterAbNormalSigningRuntime();
        if (!normalSigningRuntime) {
          throw new Error('Router A/B normal signing is not configured');
        }
        const sessionProvisionStartedAtMs = Date.now();
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
        markServerTiming('ecdsa_activate_session_provision', sessionProvisionStartedAtMs);
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
          strictRegistrationBindingJson: ecdsaBranch.strictRegistrationBindingJson,
          registrationRequest: ecdsaBranch.registrationRequest,
          publicFacts: ecdsaBranch.publicFacts,
          activation: activated.value,
          publicCapability: buildRouterAbEcdsaDerivationPublicCapabilityV1({
            registrationFacts: ecdsaBranch.strictRegistration,
            registrationRequest: ecdsaBranch.registrationRequest,
            clientActivation: ecdsaBranch.publicFacts,
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
            activationEpoch: bootstrap.activationEpoch,
            signingGrantId: bootstrap.signingGrantId,
            expiresAtMs: provisioned.expiresAtMs,
            expiresAt: new Date(provisioned.expiresAtMs).toISOString(),
            remainingUses: provisioned.remainingUses,
            participantIds: [...provisioned.participantIds],
          },
        };
        const commitStartedAtMs = Date.now();
        try {
          await store.commitEcdsaClaim({
            expected: claimed,
            next: {
              ...ceremony,
              signerState: replaceStoredWalletRegistrationSignerBranch({
                state: ceremony.signerState,
                replacement: activatedBranch,
              }),
            },
          });
        } catch (error: unknown) {
          const reconciled = await store.getCeremony(request.registrationCeremonyId);
          const reconciledBranch =
            reconciled?.signerState.kind === 'signer_set_registration'
              ? findStoredWalletRegistrationEvmFamilyEcdsaBranch(reconciled.signerState)
              : null;
          if (
            reconciledBranch?.kind !== 'evm_family_ecdsa_activated' ||
            alphabetizeStringify(reconciledBranch.publicFacts) !==
              alphabetizeStringify(activatedBranch.publicFacts) ||
            alphabetizeStringify(reconciledBranch.activation) !==
              alphabetizeStringify(activatedBranch.activation) ||
            alphabetizeStringify(reconciledBranch.bootstrap) !==
              alphabetizeStringify(activatedBranch.bootstrap)
          ) {
            throw error;
          }
        } finally {
          markServerTiming('ecdsa_activate_d1_commit', commitStartedAtMs);
        }
        return withServerTiming({
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activated_v1',
            activation: activated.value,
            bootstrap: activatedBranch.bootstrap,
          },
        } as const);
      } catch (error: unknown) {
        const message =
          errorMessage(error) || 'ECDSA activation could not establish normal signing';
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

  async prepareWalletRegistrationEcdsaActivation(
    request: PrepareWalletRegistrationEcdsaActivationInput,
  ): Promise<WalletRegistrationEcdsaActivationPrepareResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
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
          ecdsaBranch.activation.activation_correlation_id !==
            request.ecdsa.activationCorrelationId ||
          alphabetizeStringify(ecdsaBranch.publicFacts) !==
            alphabetizeStringify(request.ecdsa.publicFacts)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA activation preparation changed the verified client facts',
          };
        }
        return {
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activation_prepared_v1',
            preparation: {
              activation_correlation_id: ecdsaBranch.activation.activation_correlation_id,
              activation_request_digest: ecdsaBranch.activation.activation_request_digest,
            },
          },
        };
      }
      if (ecdsaBranch?.kind === 'evm_family_ecdsa_activation_claimed') {
        if (
          ecdsaBranch.activation.activation_correlation_id !==
            request.ecdsa.activationCorrelationId ||
          alphabetizeStringify(ecdsaBranch.publicFacts) !==
            alphabetizeStringify(request.ecdsa.publicFacts)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA activation preparation changed the claimed coordinates',
          };
        }
        return {
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activation_prepared_v1',
            preparation: ecdsaBranch.activation,
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
      const prepared = await this.ecdsaStrictRegistration.prepareActivation({
        activationCorrelationId: request.ecdsa.activationCorrelationId,
        pendingActivation: ecdsaBranch.pendingActivation,
        clientActivation: request.ecdsa.publicFacts,
        authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
      });
      if (!prepared.ok) {
        return { ok: false, code: prepared.code, message: prepared.message };
      }
      return {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activation_prepared_v1',
          preparation: prepared.value,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to prepare ECDSA wallet registration activation',
      };
    }
  }

  async queryWalletRegistrationEcdsaActivation(
    request: QueryWalletRegistrationEcdsaActivationInput,
  ): Promise<WalletRegistrationEcdsaActivationQueryResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
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
          ecdsaBranch.activation.activation_correlation_id !==
            request.ecdsa.activationCorrelationId ||
          !publicDigest32Matches(
            ecdsaBranch.activation.activation_request_digest,
            request.ecdsa.expectedActivationRequestDigest,
          ) ||
          alphabetizeStringify(ecdsaBranch.publicFacts) !==
            alphabetizeStringify(request.ecdsa.publicFacts)
        ) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'ECDSA activation query changed the committed activation coordinates',
          };
        }
        return {
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ecdsa: {
            kind: 'router_ab_ecdsa_registration_activation_queried_v1',
            result: {
              kind: 'committed',
              receipt: ecdsaBranch.activation,
            },
          },
        };
      }
      if (
        !ecdsaBranch ||
        (ecdsaBranch.kind !== 'evm_family_ecdsa_pending_activation' &&
          ecdsaBranch.kind !== 'evm_family_ecdsa_activation_claimed')
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'one pending ECDSA family activation is required',
        };
      }
      if (
        ecdsaBranch.kind === 'evm_family_ecdsa_activation_claimed' &&
        (ecdsaBranch.activation.activation_correlation_id !==
          request.ecdsa.activationCorrelationId ||
          !publicDigest32Matches(
            ecdsaBranch.activation.activation_request_digest,
            request.ecdsa.expectedActivationRequestDigest,
          ) ||
          alphabetizeStringify(ecdsaBranch.publicFacts) !==
            alphabetizeStringify(request.ecdsa.publicFacts))
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA activation query changed the claimed activation coordinates',
        };
      }
      const queried = await this.ecdsaStrictRegistration.queryActivation({
        activationCorrelationId: request.ecdsa.activationCorrelationId,
        expectedActivationRequestDigest: request.ecdsa.expectedActivationRequestDigest,
        pendingActivation: ecdsaBranch.pendingActivation,
        clientActivation: request.ecdsa.publicFacts,
        authority: ecdsaStrictRegistrationAuthority(ecdsaBranch.strictRegistration),
      });
      if (!queried.ok) {
        return { ok: false, code: queried.code, message: queried.message };
      }
      return {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activation_queried_v1',
          result: queried.value,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to query ECDSA wallet registration activation',
      };
    }
  }

  async finalizeWalletRegistration(
    request: FinalizeWalletRegistrationInput,
  ): Promise<WalletRegistrationFinalizeResponse> {
    try {
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (!idempotencyKey) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration finalize idempotencyKey is required',
        };
      }

      const requestFingerprint = await walletRegistrationFinalizeRequestFingerprint(request);
      const effectKey = base64UrlEncode(
        await sha256BytesUtf8(
          `wallet-registration-finalize-v1\0${request.registrationCeremonyId}\0${idempotencyKey}`,
        ),
      );
      const outcome = await runRouterAbEd25519YaoRegistrationSideEffectV1(
        this.finalizeSideEffects,
        {
          kind: 'prepared_resumable',
          resumeAfterMs: D1_WALLET_REGISTRATION_FINALIZE_RESUME_AFTER_MS,
          operation: 'finalize',
          key: effectKey,
          requestFingerprint,
          nowMs: Date.now,
          prepare: prepareD1WalletRegistrationFinalize,
          derivePreparedArtifactFingerprint: fingerprintD1WalletRegistrationFinalizePrepared,
          execute: this.executeWalletRegistrationFinalizeSideEffect.bind(this, request),
        },
      );
      switch (outcome.kind) {
        case 'executed':
        case 'exact_replay':
          return outcome.value;
        case 'request_conflict':
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'registration finalize idempotency key was reused for a different request',
          };
        case 'in_progress':
          return {
            ok: false,
            code: 'conflict',
            message: 'registration finalize is already in progress',
            retryAfterMs: D1_WALLET_REGISTRATION_FINALIZE_RESUME_AFTER_MS,
          };
        case 'uncertain':
          return {
            ok: false,
            code: 'internal',
            message: outcome.message || 'registration finalize outcome is uncertain',
            retryAfterMs: D1_WALLET_REGISTRATION_FINALIZE_RESUME_AFTER_MS,
          };
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'registration finalize boundary failed',
        retryAfterMs: D1_WALLET_REGISTRATION_FINALIZE_RESUME_AFTER_MS,
      };
    }
  }

  private async executeWalletRegistrationFinalizeSideEffect(
    request: FinalizeWalletRegistrationInput,
  ): Promise<WalletRegistrationFinalizeResponse> {
    const response = await this.executeWalletRegistrationFinalize(request);
    return response.ok ? response : throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1(response);
  }

  private async executeWalletRegistrationFinalize(
    request: FinalizeWalletRegistrationInput,
  ): Promise<WalletRegistrationFinalizeResponse> {
    const finalizeTiming = createD1RegistrationRouteTimingRecorder('wallets_register_finalize');
    const totalTiming = startD1RegistrationRouteTiming('registerFinalizeTotalMs');
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (!idempotencyKey) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration finalize idempotencyKey is required',
        };
      }
      const requestFingerprint = await walletRegistrationFinalizeRequestFingerprint(request);
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
        if (replay.requestFingerprint !== requestFingerprint) {
          return {
            ok: false,
            code: 'idempotency_conflict',
            message: 'registration finalize idempotency key was reused for a different request',
          };
        }
        const replayedCeremony = await store.getCeremony(request.registrationCeremonyId);
        const preservesDeferredEd25519Finalize =
          replay.response.ok &&
          replay.response.kind === 'evm_family_ecdsa' &&
          replayedCeremony !== null &&
          registrationSignerBranchesFromPlan(replayedCeremony.signerPlan).nearEd25519 !== null;
        if (preservesDeferredEd25519Finalize) {
          if (replayedCeremony.signerState.kind !== 'signer_set_registration') {
            throw new Error('Replayed mixed registration has an invalid signer state');
          }
          const replayedEcdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
            replayedCeremony.signerState,
          );
          if (replayedEcdsaBranch?.kind === 'evm_family_ecdsa_activated') {
            try {
              await store.updateCeremony({
                expected: replayedCeremony,
                next: {
                  ...replayedCeremony,
                  signerState: replaceStoredWalletRegistrationSignerBranch({
                    state: replayedCeremony.signerState,
                    replacement: buildStoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch({
                      activated: replayedEcdsaBranch,
                      finalizedAtMs: replay.createdAtMs,
                    }),
                  }),
                },
              });
            } catch (error: unknown) {
              const reconciled = await store.getCeremony(request.registrationCeremonyId);
              const reconciledEcdsaBranch =
                reconciled?.signerState.kind === 'signer_set_registration'
                  ? findStoredWalletRegistrationEvmFamilyEcdsaBranch(reconciled.signerState)
                  : null;
              if (reconciledEcdsaBranch?.kind !== 'evm_family_ecdsa_finalized') throw error;
            }
          } else if (replayedEcdsaBranch?.kind !== 'evm_family_ecdsa_finalized') {
            throw new Error('Replayed mixed registration has not completed ECDSA activation');
          }
        }
        if (!preservesDeferredEd25519Finalize) {
          await cleanupFinalizedRegistrationCeremony({
            store,
            registrationCeremonyId: request.registrationCeremonyId,
          });
        }
        finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
        return withD1RegistrationRouteDiagnostics(replay.response, finalizeTiming);
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
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const storedEcdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(
        ceremony.signerState,
      );
      const sequenceFailure = finalizeSignerWorkSequenceFailure({
        request,
        hasNearEd25519: requestedNearEd25519 !== null,
        hasEvmFamilyEcdsa: requestedEvmFamilyEcdsa !== null,
        ecdsaFinalized: storedEcdsaBranch?.kind === 'evm_family_ecdsa_finalized',
      });
      if (sequenceFailure) {
        return { ok: false, ...sequenceFailure };
      }
      /* Refactor 94 Phase 4+5. Which half this call commits comes from the
         request, not from the plan: a mixed plan finalizes ECDSA first and
         Ed25519 later, so the plan alone no longer says what is being
         committed now. The sequence check above has already confirmed the
         requested half is admitted and legal at this point. */
      const finalizeEvmFamilyEcdsa =
        request.kind === 'evm_family_ecdsa' ? requestedEvmFamilyEcdsa : null;
      const finalizeNearEd25519 = request.kind === 'near_ed25519' ? requestedNearEd25519 : null;
      /* True when this ECDSA finalize is step one of two, so the ceremony must
         survive for the Ed25519 finalize to resume from. */
      const ed25519FinalizePending = finalizeEvmFamilyEcdsa !== null && requestedNearEd25519 !== null;
      const ecdsaWalletKeys: WalletRegistrationEcdsaWalletKey[] = [];
      let ecdsaFinalizeState: D1RegistrationEcdsaFinalizeState = {
        kind: 'ecdsa_registration_disabled',
      };
      let activatedEcdsaBranch: StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch | null = null;
      if (finalizeEvmFamilyEcdsa) {
        const ecdsaState = storedEcdsaBranch;
        if (!ecdsaState || ecdsaState.kind !== 'evm_family_ecdsa_activated') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA family activation is required before finalize',
          };
        }
        activatedEcdsaBranch = ecdsaState;
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
      if (finalizeNearEd25519) {
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
          consumerBinding: requestFingerprint,
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
        const firstParticipantId = finalizeNearEd25519.participantIds[0];
        const secondParticipantId = finalizeNearEd25519.participantIds[1];
        if (
          finalizeNearEd25519.participantIds.length !== 2 ||
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
          finalizeNearEd25519.accountProvisioning,
        );
        if (sponsoredAccountId) {
          const created = await this.createSponsoredNamedNearAccount({
            accountId: sponsoredAccountId,
            publicKey,
            // Scoped to the activation session so a retry of this exact
            // registration replays its prepared transaction rather than
            // creating a second sponsored account.
            idempotencyKey: bytesToUnprefixedHex(
              Uint8Array.from(consumed.activation.result.binding.session_id),
            ),
          });
          switch (created.kind) {
            case 'rejected':
              return {
                ok: false,
                code: 'account_creation_failed',
                message: created.message,
              };
            case 'retryable':
              return {
                ok: false,
                code: 'account_creation_retryable',
                message: created.message,
                retryAfterMs: created.retryAfterMs,
              };
            case 'created':
              nearAccountId = created.accountId;
              sponsoredTransactionHash = created.transactionHash;
              break;
            default:
              return assertNeverSponsoredNamedNearAccountCreationResult(created);
          }
        }
        const resolved = resolvedRegistrationNearAccount({
          accountProvisioning: finalizeNearEd25519.accountProvisioning,
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
        const activeYaoCapability = buildRouterAbEd25519YaoRegistrationCapabilityRecordV1(
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
        const issuedAtMs = Date.now();
        const reusableTerms = registrationReusableWalletSessionTerms({
          signingBudget,
          issuedAtMs,
        });
        const reusableWalletSession =
          await this.authorizationService.issueReusableWalletSession({
            tenantId: this.authorizationTenantId,
            principalId: reusableWalletSessionPrincipalId(walletAuthAuthority),
            walletId: ceremony.intent.walletId,
            authority: await walletAuthAuthorityRef({ authority: walletAuthAuthority }),
            mintId: requireReusableWalletSessionMintId(ceremony.registrationCeremonyId),
            remainingUses: reusableTerms.remainingUses,
            issuedAtMs,
            expiresAtMs: reusableTerms.expiresAtMs,
          });
        const session = await mintD1RegistrationEd25519WalletSession({
          runtime: yaoRuntime,
          identity: {
            walletId: ceremony.intent.walletId,
            nearAccountId,
            nearEd25519SigningKeyId:
              consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
            authority: walletAuthAuthority,
            thresholdSessionId: consumed.activation.admissionRequest.scope.wallet_session_id,
            walletSessionId: reusableWalletSession.session.walletSessionId,
            quotaId: reusableWalletSession.quota.quotaId,
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
          signerSlot: finalizeNearEd25519.signerSlot,
          nearAccountId,
          nearEd25519SigningKeyId:
            consumed.activation.admissionRequest.application_binding.near_ed25519_signing_key_id,
          publicKey,
          relayerKeyId: yaoRuntime.signingWorkerId,
          keyVersion: finalizeNearEd25519.keyVersion,
          recoveryExportCapable: true,
          participantIds,
          session: session.session,
        };
        ed25519SignerRecord = buildYaoEd25519WalletSignerRecord({
          walletId: ceremony.intent.walletId,
          nearAccountId,
          nearEd25519SigningKeyId: ed25519PublicResult.nearEd25519SigningKeyId,
          thresholdSessionId: session.session.thresholdSessionId,
          signerSlot: finalizeNearEd25519.signerSlot,
          publicKey,
          signingWorkerId: yaoRuntime.signingWorkerId,
          keyVersion: finalizeNearEd25519.keyVersion,
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
        switch (ceremony.authority.kind) {
          case 'passkey':
            if (emailOtpEnrollment.persistence) {
              return {
                ok: false,
                code: 'invalid_state',
                message: 'Passkey registration cannot persist Email OTP enrollment state',
              };
            }
            await this.walletRegistrationCommitStore.commit({
              kind: 'passkey_wallet_registration_commit_v1',
              wallet,
              walletSigners,
              authority: ceremony.authority,
              now,
            });
            break;
          case 'email_otp':
            if (!emailOtpEnrollment.persistence) {
              return {
                ok: false,
                code: 'invalid_state',
                message: 'Email OTP registration is missing enrollment persistence state',
              };
            }
            await this.walletRegistrationCommitStore.commit({
              kind: 'email_otp_wallet_registration_commit_v1',
              wallet,
              walletSigners,
              authority: ceremony.authority,
              emailOtp: this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationCommitPlan(
                emailOtpEnrollment.persistence,
              ),
              now,
            });
            break;
        }
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
      if (ed25519PublicResult && finalizeNearEd25519 && resolvedNearAccount) {
        const authorityScope =
          thresholdEd25519AuthorityScopeFromWalletAuthAuthority(walletAuthAuthority);
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
                accountProvisioning: finalizeNearEd25519.accountProvisioning,
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
                accountProvisioning: finalizeNearEd25519.accountProvisioning,
                resolvedAccount: resolvedNearAccount,
                ed25519: ed25519PublicResult,
              };
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
      if (idempotencyKey && requestFingerprint) {
        const replayCacheTiming = startD1RegistrationRouteTiming(
          'registrationFinalizeReplayCacheMs',
        );
        try {
          await store.putFinalizeReplay({
            kind: 'wallet_registration_finalize_replay_v1',
            registrationCeremonyId: ceremony.registrationCeremonyId,
            idempotencyKey,
            requestFingerprint,
            response,
            createdAtMs: now,
            expiresAtMs: ceremony.expiresAtMs,
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, replayCacheTiming);
        }
      }
      /* Refactor 94 Phase 4+5. On a mixed plan this is step one of two: mark
         the ECDSA branch finalized and keep the ceremony, which is what the
         Ed25519 finalize resumes from. Deleting here would strand it. */
      if (ed25519FinalizePending) {
        if (!activatedEcdsaBranch) {
          return {
            ok: false,
            code: 'internal',
            message: 'ECDSA finalize completed without an activated branch to advance',
          };
        }
        await store.updateCeremony({
          expected: ceremony,
          next: {
            ...ceremony,
            signerState: replaceStoredWalletRegistrationSignerBranch({
              state: ceremony.signerState,
              replacement: buildStoredWalletRegistrationEvmFamilyEcdsaFinalizedBranch({
                activated: activatedEcdsaBranch,
                finalizedAtMs: now,
              }),
            }),
          },
        });
        finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
        return withD1RegistrationRouteDiagnostics(response, finalizeTiming);
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
