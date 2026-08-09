import type {
  AfterCall,
  CreateUnlockFlowEventInput,
  LoginHooksOptions,
} from '@/core/types/sdkSentEvents';
import { createUnlockFlowEvent, UnlockEventPhase } from '@/core/types/sdkSentEvents';
import type {
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  LoginResult,
  RecentUnlockAccount,
  WalletSession,
  SigningSessionStatus,
  ThresholdWarmLoginAndCreateSessionResult,
  WalletAuthMethod,
  ReusableWalletSessionState,
  WalletSessionAppIdentity,
  WalletSessionCapabilityLaneReadiness,
  WalletSessionCapabilityProjection,
  WalletSessionCapabilityReadiness,
  WalletSessionIdentityResolveFailure,
  WalletAuthenticationState,
} from '@/core/types/seams';
import type {
  EcdsaLoginSessionSurface,
  LoginUnlockSigningSurface,
  LoginWebContext,
  LoginWarmSigningSurface,
  RecentUnlocksWebContext,
  UserAccountLookupSurface,
  WalletSessionWebContext,
} from '@/SeamsWeb/signingSurface/types';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EcdsaCapabilitySelector } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  resolveManagedRuntimeScopeBootstrap,
  type ManagedRuntimeScopeBootstrap,
} from '@/core/config/managedRuntimeScope';
import {
  getUserFriendlyErrorMessage,
  isUserCancellationError,
  toError,
} from '@shared/utils/errors';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { isObject } from '@shared/utils/validation';
import {
  mpcMaterialActivationRefsEqual,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  parseReusableWalletSessionMintId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { decodeJwtPayloadRecord, walletSessionJwtAuth } from '@shared/utils/sessionTokens';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpProvider,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  walletSessionAuthorizations,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { persistActiveWalletSessionAuthorizationCurve } from '@/core/signingEngine/session/persistence/walletSessionAuthorizationProjection';
import { resolveActiveEcdsaCapabilityRuntime } from '@/core/signingEngine/session/material/activeEcdsaCapabilityRuntime';
import {
  getNearAccountProjection,
  resolveNearAccountProfileContinuity,
} from '@/core/accountData/near/accountProjection';
import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import type {
  ClientUserData,
  ThresholdEd25519KeyMaterial,
} from '@/core/accountData/near/nearAccountData.types';
import {
  exchangeSession,
  type PasskeySessionCustodyUnlockV1,
  type SessionExchangeInput,
  type SessionExchangeRuntimeScope,
} from '@/core/rpcClients/near/rpcCalls';
import { rememberPasskeyCustodySessionEnvelope } from '@/core/signingEngine/session/passkey/passkeyCustodySessionCache';
import {
  fetchWalletEcdsaKeyFactsInventoryWithAppSession,
  fetchWalletEcdsaKeyFactsInventoryWithWebAuthn,
  type WalletEcdsaKeyFactsInventoryResponse,
  type WalletEcdsaKeyFactsInventoryTarget,
} from '@/core/rpcClients/relayer/walletRegistration';
import type {
  AccountSignerRecord,
  ProfileAuthenticatorRecord,
} from '@/core/indexedDB/passkeyClientDB.types';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { parseSignerSlot } from '@/core/signingEngine/webauthnAuth/device/signerSlot';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  STALE_ECDSA_KEY_IDENTITY_ERROR_CODE,
  type ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import { buildStrictEcdsaPostRegistrationSessionActivationRequest } from '@/core/signingEngine/threshold/ecdsa/postRegistrationSessionActivation';
import {
  type EmailOtpEd25519SessionPolicyAuthority,
  type Ed25519SessionPolicyAuthority,
  type PasskeyEd25519SessionPolicyAuthority,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  type Ed25519WalletSessionMintAuthorization,
} from '@/core/signingEngine/threshold/ed25519/walletSession';
import { shouldRequireThresholdWarmSession } from '@/SeamsWeb/operations/session/thresholdWarmSessionDefaults';
import { createRouterAbNormalSigningPolicy } from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import { listConfiguredThresholdEcdsaPublicationTargets } from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  ConcreteAvailableEd25519SigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  ecdsaAvailableLaneForTarget,
  ecdsaAvailableLaneTargets,
  isConcreteAvailableSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { assertWalletRuntimePostconditions } from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  evmFamilyEcdsaWalletKeyToIdentity,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRuntimePolicyScope,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  type EvmFamilyEcdsaKeyIdentity,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  buildConfiguredTargetKeyCompletion,
  collectConfiguredTargetThresholdEcdsaWarmKeys,
  configuredTargetThresholdEcdsaWarmKey,
  mergeCanonicalThresholdEcdsaWarmSessionContexts,
  parseActiveEcdsaSignerRecordForUnlock,
  planUnlockEcdsaWarmup,
  requireCompleteConfiguredTargetKeyContext,
  type ActiveEcdsaSignerRecord,
  type BlockedEcdsaSignerRecord,
  type CanonicalThresholdEcdsaWarmSessionContext,
  type ConfiguredTargetThresholdEcdsaWarmKey,
  type KeyFactsInventoryRequiredEcdsaSignerRecord,
  type ConfiguredTargetKeyCompletion,
  type WalletUnlockSelection,
} from '@/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner';
import type { ThresholdEcdsaKeyIdentityInventoryEntry } from '@/core/signingEngine/session/passkey/ecdsaKeyFactsInventory';
import {
  DEFAULT_UNLOCK_REMAINING_USES,
  resolveWalletUnlockSessionUsesFromRequestedUses,
} from '@/core/signingEngine/threshold/sessionPolicy';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '@shared/utils/ecdsaKeyFactsInventory';
import {
  buildEmailOtpWalletAuthMethodBinding,
  buildPasskeyAuthScope,
  buildPasskeyWalletAuthMethodBinding,
  buildWalletIdentity,
  parseRpId,
  type WalletAuthMethodBinding,
} from '@shared/utils/walletCapabilityBindings';
import { collectPasskeyLoginAssertion } from '@/SeamsWeb/operations/authMethods/passkey/loginAssertion';
import {
  collectFreshLocalPasskeyUnlockCredential,
  createLocalUnlockChallengeB64u,
} from '@/SeamsWeb/operations/authMethods/passkey/localUnlock';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  passkeyCredentialIdB64uFromAuthentication,
  passkeyPrfFirstB64uFromCredential,
} from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import type {
  MintedEd25519WalletSessionAuthority,
  ProvisionWarmEd25519CapabilitySuccessResult,
} from '@/core/signingEngine/session/warmCapabilities/types';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  openWalletCustodyEd25519ActiveClientV1,
  walletCustodyCacheEnvelopeFromRecordV1,
  type WalletCustodyActivationFactsV1,
} from '@/core/signingEngine/walletCustody/openCustodyCache';
import { joinCustodyWireFromEnvelopeRecord } from '@/core/signingEngine/walletCustody/joinCustodyWire';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { reconcileCanonicalEcdsaActivationWasm } from '@/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm';
import {
  resolveWalletUnlockSubjectSet,
  resolveWalletCapabilitySubjectResolution,
  type WalletCapabilitySubjectResolution,
  type WalletUnlockSubject,
  type WalletUnlockSubjectSet,
} from './walletUnlockSubject';
import { resolveEcdsaActivationJournalSelectors } from './walletUnlockEcdsaSubject';
import {
  emailOtpAppSessionBindingFromJwt,
  emailOtpProviderFromAppSessionJwt,
} from '@/core/signingEngine/session/emailOtp/appSessionJwtCache';

type EmitUnlockEventInput = Omit<CreateUnlockFlowEventInput, 'accountId' | 'flowId'>;

function fetchWithGlobalThis(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return globalThis.fetch(input, init);
}

function emitUnlockEvent(
  onEvent: LoginHooksOptions['onEvent'] | undefined,
  unlockSubjectId: string,
  event: EmitUnlockEventInput,
): void {
  onEvent?.(
    createUnlockFlowEvent({
      flowId: `unlock:${unlockSubjectId}`,
      accountId: unlockSubjectId,
      ...event,
    }),
  );
}

function resolveLoginWalletUnlockSelection(
  selection: LoginHooksOptions['unlockSelection'] | undefined,
): WalletUnlockSelection {
  switch (selection?.mode) {
    case 'ed25519_only':
      return { mode: 'ed25519_only', ed25519: true };
    case 'ecdsa_only':
      return { mode: 'ecdsa_only', ecdsa: true };
    case 'ed25519_and_ecdsa':
    case undefined:
      return { mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true };
  }
  return assertNeverLoginState(selection);
}

export function resolveLoginWalletUnlockSelectionForSubjectSet(args: {
  selection: LoginHooksOptions['unlockSelection'] | undefined;
  subjectSet: WalletUnlockSubjectSet;
}): WalletUnlockSelection {
  if (args.selection) return resolveLoginWalletUnlockSelection(args.selection);
  let hasNearEd25519 = false;
  let hasEvmFamilyEcdsa = false;
  for (const subject of args.subjectSet.subjects) {
    switch (subject.kind) {
      case 'near_ed25519_wallet':
        hasNearEd25519 = true;
        break;
      case 'evm_family_ecdsa_wallet':
        hasEvmFamilyEcdsa = true;
        break;
      default:
        return assertNeverLoginState(subject);
    }
  }
  if (hasNearEd25519 && hasEvmFamilyEcdsa) {
    return { mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true };
  }
  if (hasNearEd25519) return { mode: 'ed25519_only', ed25519: true };
  if (hasEvmFamilyEcdsa) return { mode: 'ecdsa_only', ecdsa: true };
  throw new Error('[login] wallet unlock subject set has no supported capability');
}

function buildAnonymousWalletSession(): WalletSession {
  return {
    appIdentity: { kind: 'anonymous' },
    authentication: { kind: 'signed_out' },
    reusableWalletSession: { kind: 'absent' },
    capabilityProjection: { kind: 'not_requested' },
    nonceDiagnostics: null,
  };
}

type NearEd25519WalletSubject = Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>;
type EvmFamilyEcdsaWalletSubject = Extract<
  WalletUnlockSubject,
  { kind: 'evm_family_ecdsa_wallet' }
>;

type ResolvedLoginWalletBinding = {
  kind: 'near_ed25519_capable_wallet';
  walletId: WalletId;
  subjectSet: WalletUnlockSubjectSet;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
};

type ResolvedLoginEcdsaOnlyWallet = {
  kind: 'evm_family_ecdsa_only_wallet';
  walletId: WalletId;
  subjectSet: WalletUnlockSubjectSet;
  ecdsaSubjects: readonly [EvmFamilyEcdsaWalletSubject, ...EvmFamilyEcdsaWalletSubject[]];
  nearAccountId?: never;
  nearEd25519SigningKeyId?: never;
};

type ResolvedLoginWalletIdentity = ResolvedLoginWalletBinding | ResolvedLoginEcdsaOnlyWallet;

function isNearEd25519WalletSubject(
  subject: WalletUnlockSubject,
): subject is NearEd25519WalletSubject {
  return subject.kind === 'near_ed25519_wallet';
}

function isEvmFamilyEcdsaWalletSubject(
  subject: WalletUnlockSubject,
): subject is EvmFamilyEcdsaWalletSubject {
  return subject.kind === 'evm_family_ecdsa_wallet';
}

function selectNearEd25519WalletSubject(
  subjectSet: WalletUnlockSubjectSet,
): NearEd25519WalletSubject | null {
  const nearSubjects = subjectSet.subjects.filter(isNearEd25519WalletSubject);
  if (nearSubjects.length === 0) return null;
  if (nearSubjects.length > 1) {
    throw new Error('[WalletSession] multiple NEAR Ed25519 subjects found for wallet session');
  }
  return nearSubjects[0] || null;
}

function resolveLoginWalletIdentity(args: {
  subjectSet: WalletUnlockSubjectSet;
  selection: WalletUnlockSelection;
}): ResolvedLoginWalletIdentity {
  const nearSubject = selectNearEd25519WalletSubject(args.subjectSet);
  const ecdsaSubjects = args.subjectSet.subjects.filter(isEvmFamilyEcdsaWalletSubject);
  for (const subject of args.subjectSet.subjects) {
    if (String(subject.walletId) !== String(args.subjectSet.walletId)) {
      throw new Error('[login] wallet unlock subject belongs to a different wallet');
    }
  }

  switch (args.selection.mode) {
    case 'ed25519_only':
      if (!nearSubject || ecdsaSubjects.length !== 0) {
        throw new Error('[login] NEAR Ed25519 unlock requires one exact NEAR subject set');
      }
      return {
        kind: 'near_ed25519_capable_wallet',
        walletId: args.subjectSet.walletId,
        subjectSet: args.subjectSet,
        nearAccountId: nearSubject.nearAccountId,
        nearEd25519SigningKeyId: nearSubject.nearEd25519SigningKeyId,
      };
    case 'ecdsa_only': {
      const [firstEcdsaSubject, ...remainingEcdsaSubjects] = ecdsaSubjects;
      if (nearSubject || !firstEcdsaSubject) {
        throw new Error('[login] ECDSA-only unlock requires exact ECDSA subjects');
      }
      return {
        kind: 'evm_family_ecdsa_only_wallet',
        walletId: args.subjectSet.walletId,
        subjectSet: args.subjectSet,
        ecdsaSubjects: [firstEcdsaSubject, ...remainingEcdsaSubjects],
      };
    }
    case 'ed25519_and_ecdsa':
      if (!nearSubject || ecdsaSubjects.length === 0) {
        throw new Error('[login] combined unlock requires exact NEAR and ECDSA subjects');
      }
      return {
        kind: 'near_ed25519_capable_wallet',
        walletId: args.subjectSet.walletId,
        subjectSet: args.subjectSet,
        nearAccountId: nearSubject.nearAccountId,
        nearEd25519SigningKeyId: nearSubject.nearEd25519SigningKeyId,
      };
  }
  return assertNeverLoginState(args.selection);
}

function requireNearLoginWalletBinding(
  identity: ResolvedLoginWalletIdentity,
): ResolvedLoginWalletBinding {
  if (identity.kind === 'near_ed25519_capable_wallet') return identity;
  throw new Error('[login] NEAR Ed25519 warm-up requires an exact NEAR subject');
}

function assertEcdsaWarmupMatchesUnlockSubjects(args: {
  identity: ResolvedLoginWalletIdentity;
  context: CanonicalThresholdEcdsaWarmSessionContext;
}): void {
  const allowedThresholdKeyIds = new Set<string>();
  for (const subject of args.identity.subjectSet.subjects) {
    if (subject.kind === 'evm_family_ecdsa_wallet') {
      allowedThresholdKeyIds.add(String(subject.ecdsaThresholdKeyId));
    }
  }
  if (allowedThresholdKeyIds.size === 0) {
    throw new Error('[login] ECDSA warm-up requires an exact ECDSA unlock subject');
  }
  for (const warmKey of args.context.ecdsaKeys) {
    const thresholdKeyId = String(warmKey.key?.ecdsaThresholdKeyId || '').trim();
    if (thresholdKeyId && !allowedThresholdKeyIds.has(thresholdKeyId)) {
      throw new Error('[login] ECDSA warm-up key does not match the unlock subject set');
    }
  }
}

type CanonicalEcdsaActivationReconciliationSummary =
  | {
      readonly kind: 'settled';
      readonly didFinalize: boolean;
      readonly code?: never;
    }
  | {
      readonly kind: 'pending';
      readonly didFinalize: boolean;
      readonly code?: never;
    }
  | {
      readonly kind: 'failed';
      readonly didFinalize: boolean;
      readonly code: 'corrupt' | 'persistence_unavailable';
    };

function ecdsaActivationSelectorsFromSubjectSet(
  subjectSet: WalletUnlockSubjectSet,
): readonly EcdsaCapabilitySelector[] {
  const selectors: EcdsaCapabilitySelector[] = [];
  for (const subject of subjectSet.subjects) {
    if (subject.kind !== 'evm_family_ecdsa_wallet') continue;
    selectors.push({
      capability: subject.capability,
      authority: subject.authority,
    });
  }
  return selectors;
}

async function reconcileCanonicalEcdsaActivationSelectors(args: {
  readonly workerCtx: WorkerOperationContext;
  readonly selectors: readonly EcdsaCapabilitySelector[];
}): Promise<CanonicalEcdsaActivationReconciliationSummary> {
  let didFinalize = false;
  let pending = false;
  for (const selector of args.selectors) {
    const result = await reconcileCanonicalEcdsaActivationWasm({
      workerCtx: args.workerCtx,
      command: {
        kind: 'reconcile_canonical_ecdsa_activation_v1',
        capability: selector.capability,
        authority: selector.authority,
      },
    });
    switch (result.kind) {
      case 'canonical_ecdsa_activation_reconciliation_absent_v1':
        break;
      case 'canonical_ecdsa_activation_reconciliation_finalized_v1':
        didFinalize = true;
        break;
      case 'canonical_ecdsa_activation_reconciliation_pending_v1':
        pending = true;
        break;
      case 'canonical_ecdsa_activation_reconciliation_failed_v1':
        return {
          kind: 'failed',
          didFinalize,
          code: result.code,
        };
      default:
        assertNeverLoginState(result);
    }
  }
  return pending ? { kind: 'pending', didFinalize } : { kind: 'settled', didFinalize };
}

function reportNonSettledEcdsaActivationReconciliation(
  result: CanonicalEcdsaActivationReconciliationSummary,
): void {
  switch (result.kind) {
    case 'settled':
      return;
    case 'pending':
      console.warn('[login] ECDSA activation remains prepared and requires confirmation');
      return;
    case 'failed':
      console.warn('[login] ECDSA activation reconciliation failed without changing active state', {
        code: result.code,
      });
      return;
  }
  assertNeverLoginState(result);
}

function walletAuthMethodBindingFromRecord(
  record: Awaited<ReturnType<typeof IndexedDBManager.listWalletAuthMethodsForWallet>>[number],
): WalletAuthMethodBinding | null {
  const wallet = buildWalletIdentity({ walletId: record.walletId });
  switch (record.kind) {
    case 'passkey': {
      const rpId = parseRpId(record.rpId);
      if (!rpId.ok) return null;
      return buildPasskeyWalletAuthMethodBinding({
        scope: buildPasskeyAuthScope({ wallet, rpId: rpId.value }),
        credentialIdB64u: record.credentialIdB64u,
      });
    }
    case 'email_otp':
      return buildEmailOtpWalletAuthMethodBinding({
        wallet,
        emailHashHex: record.emailHashHex,
        registrationAuthorityId: record.registrationAuthorityId,
      });
    default:
      record satisfies never;
      return null;
  }
}

function recentUnlockAccountFromUser(user: ClientUserData): RecentUnlockAccount {
  const walletId = String(user.walletId || '').trim();
  if (!walletId) {
    throw new Error('[login] recent unlock account is missing walletId');
  }
  const displayName = String(user.loginDisplayName || '').trim() || walletId;
  return {
    walletId,
    nearAccountId: user.nearAccountId,
    displayName,
    signerSlot: user.signerSlot,
    ...(typeof user.lastLogin === 'number' ? { lastLogin: user.lastLogin } : {}),
    authMethod: user.authMethod || null,
  };
}

async function readWalletAuthMethodBindingsForSession(
  walletId: WalletId | null,
): Promise<readonly WalletAuthMethodBinding[]> {
  if (!walletId) return [];
  const records = await IndexedDBManager.listWalletAuthMethodsForWallet(String(walletId)).catch(
    () => [],
  );
  return records
    .filter((record) => record.status === 'active')
    .map(walletAuthMethodBindingFromRecord)
    .filter((binding): binding is WalletAuthMethodBinding => Boolean(binding));
}

function selectThresholdWarmupAuthMethodBinding(args: {
  authMethods: readonly WalletAuthMethodBinding[];
  authMethod: WalletAuthMethod;
  walletId: WalletId;
}): WalletAuthMethodBinding | null {
  if (args.authMethod === SIGNER_AUTH_METHODS.passkey) return null;
  if (args.authMethod !== SIGNER_AUTH_METHODS.emailOtp) {
    throw new Error(`[login] unsupported wallet auth method for warm-up: ${args.authMethod}`);
  }
  const matches = args.authMethods.filter((binding) => binding.kind === 'email_otp');
  if (matches.length !== 1) {
    throw new Error('[login] Email OTP warm-up requires one active wallet auth-method binding');
  }
  const binding = matches[0];
  if (String(binding.wallet.walletId) !== String(args.walletId)) {
    throw new Error('[login] Email OTP warm-up auth-method binding wallet mismatch');
  }
  return binding;
}

async function readThresholdWarmupAuthMethodBinding(args: {
  walletId: WalletId;
  authMethod: WalletAuthMethod;
}): Promise<WalletAuthMethodBinding | null> {
  return selectThresholdWarmupAuthMethodBinding({
    authMethods: await readWalletAuthMethodBindingsForSession(args.walletId),
    authMethod: args.authMethod,
    walletId: args.walletId,
  });
}

type LoginUnlockAccountSubject =
  | {
      kind: 'near_operational_signer';
      userData: ClientUserData;
      operationalPublicKey: string;
      walletId: WalletId;
    }
  | {
      kind: 'ecdsa_wallet_only';
      walletId: WalletId;
      userData?: never;
      operationalPublicKey: null;
    };

type LoginPasskeyAuthenticator = Pick<
  ProfileAuthenticatorRecord,
  'credentialId' | 'transports' | 'signerSlot'
>;

type LoginUnlockAccountPhase = {
  kind: 'login_unlock_account_phase_ready';
  accountSubject: LoginUnlockAccountSubject;
  authenticators: LoginPasskeyAuthenticator[];
  baseSignerSlot: number;
  localUnlockAuthMethod: WalletAuthMethod;
  requiresLocalPasskeyUnlock: boolean;
};

type LoginEcdsaKeyFactsInventoryAuthority =
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policyExpiresAtMs: number;
    }
  | {
      kind: 'webauthn';
    };

type LoginNoServerSessionPasskeyCredentialPlan =
  | {
      kind: 'warmup_phase_owns_passkey_credential';
    }
  | {
      kind: 'local_unlock_passkey_assertion';
    }
  | {
      kind: 'passkey_credential_already_collected';
    }
  | {
      kind: 'no_local_passkey_required';
    };

type LoginWarmupPasskeyCredentialPlan =
  | {
      kind: 'existing_passkey_credential';
    }
  | {
      kind: 'app_session_authorized_warmup';
    }
  | {
      kind: 'no_passkey_credential_required';
    }
  | {
      kind: 'wallet_custody';
    }
  | {
      kind: 'local_unlock_passkey_assertion_after_ecdsa_context';
    };

type LoginWarmupRouteAuthorization =
  | {
      kind: 'none';
      appSessionJwt: '';
      useAppSessionCookie: false;
    }
  | {
      kind: 'app_session_jwt';
      appSessionJwt: string;
      useAppSessionCookie: false;
    }
  | {
      kind: 'app_session_cookie';
      appSessionJwt: '';
      useAppSessionCookie: true;
    };

type LoginWarmupCredentialState =
  | {
      kind: 'available';
      credential: WebAuthnAuthenticationCredential;
      localPasskeyCredentialIdB64u: string;
    }
  | {
      kind: 'credential_id_only';
      credential?: never;
      localPasskeyCredentialIdB64u: string;
    }
  | {
      kind: 'unavailable';
      credential?: never;
      localPasskeyCredentialIdB64u: '';
    };

type LoginWarmupRuntimeScopeBootstrapState =
  | {
      kind: 'available';
      runtimeScopeBootstrap: ManagedRuntimeScopeBootstrap;
    }
  | {
      kind: 'unavailable';
      runtimeScopeBootstrap?: never;
    };

type ActivePasskeySessionCustodyUnlockV1 = Omit<PasskeySessionCustodyUnlockV1, 'ed25519'> & {
  readonly ed25519: Extract<PasskeySessionCustodyUnlockV1['ed25519'], { kind: 'active' }>;
};

type LoginWarmupEd25519MintPlan =
  | {
      kind: 'not_requested';
      thresholdSessionId?: never;
      authorization?: never;
    }
  | {
      kind: 'fresh';
      thresholdSessionId?: never;
      authorization?: never;
    }
  | {
      kind: 'ecdsa_authorized';
      thresholdSessionId: string;
      authorization?: never;
    }
  | {
      kind: 'wallet_custody';
      custody: ActivePasskeySessionCustodyUnlockV1;
      thresholdSessionId?: never;
      authorization?: never;
    };

type LoginWarmupEd25519SessionAuthority =
  | {
      kind: 'not_requested';
      authority?: never;
      source?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'passkey';
      authority: PasskeyEd25519SessionPolicyAuthority;
      source: 'login';
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'email_otp';
      authority: EmailOtpEd25519SessionPolicyAuthority;
      source: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    };

function isActiveThresholdLoginSigningSession(
  sessionStatus: SigningSessionStatus | null | undefined,
): sessionStatus is ThresholdWarmLoginAndCreateSessionResult['signingSession'] {
  return sessionStatus?.status === 'active';
}

function resolveLoginEcdsaKeyFactsInventoryAuthority(args: {
  request: LoginHooksOptions['ecdsaKeyFactsInventory'] | null;
  routeAuthorization: LoginWarmupRouteAuthorization;
}): LoginEcdsaKeyFactsInventoryAuthority | null {
  if (!args.request) return null;
  switch (args.request.mode) {
    case 'app_session': {
      const appSessionJwt = String(
        args.request.appSessionJwt ||
          (args.routeAuthorization.kind === 'app_session_jwt'
            ? args.routeAuthorization.appSessionJwt
            : ''),
      ).trim();
      if (!appSessionJwt) return null;
      const requestedTtlMs = Math.floor(Number(args.request.policyTtlMs) || 0);
      const policyTtlMs = requestedTtlMs > 0 ? requestedTtlMs : 60_000;
      return {
        kind: 'app_session',
        appSessionJwt,
        policyExpiresAtMs: Date.now() + policyTtlMs,
      };
    }
    case 'webauthn':
      return { kind: 'webauthn' };
  }
  return null;
}

function resolveLoginWarmupRouteAuthorization(args: {
  appSessionJwt: string;
  useAppSessionCookie: boolean;
}): LoginWarmupRouteAuthorization {
  const appSessionJwt = args.appSessionJwt.trim();
  if (appSessionJwt) {
    return {
      kind: 'app_session_jwt',
      appSessionJwt,
      useAppSessionCookie: false,
    };
  }
  if (args.useAppSessionCookie) {
    return {
      kind: 'app_session_cookie',
      appSessionJwt: '',
      useAppSessionCookie: true,
    };
  }
  return {
    kind: 'none',
    appSessionJwt: '',
    useAppSessionCookie: false,
  };
}

function emailOtpIdentityFromLoginAppSession(args: {
  routeAuthorization: Extract<LoginWarmupRouteAuthorization, { kind: 'app_session_jwt' }>;
  walletId: WalletId;
}): { provider: EmailOtpProvider; providerUserId: string } {
  const binding = emailOtpAppSessionBindingFromJwt({
    walletId: args.walletId,
    appSessionJwt: args.routeAuthorization.appSessionJwt,
  });
  const provider = emailOtpProviderFromAppSessionJwt(args.routeAuthorization.appSessionJwt);
  return {
    provider,
    providerUserId: binding.providerSubject,
  };
}

function loginPasskeyCredentialIdB64u(args: {
  authenticators: readonly LoginPasskeyAuthenticator[];
  signerSlot: number;
}): string {
  return String(
    args.authenticators.find((authenticator) => authenticator.signerSlot === args.signerSlot)
      ?.credentialId ||
      args.authenticators[0]?.credentialId ||
      '',
  ).trim();
}

function buildLoginPasskeyWalletAuthAuthority(args: {
  walletId: WalletId;
  rpId: string;
  credentialIdB64u: string;
}): PasskeyWalletAuthAuthority {
  return buildPasskeyWalletAuthAuthority({
    walletId: args.walletId,
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
  });
}

function resolveLoginEd25519SessionAuthority(args: {
  wantsEd25519Warmup: boolean;
  authMethod: WalletAuthMethod;
  authMethodBinding: WalletAuthMethodBinding | null;
  walletId: WalletId;
  rpId: string;
  passkeyCredentialIdB64u: string;
  routeAuthorization: LoginWarmupRouteAuthorization;
  emailOtpAuthPolicy: ThresholdEcdsaEmailOtpAuthContext['policy'];
}): LoginWarmupEd25519SessionAuthority {
  if (!args.wantsEd25519Warmup) return { kind: 'not_requested' };
  if (args.authMethod === SIGNER_AUTH_METHODS.passkey) {
    const authority = buildLoginPasskeyWalletAuthAuthority({
      walletId: args.walletId,
      rpId: args.rpId,
      credentialIdB64u: args.passkeyCredentialIdB64u,
    });
    return {
      kind: 'passkey',
      authority: { kind: 'wallet_auth_authority', authority },
      source: 'login',
    };
  }
  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    if (args.routeAuthorization.kind !== 'app_session_jwt') {
      throw new Error('[login] Email OTP Ed25519 warm-up requires app-session JWT authority');
    }
    if (!args.authMethodBinding || args.authMethodBinding.kind !== 'email_otp') {
      throw new Error('[login] Email OTP Ed25519 warm-up requires wallet auth-method binding');
    }
    const emailOtpIdentity = emailOtpIdentityFromLoginAppSession({
      routeAuthorization: args.routeAuthorization,
      walletId: args.walletId,
    });
    const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
      policy: args.emailOtpAuthPolicy,
      walletId: args.walletId,
      emailHashHex: args.authMethodBinding.emailHashHex,
      retention: 'session',
      reason: 'login',
      provider: emailOtpIdentity.provider,
      providerUserId: emailOtpIdentity.providerUserId,
    });
    return {
      kind: 'email_otp',
      authority: { kind: 'wallet_auth_authority', authority: emailOtpAuthContext.authority },
      source: 'email_otp',
      emailOtpAuthContext,
    };
  }
  throw new Error(`[login] unsupported wallet auth method for Ed25519 warm-up: ${args.authMethod}`);
}

function requireRequestedLoginEd25519SessionAuthority(
  authority: LoginWarmupEd25519SessionAuthority,
): Exclude<LoginWarmupEd25519SessionAuthority, { kind: 'not_requested' }> {
  if (authority.kind === 'not_requested') {
    throw new Error('[login] threshold Ed25519 warm-up authority is missing');
  }
  return authority;
}

function loginEd25519ExactProvisionAuthBinding(
  authority: Exclude<LoginWarmupEd25519SessionAuthority, { kind: 'not_requested' }>,
): SigningLaneAuthBinding {
  switch (authority.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: toRpId(authority.authority.authority.verifier.rpId),
        credentialIdB64u: String(
          authority.authority.authority.factor.credentialIdB64u || '',
        ).trim(),
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: String(authority.authority.authority.factor.providerUserId || '').trim(),
      };
  }
  authority satisfies never;
  throw new Error('[login] unsupported Ed25519 exact provision authority');
}

function loginEd25519ExactProvisionLaneIdentity(args: {
  walletBinding: ResolvedLoginWalletBinding;
  signerSlot: number;
  thresholdSessionId: string;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  authority: Exclude<LoginWarmupEd25519SessionAuthority, { kind: 'not_requested' }>;
}): ExactEd25519SigningLaneIdentity {
  return exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: args.walletBinding.walletId,
      nearAccountId: args.walletBinding.nearAccountId,
      nearEd25519SigningKeyId: args.walletBinding.nearEd25519SigningKeyId,
      signerSlot: args.signerSlot,
    }),
    auth: loginEd25519ExactProvisionAuthBinding(args.authority),
    walletSessionId: args.walletSessionId,
    quotaId: args.quotaId,
    thresholdSessionId: args.thresholdSessionId,
  });
}

function resolveLoginWarmEd25519ProvisioningIdentity(args: {
  mintPlan: LoginWarmupEd25519MintPlan;
  ecdsaMint: ThresholdEcdsaAuthorizedEd25519Mint | null;
  walletBinding: ResolvedLoginWalletBinding;
  signerSlot: number;
  authority: Exclude<LoginWarmupEd25519SessionAuthority, { kind: 'not_requested' }>;
}) {
  switch (args.mintPlan.kind) {
    case 'not_requested':
      throw new Error('[login] threshold Ed25519 mint plan is missing');
    case 'wallet_custody':
      return {
        kind: 'fresh_ed25519_provisioning' as const,
        materialActivation: args.mintPlan.custody.ed25519.capability.materialActivation,
      };
    case 'fresh':
      throw new Error(
        '[login] fresh Ed25519 passkey provisioning requires canonical material activation',
      );
    case 'ecdsa_authorized':
      if (!args.ecdsaMint) {
        throw new Error(
          '[login] threshold Ed25519 warm-up requires the ECDSA bootstrap session minted during unlock',
        );
      }
      return {
        kind: 'exact_ed25519_provisioning' as const,
        laneIdentity: loginEd25519ExactProvisionLaneIdentity({
          walletBinding: args.walletBinding,
          signerSlot: args.signerSlot,
          thresholdSessionId: args.mintPlan.thresholdSessionId,
          walletSessionId: args.ecdsaMint.walletSessionId,
          quotaId: args.ecdsaMint.quotaId,
          authority: args.authority,
        }),
      };
  }
  return assertNeverLoginState(args.mintPlan);
}

function requireLoginPasskeyMaterialActivation(
  identity: ReturnType<typeof resolveLoginWarmEd25519ProvisioningIdentity>,
): MpcMaterialActivationRef {
  if (identity.kind === 'fresh_ed25519_provisioning' && identity.materialActivation) {
    return identity.materialActivation;
  }
  throw new Error('[login] passkey Ed25519 warm-up requires a canonical material activation');
}

type LoginEd25519ProvisionScope = {
  relayerKeyId: string;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope | null;
  routerAbNormalSigning: ReturnType<typeof createRouterAbNormalSigningPolicy>;
};

function resolveLoginEd25519ProvisionScope(args: {
  mintPlan: LoginWarmupEd25519MintPlan;
  fallback: LoginEd25519ProvisionScope;
}): LoginEd25519ProvisionScope {
  if (args.mintPlan.kind !== 'wallet_custody') return args.fallback;
  return {
    relayerKeyId: args.mintPlan.custody.ed25519.relayerKeyId,
    participantIds: args.mintPlan.custody.ed25519.participantIds,
    runtimePolicyScope: args.mintPlan.custody.ed25519.capability.runtimePolicyScope,
    routerAbNormalSigning: args.fallback.routerAbNormalSigning,
  };
}

function resolveLoginNoServerSessionPasskeyCredentialPlan(args: {
  requiresLocalPasskeyUnlock: boolean;
  requireThresholdWarmup: boolean;
  hasLoginCredential: boolean;
}): LoginNoServerSessionPasskeyCredentialPlan {
  if (args.hasLoginCredential) return { kind: 'passkey_credential_already_collected' };
  if (!args.requiresLocalPasskeyUnlock) return { kind: 'no_local_passkey_required' };
  if (args.requireThresholdWarmup) return { kind: 'warmup_phase_owns_passkey_credential' };
  return { kind: 'local_unlock_passkey_assertion' };
}

function resolveLoginWarmupPasskeyCredentialPlan(args: {
  requiresLocalPasskeyUnlock: boolean;
  hasLoginCredential: boolean;
  routeAuthorization: LoginWarmupRouteAuthorization;
  warmupPlan: ThresholdLoginWarmupPlan;
}): LoginWarmupPasskeyCredentialPlan {
  if (args.warmupPlan.signersToWarm.includes('ed25519') && args.requiresLocalPasskeyUnlock) {
    return { kind: 'wallet_custody' };
  }
  if (args.hasLoginCredential) return { kind: 'existing_passkey_credential' };
  switch (args.routeAuthorization.kind) {
    case 'app_session_jwt':
    case 'app_session_cookie':
      return { kind: 'app_session_authorized_warmup' };
    case 'none':
      break;
    default:
      return assertNeverLoginState(args.routeAuthorization);
  }
  if (args.requiresLocalPasskeyUnlock) {
    return { kind: 'local_unlock_passkey_assertion_after_ecdsa_context' };
  }
  return { kind: 'no_passkey_credential_required' };
}

function authenticatorsForCredentialIds(args: {
  authenticators: readonly LoginPasskeyAuthenticator[];
  credentialIds: readonly string[] | null;
}): readonly LoginPasskeyAuthenticator[] {
  if (!args.credentialIds) return args.authenticators;
  const allowed = new Set<string>();
  for (const credentialId of args.credentialIds) allowed.add(credentialId.trim());
  const authenticators: LoginPasskeyAuthenticator[] = [];
  for (const authenticator of args.authenticators) {
    if (allowed.has(String(authenticator.credentialId || '').trim())) {
      authenticators.push(authenticator);
    }
  }
  if (!authenticators.length) {
    throw new Error('[login] no local authenticator matches the required credential');
  }
  return authenticators;
}

function uniqueLoginCredentialIds(authenticators: readonly LoginPasskeyAuthenticator[]): string[] {
  const credentialIds: string[] = [];
  const seen = new Set<string>();
  for (const authenticator of authenticators) {
    const credentialId = String(authenticator.credentialId || '').trim();
    if (!credentialId || seen.has(credentialId)) continue;
    seen.add(credentialId);
    credentialIds.push(credentialId);
  }
  return credentialIds;
}

function parseLoginChallengeCredentialIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const credentialIds: string[] = [];
  const seen = new Set<string>();
  for (const entry of value) {
    const credentialId = typeof entry === 'string' ? entry.trim() : '';
    if (!credentialId || seen.has(credentialId)) continue;
    seen.add(credentialId);
    credentialIds.push(credentialId);
  }
  return credentialIds;
}

function resolveLoginPasskeyPromptCredentialIds(args: {
  authenticators: readonly LoginPasskeyAuthenticator[];
  signerSlot: number;
  serverCredentialIds: readonly string[];
}): readonly string[] {
  const signerAuthenticators: LoginPasskeyAuthenticator[] = [];
  for (const authenticator of args.authenticators) {
    if (authenticator.signerSlot === args.signerSlot) {
      signerAuthenticators.push(authenticator);
    }
  }
  const localCredentialIds = uniqueLoginCredentialIds(
    signerAuthenticators.length > 0 ? signerAuthenticators : args.authenticators,
  );
  if (localCredentialIds.length === 0) {
    throw new Error('[login] selected wallet has no local passkey credential ID');
  }
  if (args.serverCredentialIds.length === 0) return localCredentialIds;

  const serverCredentialIds = new Set(args.serverCredentialIds);
  const matchingCredentialIds: string[] = [];
  for (const credentialId of localCredentialIds) {
    if (serverCredentialIds.has(credentialId)) {
      matchingCredentialIds.push(credentialId);
    }
  }
  if (matchingCredentialIds.length === 0) {
    throw new Error('[login] server passkey allow-list does not match local wallet credentials');
  }
  return matchingCredentialIds;
}

type ResolveThresholdLoginWarmupPhaseInputArgs = {
  context: LoginWebContext;
  signerSlot: number;
  authenticators: readonly LoginPasskeyAuthenticator[];
  selection: WalletUnlockSelection;
  subjectSet: WalletUnlockSubjectSet;
  authMethod: WalletAuthMethod;
  authMethodBinding: WalletAuthMethodBinding | null;
  keyFactsInventoryRequest: LoginHooksOptions['ecdsaKeyFactsInventory'] | null;
  routeAuthorization: LoginWarmupRouteAuthorization;
};

type ThresholdLoginWarmupPhaseInput = {
  kind: 'threshold_login_warmup_phase_input';
  signerSlot: number;
  selection: WalletUnlockSelection;
  relayerUrl: string;
  rpId: string;
  configuredEcdsaTargets: ConfiguredThresholdEcdsaPublicationTarget[];
  selectedEcdsaTargets: ConfiguredThresholdEcdsaPublicationTarget[];
  wantsEd25519Warmup: boolean;
  wantsEcdsaWarmup: boolean;
  ed25519SessionAuthority: LoginWarmupEd25519SessionAuthority;
  keyFactsInventoryAuthority: LoginEcdsaKeyFactsInventoryAuthority | null;
  routeAuthorization: LoginWarmupRouteAuthorization;
};

export type LoginUnlockWarmupBranchPlan =
  | {
      kind: 'near_ed25519_only';
      wantsEd25519Warmup: true;
      wantsEcdsaWarmup: false;
    }
  | {
      kind: 'evm_family_ecdsa_only';
      wantsEd25519Warmup: false;
      wantsEcdsaWarmup: boolean;
    }
  | {
      kind: 'near_ed25519_and_evm_family_ecdsa';
      wantsEd25519Warmup: true;
      wantsEcdsaWarmup: boolean;
    };

export function resolveLoginUnlockWarmupBranchPlan(args: {
  subjectSet: WalletUnlockSubjectSet;
  selection: WalletUnlockSelection;
  hasConfiguredEcdsaTargets: boolean;
}): LoginUnlockWarmupBranchPlan {
  const identity = resolveLoginWalletIdentity({
    subjectSet: args.subjectSet,
    selection: args.selection,
  });
  switch (args.selection.mode) {
    case 'ed25519_only':
      return {
        kind: 'near_ed25519_only',
        wantsEd25519Warmup: true,
        wantsEcdsaWarmup: false,
      };
    case 'ecdsa_only':
      if (identity.kind !== 'evm_family_ecdsa_only_wallet') {
        throw new Error('[login] ECDSA-only warm-up requires exact ECDSA subjects');
      }
      return {
        kind: 'evm_family_ecdsa_only',
        wantsEd25519Warmup: false,
        wantsEcdsaWarmup: args.hasConfiguredEcdsaTargets,
      };
    case 'ed25519_and_ecdsa':
      return {
        kind: 'near_ed25519_and_evm_family_ecdsa',
        wantsEd25519Warmup: true,
        wantsEcdsaWarmup: args.hasConfiguredEcdsaTargets,
      };
  }
  return assertNeverLoginState(args.selection);
}

function resolveThresholdLoginWarmupPhaseInput(
  args: ResolveThresholdLoginWarmupPhaseInputArgs,
): ThresholdLoginWarmupPhaseInput {
  const relayerUrl = String(args.context.configs?.network.relayer?.url || '').trim();
  if (!relayerUrl) {
    throw new Error('[login] threshold warm session requires relayer.url to be configured');
  }
  const configuredEcdsaTargets = listConfiguredThresholdEcdsaPublicationTargets(
    args.context.configs.network.chains,
  );
  const branchPlan = resolveLoginUnlockWarmupBranchPlan({
    subjectSet: args.subjectSet,
    selection: args.selection,
    hasConfiguredEcdsaTargets: configuredEcdsaTargets.length > 0,
  });
  const wantsEcdsaWarmup = branchPlan.wantsEcdsaWarmup;
  const wantsEd25519Warmup = branchPlan.wantsEd25519Warmup;
  const rpId = String(args.context.signingEngine.getRpId() || '').trim();
  return {
    kind: 'threshold_login_warmup_phase_input',
    signerSlot: args.signerSlot,
    selection: args.selection,
    relayerUrl,
    rpId,
    configuredEcdsaTargets,
    selectedEcdsaTargets: wantsEcdsaWarmup ? configuredEcdsaTargets : [],
    wantsEd25519Warmup,
    wantsEcdsaWarmup,
    ed25519SessionAuthority: resolveLoginEd25519SessionAuthority({
      wantsEd25519Warmup,
      authMethod: args.authMethod,
      authMethodBinding: args.authMethodBinding,
      walletId: args.subjectSet.walletId,
      rpId,
      passkeyCredentialIdB64u: loginPasskeyCredentialIdB64u({
        authenticators: args.authenticators,
        signerSlot: args.signerSlot,
      }),
      routeAuthorization: args.routeAuthorization,
      emailOtpAuthPolicy: args.context.configs.signing.emailOtp.authPolicy,
    }),
    keyFactsInventoryAuthority: resolveLoginEcdsaKeyFactsInventoryAuthority({
      request: args.keyFactsInventoryRequest,
      routeAuthorization: args.routeAuthorization,
    }),
    routeAuthorization: args.routeAuthorization,
  };
}

async function readPasskeyUnlockEd25519Status(args: {
  context: LoginWebContext;
  walletIdentity: ResolvedLoginWalletIdentity;
}): Promise<SigningSessionStatus | null> {
  const walletBinding = requireNearLoginWalletBinding(args.walletIdentity);
  return await args.context.signingEngine
    .getWarmThresholdEd25519SessionStatus({
      walletId: walletBinding.walletId,
      nearAccountId: walletBinding.nearAccountId,
      nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
    })
    .catch(() => null);
}

async function assertPasskeyUnlockRuntimePostconditions(args: {
  context: LoginWebContext;
  walletIdentity: ResolvedLoginWalletIdentity;
  signersWarmed: readonly ('ed25519' | 'ecdsa')[];
}): Promise<void> {
  const ed25519StatusPromise = args.signersWarmed.includes('ed25519')
    ? readPasskeyUnlockEd25519Status({
        context: args.context,
        walletIdentity: args.walletIdentity,
      })
    : Promise.resolve(null);

  const requiredTargets = [
    ...(args.signersWarmed.includes('ed25519') ? [{ curve: 'ed25519' as const }] : []),
    ...(args.signersWarmed.includes('ecdsa')
      ? listConfiguredThresholdEcdsaPublicationTargets(args.context.configs.network.chains).map(
          (target) => ({ curve: 'ecdsa' as const, chainTarget: target.chainTarget }),
        )
      : []),
  ];
  const runtimePostconditionsPromise =
    requiredTargets.length === 0
      ? Promise.resolve()
      : assertWalletRuntimePostconditions({
          source: 'wallet_unlock',
          walletId: String(args.walletIdentity.walletId),
          authMethod: 'passkey',
          requiredTargets,
          readPersistedAvailableSigningLanes: async (input) =>
            await args.context.signingEngine.readPersistedAvailableSigningLanes(input),
        });
  const [signingSessionStatus] = await Promise.all([
    ed25519StatusPromise,
    runtimePostconditionsPromise,
  ]);
  if (args.signersWarmed.includes('ed25519') && signingSessionStatus?.status !== 'active') {
    throw new Error(
      `[login] Ed25519 warm-session authorization postcondition failed: ${
        signingSessionStatus?.status || 'missing'
      }`,
    );
  }
}

function normalizeLoginUnlockAccountSubject(args: {
  userData: ClientUserData;
  walletId: WalletId;
  nearAccountId: AccountId;
}): LoginUnlockAccountSubject {
  if (String(args.userData.walletId) !== String(args.walletId)) {
    throw new Error('[login] NEAR account projection belongs to a different wallet');
  }
  const operationalPublicKey =
    typeof args.userData.operationalPublicKey === 'string'
      ? args.userData.operationalPublicKey.trim()
      : '';
  if (operationalPublicKey) {
    return {
      kind: 'near_operational_signer',
      userData: args.userData,
      operationalPublicKey,
      walletId: args.walletId,
    };
  }
  throw new Error(
    `No NEAR operational key found for ${args.nearAccountId}. Please register an account.`,
  );
}

async function readNearLoginUnlockAccountPhase(args: {
  signingEngine: UserAccountLookupSurface;
  identity: ResolvedLoginWalletBinding;
  signerSlotHint: number | null;
  onEvent?: LoginHooksOptions['onEvent'];
}): Promise<LoginUnlockAccountPhase> {
  emitUnlockEvent(args.onEvent, String(args.identity.nearAccountId), {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED,
    status: 'running',
    authMethod: 'passkey',
  });

  const hintUserPromise: Promise<ClientUserData | null> =
    args.signerSlotHint !== null
      ? args.signingEngine
          .getUserBySignerSlot(args.identity.nearAccountId, args.signerSlotHint)
          .catch(() => null)
      : Promise.resolve(null);

  const [hintUser, lastUser, latestByAccount, authenticators] = await Promise.all([
    hintUserPromise,
    args.signingEngine.getLastUser().catch(() => null),
    getNearAccountProjection(IndexedDBManager, args.identity.nearAccountId).catch(() => null),
    args.signingEngine.nearAuthenticatorsByAccount(args.identity.nearAccountId).catch(() => []),
  ]);

  if (authenticators.length === 0) {
    throw new Error(
      `No authenticators found for account ${args.identity.nearAccountId}. Please register an account.`,
    );
  }

  let userData: ClientUserData | null = null;
  if (hintUser && hintUser.nearAccountId === args.identity.nearAccountId) {
    userData = hintUser;
  } else if (latestByAccount && latestByAccount.nearAccountId === args.identity.nearAccountId) {
    userData = latestByAccount;
  } else if (lastUser && lastUser.nearAccountId === args.identity.nearAccountId) {
    userData = lastUser;
  } else {
    userData = await args.signingEngine
      .getUserBySignerSlot(args.identity.nearAccountId, 1)
      .catch(() => null);
  }

  if (!userData) {
    throw new Error(
      `User data not found for ${args.identity.nearAccountId} in IndexedDB. Please register an account.`,
    );
  }
  const accountSubject = normalizeLoginUnlockAccountSubject({
    userData,
    walletId: args.identity.walletId,
    nearAccountId: args.identity.nearAccountId,
  });

  emitUnlockEvent(args.onEvent, String(args.identity.nearAccountId), {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED,
    status: 'succeeded',
    authMethod: 'passkey',
    data: {
      signerSlot: userData.signerSlot,
      ...(accountSubject.operationalPublicKey
        ? { operationalPublicKey: accountSubject.operationalPublicKey }
        : { walletKind: accountSubject.kind }),
    },
  });

  const persistedSignerSlot = parseSignerSlot(userData.signerSlot, { min: 1 });
  const baseSignerSlot = args.signerSlotHint ?? persistedSignerSlot;
  if (baseSignerSlot === null) {
    throw new Error('[login] wallet signer projection is missing its exact signerSlot');
  }
  const localUnlockAuthMethod = userData.authMethod;
  if (
    localUnlockAuthMethod !== SIGNER_AUTH_METHODS.passkey &&
    localUnlockAuthMethod !== SIGNER_AUTH_METHODS.emailOtp
  ) {
    throw new Error('[login] wallet signer projection is missing a valid authMethod');
  }
  return {
    kind: 'login_unlock_account_phase_ready',
    accountSubject,
    authenticators,
    baseSignerSlot,
    localUnlockAuthMethod,
    requiresLocalPasskeyUnlock: localUnlockAuthMethod === SIGNER_AUTH_METHODS.passkey,
  };
}

async function readEcdsaLoginUnlockAccountPhase(args: {
  identity: ResolvedLoginEcdsaOnlyWallet;
  signerSlotHint: number | null;
  onEvent?: LoginHooksOptions['onEvent'];
}): Promise<LoginUnlockAccountPhase> {
  const unlockSubjectId = String(args.identity.walletId);
  emitUnlockEvent(args.onEvent, unlockSubjectId, {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED,
    status: 'running',
    authMethod: 'passkey',
  });
  const [profile, authenticators, authMethods] = await Promise.all([
    IndexedDBManager.getProfile(unlockSubjectId),
    IndexedDBManager.listWalletPasskeyAuthenticators(unlockSubjectId),
    IndexedDBManager.listWalletAuthMethodsForWallet(unlockSubjectId),
  ]);
  if (!profile || authenticators.length === 0) {
    throw new Error(`[login] ECDSA wallet ${unlockSubjectId} has no local passkey profile`);
  }
  const activePasskeyCredentialIds = new Set<string>();
  for (const method of authMethods) {
    if (method.kind === 'passkey' && method.status === 'active') {
      activePasskeyCredentialIds.add(method.credentialIdB64u);
    }
  }
  const eligibleAuthenticators: LoginPasskeyAuthenticator[] = [];
  for (const authenticator of authenticators) {
    if (activePasskeyCredentialIds.has(authenticator.credentialId)) {
      eligibleAuthenticators.push(authenticator);
    }
  }
  if (eligibleAuthenticators.length === 0) {
    throw new Error(`[login] ECDSA wallet ${unlockSubjectId} has no active passkey binding`);
  }
  const persistedSignerSlot = parseSignerSlot(profile.defaultSignerSlot, { min: 1 });
  const baseSignerSlot = args.signerSlotHint ?? persistedSignerSlot;
  if (baseSignerSlot === null) {
    throw new Error('[login] ECDSA wallet profile is missing its exact signerSlot');
  }
  emitUnlockEvent(args.onEvent, unlockSubjectId, {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED,
    status: 'succeeded',
    authMethod: 'passkey',
    data: {
      signerSlot: baseSignerSlot,
      walletKind: 'ecdsa_wallet_only',
    },
  });
  return {
    kind: 'login_unlock_account_phase_ready',
    accountSubject: {
      kind: 'ecdsa_wallet_only',
      walletId: args.identity.walletId,
      operationalPublicKey: null,
    },
    authenticators: eligibleAuthenticators,
    baseSignerSlot,
    localUnlockAuthMethod: SIGNER_AUTH_METHODS.passkey,
    requiresLocalPasskeyUnlock: true,
  };
}

async function readLoginUnlockAccountPhase(args: {
  signingEngine: UserAccountLookupSurface;
  identity: ResolvedLoginWalletIdentity;
  signerSlotHint: number | null;
  onEvent?: LoginHooksOptions['onEvent'];
}): Promise<LoginUnlockAccountPhase> {
  switch (args.identity.kind) {
    case 'near_ed25519_capable_wallet':
      return await readNearLoginUnlockAccountPhase({
        signingEngine: args.signingEngine,
        identity: args.identity,
        signerSlotHint: args.signerSlotHint,
        onEvent: args.onEvent,
      });
    case 'evm_family_ecdsa_only_wallet':
      return await readEcdsaLoginUnlockAccountPhase({
        identity: args.identity,
        signerSlotHint: args.signerSlotHint,
        onEvent: args.onEvent,
      });
  }
  return assertNeverLoginState(args.identity);
}

function buildSuccessfulLoginResult(args: {
  identity: ResolvedLoginWalletIdentity;
  accountSubject: LoginUnlockAccountSubject;
  jwt: string;
}): Extract<LoginResult, { success: true }> {
  switch (args.identity.kind) {
    case 'near_ed25519_capable_wallet':
      if (args.accountSubject.kind !== 'near_operational_signer') {
        throw new Error('[login] NEAR unlock returned an ECDSA-only account subject');
      }
      return {
        success: true,
        kind: 'near_wallet_unlocked',
        walletId: args.identity.walletId,
        loggedInNearAccountId: String(args.identity.nearAccountId),
        operationalPublicKey: args.accountSubject.operationalPublicKey,
        nearAccountId: args.identity.nearAccountId,
        ...(args.jwt ? { jwt: args.jwt } : {}),
      };
    case 'evm_family_ecdsa_only_wallet':
      if (args.accountSubject.kind !== 'ecdsa_wallet_only') {
        throw new Error('[login] ECDSA-only unlock returned a NEAR account subject');
      }
      return {
        success: true,
        kind: 'ecdsa_wallet_unlocked',
        walletId: args.identity.walletId,
        ...(args.jwt ? { jwt: args.jwt } : {}),
      };
  }
  return assertNeverLoginState(args.identity);
}

/**
 * Core login function (passkey identity + Router API-issued sessions).
 *
 * Responsibilities:
 * - Select the active account + signer slot (last-user pointer).
 * - Optionally mint a Router API app session (JWT/cookie) via session exchange.
 *
 * Note: signing flows still perform their own UserConfirm/WebAuthn prompting as needed.
 */
export async function unlock(
  context: LoginWebContext,
  nearAccountId: AccountId,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  const lastUser = await context.signingEngine.getLastUser();
  if (!lastUser || String(lastUser.nearAccountId) !== String(nearAccountId)) {
    throw new Error('[login] NEAR unlock requires the active wallet binding');
  }
  const selection = resolveLoginWalletUnlockSelection(options?.unlockSelection);
  const subjectSet = await resolveWalletUnlockSubjectSet({
    walletId: String(lastUser.walletId),
    requestedCapabilityFamilies:
      selection.mode === 'ed25519_only'
        ? { kind: 'near_ed25519_only' }
        : selection.mode === 'ecdsa_only'
          ? { kind: 'evm_family_ecdsa_only' }
          : { kind: 'all_registered_mpc' },
  });
  if (subjectSet.kind !== 'resolved') {
    throw new Error(`[login] wallet unlock subject resolution failed: ${subjectSet.kind}`);
  }
  return await unlockInternal(context, subjectSet.subjectSet, options);
}

export async function unlockResolvedWalletSubjectSet(
  context: LoginWebContext,
  subjectSet: WalletUnlockSubjectSet,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  return await unlockInternal(context, subjectSet, options);
}

async function unlockInternal(
  context: LoginWebContext,
  subjectSet: WalletUnlockSubjectSet,
  options: LoginHooksOptions | undefined,
): Promise<LoginAndCreateSessionResult> {
  const { onEvent, onError, afterCall } = options || {};
  const { signingEngine } = context;
  const walletUnlockSelection = resolveLoginWalletUnlockSelectionForSubjectSet({
    selection: options?.unlockSelection,
    subjectSet,
  });
  const walletIdentity = resolveLoginWalletIdentity({
    subjectSet,
    selection: walletUnlockSelection,
  });
  const unlockSubjectId =
    walletIdentity.kind === 'near_ed25519_capable_wallet'
      ? String(walletIdentity.nearAccountId)
      : String(walletIdentity.walletId);
  let loginCredential: WebAuthnAuthenticationCredential | undefined;

  // All unlock branches emit the same ordered event stream for caller progress UIs.
  emitUnlockEvent(onEvent, unlockSubjectId, {
    phase: UnlockEventPhase.STEP_01_STARTED,
    status: 'started',
    authMethod: 'passkey',
  });

  // Keep error normalization in one place so hooks and events behave consistently.
  try {
    // Best-effort parity check: stale sealed refresh state should not block the passkey prompt.
    void signingEngine.assertSealedRefreshStartupParity().catch((error: unknown) => {
      console.warn(
        '[login] sealed refresh startup parity check failed during unlock; continuing to local passkey prompt',
        error instanceof Error ? error.message : String(error || 'unknown error'),
      );
    });

    // WebAuthn fails outside secure contexts, so fail before any account mutation.
    if (typeof window !== 'undefined' && !window.isSecureContext) {
      const errorMessage = 'Passkey operations require a secure context (HTTPS or localhost).';
      return await finalizeLoginError({
        unlockSubjectId,
        message: errorMessage,
        error: new Error(errorMessage),
        onEvent,
        onError,
        afterCall,
        callAfterCall: false,
      });
    }

    // Resolve the account subject and authenticator allow-list once for every later prompt.
    const signerSlotHint = parseSignerSlot(options?.signerSlot, { min: 1 });
    const accountPhase = await readLoginUnlockAccountPhase({
      signingEngine,
      identity: walletIdentity,
      signerSlotHint,
      onEvent,
    });
    const {
      accountSubject,
      authenticators,
      baseSignerSlot,
      localUnlockAuthMethod,
      requiresLocalPasskeyUnlock,
    } = accountPhase;

    // Shared prompt wrapper used by local unlock, app-session exchange, and inventory repair.
    const collectLocalPasskeyCredentialForChallenge = async (args: {
      challengeB64u: string;
      saveAsLoginCredential: boolean;
      credentialIds: readonly string[] | null;
    }): Promise<WebAuthnAuthenticationCredential> => {
      const eligibleAuthenticators = authenticatorsForCredentialIds({
        authenticators,
        credentialIds: args.credentialIds,
      });
      const credential = await collectPasskeyLoginAssertion({
        signingEngine,
        subjectId: unlockSubjectId,
        challengeB64u: args.challengeB64u,
        authenticators: eligibleAuthenticators,
        onPromptStarted: () => {
          emitUnlockEvent(onEvent, unlockSubjectId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
            status: 'waiting_for_user',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'show',
            },
          });
        },
        onPromptSucceeded: () => {
          emitUnlockEvent(onEvent, unlockSubjectId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED,
            status: 'succeeded',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'hide',
            },
          });
        },
      });
      if (args.saveAsLoginCredential) {
        loginCredential = credential;
      }
      return credential;
    };

    // Local unlock asks for a fresh assertion only when no earlier branch produced one.
    const collectFreshLocalPasskeyUnlockCredentialForLogin = async (): Promise<void> => {
      const credential = await collectFreshLocalPasskeyUnlockCredential({
        currentCredential: loginCredential,
        collectCredentialForChallenge: async (challengeB64u) =>
          await collectLocalPasskeyCredentialForChallenge({
            challengeB64u,
            saveAsLoginCredential: true,
            credentialIds: resolveLoginPasskeyPromptCredentialIds({
              authenticators,
              signerSlot: baseSignerSlot,
              serverCredentialIds: [],
            }),
          }),
      });
      if (credential) loginCredential = credential;
    };

    // Warm-session policy controls whether unlock also primes threshold signing lanes.
    const signingSessionPolicy = (() => {
      const ttlMsRaw =
        options?.signingSession?.ttlMs ?? context.configs?.signing.sessionDefaults?.ttlMs;
      const configuredRemainingUses = options?.signingSession?.remainingUses;
      const defaultRemainingUses = context.configs?.signing.sessionDefaults?.remainingUses;
      const requestedRemainingUses =
        configuredRemainingUses ?? defaultRemainingUses ?? DEFAULT_UNLOCK_REMAINING_USES;
      const ttlMs =
        typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
      const unlockRemainingUses = resolveWalletUnlockSessionUsesFromRequestedUses({
        requestedRemainingUses,
      });
      return {
        ttlMs: Math.max(0, ttlMs),
        unlockRemainingUses,
      };
    })();

    // Updated by warmup branches, then copied into the public result.
    let signingSession: LoginAndCreateSessionResult['signingSession'] | undefined;
    // Warm sessions are enabled when the unlock policy has remaining uses.
    const shouldWarmThresholdSigningSession =
      signingSessionPolicy.ttlMs > 0 && signingSessionPolicy.unlockRemainingUses != null;
    const requireThresholdWarmup = shouldWarmThresholdSigningSession;
    const thresholdKeyMaterialPrefetch =
      requireThresholdWarmup && walletIdentity.kind === 'near_ed25519_capable_wallet'
        ? getNearThresholdKeyMaterial(
            {
              clientDB: IndexedDBManager,
              keyMaterialStore: IndexedDBManager,
            },
            walletIdentity.nearAccountId,
            baseSignerSlot,
          ).catch(() => null)
        : Promise.resolve(null);
    let preparedPasskeyExchangeEcdsaActivation: PreparedPasskeyExchangeEcdsaActivation | null =
      null;
    let completedPasskeyExchangeEcdsaActivation: CompletedPasskeyExchangeEcdsaActivation | null =
      null;
    let completedPasskeySessionCustody: PasskeySessionCustodyUnlockV1 | null = null;
    const session = options?.session;
    const wantsServerSession = session !== undefined;
    let localWarmupRouteAuthorization = resolveLoginWarmupRouteAuthorization({
      appSessionJwt: '',
      useAppSessionCookie: false,
    });

    // Warmup callers use this after side effects to turn a missing session into a clear error.
    const requireActiveWarmSession = (
      source: string,
      sessionStatus: SigningSessionStatus | null | undefined = signingSession,
    ): ThresholdWarmLoginAndCreateSessionResult['signingSession'] => {
      if (isActiveThresholdLoginSigningSession(sessionStatus)) {
        return sessionStatus;
      }
      const status = String(sessionStatus?.status || 'not_found');
      throw new Error(
        `[login] ${source} did not produce an active warm signing session (status=${status})`,
      );
    };

    // Threshold warmup depends on any passkey assertion collected earlier in this unlock.
    const warmThresholdSigningSessions = async (
      warmupInput: ThresholdLoginWarmupPhaseInput,
    ): Promise<ThresholdLoginWarmupPhaseResult> => {
      emitUnlockEvent(onEvent, unlockSubjectId, {
        phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
        status: 'running',
        authMethod: loginCredential ? 'passkey' : 'warm_session',
      });

      // Ed25519 warmup needs stored NEAR threshold key material; ECDSA-only unlock can skip it.
      const nearWalletBinding = warmupInput.wantsEd25519Warmup
        ? requireNearLoginWalletBinding(walletIdentity)
        : null;
      const managedRuntimeScopeBootstrap = resolveManagedRuntimeScopeBootstrap(context.configs);
      let volatileWarmMaterialCleared = false;
      const clearVolatileWarmMaterialForUnlock = async (): Promise<void> => {
        if (volatileWarmMaterialCleared) return;
        volatileWarmMaterialCleared = true;
        await signingEngine.clearVolatileWarmSigningMaterial(walletIdentity.walletId);
      };

      if (warmupInput.wantsEcdsaWarmup) {
        const reconciliation = await reconcileCanonicalEcdsaActivationSelectors({
          workerCtx: signingEngine.getSignerWorkerContext(),
          selectors: ecdsaActivationSelectorsFromSubjectSet(walletIdentity.subjectSet),
        });
        reportNonSettledEcdsaActivationReconciliation(reconciliation);
      }

      // Resolve local ECDSA key facts before planning; authenticated inventory can repair gaps.
      const storedCanonicalEcdsaContext = await resolveCanonicalThresholdEcdsaWarmSessionContext(
        context,
        walletIdentity.walletId,
        {
          keyFactsInventoryAuthority: warmupInput.keyFactsInventoryAuthority,
          keyFactsInventoryRequested: Boolean(options?.ecdsaKeyFactsInventory),
          relayerUrl: warmupInput.relayerUrl,
          rpId: warmupInput.rpId,
          collectWebAuthnInventoryCredential: async (challengeB64u) =>
            await collectLocalPasskeyCredentialForChallenge({
              challengeB64u,
              saveAsLoginCredential: true,
              credentialIds: null,
            }),
        },
      );
      const thresholdKeyMaterial = await thresholdKeyMaterialPrefetch;
      if (nearWalletBinding && !thresholdKeyMaterial) {
        throw new Error(
          `[login] threshold warm-up requires threshold key material for ${nearWalletBinding.nearAccountId} signer slot ${warmupInput.signerSlot}`,
        );
      }
      const participantIds =
        thresholdKeyMaterial?.participants.map((participant) => participant.id) || [];
      if (warmupInput.wantsEcdsaWarmup) {
        assertEcdsaWarmupMatchesUnlockSubjects({
          identity: walletIdentity,
          context: storedCanonicalEcdsaContext,
        });
      }
      const ecdsaTargetCompletion = buildConfiguredTargetKeyCompletion({
        context: storedCanonicalEcdsaContext,
        configuredTargets: warmupInput.selectedEcdsaTargets,
      });
      const canFirstBootstrapThresholdEcdsa = Boolean(managedRuntimeScopeBootstrap);

      // The plan decides which signers warm, and whether Ed25519/ECDSA depends on the other.
      const warmupPlan = resolveThresholdLoginWarmupPlan({
        selection: warmupInput.selection,
        selectedEcdsaTargets: warmupInput.selectedEcdsaTargets,
        storedCanonicalEcdsaContext,
        canFirstBootstrapThresholdEcdsa,
        wantsEd25519Warmup: warmupInput.wantsEd25519Warmup,
      });
      const combinedEd25519EcdsaWarmup =
        warmupPlan.signersToWarm.includes('ed25519') && warmupPlan.signersToWarm.includes('ecdsa');
      const passkeyExchangeEcdsaActivationForWarmup = combinedEd25519EcdsaWarmup
        ? null
        : completedPasskeyExchangeEcdsaActivation;
      const passkeyExchangeOwnsFirstEcdsaActivation = Boolean(
        passkeyExchangeEcdsaActivationForWarmup && warmupPlan.signersToWarm.includes('ecdsa'),
      );
      const ed25519DependsOnEcdsa = passkeyExchangeOwnsFirstEcdsaActivation
        ? warmupPlan.signersToWarm.includes('ed25519')
        : warmupPlan.ed25519DependsOnEcdsa;
      const ecdsaDependsOnEd25519 = passkeyExchangeOwnsFirstEcdsaActivation
        ? false
        : warmupPlan.ecdsaDependsOnEd25519;

      // Decide which branch owns the WebAuthn assertion used by warmup.
      const warmupPasskeyCredentialPlan = resolveLoginWarmupPasskeyCredentialPlan({
        requiresLocalPasskeyUnlock,
        hasLoginCredential: Boolean(loginCredential),
        routeAuthorization: warmupInput.routeAuthorization,
        warmupPlan,
      });

      // Clear old volatile material after reading durable facts, before minting new sessions.
      await clearVolatileWarmMaterialForUnlock();

      // Describe how Ed25519 should be minted so the runner receives one precise state.
      const plannedEd25519SessionId = createThresholdLoginWarmSessionId('threshold-login');
      let ed25519MintPlan: LoginWarmupEd25519MintPlan = !warmupPlan.signersToWarm.includes(
        'ed25519',
      )
        ? { kind: 'not_requested' }
        : ed25519DependsOnEcdsa
          ? {
              kind: 'ecdsa_authorized',
              thresholdSessionId: plannedEd25519SessionId,
            }
          : {
              kind: 'fresh',
            };
      switch (warmupPasskeyCredentialPlan.kind) {
        case 'existing_passkey_credential':
        case 'app_session_authorized_warmup':
        case 'no_passkey_credential_required':
          break;
        case 'wallet_custody': {
          if (warmupInput.ed25519SessionAuthority.kind !== 'passkey') {
            throw new Error('[login] wallet custody requires passkey wallet authority');
          }
          if (!completedPasskeySessionCustody || completedPasskeySessionCustody.ed25519.kind !== 'active') {
            throw createThresholdEd25519DeviceLinkRequiredError();
          }
          ed25519MintPlan = {
            kind: 'wallet_custody',
            custody: {
              ...completedPasskeySessionCustody,
              ed25519: completedPasskeySessionCustody.ed25519,
            },
          };
          break;
        }
        case 'local_unlock_passkey_assertion_after_ecdsa_context':
          await collectFreshLocalPasskeyUnlockCredentialForLogin();
          break;
        default:
          return assertNeverLoginState(warmupPasskeyCredentialPlan);
      }

      // Passkey ID can come from the fresh assertion or stored account authenticators.
      const localPasskeyCredentialIdB64u = String(
        loginCredential?.rawId ||
          loginCredential?.id ||
          authenticators.find((authenticator) => authenticator.signerSlot === baseSignerSlot)
            ?.credentialId ||
          authenticators[0]?.credentialId ||
          '',
      ).trim();
      const credentialState: LoginWarmupCredentialState = loginCredential
        ? {
            kind: 'available',
            credential: loginCredential,
            localPasskeyCredentialIdB64u,
          }
        : localPasskeyCredentialIdB64u
          ? {
              kind: 'credential_id_only',
              localPasskeyCredentialIdB64u,
            }
          : {
              kind: 'unavailable',
              localPasskeyCredentialIdB64u: '',
            };

      const runtimeScopeBootstrapState: LoginWarmupRuntimeScopeBootstrapState =
        managedRuntimeScopeBootstrap
          ? {
              kind: 'available',
              runtimeScopeBootstrap: managedRuntimeScopeBootstrap,
            }
          : {
              kind: 'unavailable',
            };

      // Run Ed25519/ECDSA warmup and then derive the public signing-session status.
      const warmupResult = await primeThresholdLoginWarmSigners({
        context,
        signingEngine,
        walletIdentity,
        signerSlot: warmupInput.signerSlot,
        thresholdKeyMaterial,
        relayerUrl: warmupInput.relayerUrl,
        relayerKeyId: thresholdKeyMaterial?.relayerKeyId || '',
        participantIds,
        ttlMs: signingSessionPolicy.ttlMs,
        unlockRemainingUses: requireLoginUnlockSessionUses(
          signingSessionPolicy.unlockRemainingUses,
        ),
        ecdsaContextResolution: warmupPlan.ecdsaContextResolution,
        credentialState,
        runtimeScopeBootstrapState,
        signersToWarm: warmupPlan.signersToWarm,
        ed25519DependsOnEcdsa,
        ecdsaDependency: ecdsaDependsOnEd25519
          ? { kind: 'ed25519_wallet_session_authority' }
          : { kind: 'none' },
        ed25519MintPlan,
        ed25519SessionAuthority: warmupInput.ed25519SessionAuthority,
        authMethod: localUnlockAuthMethod,
        routeAuthorization: warmupInput.routeAuthorization,
        passkeyExchangeEcdsaActivation: passkeyExchangeEcdsaActivationForWarmup,
      });

      // Successful provisioning has already sealed and activated the exact Ed25519 session.
      if (warmupPlan.signersToWarm.includes('ed25519')) {
        const ed25519Session = warmupResult.ed25519Session;
        if (!ed25519Session) {
          throw new Error('[login] threshold warm-up omitted the Ed25519 session result');
        }
        signingSession = createActiveLoginSigningSessionStatus({
          session: ed25519Session,
          authMethod: localUnlockAuthMethod,
        });
      }
      const activeSigningSession = requireActiveWarmSession('threshold warm-up');

      // Emit lane-specific events after active-session validation succeeds.
      if (warmupPlan.signersToWarm.includes('ed25519')) {
        emitUnlockEvent(onEvent, unlockSubjectId, {
          phase: UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
      }
      if (warmupPlan.signersToWarm.includes('ecdsa')) {
        emitUnlockEvent(onEvent, unlockSubjectId, {
          phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
      }

      return {
        kind: 'threshold_login_warmup_ready',
        signingSession: activeSigningSession,
        signersWarmed: warmupPlan.signersToWarm,
      };
    };

    // Public results for required warmup must contain an active signing session.
    const requireThresholdWarmLoginBundle = (
      source: string,
    ): Pick<ThresholdWarmLoginAndCreateSessionResult, 'signingSession'> => {
      const activeSigningSession = requireActiveWarmSession(source);
      return {
        signingSession: activeSigningSession,
      };
    };

    // Login persistence is intentionally after auth and warmup side effects succeed.
    //
    // A NEAR-capable wallet has TWO profile records: the wallet profile and the
    // NEAR account projection. setLastUser writes the last-user pointer against
    // the WALLET profile, but getLastLoggedInSignerSlot — which NEAR signing
    // resolves its signer slot through — reads it against the projection, and
    // throws "No last user session for account <id>" when they disagree.
    // Registration never hit this because it activates through
    // activateAuthenticatedWalletState, which writes the projection. Unlock has
    // to do the same, or signing works only in the session where the wallet was
    // registered. Warmup cannot repair it either: it derives its signerSlot from
    // the very read that is failing, so it skips activation exactly when the
    // pointer is missing.
    const persistSuccessfulLoginState = async (signerSlot: number): Promise<void> => {
      await signingEngine.setLastUser(walletIdentity.walletId, signerSlot);
      if (walletIdentity.kind !== 'near_ed25519_capable_wallet') return;
      await signingEngine.activateAuthenticatedWalletState({
        walletId: walletIdentity.walletId,
        nearAccountId: toAccountId(walletIdentity.nearAccountId),
        signerSlot,
        nearClient: context.nearClient,
      });
    };

    // Nonce recovery is best-effort; stale lane leases should not fail login.
    const recoverNonceLanesAfterUnlock = async (): Promise<void> => {
      await signingEngine
        .getNonceCoordinator()
        .recoverDurableLeases({ walletId: walletIdentity.walletId })
        .catch((error: unknown) => {
          console.warn('[login] nonce lane durable recovery after unlock failed', error);
        });
    };

    // Server-session flow: exchange OIDC/passkey proof, optionally warm lanes, then return.
    if (wantsServerSession) {
      const relayUrl = (session?.relayUrl || context.configs.network.relayer.url).trim();
      if (!relayUrl) {
        throw new Error('Missing relayUrl for session-style login');
      }

      const exchange = session?.exchange;
      if (exchange?.type === 'oidc_jwt' || exchange?.type === 'passkey_assertion') {
        const exchangeRoute = (session?.route || '/session/exchange').trim();
        const exchangePath = exchangeRoute.startsWith('/') ? exchangeRoute : `/${exchangeRoute}`;
        let exchanged: Awaited<ReturnType<typeof exchangeSession>>;

        // Build the exact proof the Router API expects for this exchange mode.
        if (exchange.type === 'oidc_jwt') {
          // OIDC exchange uses the caller-provided token directly.
          const exchangeInput: SessionExchangeInput = {
            type: 'oidc_jwt',
            token: exchange.token,
          };
          emitUnlockEvent(onEvent, unlockSubjectId, {
            phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
            status: 'running',
          });
          exchanged = await exchangeSession(
            relayUrl,
            exchangePath,
            session.kind,
            exchangeInput,
            resolveSessionExchangeRuntimeScope(context),
          );
        } else {
          const rpId = String(signingEngine.getRpId() || '').trim();
          if (!rpId) {
            throw new Error('Missing rpId for passkey_assertion session exchange');
          }

          preparedPasskeyExchangeEcdsaActivation =
            requireThresholdWarmup && walletUnlockSelection.mode === 'ecdsa_only'
              ? await preparePasskeyExchangeEcdsaActivation({
                  context,
                  walletIdentity,
                  selection: walletUnlockSelection,
                  ttlMs: signingSessionPolicy.ttlMs,
                  remainingUses: requireLoginUnlockSessionUses(
                    signingSessionPolicy.unlockRemainingUses,
                  ),
                })
              : null;
          const completedExchange = await completePasskeySessionExchange({
            context,
            walletIdentity,
            unlockSubjectId,
            onEvent,
            authenticators,
            signerSlot: baseSignerSlot,
            relayUrl,
            exchangePath,
            sessionKind: session.kind,
            rpId,
            expectedOrigin: exchange.expectedOrigin ?? exchange.expected_origin,
            activation: preparedPasskeyExchangeEcdsaActivation,
            collectCredentialForChallenge: async (challenge) =>
              await collectLocalPasskeyCredentialForChallenge({
                challengeB64u: challenge.challengeB64u,
                saveAsLoginCredential: true,
                credentialIds: challenge.credentialIds,
              }),
          });
          loginCredential = completedExchange.credential;
          completedPasskeyExchangeEcdsaActivation = completedExchange.activation;
          completedPasskeySessionCustody = completedExchange.custody;
          rememberPasskeySessionCustodyForExport({
            walletId: String(walletIdentity.walletId),
            exchange: completedExchange,
          });
          exchanged = completedExchange.result;
        }
        if (!exchanged.success) {
          throw new Error(exchanged.error || 'Session exchange failed');
        }

        emitUnlockEvent(onEvent, unlockSubjectId, {
          phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
          authMethod: loginCredential ? 'passkey' : undefined,
        });

        // App-session auth can authorize warmup and key-facts inventory in the same unlock.
        if (requireThresholdWarmup) {
          const authMethodBinding = await readThresholdWarmupAuthMethodBinding({
            walletId: walletIdentity.walletId,
            authMethod: localUnlockAuthMethod,
          });
          const warmupPhase = await warmThresholdSigningSessions(
            resolveThresholdLoginWarmupPhaseInput({
              context,
              signerSlot: baseSignerSlot,
              authenticators,
              selection: walletUnlockSelection,
              subjectSet: walletIdentity.subjectSet,
              authMethod: localUnlockAuthMethod,
              authMethodBinding,
              keyFactsInventoryRequest: options?.ecdsaKeyFactsInventory,
              routeAuthorization: resolveLoginWarmupRouteAuthorization({
                appSessionJwt: String(exchanged.jwt || ''),
                useAppSessionCookie: session.kind === 'cookie' && !!loginCredential,
              }),
            }),
          );
          signingSession = warmupPhase.signingSession;
          await assertPasskeyUnlockRuntimePostconditions({
            context,
            walletIdentity,
            signersWarmed: warmupPhase.signersWarmed,
          });
        }

        // Account state is part of login durability. Nonce cleanup is lane-locked and
        // best-effort, so it can continue after the wallet becomes usable.
        await persistSuccessfulLoginState(baseSignerSlot);
        void recoverNonceLanesAfterUnlock();

        emitUnlockEvent(onEvent, unlockSubjectId, {
          phase: UnlockEventPhase.STEP_06_SESSION_READY,
          status: 'succeeded',
          authMethod: loginCredential ? 'passkey' : undefined,
        });

        // Shape the public result once all optional warmup requirements have passed.
        const loginResult = buildSuccessfulLoginResult({
          identity: walletIdentity,
          accountSubject,
          jwt: String(exchanged.jwt || '').trim(),
        });

        const enrichedLoginResult: LoginAndCreateSessionResult = requireThresholdWarmup
          ? {
              ...loginResult,
              ...requireThresholdWarmLoginBundle('login'),
            }
          : {
              ...loginResult,
              ...(signingSession ? { signingSession } : {}),
            };
        return await finalizeLoginSuccess({
          context,
          authMethod: localUnlockAuthMethod,
          unlockSubjectId,
          loginResult: enrichedLoginResult,
          onEvent,
          afterCall,
        });
      }

      // Session login needs a supported exchange shape for app-session issuance.
      const requestedRouteRaw = (session?.route || '').trim();
      const requestedRoute = requestedRouteRaw
        ? requestedRouteRaw.startsWith('/')
          ? requestedRouteRaw
          : `/${requestedRouteRaw}`
        : '';
      if (!exchange && (!requestedRoute || requestedRoute === '/session/exchange')) {
        throw new Error(
          'session.exchange is required when session.route targets /session/exchange',
        );
      }
      if (!exchange) {
        throw new Error('session.exchange is required for server session issuance');
      }
      throw new Error('session.exchange.type must be one of: oidc_jwt, passkey_assertion');
    }

    // Avoid a duplicate prompt when threshold warmup will collect the assertion itself.
    const noServerSessionPasskeyCredentialPlan = resolveLoginNoServerSessionPasskeyCredentialPlan({
      requiresLocalPasskeyUnlock,
      requireThresholdWarmup,
      hasLoginCredential: Boolean(loginCredential),
    });
    switch (noServerSessionPasskeyCredentialPlan.kind) {
      case 'warmup_phase_owns_passkey_credential':
      case 'passkey_credential_already_collected':
      case 'no_local_passkey_required':
        break;
      case 'local_unlock_passkey_assertion':
        await collectFreshLocalPasskeyUnlockCredentialForLogin();
        break;
      default:
        return assertNeverLoginState(noServerSessionPasskeyCredentialPlan);
    }

    // ECDSA-only unlock consumes exchange activation directly. Combined unlock mints
    // its shared authority during Ed25519-first warm-up and avoids duplicate activation.
    let didPerformPasskeySessionExchange = false;
    if (
      requireThresholdWarmup &&
      localUnlockAuthMethod === SIGNER_AUTH_METHODS.passkey &&
      (walletUnlockSelection.mode === 'ecdsa_only' ||
        walletIdentity.kind === 'near_ed25519_capable_wallet')
    ) {
      const preparedActivation =
        walletUnlockSelection.mode === 'ecdsa_only'
          ? await preparePasskeyExchangeEcdsaActivation({
              context,
              walletIdentity,
              selection: walletUnlockSelection,
              ttlMs: signingSessionPolicy.ttlMs,
              remainingUses: requireLoginUnlockSessionUses(
                signingSessionPolicy.unlockRemainingUses,
              ),
            })
          : null;
      if (preparedActivation || walletIdentity.kind === 'near_ed25519_capable_wallet') {
        const relayUrl = String(context.configs.network.relayer.url || '').trim();
        const rpId = String(signingEngine.getRpId() || '').trim();
        if (!relayUrl || !rpId) {
          throw new Error('[login] passkey ECDSA activation requires relayer URL and rpId');
        }
        const completedExchange = await completePasskeySessionExchange({
          context,
          walletIdentity,
          unlockSubjectId,
          onEvent,
          authenticators,
          signerSlot: baseSignerSlot,
          relayUrl,
          exchangePath: '/session/exchange',
          sessionKind: 'jwt',
          rpId,
          expectedOrigin: undefined,
          activation: preparedActivation,
          collectCredentialForChallenge: async (challenge) =>
            await collectLocalPasskeyCredentialForChallenge({
              challengeB64u: challenge.challengeB64u,
              saveAsLoginCredential: true,
              credentialIds: challenge.credentialIds,
            }),
        });
        loginCredential = completedExchange.credential;
        completedPasskeyExchangeEcdsaActivation = completedExchange.activation;
        completedPasskeySessionCustody = completedExchange.custody;
        rememberPasskeySessionCustodyForExport({
          walletId: String(walletIdentity.walletId),
          exchange: completedExchange,
        });
        didPerformPasskeySessionExchange = true;
        emitUnlockEvent(onEvent, unlockSubjectId, {
          phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
          authMethod: 'passkey',
        });
        if (completedExchange.result.success && completedExchange.result.jwt) {
          localWarmupRouteAuthorization = resolveLoginWarmupRouteAuthorization({
            appSessionJwt: completedExchange.result.jwt,
            useAppSessionCookie: false,
          });
        }
      }
    }

    if (!didPerformPasskeySessionExchange) {
      emitUnlockEvent(onEvent, unlockSubjectId, {
        phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SKIPPED,
        status: 'skipped',
      });
    }

    // Warm threshold sessions with the authorization established above.
    if (requireThresholdWarmup) {
      const authMethodBinding = await readThresholdWarmupAuthMethodBinding({
        walletId: walletIdentity.walletId,
        authMethod: localUnlockAuthMethod,
      });
      const warmupPhase = await warmThresholdSigningSessions(
        resolveThresholdLoginWarmupPhaseInput({
          context,
          signerSlot: baseSignerSlot,
          authenticators,
          selection: walletUnlockSelection,
          subjectSet: walletIdentity.subjectSet,
          authMethod: localUnlockAuthMethod,
          authMethodBinding,
          keyFactsInventoryRequest: options?.ecdsaKeyFactsInventory,
          routeAuthorization: localWarmupRouteAuthorization,
        }),
      );
      signingSession = warmupPhase.signingSession;
      await assertPasskeyUnlockRuntimePostconditions({
        context,
        walletIdentity,
        signersWarmed: warmupPhase.signersWarmed,
      });
    }

    await persistSuccessfulLoginState(baseSignerSlot);
    void recoverNonceLanesAfterUnlock();

    // Return the same public result shape as the server-session branch.
    const baseLoginResult = buildSuccessfulLoginResult({
      identity: walletIdentity,
      accountSubject,
      jwt: '',
    });
    const loginResult: LoginAndCreateSessionResult = requireThresholdWarmup
      ? {
          ...baseLoginResult,
          ...requireThresholdWarmLoginBundle('login'),
        }
      : {
          ...baseLoginResult,
          ...(signingSession ? { signingSession } : {}),
        };

    emitUnlockEvent(onEvent, unlockSubjectId, {
      phase: UnlockEventPhase.STEP_06_SESSION_READY,
      status: 'succeeded',
      authMethod: loginCredential ? 'passkey' : undefined,
    });

    return await finalizeLoginSuccess({
      context,
      authMethod: localUnlockAuthMethod,
      unlockSubjectId,
      loginResult,
      onEvent,
      afterCall,
    });
  } catch (err: unknown) {
    console.warn('[login] unlock failed before active session commit', {
      unlockSubjectId,
      message:
        err && typeof err === 'object' && 'message' in err
          ? String((err as { message?: unknown }).message || '')
          : String(err || ''),
    });
    await clearFailedUnlockSessionState({
      context,
      walletId: walletIdentity.walletId,
    });
    // Normalize every thrown value through the public login error hooks/events.
    const errorMessage = getUserFriendlyErrorMessage(err, 'login') || 'Login failed';
    return await finalizeLoginError({
      unlockSubjectId,
      message: errorMessage,
      error: err,
      cancelled: isUserCancellationError(err),
      onEvent,
      onError,
      afterCall,
    });
  }
}

async function clearFailedUnlockSessionState(args: {
  context: LoginWebContext;
  walletId: WalletId;
}): Promise<void> {
  await IndexedDBManager.clearLastProfileSelection().catch(() => undefined);
  try {
    args.context.signingEngine.getNonceCoordinator().clearAll();
  } catch {}
  try {
    await args.context.signingEngine.clearVolatileWarmSigningMaterial(args.walletId);
  } catch {}
}

async function finalizeLoginSuccess(args: {
  context: LoginWebContext;
  authMethod: WalletAuthMethod;
  unlockSubjectId: string;
  loginResult: LoginResult;
  onEvent?: LoginHooksOptions['onEvent'];
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
}): Promise<LoginAndCreateSessionResult> {
  const { context, authMethod, unlockSubjectId, loginResult, onEvent, afterCall } = args;
  if (loginResult.success) {
    context.signingEngine.setWalletAuthenticated({
      kind: 'authenticated',
      walletId: loginResult.walletId,
      authMethod,
    });
  }
  emitUnlockEvent(onEvent, unlockSubjectId, {
    phase: UnlockEventPhase.STEP_07_COMPLETED,
    status: 'succeeded',
    data: {
      ...(loginResult.success && loginResult.kind === 'near_wallet_unlocked'
        ? { operationalPublicKey: loginResult.operationalPublicKey ?? '' }
        : { walletId: loginResult.success ? String(loginResult.walletId) : '' }),
    },
  });
  await afterCall?.(true, loginResult);
  return loginResult;
}

async function finalizeLoginError(args: {
  unlockSubjectId: string;
  message: string;
  error?: unknown;
  onEvent?: LoginHooksOptions['onEvent'];
  onError?: (error: Error) => void;
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
  callOnError?: boolean;
  callAfterCall?: boolean;
  cancelled?: boolean;
}): Promise<LoginAndCreateSessionResult> {
  const {
    message,
    unlockSubjectId,
    error,
    onEvent,
    onError,
    afterCall,
    callOnError = true,
    callAfterCall = true,
    cancelled = false,
  } = args;

  if (callOnError) {
    onError?.(toError(error));
  }

  emitUnlockEvent(onEvent, unlockSubjectId, {
    phase: cancelled ? UnlockEventPhase.CANCELLED : UnlockEventPhase.FAILED,
    status: cancelled ? 'cancelled' : 'failed',
    ...(cancelled ? {} : { message }),
    interaction: {
      kind: 'passkey_assert',
      overlay: 'hide',
    },
    error: {
      message,
    },
  });

  if (callAfterCall) {
    await afterCall?.(false);
  }
  return { success: false, error: message };
}

type ConfiguredThresholdEcdsaPublicationTarget = ReturnType<
  typeof listConfiguredThresholdEcdsaPublicationTargets
>[number];

type PreparedPasskeyExchangeEcdsaActivation = {
  readonly targetKey: string;
  readonly request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
};

type CompletedPasskeyExchangeEcdsaActivation = PreparedPasskeyExchangeEcdsaActivation & {
  readonly response: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
};

type CompletedPasskeySessionExchange = {
  readonly credential: WebAuthnAuthenticationCredential;
  readonly activation: CompletedPasskeyExchangeEcdsaActivation | null;
  readonly custody: PasskeySessionCustodyUnlockV1;
  readonly result: Awaited<ReturnType<typeof exchangeSession>>;
};

function rememberPasskeySessionCustodyForExport(args: {
  readonly walletId: string;
  readonly exchange: CompletedPasskeySessionExchange;
}): void {
  const credentialIdB64u = String(
    args.exchange.credential.rawId || args.exchange.credential.id || '',
  ).trim();
  if (!credentialIdB64u) throw new Error('[login] passkey assertion credential id is missing');
  rememberPasskeyCustodySessionEnvelope({
    walletId: args.walletId,
    credentialIdB64u,
    envelope: args.exchange.custody.envelope,
  });
}

async function preparePasskeyExchangeEcdsaActivation(args: {
  context: LoginWebContext;
  walletIdentity: ResolvedLoginWalletIdentity;
  selection: WalletUnlockSelection;
  ttlMs: number;
  remainingUses: number;
}): Promise<PreparedPasskeyExchangeEcdsaActivation | null> {
  const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
    args.context.configs.network.chains,
  );
  const branch = resolveLoginUnlockWarmupBranchPlan({
    subjectSet: args.walletIdentity.subjectSet,
    selection: args.selection,
    hasConfiguredEcdsaTargets: configuredTargets.length > 0,
  });
  if (!branch.wantsEcdsaWarmup) return null;
  const target = configuredTargets[0];
  if (!target) return null;
  const context = await resolveCanonicalThresholdEcdsaWarmSessionContext(
    args.context,
    args.walletIdentity.walletId,
  );
  const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
  const targetEcdsaKey = context.ecdsaKeys.find((candidate) => candidate.targetKey === targetKey);
  if (!targetEcdsaKey?.key || !targetEcdsaKey.existingRoleLocalMaterial) {
    throw createThresholdEcdsaDeviceLinkRequiredError(targetKey);
  }
  const runtimePolicyScope = context.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('[login] passkey exchange ECDSA activation requires runtime policy scope');
  }
  const publicCapability = await resolvePersistedEcdsaPublicCapabilityForLogin({
    walletId: args.walletIdentity.walletId,
    chainTarget: target.chainTarget,
    targetEcdsaKey,
  });
  const thresholdSessionId = requireThresholdLoginEcdsaSessionId(
    createThresholdLoginWarmSessionId('threshold-ecdsa-login'),
  );
  const walletSessionMintId = requireThresholdLoginWalletSessionMintId(
    createThresholdLoginWarmSessionId('wallet-session-mint'),
  );
  return {
    targetKey,
    request: buildStrictEcdsaPostRegistrationSessionActivationRequest({
      publicCapability,
      thresholdSessionId,
      walletSessionMintId,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      runtimePolicyScope,
    }),
  };
}

async function completePasskeySessionExchange(args: {
  context: LoginWebContext;
  walletIdentity: ResolvedLoginWalletIdentity;
  unlockSubjectId: string;
  onEvent?: LoginHooksOptions['onEvent'];
  authenticators: readonly LoginPasskeyAuthenticator[];
  signerSlot: number;
  relayUrl: string;
  exchangePath: string;
  sessionKind: 'jwt' | 'cookie';
  rpId: string;
  activation: PreparedPasskeyExchangeEcdsaActivation | null;
  expectedOrigin?: string;
  collectCredentialForChallenge: (args: {
    challengeB64u: string;
    credentialIds: readonly string[];
  }) => Promise<WebAuthnAuthenticationCredential>;
}): Promise<CompletedPasskeySessionExchange> {
  emitUnlockEvent(args.onEvent, args.unlockSubjectId, {
    phase: UnlockEventPhase.STEP_03_PASSKEY_CHALLENGE_STARTED,
    status: 'running',
    authMethod: 'passkey',
  });
  const challengeResponse = await fetch(
    joinNormalizedUrl(args.relayUrl, '/wallet/unlock/challenge'),
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        unlockBackend: 'passkey',
        userId: String(args.walletIdentity.walletId),
        rpId: args.rpId,
      }),
    },
  );
  const challengeBodyUnknown: unknown = await challengeResponse.json().catch(() => ({}));
  const challengeBody = isObject(challengeBodyUnknown) ? challengeBodyUnknown : {};
  const challengeMessage = typeof challengeBody.message === 'string' ? challengeBody.message : '';
  if (!challengeResponse.ok || challengeBody.ok !== true) {
    throw new Error(
      challengeMessage || `wallet/unlock/challenge failed (HTTP ${challengeResponse.status})`,
    );
  }
  const challengeId = String(challengeBody.challengeId || '').trim();
  const challengeB64u = String(challengeBody.challengeB64u || '').trim();
  if (!challengeId || !challengeB64u) {
    throw new Error('wallet/unlock/challenge returned invalid challenge');
  }

  const credentialIds = resolveLoginPasskeyPromptCredentialIds({
    authenticators: args.authenticators,
    signerSlot: args.signerSlot,
    serverCredentialIds: parseLoginChallengeCredentialIds(challengeBody.credentialIds),
  });
  const credential = await args.collectCredentialForChallenge({
    challengeB64u,
    credentialIds,
  });
  const expectedOrigin = String(
    args.expectedOrigin ?? (typeof window !== 'undefined' ? window.location.origin : ''),
  ).trim();
  const exchangeInput: SessionExchangeInput = args.activation
    ? {
        type: 'passkey_assertion',
        challengeId,
        webauthn_authentication: credential,
        ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
        ecdsaSessionActivation: args.activation.request,
      }
    : {
        type: 'passkey_assertion',
        challengeId,
        webauthn_authentication: credential,
        ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
      };
  emitUnlockEvent(args.onEvent, args.unlockSubjectId, {
    phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
    status: 'running',
    authMethod: 'passkey',
  });
  const result = await exchangeSession(
    args.relayUrl,
    args.exchangePath,
    args.sessionKind,
    exchangeInput,
    resolveSessionExchangeRuntimeScope(args.context),
  );
  if (!result.success) {
    throw new Error(result.error || 'Passkey session exchange failed');
  }
  if (!result.walletCustody) {
    throw new Error('Passkey session exchange omitted wallet custody continuity');
  }
  if (args.activation && !result.ecdsaSession) {
    throw new Error('Passkey session exchange omitted the requested ECDSA activation');
  }
  return {
    credential,
    activation:
      args.activation && result.ecdsaSession
        ? { ...args.activation, response: result.ecdsaSession }
        : null,
    custody: result.walletCustody,
    result,
  };
}

type ThresholdLoginWarmEcdsaContextResolution =
  | {
      kind: 'pre_resolved';
      context: CanonicalThresholdEcdsaWarmSessionContext;
      initialContext?: never;
      resolveAfterEd25519?: never;
    }
  | {
      kind: 'first_bootstrap_missing_target_keys';
      initialContext: CanonicalThresholdEcdsaWarmSessionContext;
      context?: never;
      resolveAfterEd25519?: never;
    }
  | {
      kind: 'resolve_after_ed25519';
      initialContext: CanonicalThresholdEcdsaWarmSessionContext;
      resolveAfterEd25519: (
        ed25519State: ThresholdLoginWarmEd25519State,
      ) => Promise<CanonicalThresholdEcdsaWarmSessionContext>;
      context?: never;
    };

type ThresholdLoginWarmupPlan = {
  kind: 'threshold_login_warmup_plan_ready';
  storedCanonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  configuredTargetKeyCompletion: ConfiguredTargetKeyCompletion;
  ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  signersToWarm: ThresholdLoginWarmSigner[];
  ed25519DependsOnEcdsa: boolean;
  ecdsaDependsOnEd25519: boolean;
};

type ThresholdLoginWarmupPhaseResult = {
  kind: 'threshold_login_warmup_ready';
  signingSession: ThresholdWarmLoginAndCreateSessionResult['signingSession'];
  signersWarmed: ThresholdLoginWarmSigner[];
};

function resolveLoginThresholdEcdsaBootstrapKey(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  walletId: unknown;
  rpId: unknown;
  thresholdOwnerAddress: unknown;
}): {
  keyHandle: string;
  key: EvmFamilyEcdsaKeyIdentity;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
} {
  const bootstrap = args.bootstrap;
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[login] threshold ECDSA bootstrap missing keyHandle');
  }
  const runtimePolicyScope = bootstrap.session.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('[login] threshold ECDSA bootstrap requires runtimePolicyScope');
  }
  const signingRootBinding = resolveThresholdSigningRootBindingFromRuntimePolicyScope({
    runtimePolicyScope,
  });
  const ecdsaThresholdKeyId = resolveThresholdEcdsaKeyIdFromRecord({
    record: { ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId },
  });
  return {
    keyHandle,
    runtimePolicyScope,
    key: buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId: args.walletId,
      ecdsaThresholdKeyId,
      signingRootId: String(signingRootBinding.signingRootId),
      signingRootVersion: String(signingRootBinding.signingRootVersion),
      participantIds: keyRef.participantIds,
      thresholdOwnerAddress: String(args.thresholdOwnerAddress || '').trim(),
    }),
  };
}

type ThresholdLoginWarmSigner = 'ed25519' | 'ecdsa';

type ThresholdLoginWarmupTask = {
  signer: ThresholdLoginWarmSigner;
  dependencies: ThresholdLoginWarmSigner[];
  onFailure: ((error: unknown) => void) | null;
  run: () => Promise<void>;
};

type ThresholdLoginWarmupTaskOutcome =
  | { kind: 'succeeded'; task: ThresholdLoginWarmupTask }
  | { kind: 'failed'; task: ThresholdLoginWarmupTask; error: Error };

type ThresholdLoginWarmEd25519State = {
  thresholdSessionId: string;
  walletSessionId: WalletSessionId | null;
  quotaId: MpcWalletSigningQuotaId | null;
  jwt: string;
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope | null;
};

type ThresholdLoginWarmSharedState = {
  ed25519: ThresholdLoginWarmEd25519State;
  activeCanonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  activeEd25519Authorization: ActiveWalletSessionAuthorizationProjection | null;
};

type ThresholdLoginWarmEcdsaDependency =
  | { kind: 'none' }
  | { kind: 'ed25519_wallet_session_authority' };

class LoginWarmupDeferred<Value> {
  readonly promise: Promise<Value>;
  private resolvePromise!: (value: Value) => void;
  private rejectPromise!: (error: Error) => void;
  private settled = false;

  constructor() {
    this.promise = new Promise(this.capturePromise.bind(this));
  }

  resolve(value: Value): void {
    if (this.settled) return;
    this.settled = true;
    this.resolvePromise(value);
  }

  reject(error: unknown): void {
    if (this.settled) return;
    this.settled = true;
    this.rejectPromise(toError(error));
  }

  async wait(): Promise<Value> {
    return await this.promise;
  }

  private capturePromise(resolve: (value: Value) => void, reject: (error: Error) => void): void {
    this.resolvePromise = resolve;
    this.rejectPromise = reject;
  }
}

async function stageMintedLoginEd25519WalletSessionAuthority(
  context: {
    sharedState: ThresholdLoginWarmSharedState;
    authorityDeferred: LoginWarmupDeferred<MintedEd25519WalletSessionAuthority> | null;
    ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  },
  minted: MintedEd25519WalletSessionAuthority,
): Promise<void> {
  context.sharedState.ed25519.thresholdSessionId = String(minted.thresholdSessionId);
  context.sharedState.ed25519.walletSessionId = minted.walletSessionId;
  context.sharedState.ed25519.quotaId = minted.quotaId;
  context.sharedState.ed25519.jwt = minted.jwt;
  context.sharedState.ed25519.expiresAtMs = minted.expiresAtMs;
  context.sharedState.ed25519.remainingUses = minted.remainingUses;
  context.sharedState.ed25519.runtimePolicyScope = minted.runtimePolicyScope;
  if (context.ecdsaContextResolution.kind === 'resolve_after_ed25519') {
    context.sharedState.activeCanonicalEcdsaContext =
      await context.ecdsaContextResolution.resolveAfterEd25519(context.sharedState.ed25519);
  }
  context.authorityDeferred?.resolve(minted);
}

function rejectLoginWarmupEd25519Deferreds(
  authorityDeferred: LoginWarmupDeferred<MintedEd25519WalletSessionAuthority> | null,
  authorizationPersistenceDeferred: LoginWarmupDeferred<void> | null,
  error: unknown,
): void {
  authorityDeferred?.reject(error);
  authorizationPersistenceDeferred?.reject(error);
}

function createActiveLoginSigningSessionStatus(args: {
  session: ProvisionWarmEd25519CapabilitySuccessResult;
  authMethod: WalletAuthMethod;
}): ThresholdWarmLoginAndCreateSessionResult['signingSession'] {
  return {
    sessionId: String(args.session.thresholdSessionId),
    status: 'active',
    authMethod: args.authMethod,
    ...(args.authMethod === SIGNER_AUTH_METHODS.emailOtp ? { retention: 'session' as const } : {}),
    remainingUses: args.session.remainingUses,
    expiresAtMs: args.session.expiresAtMs,
  };
}

type ThresholdLoginWarmEcdsaBootstrapIdentity = {
  routeAuth?: Extract<AppOrWalletSessionAuth, { kind: 'wallet_session' }>;
};

function isWalletSessionReconnectEcdsaRouteAuth(
  auth: AppOrWalletSessionAuth | undefined,
): auth is Extract<AppOrWalletSessionAuth, { kind: 'wallet_session' }> {
  return auth?.kind === 'wallet_session';
}

type ThresholdLoginWarmupResult = {
  ecdsaBootstraps: ThresholdEcdsaSessionBootstrapResult[];
  ed25519Session: ProvisionWarmEd25519CapabilitySuccessResult | null;
};

type ThresholdEcdsaAuthorizedEd25519Mint = {
  thresholdEcdsaSessionJwt: string;
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
};

function publicCapabilityFromThresholdEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): RouterAbEcdsaDerivationPublicCapabilityV1 | undefined {
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!backendBinding) return undefined;
  switch (backendBinding.materialKind) {
    case 'role_local_worker_handle':
    case 'role_local_durable_sealed_ref':
    case 'role_local_durable_public_anchor':
      return backendBinding.publicFacts.publicCapability;
    case 'email_otp_worker_handle':
    case 'role_local_ready_state_blob':
      return backendBinding.ecdsaRoleLocalReadyRecord.publicFacts.publicCapability;
    case 'metadata_only':
      return undefined;
  }
}

function sharedEcdsaActivationKey(capability: RouterAbEcdsaDerivationPublicCapabilityV1): string {
  return JSON.stringify(capability);
}

function preauthorizedEcdsaActivationFromBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): RouterAbEcdsaPostRegistrationSessionActivationResponseV1 {
  const publicCapability = publicCapabilityFromThresholdEcdsaBootstrap(bootstrap);
  if (!publicCapability) {
    throw new Error('[login] ECDSA bootstrap is missing its public capability');
  }
  const session = bootstrap.session;
  const normalSigning = bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning;
  if (!normalSigning) {
    throw new Error('[login] ECDSA bootstrap is missing normal-signing state');
  }
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
    public_capability: publicCapability,
    session: {
      authorization_session_id: session.authorizationSessionId,
      threshold_session_id: requireThresholdLoginEcdsaSessionId(session.thresholdSessionId),
      wallet_session_id: session.walletSessionId,
      quota_id: session.quotaId,
      expires_at_ms: session.expiresAtMs,
      remaining_uses: session.remainingUses,
      wallet_session_jwt: session.jwt,
    },
    normal_signing: normalSigning,
  };
}

function sameThresholdRuntimePolicyScope(
  left: ThresholdRuntimePolicyScope,
  right: ThresholdRuntimePolicyScope,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function mergeThresholdEcdsaWarmSessionContexts(args: {
  current: CanonicalThresholdEcdsaWarmSessionContext;
  incoming: CanonicalThresholdEcdsaWarmSessionContext;
  source: string;
}): CanonicalThresholdEcdsaWarmSessionContext {
  if (
    args.current.runtimePolicyScope &&
    args.incoming.runtimePolicyScope &&
    !sameThresholdRuntimePolicyScope(
      args.current.runtimePolicyScope,
      args.incoming.runtimePolicyScope,
    )
  ) {
    throw new Error(
      `[login] threshold ECDSA ${args.source} has a conflicting runtime policy scope`,
    );
  }
  return mergeCanonicalThresholdEcdsaWarmSessionContexts(args.current, args.incoming);
}

/** Public capability and authority are the manifest's half of the capability
 * split; the sealed record is only correlated runtime evidence. A persisted
 * capability on the configured target is used directly; otherwise the exact
 * manifest is resolved. There is deliberately no composite-record fallback --
 * absent canonical state is device-link-required, not a silent miss. */
async function resolvePersistedEcdsaPublicCapabilityForLogin(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  targetEcdsaKey: ConfiguredTargetThresholdEcdsaWarmKey;
}): Promise<RouterAbEcdsaDerivationPublicCapabilityV1> {
  if (args.targetEcdsaKey.publicCapability.kind === 'persisted_public_capability') {
    const publicCapability = args.targetEcdsaKey.publicCapability.value;
    if (String(publicCapability.client_id) !== String(args.walletId)) {
      throw new Error(
        `[login] threshold ECDSA persisted public capability wallet mismatch for ${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
      );
    }
    return publicCapability;
  }
  const resolved = await resolveActiveEcdsaCapabilityRuntime({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
  });
  if (resolved.kind !== 'resolved') {
    throw createThresholdEcdsaDeviceLinkRequiredError(
      thresholdEcdsaChainTargetKey(args.chainTarget),
    );
  }
  // Validated against what the manifest itself binds: wallet and key handle.
  // client_id is only checked on the persisted branch above, where it was
  // already the contract; manifest-sourced capabilities are not assumed to
  // carry the wallet id in that field.
  const publicFacts = resolved.manifest.durableMaterial.roleLocalPublicFacts;
  if (
    String(publicFacts.keyHandle) !== String(args.targetEcdsaKey.keyHandle) ||
    String(publicFacts.walletId) !== String(args.walletId)
  ) {
    throw createThresholdEcdsaDeviceLinkRequiredError(
      thresholdEcdsaChainTargetKey(args.chainTarget),
    );
  }
  return publicFacts.publicCapability;
}

function buildThresholdLoginWarmSignerSelection(
  signersToWarm: readonly ThresholdLoginWarmSigner[],
): ThresholdLoginWarmSigner[] {
  const normalized: ThresholdLoginWarmSigner[] = [];
  for (const signer of signersToWarm) {
    if (signer !== 'ed25519' && signer !== 'ecdsa') continue;
    if (normalized.includes(signer)) continue;
    normalized.push(signer);
  }
  return normalized;
}

async function runThresholdLoginWarmupTask(
  task: ThresholdLoginWarmupTask,
): Promise<ThresholdLoginWarmupTaskOutcome> {
  try {
    await task.run();
    return { kind: 'succeeded', task };
  } catch (error: unknown) {
    task.onFailure?.(error);
    return { kind: 'failed', task, error: toError(error) };
  }
}

export async function runThresholdLoginWarmupTasks(
  tasks: ThresholdLoginWarmupTask[],
): Promise<void> {
  const pendingBySigner = new Map<ThresholdLoginWarmSigner, ThresholdLoginWarmupTask>();
  for (const task of tasks) {
    pendingBySigner.set(task.signer, task);
  }
  const completed = new Set<ThresholdLoginWarmSigner>();

  while (pendingBySigner.size > 0) {
    const ready: ThresholdLoginWarmupTask[] = [];
    for (const task of pendingBySigner.values()) {
      if (task.dependencies.every((dep) => completed.has(dep))) {
        ready.push(task);
      }
    }
    if (ready.length === 0) {
      throw new Error('[login] threshold warm-up task dependency graph is unsatisfied');
    }
    const outcomes = await Promise.all(ready.map(runThresholdLoginWarmupTask));
    let firstFailure: Error | null = null;
    for (const outcome of outcomes) {
      switch (outcome.kind) {
        case 'succeeded':
          completed.add(outcome.task.signer);
          pendingBySigner.delete(outcome.task.signer);
          break;
        case 'failed':
          firstFailure ??= outcome.error;
          break;
        default:
          return assertNeverLoginState(outcome);
      }
    }
    if (firstFailure) throw firstFailure;
  }
}

function resolveThresholdLoginWarmEcdsaBootstrapIdentity(args: {
  credentialState: LoginWarmupCredentialState;
  routeAuthorization: LoginWarmupRouteAuthorization;
}): ThresholdLoginWarmEcdsaBootstrapIdentity {
  switch (args.routeAuthorization.kind) {
    case 'app_session_jwt':
      return {};
    case 'app_session_cookie':
      throw new Error('[login] threshold ECDSA warm-up requires bearer route authorization');
    case 'none':
      break;
    default:
      return assertNeverLoginState(args.routeAuthorization);
  }
  if (args.credentialState.kind === 'available') {
    return {};
  }
  throw new Error('[login] threshold ECDSA warm-up requires route authorization');
}

function thresholdLoginWarmupErrorMessage(error: unknown): string {
  return String(
    (error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error) || '',
  );
}

function assertNeverLoginState(value: never): never {
  throw new Error(`[login] unexpected state: ${String(value)}`);
}

type WithoutLoginRuntimeScope<Request extends EcdsaBootstrapRequest> =
  Request extends EcdsaBootstrapRequest
    ? Omit<Request, 'runtimeScopeBootstrap'> & { runtimeScopeBootstrap?: never }
    : never;

type LoginEcdsaBootstrapRequestWithoutRuntimeScope =
  WithoutLoginRuntimeScope<EcdsaBootstrapRequest>;

async function bootstrapLoginEcdsaSession(args: {
  signingEngine: Pick<LoginWarmSigningSurface, 'bootstrapEcdsaSession'>;
  runtimeScopeBootstrapState: LoginWarmupRuntimeScopeBootstrapState;
  request: LoginEcdsaBootstrapRequestWithoutRuntimeScope;
}): Promise<ThresholdEcdsaSessionBootstrapResult> {
  switch (args.runtimeScopeBootstrapState.kind) {
    case 'available':
      return await args.signingEngine.bootstrapEcdsaSession({
        ...args.request,
        runtimeScopeBootstrap: args.runtimeScopeBootstrapState.runtimeScopeBootstrap,
      } satisfies EcdsaBootstrapRequest);
    case 'unavailable':
      return await args.signingEngine.bootstrapEcdsaSession(args.request);
    default:
      return assertNeverLoginState(args.runtimeScopeBootstrapState);
  }
}

function buildLoginEd25519WalletSessionMintAuthorization(args: {
  routeAuthorization: LoginWarmupRouteAuthorization;
  credentialState: LoginWarmupCredentialState;
  rpId: string;
}): Ed25519WalletSessionMintAuthorization | undefined {
  switch (args.routeAuthorization.kind) {
    case 'app_session_jwt':
      if (args.credentialState.kind !== 'available') return undefined;
      return {
        kind: 'app_session_jwt',
        appSessionJwt: args.routeAuthorization.appSessionJwt,
        localSecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
          credential: args.credentialState.credential,
          rpId: args.rpId,
        }),
      };
    case 'app_session_cookie':
      if (args.credentialState.kind !== 'available') return undefined;
      return {
        kind: 'app_session_cookie',
        localSecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
          credential: args.credentialState.credential,
          rpId: args.rpId,
        }),
      };
    case 'none':
      return undefined;
    default:
      return assertNeverLoginState(args.routeAuthorization);
  }
}

type PasskeyEd25519CustodyLoginInput = {
  signingEngine: LoginUnlockSigningSurface;
  custody: ActivePasskeySessionCustodyUnlockV1;
  walletBinding: ResolvedLoginWalletBinding;
  signerSlot: number;
  passkeyPrfFirstB64u: string;
  walletSessionJwt: string;
  thresholdSessionId: string;
  routerAbNormalSigning: ReturnType<typeof createRouterAbNormalSigningPolicy>;
  relayerUrl: string;
};

function walletCustodyLoginActivationFacts(
  custody: ActivePasskeySessionCustodyUnlockV1,
): WalletCustodyActivationFactsV1 {
  const capability = custody.ed25519.capability;
  const continuity = capability.registrationContinuity;
  if (continuity.kind !== 'registration') {
    throw new Error('[login] wallet custody requires registration continuity');
  }
  return {
    materialActivation: capability.materialActivation,
    lifecycleId: capability.lifecycle.lifecycleId,
    signingRootVersion: capability.lifecycle.rootShareEpoch,
    signingRootId: capability.applicationBinding.signing_root_id,
    signerSetId: capability.lifecycle.signerSetId,
    thresholdSessionId: capability.lifecycle.thresholdSessionId,
    activationTranscriptB64u: base64UrlEncode(Uint8Array.from(continuity.activationTranscript)),
    activationCapabilityBindingB64u: base64UrlEncode(
      Uint8Array.from(capability.activeCapabilityBinding),
    ),
  };
}

function assertWalletCustodyLoginIdentity(input: PasskeyEd25519CustodyLoginInput): void {
  const ed25519 = input.custody.ed25519;
  const capability = ed25519.capability;
  if (
    ed25519.nearAccountId !== String(input.walletBinding.nearAccountId) ||
    ed25519.nearEd25519SigningKeyId !== String(input.walletBinding.nearEd25519SigningKeyId) ||
    ed25519.signerSlot !== input.signerSlot ||
    capability.applicationBinding.wallet_id !== String(input.walletBinding.walletId) ||
    capability.applicationBinding.near_ed25519_signing_key_id !==
      String(input.walletBinding.nearEd25519SigningKeyId) ||
    capability.applicationBinding.key_creation_signer_slot !== input.signerSlot ||
    capability.nearAccountId !== input.walletBinding.nearAccountId ||
    capability.lifecycle.accountId !== String(input.walletBinding.walletId) ||
    capability.lifecycle.signingWorkerId !== ed25519.relayerKeyId
  ) {
    throw new Error('[login] wallet custody identity does not match the selected signing lane');
  }
}

async function openAndActivatePasskeyEd25519CustodyLogin(
  input: PasskeyEd25519CustodyLoginInput,
): Promise<void> {
  assertWalletCustodyLoginIdentity(input);
  const capability = input.custody.ed25519.capability;
  const cached = await input.signingEngine.loadWalletCustodyEd25519Material({
    nearAccountId: String(input.walletBinding.nearAccountId),
    signerSlot: input.signerSlot,
    expectedRegisteredPublicKeyB64u: base64UrlEncode(
      Uint8Array.from(capability.registeredPublicKey),
    ),
  });
  const activation = walletCustodyLoginActivationFacts(input.custody);
  const envelope = walletCustodyCacheEnvelopeFromRecordV1(input.custody.envelope);
  let activeClient: Awaited<ReturnType<typeof openWalletCustodyEd25519ActiveClientV1>> | null = null;
  let rejoinSecret: Uint8Array | null = null;
  let openSecret: Uint8Array | null = null;
  try {
    if (cached.kind === 'found') {
      openSecret = base64UrlDecode(input.passkeyPrfFirstB64u);
      activeClient = await openWalletCustodyEd25519ActiveClientV1({
        material: cached.material,
        activation,
        envelope,
        ownedFactorSecret: openSecret,
      });
    } else {
      const continuity = capability.registrationContinuity;
      if (continuity.kind !== 'registration') {
        throw new Error('[login] wallet custody cold rejoin requires registration continuity');
      }
      const custodyWire = joinCustodyWireFromEnvelopeRecord(input.custody.envelope);
      if (!custodyWire.ok) throw new Error(custodyWire.reason);
      rejoinSecret = base64UrlDecode(input.passkeyPrfFirstB64u);
      openSecret = base64UrlDecode(input.passkeyPrfFirstB64u);
      const rejoined = await input.signingEngine.rejoinWalletCustodyNearEd25519KeySet({
        walletId: String(input.walletBinding.walletId),
        custodyJson: custodyWire.custodyJson,
        factorSecret: rejoinSecret.buffer,
        nearEd25519SigningKeyId: String(input.walletBinding.nearEd25519SigningKeyId),
        registrationCeremonyId: continuity.admissionRequest.scope.lifecycle_id,
        admissionRequest: continuity.admissionRequest,
        admissionReceipt: continuity.admissionReceipt,
        participantIds: capability.participantIds,
        registeredPublicKeyB64u: base64UrlEncode(Uint8Array.from(capability.registeredPublicKey)),
        routerOrigin: new URL(input.relayerUrl).origin,
        walletSessionJwt: input.walletSessionJwt,
      });
      const materialBinding: WalletCustodyEd25519MaterialBindingV1 = {
        kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        applicationBindingDigestB64u: rejoined.localMaterial.applicationBindingDigestB64u,
        registeredPublicKeyB64u: base64UrlEncode(rejoined.metadata.registeredPublicKey),
        participantIds: rejoined.metadata.participantIds,
        stateEpoch: String(rejoined.metadata.stateEpoch),
        walletId: String(input.walletBinding.walletId),
        nearAccountId: String(input.walletBinding.nearAccountId),
        nearEd25519SigningKeyId: String(input.walletBinding.nearEd25519SigningKeyId),
        signerSlot: input.signerSlot,
        signingWorkerId: input.custody.ed25519.relayerKeyId,
        signingWorkerVerifyingShareB64u: base64UrlEncode(
          rejoined.metadata.signingWorkerVerifyingShare,
        ),
      };
      const sealed = {
        ciphertextB64u: rejoined.localMaterial.b64u,
        nonceB64u: rejoined.localMaterial.nonceB64u,
      };
      await input.signingEngine.persistWalletCustodyEd25519Material({
        binding: materialBinding,
        sealed,
      });
      activeClient = await openWalletCustodyEd25519ActiveClientV1({
        material: { binding: materialBinding, sealed },
        activation,
        envelope,
        ownedFactorSecret: openSecret,
      });
    }
    if (!activeClient) throw new Error('[login] wallet custody produced no active client');
    const activated = await input.signingEngine.activateVerifiedNearEd25519YaoMaterial({
      activeClient,
      facts: {
        thresholdSessionId: input.thresholdSessionId,
        signer: nearEd25519SignerBindingFromBoundaryFields({
          walletId: input.walletBinding.walletId,
          nearAccountId: input.walletBinding.nearAccountId,
          nearEd25519SigningKeyId: input.walletBinding.nearEd25519SigningKeyId,
          signerSlot: input.signerSlot,
        }),
        signingRootId: capability.applicationBinding.signing_root_id,
        signingRootVersion: capability.lifecycle.rootShareEpoch,
        routerAbNormalSigning: input.routerAbNormalSigning,
        runtimePolicyScope: capability.runtimePolicyScope,
        relayerUrl: input.relayerUrl,
      },
    });
    if (
      !mpcMaterialActivationRefsEqual(
        activated.materialActivation,
        capability.materialActivation,
      )
    ) {
      throw new Error('[login] wallet custody activation changed during unlock');
    }
  } catch (error) {
    activeClient?.dispose();
    throw error;
  } finally {
    rejoinSecret?.fill(0);
    openSecret?.fill(0);
  }
}

async function primeThresholdLoginWarmSigners(args: {
  context: LoginWebContext;
  signingEngine: LoginUnlockSigningSurface;
  walletIdentity: ResolvedLoginWalletIdentity;
  signerSlot: number;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  ttlMs: number;
  unlockRemainingUses: number;
  ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  credentialState: LoginWarmupCredentialState;
  runtimeScopeBootstrapState: LoginWarmupRuntimeScopeBootstrapState;
  signersToWarm: readonly ThresholdLoginWarmSigner[];
  ed25519DependsOnEcdsa: boolean;
  ecdsaDependency: ThresholdLoginWarmEcdsaDependency;
  ed25519MintPlan: LoginWarmupEd25519MintPlan;
  ed25519SessionAuthority: LoginWarmupEd25519SessionAuthority;
  authMethod: WalletAuthMethod;
  routeAuthorization: LoginWarmupRouteAuthorization;
  passkeyExchangeEcdsaActivation: CompletedPasskeyExchangeEcdsaActivation | null;
}): Promise<ThresholdLoginWarmupResult> {
  const signersToWarm = buildThresholdLoginWarmSignerSelection(args.signersToWarm);
  const credential =
    args.credentialState.kind === 'available' ? args.credentialState.credential : undefined;
  const localPasskeyCredentialIdB64u = args.credentialState.localPasskeyCredentialIdB64u;
  const runtimeScopeBootstrap =
    args.runtimeScopeBootstrapState.kind === 'available'
      ? args.runtimeScopeBootstrapState.runtimeScopeBootstrap
      : null;
  const initialCanonicalEcdsaContext =
    args.ecdsaContextResolution.kind === 'pre_resolved'
      ? args.ecdsaContextResolution.context
      : args.ecdsaContextResolution.initialContext;
  const sharedState: ThresholdLoginWarmSharedState = {
    activeCanonicalEcdsaContext: initialCanonicalEcdsaContext,
    activeEd25519Authorization: null,
    ed25519: {
      thresholdSessionId: '',
      walletSessionId: null,
      quotaId: null,
      jwt: '',
      expiresAtMs: 0,
      remainingUses: 0,
      runtimePolicyScope: null,
    },
  };
  const authorityDeferred =
    args.ecdsaDependency.kind === 'ed25519_wallet_session_authority'
      ? new LoginWarmupDeferred<MintedEd25519WalletSessionAuthority>()
      : null;
  const ed25519AuthorizationPersistenceDeferred =
    args.ecdsaDependency.kind === 'ed25519_wallet_session_authority'
      ? new LoginWarmupDeferred<void>()
      : null;
  const ecdsaThresholdSessionState: ThresholdLoginWarmEcdsaThresholdSessionState = {
    generatedThresholdSessionId:
      args.passkeyExchangeEcdsaActivation?.request.session_policy.threshold_session_id || '',
  };
  const unlockRemainingUses = args.unlockRemainingUses;
  const ecdsaBootstraps: ThresholdEcdsaSessionBootstrapResult[] = [];
  let ed25519Session: ProvisionWarmEd25519CapabilitySuccessResult | null = null;
  let ecdsaAuthorizedEd25519Mint: ThresholdEcdsaAuthorizedEd25519Mint | null = null;

  const tasks: ThresholdLoginWarmupTask[] = [];
  if (signersToWarm.includes('ed25519')) {
    tasks.push({
      signer: 'ed25519',
      dependencies: args.ed25519DependsOnEcdsa ? ['ecdsa'] : [],
      onFailure:
        authorityDeferred || ed25519AuthorizationPersistenceDeferred
          ? rejectLoginWarmupEd25519Deferreds.bind(
              undefined,
              authorityDeferred,
              ed25519AuthorizationPersistenceDeferred,
            )
          : null,
      run: async () => {
        const walletBinding = requireNearLoginWalletBinding(args.walletIdentity);
        const ecdsaMint = ecdsaAuthorizedEd25519Mint;
        const auth = buildLoginEd25519WalletSessionMintAuthorization({
          routeAuthorization: args.routeAuthorization,
          credentialState: args.credentialState,
          rpId: args.signingEngine.getRpId(),
        });
        const ed25519SessionAuthority = requireRequestedLoginEd25519SessionAuthority(
          args.ed25519SessionAuthority,
        );
        const ed25519ProvisioningIdentity = resolveLoginWarmEd25519ProvisioningIdentity({
          mintPlan: args.ed25519MintPlan,
          ecdsaMint,
          walletBinding,
          signerSlot: args.signerSlot,
          authority: ed25519SessionAuthority,
        });
        const provisionScope = resolveLoginEd25519ProvisionScope({
          mintPlan: args.ed25519MintPlan,
          fallback: {
            relayerKeyId: args.relayerKeyId,
            participantIds: args.participantIds,
            runtimePolicyScope: initialCanonicalEcdsaContext.runtimePolicyScope ?? null,
            routerAbNormalSigning: createRouterAbNormalSigningPolicy(args.context.configs),
          },
        });
        const sharedEd25519ConnectArgs = {
          relayerUrl: args.relayerUrl,
          relayerKeyId: provisionScope.relayerKeyId,
          auth,
          runtimePolicyScope: provisionScope.runtimePolicyScope || undefined,
          routerAbNormalSigning: provisionScope.routerAbNormalSigning,
          runtimeScopeBootstrap: runtimeScopeBootstrap || undefined,
          participantIds: provisionScope.participantIds,
          sessionKind: 'jwt' as const,
          ttlMs: args.ttlMs,
          remainingUses: unlockRemainingUses,
          onWalletSessionAuthorityReady: stageMintedLoginEd25519WalletSessionAuthority.bind(
            undefined,
            {
              sharedState,
              authorityDeferred,
              ecdsaContextResolution: args.ecdsaContextResolution,
            },
          ),
        };
        const commonEd25519ConnectArgs =
          ed25519ProvisioningIdentity.kind === 'fresh_ed25519_provisioning'
            ? {
                ...ed25519ProvisioningIdentity,
                walletId: String(walletBinding.walletId),
                nearAccountId: walletBinding.nearAccountId,
                nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
                signerSlot: args.signerSlot,
                ...sharedEd25519ConnectArgs,
              }
            : {
                ...ed25519ProvisioningIdentity,
                ...sharedEd25519ConnectArgs,
              };
        let connected: Awaited<ReturnType<typeof args.signingEngine.connectEd25519Session>>;
        switch (ed25519SessionAuthority.kind) {
          case 'email_otp':
            connected = await args.signingEngine.connectEd25519Session({
              ...commonEd25519ConnectArgs,
              source: 'email_otp',
              authority: ed25519SessionAuthority.authority,
              emailOtpAuthContext: ed25519SessionAuthority.emailOtpAuthContext,
              materialActivation: undefined,
            });
            break;
          case 'passkey':
            connected = await args.signingEngine.connectEd25519Session({
              ...commonEd25519ConnectArgs,
              source: 'login',
              authority: ed25519SessionAuthority.authority,
              materialActivation: requireLoginPasskeyMaterialActivation(
                ed25519ProvisioningIdentity,
              ),
            });
            break;
          default:
            return assertNeverLoginState(ed25519SessionAuthority);
        }
        if (!connected.ok) {
          const details = String(
            connected.message || connected.code || 'Failed to connect threshold Ed25519 session',
          );
          throw new Error(`[login] threshold Ed25519 warm-up failed: ${details}`);
        }
        ed25519Session = connected;

        const connectedThresholdSessionId = connected.thresholdSessionId;
        if (!connectedThresholdSessionId) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a thresholdSessionId');
        }

        const connectedJwt = String(connected.jwt || '').trim();
        if (!connectedJwt) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a JWT session token');
        }

        sharedState.activeEd25519Authorization = await persistActiveWalletSessionAuthorizationCurve(
          walletSessionAuthorizations,
          {
            walletId: walletBinding.walletId,
            walletSessionId: connected.walletSessionId,
            quotaId: connected.quotaId,
            expiresAtMs: connected.expiresAtMs,
            authority: await walletAuthAuthorityRef({
              authority: ed25519SessionAuthority.authority.authority,
            }),
            authMethod: args.authMethod,
            walletSessionJwt: connectedJwt,
            curve: 'ed25519',
          },
        );
        ed25519AuthorizationPersistenceDeferred?.resolve(undefined);

        if (args.ed25519MintPlan.kind === 'wallet_custody') {
          if (ed25519SessionAuthority.kind !== 'passkey') {
            throw new Error('[login] wallet custody requires passkey authority');
          }
          const expectedMaterialActivation = requireLoginPasskeyMaterialActivation(
            ed25519ProvisioningIdentity,
          );
          const passkeyPrfFirstB64u = credential
            ? passkeyPrfFirstB64uFromCredential(credential)
            : '';
          if (!passkeyPrfFirstB64u) {
            throw new Error('[login] wallet custody requires WebAuthn PRF.first');
          }
          await args.signingEngine.withExactEd25519MaterialOwner({
            materialActivation: expectedMaterialActivation,
            nearAccountId: walletBinding.nearAccountId,
            task: openAndActivatePasskeyEd25519CustodyLogin.bind(undefined, {
              signingEngine: args.signingEngine,
              custody: args.ed25519MintPlan.custody,
              walletBinding,
              signerSlot: args.signerSlot,
              passkeyPrfFirstB64u,
              walletSessionJwt: connectedJwt,
              thresholdSessionId: connectedThresholdSessionId,
              routerAbNormalSigning: provisionScope.routerAbNormalSigning,
              relayerUrl: args.relayerUrl,
            }),
          });
        }
      },
    });
  }
  if (signersToWarm.includes('ecdsa')) {
    tasks.push({
      signer: 'ecdsa',
      dependencies: [],
      onFailure: null,
      run: async () => {
        await authorityDeferred?.promise;
        const beforeAuthorizationPersistence = ed25519AuthorizationPersistenceDeferred?.wait.bind(
          ed25519AuthorizationPersistenceDeferred,
        );
        let bootstrapIdentity: ThresholdLoginWarmEcdsaBootstrapIdentity | null = null;
        let consumedPasskeyExchangeActivation = false;
        const activationByMaterial = new Map<
          string,
          RouterAbEcdsaPostRegistrationSessionActivationResponseV1
        >();
        const configuredEcdsaTargets = listConfiguredThresholdEcdsaPublicationTargets(
          args.context.configs.network.chains,
        );
        const completeActiveContextFromConfiguredTargets = (source: string): void => {
          const completion = buildConfiguredTargetKeyCompletion({
            context: sharedState.activeCanonicalEcdsaContext,
            configuredTargets: configuredEcdsaTargets,
          });
          if (completion.kind === 'complete_configured_target_keys') {
            sharedState.activeCanonicalEcdsaContext = completion.context;
            return;
          }
          if (completion.kind === 'missing_configured_target_keys') {
            return;
          }
          requireCompleteConfiguredTargetKeyContext({ completion, source });
        };
        const rememberBootstrappedKey = (input: {
          target: (typeof configuredEcdsaTargets)[number];
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
        }): ConfiguredTargetThresholdEcdsaWarmKey => {
          const keyRef = input.bootstrap.thresholdEcdsaKeyRef;
          const thresholdOwnerAddress = keyRef.ethereumAddress;
          const resolved = resolveLoginThresholdEcdsaBootstrapKey({
            bootstrap: input.bootstrap,
            walletId: args.walletIdentity.walletId,
            rpId: String(args.signingEngine.getRpId() || '').trim(),
            thresholdOwnerAddress,
          });
          const warmKey = configuredTargetThresholdEcdsaWarmKey({
            chainTarget: input.target.chainTarget,
            keyHandle: resolved.keyHandle,
            key: resolved.key,
            publicCapability: publicCapabilityFromThresholdEcdsaBootstrap(input.bootstrap),
          });
          sharedState.activeCanonicalEcdsaContext = mergeCanonicalThresholdEcdsaWarmSessionContexts(
            sharedState.activeCanonicalEcdsaContext,
            {
              ecdsaKeys: [warmKey],
              runtimePolicyScope: resolved.runtimePolicyScope,
            },
          );
          completeActiveContextFromConfiguredTargets('login first-bootstrapped ECDSA key');
          return warmKey;
        };
        const rememberEcdsaAuthorizedEd25519Mint = (
          bootstrap: ThresholdEcdsaSessionBootstrapResult,
        ): void => {
          if (ecdsaAuthorizedEd25519Mint) return;
          const thresholdEcdsaSessionJwt = String(bootstrap.session.jwt || '').trim();
          const passkeyPrfFirstB64u = credential
            ? passkeyPrfFirstB64uFromCredential(credential)
            : '';
          const passkeyCredentialIdB64u =
            passkeyCredentialIdB64uFromAuthentication(credential || undefined) ||
            localPasskeyCredentialIdB64u;
          if (!thresholdEcdsaSessionJwt || !passkeyPrfFirstB64u || !passkeyCredentialIdB64u) {
            return;
          }
          ecdsaAuthorizedEd25519Mint = {
            thresholdEcdsaSessionJwt,
            passkeyPrfFirstB64u,
            passkeyCredentialIdB64u,
            walletSessionId: bootstrap.session.walletSessionId,
            quotaId: bootstrap.session.quotaId,
          };
        };
        const resolveCurrentBootstrapIdentity = (): ThresholdLoginWarmEcdsaBootstrapIdentity => {
          if (sharedState.ed25519.jwt) {
            return { routeAuth: walletSessionJwtAuth(sharedState.ed25519.jwt) };
          }
          const thresholdEcdsaSessionJwt = String(
            ecdsaAuthorizedEd25519Mint?.thresholdEcdsaSessionJwt || '',
          ).trim();
          if (thresholdEcdsaSessionJwt) {
            return {
              routeAuth: { kind: 'wallet_session', jwt: thresholdEcdsaSessionJwt },
            };
          }
          if (bootstrapIdentity) return bootstrapIdentity;
          bootstrapIdentity = resolveThresholdLoginWarmEcdsaBootstrapIdentity({
            credentialState: args.credentialState,
            routeAuthorization: args.routeAuthorization,
          });
          return bootstrapIdentity;
        };
        const bootstrapTarget = async (
          target: (typeof configuredEcdsaTargets)[number],
          targetEcdsaKey: ConfiguredTargetThresholdEcdsaWarmKey,
        ) => {
          if (!targetEcdsaKey.key) {
            throw new Error(
              '[login] threshold ECDSA warm-up requires configured target key identity',
            );
          }
          const publicCapability = await resolvePersistedEcdsaPublicCapabilityForLogin({
            walletId: args.walletIdentity.walletId,
            chainTarget: target.chainTarget,
            targetEcdsaKey,
          });
          const reusedMaterialActivation = activationByMaterial.get(
            sharedEcdsaActivationKey(publicCapability),
          );
          const exchangeActivation = args.passkeyExchangeEcdsaActivation;
          const matchingExchangeActivation =
            exchangeActivation &&
            !consumedPasskeyExchangeActivation &&
            exchangeActivation.targetKey === thresholdEcdsaChainTargetKey(target.chainTarget)
              ? exchangeActivation
              : null;
          const preauthorizedActivation =
            matchingExchangeActivation?.response || reusedMaterialActivation || null;
          const thresholdSessionId = preauthorizedActivation
            ? preauthorizedActivation.session.threshold_session_id
            : resolveThresholdLoginWarmEcdsaThresholdSessionId({
                sharedState: ecdsaThresholdSessionState,
              });
          const runtimePolicyScope = sharedState.activeCanonicalEcdsaContext.runtimePolicyScope;
          if (!runtimePolicyScope) {
            throw new Error('[login] ECDSA session lane requires runtimePolicyScope');
          }
          const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
            chainTarget: target.chainTarget,
            thresholdSessionId,
            thresholdSessionKind: 'jwt',
            ttlMs: args.ttlMs,
            remainingUses: unlockRemainingUses,
            runtimePolicyScope,
          });
          const existingRoleLocalMaterial = targetEcdsaKey.existingRoleLocalMaterial;
          if (!existingRoleLocalMaterial) {
            throw createThresholdEcdsaDeviceLinkRequiredError(
              thresholdEcdsaChainTargetKey(target.chainTarget),
            );
          }
          if (!localPasskeyCredentialIdB64u) {
            throw new Error('[login] ECDSA role-local activation requires passkey identity');
          }
          if (preauthorizedActivation) {
            if (matchingExchangeActivation) consumedPasskeyExchangeActivation = true;
            return await bootstrapLoginEcdsaSession({
              signingEngine: args.signingEngine,
              runtimeScopeBootstrapState: args.runtimeScopeBootstrapState,
              request: {
                kind: 'passkey_preauthorized_ecdsa_bootstrap',
                source: 'login',
                relayerUrl: args.relayerUrl,
                keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
                key: targetEcdsaKey.key,
                lanePolicy,
                publicCapability,
                existingRoleLocalMaterial,
                passkeyCredentialIdB64u: localPasskeyCredentialIdB64u,
                sessionActivation: preauthorizedActivation,
                beforeAuthorizationPersistence,
              },
            });
          }
          const currentBootstrapIdentity = resolveCurrentBootstrapIdentity();
          const reconnectRouteAuth = currentBootstrapIdentity.routeAuth;
          if (!isWalletSessionReconnectEcdsaRouteAuth(reconnectRouteAuth)) {
            throw new Error(
              '[login] ECDSA role-local activation requires a verified Wallet Session',
            );
          }
          return await bootstrapLoginEcdsaSession({
            signingEngine: args.signingEngine,
            runtimeScopeBootstrapState: args.runtimeScopeBootstrapState,
            request: {
              kind: 'wallet_session_reconnect_ecdsa_bootstrap',
              source: 'login',
              relayerUrl: args.relayerUrl,
              keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
              key: targetEcdsaKey.key,
              lanePolicy,
              publicCapability,
              existingRoleLocalMaterial,
              passkeyCredentialIdB64u: localPasskeyCredentialIdB64u,
              routeAuth: reconnectRouteAuth,
              beforeAuthorizationPersistence,
            },
          });
        };
        const bootstrapConfiguredTargets = async () => {
          completeActiveContextFromConfiguredTargets('login ECDSA warm-up preflight');
          for (const target of configuredEcdsaTargets) {
            const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
            const targetEcdsaKey = sharedState.activeCanonicalEcdsaContext.ecdsaKeys.find(
              (key) => key.targetKey === targetKey,
            );
            const keyHandle = String(targetEcdsaKey?.keyHandle || '').trim();
            if (!targetEcdsaKey?.key || !keyHandle) {
              throw createThresholdEcdsaDeviceLinkRequiredError(targetKey);
            }
            const bootstrap: ThresholdEcdsaSessionBootstrapResult = await bootstrapTarget(
              target,
              targetEcdsaKey,
            );
            ecdsaBootstraps.push(bootstrap);
            rememberEcdsaAuthorizedEd25519Mint(bootstrap);
            const activation = preauthorizedEcdsaActivationFromBootstrap(bootstrap);
            const activationKey = sharedEcdsaActivationKey(activation.public_capability);
            if (!activationByMaterial.has(activationKey)) {
              activationByMaterial.set(activationKey, activation);
            }
            const returnedKeyHandle = String(
              bootstrap.thresholdEcdsaKeyRef?.keyHandle || '',
            ).trim();
            if (returnedKeyHandle !== targetEcdsaKey.keyHandle) {
              throw new Error(
                `[login] threshold ECDSA warm-up returned a different keyHandle for ${targetKey}`,
              );
            }
          }
          if (args.passkeyExchangeEcdsaActivation && !consumedPasskeyExchangeActivation) {
            throw new Error(
              '[login] passkey exchange ECDSA activation did not match a configured target',
            );
          }
        };
        try {
          await bootstrapConfiguredTargets();
        } catch (error: unknown) {
          const details =
            thresholdLoginWarmupErrorMessage(error) ||
            'Failed to bootstrap threshold ECDSA session';
          throw new Error(`[login] threshold ECDSA warm-up failed: ${details}`);
        }
      },
    });
  }

  await runThresholdLoginWarmupTasks(tasks);
  return { ecdsaBootstraps, ed25519Session };
}

export async function getWalletSession(
  context: WalletSessionWebContext,
  walletId?: WalletId | string,
): Promise<WalletSession> {
  const currentAuthentication = context.signingEngine.readWalletAuthenticationState();
  const requestedWalletId =
    walletId ??
    (currentAuthentication.kind === 'authenticated' ? currentAuthentication.walletId : undefined);
  let readResolution = await resolveWalletCapabilitySubjectResolution(requestedWalletId);
  let didReconcileEcdsaActivation = false;
  if (readResolution.kind === 'no_session_request') return buildAnonymousWalletSession();
  if (readResolution.kind === 'no_session_for_wallet') {
    const journalSelectors = await resolveEcdsaActivationJournalSelectors(readResolution.walletId);
    if (journalSelectors.kind !== 'resolved') {
      return await buildCapabilityUnresolvableWalletSession({
        context,
        walletId: readResolution.walletId,
        reason: 'activation_reconciliation_failed',
      });
    }
    if (journalSelectors.selectors.length > 0) {
      didReconcileEcdsaActivation = true;
      const reconciliation = await reconcileCanonicalEcdsaActivationSelectors({
        workerCtx: context.signingEngine.getSignerWorkerContext(),
        selectors: journalSelectors.selectors,
      });
      if (reconciliation.didFinalize) {
        readResolution = await resolveWalletCapabilitySubjectResolution(readResolution.walletId);
      }
      if (readResolution.kind === 'no_session_for_wallet' && reconciliation.kind !== 'settled') {
        return await buildCapabilityUnresolvableWalletSession({
          context,
          walletId: readResolution.walletId,
          reason:
            reconciliation.kind === 'pending'
              ? 'activation_reconciliation_pending'
              : 'activation_reconciliation_failed',
        });
      }
    }
  }
  if (readResolution.kind === 'no_session_for_wallet') {
    return await buildCapabilityUnresolvableWalletSession({
      context,
      walletId: readResolution.walletId,
      reason: readResolution.reason,
    });
  }
  if (readResolution.kind === 'no_session_request') return buildAnonymousWalletSession();
  if (readResolution.kind === 'unresolvable_profile') {
    console.warn('[WalletSession] wallet session profile is unresolvable', {
      profileId: readResolution.profileId,
      reason: readResolution.reason,
    });
    return buildAnonymousWalletSession();
  }
  if (readResolution.kind === 'unresolvable') {
    console.warn('[WalletSession] wallet session identity is unresolvable', {
      walletId: String(readResolution.walletId),
      reason: readResolution.reason,
    });
    return await buildCapabilityUnresolvableWalletSession({
      context,
      walletId: readResolution.walletId,
      reason: readResolution.reason,
    });
  }

  const activeEcdsaSelectors = ecdsaActivationSelectorsFromSubjectSet(readResolution.subjectSet);
  if (!didReconcileEcdsaActivation && activeEcdsaSelectors.length > 0) {
    const reconciliation = await reconcileCanonicalEcdsaActivationSelectors({
      workerCtx: context.signingEngine.getSignerWorkerContext(),
      selectors: activeEcdsaSelectors,
    });
    reportNonSettledEcdsaActivationReconciliation(reconciliation);
  }
  await context.signingEngine.assertSealedRefreshStartupParity().catch((error: unknown) => {
    console.warn(
      '[WalletSession] sealed refresh startup parity check failed during session read; continuing with cached login state',
      error instanceof Error ? error.message : String(error || 'unknown error'),
    );
  });
  const nowMs = Date.now();
  const [appIdentity, reusableWalletSession, availableLanes] = await Promise.all([
    resolveWalletSessionAppIdentity(context, readResolution),
    readReusableWalletSessionState(context, readResolution.walletId, nowMs),
    readExactWalletSessionAvailableLanes(context, readResolution.walletId),
  ]);
  const capabilityProjection = buildWalletSessionCapabilityProjection({
    subjectSet: readResolution.subjectSet,
    availableLanes,
    reusableWalletSession,
    configuredEcdsaTargets: listConfiguredThresholdEcdsaPublicationTargets(
      context.configs.network.chains,
    ).map((target) => target.chainTarget),
  });
  return {
    appIdentity,
    authentication: walletAuthenticationForWallet(currentAuthentication, readResolution.walletId),
    reusableWalletSession,
    capabilityProjection,
    nonceDiagnostics: readWalletSessionNonceDiagnostics(context, appIdentity.nearAccountId),
  };
}

async function buildCapabilityUnresolvableWalletSession(args: {
  readonly context: WalletSessionWebContext;
  readonly walletId: WalletId;
  readonly reason: WalletSessionIdentityResolveFailure;
}): Promise<WalletSession> {
  const nowMs = Date.now();
  const [appIdentity, reusableWalletSession] = await Promise.all([
    resolveWalletSessionAppIdentityForWallet(args.context, args.walletId),
    readReusableWalletSessionState(args.context, args.walletId, nowMs),
  ]);
  return {
    appIdentity,
    authentication: walletAuthenticationForWallet(
      args.context.signingEngine.readWalletAuthenticationState(),
      args.walletId,
    ),
    reusableWalletSession,
    capabilityProjection: {
      kind: 'unresolvable',
      reason: args.reason,
    },
    nonceDiagnostics: readWalletSessionNonceDiagnostics(args.context, appIdentity.nearAccountId),
  };
}

function walletAuthenticationForWallet(
  authentication: WalletAuthenticationState,
  walletId: WalletId,
): WalletAuthenticationState {
  if (
    authentication.kind === 'authenticated' &&
    String(authentication.walletId) === String(walletId)
  ) {
    return authentication;
  }
  return { kind: 'signed_out' };
}

async function readReusableWalletSessionState(
  context: WalletSessionWebContext,
  walletId: WalletId,
  _nowMs: number,
): Promise<ReusableWalletSessionState> {
  try {
    return await context.signingEngine.readReusableWalletSessionState(walletId);
  } catch {
    return {
      kind: 'unavailable',
      walletId,
      reason: 'persistence_unavailable',
    };
  }
}

function readExactWalletSessionAvailableLanes(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<
  | { readonly kind: 'available'; readonly lanes: AvailableSigningLanes }
  | { readonly kind: 'unavailable' }
> {
  return context.signingEngine
    .readPersistedAvailableSigningLanes({ walletId })
    .then((lanes) => ({ kind: 'available' as const, lanes }))
    .catch(() => ({ kind: 'unavailable' as const }));
}

function readWalletSessionNonceDiagnostics(
  context: WalletSessionWebContext,
  nearAccountId?: AccountId | string | null,
): WalletSession['nonceDiagnostics'] {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return null;
  try {
    return context.signingEngine.getNonceCoordinator().getDiagnostics({
      accountId,
      emitMetrics: true,
    });
  } catch {
    return null;
  }
}

function normalizeEvmOwnerAddress(value: unknown): string {
  const candidate = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(candidate) ? candidate : '';
}

async function readProfileContinuityThresholdEcdsaWalletKeys(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<ActiveEcdsaSignerRecord['walletKey'][]> {
  const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
    context.configs.network.chains,
  ).map((target) => target.chainTarget);
  if (!configuredTargets.length) return [];
  const walletSigners = await IndexedDBManager.listAccountSignersByProfile({
    profileId: String(walletId),
    status: 'active',
  }).catch(() => []);
  const walletKeys: ActiveEcdsaSignerRecord['walletKey'][] = [];
  for (const signer of walletSigners) {
    const parsed = parseActiveEcdsaSignerRecordForUnlock({
      walletId,
      configuredTargets,
      signer,
    });
    if (parsed.kind === 'active_ecdsa_signer_record') {
      walletKeys.push(parsed.walletKey);
    }
  }
  return walletKeys;
}

async function resolveProfileContinuityThresholdEcdsaEthereumAddress(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<string | null> {
  const addresses = [
    ...new Set(
      (await readProfileContinuityThresholdEcdsaWalletKeys(context, walletId))
        .map((walletKey) => normalizeEvmOwnerAddress(walletKey.keyFacts.thresholdOwnerAddress))
        .filter(Boolean),
    ),
  ];
  if (addresses.length === 1) return addresses[0]!;
  if (addresses.length > 1) {
    console.warn('[WalletSession] conflicting profile threshold ECDSA addresses', {
      walletId: String(walletId),
      addresses,
    });
  }
  return null;
}

async function resolveThresholdEcdsaEthereumAddress(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<string | null> {
  const profileAddress = await resolveProfileContinuityThresholdEcdsaEthereumAddress(
    context,
    walletId,
  );
  if (profileAddress) return profileAddress;
  const snapshot = await readAvailableSigningLanesForUi(context, walletId).catch(() => null);
  if (!snapshot) return null;
  const addresses = [
    ...new Set(
      ecdsaAvailableLaneTargets(snapshot)
        .map((target) => ecdsaAvailableLaneForTarget(snapshot, target))
        .filter(
          (lane): lane is ConcreteAvailableEcdsaSigningLane =>
            lane.curve === 'ecdsa' && isConcreteAvailableSigningLane(lane),
        )
        .map((lane) => normalizeEvmOwnerAddress(lane.key.thresholdOwnerAddress))
        .filter(Boolean),
    ),
  ];
  if (addresses.length === 1) return addresses[0]!;
  if (addresses.length > 1) {
    console.warn('[WalletSession] conflicting threshold ECDSA sealed lane addresses', {
      walletId: String(walletId),
      addresses,
    });
  }
  return null;
}

function resolveThresholdLoginWarmSigners(args: {
  selection: WalletUnlockSelection;
  configuredEcdsaTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
  canonicalEcdsaContext?: CanonicalThresholdEcdsaWarmSessionContext | null;
}): ThresholdLoginWarmSigner[] {
  if (args.selection.mode === 'ed25519_only') return ['ed25519'];
  if (!args.configuredEcdsaTargets.length) {
    return args.selection.mode === 'ecdsa_only' ? [] : ['ed25519'];
  }
  const keyIdsByTarget = new Set(
    (args.canonicalEcdsaContext?.ecdsaKeys || []).map((key) => key.targetKey),
  );
  if (keyIdsByTarget.size === 0) {
    throw new Error('[login] threshold ECDSA warm-up missing canonical key identity');
  }
  const missingTargets = args.configuredEcdsaTargets
    .map((target) => thresholdEcdsaChainTargetKey(target.chainTarget))
    .filter((targetKey) => !keyIdsByTarget.has(targetKey));
  if (missingTargets.length) {
    throw new Error(
      `[login] threshold ECDSA warm-up missing configured-target key ids for ${missingTargets.join(
        ', ',
      )}`,
    );
  }
  return args.selection.mode === 'ecdsa_only' ? ['ecdsa'] : ['ed25519', 'ecdsa'];
}

function resolveThresholdLoginWarmupPlan(args: {
  selection: WalletUnlockSelection;
  selectedEcdsaTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[];
  storedCanonicalEcdsaContext: CanonicalThresholdEcdsaWarmSessionContext;
  canFirstBootstrapThresholdEcdsa: boolean;
  wantsEd25519Warmup: boolean;
}): ThresholdLoginWarmupPlan {
  const configuredTargetKeyCompletion = buildConfiguredTargetKeyCompletion({
    context: args.storedCanonicalEcdsaContext,
    configuredTargets: args.selectedEcdsaTargets,
  });
  let ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  let signersToWarm: ThresholdLoginWarmSigner[];
  const ed25519DependsOnEcdsa = false;
  let ecdsaDependsOnEd25519 = false;
  if (
    configuredTargetKeyCompletion.kind === 'missing_configured_target_keys' &&
    args.selectedEcdsaTargets.length
  ) {
    const initialContext: CanonicalThresholdEcdsaWarmSessionContext = {
      ecdsaKeys: [],
      ...(args.storedCanonicalEcdsaContext.runtimePolicyScope
        ? { runtimePolicyScope: args.storedCanonicalEcdsaContext.runtimePolicyScope }
        : {}),
    };
    if (!args.canFirstBootstrapThresholdEcdsa) {
      throw new Error(
        `[login] threshold ECDSA warm-up requires complete local key facts for ${configuredTargetKeyCompletion.missingTargets.join(
          ', ',
        )}; run explicit authenticated ECDSA key-facts inventory before unlock`,
      );
    }
    signersToWarm = args.wantsEd25519Warmup ? ['ed25519', 'ecdsa'] : ['ecdsa'];
    ecdsaDependsOnEd25519 = args.wantsEd25519Warmup;
    ecdsaContextResolution = {
      kind: 'first_bootstrap_missing_target_keys',
      initialContext,
    };
  } else {
    const resolvedCanonicalEcdsaContext = requireCompleteConfiguredTargetKeyContext({
      completion: configuredTargetKeyCompletion,
      source: 'stored ECDSA key facts',
    });
    ecdsaContextResolution = {
      kind: 'pre_resolved',
      context: resolvedCanonicalEcdsaContext,
    };
    signersToWarm = resolveThresholdLoginWarmSigners({
      selection: args.selection,
      configuredEcdsaTargets: args.selectedEcdsaTargets,
      canonicalEcdsaContext: resolvedCanonicalEcdsaContext,
    });
    if (args.wantsEd25519Warmup && !signersToWarm.includes('ed25519')) {
      signersToWarm = ['ed25519', ...signersToWarm];
    }
    ecdsaDependsOnEd25519 = signersToWarm.includes('ed25519') && signersToWarm.includes('ecdsa');
  }
  if (!signersToWarm.length) {
    throw new Error('[login] ECDSA unlock requested with no configured ECDSA targets');
  }
  return {
    kind: 'threshold_login_warmup_plan_ready',
    storedCanonicalEcdsaContext: args.storedCanonicalEcdsaContext,
    configuredTargetKeyCompletion,
    ecdsaContextResolution,
    signersToWarm,
    ed25519DependsOnEcdsa,
    ecdsaDependsOnEd25519,
  };
}

function createThresholdLoginWarmSessionId(prefix: string): string {
  return secureRandomId(prefix, 32, 'threshold login warm session IDs');
}

function requireThresholdLoginEcdsaSessionId(value: string) {
  const parsed = parseThresholdEcdsaSessionId(value);
  if (!parsed.ok) throw new Error('[login] failed to create threshold ECDSA session identity');
  return parsed.value;
}

function requireThresholdLoginWalletSessionMintId(value: string) {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) throw new Error('[login] failed to create reusable Wallet Session mint identity');
  return parsed.value;
}

function requireLoginUnlockSessionUses(remainingUses: number | null): number {
  if (remainingUses == null || remainingUses <= 0) {
    throw new Error('[login] unlock warm-up requires positive unlock session uses');
  }
  return remainingUses;
}

function createThresholdEcdsaDeviceLinkRequiredError(targetKey: string): Error & {
  code: 'device_link_required';
} {
  const error = new Error(
    `[login] device_link_required: local threshold ECDSA material is unavailable for ${targetKey}`,
  ) as Error & { code: 'device_link_required' };
  error.code = 'device_link_required';
  return error;
}

function createThresholdEd25519DeviceLinkRequiredError(): Error & {
  code: 'device_link_required';
} {
  const error = new Error(
    '[login] device_link_required: local threshold Ed25519 material is unavailable',
  ) as Error & { code: 'device_link_required' };
  error.code = 'device_link_required';
  return error;
}

type ThresholdLoginWarmEcdsaThresholdSessionState = {
  generatedThresholdSessionId: string;
};

function resolveThresholdLoginWarmEcdsaThresholdSessionId(input: {
  sharedState: ThresholdLoginWarmEcdsaThresholdSessionState;
}): string {
  const current = String(input.sharedState.generatedThresholdSessionId || '').trim();
  if (current) return current;
  const generated = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
  input.sharedState.generatedThresholdSessionId = generated;
  return generated;
}

async function resolveWalletEcdsaKeyFactsInventoryWithWebAuthn(args: {
  walletId: WalletId;
  relayerUrl: string;
  rpId: string;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  collectCredential?: (challengeB64u: string) => Promise<WebAuthnAuthenticationCredential>;
}) {
  if (!args.collectCredential) {
    throw new Error('[login] WebAuthn ECDSA key-facts inventory requires a credential collector');
  }
  const serverNonceB64u = createLocalUnlockChallengeB64u();
  const expectedChallengeDigestB64u = await computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u({
    walletId: args.walletId,
    rpId: args.rpId,
    keyTargets: args.keyTargets,
    serverNonceB64u,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  });
  const credential = await args.collectCredential(expectedChallengeDigestB64u);
  return await fetchWalletEcdsaKeyFactsInventoryWithWebAuthn({
    relayerUrl: args.relayerUrl,
    walletId: args.walletId,
    rpId: args.rpId,
    credential,
    keyTargets: args.keyTargets,
    serverNonceB64u,
    expectedChallengeDigestB64u,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  });
}

async function resolveWalletEcdsaKeyFactsInventoryForLogin(args: {
  walletId: WalletId;
  relayerUrl: string;
  rpId: string;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
  authority: LoginEcdsaKeyFactsInventoryAuthority | null;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  collectWebAuthnInventoryCredential?: (
    challengeB64u: string,
  ) => Promise<WebAuthnAuthenticationCredential>;
}): Promise<WalletEcdsaKeyFactsInventoryResponse> {
  const relayerUrl = String(args.relayerUrl || '').trim();
  const rpId = String(args.rpId || '').trim();
  if (!relayerUrl || !rpId) {
    throw new Error('[login] threshold ECDSA key-facts inventory requires relayerUrl and rpId');
  }
  if (args.authority?.kind === 'app_session') {
    return await fetchWalletEcdsaKeyFactsInventoryWithAppSession({
      relayerUrl,
      walletId: args.walletId,
      rpId,
      appSessionJwt: args.authority.appSessionJwt,
      keyTargets: args.keyTargets,
      policy: {
        permission: 'ecdsa_key_facts_inventory',
        walletId: args.walletId,
        chainTargets: args.keyTargets.map((target) => target.chainTarget),
        expiresAtMs: args.authority.policyExpiresAtMs,
      },
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    });
  }
  return await resolveWalletEcdsaKeyFactsInventoryWithWebAuthn({
    walletId: args.walletId,
    relayerUrl,
    rpId,
    keyTargets: args.keyTargets,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    collectCredential: args.collectWebAuthnInventoryCredential,
  });
}

type AuthenticatedEcdsaInventoryProfileRepairStore = Pick<
  typeof IndexedDBManager,
  'activateAccountSigner'
>;

function authenticatedInventorySignerMatch(args: {
  walletId: WalletId;
  configuredTargets: readonly ThresholdEcdsaChainTarget[];
  signer: AccountSignerRecord;
  record: ThresholdEcdsaKeyIdentityInventoryEntry;
}): boolean {
  const parsed = parseActiveEcdsaSignerRecordForUnlock({
    walletId: args.walletId,
    configuredTargets: args.configuredTargets,
    signer: args.signer,
  });
  switch (parsed.kind) {
    case 'active_ecdsa_signer_record':
      return (
        parsed.targetKey === thresholdEcdsaChainTargetKey(args.record.walletKey.chainTarget) &&
        String(parsed.walletKey.keyHandle) === String(args.record.walletKey.keyHandle)
      );
    case 'key_facts_inventory_required':
      return (
        parsed.targetKey === thresholdEcdsaChainTargetKey(args.record.walletKey.chainTarget) &&
        parsed.keyHandle === String(args.record.walletKey.keyHandle)
      );
    case 'blocked':
    case 'skipped':
      return false;
  }
  parsed satisfies never;
  return false;
}

function repairedEcdsaSignerMetadata(args: {
  signer: AccountSignerRecord;
  record: ThresholdEcdsaKeyIdentityInventoryEntry;
}): Record<string, unknown> {
  const walletKey = args.record.walletKey;
  const keyFacts = walletKey.keyFacts;
  const targetKey = thresholdEcdsaChainTargetKey(walletKey.chainTarget);
  return {
    ...(args.signer.metadata || {}),
    accountModel: 'threshold-ecdsa',
    accountAddress: args.record.accountAddress,
    ownerAddress: args.record.ownerAddress,
    thresholdOwnerAddress: keyFacts.thresholdOwnerAddress,
    keyScope: keyFacts.keyScope,
    keyHandle: walletKey.keyHandle,
    walletId: walletKey.walletId,
    ecdsaThresholdKeyId: keyFacts.ecdsaThresholdKeyId,
    signingRootId: keyFacts.signingRootId,
    signingRootVersion: keyFacts.signingRootVersion,
    publicCapability: args.record.publicCapability,
    thresholdEcdsaPublicKeyB64u: keyFacts.thresholdEcdsaPublicKeyB64u,
    participantIds: [...keyFacts.participantIds],
    chainTarget: walletKey.chainTarget,
    targetMembership: {
      targetKey,
      chainTarget: walletKey.chainTarget,
    },
    sharedEvmFamilyKey: {
      walletId: walletKey.walletId,
      keyScope: keyFacts.keyScope,
      keyHandle: walletKey.keyHandle,
      ecdsaThresholdKeyId: keyFacts.ecdsaThresholdKeyId,
      signingRootId: keyFacts.signingRootId,
      signingRootVersion: keyFacts.signingRootVersion,
      participantIds: [...keyFacts.participantIds],
      thresholdOwnerAddress: keyFacts.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: keyFacts.thresholdEcdsaPublicKeyB64u,
    },
    chainId: walletKey.chainTarget.chainId,
  };
}

export async function persistAuthenticatedEcdsaInventoryProfileRepairs(args: {
  store: AuthenticatedEcdsaInventoryProfileRepairStore;
  walletId: WalletId;
  configuredTargets: readonly ThresholdEcdsaChainTarget[];
  walletSigners: readonly AccountSignerRecord[];
  records: readonly ThresholdEcdsaKeyIdentityInventoryEntry[];
}): Promise<void> {
  for (const record of args.records) {
    const matchingSigners = args.walletSigners.filter((signer) =>
      authenticatedInventorySignerMatch({
        walletId: args.walletId,
        configuredTargets: args.configuredTargets,
        signer,
        record,
      }),
    );
    if (matchingSigners.length !== 1) {
      throw new Error(
        `[login] authenticated ECDSA key inventory could not identify one profile signer for ${thresholdEcdsaChainTargetKey(record.walletKey.chainTarget)}`,
      );
    }
    const signer = matchingSigners[0]!;
    if (
      String(record.walletKey.walletId) !== String(args.walletId) ||
      record.accountAddress !== signer.accountAddress ||
      record.ownerAddress !== signer.accountAddress ||
      String(record.walletKey.keyFacts.thresholdOwnerAddress) !== signer.accountAddress
    ) {
      throw new Error(
        `[login] authenticated ECDSA key inventory profile identity mismatch for ${thresholdEcdsaChainTargetKey(record.walletKey.chainTarget)}`,
      );
    }
    await args.store.activateAccountSigner({
      account: {
        profileId: signer.profileId,
        chainIdKey: signer.chainIdKey,
        accountAddress: signer.accountAddress,
        accountModel: 'threshold-ecdsa',
      },
      signer: {
        signerId: signer.signerId,
        signerType: signer.signerType,
        signerKind: signer.signerKind,
        signerAuthMethod: signer.signerAuthMethod,
        signerSource: signer.signerSource,
        metadata: repairedEcdsaSignerMetadata({ signer, record }),
      },
      activationPolicy: { mode: 'allocate_next_free' },
      preferredSlot: signer.signerSlot,
      selectAsActive: false,
      mutation: { routeThroughOutbox: false },
    });
  }
}

type LoginEcdsaKeyFactsInventoryInput = {
  keyFactsInventoryAuthority: LoginEcdsaKeyFactsInventoryAuthority | null;
  keyFactsInventoryRequested: boolean;
  relayerUrl: string;
  rpId: string;
  collectWebAuthnInventoryCredential?: (
    challengeB64u: string,
  ) => Promise<WebAuthnAuthenticationCredential>;
};

type ProfileContinuityEcdsaInventoryInput = LoginEcdsaKeyFactsInventoryInput &
  (
    | {
        kind: 'runtime_policy_scoped';
        runtimePolicyScope: ThresholdRuntimePolicyScope;
      }
    | {
        kind: 'runtime_policy_unscoped';
        runtimePolicyScope?: never;
      }
  );

function buildCanonicalThresholdEcdsaWarmSessionContext(
  ecdsaKeys: ConfiguredTargetThresholdEcdsaWarmKey[],
  runtimePolicyScope: ThresholdRuntimePolicyScope | undefined,
): CanonicalThresholdEcdsaWarmSessionContext {
  if (runtimePolicyScope) {
    return {
      ecdsaKeys,
      runtimePolicyScope,
    };
  }
  return { ecdsaKeys };
}

function buildProfileContinuityEcdsaInventoryInput(args: {
  input: LoginEcdsaKeyFactsInventoryInput | undefined;
  runtimePolicyScope: ThresholdRuntimePolicyScope | undefined;
}): ProfileContinuityEcdsaInventoryInput {
  const keyFactsInventoryAuthority = args.input?.keyFactsInventoryAuthority || null;
  const keyFactsInventoryRequested = args.input?.keyFactsInventoryRequested === true;
  const relayerUrl = args.input?.relayerUrl || '';
  const rpId = args.input?.rpId || '';
  const collectWebAuthnInventoryCredential = args.input?.collectWebAuthnInventoryCredential;
  if (args.runtimePolicyScope) {
    return {
      kind: 'runtime_policy_scoped',
      keyFactsInventoryAuthority,
      keyFactsInventoryRequested,
      relayerUrl,
      rpId,
      runtimePolicyScope: args.runtimePolicyScope,
      collectWebAuthnInventoryCredential,
    };
  }
  return {
    kind: 'runtime_policy_unscoped',
    keyFactsInventoryAuthority,
    keyFactsInventoryRequested,
    relayerUrl,
    rpId,
    collectWebAuthnInventoryCredential,
  };
}

async function resolveProfileContinuityEcdsaWarmKeys(
  walletId: WalletId,
  configuredTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[],
  keyFactsInventoryInput?: ProfileContinuityEcdsaInventoryInput,
): Promise<ConfiguredTargetThresholdEcdsaWarmKey[]> {
  const configuredChainTargets = configuredTargets.map((target) => target.chainTarget);
  const walletSigners = await IndexedDBManager.listAccountSignersByProfile({
    profileId: String(walletId),
    status: 'active',
  }).catch(() => []);
  const activeSignerRecords: ActiveEcdsaSignerRecord[] = [];
  const keyFactsInventoryRequiredRecords: KeyFactsInventoryRequiredEcdsaSignerRecord[] = [];
  const blockedRecords: BlockedEcdsaSignerRecord[] = [];
  for (const signer of walletSigners) {
    const parsed = parseActiveEcdsaSignerRecordForUnlock({
      walletId,
      configuredTargets: configuredChainTargets,
      signer,
    });
    switch (parsed.kind) {
      case 'active_ecdsa_signer_record':
        activeSignerRecords.push(parsed);
        break;
      case 'key_facts_inventory_required':
        keyFactsInventoryRequiredRecords.push(parsed);
        break;
      case 'blocked':
        blockedRecords.push(parsed);
        break;
      case 'skipped':
        break;
      default:
        parsed satisfies never;
    }
  }
  if (
    !activeSignerRecords.length &&
    !keyFactsInventoryRequiredRecords.length &&
    !blockedRecords.length
  ) {
    return [];
  }
  const plan = planUnlockEcdsaWarmup({
    selection: { mode: 'ecdsa_only', ecdsa: true },
    configuredTargets: configuredChainTargets,
    activeSignerRecords,
    keyFactsInventoryRequiredRecords,
    blockedRecords,
    runtimeConfig: {
      explicitKeyFactsInventoryMode: keyFactsInventoryInput?.keyFactsInventoryRequested === true,
      allowAuthenticatedKeyFactsInventory: Boolean(
        keyFactsInventoryInput?.keyFactsInventoryAuthority,
      ),
    },
  });
  switch (plan.kind) {
    case 'ready': {
      const missingCapabilityTargets = plan.readyTargets.filter(
        (target) => target.publicCapability.kind === 'missing_public_capability',
      );
      const repairedCapabilities = new Map<string, RouterAbEcdsaDerivationPublicCapabilityV1>();
      let repairedInventoryRecords: readonly ThresholdEcdsaKeyIdentityInventoryEntry[] = [];
      if (missingCapabilityTargets.length) {
        const inventory = await resolveWalletEcdsaKeyFactsInventoryForLogin({
          walletId,
          relayerUrl: keyFactsInventoryInput?.relayerUrl || '',
          rpId: keyFactsInventoryInput?.rpId || '',
          keyTargets: missingCapabilityTargets.map((target) => ({
            keyHandle: target.walletKey.keyHandle,
            chainTarget: target.chainTarget,
          })),
          authority: keyFactsInventoryInput?.keyFactsInventoryAuthority || null,
          ...(keyFactsInventoryInput?.runtimePolicyScope
            ? { runtimePolicyScope: keyFactsInventoryInput.runtimePolicyScope }
            : {}),
          collectWebAuthnInventoryCredential:
            keyFactsInventoryInput?.collectWebAuthnInventoryCredential,
        });
        repairedInventoryRecords = inventory.records;
        for (const record of inventory.records) {
          repairedCapabilities.set(
            thresholdEcdsaChainTargetKey(record.walletKey.chainTarget),
            record.publicCapability,
          );
        }
      }
      const keys = plan.readyTargets.map((target) =>
        configuredTargetThresholdEcdsaWarmKey({
          chainTarget: target.chainTarget,
          keyHandle: target.walletKey.keyHandle,
          key: evmFamilyEcdsaWalletKeyToIdentity(target.walletKey),
          publicCapability:
            target.publicCapability.kind === 'persisted_public_capability'
              ? target.publicCapability.value
              : repairedCapabilities.get(target.targetKey),
        }),
      );
      const canonicalKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
        source: 'profile continuity',
        keys,
      });
      const unresolvedCapabilities = canonicalKeys
        .filter((key) => key.publicCapability.kind === 'missing_public_capability')
        .map((key) => key.targetKey);
      if (unresolvedCapabilities.length) {
        throw new Error(
          `[login] authenticated ECDSA key inventory did not return public capabilities for ${unresolvedCapabilities.join(', ')}`,
        );
      }
      await persistAuthenticatedEcdsaInventoryProfileRepairs({
        store: IndexedDBManager,
        walletId,
        configuredTargets: configuredChainTargets,
        walletSigners,
        records: repairedInventoryRecords,
      });
      return canonicalKeys;
    }
    case 'no_configured_ecdsa_targets':
      return [];
    case 'awaiting_authenticated_key_facts_inventory': {
      const keyFactsInventoryAuthority = keyFactsInventoryInput?.keyFactsInventoryAuthority;
      if (!keyFactsInventoryAuthority) {
        throw new Error(
          '[login] threshold ECDSA key-facts inventory requires authenticated inventory authority',
        );
      }
      const inventory = await resolveWalletEcdsaKeyFactsInventoryForLogin({
        walletId,
        relayerUrl: keyFactsInventoryInput.relayerUrl,
        rpId: keyFactsInventoryInput.rpId,
        keyTargets: plan.keyTargets,
        authority: keyFactsInventoryAuthority,
        ...(keyFactsInventoryInput.runtimePolicyScope
          ? { runtimePolicyScope: keyFactsInventoryInput.runtimePolicyScope }
          : {}),
        collectWebAuthnInventoryCredential:
          keyFactsInventoryInput.collectWebAuthnInventoryCredential,
      });
      const inventoriedKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
        source: 'profile continuity inventory',
        keys: inventory.records.map((record) =>
          configuredTargetThresholdEcdsaWarmKey({
            chainTarget: record.walletKey.chainTarget,
            keyHandle: record.walletKey.keyHandle,
            key: evmFamilyEcdsaWalletKeyToIdentity(record.walletKey),
            publicCapability: record.publicCapability,
          }),
        ),
      });
      const inventoriedCompletion = buildConfiguredTargetKeyCompletion({
        context: { ecdsaKeys: inventoriedKeys },
        configuredTargets,
      });
      if (inventoriedCompletion.kind !== 'complete_configured_target_keys') {
        throw new Error(
          '[login] threshold ECDSA key-facts inventory returned incomplete key facts',
        );
      }
      await persistAuthenticatedEcdsaInventoryProfileRepairs({
        store: IndexedDBManager,
        walletId,
        configuredTargets: configuredChainTargets,
        walletSigners,
        records: inventory.records,
      });
      return inventoriedCompletion.context.ecdsaKeys;
    }
    case 'key_facts_inventory_required': {
      const targets = plan.keyFactsInventoryRequiredRecords
        .map((record) => record.targetKey)
        .join(', ');
      if (keyFactsInventoryInput?.keyFactsInventoryRequested) {
        throw new Error(
          `[login] threshold ECDSA key-facts inventory requires authenticated inventory authority for ${targets}`,
        );
      }
      throw new Error(
        `[login] threshold ECDSA warm-up requires complete local key facts for ${targets}; run explicit authenticated ECDSA key-facts inventory before unlock`,
      );
    }
    case 'blocked': {
      const reasons = plan.blockedRecords
        .map((record) => `${record.targetKey || 'unknown'}:${record.reason}`)
        .join(', ');
      throw new Error(
        `[login] threshold ECDSA warm-up requires complete local key facts before unlock; run explicit authenticated ECDSA key-facts inventory before unlock; blocked profile signer records: ${reasons}`,
      );
    }
  }
  plan satisfies never;
  return [];
}

async function resolveCanonicalThresholdEcdsaWarmSessionContext(
  context: LoginWebContext,
  walletId: WalletId,
  keyFactsInventoryInput?: LoginEcdsaKeyFactsInventoryInput,
): Promise<CanonicalThresholdEcdsaWarmSessionContext> {
  const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
    context.configs.network.chains,
  );
  const storedKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  let runtimePolicyScope: ThresholdRuntimePolicyScope | undefined;
  const exactStoredKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'stored',
    keys: storedKeys,
  });
  let canonicalContext = buildCanonicalThresholdEcdsaWarmSessionContext(
    exactStoredKeys,
    runtimePolicyScope,
  );
  const snapshot = await readAvailableSigningLanesForUi(context, walletId);
  const availableLaneKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  let availableLaneRuntimePolicyScope: ThresholdRuntimePolicyScope | undefined;
  if (snapshot) {
    for (const target of ecdsaAvailableLaneTargets(snapshot)) {
      const lane = ecdsaAvailableLaneForTarget(snapshot, target);
      if (!isConcreteAvailableSigningLane(lane)) continue;
      const keyHandle = String(lane.publicFacts.keyHandle || '').trim();
      if (!keyHandle) continue;
      const publicFacts = lane.capability.manifest.durableMaterial.roleLocalPublicFacts;
      if (String(publicFacts.keyHandle) !== keyHandle) {
        throw new Error(
          `[login] threshold ECDSA canonical lane identity mismatch for ${thresholdEcdsaChainTargetKey(target)}`,
        );
      }
      const publicCapability = publicFacts.publicCapability;
      const existingRoleLocalMaterial = lane.capability.material;
      const laneRuntimePolicyScope = lane.capability.manifest.durableMaterial.runtimePolicyScope;
      const signingRootBinding = resolveThresholdSigningRootBindingFromRuntimePolicyScope({
        runtimePolicyScope: laneRuntimePolicyScope,
      });
      if (
        String(signingRootBinding.signingRootId) !==
          String(lane.capability.manifest.signer.signingRootId) ||
        String(signingRootBinding.signingRootVersion) !==
          String(lane.capability.manifest.signer.signingRootVersion)
      ) {
        throw new Error(
          `[login] threshold ECDSA canonical runtime policy scope mismatch for ${thresholdEcdsaChainTargetKey(target)}`,
        );
      }
      if (
        availableLaneRuntimePolicyScope &&
        laneRuntimePolicyScope &&
        !sameThresholdRuntimePolicyScope(availableLaneRuntimePolicyScope, laneRuntimePolicyScope)
      ) {
        throw new Error(
          '[login] threshold ECDSA durable lanes have conflicting runtime policy scopes',
        );
      }
      if (!availableLaneRuntimePolicyScope && laneRuntimePolicyScope) {
        availableLaneRuntimePolicyScope = laneRuntimePolicyScope;
      }
      availableLaneKeys.push(
        configuredTargetThresholdEcdsaWarmKey({
          chainTarget: target,
          keyHandle,
          key: lane.key,
          publicCapability,
          existingRoleLocalMaterial,
        }),
      );
    }
  }
  const exactAvailableLaneKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'available lane',
    keys: availableLaneKeys,
  });
  canonicalContext = mergeThresholdEcdsaWarmSessionContexts({
    current: canonicalContext,
    incoming: buildCanonicalThresholdEcdsaWarmSessionContext(
      exactAvailableLaneKeys,
      availableLaneRuntimePolicyScope,
    ),
    source: 'durable lanes',
  });
  const configuredTargetCompletion = buildConfiguredTargetKeyCompletion({
    context: canonicalContext,
    configuredTargets,
  });
  if (configuredTargetCompletion.kind === 'complete_configured_target_keys') {
    return configuredTargetCompletion.context;
  }
  const missingTargets = new Set(configuredTargetCompletion.missingTargets);
  const missingConfiguredTargets = configuredTargets.filter((target) =>
    missingTargets.has(thresholdEcdsaChainTargetKey(target.chainTarget)),
  );
  const profileEcdsaThresholdKeys = await resolveProfileContinuityEcdsaWarmKeys(
    walletId,
    missingConfiguredTargets,
    buildProfileContinuityEcdsaInventoryInput({
      input: keyFactsInventoryInput,
      runtimePolicyScope: canonicalContext.runtimePolicyScope,
    }),
  );
  canonicalContext = mergeThresholdEcdsaWarmSessionContexts({
    current: canonicalContext,
    incoming: {
      ecdsaKeys: profileEcdsaThresholdKeys,
    },
    source: 'profile continuity',
  });
  return canonicalContext;
}

function resolveSessionExchangeRuntimeScope(
  context: Pick<LoginWebContext, 'configs'>,
): SessionExchangeRuntimeScope {
  const bootstrap = resolveManagedRuntimeScopeBootstrap(context.configs);
  if (!bootstrap) return { kind: 'unscoped' };
  return {
    kind: 'managed',
    projectEnvironmentId: bootstrap.projectEnvironmentId,
    publishableKey: bootstrap.publishableKey,
  };
}

async function resolveProfileContinuityThresholdEcdsaPublicKeyB64u(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<string | null> {
  const publicKeys = [
    ...new Set(
      (await readProfileContinuityThresholdEcdsaWalletKeys(context, walletId))
        .map((walletKey) => String(walletKey.keyFacts.thresholdEcdsaPublicKeyB64u || '').trim())
        .filter(Boolean),
    ),
  ];
  if (publicKeys.length === 1) return publicKeys[0]!;
  if (publicKeys.length > 1) {
    console.warn('[WalletSession] conflicting profile threshold ECDSA public keys', {
      walletId: String(walletId),
      publicKeyCount: publicKeys.length,
    });
  }
  return null;
}

async function resolveAvailableThresholdEcdsaPublicKeyB64u(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<string | null> {
  const snapshot = await readAvailableSigningLanesForUi(context, walletId).catch(() => null);
  if (!snapshot || String(snapshot.walletId) !== String(walletId)) return null;
  const publicKeys = new Set<string>();
  for (const target of ecdsaAvailableLaneTargets(snapshot)) {
    const lane = ecdsaAvailableLaneForTarget(snapshot, target);
    if (lane.curve !== 'ecdsa' || !isConcreteAvailableSigningLane(lane)) continue;
    const publicKey = String(lane.publicFacts.publicKeyB64u || '').trim();
    if (publicKey) publicKeys.add(publicKey);
  }
  const uniquePublicKeys = [...publicKeys];
  if (uniquePublicKeys.length === 1) return uniquePublicKeys[0]!;
  if (uniquePublicKeys.length > 1) {
    console.warn('[WalletSession] conflicting threshold ECDSA sealed lane public keys', {
      walletId: String(walletId),
      publicKeyCount: uniquePublicKeys.length,
    });
  }
  return null;
}

async function resolveThresholdEcdsaLoginMetadata(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<{
  ethereumAddress: string | null;
  thresholdEcdsaPublicKeyB64u: string | null;
}> {
  const [ethereumAddress, profilePublicKey] = await Promise.all([
    resolveThresholdEcdsaEthereumAddress(context, walletId),
    resolveProfileContinuityThresholdEcdsaPublicKeyB64u(context, walletId),
  ]);
  const thresholdEcdsaPublicKeyB64u =
    profilePublicKey || (await resolveAvailableThresholdEcdsaPublicKeyB64u(context, walletId));
  return {
    ethereumAddress,
    thresholdEcdsaPublicKeyB64u,
  };
}

async function readAvailableSigningLanesForUi(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<AvailableSigningLanes | null> {
  return await context.signingEngine.readPersistedAvailableSigningLanes({
    walletId,
  });
}

type ExactWalletSessionAvailableLanesRead = Awaited<
  ReturnType<typeof readExactWalletSessionAvailableLanes>
>;

type ExactAvailableSigningLane =
  | ConcreteAvailableEd25519SigningLane
  | ConcreteAvailableEcdsaSigningLane;

function failedCapabilityLane(
  reason: Extract<WalletSessionCapabilityLaneReadiness, { kind: 'failed' }>['reason'],
): Extract<WalletSessionCapabilityLaneReadiness, { kind: 'failed' }> {
  return {
    kind: 'failed',
    reason,
  };
}

function persistenceUnavailableCapabilityLane(): Extract<
  WalletSessionCapabilityLaneReadiness,
  { kind: 'failed' }
> {
  return {
    kind: 'failed',
    reason: 'persistence_unavailable',
  };
}

function supersededCapabilityLane(): Extract<
  WalletSessionCapabilityLaneReadiness,
  { kind: 'superseded' }
> {
  return {
    kind: 'superseded',
    replacement: 're_resolve_current_capability',
  };
}

function parseExactAvailableLaneReadiness(
  lane: ExactAvailableSigningLane,
): WalletSessionCapabilityLaneReadiness {
  switch (lane.state) {
    case 'ready':
      return { kind: 'ready' };
    case 'restorable':
      return { kind: 'pending', resume: 'restore_material' };
    case 'deferred':
      return { kind: 'pending', resume: 'resolve_deferred_state' };
    case 'expired':
      return { kind: 'authorization_required', requirement: 'wallet_session_expired' };
    case 'exhausted':
      return { kind: 'authorization_required', requirement: 'wallet_session_exhausted' };
  }
  throw new Error('[SeamsWeb] unsupported capability lane readiness');
}

function invalidLaneReasonForCurve(
  snapshot: AvailableSigningLanes,
  curve: 'ed25519' | 'ecdsa',
): Extract<WalletSessionCapabilityLaneReadiness, { kind: 'failed' }>['reason'] | null {
  const diagnostic = snapshot.diagnostics?.invalidLanes.find(
    (candidate) => candidate.curve === curve,
  );
  if (!diagnostic) return null;
  return diagnostic.reason === 'ambiguous_material' ||
    diagnostic.reason === 'conflicting_key_material'
    ? 'ambiguous_lane'
    : 'malformed';
}

function invalidEcdsaLaneReasonForTarget(
  snapshot: AvailableSigningLanes,
  chainTarget: ThresholdEcdsaChainTarget,
): Extract<WalletSessionCapabilityLaneReadiness, { kind: 'failed' }>['reason'] | null {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  const diagnostic = snapshot.diagnostics?.invalidLanes.find(
    (candidate) =>
      candidate.curve === 'ecdsa' &&
      (candidate.targetKey === undefined || candidate.targetKey === targetKey),
  );
  if (!diagnostic) return null;
  return diagnostic.reason === 'ambiguous_material' ||
    diagnostic.reason === 'conflicting_key_material'
    ? 'ambiguous_lane'
    : 'malformed';
}

function nearSubjectMatchesLane(
  subject: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>,
  lane: ConcreteAvailableEd25519SigningLane,
): boolean {
  return (
    String(lane.walletId) === String(subject.walletId) &&
    String(lane.nearAccountId) === String(subject.nearAccountId) &&
    String(lane.nearEd25519SigningKeyId) === String(subject.nearEd25519SigningKeyId) &&
    lane.signerSlot === subject.signerSlot
  );
}

function ecdsaSubjectMatchesLane(
  subject: Extract<WalletUnlockSubject, { kind: 'evm_family_ecdsa_wallet' }>,
  lane: ConcreteAvailableEcdsaSigningLane,
): boolean {
  return (
    String(lane.key.walletId) === String(subject.walletId) &&
    String(lane.key.ecdsaThresholdKeyId) === String(subject.ecdsaThresholdKeyId)
  );
}

function nearCapabilityReadiness(args: {
  readonly subject: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>;
  readonly availableLanes: ExactWalletSessionAvailableLanesRead;
  readonly superseded: boolean;
}): WalletSessionCapabilityReadiness {
  if (args.superseded) {
    return {
      kind: 'near_ed25519',
      subject: args.subject,
      lane: supersededCapabilityLane(),
    };
  }
  if (args.availableLanes.kind === 'unavailable') {
    return {
      kind: 'near_ed25519',
      subject: args.subject,
      lane: persistenceUnavailableCapabilityLane(),
    };
  }
  const snapshot = args.availableLanes.lanes;
  if (String(snapshot.walletId) !== String(args.subject.walletId)) {
    return {
      kind: 'near_ed25519',
      subject: args.subject,
      lane: failedCapabilityLane('identity_mismatch'),
    };
  }
  const invalidReason = invalidLaneReasonForCurve(snapshot, 'ed25519');
  if (invalidReason) {
    return {
      kind: 'near_ed25519',
      subject: args.subject,
      lane: failedCapabilityLane(invalidReason),
    };
  }
  const lane = snapshot.lanes.ed25519.near;
  if (!isConcreteAvailableSigningLane(lane)) {
    return {
      kind: 'near_ed25519',
      subject: args.subject,
      lane: failedCapabilityLane('missing'),
    };
  }
  return {
    kind: 'near_ed25519',
    subject: args.subject,
    lane: nearSubjectMatchesLane(args.subject, lane)
      ? parseExactAvailableLaneReadiness(lane)
      : failedCapabilityLane('identity_mismatch'),
  };
}

function ecdsaCapabilityLaneReadinessForTarget(args: {
  readonly subject: Extract<WalletUnlockSubject, { kind: 'evm_family_ecdsa_wallet' }>;
  readonly availableLanes: ExactWalletSessionAvailableLanesRead;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly superseded: boolean;
}): WalletSessionCapabilityLaneReadiness {
  if (args.superseded) return supersededCapabilityLane();
  if (args.availableLanes.kind === 'unavailable') return persistenceUnavailableCapabilityLane();
  const snapshot = args.availableLanes.lanes;
  if (String(snapshot.walletId) !== String(args.subject.walletId)) {
    return failedCapabilityLane('identity_mismatch');
  }
  const invalidReason = invalidEcdsaLaneReasonForTarget(snapshot, args.chainTarget);
  if (invalidReason) return failedCapabilityLane(invalidReason);
  const lane = ecdsaAvailableLaneForTarget(snapshot, args.chainTarget);
  if (!isConcreteAvailableSigningLane(lane)) return failedCapabilityLane('missing');
  if (!ecdsaSubjectMatchesLane(args.subject, lane)) {
    return failedCapabilityLane('identity_mismatch');
  }
  // A canonical-capability lane with no authorization is auth-neutral: exact
  // material, nothing authorizing it. It carries `state: 'deferred'` because
  // no authorization has scheduled it, and reporting that verbatim told the UI
  // nothing had been attempted -- when in fact the material is ready and only
  // needs a same-method step-up.
  if (lane.source === 'canonical_capability' && !lane.authorization) {
    return { kind: 'authorization_required', requirement: 'same_method_step_up' };
  }
  return parseExactAvailableLaneReadiness(lane);
}

function ecdsaCapabilityReadiness(args: {
  readonly subject: Extract<WalletUnlockSubject, { kind: 'evm_family_ecdsa_wallet' }>;
  readonly availableLanes: ExactWalletSessionAvailableLanesRead;
  readonly configuredTargets: readonly ThresholdEcdsaChainTarget[];
  readonly superseded: boolean;
}): WalletSessionCapabilityReadiness {
  const [firstTarget, ...remainingTargets] = args.configuredTargets;
  if (!firstTarget) {
    return {
      kind: 'evm_family_ecdsa',
      subject: args.subject,
      targets: { kind: 'no_configured_target' },
    };
  }
  return {
    kind: 'evm_family_ecdsa',
    subject: args.subject,
    targets: {
      kind: 'configured_targets',
      lanes: [
        {
          chainTarget: firstTarget,
          readiness: ecdsaCapabilityLaneReadinessForTarget({
            subject: args.subject,
            availableLanes: args.availableLanes,
            chainTarget: firstTarget,
            superseded: args.superseded,
          }),
        },
        ...remainingTargets.map((chainTarget) => ({
          chainTarget,
          readiness: ecdsaCapabilityLaneReadinessForTarget({
            subject: args.subject,
            availableLanes: args.availableLanes,
            chainTarget,
            superseded: args.superseded,
          }),
        })),
      ],
    },
  };
}

function buildWalletSessionCapabilityProjection(args: {
  readonly subjectSet: WalletUnlockSubjectSet;
  readonly availableLanes: ExactWalletSessionAvailableLanesRead;
  readonly reusableWalletSession: ReusableWalletSessionState;
  readonly configuredEcdsaTargets: readonly ThresholdEcdsaChainTarget[];
}): Extract<WalletSessionCapabilityProjection, { kind: 'resolved' }> {
  const capabilities = args.subjectSet.subjects.map((subject) => {
    switch (subject.kind) {
      case 'near_ed25519_wallet':
        return nearCapabilityReadiness({
          subject,
          availableLanes: args.availableLanes,
          superseded: args.reusableWalletSession.kind === 'superseded',
        });
      case 'evm_family_ecdsa_wallet':
        return ecdsaCapabilityReadiness({
          subject,
          availableLanes: args.availableLanes,
          configuredTargets: args.configuredEcdsaTargets,
          superseded: args.reusableWalletSession.kind === 'superseded',
        });
    }
    return assertNeverLoginState(subject);
  });
  const firstCapability = capabilities[0];
  if (!firstCapability) {
    throw new Error('[WalletSession] resolved capability subjects must be non-empty');
  }
  return {
    kind: 'resolved',
    subjectSet: args.subjectSet,
    capabilities: [firstCapability, ...capabilities.slice(1)],
  };
}

export function selectNearOperationalPublicKeyForLogin(
  userData: Pick<ClientUserData, 'operationalPublicKey'> | null,
): string | null {
  return userData ? userData.operationalPublicKey : null;
}

function userMatchesNearWalletSubject(
  user: ClientUserData | null,
  subject: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>,
): user is ClientUserData {
  return Boolean(
    user &&
    String(user.walletId) === String(subject.walletId) &&
    String(user.nearAccountId) === String(subject.nearAccountId) &&
    user.signerSlot === subject.signerSlot,
  );
}

async function resolveExactNearWalletUser(
  signingEngine: WalletSessionWebContext['signingEngine'],
  subject: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>,
): Promise<ClientUserData | null> {
  const lastUser = await signingEngine.getLastUser().catch(() => null);
  if (userMatchesNearWalletSubject(lastUser, subject)) return lastUser;
  const projected = await getNearAccountProjection(
    IndexedDBManager,
    subject.nearAccountId,
    subject.signerSlot,
  ).catch(() => null);
  if (userMatchesNearWalletSubject(projected, subject)) return projected;
  const stored = await signingEngine
    .getUserBySignerSlot(subject.nearAccountId, subject.signerSlot)
    .catch(() => null);
  return userMatchesNearWalletSubject(stored, subject) ? stored : null;
}

async function resolveWalletSessionAppIdentityForWallet(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<Extract<WalletSessionAppIdentity, { kind: 'resolved' }>> {
  const [authMethods, thresholdMetadata] = await Promise.all([
    readWalletAuthMethodBindingsForSession(walletId),
    resolveThresholdEcdsaLoginMetadata(context, walletId).catch(() => ({
      ethereumAddress: null,
      thresholdEcdsaPublicKeyB64u: null,
    })),
  ]);
  return {
    kind: 'resolved',
    walletId,
    nearAccountId: null,
    nearOperationalPublicKey: null,
    userData: null,
    authMethods,
    thresholdEcdsaEthereumAddress: thresholdMetadata.ethereumAddress,
    thresholdEcdsaPublicKeyB64u: thresholdMetadata.thresholdEcdsaPublicKeyB64u,
  };
}

async function resolveWalletSessionAppIdentity(
  context: WalletSessionWebContext,
  readResolution: Extract<WalletCapabilitySubjectResolution, { kind: 'resolved' }>,
): Promise<Extract<WalletSessionAppIdentity, { kind: 'resolved' }>> {
  const resolvedWalletId = readResolution.walletId;
  const nearSubject = selectNearEd25519WalletSubject(readResolution.subjectSet);
  const resolvedNearAccountId = nearSubject?.nearAccountId || null;
  const [userData, base] = await Promise.all([
    nearSubject ? resolveExactNearWalletUser(context.signingEngine, nearSubject) : null,
    resolveWalletSessionAppIdentityForWallet(context, resolvedWalletId),
  ]);
  return {
    ...base,
    nearAccountId: resolvedNearAccountId,
    nearOperationalPublicKey: selectNearOperationalPublicKeyForLogin(userData),
    userData,
  };
}

/**
 * List recently used accounts from IndexedDB.
 *
 * Used for account picker UIs and initial app bootstrap state.
 */
export async function getRecentUnlocks(
  context: RecentUnlocksWebContext,
): Promise<GetRecentUnlocksResult> {
  const allUsersData = await context.signingEngine.getAllUsers();
  const accounts = allUsersData.map((user) => recentUnlockAccountFromUser(user));
  const walletIds = [...new Set(accounts.map((account) => account.walletId))];
  const accountIds = [...new Set(accounts.map((account) => account.nearAccountId))];
  const lastUsedUser = await context.signingEngine.getLastUser();
  return {
    walletIds,
    accountIds,
    accounts,
    lastUsedAccount: lastUsedUser ? recentUnlockAccountFromUser(lastUsedUser) : null,
  };
}

/**
 * Lock: clears last-user pointer and client-side caches.
 */
export type LockOperationContext = {
  signingEngine: {
    clearWalletAuthentication(): void;
    getNonceCoordinator(): { clearAll(): void };
    clearThresholdEcdsaSigningQueue(): void;
    clearVolatileWarmSigningMaterial(): Promise<void>;
  };
};

export async function lock(context: LockOperationContext): Promise<void> {
  const { signingEngine } = context;
  signingEngine.clearWalletAuthentication();
  await IndexedDBManager.clearLastProfileSelection().catch(() => undefined);
  try {
    signingEngine.getNonceCoordinator().clearAll();
  } catch {}
  try {
    signingEngine.clearThresholdEcdsaSigningQueue();
  } catch {}
  await signingEngine.clearVolatileWarmSigningMaterial();
}
