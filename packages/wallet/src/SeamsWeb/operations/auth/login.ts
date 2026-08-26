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
import { readEmailOtpProviderSubjectForWalletV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { isWalletCustodySeedBinding } from '@shared/passkey-custody/custodySecretBinding';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { isObject } from '@shared/utils/validation';
import type { WalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import type { ActiveWalletSessionV1, WalletCapabilitySubjectV1 } from '@shared/device-linking';
import {
  mpcMaterialActivationRefsEqual,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseWalletId,
  type MpcMaterialActivationRef,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseReusableWalletSessionMintId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { requireOpaqueWalletSessionToken } from '@shared/utils/sessionTokens';
import {
  buildPasskeyWalletAuthAuthority,
  isEmailOtpWalletAuthAuthority,
  parseEmailOtpWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type EmailOtpProvider,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  resolveExactWalletAuthAuthority,
  type OwnerLaneScopeStores,
} from '@/core/signingEngine/session/identity/ownerLaneScope';
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
  verifyPasskeyWalletUnlock,
  verifyLinkedDevicePasskeyWalletSession,
  type LinkedDevicePasskeyWalletSessionUnlockInput,
  type PasskeySessionEcdsaCustodyContinuityV1,
  type PasskeySessionCustodyUnlockV1,
  type PasskeyWalletUnlockInput,
  type PasskeyWalletUnlockEd25519Session,
} from '@/core/rpcClients/near/rpcCalls';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '@/core/rpcClients/relayer/walletRegistration';
import { rememberPasskeyCustodySessionEnvelope } from '@/core/signingEngine/session/passkey/passkeyCustodySessionCache';
import { persistPasskeyEd25519YaoSignerMaterialV1 } from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import { buildPasskeyRouterAbEd25519WalletSessionState } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import {
  ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoActiveClientMetadataV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  IndexedDbEd25519YaoPublicCapabilityReferenceStore,
  publishEd25519YaoPublicCapabilityReferenceAndLane,
  type Ed25519YaoPublicCapabilityLaneReferenceV1,
} from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import {
  fetchWalletEcdsaKeyFactsInventoryWithOpaqueWalletSession,
  fetchWalletEcdsaKeyFactsInventoryWithWebAuthn,
  type WalletEcdsaKeyFactsInventoryResponse,
  type WalletEcdsaKeyFactsInventoryTarget,
} from '@/core/rpcClients/relayer/walletRegistration';
import type {
  AccountSignerRecord,
  LocalWalletAuthMethodRecordV2,
  WalletAuthorityExportRootRecordV1,
  WalletAuthorityLinkedSignerMaterialRecordV1,
  WalletAuthoritySignerMaterialRecordV1,
  WalletSelectionRecordV1,
  ProfileAuthenticatorRecord,
} from '@/core/indexedDB/passkeyClientDB.types';
import {
  openWalletAuthorityLinkedSignerMaterialV1,
  type OpenWalletAuthorityLinkedSignerMaterialResultV1,
} from '@/core/indexedDB/linkedAuthoritySignerMaterial';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { OpaqueWalletSessionAuth } from '@shared/utils/sessionTokens';
import { parseSignerSlot } from '@/core/signingEngine/webauthnAuth/device/signerSlot';
import {
  nearEd25519SigningKeyIdFromString,
  parseNearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  STALE_ECDSA_KEY_IDENTITY_ERROR_CODE,
  type ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  RouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  type EmailOtpEd25519SessionPolicyAuthority,
  type Ed25519SessionPolicyAuthority,
  type PasskeyEd25519SessionPolicyAuthority,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
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
  unlockEmailOtpAuthorityWallet,
  type EmailOtpAuthorityWalletUnlockResult,
  type EmailOtpAuthorityUnlockEd25519Request,
} from '@/core/signingEngine/session/emailOtp/walletUnlock';
import { disposeWalletCustodyEd25519ActiveClientV1 } from '@/core/signingEngine/walletCustody/ed25519ActiveClient';
import {
  destroyUnlockedWalletEd25519ExportRootCapabilitiesV1,
  establishUnlockedWalletEd25519ExportRootCapabilityV1 as establishUnlockedExportRootCapabilityV1,
  walletCustodyCeremonyTransportFromWorkerContextV1,
} from '@/core/signingEngine/walletCustody/unlockedEd25519ExportRootCapability';
import type { OwnerLaneScope } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  deriveEvmFamilySigningKeySlotId,
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
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '@shared/utils/ecdsaKeyFactsInventory';
import {
  buildEmailOtpWalletAuthMethodBinding,
  buildPasskeyAuthScope,
  buildPasskeyWalletAuthMethodBinding,
  buildWalletIdentity,
  parseRpId,
  walletAuthMethodBindingId,
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
import { base58Encode } from '@shared/utils/base58';
import {
  openWalletCustodyEd25519ActiveClientV1,
  walletCustodyActivationFactsFromActiveClientMetadataV1,
  walletCustodyCacheEnvelopeFromRecordV1,
  type WalletCustodyActivationFactsV1,
} from '@/core/signingEngine/walletCustody/openCustodyCache';
import { joinCustodyWireFromEnvelopeRecord } from '@/core/signingEngine/walletCustody/joinCustodyWire';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import {
  destroyLinkedDeviceEcdsaHolderMaterialWasm,
  reconcileCanonicalEcdsaActivationWasm,
  storeLinkedDeviceEcdsaHolderMaterialWasm,
} from '@/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm';
import {
  installLinkedEcdsaHolderRuntimeV1,
  removeLinkedEcdsaHolderRuntimeV1,
  resolveLinkedEcdsaHolderRuntimeV1,
  type LinkedEcdsaHolderRuntimeV1,
} from '@/core/signingEngine/session/material/linkedEcdsaHolderRuntime';
import {
  resolveWalletUnlockSubjectSet,
  resolveWalletCapabilitySubjectResolution,
  type WalletCapabilitySubjectResolution,
  type WalletUnlockSubject,
  type WalletUnlockSubjectSet,
} from './walletUnlockSubject';
import { resolveEcdsaActivationJournalSelectors } from './walletUnlockEcdsaSubject';

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
  signerSlot: NearEd25519WalletSubject['signerSlot'];
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
        signerSlot: nearSubject.signerSlot,
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
        signerSlot: nearSubject.signerSlot,
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
  record: LocalWalletAuthMethodRecordV2,
): WalletAuthMethodBinding | null {
  const wallet = buildWalletIdentity({ walletId: record.walletId });
  switch (record.kind) {
    case 'passkey': {
      const rpId = parseRpId(record.rpId);
      if (!rpId.ok) return null;
      return buildPasskeyWalletAuthMethodBinding({
        walletAuthMethodId: record.walletAuthMethodId,
        scope: buildPasskeyAuthScope({ wallet, rpId: rpId.value }),
        credentialIdB64u: record.credentialIdB64u,
      });
    }
    case 'email_otp':
      return buildEmailOtpWalletAuthMethodBinding({
        walletAuthMethodId: record.walletAuthMethodId,
        wallet,
        emailHashHex: record.emailHashHex,
        registrationAuthorityId: record.registrationAuthorityId,
      });
    default:
      record satisfies never;
      return null;
  }
}

async function exactPasskeyWalletAuthAuthorityRefForCredential(args: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly credentialIdB64u: string;
}): Promise<WalletAuthAuthorityRef> {
  const records = await IndexedDBManager.listWalletAuthMethodsV2ForWallet(String(args.walletId));
  const matches = records.filter(
    (record): record is Extract<LocalWalletAuthMethodRecordV2, { kind: 'passkey' }> =>
      record.kind === 'passkey' &&
      record.status === 'active' &&
      record.walletId === args.walletId &&
      String(record.rpId) === args.rpId &&
      String(record.credentialIdB64u) === args.credentialIdB64u,
  );
  const [record] = matches;
  if (matches.length !== 1 || !record) {
    throw new Error('[login] passkey authority requires one exact active V2 auth method');
  }
  return await walletAuthAuthorityRef({
    authority: {
      walletId: record.walletId,
      factor: {
        kind: 'passkey',
        credentialIdB64u: record.credentialIdB64u,
      },
      verifier: {
        kind: 'webauthn',
        rpId: record.rpId,
      },
      bindingId: record.walletAuthMethodId,
    },
  });
}

function walletAuthAuthorityForSelectedPasskeyMethod(
  record: Extract<LocalWalletAuthMethodRecordV2, { kind: 'passkey'; status: 'active' }>,
): PasskeyWalletAuthAuthority {
  return {
    walletId: record.walletId,
    factor: {
      kind: 'passkey',
      credentialIdB64u: record.credentialIdB64u,
    },
    verifier: {
      kind: 'webauthn',
      rpId: record.rpId,
    },
    bindingId: record.walletAuthMethodId,
  };
}

async function walletAuthAuthorityRefForSelectedPasskeyMethod(
  record: Extract<LocalWalletAuthMethodRecordV2, { kind: 'passkey'; status: 'active' }>,
): Promise<WalletAuthAuthorityRef> {
  return await walletAuthAuthorityRef({
    authority: walletAuthAuthorityForSelectedPasskeyMethod(record),
  });
}

function linkedDeviceOwnerLaneScopeStores(): OwnerLaneScopeStores {
  return {
    getWalletAuthMethodV2: IndexedDBManager.getWalletAuthMethodV2.bind(IndexedDBManager),
    listWalletAuthMethodsForWallet:
      IndexedDBManager.listWalletAuthMethodsForWallet.bind(IndexedDBManager),
    getWalletPasskeyAuthenticator:
      IndexedDBManager.getWalletPasskeyAuthenticator.bind(IndexedDBManager),
    readEmailOtpProviderSubjectForWallet: (walletId: string) =>
      readEmailOtpProviderSubjectForWalletV1(IndexedDBManager, walletId),
  };
}

export async function resolveExactLinkedEmailOtpAuthority(args: {
  readonly authMethod: Extract<
    LocalWalletAuthMethodRecordV2,
    { kind: 'email_otp'; status: 'active' }
  >;
  readonly provider: EmailOtpProvider;
  readonly providerSubjectId: string;
}): Promise<EmailOtpWalletAuthAuthority> {
  const authority = parseEmailOtpWalletAuthAuthority({
    walletId: args.authMethod.walletId,
    factor: {
      kind: 'email_otp',
      provider: args.provider,
      providerUserId: args.providerSubjectId,
    },
    verifier: {
      kind: 'email_otp_wallet_auth_method',
      emailHashHex: args.authMethod.emailHashHex,
    },
    bindingId: args.authMethod.walletAuthMethodId,
  });
  if (!authority) {
    throw new Error('[login] linked Email OTP provider identity does not match selected authority');
  }
  return authority;
}

async function walletAuthAuthorityForLinkedDeviceMethod(args: {
  readonly selection: LinkedDeviceAuthoritySelection;
  readonly providerIdentity?: LinkedDeviceEmailOtpProviderIdentity;
}): Promise<WalletAuthAuthority> {
  if (args.selection.authMethod.kind === 'passkey') {
    return walletAuthAuthorityForSelectedPasskeyMethod(args.selection.authMethod);
  }
  const providerIdentity = args.providerIdentity;
  if (!providerIdentity) {
    throw new Error('[login] linked Email OTP authority provider identity is missing');
  }
  return await resolveExactLinkedEmailOtpAuthority({
    authMethod: args.selection.authMethod,
    provider: providerIdentity.provider,
    providerSubjectId: providerIdentity.providerSubjectId,
  });
}

async function walletAuthAuthorityRefForLinkedDeviceMethod(args: {
  readonly selection: LinkedDeviceAuthoritySelection;
  readonly providerIdentity?: LinkedDeviceEmailOtpProviderIdentity;
}): Promise<WalletAuthAuthorityRef> {
  return await walletAuthAuthorityRef({
    authority: await walletAuthAuthorityForLinkedDeviceMethod(args),
  });
}

function selectedSignerMaterialForActivation(
  materials: readonly WalletAuthoritySignerMaterialRecordV1[],
  authorityId: string,
  walletAuthMethodId: string,
  activation: MpcMaterialActivationRef,
): WalletAuthoritySignerMaterialRecordV1 | null {
  let selected: WalletAuthoritySignerMaterialRecordV1 | null = null;
  for (const material of materials) {
    if (
      material.authorityId !== authorityId ||
      material.walletAuthMethodId !== walletAuthMethodId ||
      material.activationId !== activation.activationId
    ) {
      continue;
    }
    if (selected) return null;
    selected = material;
  }
  return selected;
}

function linkedDeviceUnlockIdentityMismatchLabels(input: {
  walletId: WalletId;
  selection: WalletSelectionRecordV1;
  authMethod: WalletAuthMethodRecordV2;
  authority: WalletAuthorityV1;
  expectedKind?: WalletAuthMethodRecordV2['kind'];
  /**
   * R109C: the caller named the method rather than taking the selected one.
   *
   * The selection still names the sibling that was in use, which is the
   * expected state for an added method rather than corruption - invariant 9
   * keeps the source selected until a lock and unlock moves it. Everything else
   * is still checked, and the move itself remains guarded to members of one
   * authority.
   */
  allowUnselectedSibling?: boolean;
}): readonly string[] {
  const failures: string[] = [];
  if (input.selection.walletId !== input.walletId) failures.push('selection_wallet_id');
  if (
    !input.allowUnselectedSibling &&
    input.selection.walletAuthMethodId !== input.authMethod.walletAuthMethodId
  ) {
    failures.push('selection_auth_method_id');
  }
  if (input.authMethod.walletId !== input.walletId) failures.push('auth_method_wallet_id');
  if (input.authMethod.status !== 'active') failures.push('auth_method_inactive');
  if (input.expectedKind && input.authMethod.kind !== input.expectedKind) {
    failures.push(`auth_method_not_${input.expectedKind}`);
  }
  if (input.authority.walletId !== input.walletId) failures.push('authority_wallet_id');
  if (input.authority.state !== 'active') failures.push('authority_inactive');
  if (input.authority.authorityId !== input.authMethod.walletAuthorityId) {
    failures.push('authority_auth_method_id');
  }
  return failures;
}

type LinkedDeviceAuthoritySelection = Readonly<{
  readonly walletId: WalletId;
  readonly selection: WalletSelectionRecordV1;
  readonly authMethod: Extract<LocalWalletAuthMethodRecordV2, { status: 'active' }>;
  readonly authority: Extract<WalletAuthorityV1, { state: 'active' }>;
  readonly signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
  readonly exportRoot: WalletAuthorityExportRootRecordV1 | null;
}>;

export type LinkedDevicePasskeyAuthoritySelection = LinkedDeviceAuthoritySelection &
  Readonly<{
    readonly kind: 'linked_device_passkey_authority_selection_v1';
    readonly walletId: WalletId;
    readonly selection: WalletSelectionRecordV1;
    readonly authMethod: Extract<
      LocalWalletAuthMethodRecordV2,
      { kind: 'passkey'; status: 'active' }
    >;
    readonly authority: Extract<WalletAuthorityV1, { state: 'active' }>;
    readonly signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
    readonly exportRoot: WalletAuthorityExportRootRecordV1 | null;
  }>;

export type LinkedDeviceEmailOtpAuthoritySelection = LinkedDeviceAuthoritySelection &
  Readonly<{
    readonly kind: 'linked_device_email_otp_authority_selection_v1';
    readonly authMethod: Extract<
      LocalWalletAuthMethodRecordV2,
      { kind: 'email_otp'; status: 'active' }
    >;
  }>;

export type LinkedDeviceEmailOtpAuthorityResolution =
  | { readonly kind: 'none' }
  | { readonly kind: 'selected'; readonly selection: LinkedDeviceEmailOtpAuthoritySelection }
  | { readonly kind: 'rejected'; readonly message: string };

export type LinkedDevicePasskeyOpenedMaterial = Extract<
  OpenWalletAuthorityLinkedSignerMaterialResultV1,
  { readonly kind: 'opened_wallet_authority_linked_signer_material_v1' }
>;

export async function resolveLinkedDevicePasskeyAuthoritySelection(
  walletIdInput: string,
): Promise<LinkedDevicePasskeyAuthoritySelection | null> {
  const parsedWalletId = parseWalletId(walletIdInput);
  if (!parsedWalletId.ok) return null;
  const walletId = parsedWalletId.value;
  try {
    const resolved = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
    if (resolved.kind !== 'resolved') return null;
    const { selection, authMethod, authority } = resolved;
    const identityMismatchLabels = linkedDeviceUnlockIdentityMismatchLabels({
      walletId,
      selection,
      authMethod,
      authority,
      expectedKind: 'passkey',
    });
    if (identityMismatchLabels.length > 0) return null;
    if (authMethod.status !== 'active' || authMethod.kind !== 'passkey') return null;
    if (authority.state !== 'active') return null;
    if (authority.provenance.kind !== 'device_link') return null;
    return {
      kind: 'linked_device_passkey_authority_selection_v1',
      walletId,
      selection,
      authMethod,
      authority,
      signerMaterials: resolved.signerMaterials,
      exportRoot: resolved.exportRoot,
    };
  } catch {
    return null;
  }
}

export async function resolveLinkedDeviceEmailOtpAuthoritySelection(args: {
  readonly walletIdInput: string;
  readonly emailHashHex: string;
  readonly provider: EmailOtpProvider;
  readonly providerSubjectId: string;
  /**
   * R109C: resolve as this method rather than as the selected one.
   *
   * An added sibling is not selected yet - invariant 9 leaves the source
   * selected until a lock and unlock - so resolving through the selection would
   * refuse the very method being unlocked. The unlock moves the selection
   * afterwards, and that move is still guarded to members of one authority.
   */
  readonly walletAuthMethodId?: string;
}): Promise<LinkedDeviceEmailOtpAuthorityResolution> {
  const parsedWalletId = parseWalletId(args.walletIdInput);
  const emailHashHex = String(args.emailHashHex || '')
    .trim()
    .toLowerCase();
  const providerSubjectId = String(args.providerSubjectId || '').trim();
  if (!parsedWalletId.ok || !emailHashHex || !providerSubjectId) return { kind: 'none' };
  const walletId = parsedWalletId.value;
  let resolved: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>;
  try {
    resolved = args.walletAuthMethodId
      ? await IndexedDBManager.resolveWalletAuthorityForMethod(
          String(walletId),
          args.walletAuthMethodId,
        )
      : await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      message:
        error instanceof Error ? error.message : 'Selected Email OTP authority is unavailable',
    };
  }
  if (resolved.kind === 'missing_selection') return { kind: 'none' };
  if (resolved.kind !== 'resolved') {
    return { kind: 'rejected', message: 'Selected Email OTP authority is unavailable' };
  }
  const { selection, authMethod, authority } = resolved;
  if (authMethod.kind !== 'email_otp') return { kind: 'none' };
  const mismatchLabels = linkedDeviceUnlockIdentityMismatchLabels({
    walletId,
    selection,
    authMethod,
    authority,
    expectedKind: 'email_otp',
    allowUnselectedSibling: Boolean(args.walletAuthMethodId),
  });
  if (mismatchLabels.length > 0 || authMethod.emailHashHex.toLowerCase() !== emailHashHex) {
    return {
      kind: 'rejected',
      message: 'Selected Email OTP authority is inactive or does not match the verified email',
    };
  }
  if (authMethod.status !== 'active' || authority.state !== 'active') {
    return { kind: 'rejected', message: 'Selected Email OTP authority is inactive' };
  }
  try {
    await resolveExactLinkedEmailOtpAuthority({
      authMethod,
      provider: args.provider,
      providerSubjectId,
    });
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      message:
        error instanceof Error
          ? error.message
          : 'Selected Email OTP provider identity does not match the local authority',
    };
  }
  if (authority.provenance.kind === 'device_link' && resolved.signerMaterials.length === 0) {
    return {
      kind: 'rejected',
      message: 'Selected linked Email OTP authority has no signer material',
    };
  }
  if (
    resolved.signerMaterials.some(
      (material) => material.kind !== 'wallet_authority_linked_signer_material_v1',
    )
  ) {
    return {
      kind: 'rejected',
      message: 'Selected Email OTP authority has an invalid linked signer material set',
    };
  }
  return {
    kind: 'selected',
    selection: {
      kind: 'linked_device_email_otp_authority_selection_v1',
      walletId,
      selection,
      authMethod,
      authority,
      signerMaterials: resolved.signerMaterials,
      exportRoot: resolved.exportRoot,
    },
  };
}

function linkedDeviceActivationForCapability(
  authority: Extract<WalletAuthorityV1, { state: 'active' }>,
  subject: Extract<WalletCapabilitySubjectV1, { kind: 'sign' | 'export_keys' }>,
): MpcMaterialActivationRef {
  const activation =
    subject.keyFamily === 'ed25519'
      ? authority.signerActivations.ed25519
      : authority.signerActivations.ecdsa;
  if (!activation) {
    throw new Error(
      `[login] linked Wallet Session requested unavailable ${subject.keyFamily} material`,
    );
  }
  if (!mpcMaterialActivationRefsEqual(activation.materialActivation, subject.materialActivation)) {
    throw new Error('[login] linked Wallet Session material activation does not match authority');
  }
  return activation.materialActivation;
}

function assertLinkedDeviceWalletSessionExact(
  selection: LinkedDeviceAuthoritySelection,
  walletSession: ActiveWalletSessionV1,
): void {
  if (
    walletSession.walletId !== selection.walletId ||
    walletSession.authorityId !== selection.authority.authorityId ||
    walletSession.authMethodId !== selection.authMethod.walletAuthMethodId ||
    walletSession.authorityDigestB64u !== selection.authority.authorityDigestB64u ||
    walletSession.authorityRevocationEpoch !== selection.authority.revocationEpoch
  ) {
    throw new Error('[login] linked Wallet Session identity does not match selected authority');
  }
  for (const subject of walletSession.capabilitySubjects) {
    switch (subject.kind) {
      case 'sign':
      case 'export_keys': {
        const activation = linkedDeviceActivationForCapability(selection.authority, subject);
        const material = selectedSignerMaterialForActivation(
          selection.signerMaterials,
          selection.authority.authorityId,
          selection.authMethod.walletAuthMethodId,
          activation,
        );
        if (!material || material.keyFamily !== subject.keyFamily) {
          throw new Error('[login] linked Wallet Session signer material is unavailable');
        }
        if (
          !mpcMaterialActivationRefsEqual(material.materialActivation, subject.materialActivation)
        ) {
          throw new Error('[login] linked Wallet Session signer material activation is invalid');
        }
        break;
      }
      case 'link_devices':
      case 'revoke_devices':
        break;
      default:
        return assertNeverLoginState(subject);
    }
  }
}

function assertLinkedPasskeyMaterialTargetFactor(
  material: Extract<
    WalletAuthoritySignerMaterialRecordV1,
    { readonly kind: 'wallet_authority_linked_signer_material_v1' }
  >,
  selection: LinkedDevicePasskeyAuthoritySelection,
): void {
  const target = material.targetFactor;
  if (
    target.kind !== 'passkey' ||
    target.walletAuthMethodId !== selection.authMethod.walletAuthMethodId ||
    target.rpId !== selection.authMethod.rpId ||
    target.credentialIdB64u !== selection.authMethod.credentialIdB64u
  ) {
    throw new Error('[login] linked passkey signer material target factor does not match V2 auth');
  }
}

async function openLinkedDevicePasskeySignerMaterials(args: {
  readonly selection: LinkedDevicePasskeyAuthoritySelection;
  readonly credential: WebAuthnAuthenticationCredential;
}): Promise<readonly [LinkedDevicePasskeyOpenedMaterial, ...LinkedDevicePasskeyOpenedMaterial[]]> {
  const prfFirstB64u = passkeyPrfFirstB64uFromCredential(args.credential);
  if (!prfFirstB64u) {
    throw new Error('[login] linked passkey unlock requires WebAuthn PRF.first output');
  }
  let factorSecret: Uint8Array;
  try {
    factorSecret = base64UrlDecode(prfFirstB64u);
  } catch {
    throw new Error('[login] linked passkey unlock returned an invalid PRF.first output');
  }
  try {
    if (factorSecret.byteLength !== 32) {
      throw new Error('[login] linked passkey unlock requires a 32-byte PRF.first output');
    }
    const opened: LinkedDevicePasskeyOpenedMaterial[] = [];
    for (const material of args.selection.signerMaterials) {
      if (material.kind !== 'wallet_authority_linked_signer_material_v1') {
        throw new Error('[login] linked passkey signer material is not a linked sealed record');
      }
      assertLinkedPasskeyMaterialTargetFactor(material, args.selection);
      const result = await openWalletAuthorityLinkedSignerMaterialV1({
        record: material,
        factorSecret,
        expected: {
          authorityId: args.selection.authority.authorityId,
          walletId: args.selection.walletId,
          walletAuthMethodId: args.selection.authMethod.walletAuthMethodId,
          packageSetDigestB64u: material.packageSetDigestB64u,
          targetFactor: material.targetFactor,
          materialActivation: material.materialActivation,
          keyFamily: material.keyFamily,
        },
      });
      if (result.kind !== 'opened_wallet_authority_linked_signer_material_v1') {
        throw new Error(`[login] linked passkey signer material open failed: ${result.reason}`);
      }
      opened.push(result);
    }
    const [first, ...rest] = opened;
    if (!first) throw new Error('[login] linked passkey signer material set is empty');
    return [first, ...rest];
  } finally {
    factorSecret.fill(0);
  }
}

function assertLinkedEmailOtpMaterialTargetFactor(
  material: Extract<
    WalletAuthoritySignerMaterialRecordV1,
    { readonly kind: 'wallet_authority_linked_signer_material_v1' }
  >,
  selection: LinkedDeviceEmailOtpAuthoritySelection,
): void {
  const target = material.targetFactor;
  if (
    target.kind !== 'email_otp' ||
    target.walletAuthMethodId !== selection.authMethod.walletAuthMethodId ||
    target.emailHashHex.toLowerCase() !== selection.authMethod.emailHashHex.toLowerCase() ||
    target.registrationAuthorityId !== selection.authMethod.registrationAuthorityId
  ) {
    throw new Error(
      '[login] linked Email OTP signer material target factor does not match V2 auth',
    );
  }
}

async function openLinkedDeviceEmailOtpSignerMaterials(args: {
  readonly selection: LinkedDeviceEmailOtpAuthoritySelection;
  readonly factorSecret32: Uint8Array;
}): Promise<readonly [LinkedDevicePasskeyOpenedMaterial, ...LinkedDevicePasskeyOpenedMaterial[]]> {
  if (args.factorSecret32.byteLength !== 32) {
    throw new Error('[login] linked Email OTP unlock requires a 32-byte factor secret');
  }
  const factorSecret = args.factorSecret32.slice();
  try {
    const opened: LinkedDevicePasskeyOpenedMaterial[] = [];
    for (const material of args.selection.signerMaterials) {
      if (material.kind !== 'wallet_authority_linked_signer_material_v1') {
        throw new Error('[login] linked Email OTP signer material is not a linked sealed record');
      }
      assertLinkedEmailOtpMaterialTargetFactor(material, args.selection);
      const result = await openWalletAuthorityLinkedSignerMaterialV1({
        record: material,
        factorSecret,
        expected: {
          authorityId: args.selection.authority.authorityId,
          walletId: args.selection.walletId,
          walletAuthMethodId: args.selection.authMethod.walletAuthMethodId,
          packageSetDigestB64u: material.packageSetDigestB64u,
          targetFactor: material.targetFactor,
          materialActivation: material.materialActivation,
          keyFamily: material.keyFamily,
        },
      });
      if (result.kind !== 'opened_wallet_authority_linked_signer_material_v1') {
        throw new Error(`[login] linked Email OTP signer material open failed: ${result.reason}`);
      }
      opened.push(result);
    }
    const [first, ...rest] = opened;
    if (!first) throw new Error('[login] linked Email OTP signer material set is empty');
    return [first, ...rest];
  } finally {
    factorSecret.fill(0);
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
  const records = await IndexedDBManager.listWalletAuthMethodsV2ForWallet(String(walletId)).catch(
    () => [] as LocalWalletAuthMethodRecordV2[],
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
      kind: 'near_wallet';
      walletId: WalletId;
      operationalPublicKey: string | null;
      userData?: never;
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

async function readActiveWalletPasskeyAuthenticators(
  walletId: WalletId,
): Promise<LoginPasskeyAuthenticator[]> {
  const [authenticators, authMethods] = await Promise.all([
    IndexedDBManager.listWalletPasskeyAuthenticators(String(walletId)),
    IndexedDBManager.listWalletAuthMethodsV2ForWallet(String(walletId)).catch(
      () => [] as LocalWalletAuthMethodRecordV2[],
    ),
  ]);
  const activeCredentialIds = new Set<string>();
  for (const method of authMethods) {
    if (method.kind === 'passkey' && method.status === 'active') {
      activeCredentialIds.add(method.credentialIdB64u);
    }
  }
  return authenticators.filter((authenticator) =>
    activeCredentialIds.has(authenticator.credentialId),
  );
}

type LoginEcdsaKeyFactsInventoryAuthority =
  | {
      kind: 'opaque_wallet_session';
      curve: 'ecdsa_secp256k1';
      walletSessionToken: string;
    }
  | {
      kind: 'webauthn';
    };

type LoginNoServerSessionPasskeyCredentialPlan =
  | {
      kind: 'wallet_unlock_owns_passkey_credential';
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
      kind: 'no_passkey_credential_required';
    }
  | {
      kind: 'wallet_custody';
    };

type LoginWarmupRouteAuthorization = {
  kind: 'none';
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
      thresholdSessionId: string;
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
    case 'opaque_wallet_session': {
      const walletSessionToken = args.request.walletSessionToken.trim();
      if (!walletSessionToken) return null;
      return {
        kind: 'opaque_wallet_session',
        curve: args.request.curve,
        walletSessionToken,
      };
    }
    case 'webauthn':
      return { kind: 'webauthn' };
  }
  return null;
}

function resolveLoginWarmupRouteAuthorization(): LoginWarmupRouteAuthorization {
  return { kind: 'none' };
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
  walletId: WalletId;
  rpId: string;
  passkeyCredentialIdB64u: string;
  routeAuthorization: LoginWarmupRouteAuthorization;
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
    throw new Error('[login] Email OTP warm-up requires its proof-bound unlock flow');
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

function bindLoginEd25519SessionAuthorityToAuthenticatedCredential(args: {
  authority: Exclude<LoginWarmupEd25519SessionAuthority, { kind: 'not_requested' }>;
  walletId: WalletId;
  rpId: string;
  credentialIdB64u: string;
}): Exclude<LoginWarmupEd25519SessionAuthority, { kind: 'not_requested' }> {
  if (args.authority.kind === 'email_otp') return args.authority;
  const authority = buildLoginPasskeyWalletAuthAuthority({
    walletId: args.walletId,
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
  });
  return {
    kind: 'passkey',
    authority: { kind: 'wallet_auth_authority', authority },
    source: 'login',
  };
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
      if (args.ecdsaMint) {
        return {
          kind: 'exact_ed25519_provisioning' as const,
          existingWalletSessionToken: args.ecdsaMint.thresholdEcdsaSessionToken,
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
        existingWalletSessionToken: args.ecdsaMint.thresholdEcdsaSessionToken,
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

function resolveLoginPasskeyMaterialActivation(
  identity: ReturnType<typeof resolveLoginWarmEd25519ProvisioningIdentity>,
  mintPlan: LoginWarmupEd25519MintPlan,
): MpcMaterialActivationRef {
  if (identity.kind === 'fresh_ed25519_provisioning' && identity.materialActivation) {
    return identity.materialActivation;
  }
  if (mintPlan.kind === 'wallet_custody') {
    return mintPlan.custody.ed25519.capability.materialActivation;
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

type PasskeyUnlockEd25519Connection = Extract<
  Awaited<ReturnType<LoginUnlockSigningSurface['connectEd25519Session']>>,
  { readonly ok: true }
>;

function passkeyUnlockEd25519Connection(args: {
  readonly session: PasskeyWalletUnlockEd25519Session;
  readonly walletBinding: ResolvedLoginWalletBinding;
  readonly signerSlot: number;
  readonly custody: ActivePasskeySessionCustodyUnlockV1;
  readonly provisionScope: LoginEd25519ProvisionScope;
  readonly credential: WebAuthnAuthenticationCredential | undefined;
  readonly remainingUses: number;
}): PasskeyUnlockEd25519Connection {
  const session = args.session;
  const custody = args.custody.ed25519;
  const passkeyPrfFirstB64u = args.credential
    ? passkeyPrfFirstB64uFromCredential(args.credential)
    : '';
  if (
    session.walletId !== String(args.walletBinding.walletId) ||
    session.nearAccountId !== String(args.walletBinding.nearAccountId) ||
    session.nearEd25519SigningKeyId !== String(args.walletBinding.nearEd25519SigningKeyId) ||
    custody.signerSlot !== args.signerSlot ||
    session.relayerKeyId !== args.provisionScope.relayerKeyId ||
    session.thresholdSessionId !== custody.capability.lifecycle.thresholdSessionId ||
    session.remainingUses !== args.remainingUses ||
    !sameCanonicalEcdsaValue(session.participantIds, args.provisionScope.participantIds) ||
    !sameCanonicalEcdsaValue(session.runtimePolicyScope, args.provisionScope.runtimePolicyScope) ||
    !sameCanonicalEcdsaValue(
      session.routerAbNormalSigning,
      args.provisionScope.routerAbNormalSigning,
    ) ||
    !passkeyPrfFirstB64u
  ) {
    throw new Error('[login] verified unlock returned an invalid Ed25519 Wallet Session');
  }
  return {
    ok: true,
    thresholdSessionId: session.thresholdSessionId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    expiresAtMs: session.expiresAtMs,
    remainingUses: session.remainingUses,
    runtimePolicyScope: session.runtimePolicyScope,
    walletSessionToken: session.walletSessionToken,
  };
}

function resolveLoginNoServerSessionPasskeyCredentialPlan(args: {
  requiresLocalPasskeyUnlock: boolean;
  requireThresholdWarmup: boolean;
  hasLoginCredential: boolean;
}): LoginNoServerSessionPasskeyCredentialPlan {
  if (args.hasLoginCredential) return { kind: 'passkey_credential_already_collected' };
  if (!args.requiresLocalPasskeyUnlock) return { kind: 'no_local_passkey_required' };
  if (args.requireThresholdWarmup) return { kind: 'wallet_unlock_owns_passkey_credential' };
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
  args.routeAuthorization.kind satisfies 'none';
  if (args.requiresLocalPasskeyUnlock) {
    throw new Error('[login] passkey warm-up requires the verified wallet-unlock credential');
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
  keyFactsInventoryAuthority: LoginEcdsaKeyFactsInventoryAuthority | null;
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
      walletId: args.subjectSet.walletId,
      rpId,
      passkeyCredentialIdB64u: loginPasskeyCredentialIdB64u({
        authenticators: args.authenticators,
        signerSlot: args.signerSlot,
      }),
      routeAuthorization: args.routeAuthorization,
    }),
    keyFactsInventoryAuthority: args.keyFactsInventoryAuthority,
    routeAuthorization: args.routeAuthorization,
  };
}

async function assertPasskeyUnlockRuntimePostconditions(args: {
  context: LoginWebContext;
  walletIdentity: ResolvedLoginWalletIdentity;
  signersWarmed: readonly ('ed25519' | 'ecdsa')[];
  credential: WebAuthnAuthenticationCredential;
}): Promise<void> {
  const requiredTargets = [
    ...(args.signersWarmed.includes('ed25519') ? [{ curve: 'ed25519' as const }] : []),
    ...(args.signersWarmed.includes('ecdsa')
      ? listConfiguredThresholdEcdsaPublicationTargets(args.context.configs.network.chains).map(
          (target) => ({ curve: 'ecdsa' as const, chainTarget: target.chainTarget }),
        )
      : []),
  ];
  const credentialIdB64u = passkeyCredentialIdB64uFromAuthentication(args.credential);
  if (!credentialIdB64u) {
    throw new Error('[login] runtime lane selection requires the authenticated credential');
  }
  // R103C: during login the verified credential is the owner-scope source, and
  // the signer slot comes from the one local authenticator that credential
  // resolves — never from the caller's slot hint, which is UI prioritization.
  const walletId = String(args.walletIdentity.walletId);
  const authenticator = await IndexedDBManager.getWalletPasskeyAuthenticator({
    walletId,
    credentialId: credentialIdB64u,
  });
  const derivedSignerSlot = parseSignerSlot(authenticator?.signerSlot, { min: 1 });
  if (!authenticator || derivedSignerSlot === null) {
    throw new Error(
      '[login] authenticated credential resolves no exact local authenticator for its signer slot',
    );
  }
  const ownerScope: OwnerLaneScope = {
    auth: {
      kind: 'passkey',
      rpId: toRpId(args.context.signingEngine.getRpId()),
      credentialIdB64u,
    },
    signerSlot: derivedSignerSlot,
  };
  if (requiredTargets.length === 0) return;
  await assertWalletRuntimePostconditions({
    source: 'wallet_unlock',
    walletId: String(args.walletIdentity.walletId),
    ownerScope,
    requiredTargets,
    readOwnerScopedSigningLanes: async (input) =>
      await args.context.signingEngine.readOwnerScopedSigningLanes(input),
  });
}

function buildNearLoginUnlockAccountSubject(args: {
  userData: ClientUserData | null;
  walletId: WalletId;
}): LoginUnlockAccountSubject {
  if (args.userData && String(args.userData.walletId) !== String(args.walletId)) {
    throw new Error('[login] NEAR account projection belongs to a different wallet');
  }
  const operationalPublicKey =
    typeof args.userData?.operationalPublicKey === 'string'
      ? args.userData.operationalPublicKey.trim()
      : '';
  return {
    kind: 'near_wallet',
    walletId: args.walletId,
    operationalPublicKey: operationalPublicKey || null,
  };
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
    readActiveWalletPasskeyAuthenticators(args.identity.walletId),
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
      .getUserBySignerSlot(args.identity.nearAccountId, Number(args.identity.signerSlot))
      .catch(() => null);
  }
  const accountSubject = buildNearLoginUnlockAccountSubject({
    userData,
    walletId: args.identity.walletId,
  });

  emitUnlockEvent(args.onEvent, String(args.identity.nearAccountId), {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED,
    status: 'succeeded',
    authMethod: 'passkey',
    data: {
      signerSlot: Number(args.identity.signerSlot),
      ...(accountSubject.operationalPublicKey
        ? { operationalPublicKey: accountSubject.operationalPublicKey }
        : { walletKind: accountSubject.kind }),
    },
  });

  const baseSignerSlot = args.signerSlotHint ?? Number(args.identity.signerSlot);
  return {
    kind: 'login_unlock_account_phase_ready',
    accountSubject,
    authenticators,
    baseSignerSlot,
    localUnlockAuthMethod: SIGNER_AUTH_METHODS.passkey,
    requiresLocalPasskeyUnlock: true,
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
  const [profile, eligibleAuthenticators] = await Promise.all([
    IndexedDBManager.getProfile(unlockSubjectId),
    readActiveWalletPasskeyAuthenticators(args.identity.walletId),
  ]);
  if (!profile || eligibleAuthenticators.length === 0) {
    throw new Error(`[login] ECDSA wallet ${unlockSubjectId} has no local passkey profile`);
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
}): Extract<LoginResult, { success: true }> {
  switch (args.identity.kind) {
    case 'near_ed25519_capable_wallet':
      if (args.accountSubject.kind !== 'near_wallet') {
        throw new Error('[login] NEAR unlock returned an ECDSA-only account subject');
      }
      return {
        success: true,
        kind: 'near_wallet_unlocked',
        walletId: args.identity.walletId,
        loggedInNearAccountId: String(args.identity.nearAccountId),
        operationalPublicKey: args.accountSubject.operationalPublicKey,
        nearAccountId: args.identity.nearAccountId,
      };
    case 'evm_family_ecdsa_only_wallet':
      if (args.accountSubject.kind !== 'ecdsa_wallet_only') {
        throw new Error('[login] ECDSA-only unlock returned a NEAR account subject');
      }
      return {
        success: true,
        kind: 'ecdsa_wallet_unlocked',
        walletId: args.identity.walletId,
      };
  }
  return assertNeverLoginState(args.identity);
}

/**
 * Core login function (passkey identity + Router API-issued sessions).
 *
 * Responsibilities:
 * - Select the active account + signer slot (last-user pointer).
 * - Optionally warm owner signing sessions from the verified unlock proof.
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
  return await unlockInternal(context, subjectSet.subjectSet, options, { kind: 'wallet_only' });
}

export async function unlockResolvedWalletSubjectSet(
  context: LoginWebContext,
  subjectSet: WalletUnlockSubjectSet,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  return await unlockInternal(context, subjectSet, options, { kind: 'wallet_only' });
}

type LinkedDeviceNearUnlockSubjectResolution =
  | { readonly kind: 'absent' }
  | {
      readonly kind: 'resolved';
      readonly subject: Extract<WalletUnlockSubject, { readonly kind: 'near_ed25519_wallet' }>;
    }
  | { readonly kind: 'invalid' };

async function resolveLinkedDeviceNearUnlockSubject(args: {
  readonly walletId: WalletId;
  readonly authMethod: Extract<LocalWalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
  readonly signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
}): Promise<LinkedDeviceNearUnlockSubjectResolution> {
  const activation = args.authority.signerActivations.ed25519;
  if (!activation) return { kind: 'absent' };
  const material = selectedSignerMaterialForActivation(
    args.signerMaterials,
    args.authority.authorityId,
    args.authMethod.walletAuthMethodId,
    activation.materialActivation,
  );
  if (
    !material ||
    material.kind !== 'wallet_authority_linked_signer_material_v1' ||
    material.keyFamily !== 'ed25519' ||
    !mpcMaterialActivationRefsEqual(material.materialActivation, activation.materialActivation)
  ) {
    return { kind: 'invalid' };
  }
  const application = material.publicFacts.applicationBinding;
  if (application.wallet_id !== String(args.walletId)) return { kind: 'invalid' };
  let match: Ed25519YaoPublicCapabilityLaneReferenceV1 | null = null;
  const references = await new IndexedDbEd25519YaoPublicCapabilityReferenceStore(
    IndexedDBManager,
  ).listLanes();
  for (const reference of references) {
    /* The factor comparison differs by kind: a Passkey lane is named by its
       exact RP and credential, while an Email OTP lane carries a provider
       subject the local auth method does not store. The remaining comparisons
       — this authority's exact material activation, threshold session, signing
       key, and slot — already identify one device's lane. */
    const factorMatches =
      args.authMethod.kind === SIGNER_AUTH_METHODS.passkey
        ? reference.auth.kind === SIGNER_AUTH_METHODS.passkey &&
          String(reference.auth.rpId) === String(args.authMethod.rpId) &&
          String(reference.auth.credentialIdB64u) === String(args.authMethod.credentialIdB64u)
        : reference.auth.kind === SIGNER_AUTH_METHODS.emailOtp;
    if (
      !factorMatches ||
      String(reference.walletId) !== String(args.walletId) ||
      reference.signerSlot !== application.key_creation_signer_slot ||
      String(reference.nearEd25519SigningKeyId) !== application.near_ed25519_signing_key_id ||
      String(reference.thresholdSessionId) !==
        material.publicFacts.targetBinding.lifecycle.session_id ||
      !mpcMaterialActivationRefsEqual(reference.materialActivation, activation.materialActivation)
    ) {
      continue;
    }
    if (match) return { kind: 'invalid' };
    match = reference;
  }
  if (!match) return { kind: 'invalid' };
  const signerSlot = parseSignerSlot(match.signerSlot, { min: 1 });
  if (!signerSlot) return { kind: 'invalid' };
  return {
    kind: 'resolved',
    subject: {
      kind: 'near_ed25519_wallet',
      walletId: args.walletId,
      nearAccountId: match.nearAccountId,
      nearEd25519SigningKeyId: match.nearEd25519SigningKeyId,
      signerSlot,
    },
  };
}

/**
 * The exact authority reference for a linked device whose factor carries no
 * local credential. It names the authority by its own digest and the exact
 * auth method, so it cannot be reconstructed from factor fields several
 * methods may share.
 */
function requireLinkedDeviceWalletAuthAuthorityRef(input: {
  readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
  readonly authMethod: Extract<LocalWalletAuthMethodRecordV2, { readonly status: 'active' }>;
}): WalletAuthAuthorityRef {
  const authorityRef = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: input.authority.walletId,
    authorityDigest: input.authority.authorityDigestB64u,
    walletAuthMethodId: input.authMethod.walletAuthMethodId,
  });
  if (!authorityRef) {
    throw new Error('[login] linked device wallet authority reference is invalid');
  }
  return authorityRef;
}

export async function resolveLinkedDeviceUnlockSubjectSet(
  walletIdInput: string,
): Promise<WalletUnlockSubjectSet | null> {
  const parsedWalletId = parseWalletId(walletIdInput);
  if (!parsedWalletId.ok) return null;
  const walletId = parsedWalletId.value;
  try {
    const resolved = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
    if (resolved.kind !== 'resolved') return null;
    const { selection, authMethod, authority } = resolved;
    const identityMismatchLabels = linkedDeviceUnlockIdentityMismatchLabels({
      walletId,
      selection,
      authMethod,
      authority,
    });
    if (identityMismatchLabels.length > 0) return null;
    /* Both supported factors install linked devices, so this resolver must not
       be Passkey-only: an Email OTP linked device otherwise resolves no
       subjects, and its wallet then reports no NEAR account after unlock. */
    if (authMethod.status !== 'active') return null;
    if (authority.state !== 'active') return null;
    const subjects: WalletUnlockSubject[] = [];
    const nearSubject = await resolveLinkedDeviceNearUnlockSubject({
      walletId,
      authMethod,
      authority,
      signerMaterials: resolved.signerMaterials,
    });
    if (nearSubject.kind === 'invalid') return null;
    if (nearSubject.kind === 'resolved') subjects.push(nearSubject.subject);
    const ecdsaActivation = authority.signerActivations.ecdsa;
    if (ecdsaActivation) {
      const ecdsaMaterial = selectedSignerMaterialForActivation(
        resolved.signerMaterials,
        authority.authorityId,
        authMethod.walletAuthMethodId,
        ecdsaActivation.materialActivation,
      );
      if (!ecdsaMaterial || ecdsaMaterial.keyFamily !== 'ecdsa_secp256k1') return null;
      if (
        !mpcMaterialActivationRefsEqual(
          ecdsaMaterial.materialActivation,
          ecdsaActivation.materialActivation,
        )
      )
        return null;
      let authorityRef: WalletAuthAuthorityRef;
      try {
        /* A Passkey ref is derived from its exact credential; an Email OTP
           method has no local credential, so its ref carries the authority's
           own digest and exact method id. */
        authorityRef =
          authMethod.kind === SIGNER_AUTH_METHODS.passkey
            ? await walletAuthAuthorityRefForSelectedPasskeyMethod(authMethod)
            : requireLinkedDeviceWalletAuthAuthorityRef({ authority, authMethod });
      } catch {
        return null;
      }
      subjects.push({
        kind: 'evm_family_ecdsa_wallet',
        walletId,
        capability: ecdsaActivation.materialActivation.capability,
        authority: authorityRef,
        ecdsaThresholdKeyId: ecdsaMaterial.ecdsaThresholdKeyId,
      });
    }
    const firstSubject = subjects[0];
    if (!firstSubject) return null;
    return {
      kind: 'wallet_unlock_subject_set',
      walletId,
      subjects: [firstSubject, ...subjects.slice(1)],
    };
  } catch {
    return null;
  }
}

type LinkedDevicePasskeyChallenge = Readonly<{
  readonly challengeId: string;
  readonly challengeB64u: string;
}>;

async function requestLinkedDevicePasskeyChallenge(args: {
  readonly relayUrl: string;
  readonly walletId: WalletId;
  readonly rpId: string;
}): Promise<LinkedDevicePasskeyChallenge> {
  const response = await fetchWithGlobalThis(
    joinNormalizedUrl(args.relayUrl, '/wallet/unlock/challenge'),
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        unlockBackend: 'passkey',
        userId: String(args.walletId),
        rpId: args.rpId,
      }),
    },
  );
  const raw: unknown = await response.json().catch(() => ({}));
  const body = isObject(raw) ? raw : {};
  if (!response.ok || body.ok !== true) {
    throw new Error(
      typeof body.message === 'string'
        ? body.message
        : `wallet/unlock/challenge failed (HTTP ${response.status})`,
    );
  }
  const challengeId = String(body.challengeId || '').trim();
  const challengeB64u = String(body.challengeB64u || '').trim();
  if (!challengeId || !challengeB64u) {
    throw new Error('[login] linked passkey challenge is incomplete');
  }
  return { challengeId, challengeB64u };
}

function linkedDevicePasskeyAllowCredential(credentialIdB64u: string): WebAuthnAllowCredential {
  return {
    id: credentialIdB64u,
    type: 'public-key',
    transports: [],
  };
}

function linkedDeviceRuntimeRequiresCurve(
  walletSession: ActiveWalletSessionV1,
  curve: 'ed25519' | 'ecdsa',
): boolean {
  return walletSession.capabilitySubjects.some(
    (subject) =>
      (subject.kind === 'sign' || subject.kind === 'export_keys') &&
      subject.keyFamily === (curve === 'ed25519' ? 'ed25519' : 'ecdsa_secp256k1'),
  );
}

function linkedDeviceEd25519Material(
  materials: readonly [LinkedDevicePasskeyOpenedMaterial, ...LinkedDevicePasskeyOpenedMaterial[]],
): Extract<LinkedDevicePasskeyOpenedMaterial, { readonly keyFamily: 'ed25519' }> | null {
  const matches = materials.filter(
    (
      material,
    ): material is Extract<LinkedDevicePasskeyOpenedMaterial, { readonly keyFamily: 'ed25519' }> =>
      material.keyFamily === 'ed25519',
  );
  if (matches.length > 1) {
    throw new Error('[login] linked passkey has multiple active Ed25519 materials');
  }
  return matches[0] ?? null;
}

function linkedDeviceEcdsaMaterial(
  materials: readonly [LinkedDevicePasskeyOpenedMaterial, ...LinkedDevicePasskeyOpenedMaterial[]],
): Extract<LinkedDevicePasskeyOpenedMaterial, { readonly keyFamily: 'ecdsa_secp256k1' }> | null {
  const matches = materials.filter(
    (
      material,
    ): material is Extract<
      LinkedDevicePasskeyOpenedMaterial,
      { readonly keyFamily: 'ecdsa_secp256k1' }
    > => material.keyFamily === 'ecdsa_secp256k1',
  );
  if (matches.length > 1) {
    throw new Error('[login] linked passkey has multiple active ECDSA materials');
  }
  return matches[0] ?? null;
}

async function activateLinkedDeviceEcdsaHolderRuntime(args: {
  readonly context: LoginWebContext;
  readonly selection: LinkedDeviceAuthoritySelection;
  readonly factorAuthority: WalletAuthAuthority;
  readonly material: Extract<
    LinkedDevicePasskeyOpenedMaterial,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
}): Promise<{ readonly runtime: LinkedEcdsaHolderRuntimeV1; readonly installed: boolean }> {
  const existing = resolveLinkedEcdsaHolderRuntimeV1({
    walletId: args.selection.walletId,
    materialActivation: args.material.materialActivation,
  });
  if (existing) {
    const [existingAuthorityRef, requestedAuthorityRef] = await Promise.all([
      walletAuthAuthorityRef({ authority: existing.factorAuthority }),
      walletAuthAuthorityRef({ authority: args.factorAuthority }),
    ]);
    if (
      existing.authorityId !== args.selection.authority.authorityId ||
      existing.walletAuthMethodId !== args.selection.authMethod.walletAuthMethodId ||
      existing.ecdsaThresholdKeyId !== args.material.publicFacts.ecdsaThresholdKeyId ||
      existingAuthorityRef.authorityDigest !== requestedAuthorityRef.authorityDigest
    ) {
      throw new Error('[login] linked ECDSA holder runtime conflicts with the selected authority');
    }
    return { runtime: existing, installed: false };
  }
  const holderHandleId = secureRandomId('linked-ecdsa-holder');
  try {
    const stored = await storeLinkedDeviceEcdsaHolderMaterialWasm({
      holderHandleId,
      ownedSigningShare32: args.material.material.slice(),
      activationReceiptJson: JSON.stringify(args.material.publicFacts.activationReceipt),
      workerCtx: args.context.signingEngine.getSignerWorkerContext(),
    });
    const runtime: LinkedEcdsaHolderRuntimeV1 = {
      kind: 'linked_ecdsa_holder_runtime_v1',
      walletId: args.selection.walletId,
      authorityId: args.selection.authority.authorityId,
      walletAuthMethodId: args.selection.authMethod.walletAuthMethodId,
      factorAuthority: args.factorAuthority,
      materialActivation: args.material.materialActivation,
      holderHandleId: stored.holderHandleId,
      ecdsaThresholdKeyId: args.material.publicFacts.ecdsaThresholdKeyId,
      activationReceipt: args.material.publicFacts.activationReceipt,
    };
    installLinkedEcdsaHolderRuntimeV1(runtime);
    return { runtime, installed: true };
  } catch (error: unknown) {
    await destroyLinkedDeviceEcdsaHolderMaterialWasm({
      holderHandleId,
      workerCtx: args.context.signingEngine.getSignerWorkerContext(),
    }).catch(() => undefined);
    throw error;
  }
}

function linkedDeviceEd25519Metadata(
  material: Extract<LinkedDevicePasskeyOpenedMaterial, { readonly keyFamily: 'ed25519' }>,
): RouterAbEd25519YaoActiveClientMetadataV1 {
  const binding = material.publicFacts.targetBinding;
  const receipt = material.publicFacts.activationReceipt;
  return {
    kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
    scope: {
      lifecycle_id: binding.lifecycle.lifecycle_id,
      root_share_epoch: binding.lifecycle.root_share_epoch,
      account_id: binding.lifecycle.account_id,
      threshold_session_id: binding.lifecycle.session_id,
      signer_set_id: binding.lifecycle.signer_set_id,
      signing_worker_id: binding.lifecycle.selected_server_id,
      material_activation: binding.material_activation,
    },
    applicationBinding: material.publicFacts.applicationBinding,
    participantIds: material.publicFacts.participantIds,
    registeredPublicKey: Uint8Array.from(receipt.registered_public_key),
    signingWorkerVerifyingShare: Uint8Array.from(receipt.signing_worker_verifying_share),
    stateEpoch: BigInt(receipt.state_epoch),
    transcript: Uint8Array.from(receipt.transcript),
    activeCapabilityBinding: binding.session_id,
    materialActivation: material.materialActivation,
  };
}

type LinkedDeviceEmailOtpProviderIdentity = Readonly<{
  readonly provider: 'google' | 'email';
  readonly providerSubjectId: string;
}>;

function linkedDeviceEmailOtpProviderSubjectId(
  providerIdentity: LinkedDeviceEmailOtpProviderIdentity | undefined,
): string {
  const providerSubjectId = String(providerIdentity?.providerSubjectId || '').trim();
  if (!providerSubjectId) {
    throw new Error('[login] linked Email OTP lane provider identity is missing');
  }
  return providerSubjectId;
}

function linkedDeviceEd25519SessionFromEmailOtpBootstrap(args: {
  readonly session: WalletRegistrationEd25519YaoBootstrapSession;
  readonly providerIdentity: LinkedDeviceEmailOtpProviderIdentity;
}): PasskeyWalletUnlockEd25519Session {
  const session = args.session;
  if (
    session.authorityScope.kind !== 'email_otp' ||
    session.authorityScope.provider !== args.providerIdentity.provider ||
    String(session.authorityScope.providerUserId) !==
      String(args.providerIdentity.providerSubjectId)
  ) {
    throw new Error('[login] linked Email OTP Ed25519 session authority mismatch');
  }
  const thresholdSessionId = parseThresholdEd25519SessionId(session.thresholdSessionId);
  const authorizationId = parseWalletSessionAuthorizationId(session.authorizationId);
  const walletSessionId = parseWalletSessionId(session.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(session.quotaId);
  if (!thresholdSessionId.ok || !authorizationId.ok || !walletSessionId.ok || !quotaId.ok) {
    throw new Error('[login] linked Email OTP Ed25519 session identity is invalid');
  }
  return {
    walletId: String(session.walletId),
    nearAccountId: session.nearAccountId,
    nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
    relayerKeyId: session.routerAbNormalSigning.signingWorkerId,
    participantIds: session.participantIds,
    thresholdSessionId: thresholdSessionId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    expiresAtMs: session.expiresAtMs,
    remainingUses: session.remainingUses,
    runtimePolicyScope: session.runtimePolicyScope,
    routerAbNormalSigning: session.routerAbNormalSigning,
    walletSessionToken: requireOpaqueWalletSessionToken(session.walletSessionToken),
  };
}

function linkedDeviceEd25519YaoLaneReference(args: {
  readonly selection: LinkedDeviceAuthoritySelection;
  readonly session: PasskeyWalletUnlockEd25519Session;
  readonly material: Extract<LinkedDevicePasskeyOpenedMaterial, { readonly keyFamily: 'ed25519' }>;
  readonly providerIdentity?: LinkedDeviceEmailOtpProviderIdentity;
}): Ed25519YaoPublicCapabilityLaneReferenceV1 {
  const nearAccountId = toAccountId(args.session.nearAccountId);
  const common = {
    walletId: args.selection.walletId,
    nearAccountId,
    thresholdSessionId: args.session.thresholdSessionId,
    runtimePolicyScope: args.session.runtimePolicyScope,
    materialActivation: args.material.materialActivation,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      args.session.nearEd25519SigningKeyId,
    ),
    signerSlot: args.material.publicFacts.applicationBinding.key_creation_signer_slot,
  };
  if (args.selection.authMethod.kind === 'passkey') {
    return {
      ...common,
      auth: {
        kind: 'passkey',
        rpId: toRpId(args.selection.authMethod.rpId),
        credentialIdB64u: args.selection.authMethod.credentialIdB64u,
      },
    };
  }
  return {
    ...common,
    auth: {
      kind: 'email_otp',
      providerSubjectId: linkedDeviceEmailOtpProviderSubjectId(args.providerIdentity),
    },
    remainingUses: args.session.remainingUses,
    expiresAtMs: args.session.expiresAtMs,
  };
}

async function activateLinkedDeviceEd25519Runtime(args: {
  readonly context: LoginWebContext;
  readonly selection: LinkedDeviceAuthoritySelection;
  readonly walletSession: ActiveWalletSessionV1;
  readonly session: PasskeyWalletUnlockEd25519Session;
  readonly material: Extract<LinkedDevicePasskeyOpenedMaterial, { readonly keyFamily: 'ed25519' }>;
  readonly relayerUrl: string;
  readonly providerIdentity?: LinkedDeviceEmailOtpProviderIdentity;
}): Promise<Extract<LoginResult, { success: true }>> {
  const metadata = linkedDeviceEd25519Metadata(args.material);
  const application = metadata.applicationBinding;
  const mismatchLabels: string[] = [];
  if (args.session.walletId !== String(args.selection.walletId)) mismatchLabels.push('walletId');
  if (application.wallet_id !== String(args.selection.walletId)) {
    mismatchLabels.push('application.walletId');
  }
  if (metadata.scope.account_id !== String(args.selection.walletId)) {
    mismatchLabels.push('material.walletId');
  }
  if (args.session.nearEd25519SigningKeyId !== application.near_ed25519_signing_key_id) {
    mismatchLabels.push('nearEd25519SigningKeyId');
  }
  if (args.session.thresholdSessionId !== metadata.scope.threshold_session_id) {
    mismatchLabels.push('thresholdSessionId');
  }
  if (args.session.relayerKeyId !== metadata.scope.signing_worker_id) {
    mismatchLabels.push('signingWorkerId');
  }
  if (mismatchLabels.length > 0) {
    throw new Error(
      `[login] linked Ed25519 Wallet Session does not match local material: ${mismatchLabels.join(', ')}`,
    );
  }
  const yaoClient = await RouterAbEd25519YaoClientV1.initializeBundled();
  const activeClient = yaoClient.importLinkedMaterial({
    ownedClientScalarShare: args.material.material,
    publicReceipt: args.material.publicFacts.activationReceipt,
    metadata,
  });
  let activated = false;
  try {
    const activatedIdentity =
      await args.context.signingEngine.activateVerifiedNearEd25519YaoMaterial({
        activeClient,
        facts: {
          thresholdSessionId: args.session.thresholdSessionId,
          signer: nearEd25519SignerBindingFromBoundaryFields({
            walletId: args.selection.walletId,
            nearAccountId: toAccountId(args.session.nearAccountId),
            nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
              args.session.nearEd25519SigningKeyId,
            ),
            signerSlot: application.key_creation_signer_slot,
          }),
          signingRootId: application.signing_root_id,
          signingRootVersion: metadata.scope.root_share_epoch,
          routerAbNormalSigning: args.session.routerAbNormalSigning,
          runtimePolicyScope: args.session.runtimePolicyScope,
          relayerUrl: args.relayerUrl,
        },
      });
    const nearAccountId = toAccountId(args.session.nearAccountId);
    if (
      String(activatedIdentity.walletId) !== String(args.selection.walletId) ||
      String(activatedIdentity.nearAccountId) !== String(nearAccountId) ||
      !mpcMaterialActivationRefsEqual(
        activatedIdentity.materialActivation,
        args.material.materialActivation,
      )
    ) {
      throw new Error('[login] linked Ed25519 activation identity does not match the V2 session');
    }
    await publishEd25519YaoPublicCapabilityReferenceAndLane(
      new IndexedDbEd25519YaoPublicCapabilityReferenceStore(IndexedDBManager),
      linkedDeviceEd25519YaoLaneReference({
        selection: args.selection,
        session: args.session,
        material: args.material,
        ...(args.providerIdentity ? { providerIdentity: args.providerIdentity } : {}),
      }),
    );
    activated = true;
  } finally {
    if (!activated) activeClient.dispose();
  }
  const authority = await walletAuthAuthorityRefForLinkedDeviceMethod({
    selection: args.selection,
    ...(args.providerIdentity ? { providerIdentity: args.providerIdentity } : {}),
  });
  await persistActiveWalletSessionAuthorizationCurve(walletSessionAuthorizations, {
    walletId: args.selection.walletId,
    authorizationId: args.session.authorizationId,
    walletSessionId: args.session.walletSessionId,
    quotaId: args.session.quotaId,
    expiresAtMs: args.session.expiresAtMs,
    authority,
    authMethod:
      args.selection.authMethod.kind === 'passkey'
        ? SIGNER_AUTH_METHODS.passkey
        : SIGNER_AUTH_METHODS.emailOtp,
    walletSessionToken: args.session.walletSessionToken,
    curve: 'ed25519',
    thresholdSessionId: args.session.thresholdSessionId,
  });
  const nearAccountId = toAccountId(args.session.nearAccountId);
  return {
    success: true,
    kind: 'near_wallet_unlocked',
    walletId: args.selection.walletId,
    loggedInNearAccountId: String(nearAccountId),
    operationalPublicKey: `ed25519:${base58Encode(metadata.registeredPublicKey)}`,
    nearAccountId,
  };
}

/**
 * R109C: an Email method added to an existing authority asks for that
 * authority's Ed25519 capability.
 *
 * A linked device carries its own sealed Ed25519 material and is answered
 * above. An added sibling has none, and looking for one is what made a
 * NEAR-capable wallet lose NEAR the moment its Email method opened it: the
 * request was skipped, so the unlock issued no Yao capability and no lane
 * existed to sign with.
 *
 * The authority's own signer activation is the right question, because the
 * Ed25519 signer belongs to the authority rather than to whichever credential
 * authenticates. Nothing is copied and no activation is created - the existing
 * material activation is left exactly as it is, and the unlock mints a fresh
 * capability bound to this method. The signer slot comes from the wallet's own
 * profile, which is where its NEAR signer slot lives whether or not a passkey
 * ever existed.
 */
async function ownerAuthorityEd25519UnlockRequest(
  selection: LinkedDeviceEmailOtpAuthoritySelection,
): Promise<{ signerSlot: number; remainingUses: number } | undefined> {
  if (!selection.authority.signerActivations.ed25519) return undefined;
  const profile = await IndexedDBManager.getProfile(String(selection.walletId));
  const signerSlot = profile ? parseSignerSlot(profile.defaultSignerSlot, { min: 1 }) : null;
  if (signerSlot === null) return undefined;
  return { signerSlot, remainingUses: DEFAULT_UNLOCK_REMAINING_USES };
}

/**
 * R109C: where an Email OTP unlock's signer material comes from.
 *
 * A linked device carries sealed material of its own and must have it. An Email
 * method added to an existing authority has none and must not be given any -
 * its access is the authority's, reached through the owner path. Both name an
 * exact authority and an exact method; only the material differs, so the two
 * are separate shapes rather than one shape with an optional field. Inferring
 * provenance from whether material happened to be present is what let an owner
 * sibling fall into the linked-device path and fail there.
 */
type EmailOtpUnlockSourceV1 =
  | {
      readonly kind: 'owner_authority';
      readonly selection: LinkedDeviceEmailOtpAuthoritySelection;
      readonly signerMaterials?: never;
    }
  | {
      readonly kind: 'linked_device';
      readonly selection: LinkedDeviceEmailOtpAuthoritySelection;
      readonly signerMaterials: readonly [
        WalletAuthoritySignerMaterialRecordV1,
        ...WalletAuthoritySignerMaterialRecordV1[],
      ];
    };

function emailOtpUnlockSource(
  selection: LinkedDeviceEmailOtpAuthoritySelection,
): EmailOtpUnlockSourceV1 {
  const [first, ...rest] = selection.signerMaterials;
  /* Provenance decides this, not the material: a device-linked authority always
     has material, so its absence there is corruption rather than an owner
     sibling. The selection resolver already refuses a device_link authority
     with no material. */
  if (selection.authority.provenance.kind === 'device_link') {
    if (!first) {
      throw new Error('[login] linked Email OTP authority has no signer material');
    }
    return { kind: 'linked_device', selection, signerMaterials: [first, ...rest] };
  }
  if (first) {
    throw new Error('[login] owner Email OTP authority must not carry linked signer material');
  }
  return { kind: 'owner_authority', selection };
}

/**
 * What this unlock should build, decided by the branch rather than by whichever
 * fields happened to be present.
 *
 * A linked device names the signer slot its own sealed material carries. An
 * owner authority has none, so the request is assembled from its exact
 * authority projection and the runtime is built inside the unlock.
 */
async function emailOtpAuthorityUnlockEd25519Request(input: {
  readonly context: LoginWebContext;
  readonly source: EmailOtpUnlockSourceV1;
  readonly providerIdentity: LinkedDeviceEmailOtpProviderIdentity;
}): Promise<EmailOtpAuthorityUnlockEd25519Request> {
  const { source } = input;
  if (source.kind === 'linked_device') {
    const ed25519Material = source.signerMaterials.find(
      (
        material,
      ): material is Extract<
        WalletAuthorityLinkedSignerMaterialRecordV1,
        { keyFamily: 'ed25519' }
      > =>
        material.kind === 'wallet_authority_linked_signer_material_v1' &&
        material.keyFamily === 'ed25519',
    );
    if (!ed25519Material) return { kind: 'no_ed25519' };
    return {
      kind: 'linked_device',
      signerSlot: ed25519Material.publicFacts.applicationBinding.key_creation_signer_slot,
      remainingUses: DEFAULT_UNLOCK_REMAINING_USES,
    };
  }
  if (!source.selection.authority.signerActivations.ed25519) return { kind: 'no_ed25519' };
  const request =
    await input.context.signingEngine.resolveOwnerAuthorityEd25519UnlockRequestInternal({
      walletSession: {
        walletId: source.selection.walletId,
        walletSessionUserId: String(source.selection.walletId),
      },
      providerSubjectId: input.providerIdentity.providerSubjectId,
      walletAuthMethodId: String(source.selection.authMethod.walletAuthMethodId),
      remainingUses: DEFAULT_UNLOCK_REMAINING_USES,
    });
  return request ?? { kind: 'no_ed25519' };
}

/**
 * R109C: install the Ed25519 runtime an owner authority's unlock just built.
 *
 * Everything is checked against the authority and method that were selected,
 * before the handle is used: a session naming a different method, or a
 * capability naming a different activation, must not be able to activate a
 * runtime under this one.
 */
async function unlockOwnerAuthorityEmailOtpEd25519(input: {
  readonly context: LoginWebContext;
  readonly selection: LinkedDeviceEmailOtpAuthoritySelection;
  readonly unlocked: EmailOtpAuthorityWalletUnlockResult;
  readonly providerIdentity: LinkedDeviceEmailOtpProviderIdentity;
  readonly emailHashHex: string;
}): Promise<void> {
  const { selection, unlocked } = input;
  const session = unlocked.walletSession;
  if (
    session.walletId !== selection.walletId ||
    session.authorityId !== selection.authority.authorityId ||
    session.authMethodId !== selection.authMethod.walletAuthMethodId ||
    session.authorityDigestB64u !== selection.authority.authorityDigestB64u ||
    session.authorityRevocationEpoch !== selection.authority.revocationEpoch
  ) {
    throw new Error('[login] owner Email OTP Wallet Session does not match the selected authority');
  }
  const activation = selection.authority.signerActivations.ed25519?.materialActivation;
  if (!activation) return;
  if (unlocked.ed25519Activation.kind !== 'ed25519_activation_ready') {
    throw new Error('[login] owner Email OTP unlock built no Ed25519 runtime to install');
  }
  const ready = unlocked.ed25519Activation;
  if (!mpcMaterialActivationRefsEqual(ready.bootstrap.capability.materialActivation, activation)) {
    throw new Error('[login] owner Email OTP Ed25519 capability names another activation');
  }
  if (!mpcMaterialActivationRefsEqual(ready.metadata.materialActivation, activation)) {
    throw new Error('[login] owner Email OTP Ed25519 runtime names another activation');
  }
  if (ready.bootstrap.session.walletSessionId !== unlocked.operationCredential.walletSessionId) {
    throw new Error('[login] owner Email OTP Ed25519 session credential mismatch');
  }
  await input.context.signingEngine.activateOwnerAuthorityEd25519RuntimeInternal({
    walletSession: {
      walletId: selection.walletId,
      walletSessionUserId: String(selection.walletId),
    },
    providerSubjectId: input.providerIdentity.providerSubjectId,
    walletAuthMethodId: String(selection.authMethod.walletAuthMethodId),
    emailHashHex: input.emailHashHex,
    /* From the selection this unlock already verified against the returned
       session, not from a lookup: activation is part of installing that
       session, so reading it back would be waiting on itself. */
    authority: await walletAuthAuthorityRefForLinkedDeviceMethod({
      selection,
      providerIdentity: input.providerIdentity,
    }),
    activeClientHandle: ready.activeClientHandle,
    metadata: ready.metadata,
    bootstrap: ready.bootstrap,
  });
}

export async function unlockLinkedDeviceEmailOtpWallet(args: {
  readonly context: LoginWebContext;
  readonly walletIdInput: string;
  readonly emailHashHex: string;
  readonly walletAuthMethodId: string;
  readonly providerSubjectId: string;
  readonly provider?: 'google' | 'email';
  readonly challengeId: string;
  readonly otpCode: string;
  readonly relayUrl: string;
}): Promise<void> {
  const providerIdentity: LinkedDeviceEmailOtpProviderIdentity = {
    provider: args.provider || 'google',
    providerSubjectId: args.providerSubjectId,
  };
  const resolution = await resolveLinkedDeviceEmailOtpAuthoritySelection({
    walletIdInput: args.walletIdInput,
    emailHashHex: args.emailHashHex,
    provider: providerIdentity.provider,
    providerSubjectId: providerIdentity.providerSubjectId,
    walletAuthMethodId: args.walletAuthMethodId,
  });
  if (resolution.kind === 'none') {
    throw new Error('[login] linked Email OTP authority is unavailable');
  }
  if (resolution.kind === 'rejected') throw new Error(resolution.message);
  const selection = resolution.selection;
  if (String(selection.authMethod.walletAuthMethodId) !== String(args.walletAuthMethodId)) {
    throw new Error('[login] linked Email OTP selected auth method changed during unlock');
  }
  const relayUrl = String(args.relayUrl || '').trim();
  if (!relayUrl) throw new Error('[login] linked Email OTP unlock requires relayer.url');
  const source = emailOtpUnlockSource(selection);
  const ed25519Request = await emailOtpAuthorityUnlockEd25519Request({
    context: args.context,
    source,
    providerIdentity,
  });
  const unlocked: EmailOtpAuthorityWalletUnlockResult = await unlockEmailOtpAuthorityWallet({
    relayUrl,
    walletId: String(selection.walletId),
    walletAuthMethodId: String(selection.authMethod.walletAuthMethodId),
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    ed25519: ed25519Request,
    workerCtx: args.context.signingEngine.getSignerWorkerContext(),
  });
  const factorSecret32: Uint8Array | null = unlocked.factorSecret32;
  let openedMaterials:
    | readonly [LinkedDevicePasskeyOpenedMaterial, ...LinkedDevicePasskeyOpenedMaterial[]]
    | null = null;
  let installedEcdsaRuntime: LinkedEcdsaHolderRuntimeV1 | null = null;
  /* A handle exists only on the owner branch, and only until the runtime it
     belongs to takes ownership. Until then every exit disposes it. */
  let ownedActiveClientHandle: string | null =
    unlocked.ed25519Activation.kind === 'ed25519_activation_ready'
      ? unlocked.ed25519Activation.activeClientHandle
      : null;
  try {
    if (source.kind === 'owner_authority') {
      /* The authorization is written first because activation resolves the
         active Wallet Session authority to bind against; activating before it
         exists looks to that lookup like no session at all. */
      await walletSessionAuthorizations.writeExactWithOperationCredential({
        record: unlocked.walletSession,
        operationCredential: unlocked.operationCredential,
      });
      await unlockOwnerAuthorityEmailOtpEd25519({
        context: args.context,
        selection,
        unlocked,
        providerIdentity,
        emailHashHex: args.emailHashHex,
      });
      ownedActiveClientHandle = null;
      await args.context.signingEngine.markWalletSelectionUnlocked({
        walletId: selection.walletId,
        walletAuthMethodId: selection.authMethod.walletAuthMethodId,
      });
      args.context.signingEngine.setWalletAuthenticated({
        kind: 'authenticated',
        walletId: selection.walletId,
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
      });
      return;
    }
    assertLinkedDeviceWalletSessionExact(selection, unlocked.walletSession);
    if (!factorSecret32) {
      throw new Error('[login] linked Email OTP factor secret ownership was lost');
    }
    openedMaterials = await openLinkedDeviceEmailOtpSignerMaterials({
      selection,
      factorSecret32,
    });
    const ed25519Material = linkedDeviceEd25519Material(openedMaterials);
    const ecdsaMaterial = linkedDeviceEcdsaMaterial(openedMaterials);
    if (linkedDeviceRuntimeRequiresCurve(unlocked.walletSession, 'ed25519')) {
      if (!ed25519Material || !unlocked.ed25519Activation.bootstrap) {
        throw new Error(
          '[login] linked Email OTP Ed25519 runtime material or capability is missing',
        );
      }
      if (
        !mpcMaterialActivationRefsEqual(
          unlocked.ed25519Activation.bootstrap!.capability.materialActivation,
          ed25519Material.materialActivation,
        )
      ) {
        throw new Error('[login] linked Email OTP Ed25519 capability activation is invalid');
      }
    }
    if (linkedDeviceRuntimeRequiresCurve(unlocked.walletSession, 'ecdsa')) {
      if (!ecdsaMaterial) {
        throw new Error('[login] linked Email OTP ECDSA runtime material is missing');
      }
      const activatedEcdsa = await activateLinkedDeviceEcdsaHolderRuntime({
        context: args.context,
        selection,
        factorAuthority: await walletAuthAuthorityForLinkedDeviceMethod({
          selection,
          providerIdentity,
        }),
        material: ecdsaMaterial,
      });
      if (activatedEcdsa.installed) installedEcdsaRuntime = activatedEcdsa.runtime;
    }
    let loginResult: Extract<LoginResult, { success: true }>;
    if (ed25519Material && unlocked.ed25519Activation.bootstrap) {
      const ed25519Session = linkedDeviceEd25519SessionFromEmailOtpBootstrap({
        session: unlocked.ed25519Activation.bootstrap.session,
        providerIdentity,
      });
      if (ed25519Session.walletSessionId !== unlocked.operationCredential.walletSessionId) {
        throw new Error('[login] linked Email OTP Ed25519 session credential mismatch');
      }
      loginResult = await activateLinkedDeviceEd25519Runtime({
        context: args.context,
        selection,
        walletSession: unlocked.walletSession,
        session: ed25519Session,
        material: ed25519Material,
        relayerUrl: relayUrl,
        providerIdentity,
      });
    } else if (ecdsaMaterial) {
      loginResult = {
        success: true,
        kind: 'ecdsa_wallet_unlocked',
        walletId: selection.walletId,
      };
    } else {
      throw new Error('[login] linked Email OTP has no unlockable signing runtime');
    }
    await walletSessionAuthorizations.writeExactWithOperationCredential({
      record: unlocked.walletSession,
      operationCredential: unlocked.operationCredential,
    });
    /* The unlocked export-root capability is derived from a wallet custody
       seed. A linked installation never receives that seed: its envelope
       carries the Ed25519 Yao Client root itself, which the ordinary export
       path opens directly from the persisted export root. */
    if (selection.exportRoot && isWalletCustodySeedBinding(selection.exportRoot.envelope.binding)) {
      await establishUnlockedExportRootCapabilityV1(
        walletCustodyCeremonyTransportFromWorkerContextV1(
          args.context.signingEngine.getSignerWorkerContext(),
        ),
        {
          existingEnvelope: selection.exportRoot.envelope,
          existingFactorSecret: factorSecret32,
          walletId: String(selection.walletId),
          walletAuthMethodId: String(selection.authMethod.walletAuthMethodId),
          walletSessionId: String(unlocked.operationCredential.walletSessionId),
          expiresAtMs: unlocked.walletSession.expiresAtMs,
        },
      );
    }
    await args.context.signingEngine.markWalletSelectionUnlocked({
      walletId: selection.walletId,
      walletAuthMethodId: selection.authMethod.walletAuthMethodId,
    });
    args.context.signingEngine.setWalletAuthenticated({
      kind: 'authenticated',
      walletId: loginResult.walletId,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    });
  } catch (error: unknown) {
    if (installedEcdsaRuntime) {
      removeLinkedEcdsaHolderRuntimeV1({
        walletId: installedEcdsaRuntime.walletId,
        materialActivation: installedEcdsaRuntime.materialActivation,
        holderHandleId: installedEcdsaRuntime.holderHandleId,
      });
      await destroyLinkedDeviceEcdsaHolderMaterialWasm({
        holderHandleId: installedEcdsaRuntime.holderHandleId,
        workerCtx: args.context.signingEngine.getSignerWorkerContext(),
      }).catch(() => undefined);
    }
    const workerContext = args.context.signingEngine.getSignerWorkerContext();
    if (workerContext) {
      await destroyUnlockedWalletEd25519ExportRootCapabilitiesV1(
        walletCustodyCeremonyTransportFromWorkerContextV1(workerContext),
        {
          kind: 'wallet_session',
          walletSessionId: String(unlocked.operationCredential.walletSessionId),
        },
      );
    }
    await Promise.allSettled([
      args.context.signingEngine.clearVolatileWarmSigningMaterial(selection.walletId),
      walletSessionAuthorizations.clearWallet(selection.walletId),
    ]);
    throw error;
  } finally {
    /* A handle still owned here belongs to no runtime - either activation never
       ran or it threw - so it is disposed rather than left registered in the
       worker for the rest of the session. */
    if (ownedActiveClientHandle) {
      const workerContext = args.context.signingEngine.getSignerWorkerContext();
      if (workerContext) {
        await disposeWalletCustodyEd25519ActiveClientV1({
          workerContext,
          activeClientHandle: ownedActiveClientHandle,
        }).catch(() => undefined);
      }
      ownedActiveClientHandle = null;
    }
    for (const openedMaterial of openedMaterials || []) openedMaterial.material.fill(0);
    factorSecret32?.fill(0);
  }
}

export async function unlockLinkedDevicePasskey(
  context: LoginWebContext,
  walletIdInput: string,
  options: LoginHooksOptions | undefined,
): Promise<LoginAndCreateSessionResult> {
  const unlockSubjectId = String(walletIdInput).trim() || 'linked-passkey';
  const { onEvent, onError, afterCall } = options || {};
  emitUnlockEvent(onEvent, unlockSubjectId, {
    phase: UnlockEventPhase.STEP_01_STARTED,
    status: 'started',
    authMethod: 'passkey',
  });
  try {
    const selection = await resolveLinkedDevicePasskeyAuthoritySelection(walletIdInput);
    if (!selection) throw new Error('[login] linked passkey authority is unavailable');
    const relayUrl = String(context.configs.network.relayer?.url || '').trim();
    if (!relayUrl) throw new Error('[login] linked passkey unlock requires relayer.url');
    emitUnlockEvent(onEvent, unlockSubjectId, {
      phase: UnlockEventPhase.STEP_03_PASSKEY_CHALLENGE_STARTED,
      status: 'running',
      authMethod: 'passkey',
    });
    const challenge = await requestLinkedDevicePasskeyChallenge({
      relayUrl,
      walletId: selection.walletId,
      rpId: selection.authMethod.rpId,
    });
    emitUnlockEvent(onEvent, unlockSubjectId, {
      phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
      status: 'running',
      authMethod: 'passkey',
      interaction: { kind: 'passkey_assert', overlay: 'show' },
    });
    const credential = await context.signingEngine.getAuthenticationCredentialsSerialized({
      subjectId: String(selection.walletId),
      challengeB64u: challenge.challengeB64u,
      allowCredentials: [linkedDevicePasskeyAllowCredential(selection.authMethod.credentialIdB64u)],
      includeSecondPrfOutput: true,
    });
    emitUnlockEvent(onEvent, unlockSubjectId, {
      phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      authMethod: 'passkey',
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
    });
    const expectedOrigin = String(
      typeof window !== 'undefined' ? window.location.origin : '',
    ).trim();
    const unlockInput: LinkedDevicePasskeyWalletSessionUnlockInput = {
      challengeId: challenge.challengeId,
      webauthn_authentication: credential,
      ed25519SessionRequest: selection.signerMaterials.some(
        (material) => material.keyFamily === 'ed25519',
      )
        ? { kind: 'requested', remainingUses: DEFAULT_UNLOCK_REMAINING_USES }
        : { kind: 'not_requested' },
      ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
    };
    emitUnlockEvent(onEvent, unlockSubjectId, {
      phase: UnlockEventPhase.STEP_04_WALLET_UNLOCK_EXCHANGE_STARTED,
      status: 'running',
      authMethod: 'passkey',
    });
    const verified = await verifyLinkedDevicePasskeyWalletSession(relayUrl, unlockInput);
    if (!verified.success) throw new Error(verified.error);
    assertLinkedDeviceWalletSessionExact(selection, verified.walletSession);
    const openedMaterials = await openLinkedDevicePasskeySignerMaterials({
      selection,
      credential,
    });
    let loginResult: Extract<LoginResult, { success: true }>;
    try {
      const ed25519Material = linkedDeviceEd25519Material(openedMaterials);
      const ecdsaMaterial = linkedDeviceEcdsaMaterial(openedMaterials);
      if (linkedDeviceRuntimeRequiresCurve(verified.walletSession, 'ed25519')) {
        if (!ed25519Material || !verified.ed25519Session) {
          throw new Error('[login] linked Ed25519 runtime material or Wallet Session is missing');
        }
      }
      if (linkedDeviceRuntimeRequiresCurve(verified.walletSession, 'ecdsa')) {
        if (!ecdsaMaterial) {
          throw new Error('[login] linked ECDSA runtime material is missing');
        }
        await activateLinkedDeviceEcdsaHolderRuntime({
          context,
          selection,
          factorAuthority: await walletAuthAuthorityForLinkedDeviceMethod({ selection }),
          material: ecdsaMaterial,
        });
      }
      if (ed25519Material && verified.ed25519Session) {
        loginResult = await activateLinkedDeviceEd25519Runtime({
          context,
          selection,
          walletSession: verified.walletSession,
          session: verified.ed25519Session,
          material: ed25519Material,
          relayerUrl: relayUrl,
        });
      } else if (ecdsaMaterial) {
        loginResult = {
          success: true,
          kind: 'ecdsa_wallet_unlocked',
          walletId: selection.walletId,
        };
      } else {
        throw new Error('[login] linked passkey has no unlockable signing runtime');
      }
      await walletSessionAuthorizations.writeExactWithOperationCredential({
        record: verified.walletSession,
        operationCredential: verified.operationCredential,
      });
      if (selection.exportRoot) {
        const passkeyPrfFirstB64u = passkeyPrfFirstB64uFromCredential(credential);
        if (!passkeyPrfFirstB64u) {
          throw new Error('[login] linked export-root unlock requires WebAuthn PRF.first output');
        }
        await context.signingEngine.establishUnlockedWalletEd25519ExportRootCapabilityV1({
          existingEnvelope: selection.exportRoot.envelope,
          passkeyPrfFirstB64u,
          walletId: String(selection.walletId),
          walletAuthMethodId: String(selection.authMethod.walletAuthMethodId),
          walletSessionId: String(verified.operationCredential.walletSessionId),
          expiresAtMs: verified.walletSession.expiresAtMs,
        });
      }
      await context.signingEngine.markWalletSelectionUnlocked({
        walletId: selection.walletId,
        walletAuthMethodId: selection.authMethod.walletAuthMethodId,
      });
    } catch (error: unknown) {
      await Promise.allSettled([
        context.signingEngine.clearVolatileWarmSigningMaterial(selection.walletId),
        walletSessionAuthorizations.clearWallet(selection.walletId),
      ]);
      throw error;
    } finally {
      for (const openedMaterial of openedMaterials) openedMaterial.material.fill(0);
    }
    emitUnlockEvent(onEvent, unlockSubjectId, {
      phase: UnlockEventPhase.STEP_04_WALLET_UNLOCK_EXCHANGE_SUCCEEDED,
      status: 'succeeded',
      authMethod: 'passkey',
    });
    return await finalizeLoginSuccess({
      context,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      unlockSubjectId,
      loginResult,
      onEvent,
      afterCall,
    });
  } catch (error: unknown) {
    const normalized = toError(error);
    return await finalizeLoginError({
      unlockSubjectId,
      message: normalized.message,
      error: normalized,
      onEvent,
      onError,
      afterCall,
      cancelled: isUserCancellationError(normalized),
    });
  }
}

type LoginUnlockCompletion = { readonly kind: 'wallet_only' };

async function unlockInternal(
  context: LoginWebContext,
  subjectSet: WalletUnlockSubjectSet,
  options: LoginHooksOptions | undefined,
  completion: LoginUnlockCompletion,
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

    // Shared prompt wrapper used by local unlock, owner-proof verification, and inventory repair.
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
    let completedPasskeyExchangeEcdsaActivation: CompletedPasskeyExchangeEcdsaActivation | null =
      null;
    let completedPasskeyEd25519Session: PasskeyWalletUnlockEd25519Session | null = null;
    let completedPasskeySessionCustody: PasskeySessionCustodyUnlockV1 | null = null;
    let localWarmupRouteAuthorization = resolveLoginWarmupRouteAuthorization();
    let warmupPhase: ThresholdLoginWarmupPhaseResult | null = null;

    // Warmup callers use this after side effects to turn a missing session into a clear error.
    const requireActiveWarmSession = (
      source: string,
      sessionStatus: SigningSessionStatus | null | undefined,
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
      const storedCanonicalEcdsaContext = warmupInput.wantsEcdsaWarmup
        ? await resolveCanonicalThresholdEcdsaWarmSessionContext(
            context,
            walletIdentity.walletId,
            {
              keyFactsInventoryAuthority: warmupInput.keyFactsInventoryAuthority,
              keyFactsInventoryRequested: Boolean(options?.ecdsaKeyFactsInventory),
              relayerUrl: warmupInput.relayerUrl,
              rpId: warmupInput.rpId,
            },
            localUnlockAuthMethod,
          )
        : { ecdsaKeys: [] };
      const thresholdKeyMaterial = await thresholdKeyMaterialPrefetch;
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
      const passkeyExchangeEcdsaActivationForWarmup = completedPasskeyExchangeEcdsaActivation;
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
        case 'no_passkey_credential_required':
          break;
        case 'wallet_custody': {
          if (warmupInput.ed25519SessionAuthority.kind !== 'passkey') {
            throw new Error('[login] wallet custody requires passkey wallet authority');
          }
          if (
            !completedPasskeySessionCustody ||
            completedPasskeySessionCustody.ed25519.kind !== 'active'
          ) {
            throw createThresholdEd25519DeviceLinkRequiredError();
          }
          ed25519MintPlan = {
            kind: 'wallet_custody',
            thresholdSessionId: plannedEd25519SessionId,
            custody: {
              ...completedPasskeySessionCustody,
              ed25519: completedPasskeySessionCustody.ed25519,
            },
          };
          break;
        }
        default:
          return assertNeverLoginState(warmupPasskeyCredentialPlan);
      }
      if (nearWalletBinding && !thresholdKeyMaterial && ed25519MintPlan.kind !== 'wallet_custody') {
        throw new Error(
          `[login] threshold warm-up requires threshold key material for ${nearWalletBinding.nearAccountId} signer slot ${warmupInput.signerSlot}`,
        );
      }

      // Passkey ID can come from the fresh assertion or stored account authenticators.
      const authenticatedPasskeyCredentialIdB64u = loginCredential
        ? passkeyCredentialIdB64uFromAuthentication(loginCredential)
        : '';
      const localPasskeyCredentialIdB64u = String(
        authenticatedPasskeyCredentialIdB64u ||
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
        passkeyUnlockEd25519Session: completedPasskeyEd25519Session,
      });

      // Successful provisioning has already sealed and activated the exact Ed25519 session.
      if (warmupPlan.signersToWarm.includes('ed25519')) {
        const ed25519Session = warmupResult.ed25519Session;
        if (!ed25519Session) {
          throw new Error('[login] threshold warm-up omitted the Ed25519 session result');
        }
        const activeSigningSession = requireActiveWarmSession(
          'threshold warm-up',
          createActiveLoginSigningSessionStatus({
            session: ed25519Session,
            authMethod: localUnlockAuthMethod,
          }),
        );

        // Emit lane-specific events after active-session validation succeeds.
        emitUnlockEvent(onEvent, unlockSubjectId, {
          phase: UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
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
      }

      if (warmupPlan.signersToWarm.length !== 1 || warmupPlan.signersToWarm[0] !== 'ecdsa') {
        throw new Error('[login] threshold warm-up signer selection is invalid');
      }

      // ECDSA-only wallets warm their ECDSA lanes without an Ed25519 session.
      emitUnlockEvent(onEvent, unlockSubjectId, {
        phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
        status: 'succeeded',
        authMethod: 'warm_session',
      });
      return {
        kind: 'threshold_login_ecdsa_only_warmup_ready',
        signersWarmed: ['ecdsa'],
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
      if (walletIdentity.kind === 'near_ed25519_capable_wallet') {
        if (
          !(accountSubject.kind === 'near_wallet' && accountSubject.operationalPublicKey === null)
        ) {
          await signingEngine.activateAuthenticatedWalletState({
            walletId: walletIdentity.walletId,
            nearAccountId: toAccountId(walletIdentity.nearAccountId),
            signerSlot,
            nearClient: context.nearClient,
          });
        }
      }
      const authenticatedCredentialIdB64u =
        passkeyCredentialIdB64uFromAuthentication(loginCredential);
      if (!authenticatedCredentialIdB64u) {
        throw new Error('[login] successful Passkey unlock omitted its credential identity');
      }
      const authenticatedAuthority = await exactPasskeyWalletAuthAuthorityRefForCredential({
        walletId: walletIdentity.walletId,
        rpId: signingEngine.getRpId(),
        credentialIdB64u: authenticatedCredentialIdB64u,
      });
      await signingEngine.markWalletSelectionUnlocked({
        walletId: walletIdentity.walletId,
        walletAuthMethodId: authenticatedAuthority.walletAuthMethodId,
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

    // Avoid a duplicate prompt when threshold warmup will collect the assertion itself.
    const noServerSessionPasskeyCredentialPlan = resolveLoginNoServerSessionPasskeyCredentialPlan({
      requiresLocalPasskeyUnlock,
      requireThresholdWarmup,
      hasLoginCredential: Boolean(loginCredential),
    });
    switch (noServerSessionPasskeyCredentialPlan.kind) {
      case 'wallet_unlock_owns_passkey_credential':
      case 'passkey_credential_already_collected':
      case 'no_local_passkey_required':
        break;
      case 'local_unlock_passkey_assertion':
        await collectFreshLocalPasskeyUnlockCredentialForLogin();
        break;
      default:
        return assertNeverLoginState(noServerSessionPasskeyCredentialPlan);
    }

    // One verified wallet-unlock assertion mints every passkey warm session requested below.
    if (requireThresholdWarmup && localUnlockAuthMethod === SIGNER_AUTH_METHODS.passkey) {
      const preparedActivation = await preparePasskeyExchangeEcdsaActivation({
        context,
        walletIdentity,
        selection: walletUnlockSelection,
        ttlMs: signingSessionPolicy.ttlMs,
        remainingUses: requireLoginUnlockSessionUses(signingSessionPolicy.unlockRemainingUses),
      });
      const relayUrl = String(context.configs.network.relayer.url || '').trim();
      const rpId = String(signingEngine.getRpId() || '').trim();
      if (!relayUrl || !rpId) {
        throw new Error('[login] passkey wallet unlock requires relayer URL and rpId');
      }
      const completedUnlock = await completePasskeyWalletUnlock({
        context,
        walletIdentity,
        unlockSubjectId,
        onEvent,
        authenticators,
        signerSlot: baseSignerSlot,
        remainingUses: requireLoginUnlockSessionUses(signingSessionPolicy.unlockRemainingUses),
        relayUrl,
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
      loginCredential = completedUnlock.credential;
      completedPasskeyExchangeEcdsaActivation = completedUnlock.activation;
      completedPasskeyEd25519Session = completedUnlock.result.ed25519Session;
      completedPasskeySessionCustody = completedUnlock.custody;
      await rememberPasskeySessionCustodyForExport({
        walletId: String(walletIdentity.walletId),
        unlock: completedUnlock,
      });
      localWarmupRouteAuthorization = resolveLoginWarmupRouteAuthorization();
    }

    // Warm threshold sessions with the authorization established above.
    if (requireThresholdWarmup) {
      const authMethodBinding = await readThresholdWarmupAuthMethodBinding({
        walletId: walletIdentity.walletId,
        authMethod: localUnlockAuthMethod,
      });
      const keyFactsInventoryAuthority = resolveUnlockEcdsaKeyFactsInventoryAuthority({
        completedActivation: completedPasskeyExchangeEcdsaActivation,
        request: options?.ecdsaKeyFactsInventory,
        routeAuthorization: localWarmupRouteAuthorization,
        wantsEcdsaWarmup: resolveLoginUnlockWarmupBranchPlan({
          subjectSet: walletIdentity.subjectSet,
          selection: walletUnlockSelection,
          hasConfiguredEcdsaTargets:
            listConfiguredThresholdEcdsaPublicationTargets(context.configs.network.chains).length >
            0,
        }).wantsEcdsaWarmup,
      });
      warmupPhase = await warmThresholdSigningSessions(
        resolveThresholdLoginWarmupPhaseInput({
          context,
          signerSlot: baseSignerSlot,
          authenticators,
          selection: walletUnlockSelection,
          subjectSet: walletIdentity.subjectSet,
          authMethod: localUnlockAuthMethod,
          authMethodBinding,
          keyFactsInventoryAuthority,
          routeAuthorization: localWarmupRouteAuthorization,
        }),
      );
      if (localUnlockAuthMethod === SIGNER_AUTH_METHODS.passkey) {
        const authenticatedCredential = loginCredential;
        if (!authenticatedCredential) {
          throw new Error('[login] passkey threshold warm-up completed without a credential');
        }
        await assertPasskeyUnlockRuntimePostconditions({
          context,
          walletIdentity,
          signersWarmed: warmupPhase.signersWarmed,
          credential: authenticatedCredential,
        });
      }
    }

    await persistSuccessfulLoginState(baseSignerSlot);
    void recoverNonceLanesAfterUnlock();

    // Return the same public result shape as the server-session branch.
    const baseLoginResult = buildSuccessfulLoginResult({
      identity: walletIdentity,
      accountSubject,
    });
    const loginResult: LoginAndCreateSessionResult = warmupPhase
      ? {
          ...baseLoginResult,
          ...(warmupPhase.kind === 'threshold_login_warmup_ready'
            ? { signingSession: warmupPhase.signingSession }
            : {}),
        }
      : baseLoginResult;

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
  readonly policy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
  readonly requiresCustodyRejoin: boolean;
};

type CompletedPasskeyExchangeEcdsaActivation = PreparedPasskeyExchangeEcdsaActivation & {
  readonly response: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly continuity: PasskeySessionEcdsaCustodyContinuityV1;
};

function resolveUnlockEcdsaKeyFactsInventoryAuthority(args: {
  completedActivation: CompletedPasskeyExchangeEcdsaActivation | null;
  request: LoginHooksOptions['ecdsaKeyFactsInventory'] | null | undefined;
  routeAuthorization: LoginWarmupRouteAuthorization;
  wantsEcdsaWarmup: boolean;
}): LoginEcdsaKeyFactsInventoryAuthority | null {
  if (!args.wantsEcdsaWarmup) return null;
  if (args.completedActivation) {
    const walletSessionToken = String(
      args.completedActivation.response.session.wallet_session_token || '',
    ).trim();
    if (!walletSessionToken) {
      throw new Error('[login] completed ECDSA unlock omitted its Wallet Session token');
    }
    return {
      kind: 'opaque_wallet_session',
      curve: 'ecdsa_secp256k1',
      walletSessionToken,
    };
  }
  const authority = resolveLoginEcdsaKeyFactsInventoryAuthority({
    request: args.request ?? null,
    routeAuthorization: args.routeAuthorization,
  });
  if (authority?.kind === 'webauthn') {
    throw new Error(
      '[login] ECDSA warm-up requires the Wallet Session minted by the unlock assertion',
    );
  }
  return authority;
}

type CompletedPasskeyWalletUnlock = {
  readonly credential: WebAuthnAuthenticationCredential;
  readonly activation: CompletedPasskeyExchangeEcdsaActivation | null;
  readonly custody: PasskeySessionCustodyUnlockV1;
  readonly result: Extract<
    Awaited<ReturnType<typeof verifyPasskeyWalletUnlock>>,
    { readonly success: true }
  >;
};

function sameCanonicalEcdsaValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertPasskeyEcdsaExchangeContinuity(args: {
  readonly walletId: string;
  readonly prepared: PreparedPasskeyExchangeEcdsaActivation;
  readonly response: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly continuity: PasskeySessionEcdsaCustodyContinuityV1;
}): void {
  const signer = args.continuity.signers.find(
    (candidate) => thresholdEcdsaChainTargetKey(candidate.chainTarget) === args.prepared.targetKey,
  );
  if (!signer) {
    throw new Error('Passkey ECDSA custody continuity omitted the requested chain target');
  }
  const capability = signer.walletKey.publicCapability;
  const receipt = signer.activationReceipt;
  const activation = receipt.ecdsa_activation;
  const normalScope = args.response.normal_signing.scope;
  if (
    signer.walletKey.walletId !== args.walletId ||
    signer.walletKey.keyHandle !== args.prepared.policy.key_handle ||
    args.response.session.threshold_session_id !==
      args.prepared.policy.session_policy.threshold_session_id ||
    !sameCanonicalEcdsaValue(
      signer.runtimePolicyScope,
      args.prepared.policy.session_policy.runtime_policy_scope,
    ) ||
    !sameCanonicalEcdsaValue(args.response.public_capability, capability) ||
    !sameCanonicalEcdsaValue(args.activationReceipt, receipt) ||
    !sameCanonicalEcdsaValue(capability.context, activation.context) ||
    !sameCanonicalEcdsaValue(capability.public_identity, activation.public_identity) ||
    !sameCanonicalEcdsaValue(capability.material_activation, activation.material_activation) ||
    !sameCanonicalEcdsaValue(capability.signer_set.selected_server, activation.signing_worker) ||
    capability.activation_epoch !== activation.activation_epoch ||
    !sameCanonicalEcdsaValue(normalScope.context, activation.context) ||
    !sameCanonicalEcdsaValue(normalScope.public_identity, activation.public_identity) ||
    !sameCanonicalEcdsaValue(normalScope.material_activation, activation.material_activation) ||
    !sameCanonicalEcdsaValue(normalScope.signing_worker, activation.signing_worker) ||
    normalScope.activation_epoch !== activation.activation_epoch ||
    normalScope.wallet_id !== args.walletId ||
    normalScope.ecdsa_threshold_key_id !== signer.walletKey.ecdsaThresholdKeyId ||
    normalScope.signing_root_id !== signer.walletKey.signingRootId ||
    normalScope.signing_root_version !== signer.walletKey.signingRootVersion
  ) {
    throw new Error('Passkey ECDSA session activation changed custody continuity');
  }
}

function assertRejoinedPasskeyEcdsaPublicFacts(args: {
  readonly publicFacts: Awaited<
    ReturnType<LoginUnlockSigningSurface['rejoinWalletCustodyEvmFamilyKeySet']>
  >['publicFacts'];
  readonly signer: PasskeySessionEcdsaCustodyContinuityV1['signers'][number];
}): void {
  const identity = args.signer.walletKey.publicCapability.public_identity;
  if (
    args.publicFacts.contextBinding32B64u !== identity.context_binding_b64u ||
    args.publicFacts.derivationClientSharePublicKey33B64u !==
      identity.derivation_client_share_public_key33_b64u ||
    args.publicFacts.relayerPublicKey33B64u !== identity.server_public_key33_b64u ||
    args.publicFacts.groupPublicKey33B64u !== identity.threshold_public_key33_b64u ||
    args.publicFacts.ethereumAddress !==
      ethereumAddressFromEcdsaIdentityB64u(identity.ethereum_address20_b64u) ||
    args.publicFacts.clientShareRetryCounter !== identity.client_share_retry_counter ||
    args.publicFacts.relayerShareRetryCounter !== identity.server_share_retry_counter
  ) {
    throw new Error('Passkey ECDSA custody rejoin changed registered public identity');
  }
}

async function rememberPasskeySessionCustodyForExport(args: {
  readonly walletId: string;
  readonly unlock: CompletedPasskeyWalletUnlock;
}): Promise<void> {
  const credentialIdB64u = String(
    args.unlock.credential.rawId || args.unlock.credential.id || '',
  ).trim();
  if (!credentialIdB64u) throw new Error('[login] passkey assertion credential id is missing');
  await rememberPasskeyCustodySessionEnvelope({
    walletId: args.walletId,
    credentialIdB64u,
    envelope: args.unlock.custody.envelope,
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
    undefined,
    'passkey',
  );
  const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
  const targetEcdsaKey = context.ecdsaKeys.find((candidate) => candidate.targetKey === targetKey);
  if (!targetEcdsaKey) {
    throw createThresholdEcdsaDeviceLinkRequiredError(targetKey);
  }
  const runtimePolicyScope = context.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('[login] passkey ECDSA activation requires runtime policy scope');
  }
  const thresholdSessionId = requireThresholdLoginEcdsaSessionId(
    createThresholdLoginWarmSessionId('threshold-ecdsa-login'),
  );
  const walletSessionMintId = requireThresholdLoginWalletSessionMintId(
    createThresholdLoginWarmSessionId('wallet-session-mint'),
  );
  return {
    targetKey,
    requiresCustodyRejoin: !targetEcdsaKey.existingRoleLocalMaterial,
    policy: {
      kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
      key_handle: targetEcdsaKey.keyHandle,
      session_policy: {
        threshold_session_id: thresholdSessionId,
        wallet_session_mint_id: walletSessionMintId,
        ttl_ms: args.ttlMs,
        remaining_uses: args.remainingUses,
        runtime_policy_scope: runtimePolicyScope,
      },
    },
  };
}

type CompletePasskeyWalletUnlockArgs = {
  context: LoginWebContext;
  walletIdentity: ResolvedLoginWalletIdentity;
  unlockSubjectId: string;
  onEvent?: LoginHooksOptions['onEvent'];
  authenticators: readonly LoginPasskeyAuthenticator[];
  signerSlot: number;
  remainingUses: number;
  relayUrl: string;
  rpId: string;
  activation: PreparedPasskeyExchangeEcdsaActivation | null;
  expectedOrigin?: string;
  collectCredentialForChallenge: (args: {
    challengeB64u: string;
    credentialIds: readonly string[];
  }) => Promise<WebAuthnAuthenticationCredential>;
};

function passkeyUnlockEd25519SessionRequest(args: {
  walletIdentity: ResolvedLoginWalletIdentity;
  remainingUses: number;
}): PasskeyWalletUnlockInput['ed25519SessionRequest'] {
  switch (args.walletIdentity.kind) {
    case 'near_ed25519_capable_wallet':
      return { kind: 'requested', remainingUses: args.remainingUses };
    case 'evm_family_ecdsa_only_wallet':
      return { kind: 'not_requested' };
    default:
      return assertNeverLoginState(args.walletIdentity);
  }
}

function passkeyWalletUnlockInput(args: {
  challengeId: string;
  credential: WebAuthnAuthenticationCredential;
  ed25519SessionRequest: PasskeyWalletUnlockInput['ed25519SessionRequest'];
  expectedOrigin: string;
  walletIdentity: ResolvedLoginWalletIdentity;
  activation: PreparedPasskeyExchangeEcdsaActivation | null;
}): PasskeyWalletUnlockInput {
  if (args.activation) {
    return {
      type: 'passkey_assertion' as const,
      challengeId: args.challengeId,
      walletId: String(args.walletIdentity.walletId),
      webauthn_authentication: args.credential,
      ed25519SessionRequest: args.ed25519SessionRequest,
      expected_origin: args.expectedOrigin,
      ecdsaSessionPolicy: args.activation.policy,
    };
  }

  return {
    type: 'passkey_assertion' as const,
    challengeId: args.challengeId,
    webauthn_authentication: args.credential,
    ed25519SessionRequest: args.ed25519SessionRequest,
    expected_origin: args.expectedOrigin,
  };
}

async function completePasskeyWalletUnlock(
  args: CompletePasskeyWalletUnlockArgs,
): Promise<CompletedPasskeyWalletUnlock> {
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
  if (!expectedOrigin) {
    throw new Error('[login] passkey wallet unlock requires an expected origin');
  }
  const unlockInput = passkeyWalletUnlockInput({
    challengeId,
    credential,
    ed25519SessionRequest: passkeyUnlockEd25519SessionRequest({
      walletIdentity: args.walletIdentity,
      remainingUses: args.remainingUses,
    }),
    expectedOrigin,
    walletIdentity: args.walletIdentity,
    activation: args.activation,
  });
  const result = await verifyPasskeyWalletUnlock(args.relayUrl, unlockInput);
  if (!result.success) {
    throw new Error(result.error || 'Passkey wallet unlock failed');
  }
  if (!result.walletCustody) {
    throw new Error('Passkey wallet unlock omitted wallet custody continuity');
  }
  if (
    args.activation &&
    (!result.ecdsaSession || !result.ecdsaActivationReceipt || !result.ecdsaCustody)
  ) {
    throw new Error('Passkey wallet unlock omitted the requested ECDSA activation');
  }
  if (
    args.activation &&
    result.ecdsaSession &&
    result.ecdsaActivationReceipt &&
    result.ecdsaCustody
  ) {
    assertPasskeyEcdsaExchangeContinuity({
      walletId: String(args.walletIdentity.walletId),
      prepared: args.activation,
      response: result.ecdsaSession,
      activationReceipt: result.ecdsaActivationReceipt,
      continuity: result.ecdsaCustody,
    });
  }
  if (args.activation?.requiresCustodyRejoin) {
    if (!('ecdsaCustody' in result) || !result.ecdsaCustody) {
      throw new Error('Passkey wallet unlock omitted ECDSA custody rejoin continuity');
    }
    const passkeyPrfFirstB64u = passkeyPrfFirstB64uFromCredential(credential);
    if (!passkeyPrfFirstB64u) {
      throw new Error('Passkey ECDSA custody rejoin requires WebAuthn PRF.first');
    }
    const credentialIdB64u = passkeyCredentialIdB64uFromAuthentication(credential);
    const authority = await exactPasskeyWalletAuthAuthorityRefForCredential({
      walletId: args.walletIdentity.walletId,
      rpId: args.rpId,
      credentialIdB64u,
    });
    await restorePasskeyEcdsaCustodyLogin({
      signingEngine: args.context.signingEngine,
      walletId: String(args.walletIdentity.walletId),
      custody: result.walletCustody,
      continuity: result.ecdsaCustody,
      authority,
      passkeyPrfFirstB64u,
    });
  }
  return {
    credential,
    activation:
      args.activation && result.ecdsaSession
        ? {
            ...args.activation,
            response: result.ecdsaSession,
            activationReceipt: result.ecdsaActivationReceipt,
            continuity: result.ecdsaCustody,
          }
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

type ThresholdLoginWarmupPhaseResult =
  | {
      kind: 'threshold_login_warmup_ready';
      signingSession: ThresholdWarmLoginAndCreateSessionResult['signingSession'];
      signersWarmed: readonly ThresholdLoginWarmSigner[];
    }
  | {
      kind: 'threshold_login_ecdsa_only_warmup_ready';
      signingSession?: never;
      signersWarmed: readonly ['ecdsa'];
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
  authorizationId: WalletSessionAuthorizationId | null;
  walletSessionId: WalletSessionId | null;
  quotaId: MpcWalletSigningQuotaId | null;
  walletSessionToken: string;
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
  context.sharedState.ed25519.authorizationId = minted.authorizationId;
  context.sharedState.ed25519.walletSessionId = minted.walletSessionId;
  context.sharedState.ed25519.quotaId = minted.quotaId;
  context.sharedState.ed25519.walletSessionToken = minted.walletSessionToken;
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
  routeAuth?: OpaqueWalletSessionAuth;
};

function isWalletSessionReconnectEcdsaRouteAuth(
  auth: OpaqueWalletSessionAuth | undefined,
): auth is OpaqueWalletSessionAuth {
  return auth?.kind === 'opaque_wallet_session';
}

type ThresholdLoginWarmupResult = {
  ecdsaBootstraps: ThresholdEcdsaSessionBootstrapResult[];
  ed25519Session: ProvisionWarmEd25519CapabilitySuccessResult | null;
};

type ThresholdEcdsaAuthorizedEd25519Mint = {
  thresholdEcdsaSessionToken: string;
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
      authorization_id: session.authorizationId,
      threshold_session_id: requireThresholdLoginEcdsaSessionId(session.thresholdSessionId),
      wallet_session_id: session.walletSessionId,
      quota_id: session.quotaId,
      expires_at_ms: session.expiresAtMs,
      remaining_uses: session.remainingUses,
      wallet_session_token: session.walletSessionToken,
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
  args.routeAuthorization.kind satisfies 'none';
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

type PasskeyEd25519CustodyLoginInput = {
  signingEngine: LoginUnlockSigningSurface;
  custody: ActivePasskeySessionCustodyUnlockV1;
  walletBinding: ResolvedLoginWalletBinding;
  signerSlot: number;
  passkeyPrfFirstB64u: string;
  walletSession: ProvisionWarmEd25519CapabilitySuccessResult;
  authority: WalletAuthAuthorityRef;
  routerAbNormalSigning: ReturnType<typeof createRouterAbNormalSigningPolicy>;
  relayerUrl: string;
};

async function ensurePasskeyEd25519OwnerProfile(
  input: Pick<PasskeyEd25519CustodyLoginInput, 'signingEngine' | 'walletBinding' | 'signerSlot'> & {
    readonly credentialIdB64u: string;
    readonly registeredPublicKey: Uint8Array;
  },
): Promise<void> {
  const existing = await input.signingEngine
    .getUserBySignerSlot(input.walletBinding.nearAccountId, input.signerSlot)
    .catch(() => null);
  if (existing) {
    if (
      existing.walletId !== String(input.walletBinding.walletId) ||
      existing.nearEd25519SigningKeyId !== String(input.walletBinding.nearEd25519SigningKeyId) ||
      existing.signerSlot !== input.signerSlot
    ) {
      throw new Error('[login] local Ed25519 owner profile identity is invalid');
    }
    return;
  }
  await input.signingEngine.storeUserData({
    walletId: String(input.walletBinding.walletId),
    nearAccountId: input.walletBinding.nearAccountId,
    nearEd25519SigningKeyId: String(input.walletBinding.nearEd25519SigningKeyId),
    signerSlot: input.signerSlot,
    operationalPublicKey: `ed25519:${base58Encode(input.registeredPublicKey)}`,
    passkeyCredential: {
      id: input.credentialIdB64u,
      rawId: input.credentialIdB64u,
    },
    lastUpdated: Date.now(),
    version: 2,
  });
}

function walletCustodyLoginActivationFacts(
  custody: ActivePasskeySessionCustodyUnlockV1,
  thresholdSessionId: string,
): WalletCustodyActivationFactsV1 {
  const capability = custody.ed25519.capability;
  const continuity = capability.registrationContinuity;
  return {
    materialActivation: capability.materialActivation,
    lifecycleId: capability.lifecycle.lifecycleId,
    signingRootVersion: capability.lifecycle.rootShareEpoch,
    signingRootId: capability.applicationBinding.signing_root_id,
    signerSetId: capability.lifecycle.signerSetId,
    thresholdSessionId,
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
  const thresholdSessionId = parseThresholdEd25519SessionId(input.walletSession.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error('[login] wallet custody returned an invalid threshold session identity');
  }
  const activation = walletCustodyLoginActivationFacts(input.custody, thresholdSessionId.value);
  const envelope = walletCustodyCacheEnvelopeFromRecordV1(input.custody.envelope);
  let activeClient: Awaited<ReturnType<typeof openWalletCustodyEd25519ActiveClientV1>> | null =
    null;
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
      const custodyWire = joinCustodyWireFromEnvelopeRecord(input.custody.envelope);
      if (!custodyWire.ok) throw new Error(custodyWire.reason);
      rejoinSecret = base64UrlDecode(input.passkeyPrfFirstB64u);
      openSecret = base64UrlDecode(input.passkeyPrfFirstB64u);
      const rejoined = await input.signingEngine.rejoinWalletCustodyNearEd25519KeySet({
        walletId: String(input.walletBinding.walletId),
        custodyJson: custodyWire.custodyJson,
        factorSecret: rejoinSecret.buffer,
        nearEd25519SigningKeyId: String(input.walletBinding.nearEd25519SigningKeyId),
        recoveryBasis: capability,
        routerOrigin: new URL(input.relayerUrl).origin,
        walletSessionToken: input.walletSession.walletSessionToken,
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
      try {
        await input.signingEngine.persistWalletCustodyEd25519Material({
          binding: materialBinding,
          sealed,
        });
      } catch (error) {
        console.warn(
          '[login] wallet custody cache write failed; continuing with verified material',
          {
            error,
          },
        );
      }
      activeClient = await openWalletCustodyEd25519ActiveClientV1({
        material: { binding: materialBinding, sealed },
        activation: walletCustodyActivationFactsFromActiveClientMetadataV1(rejoined.metadata),
        envelope,
        ownedFactorSecret: openSecret,
      });
    }
    if (!activeClient) throw new Error('[login] wallet custody produced no active client');
    const recoveredThresholdSessionId = parseThresholdEd25519SessionId(
      activeClient.metadata().scope.threshold_session_id,
    );
    if (!recoveredThresholdSessionId.ok) {
      throw new Error('[login] wallet custody returned an invalid threshold session identity');
    }
    if (recoveredThresholdSessionId.value !== input.walletSession.thresholdSessionId) {
      throw new Error('[login] wallet custody changed the threshold session identity');
    }
    const envelopeFactor = input.custody.envelope.factor;
    if (envelopeFactor.kind !== 'passkey') {
      throw new Error('[login] wallet custody returned a different factor authority');
    }
    await ensurePasskeyEd25519OwnerProfile({
      signingEngine: input.signingEngine,
      walletBinding: input.walletBinding,
      signerSlot: input.signerSlot,
      credentialIdB64u: envelopeFactor.credentialIdB64u,
      registeredPublicKey: activeClient.metadata().registeredPublicKey,
    });
    await persistPasskeyEd25519YaoSignerMaterialV1({
      store: IndexedDBManager,
      activeClient,
      identity: {
        walletId: String(input.walletBinding.walletId),
        nearAccountId: String(input.walletBinding.nearAccountId),
        nearEd25519SigningKeyId: String(input.walletBinding.nearEd25519SigningKeyId),
        thresholdSessionId: recoveredThresholdSessionId.value,
        signerSlot: input.signerSlot,
        rpId: envelopeFactor.rpId,
        credentialIdB64u: envelopeFactor.credentialIdB64u,
        signingRootId: capability.applicationBinding.signing_root_id,
        signingRootVersion: capability.lifecycle.rootShareEpoch,
        signingWorkerId: input.custody.ed25519.relayerKeyId,
      },
      stableServerScope: {
        relayerKeyId: input.custody.ed25519.relayerKeyId,
        participantIds: input.custody.ed25519.participantIds,
        runtimePolicyScope: capability.runtimePolicyScope,
        routerAbNormalSigning: input.routerAbNormalSigning,
      },
      passkeyPrfFirstB64u: input.passkeyPrfFirstB64u,
    });
    const activated = await input.signingEngine.activateVerifiedNearEd25519YaoMaterial({
      activeClient,
      facts: {
        thresholdSessionId: recoveredThresholdSessionId.value,
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
    const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
      walletId: String(input.walletBinding.walletId),
      nearAccountId: String(input.walletBinding.nearAccountId),
      nearEd25519SigningKeyId: String(input.walletBinding.nearEd25519SigningKeyId),
      walletSessionId: input.walletSession.walletSessionId,
      authorizationId: input.walletSession.authorizationId,
      quotaId: input.walletSession.quotaId,
      thresholdSessionId: recoveredThresholdSessionId.value,
      remainingUses: input.walletSession.remainingUses,
      expiresAtMs: input.walletSession.expiresAtMs,
      runtimePolicyScope: input.walletSession.runtimePolicyScope,
      signingRootId: capability.applicationBinding.signing_root_id,
      signingRootVersion: capability.lifecycle.rootShareEpoch,
      routerAbNormalSigning: input.routerAbNormalSigning,
      walletSessionToken: input.walletSession.walletSessionToken,
      nowMs: Math.min(Date.now(), input.walletSession.expiresAtMs - 1),
    });
    if (!signingWalletSession.ok) {
      throw new Error(
        `[login] wallet custody returned an unusable Ed25519 Wallet Session: ${signingWalletSession.reason}`,
      );
    }
    const session = buildPasskeyRouterAbEd25519WalletSessionState({
      walletId: input.walletBinding.walletId,
      nearAccountId: input.walletBinding.nearAccountId,
      nearEd25519SigningKeyId: input.walletBinding.nearEd25519SigningKeyId,
      signerSlot: input.signerSlot,
      rpId: toRpId(envelopeFactor.rpId),
      credentialIdB64u: envelopeFactor.credentialIdB64u,
      relayerUrl: input.relayerUrl,
      authority: input.authority,
      signingWalletSession: signingWalletSession.value,
    });
    await persistPasskeyEd25519YaoSessionForRefresh({
      persistence: input.signingEngine,
      session,
      prfFirstB64u: input.passkeyPrfFirstB64u,
      ed25519Restore: buildPasskeyEd25519RestoreMetadata({
        rpId: envelopeFactor.rpId,
        nearAccountId: String(input.walletBinding.nearAccountId),
        nearEd25519SigningKeyId: String(input.walletBinding.nearEd25519SigningKeyId),
        relayerKeyId: input.custody.ed25519.relayerKeyId,
        participantIds: input.custody.ed25519.participantIds,
        runtimePolicyScope: input.walletSession.runtimePolicyScope,
        signerSlot: input.signerSlot,
        routerAbNormalSigning: input.routerAbNormalSigning,
        credentialIdB64u: envelopeFactor.credentialIdB64u,
        materialActivation: activated.materialActivation,
      }),
      materialActivation: activated.materialActivation,
    });
    /* R103 zero-prompt handoff. The passkey factor was presented for this
       unlock and the owner Wallet Session persisted above is active, so this
       is where the linking capability is established — the linking flow itself
       never prompts and never opens the envelope again. Runs last: everything
       above has succeeded, so a failed unlock never leaves a capability. */
    await input.signingEngine.establishUnlockedWalletEd25519ExportRootCapabilityV1({
      existingEnvelope: input.custody.envelope,
      passkeyPrfFirstB64u: input.passkeyPrfFirstB64u,
      walletId: String(input.walletBinding.walletId),
      walletAuthMethodId: String(input.authority.walletAuthMethodId),
      walletSessionId: String(input.walletSession.walletSessionId),
      expiresAtMs: input.walletSession.expiresAtMs,
    });
  } catch (error) {
    activeClient?.dispose();
    throw error;
  } finally {
    rejoinSecret?.fill(0);
    openSecret?.fill(0);
  }
}

function ethereumAddressFromEcdsaIdentityB64u(value: string): `0x${string}` {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) throw new Error('[login] ECDSA custody address is invalid');
  let hex = '0x';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex as `0x${string}`;
}

function nonEmptyEcdsaCustodyChainTargets(
  signers: readonly PasskeySessionEcdsaCustodyContinuityV1['signers'][number][],
): readonly [
  PasskeySessionEcdsaCustodyContinuityV1['signers'][number]['chainTarget'],
  ...PasskeySessionEcdsaCustodyContinuityV1['signers'][number]['chainTarget'][],
] {
  const [first, ...rest] = signers;
  if (!first) throw new Error('[login] passkey ECDSA custody continuity is empty');
  return [first.chainTarget, ...rest.map((signer) => signer.chainTarget)];
}

async function restorePasskeyEcdsaCustodyLogin(input: {
  readonly signingEngine: LoginUnlockSigningSurface;
  readonly walletId: string;
  readonly custody: PasskeySessionCustodyUnlockV1;
  readonly continuity: PasskeySessionEcdsaCustodyContinuityV1;
  readonly authority: WalletAuthAuthorityRef;
  readonly passkeyPrfFirstB64u: string;
}): Promise<void> {
  const first = input.continuity.signers[0];
  if (!first) throw new Error('[login] passkey ECDSA custody continuity is empty');
  if (first.walletKey.walletId !== input.walletId) {
    throw new Error('[login] passkey ECDSA custody continuity changed wallet identity');
  }
  for (const signer of input.continuity.signers) {
    if (
      signer.walletKey.walletId !== first.walletKey.walletId ||
      signer.walletKey.keyHandle !== first.walletKey.keyHandle ||
      signer.walletKey.ecdsaThresholdKeyId !== first.walletKey.ecdsaThresholdKeyId ||
      signer.walletKey.signingRootId !== first.walletKey.signingRootId ||
      signer.walletKey.signingRootVersion !== first.walletKey.signingRootVersion ||
      signer.walletKey.relayerKeyId !== first.walletKey.relayerKeyId ||
      JSON.stringify(signer.walletKey.publicCapability) !==
        JSON.stringify(first.walletKey.publicCapability) ||
      JSON.stringify(signer.activationReceipt) !== JSON.stringify(first.activationReceipt) ||
      JSON.stringify(signer.runtimePolicyScope) !== JSON.stringify(first.runtimePolicyScope)
    ) {
      throw new Error('[login] passkey ECDSA custody continuity conflicts across targets');
    }
  }
  const custodyWire = joinCustodyWireFromEnvelopeRecord(input.custody.envelope);
  if (!custodyWire.ok) throw new Error(custodyWire.reason);
  const factorSecret = base64UrlDecode(input.passkeyPrfFirstB64u);
  try {
    const rejoined = await input.signingEngine.rejoinWalletCustodyEvmFamilyKeySet({
      walletId: input.walletId,
      custodyJson: custodyWire.custodyJson,
      factorSecret: factorSecret.buffer,
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: input.walletId,
        signingRootId: first.walletKey.signingRootId,
        signingRootVersion: first.walletKey.signingRootVersion,
      }),
      applicationBindingDigestB64u:
        first.walletKey.publicCapability.context.application_binding_digest_b64u,
      registeredClientRootPublicKey33B64u: first.walletKey.derivationClientSharePublicKey33B64u,
      relayerPublicIdentityJson: JSON.stringify({
        relayerKeyId: first.walletKey.relayerKeyId,
        relayerPublicKey33B64u:
          first.activationReceipt.ecdsa_activation.public_identity.server_public_key33_b64u,
        groupPublicKey33B64u:
          first.activationReceipt.ecdsa_activation.public_identity.threshold_public_key33_b64u,
        ethereumAddress: ethereumAddressFromEcdsaIdentityB64u(
          first.activationReceipt.ecdsa_activation.public_identity.ethereum_address20_b64u,
        ),
        relayerShareRetryCounter:
          first.activationReceipt.ecdsa_activation.public_identity.server_share_retry_counter,
      }),
    });
    assertRejoinedPasskeyEcdsaPublicFacts({
      publicFacts: rejoined.publicFacts,
      signer: first,
    });
    await input.signingEngine.restoreWalletCustodyEcdsaContinuity({
      authority: input.authority,
      chainTargets: nonEmptyEcdsaCustodyChainTargets(input.continuity.signers),
      walletId: first.walletKey.walletId,
      keyHandle: first.walletKey.keyHandle,
      ecdsaThresholdKeyId: first.walletKey.ecdsaThresholdKeyId,
      signingRootId: first.walletKey.signingRootId,
      signingRootVersion: first.walletKey.signingRootVersion,
      relayerKeyId: first.walletKey.relayerKeyId,
      participantIds: first.walletKey.participantIds,
      publicCapability: first.walletKey.publicCapability,
      activationReceipt: first.activationReceipt,
      runtimePolicyScope: first.runtimePolicyScope,
      readyStateBlobB64u: rejoined.readyStateBlobB64u,
      publicFacts: rejoined.publicFacts,
    });
  } finally {
    factorSecret.fill(0);
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
  passkeyUnlockEd25519Session: PasskeyWalletUnlockEd25519Session | null;
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
      authorizationId: null,
      walletSessionId: null,
      quotaId: null,
      walletSessionToken: '',
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
      args.passkeyExchangeEcdsaActivation?.policy.session_policy.threshold_session_id || '',
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
        const ed25519SessionAuthority = bindLoginEd25519SessionAuthorityToAuthenticatedCredential({
          authority: requireRequestedLoginEd25519SessionAuthority(args.ed25519SessionAuthority),
          walletId: walletBinding.walletId,
          rpId: args.context.signingEngine.getRpId(),
          credentialIdB64u: localPasskeyCredentialIdB64u,
        });
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
          runtimePolicyScope: provisionScope.runtimePolicyScope || undefined,
          routerAbNormalSigning: provisionScope.routerAbNormalSigning,
          runtimeScopeBootstrap: runtimeScopeBootstrap || undefined,
          participantIds: provisionScope.participantIds,
          sessionKind: 'opaque' as const,
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
            if (!args.passkeyUnlockEd25519Session) {
              throw new Error('[login] verified wallet unlock omitted its Ed25519 Wallet Session');
            }
            if (args.ed25519MintPlan.kind !== 'wallet_custody') {
              throw new Error('[login] verified unlock Ed25519 session requires wallet custody');
            }
            connected = passkeyUnlockEd25519Connection({
              session: args.passkeyUnlockEd25519Session,
              walletBinding,
              signerSlot: args.signerSlot,
              custody: args.ed25519MintPlan.custody,
              provisionScope,
              credential,
              remainingUses: unlockRemainingUses,
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

        const connectedWalletSessionToken = String(connected.walletSessionToken || '').trim();
        if (!connectedWalletSessionToken) {
          throw new Error(
            '[login] threshold Ed25519 warm-up did not return a Wallet Session token',
          );
        }

        const connectedAuthority =
          ed25519SessionAuthority.kind === 'passkey'
            ? await exactPasskeyWalletAuthAuthorityRefForCredential({
                walletId: walletBinding.walletId,
                rpId: args.context.signingEngine.getRpId(),
                credentialIdB64u:
                  passkeyCredentialIdB64uFromAuthentication(credential || undefined) ||
                  localPasskeyCredentialIdB64u,
              })
            : await walletAuthAuthorityRef({
                authority: ed25519SessionAuthority.authority.authority,
              });
        sharedState.activeEd25519Authorization = await persistActiveWalletSessionAuthorizationCurve(
          walletSessionAuthorizations,
          {
            walletId: walletBinding.walletId,
            authorizationId: connected.authorizationId,
            walletSessionId: connected.walletSessionId,
            quotaId: connected.quotaId,
            expiresAtMs: connected.expiresAtMs,
            authority: connectedAuthority,
            authMethod: args.authMethod,
            walletSessionToken: connectedWalletSessionToken,
            thresholdSessionId: connectedThresholdSessionId,
            curve: 'ed25519',
          },
        );
        ed25519AuthorizationPersistenceDeferred?.resolve(undefined);

        if (args.ed25519MintPlan.kind === 'wallet_custody') {
          if (ed25519SessionAuthority.kind !== 'passkey') {
            throw new Error('[login] wallet custody requires passkey authority');
          }
          const expectedMaterialActivation = resolveLoginPasskeyMaterialActivation(
            ed25519ProvisioningIdentity,
            args.ed25519MintPlan,
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
              walletSession: connected,
              authority: connectedAuthority,
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
          const thresholdEcdsaSessionToken = String(
            bootstrap.session.walletSessionToken || '',
          ).trim();
          const passkeyPrfFirstB64u = credential
            ? passkeyPrfFirstB64uFromCredential(credential)
            : '';
          const passkeyCredentialIdB64u =
            passkeyCredentialIdB64uFromAuthentication(credential || undefined) ||
            localPasskeyCredentialIdB64u;
          if (!thresholdEcdsaSessionToken || !passkeyPrfFirstB64u || !passkeyCredentialIdB64u) {
            return;
          }
          ecdsaAuthorizedEd25519Mint = {
            thresholdEcdsaSessionToken,
            passkeyPrfFirstB64u,
            passkeyCredentialIdB64u,
            walletSessionId: bootstrap.session.walletSessionId,
            quotaId: bootstrap.session.quotaId,
          };
        };
        const resolveCurrentBootstrapIdentity = (): ThresholdLoginWarmEcdsaBootstrapIdentity => {
          if (sharedState.ed25519.walletSessionToken) {
            return {
              routeAuth: {
                kind: 'opaque_wallet_session',
                walletSessionToken: requireOpaqueWalletSessionToken(
                  sharedState.ed25519.walletSessionToken,
                ),
              },
            };
          }
          const thresholdEcdsaSessionToken = String(
            ecdsaAuthorizedEd25519Mint?.thresholdEcdsaSessionToken || '',
          ).trim();
          if (thresholdEcdsaSessionToken) {
            return {
              routeAuth: {
                kind: 'opaque_wallet_session',
                walletSessionToken: requireOpaqueWalletSessionToken(thresholdEcdsaSessionToken),
              },
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
          const authorizationAuthority = existingRoleLocalMaterial.authority;
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
                authorizationAuthority,
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
              authorizationAuthority,
              passkeyCredentialIdB64u: localPasskeyCredentialIdB64u,
              routeAuth: reconnectRouteAuth,
              beforeAuthorizationPersistence,
            },
          });
        };
        const bootstrapConfiguredTargets = async () => {
          completeActiveContextFromConfiguredTargets('login ECDSA warm-up preflight');
          const orderedConfiguredEcdsaTargets: typeof configuredEcdsaTargets = [];
          const preauthorizedTargetKey = args.passkeyExchangeEcdsaActivation?.targetKey || null;
          if (preauthorizedTargetKey) {
            for (const target of configuredEcdsaTargets) {
              if (thresholdEcdsaChainTargetKey(target.chainTarget) === preauthorizedTargetKey) {
                orderedConfiguredEcdsaTargets.push(target);
              }
            }
          }
          for (const target of configuredEcdsaTargets) {
            if (thresholdEcdsaChainTargetKey(target.chainTarget) !== preauthorizedTargetKey) {
              orderedConfiguredEcdsaTargets.push(target);
            }
          }
          for (const target of orderedConfiguredEcdsaTargets) {
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
  let currentAuthentication = context.signingEngine.readWalletAuthenticationState();
  const requestedWalletId =
    walletId ??
    (currentAuthentication.kind !== 'signed_out' ? currentAuthentication.walletId : undefined);
  if (currentAuthentication.kind === 'signed_out' && requestedWalletId !== undefined) {
    const parsedRequestedWalletId = parseWalletId(String(requestedWalletId));
    const restoredAuthentication = parsedRequestedWalletId.ok
      ? await authenticatedWalletStateFromExactAuthority(parsedRequestedWalletId.value)
      : null;
    if (restoredAuthentication) {
      context.signingEngine.setWalletAuthenticated(restoredAuthentication);
      currentAuthentication = restoredAuthentication;
    }
  }
  let readResolution = await resolveWalletCapabilitySubjectResolution(requestedWalletId);
  if (readResolution.kind === 'no_session_for_wallet') {
    const linkedSubjectSet = await resolveLinkedDeviceUnlockSubjectSet(
      String(readResolution.walletId),
    );
    if (linkedSubjectSet) {
      readResolution = {
        kind: 'resolved',
        walletId: readResolution.walletId,
        subjectSet: linkedSubjectSet,
        source: 'local_wallet_authority',
      };
    }
  }
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
  const currentWalletAuthentication = walletAuthenticationForWallet(
    currentAuthentication,
    readResolution.walletId,
  );
  const restoredWalletAuthentication =
    currentWalletAuthentication.kind === 'signed_out'
      ? ((await authenticatedWalletStateFromExactAuthority(readResolution.walletId)) ??
        authenticatedWalletStateFromReusableSession(reusableWalletSession))
      : null;
  if (restoredWalletAuthentication) {
    context.signingEngine.setWalletAuthenticated(restoredWalletAuthentication);
  }
  return {
    appIdentity,
    authentication: restoredWalletAuthentication ?? currentWalletAuthentication,
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
    authentication.kind !== 'signed_out' &&
    String(authentication.walletId) === String(walletId)
  ) {
    return authentication;
  }
  return { kind: 'signed_out' };
}

function authenticatedWalletStateFromReusableSession(
  session: ReusableWalletSessionState,
): Extract<WalletAuthenticationState, { kind: 'authenticated' }> | null {
  switch (session.kind) {
    case 'active':
    case 'exhausted':
      return {
        kind: 'authenticated',
        walletId: session.walletId,
        authMethod: session.authMethod,
      };
    case 'absent':
    case 'expired':
    case 'invalid':
    case 'missing':
    case 'superseded':
    case 'unavailable':
      return null;
    default:
      return assertNeverLoginState(session);
  }
}

async function authenticatedWalletStateFromExactAuthority(
  walletId: WalletId,
): Promise<Extract<WalletAuthenticationState, { kind: 'authenticated' }> | null> {
  const selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId)).catch(
    () => null,
  );
  if (!selected || selected.kind !== 'resolved') return null;
  const { selection, authMethod, authority } = selected;
  if (
    selection.walletId !== walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    selection.lockState !== 'unlocked' ||
    authMethod.walletId !== walletId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authMethod.status !== 'active' ||
    authority.walletId !== walletId ||
    authority.state !== 'active'
  ) {
    return null;
  }
  const exact = await walletSessionAuthorizations
    .readExactWithOperationCredential({
      walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
    })
    .catch(() => null);
  if (
    !exact ||
    exact.record.authorityDigestB64u !== authority.authorityDigestB64u ||
    exact.record.authorityRevocationEpoch !== authority.revocationEpoch ||
    exact.record.expiresAtMs <= Date.now() ||
    exact.operationCredential.token.trim().length === 0
  ) {
    return null;
  }
  return {
    kind: 'authenticated',
    walletId,
    authMethod: authMethod.kind,
  };
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
  if (args.authority?.kind === 'opaque_wallet_session') {
    return await fetchWalletEcdsaKeyFactsInventoryWithOpaqueWalletSession({
      relayerUrl,
      walletId: args.walletId,
      rpId,
      curve: args.authority.curve,
      walletSessionToken: args.authority.walletSessionToken,
      keyTargets: args.keyTargets,
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
  /**
   * R109C: sibling auth methods hold their own access projections over one
   * activation, so a wallet-wide read returns a lane per method. Warming has to
   * name the method being unlocked, or it warms the sibling's lane and the
   * Wallet Session is minted against a credential the user is not presenting.
   */
  authMethod?: 'passkey' | 'email_otp',
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
  const snapshot = await readAvailableSigningLanesForUi(context, walletId, authMethod);
  const availableLaneKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  let availableLaneRuntimePolicyScope: ThresholdRuntimePolicyScope | undefined;
  if (snapshot) {
    for (const target of ecdsaAvailableLaneTargets(snapshot)) {
      const lane = ecdsaAvailableLaneForTarget(snapshot, target);
      if (!isConcreteAvailableSigningLane(lane)) continue;
      if (lane.source !== 'canonical_capability') continue;
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
  authMethod?: 'passkey' | 'email_otp',
): Promise<AvailableSigningLanes | null> {
  return await context.signingEngine.readPersistedAvailableSigningLanes({
    walletId,
    ...(authMethod ? { authMethod } : {}),
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

function nearWalletSubjectsEqual(
  left: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>,
  right: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.nearAccountId === right.nearAccountId &&
    left.nearEd25519SigningKeyId === right.nearEd25519SigningKeyId &&
    left.signerSlot === right.signerSlot
  );
}

async function resolveLinkedNearOperationalPublicKey(
  subject: Extract<WalletUnlockSubject, { kind: 'near_ed25519_wallet' }>,
): Promise<string | null> {
  /* Factor-agnostic on purpose: both supported factors install linked devices,
     and the checks below already require an active device-link authority whose
     resolved NEAR subject equals the one asked about. */
  const parsedWalletId = parseWalletId(String(subject.walletId));
  if (!parsedWalletId.ok) return null;
  const walletId = parsedWalletId.value;
  let resolved: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>;
  try {
    resolved = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  } catch {
    return null;
  }
  if (resolved.kind !== 'resolved') return null;
  const { selection, authMethod, authority } = resolved;
  if (
    linkedDeviceUnlockIdentityMismatchLabels({ walletId, selection, authMethod, authority })
      .length > 0 ||
    authMethod.status !== 'active' ||
    authority.state !== 'active' ||
    authority.provenance.kind !== 'device_link'
  ) {
    return null;
  }
  const resolvedSubject = await resolveLinkedDeviceNearUnlockSubject({
    walletId,
    authMethod,
    authority,
    signerMaterials: resolved.signerMaterials,
  });
  if (
    resolvedSubject.kind !== 'resolved' ||
    !nearWalletSubjectsEqual(resolvedSubject.subject, subject)
  ) {
    return null;
  }
  const activation = authority.signerActivations.ed25519;
  if (!activation) return null;
  return `ed25519:${base58Encode(base64UrlDecode(activation.signer.registeredPublicKeyB64u))}`;
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
  const persistedOperationalPublicKey = selectNearOperationalPublicKeyForLogin(userData);
  /* A linked device has no local registration profile to carry the operational
     public key, whichever source resolved its subjects, so fall back to its
     exact device-link authority whenever a NEAR subject is present. */
  const nearOperationalPublicKey =
    persistedOperationalPublicKey ||
    (nearSubject ? await resolveLinkedNearOperationalPublicKey(nearSubject) : null);
  return {
    ...base,
    nearAccountId: resolvedNearAccountId,
    nearOperationalPublicKey,
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

export async function listLocalPasskeyWalletIds(): Promise<WalletId[]> {
  const walletIds = await IndexedDBManager.listWalletSelectionWalletIds();
  return [...new Set(walletIds)];
}

/** Lock clears authentication and volatile signing material. */
export type LockOperationContext = {
  signingEngine: {
    readWalletAuthenticationState(): WalletAuthenticationState;
    advanceWalletLockGeneration(walletId: WalletId): Promise<number>;
    retireActiveWalletSessionAuthorizationForLock(walletId: WalletId): Promise<void>;
    clearWalletAuthentication(): void;
    getNonceCoordinator(): { clearAll(): void };
    clearThresholdEcdsaSigningQueue(): void;
    clearVolatileWarmSigningMaterial(): Promise<void>;
  };
};

export async function lock(context: LockOperationContext): Promise<void> {
  const { signingEngine } = context;
  const authentication = signingEngine.readWalletAuthenticationState();
  let failure: unknown;
  let failed = false;
  if (authentication.kind === 'authenticated') {
    try {
      await signingEngine.advanceWalletLockGeneration(authentication.walletId);
      await signingEngine.retireActiveWalletSessionAuthorizationForLock(authentication.walletId);
    } catch (error: unknown) {
      failure = error;
      failed = true;
    }
  }
  try {
    signingEngine.clearWalletAuthentication();
  } catch (error: unknown) {
    if (!failed) {
      failure = error;
      failed = true;
    }
  }
  try {
    signingEngine.getNonceCoordinator().clearAll();
  } catch {}
  try {
    signingEngine.clearThresholdEcdsaSigningQueue();
  } catch {}
  try {
    await signingEngine.clearVolatileWarmSigningMaterial();
  } catch (error: unknown) {
    if (!failed) {
      failure = error;
      failed = true;
    }
  }
  if (failed) throw failure;
}
