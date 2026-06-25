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
  WalletSession,
  LoginState,
  SigningSessionStatus,
  ThresholdWarmLoginAndCreateSessionResult,
  WalletAuthMethod,
} from '@/core/types/seams';
import type {
  EcdsaLoginSessionSurface,
  LockWebContext,
  LoginWebContext,
  LoginWarmSigningSurface,
  RecentUnlocksWebContext,
  UserAccountLookupSurface,
  WalletSessionWebContext,
} from '@/SeamsWeb/signingSurface/types';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  getUserFriendlyErrorMessage,
  isUserCancellationError,
  toError,
} from '@shared/utils/errors';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { isObject } from '@shared/utils/validation';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  getNearAccountProjection,
  resolveNearAccountProfileContinuity,
} from '@/core/accountData/near/accountProjection';
import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import type {
  ClientAuthenticatorData,
  ClientUserData,
} from '@/core/accountData/near/nearAccountData.types';
import { exchangeSession, type SessionExchangeInput } from '@/core/rpcClients/near/rpcCalls';
import {
  fetchWalletEcdsaKeyFactsInventoryWithAppSession,
  fetchWalletEcdsaKeyFactsInventoryWithWebAuthn,
  type WalletEcdsaKeyFactsInventoryTarget,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { WalletSessionReconnectEcdsaBootstrapRouteAuth } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { parseSignerSlot } from '@/core/signingEngine/webauthnAuth/device/signerSlot';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearStoredThresholdEd25519SessionRecordForAccount,
  getStoredThresholdEd25519SessionRecordForAccount,
  getStoredThresholdEd25519SessionRecordForWallet,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  thresholdEcdsaSessionRecordReadModel,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { parseWarmEd25519SigningSessionAuthorizationFromRecord } from '@/core/signingEngine/session/warmCapabilities/ed25519Authorization';
import { parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { ThresholdEcdsaSessionStoreSource } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  STALE_ECDSA_KEY_IDENTITY_ERROR_CODE,
  type ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  buildEd25519SessionPolicy,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildThresholdEd25519ProvidedPrfSecretSource,
  buildThresholdEd25519WebAuthnPrfSecretSource,
  type Ed25519WalletSessionMintAuthorization,
} from '@/core/signingEngine/threshold/ed25519/walletSession';
import { shouldRequireThresholdWarmSession } from '@/SeamsWeb/operations/session/thresholdWarmSessionDefaults';
import {
  createRouterAbNormalSigningPolicy,
  hydrateExactEd25519SessionFromDurableSealedWorkerMaterial,
  hydrateCurrentEd25519SessionFromDurableSealedWorkerMaterial,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import { resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential } from '@/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization';
import { classifyRouterAbEd25519PersistedSigningRecord } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { listConfiguredThresholdEcdsaPublicationTargets } from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  AvailableEcdsaSigningLane,
  AvailableEd25519SigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  availableEd25519SigningLaneAuthMethod,
  availableEcdsaSigningLaneAuthMethod,
  ecdsaAvailableLaneForTarget,
  ecdsaAvailableLaneTargets,
  isConcreteAvailableSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { assertWalletRuntimePostconditions } from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  deriveEvmFamilyWalletKeyIdFromSigningRootFacts,
  evmFamilyEcdsaWalletKeyToIdentity,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildSharedKeyTargetCompletion,
  collectConfiguredTargetThresholdEcdsaWarmKeys,
  configuredTargetThresholdEcdsaWarmKey,
  mergeCanonicalThresholdEcdsaWarmSessionContexts,
  parseActiveEcdsaSignerRecordForUnlock,
  planUnlockEcdsaWarmup,
  requireCompleteSharedKeyTargetContext,
  type ActiveEcdsaSignerRecord,
  type BlockedEcdsaSignerRecord,
  type CanonicalThresholdEcdsaWarmSessionContext,
  type ConfiguredTargetThresholdEcdsaWarmKey,
  type KeyFactsInventoryRequiredEcdsaSignerRecord,
  type SharedKeyTargetCompletion,
  type WalletUnlockSelection,
} from '@/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner';
import {
  DEV_DEFAULT_UNLOCK_REMAINING_USES,
  resolveSigningBudgetPolicyRemainingUses,
  resolveWalletUnlockBudgetPolicyFromRequestedUses,
  type WalletUnlockBudgetPolicy,
} from '@/core/signingEngine/session/budget/policy';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '@shared/utils/ecdsaKeyFactsInventory';
import { isImplicitNearAccountId } from '@shared/utils/near';
import {
  buildEmailOtpWalletAuthMethodBinding,
  buildNoCurrentWalletAuthMethod,
  buildPasskeyAuthScope,
  buildPasskeyWalletAuthMethodBinding,
  buildSelectedCurrentWalletAuthMethod,
  buildWalletIdentity,
  parseRpId,
  type CurrentWalletAuthMethod,
  type WalletAuthMethodBinding,
} from '@shared/utils/walletCapabilityBindings';
import { collectPasskeyLoginAssertion } from '@/SeamsWeb/operations/authMethods/passkey/loginAssertion';
import {
  collectFreshLocalPasskeyUnlockCredential,
  createLocalUnlockChallengeB64u,
} from '@/SeamsWeb/operations/authMethods/passkey/localUnlock';
import {
  passkeyCredentialIdB64uFromAuthentication,
  passkeyPrfFirstB64uFromCredential,
} from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';

type EmitUnlockEventInput = Omit<CreateUnlockFlowEventInput, 'accountId' | 'flowId'>;

type ResolvedWalletSessionIdentity =
  | {
      kind: 'none';
      walletId: null;
      nearAccountId: null;
      ed25519Record: null;
    }
  | {
      kind: 'wallet_only';
      walletId: WalletId;
      nearAccountId: null;
      ed25519Record: null;
    }
  | {
      kind: 'wallet_with_near_account';
      walletId: WalletId;
      nearAccountId: AccountId;
      ed25519Record: ThresholdEd25519SessionRecord | null;
    };

type ResolvedLoginWalletBinding = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
  ed25519Record: ThresholdEd25519SessionRecord | null;
};

type WalletSessionStatusIdentity =
  | {
      kind: 'wallet_only';
      walletId: WalletId;
      nearAccountId?: never;
    }
  | {
      kind: 'wallet_with_near_account';
      walletId: WalletId;
      nearAccountId: AccountId;
    };

function emitUnlockEvent(
  onEvent: LoginHooksOptions['onEvent'] | undefined,
  nearAccountId: AccountId,
  event: EmitUnlockEventInput,
): void {
  onEvent?.(
    createUnlockFlowEvent({
      flowId: `unlock:${nearAccountId}`,
      accountId: String(nearAccountId),
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
  selection satisfies never;
  return { mode: 'ed25519_and_ecdsa', ed25519: true, ecdsa: true };
}

function walletIdFromUnknown(value: unknown): WalletId | null {
  try {
    const raw = String(value || '').trim();
    if (isImplicitNearAccountId(raw)) return null;
    return toWalletId(raw);
  } catch {
    return null;
  }
}

function resolvedWalletWithNearAccount(args: {
  walletId: WalletId;
  nearAccountId: AccountId;
  ed25519Record: ThresholdEd25519SessionRecord | null;
}): ResolvedWalletSessionIdentity {
  return {
    kind: 'wallet_with_near_account',
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    ed25519Record: args.ed25519Record,
  };
}

function walletOnlySessionIdentity(walletId: WalletId): ResolvedWalletSessionIdentity {
  return {
    kind: 'wallet_only',
    walletId,
    nearAccountId: null,
    ed25519Record: null,
  };
}

function emptyWalletSessionIdentity(): ResolvedWalletSessionIdentity {
  return {
    kind: 'none',
    walletId: null,
    nearAccountId: null,
    ed25519Record: null,
  };
}

function resolveExplicitWalletSessionIdentity(
  rawWalletId: WalletId | string,
): ResolvedWalletSessionIdentity {
  const walletRecord = getStoredThresholdEd25519SessionRecordForWallet(rawWalletId);
  if (walletRecord) {
    return resolvedWalletWithNearAccount({
      walletId: walletRecord.walletId,
      nearAccountId: walletRecord.nearAccountId,
      ed25519Record: walletRecord,
    });
  }

  const walletId = walletIdFromUnknown(rawWalletId);
  return walletId ? walletOnlySessionIdentity(walletId) : emptyWalletSessionIdentity();
}

function resolveLoginWalletBinding(nearAccountId: AccountId): ResolvedLoginWalletBinding {
  const record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  if (record) {
    const recordNearAccountId = toAccountId(String(record.nearAccountId));
    if (String(recordNearAccountId) !== String(nearAccountId)) {
      throw new Error('[login] persisted Ed25519 record nearAccountId mismatch');
    }
    const nearEd25519SigningKeyId = String(record.nearEd25519SigningKeyId || '').trim();
    if (!nearEd25519SigningKeyId) {
      throw new Error('[login] persisted Ed25519 record is missing nearEd25519SigningKeyId');
    }
    return {
      walletId: toWalletId(record.walletId),
      nearAccountId: recordNearAccountId,
      nearEd25519SigningKeyId,
      ed25519Record: record,
    };
  }

  throw new Error('[login] Ed25519 login requires a persisted wallet binding');
}

function buildLoggedOutLoginState(args: {
  walletId: WalletId | null;
  nearAccountId: AccountId | null;
  thresholdEcdsaEthereumAddress: string | null;
  thresholdEcdsaPublicKeyB64u: string | null;
}): LoginState {
  return {
    isLoggedIn: false,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    publicKey: null,
    userData: null,
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    thresholdEcdsaEthereumAddress: args.thresholdEcdsaEthereumAddress,
    thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
  };
}

function buildAnonymousWalletSession(): WalletSession {
  const login = buildLoggedOutLoginState({
    walletId: null,
    nearAccountId: null,
    thresholdEcdsaEthereumAddress: null,
    thresholdEcdsaPublicKeyB64u: null,
  });
  return {
    login,
    signingSession: null,
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    authMethod: null,
    retention: null,
    nonceDiagnostics: null,
  };
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

function selectCurrentWalletAuthMethod(args: {
  authMethods: readonly WalletAuthMethodBinding[];
  authMethod: WalletAuthMethod | null;
}): CurrentWalletAuthMethod {
  if (!args.authMethod) return buildNoCurrentWalletAuthMethod();
  const matches = args.authMethods.filter((binding) => binding.kind === args.authMethod);
  if (matches.length !== 1) return buildNoCurrentWalletAuthMethod();
  return buildSelectedCurrentWalletAuthMethod({ binding: matches[0] });
}

type LoginUnlockAccountSubject =
  | {
      kind: 'near_operational_signer';
      userData: ClientUserData;
      operationalPublicKey: string;
    }
  | {
      kind: 'ecdsa_wallet_only';
      userData: ClientUserData;
      operationalPublicKey: null;
    };

type LoginUnlockAccountPhase = {
  kind: 'login_unlock_account_phase_ready';
  accountSubject: LoginUnlockAccountSubject;
  authenticators: ClientAuthenticatorData[];
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
      kind: 'ed25519_session_policy_passkey_assertion';
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
      runtimeScopeBootstrap: ManagedThresholdRuntimeScopeBootstrap;
    }
  | {
      kind: 'unavailable';
      runtimeScopeBootstrap?: never;
    };

type LoginWarmupEd25519MintPlan =
  | {
      kind: 'not_requested';
      sessionId?: never;
      signingGrantId?: never;
      authorization?: never;
    }
  | {
      kind: 'fresh';
      sessionId?: never;
      signingGrantId?: never;
      authorization?: never;
    }
  | {
      kind: 'ecdsa_authorized';
      sessionId: string;
      signingGrantId?: never;
      authorization?: never;
    }
  | {
      kind: 'session_policy_webauthn';
      sessionId: string;
      signingGrantId: string;
      authorization: Ed25519WalletSessionMintAuthorization;
    };

const THRESHOLD_LOGIN_ED25519_UNSEAL_AUTHORIZATION_DEFAULT_TTL_MS = 60 * 1000;
const THRESHOLD_LOGIN_ED25519_UNSEAL_AUTHORIZATION_MAX_TTL_MS = 5 * 60 * 1000;

function walletUnlockSelectionRequiresEd25519(selection: WalletUnlockSelection): boolean {
  return selection.mode === 'ed25519_only' || selection.mode === 'ed25519_and_ecdsa';
}

function walletUnlockSelectionRequiresEcdsa(selection: WalletUnlockSelection): boolean {
  return selection.mode === 'ecdsa_only' || selection.mode === 'ed25519_and_ecdsa';
}

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
  if (args.warmupPlan.signersToWarm.includes('ed25519') && !args.warmupPlan.ed25519DependsOnEcdsa) {
    return { kind: 'ed25519_session_policy_passkey_assertion' };
  }
  if (args.requiresLocalPasskeyUnlock) {
    return { kind: 'local_unlock_passkey_assertion_after_ecdsa_context' };
  }
  return { kind: 'no_passkey_credential_required' };
}

type ResolveThresholdLoginWarmupPhaseInputArgs = {
  context: LoginWebContext;
  signerSlot: number;
  selection: WalletUnlockSelection;
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
  keyFactsInventoryAuthority: LoginEcdsaKeyFactsInventoryAuthority | null;
  routeAuthorization: LoginWarmupRouteAuthorization;
};

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
  const wantsEd25519Warmup =
    args.selection.mode === 'ed25519_only' || args.selection.mode === 'ed25519_and_ecdsa';
  const wantsEcdsaWarmup =
    configuredEcdsaTargets.length > 0 &&
    (args.selection.mode === 'ecdsa_only' || args.selection.mode === 'ed25519_and_ecdsa');
  return {
    kind: 'threshold_login_warmup_phase_input',
    signerSlot: args.signerSlot,
    selection: args.selection,
    relayerUrl,
    rpId: String(args.context.signingEngine.getRpId() || '').trim(),
    configuredEcdsaTargets,
    selectedEcdsaTargets: wantsEcdsaWarmup ? configuredEcdsaTargets : [],
    wantsEd25519Warmup,
    wantsEcdsaWarmup,
    keyFactsInventoryAuthority: resolveLoginEcdsaKeyFactsInventoryAuthority({
      request: args.keyFactsInventoryRequest,
      routeAuthorization: args.routeAuthorization,
    }),
    routeAuthorization: args.routeAuthorization,
  };
}

async function assertPasskeyUnlockRuntimePostconditions(args: {
  context: LoginWebContext;
  walletBinding: ResolvedLoginWalletBinding;
  signersWarmed: readonly ('ed25519' | 'ecdsa')[];
}): Promise<void> {
  if (args.signersWarmed.includes('ed25519')) {
    const record = getStoredThresholdEd25519SessionRecordForWallet(args.walletBinding.walletId);
    const signingSessionStatus = await args.context.signingEngine
      .getWarmThresholdEd25519SessionStatus(args.walletBinding.nearAccountId)
      .catch(() => null);
    const authorization = parseWarmEd25519SigningSessionAuthorizationFromRecord({
      record,
      walletId: String(args.walletBinding.walletId),
      nearAccountId: args.walletBinding.nearAccountId,
      nearEd25519SigningKeyId: args.walletBinding.nearEd25519SigningKeyId,
      authMethod: 'passkey',
      signingSessionStatus,
    });
    if (!authorization.ok) {
      throw new Error(
        `[login] Ed25519 warm-session authorization postcondition failed: ${authorization.reason}`,
      );
    }
  }

  const requiredTargets = [
    ...(args.signersWarmed.includes('ecdsa')
      ? listConfiguredThresholdEcdsaPublicationTargets(args.context.configs.network.chains).map(
          (target) => ({ curve: 'ecdsa' as const, chainTarget: target.chainTarget }),
        )
      : []),
  ];
  if (requiredTargets.length === 0) return;
  await assertWalletRuntimePostconditions({
    source: 'wallet_unlock',
    walletId: String(args.walletBinding.walletId),
    authMethod: 'passkey',
    requiredTargets,
    readPersistedAvailableSigningLanes: async (input) =>
      await args.context.signingEngine.readPersistedAvailableSigningLanes(input),
  });
}

function normalizeLoginUnlockAccountSubject(args: {
  userData: ClientUserData;
  selection: WalletUnlockSelection;
  nearAccountId: AccountId;
}): LoginUnlockAccountSubject {
  const operationalPublicKey =
    typeof args.userData.operationalPublicKey === 'string'
      ? args.userData.operationalPublicKey.trim()
      : '';
  if (operationalPublicKey) {
    return {
      kind: 'near_operational_signer',
      userData: args.userData,
      operationalPublicKey,
    };
  }
  if (walletUnlockSelectionRequiresEd25519(args.selection)) {
    throw new Error(
      `No NEAR operational key found for ${args.nearAccountId}. Please register an account.`,
    );
  }
  return {
    kind: 'ecdsa_wallet_only',
    userData: args.userData,
    operationalPublicKey: null,
  };
}

async function readLoginUnlockAccountPhase(args: {
  signingEngine: UserAccountLookupSurface;
  nearAccountId: AccountId;
  signerSlotHint: number | null;
  selection: WalletUnlockSelection;
  onEvent?: LoginHooksOptions['onEvent'];
}): Promise<LoginUnlockAccountPhase> {
  emitUnlockEvent(args.onEvent, args.nearAccountId, {
    phase: UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED,
    status: 'running',
    authMethod: 'passkey',
  });

  const hintUserPromise: Promise<ClientUserData | null> =
    args.signerSlotHint !== null
      ? args.signingEngine
          .getUserBySignerSlot(args.nearAccountId, args.signerSlotHint)
          .catch(() => null)
      : Promise.resolve(null);

  const [hintUser, lastUser, latestByAccount, authenticators] = await Promise.all([
    hintUserPromise,
    args.signingEngine.getLastUser().catch(() => null),
    getNearAccountProjection(IndexedDBManager, args.nearAccountId).catch(() => null),
    args.signingEngine.nearAuthenticatorsByAccount(args.nearAccountId).catch(() => []),
  ]);

  if (authenticators.length === 0) {
    throw new Error(
      `No authenticators found for account ${args.nearAccountId}. Please register an account.`,
    );
  }

  let userData: ClientUserData | null = null;
  if (hintUser && hintUser.nearAccountId === args.nearAccountId) {
    userData = hintUser;
  } else if (latestByAccount && latestByAccount.nearAccountId === args.nearAccountId) {
    userData = latestByAccount;
  } else if (lastUser && lastUser.nearAccountId === args.nearAccountId) {
    userData = lastUser;
  } else {
    userData = await args.signingEngine
      .getUserBySignerSlot(args.nearAccountId, 1)
      .catch(() => null);
  }

  if (!userData) {
    throw new Error(
      `User data not found for ${args.nearAccountId} in IndexedDB. Please register an account.`,
    );
  }
  const accountSubject = normalizeLoginUnlockAccountSubject({
    userData,
    selection: args.selection,
    nearAccountId: args.nearAccountId,
  });

  emitUnlockEvent(args.onEvent, args.nearAccountId, {
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

  const baseSignerSlot =
    args.signerSlotHint ??
    (Number.isFinite(userData.signerSlot) && userData.signerSlot >= 1 ? userData.signerSlot : 1);
  const localUnlockAuthMethod = userData.authMethod || SIGNER_AUTH_METHODS.passkey;
  return {
    kind: 'login_unlock_account_phase_ready',
    accountSubject,
    authenticators,
    baseSignerSlot,
    localUnlockAuthMethod,
    requiresLocalPasskeyUnlock: localUnlockAuthMethod === SIGNER_AUTH_METHODS.passkey,
  };
}

/**
 * Core login function (passkey identity + relay-issued sessions).
 *
 * Responsibilities:
 * - Select the active account + signer slot (last-user pointer).
 * - Optionally mint a relayer app session (JWT/cookie) via session exchange.
 *
 * Note: signing flows still perform their own UserConfirm/WebAuthn prompting as needed.
 */
export async function unlock(
  context: LoginWebContext,
  nearAccountId: AccountId,
  options?: LoginHooksOptions,
): Promise<LoginAndCreateSessionResult> {
  const { onEvent, onError, afterCall } = options || {};
  const { signingEngine } = context;
  let loginCredential: WebAuthnAuthenticationCredential | undefined;
  let unlockWalletBinding: ResolvedLoginWalletBinding | null = null;

  // All unlock branches emit the same ordered event stream for caller progress UIs.
  emitUnlockEvent(onEvent, nearAccountId, {
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
        nearAccountId,
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
    const walletUnlockSelection = resolveLoginWalletUnlockSelection(options?.unlockSelection);
    const accountPhase = await readLoginUnlockAccountPhase({
      signingEngine,
      nearAccountId,
      signerSlotHint,
      selection: walletUnlockSelection,
      onEvent,
    });
    const { accountSubject, authenticators, baseSignerSlot, requiresLocalPasskeyUnlock } =
      accountPhase;
    const walletBinding = resolveLoginWalletBinding(nearAccountId);
    unlockWalletBinding = walletBinding;

    // Shared prompt wrapper used by local unlock, app-session exchange, and inventory repair.
    const collectLocalPasskeyCredentialForChallenge = async (args: {
      challengeB64u: string;
      saveAsLoginCredential: boolean;
    }): Promise<WebAuthnAuthenticationCredential> => {
      const credential = await collectPasskeyLoginAssertion({
        signingEngine,
        subjectId: String(nearAccountId),
        challengeB64u: args.challengeB64u,
        authenticators,
        onPromptStarted: () => {
          emitUnlockEvent(onEvent, nearAccountId, {
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
          emitUnlockEvent(onEvent, nearAccountId, {
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
        configuredRemainingUses ?? defaultRemainingUses ?? DEV_DEFAULT_UNLOCK_REMAINING_USES;
      const ttlMs =
        typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
      const unlockBudgetPolicy = resolveWalletUnlockBudgetPolicyFromRequestedUses({
        requestedRemainingUses,
        ...(configuredRemainingUses == null && defaultRemainingUses == null
          ? {}
          : { policyVersion: 'sdk_unlock_config_v1' }),
      });
      return {
        ttlMs: Math.max(0, ttlMs),
        unlockBudgetPolicy,
      };
    })();

    // Updated by warmup branches, then copied into the public result.
    let signingSession: LoginAndCreateSessionResult['signingSession'] | undefined;
    // Warm sessions are enabled when policy budgets are non-zero.
    const shouldWarmThresholdSigningSession =
      signingSessionPolicy.ttlMs > 0 && signingSessionPolicy.unlockBudgetPolicy != null;
    const requireThresholdWarmup = shouldWarmThresholdSigningSession;
    const session = options?.session;
    const wantsServerSession = session !== undefined;

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
      emitUnlockEvent(onEvent, nearAccountId, {
        phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
        status: 'running',
        authMethod: loginCredential ? 'passkey' : 'warm_session',
      });

      // Ed25519 warmup needs stored NEAR threshold key material; ECDSA-only unlock can skip it.
      const thresholdKeyMaterial = warmupInput.wantsEd25519Warmup
        ? await getNearThresholdKeyMaterial(
            {
              clientDB: IndexedDBManager,
              keyMaterialStore: IndexedDBManager,
            },
            nearAccountId,
            warmupInput.signerSlot,
          ).catch(() => null)
        : null;
      if (warmupInput.wantsEd25519Warmup && !thresholdKeyMaterial) {
        throw new Error(
          `[login] threshold warm-up requires threshold key material for ${nearAccountId} signer slot ${warmupInput.signerSlot}`,
        );
      }

      const participantIds =
        thresholdKeyMaterial?.participants.map((participant) => participant.id) || [];
      const managedRuntimeScopeBootstrap = resolveManagedThresholdRuntimeScopeBootstrap(context);
      let volatileWarmMaterialCleared = false;
      const clearVolatileWarmMaterialForUnlock = async (): Promise<void> => {
        if (volatileWarmMaterialCleared) return;
        volatileWarmMaterialCleared = true;
        await signingEngine.clearVolatileWarmSigningMaterial(walletBinding.walletId);
      };

      // Resolve local ECDSA key facts before planning; authenticated inventory can repair gaps.
      const storedCanonicalEcdsaContext = await resolveCanonicalThresholdEcdsaWarmSessionContext(
        context,
        signingEngine,
        walletBinding.walletId,
        {
          keyFactsInventoryAuthority: warmupInput.keyFactsInventoryAuthority,
          keyFactsInventoryRequested: Boolean(options?.ecdsaKeyFactsInventory),
          relayerUrl: warmupInput.relayerUrl,
          rpId: warmupInput.rpId,
          collectWebAuthnInventoryCredential: async (challengeB64u) =>
            await collectLocalPasskeyCredentialForChallenge({
              challengeB64u,
              saveAsLoginCredential: true,
            }),
        },
      );
      const ecdsaTargetCompletion = buildSharedKeyTargetCompletion({
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
        : warmupPlan.ed25519DependsOnEcdsa
          ? {
              kind: 'ecdsa_authorized',
              sessionId: plannedEd25519SessionId,
            }
          : {
              kind: 'fresh',
            };
      switch (warmupPasskeyCredentialPlan.kind) {
        case 'existing_passkey_credential':
        case 'app_session_authorized_warmup':
        case 'no_passkey_credential_required':
          break;
        case 'ed25519_session_policy_passkey_assertion': {
          const routerAbNormalSigning = createRouterAbNormalSigningPolicy(context.configs);
          const plannedEd25519Policy = await buildEd25519SessionPolicy({
            walletId: String(walletBinding.walletId),
            nearAccountId,
            nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
            rpId: warmupInput.rpId,
            relayerKeyId: thresholdKeyMaterial?.relayerKeyId || '',
            ...(storedCanonicalEcdsaContext.runtimePolicyScope
              ? { runtimePolicyScope: storedCanonicalEcdsaContext.runtimePolicyScope }
              : {}),
            routerAbNormalSigning,
            participantIds,
            thresholdSessionId: plannedEd25519SessionId,
            ttlMs: signingSessionPolicy.ttlMs,
            remainingUses: resolveSigningBudgetPolicyRemainingUses(
              signingSessionPolicy.unlockBudgetPolicy ||
                (() => {
                  throw new Error('[login] unlock warm-up requires a wallet unlock budget policy');
                })(),
            ),
          });
          loginCredential = await collectLocalPasskeyCredentialForChallenge({
            challengeB64u: plannedEd25519Policy.sessionPolicyDigest32,
            saveAsLoginCredential: true,
          });
          ed25519MintPlan = {
            kind: 'session_policy_webauthn',
            sessionId: plannedEd25519SessionId,
            signingGrantId: plannedEd25519Policy.policy.signingGrantId,
            authorization: {
              kind: 'threshold_session_policy_webauthn',
              policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
                credential: loginCredential,
                rpId: warmupInput.rpId,
              }),
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
        walletBinding,
        nearAccountId,
        signerSlot: warmupInput.signerSlot,
        relayerUrl: warmupInput.relayerUrl,
        relayerKeyId: thresholdKeyMaterial?.relayerKeyId || '',
        participantIds,
        ttlMs: signingSessionPolicy.ttlMs,
        unlockBudgetPolicy:
          signingSessionPolicy.unlockBudgetPolicy ||
          (() => {
            throw new Error('[login] unlock warm-up requires a wallet unlock budget policy');
          })(),
        ecdsaContextResolution: warmupPlan.ecdsaContextResolution,
        credentialState,
        runtimeScopeBootstrapState,
        signersToWarm: warmupPlan.signersToWarm,
        ed25519DependsOnEcdsa: warmupPlan.ed25519DependsOnEcdsa,
        ecdsaDependsOnEd25519: warmupPlan.ecdsaDependsOnEd25519,
        ed25519MintPlan,
        routeAuthorization: warmupInput.routeAuthorization,
      });

      // Ed25519 status is read from the engine; ECDSA-only unlock derives it from bootstraps.
      if (warmupPlan.signersToWarm.includes('ed25519')) {
        const warmStatus = await signingEngine
          .getWarmThresholdEd25519SessionStatus(nearAccountId)
          .catch(() => null);
        signingSession = warmStatus || signingSession;
      } else {
        signingSession =
          ecdsaOnlySigningSessionStatus(warmupResult.ecdsaBootstraps) || signingSession;
      }
      const activeSigningSession = requireActiveWarmSession('threshold warm-up');

      // Emit lane-specific events after active-session validation succeeds.
      if (warmupPlan.signersToWarm.includes('ed25519')) {
        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY,
          status: 'succeeded',
          authMethod: 'warm_session',
        });
      }
      if (warmupPlan.signersToWarm.includes('ecdsa')) {
        emitUnlockEvent(onEvent, nearAccountId, {
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
    const persistSuccessfulLoginState = async (signerSlot: number): Promise<void> => {
      await signingEngine.setLastUser(walletBinding.walletId, signerSlot).catch(() => undefined);
      await signingEngine.updateLastLogin(walletBinding.walletId).catch(() => undefined);
    };

    // Nonce recovery is best-effort; stale lane leases should not fail login.
    const recoverNonceLanesAfterUnlock = async (): Promise<void> => {
      await signingEngine
        .getNonceCoordinator()
        .recoverDurableLeases({ walletId: walletBinding.walletId })
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
        let exchangeInput: SessionExchangeInput;

        // Build the exact proof the relayer expects for this exchange mode.
        if (exchange.type === 'oidc_jwt') {
          // OIDC exchange uses the caller-provided token directly.
          exchangeInput = {
            type: 'oidc_jwt',
            token: exchange.token,
          };
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
            status: 'running',
          });
        } else {
          // Passkey exchange first asks the relayer for a challenge tied to this account and RP.
          const rpId = String(signingEngine.getRpId() || '').trim();
          if (!rpId) {
            throw new Error('Missing rpId for passkey_assertion session exchange');
          }

          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_CHALLENGE_STARTED,
            status: 'running',
            authMethod: 'passkey',
          });

          const unlockChallengeResp = await fetch(
            joinNormalizedUrl(relayUrl, '/wallet/unlock/challenge'),
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                unlockBackend: 'passkey',
                userId: String(nearAccountId),
                rpId,
              }),
            },
          );
          const unlockChallengeJsonUnknown: unknown = await unlockChallengeResp
            .json()
            .catch(() => ({}));
          const unlockChallengeJson = isObject(unlockChallengeJsonUnknown)
            ? unlockChallengeJsonUnknown
            : {};
          const unlockChallengeOk = unlockChallengeJson.ok === true;
          const unlockChallengeMessage =
            typeof unlockChallengeJson.message === 'string' ? unlockChallengeJson.message : '';
          if (!unlockChallengeResp.ok || !unlockChallengeOk) {
            throw new Error(
              unlockChallengeMessage ||
                `wallet/unlock/challenge failed (HTTP ${unlockChallengeResp.status})`,
            );
          }

          const challengeId = String(unlockChallengeJson.challengeId || '').trim();
          const challengeB64u = String(unlockChallengeJson.challengeB64u || '').trim();
          if (!challengeId || !challengeB64u) {
            throw new Error('wallet/unlock/challenge returned invalid challenge');
          }

          // Use relayer-provided credential IDs to narrow the browser passkey prompt.
          const credentialIds = Array.isArray(
            (unlockChallengeJson as { credentialIds?: unknown }).credentialIds,
          )
            ? (unlockChallengeJson as { credentialIds: unknown[] }).credentialIds
                .map((id) => String(id || '').trim())
                .filter((id) => id.length > 0)
            : [];
          const allowCredentials = credentialIds.map((id) => ({
            id,
            type: 'public-key' as const,
            transports: [],
          }));

          // This assertion both proves unlock and becomes reusable local credential material.
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED,
            status: 'waiting_for_user',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'show',
            },
          });
          const webauthnAuthentication = await signingEngine.getAuthenticationCredentialsSerialized(
            {
              subjectId: String(nearAccountId),
              challengeB64u,
              allowCredentials,
              includeSecondPrfOutput: false,
            },
          );
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED,
            status: 'succeeded',
            authMethod: 'passkey',
            interaction: {
              kind: 'passkey_assert',
              overlay: 'hide',
            },
          });
          loginCredential = webauthnAuthentication;

          // The relayer validates the assertion origin when the caller supplies one.
          const expectedOrigin = String(
            exchange.expectedOrigin ??
              exchange.expected_origin ??
              (typeof window !== 'undefined' ? window.location.origin : ''),
          ).trim();

          exchangeInput = {
            type: 'passkey_assertion',
            challengeId,
            webauthn_authentication: webauthnAuthentication,
            ...(expectedOrigin ? { expected_origin: expectedOrigin } : {}),
          };
          emitUnlockEvent(onEvent, nearAccountId, {
            phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
            status: 'running',
            authMethod: 'passkey',
          });
        }

        // Exchange the prepared proof for the configured app-session form.
        const exchanged = await exchangeSession(
          relayUrl,
          exchangePath,
          session.kind,
          exchangeInput,
        );
        if (!exchanged.success) {
          throw new Error(exchanged.error || 'Session exchange failed');
        }

        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
          authMethod: loginCredential ? 'passkey' : undefined,
        });

        // App-session auth can authorize warmup and key-facts inventory in the same unlock.
        if (requireThresholdWarmup) {
          const warmupPhase = await warmThresholdSigningSessions(
            resolveThresholdLoginWarmupPhaseInput({
              context,
              signerSlot: baseSignerSlot,
              selection: walletUnlockSelection,
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
            walletBinding,
            signersWarmed: warmupPhase.signersWarmed,
          });
        }

        // Success is durable only after account state and nonce leases are updated.
        await persistSuccessfulLoginState(baseSignerSlot);
        await recoverNonceLanesAfterUnlock();

        emitUnlockEvent(onEvent, nearAccountId, {
          phase: UnlockEventPhase.STEP_06_SESSION_READY,
          status: 'succeeded',
          authMethod: loginCredential ? 'passkey' : undefined,
        });

        // Shape the public result once all optional warmup requirements have passed.
        const loginResult: LoginResult = {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          operationalPublicKey: accountSubject.operationalPublicKey,
          nearAccountId,
          ...(exchanged.jwt ? { jwt: exchanged.jwt } : {}),
        };

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
          nearAccountId,
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

    // Local-only flow: skip app-session exchange and collect/warm local capability state.
    emitUnlockEvent(onEvent, nearAccountId, {
      phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SKIPPED,
      status: 'skipped',
    });

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

    // Warm threshold sessions without app-session route authorization.
    if (requireThresholdWarmup) {
      const warmupPhase = await warmThresholdSigningSessions(
        resolveThresholdLoginWarmupPhaseInput({
          context,
          signerSlot: baseSignerSlot,
          selection: walletUnlockSelection,
          keyFactsInventoryRequest: options?.ecdsaKeyFactsInventory,
          routeAuthorization: resolveLoginWarmupRouteAuthorization({
            appSessionJwt: '',
            useAppSessionCookie: false,
          }),
        }),
      );
      signingSession = warmupPhase.signingSession;
      await assertPasskeyUnlockRuntimePostconditions({
        context,
        walletBinding,
        signersWarmed: warmupPhase.signersWarmed,
      });
    }

    await persistSuccessfulLoginState(baseSignerSlot);
    await recoverNonceLanesAfterUnlock();

    // Return the same public result shape as the server-session branch.
    const loginResult: LoginAndCreateSessionResult = requireThresholdWarmup
      ? {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          operationalPublicKey: accountSubject.operationalPublicKey,
          nearAccountId,
          ...requireThresholdWarmLoginBundle('login'),
        }
      : {
          success: true,
          loggedInNearAccountId: String(nearAccountId),
          operationalPublicKey: accountSubject.operationalPublicKey,
          nearAccountId,
          ...(signingSession ? { signingSession } : {}),
        };

    emitUnlockEvent(onEvent, nearAccountId, {
      phase: UnlockEventPhase.STEP_06_SESSION_READY,
      status: 'succeeded',
      authMethod: loginCredential ? 'passkey' : undefined,
    });

    return await finalizeLoginSuccess({
      nearAccountId,
      loginResult,
      onEvent,
      afterCall,
    });
  } catch (err: unknown) {
    console.warn('[login] unlock failed before active session commit', {
      nearAccountId,
      message:
        err && typeof err === 'object' && 'message' in err
          ? String((err as { message?: unknown }).message || '')
          : String(err || ''),
    });
    await clearFailedUnlockSessionState({
      context,
      nearAccountId,
      walletId: unlockWalletBinding?.walletId || null,
    });
    // Normalize every thrown value through the public login error hooks/events.
    const errorMessage = getUserFriendlyErrorMessage(err, 'login') || 'Login failed';
    return await finalizeLoginError({
      nearAccountId,
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
  nearAccountId: AccountId;
  walletId: WalletId | null;
}): Promise<void> {
  await IndexedDBManager.clearLastProfileSelection().catch(() => undefined);
  try {
    args.context.signingEngine.getNonceCoordinator().clearAll();
  } catch {}
  try {
    if (args.walletId) {
      await args.context.signingEngine.clearVolatileWarmSigningMaterial(args.walletId);
    }
  } catch {}
  try {
    clearStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  } catch {}
}

async function finalizeLoginSuccess(args: {
  nearAccountId: AccountId;
  loginResult: LoginResult;
  onEvent?: LoginHooksOptions['onEvent'];
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
}): Promise<LoginAndCreateSessionResult> {
  const { nearAccountId, loginResult, onEvent, afterCall } = args;
  emitUnlockEvent(onEvent, nearAccountId, {
    phase: UnlockEventPhase.STEP_07_COMPLETED,
    status: 'succeeded',
    data: {
      operationalPublicKey: loginResult.operationalPublicKey ?? '',
    },
  });
  await afterCall?.(true, loginResult);
  return loginResult;
}

async function finalizeLoginError(args: {
  nearAccountId: AccountId;
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
    nearAccountId,
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

  emitUnlockEvent(onEvent, nearAccountId, {
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

type ThresholdLoginWarmEcdsaContextResolution =
  | {
      kind: 'pre_resolved';
      context: CanonicalThresholdEcdsaWarmSessionContext;
      initialContext?: never;
      resolveAfterEd25519?: never;
    }
  | {
      kind: 'first_bootstrap_missing_shared_key';
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
  sharedKeyTargetCompletion: SharedKeyTargetCompletion;
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
} {
  const bootstrap = args.bootstrap;
  const keyRef = bootstrap.thresholdEcdsaKeyRef;
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!keyHandle) {
    throw new Error('[login] threshold ECDSA bootstrap missing keyHandle');
  }
  const canonicalKeyHandle = toEvmFamilyEcdsaKeyHandle(keyHandle);
  const runtimePolicyScope =
    bootstrap.session.runtimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(
      String(bootstrap.session.jwt || keyRef.walletSessionJwt || '').trim(),
    );
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record: {
      keyHandle: canonicalKeyHandle,
      runtimePolicyScope,
    },
  });
  const ecdsaThresholdKeyId = resolveThresholdEcdsaKeyIdFromRecord({
    record: { ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId },
  });
  const walletKeyId = deriveEvmFamilyWalletKeyIdFromSigningRootFacts({
    walletId: args.walletId,
    ecdsaThresholdKeyId,
    signingRootId: String(signingRootBinding.signingRootId),
    signingRootVersion: String(signingRootBinding.signingRootVersion),
    participantIds: keyRef.participantIds || bootstrap.keygen.participantIds,
    thresholdOwnerAddress: String(args.thresholdOwnerAddress || '').trim(),
  });
  return {
    keyHandle,
    key: buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId: args.walletId,
      walletKeyId,
      ecdsaThresholdKeyId,
      signingRootId: String(signingRootBinding.signingRootId),
      signingRootVersion: String(signingRootBinding.signingRootVersion),
      participantIds: keyRef.participantIds || bootstrap.keygen.participantIds,
      thresholdOwnerAddress: String(args.thresholdOwnerAddress || '').trim(),
    }),
  };
}

type ManagedThresholdRuntimeScopeBootstrap = {
  environmentId: string;
  publishableKey: string;
};

type ThresholdLoginWarmSigner = 'ed25519' | 'ecdsa';

type ThresholdLoginWarmupTask = {
  signer: ThresholdLoginWarmSigner;
  dependencies: ThresholdLoginWarmSigner[];
  run: () => Promise<void>;
};

type ThresholdLoginWarmEd25519State = {
  sessionId: string;
  signingGrantId: string;
  jwt: string;
  ecdsaHssPasskeyPrfFirstB64u: string;
};

type ThresholdLoginWarmEcdsaBootstrapRouteAuth = WalletSessionReconnectEcdsaBootstrapRouteAuth;

type ThresholdLoginWarmEcdsaBootstrapIdentity = {
  routeAuth?: ThresholdLoginWarmEcdsaBootstrapRouteAuth;
};

function isWalletSessionReconnectEcdsaRouteAuth(
  auth: ThresholdLoginWarmEcdsaBootstrapRouteAuth | undefined,
): auth is WalletSessionReconnectEcdsaBootstrapRouteAuth {
  return auth?.kind === 'app_session' || auth?.kind === 'wallet_session';
}

type ThresholdLoginWarmupResult = {
  ecdsaBootstraps: ThresholdEcdsaSessionBootstrapResult[];
};

type ThresholdEcdsaAuthorizedEd25519Mint = {
  thresholdEcdsaSessionJwt: string;
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
  signingGrantId: string;
};

function passkeyCredentialIdB64uFromEcdsaRecord(record: ThresholdEcdsaSessionRecord): string {
  try {
    const readyRecord = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
    return readyRecord.authMethod.kind === 'passkey'
      ? String(readyRecord.authMethod.credentialIdB64u || '').trim()
      : '';
  } catch {
    return '';
  }
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

async function runThresholdLoginWarmupTasks(tasks: ThresholdLoginWarmupTask[]): Promise<void> {
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
    await Promise.all(
      ready.map(async (task) => {
        await task.run();
        completed.add(task.signer);
        pendingBySigner.delete(task.signer);
      }),
    );
  }
}

function resolveThresholdLoginWarmEcdsaBootstrapIdentity(args: {
  ed25519State: ThresholdLoginWarmEd25519State;
  credentialState: LoginWarmupCredentialState;
  routeAuthorization: LoginWarmupRouteAuthorization;
}): ThresholdLoginWarmEcdsaBootstrapIdentity {
  const walletSessionJwt = String(args.ed25519State.jwt || '').trim();
  switch (args.routeAuthorization.kind) {
    case 'app_session_jwt':
      return {
        routeAuth: { kind: 'app_session', jwt: args.routeAuthorization.appSessionJwt },
      };
    case 'app_session_cookie':
      if (walletSessionJwt) {
        return {
          routeAuth: { kind: 'wallet_session', jwt: walletSessionJwt },
        };
      }
      throw new Error('[login] threshold ECDSA warm-up requires bearer route authorization');
    case 'none':
      break;
    default:
      return assertNeverLoginState(args.routeAuthorization);
  }
  if (walletSessionJwt) {
    return {
      routeAuth: { kind: 'wallet_session', jwt: walletSessionJwt },
    };
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

function resolveThresholdLoginWarmEcdsaPrfFirstB64u(args: {
  ed25519State: ThresholdLoginWarmEd25519State;
  credentialState: LoginWarmupCredentialState;
}): string {
  if (args.credentialState.kind === 'available') {
    const prfFirstB64u = passkeyPrfFirstB64uFromCredential(args.credentialState.credential);
    if (prfFirstB64u) return prfFirstB64u;
  }
  const fromEd25519Session = String(args.ed25519State.ecdsaHssPasskeyPrfFirstB64u || '').trim();
  if (fromEd25519Session) {
    return fromEd25519Session;
  }
  throw new Error(
    '[login] threshold ECDSA warm-up requires passkey PRF.first or primed Ed25519 session material',
  );
}

function ecdsaOnlySigningSessionStatus(
  bootstraps: readonly ThresholdEcdsaSessionBootstrapResult[],
): SigningSessionStatus | null {
  const session = bootstraps[0]?.session;
  const sessionId = String(session?.sessionId || '').trim();
  if (!session || !sessionId) return null;
  return {
    sessionId,
    status: 'active',
    authMethod: 'passkey',
    remainingUses: session.remainingUses,
    expiresAtMs: session.expiresAtMs,
    ...(session.projectionVersion ? { projectionVersion: session.projectionVersion } : {}),
    createdAtMs: Date.now(),
  };
}

function buildLoginEd25519WalletSessionMintAuthorization(args: {
  routeAuthorization: LoginWarmupRouteAuthorization;
  credentialState: LoginWarmupCredentialState;
  rpId: string;
  thresholdEcdsaSessionJwt: string;
  localPrfFirstB64u: string;
}): Ed25519WalletSessionMintAuthorization | undefined {
  const thresholdEcdsaSessionJwt = args.thresholdEcdsaSessionJwt.trim();
  const localPrfFirstB64u = args.localPrfFirstB64u.trim();
  if (thresholdEcdsaSessionJwt && localPrfFirstB64u) {
    return {
      kind: 'threshold_ecdsa_session_jwt',
      thresholdEcdsaSessionJwt,
      localSecretSource: buildThresholdEd25519ProvidedPrfSecretSource({
        prfFirstB64u: localPrfFirstB64u,
      }),
    };
  }
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

function thresholdLoginEd25519UnsealAuthorizationExpiresAtMs(args: {
  recordExpiresAtMs: number;
  authorizationExpiresAtMs: number;
}): number {
  const nowMs = Date.now();
  return Math.min(
    args.recordExpiresAtMs,
    args.authorizationExpiresAtMs,
    nowMs + THRESHOLD_LOGIN_ED25519_UNSEAL_AUTHORIZATION_DEFAULT_TTL_MS,
    nowMs + THRESHOLD_LOGIN_ED25519_UNSEAL_AUTHORIZATION_MAX_TTL_MS,
  );
}

async function installThresholdLoginEd25519WarmSessionUnsealAuthorization(args: {
  signingEngine: LoginWarmSigningSurface;
  credential: WebAuthnAuthenticationCredential;
  nearAccountId: AccountId;
  signingGrantId: string;
  thresholdSessionId: string;
}): Promise<void> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!thresholdSessionId || !nearAccountId || !signingGrantId) {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_missing_identity',
      nearAccountId,
      signingGrantId,
      thresholdSessionId,
    });
    return;
  }
  const record = await resolveThresholdLoginEd25519WarmSessionUnsealInstallRecord({
    nearAccountId,
    signingGrantId,
    thresholdSessionId,
  });
  const state = classifyRouterAbEd25519PersistedSigningRecord(record);
  if (state.kind !== 'restore_available') {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_not_restore_available',
      nearAccountId,
      thresholdSessionId,
      state: state.kind,
      reason: 'reason' in state ? String(state.reason || '') : '',
      hasRecord: Boolean(record),
      hasSealedWorkerMaterial: Boolean(
        record?.sealedWorkerMaterialRef || record?.sealedWorkerMaterialB64u,
      ),
      hasMaterialBindingDigest: Boolean(record?.ed25519WorkerMaterialBindingDigest),
      hasClientVerifier: Boolean(record?.clientVerifyingShareB64u),
      hasSigningGrantId: Boolean(record?.signingGrantId),
    });
    return;
  }
  if (String(state.record.nearAccountId || '').trim() !== nearAccountId) {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_account_mismatch',
      nearAccountId,
      thresholdSessionId,
      recordAccountId: String(state.record.nearAccountId || '').trim(),
    });
    return;
  }
  const resolvedThresholdSessionId = String(state.record.thresholdSessionId || '').trim();
  if (resolvedThresholdSessionId !== thresholdSessionId) {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_resolved_session_mismatch',
      nearAccountId,
      thresholdSessionId,
      resolvedThresholdSessionId,
    });
    return;
  }
  const restoreAuthorization =
    await resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential({
      ctx: args.signingEngine,
      record: state.record,
      credential: args.credential,
    });
  if (restoreAuthorization.kind !== 'unseal_authorization_available') {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_unseal_authorization_unavailable',
      nearAccountId,
      thresholdSessionId,
    });
    return;
  }
  const materialBindingDigest = String(
    state.record.ed25519WorkerMaterialBindingDigest || '',
  ).trim();
  const recordSigningGrantId = String(state.record.signingGrantId || '').trim();
  const expiresAtMs = Math.floor(Number(state.record.expiresAtMs) || 0);
  if (
    !materialBindingDigest ||
    recordSigningGrantId !== signingGrantId ||
    expiresAtMs <= Date.now()
  ) {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_invalid_record_scope',
      nearAccountId,
      thresholdSessionId,
      hasMaterialBindingDigest: Boolean(materialBindingDigest),
      hasSigningGrantId: Boolean(recordSigningGrantId),
      expiresAtMs,
    });
    return;
  }
  const authorizationExpiresAtMs = Math.floor(
    Number(restoreAuthorization.unsealAuthorization.expiresAtMs) || 0,
  );
  if (authorizationExpiresAtMs <= Date.now()) {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_expired_authorization',
      nearAccountId,
      thresholdSessionId,
      authorizationExpiresAtMs,
    });
    return;
  }
  await args.signingEngine.putWarmSessionEd25519UnsealAuthorization({
    sessionId: resolvedThresholdSessionId,
    signingGrantId: recordSigningGrantId,
    walletId: state.record.walletId,
    authMethod: 'passkey',
    materialBindingDigest,
    authorization: restoreAuthorization.unsealAuthorization,
    expiresAtMs: thresholdLoginEd25519UnsealAuthorizationExpiresAtMs({
      recordExpiresAtMs: expiresAtMs,
      authorizationExpiresAtMs,
    }),
    remainingUses: 1,
  });
  logThresholdLoginEd25519UnsealInstallOutcome({
    outcome: 'installed',
    nearAccountId,
    thresholdSessionId: resolvedThresholdSessionId,
  });
}

function ignoreThresholdLoginEd25519HydrationError(): null {
  return null;
}

async function resolveThresholdLoginEd25519WarmSessionUnsealInstallRecord(args: {
  nearAccountId: string;
  signingGrantId: string;
  thresholdSessionId: string;
}): Promise<ThresholdEd25519SessionRecord | null> {
  const signingGrantId = String(args.signingGrantId || '').trim();
  const initialRecord = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
    args.thresholdSessionId,
  );
  const hydrated =
    initialRecord &&
    (await hydrateCurrentEd25519SessionFromDurableSealedWorkerMaterial(initialRecord).catch(
      ignoreThresholdLoginEd25519HydrationError,
    ));
  const volatileRecord = hydrated?.kind === 'hydrated' ? hydrated.record : initialRecord;
  if (
    classifyRouterAbEd25519PersistedSigningRecord(volatileRecord).kind === 'restore_available' &&
    String(volatileRecord?.signingGrantId || '').trim() === signingGrantId
  ) {
    return volatileRecord;
  }
  const exactHydrated = await hydrateExactEd25519SessionFromDurableSealedWorkerMaterial({
    walletId: String(volatileRecord?.walletId || '').trim(),
    nearAccountId: String(volatileRecord?.nearAccountId || args.nearAccountId || '').trim(),
    nearEd25519SigningKeyId: String(volatileRecord?.nearEd25519SigningKeyId || '').trim(),
    signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    source: 'login',
  });
  if (
    exactHydrated.kind === 'hydrated' &&
    String(exactHydrated.record.thresholdSessionId || '').trim() === args.thresholdSessionId &&
    classifyRouterAbEd25519PersistedSigningRecord(exactHydrated.record).kind === 'restore_available'
  ) {
    return exactHydrated.record;
  }
  return null;
}

function logThresholdLoginEd25519UnsealInstallSkipped(args: {
  nearAccountId: AccountId;
  thresholdSessionId: string;
  error: unknown;
}): void {
  console.warn('[login] Ed25519 warm-session unseal authorization install skipped', {
    nearAccountId: args.nearAccountId,
    thresholdSessionId: args.thresholdSessionId,
    error: args.error instanceof Error ? args.error.message : String(args.error || 'unknown error'),
  });
}

function logThresholdLoginEd25519UnsealInstallOutcome(args: {
  outcome: string;
  nearAccountId: string;
  signingGrantId?: string;
  thresholdSessionId: string;
  state?: string;
  reason?: string;
  hasRecord?: boolean;
  hasSealedWorkerMaterial?: boolean;
  hasMaterialBindingDigest?: boolean;
  hasClientVerifier?: boolean;
  hasSigningGrantId?: boolean;
  hasCredential?: boolean;
  recordAccountId?: string;
  expiresAtMs?: number;
  authorizationExpiresAtMs?: number;
  resolvedThresholdSessionId?: string;
}): void {
  if (args.outcome === 'installed') return;
  console.warn('[login] Ed25519 warm-session unseal authorization install outcome', args);
}

async function primeThresholdLoginWarmSigners(args: {
  context: LoginWebContext;
  signingEngine: LoginWarmSigningSurface;
  walletBinding: ResolvedLoginWalletBinding;
  nearAccountId: AccountId;
  signerSlot: number;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  ttlMs: number;
  unlockBudgetPolicy: WalletUnlockBudgetPolicy;
  ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  credentialState: LoginWarmupCredentialState;
  runtimeScopeBootstrapState: LoginWarmupRuntimeScopeBootstrapState;
  signersToWarm: readonly ThresholdLoginWarmSigner[];
  ed25519DependsOnEcdsa: boolean;
  ecdsaDependsOnEd25519: boolean;
  ed25519MintPlan: LoginWarmupEd25519MintPlan;
  routeAuthorization: LoginWarmupRouteAuthorization;
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
  let activeCanonicalEcdsaContext = initialCanonicalEcdsaContext;
  const warmState: ThresholdLoginWarmEd25519State = {
    sessionId: '',
    signingGrantId: '',
    jwt: '',
    ecdsaHssPasskeyPrfFirstB64u: '',
  };
  const unlockRemainingUses = resolveSigningBudgetPolicyRemainingUses(args.unlockBudgetPolicy);
  const ecdsaBootstraps: ThresholdEcdsaSessionBootstrapResult[] = [];
  let ecdsaAuthorizedEd25519Mint: ThresholdEcdsaAuthorizedEd25519Mint | null = null;

  const tasks: ThresholdLoginWarmupTask[] = [];
  if (signersToWarm.includes('ed25519')) {
    tasks.push({
      signer: 'ed25519',
      dependencies: args.ed25519DependsOnEcdsa ? ['ecdsa'] : [],
      run: async () => {
        const ecdsaMint = ecdsaAuthorizedEd25519Mint;
        const auth = (() => {
          if (args.ed25519MintPlan.kind === 'session_policy_webauthn') {
            return args.ed25519MintPlan.authorization;
          }
          return buildLoginEd25519WalletSessionMintAuthorization({
            routeAuthorization: args.routeAuthorization,
            credentialState: args.credentialState,
            rpId: args.signingEngine.getRpId(),
            thresholdEcdsaSessionJwt: String(ecdsaMint?.thresholdEcdsaSessionJwt || ''),
            localPrfFirstB64u: String(ecdsaMint?.passkeyPrfFirstB64u || ''),
          });
        })();
        const ed25519ProvisioningIdentity = (() => {
          switch (args.ed25519MintPlan.kind) {
            case 'not_requested':
              throw new Error('[login] threshold Ed25519 mint plan is missing');
            case 'session_policy_webauthn':
              return {
                kind: 'exact_ed25519_provisioning' as const,
                sessionId: args.ed25519MintPlan.sessionId,
                signingGrantId: args.ed25519MintPlan.signingGrantId,
              };
            case 'fresh':
              return { kind: 'fresh_ed25519_provisioning' as const };
            case 'ecdsa_authorized':
              if (!ecdsaMint) {
                throw new Error(
                  '[login] threshold Ed25519 warm-up requires the ECDSA bootstrap session minted during unlock',
                );
              }
              return {
                kind: 'exact_ed25519_provisioning' as const,
                sessionId: args.ed25519MintPlan.sessionId,
                signingGrantId: ecdsaMint.signingGrantId,
              };
            default:
              return assertNeverLoginState(args.ed25519MintPlan);
          }
        })();
        const routerAbNormalSigning = createRouterAbNormalSigningPolicy(args.context.configs);
        const connected = await args.signingEngine.connectEd25519Session({
          ...ed25519ProvisioningIdentity,
          walletId: String(args.walletBinding.walletId),
          nearAccountId: args.walletBinding.nearAccountId,
          nearEd25519SigningKeyId: args.walletBinding.nearEd25519SigningKeyId,
          relayerUrl: args.relayerUrl,
          relayerKeyId: args.relayerKeyId,
          source: 'login',
          ...(auth ? { auth } : {}),
          ...(initialCanonicalEcdsaContext.runtimePolicyScope
            ? { runtimePolicyScope: initialCanonicalEcdsaContext.runtimePolicyScope }
            : {}),
          routerAbNormalSigning,
          ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
          participantIds: args.participantIds,
          sessionKind: 'jwt',
          signerSlot: args.signerSlot,
          ttlMs: args.ttlMs,
          remainingUses: unlockRemainingUses,
        });
        if (!connected.ok) {
          const details = String(
            connected.message || connected.code || 'Failed to connect threshold Ed25519 session',
          );
          throw new Error(`[login] threshold Ed25519 warm-up failed: ${details}`);
        }

        const connectedSessionId = String(connected.sessionId || '').trim();
        if (!connectedSessionId) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a sessionId');
        }

        const connectedJwt = String(connected.jwt || '').trim();
        if (!connectedJwt) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a JWT session token');
        }

        const connectedSigningGrantId = String(connected.signingGrantId || '').trim();
        if (!connectedSigningGrantId) {
          throw new Error('[login] threshold Ed25519 warm-up did not return a signingGrantId');
        }

        const connectedEcdsaHssPasskeyPrfFirstB64u = String(
          connected.ecdsaHssPasskeyPrfFirstB64u || '',
        ).trim();
        if (signersToWarm.includes('ecdsa') && !connectedEcdsaHssPasskeyPrfFirstB64u) {
          throw new Error(
            '[login] threshold ECDSA warm-up missing passkey PRF.first from the primed Ed25519 session',
          );
        }

        warmState.sessionId = connectedSessionId;
        warmState.signingGrantId = connectedSigningGrantId;
        warmState.jwt = connectedJwt;
        warmState.ecdsaHssPasskeyPrfFirstB64u = connectedEcdsaHssPasskeyPrfFirstB64u;
        if (args.ecdsaContextResolution.kind === 'resolve_after_ed25519') {
          activeCanonicalEcdsaContext =
            await args.ecdsaContextResolution.resolveAfterEd25519(warmState);
        }
      },
    });
  }
  if (signersToWarm.includes('ecdsa')) {
    tasks.push({
      signer: 'ecdsa',
      dependencies: args.ecdsaDependsOnEd25519 ? ['ed25519'] : [],
      run: async () => {
        let bootstrapIdentity: ThresholdLoginWarmEcdsaBootstrapIdentity | null = null;
        const configuredEcdsaTargets = listConfiguredThresholdEcdsaPublicationTargets(
          args.context.configs.network.chains,
        );
        const completeActiveContextFromSharedKey = (source: string): void => {
          const completion = buildSharedKeyTargetCompletion({
            context: activeCanonicalEcdsaContext,
            configuredTargets: configuredEcdsaTargets,
          });
          if (completion.kind === 'complete_shared_key_targets') {
            activeCanonicalEcdsaContext = completion.context;
            return;
          }
          if (completion.kind === 'duplicate_shared_key_targets') {
            requireCompleteSharedKeyTargetContext({ completion, source });
          }
        };
        const rememberBootstrappedKey = (input: {
          target: (typeof configuredEcdsaTargets)[number];
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
        }): ConfiguredTargetThresholdEcdsaWarmKey => {
          const keyRef = input.bootstrap.thresholdEcdsaKeyRef;
          const thresholdOwnerAddress = String(
            input.bootstrap.keygen.ethereumAddress || keyRef.ethereumAddress || '',
          ).trim();
          const resolved = resolveLoginThresholdEcdsaBootstrapKey({
            bootstrap: input.bootstrap,
            walletId: args.walletBinding.walletId,
            rpId: String(args.signingEngine.getRpId() || '').trim(),
            thresholdOwnerAddress,
          });
          const warmKey = configuredTargetThresholdEcdsaWarmKey({
            chainTarget: input.target.chainTarget,
            keyHandle: resolved.keyHandle,
            key: resolved.key,
          });
          const runtimePolicyScope =
            input.bootstrap.session.runtimePolicyScope ||
            parseThresholdRuntimePolicyScopeFromJwt(
              String(input.bootstrap.session.jwt || keyRef.walletSessionJwt || '').trim(),
            );
          activeCanonicalEcdsaContext = mergeCanonicalThresholdEcdsaWarmSessionContexts(
            activeCanonicalEcdsaContext,
            {
              ecdsaKeys: [warmKey],
              ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            },
          );
          completeActiveContextFromSharedKey('login first-bootstrapped ECDSA key');
          return warmKey;
        };
        const rememberEcdsaAuthorizedEd25519Mint = (
          bootstrap: ThresholdEcdsaSessionBootstrapResult,
        ): void => {
          if (ecdsaAuthorizedEd25519Mint) return;
          const thresholdEcdsaSessionJwt = String(bootstrap.session.jwt || '').trim();
          const passkeyPrfFirstB64u =
            String(bootstrap.passkeyPrfFirstB64u || '').trim() ||
            (credential ? passkeyPrfFirstB64uFromCredential(credential) : '');
          const passkeyCredentialIdB64u =
            String(bootstrap.passkeyCredentialIdB64u || '').trim() ||
            passkeyCredentialIdB64uFromAuthentication(credential || undefined) ||
            localPasskeyCredentialIdB64u;
          const signingGrantId = String(
            bootstrap.thresholdEcdsaKeyRef?.signingGrantId ||
              bootstrap.session?.signingGrantId ||
              '',
          ).trim();
          if (
            !thresholdEcdsaSessionJwt ||
            !passkeyPrfFirstB64u ||
            !passkeyCredentialIdB64u ||
            !signingGrantId
          ) {
            return;
          }
          ecdsaAuthorizedEd25519Mint = {
            thresholdEcdsaSessionJwt,
            passkeyPrfFirstB64u,
            passkeyCredentialIdB64u,
            signingGrantId,
          };
        };
        const ecdsaOnlySigningGrantId =
          String(warmState.signingGrantId || '').trim() ||
          createThresholdLoginWarmSessionId('wallet-ecdsa-login');
        const resolveCurrentBootstrapIdentity = (): ThresholdLoginWarmEcdsaBootstrapIdentity => {
          if (bootstrapIdentity) return bootstrapIdentity;
          const thresholdEcdsaSessionJwt = String(
            ecdsaAuthorizedEd25519Mint?.thresholdEcdsaSessionJwt || '',
          ).trim();
          if (thresholdEcdsaSessionJwt) {
            return {
              routeAuth: { kind: 'wallet_session', jwt: thresholdEcdsaSessionJwt },
            };
          }
          bootstrapIdentity = resolveThresholdLoginWarmEcdsaBootstrapIdentity({
            ed25519State: warmState,
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
            throw new Error('[login] threshold ECDSA warm-up requires shared key identity');
          }
          const thresholdSessionId = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
          const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
            chainTarget: target.chainTarget,
            thresholdSessionId,
            signingGrantId: ecdsaOnlySigningGrantId,
            thresholdSessionKind: 'jwt',
            ttlMs: args.ttlMs,
            remainingUses: unlockRemainingUses,
            ...(activeCanonicalEcdsaContext.runtimePolicyScope
              ? { runtimePolicyScope: activeCanonicalEcdsaContext.runtimePolicyScope }
              : {}),
          });
          const bootstrappedPasskeyPrfFirstB64u = String(
            ecdsaAuthorizedEd25519Mint?.passkeyPrfFirstB64u || '',
          ).trim();
          const hasPasskeyPrfSource = Boolean(
            String(warmState.ecdsaHssPasskeyPrfFirstB64u || '').trim() || credential,
          );
          const passkeyPrfFirstB64u = bootstrappedPasskeyPrfFirstB64u
            ? bootstrappedPasskeyPrfFirstB64u
            : hasPasskeyPrfSource
              ? resolveThresholdLoginWarmEcdsaPrfFirstB64u({
                  ed25519State: warmState,
                  credentialState: args.credentialState,
                })
              : '';
          const currentBootstrapIdentity = passkeyPrfFirstB64u
            ? resolveCurrentBootstrapIdentity()
            : null;
          const passkeyCredentialIdB64u = String(
            passkeyCredentialIdB64uFromAuthentication(credential || undefined) ||
              ecdsaAuthorizedEd25519Mint?.passkeyCredentialIdB64u ||
              targetEcdsaKey.passkeyCredentialIdB64u ||
              localPasskeyCredentialIdB64u ||
              '',
          ).trim();
          const reconnectRouteAuth = isWalletSessionReconnectEcdsaRouteAuth(
            currentBootstrapIdentity?.routeAuth,
          )
            ? currentBootstrapIdentity.routeAuth
            : null;
          if (reconnectRouteAuth && passkeyPrfFirstB64u && passkeyCredentialIdB64u) {
            return await args.signingEngine.bootstrapEcdsaSession({
              kind: 'wallet_session_reconnect_ecdsa_bootstrap',
              source: 'login',
              relayerUrl: args.relayerUrl,
              keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
              key: targetEcdsaKey.key,
              lanePolicy,
              passkeyPrfFirstB64u: passkeyPrfFirstB64u,
              passkeyCredentialIdB64u,
              routeAuth: reconnectRouteAuth,
              ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
            });
          }
          const passkeyBootstrapProof =
            passkeyPrfFirstB64u && credential
              ? {
                  passkeyPrfFirstB64u: passkeyPrfFirstB64u,
                  webauthnAuthentication: credential,
                }
              : null;
          if (passkeyBootstrapProof) {
            const routeAuth = currentBootstrapIdentity?.routeAuth;
            if (isWalletSessionReconnectEcdsaRouteAuth(routeAuth)) {
              return await args.signingEngine.bootstrapEcdsaSession({
                kind: 'passkey_fresh_ecdsa_bootstrap',
                source: 'login',
                relayerUrl: args.relayerUrl,
                keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
                key: targetEcdsaKey.key,
                lanePolicy,
                routeAuth,
                ...passkeyBootstrapProof,
                ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
              });
            }
            return await args.signingEngine.bootstrapEcdsaSession({
              kind: 'passkey_fresh_ecdsa_bootstrap',
              source: 'login',
              relayerUrl: args.relayerUrl,
              keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
              key: targetEcdsaKey.key,
              lanePolicy,
              ...passkeyBootstrapProof,
              ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
            });
          }
          return await args.signingEngine.bootstrapEcdsaSession({
            kind: 'passkey_fresh_ecdsa_bootstrap',
            source: 'login',
            relayerUrl: args.relayerUrl,
            keyHandle: toEvmFamilyEcdsaKeyHandle(targetEcdsaKey.keyHandle),
            key: targetEcdsaKey.key,
            lanePolicy,
            ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
          });
        };
        const firstBootstrapTarget = async (target: (typeof configuredEcdsaTargets)[number]) => {
          if (!runtimeScopeBootstrap) {
            throw new Error(
              '[login] threshold ECDSA first bootstrap requires managed runtime scope bootstrap',
            );
          }
          const thresholdSessionId = createThresholdLoginWarmSessionId('threshold-ecdsa-login');
          type FirstBootstrapPasskeyMaterial =
            | {
                kind: 'webauthn_prf';
                passkeyPrfFirstB64u: string;
                webauthnAuthentication: WebAuthnAuthenticationCredential;
              }
            | {
                kind: 'stored_prf';
                passkeyPrfFirstB64u: string;
                passkeyCredentialIdB64u: string;
              };
          const passkeyPrfFirstB64u = String(
            credential
              ? resolveThresholdLoginWarmEcdsaPrfFirstB64u({
                  ed25519State: warmState,
                  credentialState: args.credentialState,
                })
              : warmState.ecdsaHssPasskeyPrfFirstB64u,
          ).trim();
          const passkeyCredentialIdB64u = String(
            passkeyCredentialIdB64uFromAuthentication(credential || undefined) ||
              localPasskeyCredentialIdB64u,
          ).trim();
          const passkeyMaterial: FirstBootstrapPasskeyMaterial =
            passkeyPrfFirstB64u && credential
              ? {
                  kind: 'webauthn_prf',
                  passkeyPrfFirstB64u,
                  webauthnAuthentication: credential,
                }
              : passkeyPrfFirstB64u && passkeyCredentialIdB64u
                ? {
                    kind: 'stored_prf',
                    passkeyPrfFirstB64u,
                    passkeyCredentialIdB64u,
                  }
                : (() => {
                    throw new Error(
                      '[login] threshold ECDSA first bootstrap requires PRF.first from the wallet unlock assertion',
                    );
                  })();
          const sessionIdentity = buildEcdsaSessionIdentity({
            thresholdSessionId,
            signingGrantId: ecdsaOnlySigningGrantId,
          });
          const appSessionJwt =
            args.routeAuthorization.kind === 'app_session_jwt'
              ? args.routeAuthorization.appSessionJwt
              : '';
          const walletSessionJwt = String(warmState.jwt || '').trim();
          const firstBootstrapBase = {
            kind: 'passkey_fresh_ecdsa_bootstrap' as const,
            walletId: args.walletBinding.walletId,
            chainTarget: target.chainTarget,
            source: 'login' as const,
            relayerUrl: args.relayerUrl,
            sessionIdentity,
            runtimeScopeBootstrap,
            ttlMs: args.ttlMs,
            remainingUses: unlockRemainingUses,
          };
          const bootstrapWithSessionAuth = async (
            routeAuth: WalletSessionReconnectEcdsaBootstrapRouteAuth,
          ): Promise<ThresholdEcdsaSessionBootstrapResult> => {
            switch (passkeyMaterial.kind) {
              case 'webauthn_prf':
                return await args.signingEngine.bootstrapEcdsaSession({
                  ...firstBootstrapBase,
                  sessionKind: 'jwt',
                  routeAuth,
                  passkeyPrfFirstB64u: passkeyMaterial.passkeyPrfFirstB64u,
                  webauthnAuthentication: passkeyMaterial.webauthnAuthentication,
                });
              case 'stored_prf':
                return await args.signingEngine.bootstrapEcdsaSession({
                  ...firstBootstrapBase,
                  sessionKind: 'jwt',
                  routeAuth,
                  passkeyPrfFirstB64u: passkeyMaterial.passkeyPrfFirstB64u,
                  passkeyCredentialIdB64u: passkeyMaterial.passkeyCredentialIdB64u,
                });
            }
            return assertNeverLoginState(passkeyMaterial);
          };
          const bootstrapWithPasskeyAuthorization =
            async (): Promise<ThresholdEcdsaSessionBootstrapResult> => {
              if (passkeyMaterial.kind !== 'webauthn_prf') {
                throw new Error(
                  '[login] threshold ECDSA first bootstrap requires passkey authorization',
                );
              }
              return await args.signingEngine.bootstrapEcdsaSession({
                ...firstBootstrapBase,
                sessionKind: 'jwt',
                passkeyPrfFirstB64u: passkeyMaterial.passkeyPrfFirstB64u,
                webauthnAuthentication: passkeyMaterial.webauthnAuthentication,
              });
            };
          if (appSessionJwt) {
            return await bootstrapWithSessionAuth({ kind: 'app_session', jwt: appSessionJwt });
          }
          if (passkeyMaterial.kind === 'webauthn_prf') {
            return await bootstrapWithPasskeyAuthorization();
          }
          if (walletSessionJwt) {
            return await bootstrapWithSessionAuth({
              kind: 'wallet_session',
              jwt: walletSessionJwt,
            });
          }
          throw new Error(
            '[login] threshold ECDSA first bootstrap requires passkey authorization or an existing bootstrap session',
          );
        };
        const bootstrapConfiguredTargets = async () => {
          completeActiveContextFromSharedKey('login ECDSA warm-up preflight');
          for (const target of configuredEcdsaTargets) {
            const targetKey = thresholdEcdsaChainTargetKey(target.chainTarget);
            let targetEcdsaKey = activeCanonicalEcdsaContext.ecdsaKeys.find(
              (key) => key.targetKey === targetKey,
            );
            const keyHandle = String(targetEcdsaKey?.keyHandle || '').trim();
            if (!targetEcdsaKey?.key || !keyHandle) {
              const bootstrap = await firstBootstrapTarget(target);
              ecdsaBootstraps.push(bootstrap);
              rememberEcdsaAuthorizedEd25519Mint(bootstrap);
              targetEcdsaKey = rememberBootstrappedKey({ target, bootstrap });
              continue;
            }
            const bootstrap: ThresholdEcdsaSessionBootstrapResult = await bootstrapTarget(
              target,
              targetEcdsaKey,
            );
            ecdsaBootstraps.push(bootstrap);
            rememberEcdsaAuthorizedEd25519Mint(bootstrap);
            const returnedKeyHandle = String(
              bootstrap.thresholdEcdsaKeyRef?.keyHandle || '',
            ).trim();
            if (returnedKeyHandle !== targetEcdsaKey.keyHandle) {
              throw new Error(
                `[login] threshold ECDSA warm-up returned a different keyHandle for ${targetKey}`,
              );
            }
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
  if (credential && warmState.sessionId) {
    try {
      await installThresholdLoginEd25519WarmSessionUnsealAuthorization({
        signingEngine: args.signingEngine,
        credential,
        nearAccountId: args.nearAccountId,
        signingGrantId: warmState.signingGrantId,
        thresholdSessionId: warmState.sessionId,
      });
    } catch (error) {
      logThresholdLoginEd25519UnsealInstallSkipped({
        nearAccountId: args.nearAccountId,
        thresholdSessionId: warmState.sessionId,
        error,
      });
    }
  } else {
    logThresholdLoginEd25519UnsealInstallOutcome({
      outcome: 'skipped_preflight_missing_credential_or_session',
      nearAccountId: args.nearAccountId,
      thresholdSessionId: warmState.sessionId,
      hasCredential: Boolean(credential),
    });
  }
  return { ecdsaBootstraps };
}

/**
 * High-level login snapshot used by React contexts/UI.
 *
 * Login state is derived from:
 * - IndexedDB last-user pointer, and
 * - when threshold-signer warm sessions are enabled, an active PRF-first cache entry
 *   in the UserConfirm worker for the account's active signing session id.
 */
export async function getWalletSession(
  context: WalletSessionWebContext,
  walletId?: WalletId | string,
): Promise<WalletSession> {
  if (!walletId) return buildAnonymousWalletSession();

  await context.signingEngine.assertSealedRefreshStartupParity().catch((error: unknown) => {
    console.warn(
      '[WalletSession] sealed refresh startup parity check failed during session read; continuing with cached login state',
      error instanceof Error ? error.message : String(error || 'unknown error'),
    );
  });
  const login = await getLoginStateInternal(context, walletId);
  const signingSession = login?.walletId && login.nearAccountId
    ? await resolveSigningSessionStatusForUi(
        context,
        {
          kind: 'wallet_with_near_account',
          walletId: login.walletId,
          nearAccountId: login.nearAccountId,
        },
      ).catch(() => null)
    : null;
  const authMethod: WalletAuthMethod | null =
    signingSession?.authMethod ||
    (login.currentAuthMethod.kind === 'selected' ? login.currentAuthMethod.binding.kind : null) ||
    (login.isLoggedIn && login.publicKey ? 'passkey' : null);
  const authMethods = login.authMethods;
  const currentAuthMethod = selectCurrentWalletAuthMethod({ authMethods, authMethod });
  const retention = signingSession?.retention || null;
  const nonceDiagnostics = readWalletSessionNonceDiagnostics(context, login.nearAccountId);
  return {
    login: { ...login, currentAuthMethod, authMethods },
    signingSession,
    currentAuthMethod,
    authMethods,
    authMethod,
    retention,
    nonceDiagnostics,
  };
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

const THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES: readonly ThresholdEcdsaSessionStoreSource[] = [
  'email_otp',
  'login',
  'registration',
  'manual-bootstrap',
];

function readThresholdEcdsaLoginMetadataRecords(
  context: WalletSessionWebContext,
  walletId: WalletId,
): ThresholdEcdsaSessionRecord[] {
  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  return listConfiguredThresholdEcdsaPublicationTargets(context.configs.network.chains).flatMap(
    (target) =>
      context.signingEngine
        .listThresholdEcdsaSessionRecordsForWalletTarget({
          walletId,
          chainTarget: target.chainTarget,
        })
        .filter((record) => allowedSources.has(record.source)),
  );
}

function normalizeEvmOwnerAddress(value: unknown): string {
  const candidate = String(value || '')
    .trim()
    .toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(candidate) ? candidate : '';
}

function resolveUniqueThresholdEcdsaRecordAddress(args: {
  walletId: WalletId;
  records: readonly ThresholdEcdsaSessionRecord[];
}): string | null {
  const addresses = [
    ...new Set(
      args.records
        .map((record) => normalizeEvmOwnerAddress(record.ethereumAddress))
        .filter(Boolean),
    ),
  ];
  if (addresses.length === 1) return addresses[0]!;
  if (addresses.length > 1) {
    console.warn('[WalletSession] conflicting threshold ECDSA record addresses', {
      walletId: String(args.walletId),
      addresses,
    });
  }
  return null;
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
  const runtimeAddress = resolveUniqueThresholdEcdsaRecordAddress({
    walletId,
    records: readThresholdEcdsaLoginMetadataRecords(context, walletId),
  });
  if (runtimeAddress) return runtimeAddress;
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
  const sharedKeyTargetCompletion = buildSharedKeyTargetCompletion({
    context: args.storedCanonicalEcdsaContext,
    configuredTargets: args.selectedEcdsaTargets,
  });
  let ecdsaContextResolution: ThresholdLoginWarmEcdsaContextResolution;
  let signersToWarm: ThresholdLoginWarmSigner[];
  let ed25519DependsOnEcdsa = false;
  let ecdsaDependsOnEd25519 = false;
  if (sharedKeyTargetCompletion.kind === 'missing_shared_key' && args.selectedEcdsaTargets.length) {
    const initialContext: CanonicalThresholdEcdsaWarmSessionContext = {
      ecdsaKeys: [],
      ...(args.storedCanonicalEcdsaContext.runtimePolicyScope
        ? { runtimePolicyScope: args.storedCanonicalEcdsaContext.runtimePolicyScope }
        : {}),
    };
    if (!args.canFirstBootstrapThresholdEcdsa) {
      throw new Error(
        `[login] threshold ECDSA warm-up requires complete local key facts for ${sharedKeyTargetCompletion.missingTargets.join(
          ', ',
        )}; run explicit authenticated ECDSA key-facts inventory before unlock`,
      );
    }
    signersToWarm = args.wantsEd25519Warmup ? ['ecdsa', 'ed25519'] : ['ecdsa'];
    ed25519DependsOnEcdsa = args.wantsEd25519Warmup;
    ecdsaContextResolution = {
      kind: 'first_bootstrap_missing_shared_key',
      initialContext,
    };
  } else {
    const resolvedCanonicalEcdsaContext = requireCompleteSharedKeyTargetContext({
      completion: sharedKeyTargetCompletion,
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
    ecdsaDependsOnEd25519 = signersToWarm.includes('ed25519') && signersToWarm.includes('ecdsa');
  }
  if (!signersToWarm.length) {
    throw new Error('[login] ECDSA unlock requested with no configured ECDSA targets');
  }
  return {
    kind: 'threshold_login_warmup_plan_ready',
    storedCanonicalEcdsaContext: args.storedCanonicalEcdsaContext,
    sharedKeyTargetCompletion,
    ecdsaContextResolution,
    signersToWarm,
    ed25519DependsOnEcdsa,
    ecdsaDependsOnEd25519,
  };
}

function createThresholdLoginWarmSessionId(prefix: string): string {
  return secureRandomId(prefix, 32, 'threshold login warm session IDs');
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

async function resolveProfileContinuityEcdsaWarmKeys(
  walletId: WalletId,
  configuredTargets: readonly ConfiguredThresholdEcdsaPublicationTarget[],
  keyFactsInventoryInput?: {
    keyFactsInventoryAuthority: LoginEcdsaKeyFactsInventoryAuthority | null;
    keyFactsInventoryRequested: boolean;
    relayerUrl: string;
    rpId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    collectWebAuthnInventoryCredential?: (
      challengeB64u: string,
    ) => Promise<WebAuthnAuthenticationCredential>;
  },
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
    localSessionRecords: [],
    runtimeConfig: {
      explicitKeyFactsInventoryMode: keyFactsInventoryInput?.keyFactsInventoryRequested === true,
      allowAuthenticatedKeyFactsInventory: Boolean(
        keyFactsInventoryInput?.keyFactsInventoryAuthority,
      ),
    },
  });
  switch (plan.kind) {
    case 'ready': {
      const keys = plan.readyTargets.map((target) =>
        configuredTargetThresholdEcdsaWarmKey({
          chainTarget: target.chainTarget,
          keyHandle: target.walletKey.keyHandle,
          key: evmFamilyEcdsaWalletKeyToIdentity(target.walletKey),
        }),
      );
      return collectConfiguredTargetThresholdEcdsaWarmKeys({
        source: 'profile continuity',
        keys,
      });
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
      const relayerUrl = String(keyFactsInventoryInput.relayerUrl || '').trim();
      const rpId = String(keyFactsInventoryInput.rpId || '').trim();
      if (!relayerUrl || !rpId) {
        throw new Error('[login] threshold ECDSA key-facts inventory requires relayerUrl and rpId');
      }
      const inventory =
        keyFactsInventoryAuthority.kind === 'app_session'
          ? await fetchWalletEcdsaKeyFactsInventoryWithAppSession({
              relayerUrl,
              walletId,
              rpId,
              appSessionJwt: keyFactsInventoryAuthority.appSessionJwt,
              keyTargets: plan.keyTargets,
              policy: {
                permission: 'ecdsa_key_facts_inventory',
                walletId,
                chainTargets: plan.keyTargets.map((target) => target.chainTarget),
                expiresAtMs: keyFactsInventoryAuthority.policyExpiresAtMs,
              },
              ...(keyFactsInventoryInput.runtimePolicyScope
                ? { runtimePolicyScope: keyFactsInventoryInput.runtimePolicyScope }
                : {}),
            })
          : await resolveWalletEcdsaKeyFactsInventoryWithWebAuthn({
              walletId,
              relayerUrl,
              rpId,
              keyTargets: plan.keyTargets,
              ...(keyFactsInventoryInput.runtimePolicyScope
                ? { runtimePolicyScope: keyFactsInventoryInput.runtimePolicyScope }
                : {}),
              collectCredential: keyFactsInventoryInput.collectWebAuthnInventoryCredential,
            });
      const inventoriedKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
        source: 'profile continuity inventory',
        keys: inventory.records.map((record) =>
          configuredTargetThresholdEcdsaWarmKey({
            chainTarget: record.walletKey.chainTarget,
            keyHandle: record.walletKey.keyHandle,
            key: evmFamilyEcdsaWalletKeyToIdentity(record.walletKey),
          }),
        ),
      });
      const inventoriedCompletion = buildSharedKeyTargetCompletion({
        context: { ecdsaKeys: inventoriedKeys },
        configuredTargets,
      });
      if (inventoriedCompletion.kind !== 'complete_shared_key_targets') {
        throw new Error(
          '[login] threshold ECDSA key-facts inventory returned incomplete key facts',
        );
      }
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
  signingEngine: Pick<EcdsaLoginSessionSurface, 'listThresholdEcdsaSessionRecordsForWalletTarget'>,
  walletId: WalletId,
  keyFactsInventoryInput?: {
    keyFactsInventoryAuthority: LoginEcdsaKeyFactsInventoryAuthority | null;
    keyFactsInventoryRequested: boolean;
    relayerUrl: string;
    rpId: string;
    collectWebAuthnInventoryCredential?: (
      challengeB64u: string,
    ) => Promise<WebAuthnAuthenticationCredential>;
  },
): Promise<CanonicalThresholdEcdsaWarmSessionContext> {
  const allowedSources = new Set<ThresholdEcdsaSessionStoreSource>(
    THRESHOLD_ECDSA_LOGIN_METADATA_SOURCES,
  );
  const configuredTargets = listConfiguredThresholdEcdsaPublicationTargets(
    context.configs.network.chains,
  );
  const storedKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  let runtimePolicyScope: ThresholdRuntimePolicyScope | undefined;
  for (const target of configuredTargets) {
    for (const record of signingEngine.listThresholdEcdsaSessionRecordsForWalletTarget({
      walletId,
      chainTarget: target.chainTarget,
    })) {
      if (!allowedSources.has(record.source)) continue;
      const keyHandle = String(record.keyHandle || '').trim();
      if (keyHandle) {
        let key: EvmFamilyEcdsaKeyIdentity;
        try {
          key = thresholdEcdsaSessionRecordReadModel(record).key;
        } catch {
          continue;
        }
        storedKeys.push(
          configuredTargetThresholdEcdsaWarmKey({
            chainTarget: target.chainTarget,
            keyHandle,
            key,
            passkeyCredentialIdB64u: passkeyCredentialIdB64uFromEcdsaRecord(record),
          }),
        );
      }
      if (!runtimePolicyScope && record.runtimePolicyScope) {
        runtimePolicyScope = record.runtimePolicyScope;
      }
    }
  }
  const exactStoredKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'stored',
    keys: storedKeys,
  });
  if (exactStoredKeys.length) {
    return {
      ecdsaKeys: exactStoredKeys,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    };
  }
  const snapshot = await readAvailableSigningLanesForUi(context, walletId).catch(() => null);
  const availableLaneKeys: ConfiguredTargetThresholdEcdsaWarmKey[] = [];
  if (snapshot) {
    for (const target of ecdsaAvailableLaneTargets(snapshot)) {
      const lane = ecdsaAvailableLaneForTarget(snapshot, target);
      if (!isConcreteAvailableSigningLane(lane)) continue;
      const keyHandle = String(lane.publicFacts.keyHandle || '').trim();
      if (!keyHandle) continue;
      availableLaneKeys.push(
        configuredTargetThresholdEcdsaWarmKey({
          chainTarget: target,
          keyHandle,
          key: lane.key,
        }),
      );
    }
  }
  const exactAvailableLaneKeys = collectConfiguredTargetThresholdEcdsaWarmKeys({
    source: 'available lane',
    keys: availableLaneKeys,
  });
  if (exactAvailableLaneKeys.length) {
    return {
      ecdsaKeys: exactAvailableLaneKeys,
    };
  }
  const profileEcdsaThresholdKeys = await resolveProfileContinuityEcdsaWarmKeys(
    walletId,
    configuredTargets,
    {
      ...(keyFactsInventoryInput || {
        keyFactsInventoryAuthority: null,
        keyFactsInventoryRequested: false,
        relayerUrl: '',
        rpId: '',
      }),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    },
  );
  if (profileEcdsaThresholdKeys.length) {
    return {
      ecdsaKeys: profileEcdsaThresholdKeys,
    };
  }
  return {
    ecdsaKeys: [],
  };
}

function resolveManagedThresholdRuntimeScopeBootstrap(
  context: Pick<LoginWebContext, 'configs'>,
): ManagedThresholdRuntimeScopeBootstrap | undefined {
  const registration = context.configs?.registration;
  if (!registration || registration.mode !== 'managed') return undefined;
  const environmentId = String(registration.environmentId || '').trim();
  const publishableKey = String(registration.publishableKey || '').trim();
  if (!environmentId || !publishableKey) return undefined;
  return { environmentId, publishableKey };
}

function resolveThresholdEcdsaPublicKeyB64u(
  context: WalletSessionWebContext,
  walletId: WalletId,
): string | null {
  for (const record of readThresholdEcdsaLoginMetadataRecords(context, walletId)) {
    const thresholdEcdsaPublicKeyB64u = String(record.thresholdEcdsaPublicKeyB64u || '').trim();
    if (thresholdEcdsaPublicKeyB64u) return thresholdEcdsaPublicKeyB64u;
  }
  return null;
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

async function resolveThresholdEcdsaLoginMetadata(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<{
  ethereumAddress: string | null;
  thresholdEcdsaPublicKeyB64u: string | null;
}> {
  const [ethereumAddress, thresholdEcdsaPublicKeyB64u] = await Promise.all([
    resolveThresholdEcdsaEthereumAddress(context, walletId),
    (async () =>
      resolveThresholdEcdsaPublicKeyB64u(context, walletId) ||
      (await resolveProfileContinuityThresholdEcdsaPublicKeyB64u(context, walletId)))(),
  ]);
  return {
    ethereumAddress,
    thresholdEcdsaPublicKeyB64u,
  };
}

function isThresholdSignerMode(context: WalletSessionWebContext): boolean {
  const signingConfig = context.configs?.signing as { mode?: { mode?: unknown } } | undefined;
  return String(signingConfig?.mode?.mode || '').trim() === 'threshold-signer';
}

async function resolveWarmSigningSessionStatusForUi(
  context: WalletSessionWebContext,
  identity: WalletSessionStatusIdentity,
  hints?: {
    ed25519?: SigningSessionStatus | null;
  },
): Promise<SigningSessionStatus | null> {
  const ed25519 =
    identity.kind === 'wallet_with_near_account' && hints && 'ed25519' in hints
      ? hints.ed25519 || null
      : identity.kind === 'wallet_with_near_account'
        ? await context.signingEngine
            .getWarmThresholdEd25519SessionStatus(identity.nearAccountId)
            .catch(() => null)
        : null;
  const ecdsaStatusGroups: SigningSessionStatus[][] = [];
  for (const target of listConfiguredThresholdEcdsaPublicationTargets(
    context.configs.network.chains,
  )) {
    const statuses = await context.signingEngine
      .listWarmThresholdEcdsaSessionStatuses(identity.walletId, target.chainTarget)
      .catch(() => []);
    ecdsaStatusGroups.push(statuses);
  }
  const ecdsaStatuses = ecdsaStatusGroups.flat();

  const statuses = [ed25519, ...ecdsaStatuses].filter((status): status is SigningSessionStatus =>
    Boolean(status),
  );
  return selectSigningSessionStatusForDisplay(statuses);
}

type AvailableSigningLanesLane = AvailableEd25519SigningLane | AvailableEcdsaSigningLane;

function selectSigningSessionStatusForDisplay(
  statuses: readonly (SigningSessionStatus | null | undefined)[],
): SigningSessionStatus | null {
  const candidates = statuses.filter((status): status is SigningSessionStatus => Boolean(status));
  const active = candidates
    .filter((status) => status.status === 'active')
    .sort((left, right) => {
      const leftUses = Math.floor(Number(left.remainingUses) || 0);
      const rightUses = Math.floor(Number(right.remainingUses) || 0);
      if (leftUses !== rightUses) return leftUses - rightUses;
      return Math.floor(Number(left.expiresAtMs) || 0) - Math.floor(Number(right.expiresAtMs) || 0);
    })[0];
  if (active) return active;
  return selectDisplayFallbackSigningSessionStatus(candidates);
}

function selectDisplayFallbackSigningSessionStatus(
  candidates: readonly SigningSessionStatus[],
): SigningSessionStatus | null {
  const priority = ['exhausted', 'expired', 'unavailable', 'budget_unknown', 'not_found'] as const;
  for (const status of priority) {
    const candidate = candidates.find((candidateStatus) => candidateStatus.status === status);
    if (candidate) return candidate;
  }
  return null;
}

function snapshotLaneToDisplaySigningSessionStatus(
  lane: AvailableSigningLanesLane,
): SigningSessionStatus | null {
  if (!isConcreteAvailableSigningLane(lane)) return null;
  const sessionId = String(lane.thresholdSessionId || '').trim();
  if (!sessionId) return null;
  if (
    lane.state !== 'ready' &&
    lane.state !== 'restorable' &&
    lane.state !== 'expired' &&
    lane.state !== 'exhausted'
  ) {
    return null;
  }
  const remainingUses = Math.floor(Number(lane.remainingUses ?? lane.policyHint?.remainingUses));
  const expiresAtMs = Math.floor(Number(lane.expiresAtMs ?? lane.policyHint?.expiresAtMs));
  if (lane.state === 'restorable') {
    if (Number.isFinite(remainingUses) && remainingUses <= 0) return null;
    if (Number.isFinite(expiresAtMs) && expiresAtMs > 0 && Date.now() >= expiresAtMs) return null;
  }
  const status: SigningSessionStatus = {
    sessionId,
    status:
      lane.state === 'ready' || lane.state === 'restorable'
        ? 'active'
        : lane.state === 'expired'
          ? 'expired'
          : 'exhausted',
    authMethod:
      lane.curve === 'ecdsa'
        ? availableEcdsaSigningLaneAuthMethod(lane)
        : availableEd25519SigningLaneAuthMethod(lane),
  };
  if (Number.isFinite(remainingUses) && remainingUses >= 0) {
    status.remainingUses = remainingUses;
  }
  if (Number.isFinite(expiresAtMs) && expiresAtMs > 0) {
    status.expiresAtMs = expiresAtMs;
  }
  return status;
}

function snapshotToSigningSessionStatusForUi(
  snapshot: AvailableSigningLanes | null,
): SigningSessionStatus | null {
  if (!snapshot) return null;
  return selectSigningSessionStatusForDisplay([
    snapshotLaneToDisplaySigningSessionStatus(snapshot.lanes.ed25519.near),
    ...ecdsaAvailableLaneTargets(snapshot).map((target) =>
      snapshotLaneToDisplaySigningSessionStatus(ecdsaAvailableLaneForTarget(snapshot, target)),
    ),
  ]);
}

async function readAvailableSigningLanesForUi(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<AvailableSigningLanes | null> {
  return await context.signingEngine.readPersistedAvailableSigningLanes({
    walletId,
  });
}

async function resolveSnapshotSigningSessionStatusForUi(
  context: WalletSessionWebContext,
  walletId: WalletId,
): Promise<SigningSessionStatus | null> {
  return snapshotToSigningSessionStatusForUi(
    await readAvailableSigningLanesForUi(context, walletId),
  );
}

async function resolveSigningSessionStatusForUi(
  context: WalletSessionWebContext,
  identity: WalletSessionStatusIdentity,
  hints?: {
    ed25519?: SigningSessionStatus | null;
    snapshot?: SigningSessionStatus | null;
  },
): Promise<SigningSessionStatus | null> {
  const [warmStatus, snapshotStatus] = await Promise.all([
    resolveWarmSigningSessionStatusForUi(context, identity, hints).catch(() => null),
    hints && 'snapshot' in hints
      ? Promise.resolve(hints.snapshot || null)
      : resolveSnapshotSigningSessionStatusForUi(context, identity.walletId).catch(() => null),
  ]);
  // Status reads are side-effect-free. The next signing command owns exact
  // restore; warm status remains useful to display currently active sessions.
  return selectSigningSessionStatusForDisplay([snapshotStatus, warmStatus]);
}

async function getLoginStateInternal(
  context: WalletSessionWebContext,
  walletId: WalletId | string,
): Promise<LoginState> {
  const { signingEngine } = context;
  try {
    const lastUser = await signingEngine.getLastUser().catch(() => null);
    const identity = resolveExplicitWalletSessionIdentity(walletId);
    if (identity.kind !== 'wallet_with_near_account') {
      return buildLoggedOutLoginState({
        walletId: identity.walletId,
        nearAccountId: null,
        thresholdEcdsaEthereumAddress: null,
        thresholdEcdsaPublicKeyB64u: null,
      });
    }

    const latestByAccount =
      lastUser && lastUser.nearAccountId === identity.nearAccountId
        ? null
        : await getNearAccountProjection(IndexedDBManager, identity.nearAccountId).catch(
            () => null,
          );
    const userData =
      (lastUser && lastUser.nearAccountId === identity.nearAccountId ? lastUser : latestByAccount) ||
      (await signingEngine.getUserBySignerSlot(identity.nearAccountId, 1).catch(() => null));
    const resolvedNearAccountId = identity.nearAccountId;
    const resolvedWalletId = identity.walletId;
    const sessionStatusIdentity: WalletSessionStatusIdentity = {
      kind: 'wallet_with_near_account',
      walletId: resolvedWalletId,
      nearAccountId: resolvedNearAccountId,
    };
    const thresholdMetadata = await resolveThresholdEcdsaLoginMetadata(context, resolvedWalletId);
    const requiresWarmSession = shouldRequireThresholdWarmSession(context);
    const thresholdSignerMode = isThresholdSignerMode(context);
    const hasThresholdEcdsaLogin = !!(
      thresholdMetadata.thresholdEcdsaPublicKeyB64u || thresholdMetadata.ethereumAddress
    );
    const ed25519WarmStatus = await signingEngine
      .getWarmThresholdEd25519SessionStatus(resolvedNearAccountId)
      .catch(() => null);
    const snapshotStatusForLogin = await resolveSnapshotSigningSessionStatusForUi(
      context,
      resolvedWalletId,
    ).catch(() => null);
    const shouldGateNearPublicKey =
      requiresWarmSession || thresholdSignerMode || hasThresholdEcdsaLogin;
    const hasThresholdEd25519SigningCapability =
      ed25519WarmStatus?.status === 'active' || snapshotStatusForLogin?.status === 'active';
    const publicKey =
      userData?.operationalPublicKey &&
      (!shouldGateNearPublicKey || hasThresholdEd25519SigningCapability)
        ? userData.operationalPublicKey
        : null;
    const hasNearOperationalLogin = !!(userData && publicKey);
    const shouldResolveWarmStatusForLogin =
      requiresWarmSession || thresholdSignerMode || hasThresholdEcdsaLogin || !publicKey;
    const warmStatusForLogin = shouldResolveWarmStatusForLogin
      ? await resolveSigningSessionStatusForUi(context, sessionStatusIdentity, {
          ed25519: ed25519WarmStatus,
          snapshot: snapshotStatusForLogin,
        }).catch(() => null)
      : null;
    const hasActiveWarmSigningSession = warmStatusForLogin?.status === 'active';
    const isLoggedIn =
      hasNearOperationalLogin || hasThresholdEcdsaLogin || hasActiveWarmSigningSession;

    if (isLoggedIn && (requiresWarmSession || !hasNearOperationalLogin)) {
      const warmStatus =
        warmStatusForLogin ||
        (await resolveSigningSessionStatusForUi(context, sessionStatusIdentity, {
          ed25519: ed25519WarmStatus,
          snapshot: snapshotStatusForLogin,
        }));
      if (!warmStatus || warmStatus.status !== 'active') {
        return buildLoggedOutLoginState({
          walletId: resolvedWalletId,
          nearAccountId: resolvedNearAccountId,
          thresholdEcdsaEthereumAddress: thresholdMetadata.ethereumAddress,
          thresholdEcdsaPublicKeyB64u: thresholdMetadata.thresholdEcdsaPublicKeyB64u,
        });
      }
    }

    const authMethod: WalletAuthMethod | null =
      isLoggedIn && publicKey ? 'passkey' : isLoggedIn ? warmStatusForLogin?.authMethod || null : null;
    const authMethods = await readWalletAuthMethodBindingsForSession(resolvedWalletId);
    const currentAuthMethod = selectCurrentWalletAuthMethod({ authMethods, authMethod });

    return {
      isLoggedIn,
      walletId: resolvedWalletId,
      nearAccountId: resolvedNearAccountId,
      publicKey,
      userData,
      currentAuthMethod,
      authMethods,
      thresholdEcdsaEthereumAddress: thresholdMetadata.ethereumAddress,
      thresholdEcdsaPublicKeyB64u: thresholdMetadata.thresholdEcdsaPublicKeyB64u,
    };
  } catch (error: unknown) {
    console.warn('Error getting login state:', error);
    const fallbackIdentity = walletId ? resolveExplicitWalletSessionIdentity(walletId) : null;
    return buildLoggedOutLoginState({
      walletId: fallbackIdentity?.walletId || null,
      nearAccountId:
        fallbackIdentity?.kind === 'wallet_with_near_account'
          ? fallbackIdentity.nearAccountId
          : null,
      thresholdEcdsaEthereumAddress: null,
      thresholdEcdsaPublicKeyB64u: null,
    });
  }
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
  const accountIds = [...new Set(allUsersData.map((user) => user.nearAccountId))];
  const lastUsedAccount = await context.signingEngine.getLastUser();
  return {
    accountIds,
    accounts: allUsersData.map((user) => ({
      nearAccountId: user.nearAccountId,
      signerSlot: user.signerSlot,
      authMethod: user.authMethod || null,
    })),
    lastUsedAccount,
  };
}

/**
 * Lock: clears last-user pointer and client-side caches.
 */
export async function lock(context: LockWebContext): Promise<void> {
  const { signingEngine } = context;
  await IndexedDBManager.clearLastProfileSelection().catch(() => undefined);
  try {
    signingEngine.getNonceCoordinator().clearAll();
  } catch {}
  try {
    signingEngine.clearThresholdEcdsaCommitQueue();
  } catch {}
  try {
    signingEngine.clearAllThresholdEcdsaSessionRecords();
  } catch {}
  try {
    await signingEngine.clearVolatileWarmSigningMaterial();
  } catch {}
  try {
    clearAllStoredThresholdEd25519SessionRecords();
  } catch {}
}
