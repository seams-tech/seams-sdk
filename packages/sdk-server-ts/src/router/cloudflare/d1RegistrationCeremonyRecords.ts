import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { derivationClientSharePublicKey33B64uFromString } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  addAuthMethodIntentGrantFromString,
  addSignerIntentGrantFromString,
  createServerAllocatedWalletId,
  normalizeAddAuthMethodInput,
  normalizeAddSignerSelection,
  normalizeRegistrationAuthMethodInput,
  normalizeRegistrationSignerPlan,
  nearEd25519SigningKeyIdFromString,
  requireServerAllocatedWalletId,
  registrationEvmFamilyEcdsaBranchKey,
  registrationIntentGrantFromString,
  registrationNearEd25519BranchKey,
  registrationSignerBranchKeyFromString,
  registrationSignerSetSelectionFromPlan,
  walletIdFromString,
  type AddAuthMethodInput,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type AddSignerSelection,
  type ServerAllocatedWalletId,
  type RegistrationAuthority,
  type RegistrationAuthMethodInput,
  type RegistrationIntentV1,
  type RegistrationNearAccountProvisioning,
  type ResolvedRegistrationNearAccount,
  type RegistrationSignerSetSelection,
  type RegistrationSignerBranchKey,
  type RuntimePolicyScopeLike,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  parseWebAuthnAuthenticatorDeviceInfo,
  unknownWebAuthnAuthenticatorDeviceInfo,
} from '@shared/utils/webauthnDeviceInfo';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseOrgId,
  parseProviderSubject,
  parseRootShareEpoch,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  deriveEvmFamilySigningKeySlotId,
  parseEvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';

function requireEvmFamilySigningKeySlotId(value: unknown) {
  const parsed = parseEvmFamilySigningKeySlotId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  parseRouterAbEcdsaRegistrationRequestFactsV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { parseStoredRouterAbEcdsaPendingActivationV1 } from '../routerAbEcdsaStrictRegistration';
import { registrationPreparationIdFromString } from '../../core/registrationContracts';
import type {
  EcdsaDerivationClientBootstrapRequest,
  EcdsaDerivationServerBootstrapResponse,
} from '../../core/types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey,
  WalletRegistrationFinalizeAuthMethod,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationEd25519YaoPublicResult,
  WalletRegistrationEd25519YaoBootstrapSession,
  WalletAddSignerFinalizeResponse,
} from '../../core/registrationContracts';
import { parseWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  parseThresholdEd25519AuthorityScope,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  thresholdEd25519AuthorityScopesMatch,
} from '../../core/ThresholdService/validation';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import {
  parseStoredWalletRegistrationPreparedContext,
  parseStoredRegistrationSignerPlan,
  storedRegistrationSignerPlansMatch,
  type StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch,
  type StoredWalletRegistrationNearEd25519YaoAuthorizedBranch,
  type StoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationSignerSetState,
  StoredAddAuthMethodIntent,
  StoredAddSignerIntent,
  StoredRegistrationIntent,
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
  StoredWalletAddSignerFinalizeReplay,
  StoredWalletAddSignerFinalizeRequest,
  StoredWalletRegistrationCeremony,
  StoredWalletRegistrationFinalizeReplay,
} from '../../core/RegistrationCeremonyStore';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromValue,
  type ThresholdEcdsaChainTarget,
} from '../../core/thresholdEcdsaChainTarget';
import {
  buildWalletEcdsaSignerRecord,
  parseWalletEd25519SignerRecord,
  type WalletEcdsaSignerRecord,
  type WalletRecord,
} from '../../core/d1WalletStore';
import { toRecordValue } from './d1RouterApiAuthBoundary';

type D1EcdsaPublicIdentity = EcdsaDerivationServerBootstrapResponse['publicIdentity'];
type D1EcdsaClientSharePublicKey = D1EcdsaPublicIdentity['derivationClientSharePublicKey33B64u'];
type D1EcdsaRelayerPublicKey = D1EcdsaPublicIdentity['relayerPublicKey33B64u'];
type PasskeyRegistrationAuthority = Extract<
  RegistrationAuthority,
  { kind: typeof WALLET_AUTH_METHODS.passkey }
>;
type EmailOtpRegistrationAuthority = Extract<
  RegistrationAuthority,
  { kind: typeof WALLET_AUTH_METHODS.emailOtp }
>;
type GoogleSsoEmailOtpRegistrationAuthority = Extract<
  EmailOtpRegistrationAuthority,
  { proofKind: 'google_sso_registration' }
>;
type D1WalletRegistrationFinalizeSuccess = Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true }
>;
type D1WalletRegistrationFinalizeEcdsaPayload = {
  readonly walletKeys: WalletRegistrationEcdsaWalletKey[];
};

export function createD1ServerAllocatedWalletId(): ServerAllocatedWalletId {
  return createServerAllocatedWalletId();
}

export function inferRuntimePolicyScopeFromSigningRoot(input: {
  readonly orgId: string;
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
}): RuntimePolicyScope | undefined {
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  if (!signingRootId || !signingRootVersion) return undefined;
  const [projectId, envId] = signingRootId.split(':');
  if (!projectId || !envId) return undefined;
  return {
    orgId: toOptionalTrimmedString(input.orgId) || '',
    projectId,
    envId,
    signingRootVersion,
  };
}

export function buildRegistrationIntent(input: {
  readonly walletId: WalletId;
  readonly authMethod: RegistrationAuthMethodInput;
  readonly signerSelection: RegistrationSignerSetSelection;
  readonly runtimePolicyScope?: RuntimePolicyScope;
}): RegistrationIntentV1 {
  const nonceB64u = secureRandomBase64Url(32);
  if (input.runtimePolicyScope) {
    return {
      version: 'registration_intent_v1',
      walletId: input.walletId,
      authMethod: input.authMethod,
      signerSelection: input.signerSelection,
      runtimePolicyScope: input.runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'registration_intent_v1',
    walletId: input.walletId,
    authMethod: input.authMethod,
    signerSelection: input.signerSelection,
    nonceB64u,
  };
}

export function buildAddSignerIntent(input: {
  readonly walletId: WalletId;
  readonly signerSelection: AddSignerSelection;
  readonly runtimePolicyScope?: RuntimePolicyScope;
}): AddSignerIntentV1 {
  const nonceB64u = secureRandomBase64Url(32);
  if (input.runtimePolicyScope) {
    return {
      version: 'add_signer_intent_v1',
      walletId: input.walletId,
      signerSelection: input.signerSelection,
      runtimePolicyScope: input.runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_signer_intent_v1',
    walletId: input.walletId,
    signerSelection: input.signerSelection,
    nonceB64u,
  };
}

export function buildAddAuthMethodIntent(input: {
  readonly walletId: WalletId;
  readonly authMethod: AddAuthMethodInput;
  readonly runtimePolicyScope?: RuntimePolicyScope;
}): AddAuthMethodIntentV1 {
  const nonceB64u = secureRandomBase64Url(32);
  if (input.runtimePolicyScope) {
    return {
      version: 'add_auth_method_intent_v1',
      walletId: input.walletId,
      authMethod: input.authMethod,
      runtimePolicyScope: input.runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_auth_method_intent_v1',
    walletId: input.walletId,
    authMethod: input.authMethod,
    nonceB64u,
  };
}

export function addAuthMethodInputMatches(
  left: AddAuthMethodInput,
  right: AddAuthMethodInput,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      return right.kind === 'passkey' && left.rpId === right.rpId;
    case 'email_otp':
      return right.kind === 'email_otp' && left.email.toLowerCase() === right.email.toLowerCase();
  }
  return unreachableAddAuthMethodInput(left);
}

export function addSignerSelectionMatches(
  left: AddSignerSelection,
  right: AddSignerSelection,
): boolean {
  if (left.mode !== right.mode) return false;
  switch (left.mode) {
    case 'ecdsa':
      return (
        right.mode === 'ecdsa' &&
        positiveIntegerArraysEqual(left.ecdsa.participantIds, right.ecdsa.participantIds) &&
        thresholdEcdsaChainTargetsEqual(left.ecdsa.chainTargets, right.ecdsa.chainTargets)
      );
    case 'ed25519':
      return right.mode === 'ed25519' && addSignerEd25519SelectionsMatch(left, right);
  }
  return unreachableAddSignerSelection(left);
}

export function parseWalletIdForIntent(raw: unknown): WalletId | null {
  const value = toOptionalTrimmedString(raw);
  if (!value) return null;
  try {
    return walletIdFromString(value);
  } catch {
    return null;
  }
}

export function parseD1StoredRegistrationIntent(raw: unknown): StoredRegistrationIntent | null {
  const record = toRecordValue(raw);
  if (!record || record.kind !== 'intent_allocated') return null;
  const grant = registrationIntentGrantFromString(toOptionalTrimmedString(record.grant) || '');
  const intent = parseD1RegistrationIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  if (!grant || !intent || !digestB64u || !orgId || expiresAtMs === null) return null;
  return {
    kind: 'intent_allocated',
    grant,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    ...intentScopeMetadata(record),
  };
}

export function parseD1RegistrationIntent(raw: unknown): RegistrationIntentV1 | null {
  const record = toRecordValue(raw);
  if (!record || record.version !== 'registration_intent_v1') return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const authMethod = normalizeRegistrationAuthMethodInput(record.authMethod);
  const signerPlan = normalizeRegistrationSignerPlan(record.signerSelection);
  const signerSelection = signerPlan.ok
    ? registrationSignerSetSelectionFromPlan(signerPlan.value, {
        normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
      })
    : signerPlan;
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (!walletId || !authMethod || !signerSelection.ok || !nonceB64u) return null;
  if (record.runtimePolicyScope !== undefined && !runtimePolicyScope) return null;
  if (runtimePolicyScope) {
    return {
      version: 'registration_intent_v1',
      walletId,
      authMethod,
      signerSelection: signerSelection.value,
      runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'registration_intent_v1',
    walletId,
    authMethod,
    signerSelection: signerSelection.value,
    nonceB64u,
  };
}

export function parseD1StoredWalletRegistrationCeremony(
  raw: unknown,
): StoredWalletRegistrationCeremony | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const registrationCeremonyId = toOptionalTrimmedString(record.registrationCeremonyId);
  const intent = parseD1RegistrationIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const authority = parseD1RegistrationAuthority(record.authority);
  const signerPlan = parseStoredRegistrationSignerPlan(record.signerPlan);
  const preparedContext = parseStoredWalletRegistrationPreparedContext(record.preparedContext);
  const intentSignerPlan = intent
    ? parseStoredRegistrationSignerPlan(intent.signerSelection)
    : null;
  const signerState = parseD1StoredWalletRegistrationSignerState(record.signerState);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (
    !registrationCeremonyId ||
    !intent ||
    !digestB64u ||
    !orgId ||
    !signingRootId ||
    !signingRootVersion ||
    expiresAtMs === null ||
    !authority ||
    !signerPlan ||
    !preparedContext ||
    !intentSignerPlan ||
    !storedRegistrationSignerPlansMatch(signerPlan, intentSignerPlan) ||
    (signingRootId && preparedContext.signingRootId !== signingRootId) ||
    (signingRootVersion && preparedContext.signingRootVersion !== signingRootVersion) ||
    !signerState
  ) {
    return null;
  }
  const ceremony: StoredWalletRegistrationCeremony = {
    registrationCeremonyId,
    intent,
    digestB64u,
    signerPlan,
    preparedContext,
    orgId,
    expiresAtMs,
    authority,
    signerState,
  };
  const expectedOrigin = toOptionalTrimmedString(record.expectedOrigin);
  if (signingRootId) ceremony.signingRootId = signingRootId;
  if (signingRootVersion) ceremony.signingRootVersion = signingRootVersion;
  if (expectedOrigin) ceremony.expectedOrigin = expectedOrigin;
  return ceremony;
}

export function parseD1StoredWalletRegistrationFinalizeReplay(
  raw: unknown,
): StoredWalletRegistrationFinalizeReplay | null {
  const record = toRecordValue(raw);
  if (!record || record.kind !== 'wallet_registration_finalize_replay_v1') return null;
  const registrationCeremonyId = toOptionalTrimmedString(record.registrationCeremonyId);
  const idempotencyKey = toOptionalTrimmedString(record.idempotencyKey);
  const response = parseD1WalletRegistrationFinalizeReplayResponse(record.response);
  const createdAtMs = safeInteger(record.createdAtMs);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  if (
    !registrationCeremonyId ||
    !idempotencyKey ||
    !response ||
    createdAtMs === null ||
    createdAtMs <= 0 ||
    expiresAtMs === null ||
    expiresAtMs <= 0
  ) {
    return null;
  }
  return {
    kind: 'wallet_registration_finalize_replay_v1',
    registrationCeremonyId,
    idempotencyKey,
    response,
    createdAtMs,
    expiresAtMs,
  };
}

export function parseD1StoredWalletAddSignerFinalizeReplay(
  raw: unknown,
): StoredWalletAddSignerFinalizeReplay | null {
  const record = toRecordValue(raw);
  if (!record || record.kind !== 'wallet_add_signer_finalize_replay_v1') return null;
  const addSignerCeremonyId = toOptionalTrimmedString(record.addSignerCeremonyId);
  const idempotencyKey = toOptionalTrimmedString(record.idempotencyKey);
  const response = parseD1WalletAddSignerFinalizeReplayResponse(record.response);
  const request = parseD1WalletAddSignerFinalizeRequest(record.request);
  const createdAtMs = safeInteger(record.createdAtMs);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  if (
    !addSignerCeremonyId ||
    !idempotencyKey ||
    !response ||
    !request ||
    request.addSignerCeremonyId !== addSignerCeremonyId ||
    request.idempotencyKey !== idempotencyKey ||
    request.kind !== response.kind ||
    createdAtMs === null ||
    createdAtMs <= 0 ||
    expiresAtMs === null ||
    expiresAtMs <= 0
  ) {
    return null;
  }
  return {
    kind: 'wallet_add_signer_finalize_replay_v1',
    addSignerCeremonyId,
    idempotencyKey,
    request,
    response,
    createdAtMs,
    expiresAtMs,
  };
}

function parseD1WalletAddSignerFinalizeReplayResponse(
  raw: unknown,
): Extract<WalletAddSignerFinalizeResponse, { ok: true }> | null {
  const record = toRecordValue(raw);
  if (!record || record.ok !== true) return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  if (!walletId) return null;
  if (record.kind === 'near_ed25519') {
    const rpId = toOptionalTrimmedString(record.rpId);
    const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
    const ed25519 = parseD1WalletRegistrationFinalizeEd25519(record.ed25519);
    if (!rpId || !credentialIdB64u || !ed25519 || ed25519.session.walletId !== walletId) {
      return null;
    }
    return {
      ok: true,
      kind: 'near_ed25519',
      walletId,
      rpId,
      credentialIdB64u,
      ed25519,
    };
  }
  if (record.kind !== 'evm_family_ecdsa') return null;
  const ecdsa = parseD1WalletRegistrationFinalizeEcdsa(record.ecdsa);
  if (!ecdsa) return null;
  const rpId = toOptionalTrimmedString(record.rpId);
  return rpId
    ? { ok: true, kind: 'evm_family_ecdsa', walletId, rpId, ecdsa }
    : { ok: true, kind: 'evm_family_ecdsa', walletId, ecdsa };
}

function parseD1WalletRegistrationFinalizeReplayResponse(
  raw: unknown,
): D1WalletRegistrationFinalizeSuccess | null {
  const record = toRecordValue(raw);
  if (!record || record.ok !== true) return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const authMethod = parseD1WalletRegistrationFinalizeAuthMethod(record.authMethod);
  const authority = parseWalletAuthAuthority(record.authority);
  if (!walletId || !authMethod || !authority || authority.walletId !== walletId) {
    return null;
  }
  const rpId = toOptionalTrimmedString(record.rpId);
  if (authMethod.kind === 'passkey' && !rpId) return null;
  if (authMethod.kind === 'email_otp' && rpId) return null;
  const ecdsa = parseD1WalletRegistrationFinalizeEcdsa(record.ecdsa);
  if (record.kind === 'evm_family_ecdsa') {
    if (!ecdsa) return null;
    if (authMethod.kind === 'passkey') {
      if (!rpId) return null;
      return {
        ok: true,
        kind: 'evm_family_ecdsa',
        walletId,
        rpId,
        authority,
        authMethod,
        ecdsa,
      };
    }
    return {
      ok: true,
      kind: 'evm_family_ecdsa',
      walletId,
      authority,
      authMethod,
      ecdsa,
    };
  }
  if (record.kind !== 'near_ed25519' && record.kind !== 'near_ed25519_and_evm_family_ecdsa') {
    return null;
  }
  if (record.kind === 'near_ed25519_and_evm_family_ecdsa' && !ecdsa) return null;
  if (record.kind === 'near_ed25519' && record.ecdsa !== undefined) return null;
  const ed25519 = parseD1WalletRegistrationFinalizeEd25519(record.ed25519);
  const authorityScope = parseThresholdEd25519AuthorityScope(record.authorityScope);
  const accountProvisioning = parseD1RegistrationNearAccountProvisioning(
    record.accountProvisioning,
  );
  const resolvedAccount = parseD1ResolvedRegistrationNearAccount(record.resolvedAccount);
  if (
    !ed25519 ||
    !authorityScope ||
    !thresholdEd25519AuthorityScopesMatch(
      authorityScope,
      thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
    ) ||
    !accountProvisioning ||
    !resolvedAccount ||
    ed25519.session.walletId !== walletId ||
    !thresholdEd25519AuthorityScopesMatch(ed25519.session.authorityScope, authorityScope) ||
    ed25519.nearAccountId !== resolvedAccount.nearAccountId ||
    ed25519.nearEd25519SigningKeyId !== resolvedAccount.nearEd25519SigningKeyId ||
    !registrationNearProvisioningMatchesResolution(accountProvisioning, resolvedAccount)
  ) {
    return null;
  }
  if (record.kind === 'near_ed25519_and_evm_family_ecdsa' && ecdsa) {
    if (authMethod.kind === 'passkey') {
      if (!rpId) return null;
      return {
        ok: true,
        kind: 'near_ed25519_and_evm_family_ecdsa',
        walletId,
        rpId,
        authority,
        authMethod,
        authorityScope,
        accountProvisioning,
        resolvedAccount,
        ed25519,
        ecdsa,
      };
    }
    return {
      ok: true,
      kind: 'near_ed25519_and_evm_family_ecdsa',
      walletId,
      authority,
      authMethod,
      authorityScope,
      accountProvisioning,
      resolvedAccount,
      ed25519,
      ecdsa,
    };
  }
  if (authMethod.kind === 'passkey') {
    if (!rpId) return null;
    return {
      ok: true,
      kind: 'near_ed25519',
      walletId,
      rpId,
      authority,
      authMethod,
      authorityScope,
      accountProvisioning,
      resolvedAccount,
      ed25519,
    };
  }
  return {
    ok: true,
    kind: 'near_ed25519',
    walletId,
    authority,
    authMethod,
    authorityScope,
    accountProvisioning,
    resolvedAccount,
    ed25519,
  };
}

function registrationNearProvisioningMatchesResolution(
  provisioning: RegistrationNearAccountProvisioning,
  resolved: ResolvedRegistrationNearAccount,
): boolean {
  switch (provisioning.kind) {
    case 'implicit_account':
      return resolved.kind === 'implicit_account';
    case 'sponsored_named_account':
      return (
        resolved.kind === 'sponsored_named_account' &&
        resolved.nearAccountId === provisioning.requestedAccountId
      );
  }
}

function parseD1WalletRegistrationFinalizeAuthMethod(
  raw: unknown,
): WalletRegistrationFinalizeAuthMethod | null {
  const record = toRecordValue(raw);
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'passkey') {
    const credentialIdB64u = toOptionalTrimmedString(record?.credentialIdB64u);
    const credentialPublicKeyB64u = toOptionalTrimmedString(record?.credentialPublicKeyB64u);
    if (!credentialIdB64u || !credentialPublicKeyB64u) return null;
    return {
      kind: 'passkey',
      credentialIdB64u,
      credentialPublicKeyB64u,
    };
  }
  if (kind === 'email_otp') {
    const registrationAuthorityId = toOptionalTrimmedString(record?.registrationAuthorityId);
    return registrationAuthorityId
      ? {
          kind: 'email_otp',
          registrationAuthorityId,
        }
      : null;
  }
  return null;
}

function parseD1WalletRegistrationFinalizeEd25519(
  raw: unknown,
): WalletRegistrationEd25519YaoPublicResult | null {
  const record = toRecordValue(raw);
  if (!record || record.recoveryExportCapable !== true) return null;
  const signerSlot = safeInteger(record.signerSlot);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(record.nearEd25519SigningKeyId);
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const keyVersion = toOptionalTrimmedString(record.keyVersion);
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  const session = parseD1WalletRegistrationEd25519YaoBootstrapSession(record.session);
  if (
    signerSlot === null ||
    signerSlot <= 0 ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !publicKey?.startsWith('ed25519:') ||
    !relayerKeyId ||
    !keyVersion ||
    !participantIds ||
    participantIds.length !== 2 ||
    !session ||
    session.nearAccountId !== nearAccountId ||
    session.nearEd25519SigningKeyId !== nearEd25519SigningKeyId ||
    session.participantIds[0] !== participantIds[0] ||
    session.participantIds[1] !== participantIds[1]
  ) {
    return null;
  }
  const firstParticipantId = participantIds[0];
  const secondParticipantId = participantIds[1];
  if (firstParticipantId === undefined || secondParticipantId === undefined) return null;
  return {
    signerSlot,
    nearAccountId,
    nearEd25519SigningKeyId,
    publicKey,
    relayerKeyId,
    keyVersion,
    recoveryExportCapable: true,
    participantIds: [firstParticipantId, secondParticipantId],
    session,
  };
}

function parseD1WalletRegistrationEd25519YaoBootstrapSession(
  raw: unknown,
): WalletRegistrationEd25519YaoBootstrapSession | null {
  const record = toRecordValue(raw);
  if (!record || record.sessionKind !== 'jwt') return null;
  const walletSessionJwt = toOptionalTrimmedString(record.walletSessionJwt);
  const walletId = parseWalletIdForIntent(record.walletId);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(record.nearEd25519SigningKeyId);
  const authorityScope = parseThresholdEd25519AuthorityScope(record.authorityScope);
  const thresholdSessionId = toOptionalTrimmedString(record.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(record.signingGrantId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  const remainingUses = safeInteger(record.remainingUses);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    record.routerAbNormalSigning,
  );
  if (
    !walletSessionJwt ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !authorityScope ||
    !thresholdSessionId ||
    !signingGrantId ||
    expiresAtMs === null ||
    expiresAtMs <= 0 ||
    !participantIds ||
    participantIds.length !== 2 ||
    remainingUses === null ||
    remainingUses <= 0 ||
    !signingRootId ||
    !signingRootVersion ||
    !runtimePolicyScope ||
    !routerAbNormalSigning
  ) {
    return null;
  }
  const firstParticipantId = participantIds[0];
  const secondParticipantId = participantIds[1];
  if (firstParticipantId === undefined || secondParticipantId === undefined) return null;
  return {
    sessionKind: 'jwt',
    walletSessionJwt,
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    authorityScope,
    thresholdSessionId,
    signingGrantId,
    expiresAtMs,
    participantIds: [firstParticipantId, secondParticipantId],
    remainingUses,
    signingRootId,
    signingRootVersion,
    runtimePolicyScope,
    routerAbNormalSigning,
  };
}

function parseD1RegistrationNearAccountProvisioning(
  raw: unknown,
): RegistrationNearAccountProvisioning | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  if (record.kind === 'implicit_account' && record.accountIdSource === 'ed25519_public_key') {
    return { kind: 'implicit_account', accountIdSource: 'ed25519_public_key' };
  }
  if (record.kind === 'sponsored_named_account' && record.sponsor === 'relayer') {
    const requestedAccountId = parseNamedNearAccountId(record.requestedAccountId);
    if (!requestedAccountId.ok) return null;
    return {
      kind: 'sponsored_named_account',
      requestedAccountId: requestedAccountId.value,
      sponsor: 'relayer',
    };
  }
  return null;
}

function parseD1ResolvedRegistrationNearAccount(
  raw: unknown,
): ResolvedRegistrationNearAccount | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const nearEd25519SigningKeyId = toOptionalTrimmedString(record.nearEd25519SigningKeyId);
  if (!nearEd25519SigningKeyId) return null;
  const signingKeyId = nearEd25519SigningKeyIdFromString(nearEd25519SigningKeyId);
  if (record.kind === 'implicit_account') {
    const nearAccountId = parseImplicitNearAccountId(record.nearAccountId);
    return nearAccountId.ok
      ? {
          kind: 'implicit_account',
          nearAccountId: nearAccountId.value,
          nearEd25519SigningKeyId: signingKeyId,
        }
      : null;
  }
  if (record.kind === 'sponsored_named_account') {
    const nearAccountId = parseNamedNearAccountId(record.nearAccountId);
    const transactionHash = toOptionalTrimmedString(record.transactionHash);
    return nearAccountId.ok && transactionHash
      ? {
          kind: 'sponsored_named_account',
          nearAccountId: nearAccountId.value,
          nearEd25519SigningKeyId: signingKeyId,
          transactionHash,
        }
      : null;
  }
  return null;
}

function parseD1WalletRegistrationFinalizeEcdsa(
  raw: unknown,
): D1WalletRegistrationFinalizeEcdsaPayload | null {
  const record = toRecordValue(raw);
  if (!record || !Array.isArray(record.walletKeys) || record.walletKeys.length === 0) {
    return null;
  }
  const walletKeys: WalletRegistrationEcdsaWalletKey[] = [];
  for (const walletKey of record.walletKeys) {
    const parsed = parseD1WalletRegistrationEcdsaWalletKey(walletKey);
    if (!parsed) return null;
    walletKeys.push(parsed);
  }
  return { walletKeys };
}

function parseD1WalletRegistrationEcdsaWalletKey(
  raw: unknown,
): WalletRegistrationEcdsaWalletKey | null {
  const record = toRecordValue(raw);
  if (!record || record.keyScope !== 'evm-family') return null;
  const chainTarget = thresholdEcdsaChainTargetFromValue(record.chainTarget);
  const walletId = toOptionalTrimmedString(record.walletId);
  const evmFamilySigningKeySlotId = toOptionalTrimmedString(record.evmFamilySigningKeySlotId);
  const keyHandle = toOptionalTrimmedString(record.keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(record.ecdsaThresholdKeyId);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(record.thresholdEcdsaPublicKeyB64u);
  const thresholdOwnerAddress = toOptionalTrimmedString(record.thresholdOwnerAddress);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const relayerVerifyingShareB64u = toOptionalTrimmedString(record.relayerVerifyingShareB64u);
  const contextBinding32B64u = toOptionalTrimmedString(record.contextBinding32B64u);
  const rawDerivationClientSharePublicKey33B64u = toOptionalTrimmedString(
    record.derivationClientSharePublicKey33B64u,
  );
  const clientShareRetryCounter = safeInteger(record.clientShareRetryCounter);
  const relayerShareRetryCounter = safeInteger(record.relayerShareRetryCounter);
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  let publicCapability;
  try {
    publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(record.publicCapability);
  } catch {
    return null;
  }
  if (
    !chainTarget ||
    !walletId ||
    !evmFamilySigningKeySlotId ||
    !keyHandle ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !thresholdEcdsaPublicKeyB64u ||
    !thresholdOwnerAddress ||
    !relayerKeyId ||
    !relayerVerifyingShareB64u ||
    !contextBinding32B64u ||
    !rawDerivationClientSharePublicKey33B64u ||
    clientShareRetryCounter === null ||
    clientShareRetryCounter < 0 ||
    relayerShareRetryCounter === null ||
    relayerShareRetryCounter < 0 ||
    !participantIds ||
    participantIds.length !== 2 ||
    participantIds[0] !== 1 ||
    participantIds[1] !== 2
  ) {
    return null;
  }
  let derivationClientSharePublicKey33B64u;
  try {
    derivationClientSharePublicKey33B64u = derivationClientSharePublicKey33B64uFromString(
      rawDerivationClientSharePublicKey33B64u,
    );
  } catch {
    return null;
  }
  return {
    keyScope: 'evm-family',
    chainTarget,
    walletId,
    evmFamilySigningKeySlotId,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u,
    thresholdOwnerAddress,
    relayerKeyId,
    relayerVerifyingShareB64u,
    contextBinding32B64u,
    derivationClientSharePublicKey33B64u,
    clientShareRetryCounter,
    relayerShareRetryCounter,
    participantIds: [1, 2],
    publicCapability,
  };
}

function parseD1StoredWalletRegistrationSignerState(
  raw: unknown,
): StoredWalletRegistrationCeremony['signerState'] | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record.kind);
  if (kind === 'signer_set_registration') return parseD1StoredSignerSetRegistrationState(record);
  return null;
}

function parseD1StoredSignerSetRegistrationState(
  record: Record<string, unknown>,
): StoredWalletRegistrationSignerSetState | null {
  if (!Array.isArray(record.branches) || record.branches.length === 0) return null;
  const branches: StoredWalletRegistrationSignerBranch[] = [];
  for (const rawBranch of record.branches) {
    const branch = parseD1StoredSignerSetRegistrationBranch(rawBranch);
    if (!branch) return null;
    branches.push(branch);
  }
  return {
    kind: 'signer_set_registration',
    branches,
  };
}

function parseD1StoredSignerSetRegistrationBranch(
  raw: unknown,
): StoredWalletRegistrationSignerBranch | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record.kind);
  switch (kind) {
    case 'near_ed25519_yao_authorized':
      return parseD1StoredNearEd25519YaoAuthorizedBranch(record);
    case 'evm_family_ecdsa_prepared':
      return parseD1StoredEvmFamilyEcdsaPreparedBranch(record);
    case 'evm_family_ecdsa_pending_activation':
      return parseD1StoredEvmFamilyEcdsaPendingActivationBranch(record);
    case 'evm_family_ecdsa_activated':
      return parseD1StoredEvmFamilyEcdsaActivatedBranch(record);
    default:
      return null;
  }
}

function parseD1StoredNearEd25519YaoAuthorizedBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationNearEd25519YaoAuthorizedBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    record.admissionRequest,
  );
  if (!branchKey || !admissionRequest.ok) return null;
  return {
    kind: 'near_ed25519_yao_authorized',
    branchKey,
    admissionRequest: admissionRequest.value,
  };
}

function parseD1StoredEvmFamilyEcdsaPreparedBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const prepared = parseD1StoredEcdsaRegistrationBase(record);
  if (!branchKey || !prepared) return null;
  return {
    kind: 'evm_family_ecdsa_prepared',
    branchKey,
    derivationKind: prepared.derivationKind,
    chainTargets: prepared.chainTargets,
    prepare: prepared.prepare,
    strictRegistration: prepared.strictRegistration,
  };
}

function parseD1StoredEvmFamilyEcdsaPendingActivationBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationEvmFamilyEcdsaPendingActivationBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const prepared = parseD1StoredEcdsaRegistrationBase(record);
  if (!branchKey || !prepared) return null;
  try {
    return {
      kind: 'evm_family_ecdsa_pending_activation',
      branchKey,
      derivationKind: prepared.derivationKind,
      chainTargets: prepared.chainTargets,
      prepare: prepared.prepare,
      strictRegistration: prepared.strictRegistration,
      registrationRequest: parseRouterAbEcdsaRegistrationRequestV1(record.registrationRequest),
      pendingActivation: parseStoredRouterAbEcdsaPendingActivationV1(record.pendingActivation),
      publicResponse: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(
        record.publicResponse,
      ),
    };
  } catch {
    return null;
  }
}

function parseD1StoredEvmFamilyEcdsaActivatedBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationEvmFamilyEcdsaActivatedBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const prepared = parseD1StoredEcdsaRegistrationBase(record);
  const bootstrap = parseD1EcdsaDerivationServerBootstrapResponse(record.bootstrap);
  if (!branchKey || !prepared || !bootstrap || bootstrap.jwt) return null;
  try {
    return {
      kind: 'evm_family_ecdsa_activated',
      branchKey,
      derivationKind: prepared.derivationKind,
      chainTargets: prepared.chainTargets,
      prepare: prepared.prepare,
      strictRegistration: prepared.strictRegistration,
      registrationRequest: parseRouterAbEcdsaRegistrationRequestV1(record.registrationRequest),
      publicFacts: parseRouterAbEcdsaVerifiedClientActivationFactsV1(record.publicFacts),
      activation: parseRouterAbEcdsaRegistrationActivationReceiptV1(record.activation),
      publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(record.publicCapability),
      bootstrap,
    };
  } catch {
    return null;
  }
}

function parseD1RegistrationSignerBranchKey(raw: unknown): RegistrationSignerBranchKey | null {
  const value = toOptionalTrimmedString(raw);
  if (!value) return null;
  try {
    return registrationSignerBranchKeyFromString(value);
  } catch {
    return null;
  }
}

function parseD1StoredEcdsaRegistrationBase(record: Record<string, unknown>): {
  readonly derivationKind: 'evm_family_ecdsa_keygen';
  readonly chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  readonly prepare: WalletRegistrationEcdsaPrepareContext;
  readonly strictRegistration: WalletRegistrationEcdsaPreparePayload['strictRegistration'];
} | null {
  const derivationKind = toOptionalTrimmedString(record.derivationKind);
  const chainTargets = parseD1ThresholdEcdsaChainTargets(record.chainTargets);
  const prepare = parseD1WalletRegistrationEcdsaPrepare(record.prepare);
  if (derivationKind !== 'evm_family_ecdsa_keygen' || !chainTargets || !prepare) return null;
  try {
    return {
      derivationKind,
      chainTargets,
      prepare,
      strictRegistration: parseRouterAbEcdsaRegistrationRequestFactsV1(record.strictRegistration),
    };
  } catch {
    return null;
  }
}

export function parseD1StoredAddSignerIntent(raw: unknown): StoredAddSignerIntent | null {
  const record = toRecordValue(raw);
  if (!record || record.kind !== 'add_signer_intent_allocated') return null;
  const grant = addSignerIntentGrantFromString(toOptionalTrimmedString(record.grant) || '');
  const intent = parseD1AddSignerIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  if (!grant || !intent || !digestB64u || !orgId || expiresAtMs === null) return null;
  return {
    kind: 'add_signer_intent_allocated',
    grant,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    ...intentScopeMetadata(record),
  };
}

export function parseD1AddSignerIntent(raw: unknown): AddSignerIntentV1 | null {
  const record = toRecordValue(raw);
  if (!record || record.version !== 'add_signer_intent_v1') return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const signerSelection = normalizeAddSignerSelection(record.signerSelection, {
    normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
  });
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (!walletId || !signerSelection.ok || !nonceB64u) return null;
  if (record.runtimePolicyScope !== undefined && !runtimePolicyScope) return null;
  if (runtimePolicyScope) {
    return {
      version: 'add_signer_intent_v1',
      walletId,
      signerSelection: signerSelection.value,
      runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_signer_intent_v1',
    walletId,
    signerSelection: signerSelection.value,
    nonceB64u,
  };
}

export function parseD1StoredWalletAddSignerCeremony(
  raw: unknown,
): StoredWalletAddSignerCeremony | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const addSignerCeremonyId = toOptionalTrimmedString(record.addSignerCeremonyId);
  const intent = parseD1AddSignerIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const auth = parseD1StoredAddSignerAuth(record.auth);
  const signerState = parseD1StoredWalletAddSignerSignerState(record.signerState);
  if (
    !addSignerCeremonyId ||
    !intent ||
    !digestB64u ||
    !orgId ||
    !signingRootId ||
    !signingRootVersion ||
    expiresAtMs === null ||
    !auth ||
    !signerState
  ) {
    return null;
  }
  if (
    (signerState.kind === 'near_ed25519_yao_add_signer_activated' ||
      signerState.kind === 'near_ed25519_yao_add_signer_finalizing') &&
    signerState.finalizeRequest.addSignerCeremonyId !== addSignerCeremonyId
  ) {
    return null;
  }
  const ceremony: StoredWalletAddSignerCeremony = {
    addSignerCeremonyId,
    intent,
    digestB64u,
    orgId,
    signingRootId,
    signingRootVersion,
    expiresAtMs,
    auth,
    signerState,
  };
  return ceremony;
}

function parseD1StoredAddSignerAuth(raw: unknown): StoredWalletAddSignerCeremony['auth'] | null {
  const record = toRecordValue(raw);
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'app_session') return { kind: 'app_session' };
  if (kind === 'webauthn_assertion') {
    const rpId = toOptionalTrimmedString(record?.rpId);
    const credentialIdB64u = toOptionalTrimmedString(record?.credentialIdB64u);
    return rpId && credentialIdB64u ? { kind: 'webauthn_assertion', rpId, credentialIdB64u } : null;
  }
  return null;
}

function parseD1StoredWalletAddSignerSignerState(
  raw: unknown,
): StoredWalletAddSignerCeremony['signerState'] | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record.kind);
  if (kind === 'near_ed25519_yao_add_signer_authorized') {
    const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
      record.admissionRequest,
    );
    return admissionRequest.ok
      ? {
          kind: 'near_ed25519_yao_add_signer_authorized',
          admissionRequest: admissionRequest.value,
        }
      : null;
  }
  if (
    kind === 'near_ed25519_yao_add_signer_activated' ||
    kind === 'near_ed25519_yao_add_signer_finalizing'
  ) {
    const activation = parseD1StoredEd25519YaoAddSignerActivation(record);
    if (!activation) return null;
    if (kind === 'near_ed25519_yao_add_signer_activated') {
      return {
        kind: 'near_ed25519_yao_add_signer_activated',
        ...activation,
      };
    }
    const response = parseD1WalletAddSignerFinalizeReplayResponse(record.response);
    const signer = parseWalletEd25519SignerRecord(record.signer);
    const finalizingAtMs = safeInteger(record.finalizingAtMs);
    if (
      !response ||
      response.kind !== 'near_ed25519' ||
      !signer ||
      finalizingAtMs === null ||
      finalizingAtMs <= 0
    ) {
      return null;
    }
    return {
      kind: 'near_ed25519_yao_add_signer_finalizing',
      ...activation,
      response,
      signer,
      finalizingAtMs,
    };
  }
  if (kind === 'ecdsa_add_signer_prepared') {
    return parseD1StoredEcdsaAddSignerPrepared(record);
  }
  if (kind === 'ecdsa_add_signer_pending_activation') {
    return parseD1StoredEcdsaAddSignerPendingActivation(record);
  }
  if (kind === 'ecdsa_add_signer_activated') {
    return parseD1StoredEcdsaAddSignerActivated(record);
  }
  return null;
}

function parseD1StoredEd25519YaoAddSignerActivation(
  record: Record<string, unknown>,
): Omit<
  Extract<
    StoredWalletAddSignerCeremony['signerState'],
    { kind: 'near_ed25519_yao_add_signer_activated' }
  >,
  'kind'
> | null {
  const activation = toRecordValue(record.activation);
  const finalizeRequest = parseD1WalletAddSignerFinalizeRequest(record.finalizeRequest);
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    activation?.admissionRequest,
  );
  const admissionReceipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
    activation?.admissionReceipt,
  );
  const result = parseRouterAbEd25519YaoRegistrationActivationResultV1(activation?.result);
  if (
    !finalizeRequest ||
    finalizeRequest.kind !== 'near_ed25519' ||
    !admissionRequest.ok ||
    !admissionReceipt.ok ||
    !result.ok
  ) {
    return null;
  }
  const lifecycleId = finalizeRequest.activationReference.lifecycleId;
  const sessionId = finalizeRequest.activationReference.sessionId;
  if (
    !sessionId ||
    lifecycleId !== admissionRequest.value.scope.lifecycle_id ||
    !d1ByteArraysEqual(sessionId, admissionReceipt.value.binding.session_id) ||
    !d1ByteArraysEqual(sessionId, result.value.binding.session_id)
  ) {
    return null;
  }
  return {
    finalizeRequest,
    activation: {
      admissionRequest: admissionRequest.value,
      admissionReceipt: admissionReceipt.value,
      result: result.value,
    },
  };
}

function parseD1WalletAddSignerFinalizeRequest(
  raw: unknown,
): StoredWalletAddSignerFinalizeRequest | null {
  const record = toRecordValue(raw);
  const addSignerCeremonyId = toOptionalTrimmedString(record?.addSignerCeremonyId);
  const idempotencyKey = toOptionalTrimmedString(record?.idempotencyKey);
  if (!record || !addSignerCeremonyId || !idempotencyKey) return null;
  if (record.kind === 'near_ed25519') {
    const activationReference = toRecordValue(record.activationReference);
    const lifecycleId = toOptionalTrimmedString(activationReference?.lifecycleId);
    const sessionId = parseD1Bytes32(activationReference?.sessionId);
    if (!lifecycleId || !sessionId) return null;
    return {
      kind: 'near_ed25519',
      addSignerCeremonyId,
      idempotencyKey,
      activationReference: { lifecycleId, sessionId },
    };
  }
  if (
    record.kind !== 'evm_family_ecdsa' ||
    !Array.isArray(record.expectedKeyHandles) ||
    record.expectedKeyHandles.length !== 1
  ) {
    return null;
  }
  const expectedKeyHandle = toOptionalTrimmedString(record.expectedKeyHandles[0]);
  if (!expectedKeyHandle) return null;
  return {
    kind: 'evm_family_ecdsa',
    addSignerCeremonyId,
    idempotencyKey,
    expectedKeyHandles: [expectedKeyHandle],
  };
}

function parseD1Bytes32(raw: unknown): number[] | null {
  if (!Array.isArray(raw) || raw.length !== 32) return null;
  const bytes: number[] = [];
  for (const byte of raw) {
    if (!Number.isInteger(byte) || Number(byte) < 0 || Number(byte) > 255) return null;
    bytes.push(Number(byte));
  }
  return bytes;
}

function d1ByteArraysEqual(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function parseD1StoredEcdsaAddSignerPrepared(
  record: Record<string, unknown>,
): Extract<
  StoredWalletAddSignerCeremony['signerState'],
  { kind: 'ecdsa_add_signer_prepared' }
> | null {
  const prepared = parseD1StoredEcdsaRegistrationBase(record);
  if (!prepared) return null;
  return {
    kind: 'ecdsa_add_signer_prepared',
    derivationKind: prepared.derivationKind,
    chainTargets: prepared.chainTargets,
    prepare: prepared.prepare,
    strictRegistration: prepared.strictRegistration,
  };
}

function parseD1StoredEcdsaAddSignerPendingActivation(
  record: Record<string, unknown>,
): Extract<
  StoredWalletAddSignerCeremony['signerState'],
  { kind: 'ecdsa_add_signer_pending_activation' }
> | null {
  const prepared = parseD1StoredEcdsaRegistrationBase(record);
  if (!prepared) return null;
  try {
    return {
      kind: 'ecdsa_add_signer_pending_activation',
      derivationKind: prepared.derivationKind,
      chainTargets: prepared.chainTargets,
      prepare: prepared.prepare,
      strictRegistration: prepared.strictRegistration,
      registrationRequest: parseRouterAbEcdsaRegistrationRequestV1(record.registrationRequest),
      pendingActivation: parseStoredRouterAbEcdsaPendingActivationV1(record.pendingActivation),
      publicResponse: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(
        record.publicResponse,
      ),
    };
  } catch {
    return null;
  }
}

function parseD1StoredEcdsaAddSignerActivated(
  record: Record<string, unknown>,
): Extract<
  StoredWalletAddSignerCeremony['signerState'],
  { kind: 'ecdsa_add_signer_activated' }
> | null {
  const prepared = parseD1StoredEcdsaRegistrationBase(record);
  const bootstrap = parseD1EcdsaDerivationServerBootstrapResponse(record.bootstrap);
  if (!prepared || !bootstrap || bootstrap.jwt) return null;
  try {
    return {
      kind: 'ecdsa_add_signer_activated',
      derivationKind: prepared.derivationKind,
      chainTargets: prepared.chainTargets,
      prepare: prepared.prepare,
      strictRegistration: prepared.strictRegistration,
      registrationRequest: parseRouterAbEcdsaRegistrationRequestV1(record.registrationRequest),
      publicFacts: parseRouterAbEcdsaVerifiedClientActivationFactsV1(record.publicFacts),
      activation: parseRouterAbEcdsaRegistrationActivationReceiptV1(record.activation),
      publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(record.publicCapability),
      bootstrap,
    };
  } catch {
    return null;
  }
}

function parseD1ThresholdEcdsaChainTargets(
  raw: unknown,
): readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]] | null {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  for (const rawTarget of raw) {
    const target = thresholdEcdsaChainTargetFromValue(rawTarget);
    if (!target) return null;
    const targetKey = thresholdEcdsaChainTargetKey(target);
    if (seen.has(targetKey)) return null;
    seen.add(targetKey);
    targets.push(target);
  }
  const firstTarget = targets[0];
  return firstTarget ? [firstTarget, ...targets.slice(1)] : null;
}

function parseD1EcdsaParticipantPair(raw: unknown): readonly [1, 2] | null {
  if (!Array.isArray(raw) || raw.length !== 2 || raw[0] !== 1 || raw[1] !== 2) {
    return null;
  }
  return [1, 2];
}

function parseD1WalletRegistrationEcdsaPrepare(
  raw: unknown,
): WalletRegistrationEcdsaPrepareContext | null {
  const record = toRecordValue(raw);
  if (!record || record.formatVersion !== 'ecdsa-derivation-role-local') return null;
  if (record.keyScope !== 'evm-family') return null;
  const registrationPreparationId = toOptionalTrimmedString(record.registrationPreparationId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const evmFamilySigningKeySlotId = toOptionalTrimmedString(record.evmFamilySigningKeySlotId);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(record.ecdsaThresholdKeyId);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const requestId = toOptionalTrimmedString(record.requestId);
  const thresholdSessionId = toOptionalTrimmedString(record.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(record.signingGrantId);
  const ttlMs = safeInteger(record.ttlMs);
  const remainingUses = safeInteger(record.remainingUses);
  const participantIds = parseD1EcdsaParticipantPair(record.participantIds);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (
    !registrationPreparationId ||
    !walletId ||
    !evmFamilySigningKeySlotId ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !relayerKeyId ||
    !requestId ||
    !thresholdSessionId ||
    !signingGrantId ||
    ttlMs === null ||
    remainingUses === null ||
    !participantIds ||
    !runtimePolicyScope
  ) {
    return null;
  }
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    registrationPreparationId: registrationPreparationIdFromString(registrationPreparationId),
    requestId,
    thresholdSessionId,
    signingGrantId,
    ttlMs,
    remainingUses,
    participantIds,
    runtimePolicyScope,
  };
}

function parseD1EcdsaDerivationServerBootstrapResponse(
  raw: unknown,
): EcdsaDerivationServerBootstrapResponse | null {
  const record = toRecordValue(raw);
  if (!record || record.formatVersion !== 'ecdsa-derivation-role-local') return null;
  const walletId = toOptionalTrimmedString(record.walletId);
  const evmFamilySigningKeySlotId = toOptionalTrimmedString(record.evmFamilySigningKeySlotId);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(record.ecdsaThresholdKeyId);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const applicationBindingDigestB64u = toOptionalTrimmedString(record.applicationBindingDigestB64u);
  const contextBinding32B64u = toOptionalTrimmedString(record.contextBinding32B64u);
  const publicIdentity = parseD1EcdsaDerivationPublicIdentity(record.publicIdentity);
  const clientShareRetryCounter = safeInteger(record.clientShareRetryCounter);
  const relayerShareRetryCounter = safeInteger(record.relayerShareRetryCounter);
  const publicTranscriptDigest32B64u = toOptionalTrimmedString(record.publicTranscriptDigest32B64u);
  const keyHandle = toOptionalTrimmedString(record.keyHandle);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(record.thresholdEcdsaPublicKeyB64u);
  const ethereumAddress = toOptionalTrimmedString(record.ethereumAddress);
  const relayerVerifyingShareB64u = toOptionalTrimmedString(record.relayerVerifyingShareB64u);
  const participantIds = parseD1EcdsaParticipantPair(record.participantIds);
  const thresholdSessionId = toOptionalTrimmedString(record.thresholdSessionId);
  const activationEpochResult = parseRootShareEpoch(record.activationEpoch);
  const activationEpoch = activationEpochResult.ok ? activationEpochResult.value : null;
  const signingGrantId = toOptionalTrimmedString(record.signingGrantId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const expiresAt = toOptionalTrimmedString(record.expiresAt);
  const remainingUses = safeInteger(record.remainingUses);
  if (
    !walletId ||
    !evmFamilySigningKeySlotId ||
    !ecdsaThresholdKeyId ||
    !relayerKeyId ||
    !applicationBindingDigestB64u ||
    !contextBinding32B64u ||
    !publicIdentity ||
    clientShareRetryCounter === null ||
    relayerShareRetryCounter === null ||
    !publicTranscriptDigest32B64u ||
    !keyHandle ||
    !signingRootId ||
    !signingRootVersion ||
    !thresholdEcdsaPublicKeyB64u ||
    !ethereumAddress ||
    !relayerVerifyingShareB64u ||
    !participantIds ||
    !thresholdSessionId ||
    !activationEpoch ||
    !signingGrantId ||
    expiresAtMs === null ||
    !expiresAt ||
    remainingUses === null
  ) {
    return null;
  }
  const bootstrap: EcdsaDerivationServerBootstrapResponse = {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    applicationBindingDigestB64u,
    contextBinding32B64u,
    publicIdentity,
    clientShareRetryCounter,
    relayerShareRetryCounter,
    publicTranscriptDigest32B64u,
    keyHandle,
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    participantIds: [...participantIds],
    thresholdSessionId,
    activationEpoch,
    signingGrantId,
    expiresAtMs,
    expiresAt,
    remainingUses,
  };
  const jwt = toOptionalTrimmedString(record.jwt);
  if (jwt) bootstrap.jwt = jwt;
  return bootstrap;
}

function parseD1EcdsaDerivationPublicIdentity(raw: unknown): D1EcdsaPublicIdentity | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const derivationClientSharePublicKey33B64u = toOptionalTrimmedString(
    record.derivationClientSharePublicKey33B64u,
  );
  const relayerPublicKey33B64u = toOptionalTrimmedString(record.relayerPublicKey33B64u);
  const groupPublicKey33B64u = toOptionalTrimmedString(record.groupPublicKey33B64u);
  const ethereumAddress = toOptionalTrimmedString(record.ethereumAddress);
  if (
    !derivationClientSharePublicKey33B64u ||
    !relayerPublicKey33B64u ||
    !groupPublicKey33B64u ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    derivationClientSharePublicKey33B64u:
      derivationClientSharePublicKey33B64u as D1EcdsaClientSharePublicKey,
    relayerPublicKey33B64u: relayerPublicKey33B64u as D1EcdsaRelayerPublicKey,
    groupPublicKey33B64u,
    ethereumAddress,
  };
}

export function runtimePolicyScopeMatches(
  left: RuntimePolicyScopeLike | undefined,
  right: RuntimePolicyScopeLike | undefined,
): boolean {
  if (!left && !right) return true;
  if (!left || !right) return false;
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

export function positiveIntegerArraysEqual(
  left: readonly number[],
  right: readonly number[],
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export function thresholdEcdsaChainTargetsEqual(
  left: readonly unknown[],
  right: readonly unknown[],
): boolean {
  const leftTargets = normalizeThresholdEcdsaChainTargets(left);
  const rightTargets = normalizeThresholdEcdsaChainTargets(right);
  if (!leftTargets || !rightTargets || leftTargets.length !== rightTargets.length) {
    return false;
  }
  for (let index = 0; index < leftTargets.length; index += 1) {
    if (
      thresholdEcdsaChainTargetKey(leftTargets[index]) !==
      thresholdEcdsaChainTargetKey(rightTargets[index])
    ) {
      return false;
    }
  }
  return true;
}

export function isMatchingD1EcdsaClientBootstrap(input: {
  readonly expected: WalletRegistrationEcdsaPrepareContext;
  readonly actual: WalletRegistrationEcdsaClientBootstrap;
}): boolean {
  const expected = input.expected;
  const actual = input.actual;
  return (
    actual.formatVersion === expected.formatVersion &&
    actual.walletId === expected.walletId &&
    actual.evmFamilySigningKeySlotId === expected.evmFamilySigningKeySlotId &&
    actual.ecdsaThresholdKeyId === expected.ecdsaThresholdKeyId &&
    actual.signingRootId === expected.signingRootId &&
    actual.signingRootVersion === expected.signingRootVersion &&
    actual.keyScope === expected.keyScope &&
    actual.relayerKeyId === expected.relayerKeyId &&
    actual.registrationPreparationId === expected.registrationPreparationId &&
    actual.requestId === expected.requestId &&
    actual.thresholdSessionId === expected.thresholdSessionId &&
    actual.signingGrantId === expected.signingGrantId &&
    actual.ttlMs === expected.ttlMs &&
    actual.remainingUses === expected.remainingUses &&
    positiveIntegerArraysEqual(actual.participantIds, expected.participantIds) &&
    runtimePolicyScopeMatches(actual.runtimePolicyScope, expected.runtimePolicyScope)
  );
}

export function toD1EcdsaDerivationClientBootstrapRequest(
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap,
): EcdsaDerivationClientBootstrapRequest {
  return {
    formatVersion: clientBootstrap.formatVersion,
    walletId: clientBootstrap.walletId,
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      clientBootstrap.evmFamilySigningKeySlotId,
    ),
    ecdsaThresholdKeyId: clientBootstrap.ecdsaThresholdKeyId,
    signingRootId: clientBootstrap.signingRootId,
    signingRootVersion: clientBootstrap.signingRootVersion,
    keyScope: clientBootstrap.keyScope,
    relayerKeyId: clientBootstrap.relayerKeyId,
    registrationPreparationId: clientBootstrap.registrationPreparationId,
    derivationClientSharePublicKey33B64u: clientBootstrap.derivationClientSharePublicKey33B64u,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: clientBootstrap.requestId,
    sessionId: clientBootstrap.thresholdSessionId,
    signingGrantId: clientBootstrap.signingGrantId,
    ttlMs: clientBootstrap.ttlMs,
    remainingUses: clientBootstrap.remainingUses,
    participantIds: [...clientBootstrap.participantIds],
    runtimePolicyScope: clientBootstrap.runtimePolicyScope,
  };
}

export type D1EcdsaWalletKeyBuildResult =
  | {
      readonly ok: true;
      readonly walletKeys: WalletRegistrationEcdsaWalletKey[];
    }
  | {
      readonly ok: false;
      readonly code: 'incomplete_ecdsa_wallet_key';
      readonly message: string;
    };

type RequiredD1EcdsaWalletKeyBootstrapFields = {
  readonly walletId: string | undefined;
  readonly evmFamilySigningKeySlotId: string | undefined;
  readonly keyHandle: string | undefined;
  readonly ecdsaThresholdKeyId: string | undefined;
  readonly signingRootId: string | undefined;
  readonly signingRootVersion: string | undefined;
  readonly thresholdEcdsaPublicKeyB64u: string | undefined;
  readonly thresholdOwnerAddress: string | undefined;
  readonly relayerKeyId: string | undefined;
  readonly relayerVerifyingShareB64u: string | undefined;
  readonly contextBinding32B64u: string | undefined;
  readonly derivationClientSharePublicKey33B64u: string | undefined;
  readonly clientShareRetryCounter: number | undefined;
  readonly relayerShareRetryCounter: number | undefined;
};

type CompleteD1EcdsaWalletKeyBootstrapFields = {
  readonly walletId: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly keyHandle: string;
  readonly ecdsaThresholdKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly thresholdEcdsaPublicKeyB64u: string;
  readonly thresholdOwnerAddress: string;
  readonly relayerKeyId: string;
  readonly relayerVerifyingShareB64u: string;
  readonly contextBinding32B64u: string;
  readonly derivationClientSharePublicKey33B64u: WalletRegistrationEcdsaWalletKey['derivationClientSharePublicKey33B64u'];
  readonly clientShareRetryCounter: number;
  readonly relayerShareRetryCounter: number;
};

type D1EcdsaWalletKeyBootstrapFieldCheck =
  | {
      readonly ok: true;
      readonly value: CompleteD1EcdsaWalletKeyBootstrapFields;
    }
  | {
      readonly ok: false;
      readonly missingField: keyof RequiredD1EcdsaWalletKeyBootstrapFields;
    };

export function buildD1EcdsaWalletKeysFromBootstrap(input: {
  readonly bootstraps: readonly {
    readonly chainTarget: ThresholdEcdsaChainTarget;
    readonly bootstrap: EcdsaDerivationServerBootstrapResponse;
  }[];
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly errorContext: string;
}): D1EcdsaWalletKeyBuildResult {
  if (input.bootstraps.length === 0) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} has no ECDSA chain targets`,
    };
  }
  const walletKeys: WalletRegistrationEcdsaWalletKey[] = [];
  const seen = new Set<string>();
  for (const targetBootstrap of input.bootstraps) {
    const targetKey = thresholdEcdsaChainTargetKey(targetBootstrap.chainTarget);
    if (seen.has(targetKey)) {
      return {
        ok: false,
        code: 'incomplete_ecdsa_wallet_key',
        message: `${input.errorContext} returned duplicate ECDSA wallet key material for ${targetKey}`,
      };
    }
    seen.add(targetKey);
    const walletKey = buildD1EcdsaWalletKeyFromBootstrap({
      bootstrap: targetBootstrap.bootstrap,
      chainTarget: targetBootstrap.chainTarget,
      publicCapability: input.publicCapability,
      errorContext: input.errorContext,
    });
    if (!walletKey.ok) return walletKey;
    walletKeys.push(walletKey.walletKey);
  }
  const sharedMaterial = requireSharedD1EvmFamilyWalletKeyMaterial({
    walletKeys,
    errorContext: input.errorContext,
  });
  if (!sharedMaterial.ok) return sharedMaterial;
  return {
    ok: true,
    walletKeys,
  };
}

function requireSharedD1EvmFamilyWalletKeyMaterial(input: {
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  readonly errorContext: string;
}):
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code: 'incomplete_ecdsa_wallet_key';
      readonly message: string;
    } {
  const first = input.walletKeys[0];
  if (!first) return { ok: true };
  for (const walletKey of input.walletKeys.slice(1)) {
    const mismatch = firstD1EvmFamilyWalletKeyMaterialMismatch(first, walletKey);
    if (!mismatch) continue;
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} returned partitioned EVM-family wallet key material: ${mismatch}`,
    };
  }
  return { ok: true };
}

function firstD1EvmFamilyWalletKeyMaterialMismatch(
  left: WalletRegistrationEcdsaWalletKey,
  right: WalletRegistrationEcdsaWalletKey,
): string | null {
  if (left.keyScope !== 'evm-family' || right.keyScope !== 'evm-family') return 'keyScope';
  if (left.walletId !== right.walletId) return 'walletId';
  if (left.evmFamilySigningKeySlotId !== right.evmFamilySigningKeySlotId) {
    return 'evmFamilySigningKeySlotId';
  }
  if (left.keyHandle !== right.keyHandle) return 'keyHandle';
  if (left.ecdsaThresholdKeyId !== right.ecdsaThresholdKeyId) return 'ecdsaThresholdKeyId';
  if (left.signingRootId !== right.signingRootId) return 'signingRootId';
  if (left.signingRootVersion !== right.signingRootVersion) return 'signingRootVersion';
  if (left.thresholdEcdsaPublicKeyB64u !== right.thresholdEcdsaPublicKeyB64u) {
    return 'thresholdEcdsaPublicKeyB64u';
  }
  if (
    normalizeD1EvmFamilyOwnerAddress(left.thresholdOwnerAddress) !==
    normalizeD1EvmFamilyOwnerAddress(right.thresholdOwnerAddress)
  ) {
    return 'thresholdOwnerAddress';
  }
  if (left.relayerKeyId !== right.relayerKeyId) return 'relayerKeyId';
  if (left.relayerVerifyingShareB64u !== right.relayerVerifyingShareB64u) {
    return 'relayerVerifyingShareB64u';
  }
  if (left.contextBinding32B64u !== right.contextBinding32B64u) {
    return 'contextBinding32B64u';
  }
  if (left.derivationClientSharePublicKey33B64u !== right.derivationClientSharePublicKey33B64u) {
    return 'derivationClientSharePublicKey33B64u';
  }
  if (left.clientShareRetryCounter !== right.clientShareRetryCounter) {
    return 'clientShareRetryCounter';
  }
  if (left.relayerShareRetryCounter !== right.relayerShareRetryCounter) {
    return 'relayerShareRetryCounter';
  }
  if (
    d1EvmFamilyParticipantKey(left.participantIds) !==
    d1EvmFamilyParticipantKey(right.participantIds)
  ) {
    return 'participantIds';
  }
  return null;
}

function normalizeD1EvmFamilyOwnerAddress(value: string): string {
  return value.trim().toLowerCase();
}

function d1EvmFamilyParticipantKey(participantIds: readonly number[]): string {
  return participantIds.join(',');
}

function buildD1EcdsaWalletKeyFromBootstrap(input: {
  readonly bootstrap: EcdsaDerivationServerBootstrapResponse;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly errorContext: string;
}):
  | {
      readonly ok: true;
      readonly walletKey: WalletRegistrationEcdsaWalletKey;
    }
  | {
      readonly ok: false;
      readonly code: 'incomplete_ecdsa_wallet_key';
      readonly message: string;
    } {
  const bootstrap = input.bootstrap;
  const required: RequiredD1EcdsaWalletKeyBootstrapFields = {
    walletId: toOptionalTrimmedString(bootstrap.walletId),
    evmFamilySigningKeySlotId: toOptionalTrimmedString(bootstrap.evmFamilySigningKeySlotId),
    keyHandle: toOptionalTrimmedString(bootstrap.keyHandle),
    ecdsaThresholdKeyId: toOptionalTrimmedString(bootstrap.ecdsaThresholdKeyId),
    signingRootId: toOptionalTrimmedString(bootstrap.signingRootId),
    signingRootVersion: toOptionalTrimmedString(bootstrap.signingRootVersion),
    thresholdEcdsaPublicKeyB64u: toOptionalTrimmedString(bootstrap.thresholdEcdsaPublicKeyB64u),
    thresholdOwnerAddress: toOptionalTrimmedString(bootstrap.ethereumAddress),
    relayerKeyId: toOptionalTrimmedString(bootstrap.relayerKeyId),
    relayerVerifyingShareB64u: toOptionalTrimmedString(bootstrap.relayerVerifyingShareB64u),
    contextBinding32B64u: toOptionalTrimmedString(bootstrap.contextBinding32B64u),
    derivationClientSharePublicKey33B64u: toOptionalTrimmedString(
      bootstrap.publicIdentity?.derivationClientSharePublicKey33B64u,
    ),
    clientShareRetryCounter: safeInteger(bootstrap.clientShareRetryCounter) ?? undefined,
    relayerShareRetryCounter: safeInteger(bootstrap.relayerShareRetryCounter) ?? undefined,
  };
  const complete = requireD1EcdsaWalletKeyBootstrapFields(required);
  if (!complete.ok) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} returned incomplete ECDSA wallet key material: ${complete.missingField}`,
    };
  }
  const participantIds = parseD1PositiveIntegerArray(bootstrap.participantIds);
  if (
    !participantIds ||
    participantIds.length !== 2 ||
    participantIds[0] !== 1 ||
    participantIds[1] !== 2
  ) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} returned incomplete ECDSA wallet key material: participantIds`,
    };
  }
  return {
    ok: true,
    walletKey: d1EcdsaWalletKeyForChainTarget({
      required: complete.value,
      participantIds,
      chainTarget: input.chainTarget,
      publicCapability: input.publicCapability,
    }),
  };
}

function requireD1EcdsaWalletKeyBootstrapFields(
  fields: RequiredD1EcdsaWalletKeyBootstrapFields,
): D1EcdsaWalletKeyBootstrapFieldCheck {
  if (!fields.walletId) return { ok: false, missingField: 'walletId' };
  if (!fields.evmFamilySigningKeySlotId)
    return { ok: false, missingField: 'evmFamilySigningKeySlotId' };
  if (!fields.keyHandle) return { ok: false, missingField: 'keyHandle' };
  if (!fields.ecdsaThresholdKeyId) {
    return { ok: false, missingField: 'ecdsaThresholdKeyId' };
  }
  if (!fields.signingRootId) return { ok: false, missingField: 'signingRootId' };
  if (!fields.signingRootVersion) return { ok: false, missingField: 'signingRootVersion' };
  if (!fields.thresholdEcdsaPublicKeyB64u) {
    return { ok: false, missingField: 'thresholdEcdsaPublicKeyB64u' };
  }
  if (!fields.thresholdOwnerAddress) {
    return { ok: false, missingField: 'thresholdOwnerAddress' };
  }
  if (!fields.relayerKeyId) return { ok: false, missingField: 'relayerKeyId' };
  if (!fields.relayerVerifyingShareB64u) {
    return { ok: false, missingField: 'relayerVerifyingShareB64u' };
  }
  if (!fields.contextBinding32B64u) {
    return { ok: false, missingField: 'contextBinding32B64u' };
  }
  if (!fields.derivationClientSharePublicKey33B64u) {
    return { ok: false, missingField: 'derivationClientSharePublicKey33B64u' };
  }
  if (fields.clientShareRetryCounter === undefined || fields.clientShareRetryCounter < 0) {
    return { ok: false, missingField: 'clientShareRetryCounter' };
  }
  if (fields.relayerShareRetryCounter === undefined || fields.relayerShareRetryCounter < 0) {
    return { ok: false, missingField: 'relayerShareRetryCounter' };
  }
  let derivationClientSharePublicKey33B64u;
  try {
    derivationClientSharePublicKey33B64u = derivationClientSharePublicKey33B64uFromString(
      fields.derivationClientSharePublicKey33B64u,
    );
  } catch {
    return { ok: false, missingField: 'derivationClientSharePublicKey33B64u' };
  }
  return {
    ok: true,
    value: {
      walletId: fields.walletId,
      evmFamilySigningKeySlotId: fields.evmFamilySigningKeySlotId,
      keyHandle: fields.keyHandle,
      ecdsaThresholdKeyId: fields.ecdsaThresholdKeyId,
      signingRootId: fields.signingRootId,
      signingRootVersion: fields.signingRootVersion,
      thresholdEcdsaPublicKeyB64u: fields.thresholdEcdsaPublicKeyB64u,
      thresholdOwnerAddress: fields.thresholdOwnerAddress,
      relayerKeyId: fields.relayerKeyId,
      relayerVerifyingShareB64u: fields.relayerVerifyingShareB64u,
      contextBinding32B64u: fields.contextBinding32B64u,
      derivationClientSharePublicKey33B64u,
      clientShareRetryCounter: fields.clientShareRetryCounter,
      relayerShareRetryCounter: fields.relayerShareRetryCounter,
    },
  };
}

function d1EcdsaWalletKeyForChainTarget(input: {
  readonly required: CompleteD1EcdsaWalletKeyBootstrapFields;
  readonly participantIds: readonly number[];
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
}): WalletRegistrationEcdsaWalletKey {
  return {
    keyScope: 'evm-family',
    chainTarget: input.chainTarget,
    walletId: input.required.walletId,
    evmFamilySigningKeySlotId: input.required.evmFamilySigningKeySlotId,
    keyHandle: input.required.keyHandle,
    ecdsaThresholdKeyId: input.required.ecdsaThresholdKeyId,
    signingRootId: input.required.signingRootId,
    signingRootVersion: input.required.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: input.required.thresholdEcdsaPublicKeyB64u,
    thresholdOwnerAddress: input.required.thresholdOwnerAddress,
    relayerKeyId: input.required.relayerKeyId,
    relayerVerifyingShareB64u: input.required.relayerVerifyingShareB64u,
    contextBinding32B64u: input.required.contextBinding32B64u,
    derivationClientSharePublicKey33B64u: input.required.derivationClientSharePublicKey33B64u,
    clientShareRetryCounter: input.required.clientShareRetryCounter,
    relayerShareRetryCounter: input.required.relayerShareRetryCounter,
    participantIds: [1, 2],
    publicCapability: input.publicCapability,
  };
}

export function buildD1WalletRecord(input: {
  readonly walletId: WalletId;
  readonly now: number;
}): WalletRecord {
  return {
    version: 'wallet_v1',
    walletId: input.walletId,
    createdAtMs: input.now,
    updatedAtMs: input.now,
  };
}

export function buildD1WalletEcdsaSignerRecords(input: {
  readonly walletId: WalletId;
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  readonly now: number;
}): WalletEcdsaSignerRecord[] {
  const records: WalletEcdsaSignerRecord[] = [];
  for (const walletKey of input.walletKeys) {
    records.push(
      buildWalletEcdsaSignerRecord({
        walletId: input.walletId,
        walletKey,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      }),
    );
  }
  return records;
}

export { deriveEvmFamilySigningKeySlotId };

export function parseD1PositiveIntegerArray(raw: unknown): number[] | null {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const values: number[] = [];
  for (const item of raw) {
    const value = safeInteger(item);
    if (value === null || value <= 0) return null;
    values.push(value);
  }
  return values;
}

export function parseD1StoredAddAuthMethodIntent(raw: unknown): StoredAddAuthMethodIntent | null {
  const record = toRecordValue(raw);
  if (!record || record.kind !== 'add_auth_method_intent_allocated') return null;
  const grant = addAuthMethodIntentGrantFromString(toOptionalTrimmedString(record.grant) || '');
  const intent = parseD1AddAuthMethodIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  if (!grant || !intent || !digestB64u || !orgId || expiresAtMs === null) return null;
  return {
    kind: 'add_auth_method_intent_allocated',
    grant,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    ...intentScopeMetadata(record),
  };
}

export function parseD1StoredWalletAddAuthMethodCeremony(
  raw: unknown,
): StoredWalletAddAuthMethodCeremony | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const addAuthMethodCeremonyId = toOptionalTrimmedString(record.addAuthMethodCeremonyId);
  const intent = parseD1AddAuthMethodIntent(record.intent);
  const digestB64u = toOptionalTrimmedString(record.digestB64u);
  const orgId = toOptionalTrimmedString(record.orgId);
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const auth = parseD1StoredAddAuthMethodAuth(record.auth);
  const authority = parseD1RegistrationAuthority(record.authority);
  if (
    !addAuthMethodCeremonyId ||
    !intent ||
    !digestB64u ||
    !orgId ||
    expiresAtMs === null ||
    !auth ||
    !authority
  ) {
    return null;
  }
  return {
    addAuthMethodCeremonyId,
    intent,
    digestB64u,
    orgId,
    ...(toOptionalTrimmedString(record.expectedOrigin)
      ? { expectedOrigin: toOptionalTrimmedString(record.expectedOrigin) }
      : {}),
    expiresAtMs,
    auth,
    authority,
  };
}

export function parseD1AddAuthMethodIntent(raw: unknown): AddAuthMethodIntentV1 | null {
  const record = toRecordValue(raw);
  if (!record || record.version !== 'add_auth_method_intent_v1') return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const authMethod = normalizeAddAuthMethodInput(record.authMethod);
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (!walletId || !authMethod || !nonceB64u) return null;
  if (record.runtimePolicyScope !== undefined && !runtimePolicyScope) return null;
  if (runtimePolicyScope) {
    return {
      version: 'add_auth_method_intent_v1',
      walletId,
      authMethod,
      runtimePolicyScope,
      nonceB64u,
    };
  }
  return {
    version: 'add_auth_method_intent_v1',
    walletId,
    authMethod,
    nonceB64u,
  };
}

export function parseD1RuntimePolicyScope(raw: unknown): RuntimePolicyScope | undefined {
  if (raw === undefined || raw === null) return undefined;
  const record = toRecordValue(raw);
  if (!record) return undefined;
  const orgId = toOptionalTrimmedString(record.orgId);
  const projectId = toOptionalTrimmedString(record.projectId);
  const envId = toOptionalTrimmedString(record.envId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return {
    orgId,
    projectId,
    envId,
    signingRootVersion,
  };
}

function parseD1StoredAddAuthMethodAuth(
  raw: unknown,
): StoredWalletAddAuthMethodCeremony['auth'] | null {
  const record = toRecordValue(raw);
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'app_session') return { kind: 'app_session' };
  if (kind === 'webauthn_assertion') {
    const rpId = toOptionalTrimmedString(record?.rpId);
    const credentialIdB64u = toOptionalTrimmedString(record?.credentialIdB64u);
    return rpId && credentialIdB64u ? { kind: 'webauthn_assertion', rpId, credentialIdB64u } : null;
  }
  return null;
}

function parseD1RegistrationAuthority(raw: unknown): RegistrationAuthority | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'passkey') return parseD1PasskeyRegistrationAuthority(record);
  if (kind === 'email_otp') return parseD1EmailOtpRegistrationAuthority(record);
  return null;
}

function parseD1PasskeyRegistrationAuthority(
  record: Record<string, unknown>,
): PasskeyRegistrationAuthority | null {
  const walletId = parseWalletIdForIntent(record.walletId);
  const rpId = parseWebAuthnRpId(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const credentialPublicKeyB64u = toOptionalTrimmedString(record.credentialPublicKeyB64u);
  const counter = safeInteger(record.counter);
  const registrationIntentDigestB64u = toOptionalTrimmedString(record.registrationIntentDigestB64u);
  if (
    !walletId ||
    !rpId.ok ||
    !credentialIdB64u ||
    !credentialPublicKeyB64u ||
    counter === null ||
    !registrationIntentDigestB64u
  ) {
    return null;
  }
  /* legacy in-flight ceremonies persisted before device capture existed get a
     synthesized unknown-device record instead of failing the parse */
  const device =
    parseWebAuthnAuthenticatorDeviceInfo(record.device) ?? unknownWebAuthnAuthenticatorDeviceInfo();
  return {
    kind: 'passkey',
    walletId,
    rpId: rpId.value,
    credentialIdB64u,
    credentialPublicKeyB64u,
    counter,
    device,
    registrationIntentDigestB64u,
  };
}

function parseD1EmailOtpRegistrationAuthority(
  record: Record<string, unknown>,
): EmailOtpRegistrationAuthority | null {
  if (record.proofKind === 'google_sso_registration') {
    return parseD1GoogleSsoEmailOtpRegistrationAuthority(record);
  }
  if (record.proofKind !== 'otp_challenge') return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const providerSubject = parseProviderSubject(record.providerSubject);
  const challengeSubjectId = parseChallengeSubjectId(record.challengeSubjectId);
  const email = toOptionalTrimmedString(record.email);
  const emailHashHex = toOptionalTrimmedString(record.emailHashHex);
  const challengeId = parseEmailOtpChallengeId(record.challengeId);
  const registrationAuthorityId = parseEmailOtpChallengeId(record.registrationAuthorityId);
  const originalWalletId = parseWalletIdForIntent(record.originalWalletId);
  const finalWalletId = parseWalletIdForIntent(record.finalWalletId);
  const orgId = parseOrgId(record.orgId);
  const appSessionVersion = parseAppSessionVersion(record.appSessionVersion);
  const challengePurpose = toOptionalTrimmedString(record.challengePurpose);
  const registrationIntentDigestB64u = toOptionalTrimmedString(record.registrationIntentDigestB64u);
  if (
    !walletId ||
    !providerSubject.ok ||
    !challengeSubjectId.ok ||
    !email ||
    !emailHashHex ||
    !challengeId.ok ||
    !registrationAuthorityId.ok ||
    !originalWalletId ||
    !finalWalletId ||
    !orgId.ok ||
    !appSessionVersion.ok ||
    (challengePurpose !== 'registration' && challengePurpose !== 'registration_reroll') ||
    !registrationIntentDigestB64u
  ) {
    return null;
  }
  return {
    kind: 'email_otp',
    proofKind: 'otp_challenge',
    walletId,
    providerSubject: providerSubject.value,
    challengeSubjectId: challengeSubjectId.value,
    email,
    emailHashHex,
    challengeId: challengeId.value,
    registrationAuthorityId: registrationAuthorityId.value,
    originalWalletId,
    finalWalletId,
    orgId: orgId.value,
    appSessionVersion: appSessionVersion.value,
    challengePurpose,
    registrationIntentDigestB64u,
  };
}

function parseD1GoogleSsoEmailOtpRegistrationAuthority(
  record: Record<string, unknown>,
): GoogleSsoEmailOtpRegistrationAuthority | null {
  const walletId = parseWalletIdForIntent(record.walletId);
  const providerSubject = parseProviderSubject(record.providerSubject);
  const email = toOptionalTrimmedString(record.email);
  const emailHashHex = toOptionalTrimmedString(record.emailHashHex);
  const googleEmailOtpRegistrationAttemptId = toOptionalTrimmedString(
    record.googleEmailOtpRegistrationAttemptId,
  );
  const googleEmailOtpRegistrationOfferId = toOptionalTrimmedString(
    record.googleEmailOtpRegistrationOfferId,
  );
  const googleEmailOtpRegistrationCandidateId = toOptionalTrimmedString(
    record.googleEmailOtpRegistrationCandidateId,
  );
  const registrationAuthorityId = toOptionalTrimmedString(record.registrationAuthorityId);
  const finalWalletId = parseWalletIdForIntent(record.finalWalletId);
  const orgId = parseOrgId(record.orgId);
  const appSessionVersion = parseAppSessionVersion(record.appSessionVersion);
  const registrationIntentDigestB64u = toOptionalTrimmedString(record.registrationIntentDigestB64u);
  if (
    !walletId ||
    !providerSubject.ok ||
    !email ||
    !emailHashHex ||
    !googleEmailOtpRegistrationAttemptId ||
    !googleEmailOtpRegistrationOfferId ||
    !googleEmailOtpRegistrationCandidateId ||
    !registrationAuthorityId ||
    !finalWalletId ||
    !orgId.ok ||
    !appSessionVersion.ok ||
    !registrationIntentDigestB64u
  ) {
    return null;
  }
  return {
    kind: 'email_otp',
    proofKind: 'google_sso_registration',
    walletId,
    providerSubject: providerSubject.value,
    email,
    emailHashHex,
    googleEmailOtpRegistrationAttemptId,
    googleEmailOtpRegistrationOfferId,
    googleEmailOtpRegistrationCandidateId,
    registrationAuthorityId,
    finalWalletId,
    orgId: orgId.value,
    appSessionVersion: appSessionVersion.value,
    registrationIntentDigestB64u,
  };
}

export function normalizeThresholdEcdsaChainTargets(
  input: readonly unknown[],
): ThresholdEcdsaChainTarget[] | null {
  const targets: ThresholdEcdsaChainTarget[] = [];
  for (const raw of input) {
    const target = thresholdEcdsaChainTargetFromValue(raw);
    if (!target) return null;
    targets.push(target);
  }
  return targets;
}

export function intentScopeMetadata(input: {
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly expectedOrigin?: string;
}): {
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
  readonly expectedOrigin?: string;
} {
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
  return {
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(expectedOrigin ? { expectedOrigin } : {}),
  };
}

function safeInteger(raw: unknown): number | null {
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

function addSignerEd25519SelectionsMatch(
  left: Extract<AddSignerSelection, { mode: 'ed25519' }>,
  right: Extract<AddSignerSelection, { mode: 'ed25519' }>,
): boolean {
  const leftEd25519 = left.ed25519;
  const rightEd25519 = right.ed25519;
  return (
    leftEd25519.mode === rightEd25519.mode &&
    leftEd25519.signerSlot === rightEd25519.signerSlot &&
    leftEd25519.keyPurpose === rightEd25519.keyPurpose &&
    leftEd25519.keyVersion === rightEd25519.keyVersion &&
    leftEd25519.derivationVersion === rightEd25519.derivationVersion &&
    positiveIntegerArraysEqual(leftEd25519.participantIds, rightEd25519.participantIds)
  );
}

function unreachableAddAuthMethodInput(value: never): never {
  throw new Error(`Unhandled add-auth-method input kind: ${String(value)}`);
}

function unreachableAddSignerSelection(value: never): never {
  throw new Error(`Unhandled add-signer selection mode: ${String(value)}`);
}
