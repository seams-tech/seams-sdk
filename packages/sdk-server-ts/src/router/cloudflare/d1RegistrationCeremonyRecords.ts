import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  addAuthMethodIntentGrantFromString,
  addSignerIntentGrantFromString,
  createServerAllocatedWalletId,
  normalizeAddAuthMethodInput,
  normalizeAddSignerSelection,
  normalizeRegistrationAuthMethodInput,
  normalizeRegistrationSignerPlan,
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
  nearEd25519SigningKeyIdFromString,
} from '@shared/utils/registrationIntent';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseOrgId,
  parseProviderSubject,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { base64UrlDecode } from '@shared/utils/encoders';
import {
  registrationPreparationIdFromString
} from '../../core/registrationContracts';
import type {
  EcdsaHssClientBootstrapRequest,
  EcdsaHssServerBootstrapResponse,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssPersistedPreparedServerSession,
  ThresholdEd25519HssPersistedRespondedServerSession,
  ThresholdEd25519HssPersistedServerInputs,
  ThresholdEd25519HssRegistrationPreparedServerState,
  ThresholdEd25519HssRegistrationRespondedServerState,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope
} from '../../core/types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey,
  WalletRegistrationFinalizeAuthMethod,
  WalletRegistrationFinalizeResponse
} from '../../core/registrationContracts';
import {
  parseThresholdEd25519AuthorityScope,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  thresholdEd25519AuthorityScopesMatch,
} from '../../core/ThresholdService/validation';
import { parseWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  parseStoredWalletRegistrationHssPreparation,
  type StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch,
  type StoredWalletRegistrationNearEd25519PreparedBranch,
  type StoredWalletRegistrationNearEd25519RespondedBranch,
  type StoredWalletRegistrationSignerBranch,
  type StoredWalletRegistrationSignerSetState,
  type StoredEd25519RegistrationPrepared,
  type StoredEd25519RegistrationResponded,
  StoredAddAuthMethodIntent,
  StoredAddSignerIntent,
  StoredRegistrationIntent,
  type StoredWalletRegistrationHssPreparation,
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
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
  type WalletEcdsaSignerRecord,
  type WalletRecord,
} from '../../core/d1WalletStore';
import { toRecordValue } from './d1RouterApiAuthBoundary';

type D1EcdsaPublicIdentity = EcdsaHssServerBootstrapResponse['publicIdentity'];
type D1EcdsaClientSharePublicKey = D1EcdsaPublicIdentity['hssClientSharePublicKey33B64u'];
type D1EcdsaRelayerPublicKey = D1EcdsaPublicIdentity['relayerPublicKey33B64u'];
type D1WalletRegistrationFinalizeSuccess = Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true }
>;
type D1WalletRegistrationEd25519FinalizeSuccess = Extract<
  D1WalletRegistrationFinalizeSuccess,
  { ed25519: object }
>;
type D1WalletRegistrationFinalizeEcdsaPayload = {
  readonly walletKeys: WalletRegistrationEcdsaWalletKey[];
};
type D1StoredEd25519RegistrationStartPayload = Pick<
  StoredEd25519RegistrationPrepared,
  'ceremonyHandle' | 'preparedSession' | 'clientOtOfferMessageB64u'
>;

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

export function parseD1StoredWalletRegistrationHssPreparation(
  raw: unknown,
): StoredWalletRegistrationHssPreparation | null {
  return parseStoredWalletRegistrationHssPreparation(raw);
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
  const signerState = parseD1StoredWalletRegistrationSignerState(record.signerState);
  if (
    !registrationCeremonyId ||
    !intent ||
    !digestB64u ||
    !orgId ||
    expiresAtMs === null ||
    !authority ||
    !signerState
  ) {
    return null;
  }
  const ceremony: StoredWalletRegistrationCeremony = {
    registrationCeremonyId,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    authority,
    signerState,
  };
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
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

function parseD1WalletRegistrationFinalizeReplayResponse(
  raw: unknown,
): D1WalletRegistrationFinalizeSuccess | null {
  const record = toRecordValue(raw);
  if (!record || record.ok !== true || record.kind !== undefined) return null;
  const walletId = parseWalletIdForIntent(record.walletId);
  const authMethod = parseD1WalletRegistrationFinalizeAuthMethod(record.authMethod);
  const authority = parseWalletAuthAuthority(record.authority);
  const authorityScope = parseThresholdEd25519AuthorityScope(record.authorityScope);
  if (!walletId || !authMethod || !authority || authority.walletId !== walletId) return null;
  const rpId = toOptionalTrimmedString(record.rpId);
  const ed25519 = parseD1WalletRegistrationFinalizeEd25519(record.ed25519);
  const ecdsa = parseD1WalletRegistrationFinalizeEcdsa(record.ecdsa);
  if (ed25519) {
    if (
      !authorityScope ||
      !thresholdEd25519AuthorityScopesMatch(
        authorityScope,
        thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
      )
    ) {
      return null;
    }
    const accountProvisioning = parseD1RegistrationNearAccountProvisioning(
      record.accountProvisioning,
    );
    const resolvedAccount = parseD1ResolvedRegistrationNearAccount(record.resolvedAccount);
    if (!accountProvisioning || !resolvedAccount) return null;
    const response: D1WalletRegistrationEd25519FinalizeSuccess = {
      ok: true,
      walletId,
      authority,
      authMethod,
      authorityScope,
      accountProvisioning,
      resolvedAccount,
      ed25519,
    };
    if (rpId) response.rpId = rpId;
    if (ecdsa) response.ecdsa = ecdsa;
    return response;
  }
  if (!ecdsa) return null;
  const response: Extract<D1WalletRegistrationFinalizeSuccess, { ecdsa: object }> = {
    ok: true,
    walletId,
    authority,
    authMethod,
    ecdsa,
  };
  if (rpId) response.rpId = rpId;
  return response;
}

function parseD1RegistrationNearAccountProvisioning(
  raw: unknown,
): RegistrationNearAccountProvisioning | null {
  const record = toRecordValue(raw);
  const kind = toOptionalTrimmedString(record?.kind);
  if (kind === 'implicit_account') {
    return record?.accountIdSource === 'ed25519_public_key'
      ? {
          kind: 'implicit_account',
          accountIdSource: 'ed25519_public_key',
        }
      : null;
  }
  if (kind === 'sponsored_named_account') {
    const requestedAccountId = parseNamedNearAccountId(record?.requestedAccountId);
    if (!requestedAccountId.ok || record?.sponsor !== 'relayer') return null;
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
  const kind = toOptionalTrimmedString(record?.kind);
  const nearEd25519SigningKeyIdRaw = toOptionalTrimmedString(record?.nearEd25519SigningKeyId);
  if (!nearEd25519SigningKeyIdRaw) return null;
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(nearEd25519SigningKeyIdRaw);
  if (kind === 'implicit_account') {
    const nearAccountId = parseImplicitNearAccountId(record?.nearAccountId);
    return nearAccountId.ok
      ? {
          kind: 'implicit_account',
          nearAccountId: nearAccountId.value,
          nearEd25519SigningKeyId,
        }
      : null;
  }
  if (kind === 'sponsored_named_account') {
    const nearAccountId = parseNamedNearAccountId(record?.nearAccountId);
    const transactionHash = toOptionalTrimmedString(record?.transactionHash);
    return nearAccountId.ok && transactionHash
      ? {
          kind: 'sponsored_named_account',
          nearAccountId: nearAccountId.value,
          nearEd25519SigningKeyId,
          transactionHash,
        }
      : null;
  }
  return null;
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

function parseD1WalletRegistrationFinalizeEd25519(
  raw: unknown,
): D1WalletRegistrationEd25519FinalizeSuccess['ed25519'] | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(record.nearEd25519SigningKeyId);
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const keyVersion = toOptionalTrimmedString(record.keyVersion);
  if (!nearAccountId || !nearEd25519SigningKeyId || !publicKey || !relayerKeyId || !keyVersion) {
    return null;
  }
  const response: D1WalletRegistrationEd25519FinalizeSuccess['ed25519'] = {
    nearAccountId,
    nearEd25519SigningKeyId,
    publicKey,
    relayerKeyId,
    keyVersion,
    recoveryExportCapable: true,
  };
  const clientParticipantId = safeInteger(record.clientParticipantId);
  const relayerParticipantId = safeInteger(record.relayerParticipantId);
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  if (clientParticipantId !== null) response.clientParticipantId = clientParticipantId;
  if (relayerParticipantId !== null) response.relayerParticipantId = relayerParticipantId;
  if (participantIds) response.participantIds = participantIds;
  if (record.session !== undefined) response.session = record.session as any;
  return response;
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
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
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
    !participantIds
  ) {
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
    participantIds,
  };
}

function parseD1StoredWalletRegistrationSignerState(
  raw: unknown,
): StoredWalletRegistrationCeremony['signerState'] | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record.kind);
  if (kind === 'ed25519_prepared') return parseD1StoredEd25519RegistrationPrepared(record);
  if (kind === 'ed25519_responded') return parseD1StoredEd25519RegistrationResponded(record);
  if (kind === 'signer_set_registration') return parseD1StoredSignerSetRegistrationState(record);
  if (kind === 'ecdsa_prepared') return parseD1StoredEcdsaRegistrationPrepared(record);
  if (kind === 'ecdsa_responded') return parseD1StoredEcdsaRegistrationResponded(record);
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
    case 'near_ed25519_prepared':
      return parseD1StoredNearEd25519PreparedBranch(record);
    case 'near_ed25519_responded':
      return parseD1StoredNearEd25519RespondedBranch(record);
    case 'evm_family_ecdsa_prepared':
      return parseD1StoredEvmFamilyEcdsaPreparedBranch(record);
    case 'evm_family_ecdsa_responded':
      return parseD1StoredEvmFamilyEcdsaRespondedBranch(record);
    default:
      return null;
  }
}

function parseD1StoredNearEd25519PreparedBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationNearEd25519PreparedBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const prepared = parseD1StoredEd25519RegistrationPrepared({
    kind: 'ed25519_prepared',
    ceremonyHandle: record.ceremonyHandle,
    preparedSession: record.preparedSession,
    clientOtOfferMessageB64u: record.clientOtOfferMessageB64u,
    serverState: record.serverState,
  });
  if (!branchKey || !prepared) return null;
  return {
    kind: 'near_ed25519_prepared',
    branchKey,
    ceremonyHandle: prepared.ceremonyHandle,
    preparedSession: prepared.preparedSession,
    clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
    serverState: prepared.serverState,
  };
}

function parseD1StoredNearEd25519RespondedBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationNearEd25519RespondedBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const startPayload = parseD1StoredEd25519RegistrationStartPayload({
    ceremonyHandle: record.ceremonyHandle,
    preparedSession: record.preparedSession,
    clientOtOfferMessageB64u: record.clientOtOfferMessageB64u,
  });
  const responded = toRecordValue(record.responded);
  const contextBindingB64u = toOptionalTrimmedString(responded?.contextBindingB64u);
  const serverInputDeliveryB64u = toOptionalTrimmedString(responded?.serverInputDeliveryB64u);
  const serverState = parseD1ThresholdEd25519HssRespondedServerState(record.serverState);
  if (
    !branchKey ||
    !startPayload ||
    !serverState ||
    !contextBindingB64u ||
    !serverInputDeliveryB64u
  ) {
    return null;
  }
  return {
    kind: 'near_ed25519_responded',
    branchKey,
    ceremonyHandle: startPayload.ceremonyHandle,
    preparedSession: startPayload.preparedSession,
    clientOtOfferMessageB64u: startPayload.clientOtOfferMessageB64u,
    serverState,
    responded: {
      contextBindingB64u,
      serverInputDeliveryB64u,
    },
  };
}

function parseD1StoredEvmFamilyEcdsaPreparedBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationEvmFamilyEcdsaPreparedBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const prepared = parseD1StoredEcdsaRegistrationPrepared({
    kind: 'ecdsa_prepared',
    hssKind: record.hssKind,
    chainTargets: record.chainTargets,
    prepare: record.prepare,
  });
  if (!branchKey || !prepared) return null;
  return {
    kind: 'evm_family_ecdsa_prepared',
    branchKey,
    hssKind: prepared.hssKind,
    chainTargets: prepared.chainTargets,
    prepare: prepared.prepare,
  };
}

function parseD1StoredEvmFamilyEcdsaRespondedBranch(
  record: Record<string, unknown>,
): StoredWalletRegistrationEvmFamilyEcdsaRespondedBranch | null {
  const branchKey = parseD1RegistrationSignerBranchKey(record.branchKey);
  const responded = parseD1StoredEcdsaRegistrationResponded({
    kind: 'ecdsa_responded',
    hssKind: record.hssKind,
    chainTargets: record.chainTargets,
    prepare: record.prepare,
    responded: record.responded,
  });
  if (!branchKey || !responded) return null;
  return {
    kind: 'evm_family_ecdsa_responded',
    branchKey,
    hssKind: responded.hssKind,
    chainTargets: responded.chainTargets,
    prepare: responded.prepare,
    responded: responded.responded,
  };
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

function parseD1StoredEd25519RegistrationPrepared(
  record: Record<string, unknown>,
): StoredEd25519RegistrationPrepared | null {
  const startPayload = parseD1StoredEd25519RegistrationStartPayload(record);
  const serverState = parseD1ThresholdEd25519HssPreparedServerState(record.serverState);
  if (!startPayload || !serverState) return null;
  return {
    kind: 'ed25519_prepared',
    ceremonyHandle: startPayload.ceremonyHandle,
    preparedSession: startPayload.preparedSession,
    clientOtOfferMessageB64u: startPayload.clientOtOfferMessageB64u,
    serverState,
  };
}

function parseD1StoredEd25519RegistrationResponded(
  record: Record<string, unknown>,
): StoredEd25519RegistrationResponded | null {
  const startPayload = parseD1StoredEd25519RegistrationStartPayload(record);
  const responded = toRecordValue(record.responded);
  const contextBindingB64u = toOptionalTrimmedString(responded?.contextBindingB64u);
  const serverInputDeliveryB64u = toOptionalTrimmedString(responded?.serverInputDeliveryB64u);
  const serverState = parseD1ThresholdEd25519HssRespondedServerState(record.serverState);
  if (!startPayload || !contextBindingB64u || !serverInputDeliveryB64u || !serverState) return null;
  return {
    kind: 'ed25519_responded',
    ceremonyHandle: startPayload.ceremonyHandle,
    preparedSession: startPayload.preparedSession,
    clientOtOfferMessageB64u: startPayload.clientOtOfferMessageB64u,
    serverState,
    responded: {
      contextBindingB64u,
      serverInputDeliveryB64u,
    },
  };
}

function parseD1StoredEd25519RegistrationStartPayload(
  record: Record<string, unknown>,
): D1StoredEd25519RegistrationStartPayload | null {
  const ceremonyHandle = toOptionalTrimmedString(record.ceremonyHandle);
  const preparedSession = parseD1ThresholdEd25519PreparedSession(record.preparedSession);
  const clientOtOfferMessageB64u = toOptionalTrimmedString(record.clientOtOfferMessageB64u);
  if (!ceremonyHandle || !preparedSession || !clientOtOfferMessageB64u) return null;
  return {
    ceremonyHandle,
    preparedSession,
    clientOtOfferMessageB64u,
  };
}

function parseD1Base64Url(raw: unknown): string {
  const value = toOptionalTrimmedString(raw);
  if (!value) return '';
  try {
    base64UrlDecode(value);
    return value;
  } catch {
    return '';
  }
}

function parseD1PresentBase64Url(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const value = raw.trim();
  try {
    base64UrlDecode(value);
    return value;
  } catch {
    return null;
  }
}

function parseD1ThresholdEd25519ParticipantIds(raw: unknown): number[] | null {
  if (!Array.isArray(raw) || raw.length < 2) return null;
  const participantIds: number[] = [];
  for (const item of raw) {
    const participantId = safeInteger(item);
    if (participantId === null || participantId <= 0) return null;
    participantIds.push(participantId);
  }
  return participantIds;
}

function parseD1ThresholdEd25519HssCanonicalContext(
  raw: unknown,
): ThresholdEd25519HssCanonicalContext | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const applicationBindingDigestB64u = parseD1Base64Url(record.applicationBindingDigestB64u);
  const participantIds = parseD1ThresholdEd25519ParticipantIds(record.participantIds);
  if (!applicationBindingDigestB64u || !participantIds) return null;
  if (base64UrlDecode(applicationBindingDigestB64u).byteLength !== 32) return null;
  return {
    applicationBindingDigestB64u,
    participantIds,
  };
}

function parseD1ThresholdEd25519HssPreparedServerSession(
  raw: unknown,
): ThresholdEd25519HssPersistedPreparedServerSession | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const evaluatorDriverStateB64u = parseD1Base64Url(record.evaluatorDriverStateB64u);
  const garblerDriverStateB64u = parseD1Base64Url(record.garblerDriverStateB64u);
  if (!evaluatorDriverStateB64u || !garblerDriverStateB64u) return null;
  return {
    evaluatorDriverStateB64u,
    garblerDriverStateB64u,
  };
}

function parseD1ThresholdEd25519HssRespondedServerSession(
  raw: unknown,
): ThresholdEd25519HssPersistedRespondedServerSession | null {
  const prepared = parseD1ThresholdEd25519HssPreparedServerSession(raw);
  const record = toRecordValue(raw);
  if (!prepared || !record) return null;
  const serverEvalStateB64u = parseD1PresentBase64Url(record.serverEvalStateB64u);
  if (serverEvalStateB64u === null) return null;
  return {
    ...prepared,
    serverEvalStateB64u,
  };
}

function parseD1ThresholdEd25519HssServerInputs(
  raw: unknown,
): ThresholdEd25519HssPersistedServerInputs | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const yRelayerB64u = parseD1Base64Url(record.yRelayerB64u);
  const tauRelayerB64u = parseD1Base64Url(record.tauRelayerB64u);
  if (!yRelayerB64u || !tauRelayerB64u) return null;
  return {
    yRelayerB64u,
    tauRelayerB64u,
  };
}

function parseD1ThresholdEd25519HssPreparedServerState(
  raw: unknown,
): ThresholdEd25519HssRegistrationPreparedServerState | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const context = parseD1ThresholdEd25519HssCanonicalContext(record.context);
  const preparedServerSession = parseD1ThresholdEd25519HssPreparedServerSession(
    record.preparedServerSession,
  );
  const serverInputs = parseD1ThresholdEd25519HssServerInputs(record.serverInputs);
  if (!context || !preparedServerSession || !serverInputs) return null;
  return {
    context,
    preparedServerSession,
    serverInputs,
  };
}

function parseD1ThresholdEd25519HssRespondedServerState(
  raw: unknown,
): ThresholdEd25519HssRegistrationRespondedServerState | null {
  const record = toRecordValue(raw);
  if (!record || Object.prototype.hasOwnProperty.call(record, 'serverInputs')) return null;
  const context = parseD1ThresholdEd25519HssCanonicalContext(record.context);
  const preparedServerSession = parseD1ThresholdEd25519HssRespondedServerSession(
    record.preparedServerSession,
  );
  if (!context || !preparedServerSession) return null;
  return {
    context,
    preparedServerSession,
  };
}

function parseD1ThresholdEd25519PreparedSession(
  raw: unknown,
): ThresholdEd25519HssPreparedSessionEnvelope | null {
  const record = toRecordValue(raw);
  const contextBindingB64u = toOptionalTrimmedString(record?.contextBindingB64u);
  const evaluatorDriverStateB64u = toOptionalTrimmedString(record?.evaluatorDriverStateB64u);
  if (!contextBindingB64u || !evaluatorDriverStateB64u) return null;
  return {
    contextBindingB64u,
    evaluatorDriverStateB64u,
  };
}

function parseD1StoredEcdsaRegistrationPrepared(
  record: Record<string, unknown>,
): Extract<StoredWalletRegistrationCeremony['signerState'], { kind: 'ecdsa_prepared' }> | null {
  const hssKind = toOptionalTrimmedString(record.hssKind);
  const chainTargets = Array.isArray(record.chainTargets)
    ? normalizeThresholdEcdsaChainTargets(record.chainTargets)
    : null;
  const prepare = parseD1WalletRegistrationEcdsaPrepare(record.prepare);
  if (hssKind !== 'evm_family_ecdsa_keygen' || !chainTargets || !prepare) return null;
  return {
    kind: 'ecdsa_prepared',
    hssKind,
    chainTargets,
    prepare,
  };
}

function parseD1StoredEcdsaRegistrationResponded(
  record: Record<string, unknown>,
): Extract<StoredWalletRegistrationCeremony['signerState'], { kind: 'ecdsa_responded' }> | null {
  const hssKind = toOptionalTrimmedString(record.hssKind);
  const chainTargets = Array.isArray(record.chainTargets)
    ? normalizeThresholdEcdsaChainTargets(record.chainTargets)
    : null;
  const prepare = parseD1WalletRegistrationEcdsaPrepare(record.prepare);
  const responded = toRecordValue(record.responded);
  const bootstrap = parseD1EcdsaHssServerBootstrapResponse(responded?.bootstrap);
  if (hssKind !== 'evm_family_ecdsa_keygen' || !chainTargets || !prepare || !bootstrap) {
    return null;
  }
  return {
    kind: 'ecdsa_responded',
    hssKind,
    chainTargets,
    prepare,
    responded: {
      bootstrap,
    },
  };
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
  const expiresAtMs = safeInteger(record.expiresAtMs);
  const auth = parseD1StoredAddSignerAuth(record.auth);
  const signerState = parseD1StoredWalletAddSignerSignerState(record.signerState);
  if (
    !addSignerCeremonyId ||
    !intent ||
    !digestB64u ||
    !orgId ||
    expiresAtMs === null ||
    !auth ||
    !signerState
  ) {
    return null;
  }
  const ceremony: StoredWalletAddSignerCeremony = {
    addSignerCeremonyId,
    intent,
    digestB64u,
    orgId,
    expiresAtMs,
    auth,
    signerState,
  };
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (signingRootId) ceremony.signingRootId = signingRootId;
  if (signingRootVersion) ceremony.signingRootVersion = signingRootVersion;
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
  if (kind === 'ecdsa_add_signer_prepared') {
    return parseD1StoredEcdsaAddSignerPrepared(record);
  }
  if (kind === 'ecdsa_add_signer_responded') {
    return parseD1StoredEcdsaAddSignerResponded(record);
  }
  return null;
}

function parseD1StoredEcdsaAddSignerPrepared(
  record: Record<string, unknown>,
): Extract<
  StoredWalletAddSignerCeremony['signerState'],
  { kind: 'ecdsa_add_signer_prepared' }
> | null {
  const hssKind = toOptionalTrimmedString(record.hssKind);
  const chainTargets = Array.isArray(record.chainTargets)
    ? normalizeThresholdEcdsaChainTargets(record.chainTargets)
    : null;
  const prepare = parseD1WalletRegistrationEcdsaPrepare(record.prepare);
  if (hssKind !== 'evm_family_ecdsa_keygen' || !chainTargets || !prepare) return null;
  return {
    kind: 'ecdsa_add_signer_prepared',
    hssKind,
    chainTargets,
    prepare,
  };
}

function parseD1StoredEcdsaAddSignerResponded(
  record: Record<string, unknown>,
): Extract<
  StoredWalletAddSignerCeremony['signerState'],
  { kind: 'ecdsa_add_signer_responded' }
> | null {
  const hssKind = toOptionalTrimmedString(record.hssKind);
  const chainTargets = Array.isArray(record.chainTargets)
    ? normalizeThresholdEcdsaChainTargets(record.chainTargets)
    : null;
  const prepare = parseD1WalletRegistrationEcdsaPrepare(record.prepare);
  const responded = toRecordValue(record.responded);
  const bootstrap = parseD1EcdsaHssServerBootstrapResponse(responded?.bootstrap);
  if (hssKind !== 'evm_family_ecdsa_keygen' || !chainTargets || !prepare || !bootstrap) {
    return null;
  }
  return {
    kind: 'ecdsa_add_signer_responded',
    hssKind,
    chainTargets,
    prepare,
    responded: {
      bootstrap,
    },
  };
}

function parseD1WalletRegistrationEcdsaPrepare(
  raw: unknown,
): WalletRegistrationEcdsaPreparePayload['prepare'] | null {
  const record = toRecordValue(raw);
  if (!record || record.formatVersion !== 'ecdsa-hss-role-local') return null;
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
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  const runtimePolicyScope = parseD1RuntimePolicyScope(record.runtimePolicyScope);
  if (
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
    (record.runtimePolicyScope !== undefined && !runtimePolicyScope)
  ) {
    return null;
  }
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    ...(registrationPreparationId
      ? {
          registrationPreparationId: registrationPreparationIdFromString(registrationPreparationId),
        }
      : {}),
    requestId,
    thresholdSessionId,
    signingGrantId,
    ttlMs,
    remainingUses,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

function parseD1EcdsaHssServerBootstrapResponse(
  raw: unknown,
): EcdsaHssServerBootstrapResponse | null {
  const record = toRecordValue(raw);
  if (!record || record.formatVersion !== 'ecdsa-hss-role-local') return null;
  const walletId = toOptionalTrimmedString(record.walletId);
  const evmFamilySigningKeySlotId = toOptionalTrimmedString(record.evmFamilySigningKeySlotId);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(record.ecdsaThresholdKeyId);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const applicationBindingDigestB64u = toOptionalTrimmedString(record.applicationBindingDigestB64u);
  const contextBinding32B64u = toOptionalTrimmedString(record.contextBinding32B64u);
  const publicIdentity = parseD1EcdsaHssPublicIdentity(record.publicIdentity);
  const clientShareRetryCounter = safeInteger(record.clientShareRetryCounter);
  const relayerShareRetryCounter = safeInteger(record.relayerShareRetryCounter);
  const publicTranscriptDigest32B64u = toOptionalTrimmedString(record.publicTranscriptDigest32B64u);
  const keyHandle = toOptionalTrimmedString(record.keyHandle);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(record.thresholdEcdsaPublicKeyB64u);
  const ethereumAddress = toOptionalTrimmedString(record.ethereumAddress);
  const relayerVerifyingShareB64u = toOptionalTrimmedString(record.relayerVerifyingShareB64u);
  const participantIds = parseD1PositiveIntegerArray(record.participantIds);
  const thresholdSessionId = toOptionalTrimmedString(record.thresholdSessionId);
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
    !signingGrantId ||
    expiresAtMs === null ||
    !expiresAt ||
    remainingUses === null
  ) {
    return null;
  }
  const bootstrap: EcdsaHssServerBootstrapResponse = {
    formatVersion: 'ecdsa-hss-role-local',
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
    participantIds,
    thresholdSessionId,
    signingGrantId,
    expiresAtMs,
    expiresAt,
    remainingUses,
  };
  const jwt = toOptionalTrimmedString(record.jwt);
  if (jwt) bootstrap.jwt = jwt;
  return bootstrap;
}

function parseD1EcdsaHssPublicIdentity(raw: unknown): D1EcdsaPublicIdentity | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  const hssClientSharePublicKey33B64u = toOptionalTrimmedString(
    record.hssClientSharePublicKey33B64u,
  );
  const relayerPublicKey33B64u = toOptionalTrimmedString(record.relayerPublicKey33B64u);
  const groupPublicKey33B64u = toOptionalTrimmedString(record.groupPublicKey33B64u);
  const ethereumAddress = toOptionalTrimmedString(record.ethereumAddress);
  if (
    !hssClientSharePublicKey33B64u ||
    !relayerPublicKey33B64u ||
    !groupPublicKey33B64u ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    hssClientSharePublicKey33B64u: hssClientSharePublicKey33B64u as D1EcdsaClientSharePublicKey,
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
  readonly expected: WalletRegistrationEcdsaPreparePayload['prepare'];
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

export function toD1EcdsaHssClientBootstrapRequest(
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap,
): EcdsaHssClientBootstrapRequest {
  return {
    formatVersion: clientBootstrap.formatVersion,
    walletId: clientBootstrap.walletId,
    evmFamilySigningKeySlotId: clientBootstrap.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: clientBootstrap.ecdsaThresholdKeyId,
    signingRootId: clientBootstrap.signingRootId,
    signingRootVersion: clientBootstrap.signingRootVersion,
    keyScope: clientBootstrap.keyScope,
    relayerKeyId: clientBootstrap.relayerKeyId,
    ...(clientBootstrap.registrationPreparationId
      ? { registrationPreparationId: clientBootstrap.registrationPreparationId }
      : {}),
    hssClientSharePublicKey33B64u: clientBootstrap.hssClientSharePublicKey33B64u,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: clientBootstrap.requestId,
    sessionId: clientBootstrap.thresholdSessionId,
    signingGrantId: clientBootstrap.signingGrantId,
    ttlMs: clientBootstrap.ttlMs,
    remainingUses: clientBootstrap.remainingUses,
    participantIds: clientBootstrap.participantIds,
    ...(clientBootstrap.runtimePolicyScope
      ? { runtimePolicyScope: clientBootstrap.runtimePolicyScope }
      : {}),
  };
}

export function buildD1EcdsaAddSignerRespondedCeremony(input: {
  readonly ceremony: StoredWalletAddSignerCeremony;
  readonly bootstrap: EcdsaHssServerBootstrapResponse;
}): StoredWalletAddSignerCeremony {
  const state = input.ceremony.signerState;
  if (state.kind !== 'ecdsa_add_signer_prepared') {
    throw new Error('ECDSA add-signer ceremony must be prepared before respond');
  }
  const ceremony: StoredWalletAddSignerCeremony = {
    addSignerCeremonyId: input.ceremony.addSignerCeremonyId,
    intent: input.ceremony.intent,
    digestB64u: input.ceremony.digestB64u,
    orgId: input.ceremony.orgId,
    expiresAtMs: input.ceremony.expiresAtMs,
    auth: input.ceremony.auth,
    signerState: {
      kind: 'ecdsa_add_signer_responded',
      hssKind: state.hssKind,
      chainTargets: state.chainTargets,
      prepare: state.prepare,
      responded: {
        bootstrap: input.bootstrap,
      },
    },
  };
  if (input.ceremony.signingRootId) ceremony.signingRootId = input.ceremony.signingRootId;
  if (input.ceremony.signingRootVersion) {
    ceremony.signingRootVersion = input.ceremony.signingRootVersion;
  }
  return ceremony;
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
  readonly bootstrap: EcdsaHssServerBootstrapResponse;
  readonly chainTargets: readonly ThresholdEcdsaChainTarget[];
  readonly errorContext: string;
}): D1EcdsaWalletKeyBuildResult {
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
  if (!participantIds) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} returned incomplete ECDSA wallet key material: participantIds`,
    };
  }
  if (input.chainTargets.length === 0) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${input.errorContext} has no ECDSA chain targets`,
    };
  }
  return {
    ok: true,
    walletKeys: d1EcdsaWalletKeysForChainTargets({
      required: complete.value,
      participantIds,
      chainTargets: input.chainTargets,
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
    },
  };
}

function d1EcdsaWalletKeysForChainTargets(input: {
  readonly required: CompleteD1EcdsaWalletKeyBootstrapFields;
  readonly participantIds: readonly number[];
  readonly chainTargets: readonly ThresholdEcdsaChainTarget[];
}): WalletRegistrationEcdsaWalletKey[] {
  const walletKeys: WalletRegistrationEcdsaWalletKey[] = [];
  for (const chainTarget of input.chainTargets) {
    walletKeys.push({
      keyScope: 'evm-family',
      chainTarget,
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
      participantIds: [...input.participantIds],
    });
  }
  return walletKeys;
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
): Extract<RegistrationAuthority, { kind: 'passkey' }> | null {
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
  return {
    kind: 'passkey',
    walletId,
    rpId: rpId.value,
    credentialIdB64u,
    credentialPublicKeyB64u,
    counter,
    registrationIntentDigestB64u,
  };
}

function parseD1EmailOtpRegistrationAuthority(
  record: Record<string, unknown>,
): Extract<RegistrationAuthority, { kind: 'email_otp' }> | null {
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
): Extract<
  RegistrationAuthority,
  { kind: 'email_otp'; proofKind: 'google_sso_registration' }
> | null {
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
    leftEd25519.nearAccountId === rightEd25519.nearAccountId &&
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
