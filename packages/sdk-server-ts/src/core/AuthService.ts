import { ActionType, type ActionArgsWasm, validateActionArgsWasm } from '@/core/types/actions';
import {
  MinimalNearClient,
  SignedTransaction,
  type AccessKeyList,
} from '@/core/rpcClients/near/NearClient';
import type { FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import { toPublicKeyStringFromSecretKey } from './nearKeys';
import { createAuthServiceConfig } from './config';
import { formatGasToTGas, formatYoctoToNear } from './utils';
import { parseContractExecutionError } from './errors';
import { coerceSignerSlot } from '@shared/utils/signerSlot';
import {
  ensureEd25519Prefix,
  isValidAccountId,
  toOptionalTrimmedString,
} from '@shared/utils/validation';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import {
  buildRecoveryEmailBody,
  buildRecoveryEmailPayload,
  buildRecoveryEmailSubject,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';
import { coerceThresholdNodeRole } from './ThresholdService/config';
import type { ThresholdSigningService as ThresholdSigningServiceType } from './ThresholdService';
import type { ThresholdEd25519RegistrationKeygenResult } from './ThresholdService';
import {
  createThresholdSigningService,
  ensureThresholdEd25519HssWasm,
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
} from './ThresholdService';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import initSignerWasm, {
  handle_signer_message,
  WorkerRequestType,
  WorkerResponseType,
  type InitInput,
  type WasmTransaction,
  type WasmSignature,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

import type {
  AuthServiceConfig,
  AuthServiceConfigInput,
  AccountCreationRequest,
  AccountCreationResult,
  CreateAddAuthMethodIntentRequest,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentRequest,
  CreateAddSignerIntentResponse,
  CreateRegistrationIntentRequest,
  CreateRegistrationIntentResponse,
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
  OidcExchangeIssuerConfig,
  ThresholdRuntimePolicyScope,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssExportShareRequest,
  EcdsaHssExportShareResponse,
  EcdsaHssRouteResult,
  EcdsaHssServerBootstrapResponse,
  WalletRegistrationEcdsaWalletKey,
  WebAuthnAuthenticationCredential,
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerHssRespondRequest,
  WalletAddSignerHssRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
  WalletAddAuthMethodFinalizeRequest,
  WalletAddAuthMethodFinalizeResponse,
  WalletRevokeAuthMethodRequest,
  WalletRevokeAuthMethodResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationHssRespondRequest,
  WalletRegistrationHssRespondResponse,
  RegistrationPreparationId,
  WalletRegistrationPrepareRequest,
  WalletRegistrationPrepareResponse,
  WalletRegistrationRouteDiagnostics,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
  SignerWasmModuleSupplier,
} from './types';
import { registrationPreparationIdFromString } from './types';
import {
  parseEcdsaHssClientBootstrapRequest,
  type ThresholdEcdsaSessionClaims,
} from './ThresholdService/validation';

export type GoogleEmailOtpResolutionMode =
  | 'existing_wallet'
  | 'register_started'
  | 'wallet_id_collision'
  | 'registration_incomplete'
  | 'stale_identity_mapping';

export type GoogleEmailOtpRegistrationOfferCandidate = {
  candidateId: string;
  walletId: string;
};

export type GoogleEmailOtpRegistrationOffer = {
  offerId: string;
  selectedCandidateId: string;
  candidates: readonly [
    GoogleEmailOtpRegistrationOfferCandidate,
    ...GoogleEmailOtpRegistrationOfferCandidate[],
  ];
};

export type GoogleEmailOtpResolutionResult =
  | {
      ok: true;
      mode: 'existing_wallet';
      walletId: string;
      providerSubject: string;
      email?: string;
      hasEmailOtpEnrollment: true;
    }
  | {
      ok: true;
      mode: 'register_started';
      walletId: string;
      providerSubject: string;
      email: string;
      registrationAttemptId: string;
      expiresAtMs: number;
      offer: GoogleEmailOtpRegistrationOffer;
    }
  | {
      ok: false;
      mode: 'wallet_id_collision' | 'registration_incomplete' | 'stale_identity_mapping';
      code: 'wallet_id_collision' | 'registration_incomplete' | 'stale_identity_mapping';
      walletId?: string;
      providerSubject: string;
      email?: string;
      message: string;
    };

import { EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT } from './defaultConfigsServer';
import { EmailRecoveryService } from '../email-recovery';
import { SignedDelegate } from '@/core/types/delegate';
import {
  deriveSigningRootId,
  normalizeRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseEmailOtpRegistrationAttemptId,
  parseGoogleProviderSubject,
  parseOrgId,
  parseProviderSubject,
  parseVerifiedGoogleEmail,
  parseWalletId,
  type AppSessionVersion,
  type ChallengeSubjectId,
  type EmailOtpChallengeId,
  type EmailOtpRegistrationAttemptId,
  type GoogleProviderSubject,
  type OrgId,
  type ProviderSubject,
  type VerifiedGoogleEmail,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  addAuthMethodIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  addSignerIntentGrantFromString,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  normalizeAddAuthMethodInput,
  normalizeEmailOtpRegistrationProof,
  normalizeNearAccountOwnershipProofV1,
  normalizeRegistrationAuthMethodInput,
  registrationIntentGrantFromString,
  serializeNearAccountOwnershipProofMessageV1,
  walletIdFromString,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type AddSignerSelection,
  type NearAccountOwnershipProofV1,
  type RegistrationAuthority,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
} from '@shared/utils/registrationIntent';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  createRegistrationCeremonyStore,
  createWalletId,
  buildStoredWalletRegistrationHssPreparationPrepared,
  getPreparedWalletRegistrationHssPreparation,
  resolveRegistrationCeremonyPostgresNamespace,
  storedEd25519RegistrationPrepareScopesMatch,
  type RegistrationCeremonyStore,
  type StoredCombinedRegistrationState,
  type StoredEd25519RegistrationPrepareScope,
  type StoredRegistrationIntent,
} from './RegistrationCeremonyStore';
import {
  buildWalletEcdsaSignerRecord,
  buildWalletEd25519SignerId,
  createWalletStore,
  putWalletRecordWithExecutor,
  putWalletSignerRecordWithExecutor,
  resolveWalletStoreNamespace,
  type WalletRecord,
  type WalletSignerRecord,
  type WalletStore,
} from './WalletStore';
import {
  createWalletAuthMethodStore,
  putWalletAuthMethodWithExecutor,
  resolveWalletAuthMethodStoreNamespace,
  type WalletAuthMethodRecord,
  type WalletAuthMethodStore,
} from './WalletAuthMethodStore';
import { deriveHostedNearAccountId } from './hostedAccountIds';
import {
  type ExecuteSignedDelegateResult,
  executeSignedDelegateWithRelayer,
  type DelegateActionPolicy,
} from '../delegateAction';
import { coerceLogger, type NormalizedLogger } from './logger';
import { errorMessage, toError } from '@shared/utils/errors';
import {
  base58Decode,
  base64Decode,
  base64UrlDecode,
  base64UrlEncode,
} from '@shared/utils/encoders';
import {
  createWebAuthnAuthenticatorStore,
  putWebAuthnAuthenticatorRecordWithExecutor,
  resolveWebAuthnAuthenticatorStoreNamespace,
  type WebAuthnAuthenticatorRecord,
  type WebAuthnAuthenticatorStore,
} from './WebAuthnAuthenticatorStore';
import {
  createWebAuthnLoginChallengeStore,
  type WebAuthnLoginChallengeStore,
} from './WebAuthnLoginChallengeStore';
import {
  createWebAuthnCredentialBindingStore,
  putWebAuthnCredentialBindingRecordWithExecutor,
  resolveWebAuthnCredentialBindingStoreNamespace,
  type WebAuthnCredentialBindingRecord,
  type WebAuthnCredentialBindingStore,
} from './WebAuthnCredentialBindingStore';
import {
  createWebAuthnSyncChallengeStore,
  type WebAuthnSyncChallengeStore,
} from './WebAuthnSyncChallengeStore';
import {
  createEmailOtpWalletEnrollmentStore,
  createEmailOtpRecoveryWrappedEnrollmentEscrowStore,
  createEmailOtpAuthStateStore,
  createEmailOtpChallengeStore,
  createEmailOtpGrantStore,
  createEmailOtpRegistrationAttemptStore,
  createEmailOtpUnlockChallengeStore,
  emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord,
  parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
  putGoogleEmailOtpRegistrationAttemptWithExecutor,
  resolveEmailOtpStoreNamespace,
  type EmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
  type EmailOtpWalletEnrollmentRecord,
  type EmailOtpWalletEnrollmentStore,
  type EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type EmailOtpRecoveryWrappedEnrollmentEscrowStore,
  type EmailOtpAuthStateRecord,
  type EmailOtpAuthStateStore,
  type EmailOtpChannel,
  type EmailOtpChallengeAction,
  type EmailOtpChallengeOperation,
  type EmailOtpChallengeRecord,
  type EmailOtpChallengeStore,
  type EmailOtpGrantStore,
  type EmailOtpLoginChallengeOperation,
  type EmailOtpRegistrationAttemptStore,
  type EmailOtpUnlockChallengeStore,
  type NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
  type PendingGoogleEmailOtpRegistrationAttemptRecord,
  type GoogleEmailOtpRegistrationAttemptRecord,
} from './EmailOtpStores';
import {
  createSigningSessionSealShamir3PassCipherAdapter,
  resolveSigningSessionSealRateLimitFromEnv,
  type SigningSessionSealRateLimiter,
} from '../threshold/session/signingSessionSeal';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from './ThresholdService/ethSignerWasm';
import {
  createDeviceLinkingSessionStore,
  type DeviceLinkingSessionRecord,
  type DeviceLinkingSessionStore,
} from './DeviceLinkingSessionStore';
import {
  createEmailRecoveryPreparationStore,
  type EmailRecoveryPreparationStore,
} from './EmailRecoveryPreparationStore';
import {
  createNearPublicKeyStore,
  type NearPublicKeyKind,
  type NearPublicKeyRecord,
  type NearPublicKeyStore,
} from './NearPublicKeyStore';
import {
  createRecoverySessionStore,
  type RecoverySessionStatus,
  type RecoverySessionStore,
} from './RecoverySessionStore';
import {
  createRecoveryExecutionStore,
  type RecoveryExecutionRecord,
  type RecoveryExecutionStatus,
  type RecoveryExecutionStore,
} from './RecoveryExecutionStore';
import {
  ensurePostgresSchema,
  getPostgresPool,
  getPostgresUrlFromConfig,
} from '../storage/postgres';
import {
  createIdentityStore,
  linkIdentitySubjectToUserIdWithExecutor,
  resolveIdentityStoreNamespace,
  type IdentityStore,
  type LinkIdentityResult,
  type UnlinkIdentityResult,
} from './IdentityStore';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from './thresholdEcdsaChainTarget';
import {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from './recoverySessionRecords';
import { buildRecoveryExecutionRecord } from './recoveryExecutionRecords';

const ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL: TxExecutionStatus = 'EXECUTED_OPTIMISTIC';
const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;
const ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK = {
  attempts: 2,
  delayMs: 100,
  finality: 'optimistic' as const,
};
const ACCOUNT_CREATE_BACKGROUND_KEY_VISIBILITY_AUDIT = {
  attempts: 8,
  delayMs: 250,
  finality: 'final' as const,
};

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function logDuration(timings: Record<string, number>, key: string, startedAtMs: number): void {
  timings[key] = Date.now() - startedAtMs;
}

type WalletRegistrationRouteTimingEntry = WalletRegistrationRouteDiagnostics['entries'][number];

function registrationRouteTimingEntries(): WalletRegistrationRouteTimingEntry[] {
  return [];
}

function pushRegistrationRouteTiming(
  entries: WalletRegistrationRouteTimingEntry[],
  name: WalletRegistrationRouteTimingEntry['name'],
  startedAtMs: number,
): void {
  entries.push({ name, durationMs: Math.max(0, Date.now() - startedAtMs) });
}

function pushRegistrationRouteDuration(
  entries: WalletRegistrationRouteTimingEntry[],
  name: WalletRegistrationRouteTimingEntry['name'],
  durationMs: number,
): void {
  if (!Number.isFinite(durationMs)) return;
  entries.push({ name, durationMs: Math.max(0, durationMs) });
}

function pushRegistrationHssPrepareTimingEntries(
  entries: WalletRegistrationRouteTimingEntry[],
  timings: {
    prepareSessionMs: number;
    extractDriverStatesMs: number;
    clientOfferMessageMs: number;
    cachePreparedSessionMs: number;
    encodeStatesMs: number;
  } | null | undefined,
): void {
  if (!timings) return;
  pushRegistrationRouteDuration(entries, 'registrationHssPrepareSessionMs', timings.prepareSessionMs);
  pushRegistrationRouteDuration(
    entries,
    'registrationHssPrepareExtractDriverStatesMs',
    timings.extractDriverStatesMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssPrepareClientOfferMessageMs',
    timings.clientOfferMessageMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssPrepareCachePreparedSessionMs',
    timings.cachePreparedSessionMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssPrepareEncodeStatesMs',
    timings.encodeStatesMs,
  );
}

function pushRegistrationHssFinalizeTimingEntries(
  entries: WalletRegistrationRouteTimingEntry[],
  timings: {
    decodeArtifactMs: number;
    serializedSessionMaterializeMs: number;
    finalizeReportMs: number;
    encodeReportMs: number;
    openServerOutputMs: number;
    openSeedOutputMs: number;
    deriveSeedKeypairMs: number;
    deriveRelayerVerifyingShareMs: number;
    keyStorePutMs: number;
  },
): void {
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeDecodeArtifactMs',
    timings.decodeArtifactMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeSerializedSessionMaterializeMs',
    timings.serializedSessionMaterializeMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeReportMs',
    timings.finalizeReportMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeEncodeReportMs',
    timings.encodeReportMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeOpenServerOutputMs',
    timings.openServerOutputMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeOpenSeedOutputMs',
    timings.openSeedOutputMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeDeriveSeedKeypairMs',
    timings.deriveSeedKeypairMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeDeriveRelayerVerifyingShareMs',
    timings.deriveRelayerVerifyingShareMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssFinalizeKeyStorePutMs',
    timings.keyStorePutMs,
  );
}

function pushRegistrationHssRespondTimingEntries(
  entries: WalletRegistrationRouteTimingEntry[],
  timings: {
    decodeMessagesMs: number;
    materializeSessionMs: number;
    prepareDeliveryMs: number;
    deliveryOtOpenJoinMs: number;
    deliveryServerInputOpenMs: number;
    deliveryServerInputShareMs: number;
    deliveryServerInputCommitmentMs: number;
    deliveryServerInputTranscriptMs: number;
    deliveryServerInputSealMs: number;
    encodeDeliveryMs: number;
  },
): void {
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondDecodeMessagesMs',
    timings.decodeMessagesMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondMaterializeSessionMs',
    timings.materializeSessionMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondPrepareDeliveryMs',
    timings.prepareDeliveryMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondDeliveryOtOpenJoinMs',
    timings.deliveryOtOpenJoinMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondDeliveryServerInputOpenMs',
    timings.deliveryServerInputOpenMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondDeliveryServerInputShareMs',
    timings.deliveryServerInputShareMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondDeliveryServerInputCommitmentMs',
    timings.deliveryServerInputCommitmentMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondDeliveryServerInputTranscriptMs',
    timings.deliveryServerInputTranscriptMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondDeliveryServerInputSealMs',
    timings.deliveryServerInputSealMs,
  );
  pushRegistrationRouteDuration(
    entries,
    'registrationHssRespondEncodeDeliveryMs',
    timings.encodeDeliveryMs,
  );
}

async function measureRegistrationRouteTiming<T>(
  entries: WalletRegistrationRouteTimingEntry[],
  name: WalletRegistrationRouteTimingEntry['name'],
  operation: () => Promise<T>,
): Promise<T> {
  const startedAtMs = Date.now();
  try {
    return await operation();
  } finally {
    pushRegistrationRouteTiming(entries, name, startedAtMs);
  }
}

function buildRegistrationRouteDiagnostics(input: {
  route: WalletRegistrationRouteDiagnostics['route'];
  entries: WalletRegistrationRouteTimingEntry[];
  totalName: WalletRegistrationRouteTimingEntry['name'];
  startedAtMs: number;
}): WalletRegistrationRouteDiagnostics {
  const entries = [
    ...input.entries,
    {
      name: input.totalName,
      durationMs: Math.max(0, Date.now() - input.startedAtMs),
    },
  ];
  return {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: input.route,
    entries,
  };
}

type ThresholdEcdsaKeyInventoryDiagnostics = {
  userId: string;
  inputCount: number;
  returnedCount: number;
  thresholdServicePresent: boolean;
  rejected: Record<string, number>;
};

type ThresholdEcdsaKeyInventorySelector = {
  kind: 'key_handle';
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};

type ThresholdEcdsaKeyInventoryTarget = {
  keySelector: ThresholdEcdsaKeyInventorySelector;
  selectorKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
};

type ThresholdEcdsaKeyInventoryRecord = {
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  targetKey: string;
  accountAddress: string;
  ownerAddress: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  key: {
    walletId: string;
    rpId: string;
    keyScope: 'evm-family';
    ecdsaThresholdKeyId: string;
    signingRootId: string;
    signingRootVersion: string;
    participantIds: number[];
    thresholdOwnerAddress: string;
  };
};

function incrementCount(bucket: Record<string, number>, reason: string): void {
  bucket[reason] = (bucket[reason] || 0) + 1;
}

function assertNever(value: never): never {
  throw new Error(`Unexpected variant: ${JSON.stringify(value)}`);
}

type RegistrationAuthorityPersistenceInput = {
  authority: RegistrationAuthority;
  walletId: WalletId;
  rpId: string;
  now: number;
  ed25519?: {
    signerSlot: number;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    recoveryExportCapable: boolean;
    clientParticipantId?: number;
    relayerParticipantId?: number;
    participantIds?: number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  };
};

type RegistrationAuthorityPersistenceRecords = Pick<
  RegistrationPersistenceRecords,
  'webAuthnAuthenticators' | 'credentialBindings' | 'walletAuthMethods'
>;

function thresholdEcdsaKeyInventorySelectorFromRaw(
  raw: Record<string, unknown>,
): { ok: true; value: ThresholdEcdsaKeyInventorySelector } | { ok: false; reason: string } {
  const keyHandle = toOptionalTrimmedString(raw.keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(raw.ecdsaThresholdKeyId);
  if (ecdsaThresholdKeyId) return { ok: false, reason: 'threshold_key_id_selector' };
  if (!keyHandle) return { ok: false, reason: 'missing_key_selector' };
  return { ok: true, value: { kind: 'key_handle', keyHandle } };
}

function thresholdEcdsaKeyInventorySelectorKey(
  selector: ThresholdEcdsaKeyInventorySelector,
): string {
  return `keyHandle:${selector.keyHandle}`;
}

function thresholdEcdsaKeyInventorySelectorMatchesIdentity(
  selector: ThresholdEcdsaKeyInventorySelector,
  identity: { keyHandle: string; ecdsaThresholdKeyId: string },
): boolean {
  return identity.keyHandle === selector.keyHandle;
}

function parseThresholdEcdsaKeyInventoryTarget(
  raw: unknown,
): { ok: true; value: ThresholdEcdsaKeyInventoryTarget } | { ok: false; reason: string } {
  if (!isObject(raw)) return { ok: false, reason: 'non_object' };
  const keySelector = thresholdEcdsaKeyInventorySelectorFromRaw(raw);
  if (!keySelector.ok) return keySelector;
  const chainTarget = thresholdEcdsaChainTargetFromValue(raw.chainTarget);
  if (!chainTarget) return { ok: false, reason: 'invalid_chain_target' };
  return {
    ok: true,
    value: {
      keySelector: keySelector.value,
      selectorKey: thresholdEcdsaKeyInventorySelectorKey(keySelector.value),
      chainTarget,
    },
  };
}

function normalizeEvmAddress(value: unknown): string {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  return /^0x[0-9a-f]{40}$/.test(normalized) ? normalized : '';
}

function decodeBase64UrlOrBase64(input: string, fieldName: string): Uint8Array {
  try {
    return base64UrlDecode(input);
  } catch {
    try {
      return base64Decode(input);
    } catch (err) {
      throw new Error(
        `Invalid ${fieldName}: expected base64url/base64 string (${errorMessage(err) || 'decode failed'})`,
      );
    }
  }
}

function credentialIdB64uFromAuthenticationCredential(
  credential: WebAuthnAuthenticationCredential,
): string | null {
  const rawId = toOptionalTrimmedString(credential.rawId);
  const id = toOptionalTrimmedString(credential.id);
  const selected = rawId || id;
  if (!selected) return null;
  try {
    return base64UrlEncode(decodeBase64UrlOrBase64(selected, 'webauthn_authentication.rawId'));
  } catch {
    return null;
  }
}

function parseClientDataJsonBase64url(clientDataJSONB64u: string): {
  challenge: string;
  origin: string;
  type: string;
} {
  const bytes = decodeBase64UrlOrBase64(
    clientDataJSONB64u,
    'webauthn_authentication.response.clientDataJSON',
  );
  const json = new TextDecoder().decode(bytes);
  const obj = JSON.parse(json) as unknown;
  if (!isObject(obj)) throw new Error('Invalid clientDataJSON: expected object');
  const challenge = typeof obj.challenge === 'string' ? obj.challenge : '';
  const origin = typeof obj.origin === 'string' ? obj.origin : '';
  const type = typeof obj.type === 'string' ? obj.type : '';
  if (!challenge) throw new Error('Invalid clientDataJSON.challenge');
  if (!origin) throw new Error('Invalid clientDataJSON.origin');
  if (!type) throw new Error('Invalid clientDataJSON.type');
  return { challenge, origin, type };
}

function originHostnameOrEmpty(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isHostWithinRpId(host: string, rpId: string): boolean {
  const h = (host || '').toLowerCase();
  const r = (rpId || '').toLowerCase();
  if (!h || !r) return false;
  if (
    (process.env.NO_CADDY === '1' || process.env.VITE_NO_CADDY === '1') &&
    (h === 'localhost' || h === '127.0.0.1') &&
    r.endsWith('.localhost')
  ) {
    return true;
  }
  return h === r || h.endsWith(`.${r}`);
}

function parseCacheControlMaxAgeSec(cacheControl: string | null): number | null {
  const s = String(cacheControl || '').trim();
  if (!s) return null;
  const m = s.match(/(?:^|,)\s*max-age=(\d+)\s*(?:,|$)/i);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

function normalizeOidcIssuer(input: string): string {
  const trimmed = String(input || '').trim();
  if (!trimmed) return '';
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

function parseJwtSegmentJson(input: string): Record<string, unknown> | null {
  try {
    const raw = new TextDecoder().decode(base64UrlDecode(input));
    const parsed = raw ? JSON.parse(raw) : null;
    return isObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseJwtAud(input: unknown): string[] {
  if (Array.isArray(input)) {
    return input.map((v) => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  }
  const single = toOptionalTrimmedString(input);
  return single ? [single] : [];
}

type ThresholdEd25519RegistrationInput = {
  keyVersion: string;
  recoveryExportCapable?: boolean;
  publicKey: string;
  relayerKeyId: string;
  sessionPolicy: Record<string, unknown> | null;
  sessionKind: string;
};

type ThresholdEd25519BootstrapSession = {
  sessionKind: 'jwt' | 'cookie';
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  expiresAt?: string;
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
};

type ThresholdEcdsaBootstrapSession = {
  sessionKind: 'jwt' | 'cookie';
  sessionId: string;
  walletSigningSessionId: string;
  subjectId?: string;
  keyHandle?: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  expiresAtMs: number;
  expiresAt?: string;
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
};

function parseThresholdEd25519RegistrationInput(raw: unknown): ThresholdEd25519RegistrationInput {
  const body = isObject(raw) ? (raw as Record<string, unknown>) : null;
  return {
    keyVersion: String(body?.key_version || '').trim(),
    recoveryExportCapable:
      typeof body?.recovery_export_capable === 'boolean'
        ? Boolean(body.recovery_export_capable)
        : undefined,
    publicKey: String(body?.public_key || '').trim(),
    relayerKeyId: String(body?.relayer_key_id || '').trim(),
    sessionPolicy: isObject(body?.session_policy)
      ? (body!.session_policy as Record<string, unknown>)
      : null,
    sessionKind: String(body?.session_kind || '')
      .trim()
      .toLowerCase(),
  };
}

function buildFullAccessAddKeyAction(publicKey: string): ActionArgsWasm {
  return {
    action_type: ActionType.AddKey,
    public_key: publicKey,
    access_key: JSON.stringify({
      nonce: 0,
      permission: { FullAccess: {} },
    }),
  };
}

function normalizeBootstrapPublicKeys(args: { publicKey: string; recoveryPublicKey?: string }): {
  publicKey: string;
  recoveryPublicKey?: string;
  expectedPublicKeys: string[];
} {
  const publicKey = ensureEd25519Prefix(toOptionalTrimmedString(args.publicKey) || '');
  if (!publicKey) {
    throw new Error('Missing or invalid bootstrap operational public key');
  }
  const recoveryPublicKey = ensureEd25519Prefix(
    toOptionalTrimmedString(args.recoveryPublicKey) || '',
  );
  if (recoveryPublicKey && recoveryPublicKey === publicKey) {
    throw new Error('Bootstrap recovery public key must differ from the operational public key');
  }
  return {
    publicKey,
    ...(recoveryPublicKey ? { recoveryPublicKey } : {}),
    expectedPublicKeys: recoveryPublicKey ? [publicKey, recoveryPublicKey] : [publicKey],
  };
}

function randomBase64Url(bytes: number): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return base64UrlEncode(data);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function normalizePositiveInteger(raw: unknown, fallback: number): number {
  const value = typeof raw === 'number' ? raw : Number(raw);
  return Number.isFinite(value) && value >= 1 ? Math.floor(value) : fallback;
}

function normalizeRegistrationSignerSelection(
  raw: unknown,
): { ok: true; value: RegistrationSignerSelection } | { ok: false; code: string; message: string } {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'signerSelection must be an object' };
  }
  const mode = String(raw.mode || '').trim();
  const ed25519Raw = isObject(raw.ed25519) ? raw.ed25519 : null;
  const ecdsaRaw = isObject(raw.ecdsa) ? raw.ecdsa : null;

  const normalizeEd25519 = (value: Record<string, unknown> | null) => {
    if (!value) return null;
    const nearAccountId = toOptionalTrimmedString(value.nearAccountId);
    const keyPurpose = toOptionalTrimmedString(value.keyPurpose);
    const keyVersion = toOptionalTrimmedString(value.keyVersion);
    const derivationVersion = Number(value.derivationVersion);
    const participantIds = Array.isArray(value.participantIds)
      ? value.participantIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)
      : [];
    if (
      !nearAccountId ||
      !keyPurpose ||
      !keyVersion ||
      !Number.isInteger(derivationVersion) ||
      derivationVersion < 1 ||
      participantIds.length === 0
    ) {
      return null;
    }
    return {
      nearAccountId,
      signerSlot: normalizePositiveInteger(value.signerSlot, 1),
      participantIds,
      keyPurpose,
      keyVersion,
      derivationVersion,
      createNearAccount: value.createNearAccount !== false,
    };
  };

  const normalizeEcdsa = (value: Record<string, unknown> | null) => {
    if (!value) return null;
    const participantIds = Array.isArray(value.participantIds)
      ? value.participantIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)
      : [];
    const chainTargets = Array.isArray(value.chainTargets) ? value.chainTargets : [];
    if (participantIds.length === 0 || chainTargets.length === 0) return null;
    return { participantIds, chainTargets };
  };

  const ed25519 = normalizeEd25519(ed25519Raw);
  const ecdsa = normalizeEcdsa(ecdsaRaw);
  switch (mode) {
    case 'ed25519_only':
      return ed25519
        ? { ok: true, value: { mode, ed25519 } }
        : { ok: false, code: 'invalid_body', message: 'ed25519 signer spec is invalid' };
    case 'ecdsa_only':
      return ecdsa
        ? { ok: true, value: { mode, ecdsa } }
        : { ok: false, code: 'invalid_body', message: 'ecdsa signer spec is invalid' };
    case 'ed25519_and_ecdsa':
      return ed25519 && ecdsa
        ? { ok: true, value: { mode, ed25519, ecdsa } }
        : {
            ok: false,
            code: 'invalid_body',
            message: 'combined registration requires valid ed25519 and ecdsa specs',
          };
    default:
      return { ok: false, code: 'invalid_body', message: 'unsupported registration mode' };
  }
}

function normalizeAddSignerSelection(
  raw: unknown,
): { ok: true; value: AddSignerSelection } | { ok: false; code: string; message: string } {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'signerSelection must be an object' };
  }
  const mode = String(raw.mode || '').trim();
  if (mode === 'ecdsa') {
    const ecdsaRaw = isObject(raw.ecdsa) ? raw.ecdsa : null;
    const participantIds = Array.isArray(ecdsaRaw?.participantIds)
      ? ecdsaRaw.participantIds
          .map((id) => Number(id))
          .filter((id) => Number.isInteger(id) && id > 0)
      : [];
    const chainTargets = Array.isArray(ecdsaRaw?.chainTargets)
      ? ecdsaRaw.chainTargets.map((target) => thresholdEcdsaChainTargetFromValue(target))
      : [];
    if (
      participantIds.length === 0 ||
      chainTargets.length === 0 ||
      chainTargets.some(Boolean) === false
    ) {
      return { ok: false, code: 'invalid_body', message: 'ecdsa add-signer spec is invalid' };
    }
    const normalizedTargets = chainTargets.filter((target): target is ThresholdEcdsaChainTarget =>
      Boolean(target),
    );
    if (normalizedTargets.length !== chainTargets.length) {
      return { ok: false, code: 'invalid_body', message: 'ecdsa add-signer spec is invalid' };
    }
    return {
      ok: true,
      value: {
        mode: 'ecdsa',
        ecdsa: {
          chainTargets: normalizedTargets,
          participantIds,
        },
      },
    };
  }
  if (mode === 'ed25519') {
    const ed25519Raw = isObject(raw.ed25519) ? raw.ed25519 : null;
    const ed25519Mode = String(ed25519Raw?.mode || '').trim();
    const nearAccountId = toOptionalTrimmedString(ed25519Raw?.nearAccountId);
    const signerSlot = normalizePositiveInteger(ed25519Raw?.signerSlot, 1);
    const keyPurpose = toOptionalTrimmedString(ed25519Raw?.keyPurpose);
    const keyVersion = toOptionalTrimmedString(ed25519Raw?.keyVersion);
    const derivationVersion = normalizePositiveInteger(ed25519Raw?.derivationVersion, 0);
    const participantIds = Array.isArray(ed25519Raw?.participantIds)
      ? ed25519Raw.participantIds
          .map((id) => Number(id))
          .filter((id) => Number.isInteger(id) && id > 0)
      : [];
    if (
      !nearAccountId ||
      !keyPurpose ||
      !keyVersion ||
      !derivationVersion ||
      participantIds.length === 0
    ) {
      return { ok: false, code: 'invalid_body', message: 'ed25519 add-signer spec is invalid' };
    }
    if (ed25519Mode === 'create_near_account') {
      return {
        ok: true,
        value: {
          mode: 'ed25519',
          ed25519: {
            mode: ed25519Mode,
            nearAccountId,
            signerSlot,
            participantIds,
            keyPurpose,
            keyVersion,
            derivationVersion,
          },
        },
      };
    }
    if (ed25519Mode === 'link_existing_near_account') {
      const accountOwnershipProof = normalizeNearAccountOwnershipProofV1(
        ed25519Raw?.accountOwnershipProof,
      );
      if (!accountOwnershipProof) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ed25519 add-signer account ownership proof is required',
        };
      }
      return {
        ok: true,
        value: {
          mode: 'ed25519',
          ed25519: {
            mode: ed25519Mode,
            nearAccountId,
            signerSlot,
            participantIds,
            keyPurpose,
            keyVersion,
            derivationVersion,
            accountOwnershipProof,
          },
        },
      };
    }
  }
  return { ok: false, code: 'invalid_body', message: 'unsupported add-signer mode' };
}

type AdjacentFlowEcdsaPrepareSpec = {
  chainTargets: ThresholdEcdsaChainTarget[];
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signingRootId?: string;
  signingRootVersion?: string;
};

function normalizeAdjacentFlowEcdsaPrepareSpec(
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

function inferRuntimePolicyScopeFromSigningRoot(input: {
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdRuntimePolicyScope | undefined {
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

function normalizeThresholdRuntimePolicyScope(
  raw: unknown,
): ThresholdRuntimePolicyScope | undefined {
  try {
    return normalizeRuntimePolicyScope(raw);
  } catch {
    return undefined;
  }
}

function thresholdRuntimePolicyScopesEqual(leftRaw: unknown, rightRaw: unknown): boolean {
  const left = normalizeThresholdRuntimePolicyScope(leftRaw);
  const right = normalizeThresholdRuntimePolicyScope(rightRaw);
  if (!left || !right) return !left && !right;
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

async function resolveBoundThresholdRuntimePolicyScope(args: {
  bindingStore: WebAuthnCredentialBindingStore;
  userId: string;
  rpId: string;
}): Promise<ThresholdRuntimePolicyScope | undefined> {
  if (typeof args.bindingStore.listByUserId !== 'function') return undefined;
  const bindings = await args.bindingStore.listByUserId({
    userId: args.userId,
    rpId: args.rpId,
  });
  for (const binding of bindings) {
    const scope = normalizeThresholdRuntimePolicyScope(binding.runtimePolicyScope);
    if (scope) return scope;
  }
  return undefined;
}

async function sha256BytesPortable(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle && typeof subtle.digest === 'function') {
    return new Uint8Array(await subtle.digest('SHA-256', toArrayBufferCopy(input)));
  }
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { createHash } = await import('node:crypto');
    return Uint8Array.from(createHash('sha256').update(input).digest());
  }
  throw new Error('SHA-256 digest is unavailable in this runtime');
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

const ED25519_SPKI_DER_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function decodeNearEd25519PublicKey(publicKey: string): Uint8Array | null {
  const normalized = ensureEd25519Prefix(publicKey);
  if (!normalized.startsWith('ed25519:')) return null;
  const encoded = normalized.slice('ed25519:'.length);
  try {
    const decoded = base58Decode(encoded);
    return decoded.length === 32 ? decoded : null;
  } catch {
    return null;
  }
}

async function verifyEd25519SignaturePortable(input: {
  publicKeyBytes: Uint8Array;
  signatureBytes: Uint8Array;
  messageBytes: Uint8Array;
}): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle && typeof subtle.importKey === 'function' && typeof subtle.verify === 'function') {
    try {
      const key = await subtle.importKey(
        'raw',
        toArrayBufferCopy(input.publicKeyBytes),
        { name: 'Ed25519' } as AlgorithmIdentifier,
        false,
        ['verify'],
      );
      return await subtle.verify(
        { name: 'Ed25519' } as AlgorithmIdentifier,
        key,
        toArrayBufferCopy(input.signatureBytes),
        toArrayBufferCopy(input.messageBytes),
      );
    } catch {
      // Fall through to Node's stable Ed25519 verifier when WebCrypto lacks support.
    }
  }
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { createPublicKey, verify } = await import('node:crypto');
    const spkiDer = new Uint8Array(ED25519_SPKI_DER_PREFIX.length + input.publicKeyBytes.length);
    spkiDer.set(ED25519_SPKI_DER_PREFIX, 0);
    spkiDer.set(input.publicKeyBytes, ED25519_SPKI_DER_PREFIX.length);
    const key = createPublicKey({
      key: Buffer.from(spkiDer),
      format: 'der',
      type: 'spki',
    });
    return verify(null, Buffer.from(input.messageBytes), key, Buffer.from(input.signatureBytes));
  }
  return false;
}

async function resolveExistingThresholdEd25519Binding(args: {
  bindingStore: WebAuthnCredentialBindingStore;
  userId: string;
  rpId: string;
}): Promise<WebAuthnCredentialBindingRecord | undefined> {
  if (typeof args.bindingStore.listByUserId !== 'function') return undefined;
  const bindings = await args.bindingStore.listByUserId({
    userId: args.userId,
    rpId: args.rpId,
  });
  return bindings.find((binding) => {
    return Boolean(
      toOptionalTrimmedString(binding.relayerKeyId) &&
      toOptionalTrimmedString(binding.publicKey) &&
      toOptionalTrimmedString(binding.keyVersion) &&
      binding.recoveryExportCapable === true,
    );
  });
}

type EcdsaWalletKeyBuildResult =
  | { ok: true; walletKeys: WalletRegistrationEcdsaWalletKey[] }
  | { ok: false; code: 'incomplete_ecdsa_wallet_key'; message: string };

function buildEcdsaWalletKeysFromBootstrap(args: {
  bootstrap: EcdsaHssServerBootstrapResponse;
  chainTargets: readonly ThresholdEcdsaChainTarget[];
  errorContext: string;
}): EcdsaWalletKeyBuildResult {
  const bootstrap = args.bootstrap;
  const required = {
    walletId: toOptionalTrimmedString(bootstrap.walletId),
    rpId: toOptionalTrimmedString(bootstrap.rpId),
    keyHandle: toOptionalTrimmedString(bootstrap.keyHandle),
    ecdsaThresholdKeyId: toOptionalTrimmedString(bootstrap.ecdsaThresholdKeyId),
    signingRootId: toOptionalTrimmedString(bootstrap.signingRootId),
    signingRootVersion: toOptionalTrimmedString(bootstrap.signingRootVersion),
    thresholdEcdsaPublicKeyB64u: toOptionalTrimmedString(bootstrap.thresholdEcdsaPublicKeyB64u),
    thresholdOwnerAddress: toOptionalTrimmedString(bootstrap.ethereumAddress),
    relayerKeyId: toOptionalTrimmedString(bootstrap.relayerKeyId),
    relayerVerifyingShareB64u: toOptionalTrimmedString(bootstrap.relayerVerifyingShareB64u),
  };
  const missingField = Object.entries(required).find(([, value]) => !value)?.[0];
  if (missingField) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${args.errorContext} returned incomplete ECDSA wallet key material: ${missingField}`,
    };
  }
  const participantIds = Array.isArray(bootstrap.participantIds)
    ? bootstrap.participantIds
        .map((participantId) => Number(participantId))
        .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0)
    : [];
  if (participantIds.length === 0) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${args.errorContext} returned incomplete ECDSA wallet key material: participantIds`,
    };
  }
  if (!Array.isArray(args.chainTargets) || args.chainTargets.length === 0) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${args.errorContext} has no ECDSA chain targets`,
    };
  }
  return {
    ok: true,
    walletKeys: args.chainTargets.map((chainTarget) => ({
      keyScope: 'evm-family',
      chainTarget,
      walletId: required.walletId,
      rpId: required.rpId,
      keyHandle: required.keyHandle,
      ecdsaThresholdKeyId: required.ecdsaThresholdKeyId,
      signingRootId: required.signingRootId,
      signingRootVersion: required.signingRootVersion,
      thresholdEcdsaPublicKeyB64u: required.thresholdEcdsaPublicKeyB64u,
      thresholdOwnerAddress: required.thresholdOwnerAddress,
      relayerKeyId: required.relayerKeyId,
      relayerVerifyingShareB64u: required.relayerVerifyingShareB64u,
      participantIds,
    })),
  };
}

function isMatchingEcdsaClientBootstrap(
  expected: WalletRegistrationEcdsaPreparePayload['prepare'],
  actual: WalletRegistrationEcdsaClientBootstrap,
): boolean {
  return (
    actual.formatVersion === expected.formatVersion &&
    actual.walletId === expected.walletId &&
    actual.rpId === expected.rpId &&
    actual.ecdsaThresholdKeyId === expected.ecdsaThresholdKeyId &&
    actual.signingRootId === expected.signingRootId &&
    actual.signingRootVersion === expected.signingRootVersion &&
    actual.keyScope === expected.keyScope &&
    actual.relayerKeyId === expected.relayerKeyId &&
    actual.registrationPreparationId === expected.registrationPreparationId &&
    actual.requestId === expected.requestId &&
    actual.sessionId === expected.sessionId &&
    actual.walletSigningSessionId === expected.walletSigningSessionId &&
    actual.ttlMs === expected.ttlMs &&
    actual.remainingUses === expected.remainingUses &&
    JSON.stringify(actual.participantIds) === JSON.stringify(expected.participantIds) &&
    thresholdRuntimePolicyScopesEqual(actual.runtimePolicyScope, expected.runtimePolicyScope)
  );
}

function validateThresholdEd25519SessionPolicyBindings(args: {
  requestedSessionPolicy: Record<string, unknown>;
  expectedRelayerKeyId: string;
  expectedNearAccountId: string;
  expectedRpId: string;
}): string | null {
  const requestedPolicyRelayerKeyId = String(args.requestedSessionPolicy.relayerKeyId || '').trim();
  if (requestedPolicyRelayerKeyId && requestedPolicyRelayerKeyId !== args.expectedRelayerKeyId) {
    return 'threshold_ed25519.session_policy.relayerKeyId mismatch';
  }
  const requestedPolicyNearAccountId = String(
    args.requestedSessionPolicy.nearAccountId || '',
  ).trim();
  if (requestedPolicyNearAccountId && requestedPolicyNearAccountId !== args.expectedNearAccountId) {
    return 'threshold_ed25519.session_policy.nearAccountId mismatch';
  }
  const requestedPolicyRpId = String(args.requestedSessionPolicy.rpId || '').trim();
  if (requestedPolicyRpId && requestedPolicyRpId !== args.expectedRpId) {
    return 'threshold_ed25519.session_policy.rpId mismatch';
  }
  return null;
}

function toThresholdEd25519BootstrapSession(session: {
  sessionId?: unknown;
  walletSigningSessionId?: unknown;
  expiresAtMs?: unknown;
  expiresAt?: unknown;
  participantIds?: unknown;
  remainingUses?: unknown;
  runtimePolicyScope?: unknown;
  jwt?: unknown;
}): ThresholdEd25519BootstrapSession | null {
  const sessionId = String(session.sessionId || '').trim();
  const walletSigningSessionId = String(session.walletSigningSessionId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(session.runtimePolicyScope);
  if (!sessionId || !walletSigningSessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0)
    return null;
  return {
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    expiresAtMs: Number(expiresAtMs),
    ...(typeof session.expiresAt === 'string' && session.expiresAt.trim()
      ? { expiresAt: session.expiresAt.trim() }
      : {}),
    ...(Array.isArray(session.participantIds) ? { participantIds: session.participantIds } : {}),
    ...(Number.isFinite(Number(session.remainingUses))
      ? { remainingUses: Number(session.remainingUses) }
      : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(typeof session.jwt === 'string' && session.jwt.trim() ? { jwt: session.jwt.trim() } : {}),
  };
}

function toThresholdEcdsaBootstrapSession(session: {
  sessionId?: unknown;
  walletSigningSessionId?: unknown;
  subjectId?: unknown;
  keyHandle?: unknown;
  chainTarget?: unknown;
  expiresAtMs?: unknown;
  expiresAt?: unknown;
  participantIds?: unknown;
  remainingUses?: unknown;
  runtimePolicyScope?: unknown;
  jwt?: unknown;
}): ThresholdEcdsaBootstrapSession | null {
  const sessionId = String(session.sessionId || '').trim();
  const walletSigningSessionId = String(session.walletSigningSessionId || '').trim();
  const subjectId = String(session.subjectId || '').trim();
  const keyHandle = String(session.keyHandle || '').trim();
  const chainTarget = thresholdEcdsaChainTargetFromValue(session.chainTarget);
  const expiresAtMs = Number(session.expiresAtMs);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(session.runtimePolicyScope);
  if (!sessionId || !walletSigningSessionId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0)
    return null;
  return {
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    ...(subjectId ? { subjectId } : {}),
    ...(keyHandle ? { keyHandle } : {}),
    ...(chainTarget ? { chainTarget } : {}),
    expiresAtMs: Number(expiresAtMs),
    ...(typeof session.expiresAt === 'string' && session.expiresAt.trim()
      ? { expiresAt: session.expiresAt.trim() }
      : {}),
    ...(Array.isArray(session.participantIds) ? { participantIds: session.participantIds } : {}),
    ...(Number.isFinite(Number(session.remainingUses))
      ? { remainingUses: Number(session.remainingUses) }
      : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(typeof session.jwt === 'string' && session.jwt.trim() ? { jwt: session.jwt.trim() } : {}),
  };
}

// =============================
// WASM URL CONSTANTS + HELPERS
// =============================

// Server dist location when this file is emitted to `dist/esm/server/core/AuthService.js`.
const SIGNER_WASM_SERVER_DIST_PATH =
  '../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm';
// Browser dist location can initialize the same signer in local package runs.
const SIGNER_WASM_BROWSER_DIST_PATH = '../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm';
// Worker copy location from `dist/esm/server/core/AuthService.js`.
const SIGNER_WASM_WORKER_DIST_PATH = '../../../workers/wasm_signer_worker_bg.wasm';
// Source-tree location when AuthService is executed directly from `packages/sdk-server-ts/src/core`.
const SIGNER_WASM_SOURCE_PATH = '../../../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm';

function getSignerWasmUrls(logger: NormalizedLogger): URL[] {
  const paths = [
    SIGNER_WASM_SERVER_DIST_PATH,
    SIGNER_WASM_BROWSER_DIST_PATH,
    SIGNER_WASM_WORKER_DIST_PATH,
    SIGNER_WASM_SOURCE_PATH,
  ];
  const resolved: URL[] = [];
  const baseUrl = import.meta.url;

  for (const path of paths) {
    try {
      if (!baseUrl) throw new Error('import.meta.url is undefined');
      resolved.push(new URL(path, baseUrl));
    } catch (err) {
      logger.warn(`Failed to resolve signer WASM relative URL for path "${path}":`, err);
    }
  }

  if (!resolved.length) {
    throw new Error(
      'Unable to resolve signer WASM location from import.meta.url. Provide AuthServiceConfig.signerWasm.moduleOrPath in this runtime.',
    );
  }

  return resolved;
}

function summarizeThresholdStoreConfig(cfg: AuthServiceConfig['thresholdStore']): string {
  if (!cfg) return 'thresholdStore: not configured';

  const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);

  const store = (() => {
    if ('kind' in cfg) {
      if (cfg.kind === 'upstash-redis-rest') return 'upstash';
      if (cfg.kind === 'redis-tcp') return 'redis';
      if (cfg.kind === 'postgres') return 'postgres';
      return 'in-memory';
    }
    const upstashUrl = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_URL);
    const upstashToken = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_TOKEN);
    const redisUrl = toOptionalTrimmedString(cfg.REDIS_URL);
    const postgresUrl = toOptionalTrimmedString(cfg.POSTGRES_URL);
    if (postgresUrl) return 'postgres';
    return upstashUrl || upstashToken ? 'upstash' : redisUrl ? 'redis' : 'in-memory';
  })();

  const hasSigningRootSecretShares = Boolean(
    cfg.signingRootShareResolver ||
    cfg.signingRootSecretResolverAdapters ||
    (cfg.signingRootSecretStore &&
      (cfg.signingRootSecretDecryptAdapter || cfg.signingRootSecretShareKekResolver)),
  );
  const parts = [
    `thresholdStore: configured`,
    `nodeRole=${nodeRole}`,
    `store=${store}`,
    `signingRootSecretShares=${hasSigningRootSecretShares ? 'configured' : 'not_configured'}`,
  ];
  return parts.join(' ');
}

type RegistrationPersistenceRecords = {
  webAuthnAuthenticators: readonly {
    userId: string;
    record: WebAuthnAuthenticatorRecord;
  }[];
  credentialBindings: readonly WebAuthnCredentialBindingRecord[];
  wallet: WalletRecord;
  walletAuthMethods: readonly WalletAuthMethodRecord[];
  walletSigners: readonly WalletSignerRecord[];
  emailOtpEnrollment?: EmailOtpRegistrationEnrollmentPersistence;
};

type GoogleEmailOtpRegistrationActivationPersistence = {
  attempt: PendingGoogleEmailOtpRegistrationAttemptRecord;
  walletId: WalletId;
};

type AddAuthMethodPersistenceRecords = Pick<
  RegistrationPersistenceRecords,
  'webAuthnAuthenticators' | 'walletAuthMethods'
>;

type EmailOtpRegistrationEnrollmentPersistence = {
  previousProviderWalletId?: string;
  enrollment: EmailOtpWalletEnrollmentRecord;
  recoveryWrappedEnrollmentEscrows: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
  authState: EmailOtpAuthStateRecord;
};

type EmailOtpRecoveryChallengeEscrow = Omit<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  | 'recoveryKeyId'
  | 'recoveryKeyStatus'
  | 'issuedAtMs'
  | 'updatedAtMs'
  | 'consumedAtMs'
  | 'revokedAtMs'
>;

function redactEmailOtpRecoveryChallengeEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): EmailOtpRecoveryChallengeEscrow {
  return {
    version: record.version,
    alg: record.alg,
    secretKind: record.secretKind,
    escrowKind: record.escrowKind,
    walletId: record.walletId,
    userId: record.userId,
    authSubjectId: record.authSubjectId,
    authMethod: record.authMethod,
    enrollmentId: record.enrollmentId,
    enrollmentVersion: record.enrollmentVersion,
    enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    nonceB64u: record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: record.aadHashB64u,
  };
}

type EmailOtpRegistrationChallengePurpose =
  | {
      kind: 'registration';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
      operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    }
  | {
      kind: 'registration_reroll';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    };

type EmailOtpRegistrationChallengeProof =
  | {
      kind: 'registration_attempt';
      /** OIDC provider subject from the app-session JWT and registration proof. */
      providerSubject: ProviderSubject;
      /** Challenge owner parsed from the same provider subject boundary input. */
      challengeSubjectId: ChallengeSubjectId;
      /** Email asserted by the signed registration proof. */
      proofEmail: string;
      /** Stable server-side registration-attempt handle for hosted Google flows. */
      registrationAttemptId: EmailOtpRegistrationAttemptId;
      /** Challenge id submitted with the registration proof. */
      challengeId: EmailOtpChallengeId;
      /** Final wallet id selected for registration after any wallet-name reroll. */
      finalWalletId: WalletId;
      /** Tenant scope that must match the OTP challenge record. */
      orgId: OrgId;
      /** App-session version that must match the OTP challenge record. */
      appSessionVersion: AppSessionVersion;
    }
  | {
      kind: 'direct_proof_email';
      /** OIDC provider subject from the app-session JWT and registration proof. */
      providerSubject: ProviderSubject;
      /** Challenge owner parsed from the same provider subject boundary input. */
      challengeSubjectId: ChallengeSubjectId;
      /** Email asserted by the signed registration proof. */
      proofEmail: string;
      registrationAttemptId?: never;
      /** Challenge id submitted with the registration proof. */
      challengeId: EmailOtpChallengeId;
      /** Final wallet id selected for registration after any wallet-name reroll. */
      finalWalletId: WalletId;
      /** Tenant scope that must match the OTP challenge record. */
      orgId: OrgId;
      /** App-session version that must match the OTP challenge record. */
      appSessionVersion: AppSessionVersion;
    };

type VerifiedEmailOtpRegistrationChallengeProofShared = {
  providerSubject: ProviderSubject;
  challengeSubjectId: ChallengeSubjectId;
  challengeEmail: string;
  challengeId: EmailOtpChallengeId;
  originalWalletId: WalletId;
  finalWalletId: WalletId;
  orgId: OrgId;
  appSessionVersion: AppSessionVersion;
  purpose: EmailOtpRegistrationChallengePurpose;
};

type VerifiedEmailOtpRegistrationChallengeProof =
  | (VerifiedEmailOtpRegistrationChallengeProofShared & {
      kind: 'registration_attempt';
      registrationAttemptId: EmailOtpRegistrationAttemptId;
    })
  | (VerifiedEmailOtpRegistrationChallengeProofShared & {
      kind: 'direct_proof_email';
      registrationAttemptId?: never;
    });

type EmailOtpChallengeVerificationIntent =
  | {
      kind: 'registration';
      binding: EmailOtpRegistrationChallengeProof;
      allowWalletReroll: boolean;
    }
  | {
      kind: 'wallet_unlock';
    }
  | {
      kind: 'transaction_sign';
    }
  | {
      kind: 'export_key';
    }
  | {
      kind: 'device_recovery';
    };

type EmailOtpStoredChallengePurpose =
  | {
      kind: 'registration';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
      operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    }
  | {
      kind: 'wallet_unlock';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    }
  | {
      kind: 'transaction_sign';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
    }
  | {
      kind: 'export_key';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_EXPORT_OPERATION;
    }
  | {
      kind: 'device_recovery';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
      operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    };

type EmailOtpChallengeBindingMismatchCode =
  | 'challenge_id_mismatch'
  | 'challenge_purpose_mismatch'
  | 'challenge_subject_mismatch'
  | 'challenge_email_mismatch'
  | 'challenge_wallet_mismatch'
  | 'challenge_session_mismatch'
  | 'challenge_org_mismatch'
  | 'challenge_channel_mismatch'
  | 'registration_reroll_disallowed';

type VerifiedEmailOtpChallengeCodeSuccessBase = {
  challengeId: EmailOtpChallengeId;
  challengeSubjectId: ChallengeSubjectId;
  walletId: WalletId;
  orgId: OrgId;
  email?: string;
  otpChannel: EmailOtpChannel;
};

type VerifiedEmailOtpChallengeCodeSuccess =
  | (VerifiedEmailOtpChallengeCodeSuccessBase & {
      intent: 'registration';
      registrationChallengeProof: VerifiedEmailOtpRegistrationChallengeProof;
    })
  | (VerifiedEmailOtpChallengeCodeSuccessBase & {
      intent: 'wallet_unlock' | 'transaction_sign' | 'export_key' | 'device_recovery';
      registrationChallengeProof?: never;
    });

type VerifiedEmailOtpChallengeCodeResult =
  | ({ ok: true } & VerifiedEmailOtpChallengeCodeSuccess)
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
    };

function emailOtpChallengeVerificationIntentFromRequest(input: {
  expectedAction: EmailOtpChallengeAction;
  expectedOperation?: EmailOtpChallengeOperation;
  registrationChallengeProof?: EmailOtpRegistrationChallengeProof;
  allowRegistrationChallengeReroll?: boolean;
}): EmailOtpChallengeVerificationIntent {
  if (input.expectedAction === WALLET_EMAIL_OTP_ACTIONS.registration) {
    if (!input.registrationChallengeProof) {
      throw new Error('Email OTP registration verification requires registration challenge proof');
    }
    return {
      kind: 'registration',
      binding: input.registrationChallengeProof,
      allowWalletReroll: input.allowRegistrationChallengeReroll === true,
    };
  }
  if (input.expectedAction === WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
    return { kind: 'device_recovery' };
  }
  const operation = input.expectedOperation || WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  if (operation === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION) {
    return { kind: 'transaction_sign' };
  }
  if (operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
    return { kind: 'export_key' };
  }
  return { kind: 'wallet_unlock' };
}

function expectedEmailOtpStoredChallengePurpose(
  intent: EmailOtpChallengeVerificationIntent,
): EmailOtpStoredChallengePurpose {
  switch (intent.kind) {
    case 'registration':
      return {
        kind: 'registration',
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      };
    case 'wallet_unlock':
      return {
        kind: 'wallet_unlock',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      };
    case 'transaction_sign':
      return {
        kind: 'transaction_sign',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      };
    case 'export_key':
      return {
        kind: 'export_key',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      };
    case 'device_recovery':
      return {
        kind: 'device_recovery',
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      };
  }
  return assertNever(intent);
}

function readEmailOtpStoredChallengePurpose(
  record: Pick<EmailOtpChallengeRecord, 'action' | 'operation'>,
): EmailOtpStoredChallengePurpose | null {
  if (
    record.action === WALLET_EMAIL_OTP_ACTIONS.registration &&
    record.operation === WALLET_EMAIL_OTP_REGISTRATION_OPERATION
  ) {
    return {
      kind: 'registration',
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    };
  }
  if (record.action === WALLET_EMAIL_OTP_ACTIONS.login) {
    if (record.operation === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION) {
      return {
        kind: 'transaction_sign',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      };
    }
    if (record.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
      return {
        kind: 'export_key',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      };
    }
    if (record.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION) {
      return {
        kind: 'wallet_unlock',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      };
    }
  }
  if (
    record.action === WALLET_EMAIL_OTP_ACTIONS.deviceRecovery &&
    record.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION
  ) {
    return {
      kind: 'device_recovery',
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    };
  }
  return null;
}

function emailOtpStoredChallengePurposeMatches(input: {
  expected: EmailOtpStoredChallengePurpose;
  actual: EmailOtpStoredChallengePurpose | null;
}): boolean {
  if (!input.actual) return false;
  return (
    input.actual.kind === input.expected.kind &&
    input.actual.action === input.expected.action &&
    input.actual.operation === input.expected.operation
  );
}

function emailOtpRegistrationChallengePurposeForRecord(input: {
  storedPurpose: EmailOtpStoredChallengePurpose | null;
  allowWalletReroll: boolean;
}): EmailOtpRegistrationChallengePurpose | null {
  if (input.storedPurpose?.kind === 'registration') {
    return {
      kind: 'registration',
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    };
  }
  if (input.allowWalletReroll && input.storedPurpose?.kind === 'wallet_unlock') {
    return {
      kind: 'registration_reroll',
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    };
  }
  return null;
}

function buildVerifiedEmailOtpRegistrationChallengeProof(input: {
  record: EmailOtpChallengeRecord;
  challengeSubjectId: ChallengeSubjectId;
  proof: EmailOtpRegistrationChallengeProof;
  storedPurpose: EmailOtpStoredChallengePurpose | null;
  allowWalletReroll: boolean;
}): VerifiedEmailOtpRegistrationChallengeProof | null {
  if (input.record.challengeSubjectId !== input.challengeSubjectId) return null;
  if (input.proof.challengeSubjectId !== input.challengeSubjectId) return null;
  if (String(input.proof.providerSubject) !== String(input.proof.challengeSubjectId)) return null;
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return null;
  if (String(input.record.orgId || '') !== input.proof.orgId) return null;
  if (input.record.appSessionVersion !== input.proof.appSessionVersion) return null;
  const purpose = emailOtpRegistrationChallengePurposeForRecord({
    storedPurpose: input.storedPurpose,
    allowWalletReroll: input.allowWalletReroll,
  });
  if (!purpose) return null;
  const proofEmail = toOptionalTrimmedString(input.proof.proofEmail)?.toLowerCase();
  const challengeEmail = toOptionalTrimmedString(input.record.email)?.toLowerCase();
  if (!proofEmail || !challengeEmail || proofEmail !== challengeEmail) return null;
  const originalWalletId = parseWalletId(input.record.walletId);
  if (!originalWalletId.ok) return null;

  switch (input.proof.kind) {
    case 'registration_attempt':
      return {
        kind: 'registration_attempt',
        providerSubject: input.proof.providerSubject,
        challengeSubjectId: input.proof.challengeSubjectId,
        challengeEmail,
        challengeId: input.proof.challengeId,
        originalWalletId: originalWalletId.value,
        finalWalletId: input.proof.finalWalletId,
        orgId: input.proof.orgId,
        appSessionVersion: input.proof.appSessionVersion,
        purpose,
        registrationAttemptId: input.proof.registrationAttemptId,
      };
    case 'direct_proof_email':
      return {
        kind: 'direct_proof_email',
        providerSubject: input.proof.providerSubject,
        challengeSubjectId: input.proof.challengeSubjectId,
        challengeEmail,
        challengeId: input.proof.challengeId,
        originalWalletId: originalWalletId.value,
        finalWalletId: input.proof.finalWalletId,
        orgId: input.proof.orgId,
        appSessionVersion: input.proof.appSessionVersion,
        purpose,
      };
  }
  return assertNever(input.proof);
}

type EmailOtpRegistrationChallengeProofResult =
  | { ok: true; proof: EmailOtpRegistrationChallengeProof }
  | { ok: false; code: string; message: string };

type EmailOtpRegistrationChallengeProofInput =
  | {
      kind: 'google_registration_attempt';
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      walletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
      registrationAttemptId: EmailOtpRegistrationAttemptId;
      challengeId: EmailOtpChallengeId;
    }
  | {
      kind: 'direct_proof_email';
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      finalWalletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
      proofEmail: string;
      challengeId: EmailOtpChallengeId;
    };

type EmailOtpRegistrationChallengeProofInputResult =
  | { ok: true; input: EmailOtpRegistrationChallengeProofInput }
  | { ok: false; code: string; message: string };

function parseRawEmailOtpRegistrationChallengeProofInput(request: {
  providerSubject: unknown;
  walletId: unknown;
  orgId: unknown;
  appSessionVersion: unknown;
  challengeId: unknown;
  proofEmail?: unknown;
  googleEmailOtpRegistrationAttemptId?: unknown;
}): EmailOtpRegistrationChallengeProofInputResult {
  const providerSubject = parseProviderSubject(request.providerSubject);
  if (!providerSubject.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires providerSubject',
    };
  }
  const challengeSubjectId = parseChallengeSubjectId(request.providerSubject);
  if (!challengeSubjectId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires challengeSubjectId',
    };
  }
  const challengeId = parseEmailOtpChallengeId(request.challengeId);
  if (!challengeId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires challengeId',
    };
  }
  const finalWalletId = parseWalletId(request.walletId);
  if (!finalWalletId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires walletId',
    };
  }
  const orgId = parseOrgId(request.orgId);
  if (!orgId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires orgId',
    };
  }
  const appSessionVersion = parseAppSessionVersion(request.appSessionVersion);
  if (!appSessionVersion.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires appSessionVersion',
    };
  }

  const registrationAttemptId = parseEmailOtpRegistrationAttemptId(
    request.googleEmailOtpRegistrationAttemptId,
  );
  if (registrationAttemptId.ok) {
    return {
      ok: true,
      input: {
        kind: 'google_registration_attempt',
        providerSubject: providerSubject.value,
        challengeSubjectId: challengeSubjectId.value,
        walletId: finalWalletId.value,
        orgId: orgId.value,
        appSessionVersion: appSessionVersion.value,
        registrationAttemptId: registrationAttemptId.value,
        challengeId: challengeId.value,
      },
    };
  }
  if (registrationAttemptId.error.code === 'invalid') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'googleEmailOtpRegistrationAttemptId must be a string',
    };
  }

  const proofEmail = toOptionalTrimmedString(request.proofEmail)?.toLowerCase();
  if (!proofEmail) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires proofEmail',
    };
  }
  return {
    ok: true,
    input: {
      kind: 'direct_proof_email',
      providerSubject: providerSubject.value,
      challengeSubjectId: challengeSubjectId.value,
      finalWalletId: finalWalletId.value,
      orgId: orgId.value,
      appSessionVersion: appSessionVersion.value,
      proofEmail,
      challengeId: challengeId.value,
    },
  };
}

function parseDirectEmailOtpRegistrationChallengeProof(request: {
  providerSubject: unknown;
  proofEmail: unknown;
  challengeId: unknown;
  finalWalletId: unknown;
  orgId: unknown;
  appSessionVersion: unknown;
}): EmailOtpRegistrationChallengeProofResult {
  const providerSubject = parseProviderSubject(request.providerSubject);
  if (!providerSubject.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration proof requires providerSubject',
    };
  }
  const challengeSubjectId = parseChallengeSubjectId(request.providerSubject);
  if (!challengeSubjectId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration proof requires challengeSubjectId',
    };
  }
  const challengeId = parseEmailOtpChallengeId(request.challengeId);
  if (!challengeId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration proof requires challengeId',
    };
  }
  const finalWalletId = parseWalletId(request.finalWalletId);
  if (!finalWalletId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration proof requires finalWalletId',
    };
  }
  const orgId = parseOrgId(request.orgId);
  if (!orgId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration proof requires orgId',
    };
  }
  const appSessionVersion = parseAppSessionVersion(request.appSessionVersion);
  if (!appSessionVersion.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration proof requires appSessionVersion',
    };
  }
  const proofEmail = toOptionalTrimmedString(request.proofEmail)?.toLowerCase();
  if (!proofEmail) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration proof requires proofEmail',
    };
  }
  return {
    ok: true,
    proof: {
      kind: 'direct_proof_email',
      providerSubject: providerSubject.value,
      challengeSubjectId: challengeSubjectId.value,
      proofEmail,
      challengeId: challengeId.value,
      finalWalletId: finalWalletId.value,
      orgId: orgId.value,
      appSessionVersion: appSessionVersion.value,
    },
  };
}

/**
 * Framework-agnostic NEAR account service
 * Core business logic for account creation and registration operations
 */
export class AuthService {
  private config: AuthServiceConfig;
  private isInitialized = false;
  private nearClient: MinimalNearClient;
  private relayerPublicKey: string = '';
  private signerWasmReady = false;
  private readonly logger: NormalizedLogger;
  private thresholdSigningServiceInitialized = false;
  private thresholdSigningService: ThresholdSigningServiceType | null = null;
  private webAuthnAuthenticatorStoreInitialized = false;
  private webAuthnAuthenticatorStore: WebAuthnAuthenticatorStore | null = null;
  private webAuthnLoginChallengeStoreInitialized = false;
  private webAuthnLoginChallengeStore: WebAuthnLoginChallengeStore | null = null;
  private webAuthnCredentialBindingStoreInitialized = false;
  private webAuthnCredentialBindingStore: WebAuthnCredentialBindingStore | null = null;
  private webAuthnSyncChallengeStoreInitialized = false;
  private webAuthnSyncChallengeStore: WebAuthnSyncChallengeStore | null = null;
  private emailOtpChallengeStoreInitialized = false;
  private emailOtpChallengeStore: EmailOtpChallengeStore | null = null;
  private emailOtpGrantStoreInitialized = false;
  private emailOtpGrantStore: EmailOtpGrantStore | null = null;
  private emailOtpWalletEnrollmentStoreInitialized = false;
  private emailOtpWalletEnrollmentStore: EmailOtpWalletEnrollmentStore | null = null;
  private emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized = false;
  private emailOtpRecoveryWrappedEnrollmentEscrowStore: EmailOtpRecoveryWrappedEnrollmentEscrowStore | null =
    null;
  private emailOtpAuthStateStoreInitialized = false;
  private emailOtpAuthStateStore: EmailOtpAuthStateStore | null = null;
  private emailOtpUnlockChallengeStoreInitialized = false;
  private emailOtpUnlockChallengeStore: EmailOtpUnlockChallengeStore | null = null;
  private emailOtpRegistrationAttemptStoreInitialized = false;
  private emailOtpRegistrationAttemptStore: EmailOtpRegistrationAttemptStore | null = null;
  private emailOtpRateLimiterInitialized = false;
  private emailOtpRateLimiter: SigningSessionSealRateLimiter | null = null;
  private registrationPrepareRateLimiterInitialized = false;
  private registrationPrepareRateLimiter: SigningSessionSealRateLimiter | null = null;
  private readonly emailOtpMemoryOutbox = new Map<
    string,
    {
      walletId: string;
      userId: string;
      otpChannel: EmailOtpChannel;
      email: string;
      emailHint: string;
      otpCode: string;
      expiresAtMs: number;
    }
  >();
  private deviceLinkingSessionStoreInitialized = false;
  private deviceLinkingSessionStore: DeviceLinkingSessionStore | null = null;
  private emailRecoveryPreparationStoreInitialized = false;
  private emailRecoveryPreparationStore: EmailRecoveryPreparationStore | null = null;
  private nearPublicKeyStoreInitialized = false;
  private nearPublicKeyStore: NearPublicKeyStore | null = null;
  private recoverySessionStoreInitialized = false;
  private recoverySessionStore: RecoverySessionStore | null = null;
  private recoveryExecutionStoreInitialized = false;
  private recoveryExecutionStore: RecoveryExecutionStore | null = null;
  private identityStoreInitialized = false;
  private identityStore: IdentityStore | null = null;
  private registrationCeremonyStoreInitialized = false;
  private registrationCeremonyStore: RegistrationCeremonyStore | null = null;
  private walletStoreInitialized = false;
  private walletStore: WalletStore | null = null;
  private walletAuthMethodStoreInitialized = false;
  private walletAuthMethodStore: WalletAuthMethodStore | null = null;
  private storageInitPromise: Promise<void> | null = null;
  private registrationRuntimeWarmPromise: Promise<void> | null = null;
  private googleJwksCache: { keysByKid: Map<string, JsonWebKey>; expiresAtMs: number } | null =
    null;
  private googleJwksFetchPromise: Promise<{
    keysByKid: Map<string, JsonWebKey>;
    expiresAtMs: number;
  }> | null = null;
  private oidcJwksCacheByUrl = new Map<
    string,
    { keysByKid: Map<string, JsonWebKey>; expiresAtMs: number }
  >();
  private oidcJwksFetchPromiseByUrl = new Map<
    string,
    Promise<{ keysByKid: Map<string, JsonWebKey>; expiresAtMs: number }>
  >();

  // Transaction queue to prevent nonce conflicts
  private transactionQueue: Promise<any> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  // DKIM/TEE email recovery logic (delegated to EmailRecoveryService)
  public readonly emailRecovery: EmailRecoveryService | null = null;

  constructor(config: AuthServiceConfigInput) {
    this.config = createAuthServiceConfig(config);
    this.logger = coerceLogger(this.config.logger);
    this.nearClient = new MinimalNearClient(this.config.nearRpcUrl);
    this.emailRecovery = new EmailRecoveryService({
      relayerAccount: this.config.relayerAccount,
      relayerPrivateKey: this.config.relayerPrivateKey,
      networkId: this.config.networkId,
      emailDkimVerifierContract: EMAIL_DKIM_VERIFIER_CONTRACT_DEFAULT,
      nearClient: this.nearClient,
      logger: this.config.logger,
      ensureSignerAndRelayerAccount: () => this._ensureSignerAndRelayerAccount(),
      queueTransaction: <T>(fn: () => Promise<T>, label: string) =>
        this.queueTransaction(fn, label),
      fetchTxContext: (accountId: string, publicKey: string) =>
        this.fetchTxContext(accountId, publicKey),
      signWithPrivateKey: (input) => this.signWithPrivateKey(input),
      getRelayerPublicKey: () => this.relayerPublicKey,
    });

    // Log effective configuration at construction time so operators can
    // verify wiring immediately when the service is created.
    this.logger.info(`
    AuthService initialized with:
    • networkId: ${this.config.networkId}
    • nearRpcUrl: ${this.config.nearRpcUrl}
    • relayerAccount: ${this.config.relayerAccount}
    • accountInitialBalance: ${this.config.accountInitialBalance} (${formatYoctoToNear(this.config.accountInitialBalance)} NEAR)
    • createAccountAndRegisterGas: ${this.config.createAccountAndRegisterGas} (${formatGasToTGas(this.config.createAccountAndRegisterGas)})
    • ${summarizeThresholdStoreConfig(this.config.thresholdStore)}
    ${
      this.config.googleOidc?.clientIds?.length
        ? `• googleOidc: ${this.config.googleOidc.clientIds.length} clientId(s)`
        : `• googleOidc: not configured`
    }
    ${
      this.config.oidcExchange?.issuers?.length
        ? `• oidcExchange: ${this.config.oidcExchange.issuers.length} issuer(s)`
        : `• oidcExchange: not configured`
    }
    `);
  }

  /**
   * Initializes backing storage (e.g. Postgres schema) when configured.
   * Safe to call multiple times; initialization is memoized.
   */
  async initStorage(): Promise<void> {
    if (this.storageInitPromise) return this.storageInitPromise;

    this.storageInitPromise = (async () => {
      if (!this.config.thresholdStore) return;

      const cfg = this.config.thresholdStore as unknown as Record<string, unknown>;
      const kind = toOptionalTrimmedString((cfg as any).kind);
      const postgresUrl = getPostgresUrlFromConfig(cfg);

      const usePostgres = kind === 'postgres' || (!kind && Boolean(postgresUrl));
      if (!usePostgres) return;
      if (!postgresUrl) throw new Error('Postgres store selected but POSTGRES_URL is not set');

      await ensurePostgresSchema({ postgresUrl, logger: this.logger });
    })();

    return this.storageInitPromise;
  }

  async getRelayerAccount(): Promise<{ accountId: string; publicKey: string }> {
    await this._ensureSignerAndRelayerAccount();
    return {
      accountId: this.config.relayerAccount,
      publicKey: this.relayerPublicKey,
    };
  }

  /**
   * Lightweight config accessor (no RPC) for diagnostics and well-known endpoints.
   * This is safe to call even when the relayer account has not been warmed/validated yet.
   */
  getConfiguredRelayerAccount(): string {
    return this.config.relayerAccount;
  }

  isGoogleOidcConfigured(): boolean {
    return Boolean(this.config.googleOidc?.clientIds?.length);
  }

  getGoogleOidcPublicConfig(): { configured: boolean; clientId?: string } {
    const clientId = String(this.config.googleOidc?.clientIds?.[0] || '').trim();
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  private isRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = String(this.config.relayerAccount || '').trim();
    return !!relayerAccount && accountId.endsWith(`.${relayerAccount}`);
  }

  private isHostedHmacReadableRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = String(this.config.relayerAccount || '').trim();
    if (!relayerAccount || !accountId.endsWith(`.${relayerAccount}`)) return false;
    const slug = accountId.slice(0, -(relayerAccount.length + 1));
    return /^[a-z]+-[a-z]+-[a-z0-9]{10}$/.test(slug);
  }

  private resolveHostedAccountScope(input?: ThresholdRuntimePolicyScope): {
    projectId: string;
    envId: string;
  } {
    const orgId = toOptionalTrimmedString(input?.orgId);
    const projectId = toOptionalTrimmedString(input?.projectId);
    const envId = toOptionalTrimmedString(input?.envId);
    if (orgId && projectId && envId) {
      return { projectId, envId };
    }
    throw new Error(
      'runtimePolicyScope.orgId, runtimePolicyScope.projectId, and runtimePolicyScope.envId are required for hosted wallet id derivation',
    );
  }

  private async deriveHostedOidcWalletId(input: {
    providerSubject?: string;
    sub?: string;
    email?: string;
    authProvider: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    walletIdDerivationNonce?: string;
    collisionCounter?: number;
  }): Promise<string> {
    const subject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    const email = toOptionalTrimmedString(input.email);
    const walletIdDerivationNonce = toOptionalTrimmedString(input.walletIdDerivationNonce);
    if (!subject && !email) {
      throw new Error('Cannot derive hosted wallet id without provider subject or verified email');
    }
    const scope = this.resolveHostedAccountScope(input.runtimePolicyScope);
    return deriveHostedNearAccountId({
      accountIdDerivationSecret: this.readConfigValue('ACCOUNT_ID_DERIVATION_SECRET'),
      relayerAccount: this.config.relayerAccount,
      projectId: scope.projectId,
      envId: scope.envId,
      authProvider: input.authProvider,
      ...(subject ? { providerSubject: subject } : {}),
      ...(email ? { verifiedEmail: email } : {}),
      ...(walletIdDerivationNonce ? { walletIdDerivationNonce } : {}),
      ...(input.collisionCounter ? { collisionCounter: input.collisionCounter } : {}),
    });
  }

  async resolveOidcWalletId(input: {
    providerSubject?: string;
    sub?: string;
    email?: string;
    accountMode?: unknown;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<string> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject) {
      throw new Error('Cannot resolve OIDC wallet id without provider subject');
    }

    if (providerSubject.startsWith('google:')) {
      const resolution = await this.resolveGoogleEmailOtpSession(input);
      if (resolution.ok) return resolution.walletId;
      const error = new Error(resolution.message) as Error & { code?: string };
      error.code = resolution.code;
      throw error;
    }

    const wallet = `wallet:${providerSubject}`;
    const identity = this.getIdentityStore();
    const linkedWalletId = await identity.getUserIdBySubject(wallet);
    if (linkedWalletId && isValidAccountId(linkedWalletId)) return linkedWalletId;

    return await this.deriveHostedOidcWalletId({
      providerSubject,
      sub: input.sub,
      email: input.email,
      authProvider: 'oidc',
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    });
  }

  private async cleanupGoogleEmailOtpRegistrationAttempts(nowMs = Date.now()): Promise<void> {
    await this.getEmailOtpRegistrationAttemptStore().deleteExpired(nowMs);
  }

  private async createGoogleEmailOtpRegistrationAttempt(input: {
    providerSubject: string;
    email: string;
    walletId: string;
    offerId: string;
    offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
    selectedCandidateId: string;
    appSessionVersion: string;
    authProvider: string;
    walletIdDerivationNonce: string;
    collisionCounter: number;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<GoogleEmailOtpRegistrationAttemptRecord> {
    const now = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(now);
    const attempt: GoogleEmailOtpRegistrationAttemptRecord = {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: this.generateOpaqueId(18),
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: input.walletId,
      offerId: input.offerId,
      offerCandidates: input.offerCandidates,
      selectedCandidateId: input.selectedCandidateId,
      appSessionVersion: input.appSessionVersion,
      authProvider: input.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: input.walletIdDerivationNonce,
      collisionCounter: input.collisionCounter,
      state: 'started',
      createdAtMs: now,
      updatedAtMs: now,
      expiresAtMs: now + 30 * 60 * 1000,
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    };
    await this.getEmailOtpRegistrationAttemptStore().put(attempt);
    return attempt;
  }

  private async findStartedGoogleEmailOtpRegistrationAttempt(input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null> {
    const now = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(now);
    const attempt = await this.getEmailOtpRegistrationAttemptStore().findStartedBySubjectEmail({
      providerSubject: input.providerSubject,
      email: input.email,
      orgId: input.orgId,
      appSessionVersion: input.appSessionVersion,
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
      nowMs: now,
    });
    if (attempt) {
      if (!this.isHostedHmacReadableRelayerSubaccount(attempt.walletId)) {
        await this.getEmailOtpRegistrationAttemptStore().put({
          ...attempt,
          state: 'failed',
          failureCode: 'non_hmac_readable_wallet_id',
          updatedAtMs: now,
        });
        return null;
      }
      const refreshedAttempt = { ...attempt, updatedAtMs: now };
      await this.getEmailOtpRegistrationAttemptStore().put(refreshedAttempt);
      return refreshedAttempt;
    }
    return null;
  }

  private async getGoogleEmailOtpEnrollmentBySubject(input: {
    providerSubject: string;
    orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!providerSubject || !orgId) return null;

    const enrollment = await this.getEmailOtpWalletEnrollmentStore().getByProviderUserId({
      providerUserId: providerSubject,
      orgId,
    });
    if (
      !enrollment ||
      enrollment.providerUserId !== providerSubject ||
      enrollment.orgId !== orgId ||
      !isValidAccountId(enrollment.walletId) ||
      !this.isHostedHmacReadableRelayerSubaccount(enrollment.walletId)
    ) {
      return null;
    }
    return enrollment;
  }

  private async repairGoogleEmailOtpWalletLink(input: {
    providerSubject: string;
    walletId: string;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const linked = await this.getIdentityStore().linkSubjectToUserId({
      userId: input.walletId,
      subject: `wallet:${input.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
    if (!linked.ok) {
      return {
        ok: false,
        code: linked.code,
        message: linked.message,
      };
    }
    return { ok: true };
  }

  private isGoogleEmailOtpEnrollmentLookupMiss(code: string): boolean {
    return (
      code === 'not_found' ||
      code === 'provider_identity_mismatch' ||
      code === 'tenant_scope_mismatch'
    );
  }

  private googleEmailOtpStaleIdentityMapping(input: {
    providerSubject: string;
    linkedWalletId: string;
    email?: string;
  }): {
    ok: false;
    mode: 'stale_identity_mapping';
    code: 'stale_identity_mapping';
    walletId: string;
    providerSubject: string;
    email?: string;
    message: string;
  } {
    return {
      ok: false,
      mode: 'stale_identity_mapping',
      code: 'stale_identity_mapping',
      walletId: input.linkedWalletId,
      providerSubject: input.providerSubject,
      ...(input.email ? { email: input.email } : {}),
      message:
        'Google Email OTP identity mapping is stale. Clear the stale identity mapping with the dev cleanup route before registering this Google account.',
    };
  }

  async consumeGoogleEmailOtpRegistrationAttemptRateLimit(input: {
    providerSubject?: unknown;
    email?: unknown;
    accountMode?: unknown;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    clientIp?: string;
    appSessionUserId?: string;
    restartRegistrationOffer?: unknown;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'invalid_body' | 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register') return { ok: true };
    const providerSubject = parseGoogleProviderSubject(input.providerSubject);
    if (!providerSubject.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: providerSubject.error.message,
      };
    }
    const email = parseVerifiedGoogleEmail(input.email);
    if (!email.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: email.error.message,
      };
    }
    const orgId = parseOrgId(input.runtimePolicyScope?.orgId);
    if (!orgId.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: orgId.error.message,
      };
    }
    const restartOffer =
      input.restartRegistrationOffer === true ||
      String(input.restartRegistrationOffer || '')
        .trim()
        .toLowerCase() === 'true';
    return await this.consumeEmailOtpRateLimit({
      scope: 'googleRegistrationAttempt',
      action: restartOffer
        ? 'google_email_otp_registration_offer_restart'
        : 'google_email_otp_registration_create',
      userId: toOptionalTrimmedString(input.appSessionUserId),
      providerSubject: providerSubject.value,
      orgId: orgId.value,
      clientIp: toOptionalTrimmedString(input.clientIp),
    });
  }

  async resolveGoogleEmailOtpSession(input: {
    providerSubject?: string | GoogleProviderSubject;
    sub?: string;
    email?: string | VerifiedGoogleEmail;
    accountMode?: unknown;
    appSessionVersion?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    restartRegistrationOffer?: unknown;
  }): Promise<GoogleEmailOtpResolutionResult> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject || !providerSubject.startsWith('google:')) {
      throw new Error('Cannot resolve Google Email OTP session without Google provider subject');
    }
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register' && accountMode !== 'login') {
      throw new Error('Google Email OTP accountMode must be register or login');
    }
    const email = toOptionalTrimmedString(input.email)?.toLowerCase() || '';
    const orgId = toOptionalTrimmedString(input.runtimePolicyScope?.orgId) || '';
    if (!orgId) {
      throw new Error('Google Email OTP requires orgId tenant scope');
    }
    const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
    if (accountMode === 'register' && !appSessionVersion) {
      throw new Error('Google Email OTP registration requires appSessionVersion');
    }
    const restartRegistrationOffer =
      input.restartRegistrationOffer === true ||
      String(input.restartRegistrationOffer || '')
        .trim()
        .toLowerCase() === 'true';
    const wallet = `wallet:${providerSubject}`;
    const identity = this.getIdentityStore();
    const linkedWalletId = await identity.getUserIdBySubject(wallet);
    const linkedIsUsableRelayerWallet = !!(
      linkedWalletId &&
      isValidAccountId(linkedWalletId) &&
      this.isRelayerSubaccount(linkedWalletId)
    );
    const linkedIsHostedHmacReadableWallet = !!(
      linkedWalletId && this.isHostedHmacReadableRelayerSubaccount(linkedWalletId)
    );

    if (accountMode === 'login') {
      if (linkedIsUsableRelayerWallet && linkedIsHostedHmacReadableWallet) {
        const enrollment = await this.readActiveEmailOtpEnrollment({
          walletId: linkedWalletId,
          orgId,
          providerUserId: providerSubject,
        });
        if (enrollment.ok) {
          return {
            ok: true,
            mode: 'existing_wallet',
            walletId: linkedWalletId,
            providerSubject,
            ...(email ? { email } : {}),
            hasEmailOtpEnrollment: true,
          };
        }
        if (!this.isGoogleEmailOtpEnrollmentLookupMiss(enrollment.code)) {
          const error = new Error(enrollment.message) as Error & { code?: string };
          error.code = enrollment.code;
          throw error;
        }
      }

      const discovered = await this.getGoogleEmailOtpEnrollmentBySubject({
        providerSubject,
        orgId,
      });
      if (!discovered) {
        if (linkedWalletId) {
          const stale = this.googleEmailOtpStaleIdentityMapping({
            providerSubject,
            linkedWalletId,
            ...(email ? { email } : {}),
          });
          const error = new Error(stale.message) as Error & { code?: string };
          error.code = stale.code;
          throw error;
        }
        const error = new Error('Email OTP enrollment not found') as Error & { code?: string };
        error.code = 'not_found';
        throw error;
      }
      const repaired = await this.repairGoogleEmailOtpWalletLink({
        providerSubject,
        walletId: discovered.walletId,
      });
      if (!repaired.ok) {
        const error = new Error(repaired.message) as Error & { code?: string };
        error.code = repaired.code;
        throw error;
      }
      return {
        ok: true,
        mode: 'existing_wallet',
        walletId: discovered.walletId,
        providerSubject,
        ...(email ? { email } : {}),
        hasEmailOtpEnrollment: true,
      };
    }

    if (!email) {
      throw new Error('Email is required to register a Google Email OTP wallet id');
    }

    const discoveredExistingEnrollment = await this.getGoogleEmailOtpEnrollmentBySubject({
      providerSubject,
      orgId,
    });
    if (discoveredExistingEnrollment && !restartRegistrationOffer) {
      const repaired = await this.repairGoogleEmailOtpWalletLink({
        providerSubject,
        walletId: discoveredExistingEnrollment.walletId,
      });
      if (!repaired.ok) {
        return {
          ok: false,
          mode: 'registration_incomplete',
          code: 'registration_incomplete',
          walletId: discoveredExistingEnrollment.walletId,
          providerSubject,
          email,
          message: repaired.message,
        };
      }
      return {
        ok: true,
        mode: 'existing_wallet',
        walletId: discoveredExistingEnrollment.walletId,
        providerSubject,
        email,
        hasEmailOtpEnrollment: true,
      };
    }
    if (linkedWalletId && !restartRegistrationOffer) {
      return this.googleEmailOtpStaleIdentityMapping({
        providerSubject,
        linkedWalletId,
        email,
      });
    }

    const now = Date.now();
    await this.getEmailOtpRegistrationAttemptStore().abandonStartedBySubjectEmailExceptAppSession({
      providerSubject,
      email,
      orgId,
      appSessionVersion,
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
      nowMs: now,
      failureCode: 'app_session_version_replaced',
    });

    const startedAttempt = await this.findStartedGoogleEmailOtpRegistrationAttempt({
      providerSubject,
      email,
      orgId,
      appSessionVersion,
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    });
    if (startedAttempt) {
      if (restartRegistrationOffer) {
        await this.getEmailOtpRegistrationAttemptStore().put({
          ...startedAttempt,
          state: 'abandoned',
          failureCode: 'offer_restarted_by_user',
          updatedAtMs: Date.now(),
        });
      } else {
        const [selectedOfferCandidate, ...remainingOfferCandidates] =
          startedAttempt.offerCandidates;
        const firstCandidate = {
          candidateId: selectedOfferCandidate.candidateId,
          walletId: selectedOfferCandidate.walletId,
        };
        const remainingCandidates = remainingOfferCandidates.map((candidate) => ({
          candidateId: candidate.candidateId,
          walletId: candidate.walletId,
        }));
        return {
          ok: true,
          mode: 'register_started',
          walletId: startedAttempt.walletId,
          providerSubject,
          email,
          registrationAttemptId: startedAttempt.attemptId,
          expiresAtMs: startedAttempt.expiresAtMs,
          offer: {
            offerId: startedAttempt.offerId,
            selectedCandidateId: startedAttempt.selectedCandidateId,
            candidates: [firstCandidate, ...remainingCandidates],
          },
        };
      }
    }

    const nowMs = Date.now();
    const authProvider = 'google_oidc';
    const walletIdDerivationNonce = this.generateOpaqueId(18);
    const offerCandidates: {
      candidateId: string;
      walletId: string;
      collisionCounter: number;
    }[] = [];
    for (let attempt = 0; attempt < 30 && offerCandidates.length < 5; attempt++) {
      const candidate = await this.deriveHostedOidcWalletId({
        providerSubject,
        email,
        authProvider,
        walletIdDerivationNonce,
        ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
        ...(attempt ? { collisionCounter: attempt } : {}),
      });
      const inUseByLiveAttempt =
        await this.getEmailOtpRegistrationAttemptStore().hasLiveStartedWalletAttempt({
          walletId: candidate,
          nowMs,
        });
      const inUseByEnrollment = await this.getEmailOtpWalletEnrollmentStore().get(candidate);
      if (inUseByEnrollment) continue;
      if (inUseByLiveAttempt) continue;
      const existingSubjects = await identity.listSubjectsByUserId(candidate);
      const linkedToDifferentWallet = existingSubjects.some(
        (subject) => subject.startsWith('wallet:') && subject !== wallet,
      );
      if (linkedToDifferentWallet) continue;
      offerCandidates.push({
        candidateId: this.generateOpaqueId(18),
        walletId: candidate,
        collisionCounter: attempt,
      });
    }
    const [selectedCandidate, ...remainingOfferCandidates] = offerCandidates;
    if (!selectedCandidate) {
      return {
        ok: false,
        mode: 'registration_incomplete',
        code: 'registration_incomplete',
        providerSubject,
        email,
        message: 'Unable to allocate a fresh Google Email OTP registration attempt',
      };
    }

    const nonEmptyOfferCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates = [
      selectedCandidate,
      ...remainingOfferCandidates,
    ];
    const walletId = selectedCandidate.walletId;
    const offerId = this.generateOpaqueId(18);
    const attempt = await this.createGoogleEmailOtpRegistrationAttempt({
      providerSubject,
      email,
      walletId,
      offerId,
      offerCandidates: nonEmptyOfferCandidates,
      selectedCandidateId: selectedCandidate.candidateId,
      appSessionVersion,
      authProvider,
      walletIdDerivationNonce,
      collisionCounter: selectedCandidate.collisionCounter,
      ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    });
    const [firstOfferCandidate, ...remainingOfferCandidatesForResponse] = nonEmptyOfferCandidates;
    const firstCandidate = {
      candidateId: firstOfferCandidate.candidateId,
      walletId: firstOfferCandidate.walletId,
    };
    const remainingCandidates = remainingOfferCandidatesForResponse.map((candidate) => ({
      candidateId: candidate.candidateId,
      walletId: candidate.walletId,
    }));
    return {
      ok: true,
      mode: 'register_started',
      walletId,
      providerSubject,
      email,
      registrationAttemptId: attempt.attemptId,
      expiresAtMs: attempt.expiresAtMs,
      offer: {
        offerId,
        selectedCandidateId: selectedCandidate.candidateId,
        candidates: [firstCandidate, ...remainingCandidates],
      },
    };
  }

  async completeGoogleEmailOtpRegistrationAttempt(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return { ok: true };
    const walletId = toOptionalTrimmedString(input.walletId);
    const attempt = await this.getEmailOtpRegistrationAttemptStore().get(registrationAttemptId);
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      await this.getEmailOtpRegistrationAttemptStore().put({
        ...attempt,
        state: 'expired',
        updatedAtMs: Date.now(),
      });
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (walletId !== attempt.walletId) {
      return {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'registrationAttemptId does not match walletId',
      };
    }
    if (attempt.state !== 'started' && attempt.state !== 'key_finalized') {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt is no longer active',
      };
    }
    const identity = this.getIdentityStore();
    const linked = await identity.linkSubjectToUserId({
      userId: attempt.walletId,
      subject: `wallet:${attempt.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
    if (!linked.ok) {
      await this.getEmailOtpRegistrationAttemptStore().put({
        ...attempt,
        state: 'failed',
        failureCode: linked.code,
        updatedAtMs: Date.now(),
      });
      return {
        ok: false,
        code: linked.code,
        message: linked.message,
      };
    }
    await this.getEmailOtpRegistrationAttemptStore().put({
      ...attempt,
      state: 'active',
      updatedAtMs: Date.now(),
    });
    return { ok: true };
  }

  async recordGoogleEmailOtpRegistrationAttemptPublicKey(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    finalizedPublicKey?: unknown;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return { ok: true };
    const walletId = toOptionalTrimmedString(input.walletId);
    const finalizedPublicKey = toOptionalTrimmedString(input.finalizedPublicKey);
    const attempt = await this.getEmailOtpRegistrationAttemptStore().get(registrationAttemptId);
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      await this.getEmailOtpRegistrationAttemptStore().put({
        ...attempt,
        state: 'expired',
        updatedAtMs: Date.now(),
      });
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (walletId !== attempt.walletId) {
      return {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'registrationAttemptId does not match walletId',
      };
    }
    if (
      attempt.state !== 'started' &&
      attempt.state !== 'key_finalized' &&
      attempt.state !== 'active'
    ) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt is no longer active',
      };
    }
    if (attempt.state === 'started') {
      if (!finalizedPublicKey) {
        await this.getEmailOtpRegistrationAttemptStore().put({
          ...attempt,
          updatedAtMs: Date.now(),
        });
      } else {
        await this.getEmailOtpRegistrationAttemptStore().put({
          ...attempt,
          state: 'key_finalized',
          finalizedPublicKey,
          updatedAtMs: Date.now(),
        });
      }
      return { ok: true };
    }
    await this.getEmailOtpRegistrationAttemptStore().put({
      ...attempt,
      ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
      updatedAtMs: Date.now(),
    });
    return { ok: true };
  }

  async failGoogleEmailOtpRegistrationAttempt(input: {
    registrationAttemptId?: unknown;
    walletId?: unknown;
    failureCode?: unknown;
  }): Promise<void> {
    const registrationAttemptId = toOptionalTrimmedString(input.registrationAttemptId);
    if (!registrationAttemptId) return;
    const attempt = await this.getEmailOtpRegistrationAttemptStore().get(registrationAttemptId);
    if (!attempt) return;
    const walletId = toOptionalTrimmedString(input.walletId);
    if (walletId && walletId !== attempt.walletId) return;
    await this.getEmailOtpRegistrationAttemptStore().put({
      ...attempt,
      state: 'failed',
      failureCode: toOptionalTrimmedString(input.failureCode) || 'failed',
      updatedAtMs: Date.now(),
    });
  }

  async cleanupGoogleEmailOtpDevRegistrationState(input: {
    providerSubject?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    nowMs?: unknown;
  }): Promise<
    | {
        ok: true;
        providerSubject: string;
        expiredRegistrationAttemptsDeleted: number;
        linkedWalletId?: string;
        orphanedWalletMappingRemoved: boolean;
        orphanedWalletMappingSkippedReason?:
          | 'no_linked_wallet'
          | 'wallet_id_mismatch'
          | 'not_relayer_subaccount'
          | 'active_email_otp_enrollment'
          | 'mismatched_email_otp_enrollment';
      }
    | { ok: false; code: string; message: string }
  > {
    if (this.isProductionEnvironment()) {
      return {
        ok: false,
        code: 'not_found',
        message: 'Google Email OTP dev cleanup is not available',
      };
    }

    const providerSubject = toOptionalTrimmedString(input.providerSubject);
    if (!providerSubject || !providerSubject.startsWith('google:')) {
      return { ok: false, code: 'invalid_body', message: 'Missing Google provider subject' };
    }

    const requestedWalletId = toOptionalTrimmedString(input.walletId);
    const requestedOrgId = toOptionalTrimmedString(input.orgId);
    const nowMsRaw = typeof input.nowMs === 'number' ? input.nowMs : Number(input.nowMs);
    const nowMs = Number.isFinite(nowMsRaw) && nowMsRaw > 0 ? Math.floor(nowMsRaw) : Date.now();
    const expiredRegistrationAttemptsDeleted =
      await this.getEmailOtpRegistrationAttemptStore().deleteExpired(nowMs);

    const identity = this.getIdentityStore();
    const subject = `wallet:${providerSubject}`;
    const linkedWalletId = await identity.getUserIdBySubject(subject);
    if (!linkedWalletId) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'no_linked_wallet',
      };
    }

    if (requestedWalletId && requestedWalletId !== linkedWalletId) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'wallet_id_mismatch',
      };
    }

    if (!isValidAccountId(linkedWalletId) || !this.isRelayerSubaccount(linkedWalletId)) {
      return {
        ok: true,
        providerSubject,
        expiredRegistrationAttemptsDeleted,
        linkedWalletId,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'not_relayer_subaccount',
      };
    }

    const activeEnrollment = await this.getEmailOtpWalletEnrollmentStore().get(linkedWalletId);
    if (activeEnrollment) {
      const enrollmentMatchesProvider = activeEnrollment.providerUserId === providerSubject;
      const enrollmentMatchesOrg = !requestedOrgId || activeEnrollment.orgId === requestedOrgId;
      if (enrollmentMatchesProvider && enrollmentMatchesOrg) {
        return {
          ok: true,
          providerSubject,
          expiredRegistrationAttemptsDeleted,
          linkedWalletId,
          orphanedWalletMappingRemoved: false,
          orphanedWalletMappingSkippedReason: 'active_email_otp_enrollment',
        };
      }
    }
    const deleted = await identity.deleteSubjectLinkForDevCleanup({
      userId: linkedWalletId,
      subject,
    });
    if (!deleted.ok && deleted.code !== 'not_found') return deleted;

    return {
      ok: true,
      providerSubject,
      expiredRegistrationAttemptsDeleted,
      linkedWalletId,
      orphanedWalletMappingRemoved: deleted.ok,
    };
  }

  isOidcExchangeConfigured(): boolean {
    return Boolean(this.config.oidcExchange?.issuers?.length);
  }

  async warmRegistrationRuntime(): Promise<void> {
    if (this.registrationRuntimeWarmPromise) return this.registrationRuntimeWarmPromise;

    this.registrationRuntimeWarmPromise = (async () => {
      const warmStartedAt = Date.now();
      await this.initStorage();

      const relayerWarmStartedAt = Date.now();
      await this.getRelayerAccount();
      this.logger.info(
        `[AuthService] registration runtime relayer/signer warm completed in ${
          Date.now() - relayerWarmStartedAt
        }ms`,
      );

      const thresholdWarmStartedAt = Date.now();
      const threshold = this.getThresholdSigningService();
      if (threshold) {
        await ensureThresholdEd25519HssWasm();
      }
      this.logger.info(
        `[AuthService] registration runtime threshold warm completed in ${
          Date.now() - thresholdWarmStartedAt
        }ms`,
      );

      const storeWarmStartedAt = Date.now();
      this.getWebAuthnAuthenticatorStore();
      this.getWebAuthnCredentialBindingStore();
      this.getNearPublicKeyStore();
      this.logger.info(
        `[AuthService] registration runtime storage warm completed in ${
          Date.now() - storeWarmStartedAt
        }ms`,
      );

      this.logger.info(
        `[AuthService] registration runtime warm completed in ${Date.now() - warmStartedAt}ms`,
      );
    })();

    try {
      await this.registrationRuntimeWarmPromise;
    } catch (error) {
      this.registrationRuntimeWarmPromise = null;
      throw error;
    }
  }

  async viewAccessKeyList(accountId: string): Promise<AccessKeyList> {
    await this._ensureSignerAndRelayerAccount();
    return this.nearClient.viewAccessKeyList(accountId);
  }

  async dispatchNearSignedTransactionBorsh(input: {
    signedTransactionBorshB64u: string;
  }): Promise<{ rpcResult: FinalExecutionOutcome }> {
    await this._ensureSignerAndRelayerAccount();
    const signedTransactionBorsh = base64UrlDecode(input.signedTransactionBorshB64u);
    const signedTransaction = SignedTransaction.fromPlain({
      transaction: {},
      signature: {},
      borsh_bytes: Array.from(signedTransactionBorsh),
    });
    return {
      rpcResult: await this.nearClient.sendTransaction(signedTransaction),
    };
  }

  /**
   * Lazily constructs the threshold signing service when `thresholdStore` is configured.
   * Routers may call this to auto-enable `/threshold-ed25519/*` endpoints.
   */
  getThresholdSigningService(): ThresholdSigningServiceType | null {
    if (this.thresholdSigningServiceInitialized) return this.thresholdSigningService;
    this.thresholdSigningServiceInitialized = true;

    if (!this.config.thresholdStore) {
      this.thresholdSigningService = null;
      return null;
    }

    this.thresholdSigningService = createThresholdSigningService({
      authService: this,
      thresholdStore: this.config.thresholdStore,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.thresholdSigningService;
  }

  /**
   * Explicit injection seam for environments that need AuthService and the threshold
   * service to share one already-constructed instance, such as E2E harnesses.
   */
  setThresholdSigningService(service: ThresholdSigningServiceType | null): void {
    this.thresholdSigningServiceInitialized = true;
    this.thresholdSigningService = service;
  }

  private getWebAuthnAuthenticatorStore(): WebAuthnAuthenticatorStore {
    if (this.webAuthnAuthenticatorStoreInitialized && this.webAuthnAuthenticatorStore) {
      return this.webAuthnAuthenticatorStore;
    }
    if (this.webAuthnAuthenticatorStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnAuthenticatorStore = createWebAuthnAuthenticatorStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnAuthenticatorStore;
    }

    this.webAuthnAuthenticatorStoreInitialized = true;
    this.webAuthnAuthenticatorStore = createWebAuthnAuthenticatorStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnAuthenticatorStore;
  }

  private getWebAuthnLoginChallengeStore(): WebAuthnLoginChallengeStore {
    if (this.webAuthnLoginChallengeStoreInitialized && this.webAuthnLoginChallengeStore) {
      return this.webAuthnLoginChallengeStore;
    }
    if (this.webAuthnLoginChallengeStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnLoginChallengeStore = createWebAuthnLoginChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnLoginChallengeStore;
    }

    this.webAuthnLoginChallengeStoreInitialized = true;
    this.webAuthnLoginChallengeStore = createWebAuthnLoginChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnLoginChallengeStore;
  }

  private getWebAuthnCredentialBindingStore(): WebAuthnCredentialBindingStore {
    if (this.webAuthnCredentialBindingStoreInitialized && this.webAuthnCredentialBindingStore) {
      return this.webAuthnCredentialBindingStore;
    }
    if (this.webAuthnCredentialBindingStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnCredentialBindingStore = createWebAuthnCredentialBindingStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnCredentialBindingStore;
    }

    this.webAuthnCredentialBindingStoreInitialized = true;
    this.webAuthnCredentialBindingStore = createWebAuthnCredentialBindingStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnCredentialBindingStore;
  }

  private getWebAuthnSyncChallengeStore(): WebAuthnSyncChallengeStore {
    if (this.webAuthnSyncChallengeStoreInitialized && this.webAuthnSyncChallengeStore) {
      return this.webAuthnSyncChallengeStore;
    }
    if (this.webAuthnSyncChallengeStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnSyncChallengeStore = createWebAuthnSyncChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnSyncChallengeStore;
    }

    this.webAuthnSyncChallengeStoreInitialized = true;
    this.webAuthnSyncChallengeStore = createWebAuthnSyncChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnSyncChallengeStore;
  }

  private getRegistrationCeremonyStore(): RegistrationCeremonyStore {
    if (this.registrationCeremonyStoreInitialized && this.registrationCeremonyStore) {
      return this.registrationCeremonyStore;
    }
    if (this.registrationCeremonyStoreInitialized) {
      this.registrationCeremonyStore = createRegistrationCeremonyStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.registrationCeremonyStore;
    }
    this.registrationCeremonyStoreInitialized = true;
    this.registrationCeremonyStore = createRegistrationCeremonyStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.registrationCeremonyStore;
  }

  private getWalletStore(): WalletStore {
    if (this.walletStoreInitialized && this.walletStore) {
      return this.walletStore;
    }
    if (this.walletStoreInitialized) {
      this.walletStore = createWalletStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.walletStore;
    }
    this.walletStoreInitialized = true;
    this.walletStore = createWalletStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.walletStore;
  }

  private getWalletAuthMethodStore(): WalletAuthMethodStore {
    if (this.walletAuthMethodStoreInitialized && this.walletAuthMethodStore) {
      return this.walletAuthMethodStore;
    }
    if (this.walletAuthMethodStoreInitialized) {
      this.walletAuthMethodStore = createWalletAuthMethodStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.walletAuthMethodStore;
    }
    this.walletAuthMethodStoreInitialized = true;
    this.walletAuthMethodStore = createWalletAuthMethodStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.walletAuthMethodStore;
  }

  private getEmailOtpChallengeStore(): EmailOtpChallengeStore {
    if (this.emailOtpChallengeStoreInitialized && this.emailOtpChallengeStore) {
      return this.emailOtpChallengeStore;
    }
    if (this.emailOtpChallengeStoreInitialized) {
      this.emailOtpChallengeStore = createEmailOtpChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpChallengeStore;
    }
    this.emailOtpChallengeStoreInitialized = true;
    this.emailOtpChallengeStore = createEmailOtpChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpChallengeStore;
  }

  private getEmailOtpGrantStore(): EmailOtpGrantStore {
    if (this.emailOtpGrantStoreInitialized && this.emailOtpGrantStore) {
      return this.emailOtpGrantStore;
    }
    if (this.emailOtpGrantStoreInitialized) {
      this.emailOtpGrantStore = createEmailOtpGrantStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpGrantStore;
    }
    this.emailOtpGrantStoreInitialized = true;
    this.emailOtpGrantStore = createEmailOtpGrantStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpGrantStore;
  }

  private getEmailOtpWalletEnrollmentStore(): EmailOtpWalletEnrollmentStore {
    if (this.emailOtpWalletEnrollmentStoreInitialized && this.emailOtpWalletEnrollmentStore) {
      return this.emailOtpWalletEnrollmentStore;
    }
    if (this.emailOtpWalletEnrollmentStoreInitialized) {
      this.emailOtpWalletEnrollmentStore = createEmailOtpWalletEnrollmentStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpWalletEnrollmentStore;
    }
    this.emailOtpWalletEnrollmentStoreInitialized = true;
    this.emailOtpWalletEnrollmentStore = createEmailOtpWalletEnrollmentStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpWalletEnrollmentStore;
  }

  private getEmailOtpRecoveryWrappedEnrollmentEscrowStore(): EmailOtpRecoveryWrappedEnrollmentEscrowStore {
    if (
      this.emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized &&
      this.emailOtpRecoveryWrappedEnrollmentEscrowStore
    ) {
      return this.emailOtpRecoveryWrappedEnrollmentEscrowStore;
    }
    if (this.emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized) {
      this.emailOtpRecoveryWrappedEnrollmentEscrowStore =
        createEmailOtpRecoveryWrappedEnrollmentEscrowStore({
          config: this.config.thresholdStore || null,
          logger: this.logger,
          isNode: this.isNodeEnvironment(),
        });
      return this.emailOtpRecoveryWrappedEnrollmentEscrowStore;
    }
    this.emailOtpRecoveryWrappedEnrollmentEscrowStoreInitialized = true;
    this.emailOtpRecoveryWrappedEnrollmentEscrowStore =
      createEmailOtpRecoveryWrappedEnrollmentEscrowStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
    return this.emailOtpRecoveryWrappedEnrollmentEscrowStore;
  }

  private getEmailOtpAuthStateStore(): EmailOtpAuthStateStore {
    if (this.emailOtpAuthStateStoreInitialized && this.emailOtpAuthStateStore) {
      return this.emailOtpAuthStateStore;
    }
    if (this.emailOtpAuthStateStoreInitialized) {
      this.emailOtpAuthStateStore = createEmailOtpAuthStateStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpAuthStateStore;
    }
    this.emailOtpAuthStateStoreInitialized = true;
    this.emailOtpAuthStateStore = createEmailOtpAuthStateStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpAuthStateStore;
  }

  private getEmailOtpUnlockChallengeStore(): EmailOtpUnlockChallengeStore {
    if (this.emailOtpUnlockChallengeStoreInitialized && this.emailOtpUnlockChallengeStore) {
      return this.emailOtpUnlockChallengeStore;
    }
    if (this.emailOtpUnlockChallengeStoreInitialized) {
      this.emailOtpUnlockChallengeStore = createEmailOtpUnlockChallengeStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpUnlockChallengeStore;
    }
    this.emailOtpUnlockChallengeStoreInitialized = true;
    this.emailOtpUnlockChallengeStore = createEmailOtpUnlockChallengeStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpUnlockChallengeStore;
  }

  private getEmailOtpRegistrationAttemptStore(): EmailOtpRegistrationAttemptStore {
    if (this.emailOtpRegistrationAttemptStoreInitialized && this.emailOtpRegistrationAttemptStore) {
      return this.emailOtpRegistrationAttemptStore;
    }
    if (this.emailOtpRegistrationAttemptStoreInitialized) {
      this.emailOtpRegistrationAttemptStore = createEmailOtpRegistrationAttemptStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailOtpRegistrationAttemptStore;
    }
    this.emailOtpRegistrationAttemptStoreInitialized = true;
    this.emailOtpRegistrationAttemptStore = createEmailOtpRegistrationAttemptStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailOtpRegistrationAttemptStore;
  }

  private isProductionEnvironment(): boolean {
    const raw = String((globalThis as any)?.process?.env?.NODE_ENV || '')
      .trim()
      .toLowerCase();
    return raw === 'production';
  }

  private readConfigValue(name: string): string {
    const fromStoreConfig = toOptionalTrimmedString(
      (this.config.thresholdStore as Record<string, unknown> | null | undefined)?.[name],
    );
    if (fromStoreConfig) return fromStoreConfig;
    return toOptionalTrimmedString((globalThis as any)?.process?.env?.[name]) || '';
  }

  private readEmailOtpConfigValue(name: string): string {
    return this.readConfigValue(name);
  }

  private readRegistrationPrepareRateLimitConfigValue(name: string): string {
    return this.readConfigValue(name);
  }

  private getRegistrationPrepareRateLimiter(): SigningSessionSealRateLimiter {
    if (this.registrationPrepareRateLimiterInitialized && this.registrationPrepareRateLimiter) {
      return this.registrationPrepareRateLimiter;
    }
    const limiterKind =
      (this.readRegistrationPrepareRateLimitConfigValue('REGISTRATION_PREPARE_RATE_LIMITER_KIND') as
        | 'in-memory'
        | 'upstash-redis-rest'
        | 'redis-tcp'
        | '') || null;
    const limiter = resolveSigningSessionSealRateLimitFromEnv({
      limiterKind,
      upstashUrl:
        this.readRegistrationPrepareRateLimitConfigValue(
          'REGISTRATION_PREPARE_RATE_LIMIT_UPSTASH_URL',
        ) || null,
      upstashToken:
        this.readRegistrationPrepareRateLimitConfigValue(
          'REGISTRATION_PREPARE_RATE_LIMIT_UPSTASH_TOKEN',
        ) || null,
      redisUrl:
        this.readRegistrationPrepareRateLimitConfigValue(
          'REGISTRATION_PREPARE_RATE_LIMIT_REDIS_URL',
        ) || null,
      keyPrefix:
        this.readRegistrationPrepareRateLimitConfigValue(
          'REGISTRATION_PREPARE_RATE_LIMIT_KEY_PREFIX',
        ) || 'registration-prepare:v1:',
      limit: 1,
      windowMs: 1,
    }).limiter;
    this.registrationPrepareRateLimiterInitialized = true;
    this.registrationPrepareRateLimiter = limiter;
    return limiter;
  }

  private parseRegistrationPrepareRateLimitInt(
    name: string,
    raw: string,
    defaultValue: number,
    min: number,
    max: number,
  ): number {
    const normalized = String(raw || '').trim();
    if (!normalized) return defaultValue;
    const n = Number(normalized);
    if (!Number.isFinite(n)) {
      throw new Error(`${name} must be a finite number`);
    }
    if (n < min || n > max) {
      throw new Error(`${name} must be between ${min} and ${max}`);
    }
    return Math.floor(n);
  }

  private resolveRegistrationPrepareRateLimitPolicy(): { limit: number; windowMs: number } {
    const production = this.isProductionEnvironment();
    const defaults = production ? { limit: 1, windowMs: 5_000 } : { limit: 100, windowMs: 60_000 };
    return {
      limit: this.parseRegistrationPrepareRateLimitInt(
        'REGISTRATION_PREPARE_RATE_LIMIT_MAX',
        this.readRegistrationPrepareRateLimitConfigValue('REGISTRATION_PREPARE_RATE_LIMIT_MAX'),
        defaults.limit,
        1,
        10_000,
      ),
      windowMs: this.parseRegistrationPrepareRateLimitInt(
        'REGISTRATION_PREPARE_RATE_LIMIT_WINDOW_MS',
        this.readRegistrationPrepareRateLimitConfigValue(
          'REGISTRATION_PREPARE_RATE_LIMIT_WINDOW_MS',
        ),
        defaults.windowMs,
        1_000,
        24 * 60 * 60_000,
      ),
    };
  }

  private async consumeRegistrationPrepareRateLimit(args: {
    request: WalletRegistrationPrepareRequest;
    storedIntent: StoredRegistrationIntent;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited' | 'invalid_body';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const gate = args.request.prepareGate;
    if (gate.kind === 'source_unavailable') {
      if (!this.isProductionEnvironment()) return { ok: true };
      return {
        ok: false,
        code: 'invalid_body',
        message: 'registration prepare requires source IP context',
      };
    }

    const limiter = this.getRegistrationPrepareRateLimiter();
    const policy = this.resolveRegistrationPrepareRateLimitPolicy();
    const authMethod = args.storedIntent.intent.authMethod;
    const email =
      authMethod.kind === 'email_otp' ? toOptionalTrimmedString(authMethod.email).toLowerCase() : '';
    const keySuffix = [
      `limit=${policy.limit}`,
      `windowMs=${policy.windowMs}`,
      `auth=${authMethod.kind}`,
      `work=${args.request.work.kind}`,
    ].join(':');
    const keys = [
      `scope=registration_prepare:${keySuffix}:ip:${gate.sourceIp}`,
      `scope=registration_prepare:${keySuffix}:org-ip:${args.storedIntent.orgId}:${gate.sourceIp}`,
      `scope=registration_prepare:${keySuffix}:wallet:${args.storedIntent.intent.walletId}`,
      email ? `scope=registration_prepare:${keySuffix}:email:${email}` : '',
    ].filter(Boolean);

    for (const key of keys) {
      const consumed = await limiter.consume({
        key,
        limit: policy.limit,
        windowMs: policy.windowMs,
        nowMs: Date.now(),
      });
      if (!consumed.ok) {
        return {
          ok: false,
          code: 'rate_limited',
          message: 'Registration prepare rate limit exceeded',
          ...(typeof consumed.retryAfterMs === 'number'
            ? { retryAfterMs: consumed.retryAfterMs }
            : {}),
          ...(typeof consumed.resetAtMs === 'number' ? { resetAtMs: consumed.resetAtMs } : {}),
        };
      }
    }
    return { ok: true };
  }

  private getEmailOtpRateLimiter(): SigningSessionSealRateLimiter {
    if (this.emailOtpRateLimiterInitialized && this.emailOtpRateLimiter) {
      return this.emailOtpRateLimiter;
    }
    const limiterKind =
      (this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMITER_KIND') as
        | 'in-memory'
        | 'upstash-redis-rest'
        | 'redis-tcp'
        | '') || null;
    const limiter = resolveSigningSessionSealRateLimitFromEnv({
      limiterKind,
      upstashUrl: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_UPSTASH_URL') || null,
      upstashToken: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_UPSTASH_TOKEN') || null,
      redisUrl: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_REDIS_URL') || null,
      keyPrefix: this.readEmailOtpConfigValue('EMAIL_OTP_RATE_LIMIT_KEY_PREFIX') || 'email-otp:v2:',
      limit: 1,
      windowMs: 1,
    }).limiter;
    this.emailOtpRateLimiterInitialized = true;
    this.emailOtpRateLimiter = limiter;
    return limiter;
  }

  private resolveEmailOtpRateLimitPolicies(): {
    challenge: { limit: number; windowMs: number };
    verify: { limit: number; windowMs: number };
    grant: { limit: number; windowMs: number };
    recoveryKeyAttempt: { limit: number; windowMs: number };
    googleRegistrationAttempt: { limit: number; windowMs: number };
  } {
    const parseConfiguredInt = (
      name: string,
      raw: string,
      defaultValue: number,
      min: number,
      max: number,
    ): number => {
      const normalized = String(raw || '').trim();
      if (!normalized) return defaultValue;
      const n = Number(normalized);
      if (!Number.isFinite(n)) {
        throw new Error(`${name} must be a finite number`);
      }
      if (n < min || n > max) {
        throw new Error(`${name} must be between ${min} and ${max}`);
      }
      return Math.floor(n);
    };
    const production = this.isProductionEnvironment();
    const challengeDefault = production
      ? { limit: 5, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    const verifyDefault = production
      ? { limit: 10, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    const grantDefault = production
      ? { limit: 8, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    const recoveryKeyAttemptDefault = production
      ? { limit: 10, windowMs: 5 * 60_000 }
      : { limit: 100, windowMs: 60_000 };
    const googleRegistrationAttemptDefault = production
      ? { limit: 12, windowMs: 10 * 60_000 }
      : { limit: 200, windowMs: 60_000 };
    return {
      challenge: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX'),
          challengeDefault.limit,
          1,
          500,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS'),
          challengeDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
      verify: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_VERIFY_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_VERIFY_RATE_LIMIT_MAX'),
          verifyDefault.limit,
          1,
          1000,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS'),
          verifyDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
      grant: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_GRANT_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_GRANT_RATE_LIMIT_MAX'),
          grantDefault.limit,
          1,
          1000,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS'),
          grantDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
      recoveryKeyAttempt: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX'),
          recoveryKeyAttemptDefault.limit,
          1,
          1000,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue('EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS'),
          recoveryKeyAttemptDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
      googleRegistrationAttempt: {
        limit: parseConfiguredInt(
          'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX',
          this.readEmailOtpConfigValue('EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX'),
          googleRegistrationAttemptDefault.limit,
          1,
          1000,
        ),
        windowMs: parseConfiguredInt(
          'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS',
          this.readEmailOtpConfigValue(
            'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS',
          ),
          googleRegistrationAttemptDefault.windowMs,
          1_000,
          24 * 60 * 60_000,
        ),
      },
    };
  }

  private async consumeEmailOtpRateLimit(args: {
    scope: 'challenge' | 'verify' | 'grant' | 'recoveryKeyAttempt' | 'googleRegistrationAttempt';
    action?: string;
    userId?: string;
    walletId?: string;
    providerSubject?: string;
    orgId?: string;
    clientIp?: string;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const limiter = this.getEmailOtpRateLimiter();
    const policy = this.resolveEmailOtpRateLimitPolicies()[args.scope];
    const keySuffix = `scope=${args.scope}:action=${args.action || 'default'}:limit=${policy.limit}:windowMs=${policy.windowMs}`;
    const keys = [
      args.clientIp ? `${keySuffix}:ip:${args.clientIp}` : '',
      args.userId ? `${keySuffix}:user:${args.userId}` : '',
      args.walletId ? `${keySuffix}:wallet:${args.walletId}` : '',
      args.providerSubject ? `${keySuffix}:providerSubject:${args.providerSubject}` : '',
      args.orgId ? `${keySuffix}:org:${args.orgId}` : '',
    ].filter(Boolean);
    for (const key of keys) {
      const consumed = await limiter.consume({
        key,
        limit: policy.limit,
        windowMs: policy.windowMs,
        nowMs: Date.now(),
      });
      if (!consumed.ok) {
        return {
          ok: false,
          code: 'rate_limited',
          message: 'Email OTP rate limit exceeded',
          ...(typeof consumed.retryAfterMs === 'number'
            ? { retryAfterMs: consumed.retryAfterMs }
            : {}),
          ...(typeof consumed.resetAtMs === 'number' ? { resetAtMs: consumed.resetAtMs } : {}),
        };
      }
    }
    return { ok: true };
  }

  private resolveEmailOtpConfig(): {
    deliveryMode: 'email_provider' | 'log' | 'memory';
    challengeTtlMs: number;
    grantTtlMs: number;
    maxAttempts: number;
    lockoutTtlMs: number;
    codeLength: number;
    devOutboxEnabled: boolean;
    maxActiveChallengesPerContext: number;
  } {
    const deliveryModeRaw = this.readEmailOtpConfigValue('EMAIL_OTP_DELIVERY_MODE').toLowerCase();
    let deliveryMode: 'email_provider' | 'log' | 'memory';
    if (!deliveryModeRaw) {
      deliveryMode = 'memory';
    } else if (
      deliveryModeRaw === 'email_provider' ||
      deliveryModeRaw === 'log' ||
      deliveryModeRaw === 'memory'
    ) {
      deliveryMode = deliveryModeRaw;
    } else {
      throw new Error('EMAIL_OTP_DELIVERY_MODE must be one of email_provider, log, or memory');
    }
    const parseConfiguredInt = (
      name: string,
      raw: string,
      defaultValue: number,
      min: number,
      max: number,
    ): number => {
      const normalized = String(raw || '').trim();
      if (!normalized) return defaultValue;
      const n = Number(normalized);
      if (!Number.isFinite(n)) {
        throw new Error(`${name} must be a finite number`);
      }
      if (n < min || n > max) {
        throw new Error(`${name} must be between ${min} and ${max}`);
      }
      return Math.floor(n);
    };
    const challengeTtlMs = parseConfiguredInt(
      'EMAIL_OTP_CHALLENGE_TTL_MS',
      this.readEmailOtpConfigValue('EMAIL_OTP_CHALLENGE_TTL_MS'),
      5 * 60_000,
      30_000,
      15 * 60_000,
    );
    const grantTtlMs = parseConfiguredInt(
      'EMAIL_OTP_GRANT_TTL_MS',
      this.readEmailOtpConfigValue('EMAIL_OTP_GRANT_TTL_MS'),
      30_000,
      10_000,
      5 * 60_000,
    );
    const maxAttempts = parseConfiguredInt(
      'EMAIL_OTP_MAX_ATTEMPTS',
      this.readEmailOtpConfigValue('EMAIL_OTP_MAX_ATTEMPTS'),
      5,
      1,
      10,
    );
    const lockoutTtlMs = parseConfiguredInt(
      'EMAIL_OTP_LOCKOUT_TTL_MS',
      this.readEmailOtpConfigValue('EMAIL_OTP_LOCKOUT_TTL_MS'),
      15 * 60_000,
      60_000,
      24 * 60 * 60_000,
    );
    const codeLength = parseConfiguredInt(
      'EMAIL_OTP_CODE_LENGTH',
      this.readEmailOtpConfigValue('EMAIL_OTP_CODE_LENGTH'),
      6,
      6,
      8,
    );
    const maxActiveChallengesPerContext = parseConfiguredInt(
      'EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT',
      this.readEmailOtpConfigValue('EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT'),
      5,
      1,
      20,
    );
    const devOutboxEnabledRaw = this.readEmailOtpConfigValue('EMAIL_OTP_DEV_OUTBOX_ENABLED');
    if (
      devOutboxEnabledRaw &&
      !['1', 'true', 'yes', 'on', '0', 'false', 'no', 'off'].includes(
        devOutboxEnabledRaw.toLowerCase(),
      )
    ) {
      throw new Error('EMAIL_OTP_DEV_OUTBOX_ENABLED must be a boolean flag when provided');
    }
    const devOutboxEnabled =
      deliveryMode === 'memory' &&
      !this.isProductionEnvironment() &&
      (devOutboxEnabledRaw
        ? ['1', 'true', 'yes', 'on'].includes(devOutboxEnabledRaw.toLowerCase())
        : true);
    return {
      deliveryMode,
      challengeTtlMs,
      grantTtlMs,
      maxAttempts,
      lockoutTtlMs,
      codeLength,
      devOutboxEnabled,
      maxActiveChallengesPerContext,
    };
  }

  private createEmailOtpShamirCipher() {
    // Local/dev bootstrap path only. Production should source the active Email OTP
    // seal material from a KMS/HSM boundary before constructing this adapter.
    const keyVersion = this.readConfigValue('SIGNING_SESSION_SEAL_KEY_VERSION');
    const shamirPrimeB64u = this.readConfigValue('SIGNING_SESSION_SHAMIR_P_B64U');
    const serverEncryptExponentB64u = this.readConfigValue('SIGNING_SESSION_SEAL_E_S_B64U');
    const serverDecryptExponentB64u = this.readConfigValue('SIGNING_SESSION_SEAL_D_S_B64U');
    if (
      !keyVersion ||
      !shamirPrimeB64u ||
      !serverEncryptExponentB64u ||
      !serverDecryptExponentB64u
    ) {
      return {
        ok: false as const,
        code: 'not_configured',
        message:
          'Email OTP unseal requires SIGNING_SESSION_SEAL_KEY_VERSION, SIGNING_SESSION_SHAMIR_P_B64U, SIGNING_SESSION_SEAL_E_S_B64U, and SIGNING_SESSION_SEAL_D_S_B64U',
      };
    }
    try {
      return {
        ok: true as const,
        keyVersion,
        cipher: createSigningSessionSealShamir3PassCipherAdapter({
          currentKeyVersion: keyVersion,
          keys: [
            {
              keyVersion,
              shamirPrimeB64u,
              serverEncryptExponentB64u,
              serverDecryptExponentB64u,
            },
          ],
        }),
      };
    } catch (error: unknown) {
      return {
        ok: false as const,
        code: 'not_configured',
        message: errorMessage(error) || 'Email OTP Shamir configuration is invalid',
      };
    }
  }

  private generateNumericOtp(length: number): string {
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      throw new Error('crypto.getRandomValues is unavailable in this runtime');
    }
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    let code = '';
    for (const byte of bytes) code += String(byte % 10);
    return code;
  }

  private generateOpaqueId(byteLength = 16): string {
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      throw new Error('crypto.getRandomValues is unavailable in this runtime');
    }
    return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
  }

  private maskEmail(email: string): string {
    const trimmed = String(email || '')
      .trim()
      .toLowerCase();
    const atIndex = trimmed.indexOf('@');
    if (atIndex <= 0 || atIndex === trimmed.length - 1) return 'hidden';
    const local = trimmed.slice(0, atIndex);
    const domain = trimmed.slice(atIndex + 1);
    const maskedLocal =
      local.length <= 2 ? `${local[0] || '*'}*` : `${local[0]}***${local.slice(-1)}`;
    const domainParts = domain.split('.');
    const domainName = domainParts[0] || '';
    const maskedDomainName =
      domainName.length <= 2
        ? `${domainName[0] || '*'}*`
        : `${domainName[0]}***${domainName.slice(-1)}`;
    return `${maskedLocal}@${[maskedDomainName, ...domainParts.slice(1)].join('.')}`;
  }

  private async deliverEmailOtpCode(input: {
    challengeId: string;
    walletId: string;
    userId: string;
    otpChannel: EmailOtpChannel;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    email: string;
    otpCode: string;
    expiresAtMs: number;
  }): Promise<
    | { ok: true; deliveryMode: 'email_provider' | 'log' | 'memory'; emailHint: string }
    | { ok: false; code: string; message: string; lockedUntilMs?: number }
  > {
    const config = this.resolveEmailOtpConfig();
    if (this.isProductionEnvironment() && config.deliveryMode !== 'email_provider') {
      return {
        ok: false,
        code: 'email_otp_delivery_not_allowed',
        message: `Email OTP delivery mode ${config.deliveryMode} is disabled in production`,
      };
    }

    const emailHint = this.maskEmail(input.email);
    const logDevelopmentOtpCode = (deliveryMode: 'log' | 'memory') => {
      this.logger.warn('[email-otp] development OTP code', {
        challengeId: input.challengeId,
        walletId: input.walletId,
        userId: input.userId,
        otpChannel: input.otpChannel,
        action: input.action,
        operation: input.operation,
        deliveryMode,
        emailHint,
        devOtpCode: input.otpCode,
        expiresAtMs: input.expiresAtMs,
      });
    };
    if (config.deliveryMode === 'email_provider') {
      return {
        ok: false,
        code: 'not_implemented',
        message: 'Email OTP email_provider delivery is not implemented yet',
      };
    }

    if (config.deliveryMode === 'memory') {
      this.emailOtpMemoryOutbox.set(input.challengeId, {
        walletId: input.walletId,
        userId: input.userId,
        otpChannel: input.otpChannel,
        email: input.email,
        emailHint,
        otpCode: input.otpCode,
        expiresAtMs: input.expiresAtMs,
      });
      logDevelopmentOtpCode('memory');
      return { ok: true, deliveryMode: 'memory', emailHint };
    }

    logDevelopmentOtpCode('log');
    return { ok: true, deliveryMode: 'log', emailHint };
  }

  private getIdentityStore(): IdentityStore {
    if (this.identityStoreInitialized && this.identityStore) {
      return this.identityStore;
    }
    if (this.identityStoreInitialized) {
      this.identityStore = createIdentityStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.identityStore;
    }

    this.identityStoreInitialized = true;
    this.identityStore = createIdentityStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.identityStore;
  }

  async listIdentities(input: {
    userId: string;
  }): Promise<{ ok: boolean; subjects?: string[]; code?: string; message?: string }> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const store = this.getIdentityStore();
      const subjects = await store.listSubjectsByUserId(userId);
      return { ok: true, subjects };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list identities',
      };
    }
  }

  async linkIdentity(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    try {
      const store = this.getIdentityStore();
      return await store.linkSubjectToUserId({
        userId: input.userId,
        subject: input.subject,
        allowMoveIfSoleIdentity: Boolean(input.allowMoveIfSoleIdentity),
      });
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to link identity' };
    }
  }

  async unlinkIdentity(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult> {
    try {
      const store = this.getIdentityStore();
      return await store.unlinkSubjectFromUserId({ userId: input.userId, subject: input.subject });
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to unlink identity',
      };
    }
  }

  async getOrCreateAppSessionVersion(input: {
    userId: string;
  }): Promise<
    | { ok: true; appSessionVersion: string }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const store = this.getIdentityStore();
      const appSessionVersion = await store.ensureAppSessionVersionByUserId(userId);
      return { ok: true, appSessionVersion };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to ensure app session version',
      };
    }
  }

  async rotateAppSessionVersion(input: {
    userId: string;
  }): Promise<
    | { ok: true; appSessionVersion: string }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const store = this.getIdentityStore();
      const appSessionVersion = await store.rotateAppSessionVersionByUserId(userId);
      return { ok: true, appSessionVersion };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to rotate app session version',
      };
    }
  }

  async validateAppSessionVersion(input: { userId: string; appSessionVersion: string }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'invalid_session_version' | 'unauthorized' | 'internal';
        message: string;
      }
  > {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      if (!userId || !appSessionVersion) {
        return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
      }
      const store = this.getIdentityStore();
      const current = await store.getAppSessionVersionByUserId(userId);
      if (!current || current !== appSessionVersion) {
        return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
      }
      return { ok: true };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to validate app session version',
      };
    }
  }

  private getDeviceLinkingSessionStore(): DeviceLinkingSessionStore {
    if (this.deviceLinkingSessionStoreInitialized && this.deviceLinkingSessionStore) {
      return this.deviceLinkingSessionStore;
    }
    if (this.deviceLinkingSessionStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.deviceLinkingSessionStore = createDeviceLinkingSessionStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.deviceLinkingSessionStore;
    }

    this.deviceLinkingSessionStoreInitialized = true;
    this.deviceLinkingSessionStore = createDeviceLinkingSessionStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.deviceLinkingSessionStore;
  }

  private getEmailRecoveryPreparationStore(): EmailRecoveryPreparationStore {
    if (this.emailRecoveryPreparationStoreInitialized && this.emailRecoveryPreparationStore) {
      return this.emailRecoveryPreparationStore;
    }
    if (this.emailRecoveryPreparationStoreInitialized) {
      this.emailRecoveryPreparationStore = createEmailRecoveryPreparationStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.emailRecoveryPreparationStore;
    }

    this.emailRecoveryPreparationStoreInitialized = true;
    this.emailRecoveryPreparationStore = createEmailRecoveryPreparationStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.emailRecoveryPreparationStore;
  }

  private getNearPublicKeyStore(): NearPublicKeyStore {
    if (this.nearPublicKeyStoreInitialized && this.nearPublicKeyStore) {
      return this.nearPublicKeyStore;
    }
    if (this.nearPublicKeyStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.nearPublicKeyStore = createNearPublicKeyStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.nearPublicKeyStore;
    }
    this.nearPublicKeyStoreInitialized = true;
    this.nearPublicKeyStore = createNearPublicKeyStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.nearPublicKeyStore;
  }

  async recordNearPublicKeyMetadata(input: {
    userId?: unknown;
    publicKey?: unknown;
    kind: NearPublicKeyKind;
    signerSlot?: unknown;
    credentialIdB64u?: unknown;
    rpId?: unknown;
    addedTxHash?: unknown;
    removedAtMs?: unknown;
    source?: string;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const userId = toOptionalTrimmedString(input.userId);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    if (!userId || !publicKey) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'userId and publicKey are required',
      };
    }

    const now = Date.now();
    const signerSlotRaw =
      typeof input.signerSlot === 'number' ? input.signerSlot : Number(input.signerSlot);
    const removedAtMsRaw =
      typeof input.removedAtMs === 'number' ? input.removedAtMs : Number(input.removedAtMs);
    const credentialIdB64u = toOptionalTrimmedString(input.credentialIdB64u);
    const rpId = toOptionalTrimmedString(input.rpId);
    const addedTxHash = toOptionalTrimmedString(input.addedTxHash);
    const record: NearPublicKeyRecord = {
      version: 'near_public_key_v1',
      userId,
      publicKey,
      kind: input.kind,
      ...(Number.isFinite(signerSlotRaw) && signerSlotRaw >= 1
        ? { signerSlot: Math.floor(signerSlotRaw) }
        : {}),
      ...(credentialIdB64u ? { credentialIdB64u } : {}),
      ...(rpId ? { rpId } : {}),
      createdAtMs: now,
      updatedAtMs: now,
      ...(addedTxHash ? { addedTxHash } : {}),
      ...(Number.isFinite(removedAtMsRaw) && removedAtMsRaw > 0
        ? { removedAtMs: Math.floor(removedAtMsRaw) }
        : {}),
    };

    try {
      await this.getNearPublicKeyStore().put(record);
      return { ok: true };
    } catch (error: unknown) {
      const source = toOptionalTrimmedString(input.source) || 'near-public-key-metadata';
      const message = errorMessage(error) || 'Failed to persist NEAR public key metadata';
      this.logger.warn(`[AuthService] ${source} failed for ${userId}`, error);
      return { ok: false, code: 'internal', message };
    }
  }

  private getRecoverySessionStore(): RecoverySessionStore {
    if (this.recoverySessionStoreInitialized && this.recoverySessionStore) {
      return this.recoverySessionStore;
    }
    if (this.recoverySessionStoreInitialized) {
      this.recoverySessionStore = createRecoverySessionStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.recoverySessionStore;
    }
    this.recoverySessionStoreInitialized = true;
    this.recoverySessionStore = createRecoverySessionStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.recoverySessionStore;
  }

  private getRecoveryExecutionStore(): RecoveryExecutionStore {
    if (this.recoveryExecutionStoreInitialized && this.recoveryExecutionStore) {
      return this.recoveryExecutionStore;
    }
    if (this.recoveryExecutionStoreInitialized) {
      this.recoveryExecutionStore = createRecoveryExecutionStore({
        config: this.config.thresholdStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.recoveryExecutionStore;
    }
    this.recoveryExecutionStoreInitialized = true;
    this.recoveryExecutionStore = createRecoveryExecutionStore({
      config: this.config.thresholdStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.recoveryExecutionStore;
  }

  async getRecoverySession(input: {
    sessionId: string;
  }): Promise<
    | { ok: true; record: Awaited<ReturnType<RecoverySessionStore['get']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
      const store = this.getRecoverySessionStore();
      const record = await store.get(sessionId);
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to read recovery session',
      };
    }
  }

  async updateRecoverySessionStatus(input: {
    sessionId: string;
    status: RecoverySessionStatus;
    metadataPatch?: Record<string, unknown> | null;
  }): Promise<
    | { ok: true; record: NonNullable<Awaited<ReturnType<RecoverySessionStore['get']>>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const status = toOptionalTrimmedString(input.status) as RecoverySessionStatus | null;
      if (
        !sessionId ||
        !status ||
        (status !== 'prepared' &&
          status !== 'verified' &&
          status !== 'near_recovered' &&
          status !== 'evm_recovering' &&
          status !== 'completed' &&
          status !== 'failed' &&
          status !== 'cancelled')
      ) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery session update' };
      }

      const store = this.getRecoverySessionStore();
      const existing = await store.get(sessionId);
      if (!existing) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }

      const record = {
        ...existing,
        status,
        updatedAtMs: Date.now(),
        ...(input.metadataPatch
          ? {
              metadata: {
                ...(existing.metadata || {}),
                ...input.metadataPatch,
              },
            }
          : existing.metadata
            ? { metadata: { ...existing.metadata } }
            : {}),
      };
      await store.put(record);
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to update recovery session',
      };
    }
  }

  async getRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
  }): Promise<
    | { ok: true; record: Awaited<ReturnType<RecoveryExecutionStore['get']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
      const accountAddress = toOptionalTrimmedString(input.accountAddress);
      const action = toOptionalTrimmedString(input.action);
      if (!sessionId || !chainIdKey || !accountAddress || !action) {
        return { ok: false, code: 'invalid_args', message: 'Missing recovery execution key' };
      }
      const store = this.getRecoveryExecutionStore();
      const record = await store.get({
        sessionId,
        chainIdKey,
        accountAddress,
        action,
      });
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to read recovery execution',
      };
    }
  }

  async listRecoveryExecutions(input: {
    sessionId: string;
  }): Promise<
    | { ok: true; records: Awaited<ReturnType<RecoveryExecutionStore['listBySessionId']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
      const store = this.getRecoveryExecutionStore();
      const records = await store.listBySessionId(sessionId);
      return { ok: true, records };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list recovery executions',
      };
    }
  }

  async listRecoveryExecutionsByStatus(input: {
    status: RecoveryExecutionStatus;
    action?: string;
    updatedBeforeMs?: number;
    limit?: number;
  }): Promise<
    | { ok: true; records: Awaited<ReturnType<RecoveryExecutionStore['listByStatus']>> }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const status = input.status;
      const action = toOptionalTrimmedString(input.action);
      const updatedBeforeMsRaw = Number(input.updatedBeforeMs);
      const updatedBeforeMs =
        Number.isFinite(updatedBeforeMsRaw) && updatedBeforeMsRaw > 0
          ? Math.floor(updatedBeforeMsRaw)
          : undefined;
      if (typeof input.updatedBeforeMs !== 'undefined' && typeof updatedBeforeMs === 'undefined') {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'updatedBeforeMs must be a positive integer',
        };
      }
      const limitRaw = Number(input.limit);
      const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : undefined;
      if (typeof input.limit !== 'undefined' && typeof limit === 'undefined') {
        return { ok: false, code: 'invalid_args', message: 'limit must be a positive integer' };
      }
      const store = this.getRecoveryExecutionStore();
      const records = await store.listByStatus({
        status,
        ...(action ? { action } : {}),
        ...(typeof updatedBeforeMs === 'number' ? { updatedBeforeMs } : {}),
        ...(typeof limit === 'number' ? { limit } : {}),
      });
      return { ok: true, records };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list recovery executions by status',
      };
    }
  }

  async recordRecoveryExecution(input: {
    sessionId: string;
    chainIdKey: string;
    accountAddress: string;
    action: string;
    status: RecoveryExecutionStatus;
    transactionHash?: string;
    errorCode?: string;
    errorMessage?: string;
    metadata?: Record<string, unknown>;
  }): Promise<
    | { ok: true; record: RecoveryExecutionRecord }
    | { ok: false; code: 'invalid_args' | 'internal'; message: string }
  > {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
      const accountAddress = toOptionalTrimmedString(input.accountAddress);
      const action = toOptionalTrimmedString(input.action);
      if (!sessionId || !chainIdKey || !accountAddress || !action) {
        return { ok: false, code: 'invalid_args', message: 'Missing recovery execution fields' };
      }

      const recoverySession = await this.getRecoverySessionStore().get(sessionId);
      if (!recoverySession) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }

      const store = this.getRecoveryExecutionStore();
      const existing = await store.get({
        sessionId,
        chainIdKey,
        accountAddress,
        action,
      });
      const nowMs = Date.now();
      const record = buildRecoveryExecutionRecord({
        sessionId,
        userId: recoverySession.userId,
        nearAccountId: recoverySession.nearAccountId,
        chainIdKey,
        accountAddress,
        action,
        status: input.status,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        nowMs,
        transactionHash: input.transactionHash,
        errorCode: input.errorCode,
        errorMessage: input.errorMessage,
        metadata: input.metadata,
      });
      if (!record) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Invalid recovery execution payload',
        };
      }

      await store.put(record);
      return { ok: true, record };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to persist recovery execution',
      };
    }
  }

  async txStatus(txHash: string, senderAccountId: string): Promise<FinalExecutionOutcome> {
    await this._ensureSignerAndRelayerAccount();
    return this.nearClient.txStatus(txHash, senderAccountId);
  }

  private async _ensureSignerAndRelayerAccount(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    // Derive public key from configured relayer private key
    try {
      this.relayerPublicKey = toPublicKeyStringFromSecretKey(this.config.relayerPrivateKey);
    } catch (e) {
      this.logger.warn(
        'Failed to derive public key from relayerPrivateKey; ensure it is in ed25519:<base58> format',
      );
      this.relayerPublicKey = '';
    }

    // Prepare signer WASM for transaction building/signing
    await this.ensureSignerWasm();
    this.isInitialized = true;
  }

  private async ensureSignerWasm(): Promise<void> {
    if (this.signerWasmReady) return;
    const override = this.config.signerWasm?.moduleOrPath;
    if (override) {
      try {
        const moduleOrPath = await this.resolveSignerWasmOverride(override);
        await initSignerWasm({ module_or_path: moduleOrPath as InitInput });
        this.signerWasmReady = true;
        return;
      } catch (e) {
        this.logger.error('Failed to initialize signer WASM via provided override:', e);
        throw e;
      }
    }

    let candidates: URL[];
    try {
      candidates = getSignerWasmUrls(this.logger);
    } catch (err) {
      this.logger.error('Failed to resolve signer WASM URLs:', err);
      throw err;
    }

    try {
      if (this.isNodeEnvironment()) {
        await this.initSignerWasmForNode(candidates);
        this.signerWasmReady = true;
        return;
      }

      let lastError: unknown = null;
      for (const candidate of candidates) {
        try {
          await initSignerWasm({ module_or_path: candidate as InitInput });
          this.signerWasmReady = true;
          return;
        } catch (err) {
          lastError = err;
          this.logger.warn(
            `Failed to initialize signer WASM from ${candidate.toString()}, trying next candidate...`,
          );
        }
      }

      throw lastError ?? new Error('Unable to initialize signer WASM from any candidate URL');
    } catch (e) {
      this.logger.error('Failed to initialize signer WASM:', e);
      throw e instanceof Error ? e : new Error(String(e));
    }
  }

  private isNodeEnvironment(): boolean {
    // Detect true Node.js, not Cloudflare Workers with nodejs_compat polyfills.
    const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } })
      .process;
    const isNode = Boolean(processObj?.versions?.node);
    // Cloudflare Workers expose WebSocketPair and may polyfill process.
    const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
    const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
    const isCloudflareWorker =
      typeof webSocketPair !== 'undefined' ||
      (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
    return isNode && !isCloudflareWorker;
  }

  private async resolveSignerWasmOverride(override: SignerWasmModuleSupplier): Promise<InitInput> {
    const candidate =
      typeof override === 'function'
        ? await (override as () => InitInput | Promise<InitInput>)()
        : await override;

    if (!candidate) {
      throw new Error('Signer WASM override resolved to an empty value');
    }

    return candidate;
  }

  /**
   * Initialize signer WASM in Node by loading the wasm file from disk.
   * Tries multiple candidate locations and falls back to path-based init if needed.
   */
  private async initSignerWasmForNode(candidates: URL[]): Promise<void> {
    const { fileURLToPath } = await import('node:url');
    const { readFile } = await import('node:fs/promises');

    // 1) Try reading and compiling bytes
    for (const url of candidates) {
      try {
        const filePath = fileURLToPath(url);
        const bytes = await readFile(filePath);
        // Ensure we pass an ArrayBuffer (not Buffer / SharedArrayBuffer) for WebAssembly.compile
        const ab = new ArrayBuffer(bytes.byteLength);
        new Uint8Array(ab).set(bytes);
        const module = await WebAssembly.compile(ab);
        await initSignerWasm({ module_or_path: module });
        return;
      } catch {} // throw at end of function
    }

    // 2) Fallback: pass file path directly (supported in some environments)
    for (const url of candidates) {
      try {
        const filePath = fileURLToPath(url);
        await initSignerWasm({ module_or_path: filePath as unknown as InitInput });
        return;
      } catch {} // throw at end of function
    }

    throw new Error('[AuthService] Failed to initialize signer WASM from filesystem candidates');
  }

  /**
   * ===== Registration & authentication =====
   *
   * Helpers for creating accounts, registering WebAuthn credentials,
   * and verifying authentication responses.
   */

  /**
   * Create a new account with the specified balance
   */
  async createAccount(request: AccountCreationRequest): Promise<AccountCreationResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        if (!isValidAccountId(request.accountId)) {
          throw new Error(`Invalid account ID format: ${request.accountId}`);
        }

        // Check if account already exists
        this.logger.info(`Checking if account ${request.accountId} already exists...`);
        const accountExists = await this.checkAccountExists(request.accountId);
        if (accountExists) {
          throw new Error(
            `Account ${request.accountId} already exists. Cannot create duplicate account.`,
          );
        }
        this.logger.info(`Account ${request.accountId} is available for creation`);

        const initialBalance = this.config.accountInitialBalance;
        const { publicKey, recoveryPublicKey, expectedPublicKeys } = normalizeBootstrapPublicKeys({
          publicKey: request.publicKey,
          recoveryPublicKey: request.recoveryPublicKey,
        });

        this.logger.info(`Creating account: ${request.accountId}`);
        this.logger.info(`Initial balance: ${initialBalance} yoctoNEAR`);

        // Build actions for CreateAccount + Transfer + AddKey(FullAccess) for bootstrap keys.
        const actions: ActionArgsWasm[] = [
          { action_type: ActionType.CreateAccount },
          { action_type: ActionType.Transfer, deposit: String(initialBalance) },
          buildFullAccessAddKeyAction(publicKey),
          ...(recoveryPublicKey ? [buildFullAccessAddKeyAction(recoveryPublicKey)] : []),
        ];

        actions.forEach(validateActionArgsWasm);

        // Fetch nonce and block hash for relayer
        const { nextNonce, blockHash } = await this.fetchTxContext(
          this.config.relayerAccount,
          this.relayerPublicKey,
        );

        // Sign with relayer private key using WASM
        const signed = await this.signWithPrivateKey({
          nearPrivateKey: this.config.relayerPrivateKey,
          signerAccountId: this.config.relayerAccount,
          receiverId: request.accountId,
          nonce: nextNonce,
          blockHash: blockHash,
          actions,
        });

        // Broadcast quickly, then perform one explicit key-visibility check against final state.
        const createAccountBroadcastStartedAt = Date.now();
        const result = await this.nearClient.sendTransaction(
          signed,
          ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL,
        );
        this.logger.info(
          `Account creation for ${request.accountId} reached ${ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL} in ${
            Date.now() - createAccountBroadcastStartedAt
          }ms`,
        );
        const createAccountKeyCheckStartedAt = Date.now();
        const keysVerified = await this.verifyAccountAccessKeysPresent(
          request.accountId,
          expectedPublicKeys,
          ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK,
        );
        this.logger.info(
          `Account creation for ${request.accountId} key visibility verified=${keysVerified} in ${
            Date.now() - createAccountKeyCheckStartedAt
          }ms`,
        );
        if (!keysVerified) {
          this.logger.warn(
            recoveryPublicKey
              ? 'Bootstrap committed before both access keys were visible on final state; scheduling background audit'
              : 'Bootstrap committed before the operational access key was visible on final state; scheduling background audit',
          );
          this.scheduleAccountAccessKeyVisibilityAudit({
            accountId: request.accountId,
            expectedPublicKeys,
            contextLabel: `Account creation for ${request.accountId}`,
          });
        }

        this.logger.info(`Account creation completed: ${result.transaction.hash}`);
        const nearAmount = (Number(BigInt(initialBalance)) / 1e24).toFixed(6);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          accountId: request.accountId,
          message: `Account ${request.accountId} created with ${nearAmount} NEAR initial balance`,
        };
      } catch (error: any) {
        this.logger.error(`Account creation failed for ${request.accountId}:`, error);
        const msg = errorMessage(error) || 'Unknown account creation error';
        return {
          success: false,
          error: msg,
          message: `Failed to create account ${request.accountId}: ${msg}`,
        };
      }
    }, `create account ${request.accountId}`);
  }

  private async verifyRegistrationCredentialForIntent(input: {
    webauthnRegistration: unknown;
    expectedChallenge: string;
    expectedOrigin: string;
    rpId: string;
  }): Promise<
    | {
        ok: true;
        credential: {
          credentialIdB64u: string;
          credentialPublicKeyB64u: string;
          counter: number;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    const cred = input.webauthnRegistration as any;
    if (!cred || typeof cred !== 'object') {
      return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };
    }
    const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
    if (clientData.type !== 'webauthn.create') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
      };
    }
    if (clientData.challenge !== input.expectedChallenge) {
      return { ok: false, code: 'challenge_mismatch', message: 'Registration challenge mismatch' };
    }
    const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
    if (!expectedOrigin) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'expected_origin is required for WebAuthn registration verification',
      };
    }
    const originHost = originHostnameOrEmpty(clientData.origin);
    if (!isHostWithinRpId(originHost, input.rpId)) {
      return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
    }

    const mod = await import('@simplewebauthn/server');
    const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as
      | undefined
      | ((args: any) => Promise<any>);
    if (typeof verifyRegistrationResponse !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'WebAuthn registration verifier is unavailable in this runtime',
      };
    }

    const registration = await verifyRegistrationResponse({
      response: cred,
      expectedChallenge: input.expectedChallenge,
      expectedOrigin,
      expectedRPID: input.rpId,
      requireUserVerification: false,
    });
    if (!registration?.verified) {
      return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
    }

    const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
    const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as
      | Uint8Array
      | undefined;
    const counter = registration?.registrationInfo?.credential?.counter as number | undefined;
    if (!credentialIdB64u || !credentialPublicKey) {
      return {
        ok: false,
        code: 'internal',
        message: 'Registration verification did not return credential public key material',
      };
    }
    return {
      ok: true,
      credential: {
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
      },
    };
  }

  private async verifyRegistrationAuthorityForIntent(input: {
    intent: RegistrationIntentV1;
    registrationIntentDigestB64u: string;
    orgId: string;
    expectedOrigin: string;
    emailOtpRegistrationProof?: unknown;
    webauthnRegistration: unknown;
  }): Promise<
    | {
        ok: true;
        authority: RegistrationAuthority;
      }
    | { ok: false; code: string; message: string }
  > {
    switch (input.intent.authMethod.kind) {
      case 'passkey': {
        const verified = await this.verifyRegistrationCredentialForIntent({
          webauthnRegistration: input.webauthnRegistration,
          expectedChallenge: input.registrationIntentDigestB64u,
          expectedOrigin: input.expectedOrigin,
          rpId: input.intent.rpId,
        });
        if (!verified.ok) return verified;
        return {
          ok: true,
          authority: {
            kind: 'passkey',
            walletId: input.intent.walletId,
            rpId: input.intent.rpId,
            credentialIdB64u: verified.credential.credentialIdB64u,
            credentialPublicKeyB64u: verified.credential.credentialPublicKeyB64u,
            counter: verified.credential.counter,
            registrationIntentDigestB64u: input.registrationIntentDigestB64u,
          },
        };
      }
      case 'email_otp': {
        const proof = normalizeEmailOtpRegistrationProof(input.emailOtpRegistrationProof);
        if (!proof) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'emailOtpRegistrationProof is required for Email OTP registration',
          };
        }
        if (proof.proofKind === 'google_sso_registration') {
          if (proof.registrationIntentDigestB64u !== input.registrationIntentDigestB64u) {
            return {
              ok: false,
              code: 'registration_intent_digest_mismatch',
              message: 'Email OTP registration proof is not bound to this registration intent',
            };
          }
          if (proof.email !== input.intent.authMethod.email.toLowerCase()) {
            return {
              ok: false,
              code: 'email_mismatch',
              message: 'Email OTP registration proof email does not match the intent',
            };
          }
          if (input.intent.authMethod.proofKind !== 'google_sso_registration') {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'Google SSO registration proof requires a Google SSO registration intent',
            };
          }
          if (
            proof.googleEmailOtpRegistrationAttemptId !==
            input.intent.authMethod.googleEmailOtpRegistrationAttemptId
          ) {
            return {
              ok: false,
              code: 'registration_attempt_mismatch',
              message: 'Google SSO registration proof does not match the registration attempt',
            };
          }
          if (
            proof.googleEmailOtpRegistrationOfferId !==
              input.intent.authMethod.googleEmailOtpRegistrationOfferId ||
            proof.googleEmailOtpRegistrationCandidateId !==
              input.intent.authMethod.googleEmailOtpRegistrationCandidateId
          ) {
            return {
              ok: false,
              code: 'registration_offer_mismatch',
              message: 'Google SSO registration proof does not match the selected offer candidate',
            };
          }
          const attempt = await this.getEmailOtpRegistrationAttemptStore().get(
            proof.googleEmailOtpRegistrationAttemptId,
          );
          if (!attempt) {
            return {
              ok: false,
              code: 'registration_attempt_missing',
              message: 'Google Email OTP registration attempt expired or was not found',
            };
          }
          if (attempt.state !== 'started' && attempt.state !== 'key_finalized') {
            return {
              ok: false,
              code: 'registration_attempt_not_started',
              message: 'Google Email OTP registration attempt is not active',
            };
          }
          if (attempt.expiresAtMs <= Date.now()) {
            await this.getEmailOtpRegistrationAttemptStore().put({
              ...attempt,
              state: 'expired',
              updatedAtMs: Date.now(),
            });
            return {
              ok: false,
              code: 'registration_attempt_expired',
              message: 'Google Email OTP registration attempt expired',
            };
          }
          if (attempt.providerSubject !== proof.providerSubject) {
            return {
              ok: false,
              code: 'challenge_subject_mismatch',
              message: 'Email OTP registration attempt does not match the provider subject',
            };
          }
          if (attempt.email.toLowerCase() !== proof.email) {
            return {
              ok: false,
              code: 'email_mismatch',
              message: 'Google Email OTP registration attempt email does not match the proof',
            };
          }
          if (attempt.appSessionVersion !== proof.appSessionVersion) {
            return {
              ok: false,
              code: 'app_session_version_mismatch',
              message: 'Google Email OTP registration attempt does not match the app session',
            };
          }
          if (attempt.offerId !== proof.googleEmailOtpRegistrationOfferId) {
            return {
              ok: false,
              code: 'registration_offer_mismatch',
              message: 'Google Email OTP registration attempt does not match the selected offer',
            };
          }
          const selectedOfferCandidate = attempt.offerCandidates.find(
            (candidate) => candidate.candidateId === proof.googleEmailOtpRegistrationCandidateId,
          );
          if (
            !selectedOfferCandidate ||
            selectedOfferCandidate.walletId !== input.intent.walletId
          ) {
            return {
              ok: false,
              code: 'registration_candidate_mismatch',
              message: 'Google Email OTP registration candidate does not match walletId',
            };
          }
          if (
            attempt.walletId !== selectedOfferCandidate.walletId ||
            attempt.selectedCandidateId !== selectedOfferCandidate.candidateId ||
            attempt.collisionCounter !== selectedOfferCandidate.collisionCounter
          ) {
            await this.getEmailOtpRegistrationAttemptStore().put({
              ...attempt,
              walletId: selectedOfferCandidate.walletId,
              collisionCounter: selectedOfferCandidate.collisionCounter,
              selectedCandidateId: selectedOfferCandidate.candidateId,
              updatedAtMs: Date.now(),
            });
          }
          if (
            attempt.runtimePolicyScope &&
            !thresholdRuntimePolicyScopesEqual(
              attempt.runtimePolicyScope,
              input.intent.runtimePolicyScope,
            )
          ) {
            return {
              ok: false,
              code: 'runtime_policy_scope_mismatch',
              message: 'Google Email OTP registration attempt does not match runtime policy scope',
            };
          }
          const providerSubject = parseProviderSubject(proof.providerSubject);
          const finalWalletId = parseWalletId(input.intent.walletId);
          const orgId = parseOrgId(input.orgId);
          const appSessionVersion = parseAppSessionVersion(proof.appSessionVersion);
          if (!providerSubject.ok || !finalWalletId.ok || !orgId.ok || !appSessionVersion.ok) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'Google SSO registration proof contains invalid domain fields',
            };
          }
          const emailHashHex = bytesToHex(await sha256BytesUtf8(attempt.email.toLowerCase()));
          return {
            ok: true,
            authority: {
              kind: 'email_otp',
              proofKind: 'google_sso_registration',
              walletId: finalWalletId.value,
              rpId: input.intent.rpId,
              providerSubject: providerSubject.value,
              email: attempt.email.toLowerCase(),
              emailHashHex,
              googleEmailOtpRegistrationAttemptId: attempt.attemptId,
              googleEmailOtpRegistrationOfferId: attempt.offerId,
              googleEmailOtpRegistrationCandidateId: selectedOfferCandidate.candidateId,
              registrationAuthorityId: attempt.attemptId,
              finalWalletId: finalWalletId.value,
              orgId: orgId.value,
              appSessionVersion: appSessionVersion.value,
              registrationIntentDigestB64u: input.registrationIntentDigestB64u,
            },
          };
        }
        if (proof.registrationIntentDigestB64u !== input.registrationIntentDigestB64u) {
          return {
            ok: false,
            code: 'registration_intent_digest_mismatch',
            message: 'Email OTP registration proof is not bound to this registration intent',
          };
        }
        if (proof.email !== input.intent.authMethod.email.toLowerCase()) {
          return {
            ok: false,
            code: 'email_mismatch',
            message: 'Email OTP registration proof email does not match the intent',
          };
        }
        const proofResult = parseDirectEmailOtpRegistrationChallengeProof({
          providerSubject: proof.providerSubject,
          proofEmail: proof.email,
          challengeId: proof.challengeId,
          finalWalletId: input.intent.walletId,
          orgId: input.orgId,
          appSessionVersion: proof.appSessionVersion,
        });
        if (!proofResult.ok) return proofResult;
        const verified = await this.verifyEmailOtpChallengeCode({
          challengeSubjectId: proofResult.proof.challengeSubjectId,
          registrationChallengeProof: proofResult.proof,
          allowRegistrationChallengeReroll: true,
          walletId: input.intent.walletId,
          orgId: input.orgId,
          challengeId: proofResult.proof.challengeId,
          otpCode: proof.otpCode,
          otpChannel: proof.otpChannel,
          sessionHash: input.registrationIntentDigestB64u,
          appSessionVersion: proof.appSessionVersion,
          expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
          expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
        });
        if (!verified.ok) return verified;
        if (verified.intent !== 'registration') {
          return {
            ok: false,
            code: 'challenge_purpose_mismatch',
            message: 'Email OTP registration verification returned a non-registration proof',
          };
        }
        const challengeProof = verified.registrationChallengeProof;
        const verifiedEmail = toOptionalTrimmedString(challengeProof.challengeEmail)?.toLowerCase();
        if (verifiedEmail !== proof.email) {
          return {
            ok: false,
            code: 'email_mismatch',
            message: 'Verified Email OTP address does not match the registration proof',
          };
        }
        const emailHashHex = bytesToHex(await sha256BytesUtf8(challengeProof.challengeEmail));
        return {
          ok: true,
          authority: {
            kind: 'email_otp',
            proofKind: 'otp_challenge',
            walletId: challengeProof.finalWalletId,
            rpId: input.intent.rpId,
            providerSubject: challengeProof.providerSubject,
            challengeSubjectId: challengeProof.challengeSubjectId,
            email: challengeProof.challengeEmail,
            emailHashHex,
            challengeId: challengeProof.challengeId,
            registrationAuthorityId: challengeProof.challengeId,
            originalWalletId: challengeProof.originalWalletId,
            finalWalletId: challengeProof.finalWalletId,
            orgId: challengeProof.orgId,
            appSessionVersion: challengeProof.appSessionVersion,
            challengePurpose: challengeProof.purpose.kind,
            registrationIntentDigestB64u: input.registrationIntentDigestB64u,
          },
        };
      }
    }
    return assertNever(input.intent.authMethod);
  }

  async createRegistrationIntent(input: {
    request: CreateRegistrationIntentRequest;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateRegistrationIntentResponse> {
    try {
      const rpId = toOptionalTrimmedString(input.request?.rpId);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };

      const signerSelection = normalizeRegistrationSignerSelection(input.request?.signerSelection);
      if (!signerSelection.ok) return signerSelection;
      const authMethod = normalizeRegistrationAuthMethodInput(input.request?.authMethod);
      if (!authMethod) {
        return { ok: false, code: 'invalid_body', message: 'authMethod is required' };
      }

      const wallet = input.request?.wallet;
      const walletId =
        wallet?.kind === 'provided'
          ? walletIdFromString(String(wallet.walletId || '').trim())
          : createWalletId();
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent: RegistrationIntentV1 = {
        version: 'registration_intent_v1',
        walletId,
        rpId,
        authMethod,
        signerSelection: signerSelection.value,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        nonceB64u: randomBase64Url(32),
      };
      const digestB64u = await computeRegistrationIntentDigestB64u(intent);
      const grant = registrationIntentGrantFromString(`rig_${randomBase64Url(32)}`);
      const expiresAtMs = Date.now() + 5 * 60_000;
      await this.getRegistrationCeremonyStore().putIntent({
        kind: 'intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        ...(input.signingRootId ? { signingRootId: input.signingRootId } : {}),
        ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
        ...(input.expectedOrigin ? { expectedOrigin: input.expectedOrigin } : {}),
        expiresAtMs,
      });
      return {
        ok: true,
        intent,
        registrationIntentDigestB64u: digestB64u,
        registrationIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create registration intent',
      };
    }
  }

  async createAddSignerIntent(input: {
    request: CreateAddSignerIntentRequest;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateAddSignerIntentResponse> {
    try {
      const walletId = walletIdFromString(String(input.request?.walletId || '').trim());
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const rpId = toOptionalTrimmedString(input.request?.rpId);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };

      const signerSelection = normalizeAddSignerSelection(input.request?.signerSelection);
      if (!signerSelection.ok) return signerSelection;

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent: AddSignerIntentV1 = {
        version: 'add_signer_intent_v1',
        walletId,
        rpId,
        signerSelection: signerSelection.value,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        nonceB64u: randomBase64Url(32),
      };
      const digestB64u = await computeAddSignerIntentDigestB64u(intent);
      const grant = addSignerIntentGrantFromString(`wasig_${randomBase64Url(32)}`);
      const expiresAtMs = Date.now() + 5 * 60_000;
      await this.getRegistrationCeremonyStore().putAddSignerIntent({
        kind: 'add_signer_intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        ...(input.signingRootId ? { signingRootId: input.signingRootId } : {}),
        ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
        ...(input.expectedOrigin ? { expectedOrigin: input.expectedOrigin } : {}),
        expiresAtMs,
      });
      return {
        ok: true,
        intent,
        addSignerIntentDigestB64u: digestB64u,
        addSignerIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create add-signer intent',
      };
    }
  }

  async createAddAuthMethodIntent(input: {
    request: CreateAddAuthMethodIntentRequest;
    orgId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin?: string;
  }): Promise<CreateAddAuthMethodIntentResponse> {
    try {
      const walletId = walletIdFromString(String(input.request?.walletId || '').trim());
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const rpId = toOptionalTrimmedString(input.request?.rpId);
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'rpId is required' };
      const authMethod = normalizeAddAuthMethodInput(input.request?.authMethod);
      if (!authMethod) {
        return { ok: false, code: 'invalid_body', message: 'authMethod is required' };
      }

      const runtimePolicyScope =
        input.runtimePolicyScope || inferRuntimePolicyScopeFromSigningRoot(input);
      const intent: AddAuthMethodIntentV1 = {
        version: 'add_auth_method_intent_v1',
        walletId,
        rpId,
        authMethod,
        nonceB64u: randomBase64Url(32),
      };
      if (runtimePolicyScope) {
        intent.runtimePolicyScope = runtimePolicyScope;
      }
      const digestB64u = await computeAddAuthMethodIntentDigestB64u(intent);
      const grant = addAuthMethodIntentGrantFromString(`waig_${randomBase64Url(32)}`);
      const expiresAtMs = Date.now() + 5 * 60_000;
      await this.getRegistrationCeremonyStore().putAddAuthMethodIntent({
        kind: 'add_auth_method_intent_allocated',
        grant,
        intent,
        digestB64u,
        orgId: toOptionalTrimmedString(input.orgId) || '',
        expiresAtMs,
        ...(input.signingRootId ? { signingRootId: input.signingRootId } : {}),
        ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
        ...(input.expectedOrigin ? { expectedOrigin: input.expectedOrigin } : {}),
      });
      return {
        ok: true,
        intent,
        addAuthMethodIntentDigestB64u: digestB64u,
        addAuthMethodIntentGrant: grant,
        expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create add-auth-method intent',
      };
    }
  }

  private async prepareEcdsaRegistrationStartPayload(input: {
    registrationCeremonyId: string;
    registrationPreparationId?: RegistrationPreparationId;
    walletId: WalletId;
    rpId: string;
    signingRootId: string;
    signingRootVersion: string;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
    participantIds: readonly number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<WalletRegistrationEcdsaPreparePayload> {
    const walletId = input.walletId;
    const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
      walletId,
      rpId: input.rpId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    });
    const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
      walletId,
      rpId: input.rpId,
    });
    return {
      kind: 'evm_family_ecdsa_keygen',
      chainTargets: [...input.chainTargets],
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId,
        rpId: input.rpId,
        ecdsaThresholdKeyId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId,
        ...(input.registrationPreparationId
          ? { registrationPreparationId: input.registrationPreparationId }
          : {}),
        requestId: `${input.registrationCeremonyId}:ecdsa`,
        sessionId: `tehss_${randomBase64Url(24)}`,
        walletSigningSessionId: `wss_${randomBase64Url(24)}`,
        ttlMs: 10 * 60_000,
        remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
        participantIds: [...input.participantIds],
        ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
      },
    };
  }

  private async bootstrapEcdsaRegistrationHss(input: {
    threshold: ThresholdSigningServiceType;
    clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
    walletId: WalletId;
  }): Promise<EcdsaHssRouteResult<EcdsaHssServerBootstrapResponse>> {
    const first = await input.threshold.ecdsaHssRoleLocalBootstrap(input.clientBootstrap);
    if (first.ok || first.code !== 'identity_mismatch') return first;

    const existingWallet = await this.getWalletStore().getWallet({ walletId: input.walletId });
    if (existingWallet) return first;

    const deleted = await input.threshold.deleteEcdsaHssRoleLocalKeyByBootstrapIdentity({
      ecdsaThresholdKeyId: input.clientBootstrap.ecdsaThresholdKeyId,
      signingRootId: input.clientBootstrap.signingRootId,
      signingRootVersion: input.clientBootstrap.signingRootVersion,
    });
    if (!deleted.ok) return deleted;
    return await input.threshold.ecdsaHssRoleLocalBootstrap(input.clientBootstrap);
  }

  private async verifyEcdsaRegistrationBootstrapPersisted(input: {
    threshold: ThresholdSigningServiceType;
    bootstrap: EcdsaHssServerBootstrapResponse;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const verified = await input.threshold.verifyEcdsaHssRoleLocalBootstrapPersisted(
      input.bootstrap,
    );
    if (!verified.ok) {
      return {
        ok: false,
        code: verified.code,
        message: verified.message,
      };
    }
    return { ok: true };
  }

  private resolveEd25519RegistrationPrepareScope(input: {
    intent: RegistrationIntentV1;
    orgId: string;
    signingRootId: string;
    signingRootVersion: string;
    expectedOrigin: string;
  }):
    | { ok: true; scope: StoredEd25519RegistrationPrepareScope }
    | { ok: false; code: string; message: string } {
    const selection = input.intent.signerSelection;
    if (selection.mode === 'ecdsa_only') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Ed25519 HSS preparation requires an Ed25519 signer selection',
      };
    }
    const ed25519 = selection.ed25519;
    return {
      ok: true,
      scope: {
        walletId: input.intent.walletId,
        rpId: input.intent.rpId,
        authMethodKind: input.intent.authMethod.kind,
        expectedOrigin: input.expectedOrigin,
        orgId: input.orgId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        nearAccountId: ed25519.nearAccountId,
        keyPurpose: ed25519.keyPurpose,
        keyVersion: ed25519.keyVersion,
        derivationVersion: ed25519.derivationVersion,
        participantIds: [...ed25519.participantIds],
      },
    };
  }

  private async prepareEd25519RegistrationHss(input: {
    scope: StoredEd25519RegistrationPrepareScope;
  }) {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false as const,
        code: 'not_configured',
        message: 'threshold signing is not configured on this server',
      };
    }
    return await threshold.ed25519Hss.prepareForRegistration({
      orgId: input.scope.orgId,
      signingRootId: input.scope.signingRootId,
      signingRootVersion: input.scope.signingRootVersion,
      request: {
        new_account_id: input.scope.nearAccountId,
        rp_id: input.scope.rpId,
        context: {
          signingRootId: input.scope.signingRootId,
          nearAccountId: input.scope.nearAccountId,
          keyPurpose: input.scope.keyPurpose,
          keyVersion: input.scope.keyVersion,
          participantIds: input.scope.participantIds,
          derivationVersion: input.scope.derivationVersion,
        },
      },
    });
  }

  async prepareWalletRegistration(
    request: WalletRegistrationPrepareRequest,
  ): Promise<WalletRegistrationPrepareResponse> {
    const routeStartedAtMs = Date.now();
    const routeTimings = registrationRouteTimingEntries();
    const prepareDiagnostics = () =>
      buildRegistrationRouteDiagnostics({
        route: 'wallets_register_prepare',
        entries: routeTimings,
        totalName: 'registerPrepareTotalMs',
        startedAtMs: routeStartedAtMs,
      });
    try {
      const grant = registrationIntentGrantFromString(request.registrationIntentGrant);
      const ceremonyStore = this.getRegistrationCeremonyStore();
      const storedIntent = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationIntentLoadMs',
        () => ceremonyStore.getIntent(grant),
      );
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      if (storedIntent.intent.signerSelection.mode === 'ecdsa_only') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 HSS preparation requires an Ed25519 registration mode',
        };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      if (!digestB64u || digestB64u !== storedIntent.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'registration intent digest mismatch' };
      }
      const requestDigest = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationIntentDigestMs',
        () => computeRegistrationIntentDigestB64u(request.intent),
      );
      if (requestDigest !== storedIntent.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'registration intent mismatch' };
      }
      const gate = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationAttemptGateMs',
        () => this.consumeRegistrationPrepareRateLimit({ request, storedIntent }),
      );
      if (!gate.ok) {
        return {
          ok: false,
          code: gate.code,
          message: gate.message,
          ...(typeof gate.retryAfterMs === 'number' ? { retryAfterMs: gate.retryAfterMs } : {}),
          ...(typeof gate.resetAtMs === 'number' ? { resetAtMs: gate.resetAtMs } : {}),
        };
      }
      const signingRootId =
        storedIntent.signingRootId ||
        (storedIntent.intent.runtimePolicyScope
          ? deriveSigningRootId(storedIntent.intent.runtimePolicyScope)
          : '');
      const signingRootVersion =
        storedIntent.signingRootVersion ||
        storedIntent.intent.runtimePolicyScope?.signingRootVersion ||
        'default';
      const scopeResult = this.resolveEd25519RegistrationPrepareScope({
        intent: storedIntent.intent,
        orgId: storedIntent.orgId,
        signingRootId,
        signingRootVersion,
        expectedOrigin: toOptionalTrimmedString(storedIntent.expectedOrigin) || '',
      });
      if (!scopeResult.ok) return scopeResult;
      const prepared = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationPreauthHssPrepareMs',
        () => this.prepareEd25519RegistrationHss({ scope: scopeResult.scope }),
      );
      if (!prepared.ok) {
        return {
          ok: false,
          code: prepared.code || 'hss_prepare_failed',
          message: prepared.message || 'Ed25519 HSS prepare failed',
        };
      }
      pushRegistrationRouteDuration(
        routeTimings,
        'registrationHssServerInputDeriveMs',
        prepared.serverInputDeriveMs,
      );
      pushRegistrationRouteDuration(
        routeTimings,
        'registrationHssServerSessionPrepareTotalMs',
        prepared.serverSessionPrepareTotalMs,
      );
      pushRegistrationHssPrepareTimingEntries(routeTimings, prepared.serverSessionTimings);
      const registrationPreparationId = registrationPreparationIdFromString(
        `wrp_${randomBase64Url(24)}`,
      );
      const preparedEd25519 = {
        kind: 'ed25519_prepared' as const,
        ceremonyHandle: prepared.ceremonyHandle,
        preparedSession: prepared.preparedSession,
        clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
      };
      const expiresAtMs = Math.min(storedIntent.expiresAtMs, Date.now() + 10 * 60_000);
      const preparation = buildStoredWalletRegistrationHssPreparationPrepared({
        registrationPreparationId,
        registrationIntentGrant: grant,
        registrationIntentDigestB64u: storedIntent.digestB64u,
        intent: storedIntent.intent,
        orgId: storedIntent.orgId,
        expectedOrigin: toOptionalTrimmedString(storedIntent.expectedOrigin) || '',
        signingRootId,
        signingRootVersion,
        ed25519Scope: scopeResult.scope,
        prepared: preparedEd25519,
        createdAtMs: Date.now(),
        expiresAtMs,
      });
      await measureRegistrationRouteTiming(routeTimings, 'registrationPreparationPersistMs', () =>
        ceremonyStore.putPreparation(preparation),
      );
      return {
        ok: true,
        state: 'prepared',
        registrationPreparationId,
        expiresAtMs,
        registrationDiagnostics: prepareDiagnostics(),
        ed25519: {
          ceremonyHandle: preparedEd25519.ceremonyHandle,
          preparedSession: preparedEd25519.preparedSession,
          clientOtOfferMessageB64u: preparedEd25519.clientOtOfferMessageB64u,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to prepare wallet registration',
      };
    }
  }

  async startWalletRegistration(
    request: WalletRegistrationStartRequest,
  ): Promise<WalletRegistrationStartResponse> {
    const routeStartedAtMs = Date.now();
    const routeTimings = registrationRouteTimingEntries();
    try {
      const grant = registrationIntentGrantFromString(request.registrationIntentGrant);
      const ceremonyStore = this.getRegistrationCeremonyStore();
      const intentPreview = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationIntentLoadMs',
        () => ceremonyStore.getIntent(grant),
      );
      if (!intentPreview) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      if (!digestB64u || digestB64u !== intentPreview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'registration intent digest mismatch' };
      }
      const requestDigest = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationIntentDigestMs',
        () => computeRegistrationIntentDigestB64u(request.intent),
      );
      if (requestDigest !== intentPreview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'registration intent mismatch' };
      }
      const selection = intentPreview.intent.signerSelection;
      const normalizedEcdsaChainTargets =
        selection.mode === 'ecdsa_only' || selection.mode === 'ed25519_and_ecdsa'
          ? selection.ecdsa.chainTargets.map((target) => thresholdEcdsaChainTargetFromValue(target))
          : [];
      if (
        (selection.mode === 'ecdsa_only' || selection.mode === 'ed25519_and_ecdsa') &&
        normalizedEcdsaChainTargets.some((target) => !target)
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration contains an invalid chain target',
        };
      }
      const signingRootId =
        intentPreview.signingRootId ||
        (intentPreview.intent.runtimePolicyScope
          ? deriveSigningRootId(intentPreview.intent.runtimePolicyScope)
          : undefined);
      const signingRootVersion =
        intentPreview.signingRootVersion ||
        intentPreview.intent.runtimePolicyScope?.signingRootVersion ||
        'default';
      if (
        (selection.mode === 'ecdsa_only' || selection.mode === 'ed25519_and_ecdsa') &&
        !signingRootId
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration requires a signing root',
        };
      }

      const storedExpectedOrigin = toOptionalTrimmedString(intentPreview.expectedOrigin);
      if (request.authority.kind === 'passkey' && !storedExpectedOrigin) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }

      const verifiedAuthority = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationAuthorityVerifyMs',
        () =>
          this.verifyRegistrationAuthorityForIntent({
            intent: intentPreview.intent,
            registrationIntentDigestB64u: intentPreview.digestB64u,
            orgId: intentPreview.orgId,
            expectedOrigin: storedExpectedOrigin || '',
            emailOtpRegistrationProof:
              request.authority.kind === 'email_otp'
                ? request.authority.emailOtpRegistrationProof
                : undefined,
            webauthnRegistration:
              request.authority.kind === 'passkey'
                ? request.authority.webauthnRegistration
                : undefined,
          }),
      );
      if (!verifiedAuthority.ok) return verifiedAuthority;
      const authority = verifiedAuthority.authority;
      const preparedRegistration =
        selection.mode === 'ecdsa_only'
          ? null
          : await measureRegistrationRouteTiming(routeTimings, 'registrationPreparationLoadMs', () =>
              request.registrationPreparationId
                ? ceremonyStore.getPreparation(request.registrationPreparationId)
                : Promise.resolve(null),
            );
      if (selection.mode !== 'ecdsa_only' && !preparedRegistration) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationPreparationId is required for Ed25519 registration',
        };
      }
      const preparedRegistrationState = preparedRegistration
        ? getPreparedWalletRegistrationHssPreparation(preparedRegistration)
        : null;
      if (preparedRegistrationState && !preparedRegistrationState.ok) {
        return {
          ok: false,
          code: preparedRegistrationState.code,
          message: preparedRegistrationState.message,
        };
      }
      if (preparedRegistration) {
        const preparedHss = getPreparedWalletRegistrationHssPreparation(preparedRegistration);
        if (!preparedHss.ok) {
          return {
            ok: false,
            code: preparedHss.code,
            message: preparedHss.message,
          };
        }
        const preparedScopeResult = this.resolveEd25519RegistrationPrepareScope({
          intent: intentPreview.intent,
          orgId: intentPreview.orgId,
          signingRootId: signingRootId || '',
          signingRootVersion,
          expectedOrigin: storedExpectedOrigin || '',
        });
        if (!preparedScopeResult.ok) return preparedScopeResult;
        const scopeMatches = await measureRegistrationRouteTiming(
          routeTimings,
          'registrationPreparationScopeCheckMs',
          async () =>
            preparedRegistration.registrationIntentGrant === grant &&
            preparedRegistration.registrationIntentDigestB64u === intentPreview.digestB64u &&
            storedEd25519RegistrationPrepareScopesMatch(
              preparedHss.preparation.ed25519Scope,
              preparedScopeResult.scope,
            ),
        );
        if (!scopeMatches) {
          return {
            ok: false,
            code: 'scope_mismatch',
            message: 'registration preparation scope does not match verified intent',
          };
        }
      }
      const preparedScope =
        preparedRegistrationState && preparedRegistrationState.ok
          ? preparedRegistrationState.preparation.ed25519Scope
          : null;
      const storedIntentResult = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationIntentConsumeMs',
        () =>
          selection.mode === 'ecdsa_only'
            ? ceremonyStore.takeIntent(grant).then((intent) =>
                intent
                  ? ({ ok: true as const, intent })
                  : ({
                      ok: false as const,
                      code: 'invalid_grant' as const,
                      message: 'registration intent grant expired',
                    }),
              )
            : ceremonyStore.consumeRegistrationIntentForPreparation({
                registrationIntentGrant: grant,
                registrationIntentDigestB64u: intentPreview.digestB64u,
                registrationPreparationId: request.registrationPreparationId!,
                ed25519Scope: preparedScope!,
              }),
      );
      if (!storedIntentResult.ok) {
        return {
          ok: false,
          code: storedIntentResult.code,
          message: storedIntentResult.message,
        };
      }
      const storedIntent = storedIntentResult.intent;
      const startDiagnostics = () =>
        buildRegistrationRouteDiagnostics({
          route: 'wallets_register_start',
          entries: routeTimings,
          totalName: 'registerStartTotalMs',
          startedAtMs: routeStartedAtMs,
        });

      const registrationCeremonyId = `wrc_${randomBase64Url(24)}`;
      if (selection.mode === 'ecdsa_only') {
        const threshold = this.getThresholdSigningService();
        if (!threshold) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'threshold signing is not configured on this server',
          };
        }
        const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
          storedIntent.intent.runtimePolicyScope,
        );
        const responseEcdsa = await measureRegistrationRouteTiming(
          routeTimings,
          'registrationEcdsaPrepareMs',
          () =>
            this.prepareEcdsaRegistrationStartPayload({
              registrationCeremonyId,
              walletId: storedIntent.intent.walletId,
              rpId: storedIntent.intent.rpId,
              signingRootId: signingRootId!,
              signingRootVersion,
              chainTargets: normalizedEcdsaChainTargets as ThresholdEcdsaChainTarget[],
              participantIds: selection.ecdsa.participantIds,
              ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            }),
        );
        await measureRegistrationRouteTiming(routeTimings, 'registrationCeremonyPersistMs', () =>
          this.getRegistrationCeremonyStore().putCeremony({
            registrationCeremonyId,
            intent: storedIntent.intent,
            digestB64u: storedIntent.digestB64u,
            orgId: storedIntent.orgId,
            ...(storedIntent.signingRootId ? { signingRootId: storedIntent.signingRootId } : {}),
            ...(storedIntent.signingRootVersion
              ? { signingRootVersion: storedIntent.signingRootVersion }
              : {}),
            ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
            expiresAtMs: Date.now() + 10 * 60_000,
            authority,
            signerState: {
              kind: 'ecdsa_prepared',
              hssKind: responseEcdsa.kind,
              chainTargets: responseEcdsa.chainTargets,
              prepare: responseEcdsa.prepare,
            },
          }),
        );
        await measureRegistrationRouteTiming(routeTimings, 'registrationPreparationConsumeMs', () =>
          ceremonyStore.takePreparation(request.registrationPreparationId!),
        );
        return {
          ok: true,
          registrationCeremonyId,
          intent: storedIntent.intent,
          registrationDiagnostics: startDiagnostics(),
          ecdsa: responseEcdsa,
        };
      }

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const runtimePolicyScope =
        selection.mode === 'ed25519_and_ecdsa'
          ? normalizeThresholdRuntimePolicyScope(storedIntent.intent.runtimePolicyScope)
          : undefined;
      const combinedEcdsaPrepare =
        selection.mode === 'ed25519_and_ecdsa'
          ? await measureRegistrationRouteTiming(routeTimings, 'registrationEcdsaPrepareMs', () =>
                this.prepareEcdsaRegistrationStartPayload({
                  registrationCeremonyId,
                  registrationPreparationId: request.registrationPreparationId!,
                  walletId: storedIntent.intent.walletId,
                  rpId: storedIntent.intent.rpId,
                  signingRootId: signingRootId!,
                  signingRootVersion,
                  chainTargets: normalizedEcdsaChainTargets as ThresholdEcdsaChainTarget[],
                  participantIds: selection.ecdsa.participantIds,
                  ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
                }),
              )
          : null;

      const responseEd25519 = {
        ceremonyHandle: preparedRegistrationState!.preparation.prepared.ceremonyHandle,
        preparedSession: preparedRegistrationState!.preparation.prepared.preparedSession,
        clientOtOfferMessageB64u:
          preparedRegistrationState!.preparation.prepared.clientOtOfferMessageB64u,
      };
      if (selection.mode === 'ed25519_and_ecdsa') {
        const responseEcdsa = combinedEcdsaPrepare;
        if (!responseEcdsa) {
          return {
            ok: false,
            code: 'internal',
            message: 'ECDSA registration prepare failed',
          };
        }
        await measureRegistrationRouteTiming(routeTimings, 'registrationCeremonyPersistMs', () =>
          this.getRegistrationCeremonyStore().putCeremony({
            registrationCeremonyId,
            intent: storedIntent.intent,
            digestB64u: storedIntent.digestB64u,
            orgId: storedIntent.orgId,
            ...(storedIntent.signingRootId ? { signingRootId: storedIntent.signingRootId } : {}),
            ...(storedIntent.signingRootVersion
              ? { signingRootVersion: storedIntent.signingRootVersion }
              : {}),
            ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
            expiresAtMs: Date.now() + 10 * 60_000,
            authority,
            signerState: {
              kind: 'combined_registration',
              ed25519: {
                kind: 'ed25519_prepared',
                ...responseEd25519,
              },
              ecdsa: {
                kind: 'ecdsa_prepared',
                hssKind: responseEcdsa.kind,
                chainTargets: responseEcdsa.chainTargets,
                prepare: responseEcdsa.prepare,
              },
            },
          }),
        );
        await measureRegistrationRouteTiming(routeTimings, 'registrationPreparationConsumeMs', () =>
          ceremonyStore.takePreparation(request.registrationPreparationId!),
        );
        return {
          ok: true,
          registrationCeremonyId,
          intent: storedIntent.intent,
          registrationDiagnostics: startDiagnostics(),
          ed25519: responseEd25519,
          ecdsa: responseEcdsa,
        };
      }
      const signerState = {
        kind: 'ed25519_prepared' as const,
        ...responseEd25519,
      };
      await measureRegistrationRouteTiming(routeTimings, 'registrationCeremonyPersistMs', () =>
        this.getRegistrationCeremonyStore().putCeremony({
          registrationCeremonyId,
          intent: storedIntent.intent,
          digestB64u: storedIntent.digestB64u,
          orgId: storedIntent.orgId,
          ...(storedIntent.signingRootId ? { signingRootId: storedIntent.signingRootId } : {}),
          ...(storedIntent.signingRootVersion
            ? { signingRootVersion: storedIntent.signingRootVersion }
            : {}),
          ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
          expiresAtMs: Date.now() + 10 * 60_000,
          authority,
          signerState,
        }),
      );
      await measureRegistrationRouteTiming(routeTimings, 'registrationPreparationConsumeMs', () =>
        ceremonyStore.takePreparation(request.registrationPreparationId!),
      );
      return {
        ok: true,
        registrationCeremonyId,
        intent: storedIntent.intent,
        registrationDiagnostics: startDiagnostics(),
        ed25519: responseEd25519,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet registration',
      };
    }
  }

  async respondWalletRegistrationHss(
    request: WalletRegistrationHssRespondRequest,
  ): Promise<WalletRegistrationHssRespondResponse> {
    const routeStartedAtMs = Date.now();
    const routeTimings = registrationRouteTimingEntries();
    const respondDiagnostics = () =>
      buildRegistrationRouteDiagnostics({
        route: 'wallets_register_hss_respond',
        entries: routeTimings,
        totalName: 'registerHssRespondTotalMs',
        startedAtMs: routeStartedAtMs,
      });
    const ceremony = await this.getRegistrationCeremonyStore().getCeremony(
      request.registrationCeremonyId,
    );
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
    }
    if (ceremony.signerState.kind === 'combined_registration') {
      if (ceremony.intent.signerSelection.mode !== 'ed25519_and_ecdsa') {
        return { ok: false, code: 'invalid_state', message: 'combined ceremony scope mismatch' };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const combinedSignerState = ceremony.signerState;
      const nextSignerState: StoredCombinedRegistrationState = {
        kind: 'combined_registration',
        ed25519: combinedSignerState.ed25519,
        ecdsa: combinedSignerState.ecdsa,
      };
      const response: Extract<WalletRegistrationHssRespondResponse, { ok: true }> = {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
      };
      const requestEd25519 = request.ed25519;
      if (requestEd25519) {
        const preparedEd25519 = combinedSignerState.ed25519;
        if (preparedEd25519.kind !== 'ed25519_prepared') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 HSS response already recorded',
          };
        }
        const ed25519 = ceremony.intent.signerSelection.ed25519;
        const responded = await measureRegistrationRouteTiming(
          routeTimings,
          'registrationHssRespondMs',
          () =>
            threshold.ed25519Hss.respondForRegistration({
              orgId: ceremony.orgId,
              request: {
                new_account_id: ed25519.nearAccountId,
                rp_id: ceremony.intent.rpId,
                ceremonyHandle: preparedEd25519.ceremonyHandle,
                clientRequest: requestEd25519.clientRequest,
              },
            }),
        );
        if (!responded.ok) {
          return {
            ok: false,
            code: responded.code || 'hss_respond_failed',
            message: responded.message || 'Ed25519 HSS respond failed',
          };
        }
        if (responded.serverInputDeliveryTimings) {
          pushRegistrationHssRespondTimingEntries(
            routeTimings,
            responded.serverInputDeliveryTimings,
          );
        }
        const respondedEd25519 = {
          contextBindingB64u: responded.contextBindingB64u,
          serverInputDeliveryB64u: responded.serverInputDeliveryB64u,
        };
        nextSignerState.ed25519 = {
          kind: 'ed25519_responded',
          ceremonyHandle: preparedEd25519.ceremonyHandle,
          preparedSession: preparedEd25519.preparedSession,
          clientOtOfferMessageB64u: preparedEd25519.clientOtOfferMessageB64u,
          responded: respondedEd25519,
        };
        response.ed25519 = respondedEd25519;
      }
      if (request.ecdsa) {
        if (ceremony.signerState.ecdsa.kind !== 'ecdsa_prepared') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA HSS response already recorded',
          };
        }
        const expected = ceremony.signerState.ecdsa.prepare;
        const actual = request.ecdsa.clientBootstrap;
        if (!isMatchingEcdsaClientBootstrap(expected, actual)) {
          return { ok: false, code: 'invalid_body', message: 'ECDSA bootstrap identity mismatch' };
        }
        const bootstrap = await measureRegistrationRouteTiming(
          routeTimings,
          'registrationEcdsaRespondMs',
          () =>
            this.bootstrapEcdsaRegistrationHss({
              threshold,
              clientBootstrap: actual,
              walletId: ceremony.intent.walletId,
            }),
        );
        if (!bootstrap.ok) {
          return {
            ok: false,
            code: bootstrap.code || 'hss_respond_failed',
            message: bootstrap.message || 'ECDSA HSS bootstrap failed',
          };
        }
        nextSignerState.ecdsa = {
          kind: 'ecdsa_responded',
          hssKind: ceremony.signerState.ecdsa.hssKind,
          chainTargets: ceremony.signerState.ecdsa.chainTargets,
          prepare: ceremony.signerState.ecdsa.prepare,
          responded: {
            bootstrap: bootstrap.value,
          },
        };
        response.ecdsa = {
          bootstrap: bootstrap.value,
        };
      }
      if (!response.ed25519 && !response.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration HSS response is required',
        };
      }
      await this.getRegistrationCeremonyStore().updateCeremony({
        ...ceremony,
        signerState: nextSignerState,
      });
      response.registrationDiagnostics = respondDiagnostics();
      return response;
    }
    if (ceremony.intent.signerSelection.mode === 'ecdsa_only') {
      if (!request.ecdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA HSS response' };
      }
      if (ceremony.signerState.kind !== 'ecdsa_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response already recorded',
        };
      }
      const expected = ceremony.signerState.prepare;
      const actual = request.ecdsa.clientBootstrap;
      if (!isMatchingEcdsaClientBootstrap(expected, actual)) {
        return { ok: false, code: 'invalid_body', message: 'ECDSA bootstrap identity mismatch' };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const bootstrap = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationEcdsaRespondMs',
        () =>
          this.bootstrapEcdsaRegistrationHss({
            threshold,
            clientBootstrap: actual,
            walletId: ceremony.intent.walletId,
          }),
      );
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'hss_respond_failed',
          message: bootstrap.message || 'ECDSA HSS bootstrap failed',
        };
      }
      await this.getRegistrationCeremonyStore().updateCeremony({
        ...ceremony,
        signerState: {
          ...ceremony.signerState,
          kind: 'ecdsa_responded',
          responded: {
            bootstrap: bootstrap.value,
          },
        },
      });
      return {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
        registrationDiagnostics: respondDiagnostics(),
        ecdsa: {
          bootstrap: bootstrap.value,
        },
      };
    }
    if (!request.ed25519) {
      return { ok: false, code: 'invalid_body', message: 'missing Ed25519 HSS response' };
    }
    if (ceremony.signerState.kind !== 'ed25519_prepared') {
      return { ok: false, code: 'invalid_state', message: 'Ed25519 HSS response already recorded' };
    }
    if (ceremony.intent.signerSelection.mode !== 'ed25519_only') {
      return { ok: false, code: 'invalid_body', message: 'Ed25519 response scope mismatch' };
    }
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold signing is not configured on this server',
      };
    }
    const requestEd25519 = request.ed25519;
    const preparedEd25519 = ceremony.signerState;
    const ed25519 = ceremony.intent.signerSelection.ed25519;
    const responded = await measureRegistrationRouteTiming(
      routeTimings,
      'registrationHssRespondMs',
      () =>
        threshold.ed25519Hss.respondForRegistration({
          orgId: ceremony.orgId,
          request: {
            new_account_id: ed25519.nearAccountId,
            rp_id: ceremony.intent.rpId,
            ceremonyHandle: preparedEd25519.ceremonyHandle,
            clientRequest: requestEd25519.clientRequest,
          },
        }),
    );
    if (!responded.ok) {
      return {
        ok: false,
        code: responded.code || 'hss_respond_failed',
        message: responded.message || 'Ed25519 HSS respond failed',
      };
    }
    if (responded.serverInputDeliveryTimings) {
      pushRegistrationHssRespondTimingEntries(
        routeTimings,
        responded.serverInputDeliveryTimings,
      );
    }
    const respondedEd25519 = {
      contextBindingB64u: responded.contextBindingB64u,
      serverInputDeliveryB64u: responded.serverInputDeliveryB64u,
    };
    await this.getRegistrationCeremonyStore().updateCeremony({
      ...ceremony,
      signerState: {
        ...ceremony.signerState,
        kind: 'ed25519_responded',
        responded: respondedEd25519,
      },
    });
    return {
      ok: true,
      registrationCeremonyId: ceremony.registrationCeremonyId,
      registrationDiagnostics: respondDiagnostics(),
      ed25519: respondedEd25519,
    };
  }

  private buildWalletRecord(input: {
    walletId: WalletId;
    rpId: string;
    now: number;
  }): WalletRecord {
    return {
      version: 'wallet_v1',
      walletId: input.walletId,
      rpId: input.rpId,
      createdAtMs: input.now,
      updatedAtMs: input.now,
    };
  }

  private buildPasskeyWalletAuthMethodRecord(input: {
    walletId: WalletId;
    rpId: string;
    credentialIdB64u: string;
    credentialPublicKeyB64u: string;
    counter: number;
    now: number;
  }): WalletAuthMethodRecord {
    return {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      walletId: input.walletId,
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      credentialPublicKeyB64u: input.credentialPublicKeyB64u,
      counter: input.counter,
      createdAtMs: input.now,
      updatedAtMs: input.now,
    };
  }

  private buildEmailOtpWalletAuthMethodRecord(input: {
    walletId: WalletId;
    rpId: string;
    emailHashHex: string;
    registrationAuthorityId: string;
    now: number;
  }): WalletAuthMethodRecord {
    return {
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: input.walletId,
      rpId: input.rpId,
      emailHashHex: input.emailHashHex,
      registrationAuthorityId: input.registrationAuthorityId,
      createdAtMs: input.now,
      updatedAtMs: input.now,
    };
  }

  private buildAddAuthMethodPersistenceRecords(input: {
    authority: RegistrationAuthority;
    now: number;
  }): AddAuthMethodPersistenceRecords {
    switch (input.authority.kind) {
      case 'passkey': {
        const authenticator: WebAuthnAuthenticatorRecord = {
          version: 'webauthn_authenticator_v1',
          credentialIdB64u: input.authority.credentialIdB64u,
          credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
          counter: input.authority.counter,
          createdAtMs: input.now,
          updatedAtMs: input.now,
        };
        return {
          webAuthnAuthenticators: [
            {
              userId: input.authority.walletId,
              record: authenticator,
            },
          ],
          walletAuthMethods: [
            this.buildPasskeyWalletAuthMethodRecord({
              walletId: input.authority.walletId,
              rpId: input.authority.rpId,
              credentialIdB64u: input.authority.credentialIdB64u,
              credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
              counter: input.authority.counter,
              now: input.now,
            }),
          ],
        };
      }
      case 'email_otp':
        return {
          webAuthnAuthenticators: [],
          walletAuthMethods: [
            this.buildEmailOtpWalletAuthMethodRecord({
              walletId: input.authority.walletId,
              rpId: input.authority.rpId,
              emailHashHex: input.authority.emailHashHex,
              registrationAuthorityId: input.authority.registrationAuthorityId,
              now: input.now,
            }),
          ],
        };
    }
    return assertNever(input.authority);
  }

  private buildRegistrationAuthorityPersistenceRecords(
    input: RegistrationAuthorityPersistenceInput,
  ): RegistrationAuthorityPersistenceRecords {
    switch (input.authority.kind) {
      case 'passkey': {
        const webAuthnAuthenticatorRecord: WebAuthnAuthenticatorRecord = {
          version: 'webauthn_authenticator_v1',
          credentialIdB64u: input.authority.credentialIdB64u,
          credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
          counter: input.authority.counter,
          createdAtMs: input.now,
          updatedAtMs: input.now,
        };
        const credentialBindings: WebAuthnCredentialBindingRecord[] = input.ed25519
          ? [
              {
                version: 'webauthn_credential_binding_v1',
                rpId: input.rpId,
                credentialIdB64u: input.authority.credentialIdB64u,
                userId: input.walletId,
                signerSlot: input.ed25519.signerSlot,
                publicKey: input.ed25519.publicKey,
                relayerKeyId: input.ed25519.relayerKeyId,
                keyVersion: input.ed25519.keyVersion,
                recoveryExportCapable: input.ed25519.recoveryExportCapable,
                clientParticipantId: input.ed25519.clientParticipantId,
                relayerParticipantId: input.ed25519.relayerParticipantId,
                participantIds: input.ed25519.participantIds,
                ...(input.ed25519.runtimePolicyScope
                  ? { runtimePolicyScope: input.ed25519.runtimePolicyScope }
                  : {}),
                createdAtMs: input.now,
                updatedAtMs: input.now,
              },
            ]
          : [];
        return {
          webAuthnAuthenticators: [{ userId: input.walletId, record: webAuthnAuthenticatorRecord }],
          credentialBindings,
          walletAuthMethods: [
            this.buildPasskeyWalletAuthMethodRecord({
              walletId: input.walletId,
              rpId: input.rpId,
              credentialIdB64u: input.authority.credentialIdB64u,
              credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
              counter: input.authority.counter,
              now: input.now,
            }),
          ],
        };
      }
      case 'email_otp':
        return {
          webAuthnAuthenticators: [],
          credentialBindings: [],
          walletAuthMethods: [
            this.buildEmailOtpWalletAuthMethodRecord({
              walletId: input.walletId,
              rpId: input.rpId,
              emailHashHex: input.authority.emailHashHex,
              registrationAuthorityId: input.authority.registrationAuthorityId,
              now: input.now,
            }),
          ],
        };
    }
    return assertNever(input.authority);
  }

  private async prepareGoogleEmailOtpRegistrationActivation(input: {
    authority: RegistrationAuthority;
    walletId: WalletId;
  }): Promise<
    | { ok: true; activation?: GoogleEmailOtpRegistrationActivationPersistence }
    | { ok: false; code: string; message: string }
  > {
    if (
      input.authority.kind !== 'email_otp' ||
      input.authority.proofKind !== 'google_sso_registration'
    ) {
      return { ok: true };
    }

    const attempt = await this.getEmailOtpRegistrationAttemptStore().get(
      input.authority.googleEmailOtpRegistrationAttemptId,
    );
    if (!attempt) {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired or was not found',
      };
    }
    if (attempt.expiresAtMs <= Date.now()) {
      await this.getEmailOtpRegistrationAttemptStore().put({
        ...attempt,
        state: 'expired',
        updatedAtMs: Date.now(),
      });
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt expired',
      };
    }
    if (attempt.walletId !== input.walletId) {
      return {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'registrationAttemptId does not match walletId',
      };
    }
    if (attempt.state !== 'started' && attempt.state !== 'key_finalized') {
      return {
        ok: false,
        code: 'registration_incomplete',
        message: 'Google Email OTP registration attempt is no longer active',
      };
    }
    return {
      ok: true,
      activation: {
        attempt,
        walletId: input.walletId,
      },
    };
  }

  private activeGoogleEmailOtpRegistrationAttemptRecord(
    activation: GoogleEmailOtpRegistrationActivationPersistence,
  ): GoogleEmailOtpRegistrationAttemptRecord {
    return {
      ...activation.attempt,
      state: 'active',
      updatedAtMs: Date.now(),
    };
  }

  private async persistGoogleEmailOtpRegistrationActivationToStores(
    activation: GoogleEmailOtpRegistrationActivationPersistence,
  ): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const linked = await this.getIdentityStore().linkSubjectToUserId({
      userId: activation.walletId,
      subject: `wallet:${activation.attempt.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
    if (!linked.ok) {
      await this.getEmailOtpRegistrationAttemptStore().put({
        ...activation.attempt,
        state: 'failed',
        failureCode: linked.code,
        updatedAtMs: Date.now(),
      });
      return {
        ok: false,
        code: linked.code,
        message: linked.message,
      };
    }
    await this.getEmailOtpRegistrationAttemptStore().put(
      this.activeGoogleEmailOtpRegistrationAttemptRecord(activation),
    );
    return { ok: true };
  }

  private async preflightGoogleEmailOtpRegistrationActivationForStores(
    activation: GoogleEmailOtpRegistrationActivationPersistence,
  ): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const subject = `wallet:${activation.attempt.providerSubject}`;
    const linkedWalletId = await this.getIdentityStore().getUserIdBySubject(subject);
    if (!linkedWalletId || linkedWalletId === activation.walletId) return { ok: true };
    const sourceSubjects = await this.getIdentityStore().listSubjectsByUserId(linkedWalletId);
    if (sourceSubjects.length === 1 && sourceSubjects[0] === subject) return { ok: true };
    return {
      ok: false,
      code: 'already_linked',
      message: 'Subject is linked to a different user with other identities; merge is not allowed',
    };
  }

  private async persistGoogleEmailOtpRegistrationActivationWithExecutor(input: {
    executor: {
      query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
    };
    identityNamespace: string;
    emailOtpNamespace: string;
    activation: GoogleEmailOtpRegistrationActivationPersistence;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const linked = await linkIdentitySubjectToUserIdWithExecutor({
      executor: input.executor,
      namespace: input.identityNamespace,
      userId: input.activation.walletId,
      subject: `wallet:${input.activation.attempt.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
    if (!linked.ok) {
      await putGoogleEmailOtpRegistrationAttemptWithExecutor({
        executor: input.executor,
        namespace: input.emailOtpNamespace,
        record: {
          ...input.activation.attempt,
          state: 'failed',
          failureCode: linked.code,
          updatedAtMs: Date.now(),
        },
      });
      return {
        ok: false,
        code: linked.code,
        message: linked.message,
      };
    }
    await putGoogleEmailOtpRegistrationAttemptWithExecutor({
      executor: input.executor,
      namespace: input.emailOtpNamespace,
      record: this.activeGoogleEmailOtpRegistrationAttemptRecord(input.activation),
    });
    return { ok: true };
  }

  private googleEmailOtpRegistrationFinalizeIdempotencyKey(input: {
    authority: RegistrationAuthority;
    idempotencyKey?: unknown;
  }): { ok: true; idempotencyKey?: string } | { ok: false; code: string; message: string } {
    if (
      input.authority.kind !== 'email_otp' ||
      input.authority.proofKind !== 'google_sso_registration'
    ) {
      return { ok: true };
    }
    const idempotencyKey = toOptionalTrimmedString(input.idempotencyKey);
    if (!idempotencyKey) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Google Email OTP registration finalize requires idempotencyKey',
      };
    }
    return { ok: true, idempotencyKey };
  }

  private nonSecretWalletRegistrationFinalizeReplay(
    response: Extract<WalletRegistrationFinalizeResponse, { ok: true }>,
  ): Extract<WalletRegistrationFinalizeResponse, { ok: true }> {
    if ('kind' in response && response.kind === 'already_finalized_restore_required') {
      return response;
    }
    if (!('ed25519' in response) || !response.ed25519) return response;
    if (!response.ed25519.session) return response;
    return {
      ok: true,
      kind: 'already_finalized_restore_required',
      walletId: response.walletId,
      rpId: response.rpId,
      reason: 'replay_without_session_material',
    };
  }

  private async cacheGoogleEmailOtpRegistrationFinalizeReplay(input: {
    authority: RegistrationAuthority;
    registrationCeremonyId: string;
    idempotencyKey?: string;
    expiresAtMs: number;
    response: Extract<WalletRegistrationFinalizeResponse, { ok: true }>;
  }): Promise<void> {
    if (
      input.authority.kind !== 'email_otp' ||
      input.authority.proofKind !== 'google_sso_registration' ||
      !input.idempotencyKey
    ) {
      return;
    }
    await this.getRegistrationCeremonyStore().putFinalizeReplay({
      kind: 'wallet_registration_finalize_replay_v1',
      registrationCeremonyId: input.registrationCeremonyId,
      idempotencyKey: input.idempotencyKey,
      response: this.nonSecretWalletRegistrationFinalizeReplay(input.response),
      createdAtMs: Date.now(),
      expiresAtMs: input.expiresAtMs,
    });
  }

  private buildWalletEd25519SignerRecord(input: {
    walletId: WalletId;
    rpId: string;
    nearAccountId: string;
    signerSlot: number;
    keygen: Extract<ThresholdEd25519RegistrationKeygenResult, { ok: true }>;
    now: number;
  }): WalletSignerRecord {
    return {
      version: 'wallet_signer_ed25519_v1',
      walletId: input.walletId,
      rpId: input.rpId,
      signerId: buildWalletEd25519SignerId({
        nearAccountId: input.nearAccountId,
        signerSlot: input.signerSlot,
      }),
      nearAccountId: input.nearAccountId,
      signerSlot: input.signerSlot,
      publicKey: input.keygen.publicKey,
      relayerKeyId: input.keygen.relayerKeyId,
      keyVersion: input.keygen.keyVersion,
      recoveryExportCapable: input.keygen.recoveryExportCapable,
      clientParticipantId: input.keygen.clientParticipantId,
      relayerParticipantId: input.keygen.relayerParticipantId,
      participantIds: input.keygen.participantIds,
      createdAtMs: input.now,
      updatedAtMs: input.now,
    };
  }

  private buildWalletEcdsaSignerRecords(input: {
    walletId: WalletId;
    walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
    now: number;
  }): WalletSignerRecord[] {
    return input.walletKeys.map((walletKey) =>
      buildWalletEcdsaSignerRecord({
        walletId: input.walletId,
        walletKey,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      }),
    );
  }

  private postgresRegistrationPersistenceConfig(): {
    postgresUrl: string;
    registrationNamespace: string;
    webAuthnAuthenticatorNamespace: string;
    webAuthnCredentialBindingNamespace: string;
    walletNamespace: string;
    walletAuthMethodNamespace: string;
    emailOtpNamespace: string;
    identityNamespace: string;
  } | null {
    if (!this.isNodeEnvironment()) return null;
    const config = (
      this.config.thresholdStore && typeof this.config.thresholdStore === 'object'
        ? this.config.thresholdStore
        : {}
    ) as Record<string, unknown>;
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) return null;
    const kind = toOptionalTrimmedString(config.kind);
    if (kind && kind !== 'postgres') return null;
    return {
      postgresUrl,
      registrationNamespace: resolveRegistrationCeremonyPostgresNamespace(config),
      webAuthnAuthenticatorNamespace: resolveWebAuthnAuthenticatorStoreNamespace(config),
      webAuthnCredentialBindingNamespace: resolveWebAuthnCredentialBindingStoreNamespace(config),
      walletNamespace: resolveWalletStoreNamespace(config),
      walletAuthMethodNamespace: resolveWalletAuthMethodStoreNamespace(config),
      emailOtpNamespace: resolveEmailOtpStoreNamespace(config),
      identityNamespace: resolveIdentityStoreNamespace(config),
    };
  }

  private async writeRegistrationPersistenceToStores(input: {
    records: RegistrationPersistenceRecords;
    deferWalletRecordUntilActivation?: boolean;
  }): Promise<void> {
    const { records } = input;
    for (const item of records.webAuthnAuthenticators) {
      await this.getWebAuthnAuthenticatorStore().put(item.userId, item.record);
    }
    for (const record of records.credentialBindings) {
      await this.getWebAuthnCredentialBindingStore().put(record);
    }
    if (!input.deferWalletRecordUntilActivation) {
      await this.getWalletStore().putSubject(records.wallet);
    }
    for (const record of records.walletAuthMethods) {
      await this.getWalletAuthMethodStore().put(record);
    }
    await this.getWalletStore().putSigners(records.walletSigners);
    if (records.emailOtpEnrollment) {
      const emailOtpEnrollment = records.emailOtpEnrollment;
      if (emailOtpEnrollment.previousProviderWalletId) {
        await this.getEmailOtpWalletEnrollmentStore().del(
          emailOtpEnrollment.previousProviderWalletId,
        );
      }
      await this.getEmailOtpWalletEnrollmentStore().put(emailOtpEnrollment.enrollment);
      const recoveryStore = this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore();
      await recoveryStore.putMany(emailOtpEnrollment.recoveryWrappedEnrollmentEscrows);
      await this.getEmailOtpAuthStateStore().put(emailOtpEnrollment.authState);
    }
    if (input.deferWalletRecordUntilActivation) {
      await this.getWalletStore().putSubject(records.wallet);
    }
  }

  private async writeAddAuthMethodPersistenceToStores(
    records: AddAuthMethodPersistenceRecords,
  ): Promise<void> {
    for (const item of records.webAuthnAuthenticators) {
      await this.getWebAuthnAuthenticatorStore().put(item.userId, item.record);
    }
    for (const record of records.walletAuthMethods) {
      await this.getWalletAuthMethodStore().put(record);
    }
  }

  private async writeRegistrationPersistenceWithExecutor(input: {
    executor: {
      query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
    };
    namespaces: {
      webAuthnAuthenticatorNamespace: string;
      webAuthnCredentialBindingNamespace: string;
      walletNamespace: string;
      walletAuthMethodNamespace: string;
      emailOtpNamespace: string;
    };
    records: RegistrationPersistenceRecords;
  }): Promise<void> {
    for (const item of input.records.webAuthnAuthenticators) {
      await putWebAuthnAuthenticatorRecordWithExecutor({
        executor: input.executor,
        namespace: input.namespaces.webAuthnAuthenticatorNamespace,
        userId: item.userId,
        record: item.record,
      });
    }
    for (const record of input.records.credentialBindings) {
      await putWebAuthnCredentialBindingRecordWithExecutor({
        executor: input.executor,
        namespace: input.namespaces.webAuthnCredentialBindingNamespace,
        record,
      });
    }
    await putWalletRecordWithExecutor({
      executor: input.executor,
      namespace: input.namespaces.walletNamespace,
      record: input.records.wallet,
    });
    for (const record of input.records.walletAuthMethods) {
      await putWalletAuthMethodWithExecutor({
        executor: input.executor,
        namespace: input.namespaces.walletAuthMethodNamespace,
        record,
      });
    }
    for (const record of input.records.walletSigners) {
      await putWalletSignerRecordWithExecutor({
        executor: input.executor,
        namespace: input.namespaces.walletNamespace,
        record,
      });
    }
    if (input.records.emailOtpEnrollment) {
      await this.writeEmailOtpRegistrationEnrollmentWithExecutor({
        executor: input.executor,
        namespace: input.namespaces.emailOtpNamespace,
        enrollment: input.records.emailOtpEnrollment,
      });
    }
  }

  private async writeAddAuthMethodPersistenceWithExecutor(input: {
    executor: {
      query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
    };
    namespaces: {
      webAuthnAuthenticatorNamespace: string;
      walletAuthMethodNamespace: string;
    };
    records: AddAuthMethodPersistenceRecords;
  }): Promise<void> {
    for (const item of input.records.webAuthnAuthenticators) {
      await putWebAuthnAuthenticatorRecordWithExecutor({
        executor: input.executor,
        namespace: input.namespaces.webAuthnAuthenticatorNamespace,
        userId: item.userId,
        record: item.record,
      });
    }
    for (const record of input.records.walletAuthMethods) {
      await putWalletAuthMethodWithExecutor({
        executor: input.executor,
        namespace: input.namespaces.walletAuthMethodNamespace,
        record,
      });
    }
  }

  private async writeEmailOtpRegistrationEnrollmentWithExecutor(input: {
    executor: {
      query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
    };
    namespace: string;
    enrollment: EmailOtpRegistrationEnrollmentPersistence;
  }): Promise<void> {
    const { enrollment } = input.enrollment;
    if (input.enrollment.previousProviderWalletId) {
      await input.executor.query(
        `
          DELETE FROM email_otp_wallet_enrollments
          WHERE namespace = $1 AND wallet_id = $2
        `,
        [input.namespace, input.enrollment.previousProviderWalletId],
      );
    }
    await input.executor.query(
      `
        INSERT INTO email_otp_wallet_enrollments
          (namespace, wallet_id, org_id, record_json, updated_at_ms)
        VALUES ($1, $2, $3, $4::jsonb, $5)
        ON CONFLICT (namespace, wallet_id) DO UPDATE SET
          org_id = EXCLUDED.org_id,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        input.namespace,
        enrollment.walletId,
        enrollment.orgId,
        JSON.stringify(enrollment),
        enrollment.updatedAtMs,
      ],
    );
    for (const record of input.enrollment.recoveryWrappedEnrollmentEscrows) {
      await input.executor.query(
        `
          INSERT INTO email_otp_recovery_wrapped_enrollment_escrows (
            namespace,
            wallet_id,
            recovery_key_id,
            recovery_key_status,
            record_json,
            updated_at_ms
          )
          VALUES ($1, $2, $3, $4, $5::jsonb, $6)
          ON CONFLICT (namespace, wallet_id, recovery_key_id)
          DO UPDATE SET
            recovery_key_status = EXCLUDED.recovery_key_status,
            record_json = EXCLUDED.record_json,
            updated_at_ms = EXCLUDED.updated_at_ms
        `,
        [
          input.namespace,
          record.walletId,
          record.recoveryKeyId,
          record.recoveryKeyStatus,
          JSON.stringify(record),
          record.updatedAtMs,
        ],
      );
    }
    const authState = input.enrollment.authState;
    await input.executor.query(
      `
        INSERT INTO email_otp_auth_states
          (namespace, wallet_id, org_id, record_json, updated_at_ms)
        VALUES ($1, $2, $3, $4::jsonb, $5)
        ON CONFLICT (namespace, wallet_id)
        DO UPDATE SET
          org_id = EXCLUDED.org_id,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        input.namespace,
        authState.walletId,
        authState.orgId,
        JSON.stringify(authState),
        authState.updatedAtMs,
      ],
    );
  }

  private async consumeRegistrationCeremonyAndPersist(input: {
    registrationCeremonyId: string;
    records: RegistrationPersistenceRecords;
    googleEmailOtpActivation?: GoogleEmailOtpRegistrationActivationPersistence;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const postgres = this.postgresRegistrationPersistenceConfig();
    if (!postgres) {
      const ceremony = await this.getRegistrationCeremonyStore().takeCeremony(
        input.registrationCeremonyId,
      );
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (input.googleEmailOtpActivation) {
        const preflight = await this.preflightGoogleEmailOtpRegistrationActivationForStores(
          input.googleEmailOtpActivation,
        );
        if (!preflight.ok) return preflight;
      }
      if (input.googleEmailOtpActivation) {
        const activated = await this.persistGoogleEmailOtpRegistrationActivationToStores(
          input.googleEmailOtpActivation,
        );
        if (!activated.ok) return activated;
      }
      await this.writeRegistrationPersistenceToStores({
        records: input.records,
        deferWalletRecordUntilActivation: !!input.googleEmailOtpActivation,
      });
      return { ok: true };
    }

    const pool = await getPostgresPool(postgres.postgresUrl);
    if (typeof pool.connect !== 'function') {
      throw new Error('Postgres finalization requires a transaction-capable pool');
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const deleted = await client.query(
        `
          DELETE FROM wallet_registration_ceremonies
          WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $3
          RETURNING registration_ceremony_id
        `,
        [postgres.registrationNamespace, input.registrationCeremonyId, Date.now()],
      );
      if (!deleted.rows[0]) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      await this.writeRegistrationPersistenceWithExecutor({
        executor: client,
        namespaces: postgres,
        records: input.records,
      });
      if (input.googleEmailOtpActivation) {
        const activated = await this.persistGoogleEmailOtpRegistrationActivationWithExecutor({
          executor: client,
          identityNamespace: postgres.identityNamespace,
          emailOtpNamespace: postgres.emailOtpNamespace,
          activation: input.googleEmailOtpActivation,
        });
        if (!activated.ok) {
          await client.query('ROLLBACK');
          return activated;
        }
      }
      await client.query('COMMIT');
      return { ok: true };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  private async consumeAddSignerCeremonyAndPersist(input: {
    addSignerCeremonyId: string;
    records: RegistrationPersistenceRecords;
  }): Promise<boolean> {
    const postgres = this.postgresRegistrationPersistenceConfig();
    if (!postgres) {
      const ceremony = await this.getRegistrationCeremonyStore().takeAddSignerCeremony(
        input.addSignerCeremonyId,
      );
      if (!ceremony) return false;
      await this.writeRegistrationPersistenceToStores({ records: input.records });
      return true;
    }

    const pool = await getPostgresPool(postgres.postgresUrl);
    if (typeof pool.connect !== 'function') {
      throw new Error('Postgres finalization requires a transaction-capable pool');
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const deleted = await client.query(
        `
          DELETE FROM wallet_registration_ceremonies
          WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $3
          RETURNING registration_ceremony_id
        `,
        [postgres.registrationNamespace, input.addSignerCeremonyId, Date.now()],
      );
      if (!deleted.rows[0]) {
        await client.query('ROLLBACK');
        return false;
      }
      await this.writeRegistrationPersistenceWithExecutor({
        executor: client,
        namespaces: postgres,
        records: input.records,
      });
      await client.query('COMMIT');
      return true;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  private async consumeAddAuthMethodCeremonyAndPersist(input: {
    addAuthMethodCeremonyId: string;
    records: AddAuthMethodPersistenceRecords;
  }): Promise<boolean> {
    const postgres = this.postgresRegistrationPersistenceConfig();
    if (!postgres) {
      const ceremony = await this.getRegistrationCeremonyStore().takeAddAuthMethodCeremony(
        input.addAuthMethodCeremonyId,
      );
      if (!ceremony) return false;
      await this.writeAddAuthMethodPersistenceToStores(input.records);
      return true;
    }

    const pool = await getPostgresPool(postgres.postgresUrl);
    if (typeof pool.connect !== 'function') {
      throw new Error('Postgres finalization requires a transaction-capable pool');
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const deleted = await client.query(
        `
          DELETE FROM wallet_registration_ceremonies
          WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $3
          RETURNING registration_ceremony_id
        `,
        [postgres.registrationNamespace, input.addAuthMethodCeremonyId, Date.now()],
      );
      if (!deleted.rows[0]) {
        await client.query('ROLLBACK');
        return false;
      }
      await this.writeAddAuthMethodPersistenceWithExecutor({
        executor: client,
        namespaces: {
          webAuthnAuthenticatorNamespace: postgres.webAuthnAuthenticatorNamespace,
          walletAuthMethodNamespace: postgres.walletAuthMethodNamespace,
        },
        records: input.records,
      });
      await client.query('COMMIT');
      return true;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async finalizeWalletRegistration(
    request: WalletRegistrationFinalizeRequest,
  ): Promise<WalletRegistrationFinalizeResponse> {
    const routeStartedAtMs = Date.now();
    const routeTimings = registrationRouteTimingEntries();
    const finalizeDiagnostics = () =>
      buildRegistrationRouteDiagnostics({
        route: 'wallets_register_finalize',
        entries: routeTimings,
        totalName: 'registerFinalizeTotalMs',
        startedAtMs: routeStartedAtMs,
      });
    const ceremonyStore = this.getRegistrationCeremonyStore();
    const requestIdempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
    if (requestIdempotencyKey) {
      const replay = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationFinalizeReplayLoadMs',
        () =>
          ceremonyStore.getFinalizeReplay({
            registrationCeremonyId: request.registrationCeremonyId,
            idempotencyKey: requestIdempotencyKey,
          }),
      );
      if (replay) return replay.response;
    }
    const ceremony = await measureRegistrationRouteTiming(
      routeTimings,
      'registrationCeremonyLoadMs',
      () => ceremonyStore.getCeremony(request.registrationCeremonyId),
    );
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
    }
    const finalizeIdempotency = this.googleEmailOtpRegistrationFinalizeIdempotencyKey({
      authority: ceremony.authority,
      idempotencyKey: request.idempotencyKey,
    });
    if (!finalizeIdempotency.ok) return finalizeIdempotency;
    if (ceremony.signerState.kind === 'combined_registration') {
      if (ceremony.intent.signerSelection.mode !== 'ed25519_and_ecdsa') {
        return { ok: false, code: 'invalid_state', message: 'combined ceremony scope mismatch' };
      }
      if (!request.ed25519 || !request.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'combined registration finalize requires Ed25519 and ECDSA inputs',
        };
      }
      if (
        ceremony.signerState.ed25519.kind !== 'ed25519_responded' ||
        ceremony.signerState.ecdsa.kind !== 'ecdsa_responded'
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'combined registration requires Ed25519 and ECDSA HSS responses before finalize',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const ed25519 = ceremony.intent.signerSelection.ed25519;
      const combinedSignerState = ceremony.signerState;
      const ed25519FinalizeRequest = request.ed25519;
      const finalized = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationHssFinalizeMs',
        () =>
          threshold.ed25519Hss.finalizeForRegistration({
            orgId: ceremony.orgId,
            request: {
              new_account_id: ed25519.nearAccountId,
              rp_id: ceremony.intent.rpId,
              ceremonyHandle: combinedSignerState.ed25519.ceremonyHandle,
              evaluationResult: ed25519FinalizeRequest.evaluationResult,
            },
          }),
      );
      if (!finalized.ok) {
        return {
          ok: false,
          code: finalized.code || 'hss_finalize_failed',
          message: finalized.message || 'Ed25519 HSS finalize failed',
        };
      }
      if (finalized.finalizeReportTimings) {
        pushRegistrationHssFinalizeTimingEntries(routeTimings, finalized.finalizeReportTimings);
      }
      const bootstrap = ceremony.signerState.ecdsa.responded.bootstrap;
      const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
      if (expectedKeyHandles.some((keyHandle) => keyHandle !== bootstrap.keyHandle)) {
        return {
          ok: false,
          code: 'key_handle_mismatch',
          message: 'ECDSA finalize expected key handle mismatch',
        };
      }
      const verifiedEcdsaKey = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationEcdsaBootstrapVerifyMs',
        () =>
          this.verifyEcdsaRegistrationBootstrapPersisted({
            threshold,
            bootstrap,
          }),
      );
      if (!verifiedEcdsaKey.ok) return verifiedEcdsaKey;
      const walletKeyResult = buildEcdsaWalletKeysFromBootstrap({
        bootstrap,
        chainTargets: ceremony.signerState.ecdsa.chainTargets,
        errorContext: 'combined ECDSA registration finalize',
      });
      if (!walletKeyResult.ok) return walletKeyResult;

      if (ed25519.createNearAccount) {
        const created = await measureRegistrationRouteTiming(
          routeTimings,
          'nearAccountCreateMs',
          () =>
            this.createAccount({
              accountId: ed25519.nearAccountId,
              publicKey: finalized.publicKey,
            }),
        );
        if (!created.success) {
          return {
            ok: false,
            code: 'account_creation_failed',
            message: created.error || created.message || 'Failed to create NEAR account',
          };
        }
      }

      const schemeAny = threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
      if (!schemeAny || schemeAny.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
        return {
          ok: false,
          code: 'not_configured',
          message: `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled`,
        };
      }
      const keygen = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationKeygenMs',
        () =>
          schemeAny.registration.keygenFromRegistrationMaterial({
            nearAccountId: ed25519.nearAccountId,
            rpId: ceremony.intent.rpId,
            keyVersion: ed25519.keyVersion,
            recoveryExportCapable: true,
            publicKey: finalized.publicKey,
            relayerKeyId: finalized.relayerKeyId,
          }),
      );
      if (!keygen.ok) {
        return {
          ok: false,
          code: keygen.code || 'keygen_failed',
          message: keygen.message || 'Ed25519 registration keygen failed',
        };
      }

      const now = Date.now();
      const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
        ceremony.intent.runtimePolicyScope,
      );
      const emailOtpEnrollment = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationEmailOtpEnrollmentPlanMs',
        () =>
          this.emailOtpEnrollmentPersistenceForRegistrationFinalize({
            authority: ceremony.authority,
            request,
            walletId: ceremony.intent.walletId,
            orgId: ceremony.orgId,
            nowMs: now,
          }),
      );
      if (!emailOtpEnrollment.ok) return emailOtpEnrollment;
      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      const requestedSessionPolicy = request.ed25519.sessionPolicy;
      if (requestedSessionPolicy) {
        const sessionKind = String(request.ed25519.sessionKind || 'jwt')
          .trim()
          .toLowerCase();
        if (sessionKind !== 'jwt') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ed25519.sessionKind must be jwt',
          };
        }
        const requestedPolicy = requestedSessionPolicy as Record<string, unknown>;
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy: requestedPolicy,
          expectedRelayerKeyId: keygen.relayerKeyId,
          expectedNearAccountId: ed25519.nearAccountId,
          expectedRpId: ceremony.intent.rpId,
        });
        if (policyBindingError) {
          return { ok: false, code: 'invalid_body', message: policyBindingError };
        }
        const session = await measureRegistrationRouteTiming(routeTimings, 'relaySessionMintMs', () =>
          threshold.mintEd25519SessionFromRegistration({
            nearAccountId: ed25519.nearAccountId,
            rpId: ceremony.intent.rpId,
            relayerKeyId: keygen.relayerKeyId,
            sessionPolicy: {
              ...requestedPolicy,
              nearAccountId: ed25519.nearAccountId,
              rpId: ceremony.intent.rpId,
              relayerKeyId: keygen.relayerKeyId,
              ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
            } as any,
          }),
        );
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 session bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ed25519 session bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      const wallet = this.buildWalletRecord({
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        now,
      });
      const authorityPersistence = this.buildRegistrationAuthorityPersistenceRecords({
        authority: ceremony.authority,
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        now,
        ed25519: {
          signerSlot: ed25519.signerSlot,
          publicKey: keygen.publicKey,
          relayerKeyId: keygen.relayerKeyId,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: keygen.recoveryExportCapable,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        },
      });
      const walletSigners = [
        this.buildWalletEd25519SignerRecord({
          walletId: ceremony.intent.walletId,
          rpId: ceremony.intent.rpId,
          nearAccountId: ed25519.nearAccountId,
          signerSlot: ed25519.signerSlot,
          keygen,
          now,
        }),
        ...this.buildWalletEcdsaSignerRecords({
          walletId: ceremony.intent.walletId,
          walletKeys: walletKeyResult.walletKeys,
          now,
        }),
      ];
      const googleEmailOtpActivation = await measureRegistrationRouteTiming(
        routeTimings,
        'relayGoogleEmailOtpActivationPlanMs',
        () =>
          this.prepareGoogleEmailOtpRegistrationActivation({
            authority: ceremony.authority,
            walletId: ceremony.intent.walletId,
          }),
      );
      if (!googleEmailOtpActivation.ok) return googleEmailOtpActivation;
      const persisted = await measureRegistrationRouteTiming(routeTimings, 'relayPersistenceMs', () =>
        this.consumeRegistrationCeremonyAndPersist({
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ...(googleEmailOtpActivation.activation
            ? { googleEmailOtpActivation: googleEmailOtpActivation.activation }
            : {}),
          records: {
            webAuthnAuthenticators: authorityPersistence.webAuthnAuthenticators,
            credentialBindings: authorityPersistence.credentialBindings,
            wallet,
            walletAuthMethods: authorityPersistence.walletAuthMethods,
            walletSigners,
            ...(emailOtpEnrollment.persistence
              ? { emailOtpEnrollment: emailOtpEnrollment.persistence }
              : {}),
          },
        }),
      );
      if (!persisted.ok) return persisted;

      const response: Extract<WalletRegistrationFinalizeResponse, { ok: true }> = {
        ok: true,
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        registrationDiagnostics: finalizeDiagnostics(),
        ed25519: {
          nearAccountId: ed25519.nearAccountId,
          publicKey: keygen.publicKey,
          relayerKeyId: keygen.relayerKeyId,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: keygen.recoveryExportCapable,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
        ecdsa: {
          walletKeys: walletKeyResult.walletKeys,
        },
      };
      await measureRegistrationRouteTiming(
        routeTimings,
        'registrationFinalizeReplayCacheMs',
        () =>
          this.cacheGoogleEmailOtpRegistrationFinalizeReplay({
            authority: ceremony.authority,
            registrationCeremonyId: ceremony.registrationCeremonyId,
            idempotencyKey: finalizeIdempotency.idempotencyKey,
            expiresAtMs: ceremony.expiresAtMs,
            response,
          }),
      );
      response.registrationDiagnostics = finalizeDiagnostics();
      return response;
    }
    if (ceremony.intent.signerSelection.mode === 'ecdsa_only') {
      if (!request.ecdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA finalize input' };
      }
      if (ceremony.signerState.kind !== 'ecdsa_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response is required before finalize',
        };
      }
      const bootstrap = ceremony.signerState.responded.bootstrap;
      const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
      if (expectedKeyHandles.some((keyHandle) => keyHandle !== bootstrap.keyHandle)) {
        return {
          ok: false,
          code: 'key_handle_mismatch',
          message: 'ECDSA finalize expected key handle mismatch',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const verifiedEcdsaKey = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationEcdsaBootstrapVerifyMs',
        () =>
          this.verifyEcdsaRegistrationBootstrapPersisted({
            threshold,
            bootstrap,
          }),
      );
      if (!verifiedEcdsaKey.ok) return verifiedEcdsaKey;
      const walletKeyResult = buildEcdsaWalletKeysFromBootstrap({
        bootstrap,
        chainTargets: ceremony.signerState.chainTargets,
        errorContext: 'ECDSA registration finalize',
      });
      if (!walletKeyResult.ok) return walletKeyResult;
      const walletKeys = walletKeyResult.walletKeys;
      const now = Date.now();
      const emailOtpEnrollment = await measureRegistrationRouteTiming(
        routeTimings,
        'registrationEmailOtpEnrollmentPlanMs',
        () =>
          this.emailOtpEnrollmentPersistenceForRegistrationFinalize({
            authority: ceremony.authority,
            request,
            walletId: ceremony.intent.walletId,
            orgId: ceremony.orgId,
            nowMs: now,
          }),
      );
      if (!emailOtpEnrollment.ok) return emailOtpEnrollment;
      const wallet = this.buildWalletRecord({
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        now,
      });
      const authorityPersistence = this.buildRegistrationAuthorityPersistenceRecords({
        authority: ceremony.authority,
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        now,
      });
      const walletSigners = this.buildWalletEcdsaSignerRecords({
        walletId: ceremony.intent.walletId,
        walletKeys,
        now,
      });
      const googleEmailOtpActivation = await measureRegistrationRouteTiming(
        routeTimings,
        'relayGoogleEmailOtpActivationPlanMs',
        () =>
          this.prepareGoogleEmailOtpRegistrationActivation({
            authority: ceremony.authority,
            walletId: ceremony.intent.walletId,
          }),
      );
      if (!googleEmailOtpActivation.ok) return googleEmailOtpActivation;
      const persisted = await measureRegistrationRouteTiming(routeTimings, 'relayPersistenceMs', () =>
        this.consumeRegistrationCeremonyAndPersist({
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ...(googleEmailOtpActivation.activation
            ? { googleEmailOtpActivation: googleEmailOtpActivation.activation }
            : {}),
          records: {
            webAuthnAuthenticators: authorityPersistence.webAuthnAuthenticators,
            credentialBindings: authorityPersistence.credentialBindings,
            wallet,
            walletAuthMethods: authorityPersistence.walletAuthMethods,
            walletSigners,
            ...(emailOtpEnrollment.persistence
              ? { emailOtpEnrollment: emailOtpEnrollment.persistence }
              : {}),
          },
        }),
      );
      if (!persisted.ok) return persisted;
      const response: Extract<WalletRegistrationFinalizeResponse, { ok: true }> = {
        ok: true,
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        registrationDiagnostics: finalizeDiagnostics(),
        ecdsa: {
          walletKeys,
        },
      };
      await measureRegistrationRouteTiming(
        routeTimings,
        'registrationFinalizeReplayCacheMs',
        () =>
          this.cacheGoogleEmailOtpRegistrationFinalizeReplay({
            authority: ceremony.authority,
            registrationCeremonyId: ceremony.registrationCeremonyId,
            idempotencyKey: finalizeIdempotency.idempotencyKey,
            expiresAtMs: ceremony.expiresAtMs,
            response,
          }),
      );
      response.registrationDiagnostics = finalizeDiagnostics();
      return response;
    }
    if (!request.ed25519) {
      return { ok: false, code: 'invalid_body', message: 'missing Ed25519 finalize input' };
    }
    if (ceremony.signerState.kind !== 'ed25519_responded') {
      return {
        ok: false,
        code: 'invalid_state',
        message: 'Ed25519 HSS response is required before finalize',
      };
    }
    if (ceremony.intent.signerSelection.mode !== 'ed25519_only') {
      return { ok: false, code: 'invalid_body', message: 'Ed25519 finalize scope mismatch' };
    }
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold signing is not configured on this server',
      };
    }
    const ed25519 = ceremony.intent.signerSelection.ed25519;
    const ed25519SignerState = ceremony.signerState;
    const ed25519FinalizeRequest = request.ed25519;
    const finalized = await measureRegistrationRouteTiming(
      routeTimings,
      'registrationHssFinalizeMs',
      () =>
        threshold.ed25519Hss.finalizeForRegistration({
          orgId: ceremony.orgId,
          request: {
            new_account_id: ed25519.nearAccountId,
            rp_id: ceremony.intent.rpId,
            ceremonyHandle: ed25519SignerState.ceremonyHandle,
            evaluationResult: ed25519FinalizeRequest.evaluationResult,
          },
        }),
    );
    if (!finalized.ok) {
      return {
        ok: false,
        code: finalized.code || 'hss_finalize_failed',
        message: finalized.message || 'Ed25519 HSS finalize failed',
      };
    }
    if (finalized.finalizeReportTimings) {
      pushRegistrationHssFinalizeTimingEntries(routeTimings, finalized.finalizeReportTimings);
    }

    if (ed25519.createNearAccount) {
      const created = await measureRegistrationRouteTiming(
        routeTimings,
        'nearAccountCreateMs',
        () =>
          this.createAccount({
            accountId: ed25519.nearAccountId,
            publicKey: finalized.publicKey,
          }),
      );
      if (!created.success) {
        return {
          ok: false,
          code: 'account_creation_failed',
          message: created.error || created.message || 'Failed to create NEAR account',
        };
      }
    }

    const schemeAny = threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
    if (!schemeAny || schemeAny.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
      return {
        ok: false,
        code: 'not_configured',
        message: `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled`,
      };
    }
    const keygen = await measureRegistrationRouteTiming(
      routeTimings,
      'registrationKeygenMs',
      () =>
        schemeAny.registration.keygenFromRegistrationMaterial({
          nearAccountId: ed25519.nearAccountId,
          rpId: ceremony.intent.rpId,
          keyVersion: ed25519.keyVersion,
          recoveryExportCapable: true,
          publicKey: finalized.publicKey,
          relayerKeyId: finalized.relayerKeyId,
        }),
    );
    if (!keygen.ok) {
      return {
        ok: false,
        code: keygen.code || 'keygen_failed',
        message: keygen.message || 'Ed25519 registration keygen failed',
      };
    }

    const now = Date.now();
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
      ceremony.intent.runtimePolicyScope,
    );
    const emailOtpEnrollment = await measureRegistrationRouteTiming(
      routeTimings,
      'registrationEmailOtpEnrollmentPlanMs',
      () =>
        this.emailOtpEnrollmentPersistenceForRegistrationFinalize({
          authority: ceremony.authority,
          request,
          walletId: ceremony.intent.walletId,
          orgId: ceremony.orgId,
          nowMs: now,
        }),
    );
    if (!emailOtpEnrollment.ok) return emailOtpEnrollment;
    let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
    const requestedSessionPolicy = request.ed25519.sessionPolicy;
    if (requestedSessionPolicy) {
      const sessionKind = String(request.ed25519.sessionKind || 'jwt')
        .trim()
        .toLowerCase();
      if (sessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ed25519.sessionKind must be jwt',
        };
      }
      const requestedPolicy = requestedSessionPolicy as Record<string, unknown>;
      const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
        requestedSessionPolicy: requestedPolicy,
        expectedRelayerKeyId: keygen.relayerKeyId,
        expectedNearAccountId: ed25519.nearAccountId,
        expectedRpId: ceremony.intent.rpId,
      });
      if (policyBindingError) {
        return { ok: false, code: 'invalid_body', message: policyBindingError };
      }
      const session = await measureRegistrationRouteTiming(routeTimings, 'relaySessionMintMs', () =>
        threshold.mintEd25519SessionFromRegistration({
          nearAccountId: ed25519.nearAccountId,
          rpId: ceremony.intent.rpId,
          relayerKeyId: keygen.relayerKeyId,
          sessionPolicy: {
            ...requestedPolicy,
            nearAccountId: ed25519.nearAccountId,
            rpId: ceremony.intent.rpId,
            relayerKeyId: keygen.relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        }),
      );
      if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
        return {
          ok: false,
          code: session.code || 'internal',
          message: session.message || 'threshold-ed25519 session bootstrap failed',
        };
      }
      const normalizedSession = toThresholdEd25519BootstrapSession(session);
      if (!normalizedSession) {
        return {
          ok: false,
          code: 'internal',
          message: 'threshold-ed25519 session bootstrap failed',
        };
      }
      thresholdEd25519Session = normalizedSession;
    }

    const wallet = this.buildWalletRecord({
      walletId: ceremony.intent.walletId,
      rpId: ceremony.intent.rpId,
      now,
    });
    const authorityPersistence = this.buildRegistrationAuthorityPersistenceRecords({
      authority: ceremony.authority,
      walletId: ceremony.intent.walletId,
      rpId: ceremony.intent.rpId,
      now,
      ed25519: {
        signerSlot: ed25519.signerSlot,
        publicKey: keygen.publicKey,
        relayerKeyId: keygen.relayerKeyId,
        keyVersion: keygen.keyVersion,
        recoveryExportCapable: keygen.recoveryExportCapable,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      },
    });
    const walletSigners = [
      this.buildWalletEd25519SignerRecord({
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        nearAccountId: ed25519.nearAccountId,
        signerSlot: ed25519.signerSlot,
        keygen,
        now,
      }),
    ];
    const googleEmailOtpActivation = await measureRegistrationRouteTiming(
      routeTimings,
      'relayGoogleEmailOtpActivationPlanMs',
      () =>
        this.prepareGoogleEmailOtpRegistrationActivation({
          authority: ceremony.authority,
          walletId: ceremony.intent.walletId,
        }),
    );
    if (!googleEmailOtpActivation.ok) return googleEmailOtpActivation;
    const persisted = await measureRegistrationRouteTiming(routeTimings, 'relayPersistenceMs', () =>
      this.consumeRegistrationCeremonyAndPersist({
        registrationCeremonyId: ceremony.registrationCeremonyId,
        ...(googleEmailOtpActivation.activation
          ? { googleEmailOtpActivation: googleEmailOtpActivation.activation }
          : {}),
        records: {
          webAuthnAuthenticators: authorityPersistence.webAuthnAuthenticators,
          credentialBindings: authorityPersistence.credentialBindings,
          wallet,
          walletAuthMethods: authorityPersistence.walletAuthMethods,
          walletSigners,
          ...(emailOtpEnrollment.persistence
            ? { emailOtpEnrollment: emailOtpEnrollment.persistence }
            : {}),
        },
      }),
    );
    if (!persisted.ok) return persisted;

    const response: Extract<WalletRegistrationFinalizeResponse, { ok: true }> = {
      ok: true,
      walletId: ceremony.intent.walletId,
      rpId: ceremony.intent.rpId,
      registrationDiagnostics: finalizeDiagnostics(),
      ed25519: {
        nearAccountId: ed25519.nearAccountId,
        publicKey: keygen.publicKey,
        relayerKeyId: keygen.relayerKeyId,
        keyVersion: keygen.keyVersion,
        recoveryExportCapable: keygen.recoveryExportCapable,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
      },
    };
    await measureRegistrationRouteTiming(
      routeTimings,
      'registrationFinalizeReplayCacheMs',
      () =>
        this.cacheGoogleEmailOtpRegistrationFinalizeReplay({
          authority: ceremony.authority,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          idempotencyKey: finalizeIdempotency.idempotencyKey,
          expiresAtMs: ceremony.expiresAtMs,
          response,
        }),
    );
    response.registrationDiagnostics = finalizeDiagnostics();
    return response;
  }

  private async verifyNearAccountOwnershipProofForAddSigner(input: {
    walletId: WalletId;
    rpId: string;
    nearAccountId: string;
    proof: NearAccountOwnershipProofV1;
  }): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const { proof } = input;
    const message = proof.message;
    const publicKey = ensureEd25519Prefix(message.publicKey);
    if (
      String(message.walletId) !== String(input.walletId) ||
      message.rpId !== input.rpId ||
      message.nearAccountId !== input.nearAccountId
    ) {
      return {
        ok: false,
        code: 'invalid_account_ownership_proof',
        message: 'NEAR account ownership proof does not match the add-signer intent',
      };
    }
    const nowMs = Date.now();
    if (message.expiresAtMs <= nowMs || message.issuedAtMs > nowMs + 60_000) {
      return {
        ok: false,
        code: 'invalid_account_ownership_proof',
        message: 'NEAR account ownership proof is expired or not yet valid',
      };
    }
    try {
      const nonceBytes = base64UrlDecode(message.nonceB64u);
      if (nonceBytes.length < 16) {
        return {
          ok: false,
          code: 'invalid_account_ownership_proof',
          message: 'NEAR account ownership proof nonce is invalid',
        };
      }
    } catch {
      return {
        ok: false,
        code: 'invalid_account_ownership_proof',
        message: 'NEAR account ownership proof nonce is invalid',
      };
    }
    const publicKeyBytes = decodeNearEd25519PublicKey(publicKey);
    if (!publicKeyBytes) {
      return {
        ok: false,
        code: 'invalid_account_ownership_proof',
        message: 'NEAR account ownership proof public key is invalid',
      };
    }
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = base64UrlDecode(proof.signatureB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_account_ownership_proof',
        message: 'NEAR account ownership proof signature is invalid',
      };
    }
    if (signatureBytes.length !== 64) {
      return {
        ok: false,
        code: 'invalid_account_ownership_proof',
        message: 'NEAR account ownership proof signature is invalid',
      };
    }
    try {
      await this.nearClient.viewAccessKey(input.nearAccountId, publicKey, { finality: 'final' });
    } catch {
      return {
        ok: false,
        code: 'account_key_not_found',
        message: 'NEAR account ownership proof key is not an active access key',
      };
    }
    const verified = await verifyEd25519SignaturePortable({
      publicKeyBytes,
      signatureBytes,
      messageBytes: new TextEncoder().encode(serializeNearAccountOwnershipProofMessageV1(message)),
    });
    if (!verified) {
      return {
        ok: false,
        code: 'invalid_account_ownership_proof',
        message: 'NEAR account ownership proof signature verification failed',
      };
    }
    return { ok: true };
  }

  async startWalletAddSigner(
    request: WalletAddSignerStartRequest,
  ): Promise<WalletAddSignerStartResponse> {
    try {
      const walletId = walletIdFromString(String(request.walletId || '').trim());
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const grant = addSignerIntentGrantFromString(
        String(request.addSignerIntentGrant || '').trim(),
      );
      if (!grant) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant is required' };
      }
      const ceremonyStore = this.getRegistrationCeremonyStore();
      const intentPreview = await ceremonyStore.getAddSignerIntent(grant);
      if (!intentPreview) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
      }
      if (String(request.intent.walletId || '').trim() !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'add-signer walletId mismatch' };
      }
      const digestB64u = toOptionalTrimmedString(request.addSignerIntentDigestB64u);
      const requestDigest = await computeAddSignerIntentDigestB64u(request.intent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'add-signer intent digest mismatch' };
      }
      if (requestDigest !== intentPreview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'add-signer intent mismatch' };
      }
      const previewSelection = intentPreview.intent.signerSelection;
      if (
        previewSelection.mode === 'ed25519' &&
        previewSelection.ed25519.mode === 'link_existing_near_account'
      ) {
        const proofVerified = await this.verifyNearAccountOwnershipProofForAddSigner({
          walletId,
          rpId: intentPreview.intent.rpId,
          nearAccountId: previewSelection.ed25519.nearAccountId,
          proof: previewSelection.ed25519.accountOwnershipProof,
        });
        if (!proofVerified.ok) return proofVerified;
      }

      const storedIntent = await ceremonyStore.takeAddSignerIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'add-signer intent grant expired' };
      }
      let addSignerAuth:
        | { kind: 'webauthn_assertion'; credentialIdB64u: string }
        | { kind: 'app_session' };
      if (request.auth.kind === 'webauthn_assertion') {
        const credentialIdB64u = credentialIdB64uFromAuthenticationCredential(
          request.auth.credential,
        );
        if (!credentialIdB64u) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'add-signer WebAuthn credential id is required',
          };
        }
        addSignerAuth = { kind: 'webauthn_assertion', credentialIdB64u };
      } else {
        addSignerAuth = { kind: 'app_session' };
      }
      const selection = storedIntent.intent.signerSelection;
      const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
        storedIntent.intent.runtimePolicyScope,
      );
      const signingRootId = runtimePolicyScope
        ? storedIntent.signingRootId || deriveSigningRootId(runtimePolicyScope)
        : storedIntent.signingRootId;
      const signingRootVersion =
        storedIntent.signingRootVersion || runtimePolicyScope?.signingRootVersion || 'default';
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }

      const addSignerCeremonyId = `wasc_${randomBase64Url(24)}`;
      if (selection.mode === 'ed25519') {
        const ed25519 = selection.ed25519;
        const prepared = await threshold.ed25519Hss.prepareForRegistration({
          orgId: storedIntent.orgId,
          ...(signingRootId ? { signingRootId } : {}),
          ...(signingRootVersion ? { signingRootVersion } : {}),
          request: {
            new_account_id: ed25519.nearAccountId,
            rp_id: storedIntent.intent.rpId,
            context: {
              signingRootId: signingRootId || '',
              nearAccountId: ed25519.nearAccountId,
              keyPurpose: ed25519.keyPurpose,
              keyVersion: ed25519.keyVersion,
              participantIds: ed25519.participantIds,
              derivationVersion: ed25519.derivationVersion,
            },
          },
        });
        if (!prepared.ok) {
          return {
            ok: false,
            code: prepared.code || 'hss_prepare_failed',
            message: prepared.message || 'Ed25519 add-signer HSS prepare failed',
          };
        }
        const responseEd25519 = {
          ceremonyHandle: prepared.ceremonyHandle,
          preparedSession: prepared.preparedSession,
          clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
        };
        await this.getRegistrationCeremonyStore().putAddSignerCeremony({
          addSignerCeremonyId,
          intent: storedIntent.intent,
          digestB64u,
          orgId: storedIntent.orgId,
          ...(signingRootId ? { signingRootId } : {}),
          ...(signingRootVersion ? { signingRootVersion } : {}),
          expiresAtMs: Date.now() + 10 * 60_000,
          auth: addSignerAuth,
          signerState: {
            kind: 'ed25519_add_signer_prepared',
            ...responseEd25519,
          },
        });
        return {
          ok: true,
          addSignerCeremonyId,
          intent: storedIntent.intent,
          ed25519: responseEd25519,
        };
      }

      if (!runtimePolicyScope || !signingRootId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer requires a runtime policy scope',
        };
      }
      const chainTargets = selection.ecdsa.chainTargets.map((target) =>
        thresholdEcdsaChainTargetFromValue(target),
      );
      if (chainTargets.some((target) => !target)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA add-signer contains an invalid chain target',
        };
      }
      const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
        walletId,
        rpId: storedIntent.intent.rpId,
        signingRootId,
        signingRootVersion,
      });
      const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
        walletId,
        rpId: storedIntent.intent.rpId,
      });
      const responseEcdsa = {
        kind: 'evm_family_ecdsa_keygen' as const,
        chainTargets: chainTargets as ThresholdEcdsaChainTarget[],
        prepare: {
          formatVersion: 'ecdsa-hss-role-local' as const,
          walletId,
          rpId: storedIntent.intent.rpId,
          ecdsaThresholdKeyId,
          signingRootId,
          signingRootVersion,
          keyScope: 'evm-family' as const,
          relayerKeyId,
          requestId: `${addSignerCeremonyId}:ecdsa`,
          sessionId: `tehss_${randomBase64Url(24)}`,
          walletSigningSessionId: `wss_${randomBase64Url(24)}`,
          ttlMs: 10 * 60_000,
          remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
          participantIds: selection.ecdsa.participantIds,
          runtimePolicyScope,
        },
      };
      await this.getRegistrationCeremonyStore().putAddSignerCeremony({
        addSignerCeremonyId,
        intent: storedIntent.intent,
        digestB64u,
        orgId: runtimePolicyScope.orgId,
        signingRootId,
        signingRootVersion,
        expiresAtMs: Date.now() + 10 * 60_000,
        auth: addSignerAuth,
        signerState: {
          kind: 'ecdsa_add_signer_prepared',
          hssKind: responseEcdsa.kind,
          chainTargets: responseEcdsa.chainTargets,
          prepare: responseEcdsa.prepare,
        },
      });
      return {
        ok: true,
        addSignerCeremonyId,
        intent: storedIntent.intent,
        ecdsa: responseEcdsa,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-signer ceremony',
      };
    }
  }

  private async verifyAddAuthMethodAuthority(input: {
    orgId: string;
    authority: WalletAddAuthMethodStartRequest['authority'];
    expectedDigestB64u: string;
    expectedOrigin: string;
    intent: AddAuthMethodIntentV1;
    walletAuthMethodStore: WalletAuthMethodStore;
  }): Promise<
    | {
        ok: true;
        authority: RegistrationAuthority;
      }
    | {
        ok: false;
        code: string;
        message: string;
      }
  > {
    switch (input.authority.kind) {
      case 'passkey': {
        const verified = await this.verifyRegistrationCredentialForIntent({
          webauthnRegistration: input.authority.webauthnRegistration,
          expectedChallenge: input.expectedDigestB64u,
          expectedOrigin: input.expectedOrigin,
          rpId: input.intent.rpId,
        });
        if (!verified.ok) return verified;
        const duplicateCredential = await input.walletAuthMethodStore.getPasskey({
          rpId: input.intent.rpId,
          credentialIdB64u: verified.credential.credentialIdB64u,
        });
        if (duplicateCredential) {
          return {
            ok: false,
            code: 'duplicate_auth_method',
            message: 'Passkey credential is already registered',
          };
        }
        return {
          ok: true,
          authority: {
            kind: 'passkey',
            walletId: input.intent.walletId,
            rpId: input.intent.rpId,
            credentialIdB64u: verified.credential.credentialIdB64u,
            credentialPublicKeyB64u: verified.credential.credentialPublicKeyB64u,
            counter: verified.credential.counter,
            registrationIntentDigestB64u: input.expectedDigestB64u,
          },
        };
      }
      case 'email_otp': {
        const proof = input.authority.emailOtpRegistrationProof;
        if (proof.proofKind !== 'otp_challenge') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Email OTP add-auth-method requires an OTP challenge proof',
          };
        }
        if (proof.registrationIntentDigestB64u !== input.expectedDigestB64u) {
          return {
            ok: false,
            code: 'registration_intent_digest_mismatch',
            message: 'Email OTP registration proof is not bound to this add-auth-method intent',
          };
        }
        if (input.intent.authMethod.kind !== 'email_otp') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Email OTP add-auth-method authority requires an Email OTP intent',
          };
        }
        if (proof.email !== input.intent.authMethod.email.toLowerCase()) {
          return {
            ok: false,
            code: 'email_mismatch',
            message: 'Email OTP registration proof email does not match the intent',
          };
        }
        const proofResult = parseDirectEmailOtpRegistrationChallengeProof({
          providerSubject: proof.providerSubject,
          proofEmail: proof.email,
          challengeId: proof.challengeId,
          finalWalletId: input.intent.walletId,
          orgId: input.orgId,
          appSessionVersion: proof.appSessionVersion,
        });
        if (!proofResult.ok) return proofResult;
        const verified = await this.verifyEmailOtpChallengeCode({
          challengeSubjectId: proofResult.proof.challengeSubjectId,
          registrationChallengeProof: proofResult.proof,
          allowRegistrationChallengeReroll: false,
          walletId: input.intent.walletId,
          orgId: input.orgId,
          challengeId: proofResult.proof.challengeId,
          otpCode: proof.otpCode,
          otpChannel: proof.otpChannel,
          sessionHash: input.expectedDigestB64u,
          appSessionVersion: proof.appSessionVersion,
          expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
          expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
        });
        if (!verified.ok) return verified;
        if (verified.intent !== 'registration') {
          return {
            ok: false,
            code: 'challenge_purpose_mismatch',
            message: 'Email OTP add-auth-method verification returned a non-registration proof',
          };
        }
        const challengeProof = verified.registrationChallengeProof;
        const verifiedEmail = toOptionalTrimmedString(challengeProof.challengeEmail)?.toLowerCase();
        if (verifiedEmail !== proof.email) {
          return {
            ok: false,
            code: 'email_mismatch',
            message: 'Verified Email OTP address does not match the registration proof',
          };
        }
        const emailHashHex = bytesToHex(await sha256BytesUtf8(challengeProof.challengeEmail));
        const duplicateEmailOtp = await input.walletAuthMethodStore.getEmailOtp({
          walletId: input.intent.walletId,
          rpId: input.intent.rpId,
          emailHashHex,
        });
        if (duplicateEmailOtp && duplicateEmailOtp.status === 'active') {
          return {
            ok: false,
            code: 'duplicate_auth_method',
            message: 'Email OTP auth method is already registered',
          };
        }
        return {
          ok: true,
          authority: {
            kind: 'email_otp',
            proofKind: 'otp_challenge',
            walletId: challengeProof.finalWalletId,
            rpId: input.intent.rpId,
            providerSubject: challengeProof.providerSubject,
            challengeSubjectId: challengeProof.challengeSubjectId,
            email: challengeProof.challengeEmail,
            emailHashHex,
            challengeId: challengeProof.challengeId,
            registrationAuthorityId: challengeProof.challengeId,
            originalWalletId: challengeProof.originalWalletId,
            finalWalletId: challengeProof.finalWalletId,
            orgId: challengeProof.orgId,
            appSessionVersion: challengeProof.appSessionVersion,
            challengePurpose: challengeProof.purpose.kind,
            registrationIntentDigestB64u: input.expectedDigestB64u,
          },
        };
      }
    }
    return assertNever(input.authority);
  }

  private async findWalletAuthMethodRecordForTarget(input: {
    walletId: WalletId;
    rpId: string;
    target: WalletRevokeAuthMethodRequest['target'];
    walletAuthMethodStore: WalletAuthMethodStore;
  }): Promise<WalletAuthMethodRecord | null> {
    switch (input.target.kind) {
      case 'passkey': {
        const record = await input.walletAuthMethodStore.getPasskey({
          rpId: input.rpId,
          credentialIdB64u: input.target.credentialIdB64u,
        });
        if (!record || record.kind !== 'passkey' || record.walletId !== input.walletId) {
          return null;
        }
        return record;
      }
      case 'email_otp': {
        const emailHashHex = bytesToHex(await sha256BytesUtf8(input.target.email));
        const record = await input.walletAuthMethodStore.getEmailOtp({
          walletId: input.walletId,
          rpId: input.rpId,
          emailHashHex,
        });
        if (!record || record.kind !== 'email_otp') {
          return null;
        }
        return record;
      }
    }
    return assertNever(input.target);
  }

  async startWalletAddAuthMethod(
    request: WalletAddAuthMethodStartRequest,
  ): Promise<WalletAddAuthMethodStartResponse> {
    try {
      const walletId = walletIdFromString(String(request.walletId || '').trim());
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const grant = addAuthMethodIntentGrantFromString(
        String(request.addAuthMethodIntentGrant || '').trim(),
      );
      if (!grant) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant is required',
        };
      }
      const ceremonyStore = this.getRegistrationCeremonyStore();
      const intentPreview = await ceremonyStore.getAddAuthMethodIntent(grant);
      if (!intentPreview) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant expired',
        };
      }
      if (String(request.intent.walletId || '').trim() !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'add-auth-method walletId mismatch' };
      }
      const digestB64u = toOptionalTrimmedString(request.addAuthMethodIntentDigestB64u);
      const requestDigest = await computeAddAuthMethodIntentDigestB64u(request.intent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method intent digest mismatch',
        };
      }
      if (requestDigest !== intentPreview.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'add-auth-method intent mismatch' };
      }

      const walletAuthMethodStore = this.getWalletAuthMethodStore();
      const walletMethods = await walletAuthMethodStore.listForWallet({
        walletId,
        rpId: intentPreview.intent.rpId,
      });
      const activeWalletMethods = walletMethods.filter((record) => record.status === 'active');
      if (activeWalletMethods.length === 0) {
        return {
          ok: false,
          code: 'not_found',
          message: 'wallet has no active auth methods',
        };
      }
      let authorizationCredentialId: string | null = null;
      if (request.auth.kind === 'webauthn_assertion') {
        authorizationCredentialId = credentialIdB64uFromAuthenticationCredential(
          request.auth.credential,
        );
        if (!authorizationCredentialId) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'add-auth-method WebAuthn credential id is required',
          };
        }
        const authorizationMethod = await walletAuthMethodStore.getPasskey({
          rpId: intentPreview.intent.rpId,
          credentialIdB64u: authorizationCredentialId,
        });
        if (
          !authorizationMethod ||
          authorizationMethod.kind !== 'passkey' ||
          authorizationMethod.walletId !== walletId ||
          authorizationMethod.status !== 'active'
        ) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'WebAuthn authorization credential is not active for this wallet',
          };
        }
      }

      const storedIntent = await ceremonyStore.takeAddAuthMethodIntent(grant);
      if (!storedIntent) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant expired',
        };
      }
      const storedExpectedOrigin = toOptionalTrimmedString(storedIntent.expectedOrigin);
      if (request.authority.kind === 'passkey' && !storedExpectedOrigin) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const authority = await this.verifyAddAuthMethodAuthority({
        orgId: storedIntent.orgId,
        authority: request.authority,
        expectedDigestB64u: storedIntent.digestB64u,
        expectedOrigin: storedExpectedOrigin || '',
        intent: storedIntent.intent,
        walletAuthMethodStore,
      });
      if (!authority.ok) return authority;

      const addAuthMethodCeremonyId = `wauthc_${randomBase64Url(24)}`;
      const storedAuth =
        request.auth.kind === 'webauthn_assertion'
          ? {
              kind: 'webauthn_assertion' as const,
              credentialIdB64u: authorizationCredentialId || '',
            }
          : { kind: 'app_session' as const };
      if (storedAuth.kind === 'webauthn_assertion' && !storedAuth.credentialIdB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method WebAuthn credential id is required',
        };
      }
      await ceremonyStore.putAddAuthMethodCeremony({
        addAuthMethodCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        orgId: storedIntent.orgId,
        expiresAtMs: Date.now() + 10 * 60_000,
        auth: storedAuth,
        authority: authority.authority,
        ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
      });
      return {
        ok: true,
        addAuthMethodCeremonyId,
        intent: storedIntent.intent,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-auth-method ceremony',
      };
    }
  }

  async revokeWalletAuthMethod(
    request: WalletRevokeAuthMethodRequest,
  ): Promise<WalletRevokeAuthMethodResponse> {
    try {
      const walletId = walletIdFromString(String(request.walletId || '').trim());
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const rpId = toOptionalTrimmedString(request.rpId);
      if (!rpId) {
        return { ok: false, code: 'invalid_body', message: 'rpId is required' };
      }
      if (request.auth.kind === 'app_session') {
        if (request.auth.policy.walletId !== walletId) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'auth-method revoke policy wallet mismatch',
          };
        }
        if (
          request.auth.policy.target.kind !== request.target.kind ||
          (request.target.kind === 'passkey'
            ? request.auth.policy.target.credentialIdB64u !== request.target.credentialIdB64u
            : request.auth.policy.target.email !== request.target.email)
        ) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'auth-method revoke policy target mismatch',
          };
        }
        if (request.auth.policy.expiresAtMs <= Date.now()) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'auth-method revoke policy is expired',
          };
        }
      }
      const walletAuthMethodStore = this.getWalletAuthMethodStore();
      const walletMethods = await walletAuthMethodStore.listForWallet({ walletId, rpId });
      const activeWalletMethods = walletMethods.filter((record) => record.status === 'active');
      if (activeWalletMethods.length === 0) {
        return { ok: false, code: 'not_found', message: 'wallet has no active auth methods' };
      }
      if (request.auth.kind === 'webauthn_assertion') {
        const authorizationCredentialId = credentialIdB64uFromAuthenticationCredential(
          request.auth.credential,
        );
        if (!authorizationCredentialId) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'auth-method revoke WebAuthn credential id is required',
          };
        }
        const authorizationMethod = await walletAuthMethodStore.getPasskey({
          rpId,
          credentialIdB64u: authorizationCredentialId,
        });
        if (
          !authorizationMethod ||
          authorizationMethod.kind !== 'passkey' ||
          authorizationMethod.walletId !== walletId ||
          authorizationMethod.status !== 'active'
        ) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'WebAuthn authorization credential is not active for this wallet',
          };
        }
      }

      const targetRecord = await this.findWalletAuthMethodRecordForTarget({
        rpId,
        target: request.target,
        walletAuthMethodStore,
        walletId,
      });
      if (!targetRecord) {
        return { ok: false, code: 'not_found', message: 'wallet auth method not found' };
      }
      if (targetRecord.status !== 'active') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet auth method is already revoked',
        };
      }
      if (activeWalletMethods.length <= 1) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet must retain at least one active auth method',
        };
      }
      await walletAuthMethodStore.put({
        ...targetRecord,
        status: 'revoked',
        updatedAtMs: Date.now(),
      });
      return {
        ok: true,
        walletId,
        rpId,
        authMethod: {
          kind: targetRecord.kind,
          status: 'revoked',
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to revoke wallet auth method',
      };
    }
  }

  async finalizeWalletAddAuthMethod(
    request: WalletAddAuthMethodFinalizeRequest,
  ): Promise<WalletAddAuthMethodFinalizeResponse> {
    const ceremony = await this.getRegistrationCeremonyStore().getAddAuthMethodCeremony(
      request.addAuthMethodCeremonyId,
    );
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'add-auth-method ceremony not found' };
    }

    if (ceremony.authority.kind === 'passkey') {
      const duplicateCredential = await this.getWalletAuthMethodStore().getPasskey({
        rpId: ceremony.authority.rpId,
        credentialIdB64u: ceremony.authority.credentialIdB64u,
      });
      if (duplicateCredential) {
        return {
          ok: false,
          code: 'duplicate_auth_method',
          message: 'Passkey credential is already registered',
        };
      }
    } else {
      const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtp({
        walletId: ceremony.authority.walletId,
        rpId: ceremony.authority.rpId,
        emailHashHex: ceremony.authority.emailHashHex,
      });
      if (duplicateEmailOtp && duplicateEmailOtp.status === 'active') {
        return {
          ok: false,
          code: 'duplicate_auth_method',
          message: 'Email OTP auth method is already registered',
        };
      }
    }

    const persisted = await this.consumeAddAuthMethodCeremonyAndPersist({
      addAuthMethodCeremonyId: ceremony.addAuthMethodCeremonyId,
      records: this.buildAddAuthMethodPersistenceRecords({
        authority: ceremony.authority,
        now: Date.now(),
      }),
    });
    if (!persisted) {
      return { ok: false, code: 'not_found', message: 'add-auth-method ceremony not found' };
    }
    return {
      ok: true,
      walletId: ceremony.intent.walletId,
      rpId: ceremony.intent.rpId,
      authMethod: {
        kind: ceremony.authority.kind,
        status: 'active',
      },
    };
  }

  async respondWalletAddSignerHss(
    request: WalletAddSignerHssRespondRequest,
  ): Promise<WalletAddSignerHssRespondResponse> {
    const ceremony = await this.getRegistrationCeremonyStore().getAddSignerCeremony(
      request.addSignerCeremonyId,
    );
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
    }
    if (ceremony.intent.signerSelection.mode === 'ed25519') {
      if (!request.ed25519) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'missing Ed25519 add-signer HSS response',
        };
      }
      if (ceremony.signerState.kind !== 'ed25519_add_signer_prepared') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 add-signer HSS response already recorded',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const ed25519 = ceremony.intent.signerSelection.ed25519;
      const responded = await threshold.ed25519Hss.respondForRegistration({
        orgId: ceremony.orgId,
        request: {
          new_account_id: ed25519.nearAccountId,
          rp_id: ceremony.intent.rpId,
          ceremonyHandle: ceremony.signerState.ceremonyHandle,
          clientRequest: request.ed25519.clientRequest,
        },
      });
      if (!responded.ok) {
        return {
          ok: false,
          code: responded.code || 'hss_respond_failed',
          message: responded.message || 'Ed25519 add-signer HSS respond failed',
        };
      }
      const respondedEd25519 = {
        contextBindingB64u: responded.contextBindingB64u,
        serverInputDeliveryB64u: responded.serverInputDeliveryB64u,
      };
      await this.getRegistrationCeremonyStore().updateAddSignerCeremony({
        ...ceremony,
        signerState: {
          ...ceremony.signerState,
          kind: 'ed25519_add_signer_responded',
          responded: respondedEd25519,
        },
      });
      return {
        ok: true,
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        ed25519: respondedEd25519,
      };
    }
    if (!request.ecdsa) {
      return { ok: false, code: 'invalid_body', message: 'missing ECDSA add-signer HSS response' };
    }
    if (ceremony.signerState.kind !== 'ecdsa_add_signer_prepared') {
      return {
        ok: false,
        code: 'invalid_state',
        message: 'ECDSA add-signer HSS response already recorded',
      };
    }
    const expected = ceremony.signerState.prepare;
    const actual = request.ecdsa.clientBootstrap;
    if (!isMatchingEcdsaClientBootstrap(expected, actual)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ECDSA add-signer bootstrap identity mismatch',
      };
    }
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold signing is not configured on this server',
      };
    }
    const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(actual);
    if (!bootstrap.ok) {
      return {
        ok: false,
        code: bootstrap.code || 'hss_respond_failed',
        message: bootstrap.message || 'ECDSA add-signer HSS bootstrap failed',
      };
    }
    await this.getRegistrationCeremonyStore().updateAddSignerCeremony({
      ...ceremony,
      signerState: {
        ...ceremony.signerState,
        kind: 'ecdsa_add_signer_responded',
        responded: {
          bootstrap: bootstrap.value,
        },
      },
    });
    return {
      ok: true,
      addSignerCeremonyId: ceremony.addSignerCeremonyId,
      ecdsa: {
        bootstrap: bootstrap.value,
      },
    };
  }

  async finalizeWalletAddSigner(
    request: WalletAddSignerFinalizeRequest,
  ): Promise<WalletAddSignerFinalizeResponse> {
    const ceremony = await this.getRegistrationCeremonyStore().getAddSignerCeremony(
      request.addSignerCeremonyId,
    );
    if (!ceremony) {
      return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
    }
    if (ceremony.intent.signerSelection.mode === 'ed25519') {
      if (!request.ed25519) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'missing Ed25519 add-signer finalize input',
        };
      }
      if (ceremony.signerState.kind !== 'ed25519_add_signer_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 add-signer HSS response is required before finalize',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold signing is not configured on this server',
        };
      }
      const ed25519 = ceremony.intent.signerSelection.ed25519;
      const finalized = await threshold.ed25519Hss.finalizeForRegistration({
        orgId: ceremony.orgId,
        request: {
          new_account_id: ed25519.nearAccountId,
          rp_id: ceremony.intent.rpId,
          ceremonyHandle: ceremony.signerState.ceremonyHandle,
          evaluationResult: request.ed25519.evaluationResult,
        },
      });
      if (!finalized.ok) {
        return {
          ok: false,
          code: finalized.code || 'hss_finalize_failed',
          message: finalized.message || 'Ed25519 add-signer HSS finalize failed',
        };
      }

      if (ed25519.mode === 'create_near_account') {
        const created = await this.createAccount({
          accountId: ed25519.nearAccountId,
          publicKey: finalized.publicKey,
        });
        if (!created.success) {
          return {
            ok: false,
            code: 'account_creation_failed',
            message: created.error || created.message || 'Failed to create NEAR account',
          };
        }
      }

      const schemeAny = threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
      if (!schemeAny || schemeAny.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
        return {
          ok: false,
          code: 'not_configured',
          message: `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled`,
        };
      }
      const keygen = await schemeAny.registration.keygenFromRegistrationMaterial({
        nearAccountId: ed25519.nearAccountId,
        rpId: ceremony.intent.rpId,
        keyVersion: ed25519.keyVersion,
        recoveryExportCapable: true,
        publicKey: finalized.publicKey,
        relayerKeyId: finalized.relayerKeyId,
      });
      if (!keygen.ok) {
        return {
          ok: false,
          code: keygen.code || 'keygen_failed',
          message: keygen.message || 'Ed25519 add-signer keygen failed',
        };
      }

      const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
        ceremony.intent.runtimePolicyScope,
      );
      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      const requestedSessionPolicy = request.ed25519.sessionPolicy;
      if (requestedSessionPolicy) {
        const sessionKind = String(request.ed25519.sessionKind || 'jwt')
          .trim()
          .toLowerCase();
        if (sessionKind !== 'jwt') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ed25519.sessionKind must be jwt',
          };
        }
        const requestedPolicy = requestedSessionPolicy as Record<string, unknown>;
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy: requestedPolicy,
          expectedRelayerKeyId: keygen.relayerKeyId,
          expectedNearAccountId: ed25519.nearAccountId,
          expectedRpId: ceremony.intent.rpId,
        });
        if (policyBindingError) {
          return { ok: false, code: 'invalid_body', message: policyBindingError };
        }
        const session = await threshold.mintEd25519SessionFromRegistration({
          nearAccountId: ed25519.nearAccountId,
          rpId: ceremony.intent.rpId,
          relayerKeyId: keygen.relayerKeyId,
          sessionPolicy: {
            ...requestedPolicy,
            nearAccountId: ed25519.nearAccountId,
            rpId: ceremony.intent.rpId,
            relayerKeyId: keygen.relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        });
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 add-signer session bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ed25519 add-signer session bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      const signerWriteNow = Date.now();
      const credentialBindings: WebAuthnCredentialBindingRecord[] = [];
      if (ceremony.auth.kind === 'webauthn_assertion') {
        credentialBindings.push({
          version: 'webauthn_credential_binding_v1',
          rpId: ceremony.intent.rpId,
          credentialIdB64u: ceremony.auth.credentialIdB64u,
          userId: ceremony.intent.walletId,
          signerSlot: ed25519.signerSlot,
          publicKey: keygen.publicKey,
          relayerKeyId: keygen.relayerKeyId,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: keygen.recoveryExportCapable,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          createdAtMs: signerWriteNow,
          updatedAtMs: signerWriteNow,
        });
      }
      const wallet = this.buildWalletRecord({
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        now: signerWriteNow,
      });
      const walletSigners = [
        this.buildWalletEd25519SignerRecord({
          walletId: ceremony.intent.walletId,
          rpId: ceremony.intent.rpId,
          nearAccountId: ed25519.nearAccountId,
          signerSlot: ed25519.signerSlot,
          keygen,
          now: signerWriteNow,
        }),
      ];
      const persisted = await this.consumeAddSignerCeremonyAndPersist({
        addSignerCeremonyId: ceremony.addSignerCeremonyId,
        records: {
          webAuthnAuthenticators: [],
          credentialBindings,
          wallet,
          walletAuthMethods: [],
          walletSigners,
        },
      });
      if (!persisted) {
        return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
      }

      return {
        ok: true,
        walletId: ceremony.intent.walletId,
        rpId: ceremony.intent.rpId,
        ed25519: {
          nearAccountId: ed25519.nearAccountId,
          publicKey: keygen.publicKey,
          relayerKeyId: keygen.relayerKeyId,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: keygen.recoveryExportCapable,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
      };
    }
    if (!request.ecdsa) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'missing ECDSA add-signer finalize input',
      };
    }
    if (ceremony.signerState.kind !== 'ecdsa_add_signer_responded') {
      return {
        ok: false,
        code: 'invalid_state',
        message: 'ECDSA add-signer HSS response is required before finalize',
      };
    }
    const bootstrap = ceremony.signerState.responded.bootstrap;
    const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
    if (expectedKeyHandles.some((keyHandle) => keyHandle !== bootstrap.keyHandle)) {
      return {
        ok: false,
        code: 'key_handle_mismatch',
        message: 'ECDSA add-signer finalize expected key handle mismatch',
      };
    }
    const walletKeyResult = buildEcdsaWalletKeysFromBootstrap({
      bootstrap,
      chainTargets: ceremony.signerState.chainTargets,
      errorContext: 'ECDSA add-signer finalize',
    });
    if (!walletKeyResult.ok) return walletKeyResult;
    const walletKeys = walletKeyResult.walletKeys;
    const signerWriteNow = Date.now();
    const wallet = this.buildWalletRecord({
      walletId: ceremony.intent.walletId,
      rpId: ceremony.intent.rpId,
      now: signerWriteNow,
    });
    const walletSigners = this.buildWalletEcdsaSignerRecords({
      walletId: ceremony.intent.walletId,
      walletKeys,
      now: signerWriteNow,
    });
    const persisted = await this.consumeAddSignerCeremonyAndPersist({
      addSignerCeremonyId: ceremony.addSignerCeremonyId,
      records: {
        webAuthnAuthenticators: [],
        credentialBindings: [],
        wallet,
        walletAuthMethods: [],
        walletSigners,
      },
    });
    if (!persisted) {
      return { ok: false, code: 'not_found', message: 'add-signer ceremony not found' };
    }
    return {
      ok: true,
      walletId: ceremony.intent.walletId,
      rpId: ceremony.intent.rpId,
      ecdsa: {
        walletKeys,
      },
    };
  }

  /**
   * Create a new NEAR subaccount and register a WebAuthn authenticator in relay-private storage.
   *
   * Notes:
   * - WebAuthn-only: the registration challenge is derived deterministically from `{ accountId, signer_slot }`.
   * - Contract-free: no on-chain WebAuthn verifier is used.
   */
  async createAccountAndRegisterUser(
    request: CreateAccountAndRegisterRequest,
  ): Promise<CreateAccountAndRegisterResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        const registrationStartedAt = Date.now();
        const registrationTimings: Record<string, number> = {};
        const accountId = String(request?.new_account_id || '').trim();
        if (!isValidAccountId(accountId))
          throw new Error(`Invalid account ID format: ${accountId}`);

        const relayerAccount = String(this.config.relayerAccount || '').trim();
        const expectedSuffix = relayerAccount ? `.${relayerAccount}` : '';
        if (!relayerAccount || !expectedSuffix || !accountId.endsWith(expectedSuffix)) {
          throw new Error(
            `new_account_id must be a subaccount of relayerAccount (${relayerAccount})`,
          );
        }

        const thresholdEd25519Registration = parseThresholdEd25519RegistrationInput(
          (request as any)?.threshold_ed25519,
        );
        const thresholdEd25519SessionPolicy = thresholdEd25519Registration.sessionPolicy;
        const thresholdEd25519SessionKind = thresholdEd25519Registration.sessionKind;
        let thresholdKeygen: Extract<
          ThresholdEd25519RegistrationKeygenResult,
          { ok: true }
        > | null = null;
        let thresholdEd25519Session: ThresholdEd25519BootstrapSession | null = null;

        const rpId = String(
          (request as unknown as { rp_id?: unknown; rpId?: unknown })?.rp_id ??
            (request as unknown as { rpId?: unknown })?.rpId ??
            '',
        ).trim();
        if (!rpId) throw new Error('Missing rp_id');
        if ('threshold_ecdsa' in (request as unknown as Record<string, unknown>)) {
          throw new Error(
            'threshold_ecdsa registration bootstrap has been removed; use /wallets/register/*',
          );
        }

        if (thresholdEd25519Registration.relayerKeyId) {
          if (!thresholdEd25519SessionPolicy || typeof thresholdEd25519SessionPolicy !== 'object') {
            throw new Error('threshold_ed25519.session_policy is required');
          }
          if (thresholdEd25519SessionKind !== 'jwt') {
            throw new Error('threshold_ed25519.session_kind must be jwt');
          }
          if (
            !thresholdEd25519Registration.keyVersion ||
            !thresholdEd25519Registration.publicKey ||
            !thresholdEd25519Registration.relayerKeyId
          ) {
            throw new Error('threshold_ed25519 registration material is incomplete');
          }
          if (thresholdEd25519Registration.recoveryExportCapable !== true) {
            throw new Error('threshold_ed25519.recovery_export_capable must be true');
          }
        }
        const thresholdService = this.getThresholdSigningService();
        if (thresholdEd25519Registration.relayerKeyId && !thresholdService) {
          throw new Error('threshold signing is not configured on this server');
        }

        if (thresholdEd25519Registration.relayerKeyId) {
          const thresholdEd25519KeygenStartedAt = Date.now();
          const schemeAny = thresholdService!.getSchemeModule(
            THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
          );
          if (!schemeAny || schemeAny.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
            throw new Error(
              `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled on this server`,
            );
          }
          const out = await schemeAny.registration.keygenFromRegistrationMaterial({
            nearAccountId: accountId,
            rpId,
            keyVersion: thresholdEd25519Registration.keyVersion,
            recoveryExportCapable: true,
            publicKey: thresholdEd25519Registration.publicKey,
            relayerKeyId: thresholdEd25519Registration.relayerKeyId,
          });
          if (!out.ok) {
            throw new Error(out.message || 'threshold-ed25519 registration keygen failed');
          }
          thresholdKeygen = out;
          logDuration(
            registrationTimings,
            'thresholdEd25519RegistrationMaterialMs',
            thresholdEd25519KeygenStartedAt,
          );
        }

        const { publicKey: newPublicKey, expectedPublicKeys } = normalizeBootstrapPublicKeys({
          publicKey: String(thresholdKeygen?.publicKey || '').trim(),
        });
        if (!newPublicKey) {
          throw new Error('threshold_ed25519 registration key material is required');
        }

        const signerSlot = (() => {
          const raw =
            (request as unknown as { signer_slot?: unknown; signerSlot?: unknown })?.signer_slot ??
            (request as unknown as { signerSlot?: unknown })?.signerSlot ??
            1;
          const n = typeof raw === 'number' ? raw : Number(raw);
          return Number.isFinite(n) && n > 0 ? Math.floor(n) : 1;
        })();

        const expectedOrigin = String(
          (request as unknown as { expected_origin?: unknown; expectedOrigin?: unknown })
            ?.expected_origin ??
            (request as unknown as { expectedOrigin?: unknown })?.expectedOrigin ??
            '',
        ).trim();

        const cred = request.webauthn_registration as any;
        if (!cred || typeof cred !== 'object') throw new Error('Missing webauthn_registration');

        // 1) Verify the registration ceremony (standard WebAuthn) off-chain.
        const expectedIntent = `register:${accountId}:${signerSlot}`;
        const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

        const clientData = parseClientDataJsonBase64url(
          String(cred.response?.clientDataJSON || ''),
        );
        if (clientData.type !== 'webauthn.create') {
          throw new Error(
            'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
          );
        }
        if (clientData.challenge !== expectedChallenge) {
          throw new Error('Registration challenge mismatch');
        }
        const originHost = originHostnameOrEmpty(clientData.origin);
        if (!isHostWithinRpId(originHost, rpId)) {
          throw new Error('WebAuthn origin is not within rpId');
        }

        const mod = await import('@simplewebauthn/server');
        const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as
          | undefined
          | ((args: any) => Promise<any>);
        if (typeof verifyRegistrationResponse !== 'function') {
          throw new Error('WebAuthn registration verifier is unavailable in this runtime');
        }

        const expectedOriginStrict = toOptionalTrimmedString(expectedOrigin);
        if (!expectedOriginStrict) {
          throw new Error('expected_origin is required for WebAuthn registration verification');
        }
        const verification = await verifyRegistrationResponse({
          response: cred,
          expectedChallenge,
          expectedOrigin: expectedOriginStrict,
          expectedRPID: rpId,
          requireUserVerification: false,
        });
        if (!verification?.verified) {
          throw new Error('Registration verification failed');
        }

        // 2) Create the on-chain account as a subaccount of the relayer signer.
        // In the lite architecture, account creation is done directly (no WebAuthn contract call).
        const accountExists = await this.checkAccountExists(accountId);
        if (accountExists) {
          throw new Error(`Account ${accountId} already exists. Cannot create duplicate account.`);
        }

        const actions: ActionArgsWasm[] = [
          {
            action_type: ActionType.CreateAccount,
          },
          {
            action_type: ActionType.Transfer,
            deposit: String(this.config.accountInitialBalance),
          },
          buildFullAccessAddKeyAction(newPublicKey),
        ];
        actions.forEach(validateActionArgsWasm);

        const { nextNonce, blockHash } = await this.fetchTxContext(
          relayerAccount,
          this.relayerPublicKey,
        );
        const signed = await this.signWithPrivateKey({
          nearPrivateKey: this.config.relayerPrivateKey,
          signerAccountId: relayerAccount,
          receiverId: accountId,
          nonce: nextNonce,
          blockHash,
          actions,
        });
        // Reach execution quickly, then perform one authoritative final key-visibility check.
        const atomicRegistrationBroadcastStartedAt = Date.now();
        const result = await this.nearClient.sendTransaction(
          signed,
          ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL,
        );
        this.logger.info(
          `Atomic registration account creation for ${accountId} reached ${ACCOUNT_CREATE_BROADCAST_WAIT_UNTIL} in ${
            Date.now() - atomicRegistrationBroadcastStartedAt
          }ms`,
        );
        logDuration(
          registrationTimings,
          'nearAccountCreateBroadcastMs',
          atomicRegistrationBroadcastStartedAt,
        );
        const atomicRegistrationKeyCheckStartedAt = Date.now();
        const bootstrapKeysVerified = await this.verifyAccountAccessKeysPresent(
          accountId,
          expectedPublicKeys,
          ACCOUNT_CREATE_FAST_KEY_VISIBILITY_CHECK,
        );
        this.logger.info(
          `Atomic registration account creation for ${accountId} key visibility verified=${bootstrapKeysVerified} in ${
            Date.now() - atomicRegistrationKeyCheckStartedAt
          }ms`,
        );
        logDuration(
          registrationTimings,
          'nearAccessKeyVisibilityMs',
          atomicRegistrationKeyCheckStartedAt,
        );
        if (!bootstrapKeysVerified) {
          this.logger.warn(
            `Atomic registration committed for ${accountId} before the operational access key was visible on final state; scheduling background audit`,
          );
          this.scheduleAccountAccessKeyVisibilityAudit({
            accountId,
            expectedPublicKeys,
            contextLabel: `Atomic registration account creation for ${accountId}`,
          });
        }

        // 3) Persist the authenticator privately on the relay.
        const credentialIdB64u = String(
          verification?.registrationInfo?.credential?.id || '',
        ).trim();
        const credentialPublicKey = verification?.registrationInfo?.credential?.publicKey as
          | Uint8Array
          | undefined;
        const counter = verification?.registrationInfo?.credential?.counter as number | undefined;

        if (!credentialIdB64u || !credentialPublicKey) {
          throw new Error(
            'Registration verification did not return credential public key material',
          );
        }

        const store = this.getWebAuthnAuthenticatorStore();
        const now = Date.now();
        const authenticatorStoreStartedAt = Date.now();
        await store.put(accountId, {
          version: 'webauthn_authenticator_v1',
          credentialIdB64u,
          credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
          counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
          createdAtMs: now,
          updatedAtMs: now,
        });
        logDuration(registrationTimings, 'authenticatorStoreMs', authenticatorStoreStartedAt);

        // 4) Persist passkey→account binding for sync/link/recovery flows.
        // This is relay-private storage (no on-chain authenticator registry dependence).
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        const binding: WebAuthnCredentialBindingRecord = {
          version: 'webauthn_credential_binding_v1',
          rpId,
          credentialIdB64u,
          userId: accountId,
          signerSlot,
          publicKey: newPublicKey,
          ...(thresholdKeygen ? { relayerKeyId: thresholdKeygen.relayerKeyId } : {}),
          ...(thresholdKeygen ? { keyVersion: thresholdKeygen.keyVersion } : {}),
          ...(thresholdKeygen
            ? { recoveryExportCapable: thresholdKeygen.recoveryExportCapable }
            : {}),
          ...(thresholdKeygen ? { clientParticipantId: thresholdKeygen.clientParticipantId } : {}),
          ...(thresholdKeygen
            ? { relayerParticipantId: thresholdKeygen.relayerParticipantId }
            : {}),
          ...(thresholdKeygen ? { participantIds: thresholdKeygen.participantIds } : {}),
          ...(normalizeThresholdRuntimePolicyScope(
            (thresholdEd25519SessionPolicy as Record<string, unknown> | undefined)
              ?.runtimePolicyScope,
          )
            ? {
                runtimePolicyScope: normalizeThresholdRuntimePolicyScope(
                  (thresholdEd25519SessionPolicy as Record<string, unknown> | undefined)
                    ?.runtimePolicyScope,
                ),
              }
            : {}),
          createdAtMs: now,
          updatedAtMs: now,
        };
        const bindingStoreStartedAt = Date.now();
        await bindingStore.put(binding);
        logDuration(registrationTimings, 'credentialBindingStoreMs', bindingStoreStartedAt);

        if (thresholdKeygen && thresholdEd25519SessionPolicy) {
          const thresholdEd25519SessionStartedAt = Date.now();
          const requestedThresholdEd25519PolicyRelayerKeyId = String(
            (thresholdEd25519SessionPolicy as Record<string, unknown>)?.relayerKeyId || '',
          ).trim();
          if (
            requestedThresholdEd25519PolicyRelayerKeyId &&
            requestedThresholdEd25519PolicyRelayerKeyId !== thresholdKeygen.relayerKeyId
          ) {
            throw new Error('threshold_ed25519.session_policy.relayerKeyId mismatch');
          }
          const thresholdEd25519PolicyWithRelayerKeyId = {
            ...(thresholdEd25519SessionPolicy as Record<string, unknown>),
            relayerKeyId: thresholdKeygen.relayerKeyId,
          } as any;
          const session = await thresholdService!.mintEd25519SessionFromRegistration({
            nearAccountId: accountId,
            rpId,
            relayerKeyId: thresholdKeygen.relayerKeyId,
            sessionPolicy: thresholdEd25519PolicyWithRelayerKeyId,
          });
          if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
            throw new Error(
              session.message ||
                session.code ||
                'threshold-ed25519 registration session bootstrap failed',
            );
          }
          const normalizedSession = toThresholdEd25519BootstrapSession(session);
          if (!normalizedSession) {
            throw new Error('threshold-ed25519 registration session bootstrap failed');
          }
          thresholdEd25519Session = normalizedSession;
          logDuration(
            registrationTimings,
            'thresholdEd25519SessionMintMs',
            thresholdEd25519SessionStartedAt,
          );
        }

        // Best-effort: persist NEAR public key metadata for UI surfaces.
        // This is not required for account correctness, so keep it off the blocking path.
        void (async () => {
          const nearPublicKeyMetadataStartedAt = Date.now();
          const recorded = await this.recordNearPublicKeyMetadata({
            userId: accountId,
            publicKey: newPublicKey,
            kind: 'threshold',
            signerSlot,
            rpId,
            credentialIdB64u,
            source: 'atomic registration NEAR public key metadata persistence',
          });
          if (recorded.ok) {
            this.logger.info('[AuthService] atomic registration async persistence', {
              nearAccountId: accountId,
              nearPublicKeyMetadataMs: Date.now() - nearPublicKeyMetadataStartedAt,
            });
          }
        })();

        this.logger.info(`Registration completed: ${result.transaction.hash}`);
        this.logger.info('[AuthService] atomic registration timings', {
          nearAccountId: accountId,
          ...registrationTimings,
          totalMs: Date.now() - registrationStartedAt,
        });
        return {
          success: true,
          transactionHash: result.transaction.hash,
          ...(thresholdKeygen
            ? {
                thresholdEd25519: {
                  keyVersion: thresholdKeygen.keyVersion,
                  recoveryExportCapable: thresholdKeygen.recoveryExportCapable,
                  relayerKeyId: thresholdKeygen.relayerKeyId,
                  publicKey: newPublicKey,
                  clientParticipantId: thresholdKeygen.clientParticipantId,
                  relayerParticipantId: thresholdKeygen.relayerParticipantId,
                  participantIds: thresholdKeygen.participantIds,
                  ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
                },
              }
            : {}),
          message: `Account ${accountId} created and registered successfully`,
        };
      } catch (error: any) {
        this.logger.error(`Atomic registration failed for ${request.new_account_id}:`, error);
        const msg = errorMessage(error) || 'Unknown atomic registration error';
        return {
          success: false,
          error: msg,
          message: `Failed to create and register account ${request.new_account_id}: ${msg}`,
        };
      }
    }, `atomic create and register ${request.new_account_id}`);
  }

  /**
   * Standard WebAuthn assertion verification for lite flows.
   *
   * This verifies:
   * - the assertion signature against the credential public key stored in relay-private storage,
   * - the RP ID hash against `rpId`,
   * - the challenge against `expectedChallenge` (base64url string),
   * - and that `clientDataJSON.origin` is within the RP ID domain.
   *
   * Notes:
   * - This intentionally does not involve on-chain challenge proofs or `verify_authentication_response`.
   * - Replay protection is handled by upstream protocol bindings (e.g., unique sessionPolicyDigest32 via sessionId).
   */
  async verifyWebAuthnAuthenticationLite(input: {
    nearAccountId: string;
    rpId: string;
    expectedChallenge: string;
    webauthn_authentication: WebAuthnAuthenticationCredential;
    expected_origin: string;
  }): Promise<{ success: boolean; verified: boolean; code?: string; message?: string }> {
    try {
      await this._ensureSignerAndRelayerAccount();

      const nearAccountId = String(input.nearAccountId || '').trim();
      const rpId = String(input.rpId || '').trim();
      const expectedChallenge = String(input.expectedChallenge || '').trim();
      const expectedOrigin = toOptionalTrimmedString(input.expected_origin);
      const cred = input.webauthn_authentication as any;

      if (!nearAccountId)
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing nearAccountId',
        };
      if (!rpId)
        return { success: false, verified: false, code: 'invalid_body', message: 'Missing rpId' };
      if (!expectedChallenge)
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing expectedChallenge',
        };
      if (!expectedOrigin)
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      if (!cred || typeof cred !== 'object')
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication',
        };

      let clientData: { challenge: string; origin: string; type: string };
      try {
        clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: errorMessage(e) || 'Invalid webauthn_authentication.response.clientDataJSON',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return {
          success: false,
          verified: false,
          code: 'invalid_origin',
          message: 'WebAuthn origin is not within rpId',
        };
      }

      const credentialId = String(cred.id || '').trim();
      const rawId = String(cred.rawId || '').trim();
      const chosen = rawId || credentialId;
      if (!chosen) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication.id/rawId',
        };
      }

      let credentialIDBytes: Uint8Array;
      try {
        credentialIDBytes = decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId');
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: errorMessage(e) || 'Invalid credential rawId',
        };
      }
      const credentialIdB64u = base64UrlEncode(credentialIDBytes);

      const store = this.getWebAuthnAuthenticatorStore();
      const matched = await store.get(nearAccountId, credentialIdB64u);
      if (!matched) {
        return {
          success: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }

      // Lazy import to avoid forcing Node-only deps into non-Node runtimes unless used.
      const mod = await import('@simplewebauthn/server');
      const verifyAuthenticationResponse = (mod as any).verifyAuthenticationResponse as
        | undefined
        | ((args: any) => Promise<any>);
      if (typeof verifyAuthenticationResponse !== 'function') {
        return {
          success: false,
          verified: false,
          code: 'unsupported',
          message: 'WebAuthn verifier is unavailable in this runtime',
        };
      }

      let credentialPublicKeyBytes: Uint8Array;
      try {
        credentialPublicKeyBytes = decodeBase64UrlOrBase64(
          matched.credentialPublicKeyB64u,
          'authenticator.credentialPublicKeyB64u',
        );
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'internal',
          message: `Stored credential public key is invalid: ${errorMessage(e) || 'decode failed'}`,
        };
      }

      const credential = {
        id: credentialIdB64u,
        publicKey:
          typeof Buffer !== 'undefined'
            ? Buffer.from(credentialPublicKeyBytes)
            : credentialPublicKeyBytes,
        counter: matched.counter,
      };

      let verification: any;
      try {
        verification = await verifyAuthenticationResponse({
          response: cred,
          expectedChallenge,
          expectedOrigin,
          expectedRPID: rpId,
          credential,
          requireUserVerification: false,
        });
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_assertion',
          message: errorMessage(e) || 'Authentication assertion verification threw',
        };
      }

      if (!verification?.verified) {
        return {
          success: false,
          verified: false,
          code: 'not_verified',
          message: 'Authentication verification failed',
        };
      }

      const newCounter = (() => {
        const v = (verification as { authenticationInfo?: { newCounter?: unknown } })
          ?.authenticationInfo?.newCounter;
        const n = typeof v === 'number' ? v : Number(v);
        return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
      })();

      // Persist signature counter updates to harden against assertion replay.
      // Note: some authenticators do not implement counters (always 0); in that case, replay defense must come from one-time challenges.
      if (newCounter !== null) {
        try {
          const latest = await store.get(nearAccountId, credentialIdB64u);
          if (latest && newCounter > latest.counter) {
            await store.put(nearAccountId, {
              ...latest,
              credentialPublicKeyB64u: matched.credentialPublicKeyB64u,
              counter: newCounter,
              updatedAtMs: Date.now(),
            });
          }
        } catch (e: unknown) {
          return {
            success: false,
            verified: false,
            code: 'internal',
            message: `Failed to persist authenticator counter: ${errorMessage(e) || 'store error'}`,
          };
        }
      }

      return { success: true, verified: true };
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Verification failed';
      this.logger.error('[webauthn] verifyWebAuthnAuthenticationLite internal error', {
        message: msg,
        nearAccountId: String(input?.nearAccountId || ''),
        rpId: String(input?.rpId || ''),
      });
      return { success: false, verified: false, code: 'internal', message: msg };
    }
  }

  /**
   * List WebAuthn authenticators for the given user.
   *
   * This is relay-private state (no on-chain authenticator registry).
   * Intended for UI surfaces like "Linked Devices" in the SDK.
   */
  async listWebAuthnAuthenticatorsForUser(input: { userId: string; rpId?: string }): Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    authenticators?: Array<{
      credentialIdB64u: string;
      signerSlot?: number;
      publicKey?: string;
      createdAtMs?: number;
      updatedAtMs?: number;
    }>;
  }> {
    try {
      const userId = String(input.userId || '').trim();
      const rpId = String(input.rpId || '').trim();
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };

      const authStore = this.getWebAuthnAuthenticatorStore();
      const bindingStore = this.getWebAuthnCredentialBindingStore();

      if (typeof authStore.list !== 'function') {
        return {
          ok: false,
          code: 'not_supported',
          message: 'Authenticator listing is not supported by this store',
        };
      }
      if (typeof bindingStore.listByUserId !== 'function') {
        return {
          ok: false,
          code: 'not_supported',
          message: 'Credential binding listing is not supported by this store',
        };
      }

      const [authenticators, bindings] = await Promise.all([
        authStore.list(userId),
        bindingStore.listByUserId({ userId, ...(rpId ? { rpId } : {}) }),
      ]);

      const authByCid = new Map<string, WebAuthnAuthenticatorRecord>();
      for (const a of authenticators || []) {
        authByCid.set(String(a.credentialIdB64u || '').trim(), a);
      }

      const merged = (bindings || []).map((b) => {
        const cid = String(b.credentialIdB64u || '').trim();
        const a = authByCid.get(cid);
        return {
          credentialIdB64u: cid,
          signerSlot: b.signerSlot,
          publicKey: b.publicKey,
          createdAtMs: a?.createdAtMs ?? b.createdAtMs,
          updatedAtMs: a?.updatedAtMs ?? b.updatedAtMs,
        };
      });

      merged.sort((x, y) => (Number(x.signerSlot || 0) || 0) - (Number(y.signerSlot || 0) || 0));

      return { ok: true, authenticators: merged };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to list authenticators',
      };
    }
  }

  async listNearPublicKeysForUser(input: { userId: string }): Promise<{
    ok: boolean;
    code?: string;
    message?: string;
    keys?: Array<{
      publicKey: string;
      kind: NearPublicKeyKind;
      signerSlot?: number;
      createdAtMs?: number;
      updatedAtMs?: number;
      rpId?: string;
      credentialIdB64u?: string;
    }>;
  }> {
    try {
      const userId = String(input.userId || '').trim();
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };

      const store = this.getNearPublicKeyStore();
      if (typeof store.listByUserId !== 'function') {
        return {
          ok: false,
          code: 'not_supported',
          message: 'Key listing is not supported by this store',
        };
      }

      const records = await store.listByUserId(userId);
      const keys = (records || []).map((r) => ({
        publicKey: r.publicKey,
        kind: r.kind,
        ...(typeof r.signerSlot === 'number' ? { signerSlot: r.signerSlot } : {}),
        createdAtMs: r.createdAtMs,
        updatedAtMs: r.updatedAtMs,
        ...(r.rpId ? { rpId: r.rpId } : {}),
        ...(r.credentialIdB64u ? { credentialIdB64u: r.credentialIdB64u } : {}),
      }));
      return { ok: true, keys };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to list keys' };
    }
  }

  async createWebAuthnLoginOptions(request: {
    userId?: unknown;
    user_id?: unknown;
    rpId?: unknown;
    rp_id?: unknown;
    ttlMs?: unknown;
    ttl_ms?: unknown;
  }): Promise<{
    ok: boolean;
    challengeId?: string;
    challengeB64u?: string;
    expiresAtMs?: number;
    code?: string;
    message?: string;
  }> {
    try {
      const userId = String(request?.userId ?? request?.user_id ?? '').trim();
      const rpId = String(request?.rpId ?? request?.rp_id ?? '').trim();
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!isValidAccountId(userId))
        return { ok: false, code: 'invalid_body', message: 'Invalid userId' };
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rpId' };

      const ttlMsRaw = request?.ttlMs ?? request?.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

      const store = this.getWebAuthnLoginChallengeStore();
      await store.put({
        version: 'webauthn_login_challenge_v1',
        challengeId,
        userId,
        rpId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return { ok: true, challengeId, challengeB64u, expiresAtMs };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create login options',
      };
    }
  }

  async verifyWebAuthnLogin(request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
  }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    rpId?: string;
    code?: string;
    message?: string;
  }> {
    try {
      const challengeId = String(request?.challengeId ?? request?.challenge_id ?? '').trim();
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

      const store = this.getWebAuthnLoginChallengeStore();
      const record = await store.consume(challengeId);
      if (!record) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Login challenge expired or invalid',
        };
      }

      const expectedOrigin = toOptionalTrimmedString(request.expected_origin);
      if (!expectedOrigin) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: record.userId,
        rpId: record.rpId,
        expectedChallenge: record.challengeB64u,
        webauthn_authentication: request?.webauthn_authentication as any,
        expected_origin: expectedOrigin,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      // Best-effort: ensure identity map includes this user's NEAR account id.
      // This enables provider linking flows to treat `near:{accountId}` as a stable identity.
      try {
        const identity = this.getIdentityStore();
        await identity.linkSubjectToUserId({
          userId: record.userId,
          subject: `near:${record.userId}`,
        });
      } catch {}

      return { ok: true, verified: true, userId: record.userId, rpId: record.rpId };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Login verification failed',
      };
    }
  }

  async createEmailOtpUnlockChallenge(request: {
    walletId?: unknown;
    orgId?: unknown;
    ttlMs?: unknown;
    ttl_ms?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        challengeId: string;
        challengeB64u: string;
        expiresAtMs: number;
        unlockKeyVersion: string;
      }
    | { ok: false; code: string; message: string; lockedUntilMs?: number }
  > {
    try {
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || undefined;
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!isValidAccountId(walletId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid walletId' };
      }

      const activeEnrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!activeEnrollment.ok) return activeEnrollment;
      const enrollment = activeEnrollment.enrollment;

      const ttlMsRaw = request.ttlMs ?? request.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
      await this.getEmailOtpUnlockChallengeStore().put({
        version: 'email_otp_unlock_challenge_v1',
        challengeId,
        walletId: enrollment.walletId,
        userId: enrollment.providerUserId,
        orgId: enrollment.orgId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return {
        ok: true,
        walletId: enrollment.walletId,
        challengeId,
        challengeB64u,
        expiresAtMs,
        unlockKeyVersion: enrollment.unlockKeyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create Email OTP unlock challenge',
      };
    }
  }

  async verifyEmailOtpUnlockProof(request: {
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    unlockProof?: unknown;
  }): Promise<
    | {
        ok: true;
        verified: true;
        userId: string;
        walletId: string;
        unlockKeyVersion: string;
      }
    | { ok: false; verified: false; code: string; message: string }
  > {
    try {
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || undefined;
      const challengeId = toOptionalTrimmedString(request.challengeId);
      if (!walletId)
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!isValidAccountId(walletId)) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Invalid walletId' };
      }
      if (!challengeId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (
        !request.unlockProof ||
        typeof request.unlockProof !== 'object' ||
        Array.isArray(request.unlockProof)
      ) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof is required',
        };
      }

      const providedPublicKey = toOptionalTrimmedString(
        (request.unlockProof as Record<string, unknown>).publicKey,
      );
      const signatureB64u = toOptionalTrimmedString(
        (request.unlockProof as Record<string, unknown>).signature,
      );
      if (!providedPublicKey) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is required',
        };
      }
      if (!signatureB64u) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature is required',
        };
      }

      const challengeRecord = await this.getEmailOtpUnlockChallengeStore().consume(challengeId);
      if (!challengeRecord) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP unlock challenge expired or invalid',
        };
      }
      if (Date.now() > challengeRecord.expiresAtMs) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP unlock challenge expired or invalid',
        };
      }
      if (challengeRecord.walletId !== walletId) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this walletId',
        };
      }

      const activeEnrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!activeEnrollment.ok) {
        return {
          ok: false,
          verified: false,
          code: activeEnrollment.code,
          message: activeEnrollment.message,
        };
      }
      const enrollment = activeEnrollment.enrollment;
      if (
        challengeRecord.userId !== enrollment.providerUserId ||
        challengeRecord.orgId !== enrollment.orgId
      ) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this enrollment',
        };
      }

      let publicKey33: Uint8Array;
      try {
        publicKey33 = base64UrlDecode(providedPublicKey);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey must be valid base64url',
        };
      }
      if (publicKey33.length !== 33) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey must decode to 33 bytes',
        };
      }
      try {
        await validateSecp256k1PublicKey33(publicKey33);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is not a valid secp256k1 public key',
        };
      }

      let signature65: Uint8Array;
      try {
        signature65 = base64UrlDecode(signatureB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature must be valid base64url',
        };
      }
      if (signature65.length !== 65) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature must decode to 65 bytes',
        };
      }

      const enrolledPublicKey = base64UrlDecode(enrollment.clientUnlockPublicKeyB64u);
      if (
        enrolledPublicKey.length !== publicKey33.length ||
        !enrolledPublicKey.every((value, index) => value === publicKey33[index])
      ) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.publicKey does not match the enrolled clientUnlockPublicKeyB64u',
        };
      }

      let challengeDigest32: Uint8Array;
      try {
        challengeDigest32 = base64UrlDecode(challengeRecord.challengeB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Stored unlock challenge digest was invalid',
        };
      }
      if (challengeDigest32.length !== 32) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Stored unlock challenge digest must decode to 32 bytes',
        };
      }

      try {
        await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
          challengeDigest32,
          signature65,
          publicKey33,
        );
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.signature did not verify against unlockProof.publicKey',
        };
      }

      const nowMs = Date.now();
      await this.putEmailOtpAuthStateForEnrollment(enrollment, {
        lastEmailOtpLoginAtMs: nowMs,
      });

      return {
        ok: true,
        verified: true,
        userId: enrollment.walletId,
        walletId: enrollment.walletId,
        unlockKeyVersion: enrollment.unlockKeyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to verify Email OTP unlock proof',
      };
    }
  }

  private async pruneExpiredEmailOtpChallenges(
    challengeStore: EmailOtpChallengeStore,
    nowMs: number,
  ): Promise<void> {
    const deleted = await challengeStore.deleteExpired(nowMs);
    for (const record of deleted) {
      this.emailOtpMemoryOutbox.delete(record.challengeId);
    }
  }

  private async enforceEmailOtpActiveChallengeLimit(input: {
    challengeStore: EmailOtpChallengeStore;
    challengeSubjectId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
    maxActiveChallenges: number;
  }): Promise<void> {
    const maxActive = Math.max(1, Math.floor(input.maxActiveChallenges));
    while (
      (await input.challengeStore.countActiveByContext({
        challengeSubjectId: input.challengeSubjectId,
        walletId: input.walletId,
        ...(input.orgId ? { orgId: input.orgId } : {}),
        otpChannel: input.otpChannel,
        sessionHash: input.sessionHash,
        appSessionVersion: input.appSessionVersion,
        action: input.action,
        operation: input.operation,
        nowMs: input.nowMs,
      })) >= maxActive
    ) {
      const deleted = await input.challengeStore.deleteOldestActiveByContext({
        challengeSubjectId: input.challengeSubjectId,
        walletId: input.walletId,
        ...(input.orgId ? { orgId: input.orgId } : {}),
        otpChannel: input.otpChannel,
        sessionHash: input.sessionHash,
        appSessionVersion: input.appSessionVersion,
        action: input.action,
        operation: input.operation,
        nowMs: input.nowMs,
      });
      if (!deleted) break;
      this.emailOtpMemoryOutbox.delete(deleted.challengeId);
    }
  }

  private async readEmailOtpAuthStateForEnrollment(
    enrollmentRecord: EmailOtpWalletEnrollmentRecord,
  ): Promise<
    | { ok: true; state: EmailOtpAuthStateRecord | null }
    | { ok: false; code: string; message: string }
  > {
    const state = await this.getEmailOtpAuthStateStore().get(enrollmentRecord.walletId);
    if (!state) return { ok: true, state: null };
    if (
      state.orgId !== enrollmentRecord.orgId ||
      state.providerUserId !== enrollmentRecord.providerUserId
    ) {
      return {
        ok: false,
        code: 'auth_state_enrollment_mismatch',
        message: 'Email OTP auth state does not match the active enrollment',
      };
    }
    return { ok: true, state };
  }

  private async putEmailOtpAuthStateForEnrollment(
    enrollmentRecord: EmailOtpWalletEnrollmentRecord,
    patch: Partial<
      Pick<
        EmailOtpAuthStateRecord,
        | 'otpFailureCount'
        | 'lastOtpFailureAtMs'
        | 'otpLockedUntilMs'
        | 'lastEmailOtpLoginAtMs'
        | 'lastStrongAuthAtMs'
      >
    >,
  ): Promise<EmailOtpAuthStateRecord> {
    const nowMs = Date.now();
    const existing = await this.getEmailOtpAuthStateStore().get(enrollmentRecord.walletId);
    if (
      existing &&
      (existing.orgId !== enrollmentRecord.orgId ||
        existing.providerUserId !== enrollmentRecord.providerUserId)
    ) {
      throw new Error('Email OTP auth state does not match the active enrollment');
    }
    const next: EmailOtpAuthStateRecord = {
      version: 'email_otp_auth_state_v1',
      walletId: enrollmentRecord.walletId,
      providerUserId: enrollmentRecord.providerUserId,
      orgId: enrollmentRecord.orgId,
      createdAtMs: existing?.createdAtMs ?? nowMs,
      updatedAtMs: nowMs,
      ...(existing?.otpFailureCount != null ? { otpFailureCount: existing.otpFailureCount } : {}),
      ...(existing?.lastOtpFailureAtMs ? { lastOtpFailureAtMs: existing.lastOtpFailureAtMs } : {}),
      ...(existing?.otpLockedUntilMs ? { otpLockedUntilMs: existing.otpLockedUntilMs } : {}),
      ...(existing?.lastEmailOtpLoginAtMs
        ? { lastEmailOtpLoginAtMs: existing.lastEmailOtpLoginAtMs }
        : {}),
      ...(existing?.lastStrongAuthAtMs ? { lastStrongAuthAtMs: existing.lastStrongAuthAtMs } : {}),
      ...patch,
    };
    await this.getEmailOtpAuthStateStore().put(next);
    return next;
  }

  private async createEmailOtpChallengeWithAction(request: {
    challengeSubjectId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
    reuseActiveChallenge?: unknown;
    action: EmailOtpChallengeAction;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          challengeSubjectId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: EmailOtpChallengeAction;
          operation: EmailOtpChallengeOperation;
        };
        delivery: {
          status: 'sent' | 'reused';
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        lockedUntilMs?: number;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    try {
      const challengeSubjectId = toOptionalTrimmedString(request.challengeSubjectId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const email = toOptionalTrimmedString(request.email)?.toLowerCase() || '';
      const otpChannel = toOptionalTrimmedString(request.otpChannel);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      const reuseActiveChallenge = request.reuseActiveChallenge === true;
      const action = request.action;
      const operationRaw = toOptionalTrimmedString(request.operation);
      let operation: EmailOtpChallengeOperation;
      if (operationRaw && isWalletEmailOtpLoginOperation(operationRaw)) {
        operation = operationRaw;
      } else if (operationRaw === WALLET_EMAIL_OTP_REGISTRATION_OPERATION) {
        operation = WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
      } else {
        operation =
          action === WALLET_EMAIL_OTP_ACTIONS.registration
            ? WALLET_EMAIL_OTP_REGISTRATION_OPERATION
            : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
      }
      if (!challengeSubjectId) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeSubjectId' };
      }
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const activeEnrollment =
        action !== WALLET_EMAIL_OTP_ACTIONS.registration
          ? await this.readActiveEmailOtpEnrollment({ walletId, orgId })
          : null;
      if (activeEnrollment && !activeEnrollment.ok) return activeEnrollment;
      const existingEnrollment = activeEnrollment?.ok ? activeEnrollment.enrollment : null;
      const existingAuthStateResult = existingEnrollment
        ? await this.readEmailOtpAuthStateForEnrollment(existingEnrollment)
        : { ok: true as const, state: null };
      if (!existingAuthStateResult.ok) return existingAuthStateResult;
      const existingAuthState = existingAuthStateResult.state;
      const challengeEmail =
        action === WALLET_EMAIL_OTP_ACTIONS.registration
          ? email
          : existingEnrollment?.verifiedEmail || '';
      if (!challengeEmail) {
        return {
          ok: false,
          code: 'recovery_email_missing',
          message: 'Current app session does not include a recovery email',
        };
      }
      if (existingAuthState?.otpLockedUntilMs && existingAuthState.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: existingAuthState.otpLockedUntilMs,
        };
      }
      const issuedAtMs = Date.now();
      const challengeStore = this.getEmailOtpChallengeStore();
      await this.pruneExpiredEmailOtpChallenges(challengeStore, issuedAtMs);
      if (reuseActiveChallenge) {
        const existingChallenge = await challengeStore.findLatestActiveByContext({
          challengeSubjectId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action,
          operation,
          nowMs: issuedAtMs,
        });
        if (existingChallenge) {
          return {
            ok: true,
            challenge: {
              challengeId: existingChallenge.challengeId,
              issuedAtMs: existingChallenge.createdAtMs,
              expiresAtMs: existingChallenge.expiresAtMs,
              challengeSubjectId,
              walletId,
              orgId,
              otpChannel: EMAIL_OTP_CHANNEL,
              sessionHash,
              appSessionVersion,
              action,
              operation,
            },
            delivery: {
              status: 'reused',
              mode: 'memory',
              emailHint: this.maskEmail(existingChallenge.email),
            },
          };
        }
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'challenge',
        action,
        userId: challengeSubjectId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;
      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const otpConfig = this.resolveEmailOtpConfig();
      const expiresAtMs = issuedAtMs + otpConfig.challengeTtlMs;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const otpCode = this.generateNumericOtp(otpConfig.codeLength);
      await this.enforceEmailOtpActiveChallengeLimit({
        challengeStore,
        challengeSubjectId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        nowMs: issuedAtMs,
        maxActiveChallenges: otpConfig.maxActiveChallengesPerContext,
      });

      const challengeRecord: EmailOtpChallengeRecord = {
        version: 'email_otp_challenge_v1' as const,
        challengeId,
        challengeSubjectId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        email: challengeEmail,
        otpCode,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        createdAtMs: issuedAtMs,
        expiresAtMs,
        attemptCount: 0,
        maxAttempts: otpConfig.maxAttempts,
      };
      await challengeStore.put(challengeRecord);
      const persistedChallenge = await challengeStore.get(challengeId);
      if (!persistedChallenge) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email OTP challenge could not be persisted',
        };
      }

      const delivery = await this.deliverEmailOtpCode({
        challengeId,
        walletId,
        userId: challengeSubjectId,
        otpChannel: EMAIL_OTP_CHANNEL,
        action,
        operation,
        email: challengeEmail,
        otpCode,
        expiresAtMs,
      });
      if (!delivery.ok) {
        await challengeStore.del(challengeId);
        this.emailOtpMemoryOutbox.delete(challengeId);
        return delivery;
      }

      return {
        ok: true,
        challenge: {
          challengeId,
          issuedAtMs,
          expiresAtMs,
          challengeSubjectId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action,
          operation,
        },
        delivery: {
          status: 'sent',
          mode: delivery.deliveryMode,
          emailHint: delivery.emailHint,
        },
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create Email OTP challenge',
      };
    }
  }

  async createEmailOtpChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
    reuseActiveChallenge?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
          operation: EmailOtpLoginChallengeOperation;
        };
        delivery: {
          status: 'sent' | 'reused';
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    const result = await this.createEmailOtpChallengeWithAction({
      ...request,
      challengeSubjectId: request.userId,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      reuseActiveChallenge: request.reuseActiveChallenge,
    });
    if (!result.ok) return result;
    const operation =
      result.challenge.operation === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION ||
      result.challenge.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? result.challenge.operation
        : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    return {
      ok: true,
      challenge: {
        ...result.challenge,
        userId: result.challenge.challengeSubjectId,
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation,
      },
      delivery: result.delivery,
    };
  }

  async createEmailOtpEnrollmentChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
          operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    const result = await this.createEmailOtpChallengeWithAction({
      ...request,
      challengeSubjectId: request.userId,
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        ...result.challenge,
        userId: result.challenge.challengeSubjectId,
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      },
      delivery: result.delivery,
    };
  }

  async createEmailOtpDeviceRecoveryChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    email?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challenge: {
          challengeId: string;
          issuedAtMs: number;
          expiresAtMs: number;
          userId: string;
          walletId: string;
          orgId: string;
          otpChannel: EmailOtpChannel;
          sessionHash: string;
          appSessionVersion: string;
          action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
          operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
        };
        delivery: {
          mode: 'email_provider' | 'log' | 'memory';
          emailHint: string;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    const result = await this.createEmailOtpChallengeWithAction({
      ...request,
      challengeSubjectId: request.userId,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        ...result.challenge,
        userId: result.challenge.challengeSubjectId,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      },
      delivery: result.delivery,
    };
  }

  private async verifyEmailOtpChallengeCode(request: {
    challengeSubjectId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    registrationChallengeProof?: EmailOtpRegistrationChallengeProof;
    allowRegistrationChallengeReroll?: boolean;
    clientIp?: unknown;
    expectedAction: EmailOtpChallengeAction;
    expectedOperation?: EmailOtpChallengeOperation;
  }): Promise<VerifiedEmailOtpChallengeCodeResult> {
    try {
      const challengeSubjectId = parseChallengeSubjectId(request.challengeSubjectId);
      const walletId = parseWalletId(request.walletId);
      const orgId = parseOrgId(request.orgId);
      const challengeId = parseEmailOtpChallengeId(request.challengeId);
      const otpCode = toOptionalTrimmedString(request.otpCode);
      const otpChannel = toOptionalTrimmedString(request.otpChannel);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      const expectedAction = request.expectedAction;
      const expectedOperation = request.expectedOperation;
      if (
        expectedAction === WALLET_EMAIL_OTP_ACTIONS.registration &&
        !request.registrationChallengeProof
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration verification requires registration challenge proof',
        };
      }
      const verificationIntent = emailOtpChallengeVerificationIntentFromRequest({
        expectedAction,
        ...(expectedOperation ? { expectedOperation } : {}),
        ...(request.registrationChallengeProof
          ? { registrationChallengeProof: request.registrationChallengeProof }
          : {}),
        ...(request.allowRegistrationChallengeReroll
          ? { allowRegistrationChallengeReroll: true }
          : {}),
      });
      const expectedPurpose = expectedEmailOtpStoredChallengePurpose(verificationIntent);
      if (!challengeSubjectId.ok) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeSubjectId' };
      }
      if (!walletId.ok) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId.ok) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId.ok)
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.challengeId !== challengeId.value
      ) {
        return {
          ok: false,
          code: 'challenge_id_mismatch',
          message: 'Email OTP registration proof does not match challengeId',
        };
      }
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.finalWalletId !== walletId.value
      ) {
        return {
          ok: false,
          code: 'challenge_wallet_mismatch',
          message: 'Email OTP registration proof does not match walletId',
        };
      }
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.orgId !== orgId.value
      ) {
        return {
          ok: false,
          code: 'challenge_org_mismatch',
          message: 'Email OTP registration proof does not match orgId',
        };
      }
      if (
        request.registrationChallengeProof &&
        request.registrationChallengeProof.appSessionVersion !== appSessionVersion
      ) {
        return {
          ok: false,
          code: 'challenge_session_mismatch',
          message: 'Email OTP registration proof does not match appSessionVersion',
        };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'verify',
        action: expectedAction,
        userId: challengeSubjectId.value,
        walletId: walletId.value,
        orgId: orgId.value,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const activeEnrollment =
        expectedAction !== WALLET_EMAIL_OTP_ACTIONS.registration
          ? await this.readActiveEmailOtpEnrollment({
              walletId: walletId.value,
              orgId: orgId.value,
            })
          : null;
      if (activeEnrollment && !activeEnrollment.ok) return activeEnrollment;
      const enrollment = activeEnrollment?.ok
        ? activeEnrollment.enrollment
        : await this.getEmailOtpWalletEnrollmentStore().get(walletId.value);
      if (enrollment && enrollment.orgId !== orgId.value) {
        return {
          ok: false,
          code: 'tenant_scope_mismatch',
          message: 'Email OTP enrollment does not match the requested orgId',
        };
      }
      const authStateResult = enrollment
        ? await this.readEmailOtpAuthStateForEnrollment(enrollment)
        : { ok: true as const, state: null };
      if (!authStateResult.ok) return authStateResult;
      const authState = authStateResult.state;
      const activeLockoutUntilMs =
        authState?.otpLockedUntilMs && authState.otpLockedUntilMs > Date.now()
          ? authState.otpLockedUntilMs
          : undefined;
      if (activeLockoutUntilMs) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: activeLockoutUntilMs,
        };
      }

      const challengeStore = this.getEmailOtpChallengeStore();
      const nowMs = Date.now();
      await this.pruneExpiredEmailOtpChallenges(challengeStore, nowMs);
      let record = await challengeStore.get(challengeId.value);
      if (!record) {
        record = await challengeStore.findActiveByContext({
          challengeSubjectId: challengeSubjectId.value,
          walletId: walletId.value,
          orgId: orgId.value,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action: expectedAction,
          operation: expectedPurpose.operation,
          otpCode,
          nowMs,
        });
        if (!record) {
          this.logger.warn('[email-otp] challenge record not found during verification', {
            challengeId: challengeId.value,
            walletId: walletId.value,
            challengeSubjectId: challengeSubjectId.value,
            otpChannel: EMAIL_OTP_CHANNEL,
            action: expectedAction,
          });
          return {
            ok: false,
            code: 'challenge_expired_or_invalid',
            message: 'Email OTP challenge expired or invalid',
          };
        }
      }

      if (nowMs > record.expiresAtMs) {
        await challengeStore.del(record.challengeId);
        this.emailOtpMemoryOutbox.delete(record.challengeId);
        return {
          ok: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP challenge expired or invalid',
        };
      }

      const storedPurpose = readEmailOtpStoredChallengePurpose(record);
      const purposeMatches = emailOtpStoredChallengePurposeMatches({
        expected: expectedPurpose,
        actual: storedPurpose,
      });
      const verifiedRegistrationChallengeProof =
        verificationIntent.kind === 'registration'
          ? buildVerifiedEmailOtpRegistrationChallengeProof({
              record,
              challengeSubjectId: challengeSubjectId.value,
              proof: verificationIntent.binding,
              storedPurpose,
              allowWalletReroll: verificationIntent.allowWalletReroll,
            })
          : null;
      const registrationChallengeCanFollowReroll = verifiedRegistrationChallengeProof != null;
      const registrationChallengeEmailMatches =
        verificationIntent.kind === 'registration' &&
        toOptionalTrimmedString(record.email)?.toLowerCase() ===
          toOptionalTrimmedString(verificationIntent.binding.proofEmail)?.toLowerCase();
      const registrationRerollDisallowed =
        verificationIntent.kind === 'registration' &&
        storedPurpose?.kind === 'wallet_unlock' &&
        !verificationIntent.allowWalletReroll;
      // Registration name rerolls change only the final wallet id; the OTP
      // remains bound to the same provider subject, email, org, and app session.
      const subjectMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.challengeSubjectId !== challengeSubjectId.value;
      const walletMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.walletId !== walletId.value;
      const actionMismatch = registrationChallengeCanFollowReroll ? false : !purposeMatches;
      const operationMismatch = registrationChallengeCanFollowReroll ? false : !purposeMatches;
      const sessionHashMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.sessionHash !== sessionHash;
      const appSessionVersionMismatch = registrationChallengeCanFollowReroll
        ? false
        : record.appSessionVersion !== appSessionVersion;
      const bindingMismatch =
        subjectMismatch ||
        walletMismatch ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        actionMismatch ||
        operationMismatch ||
        sessionHashMismatch ||
        appSessionVersionMismatch ||
        String(record.orgId || '') !== String(orgId.value || '');
      if (bindingMismatch) {
        const mismatchCode: EmailOtpChallengeBindingMismatchCode =
          record.otpChannel !== EMAIL_OTP_CHANNEL
            ? 'challenge_channel_mismatch'
            : subjectMismatch
              ? 'challenge_subject_mismatch'
              : verificationIntent.kind === 'registration' && !registrationChallengeEmailMatches
                ? 'challenge_email_mismatch'
                : String(record.orgId || '') !== String(orgId.value || '')
                  ? 'challenge_org_mismatch'
                  : registrationRerollDisallowed
                    ? 'registration_reroll_disallowed'
                    : actionMismatch || operationMismatch
                      ? 'challenge_purpose_mismatch'
                      : walletMismatch
                        ? 'challenge_wallet_mismatch'
                        : sessionHashMismatch || appSessionVersionMismatch
                          ? 'challenge_session_mismatch'
                          : 'challenge_org_mismatch';
        this.logger.warn('[email-otp] challenge binding mismatch during verification', {
          challengeId: record.challengeId,
          expectedChallengeId: challengeId.value,
          expectedAction,
          expectedOperation: expectedOperation || null,
          recordAction: record.action,
          recordOperation: record.operation,
          hasRegistrationChallengeProof: request.registrationChallengeProof != null,
          registrationChallengeCanFollowReroll,
          registrationRerollDisallowed,
          registrationChallengeEmailMatches,
          registrationChallengePurpose: verifiedRegistrationChallengeProof?.purpose.kind || null,
          subjectMatches: !subjectMismatch,
          walletMatches: !walletMismatch,
          otpChannelMatches: record.otpChannel === EMAIL_OTP_CHANNEL,
          actionMatches: !actionMismatch,
          operationMatches: !operationMismatch,
          sessionHashMatches: !sessionHashMismatch,
          appSessionVersionMatches: !appSessionVersionMismatch,
          orgMatches: String(record.orgId || '') === String(orgId.value || ''),
          recordWalletId: record.walletId,
          requestWalletId: walletId.value,
          mismatchCode,
          expectedPurpose,
          storedPurpose,
        });
        return {
          ok: false,
          code: mismatchCode,
          message: 'Email OTP challenge is not valid for the current app session',
        };
      }
      if (registrationChallengeCanFollowReroll) {
        this.logger.info('[email-otp] registration reroll challenge validation', {
          challengeId: record.challengeId,
          registrationAttemptId:
            verifiedRegistrationChallengeProof.kind === 'registration_attempt'
              ? verifiedRegistrationChallengeProof.registrationAttemptId
              : null,
          originalWalletId: verifiedRegistrationChallengeProof.originalWalletId,
          finalWalletId: verifiedRegistrationChallengeProof.finalWalletId,
          providerSubject: verifiedRegistrationChallengeProof.providerSubject,
          providerSubjectMatches:
            record.challengeSubjectId === verifiedRegistrationChallengeProof.challengeSubjectId,
          proofEmailMatches: registrationChallengeEmailMatches,
          appSessionVersionMatches:
            record.appSessionVersion === verifiedRegistrationChallengeProof.appSessionVersion,
          orgMatches:
            String(record.orgId || '') === String(verifiedRegistrationChallengeProof.orgId),
          purpose: verifiedRegistrationChallengeProof.purpose,
          expectedPurpose,
          storedPurpose,
        });
      }

      if (record.otpCode !== otpCode) {
        const matchingRecord = await challengeStore.findActiveByContext({
          challengeSubjectId: challengeSubjectId.value,
          walletId: walletId.value,
          orgId: orgId.value,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action: expectedAction,
          operation: expectedOperation || record.operation,
          otpCode,
          nowMs,
        });
        if (matchingRecord) {
          record = matchingRecord;
        }
      }

      if (record.otpCode !== otpCode) {
        const nextAttemptCount = record.attemptCount + 1;
        const otpConfig = this.resolveEmailOtpConfig();
        const nextLockedUntilMs =
          nextAttemptCount >= record.maxAttempts ? Date.now() + otpConfig.lockoutTtlMs : undefined;
        if (enrollment) {
          const nowMsForFailure = Date.now();
          const nextFailureCount = Number(authState?.otpFailureCount || 0) + 1;
          await this.putEmailOtpAuthStateForEnrollment(enrollment, {
            otpFailureCount: nextFailureCount,
            lastOtpFailureAtMs: nowMsForFailure,
            ...(nextLockedUntilMs ? { otpLockedUntilMs: nextLockedUntilMs } : {}),
          });
        }
        if (nextAttemptCount >= record.maxAttempts) {
          await challengeStore.del(record.challengeId);
          this.emailOtpMemoryOutbox.delete(record.challengeId);
          return {
            ok: false,
            code: 'otp_attempts_exhausted',
            message: 'Email OTP challenge exceeded the maximum number of attempts',
            attemptsRemaining: 0,
            ...(nextLockedUntilMs ? { lockedUntilMs: nextLockedUntilMs } : {}),
          };
        }

        await challengeStore.put({
          ...record,
          attemptCount: nextAttemptCount,
        });
        return {
          ok: false,
          code: 'invalid_otp',
          message: 'OTP code is invalid',
          attemptsRemaining: record.maxAttempts - nextAttemptCount,
        };
      }

      await challengeStore.del(record.challengeId);
      this.emailOtpMemoryOutbox.delete(record.challengeId);

      if (enrollment) {
        const hadOtpFailureState =
          Number(authState?.otpFailureCount || 0) > 0 ||
          authState?.lastOtpFailureAtMs != null ||
          authState?.otpLockedUntilMs != null;
        if (hadOtpFailureState) {
          await this.putEmailOtpAuthStateForEnrollment(enrollment, {
            otpFailureCount: 0,
            lastOtpFailureAtMs: undefined,
            otpLockedUntilMs: undefined,
          });
        }
      }

      const verifiedChallengeId = parseEmailOtpChallengeId(record.challengeId);
      if (!verifiedChallengeId.ok) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email OTP challenge record has an invalid challenge id',
        };
      }
      const successBase: VerifiedEmailOtpChallengeCodeSuccessBase = {
        challengeId: verifiedChallengeId.value,
        challengeSubjectId: challengeSubjectId.value,
        walletId: walletId.value,
        orgId: orgId.value,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
      if (record.email) successBase.email = record.email;
      if (verificationIntent.kind === 'registration') {
        const finalRegistrationChallengeProof = buildVerifiedEmailOtpRegistrationChallengeProof({
          record,
          challengeSubjectId: challengeSubjectId.value,
          proof: verificationIntent.binding,
          storedPurpose: readEmailOtpStoredChallengePurpose(record),
          allowWalletReroll: verificationIntent.allowWalletReroll,
        });
        if (!finalRegistrationChallengeProof) {
          return {
            ok: false,
            code: 'challenge_purpose_mismatch',
            message: 'Email OTP challenge is not valid for registration',
          };
        }
        return {
          ok: true,
          ...successBase,
          intent: 'registration',
          registrationChallengeProof: finalRegistrationChallengeProof,
        };
      }
      return {
        ok: true,
        ...successBase,
        intent: verificationIntent.kind,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to verify Email OTP challenge',
      };
    }
  }

  async verifyEmailOtpChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
    operation?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        loginGrant: string;
        grantExpiresAtMs: number;
        otpChannel: EmailOtpChannel;
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    const operationRaw = toOptionalTrimmedString(request.operation);
    const verified = await this.verifyEmailOtpChallengeCode({
      ...request,
      challengeSubjectId: request.userId,
      expectedAction: WALLET_EMAIL_OTP_ACTIONS.login,
      expectedOperation:
        operationRaw === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION ||
        operationRaw === WALLET_EMAIL_OTP_EXPORT_OPERATION
          ? operationRaw
          : WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }
    const otpConfig = this.resolveEmailOtpConfig();
    const grantToken = base64UrlEncode(crypto.getRandomValues(new Uint8Array(24)));
    const issuedAtMs = Date.now();
    const grantExpiresAtMs = issuedAtMs + otpConfig.grantTtlMs;
    await this.getEmailOtpGrantStore().put({
      version: 'email_otp_grant_v1',
      grantToken,
      userId: verified.challengeSubjectId,
      walletId: verified.walletId,
      orgId: verified.orgId,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      sessionHash: String(request.sessionHash || '').trim(),
      appSessionVersion: String(request.appSessionVersion || '').trim(),
      action: WALLET_EMAIL_OTP_ACTIONS.unseal,
      issuedAtMs,
      expiresAtMs: grantExpiresAtMs,
    });
    return {
      ok: true,
      challengeId: verified.challengeId,
      loginGrant: grantToken,
      grantExpiresAtMs,
      otpChannel: verified.otpChannel,
    };
  }

  async verifyEmailOtpDeviceRecoveryChallenge(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    challengeId?: unknown;
    otpCode?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        otpChannel: EmailOtpChannel;
        recoveryConsumeGrant: string;
        recoveryConsumeGrantExpiresAtMs: number;
        recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryChallengeEscrow[];
        enrollment: {
          walletId: string;
          providerUserId: string;
          orgId: string;
          enrollmentId: string;
          enrollmentVersion: string;
          enrollmentSealKeyVersion: string;
          signingRootId: string;
          signingRootVersion: string;
          recoveryWrappedEnrollmentEscrowCount: number;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    const verified = await this.verifyEmailOtpChallengeCode({
      ...request,
      challengeSubjectId: request.userId,
      expectedAction: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      expectedOperation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;
    const enrollment = await this.readActiveEmailOtpEnrollment({
      walletId: verified.walletId,
      orgId: verified.orgId,
      providerUserId: verified.challengeSubjectId,
    });
    if (!enrollment.ok) return enrollment;
    const recoveryWrappedEnrollmentEscrows =
      await this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore().listActiveByWallet(
        verified.walletId,
      );
    const scopedRecoveryWrappedEnrollmentEscrows = recoveryWrappedEnrollmentEscrows.filter(
      (record) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
          enrollment.enrollment,
        ),
    );
    if (scopedRecoveryWrappedEnrollmentEscrows.length <= 0) {
      return {
        ok: false,
        code: 'recovery_wrapped_escrows_missing',
        message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
      };
    }
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }
    const otpConfig = this.resolveEmailOtpConfig();
    const recoveryConsumeGrant = base64UrlEncode(crypto.getRandomValues(new Uint8Array(24)));
    const issuedAtMs = Date.now();
    const recoveryConsumeGrantExpiresAtMs = issuedAtMs + otpConfig.grantTtlMs;
    await this.getEmailOtpGrantStore().put({
      version: 'email_otp_grant_v1',
      grantToken: recoveryConsumeGrant,
      userId: verified.challengeSubjectId,
      walletId: verified.walletId,
      orgId: verified.orgId,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      sessionHash: String(request.sessionHash || '').trim(),
      appSessionVersion: String(request.appSessionVersion || '').trim(),
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      issuedAtMs,
      expiresAtMs: recoveryConsumeGrantExpiresAtMs,
    });
    return {
      ok: true,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      recoveryConsumeGrant,
      recoveryConsumeGrantExpiresAtMs,
      recoveryWrappedEnrollmentEscrows: scopedRecoveryWrappedEnrollmentEscrows.map(
        redactEmailOtpRecoveryChallengeEscrow,
      ),
      enrollment: {
        walletId: enrollment.enrollment.walletId,
        providerUserId: enrollment.enrollment.providerUserId,
        orgId: enrollment.enrollment.orgId,
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentVersion: enrollment.enrollment.enrollmentVersion,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        signingRootId: enrollment.enrollment.signingRootId,
        signingRootVersion: enrollment.enrollment.signingRootVersion,
        recoveryWrappedEnrollmentEscrowCount:
          enrollment.enrollment.recoveryWrappedEnrollmentEscrowCount,
      },
    };
  }

  private async validateEmailOtpEnrollmentMaterial(request: {
    recoveryWrappedEnrollmentEscrows?: unknown;
    enrollmentSealKeyVersion?: unknown;
    clientUnlockPublicKeyB64u?: unknown;
    unlockKeyVersion?: unknown;
    thresholdEcdsaClientVerifyingShareB64u?: unknown;
  }): Promise<
    | {
        ok: true;
        recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
        enrollmentSealKeyVersion: string;
        clientUnlockPublicKeyB64u: string;
        unlockKeyVersion: string;
        thresholdEcdsaClientVerifyingShareB64u: string;
      }
    | { ok: false; code: string; message: string }
  > {
    const enrollmentSealKeyVersion = toOptionalTrimmedString(request.enrollmentSealKeyVersion);
    const rawRecoveryWrappedEnrollmentEscrows = Array.isArray(
      request.recoveryWrappedEnrollmentEscrows,
    )
      ? request.recoveryWrappedEnrollmentEscrows
      : [];
    const parsedRecoveryWrappedEnrollmentEscrows = rawRecoveryWrappedEnrollmentEscrows
      .map((record) => parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary(record))
      .filter((record): record is EmailOtpRecoveryWrappedEnrollmentEscrowBoundary =>
        Boolean(record),
      );
    const recoveryWrappedEnrollmentEscrows = parsedRecoveryWrappedEnrollmentEscrows.map(
      (parsed) => parsed.record,
    );
    const clientUnlockPublicKeyB64u = toOptionalTrimmedString(request.clientUnlockPublicKeyB64u);
    const unlockKeyVersion = toOptionalTrimmedString(request.unlockKeyVersion);
    const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
      request.thresholdEcdsaClientVerifyingShareB64u,
    );
    if (
      rawRecoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
      recoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }
    if (!enrollmentSealKeyVersion) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'enrollmentSealKeyVersion is required',
      };
    }
    const escrowSetValidation = await this.validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
      parsedRecoveryWrappedEnrollmentEscrows,
    );
    if (!escrowSetValidation.ok) return escrowSetValidation;
    if (!clientUnlockPublicKeyB64u) {
      return { ok: false, code: 'invalid_body', message: 'clientUnlockPublicKeyB64u is required' };
    }
    if (!unlockKeyVersion) {
      return { ok: false, code: 'invalid_body', message: 'unlockKeyVersion is required' };
    }
    if (!thresholdEcdsaClientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u is required',
      };
    }

    let unlockPublicKeyBytes: Uint8Array;
    try {
      unlockPublicKeyBytes = base64UrlDecode(clientUnlockPublicKeyB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u must be valid base64url',
      };
    }
    if (unlockPublicKeyBytes.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
      };
    }
    try {
      await validateSecp256k1PublicKey33(unlockPublicKeyBytes);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'clientUnlockPublicKeyB64u is not a valid secp256k1 public key',
      };
    }

    let clientVerifyingShareBytes: Uint8Array;
    try {
      clientVerifyingShareBytes = base64UrlDecode(thresholdEcdsaClientVerifyingShareB64u);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u must be valid base64url',
      };
    }
    if (clientVerifyingShareBytes.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'thresholdEcdsaClientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
      };
    }
    try {
      await validateSecp256k1PublicKey33(clientVerifyingShareBytes);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'thresholdEcdsaClientVerifyingShareB64u is not a valid secp256k1 public key',
      };
    }

    return {
      ok: true,
      recoveryWrappedEnrollmentEscrows,
      enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u,
      unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u,
    };
  }

  private async validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
    records: EmailOtpRecoveryWrappedEnrollmentEscrowBoundary[],
  ): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
    const recoveryKeyIds = new Set<string>();
    const nonceB64us = new Set<string>();
    const first = records[0];
    if (!first) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }

    for (const boundary of records) {
      if (boundary.lifecycle.status !== 'active') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrows must be active at enrollment',
        };
      }
      const record = boundary.record;
      if (recoveryKeyIds.has(record.recoveryKeyId)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow recoveryKeyId values must be unique',
        };
      }
      recoveryKeyIds.add(record.recoveryKeyId);

      if (nonceB64us.has(record.nonceB64u)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow nonce values must be unique',
        };
      }
      nonceB64us.add(record.nonceB64u);

      if (
        record.walletId !== first.record.walletId ||
        record.userId !== first.record.userId ||
        record.authSubjectId !== first.record.authSubjectId ||
        record.authMethod !== first.record.authMethod ||
        record.enrollmentId !== first.record.enrollmentId ||
        record.enrollmentVersion !== first.record.enrollmentVersion ||
        record.enrollmentSealKeyVersion !== first.record.enrollmentSealKeyVersion ||
        record.signingRootId !== first.record.signingRootId ||
        record.signingRootVersion !== first.record.signingRootVersion
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow metadata must share one enrollment scope',
        };
      }

      const expectedAadHashB64u = base64UrlEncode(
        await sha256BytesPortable(encodeEmailOtpRecoveryWrappedEnrollmentAad(boundary.binding)),
      );
      if (record.aadHashB64u !== expectedAadHashB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow aadHashB64u does not match metadata',
        };
      }
    }

    if (
      recoveryKeyIds.size !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
      nonceB64us.size !== EMAIL_OTP_RECOVERY_KEY_COUNT
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} distinct recovery-wrapped enrollment escrows are required`,
      };
    }

    return { ok: true };
  }

  private emailOtpRecoveryEscrowMatchesEnrollment(
    boundary: EmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): boolean {
    const { auth, enrollment: bindingEnrollment, signingRoot } = boundary.binding;
    return (
      auth.walletId === enrollment.walletId &&
      auth.userId === enrollment.providerUserId &&
      auth.authSubjectId === enrollment.providerUserId &&
      bindingEnrollment.enrollmentId === enrollment.enrollmentId &&
      bindingEnrollment.enrollmentVersion === enrollment.enrollmentVersion &&
      bindingEnrollment.enrollmentSealKeyVersion === enrollment.enrollmentSealKeyVersion &&
      signingRoot.signingRootId === enrollment.signingRootId &&
      signingRoot.signingRootVersion === enrollment.signingRootVersion
    );
  }

  private async buildEmailOtpRegistrationEnrollmentPersistence(input: {
    walletId: string;
    orgId: string;
    authSubjectId: string;
    verifiedEmail: string;
    material: NonNullable<WalletRegistrationFinalizeRequest['emailOtpEnrollment']>;
    nowMs: number;
  }): Promise<
    | { ok: true; persistence: EmailOtpRegistrationEnrollmentPersistence }
    | { ok: false; code: string; message: string }
  > {
    const enrollmentMaterial = await this.validateEmailOtpEnrollmentMaterial(input.material);
    if (!enrollmentMaterial.ok) return enrollmentMaterial;
    const orgId = toOptionalTrimmedString(input.orgId) || '';
    const walletId = toOptionalTrimmedString(input.walletId) || '';
    const authSubjectId = toOptionalTrimmedString(input.authSubjectId) || '';
    const verifiedEmail = toOptionalTrimmedString(input.verifiedEmail)?.toLowerCase() || '';
    if (!orgId || !walletId || !authSubjectId || !verifiedEmail) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration enrollment requires wallet, org, and email identity',
      };
    }
    const existing = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    const existingState = await this.getEmailOtpAuthStateStore().get(walletId);
    const enrollmentScope = enrollmentMaterial.recoveryWrappedEnrollmentEscrows[0];
    if (!enrollmentScope) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }
    for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
      if (
        record.walletId !== walletId ||
        record.userId !== authSubjectId ||
        record.authSubjectId !== authSubjectId ||
        record.enrollmentSealKeyVersion !== enrollmentMaterial.enrollmentSealKeyVersion ||
        record.recoveryKeyStatus !== 'active'
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow metadata does not match registration',
        };
      }
    }
    const enrollment: EmailOtpWalletEnrollmentRecord = {
      version: 'email_otp_wallet_enrollment_v1',
      walletId,
      providerUserId: authSubjectId,
      orgId,
      verifiedEmail,
      enrollmentId: enrollmentScope.enrollmentId,
      enrollmentVersion: enrollmentScope.enrollmentVersion,
      enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
      signingRootId: enrollmentScope.signingRootId,
      signingRootVersion: enrollmentScope.signingRootVersion,
      recoveryWrappedEnrollmentEscrowCount:
        enrollmentMaterial.recoveryWrappedEnrollmentEscrows.length,
      clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
      unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u:
        enrollmentMaterial.thresholdEcdsaClientVerifyingShareB64u,
      createdAtMs: existing?.createdAtMs ?? input.nowMs,
      updatedAtMs: input.nowMs,
    };
    const existingProviderEnrollment =
      await this.getEmailOtpWalletEnrollmentStore().getByProviderUserId({
        providerUserId: enrollment.providerUserId,
        orgId: enrollment.orgId,
      });
    const recoveryWrappedEnrollmentEscrows =
      enrollmentMaterial.recoveryWrappedEnrollmentEscrows.map((record) => ({
        ...record,
        updatedAtMs: input.nowMs,
      }));
    const authState: EmailOtpAuthStateRecord = {
      version: 'email_otp_auth_state_v1',
      walletId: enrollment.walletId,
      providerUserId: enrollment.providerUserId,
      orgId: enrollment.orgId,
      createdAtMs:
        existingState &&
        existingState.providerUserId === enrollment.providerUserId &&
        existingState.orgId === enrollment.orgId
          ? existingState.createdAtMs
          : input.nowMs,
      updatedAtMs: input.nowMs,
      otpFailureCount: 0,
      lastOtpFailureAtMs: undefined,
      otpLockedUntilMs: undefined,
      ...(existingState?.lastEmailOtpLoginAtMs &&
      existingState.providerUserId === enrollment.providerUserId &&
      existingState.orgId === enrollment.orgId
        ? { lastEmailOtpLoginAtMs: existingState.lastEmailOtpLoginAtMs }
        : {}),
      ...(existingState?.lastStrongAuthAtMs &&
      existingState.providerUserId === enrollment.providerUserId &&
      existingState.orgId === enrollment.orgId
        ? { lastStrongAuthAtMs: existingState.lastStrongAuthAtMs }
        : {}),
    };
    return {
      ok: true,
      persistence: {
        ...(existingProviderEnrollment &&
        existingProviderEnrollment.walletId !== enrollment.walletId
          ? { previousProviderWalletId: existingProviderEnrollment.walletId }
          : {}),
        enrollment,
        recoveryWrappedEnrollmentEscrows,
        authState,
      },
    };
  }

  private async emailOtpEnrollmentPersistenceForRegistrationFinalize(input: {
    authority: RegistrationAuthority;
    request: WalletRegistrationFinalizeRequest;
    walletId: WalletId;
    orgId: string;
    nowMs: number;
  }): Promise<
    | { ok: true; persistence?: EmailOtpRegistrationEnrollmentPersistence }
    | { ok: false; code: string; message: string }
  > {
    if (input.authority.kind !== 'email_otp') {
      if (input.request.emailOtpEnrollment) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'emailOtpEnrollment is only valid for Email OTP registration',
        };
      }
      return { ok: true };
    }
    if (!input.request.emailOtpEnrollment) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration finalize requires emailOtpEnrollment',
      };
    }
    const backupAck = input.request.emailOtpBackupAck;
    if (!backupAck) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration finalize requires emailOtpBackupAck',
      };
    }
    if (
      input.authority.walletId !== input.walletId ||
      input.authority.finalWalletId !== input.walletId ||
      input.authority.orgId !== input.orgId
    ) {
      return {
        ok: false,
        code: 'authority_binding_mismatch',
        message: 'Email OTP registration authority does not match finalize scope',
      };
    }
    if (
      input.authority.proofKind === 'google_sso_registration' &&
      (backupAck.offerId !== input.authority.googleEmailOtpRegistrationOfferId ||
        backupAck.candidateId !== input.authority.googleEmailOtpRegistrationCandidateId)
    ) {
      return {
        ok: false,
        code: 'backup_ack_binding_mismatch',
        message: 'Email OTP recovery-code backup acknowledgement does not match the offer',
      };
    }
    if (
      input.authority.proofKind !== 'google_sso_registration' &&
      (backupAck.offerId || backupAck.candidateId)
    ) {
      return {
        ok: false,
        code: 'backup_ack_binding_mismatch',
        message: 'Email OTP recovery-code backup acknowledgement has unexpected offer metadata',
      };
    }
    if (backupAck.acknowledgedAtMs < backupAck.recoveryCodesIssuedAtMs) {
      return {
        ok: false,
        code: 'backup_ack_invalid',
        message: 'Email OTP recovery-code backup acknowledgement predates code issuance',
      };
    }
    const authSubjectId = toOptionalTrimmedString(input.authority.providerSubject) || '';
    const verifiedEmail = toOptionalTrimmedString(input.authority.email)?.toLowerCase() || '';
    const enrollment = await this.buildEmailOtpRegistrationEnrollmentPersistence({
      walletId: input.walletId,
      orgId: input.orgId,
      authSubjectId,
      verifiedEmail,
      material: input.request.emailOtpEnrollment,
      nowMs: input.nowMs,
    });
    if (!enrollment.ok) return enrollment;
    const firstEscrow = enrollment.persistence.recoveryWrappedEnrollmentEscrows[0];
    if (!firstEscrow || firstEscrow.issuedAtMs !== backupAck.recoveryCodesIssuedAtMs) {
      return {
        ok: false,
        code: 'backup_ack_binding_mismatch',
        message:
          'Email OTP recovery-code backup acknowledgement timestamp does not match enrollment',
      };
    }
    return { ok: true, persistence: enrollment.persistence };
  }

  private async resolveEmailOtpRegistrationChallengeProof(
    input: EmailOtpRegistrationChallengeProofInput,
  ): Promise<EmailOtpRegistrationChallengeProofResult> {
    switch (input.kind) {
      case 'google_registration_attempt': {
        const attempt = await this.getEmailOtpRegistrationAttemptStore().get(
          input.registrationAttemptId,
        );
        if (!attempt) {
          return {
            ok: false,
            code: 'registration_attempt_missing',
            message: 'Google Email OTP registration attempt expired or was not found',
          };
        }
        if (attempt.providerSubject !== input.providerSubject) {
          return {
            ok: false,
            code: 'challenge_subject_mismatch',
            message: 'Email OTP registration attempt does not match the provider subject',
          };
        }
        if (attempt.expiresAtMs <= Date.now()) {
          return {
            ok: false,
            code: 'registration_attempt_expired',
            message: 'Google Email OTP registration attempt expired',
          };
        }
        if (attempt.walletId !== input.walletId) {
          return {
            ok: false,
            code: 'wallet_identity_mismatch',
            message: 'registrationAttemptId does not match walletId',
          };
        }
        return {
          ok: true,
          proof: {
            kind: 'registration_attempt',
            providerSubject: input.providerSubject,
            challengeSubjectId: input.challengeSubjectId,
            proofEmail: attempt.email.toLowerCase(),
            registrationAttemptId: input.registrationAttemptId,
            challengeId: input.challengeId,
            finalWalletId: input.walletId,
            orgId: input.orgId,
            appSessionVersion: input.appSessionVersion,
          },
        };
      }
      case 'direct_proof_email':
        return {
          ok: true,
          proof: {
            kind: 'direct_proof_email',
            providerSubject: input.providerSubject,
            challengeSubjectId: input.challengeSubjectId,
            proofEmail: input.proofEmail,
            challengeId: input.challengeId,
            finalWalletId: input.finalWalletId,
            orgId: input.orgId,
            appSessionVersion: input.appSessionVersion,
          },
        };
    }
    return assertNever(input);
  }

  async verifyEmailOtpEnrollment(request: {
    /** Provider subject from the app-session JWT that requested the registration OTP. */
    providerSubject: unknown;
    walletId: unknown;
    orgId: unknown;
    challengeId: unknown;
    otpCode: unknown;
    otpChannel: unknown;
    sessionHash: unknown;
    appSessionVersion: unknown;
    /** Email asserted by the registration proof. It must match the challenged email. */
    proofEmail?: unknown;
    clientIp?: unknown;
    recoveryWrappedEnrollmentEscrows?: unknown;
    enrollmentSealKeyVersion?: unknown;
    clientUnlockPublicKeyB64u?: unknown;
    unlockKeyVersion?: unknown;
    thresholdEcdsaClientVerifyingShareB64u?: unknown;
    googleEmailOtpRegistrationAttemptId?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        otpChannel: EmailOtpChannel;
        enrollment: {
          createdAtMs: number;
          updatedAtMs: number;
          enrollmentSealKeyVersion: string;
          unlockKeyVersion: string;
        };
      }
    | {
        ok: false;
        code: string;
        message: string;
        attemptsRemaining?: number;
        lockedUntilMs?: number;
      }
  > {
    const proofInput = parseRawEmailOtpRegistrationChallengeProofInput(request);
    if (!proofInput.ok) return proofInput;
    const proofResult = await this.resolveEmailOtpRegistrationChallengeProof(proofInput.input);
    if (!proofResult.ok) return proofResult;
    const verified = await this.verifyEmailOtpChallengeCode({
      ...request,
      challengeSubjectId: proofResult.proof.challengeSubjectId,
      registrationChallengeProof: proofResult.proof,
      allowRegistrationChallengeReroll: true,
      expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
    });
    if (!verified.ok) return verified;
    const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase();
    if (!verifiedEmail) {
      return {
        ok: false,
        code: 'internal',
        message: 'Email OTP enrollment verification did not include a verified email',
      };
    }
    const enrollmentMaterial = await this.validateEmailOtpEnrollmentMaterial(request);
    if (!enrollmentMaterial.ok) return enrollmentMaterial;
    const orgId = toOptionalTrimmedString(verified.orgId) || '';
    if (!orgId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP enrollment requires orgId tenant scope',
      };
    }
    const canonicalWallet = await this.getWalletStore().getWallet({
      walletId: verified.walletId as WalletId,
    });
    if (!canonicalWallet) {
      return {
        ok: false,
        code: 'wallet_registration_incomplete',
        message:
          'Email OTP enrollment requires an existing canonical wallet. New wallet registration must finalize through /wallets/register/finalize.',
      };
    }
    const existing = await this.getEmailOtpWalletEnrollmentStore().get(verified.walletId);
    const existingState = await this.getEmailOtpAuthStateStore().get(verified.walletId);
    const nowMs = Date.now();
    const enrollmentScope = enrollmentMaterial.recoveryWrappedEnrollmentEscrows[0];
    if (!enrollmentScope) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }
    for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
      if (
        record.walletId !== verified.walletId ||
        record.userId !== verified.challengeSubjectId ||
        record.authSubjectId !== verified.challengeSubjectId ||
        record.enrollmentSealKeyVersion !== enrollmentMaterial.enrollmentSealKeyVersion ||
        record.recoveryKeyStatus !== 'active'
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-wrapped enrollment escrow metadata does not match enrollment',
        };
      }
    }
    const enrollmentRecord: EmailOtpWalletEnrollmentRecord = {
      version: 'email_otp_wallet_enrollment_v1',
      walletId: verified.walletId,
      providerUserId: verified.challengeSubjectId,
      orgId,
      verifiedEmail,
      enrollmentId: enrollmentScope.enrollmentId,
      enrollmentVersion: enrollmentScope.enrollmentVersion,
      enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
      signingRootId: enrollmentScope.signingRootId,
      signingRootVersion: enrollmentScope.signingRootVersion,
      recoveryWrappedEnrollmentEscrowCount:
        enrollmentMaterial.recoveryWrappedEnrollmentEscrows.length,
      clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
      unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u:
        enrollmentMaterial.thresholdEcdsaClientVerifyingShareB64u,
      createdAtMs: existing?.createdAtMs ?? nowMs,
      updatedAtMs: nowMs,
    };
    const existingProviderEnrollment =
      await this.getEmailOtpWalletEnrollmentStore().getByProviderUserId({
        providerUserId: enrollmentRecord.providerUserId,
        orgId: enrollmentRecord.orgId,
      });
    if (
      existingProviderEnrollment &&
      existingProviderEnrollment.walletId !== enrollmentRecord.walletId
    ) {
      await this.getEmailOtpWalletEnrollmentStore().del(existingProviderEnrollment.walletId);
    }
    await this.getEmailOtpWalletEnrollmentStore().put(enrollmentRecord);
    const recoveryWrappedEnrollmentEscrowStore =
      this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore();
    await recoveryWrappedEnrollmentEscrowStore.putMany(
      enrollmentMaterial.recoveryWrappedEnrollmentEscrows.map((record) => ({
        ...record,
        updatedAtMs: nowMs,
      })),
    );
    const activeRecoveryWrappedEnrollmentEscrowCount = (
      await recoveryWrappedEnrollmentEscrowStore.listByWallet(verified.walletId)
    ).filter(
      (record) =>
        record.recoveryKeyStatus === 'active' &&
        this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
          enrollmentRecord,
        ),
    ).length;
    if (activeRecoveryWrappedEnrollmentEscrowCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
      return {
        ok: false,
        code: 'internal',
        message: `Email OTP enrollment persisted ${activeRecoveryWrappedEnrollmentEscrowCount} active recovery-wrapped escrows; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
      };
    }
    await this.getEmailOtpAuthStateStore().put({
      version: 'email_otp_auth_state_v1',
      walletId: enrollmentRecord.walletId,
      providerUserId: enrollmentRecord.providerUserId,
      orgId: enrollmentRecord.orgId,
      createdAtMs:
        existingState &&
        existingState.providerUserId === enrollmentRecord.providerUserId &&
        existingState.orgId === enrollmentRecord.orgId
          ? existingState.createdAtMs
          : nowMs,
      updatedAtMs: nowMs,
      otpFailureCount: 0,
      lastOtpFailureAtMs: undefined,
      otpLockedUntilMs: undefined,
      ...(existingState?.lastEmailOtpLoginAtMs &&
      existingState.providerUserId === enrollmentRecord.providerUserId &&
      existingState.orgId === enrollmentRecord.orgId
        ? { lastEmailOtpLoginAtMs: existingState.lastEmailOtpLoginAtMs }
        : {}),
      ...(existingState?.lastStrongAuthAtMs &&
      existingState.providerUserId === enrollmentRecord.providerUserId &&
      existingState.orgId === enrollmentRecord.orgId
        ? { lastStrongAuthAtMs: existingState.lastStrongAuthAtMs }
        : {}),
    });
    const completedRegistration = await this.completeGoogleEmailOtpRegistrationAttempt({
      registrationAttemptId: request.googleEmailOtpRegistrationAttemptId,
      walletId: verified.walletId,
    });
    if (!completedRegistration.ok) return completedRegistration;
    return {
      ok: true,
      walletId: verified.walletId,
      otpChannel: verified.otpChannel,
      enrollment: {
        createdAtMs: existing?.createdAtMs ?? nowMs,
        updatedAtMs: nowMs,
        enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
        unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
      },
    };
  }

  async readEmailOtpEnrollment(request: { walletId?: unknown; orgId: unknown }): Promise<
    | {
        ok: true;
        enrollment: EmailOtpWalletEnrollmentRecord;
      }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    const orgId = toOptionalTrimmedString(request.orgId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) {
      return {
        ok: false,
        code: 'tenant_scope_mismatch',
        message: 'Email OTP enrollment does not match the requested orgId',
      };
    }
    return { ok: true, enrollment };
  }

  async readActiveEmailOtpEnrollment(request: {
    walletId?: unknown;
    orgId: unknown;
    providerUserId?: unknown;
  }): Promise<
    | {
        ok: true;
        enrollment: EmailOtpWalletEnrollmentRecord;
      }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    const orgId = toOptionalTrimmedString(request.orgId);
    const providerUserId = toOptionalTrimmedString(request.providerUserId) || undefined;
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) {
      return {
        ok: false,
        code: 'tenant_scope_mismatch',
        message: 'Email OTP enrollment does not match the requested orgId',
      };
    }
    if (providerUserId && enrollment.providerUserId !== providerUserId) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not match the requested provider user',
      };
    }
    return { ok: true, enrollment };
  }

  async isEmailOtpStrongAuthRequired(request: { walletId?: unknown }): Promise<
    | {
        ok: true;
        required: boolean;
        walletId: string;
        lastEmailOtpLoginAtMs?: number;
        lastStrongAuthAtMs?: number;
      }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) {
      return { ok: true, required: false, walletId };
    }
    const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment);
    if (!authState.ok) return authState;
    const state = authState.state;
    if (!state) {
      return { ok: true, required: false, walletId };
    }
    const lastEmailOtpLoginAtMs =
      typeof state.lastEmailOtpLoginAtMs === 'number' ? state.lastEmailOtpLoginAtMs : undefined;
    const lastStrongAuthAtMs =
      typeof state.lastStrongAuthAtMs === 'number' ? state.lastStrongAuthAtMs : undefined;
    return {
      ok: true,
      required: Boolean(
        lastEmailOtpLoginAtMs &&
        (!lastStrongAuthAtMs || lastEmailOtpLoginAtMs > lastStrongAuthAtMs),
      ),
      walletId,
      ...(lastEmailOtpLoginAtMs ? { lastEmailOtpLoginAtMs } : {}),
      ...(lastStrongAuthAtMs ? { lastStrongAuthAtMs } : {}),
    };
  }

  async markEmailOtpStrongAuthSatisfied(request: {
    walletId?: unknown;
  }): Promise<
    | { ok: true; walletId: string; lastStrongAuthAtMs?: number }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(request.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.getEmailOtpWalletEnrollmentStore().get(walletId);
    if (!enrollment) return { ok: true, walletId };
    const nowMs = Date.now();
    await this.putEmailOtpAuthStateForEnrollment(enrollment, {
      lastStrongAuthAtMs: nowMs,
    });
    return { ok: true, walletId, lastStrongAuthAtMs: nowMs };
  }

  async consumeEmailOtpGrant(request: {
    loginGrant?: unknown;
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    otpChannel?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        otpChannel: EmailOtpChannel;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const loginGrant = toOptionalTrimmedString(request.loginGrant);
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const otpChannel = toOptionalTrimmedString(request.otpChannel);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      if (!loginGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing loginGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'otpChannel must be email_otp',
        };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const record = await this.getEmailOtpGrantStore().consume(loginGrant);
      if (!record) {
        return {
          ok: false,
          code: 'login_grant_invalid_or_expired',
          message: 'Login grant is invalid or expired',
        };
      }

      if (Date.now() > record.expiresAtMs) {
        return {
          ok: false,
          code: 'login_grant_invalid_or_expired',
          message: 'Login grant is invalid or expired',
        };
      }
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.unseal) {
        return {
          ok: false,
          code: 'login_grant_invalid_or_expired',
          message: 'Login grant is invalid or expired',
        };
      }

      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      return {
        ok: true,
        challengeId: record.challengeId,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to consume Email OTP grant',
      };
    }
  }

  async getEmailOtpRecoveryCodeStatus(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
  }): Promise<
    | {
        ok: true;
        status: 'ready' | 'incomplete' | 'not_enrolled';
        walletId: string;
        enrollmentId: string;
        enrollmentSealKeyVersion: string;
        expectedRecoveryCodeCount: number;
        activeRecoveryCodeCount: number;
        consumedRecoveryCodeCount: number;
        revokedRecoveryCodeCount: number;
        totalRecoveryCodeCount: number;
        issuedAtMs: number | null;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) {
        if (enrollment.code === 'not_found') {
          return {
            ok: true,
            status: 'not_enrolled',
            walletId,
            enrollmentId: '',
            enrollmentSealKeyVersion: '',
            expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
            activeRecoveryCodeCount: 0,
            consumedRecoveryCodeCount: 0,
            revokedRecoveryCodeCount: 0,
            totalRecoveryCodeCount: 0,
            issuedAtMs: null,
          };
        }
        return enrollment;
      }

      const records = (
        await this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore().listByWallet(walletId)
      )
        .map((record) => emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record))
        .filter((record) =>
          this.emailOtpRecoveryEscrowMatchesEnrollment(record, enrollment.enrollment),
        )
        .map((boundary) => boundary.record);
      const activeRecords = records.filter((record) => record.recoveryKeyStatus === 'active');
      const consumedRecords = records.filter((record) => record.recoveryKeyStatus === 'consumed');
      const revokedRecords = records.filter((record) => record.recoveryKeyStatus === 'revoked');
      const issuedAtValues = records.map((record) => record.issuedAtMs);
      const status = activeRecords.length === EMAIL_OTP_RECOVERY_KEY_COUNT ? 'ready' : 'incomplete';
      return {
        ok: true,
        status,
        walletId,
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        activeRecoveryCodeCount: activeRecords.length,
        consumedRecoveryCodeCount: consumedRecords.length,
        revokedRecoveryCodeCount: revokedRecords.length,
        totalRecoveryCodeCount: records.length,
        issuedAtMs: issuedAtValues.length > 0 ? Math.min(...issuedAtValues) : null,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to read Email OTP recovery-code status',
      };
    }
  }

  async consumeEmailOtpRecoveryKey(request: {
    recoveryConsumeGrant?: unknown;
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    recoveryKeyId?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        recoveryKeyId: string;
        consumedAtMs: number;
        activeRecoveryWrappedEnrollmentEscrowCount: number;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(request.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const recoveryKeyId = toOptionalTrimmedString(request.recoveryKeyId);
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!recoveryKeyId) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryKeyId' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const record = await this.getEmailOtpGrantStore().consume(recoveryConsumeGrant);
      if (!record || Date.now() > record.expiresAtMs) {
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }

      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const recoveryWrappedEnrollmentEscrowStore =
        this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore();
      const recoveryRecord = await recoveryWrappedEnrollmentEscrowStore.get({
        walletId,
        recoveryKeyId,
      });
      if (!recoveryRecord || recoveryRecord.recoveryKeyStatus !== 'active') {
        return {
          ok: false,
          code: 'recovery_key_not_active',
          message: 'Recovery key is not active',
        };
      }
      if (
        !this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(recoveryRecord),
          enrollment.enrollment,
        )
      ) {
        return {
          ok: false,
          code: 'recovery_key_binding_mismatch',
          message: 'Recovery key is not valid for this Email OTP enrollment',
        };
      }

      const consumedAtMs = Date.now();
      await recoveryWrappedEnrollmentEscrowStore.put({
        ...recoveryRecord,
        recoveryKeyStatus: 'consumed',
        consumedAtMs,
        updatedAtMs: consumedAtMs,
      });
      await this.putEmailOtpAuthStateForEnrollment(enrollment.enrollment, {
        lastStrongAuthAtMs: consumedAtMs,
      });
      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await recoveryWrappedEnrollmentEscrowStore.listActiveByWallet(walletId)
      ).filter((activeRecord) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(activeRecord),
          enrollment.enrollment,
        ),
      ).length;

      return {
        ok: true,
        walletId,
        recoveryKeyId,
        consumedAtMs,
        activeRecoveryWrappedEnrollmentEscrowCount,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to consume Email OTP recovery key',
      };
    }
  }

  async rotateEmailOtpRecoveryKeys(request: {
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    enrollmentId?: unknown;
    enrollmentSealKeyVersion?: unknown;
    recoveryWrappedEnrollmentEscrows?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        enrollmentId: string;
        enrollmentSealKeyVersion: string;
        activeRecoveryCodeCount: number;
        revokedRecoveryCodeCount: number;
        totalRecoveryCodeCount: number;
        issuedAtMs: number;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const enrollmentId = toOptionalTrimmedString(request.enrollmentId);
      const enrollmentSealKeyVersion = toOptionalTrimmedString(request.enrollmentSealKeyVersion);
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!enrollmentId) {
        return { ok: false, code: 'invalid_body', message: 'Missing enrollmentId' };
      }
      if (!enrollmentSealKeyVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing enrollmentSealKeyVersion' };
      }
      const rawEscrows = Array.isArray(request.recoveryWrappedEnrollmentEscrows)
        ? request.recoveryWrappedEnrollmentEscrows
        : [];
      if (rawEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return {
          ok: false,
          code: 'invalid_body',
          message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
        };
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;
      if (
        enrollment.enrollment.enrollmentId !== enrollmentId ||
        enrollment.enrollment.enrollmentSealKeyVersion !== enrollmentSealKeyVersion
      ) {
        return {
          ok: false,
          code: 'recovery_rotation_binding_mismatch',
          message: 'Recovery-code rotation does not match the active Email OTP enrollment',
        };
      }

      const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment.enrollment);
      if (!authState.ok) return authState;
      const lastStrongAuthAtMs =
        typeof authState.state?.lastStrongAuthAtMs === 'number'
          ? authState.state.lastStrongAuthAtMs
          : 0;
      const nowMs = Date.now();
      const otpConfig = this.resolveEmailOtpConfig();
      if (!lastStrongAuthAtMs || nowMs > lastStrongAuthAtMs + otpConfig.grantTtlMs) {
        return {
          ok: false,
          code: 'fresh_auth_required',
          message: 'Fresh account authentication is required to rotate recovery codes',
        };
      }

      const issuedAtMs = nowMs;
      const recoveryKeyIds = new Set<string>();
      const nonceB64us = new Set<string>();
      const nextActiveRecords = [];
      for (const raw of rawEscrows) {
        const obj =
          raw && typeof raw === 'object' && !Array.isArray(raw)
            ? (raw as Record<string, unknown>)
            : null;
        if (!obj) {
          return { ok: false, code: 'invalid_body', message: 'Invalid recovery escrow input' };
        }
        const recoveryKeyId = toOptionalTrimmedString(obj.recoveryKeyId);
        const nonceB64u = toOptionalTrimmedString(obj.nonceB64u);
        const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
          obj.wrappedDeviceEnrollmentEscrowB64u,
        );
        const aadHashB64u = toOptionalTrimmedString(obj.aadHashB64u);
        if (!recoveryKeyId || !nonceB64u || !wrappedDeviceEnrollmentEscrowB64u || !aadHashB64u) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Recovery rotation escrow input is missing required fields',
          };
        }
        if (recoveryKeyIds.has(recoveryKeyId)) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Recovery rotation recoveryKeyId values must be unique',
          };
        }
        if (nonceB64us.has(nonceB64u)) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Recovery rotation nonce values must be unique',
          };
        }
        try {
          base64UrlDecode(nonceB64u);
          base64UrlDecode(wrappedDeviceEnrollmentEscrowB64u);
          base64UrlDecode(aadHashB64u);
        } catch {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Recovery rotation escrow input must use base64url fields',
          };
        }
        recoveryKeyIds.add(recoveryKeyId);
        nonceB64us.add(nonceB64u);
        const binding = buildEmailOtpRecoveryWrapBinding({
          walletId: enrollment.enrollment.walletId,
          userId: enrollment.enrollment.providerUserId,
          authSubjectId: enrollment.enrollment.providerUserId,
          authMethod: 'google_sso_email_otp',
          enrollmentId: enrollment.enrollment.enrollmentId,
          enrollmentVersion: enrollment.enrollment.enrollmentVersion,
          enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
          signingRootId: enrollment.enrollment.signingRootId,
          signingRootVersion: enrollment.enrollment.signingRootVersion,
          recoveryKeyId,
        });
        const expectedAadHashB64u = base64UrlEncode(
          await sha256BytesPortable(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)),
        );
        if (aadHashB64u !== expectedAadHashB64u) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Recovery rotation aadHashB64u does not match enrollment metadata',
          };
        }
        nextActiveRecords.push({
          version: 'email_otp_recovery_wrapped_enrollment_escrow_v1' as const,
          alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
          secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
          escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
          walletId: enrollment.enrollment.walletId,
          userId: enrollment.enrollment.providerUserId,
          authSubjectId: enrollment.enrollment.providerUserId,
          authMethod: 'google_sso_email_otp' as const,
          enrollmentId: enrollment.enrollment.enrollmentId,
          enrollmentVersion: enrollment.enrollment.enrollmentVersion,
          enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
          signingRootId: enrollment.enrollment.signingRootId,
          signingRootVersion: enrollment.enrollment.signingRootVersion,
          recoveryKeyId,
          recoveryKeyStatus: 'active' as const,
          nonceB64u,
          wrappedDeviceEnrollmentEscrowB64u,
          aadHashB64u,
          issuedAtMs,
          updatedAtMs: issuedAtMs,
        });
      }

      const store = this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore();
      const oldActiveRecords = (await store.listActiveByWallet(walletId)).filter((record) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
          enrollment.enrollment,
        ),
      );
      const revokedRecords = oldActiveRecords.map((record) => ({
        version: record.version,
        alg: record.alg,
        secretKind: record.secretKind,
        escrowKind: record.escrowKind,
        walletId: record.walletId,
        userId: record.userId,
        authSubjectId: record.authSubjectId,
        authMethod: record.authMethod,
        enrollmentId: record.enrollmentId,
        enrollmentVersion: record.enrollmentVersion,
        enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
        signingRootId: record.signingRootId,
        signingRootVersion: record.signingRootVersion,
        recoveryKeyId: record.recoveryKeyId,
        ...(record.recoveryKeyLabel ? { recoveryKeyLabel: record.recoveryKeyLabel } : {}),
        recoveryKeyStatus: 'revoked' as const,
        nonceB64u: record.nonceB64u,
        wrappedDeviceEnrollmentEscrowB64u: record.wrappedDeviceEnrollmentEscrowB64u,
        aadHashB64u: record.aadHashB64u,
        issuedAtMs: record.issuedAtMs,
        updatedAtMs: issuedAtMs,
        revokedAtMs: issuedAtMs,
      }));
      await store.putMany([...revokedRecords, ...nextActiveRecords]);
      const activeRecoveryCodeCount = (await store.listActiveByWallet(walletId)).filter((record) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
          enrollment.enrollment,
        ),
      ).length;
      if (activeRecoveryCodeCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return {
          ok: false,
          code: 'internal',
          message: `Email OTP recovery-code rotation left ${activeRecoveryCodeCount} active codes; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
        };
      }
      const totalRecoveryCodeCount = (await store.listByWallet(walletId)).filter((record) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
          enrollment.enrollment,
        ),
      ).length;
      return {
        ok: true,
        walletId,
        enrollmentId,
        enrollmentSealKeyVersion,
        activeRecoveryCodeCount,
        revokedRecoveryCodeCount: revokedRecords.length,
        totalRecoveryCodeCount,
        issuedAtMs,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to rotate Email OTP recovery codes',
      };
    }
  }

  async recordEmailOtpRecoveryKeyAttemptFailure(request: {
    recoveryConsumeGrant?: unknown;
    userId?: unknown;
    walletId?: unknown;
    orgId?: unknown;
    sessionHash?: unknown;
    appSessionVersion?: unknown;
    clientIp?: unknown;
  }): Promise<
    | {
        ok: true;
        walletId: string;
        recordedAtMs: number;
      }
    | { ok: false; code: string; message: string; retryAfterMs?: number; resetAtMs?: number }
  > {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(request.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(request.userId);
      const walletId = toOptionalTrimmedString(request.walletId);
      const orgId = toOptionalTrimmedString(request.orgId) || '';
      const sessionHash = toOptionalTrimmedString(request.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
      const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const record = await this.getEmailOtpGrantStore().get(recoveryConsumeGrant);
      if (!record || Date.now() > record.expiresAtMs) {
        if (record && Date.now() > record.expiresAtMs) {
          await this.getEmailOtpGrantStore().del(recoveryConsumeGrant);
        }
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return {
          ok: false,
          code: 'recovery_consume_grant_invalid_or_expired',
          message: 'Recovery consume grant is invalid or expired',
        };
      }

      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'recoveryKeyAttempt',
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await this.getEmailOtpRecoveryWrappedEnrollmentEscrowStore().listActiveByWallet(walletId)
      ).filter((activeRecord) =>
        this.emailOtpRecoveryEscrowMatchesEnrollment(
          emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(activeRecord),
          enrollment.enrollment,
        ),
      ).length;
      if (activeRecoveryWrappedEnrollmentEscrowCount <= 0) {
        return {
          ok: false,
          code: 'recovery_wrapped_escrows_missing',
          message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
        };
      }

      return {
        ok: true,
        walletId,
        recordedAtMs: Date.now(),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to record Email OTP recovery-key failure',
      };
    }
  }

  async readEmailOtpOutboxEntry(request: {
    challengeId?: unknown;
    userId?: unknown;
    walletId?: unknown;
  }): Promise<
    | {
        ok: true;
        challengeId: string;
        walletId: string;
        userId: string;
        otpChannel: EmailOtpChannel;
        emailHint: string;
        otpCode: string;
        expiresAtMs: number;
      }
    | { ok: false; code: string; message: string }
  > {
    const config = this.resolveEmailOtpConfig();
    if (!config.devOutboxEnabled) {
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP dev outbox is not enabled',
      };
    }

    const challengeId = toOptionalTrimmedString(request.challengeId);
    const userId = toOptionalTrimmedString(request.userId);
    const walletId = toOptionalTrimmedString(request.walletId);
    if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };

    const entry = this.emailOtpMemoryOutbox.get(challengeId);
    if (!entry) {
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry was not found' };
    }
    if (entry.userId !== userId || entry.walletId !== walletId) {
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP outbox entry was not found',
      };
    }
    if (Date.now() > entry.expiresAtMs) {
      this.emailOtpMemoryOutbox.delete(challengeId);
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry expired' };
    }
    return {
      ok: true,
      challengeId,
      walletId,
      userId,
      otpChannel: entry.otpChannel,
      emailHint: entry.emailHint,
      otpCode: entry.otpCode,
      expiresAtMs: entry.expiresAtMs,
    };
  }

  async removeEmailOtpServerSeal(request: {
    wrappedCiphertext?: unknown;
  }): Promise<
    | { ok: true; ciphertext: string; enrollmentSealKeyVersion: string }
    | { ok: false; code: string; message: string }
  > {
    try {
      const wrappedCiphertext = toOptionalTrimmedString(request.wrappedCiphertext);
      if (!wrappedCiphertext) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing wrappedCiphertext',
        };
      }
      const shamir = this.createEmailOtpShamirCipher();
      if (!shamir.ok) return shamir;
      const removed = await shamir.cipher.run({
        operation: 'remove-server-seal',
        thresholdSessionId: 'email-otp-unseal',
        ciphertext: wrappedCiphertext,
        keyVersion: shamir.keyVersion,
        auth: { userId: 'email_otp', claims: {} },
      });
      if (!removed.ok) return removed;
      return {
        ok: true,
        ciphertext: removed.ciphertext,
        enrollmentSealKeyVersion: removed.keyVersion || shamir.keyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to remove Email OTP server seal',
      };
    }
  }

  async applyEmailOtpServerSeal(request: {
    wrappedCiphertext?: unknown;
  }): Promise<
    | { ok: true; ciphertext: string; enrollmentSealKeyVersion: string }
    | { ok: false; code: string; message: string }
  > {
    try {
      const wrappedCiphertext = toOptionalTrimmedString(request.wrappedCiphertext);
      if (!wrappedCiphertext) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing wrappedCiphertext',
        };
      }
      const shamir = this.createEmailOtpShamirCipher();
      if (!shamir.ok) return shamir;
      const applied = await shamir.cipher.run({
        operation: 'apply-server-seal',
        thresholdSessionId: 'email-otp-enroll',
        ciphertext: wrappedCiphertext,
        keyVersion: shamir.keyVersion,
        auth: { userId: 'email_otp', claims: {} },
      });
      if (!applied.ok) return applied;
      return {
        ok: true,
        ciphertext: applied.ciphertext,
        enrollmentSealKeyVersion: applied.keyVersion || shamir.keyVersion,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to apply Email OTP server seal',
      };
    }
  }

  private async getGoogleJwks(): Promise<{
    keysByKid: Map<string, JsonWebKey>;
    expiresAtMs: number;
  }> {
    const now = Date.now();
    if (this.googleJwksCache && now < this.googleJwksCache.expiresAtMs) {
      return this.googleJwksCache;
    }
    if (this.googleJwksFetchPromise) return this.googleJwksFetchPromise;

    this.googleJwksFetchPromise = (async () => {
      const resp = await fetch('https://www.googleapis.com/oauth2/v3/certs');
      const text = await resp.text();
      if (!resp.ok) {
        throw new Error(
          `Google OIDC certs fetch failed (HTTP ${resp.status}): ${text.slice(0, 200)}`,
        );
      }
      let json: unknown;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        throw new Error('Google OIDC certs returned non-JSON response');
      }
      if (!isObject(json)) {
        throw new Error('Google OIDC certs returned invalid JSON shape');
      }
      const keysRaw = (json as { keys?: unknown }).keys;
      if (!Array.isArray(keysRaw)) {
        throw new Error('Google OIDC certs missing "keys" array');
      }
      const keysByKid = new Map<string, JsonWebKey>();
      for (const rawKey of keysRaw) {
        if (!isObject(rawKey)) continue;
        const kid = toOptionalTrimmedString((rawKey as { kid?: unknown }).kid);
        const kty = toOptionalTrimmedString((rawKey as { kty?: unknown }).kty);
        const use = toOptionalTrimmedString((rawKey as { use?: unknown }).use);
        const alg = toOptionalTrimmedString((rawKey as { alg?: unknown }).alg);
        const n = toOptionalTrimmedString((rawKey as { n?: unknown }).n);
        const e = toOptionalTrimmedString((rawKey as { e?: unknown }).e);
        if (!kid || kty !== 'RSA' || use !== 'sig' || alg !== 'RS256' || !n || !e) continue;
        keysByKid.set(kid, rawKey as unknown as JsonWebKey);
      }
      if (!keysByKid.size) {
        throw new Error('Google OIDC certs returned no usable RSA keys');
      }

      const maxAgeSec = parseCacheControlMaxAgeSec(resp.headers.get('cache-control')) || 60 * 60;
      const expiresAtMs = now + maxAgeSec * 1000;
      const value = { keysByKid, expiresAtMs };
      this.googleJwksCache = value;
      return value;
    })();

    try {
      return await this.googleJwksFetchPromise;
    } finally {
      this.googleJwksFetchPromise = null;
    }
  }

  private async getOidcJwksByUrl(jwksUrl: string): Promise<{
    keysByKid: Map<string, JsonWebKey>;
    expiresAtMs: number;
  }> {
    const url = String(jwksUrl || '').trim();
    if (!url) throw new Error('Missing OIDC JWKS URL');

    const now = Date.now();
    const cached = this.oidcJwksCacheByUrl.get(url) || null;
    if (cached && now < cached.expiresAtMs) return cached;

    const inflight = this.oidcJwksFetchPromiseByUrl.get(url) || null;
    if (inflight) return inflight;

    const fetchPromise = (async () => {
      const resp = await fetch(url);
      const text = await resp.text();
      if (!resp.ok) {
        throw new Error(`OIDC JWKS fetch failed (HTTP ${resp.status}): ${text.slice(0, 200)}`);
      }
      let json: unknown;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        throw new Error('OIDC JWKS returned non-JSON response');
      }
      if (!isObject(json)) {
        throw new Error('OIDC JWKS returned invalid JSON shape');
      }
      const keysRaw = (json as { keys?: unknown }).keys;
      if (!Array.isArray(keysRaw)) {
        throw new Error('OIDC JWKS missing "keys" array');
      }
      const keysByKid = new Map<string, JsonWebKey>();
      for (const rawKey of keysRaw) {
        if (!isObject(rawKey)) continue;
        const kid = toOptionalTrimmedString((rawKey as { kid?: unknown }).kid);
        const kty = toOptionalTrimmedString((rawKey as { kty?: unknown }).kty);
        const use = toOptionalTrimmedString((rawKey as { use?: unknown }).use);
        const alg = toOptionalTrimmedString((rawKey as { alg?: unknown }).alg);
        const n = toOptionalTrimmedString((rawKey as { n?: unknown }).n);
        const e = toOptionalTrimmedString((rawKey as { e?: unknown }).e);
        if (!kid || kty !== 'RSA' || !n || !e) continue;
        if (use && use !== 'sig') continue;
        if (alg && alg !== 'RS256') continue;
        keysByKid.set(kid, rawKey as unknown as JsonWebKey);
      }
      if (!keysByKid.size) {
        throw new Error('OIDC JWKS returned no usable RSA keys');
      }

      const maxAgeSec = parseCacheControlMaxAgeSec(resp.headers.get('cache-control')) || 60 * 60;
      const expiresAtMs = now + maxAgeSec * 1000;
      const value = { keysByKid, expiresAtMs };
      this.oidcJwksCacheByUrl.set(url, value);
      return value;
    })();

    this.oidcJwksFetchPromiseByUrl.set(url, fetchPromise);
    try {
      return await fetchPromise;
    } finally {
      this.oidcJwksFetchPromiseByUrl.delete(url);
    }
  }

  async verifyOidcJwtExchange(request: { token?: unknown }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    providerSubject?: string;
    iss?: string;
    aud?: string[];
    sub?: string;
    email?: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    code?: string;
    message?: string;
  }> {
    try {
      const cfg = this.config.oidcExchange;
      const issuers = Array.isArray(cfg?.issuers) ? cfg.issuers : [];
      if (!issuers.length) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'OIDC exchange is not configured on this server',
        };
      }

      const token = toOptionalTrimmedString(request?.token);
      if (!token) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token is required',
        };
      }
      if (typeof crypto === 'undefined' || !crypto.subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parts = token.split('.');
      if (parts.length !== 3) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token must be a JWT (3 segments)',
        };
      }
      const [headerB64u, payloadB64u, signatureB64u] = parts;
      const header = parseJwtSegmentJson(headerB64u);
      if (!header) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid exchange.token header encoding',
        };
      }
      const payload = parseJwtSegmentJson(payloadB64u);
      if (!payload) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid exchange.token payload encoding',
        };
      }

      const kid = toOptionalTrimmedString(header.kid);
      const alg = toOptionalTrimmedString(header.alg);
      if (!kid) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token header.kid is required',
        };
      }
      if (alg !== 'RS256') {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'exchange.token header.alg must be RS256',
        };
      }

      const iss = normalizeOidcIssuer(toOptionalTrimmedString(payload.iss) || '');
      if (!iss) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token iss',
        };
      }
      const issuerConfig = issuers.find((candidate: OidcExchangeIssuerConfig) => {
        return normalizeOidcIssuer(candidate.issuer) === iss;
      });
      if (!issuerConfig) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_issuer',
          message: 'exchange.token issuer is not allowed',
        };
      }

      const aud = parseJwtAud(payload.aud);
      if (!aud.length) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token aud',
        };
      }
      const allowedAud = new Set(issuerConfig.audiences || []);
      const audOk = aud.some((value) => allowedAud.has(value));
      if (!audOk) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_audience',
          message: 'exchange.token audience mismatch',
        };
      }

      const sub = toOptionalTrimmedString(payload.sub);
      if (!sub) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing exchange.token sub',
        };
      }

      const jwks = await this.getOidcJwksByUrl(issuerConfig.jwksUrl);
      const jwk = jwks.keysByKid.get(kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown OIDC key id (kid)',
        };
      }

      let signatureBytes: Uint8Array;
      try {
        signatureBytes = base64UrlDecode(signatureB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid exchange.token signature encoding',
        };
      }

      const dataBytes = new TextEncoder().encode(`${headerB64u}.${payloadB64u}`);
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      );
      const verified = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        key,
        toArrayBufferCopy(signatureBytes),
        toArrayBufferCopy(dataBytes),
      );
      if (!verified) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_signature',
          message: 'Invalid exchange.token signature',
        };
      }

      const clockSkewInput = Number(cfg?.clockSkewSec);
      const clockSkewSec = Number.isFinite(clockSkewInput)
        ? Math.max(0, Math.floor(clockSkewInput))
        : 60;
      const nowSec = Math.floor(Date.now() / 1000);
      const exp = Number(payload.exp);
      if (!Number.isFinite(exp) || exp <= 0) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Invalid exchange.token exp',
        };
      }
      if (nowSec > exp + clockSkewSec) {
        return {
          ok: false,
          verified: false,
          code: 'expired',
          message: 'exchange.token is expired',
        };
      }
      const nbfRaw = payload.nbf;
      if (nbfRaw !== undefined) {
        const nbf = Number(nbfRaw);
        if (!Number.isFinite(nbf)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid exchange.token nbf',
          };
        }
        if (nowSec + clockSkewSec < nbf) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'exchange.token is not yet valid',
          };
        }
      }
      const iatRaw = payload.iat;
      if (iatRaw !== undefined) {
        const iat = Number(iatRaw);
        if (!Number.isFinite(iat)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid exchange.token iat',
          };
        }
        if (iat > nowSec + clockSkewSec) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'exchange.token issued-at is in the future',
          };
        }
      }

      const subjectPrefix = toOptionalTrimmedString(issuerConfig.subjectPrefix) || `oidc:${iss}:`;
      const providerSubject = `${subjectPrefix}${sub}`;
      const email = toOptionalTrimmedString(payload?.email);
      const name = toOptionalTrimmedString(payload?.name);
      const givenName = toOptionalTrimmedString(payload?.given_name);
      const familyName = toOptionalTrimmedString(payload?.family_name);

      let userId = providerSubject;
      try {
        const identity = this.getIdentityStore();
        const linked = await identity.getUserIdBySubject(providerSubject);
        if (linked) userId = linked;
        await identity.linkSubjectToUserId({
          userId,
          subject: providerSubject,
          allowMoveIfSoleIdentity: false,
        });
      } catch {}

      return {
        ok: true,
        verified: true,
        userId,
        providerSubject,
        iss,
        aud,
        sub,
        ...(email ? { email } : {}),
        ...(name ? { name } : {}),
        ...(givenName ? { given_name: givenName } : {}),
        ...(familyName ? { family_name: familyName } : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'OIDC exchange verification failed',
      };
    }
  }

  async verifyGoogleLogin(request: { idToken?: unknown; id_token?: unknown }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    providerSubject?: string;
    sub?: string;
    email?: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    emailVerified?: boolean;
    hostedDomain?: string;
    code?: string;
    message?: string;
  }> {
    try {
      const googleCfg = this.config.googleOidc;
      if (!googleCfg?.clientIds?.length) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'Google OIDC is not configured on this server',
        };
      }

      const idToken = toOptionalTrimmedString(request.idToken ?? request.id_token);
      if (!idToken)
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token is required',
        };

      if (typeof crypto === 'undefined' || !crypto.subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parts = idToken.split('.');
      if (parts.length !== 3) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token must be a JWT (3 segments)',
        };
      }
      const [headerB64u, payloadB64u, signatureB64u] = parts;

      let header: any;
      let payload: any;
      try {
        header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64u)));
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token header encoding',
        };
      }
      try {
        payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64u)));
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token payload encoding',
        };
      }

      const kid = toOptionalTrimmedString(header?.kid);
      const alg = toOptionalTrimmedString(header?.alg);
      if (!kid)
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token header.kid is required',
        };
      if (alg !== 'RS256')
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token header.alg must be RS256',
        };

      const jwks = await this.getGoogleJwks();
      const jwk = jwks.keysByKid.get(kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown Google key id (kid)',
        };
      }

      let signatureBytes: Uint8Array;
      try {
        signatureBytes = base64UrlDecode(signatureB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token signature encoding',
        };
      }

      const dataBytes = new TextEncoder().encode(`${headerB64u}.${payloadB64u}`);
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      );
      const verified = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        key,
        toArrayBufferCopy(signatureBytes),
        toArrayBufferCopy(dataBytes),
      );
      if (!verified) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_signature',
          message: 'Invalid Google id_token signature',
        };
      }

      const iss = toOptionalTrimmedString(payload?.iss);
      if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
        return {
          ok: false,
          verified: false,
          code: 'invalid_issuer',
          message: 'Invalid Google id_token issuer',
        };
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const expRaw = payload?.exp;
      const exp = typeof expRaw === 'number' ? expRaw : Number(expRaw);
      if (!Number.isFinite(exp) || exp <= 0) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Invalid Google id_token exp',
        };
      }
      if (nowSec >= exp) {
        return {
          ok: false,
          verified: false,
          code: 'expired',
          message: 'Google id_token is expired',
        };
      }
      const nbfRaw = payload?.nbf;
      if (nbfRaw !== undefined) {
        const nbf = typeof nbfRaw === 'number' ? nbfRaw : Number(nbfRaw);
        if (!Number.isFinite(nbf)) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_claims',
            message: 'Invalid Google id_token nbf',
          };
        }
        if (nowSec < nbf) {
          return {
            ok: false,
            verified: false,
            code: 'not_yet_valid',
            message: 'Google id_token is not yet valid',
          };
        }
      }

      const audRaw = payload?.aud;
      const aud = Array.isArray(audRaw)
        ? audRaw.map((v) => (typeof v === 'string' ? v.trim() : '')).filter(Boolean)
        : [toOptionalTrimmedString(audRaw) || ''].filter(Boolean);
      if (!aud.length) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing Google id_token aud',
        };
      }
      const allowedAudSet = new Set(googleCfg.clientIds);
      const audOk = aud.some((a) => allowedAudSet.has(a));
      if (!audOk) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_audience',
          message: 'Google id_token audience mismatch',
        };
      }

      const sub = toOptionalTrimmedString(payload?.sub);
      if (!sub)
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Missing Google id_token sub',
        };

      const hostedDomain = toOptionalTrimmedString(payload?.hd);
      if (googleCfg.hostedDomains?.length) {
        const allowHd = new Set((googleCfg.hostedDomains || []).map((d) => d.toLowerCase()));
        if (!hostedDomain || !allowHd.has(hostedDomain.toLowerCase())) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_hosted_domain',
            message: 'Google hosted domain is not allowed',
          };
        }
      }

      const email = toOptionalTrimmedString(payload?.email);
      const name = toOptionalTrimmedString(payload?.name);
      const givenName = toOptionalTrimmedString(payload?.given_name);
      const familyName = toOptionalTrimmedString(payload?.family_name);
      const emailVerifiedRaw = payload?.email_verified;
      const emailVerified =
        typeof emailVerifiedRaw === 'boolean'
          ? emailVerifiedRaw
          : typeof emailVerifiedRaw === 'string'
            ? emailVerifiedRaw.trim().toLowerCase() === 'true'
            : undefined;

      const providerSubject = `google:${sub}`;
      let userId = providerSubject;
      try {
        const identity = this.getIdentityStore();
        const linked = await identity.getUserIdBySubject(providerSubject);
        if (linked) userId = linked;
        await identity.linkSubjectToUserId({
          userId,
          subject: providerSubject,
          allowMoveIfSoleIdentity: false,
        });
      } catch {}

      return {
        ok: true,
        verified: true,
        userId,
        providerSubject,
        sub,
        ...(email ? { email } : {}),
        ...(name ? { name } : {}),
        ...(givenName ? { given_name: givenName } : {}),
        ...(familyName ? { family_name: familyName } : {}),
        ...(typeof emailVerified === 'boolean' ? { emailVerified } : {}),
        ...(hostedDomain ? { hostedDomain } : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Google OIDC verification failed',
      };
    }
  }

  async createWebAuthnSyncAccountOptions(request: {
    rp_id?: unknown;
    account_id?: unknown;
    ttl_ms?: unknown;
    ttlMs?: unknown;
  }): Promise<{
    ok: boolean;
    challengeId?: string;
    challengeB64u?: string;
    credentialIds?: string[];
    expiresAtMs?: number;
    code?: string;
    message?: string;
  }> {
    try {
      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };
      const expectedUserId = toOptionalTrimmedString(request?.account_id);
      if (expectedUserId && !isValidAccountId(expectedUserId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid account_id' };
      }

      const ttlMsRaw = request?.ttlMs ?? request?.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'crypto.getRandomValues is unavailable in this runtime',
        };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
      let credentialIds: string[] | undefined;

      if (expectedUserId) {
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        if (typeof bindingStore.listByUserId !== 'function') {
          return {
            ok: false,
            code: 'not_supported',
            message: 'Credential listing is not supported by this store',
          };
        }
        const bindings = await bindingStore.listByUserId({ userId: expectedUserId, rpId });
        const seen = new Set<string>();
        credentialIds = [];
        for (const binding of bindings) {
          const credentialId = String(binding.credentialIdB64u || '').trim();
          if (!credentialId || seen.has(credentialId)) continue;
          seen.add(credentialId);
          credentialIds.push(credentialId);
        }
      }

      const store = this.getWebAuthnSyncChallengeStore();
      await store.put({
        version: 'webauthn_sync_challenge_v1',
        challengeId,
        rpId,
        ...(expectedUserId ? { expectedUserId } : {}),
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return {
        ok: true,
        challengeId,
        challengeB64u,
        ...(credentialIds ? { credentialIds } : {}),
        expiresAtMs,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to create sync account options',
      };
    }
  }

  async listThresholdEcdsaKeyIdentityTargetsForUser(input: {
    userId: string;
    rpId: string;
    keyTargets: readonly unknown[];
  }): Promise<{
    records: ThresholdEcdsaKeyInventoryRecord[];
    diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
  }> {
    const userId = toOptionalTrimmedString(input.userId);
    const rpId = toOptionalTrimmedString(input.rpId);
    const threshold = this.getThresholdSigningService();
    const diagnostics: ThresholdEcdsaKeyInventoryDiagnostics = {
      userId: userId || '',
      inputCount: input.keyTargets.length,
      returnedCount: 0,
      thresholdServicePresent: Boolean(threshold),
      rejected: {},
    };
    if (!userId || !rpId) {
      incrementCount(diagnostics.rejected, 'missing_scope');
      return { records: [], diagnostics };
    }
    if (!threshold) {
      incrementCount(diagnostics.rejected, 'threshold_service_missing');
      return { records: [], diagnostics };
    }

    const records: ThresholdEcdsaKeyInventoryRecord[] = [];
    const seen = new Set<string>();
    for (const rawTarget of input.keyTargets) {
      const parsed = parseThresholdEcdsaKeyInventoryTarget(rawTarget);
      if (!parsed.ok) {
        incrementCount(diagnostics.rejected, parsed.reason);
        continue;
      }
      const targetKey = thresholdEcdsaChainTargetKey(parsed.value.chainTarget);
      const requestKey = `${targetKey}::${parsed.value.selectorKey}`;
      if (seen.has(requestKey)) {
        incrementCount(diagnostics.rejected, 'duplicate_target_key');
        continue;
      }
      seen.add(requestKey);
      const identity = await threshold.getEcdsaKeyIdentityMetadata({
        walletId: userId,
        rpId,
        keySelector: parsed.value.keySelector,
      });
      if (!identity) {
        incrementCount(diagnostics.rejected, 'identity_not_found');
        continue;
      }
      if (
        identity.walletId !== userId ||
        identity.rpId !== rpId ||
        !thresholdEcdsaKeyInventorySelectorMatchesIdentity(parsed.value.keySelector, identity)
      ) {
        incrementCount(diagnostics.rejected, 'identity_mismatch');
        continue;
      }
      const keyHandle = toOptionalTrimmedString(identity.keyHandle);
      const ownerAddress = normalizeEvmAddress(identity.thresholdOwnerAddress);
      const relayerKeyId = toOptionalTrimmedString(identity.relayerKeyId);
      const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(
        identity.thresholdEcdsaPublicKeyB64u,
      );
      if (!keyHandle || !ownerAddress || !relayerKeyId || !thresholdEcdsaPublicKeyB64u) {
        incrementCount(diagnostics.rejected, 'incomplete_identity');
        continue;
      }
      records.push({
        keyHandle,
        ecdsaThresholdKeyId: identity.ecdsaThresholdKeyId,
        chainTarget: parsed.value.chainTarget,
        targetKey,
        accountAddress: ownerAddress,
        ownerAddress,
        relayerKeyId,
        thresholdEcdsaPublicKeyB64u,
        key: {
          walletId: identity.walletId,
          rpId: identity.rpId,
          keyScope: identity.keyScope,
          ecdsaThresholdKeyId: identity.ecdsaThresholdKeyId,
          signingRootId: identity.signingRootId,
          signingRootVersion: identity.signingRootVersion,
          participantIds: [...identity.participantIds],
          thresholdOwnerAddress: ownerAddress,
        },
      });
    }
    diagnostics.returnedCount = records.length;
    this.logger.info('[threshold-ecdsa-key-inventory][diagnostic]', diagnostics);
    return { records, diagnostics };
  }

  async listWalletEcdsaKeyFactsInventory(input: {
    walletId: string;
    rpId: string;
    keyTargets: readonly unknown[];
  }): Promise<{
    records: ThresholdEcdsaKeyInventoryRecord[];
    diagnostics: ThresholdEcdsaKeyInventoryDiagnostics;
  }> {
    return await this.listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: input.walletId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
    });
  }

  async ecdsaHssRoleLocalBootstrap(
    request: EcdsaHssClientBootstrapRequest,
  ): Promise<EcdsaHssRouteResult<EcdsaHssServerBootstrapResponse>> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.ecdsaHssRoleLocalBootstrap(request);
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: EcdsaHssClientBootstrapRequest & {
      clientRootProof: NonNullable<EcdsaHssClientBootstrapRequest['clientRootProof']>;
    },
  ): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.verifyEcdsaHssRoleLocalClientRootProofForExistingKey(request);
  }

  async ecdsaHssRoleLocalExportShare(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    claims: ThresholdEcdsaSessionClaims;
  }): Promise<EcdsaHssRouteResult<EcdsaHssExportShareResponse>> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.ecdsaHssRoleLocalExportShare(input);
  }

  async verifyWebAuthnSyncAccount(request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
    threshold_ed25519?: unknown;
  }): Promise<{
    ok: boolean;
    verified?: boolean;
    accountId?: string;
    rpId?: string;
    signerSlot?: number;
    publicKey?: string;
    relayerKeyId?: string;
    credentialIdB64u?: string;
    credentialPublicKeyB64u?: string;
    thresholdEd25519?: {
      relayerKeyId: string;
      publicKey: string;
      keyVersion?: string;
      recoveryExportCapable?: boolean;
      clientParticipantId?: number;
      relayerParticipantId?: number;
      participantIds?: number[];
      session?: {
        sessionKind: 'jwt' | 'cookie';
        sessionId: string;
        walletSigningSessionId: string;
        expiresAtMs: number;
        expiresAt?: string;
        participantIds?: number[];
        remainingUses?: number;
        jwt?: string;
      };
    };
    code?: string;
    message?: string;
  }> {
    try {
      const challengeId = String(request?.challengeId ?? request?.challenge_id ?? '').trim();
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

      const store = this.getWebAuthnSyncChallengeStore();
      const challenge = await store.consume(challengeId);
      if (!challenge) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Sync challenge expired or invalid',
        };
      }

      const thresholdEd25519Bootstrap = parseThresholdEd25519RegistrationInput(
        (request as any)?.threshold_ed25519,
      );
      const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
      const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
      if (thresholdEd25519SessionPolicy && !isObject(thresholdEd25519SessionPolicy)) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy is required',
        };
      }
      if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        };
      }

      const cred = request?.webauthn_authentication as any;
      const credentialId = String(cred?.id || '').trim();
      const rawId = String(cred?.rawId || '').trim();
      const chosen = rawId || credentialId;
      if (!chosen) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Missing webauthn_authentication.id/rawId',
        };
      }

      const credentialIDBytes = decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId');
      const credentialIdB64u = base64UrlEncode(credentialIDBytes);

      const bindingStore = this.getWebAuthnCredentialBindingStore();
      const binding = await bindingStore.get(challenge.rpId, credentialIdB64u);
      if (!binding) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered on this relay',
        };
      }
      if (challenge.expectedUserId && binding.userId !== challenge.expectedUserId) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: `Credential is not registered for account ${challenge.expectedUserId}`,
        };
      }

      const expectedOrigin = toOptionalTrimmedString(request.expected_origin);
      if (!expectedOrigin) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        };
      }
      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: binding.userId,
        rpId: binding.rpId,
        expectedChallenge: challenge.challengeB64u,
        webauthn_authentication: request?.webauthn_authentication as any,
        expected_origin: expectedOrigin,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      const authStore = this.getWebAuthnAuthenticatorStore();
      const auth = await authStore.get(binding.userId, credentialIdB64u);
      if (!auth) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_credential',
          message: 'Credential is not registered for user',
        };
      }

      const thresholdEd25519 = binding.relayerKeyId
        ? {
            relayerKeyId: binding.relayerKeyId,
            publicKey: binding.publicKey,
            ...(binding.keyVersion ? { keyVersion: binding.keyVersion } : {}),
            ...(typeof binding.recoveryExportCapable === 'boolean'
              ? { recoveryExportCapable: binding.recoveryExportCapable }
              : {}),
            ...(typeof binding.clientParticipantId === 'number'
              ? { clientParticipantId: binding.clientParticipantId }
              : {}),
            ...(typeof binding.relayerParticipantId === 'number'
              ? { relayerParticipantId: binding.relayerParticipantId }
              : {}),
            ...(Array.isArray(binding.participantIds)
              ? { participantIds: binding.participantIds }
              : {}),
          }
        : undefined;

      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      if (thresholdEd25519SessionPolicy) {
        const thresholdService = this.getThresholdSigningService();
        if (!thresholdService) {
          return {
            ok: false,
            verified: false,
            code: 'not_configured',
            message: 'Threshold signing is not configured on this server',
          };
        }
        const relayerKeyId = String(binding.relayerKeyId || '').trim();
        if (!relayerKeyId) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_body',
            message: 'Credential is not bound to threshold key material',
          };
        }
        const requestedSessionPolicy = thresholdEd25519SessionPolicy as Record<string, unknown>;
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(requestedSessionPolicy.runtimePolicyScope) ||
          normalizeThresholdRuntimePolicyScope(binding.runtimePolicyScope);
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy,
          expectedRelayerKeyId: relayerKeyId,
          expectedNearAccountId: binding.userId,
          expectedRpId: binding.rpId,
        });
        if (policyBindingError) {
          return {
            ok: false,
            verified: false,
            code: 'invalid_body',
            message: policyBindingError,
          };
        }

        const session = await thresholdService.mintEd25519SessionFromRegistration({
          nearAccountId: binding.userId,
          rpId: binding.rpId,
          relayerKeyId,
          sessionPolicy: {
            ...requestedSessionPolicy,
            nearAccountId: binding.userId,
            rpId: binding.rpId,
            relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        });
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            verified: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 session bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            verified: false,
            code: 'internal',
            message: 'threshold-ed25519 session bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      return {
        ok: true,
        verified: true,
        accountId: binding.userId,
        rpId: binding.rpId,
        signerSlot: binding.signerSlot,
        publicKey: binding.publicKey,
        ...(binding.relayerKeyId ? { relayerKeyId: binding.relayerKeyId } : {}),
        credentialIdB64u,
        credentialPublicKeyB64u: auth.credentialPublicKeyB64u,
        ...(thresholdEd25519
          ? {
              thresholdEd25519: {
                ...thresholdEd25519,
                ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
              },
            }
          : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(e) || 'Sync verification failed',
      };
    }
  }

  async getLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
  }): Promise<
    { ok: true; session: DeviceLinkingSessionRecord } | { ok: false; code: string; message: string }
  > {
    try {
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const store = this.getDeviceLinkingSessionStore();
      const session = await store.get(sessionId);
      if (!session)
        return { ok: false, code: 'not_found', message: 'Unknown or expired link-device session' };
      return { ok: true, session };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to load link-device session',
      };
    }
  }

  async registerLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
    device2_public_key?: unknown;
    device2PublicKey?: unknown;
    expires_at_ms?: unknown;
    expiresAtMs?: unknown;
  }): Promise<
    { ok: true; session: DeviceLinkingSessionRecord } | { ok: false; code: string; message: string }
  > {
    try {
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const device2PublicKey = String(
        request?.device2_public_key ?? request?.device2PublicKey ?? '',
      ).trim();
      if (!device2PublicKey || !device2PublicKey.startsWith('ed25519:')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid device2PublicKey (expected ed25519:...)',
        };
      }

      const now = Date.now();
      const requestedExpiresRaw = request?.expires_at_ms ?? request?.expiresAtMs;
      const requestedExpires =
        typeof requestedExpiresRaw === 'number' ? requestedExpiresRaw : Number(requestedExpiresRaw);
      const ttlMs = 15 * 60_000;
      const maxTtlMs = 60 * 60_000;
      const baseExpires = now + ttlMs;
      const expiresAtMs =
        Number.isFinite(requestedExpires) && requestedExpires > now
          ? Math.min(Math.floor(requestedExpires), now + maxTtlMs)
          : baseExpires;

      const store = this.getDeviceLinkingSessionStore();
      const existing = await store.get(sessionId);
      if (existing?.device2PublicKey && existing.device2PublicKey !== device2PublicKey) {
        return { ok: false, code: 'conflict', message: 'Session public key mismatch' };
      }

      const session: DeviceLinkingSessionRecord = {
        version: 'device_linking_session_v1',
        sessionId,
        device2PublicKey,
        createdAtMs: existing?.createdAtMs ?? now,
        expiresAtMs: Math.max(existing?.expiresAtMs ?? 0, expiresAtMs),
        ...(existing?.claimedAtMs ? { claimedAtMs: existing.claimedAtMs } : {}),
        ...(existing?.accountId ? { accountId: existing.accountId } : {}),
        ...(existing?.signerSlot ? { signerSlot: existing.signerSlot } : {}),
        ...(existing?.addKeyTxHash ? { addKeyTxHash: existing.addKeyTxHash } : {}),
        ...(existing?.preparedEcdsa ? { preparedEcdsa: existing.preparedEcdsa } : {}),
      };

      await store.put(session);
      this.logger.info('[link-device] session registered', {
        sessionId,
        device2PublicKey,
        expiresAtMs: session.expiresAtMs,
        hasExisting: !!existing,
        storeKind: String((this.config.thresholdStore as any)?.kind || ''),
      });
      return { ok: true, session };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to register link-device session',
      };
    }
  }

  async claimLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
    account_id?: unknown;
    accountId?: unknown;
    device2_public_key?: unknown;
    device2PublicKey?: unknown;
    signer_slot?: unknown;
    signerSlot?: unknown;
    add_key_tx_hash?: unknown;
    addKeyTxHash?: unknown;
  }): Promise<
    { ok: true; session: DeviceLinkingSessionRecord } | { ok: false; code: string; message: string }
  > {
    try {
      if ('threshold_ecdsa' in (request as unknown as Record<string, unknown>)) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            'threshold_ecdsa link-device bootstrap has been removed; use role-local ECDSA HSS bootstrap',
        };
      }
      await this._ensureSignerAndRelayerAccount();

      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }

      const device2PublicKey = String(
        request?.device2_public_key ?? request?.device2PublicKey ?? '',
      ).trim();
      if (!device2PublicKey || !device2PublicKey.startsWith('ed25519:')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid device2PublicKey (expected ed25519:...)',
        };
      }

      const addKeyTxHash =
        String(request?.add_key_tx_hash ?? request?.addKeyTxHash ?? '').trim() || undefined;

      const keys = await this.nearClient.viewAccessKeyList(accountId);
      const hasKey =
        Array.isArray(keys?.keys) &&
        keys.keys.some((k: any) => String(k?.public_key || '').trim() === device2PublicKey);
      if (!hasKey) {
        return {
          ok: false,
          code: 'missing_access_key',
          message:
            'device2 public key is not present on account (ensure AddKey has been submitted and propagated)',
        };
      }

      const store = this.getDeviceLinkingSessionStore();
      const existing = await store.get(sessionId);
      if (existing?.accountId && existing.accountId !== accountId) {
        return {
          ok: false,
          code: 'conflict',
          message: 'Session is already claimed by a different accountId',
        };
      }
      if (existing?.device2PublicKey && existing.device2PublicKey !== device2PublicKey) {
        return { ok: false, code: 'conflict', message: 'Session public key mismatch' };
      }

      const fallbackSignerSlot = coerceSignerSlot(
        request?.signer_slot ?? request?.signerSlot ?? existing?.signerSlot ?? 2,
        { min: 1, fallback: 2 },
      );
      let signerSlot = fallbackSignerSlot;
      try {
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        if (bindingStore.getMaxSignerSlot) {
          const maxSignerSlot = await bindingStore.getMaxSignerSlot({ userId: accountId });
          if (typeof maxSignerSlot === 'number' && maxSignerSlot >= signerSlot) {
            signerSlot = maxSignerSlot + 1;
          }
        }
      } catch {
        // ignore and keep fallback
      }

      const now = Date.now();
      const ttlMs = 15 * 60_000;
      const expiresAtMs = Math.max(existing?.expiresAtMs ?? 0, now + ttlMs);

      const session: DeviceLinkingSessionRecord = {
        version: 'device_linking_session_v1',
        sessionId,
        device2PublicKey,
        createdAtMs: existing?.createdAtMs ?? now,
        expiresAtMs,
        claimedAtMs: now,
        accountId,
        signerSlot,
        ...(addKeyTxHash ? { addKeyTxHash } : {}),
        ...(existing?.preparedEcdsa ? { preparedEcdsa: existing.preparedEcdsa } : {}),
      };

      await store.put(session);

      // Best-effort: persist the ephemeral (device2) key metadata. This key is expected to be deleted
      // by Device2 during completion, but storing it helps UIs classify access keys while linking is in flight.
      await this.recordNearPublicKeyMetadata({
        userId: accountId,
        publicKey: device2PublicKey,
        kind: 'ephemeral',
        signerSlot,
        ...(addKeyTxHash ? { addedTxHash: addKeyTxHash } : {}),
        source: 'link-device ephemeral NEAR public key metadata persistence',
      });

      this.logger.info('[link-device] session claimed', {
        sessionId,
        accountId,
        device2PublicKey,
        signerSlot,
        addKeyTxHash: addKeyTxHash || '',
        storeKind: String((this.config.thresholdStore as any)?.kind || ''),
      });
      return { ok: true, session };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Failed to claim link-device session',
      };
    }
  }

  async prepareLinkDevice(request: {
    account_id?: unknown;
    accountId?: unknown;
    session_id?: unknown;
    sessionId?: unknown;
    signer_slot?: unknown;
    signerSlot?: unknown;
    threshold_ed25519?: unknown;
    threshold_ecdsa_prepare?: unknown;
    rp_id?: unknown;
    webauthn_registration?: unknown;
    expected_origin?: string;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          publicKey: string;
          keyVersion?: string;
          recoveryExportCapable?: boolean;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: {
            sessionKind: 'jwt' | 'cookie';
            sessionId: string;
            walletSigningSessionId: string;
            expiresAtMs: number;
            expiresAt?: string;
            participantIds?: number[];
            remainingUses?: number;
            runtimePolicyScope?: ThresholdRuntimePolicyScope;
            jwt?: string;
          };
        };
        ecdsa?: WalletRegistrationEcdsaPreparePayload;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      if ('threshold_ecdsa' in (request as unknown as Record<string, unknown>)) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            'threshold_ecdsa link-device bootstrap has been removed; use role-local ECDSA HSS bootstrap',
        };
      }
      await this._ensureSignerAndRelayerAccount();

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim() || undefined;

      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const signerSlot = (() => {
        const raw = request?.signer_slot ?? request?.signerSlot ?? 2;
        const n = typeof raw === 'number' ? raw : Number(raw);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 2;
      })();
      const thresholdEd25519Bootstrap = parseThresholdEd25519RegistrationInput(
        (request as any)?.threshold_ed25519,
      );
      const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
      if (
        (request as any)?.threshold_ed25519?.session_policy != null &&
        !thresholdEd25519SessionPolicy
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy must be an object',
        };
      }
      const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
      if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        };
      }
      if (!thresholdEd25519SessionPolicy && thresholdEd25519SessionKind) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy is required when session_kind is provided',
        };
      }
      const ecdsaPrepareSpec = normalizeAdjacentFlowEcdsaPrepareSpec(
        (request as any)?.threshold_ecdsa_prepare,
      );
      if (!ecdsaPrepareSpec.ok) return ecdsaPrepareSpec;

      const cred = request.webauthn_registration as any;
      if (!cred || typeof cred !== 'object')
        return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };

      // NOTE: We reuse the same deterministic registration intent schema as account creation:
      // `sha256("register:<accountId>:<signerSlot>")`. This keeps client-side plumbing simple
      // (reuses existing SecureConfirm registration helpers).
      const expectedIntent = `register:${accountId}:${signerSlot}`;
      const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

      const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      if (clientData.type !== 'webauthn.create') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
        };
      }
      if (clientData.challenge !== expectedChallenge) {
        return {
          ok: false,
          code: 'challenge_mismatch',
          message: 'Registration challenge mismatch',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const mod = await import('@simplewebauthn/server');
      const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as
        | undefined
        | ((args: any) => Promise<any>);
      if (typeof verifyRegistrationResponse !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'WebAuthn registration verifier is unavailable in this runtime',
        };
      }

      const expectedOriginStrict = toOptionalTrimmedString(request.expected_origin);
      if (!expectedOriginStrict) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const registration = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge,
        expectedOrigin: expectedOriginStrict,
        expectedRPID: rpId,
        requireUserVerification: false,
      });
      if (!registration?.verified) {
        return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
      }

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bindingStore = this.getWebAuthnCredentialBindingStore();
      const existingRuntimePolicyScope = await resolveBoundThresholdRuntimePolicyScope({
        bindingStore,
        userId: accountId,
        rpId,
      });
      const existingThresholdEd25519Binding = await resolveExistingThresholdEd25519Binding({
        bindingStore,
        userId: accountId,
        rpId,
      });
      if (!existingThresholdEd25519Binding) {
        return {
          ok: false,
          code: 'not_found',
          message: 'No existing threshold-ed25519 key binding found for account',
        };
      }
      const keygen = {
        relayerKeyId: String(existingThresholdEd25519Binding.relayerKeyId || '').trim(),
        publicKey: existingThresholdEd25519Binding.publicKey,
        keyVersion: String(existingThresholdEd25519Binding.keyVersion || '').trim(),
        recoveryExportCapable:
          existingThresholdEd25519Binding.recoveryExportCapable === true ? true : undefined,
        clientParticipantId: existingThresholdEd25519Binding.clientParticipantId,
        relayerParticipantId: existingThresholdEd25519Binding.relayerParticipantId,
        participantIds: existingThresholdEd25519Binding.participantIds,
      };
      if (
        !keygen.relayerKeyId ||
        !keygen.publicKey ||
        !keygen.keyVersion ||
        keygen.recoveryExportCapable !== true
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Existing threshold-ed25519 binding is incomplete',
        };
      }
      let ecdsaPrepare: WalletRegistrationEcdsaPreparePayload | undefined;
      if (ecdsaPrepareSpec.value) {
        if (!sessionId) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'threshold_ecdsa_prepare requires a link-device session_id',
          };
        }
        const ecdsaRuntimePolicyScope =
          ecdsaPrepareSpec.value.runtimePolicyScope || existingRuntimePolicyScope;
        const signingRootId =
          ecdsaPrepareSpec.value.signingRootId ||
          (ecdsaRuntimePolicyScope ? deriveSigningRootId(ecdsaRuntimePolicyScope) : undefined);
        const signingRootVersion =
          ecdsaPrepareSpec.value.signingRootVersion ||
          ecdsaRuntimePolicyScope?.signingRootVersion ||
          'default';
        if (!signingRootId || !signingRootVersion) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'threshold_ecdsa_prepare requires a signing root',
          };
        }
        ecdsaPrepare = await this.prepareEcdsaRegistrationStartPayload({
          registrationCeremonyId: `link_device_${randomBase64Url(16)}`,
          walletId: walletIdFromString(accountId),
          rpId,
          signingRootId,
          signingRootVersion,
          chainTargets: ecdsaPrepareSpec.value.chainTargets,
          participantIds: ecdsaPrepareSpec.value.participantIds,
          ...(ecdsaRuntimePolicyScope ? { runtimePolicyScope: ecdsaRuntimePolicyScope } : {}),
        });
      }
      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      if (thresholdEd25519SessionPolicy) {
        const requestedSessionPolicy = thresholdEd25519SessionPolicy as Record<string, unknown>;
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(requestedSessionPolicy.runtimePolicyScope) ||
          existingRuntimePolicyScope;
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy,
          expectedRelayerKeyId: keygen.relayerKeyId,
          expectedNearAccountId: accountId,
          expectedRpId: rpId,
        });
        if (policyBindingError) {
          return {
            ok: false,
            code: 'invalid_body',
            message: policyBindingError,
          };
        }

        const session = await threshold.mintEd25519SessionFromRegistration({
          nearAccountId: accountId,
          rpId,
          relayerKeyId: keygen.relayerKeyId,
          sessionPolicy: {
            ...requestedSessionPolicy,
            nearAccountId: accountId,
            rpId,
            relayerKeyId: keygen.relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        });
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 link-device bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ed25519 link-device bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
      const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as
        | Uint8Array
        | undefined;
      const counter = registration?.registrationInfo?.credential?.counter as number | undefined;

      if (!credentialIdB64u || !credentialPublicKey) {
        return {
          ok: false,
          code: 'internal',
          message: 'Registration verification did not return credential public key material',
        };
      }

      const now = Date.now();

      const authStore = this.getWebAuthnAuthenticatorStore();
      await authStore.put(accountId, {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
        createdAtMs: now,
        updatedAtMs: now,
      });

      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId,
        credentialIdB64u,
        userId: accountId,
        signerSlot,
        publicKey: keygen.publicKey,
        relayerKeyId: keygen.relayerKeyId,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        ...(thresholdEd25519Session?.runtimePolicyScope || existingRuntimePolicyScope
          ? {
              runtimePolicyScope:
                thresholdEd25519Session?.runtimePolicyScope || existingRuntimePolicyScope,
            }
          : {}),
        createdAtMs: now,
        updatedAtMs: now,
      });

      // Best-effort: persist key metadata for UI surfaces like "Linked Devices".
      await this.recordNearPublicKeyMetadata({
        userId: accountId,
        publicKey: keygen.publicKey,
        kind: 'threshold',
        signerSlot,
        rpId,
        credentialIdB64u,
        source: 'WebAuthn registration NEAR public key metadata persistence',
      });

      if (sessionId) {
        const sessionStore = this.getDeviceLinkingSessionStore();
        const existingSession = await sessionStore.get(sessionId);
        if (!existingSession) {
          return {
            ok: false,
            code: 'not_found',
            message: 'Unknown or expired link-device session',
          };
        }
        if (existingSession.accountId && existingSession.accountId !== accountId) {
          return {
            ok: false,
            code: 'conflict',
            message: 'Link-device session accountId mismatch',
          };
        }

        await sessionStore.put({
          ...existingSession,
          ...(ecdsaPrepare ? { preparedEcdsa: ecdsaPrepare } : {}),
        });
      }

      return {
        ok: true,
        accountId,
        signerSlot,
        credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          publicKey: keygen.publicKey,
          ...(keygen.keyVersion ? { keyVersion: keygen.keyVersion } : {}),
          ...(typeof keygen.recoveryExportCapable === 'boolean'
            ? { recoveryExportCapable: keygen.recoveryExportCapable }
            : {}),
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
        ...(ecdsaPrepare ? { ecdsa: ecdsaPrepare } : {}),
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Link device preparation failed',
      };
    }
  }

  async respondLinkDeviceEcdsa(request: {
    session_id?: unknown;
    sessionId?: unknown;
    client_bootstrap?: unknown;
    clientBootstrap?: unknown;
  }): Promise<
    | {
        ok: true;
        sessionId: string;
        ecdsa: {
          bootstrap: EcdsaHssServerBootstrapResponse;
          walletKeys: WalletRegistrationEcdsaWalletKey[];
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }
      const parsed = parseEcdsaHssClientBootstrapRequest(
        request?.client_bootstrap ?? request?.clientBootstrap,
      );
      if (!parsed || parsed.clientRootProof || parsed.passkeyBootstrapAuthorization) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid Link Device ECDSA client bootstrap',
        };
      }

      const sessionStore = this.getDeviceLinkingSessionStore();
      const session = await sessionStore.get(sessionId);
      if (!session) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Unknown or expired link-device session',
        };
      }
      const prepared = session.preparedEcdsa;
      if (!prepared) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Link Device ECDSA prepare context is missing',
        };
      }
      if (!isMatchingEcdsaClientBootstrap(prepared.prepare, parsed)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Link Device ECDSA bootstrap identity mismatch',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(parsed);
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'hss_respond_failed',
          message: bootstrap.message || 'Link Device ECDSA HSS bootstrap failed',
        };
      }
      const walletKeys = buildEcdsaWalletKeysFromBootstrap({
        bootstrap: bootstrap.value,
        chainTargets: prepared.chainTargets,
        errorContext: 'Link Device ECDSA bootstrap',
      });
      if (!walletKeys.ok) return walletKeys;
      return {
        ok: true,
        sessionId,
        ecdsa: {
          bootstrap: bootstrap.value,
          walletKeys: walletKeys.walletKeys,
        },
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Link Device ECDSA response failed',
      };
    }
  }

  async prepareEmailRecovery(request: {
    account_id?: unknown;
    accountId?: unknown;
    request_id?: unknown;
    requestId?: unknown;
    signer_slot?: unknown;
    signerSlot?: unknown;
    threshold_ed25519?: unknown;
    threshold_ecdsa_prepare?: unknown;
    rp_id?: unknown;
    webauthn_registration?: unknown;
    expected_origin?: string;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        requestId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          publicKey: string;
          keyVersion?: string;
          recoveryExportCapable?: boolean;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: {
            sessionKind: 'jwt' | 'cookie';
            sessionId: string;
            walletSigningSessionId: string;
            expiresAtMs: number;
            expiresAt?: string;
            participantIds?: number[];
            remainingUses?: number;
            runtimePolicyScope?: ThresholdRuntimePolicyScope;
            jwt?: string;
          };
        };
        ecdsa: WalletRegistrationEcdsaPreparePayload;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      if ('threshold_ecdsa' in (request as unknown as Record<string, unknown>)) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            'threshold_ecdsa email-recovery bootstrap has been removed; use role-local ECDSA HSS bootstrap',
        };
      }
      await this._ensureSignerAndRelayerAccount();

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }

      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }

      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const signerSlot = (() => {
        const raw = request?.signer_slot ?? request?.signerSlot ?? 1;
        const n = typeof raw === 'number' ? raw : Number(raw);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
      })();

      const thresholdEd25519Bootstrap = parseThresholdEd25519RegistrationInput(
        (request as any)?.threshold_ed25519,
      );
      const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
      if (
        (request as any)?.threshold_ed25519?.session_policy != null &&
        !thresholdEd25519SessionPolicy
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy must be an object',
        };
      }
      const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
      if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        };
      }
      if (!thresholdEd25519SessionPolicy && thresholdEd25519SessionKind) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy is required when session_kind is provided',
        };
      }
      const ecdsaPrepareSpec = normalizeAdjacentFlowEcdsaPrepareSpec(
        (request as any)?.threshold_ecdsa_prepare,
      );
      if (!ecdsaPrepareSpec.ok) return ecdsaPrepareSpec;
      if (!ecdsaPrepareSpec.value) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa_prepare is required for email recovery',
        };
      }

      const cred = request.webauthn_registration as any;
      if (!cred || typeof cred !== 'object')
        return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };

      // Reuse the canonical deterministic registration challenge schema.
      // Email recovery authorization happens out-of-band (DKIM/TEE), so we don't
      // need to bind the WebAuthn registration challenge to the email `requestId`.
      const expectedIntent = `register:${accountId}:${signerSlot}`;
      const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

      const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      if (clientData.type !== 'webauthn.create') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
        };
      }
      if (clientData.challenge !== expectedChallenge) {
        return {
          ok: false,
          code: 'challenge_mismatch',
          message: 'Registration challenge mismatch',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const mod = await import('@simplewebauthn/server');
      const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as
        | undefined
        | ((args: any) => Promise<any>);
      if (typeof verifyRegistrationResponse !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'WebAuthn registration verifier is unavailable in this runtime',
        };
      }

      const expectedOriginStrict = toOptionalTrimmedString(request.expected_origin);
      if (!expectedOriginStrict) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const registration = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge,
        expectedOrigin: expectedOriginStrict,
        expectedRPID: rpId,
        requireUserVerification: false,
      });
      if (!registration?.verified) {
        return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
      }

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bindingStore = this.getWebAuthnCredentialBindingStore();
      const existingRuntimePolicyScope = await resolveBoundThresholdRuntimePolicyScope({
        bindingStore,
        userId: accountId,
        rpId,
      });
      const existingThresholdEd25519Binding = await resolveExistingThresholdEd25519Binding({
        bindingStore,
        userId: accountId,
        rpId,
      });
      if (!existingThresholdEd25519Binding) {
        return {
          ok: false,
          code: 'not_found',
          message: 'No existing threshold-ed25519 key binding found for account',
        };
      }
      const keygen = {
        relayerKeyId: String(existingThresholdEd25519Binding.relayerKeyId || '').trim(),
        publicKey: existingThresholdEd25519Binding.publicKey,
        keyVersion: String(existingThresholdEd25519Binding.keyVersion || '').trim(),
        recoveryExportCapable:
          existingThresholdEd25519Binding.recoveryExportCapable === true ? true : undefined,
        clientParticipantId: existingThresholdEd25519Binding.clientParticipantId,
        relayerParticipantId: existingThresholdEd25519Binding.relayerParticipantId,
        participantIds: existingThresholdEd25519Binding.participantIds,
      };
      if (
        !keygen.relayerKeyId ||
        !keygen.publicKey ||
        !keygen.keyVersion ||
        keygen.recoveryExportCapable !== true
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Existing threshold-ed25519 binding is incomplete',
        };
      }
      const ecdsaRuntimePolicyScope =
        ecdsaPrepareSpec.value.runtimePolicyScope || existingRuntimePolicyScope;
      const signingRootId =
        ecdsaPrepareSpec.value.signingRootId ||
        (ecdsaRuntimePolicyScope ? deriveSigningRootId(ecdsaRuntimePolicyScope) : undefined);
      const signingRootVersion =
        ecdsaPrepareSpec.value.signingRootVersion ||
        ecdsaRuntimePolicyScope?.signingRootVersion ||
        'default';
      if (!signingRootId || !signingRootVersion) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa_prepare requires a signing root',
        };
      }
      const ecdsaPrepare = await this.prepareEcdsaRegistrationStartPayload({
        registrationCeremonyId: `email_recovery_${randomBase64Url(16)}`,
        walletId: walletIdFromString(accountId),
        rpId,
        signingRootId,
        signingRootVersion,
        chainTargets: ecdsaPrepareSpec.value.chainTargets,
        participantIds: ecdsaPrepareSpec.value.participantIds,
        ...(ecdsaRuntimePolicyScope ? { runtimePolicyScope: ecdsaRuntimePolicyScope } : {}),
      });
      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      if (thresholdEd25519SessionPolicy) {
        const requestedSessionPolicy = thresholdEd25519SessionPolicy as Record<string, unknown>;
        const runtimePolicyScope =
          normalizeThresholdRuntimePolicyScope(requestedSessionPolicy.runtimePolicyScope) ||
          existingRuntimePolicyScope;
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy,
          expectedRelayerKeyId: keygen.relayerKeyId,
          expectedNearAccountId: accountId,
          expectedRpId: rpId,
        });
        if (policyBindingError) {
          return {
            ok: false,
            code: 'invalid_body',
            message: policyBindingError,
          };
        }

        const session = await threshold.mintEd25519SessionFromRegistration({
          nearAccountId: accountId,
          rpId,
          relayerKeyId: keygen.relayerKeyId,
          sessionPolicy: {
            ...requestedSessionPolicy,
            nearAccountId: accountId,
            rpId,
            relayerKeyId: keygen.relayerKeyId,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          } as any,
        });
        if (!session.ok || !session.sessionId || !Number.isFinite(Number(session.expiresAtMs))) {
          return {
            ok: false,
            code: session.code || 'internal',
            message: session.message || 'threshold-ed25519 email-recovery bootstrap failed',
          };
        }
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ed25519 email-recovery bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

      const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
      const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as
        | Uint8Array
        | undefined;
      const counter = registration?.registrationInfo?.credential?.counter as number | undefined;

      if (!credentialIdB64u || !credentialPublicKey) {
        return {
          ok: false,
          code: 'internal',
          message: 'Registration verification did not return credential public key material',
        };
      }

      const now = Date.now();
      await this.getEmailRecoveryPreparationStore().put({
        version: 'email_recovery_preparation_v1',
        requestId,
        accountId,
        rpId,
        signerSlot,
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
        createdAtMs: now,
        expiresAtMs: now + DEFAULT_RECOVERY_SESSION_TTL_MS,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          publicKey: keygen.publicKey,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: true,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
        ecdsa: ecdsaPrepare,
        ...(existingRuntimePolicyScope ? { existingRuntimePolicyScope } : {}),
      });

      return {
        ok: true,
        accountId,
        requestId,
        signerSlot,
        credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          publicKey: keygen.publicKey,
          ...(keygen.keyVersion ? { keyVersion: keygen.keyVersion } : {}),
          ...(typeof keygen.recoveryExportCapable === 'boolean'
            ? { recoveryExportCapable: keygen.recoveryExportCapable }
            : {}),
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
        ecdsa: ecdsaPrepare,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Email recovery preparation failed',
      };
    }
  }

  async respondEmailRecoveryEcdsa(request: {
    request_id?: unknown;
    requestId?: unknown;
    client_bootstrap?: unknown;
    clientBootstrap?: unknown;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        requestId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          publicKey: string;
          keyVersion: string;
          recoveryExportCapable: true;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: ThresholdEd25519BootstrapSession;
        };
        ecdsa: {
          bootstrap: EcdsaHssServerBootstrapResponse;
          walletKeys: WalletRegistrationEcdsaWalletKey[];
        };
        recoverySession: {
          sessionId: string;
          status: 'prepared';
          expiresAtMs: number;
          deadlineEpochSeconds: number;
          payloadHash: string;
        };
        recoveryEmail: {
          subject: string;
          body: string;
          payload: RecoveryEmailPayload;
          payloadHash: string;
          deadlineEpochSeconds: number;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }
      const parsed = parseEcdsaHssClientBootstrapRequest(
        request?.client_bootstrap ?? request?.clientBootstrap,
      );
      if (!parsed || parsed.clientRootProof || parsed.passkeyBootstrapAuthorization) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid Email Recovery ECDSA client bootstrap',
        };
      }

      const preparationStore = this.getEmailRecoveryPreparationStore();
      const preparation = await preparationStore.get(requestId);
      if (!preparation) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Unknown or expired email recovery preparation',
        };
      }
      if (!isMatchingEcdsaClientBootstrap(preparation.ecdsa.prepare, parsed)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email Recovery ECDSA bootstrap identity mismatch',
        };
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(parsed);
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'hss_respond_failed',
          message: bootstrap.message || 'Email Recovery ECDSA HSS bootstrap failed',
        };
      }
      const walletKeys = buildEcdsaWalletKeysFromBootstrap({
        bootstrap: bootstrap.value,
        chainTargets: preparation.ecdsa.chainTargets,
        errorContext: 'Email Recovery ECDSA bootstrap',
      });
      if (!walletKeys.ok) return walletKeys;

      const newEvmOwnerAddress = toOptionalTrimmedString(bootstrap.value.ethereumAddress);
      if (!newEvmOwnerAddress) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email Recovery ECDSA bootstrap returned no owner address',
        };
      }

      const now = Date.now();
      const recoveryDeadlineEpochSeconds = Math.floor(preparation.expiresAtMs / 1000);
      const recoveryEmailPayload = buildRecoveryEmailPayload({
        nearAccountId: preparation.accountId,
        recoverySessionId: requestId,
        newNearPublicKey: preparation.thresholdEd25519.publicKey,
        newEvmOwnerAddress,
        deadlineEpochSeconds: recoveryDeadlineEpochSeconds,
        scope: 'all-linked-evm-accounts',
      });
      const recoveryEmailPayloadHash = await hashRecoveryEmailPayload(recoveryEmailPayload);
      const recoveryEmailSubject = buildRecoveryEmailSubject(recoveryEmailPayload);
      const recoveryEmailBody = buildRecoveryEmailBody(recoveryEmailPayload);

      const authStore = this.getWebAuthnAuthenticatorStore();
      await authStore.put(preparation.accountId, {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: preparation.credentialIdB64u,
        credentialPublicKeyB64u: preparation.credentialPublicKeyB64u,
        counter: preparation.counter,
        createdAtMs: now,
        updatedAtMs: now,
      });

      const bindingStore = this.getWebAuthnCredentialBindingStore();
      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId: preparation.rpId,
        credentialIdB64u: preparation.credentialIdB64u,
        userId: preparation.accountId,
        signerSlot: preparation.signerSlot,
        publicKey: preparation.thresholdEd25519.publicKey,
        relayerKeyId: preparation.thresholdEd25519.relayerKeyId,
        keyVersion: preparation.thresholdEd25519.keyVersion,
        recoveryExportCapable: true,
        clientParticipantId: preparation.thresholdEd25519.clientParticipantId,
        relayerParticipantId: preparation.thresholdEd25519.relayerParticipantId,
        participantIds: preparation.thresholdEd25519.participantIds,
        ...(preparation.thresholdEd25519.session?.runtimePolicyScope ||
        preparation.existingRuntimePolicyScope
          ? {
              runtimePolicyScope:
                preparation.thresholdEd25519.session?.runtimePolicyScope ||
                preparation.existingRuntimePolicyScope,
            }
          : {}),
        createdAtMs: now,
        updatedAtMs: now,
      });

      const recoverySessionRecord = buildPreparedRecoverySessionRecord({
        sessionId: requestId,
        userId: preparation.accountId,
        nearAccountId: preparation.accountId,
        signerSlot: preparation.signerSlot,
        newNearPublicKey: preparation.thresholdEd25519.publicKey,
        newEvmOwnerAddress,
        recoveryDeadlineEpochSeconds,
        recoveryEmailPayloadHash,
        scope: 'all-linked-evm-accounts',
        expiresAtMs: preparation.expiresAtMs,
        metadata: {
          rpId: preparation.rpId,
          credentialIdB64u: preparation.credentialIdB64u,
          recoveryEmail: {
            subject: recoveryEmailSubject,
            body: recoveryEmailBody,
          },
          thresholdEd25519: {
            relayerKeyId: preparation.thresholdEd25519.relayerKeyId,
            ...(preparation.thresholdEd25519.session
              ? { sessionId: preparation.thresholdEd25519.session.sessionId }
              : {}),
          },
          thresholdEcdsa: {
            relayerKeyId: bootstrap.value.relayerKeyId,
            ethereumAddress: newEvmOwnerAddress,
            sessionId: bootstrap.value.sessionId,
          },
        },
      });
      if (!recoverySessionRecord) {
        return {
          ok: false,
          code: 'internal',
          message: 'Failed to build recovery session record',
        };
      }
      await this.getRecoverySessionStore().put(recoverySessionRecord);
      await preparationStore.del(requestId);

      return {
        ok: true,
        accountId: preparation.accountId,
        requestId,
        signerSlot: preparation.signerSlot,
        credentialIdB64u: preparation.credentialIdB64u,
        thresholdEd25519: preparation.thresholdEd25519,
        ecdsa: {
          bootstrap: bootstrap.value,
          walletKeys: walletKeys.walletKeys,
        },
        recoverySession: {
          sessionId: recoverySessionRecord.sessionId,
          status: 'prepared',
          expiresAtMs: recoverySessionRecord.expiresAtMs,
          deadlineEpochSeconds: recoverySessionRecord.recoveryDeadlineEpochSeconds,
          payloadHash: recoverySessionRecord.recoveryEmailPayloadHash,
        },
        recoveryEmail: {
          subject: recoveryEmailSubject,
          body: recoveryEmailBody,
          payload: recoveryEmailPayload,
          payloadHash: recoveryEmailPayloadHash,
          deadlineEpochSeconds: recoveryDeadlineEpochSeconds,
        },
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Email Recovery ECDSA response failed',
      };
    }
  }

  /**
   * Account existence helper used by registration flows.
   */
  async checkAccountExists(accountId: string): Promise<boolean> {
    await this._ensureSignerAndRelayerAccount();
    const isNotFound = (m: string) => /does not exist|UNKNOWN_ACCOUNT|unknown\s+account/i.test(m);
    const isRetryable = (m: string) =>
      /server error|internal|temporar|timeout|too many requests|429|empty response|rpc request failed/i.test(
        m,
      );
    const attempts = 3;
    let lastErr: Error | null = null;
    for (let i = 1; i <= attempts; i++) {
      try {
        const view = await this.nearClient.viewAccount(accountId);
        return !!view;
      } catch (error: unknown) {
        const err = toError(error);
        lastErr = err;
        const msg = err.message;
        const details = (err as { details?: unknown }).details;
        let detailsBlob = '';
        if (details) {
          try {
            detailsBlob = typeof details === 'string' ? details : JSON.stringify(details);
          } catch {
            detailsBlob = '';
          }
        }
        const combined = `${msg}\n${detailsBlob}`;
        if (isNotFound(combined)) return false;
        if (isRetryable(msg) && i < attempts) {
          const backoff = 150 * Math.pow(2, i - 1);
          await new Promise((r) => setTimeout(r, backoff));
          continue;
        }
        // As a safety valve for flaky RPCs, treat persistent retryable errors as not-found
        if (isRetryable(msg)) {
          this.logger.warn(
            `[AuthService] Assuming account '${accountId}' not found after retryable RPC errors:`,
            msg,
          );
          return false;
        }
        this.logger.error(`Error checking account existence for ${accountId}:`, err);
        throw err;
      }
    }
    throw lastErr || new Error('Unknown error');
  }

  /**
   * ===== Delegate actions & transaction execution =====
   *
   * Flows that build and submit on-chain transactions, including NEP-461
   * SignedDelegate meta-transactions.
   */

  /**
   * Execute a NEP-461 SignedDelegate by wrapping it in an outer transaction
   * from the relayer account. This method is intended to be called by
   * example relayers (Node/Cloudflare) once a SignedDelegate has been
   * produced by the signer worker and returned to the application.
   *
   * Notes:
   * - Signature and hash computation are performed by the signer worker.
   *   This method focuses on expiry/policy enforcement and meta-tx submission.
   * - Nonce/replay protection is left to the integrator; see docs for guidance.
   */
  async executeSignedDelegate(input: {
    hash: string;
    signedDelegate: SignedDelegate;
    policy?: DelegateActionPolicy;
  }): Promise<ExecuteSignedDelegateResult> {
    await this._ensureSignerAndRelayerAccount();

    if (!input?.hash || !input?.signedDelegate) {
      return {
        ok: false,
        code: 'invalid_delegate_request',
        error: 'hash and signedDelegate are required',
      };
    }

    const senderId = input.signedDelegate?.delegateAction?.senderId ?? 'unknown-sender';

    return this.queueTransaction(
      () =>
        executeSignedDelegateWithRelayer({
          nearClient: this.nearClient,
          relayerAccount: this.config.relayerAccount,
          relayerPublicKey: this.relayerPublicKey,
          relayerPrivateKey: this.config.relayerPrivateKey,
          hash: input.hash,
          signedDelegate: input.signedDelegate,
          policy: input.policy,
          signWithPrivateKey: (args) => this.signWithPrivateKey(args),
        }),
      `execute signed delegate for ${senderId}`,
    );
  }

  // === Internal helpers for signing & RPC ===
  private async verifyAccountAccessKeysPresent(
    accountId: string,
    expectedPublicKeys: string[],
    opts?: { attempts?: number; delayMs?: number; finality?: 'optimistic' | 'final' },
  ): Promise<boolean> {
    const unique = Array.from(
      new Set(expectedPublicKeys.map((k) => ensureEd25519Prefix(k)).filter(Boolean)),
    );
    if (!unique.length) return false;

    const attempts = Math.max(1, Math.floor(opts?.attempts ?? 4));
    const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 250));
    const finality = opts?.finality ?? 'final';

    for (let i = 0; i < attempts; i += 1) {
      try {
        const accessKeyList = await this.nearClient.viewAccessKeyList(accountId, { finality });
        const keys = accessKeyList.keys
          .map((k) => ensureEd25519Prefix(String(k?.public_key || '').trim()))
          .filter(Boolean);
        if (unique.every((expected) => keys.includes(expected))) return true;
      } catch {
        // tolerate transient RPC lag during finality propagation
      }
      if (i < attempts - 1) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }

    return false;
  }

  private scheduleAccountAccessKeyVisibilityAudit(input: {
    accountId: string;
    expectedPublicKeys: string[];
    contextLabel: string;
  }): void {
    void (async () => {
      const startedAt = Date.now();
      const verified = await this.verifyAccountAccessKeysPresent(
        input.accountId,
        input.expectedPublicKeys,
        ACCOUNT_CREATE_BACKGROUND_KEY_VISIBILITY_AUDIT,
      );
      if (verified) {
        this.logger.info(
          `${input.contextLabel} final key visibility verified=true in ${Date.now() - startedAt}ms`,
        );
        return;
      }
      this.logger.warn(
        `${input.contextLabel} final key visibility is still pending after ${
          Date.now() - startedAt
        }ms`,
      );
    })().catch((error: unknown) => {
      this.logger.warn(`${input.contextLabel} final key visibility audit failed`, error);
    });
  }

  private async fetchTxContext(
    accountId: string,
    publicKey: string,
  ): Promise<{ nextNonce: string; blockHash: string }> {
    // Access key (if missing, assume nonce=0)
    let nonce = 0n;
    try {
      const ak = await this.nearClient.viewAccessKey(accountId, publicKey);
      nonce = BigInt(ak?.nonce ?? 0);
    } catch {
      nonce = 0n;
    }
    // Block
    const block = await this.nearClient.viewBlock({ finality: 'final' });
    const txBlockHash = block.header.hash;
    const nextNonce = (nonce + 1n).toString();
    return { nextNonce, blockHash: txBlockHash };
  }

  private async signWithPrivateKey(input: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<SignedTransaction> {
    await this.ensureSignerWasm();
    const message = {
      type: WorkerRequestType.SignTransactionWithKeyPair,
      payload: {
        nearPrivateKey: input.nearPrivateKey,
        signerAccountId: input.signerAccountId,
        receiverId: input.receiverId,
        nonce: input.nonce,
        blockHash: input.blockHash,
        actions: input.actions,
      },
    };
    // uses wasm signer worker's SignTransactionWithKeyPair action (no WebAuthn/signing session required)
    let response: unknown;
    try {
      response = await handle_signer_message(message);
    } catch (e: unknown) {
      const msg = errorMessage(e);
      // Log payload for debugging (redacting private key)
      this.logger.error('Signer WASM rejected message:', {
        error: msg,
        payload: JSON.stringify(message, (key, value) =>
          key === 'nearPrivateKey' ? '[REDACTED]' : value,
        ),
      });

      // This specific error is intentionally redacted inside the WASM worker.
      // When it occurs in production, it's commonly due to a JS/WASM version mismatch
      // (the JS message schema changed but an old worker wasm is still deployed).
      if (msg.includes('Invalid payload for SIGN_TRANSACTION_WITH_KEYPAIR')) {
        throw new Error(
          `Signer WASM rejected SIGN_TRANSACTION_WITH_KEYPAIR payload: ${msg}. Rebuild + redeploy the relayer so the bundled \`wasm_signer_worker.js\` and \`wasm_signer_worker_bg.wasm\` come from the same build.`,
        );
      }
      throw e instanceof Error ? e : new Error(msg || 'Signing failed');
    }
    const { transaction, signature, borshBytes } =
      extractFirstSignedTransactionFromWorkerResponse(response);

    return new SignedTransaction({
      transaction: transaction,
      signature: signature,
      borsh_bytes: borshBytes,
    });
  }

  /**
   * Queue transactions to prevent nonce conflicts
   */
  private async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    this.logger.debug(
      `[AuthService] Queueing: ${description} (pending: ${this.queueStats.pending})`,
    );

    this.transactionQueue = this.transactionQueue
      .then(async () => {
        try {
          this.logger.debug(`[AuthService] Executing: ${description}`);
          const result = await operation();
          this.queueStats.completed++;
          this.queueStats.pending--;
          this.logger.debug(
            `[AuthService] Completed: ${description} (pending: ${this.queueStats.pending})`,
          );
          return result;
        } catch (error: any) {
          this.queueStats.failed++;
          this.queueStats.pending--;
          this.logger.error(
            `[AuthService] Failed: ${description} (failed: ${this.queueStats.failed}):`,
            errorMessage(error) || 'unknown error',
          );
          throw error;
        }
      })
      .catch((error) => {
        throw error;
      });

    return this.transactionQueue;
  }
}

interface WorkerSignedTransactionPayload {
  transaction: WasmTransaction;
  signature: WasmSignature;
  borshBytes?: number[];
  borsh_bytes?: number[];
}

function extractFirstSignedTransactionFromWorkerResponse(response: any): {
  transaction: WasmTransaction;
  signature: WasmSignature;
  borshBytes: number[];
} {
  const res = (typeof response === 'string' ? JSON.parse(response) : response) as
    | {
        type?: WorkerResponseType;
        payload?: { signedTransactions?: WorkerSignedTransactionPayload[]; error?: string };
      }
    | undefined;

  if (res?.type !== WorkerResponseType.SignTransactionWithKeyPairSuccess) {
    const errMsg = res?.payload?.error || 'Signing failed';
    throw new Error(errMsg);
  }

  const payload = res?.payload;
  const signedTxs = (payload?.signedTransactions ?? []) as WorkerSignedTransactionPayload[];
  if (!Array.isArray(signedTxs) || signedTxs.length === 0) {
    throw new Error('No signed transaction returned');
  }
  const first = signedTxs[0];
  const borshBytes = first?.borshBytes ?? first?.borsh_bytes;
  if (!Array.isArray(borshBytes)) {
    throw new Error('Missing borsh bytes');
  }
  return {
    transaction: first.transaction,
    signature: first.signature,
    borshBytes,
  };
}
