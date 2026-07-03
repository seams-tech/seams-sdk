import type { NormalizedLogger } from '../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  computeSdkEcdsaHssApplicationBindingDigest32,
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
  parseSdkEcdsaHssThresholdKeyId,
  type EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { computeSdkEd25519HssApplicationBindingDigestB64u } from '@shared/threshold/ed25519HssBinding';
import {
  parseWalletId,
  parseWalletKeyId,
  parseWebAuthnRpId,
  type WalletId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { isObject, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  deriveImplicitNearAccountIdFromEd25519PublicKey,
  isImplicitNearAccountId,
  parseNamedNearAccountId,
  parseNearAccountId,
} from '@shared/utils/near';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  formatEcdsaHssKeyVersionForWire,
  parseEcdsaHssKeyVersion,
  type EcdsaHssKeyVersion,
} from '../keyMaterialBrands';
import {
  parseRouterAbNormalSigningServerPolicy,
  validateRouterAbNormalSigningServerPolicy,
  type ParseResult,
  type RouterAbNormalSigningServerPolicy,
} from './routerAbNormalSigningPolicy';
import type { SessionClaims } from '../../router/routerApi';
import type {
  ThresholdEcdsaIntegratedKeyStore,
  ThresholdEd25519KeyStore,
} from './stores/KeyStore';
import type {
  ThresholdEcdsaMpcSessionRecord,
  ThresholdEcdsaSessionStore,
  ThresholdEd25519MpcSessionRecord,
  ThresholdEd25519SessionStore,
} from './stores/SessionStore';
import type {
  RouterAbEcdsaHssPoolFillSessionStore,
  RouterAbEcdsaHssPresignaturePool,
} from './stores/EcdsaSigningStore';
import type {
  Ed25519WalletSessionStore,
  Ed25519WalletSessionRecord,
  EcdsaWalletSessionStore,
  WalletSigningBudgetSessionStore,
  WalletSigningBudgetSessionRecord,
  WalletSessionBudgetReservationResult,
  WalletSessionBudgetReleaseResult,
} from './stores/WalletSessionStore';
import type {
  ThresholdEd25519KeygenMaterial,
  ThresholdEd25519KeygenStrategy,
} from './keygenStrategy';
import { ThresholdEd25519KeygenStrategyV1 } from './keygenStrategy';
import type {
  VerifyAuthenticationResponse,
  WebAuthnAuthenticationCredential,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
  ThresholdEd25519VerifiedWalletAuth,
  ThresholdEd25519SessionAuth,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  ThresholdEd25519HssFinalizeForRegistrationRequest,
  ThresholdEd25519HssFinalizeForRegistrationResponse,
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssFinalizeWithSessionResponse,
  ThresholdEd25519HssPrepareForRegistrationRequest,
  ThresholdEd25519HssPrepareForRegistrationResponse,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionResponse,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssPreparedServerSessionEnvelope,
  ThresholdEd25519HssRegistrationPreparedServerState,
  ThresholdEd25519HssRegistrationRespondedServerState,
  ThresholdEd25519HssStoredPreparedServerSession,
  ThresholdEd25519HssStoredRespondedServerSession,
  ThresholdEd25519HssSessionOperation,
  ThresholdEd25519HssStoredStagedEvaluatorArtifact,
  ThresholdEd25519HssServerInputs,
  ThresholdEd25519HssStoredServerInputs,
  ThresholdEd25519HssRespondForRegistrationRequest,
  ThresholdEd25519HssRespondForRegistrationResponse,
  ThresholdEd25519HssRespondWithSessionRequest,
  ThresholdEd25519HssRespondWithSessionResponse,
  ThresholdEd25519HssStagedEvaluatorArtifactEnvelope,
  ThresholdEd25519RegistrationAccountScope,
  ThresholdEd25519AuthorityScope,
  Ed25519SessionPolicy,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssExportShareRequest,
  EcdsaHssExportShareResponse,
  EcdsaHssRoleLocalKeyRecord,
  EcdsaHssRouteResult,
  EcdsaHssServerBootstrapResponse,
  ThresholdEcdsaSigningRootMetadata,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdStoreConfigInput,
} from '../types';
import {
  addSecp256k1PublicKeys33,
  roleLocalThresholdEcdsaHssRelayerBootstrap,
  secp256k1PrivateKey32ToPublicKey33,
  secp256k1PublicKey33ToEthereumAddress,
  validateSecp256k1PublicKey33,
} from './ethSignerWasm';
import { verifyEcdsaClientRootProof } from './ecdsaClientRootProof';
import {
  deriveThresholdEd25519VerifyingShareFromSigningShare,
  deriveThresholdEd25519RegistrationMaterialFromHssFinalize,
  finalizeThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssRoleSeparatedServerInputDelivery,
  prepareThresholdEd25519HssServerSession,
  releaseThresholdEd25519HssPreparedServerSession,
} from './ed25519HssWasm';
import {
  extractAuthorizeSigningPublicKey,
  parseRouterAbEd25519WalletSessionClaims,
  parseThresholdEd25519AuthorityScope,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  thresholdEd25519AuthorityScopesMatch,
  toNearPublicKeyStr,
  type RouterAbEd25519WalletSessionClaims,
  type RouterAbEcdsaHssWalletSessionClaims,
} from './validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  normalizeThresholdEd25519ParticipantId,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../thresholdEcdsaChainTarget';
import {
  coerceThresholdNodeRole,
  parseThresholdCoordinatorPeers,
  parseThresholdCoordinatorSharedSecretBytes,
  parseThresholdEd25519ParticipantIds2p,
} from './config';
import { RouterAbEcdsaHssPoolFillHandlers } from './routerAb/ecdsaHssPoolFillHandlers';
import type { RouterAbEcdsaHssPoolFillLiveSessionOwner } from './routerAb/ecdsaHssPoolFillLiveSession';
import { ThresholdEd25519SigningHandlers } from './signingHandlers';
import { resolveThresholdEd25519RelayerKeyMaterial } from './relayerKeyMaterial';
import {
  deriveEcdsaHssYRelayerFromSigningRootShareResolver,
  deriveEd25519HssServerInputsFromSigningRootShareResolver,
  type FixedSigningRootScope,
  type SigningRootShareResolver,
} from './signingRootShareResolver';
import { randomBytes } from 'node:crypto';
import type {
  ThresholdAnySchemeModule,
  ThresholdEd25519RegistrationKeygenRequest,
  ThresholdEd25519RegistrationKeygenResult,
} from './schemes/thresholdServiceSchemes.types';
import type { ThresholdSchemeId } from './schemes/schemeIds';
import {
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
  THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
} from './schemes/schemeIds';
import { createThresholdEd25519Frost2pSchemeModule } from './schemes/ed25519Frost2p';
import { createThresholdSecp256k1Ecdsa2pSchemeModule } from './schemes/secp256k1Ecdsa2p';
import { walletSigningBudgetSessionId } from './walletSigningBudget';
import { secureRandomIdFragment } from './secureRandomId';

type ThresholdEd25519SessionClaims = RouterAbEd25519WalletSessionClaims;
type ThresholdEcdsaSessionClaims = RouterAbEcdsaHssWalletSessionClaims;

export type LocalRouterAbEd25519NormalSigningSeedInput = {
  readonly relayerKeyId: string;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly rpId: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly publicKey: string;
  readonly relayerSigningShareB64u: string;
  readonly keyVersion: string;
  readonly thresholdExpiresAtMs: number;
  readonly participantIds: readonly number[];
  readonly remainingUses: number;
  readonly recoveryExportCapable: true;
};

export type LocalRouterAbEd25519NormalSigningSeedResult =
  | {
      readonly ok: true;
      readonly relayerKeyId: string;
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly remainingUses: number;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type LocalRouterAbEcdsaHssNormalSigningSeedInput = {
  readonly walletId: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly ecdsaThresholdKeyId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly walletKeyVersion: string;
  readonly derivationVersion: number;
  readonly relayerKeyId: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly thresholdExpiresAtMs: number;
  readonly participantIds: readonly number[];
  readonly remainingUses: number;
};

export type LocalRouterAbEcdsaHssNormalSigningSeedResult =
  | {
      readonly ok: true;
      readonly relayerKeyId: string;
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly remainingUses: number;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

type WalletSessionBudgetStore = Pick<
  Ed25519WalletSessionStore,
  | 'reserveUseCountOnce'
  | 'commitReservedUseCountOnce'
  | 'validateReservedUseCount'
  | 'releaseReservedUseCount'
  | 'releaseReservedUseCountForIdentity'
>;

type ThresholdEd25519HssSessionError = { ok: false; code?: string; message?: string };

function participantIdsEqual(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((id, index) => id === right[index]);
}

function passkeyRpAuthorityScope(rpId: WebAuthnRpId): ThresholdEd25519AuthorityScope {
  return { kind: 'passkey_rp', rpId };
}

function thresholdEd25519PasskeyAuthorityRpId(
  scope: ThresholdEd25519AuthorityScope,
): WebAuthnRpId | null {
  switch (scope.kind) {
    case 'passkey_rp':
      return scope.rpId;
    case 'email_otp':
      return null;
  }
}

function verifyImplicitNearAccountPublicKeyBinding(input: {
  nearAccountId: string;
  relayerPublicKey: string;
}): ParseResult<void> {
  try {
    const expectedAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(
      input.relayerPublicKey,
    );
    if (expectedAccountId !== input.nearAccountId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'implicit nearAccountId does not match threshold Ed25519 public key',
      };
    }
    return { ok: true, value: undefined };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: `Failed to verify implicit account scope: ${errorMessage(error)}`,
    };
  }
}

function requireSdkEcdsaHssWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

const ED25519_HSS_SERVER_VISIBLE_CLIENT_REQUEST_FORBIDDEN_FIELDS = [
  'evaluatorOtStateB64u',
  'yClientB64u',
  'tauClientB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'yRelayerB64u',
  'tauRelayerB64u',
] as const;

const ED25519_HSS_CLIENT_OWNED_STAGED_ARTIFACT_FORBIDDEN_FIELDS = [
  'serverEvalFinalizeOutputB64u',
  'stagedEvaluatorArtifactHandle',
  'evaluatorOtStateB64u',
  'xClientBaseB64u',
  'xRelayerBaseB64u',
  'yClientB64u',
  'tauClientB64u',
  'yRelayerB64u',
  'tauRelayerB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'seedOutputMessageB64u',
] as const;

function findOwnField(raw: Record<string, unknown>, fields: readonly string[]): string | undefined {
  return fields.find((field) => Object.prototype.hasOwnProperty.call(raw, field));
}

export type ThresholdEd25519HssCeremonyRecord =
  | {
      kind: 'session';
      expiresAtMs: number;
      relayerKeyId: string;
      operation: ThresholdEd25519HssSessionOperation;
      context: ThresholdEd25519HssCanonicalContext;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
      serverInputs?: ThresholdEd25519HssStoredServerInputs;
      evaluationResult?: ThresholdEd25519HssStoredStagedEvaluatorArtifact;
    }
  | {
      kind: 'registration';
      expiresAtMs: number;
      orgId: string;
      registrationAccountScope: ThresholdEd25519RegistrationAccountScope;
      context: ThresholdEd25519HssCanonicalContext;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
      serverInputs?: ThresholdEd25519HssStoredServerInputs;
      evaluationResult?: ThresholdEd25519HssStoredStagedEvaluatorArtifact;
    };

type ThresholdEd25519HssCeremonyRecordInput =
  | Omit<Extract<ThresholdEd25519HssCeremonyRecord, { kind: 'session' }>, 'expiresAtMs'>
  | Omit<Extract<ThresholdEd25519HssCeremonyRecord, { kind: 'registration' }>, 'expiresAtMs'>;

export interface ThresholdEd25519HssCeremonyStore {
  cleanupExpired(nowMs: number): Promise<void>;
  put(handle: string, record: ThresholdEd25519HssCeremonyRecord): Promise<void>;
  get(handle: string): Promise<ThresholdEd25519HssCeremonyRecord | null>;
  take(handle: string): Promise<ThresholdEd25519HssCeremonyRecord | null>;
  delete(handle: string): Promise<void>;
}

class InMemoryThresholdEd25519HssCeremonyStore implements ThresholdEd25519HssCeremonyStore {
  private readonly records = new Map<string, ThresholdEd25519HssCeremonyRecord>();

  async cleanupExpired(nowMs: number): Promise<void> {
    for (const [handle, record] of this.records.entries()) {
      if (record.expiresAtMs <= nowMs) {
        this.records.delete(handle);
      }
    }
  }

  async put(handle: string, record: ThresholdEd25519HssCeremonyRecord): Promise<void> {
    this.records.set(handle, record);
  }

  async get(handle: string): Promise<ThresholdEd25519HssCeremonyRecord | null> {
    const record = this.records.get(handle);
    if (!record) return null;
    if (record.expiresAtMs <= Date.now()) {
      this.records.delete(handle);
      return null;
    }
    return record;
  }

  async take(handle: string): Promise<ThresholdEd25519HssCeremonyRecord | null> {
    const record = await this.get(handle);
    this.records.delete(handle);
    return record;
  }

  async delete(handle: string): Promise<void> {
    this.records.delete(handle);
  }
}

type ThresholdEcdsaBootstrapSessionResult =
  | {
      ok: true;
      sessionId: string;
      signingGrantId?: string;
      chainTarget?: ThresholdEcdsaChainTarget;
      ecdsaThresholdKeyId?: string;
      keyHandle?: string;
      expiresAtMs: number;
      expiresAt: string;
      participantIds: number[];
      remainingUses?: number;
      jwt?: string;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

type ThresholdEcdsaWalletSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

function routerAbBudgetStoreFailure(input: { code: string; message: string }): {
  ok: false;
  status: number;
  code: string;
  message: string;
} {
  const code = toOptionalTrimmedString(input.code) || 'wallet_budget_internal';
  const message = toOptionalTrimmedString(input.message) || 'Wallet Session budget rejected';
  switch (code) {
    case 'unauthorized':
      return { ok: false, status: 401, code, message };
    case 'wallet_budget_forbidden':
      return { ok: false, status: 403, code, message };
    case 'wallet_budget_exhausted':
    case 'wallet_budget_in_flight':
    case 'wallet_budget_reservation_mismatch':
      return { ok: false, status: 409, code, message };
    case 'wallet_budget_reservation_expired':
      return { ok: false, status: 410, code, message };
    case 'invalid_budget_request':
    case 'invalid_body':
      return { ok: false, status: 422, code: 'invalid_budget_request', message };
    default:
      return { ok: false, status: 500, code: 'wallet_budget_internal', message };
  }
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

type ThresholdNearTransactionDispatchResult = {
  rpcResult: unknown;
};

type ThresholdNearTransactionDispatcher = (input: {
  signedTransactionBorshB64u: string;
}) => Promise<ThresholdNearTransactionDispatchResult>;

function isEcdsaHssPublicKeyValidationError(message: string): boolean {
  const normalized = message.toLowerCase();
  return (
    normalized.includes('public key') &&
    (normalized.includes('invalid') ||
      normalized.includes('secp256k1') ||
      normalized.includes('point') ||
      normalized.includes('identity'))
  );
}

function compactDiagnosticValue(value: unknown): string | null {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) return null;
  return normalized.length <= 16
    ? normalized
    : `${normalized.slice(0, 10)}...${normalized.slice(-6)}`;
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length;
}

function jsonBytes(value: unknown): number {
  return utf8Bytes(JSON.stringify(value));
}

function bytesToLowerHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

const THRESHOLD_ECDSA_HSS_KEY_PURPOSE_V1 = 'evm-signing';
const THRESHOLD_ECDSA_HSS_KEY_VERSION_V1 = parseEcdsaHssKeyVersion('v1');
const THRESHOLD_ECDSA_SIGNING_ROOT_VERSION_DEFAULT = 'default';
const THRESHOLD_ECDSA_DERIVATION_VERSION_V1 = 1;
const THRESHOLD_ECDSA_HSS_EXPORT_CLOCK_SKEW_MS = 5 * 60_000;
const THRESHOLD_ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-confirmation:v2';
const THRESHOLD_ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-authorization:v2';
const WALLET_SIGNING_BUDGET_RELAYER_KEY_ID = 'wallet-signing-budget';

export type ThresholdEcdsaKeyIdentityMetadata = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyScope: 'evm-family';
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  participantIds: number[];
  thresholdOwnerAddress: string;
  thresholdEcdsaPublicKeyB64u: string;
};

type EcdsaSigningRootReference = {
  signingRootId: string;
  signingRootVersion?: string;
};

function canonicalEcdsaHssSigningRootVersion(signingRootVersion: unknown): string {
  return toOptionalTrimmedString(signingRootVersion) || 'default';
}

function parseEcdsaHssKeyVersionOrDefault(value: unknown): EcdsaHssKeyVersion {
  const raw = toOptionalTrimmedString(value);
  return raw ? parseEcdsaHssKeyVersion(raw) : THRESHOLD_ECDSA_HSS_KEY_VERSION_V1;
}

function ecdsaHssKeyVersionWire(value: EcdsaHssKeyVersion): string {
  return formatEcdsaHssKeyVersionForWire(value);
}

async function deriveThresholdEcdsaHssKeyHandle(input: {
  readonly ecdsaThresholdKeyId: unknown;
  readonly signingRootId: unknown;
  readonly signingRootVersion?: unknown;
}): Promise<string> {
  return String(
    await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
  );
}

function createEcdsaSigningRootMetadata(
  signingRootId: string,
  signingRootVersion?: string,
  ecdsaHssKeyVersion: EcdsaHssKeyVersion = THRESHOLD_ECDSA_HSS_KEY_VERSION_V1,
): ThresholdEcdsaSigningRootMetadata {
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    walletKeyVersion: ecdsaHssKeyVersionWire(ecdsaHssKeyVersion),
    derivationVersion: THRESHOLD_ECDSA_DERIVATION_VERSION_V1,
  };
}

function ecdsaHssRoleLocalRecordMatchesBootstrap(
  record: EcdsaHssRoleLocalKeyRecord,
  bootstrap: EcdsaHssServerBootstrapResponse,
): boolean {
  return (
    record.walletId === bootstrap.walletId &&
    record.evmFamilySigningKeySlotId === bootstrap.evmFamilySigningKeySlotId &&
    record.ecdsaThresholdKeyId === bootstrap.ecdsaThresholdKeyId &&
    record.keyHandle === bootstrap.keyHandle &&
    record.signingRootId === bootstrap.signingRootId &&
    record.signingRootVersion ===
      canonicalEcdsaHssSigningRootVersion(bootstrap.signingRootVersion) &&
    record.keyScope === 'evm-family' &&
    record.relayerKeyId === bootstrap.relayerKeyId &&
    record.contextBinding32B64u === bootstrap.contextBinding32B64u &&
    record.clientPublicKey33B64u === bootstrap.publicIdentity.hssClientSharePublicKey33B64u &&
    record.relayerPublicKey33B64u === bootstrap.publicIdentity.relayerPublicKey33B64u &&
    record.groupPublicKey33B64u === bootstrap.publicIdentity.groupPublicKey33B64u &&
    record.ethereumAddress.toLowerCase() ===
      bootstrap.publicIdentity.ethereumAddress.toLowerCase() &&
    record.groupPublicKey33B64u === bootstrap.thresholdEcdsaPublicKeyB64u &&
    record.ethereumAddress.toLowerCase() === bootstrap.ethereumAddress.toLowerCase() &&
    record.relayerPublicKey33B64u === bootstrap.relayerVerifyingShareB64u
  );
}

function createEcdsaSigningRootReference(input: {
  readonly signingRootId: unknown;
  readonly signingRootVersion?: unknown;
}): EcdsaSigningRootReference | null {
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  if (!signingRootId) return null;
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
  };
}

function resolveEcdsaSigningRootFromScope(scope: unknown): EcdsaSigningRootReference | null {
  if (!isObject(scope)) return null;
  try {
    return createEcdsaSigningRootReference(
      signingRootScopeFromRuntimePolicyScope(scope as RuntimePolicyScope),
    );
  } catch {
    return null;
  }
}

function haveSameEcdsaSigningRootMetadata(
  left: Partial<ThresholdEcdsaSigningRootMetadata> | null | undefined,
  right: Partial<ThresholdEcdsaSigningRootMetadata> | null | undefined,
): boolean {
  return Boolean(
    left &&
    right &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion &&
    left.walletKeyVersion === right.walletKeyVersion &&
    left.derivationVersion === right.derivationVersion,
  );
}

function parseThresholdEd25519HssSessionOperation(
  raw: unknown,
): ParseResult<ThresholdEd25519HssSessionOperation> {
  const value = toOptionalTrimmedString(raw);
  switch (value) {
    case 'tx_signing':
    case 'link_device':
    case 'email_recovery':
    case 'warm_session_reconstruction':
    case 'explicit_key_export':
      return { ok: true, value };
    default:
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'operation must be one of tx_signing, link_device, email_recovery, warm_session_reconstruction, explicit_key_export',
      };
  }
}

function thresholdEd25519HssSessionOperationIncludesSeedOutput(
  operation: ThresholdEd25519HssSessionOperation,
): boolean {
  return operation === 'explicit_key_export';
}

function base64UrlPayloadBytes(value: string): number {
  try {
    return base64UrlDecode(String(value || '')).length;
  } catch {
    return 0;
  }
}

function storedThresholdEd25519HssEvaluationResultFromClientOwnedEnvelope(
  evaluationResult: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
): ThresholdEd25519HssStoredStagedEvaluatorArtifact {
  return {
    stagedEvaluatorArtifactBytes: base64UrlDecode(evaluationResult.stagedEvaluatorArtifactB64u),
  };
}

function thresholdEd25519HssEvaluationResultTransportBytes(
  evaluationResult: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
): number {
  return utf8Bytes(evaluationResult.stagedEvaluatorArtifactB64u);
}

function thresholdEd25519HssEvaluationResultPayloadBytes(
  evaluationResult: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
): number {
  return base64UrlPayloadBytes(evaluationResult.stagedEvaluatorArtifactB64u);
}

function summarizeThresholdEd25519HssCeremonyRecordBytes(
  record: ThresholdEd25519HssCeremonyRecordInput | ThresholdEd25519HssCeremonyRecord,
): Record<string, number> {
  const respondedServerSession = requireThresholdEd25519HssRespondedServerSession(
    record.preparedServerSession,
  );
  const preparedServerSessionBytes =
    record.preparedServerSession.evaluatorDriverStateBytes.byteLength +
    record.preparedServerSession.garblerDriverStateBytes.byteLength +
    (respondedServerSession ? respondedServerSession.serverEvalStateBytes.byteLength : 0);
  const serverInputsBytes = record.serverInputs
    ? record.serverInputs.yRelayerBytes.byteLength + record.serverInputs.tauRelayerBytes.byteLength
    : 0;
  const evaluationResultBytes =
    'evaluationResult' in record && record.evaluationResult
      ? record.evaluationResult.stagedEvaluatorArtifactBytes.byteLength
      : 0;
  const totalWithoutEvaluationResult =
    'evaluationResult' in record && record.evaluationResult
      ? (() => {
          const { evaluationResult: _ignored, ...rest } = record;
          return jsonBytes(rest);
        })()
      : jsonBytes(record);
  const base: Record<string, number> = {
    totalBytes: totalWithoutEvaluationResult + evaluationResultBytes,
    contextBytes: jsonBytes(record.context),
    preparedSessionBytes: jsonBytes(record.preparedSession),
    preparedServerSessionBytes,
    serverInputsBytes,
  };
  if (record.kind === 'session') {
    base.relayerKeyIdBytes = utf8Bytes(record.relayerKeyId);
    base.operationBytes = utf8Bytes(record.operation);
  } else {
    base.orgIdBytes = utf8Bytes(record.orgId);
    base.registrationAccountScopeBytes = jsonBytes(record.registrationAccountScope);
    base.nearEd25519SigningKeyIdBytes = utf8Bytes(
      record.registrationAccountScope.nearEd25519SigningKeyId,
    );
  }
  if ('evaluationResult' in record && record.evaluationResult) {
    base.evaluationResultBytes = evaluationResultBytes;
    base.stagedEvaluatorArtifactBytes =
      record.evaluationResult.stagedEvaluatorArtifactBytes.byteLength;
  }
  if (respondedServerSession) {
    base.serverEvalStateBytes = respondedServerSession.serverEvalStateBytes.byteLength;
  }
  return base;
}

function clearThresholdEd25519HssStoredServerInputs(
  serverInputs: ThresholdEd25519HssStoredServerInputs | undefined,
): void {
  if (!serverInputs) return;
  serverInputs.yRelayerBytes.fill(0);
  serverInputs.tauRelayerBytes.fill(0);
}

function summarizeThresholdEd25519HssWasmBreakdown(
  timings:
    | {
        decodeStatesMs: number;
        decodeMessagesMs: number;
        materializeRuntimeMs: number;
        materializeSessionsMs: number;
        ceremonyCoreMs: number;
        ceremonyOtOpenJoinMs?: number;
        ceremonyOtBranchKeyDerivationMs?: number;
        ceremonyOtBranchDecryptMs?: number;
        ceremonyOtPointScalarReconstructionMs?: number;
        ceremonyOtCommitmentVerificationMs?: number;
        ceremonyServerInputOpenMs?: number;
        ceremonyServerInputShareMs?: number;
        ceremonyServerInputCommitmentMs?: number;
        ceremonyServerInputTranscriptMs?: number;
        ceremonyAddStageMs?: number;
        ceremonyMessageScheduleMs?: number;
        ceremonyRoundCoreMs?: number;
        ceremonyOutputProjectorMs?: number;
        ceremonyResultAssemblyMs?: number;
        ceremonyOutputSealingFinalizationMs?: number;
        encodeArtifactMs: number;
      }
    | undefined,
): Record<string, number | string> | null {
  if (!timings) return null;
  const buckets = [
    ['decodeStatesMs', Number(timings.decodeStatesMs || 0)],
    ['decodeMessagesMs', Number(timings.decodeMessagesMs || 0)],
    ['materializeRuntimeMs', Number(timings.materializeRuntimeMs || 0)],
    ['materializeSessionsMs', Number(timings.materializeSessionsMs || 0)],
    ['ceremonyCoreMs', Number(timings.ceremonyCoreMs || 0)],
    ['encodeArtifactMs', Number(timings.encodeArtifactMs || 0)],
  ] as const;
  const [dominantBucket, dominantBucketMs] = buckets.reduce((best, next) =>
    next[1] > best[1] ? next : best,
  );
  const ceremonyBuckets = [
    ['ceremonyAddStageMs', Number(timings.ceremonyAddStageMs || 0)],
    ['ceremonyMessageScheduleMs', Number(timings.ceremonyMessageScheduleMs || 0)],
    ['ceremonyRoundCoreMs', Number(timings.ceremonyRoundCoreMs || 0)],
    ['ceremonyOutputProjectorMs', Number(timings.ceremonyOutputProjectorMs || 0)],
    ['ceremonyOtOpenJoinMs', Number(timings.ceremonyOtOpenJoinMs || 0)],
    ['ceremonyOtBranchKeyDerivationMs', Number(timings.ceremonyOtBranchKeyDerivationMs || 0)],
    ['ceremonyOtBranchDecryptMs', Number(timings.ceremonyOtBranchDecryptMs || 0)],
    [
      'ceremonyOtPointScalarReconstructionMs',
      Number(timings.ceremonyOtPointScalarReconstructionMs || 0),
    ],
    ['ceremonyOtCommitmentVerificationMs', Number(timings.ceremonyOtCommitmentVerificationMs || 0)],
    ['ceremonyServerInputOpenMs', Number(timings.ceremonyServerInputOpenMs || 0)],
    ['ceremonyServerInputShareMs', Number(timings.ceremonyServerInputShareMs || 0)],
    ['ceremonyServerInputCommitmentMs', Number(timings.ceremonyServerInputCommitmentMs || 0)],
    ['ceremonyServerInputTranscriptMs', Number(timings.ceremonyServerInputTranscriptMs || 0)],
    ['ceremonyResultAssemblyMs', Number(timings.ceremonyResultAssemblyMs || 0)],
    [
      'ceremonyOutputSealingFinalizationMs',
      Number(timings.ceremonyOutputSealingFinalizationMs || 0),
    ],
  ] as const;
  const [dominantCeremonyStage, dominantCeremonyStageMs] = ceremonyBuckets.reduce((best, next) =>
    next[1] > best[1] ? next : best,
  );
  const hasMeasuredCeremonyStageBreakdown = dominantCeremonyStageMs > 0;
  return {
    totalMeasuredMs: buckets.reduce((sum, [, value]) => sum + value, 0),
    materializationMs:
      Number(timings.materializeRuntimeMs || 0) + Number(timings.materializeSessionsMs || 0),
    dominantBucket,
    dominantBucketMs,
    dominantCeremonyStage: hasMeasuredCeremonyStageBreakdown
      ? dominantCeremonyStage
      : 'unavailable',
    dominantCeremonyStageMs: hasMeasuredCeremonyStageBreakdown ? dominantCeremonyStageMs : 0,
  };
}

function isEthSignerWasmRuntimeError(messageRaw: string): boolean {
  const message = String(messageRaw || '').toLowerCase();
  return (
    message.includes('eth_signer wasm') ||
    message.includes('initialize eth_signer wasm') ||
    message.includes('not initialized')
  );
}

function parseThresholdEd25519SessionRequest(
  request: ThresholdEd25519SessionRequest,
  participantIds2p: number[],
): ParseResult<{
  relayerKeyId: string;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authority: Ed25519SessionPolicy['authority'];
  authorityScope: ThresholdEd25519AuthorityScope;
  thresholdSessionId: string;
  signingGrantId: string;
  runtimePolicyScope?: RuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  ttlMsRaw: number;
  remainingUsesRaw: number;
  policyParticipantIds: number[] | null;
  expectedOrigin: string | null;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  }

  const policyRaw = (rec as { sessionPolicy?: unknown }).sessionPolicy;
  if (!isObject(policyRaw)) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy (object) is required' };
  }
  const version = toOptionalTrimmedString((policyRaw as Record<string, unknown>).version);
  if (version !== 'threshold_session_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.version must be threshold_session_v1',
    };
  }
  const nearAccountId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).nearAccountId,
  );
  const nearEd25519SigningKeyId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).nearEd25519SigningKeyId,
  );
  if (Object.prototype.hasOwnProperty.call(policyRaw, 'rpId')) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.rpId belongs in sessionPolicy.authority',
    };
  }
  const authority = parseWalletAuthAuthority((policyRaw as Record<string, unknown>).authority);
  const walletId = authority ? toOptionalTrimmedString(authority.walletId) : '';
  const authorityScope = authority
    ? thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority)
    : null;
  const thresholdSessionId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).thresholdSessionId,
  );
  const signingGrantId =
    toOptionalTrimmedString((policyRaw as Record<string, unknown>).signingGrantId) ||
    thresholdSessionId;
  const policyRelayerKeyId = toOptionalTrimmedString(
    (policyRaw as Record<string, unknown>).relayerKeyId,
  );
  let runtimePolicyScope: RuntimePolicyScope | undefined;
  if (Object.prototype.hasOwnProperty.call(policyRaw, 'runtimePolicyScope')) {
    try {
      runtimePolicyScope = normalizeRuntimePolicyScope(
        (policyRaw as Record<string, unknown>).runtimePolicyScope,
      );
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'sessionPolicy.runtimePolicyScope must be a valid runtime policy scope',
      };
    }
  }
  let routerAbNormalSigning: RouterAbEd25519NormalSigningState | undefined;
  if (Object.prototype.hasOwnProperty.call(policyRaw, 'routerAbNormalSigning')) {
    try {
      const parsedRouterAbNormalSigning = parseRouterAbEd25519NormalSigningState(
        (policyRaw as Record<string, unknown>).routerAbNormalSigning,
      );
      if (!parsedRouterAbNormalSigning) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'sessionPolicy.routerAbNormalSigning must be a Router A/B normal-signing state',
        };
      }
      routerAbNormalSigning = parsedRouterAbNormalSigning;
    } catch (error) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          error && typeof error === 'object' && 'message' in error
            ? String((error as { message?: unknown }).message)
            : 'sessionPolicy.routerAbNormalSigning is invalid',
      };
    }
  }
  const ttlMsRaw = Number((policyRaw as Record<string, unknown>).ttlMs);
  const remainingUsesRaw = Number((policyRaw as Record<string, unknown>).remainingUses);
  const authRaw = (rec as { auth?: unknown }).auth;
  if (!isObject(authRaw)) {
    return { ok: false, code: 'invalid_body', message: 'auth is required' };
  }
  const authKind = toOptionalTrimmedString((authRaw as Record<string, unknown>).kind);
  if (authKind !== 'verified_wallet' && authKind !== 'passkey') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth.kind must be verified_wallet or passkey',
    };
  }
  const expectedOrigin =
    authKind === 'passkey'
      ? toOptionalTrimmedString((authRaw as Record<string, unknown>).expected_origin) || null
      : null;
  if (authKind === 'passkey' && !expectedOrigin) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth.expected_origin is required for passkey auth',
    };
  }
  if (
    !authority ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !authorityScope ||
    !thresholdSessionId ||
    !signingGrantId ||
    !policyRelayerKeyId
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message:
        'sessionPolicy{authority,nearAccountId,nearEd25519SigningKeyId,relayerKeyId,thresholdSessionId,signingGrantId} are required',
    };
  }
  if (policyRelayerKeyId !== relayerKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.relayerKeyId must match relayerKeyId',
    };
  }

  const policyHasParticipantIds = Object.prototype.hasOwnProperty.call(policyRaw, 'participantIds');
  const policyParticipantIds = normalizeThresholdEd25519ParticipantIds(
    (policyRaw as Record<string, unknown>).participantIds,
  );
  if (policyHasParticipantIds && !policyParticipantIds) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.participantIds must be a non-empty array of positive integers',
    };
  }
  if (policyParticipantIds) {
    if (policyParticipantIds.length < 2) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'sessionPolicy.participantIds must contain at least 2 participant ids',
      };
    }
    for (const id of participantIds2p) {
      if (!policyParticipantIds.includes(id)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: `sessionPolicy.participantIds must include server signer set (expected to include participantIds=[${participantIds2p.join(',')}])`,
        };
      }
    }
  }

  if (!Number.isFinite(ttlMsRaw) || ttlMsRaw <= 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.ttlMs must be a positive number',
    };
  }
  if (!Number.isFinite(remainingUsesRaw) || remainingUsesRaw <= 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'sessionPolicy.remainingUses must be a positive number',
    };
  }

  return {
    ok: true,
    value: {
      relayerKeyId,
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      authority,
      authorityScope,
      thresholdSessionId,
      signingGrantId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds: policyParticipantIds || null,
      expectedOrigin,
    },
  };
}

type AuthorizedThresholdEd25519SessionAuth =
  | {
      kind: 'authorized_app_session';
      walletAuth: Extract<ThresholdEd25519VerifiedWalletAuth, { kind: 'app_session' }>;
      webauthnAuthentication?: never;
    }
  | {
      kind: 'authorized_threshold_ecdsa_session';
      walletAuth: Extract<
        ThresholdEd25519VerifiedWalletAuth,
        { kind: 'threshold_ecdsa_session' }
      >;
      webauthnAuthentication?: never;
    }
  | {
      kind: 'passkey_challenge_response';
      walletAuth?: never;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
    };

function resolveAuthorizedThresholdEd25519SessionAuth(input: {
  auth: ThresholdEd25519SessionAuth;
  hasAppSessionAuth: boolean;
  hasEcdsaSessionAuth: boolean;
}): ParseResult<AuthorizedThresholdEd25519SessionAuth> {
  switch (input.auth.kind) {
    case 'verified_wallet': {
      switch (input.auth.walletAuth.kind) {
        case 'app_session':
          if (!input.hasAppSessionAuth) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'app session does not match threshold-ed25519 session scope',
            };
          }
          return {
            ok: true,
            value: {
              kind: 'authorized_app_session',
              walletAuth: input.auth.walletAuth,
            },
          };
        case 'threshold_ecdsa_session':
          if (!input.hasEcdsaSessionAuth) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'threshold-ecdsa session does not match threshold-ed25519 session scope',
            };
          }
          return {
            ok: true,
            value: {
              kind: 'authorized_threshold_ecdsa_session',
              walletAuth: input.auth.walletAuth,
            },
          };
        default:
          return assertNever(input.auth.walletAuth);
      }
    }
    case 'passkey':
      return {
        ok: true,
        value: {
          kind: 'passkey_challenge_response',
          webauthnAuthentication: input.auth.webauthn_authentication,
        },
      };
    default:
      return assertNever(input.auth);
  }
}

function parseThresholdEd25519HssCanonicalContext(
  raw: unknown,
): ParseResult<ThresholdEd25519HssCanonicalContext> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'context is required' };
  }
  const forbidden = [
    'signingRootId',
    'signing_root_id',
    'nearAccountId',
    'near_account_id',
    'accountId',
    'account_id',
    'keyPurpose',
    'key_purpose',
    'keyVersion',
    'key_version',
    'nearEd25519SigningKeyId',
    'near_ed25519_signing_key_id',
    'signingRootVersion',
    'signing_root_version',
    'derivationVersion',
    'derivation_version',
  ] as const;
  for (const field of forbidden) {
    if (Object.prototype.hasOwnProperty.call(raw, field)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `context.${field} is not allowed in Ed25519-HSS context`,
      };
    }
  }
  const applicationBindingDigestB64u = toOptionalTrimmedString(raw.applicationBindingDigestB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  if (!applicationBindingDigestB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'context.applicationBindingDigestB64u is required',
    };
  }
  try {
    const decoded = base64UrlDecode(applicationBindingDigestB64u);
    if (decoded.length !== 32) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'context.applicationBindingDigestB64u must decode to 32 bytes',
      };
    }
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'context.applicationBindingDigestB64u must be valid base64url',
    };
  }
  if (!participantIds || participantIds.length < 2) {
    return { ok: false, code: 'invalid_body', message: 'context.participantIds is required' };
  }
  return {
    ok: true,
    value: {
      applicationBindingDigestB64u,
      participantIds,
    },
  };
}

function decodeThresholdEd25519HssBase64UrlField(
  raw: unknown,
  fieldName: string,
): ParseResult<Uint8Array> {
  const value = toOptionalTrimmedString(raw);
  if (!value) {
    return { ok: false, code: 'invalid_body', message: `${fieldName} is required` };
  }
  try {
    const decoded = base64UrlDecode(value);
    if (decoded.byteLength === 0) {
      return { ok: false, code: 'invalid_body', message: `${fieldName} must not be empty` };
    }
    return { ok: true, value: decoded };
  } catch {
    return { ok: false, code: 'invalid_body', message: `${fieldName} must be valid base64url` };
  }
}

function decodeThresholdEd25519HssPresentBase64UrlField(
  raw: unknown,
  fieldName: string,
): ParseResult<Uint8Array> {
  if (typeof raw !== 'string') {
    return { ok: false, code: 'invalid_body', message: `${fieldName} is required` };
  }
  try {
    return { ok: true, value: base64UrlDecode(raw.trim()) };
  } catch {
    return { ok: false, code: 'invalid_body', message: `${fieldName} must be valid base64url` };
  }
}

function parseThresholdEd25519HssPersistedPreparedServerSession(
  raw: unknown,
): ParseResult<ThresholdEd25519HssStoredPreparedServerSession> {
  if (!isObject(raw)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'serverState.preparedServerSession is required',
    };
  }
  if (toOptionalTrimmedString(raw.preparedSessionHandle)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'serverState.preparedServerSession.preparedSessionHandle is process-local',
    };
  }
  const evaluatorDriverStateBytes = decodeThresholdEd25519HssBase64UrlField(
    raw.evaluatorDriverStateB64u,
    'serverState.preparedServerSession.evaluatorDriverStateB64u',
  );
  if (!evaluatorDriverStateBytes.ok) return evaluatorDriverStateBytes;
  const garblerDriverStateBytes = decodeThresholdEd25519HssBase64UrlField(
    raw.garblerDriverStateB64u,
    'serverState.preparedServerSession.garblerDriverStateB64u',
  );
  if (!garblerDriverStateBytes.ok) return garblerDriverStateBytes;
  return {
    ok: true,
    value: {
      evaluatorDriverStateBytes: evaluatorDriverStateBytes.value,
      garblerDriverStateBytes: garblerDriverStateBytes.value,
    },
  };
}

function parseThresholdEd25519HssPersistedRespondedServerSession(
  raw: unknown,
): ParseResult<ThresholdEd25519HssStoredRespondedServerSession> {
  const preparedServerSession = parseThresholdEd25519HssPersistedPreparedServerSession(raw);
  if (!preparedServerSession.ok) return preparedServerSession;
  if (!isObject(raw)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'serverState.preparedServerSession is required',
    };
  }
  const serverEvalStateBytes = decodeThresholdEd25519HssPresentBase64UrlField(
    raw.serverEvalStateB64u,
    'serverState.preparedServerSession.serverEvalStateB64u',
  );
  if (!serverEvalStateBytes.ok) return serverEvalStateBytes;
  return {
    ok: true,
    value: {
      ...preparedServerSession.value,
      serverEvalStateBytes: serverEvalStateBytes.value,
    },
  };
}

function parseThresholdEd25519HssPersistedServerInputs(
  raw: unknown,
): ParseResult<ThresholdEd25519HssStoredServerInputs> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'serverState.serverInputs is required' };
  }
  const yRelayerBytes = decodeThresholdEd25519HssBase64UrlField(
    raw.yRelayerB64u,
    'serverState.serverInputs.yRelayerB64u',
  );
  if (!yRelayerBytes.ok) return yRelayerBytes;
  const tauRelayerBytes = decodeThresholdEd25519HssBase64UrlField(
    raw.tauRelayerB64u,
    'serverState.serverInputs.tauRelayerB64u',
  );
  if (!tauRelayerBytes.ok) return tauRelayerBytes;
  return {
    ok: true,
    value: {
      yRelayerBytes: yRelayerBytes.value,
      tauRelayerBytes: tauRelayerBytes.value,
    },
  };
}

function parseThresholdEd25519HssRegistrationPreparedServerState(raw: unknown): ParseResult<{
  context: ThresholdEd25519HssCanonicalContext;
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
  serverInputs: ThresholdEd25519HssStoredServerInputs;
}> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'serverState is required' };
  }
  const context = parseThresholdEd25519HssCanonicalContext(raw.context);
  if (!context.ok) return context;
  const preparedServerSession = parseThresholdEd25519HssPersistedPreparedServerSession(
    raw.preparedServerSession,
  );
  if (!preparedServerSession.ok) return preparedServerSession;
  const serverInputs = parseThresholdEd25519HssPersistedServerInputs(raw.serverInputs);
  if (!serverInputs.ok) return serverInputs;
  return {
    ok: true,
    value: {
      context: context.value,
      preparedServerSession: preparedServerSession.value,
      serverInputs: serverInputs.value,
    },
  };
}

function parseThresholdEd25519HssRegistrationRespondedServerState(raw: unknown): ParseResult<{
  context: ThresholdEd25519HssCanonicalContext;
  preparedServerSession: ThresholdEd25519HssStoredRespondedServerSession;
}> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'serverState is required' };
  }
  if (Object.prototype.hasOwnProperty.call(raw, 'serverInputs')) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'serverState.serverInputs is valid only before respond',
    };
  }
  const context = parseThresholdEd25519HssCanonicalContext(raw.context);
  if (!context.ok) return context;
  const preparedServerSession = parseThresholdEd25519HssPersistedRespondedServerSession(
    raw.preparedServerSession,
  );
  if (!preparedServerSession.ok) return preparedServerSession;
  return {
    ok: true,
    value: {
      context: context.value,
      preparedServerSession: preparedServerSession.value,
    },
  };
}

function thresholdEd25519HssRegistrationPreparedServerState(input: {
  readonly context: ThresholdEd25519HssCanonicalContext;
  readonly preparedServerSession: ThresholdEd25519HssPreparedServerSessionEnvelope;
  readonly serverInputs: ThresholdEd25519HssServerInputs;
}): ThresholdEd25519HssRegistrationPreparedServerState {
  return {
    context: input.context,
    preparedServerSession: {
      evaluatorDriverStateB64u: input.preparedServerSession.evaluatorDriverStateB64u,
      garblerDriverStateB64u: input.preparedServerSession.garblerDriverStateB64u,
    },
    serverInputs: {
      yRelayerB64u: input.serverInputs.yRelayerB64u,
      tauRelayerB64u: input.serverInputs.tauRelayerB64u,
    },
  };
}

function thresholdEd25519HssRegistrationRespondedServerState(input: {
  readonly context: ThresholdEd25519HssCanonicalContext;
  readonly preparedServerSession: ThresholdEd25519HssStoredRespondedServerSession;
}): ThresholdEd25519HssRegistrationRespondedServerState {
  return {
    context: input.context,
    preparedServerSession: {
      evaluatorDriverStateB64u: base64UrlEncode(
        input.preparedServerSession.evaluatorDriverStateBytes,
      ),
      garblerDriverStateB64u: base64UrlEncode(input.preparedServerSession.garblerDriverStateBytes),
      serverEvalStateB64u: base64UrlEncode(input.preparedServerSession.serverEvalStateBytes),
    },
  };
}

function isThresholdEd25519HssStoredRespondedServerSession(
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession,
): preparedServerSession is ThresholdEd25519HssStoredRespondedServerSession {
  return (
    'serverEvalStateBytes' in preparedServerSession &&
    preparedServerSession.serverEvalStateBytes instanceof Uint8Array
  );
}

function requireThresholdEd25519HssRespondedServerSession(
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession,
): ThresholdEd25519HssStoredRespondedServerSession | null {
  return isThresholdEd25519HssStoredRespondedServerSession(preparedServerSession)
    ? preparedServerSession
    : null;
}

function parseNearEd25519SigningKeyIdField(
  raw: unknown,
  fieldName: string,
): ParseResult<NearEd25519SigningKeyId> {
  try {
    return { ok: true, value: parseNearEd25519SigningKeyId(raw) };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message:
        error instanceof Error ? `${fieldName}: ${error.message}` : `${fieldName} is invalid`,
    };
  }
}

function parseWebAuthnRpIdField(raw: unknown, fieldName: string): ParseResult<WebAuthnRpId> {
  const parsed = parseWebAuthnRpId(raw);
  if (parsed.ok) return { ok: true, value: parsed.value };
  return {
    ok: false,
    code: 'invalid_body',
    message: `${fieldName}: ${parsed.error.message}`,
  };
}

function parseThresholdEd25519RegistrationAccountScope(
  raw: unknown,
): ParseResult<ThresholdEd25519RegistrationAccountScope> {
  if (!isObject(raw)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registrationAccountScope is required',
    };
  }
  const kind = toOptionalTrimmedString(raw.kind);
  const walletId = toOptionalTrimmedString(raw.walletId);
  if (toOptionalTrimmedString(raw.rpId)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registrationAccountScope.rpId is not valid for Ed25519 HSS',
    };
  }
  if (toOptionalTrimmedString(raw.evmFamilySigningKeySlotId)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registrationAccountScope.evmFamilySigningKeySlotId is not valid for Ed25519 HSS',
    };
  }
  const intentDigestB64u = toOptionalTrimmedString(raw.intentDigestB64u);
  const signingRootId = toOptionalTrimmedString(raw.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(raw.signingRootVersion);
  const nearEd25519SigningKeyId = parseNearEd25519SigningKeyIdField(
    raw.nearEd25519SigningKeyId,
    'registrationAccountScope.nearEd25519SigningKeyId',
  );
  if (!nearEd25519SigningKeyId.ok) return nearEd25519SigningKeyId;
  const keyPurpose = toOptionalTrimmedString(raw.keyPurpose);
  const keyVersion = toOptionalTrimmedString(raw.keyVersion);
  const signerSlot = Number(raw.signerSlot);
  const derivationVersion = Number(raw.derivationVersion);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  if (
    !walletId ||
    !intentDigestB64u ||
    !signingRootId ||
    !signingRootVersion ||
    !keyPurpose ||
    !keyVersion ||
    !Number.isSafeInteger(signerSlot) ||
    signerSlot < 1 ||
    !Number.isSafeInteger(derivationVersion) ||
    derivationVersion < 1 ||
    !participantIds ||
    participantIds.length < 2
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message:
        'registrationAccountScope requires walletId, intentDigestB64u, signingRootId, signingRootVersion, nearEd25519SigningKeyId, signerSlot, keyPurpose, keyVersion, derivationVersion, and participantIds',
    };
  }
  const common = {
    walletId,
    intentDigestB64u,
    signingRootId,
    signingRootVersion,
    nearEd25519SigningKeyId: nearEd25519SigningKeyId.value,
    signerSlot,
    keyPurpose,
    keyVersion,
    derivationVersion,
    participantIds,
  };
  switch (kind) {
    case 'generated_implicit_registration_scope':
      return {
        ok: true,
        value: {
          kind,
          ...common,
        },
      };
    case 'sponsored_named_registration_scope': {
      const requestedAccountId = toOptionalTrimmedString(raw.requestedAccountId);
      if (!requestedAccountId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationAccountScope.requestedAccountId is required',
        };
      }
      const parsedRequestedAccountId = parseNamedNearAccountId(requestedAccountId);
      if (!parsedRequestedAccountId.ok) {
        return {
          ok: false,
          code: 'invalid_body',
          message: parsedRequestedAccountId.message,
        };
      }
      return {
        ok: true,
        value: {
          kind,
          ...common,
          requestedAccountId: parsedRequestedAccountId.value,
        },
      };
    }
    case 'known_account_registration_scope': {
      const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
      if (!nearAccountId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationAccountScope.nearAccountId is required',
        };
      }
      const parsedNearAccountId = parseNearAccountId(nearAccountId);
      if (!parsedNearAccountId.ok) {
        return {
          ok: false,
          code: 'invalid_body',
          message: parsedNearAccountId.message,
        };
      }
      return {
        ok: true,
        value: {
          kind,
          ...common,
          nearAccountId: parsedNearAccountId.value,
        },
      };
    }
    default:
      return {
        ok: false,
        code: 'invalid_body',
        message: 'registrationAccountScope.kind is unsupported',
      };
  }
}

function thresholdEd25519RegistrationAccountScopesEqual(
  left: ThresholdEd25519RegistrationAccountScope,
  right: ThresholdEd25519RegistrationAccountScope,
): boolean {
  if (
    left.kind !== right.kind ||
    left.walletId !== right.walletId ||
    left.intentDigestB64u !== right.intentDigestB64u ||
    left.signingRootId !== right.signingRootId ||
    left.signingRootVersion !== right.signingRootVersion ||
    left.nearEd25519SigningKeyId !== right.nearEd25519SigningKeyId ||
    left.signerSlot !== right.signerSlot ||
    left.keyPurpose !== right.keyPurpose ||
    left.keyVersion !== right.keyVersion ||
    left.derivationVersion !== right.derivationVersion ||
    !haveSameParticipantIds(left.participantIds, right.participantIds)
  ) {
    return false;
  }
  switch (left.kind) {
    case 'generated_implicit_registration_scope':
      return true;
    case 'sponsored_named_registration_scope':
      return (
        right.kind === 'sponsored_named_registration_scope' &&
        left.requestedAccountId === right.requestedAccountId
      );
    case 'known_account_registration_scope':
      return (
        right.kind === 'known_account_registration_scope' &&
        left.nearAccountId === right.nearAccountId
      );
    default:
      return assertNever(left);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unhandled Threshold Ed25519 HSS branch: ${String(value)}`);
}

function resolveThresholdEd25519FinalizeNearAccountId(input: {
  accountResolution: ThresholdEd25519HssFinalizeForRegistrationRequest['accountResolution'];
  publicKey: string;
}): ParseResult<string> {
  switch (input.accountResolution.kind) {
    case 'known_account': {
      const parsed = parseNearAccountId(input.accountResolution.nearAccountId);
      if (!parsed.ok) {
        return {
          ok: false,
          code: 'invalid_body',
          message: parsed.message,
        };
      }
      return { ok: true, value: parsed.value };
    }
    case 'registration_provisioning':
      return resolveThresholdEd25519RegistrationProvisionedNearAccountId({
        accountProvisioning: input.accountResolution.accountProvisioning,
        publicKey: input.publicKey,
      });
    default:
      return assertNever(input.accountResolution);
  }
}

function resolveThresholdEd25519RegistrationProvisionedNearAccountId(input: {
  accountProvisioning: Extract<
    ThresholdEd25519HssFinalizeForRegistrationRequest['accountResolution'],
    { kind: 'registration_provisioning' }
  >['accountProvisioning'];
  publicKey: string;
}): ParseResult<string> {
  switch (input.accountProvisioning.kind) {
    case 'implicit_account':
      try {
        return {
          ok: true,
          value: deriveImplicitNearAccountIdFromEd25519PublicKey(input.publicKey),
        };
      } catch (error: unknown) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            error instanceof Error
              ? error.message
              : 'Implicit account registration returned an invalid Ed25519 public key',
        };
      }
    case 'sponsored_named_account': {
      const parsed = parseNamedNearAccountId(input.accountProvisioning.requestedAccountId);
      if (!parsed.ok) {
        return {
          ok: false,
          code: 'invalid_body',
          message: parsed.message,
        };
      }
      return { ok: true, value: parsed.value };
    }
    default:
      return assertNever(input.accountProvisioning);
  }
}

function parseThresholdEd25519HssPreparedSessionEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssPreparedSessionEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'preparedSession is required' };
  }
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const evaluatorDriverStateB64u = toOptionalTrimmedString(raw.evaluatorDriverStateB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.contextBindingB64u is required',
    };
  }
  if (!evaluatorDriverStateB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'preparedSession.evaluatorDriverStateB64u is required',
    };
  }
  return {
    ok: true,
    value: {
      contextBindingB64u,
      evaluatorDriverStateB64u,
    },
  };
}

function parseThresholdEd25519HssServerVisibleClientRequestEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssServerVisibleClientRequestEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'clientRequest is required' };
  }
  const clientRequestMessageB64u = toOptionalTrimmedString(raw.clientRequestMessageB64u);
  if (!clientRequestMessageB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRequest.clientRequestMessageB64u is required',
    };
  }
  const forbiddenField = findOwnField(
    raw,
    ED25519_HSS_SERVER_VISIBLE_CLIENT_REQUEST_FORBIDDEN_FIELDS,
  );
  if (forbiddenField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `clientRequest.${forbiddenField} must stay outside the server-visible request`,
    };
  }
  return {
    ok: true,
    value: { clientRequestMessageB64u },
  };
}

function parseThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope(
  raw: unknown,
): ParseResult<ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope> {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'evaluationResult is required' };
  }
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const stagedEvaluatorArtifactB64u = toOptionalTrimmedString(raw.stagedEvaluatorArtifactB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.contextBindingB64u is required',
    };
  }
  if (!stagedEvaluatorArtifactB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.stagedEvaluatorArtifactB64u is required',
    };
  }
  const forbiddenField = findOwnField(
    raw,
    ED25519_HSS_CLIENT_OWNED_STAGED_ARTIFACT_FORBIDDEN_FIELDS,
  );
  if (forbiddenField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `evaluationResult.${forbiddenField} must stay outside the client-owned staged artifact`,
    };
  }
  return {
    ok: true,
    value: { contextBindingB64u, stagedEvaluatorArtifactB64u },
  };
}

function haveSameParticipantIds(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export type ThresholdEcdsaKeySelector = {
  kind: 'key_handle';
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};
type ThresholdEcdsaKeyHandleSelector = ThresholdEcdsaKeySelector;

function parseThresholdEcdsaKeySelector(
  rec: Record<string, unknown>,
  input: {
    required: boolean;
    missingMessage: string;
  },
): ParseResult<ThresholdEcdsaKeyHandleSelector | null> {
  const keyHandle = toOptionalTrimmedString(rec.keyHandle);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(rec.ecdsaThresholdKeyId);
  if (ecdsaThresholdKeyId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyHandle is required for threshold-ecdsa key selection',
    };
  }
  if (!keyHandle) {
    if (!input.required) return { ok: true, value: null };
    return {
      ok: false,
      code: 'invalid_body',
      message: input.missingMessage,
    };
  }
  return { ok: true, value: { kind: 'key_handle', keyHandle } };
}

export type RouterAbSigningWorkerPrivateHttpConfig = {
  signingWorkerBaseUrl: string;
  auth: { kind: 'internal_service_auth_token'; token: string };
};

export type RouterAbEd25519SigningWorkerPrivateMaterial = {
  kind: 'router_ab_ed25519_signing_worker_material_v1';
  account_public_key: string;
  x_server_base_b64u: string;
  signing_worker_material_handle: string;
  activated_at_ms: number;
};

export type RouterAbNormalSigningPrepareReplayReservationInput =
  | {
      curve: 'ed25519';
      phase: 'prepare' | 'presign-pool-prepare';
      thresholdSessionId: string;
      requestId: string;
      expiresAtMs: number;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'prepare';
      thresholdSessionId: string;
      requestId: string;
      expiresAtMs: number;
    };

export type RouterAbNormalSigningPrepareReplayReservationResult =
  | { ok: true }
  | { ok: false; status: number; code: string; message: string };

export type RouterAbNormalSigningBudgetReservationInput =
  | {
      curve: 'ed25519';
      phase: 'prepare' | 'finalize';
      thresholdSessionId: string;
      signingGrantId: string;
      signingWorkerId: string;
      operationId: string;
      requestDigest: string;
      signatureUses: number;
      expiresAtMs: number;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'prepare';
      thresholdSessionId: string;
      signingGrantId: string;
      signingWorkerId: string;
      operationId: string;
      requestDigest: string;
      signatureUses: number;
      expiresAtMs: number;
    };

export type RouterAbNormalSigningBudgetReservationResult =
  | {
      ok: true;
      reservationId: string;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }
  | { ok: false; status: number; code: string; message: string };

export type RouterAbNormalSigningBudgetCommitInput =
  | {
      curve: 'ed25519';
      phase: 'finalize';
      thresholdSessionId: string;
      signingGrantId: string;
      reservationId: string;
      signingWorkerId: string;
      operationId: string;
      requestDigest: string;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'finalize';
      thresholdSessionId: string;
      signingGrantId: string;
      reservationId: string;
      signingWorkerId: string;
      operationId: string;
      requestDigest: string;
    };

export type RouterAbNormalSigningBudgetValidateInput = RouterAbNormalSigningBudgetCommitInput;

export type RouterAbNormalSigningBudgetIdentityReleaseInput =
  RouterAbNormalSigningBudgetCommitInput;

export type RouterAbNormalSigningBudgetCommitResult =
  | { ok: true; remainingUses: number }
  | { ok: false; status: number; code: string; message: string };

export type RouterAbNormalSigningBudgetReleaseInput =
  | {
      curve: 'ed25519';
      phase: 'prepare' | 'finalize';
      thresholdSessionId: string;
      signingGrantId: string;
      reservationId: string;
    }
  | {
      curve: 'ecdsa-hss';
      phase: 'prepare' | 'finalize';
      thresholdSessionId: string;
      signingGrantId: string;
      reservationId: string;
    };

export type RouterAbNormalSigningBudgetReleaseResult =
  | {
      ok: true;
      released: boolean;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }
  | { ok: false; status: number; code: string; message: string };

function resolveRouterAbSigningWorkerPrivateHttpConfig(
  cfg: Record<string, unknown>,
): RouterAbSigningWorkerPrivateHttpConfig | null {
  const signingWorkerBaseUrl =
    toOptionalTrimmedString(cfg.ROUTER_AB_SIGNING_WORKER_URL) ||
    toOptionalTrimmedString(cfg.ROUTER_AB_ECDSA_HSS_POOL_FILL_SIGNING_WORKER_URL) ||
    toOptionalTrimmedString(cfg.SIGNING_WORKER_URL);
  const token =
    toOptionalTrimmedString(cfg.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET) ||
    toOptionalTrimmedString(cfg.ROUTER_AB_INTERNAL_SERVICE_AUTH_TOKEN);
  if (!signingWorkerBaseUrl && !token) return null;
  if (!signingWorkerBaseUrl) {
    throw new Error(
      'ROUTER_AB_SIGNING_WORKER_URL is required when Router A/B internal service auth is configured',
    );
  }
  if (!token) {
    throw new Error(
      'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET is required when Router A/B SigningWorker URL is configured',
    );
  }
  return {
    signingWorkerBaseUrl,
    auth: { kind: 'internal_service_auth_token', token },
  };
}

export class ThresholdSigningService {
  private readonly logger: NormalizedLogger;
  private readonly keyStore: ThresholdEd25519KeyStore;
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly walletSessionStore: Ed25519WalletSessionStore;
  private readonly walletBudgetSessionStore: WalletSigningBudgetSessionStore;
  private readonly ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
  private readonly ecdsaSessionStore: ThresholdEcdsaSessionStore;
  private readonly ecdsaWalletSessionStore: EcdsaWalletSessionStore;
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly participantIds2p: number[];
  private readonly keygenStrategy: ThresholdEd25519KeygenStrategy;
  private readonly signingHandlers: ThresholdEd25519SigningHandlers;
  private readonly ecdsaPoolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
  private readonly ecdsaPresignaturePool: RouterAbEcdsaHssPresignaturePool;
  private readonly signingRootShareResolver: SigningRootShareResolver | null;
  private readonly routerAbNormalSigningPolicy: RouterAbNormalSigningServerPolicy;
  private readonly routerAbSigningWorkerPrivateHttp: RouterAbSigningWorkerPrivateHttpConfig | null;
  private readonly routerAbEcdsaHssPoolFillHandlers: RouterAbEcdsaHssPoolFillHandlers;
  private readonly ensureReady: () => Promise<void>;
  private readonly ensureSignerWasm: () => Promise<void>;
  private readonly verifyWebAuthnAuthenticationLite:
    | ((request: {
        userId: string;
        rpId: WebAuthnRpId;
        expectedChallenge: string;
        expected_origin: string;
        webauthn_authentication: WebAuthnAuthenticationCredential;
      }) => Promise<VerifyAuthenticationResponse>)
    | null;
  private readonly dispatchNearTransaction: ThresholdNearTransactionDispatcher;
  private readonly ed25519HssCeremonyTtlMs = 2 * 60_000;
  private readonly ed25519HssCeremonyStore: ThresholdEd25519HssCeremonyStore;
  private cachedSchemeModules: Partial<Record<ThresholdSchemeId, ThresholdAnySchemeModule>> | null =
    null;

  readonly ed25519Hss = {
    prepareForRegistration: async (input: {
      orgId: string;
      signingRootId?: string;
      signingRootVersion?: string;
      request: ThresholdEd25519HssPrepareForRegistrationRequest;
    }): Promise<ThresholdEd25519HssPrepareForRegistrationResponse> => {
      return this.ed25519HssPrepareForRegistration(input);
    },
    respondForRegistration: async (input: {
      orgId: string;
      request: ThresholdEd25519HssRespondForRegistrationRequest;
    }): Promise<ThresholdEd25519HssRespondForRegistrationResponse> => {
      return this.ed25519HssRespondForRegistration(input);
    },
    finalizeForRegistration: async (input: {
      orgId: string;
      request: ThresholdEd25519HssFinalizeForRegistrationRequest;
    }): Promise<ThresholdEd25519HssFinalizeForRegistrationResponse> => {
      return this.ed25519HssFinalizeForRegistration(input);
    },
    prepareWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssPrepareWithSessionRequest;
    }): Promise<ThresholdEd25519HssPrepareWithSessionResponse> => {
      const claims = parseRouterAbEd25519WalletSessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid Wallet Session claims',
        };
      }
      return this.ed25519HssPrepareWithSession({ claims, request: input.request });
    },
    respondWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssRespondWithSessionRequest;
    }): Promise<ThresholdEd25519HssRespondWithSessionResponse> => {
      const claims = parseRouterAbEd25519WalletSessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid Wallet Session claims',
        };
      }
      return this.ed25519HssRespondWithSession({ claims, request: input.request });
    },
    finalizeWithSession: async (input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssFinalizeWithSessionRequest;
    }): Promise<ThresholdEd25519HssFinalizeWithSessionResponse> => {
      const claims = parseRouterAbEd25519WalletSessionClaims(input.claims);
      if (!claims) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid Wallet Session claims',
        };
      }
      return this.ed25519HssFinalizeWithSession({ claims, request: input.request });
    },
  };

  constructor(input: {
    logger: NormalizedLogger;
    keyStore: ThresholdEd25519KeyStore;
    sessionStore: ThresholdEd25519SessionStore;
    walletSessionStore: Ed25519WalletSessionStore;
    walletBudgetSessionStore: WalletSigningBudgetSessionStore;
    ecdsaKeyStore: ThresholdEcdsaIntegratedKeyStore;
    ecdsaSessionStore: ThresholdEcdsaSessionStore;
    ecdsaWalletSessionStore: EcdsaWalletSessionStore;
    ecdsaPoolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
    ecdsaPresignaturePool: RouterAbEcdsaHssPresignaturePool;
    signingRootShareResolver?: SigningRootShareResolver | null;
    config?: ThresholdStoreConfigInput | null;
    ensureReady: () => Promise<void>;
    ensureSignerWasm: () => Promise<void>;
    verifyWebAuthnAuthenticationLite?: (request: {
      userId: string;
      rpId: WebAuthnRpId;
      expectedChallenge: string;
      expected_origin: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
    }) => Promise<VerifyAuthenticationResponse>;
    dispatchNearTransaction: ThresholdNearTransactionDispatcher;
    ed25519HssCeremonyStore?: ThresholdEd25519HssCeremonyStore;
    ecdsaPoolFillLiveSessionOwner?: RouterAbEcdsaHssPoolFillLiveSessionOwner;
  }) {
    this.logger = input.logger;
    this.keyStore = input.keyStore;
    this.sessionStore = input.sessionStore;
    this.walletSessionStore = input.walletSessionStore;
    this.walletBudgetSessionStore = input.walletBudgetSessionStore;
    this.ecdsaKeyStore = input.ecdsaKeyStore;
    this.ecdsaSessionStore = input.ecdsaSessionStore;
    this.ecdsaWalletSessionStore = input.ecdsaWalletSessionStore;
    this.ecdsaPoolFillSessionStore = input.ecdsaPoolFillSessionStore;
    this.ecdsaPresignaturePool = input.ecdsaPresignaturePool;
    this.signingRootShareResolver = input.signingRootShareResolver || null;
    this.ed25519HssCeremonyStore =
      input.ed25519HssCeremonyStore || new InMemoryThresholdEd25519HssCeremonyStore();
    const cfg = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
    this.routerAbNormalSigningPolicy = parseRouterAbNormalSigningServerPolicy(cfg);

    const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);
    const coordinatorSharedSecretBytes = parseThresholdCoordinatorSharedSecretBytes(
      cfg.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
    );
    const coordinatorInstanceId = toOptionalTrimmedString(cfg.THRESHOLD_COORDINATOR_INSTANCE_ID);
    const coordinatorPeers = parseThresholdCoordinatorPeers(cfg.THRESHOLD_COORDINATOR_PEERS) || [];
    const relayerCosignerIdRaw = cfg.THRESHOLD_ED25519_RELAYER_COSIGNER_ID;
    const relayerCosignerId =
      relayerCosignerIdRaw === undefined
        ? null
        : normalizeThresholdEd25519ParticipantId(relayerCosignerIdRaw);
    if (nodeRole === 'cosigner' && !relayerCosignerId) {
      throw new Error(
        'THRESHOLD_ED25519_RELAYER_COSIGNER_ID is required when THRESHOLD_NODE_ROLE=cosigner',
      );
    }

    const ids = parseThresholdEd25519ParticipantIds2p({
      THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID: cfg.THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID,
      THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID: cfg.THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID,
    });
    this.clientParticipantId = ids.clientParticipantId;
    this.relayerParticipantId = ids.relayerParticipantId;
    this.participantIds2p = ids.participantIds2p;

    this.ensureReady = input.ensureReady;
    this.ensureSignerWasm = input.ensureSignerWasm;
    this.verifyWebAuthnAuthenticationLite = input.verifyWebAuthnAuthenticationLite || null;
    this.dispatchNearTransaction = input.dispatchNearTransaction;
    this.keygenStrategy = new ThresholdEd25519KeygenStrategyV1({
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
    });
    this.signingHandlers = new ThresholdEd25519SigningHandlers({
      logger: this.logger,
      nodeRole,
      relayerCosignerId,
      coordinatorSharedSecretBytes,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      participantIds2p: this.participantIds2p,
      sessionStore: this.sessionStore,
      ensureReady: this.ensureReady,
      ensureSignerWasm: this.ensureSignerWasm,
    });
    const routerAbSigningWorkerPrivateHttp = resolveRouterAbSigningWorkerPrivateHttpConfig(cfg);
    this.routerAbSigningWorkerPrivateHttp = routerAbSigningWorkerPrivateHttp;

    this.routerAbEcdsaHssPoolFillHandlers = new RouterAbEcdsaHssPoolFillHandlers({
      logger: this.logger,
      nodeRole,
      participantIds2p: this.participantIds2p,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      coordinatorInstanceId: coordinatorInstanceId || null,
      coordinatorPeers,
      sessionStore: {
        readMpcSession: async (sessionId) => await this.readEcdsaMpcSession(sessionId),
        claimMpcSession: async (sessionId, version) =>
          await this.claimEcdsaMpcSession(sessionId, version),
      },
      poolFillSessionStore: this.ecdsaPoolFillSessionStore,
      presignaturePool: this.ecdsaPresignaturePool,
      resolveRoleLocalKeyRecord: async (selector) =>
        this.ecdsaKeyStore.getRoleLocalByKeyHandle(selector.keyHandle),
      ensureReady: this.ensureReady,
      createPoolFillSessionId: () => this.createRouterAbEcdsaHssPoolFillSessionId(),
      liveSessionOwner: input.ecdsaPoolFillLiveSessionOwner,
      routerAbEcdsaHssPoolFill: routerAbSigningWorkerPrivateHttp,
    });
  }

  hasSigningRootShareResolver(): boolean {
    return this.signingRootShareResolver !== null;
  }

  getRouterAbNormalSigningWorkerId(): string {
    return this.routerAbNormalSigningPolicy.signingWorkerId;
  }

  getRouterAbSigningWorkerPrivateHttpConfig(): RouterAbSigningWorkerPrivateHttpConfig | null {
    return this.routerAbSigningWorkerPrivateHttp;
  }

  async reserveRouterAbNormalSigningPrepareReplay(
    input: RouterAbNormalSigningPrepareReplayReservationInput,
  ): Promise<RouterAbNormalSigningPrepareReplayReservationResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const requestId = toOptionalTrimmedString(input.requestId);
    const expiresAtMs = Number(input.expiresAtMs);
    if (!sessionId || !requestId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
      return {
        ok: false,
        status: 400,
        code: 'invalid_body',
        message:
          'Router A/B normal-signing replay reservation requires session, request id, and expiry',
      };
    }
    const store =
      input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
    const replayGuard = await store.reserveReplayGuard(
      ['router-ab-normal-signing', input.curve, input.phase, sessionId].join(':'),
      requestId,
      expiresAtMs,
    );
    if (replayGuard.ok) return { ok: true };
    if (replayGuard.code === 'export_nonce_replay') {
      return {
        ok: false,
        status: 400,
        code: 'one_use_replay_rejected',
        message: 'Router A/B normal-signing prepare request id already used',
      };
    }
    if (replayGuard.code === 'export_authorization_expired') {
      return {
        ok: false,
        status: 400,
        code: 'expired_request',
        message: 'Router A/B normal-signing prepare request is expired',
      };
    }
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: replayGuard.message,
    };
  }

  async reserveRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetReservationInput,
  ): Promise<RouterAbNormalSigningBudgetReservationResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    const signatureUses = Math.floor(Number(input.signatureUses));
    const expiresAtMs = Number(input.expiresAtMs);
    if (
      !sessionId ||
      !signingGrantId ||
      !signingWorkerId ||
      !operationId ||
      !requestDigest ||
      !Number.isSafeInteger(signatureUses) ||
      signatureUses <= 0 ||
      !Number.isFinite(expiresAtMs)
    ) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: 'Router A/B budget reservation requires operation, digest, uses, and expiry',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const reserved = await resolved.store.reserveUseCountOnce({
      signingGrantId: resolved.budgetSessionId,
      curve,
      thresholdSessionId: sessionId,
      signingWorkerId,
      operationId,
      requestDigest,
      signatureUses,
      expiresAtMs,
    });
    if (!reserved.ok) return routerAbBudgetStoreFailure(reserved);
    return {
      ok: true,
      reservationId: reserved.reservation.reservationId,
      remainingUses: reserved.remainingUses,
      reservedUses: reserved.reservedUses,
      availableUses: reserved.availableUses,
    };
  }

  async commitRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetCommitInput,
  ): Promise<RouterAbNormalSigningBudgetCommitResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    if (
      !sessionId ||
      !signingGrantId ||
      !reservationId ||
      !signingWorkerId ||
      !operationId ||
      !requestDigest
    ) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message:
          'Router A/B budget commit requires reservation, SigningWorker, operation, and digest',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const committed = await resolved.store.commitReservedUseCountOnce({
      signingGrantId: resolved.budgetSessionId,
      reservationId,
      signingWorkerId,
      operationId,
      requestDigest,
    });
    if (!committed.ok) return routerAbBudgetStoreFailure(committed);
    return {
      ok: true,
      remainingUses: Math.max(0, Math.floor(Number(committed.remainingUses) || 0)),
    };
  }

  async validateRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetValidateInput,
  ): Promise<RouterAbNormalSigningBudgetCommitResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    if (
      !sessionId ||
      !signingGrantId ||
      !reservationId ||
      !signingWorkerId ||
      !operationId ||
      !requestDigest
    ) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message:
          'Router A/B budget validation requires reservation, SigningWorker, operation, and digest',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const validated = await resolved.store.validateReservedUseCount({
      signingGrantId: resolved.budgetSessionId,
      reservationId,
      signingWorkerId,
      operationId,
      requestDigest,
    });
    if (!validated.ok) return routerAbBudgetStoreFailure(validated);
    return {
      ok: true,
      remainingUses: Math.max(0, Math.floor(Number(validated.remainingUses) || 0)),
    };
  }

  async releaseRouterAbNormalSigningBudget(
    input: RouterAbNormalSigningBudgetReleaseInput,
  ): Promise<RouterAbNormalSigningBudgetReleaseResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    if (!sessionId || !signingGrantId || !reservationId) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message: 'Router A/B budget release requires session and reservation',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const released = await resolved.store.releaseReservedUseCount({
      signingGrantId: resolved.budgetSessionId,
      reservationId,
    });
    if (!released.ok) return routerAbBudgetStoreFailure(released);
    return released;
  }

  async releaseRouterAbNormalSigningBudgetForIdentity(
    input: RouterAbNormalSigningBudgetIdentityReleaseInput,
  ): Promise<RouterAbNormalSigningBudgetReleaseResult> {
    const sessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const reservationId = toOptionalTrimmedString(input.reservationId);
    const signingWorkerId = toOptionalTrimmedString(input.signingWorkerId);
    const operationId = toOptionalTrimmedString(input.operationId);
    const requestDigest = toOptionalTrimmedString(input.requestDigest);
    if (
      !sessionId ||
      !signingGrantId ||
      !reservationId ||
      !signingWorkerId ||
      !operationId ||
      !requestDigest
    ) {
      return {
        ok: false,
        status: 422,
        code: 'invalid_budget_request',
        message:
          'Router A/B budget identity release requires reservation, SigningWorker, operation, and digest',
      };
    }
    const curve = input.curve === 'ed25519' ? 'ed25519' : 'ecdsa';
    const resolved = await this.resolveWalletOrCurveBudgetStore({
      signingGrantId,
      curve,
      curveSessionId: sessionId,
    });
    if (!resolved.ok) return routerAbBudgetStoreFailure(resolved);
    const released = await resolved.store.releaseReservedUseCountForIdentity({
      signingGrantId: resolved.budgetSessionId,
      reservationId,
      signingWorkerId,
      operationId,
      requestDigest,
    });
    if (!released.ok) return routerAbBudgetStoreFailure(released);
    return released;
  }

  async resolveRouterAbEd25519SigningWorkerPrivateMaterial(input: {
    claims: RouterAbEd25519WalletSessionClaims;
  }): Promise<
    | { ok: true; material: RouterAbEd25519SigningWorkerPrivateMaterial }
    | { ok: false; status: number; code: string; message: string }
  > {
    const claims = input.claims;
    const stored = await this.keyStore.get(claims.relayerKeyId);
    if (!stored) {
      return {
        ok: false,
        status: 404,
        code: 'not_found',
        message: 'Router A/B Ed25519 SigningWorker material is not available',
      };
    }
    if (
      stored.walletId !== claims.walletId ||
      stored.nearAccountId !== claims.nearAccountId ||
      stored.nearEd25519SigningKeyId !== claims.nearEd25519SigningKeyId ||
      !thresholdEd25519AuthorityScopesMatch(stored.authorityScope, claims.authorityScope) ||
      stored.publicKey !== claims.relayerKeyId
    ) {
      return {
        ok: false,
        status: 403,
        code: 'forbidden',
        message: 'Router A/B Ed25519 SigningWorker material does not match Wallet Session claims',
      };
    }
    const xServerBaseB64u = toOptionalTrimmedString(stored.routerMaterial.signingShareB64u);
    if (!xServerBaseB64u) {
      return {
        ok: false,
        status: 409,
        code: 'invalid_state',
        message: 'Router A/B Ed25519 SigningWorker material is incomplete',
      };
    }
    const storedRelayerVerifyingShareB64u = toOptionalTrimmedString(
      stored.routerMaterial.verifyingShareB64u,
    );
    if (!storedRelayerVerifyingShareB64u) {
      return {
        ok: false,
        status: 409,
        code: 'invalid_state',
        message: 'Router A/B Ed25519 SigningWorker material is missing verifying-share binding',
      };
    }
    try {
      const derivedRelayerVerifyingShare =
        await deriveThresholdEd25519VerifyingShareFromSigningShare({
          signingShareB64u: xServerBaseB64u,
        });
      const derivedRelayerVerifyingShareB64u = toOptionalTrimmedString(
        derivedRelayerVerifyingShare.verifyingShareB64u,
      );
      if (derivedRelayerVerifyingShareB64u !== storedRelayerVerifyingShareB64u) {
        return {
          ok: false,
          status: 409,
          code: 'invalid_state',
          message: 'Router A/B Ed25519 SigningWorker material verifying-share binding mismatch',
        };
      }
    } catch (error: unknown) {
      return {
        ok: false,
        status: 409,
        code: 'invalid_state',
        message: `Router A/B Ed25519 SigningWorker material verification failed: ${errorMessage(
          error,
        )}`,
      };
    }
    const walletSessionIssuedAtSec = claims.iat;
    if (!Number.isFinite(walletSessionIssuedAtSec) || Number(walletSessionIssuedAtSec) <= 0) {
      return {
        ok: false,
        status: 401,
        code: 'unauthorized',
        message: 'Router A/B Ed25519 Wallet Session JWT is missing issued-at timestamp',
      };
    }
    const activatedAtMs = Math.max(1, Math.floor(Number(walletSessionIssuedAtSec) * 1000));
    return {
      ok: true,
      material: {
        kind: 'router_ab_ed25519_signing_worker_material_v1',
        account_public_key: stored.publicKey,
        x_server_base_b64u: xServerBaseB64u,
        signing_worker_material_handle: `ed25519-hss/${claims.relayerKeyId}/${claims.thresholdSessionId}`,
        activated_at_ms: activatedAtMs,
      },
    };
  }

  private validateRouterAbNormalSigningSessionPolicy(
    requested: RouterAbEd25519NormalSigningState | undefined,
  ): ParseResult<null> {
    return validateRouterAbNormalSigningServerPolicy({
      requested,
      policy: this.routerAbNormalSigningPolicy,
    });
  }

  private createThresholdEd25519HssCeremonyHandle(): string {
    return base64UrlEncode(randomBytes(18));
  }

  private async storeThresholdEd25519HssCeremony(
    record: ThresholdEd25519HssCeremonyRecordInput,
  ): Promise<string> {
    const nowMs = Date.now();
    await this.ed25519HssCeremonyStore.cleanupExpired(nowMs);
    const handle = this.createThresholdEd25519HssCeremonyHandle();
    await this.ed25519HssCeremonyStore.put(handle, {
      ...record,
      expiresAtMs: nowMs + this.ed25519HssCeremonyTtlMs,
    });
    return handle;
  }

  private async getThresholdEd25519HssCeremony(
    handleRaw: unknown,
  ): Promise<ParseResult<ThresholdEd25519HssCeremonyRecord>> {
    const handle = toOptionalTrimmedString(handleRaw);
    if (!handle) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
    }
    await this.ed25519HssCeremonyStore.cleanupExpired(Date.now());
    const record = await this.ed25519HssCeremonyStore.get(handle);
    if (!record) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ceremonyHandle is invalid or expired',
      };
    }
    return { ok: true, value: record };
  }

  private async deleteThresholdEd25519HssCeremony(handleRaw: unknown): Promise<void> {
    const handle = toOptionalTrimmedString(handleRaw);
    if (!handle) return;
    const record = await this.ed25519HssCeremonyStore.get(handle);
    if (record) {
      this.releaseThresholdEd25519HssCeremonyResources(record);
    }
    await this.ed25519HssCeremonyStore.delete(handle);
  }

  private releaseThresholdEd25519HssCeremonyResources(
    record: ThresholdEd25519HssCeremonyRecord,
  ): void {
    clearThresholdEd25519HssStoredServerInputs(record.serverInputs);
    releaseThresholdEd25519HssPreparedServerSession(
      record.preparedServerSession.preparedSessionHandle,
    );
  }

  private async takeThresholdEd25519HssCeremony(
    handleRaw: unknown,
  ): Promise<ParseResult<ThresholdEd25519HssCeremonyRecord>> {
    const handle = toOptionalTrimmedString(handleRaw);
    if (!handle) {
      return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
    }
    await this.ed25519HssCeremonyStore.cleanupExpired(Date.now());
    const record = await this.ed25519HssCeremonyStore.take(handle);
    if (!record) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ceremonyHandle is invalid or expired',
      };
    }
    return { ok: true, value: record };
  }

  private resolveFixedEcdsaSigningRoot(): EcdsaSigningRootReference | null {
    const fixedScope: FixedSigningRootScope | undefined =
      this.signingRootShareResolver?.fixedSigningRootScope;
    if (!fixedScope) return null;
    return createEcdsaSigningRootReference({
      signingRootId: fixedScope.signingRootId,
      signingRootVersion: fixedScope.signingRootVersion,
    });
  }

  private resolveEcdsaSigningRootFromScopeOrFixed(
    scope: unknown,
  ): EcdsaSigningRootReference | null {
    const scopedSigningRoot = resolveEcdsaSigningRootFromScope(scope);
    if (scopedSigningRoot) return scopedSigningRoot;
    return this.resolveFixedEcdsaSigningRoot();
  }

  private async deriveThresholdEcdsaHssYRelayerForContext(input: {
    hssContext: {
      applicationBindingDigest: Uint8Array;
    };
    signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
  }): Promise<ParseResult<Uint8Array>> {
    if (!this.signingRootShareResolver) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-ecdsa requires a signing-root share resolver',
      };
    }

    const derived = await deriveEcdsaHssYRelayerFromSigningRootShareResolver({
      signingRootId: input.signingRootMetadata.signingRootId,
      ...(input.signingRootMetadata.signingRootVersion
        ? { signingRootVersion: input.signingRootMetadata.signingRootVersion }
        : {}),
      resolver: this.signingRootShareResolver,
      context: input.hssContext,
    });
    if (!derived.ok) {
      return {
        ok: false,
        code: derived.code,
        message: `threshold-prf signing-root derivation failed: ${derived.message}`,
      };
    }
    return { ok: true, value: derived.value };
  }

  getSchemeModule(schemeId: ThresholdSchemeId): ThresholdAnySchemeModule | null {
    if (!this.cachedSchemeModules) this.cachedSchemeModules = {};
    const existing = this.cachedSchemeModules[schemeId];
    if (existing) return existing;

    const created: ThresholdAnySchemeModule | null = (() => {
      if (schemeId === THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
        return createThresholdEd25519Frost2pSchemeModule({
          registrationKeygenFromRegistrationMaterial: (request) =>
            this.ed25519RegistrationKeygenFromRegistrationMaterial(request),
          session: (request) => this.ed25519Session(request),
          protocol: {
            internalCosignInit: (request) =>
              this.signingHandlers.thresholdEd25519CosignInit(request),
            internalCosignFinalize: (request) =>
              this.signingHandlers.thresholdEd25519CosignFinalize(request),
          },
        });
      }
      if (schemeId === THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID) {
        return createThresholdSecp256k1Ecdsa2pSchemeModule({
          poolFill: {
            init: (input) =>
              this.routerAbEcdsaHssPoolFillHandlers.routerAbEcdsaHssPresignaturePoolFillInit(input),
            step: (input) =>
              this.routerAbEcdsaHssPoolFillHandlers.routerAbEcdsaHssPresignaturePoolFillStep(input),
          },
          protocol: {},
        });
      }
      return null;
    })();

    if (!created) return null;
    this.cachedSchemeModules[schemeId] = created;
    return created;
  }

  private async resolveRelayerKeyMaterial(input: { relayerKeyId: string }): Promise<
    | {
        ok: true;
        publicKey: string;
        relayerSigningShareB64u: string;
        relayerVerifyingShareB64u: string;
      }
    | { ok: false; code: string; message: string }
  > {
    const startedAt = Date.now();
    const resolved = await resolveThresholdEd25519RelayerKeyMaterial({
      relayerKeyId: input.relayerKeyId,
      keyStore: this.keyStore,
    });
    const durationMs = Date.now() - startedAt;
    if (!resolved.ok) {
      if (resolved.code === 'missing_key') {
        this.logger?.warn?.('[threshold-ed25519] relayer share cache miss', {
          relayerKeyId: input.relayerKeyId,
          durationMs,
        });
      } else {
        this.logger?.error?.('[threshold-ed25519] relayer share cache lookup failed', {
          relayerKeyId: input.relayerKeyId,
          durationMs,
          code: resolved.code,
          message: resolved.message,
        });
      }
      return resolved;
    }
    this.logger?.debug?.('[threshold-ed25519] relayer share cache hit', {
      relayerKeyId: input.relayerKeyId,
      durationMs,
    });
    return resolved;
  }

  private clampSessionPolicy(input: { ttlMs: number; remainingUses: number }): {
    ttlMs: number;
    remainingUses: number;
  } {
    const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
    const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
    // Hard caps (server-side). Must stay aligned with client-side policy clamping
    // to keep sessionPolicyDigest32 challenge binding deterministic.
    const MAX_TTL_MS = 30 * 24 * 60 * 60_000; // 30 days
    const MAX_USES = 1_000_000;
    return {
      ttlMs: Math.min(ttlMs, MAX_TTL_MS),
      remainingUses: Math.min(remainingUses, MAX_USES),
    };
  }

  private async computeSessionPolicyDigest32(policy: unknown): Promise<Uint8Array> {
    const json = alphabetizeStringify(policy);
    return await sha256BytesUtf8(json);
  }

  private async putWalletSessionRecord(input: {
    store: Ed25519WalletSessionStore;
    sessionId: string;
    record: Ed25519WalletSessionRecord;
    ttlMs: number;
    remainingUses: number;
  }): Promise<void> {
    await input.store.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private async getEcdsaWalletSession(
    sessionId: string,
  ): Promise<ThresholdEcdsaWalletSessionRecord | null> {
    return await this.ecdsaWalletSessionStore.getSession(sessionId);
  }

  private async putEcdsaWalletSessionRecord(input: {
    sessionId: string;
    record: ThresholdEcdsaWalletSessionRecord;
    ttlMs: number;
    remainingUses: number;
  }): Promise<void> {
    await this.ecdsaWalletSessionStore.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private async putWalletBudgetSessionRecord(input: {
    sessionId: string;
    record: WalletSigningBudgetSessionRecord;
    ttlMs: number;
    remainingUses: number;
  }): Promise<void> {
    await this.walletBudgetSessionStore.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private async putEcdsaMpcSession(
    sessionId: string,
    record: ThresholdEcdsaMpcSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    await this.ecdsaSessionStore.putMpcSession(sessionId, record, ttlMs);
  }

  private async readEcdsaMpcSession(
    sessionId: string,
  ): Promise<{ record: ThresholdEcdsaMpcSessionRecord; version: string } | null> {
    return await this.ecdsaSessionStore.readMpcSession(sessionId);
  }

  private async claimEcdsaMpcSession(
    sessionId: string,
    version: string,
  ): Promise<
    | { ok: true; record: ThresholdEcdsaMpcSessionRecord }
    | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' | 'invalid_record' }
  > {
    return await this.ecdsaSessionStore.claimMpcSession(sessionId, version);
  }

  private walletSigningBudgetSessionId(input: {
    signingGrantId: string;
  }): string {
    return walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId,
    });
  }

  private async ensureSigningGrantBudget(
    input: {
      signingGrantId: string;
      thresholdSessionId: string;
      userId: string;
      participantIds: number[];
      ttlMs: number;
      remainingUses: number;
      refreshExisting: boolean;
    } & (
      | {
          curve: 'ed25519';
          authorityScope: ThresholdEd25519AuthorityScope;
          evmFamilySigningKeySlotId?: never;
        }
      | {
          curve: 'ecdsa';
          evmFamilySigningKeySlotId: string;
          authorityScope?: never;
        }
    ),
  ): Promise<
    | { ok: true; expiresAtMs: number; participantIds: number[] }
    | { ok: false; code: string; message: string }
  > {
    const binding = {
      curve: input.curve,
      thresholdSessionId: toOptionalTrimmedString(input.thresholdSessionId) || '',
    };
    let branchScopeId = '';
    let branchScopeLabel = '';
    if (input.curve === 'ecdsa') {
      branchScopeId = toOptionalTrimmedString(input.evmFamilySigningKeySlotId) || '';
      branchScopeLabel = 'evmFamilySigningKeySlotId';
    } else {
      branchScopeId = input.authorityScope.kind;
      branchScopeLabel = 'authorityScope';
    }
    const sessionId = this.walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId,
    });
    if (!binding.thresholdSessionId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'signing grant budget binding thresholdSessionId is required',
      };
    }
    if (!branchScopeId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `signing grant budget ${branchScopeLabel} is required`,
      };
    }
    if (!sessionId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'signingGrantId is required',
      };
    }
    const existingSession = await this.walletBudgetSessionStore.getSession(sessionId);
    if (existingSession) {
      if (existingSession.walletId !== input.userId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingGrantId already exists for a different user',
        };
      }
      const sameParticipantIds =
        existingSession.participantIds.length === input.participantIds.length &&
        existingSession.participantIds.every((id, i) => id === input.participantIds[i]);
      if (!sameParticipantIds) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'signingGrantId already exists for a different participant set',
        };
      }
      if (!input.refreshExisting) {
        return {
          ok: true,
          expiresAtMs: existingSession.expiresAtMs,
          participantIds: existingSession.participantIds,
        };
      }
      const expiresAtMs = Date.now() + input.ttlMs;
      // Only mint paths that prove fresh wallet auth can refresh an exhausted
      // wallet budget. Threshold-session-authorized ECDSA bootstraps cannot
      // refill the shared budget by presenting an old JWT.
      await this.putWalletBudgetSessionRecord({
        sessionId,
        record: {
          kind: 'wallet_signing_budget_session',
          expiresAtMs,
          relayerKeyId: WALLET_SIGNING_BUDGET_RELAYER_KEY_ID,
          walletId: input.userId,
          participantIds: input.participantIds,
        },
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
      });
      return {
        ok: true,
        expiresAtMs,
        participantIds: input.participantIds,
      };
    }

    const expiresAtMs = Date.now() + input.ttlMs;
    await this.putWalletBudgetSessionRecord({
      sessionId,
      record: {
        kind: 'wallet_signing_budget_session',
        expiresAtMs,
        relayerKeyId: WALLET_SIGNING_BUDGET_RELAYER_KEY_ID,
        walletId: input.userId,
        participantIds: input.participantIds,
      },
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
    return { ok: true, expiresAtMs, participantIds: input.participantIds };
  }

  async seedLocalRouterAbEd25519NormalSigningSession(
    input: LocalRouterAbEd25519NormalSigningSeedInput,
  ): Promise<LocalRouterAbEd25519NormalSigningSeedResult> {
    const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
    const walletId = toOptionalTrimmedString(input.walletId);
    const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
    const nearEd25519SigningKeyId = toOptionalTrimmedString(input.nearEd25519SigningKeyId);
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    const relayerSigningShareB64u = toOptionalTrimmedString(input.relayerSigningShareB64u);
    const keyVersion = toOptionalTrimmedString(input.keyVersion);
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
    const remainingUses = Math.floor(Number(input.remainingUses));
    const thresholdExpiresAtMs = Number(input.thresholdExpiresAtMs);
    const rpId = parseWebAuthnRpId(input.rpId);
    if (
      !relayerKeyId ||
      !walletId ||
      !nearAccountId ||
      !nearEd25519SigningKeyId ||
      !thresholdSessionId ||
      !signingGrantId ||
      !publicKey ||
      !relayerSigningShareB64u ||
      !keyVersion ||
      !participantIds ||
      participantIds.length < 2 ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses <= 0 ||
      !Number.isFinite(thresholdExpiresAtMs) ||
      thresholdExpiresAtMs <= Date.now() ||
      !rpId.ok ||
      input.recoveryExportCapable !== true
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'local Router A/B Ed25519 seed is invalid',
      };
    }

    try {
      const relayerVerifyingShare = await deriveThresholdEd25519VerifyingShareFromSigningShare({
        signingShareB64u: relayerSigningShareB64u,
      });
      const relayerVerifyingShareB64u = toOptionalTrimmedString(
        relayerVerifyingShare.verifyingShareB64u,
      );
      if (!relayerVerifyingShareB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'local Router A/B Ed25519 seed produced no verifying share',
        };
      }

      const ttlMs = Math.max(1, Math.floor(thresholdExpiresAtMs - Date.now()));
      const authorityScope = passkeyRpAuthorityScope(rpId.value);
      await this.keyStore.put(relayerKeyId, {
        kind: 'ready',
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authorityScope,
        publicKey,
        routerMaterial: {
          signingShareB64u: relayerSigningShareB64u,
          verifyingShareB64u: relayerVerifyingShareB64u,
        },
        keyVersion,
        recoveryExportCapable: true,
      });
      await this.putWalletSessionRecord({
        store: this.walletSessionStore,
        sessionId: thresholdSessionId,
        record: {
          expiresAtMs: thresholdExpiresAtMs,
          relayerKeyId,
          userId: walletId,
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          authorityScope,
          participantIds,
        },
        ttlMs,
        remainingUses,
      });
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ed25519',
        thresholdSessionId,
        userId: walletId,
        authorityScope,
        participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: true,
      });
      if (!walletBudget.ok) return walletBudget;
      return {
        ok: true,
        relayerKeyId,
        thresholdSessionId,
        signingGrantId,
        remainingUses,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'local Router A/B Ed25519 seed failed',
      };
    }
  }

  async seedLocalRouterAbEcdsaHssNormalSigningSession(
    input: LocalRouterAbEcdsaHssNormalSigningSeedInput,
  ): Promise<LocalRouterAbEcdsaHssNormalSigningSeedResult> {
    const walletId = parseWalletId(input.walletId);
    const evmFamilySigningKeySlotId = parseWalletKeyId(input.evmFamilySigningKeySlotId);
    let ecdsaThresholdKeyId = '';
    let signingRootId = '';
    let signingRootVersion = '';
    try {
      ecdsaThresholdKeyId = parseSdkEcdsaHssThresholdKeyId(input.ecdsaThresholdKeyId);
      signingRootId = parseSdkEcdsaHssSigningRootId(input.signingRootId);
      signingRootVersion = parseSdkEcdsaHssSigningRootVersion(input.signingRootVersion);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'local Router A/B ECDSA-HSS seed is invalid',
      };
    }
    const walletKeyVersion = toOptionalTrimmedString(input.walletKeyVersion);
    const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
    const thresholdSessionId = toOptionalTrimmedString(input.thresholdSessionId);
    const signingGrantId = toOptionalTrimmedString(input.signingGrantId);
    const derivationVersion = Math.floor(Number(input.derivationVersion));
    const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds);
    const remainingUses = Math.floor(Number(input.remainingUses));
    const thresholdExpiresAtMs = Number(input.thresholdExpiresAtMs);
    if (
      !walletId.ok ||
      !evmFamilySigningKeySlotId.ok ||
      !ecdsaThresholdKeyId ||
      !signingRootId ||
      !signingRootVersion ||
      !walletKeyVersion ||
      !relayerKeyId ||
      !thresholdSessionId ||
      !signingGrantId ||
      derivationVersion !== THRESHOLD_ECDSA_DERIVATION_VERSION_V1 ||
      !participantIds ||
      participantIds.length < 2 ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses <= 0 ||
      !Number.isFinite(thresholdExpiresAtMs) ||
      thresholdExpiresAtMs <= Date.now()
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'local Router A/B ECDSA-HSS seed is invalid',
      };
    }

    try {
      const ttlMs = Math.max(1, Math.floor(thresholdExpiresAtMs - Date.now()));
      await this.putEcdsaWalletSessionRecord({
        sessionId: thresholdSessionId,
        record: {
          expiresAtMs: thresholdExpiresAtMs,
          relayerKeyId,
          walletId: walletId.value,
          evmFamilySigningKeySlotId: evmFamilySigningKeySlotId.value,
          signingRootId,
          signingRootVersion,
          walletKeyVersion,
          derivationVersion,
          participantIds,
        },
        ttlMs,
        remainingUses,
      });
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ecdsa',
        thresholdSessionId,
        userId: walletId.value,
        evmFamilySigningKeySlotId: evmFamilySigningKeySlotId.value,
        participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: true,
      });
      if (!walletBudget.ok) return walletBudget;
      return {
        ok: true,
        relayerKeyId,
        thresholdSessionId,
        signingGrantId,
        remainingUses,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'local Router A/B ECDSA-HSS seed failed',
      };
    }
  }

  private async resolveWalletOrCurveBudgetStore(input: {
    signingGrantId?: string;
    curve: 'ed25519' | 'ecdsa';
    curveSessionId: string;
  }): Promise<
    | { ok: true; budgetSessionId: string; store: WalletSessionBudgetStore }
    | { ok: false; code: string; message: string }
  > {
    const walletBudgetSessionId = this.walletSigningBudgetSessionId({
      signingGrantId: input.signingGrantId || '',
    });
    if (!walletBudgetSessionId) {
      const store =
        input.curve === 'ed25519' ? this.walletSessionStore : this.ecdsaWalletSessionStore;
      return { ok: true, budgetSessionId: input.curveSessionId, store };
    }
    const walletBudgetSession =
      await this.walletBudgetSessionStore.getSession(walletBudgetSessionId);
    if (!walletBudgetSession) {
      return {
        ok: false,
        code: 'wallet_budget_forbidden',
        message: 'signing grant budget does not match this threshold session',
      };
    }
    switch (input.curve) {
      case 'ed25519': {
        const curveSession = await this.walletSessionStore.getSession(input.curveSessionId);
        if (
          !curveSession ||
          walletBudgetSession.walletId !== curveSession.userId ||
          !participantIdsEqual(walletBudgetSession.participantIds, curveSession.participantIds)
        ) {
          return {
            ok: false,
            code: 'wallet_budget_forbidden',
            message: 'signing grant budget does not match this threshold session',
          };
        }
        break;
      }
      case 'ecdsa': {
        const curveSession = await this.ecdsaWalletSessionStore.getSession(input.curveSessionId);
        if (
          !curveSession ||
          walletBudgetSession.walletId !== curveSession.walletId ||
          !curveSession.evmFamilySigningKeySlotId ||
          !participantIdsEqual(walletBudgetSession.participantIds, curveSession.participantIds)
        ) {
          return {
            ok: false,
            code: 'wallet_budget_forbidden',
            message: 'signing grant budget does not match this threshold session',
          };
        }
        break;
      }
    }
    return {
      ok: true,
      budgetSessionId: walletBudgetSessionId,
      store: this.walletBudgetSessionStore,
    };
  }

  private createRouterAbEcdsaHssPoolFillSessionId(): string {
    return `ecdsa-presign-${secureRandomIdFragment()}`;
  }

  private createThresholdEd25519SigningSessionId(): string {
    return `sign-${secureRandomIdFragment()}`;
  }

  private async resolveEd25519KeygenMaterial(input: {
    nearAccountId: string;
    keyVersion: string;
    recoveryExportCapable: true;
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u: string;
  }): Promise<
    | { ok: true; keyMaterial: ThresholdEd25519KeygenMaterial }
    | { ok: false; code: string; message: string }
  > {
    const keyVersion = toOptionalTrimmedString(input.keyVersion);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    const relayerSigningShareB64u = toOptionalTrimmedString(input.relayerSigningShareB64u);
    const relayerVerifyingShareB64u = toOptionalTrimmedString(input.relayerVerifyingShareB64u);

    if (!keyVersion || !publicKey || !relayerSigningShareB64u || !relayerVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'threshold-ed25519 keygen requires complete registration material',
      };
    }

    return await this.keygenStrategy.keygenFromRegistrationMaterial({
      keyVersion,
      publicKey,
      relayerSigningShareB64u,
      relayerVerifyingShareB64u,
      recoveryExportCapable: true,
    });
  }

  private async resolveStoredEd25519KeygenMaterial(input: {
    walletId: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    authorityScope: ThresholdEd25519AuthorityScope;
    relayerKeyId: string;
    keyVersion: string;
    recoveryExportCapable: true;
    publicKey: string;
  }): Promise<
    | { ok: true; keyMaterial: ThresholdEd25519KeygenMaterial }
    | { ok: false; code: string; message: string }
  > {
    const walletId = toOptionalTrimmedString(input.walletId);
    const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
    const nearEd25519SigningKeyId = toOptionalTrimmedString(input.nearEd25519SigningKeyId);
    const authorityScope = input.authorityScope;
    const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
    const keyVersion = toOptionalTrimmedString(input.keyVersion);
    const publicKey = toOptionalTrimmedString(input.publicKey);
    if (
      !walletId ||
      !nearAccountId ||
      !nearEd25519SigningKeyId ||
      !relayerKeyId ||
      !keyVersion ||
      !publicKey
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'threshold-ed25519 registration requires relayerKeyId, publicKey, and key metadata',
      };
    }
    const stored = await this.keyStore.get(relayerKeyId);
    if (!stored) {
      return {
        ok: false,
        code: 'not_found',
        message: 'threshold-ed25519 registration material was not prepared on the Router API',
      };
    }
    if (
      stored.nearAccountId !== nearAccountId ||
      stored.walletId !== walletId ||
      stored.nearEd25519SigningKeyId !== nearEd25519SigningKeyId ||
      !thresholdEd25519AuthorityScopesMatch(stored.authorityScope, authorityScope) ||
      stored.publicKey !== publicKey ||
      stored.keyVersion !== keyVersion ||
      stored.recoveryExportCapable !== true
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'threshold-ed25519 registration material does not match the prepared Router API state',
      };
    }

    return await this.resolveEd25519KeygenMaterial({
      nearAccountId,
      keyVersion,
      recoveryExportCapable: true,
      publicKey,
      relayerSigningShareB64u: stored.routerMaterial.signingShareB64u,
      relayerVerifyingShareB64u: stored.routerMaterial.verifyingShareB64u,
    });
  }

  private async ed25519RegistrationKeygenFromRegistrationMaterial(
    input: ThresholdEd25519RegistrationKeygenRequest,
  ): Promise<ThresholdEd25519RegistrationKeygenResult> {
    try {
      await this.ensureReady();
      const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const nearEd25519SigningKeyId = toOptionalTrimmedString(input.nearEd25519SigningKeyId);
      if (!nearAccountId) {
        return { ok: false, code: 'invalid_body', message: 'nearAccountId is required' };
      }
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      if (!nearEd25519SigningKeyId) {
        return { ok: false, code: 'invalid_body', message: 'nearEd25519SigningKeyId is required' };
      }
      const authorityScope = parseThresholdEd25519AuthorityScope(input.authorityScope);
      if (!authorityScope) {
        return { ok: false, code: 'invalid_body', message: 'authorityScope is required' };
      }
      const keyVersion = toOptionalTrimmedString((input as { keyVersion?: unknown }).keyVersion);
      const publicKey = toOptionalTrimmedString((input as { publicKey?: unknown }).publicKey);
      const relayerKeyId = toOptionalTrimmedString(
        (input as { relayerKeyId?: unknown }).relayerKeyId,
      );
      if (!keyVersion || !publicKey || !relayerKeyId) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            'threshold-ed25519 registration requires relayerKeyId, publicKey, and keyVersion',
        };
      }
      if ((input as { recoveryExportCapable?: unknown }).recoveryExportCapable !== true) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'recoveryExportCapable must be true',
        };
      }

      const keygen = await this.resolveStoredEd25519KeygenMaterial({
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authorityScope,
        relayerKeyId,
        keyVersion,
        recoveryExportCapable: true,
        publicKey,
      });
      if (!keygen.ok) return keygen;
      const { keyMaterial } = keygen;

      await this.keyStore.put(keyMaterial.relayerKeyId, {
        kind: 'ready',
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authorityScope,
        publicKey: keyMaterial.publicKey,
        routerMaterial: {
          signingShareB64u: keyMaterial.relayerSigningShareB64u,
          verifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
        },
        keyVersion: keyMaterial.keyVersion,
        recoveryExportCapable: keyMaterial.recoveryExportCapable,
      });

      return {
        ok: true,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        participantIds: [...this.participantIds2p],
        relayerKeyId: keyMaterial.relayerKeyId,
        publicKey: keyMaterial.publicKey,
        keyVersion: keyMaterial.keyVersion,
        recoveryExportCapable: keyMaterial.recoveryExportCapable,
        relayerVerifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async mintEd25519SessionFromRegistration(input: {
    walletId: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    authorityScope: ThresholdEd25519AuthorityScope;
    relayerKeyId: string;
    sessionPolicy: Ed25519SessionPolicy;
  }): Promise<ThresholdEd25519SessionResponse> {
    try {
      await this.ensureReady();

      const walletId = toOptionalTrimmedString(input.walletId);
      const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
      const nearEd25519SigningKeyId = toOptionalTrimmedString(input.nearEd25519SigningKeyId);
      const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
      if (!walletId || !nearAccountId || !nearEd25519SigningKeyId || !relayerKeyId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Missing required ed25519 session bootstrap identity inputs',
        };
      }
      const authorityScope = input.authorityScope;

      const policy = (input.sessionPolicy || {}) as Ed25519SessionPolicy;
      if (Object.prototype.hasOwnProperty.call(policy, 'rpId')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.rpId belongs in authority',
        };
      }
      const policyAuthority = parseWalletAuthAuthority(policy.authority);
      if (!policyAuthority) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.authority is required',
        };
      }
      const policyWalletId = String(policyAuthority.walletId || '').trim();
      const policyAuthorityScope =
        thresholdEd25519AuthorityScopeFromWalletAuthAuthority(policyAuthority);
      const runtimePolicyScope = (() => {
        const raw = policy.runtimePolicyScope;
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
        try {
          return raw as RuntimePolicyScope;
        } catch {
          return undefined;
        }
      })();
      let routerAbNormalSigning: RouterAbEd25519NormalSigningState | undefined;
      if (Object.prototype.hasOwnProperty.call(policy, 'routerAbNormalSigning')) {
        try {
          const parsedRouterAbNormalSigning = parseRouterAbEd25519NormalSigningState(
            policy.routerAbNormalSigning,
          );
          if (!parsedRouterAbNormalSigning) {
            return {
              ok: false,
              code: 'invalid_body',
              message:
                'threshold_ed25519.session_policy.routerAbNormalSigning must be a Router A/B normal-signing state',
            };
          }
          routerAbNormalSigning = parsedRouterAbNormalSigning;
        } catch (error) {
          return {
            ok: false,
            code: 'invalid_body',
            message:
              error && typeof error === 'object' && 'message' in error
                ? String((error as { message?: unknown }).message)
                : 'threshold_ed25519.session_policy.routerAbNormalSigning is invalid',
          };
        }
      }
      const routerAbPolicy = this.validateRouterAbNormalSigningSessionPolicy(routerAbNormalSigning);
      if (!routerAbPolicy.ok) return routerAbPolicy;
      if (String(policy.version || '').trim() !== 'threshold_session_v1') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.version must be threshold_session_v1',
        };
      }
      if (String(policy.nearAccountId || '').trim() !== nearAccountId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.nearAccountId mismatch',
        };
      }
      if (policyWalletId !== walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.authority.walletId mismatch',
        };
      }
      if (String(policy.nearEd25519SigningKeyId || '').trim() !== nearEd25519SigningKeyId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.nearEd25519SigningKeyId mismatch',
        };
      }
      if (!thresholdEd25519AuthorityScopesMatch(policyAuthorityScope, authorityScope)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.authority mismatch',
        };
      }
      if (String(policy.relayerKeyId || '').trim() !== relayerKeyId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.relayerKeyId mismatch',
        };
      }

      const thresholdSessionId = String(policy.thresholdSessionId || '').trim();
      if (!thresholdSessionId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.thresholdSessionId is required',
        };
      }
      const signingGrantId = String(policy.signingGrantId || '').trim() || thresholdSessionId;

      const { ttlMs, remainingUses } = this.clampSessionPolicy({
        ttlMs: Number(policy.ttlMs),
        remainingUses: Number(policy.remainingUses),
      });
      if (ttlMs <= 0 || remainingUses <= 0) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy ttlMs/remainingUses must be positive',
        };
      }

      const participantIds = normalizeThresholdEd25519ParticipantIds(policy.participantIds) || [
        ...this.participantIds2p,
      ];
      if (participantIds.length < 2) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy.participantIds must contain at least 2 ids',
        };
      }
      for (const id of this.participantIds2p) {
        if (!participantIds.includes(id)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: `threshold_ed25519.session_policy.participantIds must include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
          };
        }
      }

      const relayerKey = await this.resolveRelayerKeyMaterial({
        relayerKeyId,
      });
      if (!relayerKey.ok) {
        return { ok: false, code: relayerKey.code, message: relayerKey.message };
      }

      const existingSession = await this.walletSessionStore.getSession(thresholdSessionId);
      if (existingSession) {
        if (existingSession.userId !== walletId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different user',
          };
        }
        if (
          existingSession.walletId !== walletId ||
          existingSession.nearAccountId !== nearAccountId
        ) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different wallet identity',
          };
        }
        if (existingSession.nearEd25519SigningKeyId !== nearEd25519SigningKeyId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different NEAR Ed25519 signing key',
          };
        }
        if (existingSession.relayerKeyId !== relayerKeyId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different relayerKeyId',
          };
        }
        if (!thresholdEd25519AuthorityScopesMatch(existingSession.authorityScope, authorityScope)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different authority scope',
          };
        }
        const sameParticipantIds =
          existingSession.participantIds.length === participantIds.length &&
          existingSession.participantIds.every((id, i) => id === participantIds[i]);
        if (!sameParticipantIds) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different participant set',
          };
        }
        const walletBudget = await this.ensureSigningGrantBudget({
          signingGrantId,
          curve: 'ed25519',
          thresholdSessionId,
          userId: walletId,
          authorityScope,
          participantIds: existingSession.participantIds,
          ttlMs,
          remainingUses,
          refreshExisting: false,
        });
        if (!walletBudget.ok) return walletBudget;
        return {
          ok: true,
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          thresholdSessionId,
          signingGrantId,
          expiresAtMs: walletBudget.expiresAtMs,
          expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
          participantIds: walletBudget.participantIds,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
        };
      }

      const expiresAtMs = Date.now() + ttlMs;
      await this.putWalletSessionRecord({
        store: this.walletSessionStore,
        sessionId: thresholdSessionId,
        record: {
          expiresAtMs,
          relayerKeyId,
          userId: walletId,
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          authorityScope,
          participantIds,
        },
        ttlMs,
        remainingUses,
      });
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ed25519',
        thresholdSessionId,
        userId: walletId,
        authorityScope,
        participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: true,
      });
      if (!walletBudget.ok) return walletBudget;

      return {
        ok: true,
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        thresholdSessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
        participantIds: walletBudget.participantIds,
        remainingUses,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async getEcdsaKeyIdentityMetadata(input: {
    walletId: string;
    keySelector: ThresholdEcdsaKeyHandleSelector;
  }): Promise<ThresholdEcdsaKeyIdentityMetadata | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return null;
    const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(input.keySelector.keyHandle);
    if (!record) return null;
    const keyHandle = toOptionalTrimmedString(record.keyHandle);
    if (keyHandle !== input.keySelector.keyHandle) return null;
    if (record.walletId !== walletId) {
      return null;
    }
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const recordOwnerAddress = toOptionalTrimmedString(record.ethereumAddress);
    if (!relayerKeyId || !recordOwnerAddress) return null;
    const thresholdOwnerAddress = recordOwnerAddress.toLowerCase();
    return {
      walletId: record.walletId,
      evmFamilySigningKeySlotId: record.evmFamilySigningKeySlotId,
      keyScope: 'evm-family',
      keyHandle,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      relayerKeyId,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      participantIds: [...this.participantIds2p],
      thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: record.groupPublicKey33B64u,
    };
  }

  async verifyEcdsaSigningRootWalletAddress(input: {
    signingRootId: string;
    signingRootVersion: string;
    walletId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId: string;
    evmFamilySigningKeySlotId: string;
    clientPublicKey33B64u: string;
    expectedEthereumAddress?: string;
    walletKeyVersion?: string;
  }): Promise<
    | {
        ok: true;
        verified: boolean;
        signingRootId: string;
        signingRootVersion: string;
        walletId: string;
        evmFamilySigningKeySlotId: string;
        walletKeyVersion: string;
        canonicalPublicKeyHex: string;
        canonicalEthereumAddress: string;
        expectedEthereumAddress?: string;
      }
    | { ok: false; code: string; message: string }
  > {
    const signingRootId = toOptionalTrimmedString(input.signingRootId);
    const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
    const walletId = toOptionalTrimmedString(input.walletId);
    const chainTarget = input.chainTarget;
    const ecdsaThresholdKeyId = toOptionalTrimmedString(input.ecdsaThresholdKeyId);
    const evmFamilySigningKeySlotId = toOptionalTrimmedString(input.evmFamilySigningKeySlotId);
    const ecdsaHssKeyVersion = parseEcdsaHssKeyVersionOrDefault(input.walletKeyVersion);
    const walletKeyVersion = ecdsaHssKeyVersionWire(ecdsaHssKeyVersion);
    if (
      !signingRootId ||
      !signingRootVersion ||
      !walletId ||
      !ecdsaThresholdKeyId ||
      !evmFamilySigningKeySlotId
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message:
          'signingRootId, signingRootVersion, walletId, chainTarget, ecdsaThresholdKeyId, and evmFamilySigningKeySlotId are required',
      };
    }
    if (!this.signingRootShareResolver) {
      return {
        ok: false,
        code: 'not_configured',
        message: 'threshold-ecdsa wallet verification requires a signing-root share resolver',
      };
    }

    const parsedClientPublicKey = await this.parseCompressedSecp256k1PublicKeyB64u({
      fieldName: 'clientPublicKey33B64u',
      value: input.clientPublicKey33B64u,
    });
    if (!parsedClientPublicKey.ok) return parsedClientPublicKey;
    const clientPublicKey33 = base64UrlDecode(parsedClientPublicKey.value);

    const expectedEthereumAddress = toOptionalTrimmedString(input.expectedEthereumAddress);
    let yRelayer32Le: Uint8Array | null = null;
    try {
      const signingRootMetadata = createEcdsaSigningRootMetadata(
        signingRootId,
        signingRootVersion,
        ecdsaHssKeyVersion,
      );
      const canonicalSigningRootVersion = canonicalEcdsaHssSigningRootVersion(signingRootVersion);
      const hssContext = {
        applicationBindingDigest: await computeSdkEcdsaHssApplicationBindingDigest32({
          walletId: requireSdkEcdsaHssWalletId(walletId),
          ecdsaThresholdKeyId: parseSdkEcdsaHssThresholdKeyId(ecdsaThresholdKeyId),
          signingRootId: parseSdkEcdsaHssSigningRootId(signingRootId),
          signingRootVersion: parseSdkEcdsaHssSigningRootVersion(canonicalSigningRootVersion),
        }),
      };
      const derived = await this.deriveThresholdEcdsaHssYRelayerForContext({
        hssContext,
        signingRootMetadata,
      });
      if (!derived.ok) return derived;
      yRelayer32Le = derived.value;

      const relayerPublicKey33 = await secp256k1PrivateKey32ToPublicKey33(yRelayer32Le);
      const groupPublicKey33 = await addSecp256k1PublicKeys33({
        left33: clientPublicKey33,
        right33: relayerPublicKey33,
      });
      const canonicalEthereumAddress =
        await secp256k1PublicKey33ToEthereumAddress(groupPublicKey33);
      const normalizedExpected = expectedEthereumAddress?.toLowerCase();
      return {
        ok: true,
        verified: normalizedExpected ? canonicalEthereumAddress === normalizedExpected : true,
        signingRootId,
        signingRootVersion,
        walletId,
        evmFamilySigningKeySlotId,
        walletKeyVersion,
        canonicalPublicKeyHex: bytesToLowerHex(groupPublicKey33),
        canonicalEthereumAddress,
        ...(expectedEthereumAddress ? { expectedEthereumAddress } : {}),
      };
    } finally {
      yRelayer32Le?.fill(0);
    }
  }

  private async parseCompressedSecp256k1PublicKeyB64u(input: {
    value: string;
    fieldName: string;
  }): Promise<ParseResult<string>> {
    let publicKey33: Uint8Array;
    try {
      publicKey33 = base64UrlDecode(input.value);
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} must be valid base64url`,
      };
    }
    if (publicKey33.length !== 33) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} must decode to 33 bytes (compressed secp256k1 pubkey)`,
      };
    }
    try {
      await validateSecp256k1PublicKey33(publicKey33);
    } catch (e: unknown) {
      const runtimeMessage = errorMessage(e);
      if (isEthSignerWasmRuntimeError(runtimeMessage)) {
        return {
          ok: false,
          code: 'internal',
          message: runtimeMessage || 'eth_signer WASM runtime error',
        };
      }
      return {
        ok: false,
        code: 'invalid_body',
        message: `${input.fieldName} is not a valid secp256k1 public key`,
      };
    }
    return { ok: true, value: input.value };
  }

  private async ecdsaMintSessionWithoutWebAuthn(input: {
    relayerKeyId: string;
    clientVerifyingShareB64u: string;
    walletId: string;
    evmFamilySigningKeySlotId: string;
    sessionId: string;
    signingGrantId: string;
    ttlMsRaw: number;
    remainingUsesRaw: number;
    policyParticipantIds: number[] | null;
    signingRootMetadata: ThresholdEcdsaSigningRootMetadata;
    refreshExistingWalletBudget?: boolean;
  }): Promise<ThresholdEcdsaBootstrapSessionResult> {
    const {
      relayerKeyId,
      clientVerifyingShareB64u,
      walletId,
      evmFamilySigningKeySlotId,
      sessionId,
      signingGrantId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds,
      signingRootMetadata,
      refreshExistingWalletBudget,
    } = input;

    const parsedClientVerifyingShare = await this.parseCompressedSecp256k1PublicKeyB64u({
      value: clientVerifyingShareB64u,
      fieldName: 'clientVerifyingShareB64u',
    });
    if (!parsedClientVerifyingShare.ok) {
      return parsedClientVerifyingShare;
    }

    const { ttlMs, remainingUses } = this.clampSessionPolicy({
      ttlMs: ttlMsRaw,
      remainingUses: remainingUsesRaw,
    });
    const participantIds = policyParticipantIds || [...this.participantIds2p];

    const existingSession = await this.getEcdsaWalletSession(sessionId);
    if (existingSession) {
      if (existingSession.walletId !== walletId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different user',
        };
      }
      if (existingSession.relayerKeyId !== relayerKeyId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different relayerKeyId',
        };
      }
      if (existingSession.evmFamilySigningKeySlotId !== evmFamilySigningKeySlotId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different evmFamilySigningKeySlotId',
        };
      }
      const sameParticipantIds =
        existingSession.participantIds.length === participantIds.length &&
        existingSession.participantIds.every((id, i) => id === participantIds[i]);
      if (!sameParticipantIds) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different participant set',
        };
      }
      if (!haveSameEcdsaSigningRootMetadata(existingSession, signingRootMetadata)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'threshold sessionId already exists for a different signing root',
        };
      }
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ecdsa',
        thresholdSessionId: sessionId,
        userId: walletId,
        evmFamilySigningKeySlotId,
        participantIds: existingSession.participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: refreshExistingWalletBudget === true,
      });
      if (!walletBudget.ok) return walletBudget;
      return {
        ok: true,
        sessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
        participantIds: walletBudget.participantIds,
        remainingUses,
      };
    }

    const expiresAtMs = Date.now() + ttlMs;
    await this.putEcdsaWalletSessionRecord({
      sessionId,
      record: {
        expiresAtMs,
        relayerKeyId,
        walletId,
        evmFamilySigningKeySlotId,
        participantIds,
        ...signingRootMetadata,
      },
      ttlMs,
      remainingUses,
    });
    const walletBudget = await this.ensureSigningGrantBudget({
      signingGrantId,
      curve: 'ecdsa',
      thresholdSessionId: sessionId,
      userId: walletId,
      evmFamilySigningKeySlotId,
      participantIds,
      ttlMs,
      remainingUses,
      refreshExisting: refreshExistingWalletBudget === true,
    });
    if (!walletBudget.ok) return walletBudget;

    return {
      ok: true,
      sessionId,
      signingGrantId,
      expiresAtMs: walletBudget.expiresAtMs,
      expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
      participantIds: walletBudget.participantIds,
      remainingUses,
    };
  }

  async deleteEcdsaHssRoleLocalKeyByBootstrapIdentity(input: {
    ecdsaThresholdKeyId: unknown;
    signingRootId: unknown;
    signingRootVersion?: unknown;
  }): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    try {
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
      });
      await this.ecdsaKeyStore.deleteByKeyHandle(keyHandle);
      return { ok: true, value: { keyHandle } };
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to delete ECDSA HSS role-local key',
      };
    }
  }

  async verifyEcdsaHssRoleLocalBootstrapPersisted(
    bootstrap: EcdsaHssServerBootstrapResponse,
  ): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    try {
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
        signingRootId: bootstrap.signingRootId,
        signingRootVersion: bootstrap.signingRootVersion,
      });
      if (bootstrap.keyHandle !== keyHandle) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA HSS bootstrap key handle does not match persisted key identity',
        };
      }
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA HSS role-local key not found for registration finalize',
        };
      }
      if (!ecdsaHssRoleLocalRecordMatchesBootstrap(record, bootstrap)) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA HSS registration finalize does not match persisted key identity',
        };
      }
      return { ok: true, value: { keyHandle } };
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify ECDSA HSS role-local key',
      };
    }
  }

  async ecdsaHssRoleLocalBootstrap(
    request: EcdsaHssClientBootstrapRequest,
  ): Promise<EcdsaHssRouteResult<EcdsaHssServerBootstrapResponse>> {
    try {
      const signingRootMetadata = createEcdsaSigningRootMetadata(
        request.signingRootId,
        request.signingRootVersion,
      );
      const ecdsaHssKeyVersion = THRESHOLD_ECDSA_HSS_KEY_VERSION_V1;
      const canonicalSigningRootVersion = canonicalEcdsaHssSigningRootVersion(
        signingRootMetadata.signingRootVersion,
      );
      const hssContext = {
        applicationBindingDigest: await computeSdkEcdsaHssApplicationBindingDigest32({
          walletId: requireSdkEcdsaHssWalletId(request.walletId),
          ecdsaThresholdKeyId: parseSdkEcdsaHssThresholdKeyId(request.ecdsaThresholdKeyId),
          signingRootId: parseSdkEcdsaHssSigningRootId(signingRootMetadata.signingRootId),
          signingRootVersion: parseSdkEcdsaHssSigningRootVersion(canonicalSigningRootVersion),
        }),
      };
      const derivedRelayerShare = await this.deriveThresholdEcdsaHssYRelayerForContext({
        hssContext,
        signingRootMetadata,
      });
      if (!derivedRelayerShare.ok) {
        return {
          ok: false,
          code: 'internal',
          message: derivedRelayerShare.message,
        };
      }
      const hssClientSharePublicKey33 = base64UrlDecode(request.hssClientSharePublicKey33B64u);
      const relayerBootstrap = await roleLocalThresholdEcdsaHssRelayerBootstrap({
        applicationBindingDigest: hssContext.applicationBindingDigest,
        relayerKeyId: request.relayerKeyId,
        yRelayer32Le: derivedRelayerShare.value,
        clientPublicKey33: hssClientSharePublicKey33,
        clientShareRetryCounter: request.clientShareRetryCounter,
      });
      const expectedContextBinding32 = base64UrlDecode(request.contextBinding32B64u);
      if (!bytesEqual(expectedContextBinding32, relayerBootstrap.contextBinding32)) {
        return {
          ok: false,
          code: 'context_mismatch',
          message: 'contextBinding32B64u does not match role-local HSS context',
        };
      }
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: signingRootMetadata.signingRootId,
        signingRootVersion: signingRootMetadata.signingRootVersion,
      });
      const existing = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (existing) {
        const signingRootVersion = canonicalEcdsaHssSigningRootVersion(
          signingRootMetadata.signingRootVersion,
        );
        if (existing.relayerKeyId !== request.relayerKeyId) {
          return {
            ok: false,
            code: 'relayer_key_mismatch',
            message: 'relayerKeyId mismatch requires ECDSA HSS re-bootstrap',
          };
        }
        if (
          existing.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
          existing.keyHandle !== keyHandle ||
          existing.walletId !== request.walletId ||
          existing.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
          existing.signingRootId !== signingRootMetadata.signingRootId ||
          existing.signingRootVersion !== signingRootVersion ||
          existing.keyScope !== request.keyScope ||
          existing.contextBinding32B64u !== request.contextBinding32B64u ||
          existing.clientPublicKey33B64u !== request.hssClientSharePublicKey33B64u
        ) {
          return {
            ok: false,
            code: 'identity_mismatch',
            message: 'ECDSA HSS key identity mismatch',
          };
        }
      }
      const session = await this.ecdsaMintSessionWithoutWebAuthn({
        relayerKeyId: request.relayerKeyId,
        clientVerifyingShareB64u: request.hssClientSharePublicKey33B64u,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        sessionId: request.sessionId,
        signingGrantId: request.signingGrantId,
        ttlMsRaw: request.ttlMs,
        remainingUsesRaw: request.remainingUses,
        policyParticipantIds: request.participantIds,
        signingRootMetadata,
        refreshExistingWalletBudget: true,
      });
      if (!session.ok) {
        return {
          ok: false,
          code:
            session.code === 'invalid_body' || session.code === 'unauthorized'
              ? session.code
              : 'internal',
          message: session.message || 'threshold-ecdsa role-local session mint failed',
        };
      }
      const nowMs = Date.now();
      const relayerPublicKey33B64u = base64UrlEncode(relayerBootstrap.relayerPublicKey33);
      const groupPublicKey33B64u = base64UrlEncode(relayerBootstrap.groupPublicKey33);
      const ethereumAddress = bytesToLowerHex(relayerBootstrap.ethereumAddress20);
      const publicTranscriptDigest32B64u = base64UrlEncode(
        relayerBootstrap.publicTranscriptDigest32,
      );
      const record = {
        version: 'threshold_ecdsa_hss_role_local_v2',
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        keyHandle,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        signingRootId: signingRootMetadata.signingRootId,
        signingRootVersion: canonicalEcdsaHssSigningRootVersion(
          signingRootMetadata.signingRootVersion,
        ),
        keyScope: 'evm-family',
        relayerKeyId: request.relayerKeyId,
        contextBinding32B64u: request.contextBinding32B64u,
        relayerShare32B64u: base64UrlEncode(relayerBootstrap.relayerShare32),
        relayerPublicKey33B64u,
        clientPublicKey33B64u: request.hssClientSharePublicKey33B64u,
        groupPublicKey33B64u,
        ethereumAddress,
        relayerCaitSithInput: {
          participantId: 2,
          mappedPrivateShare32B64u: base64UrlEncode(relayerBootstrap.relayerMappedPrivateShare32),
          verifyingShare33B64u: relayerPublicKey33B64u,
        },
        publicTranscriptDigest32B64u,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        updatedAtMs: nowMs,
      } satisfies EcdsaHssRoleLocalKeyRecord;
      await this.ecdsaKeyStore.putRoleLocalByKeyHandle(record);
      return {
        ok: true,
        value: {
          formatVersion: 'ecdsa-hss-role-local',
          walletId: request.walletId,
          evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          relayerKeyId: request.relayerKeyId,
          applicationBindingDigestB64u: base64UrlEncode(hssContext.applicationBindingDigest),
          contextBinding32B64u: request.contextBinding32B64u,
          publicIdentity: {
            hssClientSharePublicKey33B64u: request.hssClientSharePublicKey33B64u,
            relayerPublicKey33B64u: relayerPublicKey33B64u as EcdsaRelayerHssPublicKey33B64u,
            groupPublicKey33B64u,
            ethereumAddress,
          },
          clientShareRetryCounter: request.clientShareRetryCounter,
          relayerShareRetryCounter: relayerBootstrap.relayerShareRetryCounter,
          publicTranscriptDigest32B64u,
          keyHandle,
          signingRootId: signingRootMetadata.signingRootId,
          signingRootVersion: canonicalEcdsaHssSigningRootVersion(
            signingRootMetadata.signingRootVersion,
          ),
          thresholdEcdsaPublicKeyB64u: groupPublicKey33B64u,
          ethereumAddress,
          relayerVerifyingShareB64u: relayerPublicKey33B64u,
          participantIds: session.participantIds,
          thresholdSessionId: session.sessionId,
          signingGrantId: session.signingGrantId || request.signingGrantId,
          expiresAtMs: session.expiresAtMs,
          expiresAt: session.expiresAt,
          remainingUses: session.remainingUses ?? request.remainingUses,
        },
      };
    } catch (error) {
      const message = errorMessage(error);
      if (isEcdsaHssPublicKeyValidationError(message)) {
        return {
          ok: false,
          code: 'public_key_invalid',
          message,
        };
      }
      return {
        ok: false,
        code: 'internal',
        message: message || 'threshold-ecdsa role-local bootstrap failed',
      };
    }
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: EcdsaHssClientBootstrapRequest & {
      clientRootProof: NonNullable<EcdsaHssClientBootstrapRequest['clientRootProof']>;
    },
  ): Promise<EcdsaHssRouteResult<{ keyHandle: string }>> {
    try {
      const keyHandle = await deriveThresholdEcdsaHssKeyHandle({
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        signingRootId: request.signingRootId,
        signingRootVersion: request.signingRootVersion,
      });
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'ECDSA role-local key is not active for bootstrap authorization',
        };
      }
      if (
        record.walletId !== request.walletId ||
        record.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
        record.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
        record.keyHandle !== keyHandle ||
        record.signingRootId !== request.signingRootId ||
        record.signingRootVersion !==
          canonicalEcdsaHssSigningRootVersion(request.signingRootVersion) ||
        record.relayerKeyId !== request.relayerKeyId ||
        record.keyScope !== request.keyScope ||
        record.contextBinding32B64u !== request.contextBinding32B64u ||
        record.clientPublicKey33B64u !== request.hssClientSharePublicKey33B64u
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA role-local bootstrap proof does not match persisted key identity',
        };
      }
      const verifiedRootProof = await verifyEcdsaClientRootProof(request.clientRootProof);
      if (!verifiedRootProof.ok) return verifiedRootProof;
      return { ok: true, value: { keyHandle } };
    } catch {
      return { ok: false, code: 'unauthorized', message: 'Invalid client root proof' };
    }
  }

  private async computeEcdsaHssExportConfirmationDigest32(input: {
    request: EcdsaHssExportShareRequest;
  }): Promise<Uint8Array> {
    const { request } = input;
    return await sha256BytesUtf8(
      alphabetizeStringify({
        version: THRESHOLD_ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        relayerKeyId: request.relayerKeyId,
        contextBinding32B64u: request.contextBinding32B64u,
        publicIdentity: request.publicIdentity,
        clientDeviceId: request.clientDeviceId,
        clientSessionId: request.clientSessionId,
        exportRequestNonce32B64u: request.exportRequestNonce32B64u,
        issuedAtUnixMs: request.issuedAtUnixMs,
        expiresAtUnixMs: request.expiresAtUnixMs,
      }),
    );
  }

  private async computeEcdsaHssExportAuthorizationDigest32(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    record: EcdsaHssRoleLocalKeyRecord;
    claims: ThresholdEcdsaSessionClaims;
  }): Promise<Uint8Array> {
    const { request, record, claims } = input;
    return await sha256BytesUtf8(
      alphabetizeStringify({
        version: THRESHOLD_ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION,
        operation: 'explicit_key_export',
        keyHandle: input.keyHandle,
        walletId: request.walletId,
        evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
        relayerKeyId: request.relayerKeyId,
        signingRootId: record.signingRootId,
        signingRootVersion: record.signingRootVersion,
        contextBinding32B64u: request.contextBinding32B64u,
        publicIdentity: request.publicIdentity,
        exportRequestNonce32B64u: request.exportRequestNonce32B64u,
        confirmationDigest32B64u: request.confirmationDigest32B64u,
        issuedAtUnixMs: request.issuedAtUnixMs,
        expiresAtUnixMs: request.expiresAtUnixMs,
        clientDeviceId: request.clientDeviceId,
        clientSessionId: request.clientSessionId,
        thresholdSessionId: claims.thresholdSessionId,
        signingGrantId: claims.signingGrantId,
        thresholdExpiresAtMs: claims.thresholdExpiresAtMs,
        participantIds: claims.participantIds,
      }),
    );
  }

  private ecdsaHssExportReplayScope(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    claims: ThresholdEcdsaSessionClaims;
  }): string {
    return [
      'ecdsa-hss-export',
      input.request.walletId,
      input.request.evmFamilySigningKeySlotId,
      input.request.ecdsaThresholdKeyId,
      input.request.relayerKeyId,
      input.keyHandle,
      input.claims.thresholdSessionId,
    ].join(':');
  }

  private ecdsaHssExportReplayKey(request: EcdsaHssExportShareRequest): string {
    return request.exportRequestNonce32B64u;
  }

  async ecdsaHssRoleLocalExportShare(input: {
    request: EcdsaHssExportShareRequest;
    keyHandle: string;
    claims: ThresholdEcdsaSessionClaims;
  }): Promise<EcdsaHssRouteResult<EcdsaHssExportShareResponse>> {
    try {
      const { request } = input;
      const nowMs = Date.now();
      const keyHandle = toOptionalTrimmedString(input.keyHandle);
      if (!keyHandle) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Missing ECDSA HSS key handle',
        };
      }
      const { claims } = input;
      const replayGuard = await this.ecdsaWalletSessionStore.reserveReplayGuard(
        this.ecdsaHssExportReplayScope({ request, keyHandle, claims }),
        this.ecdsaHssExportReplayKey(request),
        request.expiresAtUnixMs,
      );
      if (!replayGuard.ok) {
        return {
          ok: false,
          code:
            replayGuard.code === 'export_nonce_replay'
              ? 'export_nonce_replay'
              : replayGuard.code === 'export_authorization_expired'
                ? 'export_authorization_expired'
                : 'export_authorization_invalid',
          message: replayGuard.message,
        };
      }
      if (request.expiresAtUnixMs <= nowMs) {
        return {
          ok: false,
          code: 'export_authorization_expired',
          message: 'ECDSA HSS export authorization is expired',
        };
      }
      if (request.issuedAtUnixMs > nowMs + THRESHOLD_ECDSA_HSS_EXPORT_CLOCK_SKEW_MS) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA HSS export authorization issue time is invalid',
        };
      }
      const record = await this.ecdsaKeyStore.getRoleLocalByKeyHandle(keyHandle);
      if (!record) {
        return {
          ok: false,
          code: 'not_found',
          message: 'ECDSA HSS role-local key not found',
        };
      }
      if (
        record.walletId !== request.walletId ||
        record.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
        record.ecdsaThresholdKeyId !== request.ecdsaThresholdKeyId ||
        record.relayerKeyId !== request.relayerKeyId ||
        claims.walletId !== request.walletId ||
        claims.evmFamilySigningKeySlotId !== request.evmFamilySigningKeySlotId ||
        claims.relayerKeyId !== request.relayerKeyId ||
        claims.keyHandle !== keyHandle
      ) {
        return {
          ok: false,
          code: 'identity_mismatch',
          message: 'ECDSA HSS export request does not match persisted key identity',
        };
      }
      if (record.contextBinding32B64u !== request.contextBinding32B64u) {
        return {
          ok: false,
          code: 'context_mismatch',
          message: 'ECDSA HSS export request context does not match persisted key',
        };
      }
      if (
        record.clientPublicKey33B64u !== request.publicIdentity.hssClientSharePublicKey33B64u ||
        record.relayerPublicKey33B64u !== request.publicIdentity.relayerPublicKey33B64u ||
        record.groupPublicKey33B64u !== request.publicIdentity.groupPublicKey33B64u ||
        record.ethereumAddress.toLowerCase() !==
          request.publicIdentity.ethereumAddress.toLowerCase()
      ) {
        return {
          ok: false,
          code: 'public_key_invalid',
          message: 'ECDSA HSS export request public identity does not match persisted key',
        };
      }
      const expectedConfirmationDigest32 = await this.computeEcdsaHssExportConfirmationDigest32({
        request,
      });
      if (
        !bytesEqual(base64UrlDecode(request.confirmationDigest32B64u), expectedConfirmationDigest32)
      ) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA HSS export confirmation digest is invalid',
        };
      }
      const expectedAuthorizationDigest32 = await this.computeEcdsaHssExportAuthorizationDigest32({
        request,
        keyHandle,
        record,
        claims,
      });
      if (
        !bytesEqual(
          base64UrlDecode(request.authorizationDigest32B64u),
          expectedAuthorizationDigest32,
        )
      ) {
        return {
          ok: false,
          code: 'export_authorization_invalid',
          message: 'ECDSA HSS export authorization digest is invalid',
        };
      }
      return {
        ok: true,
        value: {
          formatVersion: 'ecdsa-hss-role-local-export',
          walletId: request.walletId,
          evmFamilySigningKeySlotId: request.evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          relayerKeyId: request.relayerKeyId,
          contextBinding32B64u: request.contextBinding32B64u,
          publicIdentity: request.publicIdentity,
          exportAuthorizationDigest32B64u: request.authorizationDigest32B64u,
          serverExportShare32B64u: record.relayerShare32B64u,
        },
      };
    } catch (error) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'threshold-ecdsa role-local export share failed',
      };
    }
  }

  private async ed25519Session(
    request: ThresholdEd25519SessionRequest,
  ): Promise<ThresholdEd25519SessionResponse> {
    let context: Record<string, unknown> | null = null;
    try {
      const parsedRequest = parseThresholdEd25519SessionRequest(request, this.participantIds2p);
      if (!parsedRequest.ok) return parsedRequest;
      const {
        relayerKeyId,
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authority,
        authorityScope,
        thresholdSessionId,
        signingGrantId,
        runtimePolicyScope,
        routerAbNormalSigning,
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
      } = parsedRequest.value;
      const sessionId = thresholdSessionId;
      const routerAbPolicy = this.validateRouterAbNormalSigningSessionPolicy(routerAbNormalSigning);
      if (!routerAbPolicy.ok) return routerAbPolicy;
      context = {
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authorityKind: authority.factor.kind,
        authorityScope,
        relayerKeyId,
        thresholdSessionId,
        signingGrantId,
      };

      await this.ensureReady();

      const sessionAuth = request.auth;
      const appSessionClaims =
        sessionAuth.kind === 'verified_wallet' && sessionAuth.walletAuth.kind === 'app_session'
          ? sessionAuth.walletAuth.claims
          : null;
      const ecdsaSessionClaims =
        sessionAuth.kind === 'verified_wallet' &&
        sessionAuth.walletAuth.kind === 'threshold_ecdsa_session'
          ? sessionAuth.walletAuth.claims
          : null;
      const sessionWalletId =
        sessionAuth.kind === 'verified_wallet' && sessionAuth.walletAuth.kind === 'app_session'
          ? sessionAuth.walletAuth.sessionWalletId
          : '';
      const hasAppSessionAuth = Boolean(
        sessionAuth.kind === 'verified_wallet' &&
        sessionAuth.walletAuth.kind === 'app_session' &&
        sessionWalletId === walletId,
      );
      const policySigningRoot = resolveEcdsaSigningRootFromScope(
        request.sessionPolicy?.runtimePolicyScope,
      );
      const ecdsaSigningRoot = resolveEcdsaSigningRootFromScope(
        ecdsaSessionClaims?.runtimePolicyScope,
      );
      const hasEcdsaSessionAuth = Boolean(
        sessionAuth.kind === 'verified_wallet' &&
        sessionAuth.walletAuth.kind === 'threshold_ecdsa_session' &&
        ecdsaSessionClaims &&
        ecdsaSessionClaims.walletId === walletId &&
        ecdsaSessionClaims.thresholdExpiresAtMs > Date.now() &&
        (!policySigningRoot ||
          (ecdsaSigningRoot &&
            ecdsaSigningRoot.signingRootId === policySigningRoot.signingRootId &&
            ecdsaSigningRoot.signingRootVersion === policySigningRoot.signingRootVersion)),
      );
      const hasSessionAuth = hasAppSessionAuth || hasEcdsaSessionAuth;
      if (!hasSessionAuth && !this.verifyWebAuthnAuthenticationLite) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Lite WebAuthn verification is not configured on this server',
        };
      }

      const relayerKey = await this.resolveRelayerKeyMaterial({
        relayerKeyId,
      });
      if (!relayerKey.ok) {
        return { ok: false, code: relayerKey.code, message: relayerKey.message };
      }

      const { ttlMs, remainingUses } = this.clampSessionPolicy({
        ttlMs: ttlMsRaw,
        remainingUses: remainingUsesRaw,
      });
      const participantIds = policyParticipantIds || [...this.participantIds2p];
      const normalizedPolicy = {
        version: 'threshold_session_v1',
        nearAccountId,
        nearEd25519SigningKeyId,
        authority,
        relayerKeyId,
        thresholdSessionId,
        signingGrantId,
        ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
        ...(policyParticipantIds ? { participantIds: policyParticipantIds } : {}),
        ttlMs,
        remainingUses,
      };
      const sessionPolicyDigest32 = await this.computeSessionPolicyDigest32(normalizedPolicy);
      const expectedChallenge = base64UrlEncode(sessionPolicyDigest32);

      const existingSession = await this.walletSessionStore.getSession(sessionId);
      if (existingSession) {
        if (existingSession.userId !== walletId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different user',
          };
        }
        if (existingSession.relayerKeyId !== relayerKeyId) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different relayerKeyId',
          };
        }
        if (!thresholdEd25519AuthorityScopesMatch(existingSession.authorityScope, authorityScope)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different authority scope',
          };
        }
        const sameParticipantIds =
          existingSession.participantIds.length === participantIds.length &&
          existingSession.participantIds.every((id, i) => id === participantIds[i]);
        if (!sameParticipantIds) {
          return {
            ok: false,
            code: 'unauthorized',
            message: 'threshold sessionId already exists for a different participant set',
          };
        }
      }

      const authorizedSessionAuth = resolveAuthorizedThresholdEd25519SessionAuth({
        auth: sessionAuth,
        hasAppSessionAuth,
        hasEcdsaSessionAuth,
      });
      if (!authorizedSessionAuth.ok) return authorizedSessionAuth;

      switch (authorizedSessionAuth.value.kind) {
        case 'authorized_app_session': {
          const walletAuth = authorizedSessionAuth.value.walletAuth;
          if (walletAuth.claims.sub !== walletId && walletAuth.sessionWalletId !== walletId) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'app session does not match threshold-ed25519 session scope',
            };
          }
          break;
        }
        case 'authorized_threshold_ecdsa_session':
          break;
        case 'passkey_challenge_response': {
          if (!parsedRequest.value.expectedOrigin) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'expected_origin is required for threshold-ed25519 passkey session mint',
            };
          }
          const rpId = thresholdEd25519PasskeyAuthorityRpId(authorityScope);
          if (!rpId) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'threshold-ed25519 passkey session mint requires passkey_rp authority',
            };
          }
          const webAuthnRpId = parseWebAuthnRpIdField(rpId, 'sessionPolicy.authority.verifier.rpId');
          if (!webAuthnRpId.ok) return webAuthnRpId;
          const verification = await this.verifyWebAuthnAuthenticationLite!({
            userId: walletId,
            rpId: webAuthnRpId.value,
            expectedChallenge,
            expected_origin: parsedRequest.value.expectedOrigin,
            webauthn_authentication: authorizedSessionAuth.value.webauthnAuthentication,
          });

          if (!verification.success || !verification.verified) {
            return {
              ok: false,
              code: verification.code || 'not_verified',
              message: verification.message || 'Authentication verification failed',
            };
          }

          if (isImplicitNearAccountId(nearAccountId)) {
            const scope = verifyImplicitNearAccountPublicKeyBinding({
              nearAccountId,
              relayerPublicKey: relayerKey.publicKey,
            });
            if (!scope.ok) {
              return { ok: false, code: scope.code, message: scope.message };
            }
          }
          break;
        }
        default:
          assertNever(authorizedSessionAuth.value);
      }

      if (existingSession) {
        const walletBudget = await this.ensureSigningGrantBudget({
          signingGrantId,
          curve: 'ed25519',
          thresholdSessionId: sessionId,
          userId: walletId,
          authorityScope,
          participantIds: existingSession.participantIds,
          ttlMs,
          remainingUses,
          refreshExisting: false,
        });
        if (!walletBudget.ok) return walletBudget;
        return {
          ok: true,
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          thresholdSessionId: sessionId,
          signingGrantId,
          expiresAtMs: walletBudget.expiresAtMs,
          expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
          participantIds: walletBudget.participantIds,
          ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
        };
      }

      const expiresAtMs = Date.now() + ttlMs;
      await this.putWalletSessionRecord({
        store: this.walletSessionStore,
        sessionId,
        record: {
          expiresAtMs,
          relayerKeyId,
          userId: walletId,
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          authorityScope,
          participantIds,
        },
        ttlMs,
        remainingUses,
      });
      const walletBudget = await this.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ed25519',
        thresholdSessionId: sessionId,
        userId: walletId,
        authorityScope,
        participantIds,
        ttlMs,
        remainingUses,
        refreshExisting: true,
      });
      if (!walletBudget.ok) return walletBudget;

      return {
        ok: true,
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        thresholdSessionId: sessionId,
        signingGrantId,
        expiresAtMs: walletBudget.expiresAtMs,
        expiresAt: new Date(walletBudget.expiresAtMs).toISOString(),
        participantIds: walletBudget.participantIds,
        remainingUses,
        ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Internal error',
      );
      this.logger?.error?.('[threshold-ed25519] session mint failed', {
        message: msg,
        ...(context || {}),
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async expectedThresholdEd25519HssApplicationBindingDigestB64u(input: {
    nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    signingRootId: unknown;
    signingRootVersion: unknown;
  }): Promise<string> {
    return await computeSdkEd25519HssApplicationBindingDigestB64u({
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signingRootId: parseSdkEcdsaHssSigningRootId(input.signingRootId),
      signingRootVersion: parseSdkEcdsaHssSigningRootVersion(input.signingRootVersion),
    });
  }

  private async validateThresholdEd25519HssSessionScope(input: {
    claims: ThresholdEd25519SessionClaims;
    relayerKeyId: string;
    context: ThresholdEd25519HssCanonicalContext;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  }): Promise<ThresholdEd25519HssSessionError | null> {
    const sessionId = toOptionalTrimmedString(input.claims?.thresholdSessionId);
    if (!sessionId) {
      return { ok: false, code: 'unauthorized', message: 'Missing threshold sessionId' };
    }
    const userId = toOptionalTrimmedString(input.claims?.walletId);
    if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing threshold userId' };
    const tokenRelayerKeyId = toOptionalTrimmedString(input.claims?.relayerKeyId);
    if (!tokenRelayerKeyId) {
      return { ok: false, code: 'unauthorized', message: 'Invalid Wallet Session claims' };
    }
    if (input.relayerKeyId !== tokenRelayerKeyId) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'relayerKeyId does not match threshold session scope',
      };
    }
    if (Date.now() > input.claims.thresholdExpiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    for (const id of this.participantIds2p) {
      if (!input.claims.participantIds.includes(id)) {
        return {
          ok: false,
          code: 'unauthorized',
          message: `Wallet Session does not include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
        };
      }
    }
    if (!haveSameParticipantIds(input.context.participantIds, input.claims.participantIds)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.participantIds does not match threshold session scope',
      };
    }
    if (!toOptionalTrimmedString(input.preparedSession.contextBindingB64u)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'preparedSession.contextBindingB64u is required',
      };
    }
    const claimSigningRoot = resolveEcdsaSigningRootFromScope(input.claims.runtimePolicyScope);
    if (!claimSigningRoot?.signingRootId || !claimSigningRoot.signingRootVersion) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Wallet Session is missing Ed25519 HSS binding facts',
      };
    }
    let nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    try {
      nearEd25519SigningKeyId = parseNearEd25519SigningKeyId(input.claims.nearEd25519SigningKeyId);
    } catch {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Wallet Session is missing Ed25519 HSS binding facts',
      };
    }
    const expectedDigest = await this.expectedThresholdEd25519HssApplicationBindingDigestB64u({
      nearEd25519SigningKeyId,
      signingRootId: claimSigningRoot.signingRootId,
      signingRootVersion: claimSigningRoot.signingRootVersion,
    });
    if (input.context.applicationBindingDigestB64u !== expectedDigest) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.applicationBindingDigestB64u does not match threshold session scope',
      };
    }
    return null;
  }

  private validateThresholdEd25519HssContextPreparedSessionScope(input: {
    context: ThresholdEd25519HssCanonicalContext;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  }): ThresholdEd25519HssSessionError | null {
    if (!haveSameParticipantIds(input.context.participantIds, this.participantIds2p)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: `threshold-ed25519 HSS context must match server signer set participantIds=[${this.participantIds2p.join(',')}]`,
      };
    }
    if (!toOptionalTrimmedString(input.preparedSession.contextBindingB64u)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'preparedSession.contextBindingB64u is required',
      };
    }
    return null;
  }

  private async validateThresholdEd25519HssRegistrationScope(input: {
    orgId: string;
    registrationAccountScope: ThresholdEd25519RegistrationAccountScope;
    context: ThresholdEd25519HssCanonicalContext;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  }): Promise<ThresholdEd25519HssSessionError | null> {
    const scope = input.registrationAccountScope;
    if (!input.orgId) {
      return { ok: false, code: 'unauthorized', message: 'Missing registration orgId' };
    }
    const expectedDigest = await this.expectedThresholdEd25519HssApplicationBindingDigestB64u({
      nearEd25519SigningKeyId: scope.nearEd25519SigningKeyId,
      signingRootId: scope.signingRootId,
      signingRootVersion: scope.signingRootVersion,
    });
    if (input.context.applicationBindingDigestB64u !== expectedDigest) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.applicationBindingDigestB64u does not match registration scope',
      };
    }
    if (!haveSameParticipantIds(input.context.participantIds, scope.participantIds)) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'context.participantIds do not match registration scope',
      };
    }
    return this.validateThresholdEd25519HssContextPreparedSessionScope({
      context: input.context,
      preparedSession: input.preparedSession,
    });
  }

  private validateThresholdEd25519HssSigningRootConstraint(input: {
    actualSigningRootId?: unknown;
    expectedSigningRootId?: unknown;
  }): ThresholdEd25519HssSessionError | null {
    const expectedSigningRootId = toOptionalTrimmedString(input.expectedSigningRootId);
    const actualSigningRootId = toOptionalTrimmedString(input.actualSigningRootId);
    if (
      expectedSigningRootId &&
      actualSigningRootId &&
      expectedSigningRootId !== actualSigningRootId
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'signingRootId does not match authenticated signing root scope',
      };
    }
    return null;
  }

  private async deriveSigningRootEd25519HssServerInputsForContext(
    context: ThresholdEd25519HssCanonicalContext,
    signingRootId: string | undefined,
    signingRoot?: { readonly signingRootVersion?: unknown },
  ): Promise<ThresholdEd25519HssCanonicalContext & ThresholdEd25519HssServerInputs> {
    if (!this.signingRootShareResolver) {
      throw new Error('threshold-ed25519 HSS requires a signing-root share resolver');
    }

    const fixedScope = this.signingRootShareResolver.fixedSigningRootScope;
    const signingRootVersion =
      toOptionalTrimmedString(signingRoot?.signingRootVersion) ||
      toOptionalTrimmedString(fixedScope?.signingRootVersion);
    const resolvedSigningRootId =
      toOptionalTrimmedString(signingRootId) || toOptionalTrimmedString(fixedScope?.signingRootId);
    if (!resolvedSigningRootId) {
      throw new Error('threshold-ed25519 HSS requires a signingRootId');
    }
    const derived = await deriveEd25519HssServerInputsFromSigningRootShareResolver({
      signingRootId: resolvedSigningRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
      resolver: this.signingRootShareResolver,
      context,
    });
    if (!derived.ok) {
      throw new Error(`threshold-prf signing-root derivation failed: ${derived.message}`);
    }
    return derived.value;
  }

  private async ed25519HssPrepareWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519HssPrepareWithSessionRequest;
  }): Promise<ThresholdEd25519HssPrepareWithSessionResponse> {
    try {
      const prepareStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
      if (!relayerKeyId) {
        return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
      }
      const operation = parseThresholdEd25519HssSessionOperation(rec.operation);
      if (!operation.ok) return operation;
      const context = parseThresholdEd25519HssCanonicalContext(rec.context);
      if (!context.ok) return context;
      const expectedSigningRoot = input.claims.runtimePolicyScope
        ? signingRootScopeFromRuntimePolicyScope(input.claims.runtimePolicyScope)
        : undefined;
      const signingRootConstraintError = this.validateThresholdEd25519HssSigningRootConstraint({
        actualSigningRootId: expectedSigningRoot?.signingRootId,
        expectedSigningRootId: expectedSigningRoot?.signingRootId,
      });
      if (signingRootConstraintError) return signingRootConstraintError;
      const parseMs = Date.now() - parseStartedAt;

      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();
      if (!this.signingRootShareResolver) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires a signing-root share resolver',
        };
      }

      const wasmStartedAt = Date.now();
      let serverInputDeriveMs = 0;
      let serverSessionPrepareTotalMs = 0;
      const [serverInputs, preparedServerSession] = await Promise.all([
        (async () => {
          const startedAt = Date.now();
          try {
            return await this.deriveSigningRootEd25519HssServerInputsForContext(
              context.value,
              expectedSigningRoot?.signingRootId,
              expectedSigningRoot,
            );
          } finally {
            serverInputDeriveMs = Date.now() - startedAt;
          }
        })(),
        (async () => {
          const startedAt = Date.now();
          try {
            return await prepareThresholdEd25519HssServerSession({
              context: context.value,
            });
          } finally {
            serverSessionPrepareTotalMs = Date.now() - startedAt;
          }
        })(),
      ]);
      const resolvedPreparedSession: ThresholdEd25519HssPreparedSessionEnvelope = {
        contextBindingB64u: preparedServerSession.contextBindingB64u,
        evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
      };
      const storedPreparedServerSession: ThresholdEd25519HssStoredPreparedServerSession = {
        evaluatorDriverStateBytes: base64UrlDecode(preparedServerSession.evaluatorDriverStateB64u),
        garblerDriverStateBytes: base64UrlDecode(preparedServerSession.garblerDriverStateB64u),
      };
      const storedServerInputs: ThresholdEd25519HssStoredServerInputs = {
        yRelayerBytes: base64UrlDecode(serverInputs.yRelayerB64u),
        tauRelayerBytes: base64UrlDecode(serverInputs.tauRelayerB64u),
      };
      const scopeError = await this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId,
        context: context.value,
        preparedSession: resolvedPreparedSession,
      });
      if (scopeError) return scopeError;
      const ceremonyRecord: ThresholdEd25519HssCeremonyRecordInput = {
        kind: 'session',
        relayerKeyId,
        operation: operation.value,
        context: context.value,
        preparedSession: resolvedPreparedSession,
        preparedServerSession: storedPreparedServerSession,
        serverInputs: storedServerInputs,
      };
      const ceremonyHandle = await this.storeThresholdEd25519HssCeremony(ceremonyRecord);
      const responsePayload = {
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
      };

      this.logger?.info?.('[threshold-ed25519] hss prepare timings', {
        relayerKeyId,
        nearAccountId: input.claims.nearAccountId,
        requestBytes: jsonBytes(input.request || {}),
        parseMs,
        ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
        wasmPrepareMs: Date.now() - wasmStartedAt,
        responseBytes: jsonBytes(responsePayload),
        ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
        preparedSessionBytes: jsonBytes(resolvedPreparedSession),
        evaluatorDriverStateBytes: utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        evaluatorDriverStatePayloadBytes: base64UrlPayloadBytes(
          resolvedPreparedSession.evaluatorDriverStateB64u,
        ),
        evaluatorDriverStateTransportOverheadBytes:
          utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u) -
          base64UrlPayloadBytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        clientOtOfferMessageBytes: utf8Bytes(preparedServerSession.clientOtOfferMessageB64u),
        clientOtOfferMessagePayloadBytes: base64UrlPayloadBytes(
          preparedServerSession.clientOtOfferMessageB64u,
        ),
        clientOtOfferMessageTransportOverheadBytes:
          utf8Bytes(preparedServerSession.clientOtOfferMessageB64u) -
          base64UrlPayloadBytes(preparedServerSession.clientOtOfferMessageB64u),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(ceremonyRecord),
        totalMs: Date.now() - prepareStartedAt,
      });

      return {
        ok: true,
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
        serverInputDeriveMs,
        serverSessionPrepareTotalMs,
        serverSessionTimings: preparedServerSession.timings,
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519] hss prepare failed', { message: msg });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssPrepareForRegistration(input: {
    orgId: string;
    signingRootId?: string;
    signingRootVersion?: string;
    request: ThresholdEd25519HssPrepareForRegistrationRequest;
  }): Promise<ThresholdEd25519HssPrepareForRegistrationResponse> {
    try {
      const prepareStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const registrationAccountScope = parseThresholdEd25519RegistrationAccountScope(
        rec.registrationAccountScope,
      );
      if (!registrationAccountScope.ok) return registrationAccountScope;
      const requestNearEd25519SigningKeyId = parseNearEd25519SigningKeyIdField(
        rec.wallet_key_id,
        'wallet_key_id',
      );
      if (!requestNearEd25519SigningKeyId.ok) return requestNearEd25519SigningKeyId;
      if (
        registrationAccountScope.value.nearEd25519SigningKeyId !==
        requestNearEd25519SigningKeyId.value
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationAccountScope.nearEd25519SigningKeyId does not match wallet_key_id',
        };
      }
      const nearEd25519SigningKeyId = registrationAccountScope.value.nearEd25519SigningKeyId;
      const context = parseThresholdEd25519HssCanonicalContext(rec.context);
      if (!context.ok) return context;
      const signingRootConstraintError = this.validateThresholdEd25519HssSigningRootConstraint({
        actualSigningRootId: registrationAccountScope.value.signingRootId,
        expectedSigningRootId: input.signingRootId,
      });
      if (signingRootConstraintError) return signingRootConstraintError;
      const parseMs = Date.now() - parseStartedAt;

      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();
      if (!this.signingRootShareResolver) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-ed25519 HSS requires a signing-root share resolver',
        };
      }

      const wasmStartedAt = Date.now();
      let serverInputDeriveMs = 0;
      let serverSessionPrepareTotalMs = 0;
      const [serverInputs, preparedServerSession] = await Promise.all([
        (async () => {
          const startedAt = Date.now();
          try {
            return await this.deriveSigningRootEd25519HssServerInputsForContext(
              context.value,
              input.signingRootId || registrationAccountScope.value.signingRootId,
              {
                signingRootVersion: input.signingRootVersion,
              },
            );
          } finally {
            serverInputDeriveMs = Date.now() - startedAt;
          }
        })(),
        (async () => {
          const startedAt = Date.now();
          try {
            return await prepareThresholdEd25519HssServerSession({
              context: context.value,
            });
          } finally {
            serverSessionPrepareTotalMs = Date.now() - startedAt;
          }
        })(),
      ]);
      const resolvedPreparedSession: ThresholdEd25519HssPreparedSessionEnvelope = {
        contextBindingB64u: preparedServerSession.contextBindingB64u,
        evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
      };
      const storedPreparedServerSession: ThresholdEd25519HssStoredPreparedServerSession = {
        preparedSessionHandle: preparedServerSession.preparedSessionHandle,
        evaluatorDriverStateBytes: base64UrlDecode(preparedServerSession.evaluatorDriverStateB64u),
        garblerDriverStateBytes: base64UrlDecode(preparedServerSession.garblerDriverStateB64u),
      };
      const storedServerInputs: ThresholdEd25519HssStoredServerInputs = {
        yRelayerBytes: base64UrlDecode(serverInputs.yRelayerB64u),
        tauRelayerBytes: base64UrlDecode(serverInputs.tauRelayerB64u),
      };
      const scopeError = await this.validateThresholdEd25519HssRegistrationScope({
        orgId: toOptionalTrimmedString(input.orgId) || '',
        registrationAccountScope: registrationAccountScope.value,
        context: context.value,
        preparedSession: resolvedPreparedSession,
      });
      if (scopeError) {
        releaseThresholdEd25519HssPreparedServerSession(
          preparedServerSession.preparedSessionHandle,
        );
        return scopeError;
      }
      const ceremonyRecord: ThresholdEd25519HssCeremonyRecordInput = {
        kind: 'registration',
        orgId: toOptionalTrimmedString(input.orgId) || '',
        registrationAccountScope: registrationAccountScope.value,
        context: context.value,
        preparedSession: resolvedPreparedSession,
        preparedServerSession: storedPreparedServerSession,
        serverInputs: storedServerInputs,
      };
      const ceremonyHandle = this.createThresholdEd25519HssCeremonyHandle();
      const serverState = thresholdEd25519HssRegistrationPreparedServerState({
        context: context.value,
        preparedServerSession,
        serverInputs,
      });
      const responsePayload = {
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
      };

      this.logger?.info?.('[threshold-ed25519][registration] hss prepare timings', {
        nearEd25519SigningKeyId,
        requestBytes: jsonBytes(input.request || {}),
        parseMs,
        ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
        wasmPrepareMs: Date.now() - wasmStartedAt,
        responseBytes: jsonBytes(responsePayload),
        ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
        preparedSessionBytes: jsonBytes(resolvedPreparedSession),
        evaluatorDriverStateBytes: utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        evaluatorDriverStatePayloadBytes: base64UrlPayloadBytes(
          resolvedPreparedSession.evaluatorDriverStateB64u,
        ),
        evaluatorDriverStateTransportOverheadBytes:
          utf8Bytes(resolvedPreparedSession.evaluatorDriverStateB64u) -
          base64UrlPayloadBytes(resolvedPreparedSession.evaluatorDriverStateB64u),
        clientOtOfferMessageBytes: utf8Bytes(preparedServerSession.clientOtOfferMessageB64u),
        clientOtOfferMessagePayloadBytes: base64UrlPayloadBytes(
          preparedServerSession.clientOtOfferMessageB64u,
        ),
        clientOtOfferMessageTransportOverheadBytes:
          utf8Bytes(preparedServerSession.clientOtOfferMessageB64u) -
          base64UrlPayloadBytes(preparedServerSession.clientOtOfferMessageB64u),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(ceremonyRecord),
        totalMs: Date.now() - prepareStartedAt,
      });
      releaseThresholdEd25519HssPreparedServerSession(preparedServerSession.preparedSessionHandle);

      return {
        ok: true,
        ceremonyHandle,
        preparedSession: resolvedPreparedSession,
        clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
        serverState,
        serverInputDeriveMs,
        serverSessionPrepareTotalMs,
        serverSessionTimings: preparedServerSession.timings,
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519][registration] hss prepare failed', {
        message: msg,
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssRespondWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519HssRespondWithSessionRequest;
  }): Promise<ThresholdEd25519HssRespondWithSessionResponse> {
    try {
      const respondStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const ceremonyHandle = toOptionalTrimmedString(rec.ceremonyHandle);
      if (!ceremonyHandle) {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
      }
      const ceremony = await this.getThresholdEd25519HssCeremony(ceremonyHandle);
      if (!ceremony.ok) return ceremony;
      if (ceremony.value.kind !== 'session') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      const clientRequest = parseThresholdEd25519HssServerVisibleClientRequestEnvelope(
        rec.clientRequest,
      );
      if (!clientRequest.ok) return clientRequest;

      const scopeError = await this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId: ceremony.value.relayerKeyId,
        context: ceremony.value.context,
        preparedSession: ceremony.value.preparedSession,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;
      if (!ceremony.value.serverInputs) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle no longer retains relayer roots for respond',
        };
      }
      const claimedCeremony = await this.takeThresholdEd25519HssCeremony(ceremonyHandle);
      if (!claimedCeremony.ok) return claimedCeremony;
      if (claimedCeremony.value.kind !== 'session') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      const { serverInputs, ...respondedCeremony } = claimedCeremony.value;
      if (!serverInputs) {
        await this.ed25519HssCeremonyStore.put(ceremonyHandle, respondedCeremony);
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ceremonyHandle no longer retains relayer roots for respond',
        };
      }

      const wasmStartedAt = Date.now();
      const result = await prepareThresholdEd25519HssRoleSeparatedServerInputDelivery({
        operation: claimedCeremony.value.operation,
        preparedServerSession: claimedCeremony.value.preparedServerSession,
        expectedContextBindingB64u: claimedCeremony.value.preparedSession.contextBindingB64u,
        clientRequest: clientRequest.value,
        serverInputs,
      });
      clearThresholdEd25519HssStoredServerInputs(serverInputs);
      const respondedServerSession: ThresholdEd25519HssStoredRespondedServerSession = {
        ...respondedCeremony.preparedServerSession,
        serverEvalStateBytes: result.serverEvalStateBytes,
      };
      const storedRespondedCeremony: ThresholdEd25519HssCeremonyRecord = {
        ...respondedCeremony,
        preparedServerSession: respondedServerSession,
      };
      await this.ed25519HssCeremonyStore.put(ceremonyHandle, storedRespondedCeremony);
      const wasmRespondMs = Date.now() - wasmStartedAt;
      const responsePayload = {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
      };

      this.logger?.info?.('[threshold-ed25519] hss respond timings', {
        relayerKeyId: claimedCeremony.value.relayerKeyId,
        nearAccountId: input.claims.nearAccountId,
        requestBytes: jsonBytes(input.request || {}),
        clientRequestBytes: jsonBytes(clientRequest.value),
        clientRequestMessageBytes: utf8Bytes(clientRequest.value.clientRequestMessageB64u),
        clientRequestMessagePayloadBytes: base64UrlPayloadBytes(
          clientRequest.value.clientRequestMessageB64u,
        ),
        clientRequestMessageTransportOverheadBytes:
          utf8Bytes(clientRequest.value.clientRequestMessageB64u) -
          base64UrlPayloadBytes(clientRequest.value.clientRequestMessageB64u),
        parseMs,
        respondEngine: result.engine,
        wasmRespondMs,
        wasmRespondBreakdownMs: result.timings || null,
        responseBytes: jsonBytes(responsePayload),
        serverInputDeliveryBytes: utf8Bytes(result.serverInputDelivery.serverInputDeliveryB64u),
        serverInputDeliveryPayloadBytes: base64UrlPayloadBytes(
          result.serverInputDelivery.serverInputDeliveryB64u,
        ),
        ceremonyStateBytes: summarizeThresholdEd25519HssCeremonyRecordBytes(storedRespondedCeremony),
        totalMs: Date.now() - respondStartedAt,
      });

      return {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
        ...(result.timings ? { serverInputDeliveryTimings: result.timings } : {}),
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519] hss respond failed', { message: msg });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssRespondForRegistration(input: {
    orgId: string;
    request: ThresholdEd25519HssRespondForRegistrationRequest;
  }): Promise<ThresholdEd25519HssRespondForRegistrationResponse> {
    try {
      const respondStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const registrationAccountScope = parseThresholdEd25519RegistrationAccountScope(
        rec.registrationAccountScope,
      );
      if (!registrationAccountScope.ok) return registrationAccountScope;
      const requestNearEd25519SigningKeyId = parseNearEd25519SigningKeyIdField(
        rec.wallet_key_id,
        'wallet_key_id',
      );
      if (!requestNearEd25519SigningKeyId.ok) return requestNearEd25519SigningKeyId;
      if (
        registrationAccountScope.value.nearEd25519SigningKeyId !==
        requestNearEd25519SigningKeyId.value
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationAccountScope.nearEd25519SigningKeyId does not match wallet_key_id',
        };
      }
      const nearEd25519SigningKeyId = registrationAccountScope.value.nearEd25519SigningKeyId;
      const ceremonyHandle = toOptionalTrimmedString(rec.ceremonyHandle);
      if (!ceremonyHandle) {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
      }
      const preparedSession = parseThresholdEd25519HssPreparedSessionEnvelope(rec.preparedSession);
      if (!preparedSession.ok) return preparedSession;
      const serverState = parseThresholdEd25519HssRegistrationPreparedServerState(rec.serverState);
      if (!serverState.ok) return serverState;
      const clientRequest = parseThresholdEd25519HssServerVisibleClientRequestEnvelope(
        rec.clientRequest,
      );
      if (!clientRequest.ok) return clientRequest;

      const scopeError = await this.validateThresholdEd25519HssRegistrationScope({
        orgId: toOptionalTrimmedString(input.orgId) || '',
        registrationAccountScope: registrationAccountScope.value,
        context: serverState.value.context,
        preparedSession: preparedSession.value,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;
      const serverInputs = serverState.value.serverInputs;

      const wasmStartedAt = Date.now();
      const result = await prepareThresholdEd25519HssRoleSeparatedServerInputDelivery({
        operation: 'registration',
        preparedServerSession: serverState.value.preparedServerSession,
        expectedContextBindingB64u: preparedSession.value.contextBindingB64u,
        clientRequest: clientRequest.value,
        serverInputs,
      });
      clearThresholdEd25519HssStoredServerInputs(serverInputs);
      const respondedServerSession: ThresholdEd25519HssStoredRespondedServerSession = {
        ...serverState.value.preparedServerSession,
        serverEvalStateBytes: result.serverEvalStateBytes,
      };
      const respondedServerState = thresholdEd25519HssRegistrationRespondedServerState({
        context: serverState.value.context,
        preparedServerSession: respondedServerSession,
      });
      const wasmRespondMs = Date.now() - wasmStartedAt;
      const responsePayload = {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
      };

      this.logger?.info?.('[threshold-ed25519][registration] hss respond timings', {
        nearEd25519SigningKeyId,
        requestBytes: jsonBytes(input.request || {}),
        clientRequestBytes: jsonBytes(clientRequest.value),
        clientRequestMessageBytes: utf8Bytes(clientRequest.value.clientRequestMessageB64u),
        clientRequestMessagePayloadBytes: base64UrlPayloadBytes(
          clientRequest.value.clientRequestMessageB64u,
        ),
        clientRequestMessageTransportOverheadBytes:
          utf8Bytes(clientRequest.value.clientRequestMessageB64u) -
          base64UrlPayloadBytes(clientRequest.value.clientRequestMessageB64u),
        parseMs,
        respondEngine: result.engine,
        wasmRespondMs,
        wasmRespondBreakdownMs: result.timings || null,
        responseBytes: jsonBytes(responsePayload),
        serverInputDeliveryBytes: utf8Bytes(result.serverInputDelivery.serverInputDeliveryB64u),
        serverInputDeliveryPayloadBytes: base64UrlPayloadBytes(
          result.serverInputDelivery.serverInputDeliveryB64u,
        ),
        totalMs: Date.now() - respondStartedAt,
      });

      return {
        ok: true,
        contextBindingB64u: result.serverInputDelivery.contextBindingB64u,
        serverInputDeliveryB64u: result.serverInputDelivery.serverInputDeliveryB64u,
        serverState: respondedServerState,
        ...(result.timings ? { serverInputDeliveryTimings: result.timings } : {}),
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519][registration] hss respond failed', {
        message: msg,
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssFinalizeWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519HssFinalizeWithSessionRequest;
  }): Promise<ThresholdEd25519HssFinalizeWithSessionResponse> {
    try {
      const finalizeStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const ceremonyHandle = toOptionalTrimmedString(rec.ceremonyHandle);
      if (!ceremonyHandle) {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
      }
      const ceremony = await this.getThresholdEd25519HssCeremony(ceremonyHandle);
      if (!ceremony.ok) return ceremony;
      if (ceremony.value.kind !== 'session') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      const evaluationResult = parseThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope(
        rec.evaluationResult,
      );
      if (!evaluationResult.ok) return evaluationResult;
      if (
        evaluationResult.value.contextBindingB64u !==
        ceremony.value.preparedSession.contextBindingB64u
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'evaluationResult context binding mismatch',
        };
      }
      const storedEvaluationResult =
        storedThresholdEd25519HssEvaluationResultFromClientOwnedEnvelope(evaluationResult.value);

      const scopeError = await this.validateThresholdEd25519HssSessionScope({
        claims: input.claims,
        relayerKeyId: ceremony.value.relayerKeyId,
        context: ceremony.value.context,
        preparedSession: ceremony.value.preparedSession,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;
      const ensureReadyStartedAt = Date.now();
      await this.ensureReady();

      const takenCeremony = await this.takeThresholdEd25519HssCeremony(ceremonyHandle);
      if (!takenCeremony.ok) return takenCeremony;
      if (takenCeremony.value.kind !== 'session') {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle scope mismatch' };
      }
      const finalizingCeremony: ThresholdEd25519HssCeremonyRecord = {
        ...takenCeremony.value,
        evaluationResult: storedEvaluationResult,
      };
      const respondedServerSession = requireThresholdEd25519HssRespondedServerSession(
        takenCeremony.value.preparedServerSession,
      );
      if (!respondedServerSession) {
        await this.ed25519HssCeremonyStore.put(ceremonyHandle, takenCeremony.value);
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ceremonyHandle has not recorded responded server eval state',
        };
      }
      await this.ed25519HssCeremonyStore.put(ceremonyHandle, finalizingCeremony);
      try {
        const wasmStartedAt = Date.now();
        const result = await finalizeThresholdEd25519HssServerCeremony({
          operation: takenCeremony.value.operation,
          preparedSession: takenCeremony.value.preparedSession,
          preparedServerSession: respondedServerSession,
          evaluationResult: storedEvaluationResult,
          expectedContextBindingB64u: takenCeremony.value.preparedSession.contextBindingB64u,
        });
        const responsePayload = {
          finalizedReport: result.finalizedReport,
        };
        const wasmFinalizeMs = Date.now() - wasmStartedAt;

        this.logger?.info?.('[threshold-ed25519] hss finalize timings', {
          relayerKeyId: ceremony.value.relayerKeyId,
          nearAccountId: input.claims.nearAccountId,
          requestBytes: jsonBytes(input.request || {}),
          evaluationResultBytes: thresholdEd25519HssEvaluationResultTransportBytes(
            evaluationResult.value,
          ),
          evaluationResultPayloadBytes: thresholdEd25519HssEvaluationResultPayloadBytes(
            evaluationResult.value,
          ),
          parseMs,
          ensureReadyMs: wasmStartedAt - ensureReadyStartedAt,
          wasmFinalizeMs,
          responseBytes: jsonBytes(responsePayload),
          finalizedReportBytes: jsonBytes(result.finalizedReport),
          totalMs: Date.now() - finalizeStartedAt,
        });

        return {
          ok: true,
          finalizedReport: result.finalizedReport,
        };
      } finally {
        await this.ed25519HssCeremonyStore.delete(ceremonyHandle);
        this.releaseThresholdEd25519HssCeremonyResources(finalizingCeremony);
      }
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519] hss finalize failed', { message: msg });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519HssFinalizeForRegistration(input: {
    orgId: string;
    request: ThresholdEd25519HssFinalizeForRegistrationRequest;
  }): Promise<ThresholdEd25519HssFinalizeForRegistrationResponse> {
    try {
      const finalizeStartedAt = Date.now();
      const parseStartedAt = Date.now();
      const rec = (input.request || {}) as unknown as Record<string, unknown>;
      const registrationAccountScope = parseThresholdEd25519RegistrationAccountScope(
        rec.registrationAccountScope,
      );
      if (!registrationAccountScope.ok) return registrationAccountScope;
      const requestNearEd25519SigningKeyId = parseNearEd25519SigningKeyIdField(
        rec.wallet_key_id,
        'wallet_key_id',
      );
      if (!requestNearEd25519SigningKeyId.ok) return requestNearEd25519SigningKeyId;
      const authorityScope = parseThresholdEd25519AuthorityScope(rec.authorityScope);
      if (!authorityScope) {
        return { ok: false, code: 'invalid_body', message: 'authorityScope is required' };
      }
      if (
        registrationAccountScope.value.nearEd25519SigningKeyId !==
        requestNearEd25519SigningKeyId.value
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationAccountScope.nearEd25519SigningKeyId does not match wallet_key_id',
        };
      }
      const nearEd25519SigningKeyId = registrationAccountScope.value.nearEd25519SigningKeyId;
      const ceremonyHandle = toOptionalTrimmedString(rec.ceremonyHandle);
      if (!ceremonyHandle) {
        return { ok: false, code: 'invalid_body', message: 'ceremonyHandle is required' };
      }
      const preparedSession = parseThresholdEd25519HssPreparedSessionEnvelope(rec.preparedSession);
      if (!preparedSession.ok) return preparedSession;
      const serverState = parseThresholdEd25519HssRegistrationRespondedServerState(rec.serverState);
      if (!serverState.ok) return serverState;
      const evaluationResult = parseThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope(
        rec.evaluationResult,
      );
      if (!evaluationResult.ok) return evaluationResult;
      if (evaluationResult.value.contextBindingB64u !== preparedSession.value.contextBindingB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'evaluationResult context binding mismatch',
        };
      }
      const storedEvaluationResult =
        storedThresholdEd25519HssEvaluationResultFromClientOwnedEnvelope(evaluationResult.value);

      const scopeError = await this.validateThresholdEd25519HssRegistrationScope({
        orgId: toOptionalTrimmedString(input.orgId) || '',
        registrationAccountScope: registrationAccountScope.value,
        context: serverState.value.context,
        preparedSession: preparedSession.value,
      });
      if (scopeError) return scopeError;

      const parseMs = Date.now() - parseStartedAt;

      await this.ensureReady();

      const hssFinalizeStartedAt = Date.now();
      const result = await finalizeThresholdEd25519HssServerCeremony({
        operation: 'registration',
        preparedSession: preparedSession.value,
        preparedServerSession: serverState.value.preparedServerSession,
        evaluationResult: storedEvaluationResult,
        expectedContextBindingB64u: preparedSession.value.contextBindingB64u,
      });
      const registrationMaterialStartedAt = Date.now();
      const registrationMaterial = await deriveThresholdEd25519RegistrationMaterialFromHssFinalize({
        preparedSession: preparedSession.value,
        preparedServerSession: serverState.value.preparedServerSession,
        finalizedReport: result.finalizedReport,
        serverOutput: result.serverOutput,
      });
      const resolvedNearAccountId = resolveThresholdEd25519FinalizeNearAccountId({
        accountResolution: input.request.accountResolution,
        publicKey: registrationMaterial.publicKey,
      });
      if (!resolvedNearAccountId.ok) return resolvedNearAccountId;
      const keyStorePutStartedAt = Date.now();
      await this.keyStore.put(registrationMaterial.relayerKeyId, {
        kind: 'ready',
        walletId: registrationAccountScope.value.walletId,
        nearAccountId: resolvedNearAccountId.value,
        nearEd25519SigningKeyId,
        authorityScope,
        publicKey: registrationMaterial.publicKey,
        routerMaterial: {
          signingShareB64u: registrationMaterial.relayerSigningShareB64u,
          verifyingShareB64u: registrationMaterial.relayerVerifyingShareB64u,
        },
        keyVersion: registrationAccountScope.value.keyVersion,
        recoveryExportCapable: true,
      });
      const keyStorePutMs = Date.now() - keyStorePutStartedAt;
      const responsePayload = {
        publicKey: registrationMaterial.publicKey,
        nearAccountId: resolvedNearAccountId.value,
        relayerKeyId: registrationMaterial.relayerKeyId,
        finalizedReport: result.finalizedReport,
      };
      this.logger?.info?.('[threshold-ed25519][registration] hss finalize timings', {
        nearAccountId: resolvedNearAccountId.value,
        nearEd25519SigningKeyId,
        requestBytes: jsonBytes(input.request || {}),
        evaluationResultBytes: thresholdEd25519HssEvaluationResultTransportBytes(
          evaluationResult.value,
        ),
        evaluationResultPayloadBytes: thresholdEd25519HssEvaluationResultPayloadBytes(
          evaluationResult.value,
        ),
        parseMs,
        hssFinalizeMs: Date.now() - hssFinalizeStartedAt,
        registrationMaterialMs: keyStorePutStartedAt - registrationMaterialStartedAt,
        keyStorePutMs,
        responseBytes: jsonBytes(responsePayload),
        finalizedReportBytes: jsonBytes(result.finalizedReport),
        totalMs: Date.now() - finalizeStartedAt,
      });

      return {
        ok: true,
        publicKey: registrationMaterial.publicKey,
        nearAccountId: resolvedNearAccountId.value,
        relayerKeyId: registrationMaterial.relayerKeyId,
        finalizedReport: result.finalizedReport,
        finalizeReportTimings: {
          ...(result.finalizeReportTimings ?? {
            decodeArtifactMs: 0,
            serializedSessionMaterializeMs: 0,
            finalizeReportMs: 0,
            encodeReportMs: 0,
            openServerOutputMs: 0,
            openSeedOutputMs: 0,
            deriveSeedKeypairMs: 0,
            deriveRelayerVerifyingShareMs: 0,
            keyStorePutMs: 0,
          }),
          openSeedOutputMs: registrationMaterial.timings.openSeedOutputMs,
          deriveSeedKeypairMs: registrationMaterial.timings.deriveSeedKeypairMs,
          deriveRelayerVerifyingShareMs: registrationMaterial.timings.deriveRelayerVerifyingShareMs,
          keyStorePutMs,
        },
      };
    } catch (e: unknown) {
      const msg = errorMessage(e);
      this.logger?.error?.('[threshold-ed25519][registration] hss finalize failed', {
        message: msg,
      });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  // Signing round endpoints are exposed via SchemeModule.protocol (see `getSchemeModule`).
}
