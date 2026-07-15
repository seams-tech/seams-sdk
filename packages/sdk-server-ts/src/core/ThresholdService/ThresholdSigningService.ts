import type { NormalizedLogger } from '../logger';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  parseWebAuthnRpId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
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
import type { ParseResult } from './routerAbNormalSigningPolicy';
import type { SessionClaims } from '../../router/routerApi';
import type {
  RouterAbNormalSigningRuntime,
  RouterAbSigningWorkerPrivateTransport,
} from '../routerAbSigning/RouterAbNormalSigningRuntime';
import type { ThresholdEcdsaIntegratedKeyStore, ThresholdEd25519KeyStore } from './stores/KeyStore';
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
  ThresholdEd25519AuthorityScope,
  Ed25519SessionPolicy,
  ThresholdEcdsaSigningRootMetadata,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdStoreConfigInput,
} from '../types';
import {
  extractAuthorizeSigningPublicKey,
  parseRouterAbEd25519WalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  thresholdEd25519AuthorityScopesMatch,
  toNearPublicKeyStr,
  type RouterAbEd25519WalletSessionClaims,
} from './validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
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
import { secureRandomIdFragment } from './secureRandomId';

type ThresholdEd25519SessionClaims = RouterAbEd25519WalletSessionClaims;
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

type ThresholdEcdsaWalletSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  participantIds: number[];
} & Partial<ThresholdEcdsaSigningRootMetadata>;

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

function compactDiagnosticValue(value: unknown): string | null {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) return null;
  return normalized.length <= 16
    ? normalized
    : `${normalized.slice(0, 10)}...${normalized.slice(-6)}`;
}

type EcdsaSigningRootReference = {
  signingRootId: string;
  signingRootVersion?: string;
};

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
      walletAuth: Extract<ThresholdEd25519VerifiedWalletAuth, { kind: 'threshold_ecdsa_session' }>;
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

function parseWebAuthnRpIdField(raw: unknown, fieldName: string): ParseResult<WebAuthnRpId> {
  const parsed = parseWebAuthnRpId(raw);
  if (parsed.ok) return { ok: true, value: parsed.value };
  return {
    ok: false,
    code: 'invalid_body',
    message: `${fieldName}: ${parsed.error.message}`,
  };
}

function assertNever(value: never): never {
  throw new Error(`Unhandled threshold signing branch: ${String(value)}`);
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

function ecdsaPoolFillTransportFromNormalSigningTransport(
  transport: RouterAbSigningWorkerPrivateTransport,
): {
  signingWorkerBaseUrl: string;
  auth: { kind: 'internal_service_auth_secret'; secret: string };
} | null {
  switch (transport.kind) {
    case 'configured':
      return {
        signingWorkerBaseUrl: transport.signingWorkerBaseUrl,
        auth: transport.auth,
      };
    case 'unconfigured':
      return null;
    default:
      return assertNever(transport);
  }
}

export class ThresholdSigningService {
  private readonly logger: NormalizedLogger;
  private readonly keyStore: ThresholdEd25519KeyStore;
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly walletSessionStore: Ed25519WalletSessionStore;
  private readonly routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
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
  private cachedSchemeModules: Partial<Record<ThresholdSchemeId, ThresholdAnySchemeModule>> | null =
    null;

  constructor(input: {
    logger: NormalizedLogger;
    keyStore: ThresholdEd25519KeyStore;
    sessionStore: ThresholdEd25519SessionStore;
    walletSessionStore: Ed25519WalletSessionStore;
    routerAbNormalSigningRuntime: RouterAbNormalSigningRuntime;
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
    ecdsaPoolFillLiveSessionOwner?: RouterAbEcdsaHssPoolFillLiveSessionOwner;
  }) {
    this.logger = input.logger;
    this.keyStore = input.keyStore;
    this.sessionStore = input.sessionStore;
    this.walletSessionStore = input.walletSessionStore;
    this.routerAbNormalSigningRuntime = input.routerAbNormalSigningRuntime;
    this.ecdsaKeyStore = input.ecdsaKeyStore;
    this.ecdsaSessionStore = input.ecdsaSessionStore;
    this.ecdsaWalletSessionStore = input.ecdsaWalletSessionStore;
    this.ecdsaPoolFillSessionStore = input.ecdsaPoolFillSessionStore;
    this.ecdsaPresignaturePool = input.ecdsaPresignaturePool;
    this.signingRootShareResolver = input.signingRootShareResolver || null;
    const cfg = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;

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
    const routerAbEcdsaPoolFillTransport = ecdsaPoolFillTransportFromNormalSigningTransport(
      this.routerAbNormalSigningRuntime.getSigningWorkerPrivateTransport(),
    );

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
      routerAbEcdsaHssPoolFill: routerAbEcdsaPoolFillTransport,
    });
  }

  hasSigningRootShareResolver(): boolean {
    return this.signingRootShareResolver !== null;
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
    authority: WalletAuthAuthority;
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
    const authority = input.authority;
    const authorityScope = thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority);
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
      const keyVersion = toOptionalTrimmedString((input as { keyVersion?: unknown }).keyVersion);
      const publicKey = toOptionalTrimmedString((input as { publicKey?: unknown }).publicKey);
      const relayerKeyId = toOptionalTrimmedString(
        (input as { relayerKeyId?: unknown }).relayerKeyId,
      );
      const authority = parseWalletAuthAuthority((input as { authority?: unknown }).authority);
      if (!authority || authority.walletId !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'authority is required' };
      }
      const authorityScope = thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority);
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
        authority,
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
    authority: WalletAuthAuthority;
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
      const authority = parseWalletAuthAuthority(input.authority);
      if (!authority || authority.walletId !== walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.authority is required',
        };
      }
      const authorityScope = thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority);

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
      const routerAbPolicy =
        this.routerAbNormalSigningRuntime.validateSessionPolicy(routerAbNormalSigning);
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
      if (
        !thresholdEd25519AuthorityScopesMatch(policyAuthorityScope, authorityScope) ||
        !walletAuthAuthoritiesMatch(policyAuthority, authority)
      ) {
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
        const walletBudget = await this.routerAbNormalSigningRuntime.ensureSigningGrantBudget({
          signingGrantId,
          curve: 'ed25519',
          thresholdSessionId,
          userId: walletId,
          authorityScope,
          participantIds: existingSession.participantIds,
          ttlMs,
          remainingUses,
          operation: 'provision_curve_binding',
        });
        if (!walletBudget.ok) return walletBudget;
        return {
          ok: true,
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          authorityScope,
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
      const walletBudget = await this.routerAbNormalSigningRuntime.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ed25519',
        thresholdSessionId,
        userId: walletId,
        authorityScope,
        participantIds,
        ttlMs,
        remainingUses,
        operation: 'provision_curve_binding',
      });
      if (!walletBudget.ok) return walletBudget;

      return {
        ok: true,
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        authorityScope,
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
      const routerAbPolicy =
        this.routerAbNormalSigningRuntime.validateSessionPolicy(routerAbNormalSigning);
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
          const webAuthnRpId = parseWebAuthnRpIdField(
            rpId,
            'sessionPolicy.authority.verifier.rpId',
          );
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
        const walletBudget = await this.routerAbNormalSigningRuntime.ensureSigningGrantBudget({
          signingGrantId,
          curve: 'ed25519',
          thresholdSessionId: sessionId,
          userId: walletId,
          authorityScope,
          participantIds: existingSession.participantIds,
          ttlMs,
          remainingUses,
          operation: 'provision_curve_binding',
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
      const walletBudget = await this.routerAbNormalSigningRuntime.ensureSigningGrantBudget({
        signingGrantId,
        curve: 'ed25519',
        thresholdSessionId: sessionId,
        userId: walletId,
        authorityScope,
        participantIds,
        ttlMs,
        remainingUses,
        operation: 'provision_curve_binding',
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

  // Signing round endpoints are exposed via SchemeModule.protocol (see `getSchemeModule`).
}
