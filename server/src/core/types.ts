// Platform-agnostic types for server functionality
import {
  AuthenticatorOptions,
  UserVerificationPolicy,
  OriginPolicyInput,
} from '@/core/types/authenticatorOptions';
import type { InitInput } from '../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { Logger } from './logger';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type {
  SigningRootSecretDecryptAdapter,
  SigningRootSecretResolverAdapters,
  SigningRootSecretShareSource,
} from './ThresholdService/signingRootSecretResolverAdapters';
import type { SigningRootSecretShareKekResolver } from './ThresholdService/signingRootSecretSealing';
import type { SigningRootShareResolver } from './ThresholdService/signingRootShareResolver';

/**
 * WASM Bindgen generates a `free` method and a `[Symbol.dispose]` method on all structs.
 * Strip both so we can pass plain objects to the worker.
 */
export type StripFree<T> = T extends object
  ? { [K in keyof T as K extends 'free' | symbol ? never : K]: StripFree<T[K]> }
  : T;

// Standard request/response interfaces that work across all platforms
export interface ServerRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface ServerResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export type SignerWasmModuleSupplier =
  | InitInput
  | Promise<InitInput>
  | (() => InitInput | Promise<InitInput>);

export interface SignerWasmConfig {
  /**
   * Optional override for locating the signer WASM module. Useful for serverless
   * runtimes (e.g. Workers) where filesystem-relative URLs are unavailable.
   * Accepts any value supported by `initSignerWasm({ module_or_path })` or a
   * function that resolves to one.
   */
  moduleOrPath?: SignerWasmModuleSupplier;
}

export interface ThresholdEd25519HssCanonicalContext {
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
}

export interface ThresholdEd25519HssClientInputs {
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
}

export interface ThresholdEd25519HssServerInputs {
  yRelayerB64u: string;
  tauRelayerB64u: string;
}

export interface ThresholdEd25519HssStoredServerInputs {
  yRelayerBytes: Uint8Array;
  tauRelayerBytes: Uint8Array;
}

export interface ThresholdEd25519HssSessionInputs {
  context: ThresholdEd25519HssCanonicalContext;
  client: ThresholdEd25519HssClientInputs;
  server: ThresholdEd25519HssServerInputs;
}

export interface ThresholdEd25519HssPreparedSessionEnvelope {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
}

export interface ThresholdEd25519HssPreparedServerSessionEnvelope {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
  garblerDriverStateB64u: string;
  clientOtOfferMessageB64u: string;
  preparedSessionHandle: string;
}

export interface ThresholdEd25519HssStoredPreparedServerSession {
  preparedSessionHandle?: string;
  evaluatorDriverStateBytes: Uint8Array;
  garblerDriverStateBytes: Uint8Array;
}

export interface ThresholdEd25519HssClientRequestEnvelope {
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u: string;
}

export type ThresholdEd25519HssStagedEvaluatorArtifactEnvelope =
  | {
      contextBindingB64u: string;
      stagedEvaluatorArtifactHandle: string;
      stagedEvaluatorArtifactBytes?: undefined;
    }
  | {
      contextBindingB64u: string;
      stagedEvaluatorArtifactBytes: Uint8Array;
      stagedEvaluatorArtifactHandle?: undefined;
    };

export type ThresholdEd25519HssStoredStagedEvaluatorArtifact =
  | {
      stagedEvaluatorArtifactHandle: string;
      stagedEvaluatorArtifactBytes?: undefined;
    }
  | {
      stagedEvaluatorArtifactBytes: Uint8Array;
      stagedEvaluatorArtifactHandle?: undefined;
    };

export interface ThresholdEd25519HssFinalizedReportEnvelope {
  contextBindingB64u: string;
  clientOutputMessageB64u: string;
  seedOutputMessageB64u?: string;
}

export interface ThresholdEd25519HssOpenedClientOutput {
  contextBindingB64u: string;
  xClientBaseB64u: string;
}

export interface ThresholdEd25519HssOpenedServerOutput {
  contextBindingB64u: string;
  xRelayerBaseB64u: string;
}

export interface ThresholdEd25519HssOpenedSeedOutput {
  contextBindingB64u: string;
  canonicalSeedB64u: string;
}

export interface ThresholdEd25519HssDerivedPublicKey {
  publicKeyB64u: string;
}

export type ThresholdEd25519HssSessionOperation =
  | 'tx_signing'
  | 'link_device'
  | 'email_recovery'
  | 'warm_session_reconstruction'
  | 'explicit_key_export';

export interface ThresholdEd25519HssPrepareWithSessionRequest {
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  context: ThresholdEd25519HssCanonicalContext;
}

export interface ThresholdEd25519HssPrepareForRegistrationRequest {
  new_account_id: string;
  rp_id: string;
  context: ThresholdEd25519HssCanonicalContext;
}

export interface ThresholdEd25519HssRespondWithSessionRequest {
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}

export interface ThresholdEd25519HssRespondForRegistrationRequest {
  new_account_id: string;
  rp_id: string;
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}

export type ThresholdEd25519HssPrepareWithSessionResponse =
  | {
      ok: true;
      ceremonyHandle: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      clientOtOfferMessageB64u: string;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssPrepareForRegistrationResponse =
  | {
      ok: true;
      ceremonyHandle: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      clientOtOfferMessageB64u: string;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssRespondWithSessionResponse =
  | {
      ok: true;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssRespondForRegistrationResponse =
  | {
      ok: true;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export interface ThresholdEd25519HssFinalizeWithSessionRequest {
  ceremonyHandle: string;
}

export interface ThresholdEd25519HssFinalizeForRegistrationRequest {
  new_account_id: string;
  rp_id: string;
  ceremonyHandle: string;
  account_provisioning?: {
    mode: 'create_if_missing';
  };
}

export type ThresholdEd25519HssFinalizeWithSessionResponse =
  | {
      ok: true;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

export type ThresholdEd25519HssFinalizeForRegistrationResponse =
  | {
      ok: true;
      publicKey: string;
      relayerKeyId: string;
      accountProvisioning?: {
        mode: 'create_if_missing';
        status: 'created' | 'already_ready';
        transactionHash?: string;
      };
    }
  | {
      ok: false;
      code?: string;
      message?: string;
    };

// ================================
// Threshold Ed25519 key persistence
// ================================

export type ThresholdEd25519KeyStoreKind =
  | 'in-memory'
  | 'upstash-redis-rest'
  | 'redis-tcp'
  | 'cloudflare-do';

// Structural types so Workers can pass Durable Object bindings without depending on CF type packages.
export interface CloudflareDurableObjectStubLike {
  fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

export interface CloudflareDurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): CloudflareDurableObjectStubLike;
}

export type ThresholdStoreConfig =
  | { kind: 'in-memory' }
  | { kind: 'upstash-redis-rest'; url: string; token: string; keyPrefix?: string }
  | { kind: 'redis-tcp'; redisUrl: string; keyPrefix?: string }
  | { kind: 'postgres'; postgresUrl: string; keyPrefix?: string }
  | {
      kind: 'cloudflare-do';
      /**
       * Durable Object namespace binding (e.g. `env.THRESHOLD_STORE`).
       * Must point to a DO class compatible with the SDK's threshold store protocol.
       */
      namespace: CloudflareDurableObjectNamespaceLike;
      /**
       * Optional DO instance name. Defaults to `threshold-store`.
       * Use different names to isolate environments within the same Worker script.
       */
      name?: string;
    };

/**
 * Env-shaped input for threshold key store selection.
 * - Upstash REST (Cloudflare-friendly): UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN
 * - Redis TCP (Node-only): REDIS_URL
 */
export type ThresholdStoreEnvInput = {
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
  REDIS_URL?: string;
  /** Node-only Postgres connection string for durable storage. */
  POSTGRES_URL?: string;
  /**
   * Optional global base prefix for all threshold keyspaces.
   *
   * When set, and the more specific `THRESHOLD_ED25519_*_PREFIX` variables are not set,
   * the SDK derives:
   * - `THRESHOLD_ED25519_AUTH_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:auth:`
   * - `THRESHOLD_ED25519_SESSION_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:sess:`
   * - `THRESHOLD_ED25519_KEYSTORE_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:key:`
   *
   * Trailing `:` is optional.
   */
  THRESHOLD_PREFIX?: string;
  THRESHOLD_ED25519_KEYSTORE_PREFIX?: string;
  THRESHOLD_ED25519_SESSION_PREFIX?: string;
  THRESHOLD_ED25519_AUTH_PREFIX?: string;
  /**
   * Ed25519 relayer-share source mode. This remains Ed25519-specific because
   * it controls the Ed25519 threshold signing protocol, not the shared store.
   */
  THRESHOLD_ED25519_SHARE_MODE?: string;
  /**
   * Optional prefixes for threshold ECDSA key/session/auth storage.
   * Defaults derive from `THRESHOLD_PREFIX` with a `threshold-ecdsa:*` namespace when unset.
   */
  THRESHOLD_ECDSA_KEYSTORE_PREFIX?: string;
  THRESHOLD_ECDSA_SESSION_PREFIX?: string;
  THRESHOLD_ECDSA_AUTH_PREFIX?: string;
  /**
   * Optional prefixes for threshold ECDSA presignature pool and signing-session storage.
   * Defaults derive from `THRESHOLD_PREFIX` with a `threshold-ecdsa:*` namespace when unset.
   */
  THRESHOLD_ECDSA_PRESIGN_PREFIX?: string;
  THRESHOLD_ECDSA_SIGNING_PREFIX?: string;
  /**
   * Optional override for the client FROST participant identifier (u16, >= 1).
   * Must be distinct from `THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID`.
   */
  THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID?: string;
  /**
   * Optional override for the relayer FROST participant identifier (u16, >= 1).
   * Must be distinct from `THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID`.
   */
  THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID?: string;
  /**
   * Threshold node role.
   * - "coordinator" (default): exposes `/threshold-ed25519/sign/*` and can fan out to cosigners when configured.
   * - "cosigner": does not expose public signing endpoints; intended for internal relayer-fleet t-of-n cosigning.
   */
  THRESHOLD_NODE_ROLE?: string;
  /**
   * 32-byte base64url shared secret used to authenticate coordinator→peer calls.
   *
   * When set, cosigner relayers can expose internal endpoints that accept
   * coordinator-signed grants (HMAC-SHA256).
   */
  THRESHOLD_COORDINATOR_SHARED_SECRET_B64U?: string;
  /**
   * Stable identifier for this coordinator instance.
   *
   * Used to pin `/threshold-ecdsa/presign/*` sessions to the instance that
   * created the live in-memory WASM session object.
   */
  THRESHOLD_COORDINATOR_INSTANCE_ID?: string;
  /**
   * Optional coordinator peer list (JSON) for cross-instance presign-step forwarding.
   *
   * Example:
   * `THRESHOLD_COORDINATOR_PEERS=[{"instanceId":"coordinator-a","relayerUrl":"https://relay-a.internal"},{"instanceId":"coordinator-b","relayerUrl":"https://relay-b.internal"}]`
   */
  THRESHOLD_COORDINATOR_PEERS?: string;
  /**
   * Optional relayer-fleet cosigner list (JSON) for internal t-of-n cosigning.
   *
   * When configured on a coordinator node, the coordinator can fan out to relayer cosigners
   * (internal-only nodes) and combine their partials into a single outer relayer signature share.
   *
   * Example:
   * `THRESHOLD_ED25519_RELAYER_COSIGNERS=[{"cosignerId":1,"relayerUrl":"https://cosigner-a.internal"},{"cosignerId":2,"relayerUrl":"https://cosigner-b.internal"},{"cosignerId":3,"relayerUrl":"https://cosigner-c.internal"}]`
   */
  THRESHOLD_ED25519_RELAYER_COSIGNERS?: string;
  /**
   * Internal relayer cosigner id for this node (u16, >= 1).
   * Required when running `THRESHOLD_NODE_ROLE=cosigner`.
   */
  THRESHOLD_ED25519_RELAYER_COSIGNER_ID?: string;
  /**
   * Internal relayer cosigner threshold `T` (integer, >= 1).
   * When set together with `THRESHOLD_ED25519_RELAYER_COSIGNERS`, the coordinator will wait for
   * `T` cosigners per signing round.
   */
  THRESHOLD_ED25519_RELAYER_COSIGNER_T?: string;
  /**
   * Optional threshold ECDSA presign-pool policy hint returned to clients during `/threshold-ecdsa/authorize`.
   * Values are advisory and clients may clamp them locally.
   */
  THRESHOLD_ECDSA_PRESIGN_POOL_HINT_ENABLED?: string;
  THRESHOLD_ECDSA_PRESIGN_POOL_HINT_TARGET_DEPTH?: string;
  THRESHOLD_ECDSA_PRESIGN_POOL_HINT_LOW_WATERMARK?: string;
  THRESHOLD_ECDSA_PRESIGN_POOL_HINT_MAX_REFILL_IN_FLIGHT?: string;
  THRESHOLD_ECDSA_PRESIGN_POOL_HINT_REFILL_ATTEMPT_TIMEOUT_MS?: string;
  /** Optional signing session-seal key metadata and Shamir 3-pass parameters. */
  SIGNING_SESSION_SEAL_KEY_VERSION?: string;
  SIGNING_SESSION_SHAMIR_P_B64U?: string;
  SIGNING_SESSION_SEAL_E_S_B64U?: string;
  SIGNING_SESSION_SEAL_D_S_B64U?: string;
  /** Optional signing session-seal idempotency backend configuration. */
  SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX?: string;
  SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS?: string;
  /**
   * Core signing-root dependency for signing. Hosted deployments usually build
   * this from storage/decrypt adapters. Direct self-host deployments can supply
   * a resolver backed by imported signing-root shares and do not need a KEK env.
   */
  signingRootShareResolver?: SigningRootShareResolver;
  signingRootSecretResolverAdapters?: SigningRootSecretResolverAdapters;
  signingRootSecretStore?: SigningRootSecretShareSource;
  signingRootSecretDecryptAdapter?: SigningRootSecretDecryptAdapter;
  signingRootSecretShareKekResolver?: SigningRootSecretShareKekResolver;
};

/**
 * Threshold key store config input.
 *
 * Accepts either:
 * - an env-shaped object (for ergonomics in server examples), or
 * - an explicit `kind` object, optionally augmented with env-shaped overrides
 *   (useful when wiring via code but still wanting env vars like THRESHOLD_NODE_ROLE).
 */
export type ThresholdStoreConfigInput =
  | ThresholdStoreEnvInput
  | (ThresholdStoreConfig & Partial<ThresholdStoreEnvInput>);

export interface AuthServiceConfig {
  relayerAccount: string;
  relayerPrivateKey: string;
  nearRpcUrl: string;
  networkId: string;
  accountInitialBalance: string;
  createAccountAndRegisterGas: string;
  signerWasm?: SignerWasmConfig;
  /**
   * Optional persistence for relayer-held threshold signing shares.
   * Defaults to in-memory unless env-shaped config enables Redis/Upstash.
   */
  thresholdStore?: ThresholdStoreConfigInput;
  /**
   * Optional logger. When unset, the server SDK is silent (no `console.*`).
   * Pass `logger: console` to enable default logging.
   */
  logger?: Logger | null;
  /**
   * Optional Google OIDC configuration for verifying Google `id_token` login sessions.
   */
  googleOidc?: GoogleOidcConfig;
  /**
   * Optional generic OIDC JWT exchange configuration for `POST /session/exchange`.
   */
  oidcExchange?: OidcExchangeConfig;
}

export type GoogleOidcConfig = {
  /** Allowed OAuth client ids (audiences) for Google ID tokens. */
  clientIds: string[];
  /** Optional hosted domain allowlist (the `hd` claim). */
  hostedDomains?: string[];
};

export interface GoogleOidcConfigEnvInput {
  /** Single client id convenience. */
  GOOGLE_OIDC_CLIENT_ID?: string;
  /** Comma-separated client ids. */
  GOOGLE_OIDC_CLIENT_IDS?: string;
  /** Optional comma-separated hosted domains (`hd` claim). */
  GOOGLE_OIDC_HOSTED_DOMAINS?: string;
}

export type GoogleOidcConfigInput = GoogleOidcConfig | GoogleOidcConfigEnvInput;

export type OidcExchangeIssuerConfig = {
  /** Exact issuer (`iss`) value to trust. */
  issuer: string;
  /** Allowed audiences (`aud`) for this issuer. */
  audiences: string[];
  /** JWKS endpoint used to verify JWT signatures for this issuer. */
  jwksUrl: string;
  /**
   * Optional stable subject prefix for internal identity mapping.
   * Defaults to `oidc:{issuer}:`.
   */
  subjectPrefix?: string;
};

export type OidcExchangeConfig = {
  issuers: OidcExchangeIssuerConfig[];
  /**
   * Allowed JWT clock skew in seconds for `iat`/`nbf`/`exp` checks.
   * Defaults to 60 seconds.
   */
  clockSkewSec?: number;
};

export type OidcExchangeConfigInput = OidcExchangeConfig;

/**
 * User-facing input shape for `AuthService`. Fields that have SDK defaults are optional here.
 *
 * Defaults are applied by `createAuthServiceConfig(...)` and by `new AuthService(...)`.
 */
export type AuthServiceConfigInput = Omit<
  AuthServiceConfig,
  | 'nearRpcUrl'
  | 'networkId'
  | 'accountInitialBalance'
  | 'createAccountAndRegisterGas'
  | 'thresholdStore'
  | 'googleOidc'
  | 'oidcExchange'
> & {
  nearRpcUrl?: string;
  networkId?: string;
  accountInitialBalance?: string;
  createAccountAndRegisterGas?: string;
  thresholdStore?: ThresholdStoreConfigInput;
  googleOidc?: GoogleOidcConfigInput;
  oidcExchange?: OidcExchangeConfigInput;
};

// Account creation and registration types (imported from relay-server types)
export interface AccountCreationRequest {
  accountId: string;
  publicKey: string;
  recoveryPublicKey?: string;
}

export interface AccountCreationResult {
  success: boolean;
  transactionHash?: string;
  accountId?: string;
  error?: string;
  message?: string;
}

// WebAuthn registration credential structure
export interface WebAuthnRegistrationCredential {
  id: string;
  rawId: string; // base64-encoded
  type: string;
  authenticatorAttachment: string | null;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
  };
  // PRF outputs are not sent to the relay server
  clientExtensionResults: null;
}

// Interface for atomic account creation and registration
export interface CreateAccountAndRegisterRequest {
  new_account_id: string;
  /**
   * Signer slot used during registration.
   *
   * This is used to deterministically derive the registration WebAuthn challenge
   * in WebAuthn-only mode (e.g. `sha256("register:${accountId}:${signerSlot}")`).
   */
  signer_slot?: number;
  threshold_ed25519?: {
    key_version: string;
    recovery_export_capable: boolean;
    public_key: string;
    relayer_key_id: string;
    session_policy: Omit<Ed25519SessionPolicy, 'relayerKeyId'> & {
      relayerKeyId?: string;
    };
    session_kind: 'jwt' | 'cookie';
  };
  threshold_ecdsa?: {
    client_root_share32_b64u: string;
    session_policy: Omit<EcdsaSessionPolicy, 'relayerKeyId'> & {
      relayerKeyId?: string;
    };
    session_kind: 'jwt' | 'cookie';
    smart_account_targets?: CreateAccountAndRegisterSmartAccountTarget[];
  };
  /**
   * WebAuthn RP ID used for the registration ceremony (e.g. `wallet.example.com`).
   *
   * This is required for standard WebAuthn verification on the relay.
   */
  rp_id: string;
  webauthn_registration: WebAuthnRegistrationCredential;
  /**
   * Optional expected origin override for strict WebAuthn verification.
   *
   * Routers typically populate this from the request `Origin` header.
   */
  expected_origin?: string;
  authenticator_options?: AuthenticatorOptions;
}

export interface CreateAccountAndRegisterSmartAccountTarget {
  chain: 'evm' | 'tempo';
  chain_id: number;
  factory?: string;
  entry_point?: string;
  recovery_authority?: string;
  salt?: string;
  counterfactual_address?: string;
}

export interface CreateAccountAndRegisterSmartAccountDeployment {
  chain: 'evm' | 'tempo';
  chainId: number;
  accountAddress: string;
  accountModel: 'erc4337' | 'tempo-native';
  deployed: boolean;
  deploymentTxHash?: string;
  code?: string;
  message?: string;
  counterfactualAddress?: string;
}

// Result type for atomic account creation and registration
export interface CreateAccountAndRegisterResult {
  success: boolean;
  code?: string;
  transactionHash?: string;
  thresholdEd25519?: {
    keyVersion: string;
    recoveryExportCapable: true;
    relayerKeyId: string;
    publicKey: string;
    clientParticipantId?: number;
    relayerParticipantId?: number;
    participantIds?: number[];
    session?: {
      sessionKind: 'jwt' | 'cookie';
      sessionId: string;
      expiresAtMs: number;
      expiresAt?: string;
      participantIds?: number[];
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      jwt?: string;
    };
  };
  thresholdEcdsa?: {
    relayerKeyId: string;
    thresholdEcdsaPublicKeyB64u: string;
    ethereumAddress: string;
    relayerVerifyingShareB64u: string;
    participantIds?: number[];
    session?: {
      sessionKind: 'jwt' | 'cookie';
      sessionId: string;
      expiresAtMs: number;
      expiresAt?: string;
      participantIds?: number[];
      remainingUses?: number;
      jwt?: string;
    };
  };
  smartAccountDeployments?: CreateAccountAndRegisterSmartAccountDeployment[];
  error?: string;
  message?: string;
  contractResult?: any; // FinalExecutionOutcome
}

// Runtime-tested NEAR error types
export interface NearActionErrorKind {
  AccountAlreadyExists?: {
    accountId: string;
  };
  AccountDoesNotExist?: {
    account_id: string;
  };
  InsufficientStake?: {
    account_id: string;
    stake: string;
    minimum_stake: string;
  };
  LackBalanceForState?: {
    account_id: string;
    balance: string;
  };
  [key: string]: any;
}

export interface NearActionError {
  kind: NearActionErrorKind;
  index: string;
}

export interface NearExecutionFailure {
  ActionError?: NearActionError;
  [key: string]: any;
}

export interface NearReceiptStatus {
  SuccessValue?: string;
  SuccessReceiptId?: string;
  Failure?: NearExecutionFailure;
}

export interface NearReceiptOutcomeWithId {
  id: string;
  outcome: {
    logs: string[];
    receipt_ids: string[];
    gas_burnt: number;
    tokens_burnt: string;
    executor_id: string;
    status: NearReceiptStatus;
  };
}

// Re-export authenticator types from core
export type { AuthenticatorOptions, UserVerificationPolicy, OriginPolicyInput };

export interface WebAuthnAuthenticationCredential {
  id: string;
  rawId: string; // base64-encoded
  type: string;
  authenticatorAttachment: string | null;
  response: {
    clientDataJSON: string; // base64url-encoded
    authenticatorData: string; // base64url-encoded
    signature: string; // base64url-encoded
    userHandle: string | null; // base64url-encoded or null
  };
  clientExtensionResults: any | null;
}

export interface VerifyAuthenticationResponse {
  success: boolean;
  verified?: boolean;
  jwt?: string;
  sessionCredential?: any;
  // Unified error model
  code?: string;
  message?: string;
  contractResponse?: any;
}

// ================================
// Threshold Ed25519 (2-party) APIs
// ================================

export type ThresholdRuntimePolicyScope = RuntimePolicyScope;

export type ThresholdEcdsaSigningRootMetadata = {
  signingRootId: string;
  signingRootVersion?: string;
  walletKeyVersion: string;
  derivationVersion: number;
};

export type ThresholdRuntimeSnapshotExpectation = {
  snapshotId?: string;
  version?: number;
  checksum?: string;
};

export type ThresholdEd25519Purpose = 'near_tx' | 'nep461_delegate' | 'nep413' | string;

export type Ed25519SessionPolicy = {
  version: 'threshold_session_v1';
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  sessionId: string;
  walletSigningSessionId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export interface ThresholdEd25519SessionRequest {
  relayerKeyId: string;
  sessionPolicy: Ed25519SessionPolicy;
  runtimeEnvironmentId?: string;
  webauthn_authentication?: WebAuthnAuthenticationCredential;
  appSessionClaims?: Record<string, unknown>;
  ecdsaSessionClaims?: Record<string, unknown>;
  // Optional: whether to return JWT in JSON or set an HttpOnly cookie
  sessionKind?: 'jwt' | 'cookie';
}

export interface ThresholdEd25519SessionResponse {
  ok: boolean;
  code?: string;
  message?: string;
  sessionId?: string;
  walletSigningSessionId?: string;
  /** Server-enforced expiry (ms since epoch). */
  expiresAtMs?: number;
  expiresAt?: string;
  /** Signer-set binding (sorted unique participant ids) when available. */
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
}

export interface ThresholdEd25519AuthorizeWithSessionRequest {
  relayerKeyId: string;
  purpose: ThresholdEd25519Purpose;
  signing_digest_32: number[];
  signingPayload?: unknown;
  runtimeSnapshot?: ThresholdRuntimeSnapshotExpectation;
}

export interface ThresholdEd25519AuthorizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  mpcSessionId?: string;
  expiresAt?: string;
}

export interface ThresholdEd25519SignInitRequest {
  mpcSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  /**
   * Base64url-encoded message bytes (the exact digest the co-signers will sign).
   * For NEAR tx/delegate flows this is expected to be 32 bytes.
   */
  signingDigestB64u: string;
  clientCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519SignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  signingSessionId?: string;
  /** Commitments keyed by participant id (stringified u16). */
  commitmentsById?: Record<string, { hiding: string; binding: string }>;
  /** Relayer verifying shares keyed by relayer participant id (stringified u16). */
  relayerVerifyingSharesById?: Record<string, string>;
  /** Convenience list of participant ids for this signer set. */
  participantIds?: number[];
}

export interface ThresholdEd25519SignFinalizeRequest {
  signingSessionId: string;
  clientSignatureShareB64u: string;
}

export interface ThresholdEd25519SignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  /** Signature shares keyed by relayer participant id (stringified u16). */
  relayerSignatureSharesById?: Record<string, string>;
}

// ==========================================
// Threshold Ed25519 cosign continuation payloads
// ==========================================

export interface ThresholdEd25519CosignInitRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  /**
   * Base64url-encoded 32-byte relayer cosigner signing share (a secret share; unweighted).
   * The cosigner derives its effective outer-protocol share from this and the selected cosigner set.
   */
  cosignerShareB64u: string;
  clientCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerCommitments?: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignFinalizeRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  /**
   * The selected cosigner id set used for internal Lagrange interpolation.
   * Must include this cosigner's configured id.
   */
  cosignerIds: number[];
  /** NEAR ed25519 public key string (`ed25519:<base58>`). */
  groupPublicKey: string;
  /**
   * The combined outer-protocol relayer commitments (sum across the selected cosigners).
   * This must match what the client used for its signing transcript.
   */
  relayerCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerSignatureShareB64u?: string;
}

// ================================
// Threshold ECDSA (2-party) APIs
// ================================

export type ThresholdEcdsaPurpose = string;
export type EcdsaThresholdKeyId = string;

export type ThresholdEcdsaHssOperation =
  | 'registration_bootstrap'
  | 'email_otp_bootstrap'
  | 'session_bootstrap'
  | 'explicit_key_export';

export interface ThresholdEcdsaHssPrepareRequest {
  userId: string;
  rpId: string;
  operation: ThresholdEcdsaHssOperation;
  ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
  keygenSessionId?: string;
  sessionPolicy?: ThresholdEcdsaBootstrapSessionPolicy;
  runtimeEnvironmentId?: string;
  webauthn_authentication?: WebAuthnAuthenticationCredential;
  /**
   * Internal relay field: optional validated threshold-ed25519 session claims
   * extracted from bearer/cookie transport by the route layer.
   */
  ed25519SessionClaims?: Record<string, unknown>;
  /**
   * Internal relay field: optional validated app-session claims extracted from
   * bearer/cookie transport by the route layer.
   */
  appSessionClaims?: Record<string, unknown>;
  /**
   * Internal relay field: validated Email OTP enrollment metadata extracted by
   * the route layer for Email OTP-authorized threshold ECDSA bootstrap.
   */
  emailOtpEnrollmentClaims?: {
    walletId: string;
    userId: string;
    otpChannel: WalletEmailOtpChannel;
    thresholdEcdsaClientVerifyingShareB64u: string;
  };
  /**
   * Internal relay field: optional validated threshold-ecdsa session claims
   * extracted from bearer/cookie transport by the route layer.
   */
  ecdsaSessionClaims?: Record<string, unknown>;
  sessionKind?: 'jwt' | 'cookie';
}

export interface ThresholdEcdsaHssPrepareResponse {
  ok: boolean;
  code?: string;
  message?: string;
  ceremonyId?: string;
  preparedServerSessionB64u?: string;
  serverAssistInitB64u?: string;
}

export interface ThresholdEcdsaHssRespondRequest {
  ceremonyId: string;
  requestMessageB64u: string;
}

export interface ThresholdEcdsaHssRespondResponse {
  ok: boolean;
  code?: string;
  message?: string;
  responseMessageB64u?: string;
}

export interface ThresholdEcdsaHssFinalizeRequest {
  ceremonyId: string;
  clientFinalizeMessageB64u: string;
}

export interface ThresholdEcdsaHssFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  sessionKind?: 'jwt' | 'cookie';
  sessionJwtUserId?: string;
  sessionJwtRpId?: string;
  ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
  clientVerifyingShareB64u?: string;
  clientAdditiveShare32B64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress?: string;
  participantIds?: number[];
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  chainId?: number;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
  sessionId?: string;
  walletSigningSessionId?: string;
  expiresAtMs?: number;
  expiresAt?: string;
  remainingUses?: number;
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
  canonicalPublicKeyHex?: string;
  privateKeyHex?: string;
  canonicalEthereumAddress?: string;
}

export interface ThresholdEcdsaIntegratedKeyRecord {
  version: 'threshold_ecdsa_hss_key_v1';
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  userId: string;
  rpId: string;
  schemeId: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  signingRootId: string;
  signingRootVersion?: string;
  walletKeyVersion: string;
  derivationVersion: number;
  participantIds: number[];
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  relayerRootShare32B64u: string;
  relayerBackendInputB64u: string;
  createdAtMs: number;
  updatedAtMs: number;
}

export type EcdsaSessionPolicy = {
  version: 'threshold_session_v1';
  userId: string;
  rpId: string;
  relayerKeyId: string;
  sessionId: string;
  walletSigningSessionId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export type ThresholdEcdsaBootstrapSessionPolicy = {
  version: 'threshold_session_v1';
  userId: string;
  rpId: string;
  sessionId: string;
  walletSigningSessionId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export interface ThresholdEcdsaAuthorizeWithSessionRequest {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  purpose: ThresholdEcdsaPurpose;
  signing_digest_32: number[];
  signingPayload?: unknown;
  runtimeSnapshot?: ThresholdRuntimeSnapshotExpectation;
}

export interface ThresholdEcdsaPresignPoolPolicyHint {
  enabled?: boolean;
  targetDepth?: number;
  lowWatermark?: number;
  maxRefillInFlight?: number;
  refillAttemptTimeoutMs?: number;
}

export interface ThresholdEcdsaAuthorizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  mpcSessionId?: string;
  expiresAt?: string;
  presignPoolPolicy?: ThresholdEcdsaPresignPoolPolicyHint;
}

// =====================================
// Threshold ECDSA (presignature pool)
// =====================================

export type ThresholdEcdsaPresignInitRequest = {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  /**
   * Number of presignatures to generate.
   * v1 supports only `1` (single presignature session).
   */
  count?: number;
  /**
   * Optional client-provided request classification for logging/observability.
   * Example: `background_presign_pool_refill`.
   */
  requestTag?: string;
};

export type ThresholdEcdsaPresignInitResponse = {
  ok: boolean;
  code?: string;
  message?: string;
  presignSessionId?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  outgoingMessagesB64u?: string[];
};

export type ThresholdEcdsaPresignStepRequest = {
  presignSessionId: string;
  /**
   * The client-requested stage transition:
   * - `triples`: continue triple generation
   * - `presign`: start/continue presigning (only valid once server is `triples_done`)
   */
  stage: 'triples' | 'presign';
  outgoingMessagesB64u?: string[];
  /**
   * Optional client-provided request classification for logging/observability.
   * Example: `background_presign_pool_refill`.
   */
  requestTag?: string;
};

export type ThresholdEcdsaPresignStepResponse = {
  ok: boolean;
  code?: string;
  message?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  event?: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u?: string[];
  /** Deterministic id derived from `bigR` (only present when `event==='presign_done'`). */
  presignatureId?: string;
  /** Base64url-encoded compressed secp256k1 point (33 bytes) for `R` (only present when `event==='presign_done'`). */
  bigRB64u?: string;
};

export type ThresholdEcdsaSignInitClientRound1V1 = {
  /**
   * Optional presignature id chosen by the client.
   * When omitted, the relayer selects a presignature from its pool.
   */
  presignatureId?: string;
};

export type ThresholdEcdsaSignInitRelayerRound1V1 = {
  presignatureId: string;
  /**
   * Base64url-encoded 32 bytes of public entropy used for presignature rerandomization.
   * Both parties must use exactly this value.
   */
  entropyB64u: string;
  /**
   * Base64url-encoded compressed secp256k1 point (33 bytes) for R = k·G (optional echo).
   * When present, the client should verify it matches its local presignature.
   */
  bigRB64u?: string;
};

export interface ThresholdEcdsaSignInitRequest {
  mpcSessionId: string;
  relayerKeyId: string;
  /** Base64url-encoded digest bytes (typically 32 bytes for secp256k1/ECDSA). */
  signingDigestB64u: string;
  /** Scheme-specific round-1 payload (nonce commitments, preprocessing selection, etc.). */
  clientRound1?: ThresholdEcdsaSignInitClientRound1V1;
}

export interface ThresholdEcdsaSignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  signingSessionId?: string;
  /** Scheme-specific round-1 payload to return to the client. */
  relayerRound1?: ThresholdEcdsaSignInitRelayerRound1V1;
}

export type ThresholdEcdsaSignFinalizeClientRound2V1 = {
  /**
   * Base64url-encoded scalar signature share produced by the client (implementation-defined).
   * For NEAR `threshold-signatures` OT-based ECDSA, this is the participant's `s_i`.
   */
  clientSignatureShareB64u: string;
};

export type ThresholdEcdsaSignFinalizeRelayerRound2V1 = {
  /**
   * Base64url-encoded recoverable ECDSA signature bytes: `r(32) || s(32) || recId(1)`.
   * `s` must be low-s normalized.
   */
  signature65B64u: string;
  /** Base64url-encoded 32-byte `r` (x-coordinate of R). */
  rB64u: string;
  /** Base64url-encoded 32-byte low-s `s`. */
  sB64u: string;
  /** Recovery id in [0..3]. EVM yParity is `recId & 1`. */
  recId: number;
};

export interface ThresholdEcdsaSignFinalizeRequest {
  signingSessionId: string;
  /** Scheme-specific round-2 payload (signature share contribution, etc.). */
  clientRound2?: ThresholdEcdsaSignFinalizeClientRound2V1;
}

export interface ThresholdEcdsaSignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  /** Scheme-specific relayer-side contribution used by the client to finalize the signature. */
  relayerRound2?: ThresholdEcdsaSignFinalizeRelayerRound2V1;
}

// =======================================
// Threshold ECDSA cosign continuation payloads
// =======================================

export interface ThresholdEcdsaCosignInitRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  cosignerShareB64u: string;
  clientRound1?: unknown;
}

export interface ThresholdEcdsaCosignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerRound1?: unknown;
}

export interface ThresholdEcdsaCosignFinalizeRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  cosignerIds: number[];
  groupPublicKey: string;
  relayerRound1?: unknown;
}

export interface ThresholdEcdsaCosignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerRound2?: unknown;
}

export interface RefreshSessionResult {
  ok: boolean;
  jwt?: string;
  code?: string;
  message?: string;
}
