import type { FinalExecutionOutcome } from '@near-js/types';
import type { AccountId } from './accountIds';
import type { SignedTransaction } from '../rpcClients/near/NearClient';
import type {
  NonceCoordinatorDiagnostics,
  NonceLeaseRef,
} from '../signingEngine/nonce/NonceCoordinator';
import type { AuthenticatorOptions } from './authenticatorOptions';
import type { WalletHostVariant } from '../browser/walletIframe/hostVariant';
import type { ClientUserData } from '../accountData/near/types';
import type { WasmSignedDelegate } from './signer-worker';
import type { EcdsaSignerProvisioningDefaults } from './ecdsaSignerProvisioningDefaults';
import type {
  AuthMethod,
  SensitiveOperationPolicy,
  SigningSessionPolicy,
  SigningSessionRetention,
  WalletAuthMethod,
} from '@shared/utils';

export type {
  AuthMethod,
  SensitiveOperationPolicy,
  SigningSessionPolicy,
  SigningSessionRetention,
  WalletAuthMethod,
} from '@shared/utils';

export type SigningSessionPersistenceMode = 'none' | 'sealed_refresh_v1';
export type EmailOtpAuthPolicy = SigningSessionPolicy;

export type RouterAbNormalSigningConfigInput =
  | {
      mode?: 'disabled';
      signingWorkerId?: never;
    }
  | {
      mode: 'enabled';
      signingWorkerId: string;
    };

export type RouterAbNormalSigningConfig =
  | {
      mode: 'disabled';
      signingWorkerId?: never;
    }
  | {
      mode: 'enabled';
      signingWorkerId: string;
    };

export interface RouterAbConfigInput {
  normalSigning?: RouterAbNormalSigningConfigInput;
}

export interface SeamsRouterAbConfig {
  normalSigning: RouterAbNormalSigningConfig;
}

export type WalletAuthIntent =
  | 'wallet_unlock'
  | 'transaction_sign'
  | 'ed25519_export'
  | 'ecdsa_export'
  | 'session_mint';

export type WalletAuthCurve = 'ed25519' | 'ecdsa';

export interface SigningSessionSealConfigInput {
  keyVersion?: string;
  shamirPrimeB64u?: string;
}

export interface SigningSessionSealConfig {
  keyVersion?: string;
  shamirPrimeB64u?: string;
}

/**
 * Public SDK configuration overrides accepted by `new SeamsWeb(config)`.
 *
 * The SDK normalizes this input shape into the grouped resolved config
 * (`SeamsConfigsReadonly`) used at runtime.
 *
 * Arg shape:
 * ```ts
 * {
 *   chains?: Array<{
 *     network:
 *       | 'near-mainnet'
 *       | 'near-testnet'
 *       | 'tempo-mainnet'
 *       | 'tempo-testnet'
 *       | 'arc-mainnet'
 *       | 'arc-testnet'
 *       | 'ethereum-mainnet'
 *       | 'ethereum-sepolia';
 *     rpcUrl?: string;
 *     explorerUrl?: string;
 *     chainId: number; // required for tempo-* and evm networks (arc-*, ethereum-*)
 *   }>;
 *   appearance?: {
 *     theme?: 'light' | 'dark';
 *     palette?: 'default';
 *     tokens?: {
 *       light?: { colors?: Record<string, string> };
 *       dark?: { colors?: Record<string, string> };
 *     };
 *   };
 *   relayerAccount?: string;
 *   signingSessionDefaults?: {
 *     ttlMs?: number;
 *     remainingUses?: number;
 *   };
 *   signingSessionPersistenceMode?: 'none' | 'sealed_refresh_v1';
 *   emailOtpAuthPolicy?: 'session' | 'per_operation';
 *   signingSessionSeal?: {
 *     keyVersion?: string;
 *     shamirPrimeB64u?: string;
 *   };
 *   routerAb?: {
 *     normalSigning?: {
 *       mode: 'disabled' | 'enabled';
 *       signingWorkerId?: string; // required when mode === 'enabled'
 *     };
 *   };
 *   routerAbEcdsaHssPresignaturePool?: {
 *     enabled?: boolean;
 *     targetDepth?: number;
 *     lowWatermark?: number;
 *     maxRefillInFlight?: number;
 *     refillAttemptTimeoutMs?: number;
 *   };
 *   provisioningDefaults?: {
 *     tempo: {
 *       enabled: boolean;
 *       signingSession: {
 *         kind: 'jwt' | 'cookie';
 *         ttlMs: number;
 *         remainingUses: number;
 *       }; *     };
 *     evm: {
 *       enabled: boolean;
 *       signingSession: {
 *         kind: 'jwt' | 'cookie';
 *         ttlMs: number;
 *         remainingUses: number;
 *       }; *     };
 *   };
 *   iframeWallet?: {
 *     walletOrigin?: string;
 *     walletServicePath?: string;
 *     sdkBasePath?: string;
 *     rpIdOverride?: string;
 *   };
 *   relayer?: {
 *     url?: string;
 *     delegateActionRoute?: string;
 *     emailRecovery?: {
 *       minBalanceYocto?: string;
 *       pollingIntervalMs?: number;
 *       maxPollingDurationMs?: number;
 *       pendingTtlMs?: number;
 *       mailtoAddress?: string;
 *       emailDkimVerifierContract?: string;
 *     };
 *   };
 *   registration?: {
 *     mode?: 'backend_proxy';
 *     registrationBootstrapUrl?: string;
 *   } | {
 *     mode: 'managed';
 *     environmentId: string;
 *     publishableKey: string;
 *     paymentMode?: 'disabled' | 'quota_then_x402' | 'always_x402';
 *   };
 *   authenticatorOptions?: AuthenticatorOptions;
 * }
 * ```
 *
 * Notes:
 * - `relayer.url` is required after defaults are merged; missing values fail fast.
 * - Managed registration uses `${relayer.url}/v1/registration/bootstrap-grants`
 *   to obtain a one-time bootstrap token before creating a wallet-registration intent.
 * - `iframeWallet.walletOrigin` controls iframe-wallet mode:
 *   - provided non-empty: iframe mode
 *   - provided empty string: force direct mode
 *   - omitted: keep default mode
 * - `relayer.emailRecovery.emailDkimVerifierContract` configures the DKIM verifier
 *   contract account used by email recovery flows.
 */
export interface SeamsConfigsInput {
  chains?: SeamsChainConfigInput[];
  appearance?: AppearanceConfigInput;
  /**
   * NEAR account ID under which the Router API server creates new subaccounts.
   *
   * This must match the server config `RELAYER_ACCOUNT_ID` when
   * using the wallet-registration ceremony.
   *
   * Defaults to the SDK relayer account default.
   */
  relayerAccount?: string;
  /**
   * Default warm signing-session budgets for threshold signing flows.
   */
  signingSessionDefaults?: SeamsSigningSessionDefaultsInput;
  /**
   * Warm signing session persistence mode.
   *
   * - `none`: no refresh-time persistence (default).
   * - `sealed_refresh_v1`: sealed refresh persistence via worker + server signing-session seal module.
   */
  signingSessionPersistenceMode?: SigningSessionPersistenceMode;
  /**
   * Email OTP signing-session policy.
   *
   * - `session`: recover once after OTP and keep warm signing material in memory until expiry/logout.
   * - `per_operation`: recover on demand, use once, and discard immediately after the operation.
   */
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  /**
   * Optional seal transport hints for `sealed_refresh_v1`.
   *
   * - `keyVersion`: preferred server key version for apply/remove routes.
   * - `shamirPrimeB64u`: shared Shamir prime (base64url-encoded positive bigint).
   *
   * Notes:
   * - Ignored when `signingSessionPersistenceMode !== 'sealed_refresh_v1'`.
   * - `shamirPrimeB64u` is required when `signingSessionPersistenceMode === 'sealed_refresh_v1'`.
   */
  signingSessionSeal?: SigningSessionSealConfigInput;
  /**
   * Router A/B signing-session policy.
   *
   * When `normalSigning.mode === 'enabled'`, passkey registration/unlock
   * sessions bind Ed25519 normal signing to the configured SigningWorker id.
   */
  routerAb?: RouterAbConfigInput;
  /**
   * Client-side presign pool policy for threshold ECDSA.
   *
   * Controls best-effort background refill behavior only; signing correctness does not depend on refill success.
   */
  routerAbEcdsaHssPresignaturePool?: RouterAbEcdsaHssPresignaturePoolPolicyInput;
  /**
   * Default threshold-ECDSA provisioning policy used at registration time for
   * `tempo` and `evm` chains.
   *
   * Shape:
   * - `tempo`: `EcdsaSignerProvisioningPolicy`
   * - `evm`: `EcdsaSignerProvisioningPolicy`
   *
   * `EcdsaSignerProvisioningPolicy` contains:
   * - `enabled`: enable/disable provisioning on that chain.
   * - `signingSession.kind`: `'jwt' | 'cookie'` for the minted signer session.
   * - `signingSession.ttlMs`: session expiration window in milliseconds.
   * - `signingSession.remainingUses`: max allowed signer operations for the session.
   *
   * Used when a registration call does not provide per-call overrides via
   * `RegistrationHooksOptions.signerOptions`.
   */
  provisioningDefaults?: EcdsaSignerProvisioningDefaults;
  // Iframe Wallet configuration (when using a separate wallet origin)
  iframeWallet?: SeamsIframeWalletConfigInput;
  // Relay Server is used to create new NEAR accounts
  relayer?: SeamsRelayerConfigInput;
  // Registration transport for browser-safe bootstrap requests
  registration?: SeamsRegistrationConfigInput;
  // authenticator options for registrations
  authenticatorOptions?: AuthenticatorOptions;
}

/**
 * Canonical resolved configuration used internally by SDK runtime domains.
 *
 * Produced by `buildConfigsFromEnv()` after merging defaults + input overrides.
 * This is deeply readonly so runtime code treats config as immutable.
 *
 * Resolved shape:
 * ```ts
 * {
 *   network: {
 *     chains: SeamsChainConfig[];
 *     relayer: {
 *       accountId: string;
 *       url: string;
 *       routes: {
 *         delegateAction: string; *       };
 *       emailRecovery: {
 *         minBalanceYocto: string;
 *         pollingIntervalMs: number;
 *         maxPollingDurationMs: number;
 *         pendingTtlMs: number;
 *         mailtoAddress: string;
 *         emailDkimVerifierContract: string;
 *       };
 *     };
 *     registration:
 *       | {
 *           mode: 'backend_proxy';
 *           bootstrapUrl: string;
 *         }
 *       | {
 *           mode: 'managed';
 *           environmentId: string;
 *           publishableKey: string;
 *           paymentMode: 'disabled' | 'quota_then_x402' | 'always_x402';
 *         };
 *   };
 *   signing: {
 *     sessionDefaults: { ttlMs: number; remainingUses: number };
 *     sessionPersistenceMode: SigningSessionPersistenceMode;
 *     sessionSeal: SigningSessionSealConfig;
 *     routerAb: {
 *       normalSigning:
 *         | { mode: 'disabled' }
 *         | { mode: 'enabled'; signingWorkerId: string };
 *     };
 *     routerAbEcdsaHss: {
 *       presignaturePool: RouterAbEcdsaHssPresignaturePoolPolicy;
 *     };
 *     thresholdEcdsa: {
 *       provisioningDefaults: EcdsaSignerProvisioningDefaults;
 *     };
 *   };
 *   webauthn: {
 *     authenticatorOptions: AuthenticatorOptions;
 *   };
 *   wallet:
 *     | { mode: 'direct'; iframe: { origin?: string; servicePath: string; sdkBasePath: string; rpIdOverride?: string } }
 *     | { mode: 'iframe'; iframe: { origin: string; servicePath: string; sdkBasePath: string; rpIdOverride?: string } };
 *   ui: {
 *     appearance: AppearanceConfig;
 *   };
 * }
 * ```
 */
export type SeamsConfigsReadonly = ReadonlyDeep<SeamsConfigsResolved>;

//////////////////////////////////
/// Result Types
//////////////////////////////////

export interface LoginState {
  isLoggedIn: boolean;
  nearAccountId: AccountId | null;
  publicKey: string | null;
  userData: ClientUserData | null;
  authMethod?: WalletAuthMethod | null;
  thresholdEcdsaEthereumAddress?: string | null;
  thresholdEcdsaPublicKeyB64u?: string | null;
}

export type ThemeName = 'light' | 'dark';
export type ThemePaletteName = 'default';

export interface ThemeTokenOverridesModeInput {
  colors?: Record<string, string>;
}

export interface ThemeTokenOverridesInput {
  light?: ThemeTokenOverridesModeInput;
  dark?: ThemeTokenOverridesModeInput;
}

export interface AppearanceConfigInput {
  theme?: ThemeName;
  palette?: ThemePaletteName;
  tokens?: ThemeTokenOverridesInput;
}

export interface AppearanceConfig {
  theme: ThemeName;
  palette: ThemePaletteName;
  tokens: {
    light: {
      colors: Record<string, string>;
    };
    dark: {
      colors: Record<string, string>;
    };
  };
}

export interface RegistrationResult {
  success: boolean;
  error?: string;
  errorCode?: RegistrationErrorCode;
  operationalPublicKey?: string | null;
  nearAccountId?: AccountId;
  transactionId?: string | null;
  thresholdEcdsaEthereumAddress?: string;
  thresholdEcdsaPublicKeyB64u?: string;
}

export type RelaySecretKeyAuthErrorCode =
  | 'secret_key_missing'
  | 'secret_key_invalid'
  | 'secret_key_revoked'
  | 'secret_key_forbidden_scope'
  | 'secret_key_ip_blocked'
  | 'secret_key_environment_mismatch';

export type RelayBootstrapGrantErrorCode =
  | 'publishable_key_missing'
  | 'publishable_key_invalid'
  | 'publishable_key_revoked'
  | 'publishable_key_origin_blocked'
  | 'publishable_key_environment_mismatch'
  | 'publishable_key_rate_limited'
  | 'publishable_key_quota_exhausted'
  | 'invalid_environment'
  | 'environment_archived'
  | 'invalid_body'
  | 'payment_required'
  | 'payment_invalid';

export type RelayBootstrapTokenErrorCode =
  | 'bootstrap_token_missing'
  | 'bootstrap_token_invalid'
  | 'bootstrap_token_expired'
  | 'bootstrap_token_already_used'
  | 'bootstrap_token_request_mismatch'
  | 'bootstrap_token_origin_mismatch';

export type RegistrationErrorCode =
  | RelaySecretKeyAuthErrorCode
  | RelayBootstrapGrantErrorCode
  | RelayBootstrapTokenErrorCode
  | string;

export interface LoginResult {
  success: boolean;
  error?: string;
  loggedInNearAccountId?: string;
  operationalPublicKey?: string | null;
  nearAccountId?: AccountId;
  // Present when session.kind === 'jwt' and verification succeeded
  jwt?: string;
}

export interface SigningSessionStatus {
  sessionId: string;
  status: 'active' | 'exhausted' | 'expired' | 'not_found' | 'unavailable' | 'budget_unknown';
  statusCode?: string;
  authMethod?: WalletAuthMethod | null;
  retention?: SigningSessionRetention | null;
  availableUses?: number;
  inFlightReservedUses?: number;
  committedRemainingUses?: number;
  remainingUses?: number;
  expiresAtMs?: number;
  createdAtMs?: number;
  projectionVersion?: string;
}

export interface LoginAndCreateSessionResult extends LoginResult {
  signingSession?: SigningSessionStatus;
}

export interface ThresholdWarmLoginAndCreateSessionResult extends LoginAndCreateSessionResult {
  success: true;
  signingSession: SigningSessionStatus & { status: 'active' };
}

export interface WalletSession {
  login: LoginState;
  signingSession: SigningSessionStatus | null;
  authMethod?: WalletAuthMethod | null;
  retention?: SigningSessionRetention | null;
  nonceDiagnostics?: NonceCoordinatorDiagnostics | null;
}

export interface ActionResult {
  success: boolean;
  error?: string;
  // Optional structured error details when available (e.g., NEAR RPC error payload)
  errorDetails?: unknown;
  transactionId?: string;
  result?: FinalExecutionOutcome;
}

export interface SignTransactionResult {
  signedTransaction: SignedTransaction;
  nearAccountId: string;
  nonceLease?: NonceLeaseRef;
  logs?: string[];
}

export interface RecentUnlockAccount {
  nearAccountId: AccountId;
  signerSlot: number;
  authMethod?: WalletAuthMethod | null;
}

export interface GetRecentUnlocksResult {
  accountIds: string[];
  accounts?: RecentUnlockAccount[];
  lastUsedAccount: {
    nearAccountId: AccountId;
    signerSlot: number;
    authMethod?: WalletAuthMethod | null;
  } | null;
}

export interface SignDelegateActionResult {
  hash: string;
  signedDelegate: WasmSignedDelegate;
  nearAccountId: string;
  logs?: string[];
}

export interface DelegateRelayResult {
  ok: boolean;
  relayerTxHash?: string;
  status?: string;
  outcome?: unknown;
  error?: string;
}

export interface SignAndSendDelegateActionResult {
  signResult: SignDelegateActionResult;
  relayResult: DelegateRelayResult;
}

export interface RouterAbEcdsaHssPresignaturePoolPolicyInput {
  enabled?: boolean;
  targetDepth?: number;
  lowWatermark?: number;
  maxRefillInFlight?: number;
  refillAttemptTimeoutMs?: number;
}

export interface RouterAbEcdsaHssPresignaturePoolPolicy {
  enabled: boolean;
  targetDepth: number;
  lowWatermark: number;
  maxRefillInFlight: number;
  refillAttemptTimeoutMs: number;
}

//////////////////////////////////
/// SeamsWeb Configuration
//////////////////////////////////

export type SeamsNearChainNetwork = 'near-mainnet' | 'near-testnet';
export type SeamsTempoChainNetwork = 'tempo-mainnet' | 'tempo-testnet';
export type SeamsEvmChainNetwork =
  | 'arc-mainnet'
  | 'arc-testnet'
  | 'ethereum-mainnet'
  | 'ethereum-sepolia';
export type SeamsChainNetwork =
  | SeamsNearChainNetwork
  | SeamsTempoChainNetwork
  | SeamsEvmChainNetwork;
export type SeamsChainFamily = 'near' | 'tempo' | 'evm';

export interface SeamsNearChainConfigInput {
  network: SeamsNearChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
}

export interface SeamsTempoChainConfigInput {
  network: SeamsTempoChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
  chainId: number;
}

export interface SeamsEvmChainConfigInput {
  network: SeamsEvmChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
  chainId: number;
}

export type SeamsChainConfigInput =
  | SeamsNearChainConfigInput
  | SeamsTempoChainConfigInput
  | SeamsEvmChainConfigInput;

export interface SeamsNearChainConfig {
  network: SeamsNearChainNetwork;
  rpcUrl: string;
  explorerUrl: string;
}

export interface SeamsTempoChainConfig {
  network: SeamsTempoChainNetwork;
  rpcUrl: string;
  explorerUrl: string;
  chainId: number;
}

export interface SeamsEvmChainConfig {
  network: SeamsEvmChainNetwork;
  rpcUrl: string;
  explorerUrl: string;
  chainId: number;
}

export type SeamsChainConfig = SeamsNearChainConfig | SeamsTempoChainConfig | SeamsEvmChainConfig;

export type ReadonlyDeep<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly ReadonlyDeep<U>[]
    : T extends object
      ? { readonly [K in keyof T]: ReadonlyDeep<T[K]> }
      : T;

export type SeamsWalletMode = 'direct' | 'iframe';

export type SeamsRegistrationPaymentMode = 'disabled' | 'quota_then_x402' | 'always_x402';

export interface SeamsSigningSessionDefaultsInput {
  /**
   * Defaults for relay-minted warm signing sessions minted by `unlock()`.
   * These can be overridden per-call via `LoginHooksOptions.signingSession`.
   */
  ttlMs?: number;
  remainingUses?: number;
}

export interface SeamsIframeWalletConfigInput {
  walletOrigin?: string; // e.g., https://wallet.example.com
  walletServicePath?: string; // defaults to '/wallet-service'
  // SDK assets base used by the parent app to tell the wallet
  // where to load embedded bundles from.
  sdkBasePath?: string; // defaults to '/sdk'
  walletHostVariant?: WalletHostVariant; // defaults to 'runtime'
  // Force WebAuthn rpId to a base domain so credentials work across subdomains
  // Example: rpIdOverride = 'example.localhost' usable from wallet.example.localhost
  rpIdOverride?: string;
}

export type SeamsRegistrationConfigInput =
  | {
      mode?: 'backend_proxy';
      registrationBootstrapUrl?: string;
    }
  | {
      mode: 'managed';
      environmentId: string;
      publishableKey: string;
      paymentMode?: SeamsRegistrationPaymentMode;
    };

export interface SeamsRelayerConfigInput {
  url?: string;
  /**
   * Relative path on the relayer used for delegate action execution.
   * Defaults to '/signed-delegate'.
   */
  delegateActionRoute?: string;
  emailRecovery?: {
    minBalanceYocto?: string;
    pollingIntervalMs?: number;
    maxPollingDurationMs?: number;
    pendingTtlMs?: number;
    mailtoAddress?: string;
    // Contract account that verifies DKIM signatures for email recovery.
    emailDkimVerifierContract?: string;
  };
}

export interface SeamsRelayerRoutesConfig {
  delegateAction: string;
}

export interface SeamsRelayerEmailRecoveryConfig {
  minBalanceYocto: string;
  pollingIntervalMs: number;
  maxPollingDurationMs: number;
  pendingTtlMs: number;
  mailtoAddress: string;
  // Contract account that verifies DKIM signatures for email recovery.
  emailDkimVerifierContract: string;
}

export interface SeamsRelayerConfig {
  accountId: string;
  url: string;
  routes: SeamsRelayerRoutesConfig;
  emailRecovery: SeamsRelayerEmailRecoveryConfig;
}

export type SeamsRegistrationConfig =
  | {
      mode: 'backend_proxy';
      bootstrapUrl: string;
    }
  | {
      mode: 'managed';
      environmentId: string;
      publishableKey: string;
      paymentMode: SeamsRegistrationPaymentMode;
    };

export interface SeamsNetworkConfig {
  chains: SeamsChainConfig[];
  relayer: SeamsRelayerConfig;
}

export interface SeamsSigningSessionDefaults {
  ttlMs: number;
  remainingUses: number;
}

export interface SeamsEmailOtpConfig {
  authPolicy: EmailOtpAuthPolicy;
}

export interface SeamsRouterAbEcdsaHssConfig {
  presignaturePool: RouterAbEcdsaHssPresignaturePoolPolicy;
}

export interface SeamsThresholdEcdsaConfig {
  provisioningDefaults: EcdsaSignerProvisioningDefaults;
}

export interface SeamsSigningConfig {
  sessionDefaults: SeamsSigningSessionDefaults;
  emailOtp: SeamsEmailOtpConfig;
  sessionPersistenceMode: SigningSessionPersistenceMode;
  sessionSeal: SigningSessionSealConfig;
  routerAb: SeamsRouterAbConfig;
  routerAbEcdsaHss: SeamsRouterAbEcdsaHssConfig;
  thresholdEcdsa: SeamsThresholdEcdsaConfig;
}

export interface SeamsWebauthnConfig {
  authenticatorOptions: AuthenticatorOptions;
}

export interface SeamsIframeWalletConfig {
  origin?: string;
  servicePath: string;
  sdkBasePath: string;
  walletHostVariant: WalletHostVariant;
  rpIdOverride?: string;
}

export type SeamsWalletConfig =
  | {
      mode: 'direct';
      iframe: SeamsIframeWalletConfig;
    }
  | {
      mode: 'iframe';
      iframe: SeamsIframeWalletConfig & { origin: string };
    };

export interface SeamsUiConfig {
  appearance: AppearanceConfig;
}

/**
 * Resolved, internal config shape used by SDK classes after merging defaults and validation.
 * All fields that the SDK relies on at runtime are non-optional here.
 */
export interface SeamsConfigsResolved {
  network: SeamsNetworkConfig;
  registration: SeamsRegistrationConfig;
  signing: SeamsSigningConfig;
  webauthn: SeamsWebauthnConfig;
  wallet: SeamsWalletConfig;
  ui: SeamsUiConfig;
}

// === TRANSACTION TYPES ===
export interface TransactionParams {
  receiverId: string;
  methodName: string;
  args: Record<string, unknown>;
  gas?: string;
  deposit?: string;
}
