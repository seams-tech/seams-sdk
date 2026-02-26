import type { FinalExecutionOutcome } from '@near-js/types';
import type { AccountId } from './accountIds';
import type { SignedTransaction } from '../rpcClients/near/NearClient';
import type { AuthenticatorOptions } from './authenticatorOptions';
import type { ClientUserData } from '../indexedDB/passkeyClientDB.types';
import type { SignerMode, WasmSignedDelegate } from './signer-worker';
import type { RegistrationSignerOptions } from './registrationSignerOptions';

//////////////////////////////////
/// Result Types
//////////////////////////////////

export interface LoginState {
  isLoggedIn: boolean;
  nearAccountId: AccountId | null;
  publicKey: string | null;
  userData: ClientUserData | null;
  thresholdEcdsaEthereumAddress?: string | null;
  thresholdEcdsaGroupPublicKeyB64u?: string | null;
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
  clientNearPublicKey?: string | null;
  nearAccountId?: AccountId;
  transactionId?: string | null;
  thresholdEcdsaEthereumAddress?: string;
  thresholdEcdsaGroupPublicKeyB64u?: string;
}

export interface LoginResult {
  success: boolean;
  error?: string;
  loggedInNearAccountId?: string;
  clientNearPublicKey?: string | null;
  nearAccountId?: AccountId;
  // Present when session.kind === 'jwt' and verification succeeded
  jwt?: string;
}

export interface SigningSessionStatus {
  sessionId: string;
  status: 'active' | 'exhausted' | 'expired' | 'not_found';
  remainingUses?: number;
  expiresAtMs?: number;
  createdAtMs?: number;
}

export interface LoginAndCreateSessionResult extends LoginResult {
  signingSession?: SigningSessionStatus;
}

export interface ThresholdWarmLoginAndCreateSessionResult extends LoginAndCreateSessionResult {
  success: true;
  signingSession: SigningSessionStatus & { status: 'active' };
}

export interface LoginSession {
  login: LoginState;
  signingSession: SigningSessionStatus | null;
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
  logs?: string[];
}

export interface GetRecentLoginsResult {
  accountIds: string[];
  lastUsedAccount: {
    nearAccountId: AccountId;
    deviceNumber: number;
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

export interface ThresholdEcdsaPresignPoolPolicyInput {
  enabled?: boolean;
  targetDepth?: number;
  lowWatermark?: number;
  maxRefillInFlight?: number;
  refillAttemptTimeoutMs?: number;
}

export interface ThresholdEcdsaPresignPoolPolicy {
  enabled: boolean;
  targetDepth: number;
  lowWatermark: number;
  maxRefillInFlight: number;
  refillAttemptTimeoutMs: number;
}

//////////////////////////////////
/// TatchiPasskey Configuration
//////////////////////////////////

export type TatchiNearChainNetwork = 'near-mainnet' | 'near-testnet';
export type TatchiTempoChainNetwork = 'tempo-mainnet' | 'tempo-testnet';
export type TatchiArcChainNetwork = 'arc-mainnet' | 'arc-testnet';
export type TatchiChainNetwork =
  | TatchiNearChainNetwork
  | TatchiTempoChainNetwork
  | TatchiArcChainNetwork;
export type TatchiChainFamily = 'near' | 'tempo' | 'arc';

export interface TatchiNearChainConfigInput {
  network: TatchiNearChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
}

export interface TatchiTempoChainConfigInput {
  network: TatchiTempoChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
}

export interface TatchiArcChainConfigInput {
  network: TatchiArcChainNetwork;
  rpcUrl?: string;
  explorerUrl?: string;
  chainId?: number;
}

export type TatchiChainConfigInput =
  | TatchiNearChainConfigInput
  | TatchiTempoChainConfigInput
  | TatchiArcChainConfigInput;

export interface TatchiNearChainConfig {
  network: TatchiNearChainNetwork;
  rpcUrl: string;
  explorerUrl: string;
}

export interface TatchiTempoChainConfig {
  network: TatchiTempoChainNetwork;
  rpcUrl: string;
  explorerUrl: string;
}

export interface TatchiArcChainConfig {
  network: TatchiArcChainNetwork;
  rpcUrl: string;
  explorerUrl: string;
  chainId?: number;
}

export type TatchiChainConfig =
  | TatchiNearChainConfig
  | TatchiTempoChainConfig
  | TatchiArcChainConfig;

export type ReadonlyDeep<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly ReadonlyDeep<U>[]
    : T extends object
      ? { readonly [K in keyof T]: ReadonlyDeep<T[K]> }
      : T;

export type TatchiWalletMode = 'direct' | 'iframe';

export interface TatchiSigningSessionDefaultsInput {
  /**
   * Defaults for relay-minted warm signing sessions minted by `loginAndCreateSession()`.
   * These can be overridden per-call via `LoginHooksOptions.signingSession`.
   */
  ttlMs?: number;
  remainingUses?: number;
}

export interface TatchiIframeWalletConfigInput {
  walletOrigin?: string; // e.g., https://wallet.example.com
  walletServicePath?: string; // defaults to '/wallet-service'
  // SDK assets base used by the parent app to tell the wallet
  // where to load embedded bundles from.
  sdkBasePath?: string; // defaults to '/sdk'
  // Force WebAuthn rpId to a base domain so credentials work across subdomains
  // Example: rpIdOverride = 'example.localhost' usable from wallet.example.localhost
  rpIdOverride?: string;
}

export interface TatchiRelayerConfigInput {
  url?: string;
  /**
   * Relative path on the relayer used for delegate action execution.
   * Defaults to '/signed-delegate'.
   */
  delegateActionRoute?: string;
  /**
   * Relative path on the relayer used for smart-account deployment.
   * Defaults to '/smart-account/deploy'.
   */
  smartAccountDeployRoute?: string;
  /**
   * Smart-account deployment gate mode for EVM/Tempo sends.
   * - `observe`: stamp checks and continue signing without blocking undeployed accounts.
   * - `enforce`: require successful deploy-on-first-use before signing proceeds.
   *
   * Defaults to `enforce`.
   */
  smartAccountDeploymentMode?: 'observe' | 'enforce';
  /**
   * Maximum deploy attempts for deploy-on-first-use in enforce mode.
   * Values are clamped to [1, 5].
   *
   * Defaults to `2`.
   */
  smartAccountDeploymentMaxAttempts?: number;
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

export interface TatchiConfigsInput {
  chains?: TatchiChainConfigInput[];
  appearance?: AppearanceConfigInput;
  /**
   * NEAR account ID under which the relay server creates new subaccounts.
   *
   * This must match the relay server config `RELAYER_ACCOUNT_ID` when
   * using atomic registration via `POST /registration/bootstrap`.
   *
   * Defaults to the SDK relayer account default.
   */
  relayerAccount?: string;
  /**
   * Default signing mode used by higher-level convenience helpers and UI wrappers when a per-call
   * `signerMode` is not explicitly provided.
   *
   * Defaults to `{ mode: 'local-signer' }`.
   *
   */
  signerMode?: SignerMode;
  signingSessionDefaults?: TatchiSigningSessionDefaultsInput;
  /**
   * Client-side presign pool policy for threshold ECDSA.
   *
   * Controls best-effort background refill behavior only; signing correctness does not depend on refill success.
   */
  thresholdEcdsaPresignPool?: ThresholdEcdsaPresignPoolPolicyInput;
  /**
   * Default registration signer provisioning policy.
   * Per-call overrides are available via `RegistrationHooksOptions.signerOptions`.
   */
  registrationSignerDefaults?: RegistrationSignerOptions;
  // Iframe Wallet configuration (when using a separate wallet origin)
  iframeWallet?: TatchiIframeWalletConfigInput;
  // Relay Server is used to create new NEAR accounts
  relayer?: TatchiRelayerConfigInput;
  // authenticator options for registrations
  authenticatorOptions?: AuthenticatorOptions;
}

export interface TatchiRelayerRoutesConfig {
  delegateAction: string;
  smartAccountDeploy: string;
}

export interface TatchiSmartAccountDeploymentConfig {
  mode: 'observe' | 'enforce';
  maxAttempts: number;
}

export interface TatchiRelayerEmailRecoveryConfig {
  minBalanceYocto: string;
  pollingIntervalMs: number;
  maxPollingDurationMs: number;
  pendingTtlMs: number;
  mailtoAddress: string;
  // Contract account that verifies DKIM signatures for email recovery.
  emailDkimVerifierContract: string;
}

export interface TatchiRelayerConfig {
  accountId: string;
  url: string;
  routes: TatchiRelayerRoutesConfig;
  smartAccountDeployment: TatchiSmartAccountDeploymentConfig;
  emailRecovery: TatchiRelayerEmailRecoveryConfig;
}

export interface TatchiNetworkConfig {
  chains: TatchiChainConfig[];
  relayer: TatchiRelayerConfig;
}

export interface TatchiSigningSessionDefaults {
  ttlMs: number;
  remainingUses: number;
}

export interface TatchiThresholdEcdsaConfig {
  presignPool: ThresholdEcdsaPresignPoolPolicy;
}

export interface TatchiSigningConfig {
  mode: SignerMode;
  sessionDefaults: TatchiSigningSessionDefaults;
  thresholdEcdsa: TatchiThresholdEcdsaConfig;
  registrationDefaults: RegistrationSignerOptions;
}

export interface TatchiWebauthnConfig {
  authenticatorOptions?: AuthenticatorOptions;
}

export interface TatchiAuthConfig {
  webauthn: TatchiWebauthnConfig;
}

export interface TatchiIframeWalletConfig {
  origin?: string;
  servicePath: string;
  sdkBasePath: string;
  rpIdOverride?: string;
}

export type TatchiWalletConfig =
  | {
      mode: 'direct';
      iframe: TatchiIframeWalletConfig;
    }
  | {
      mode: 'iframe';
      iframe: TatchiIframeWalletConfig & { origin: string };
    };

export interface TatchiUiConfig {
  appearance: AppearanceConfig;
}

/**
 * Resolved, internal config shape used by SDK classes after merging defaults and validation.
 * All fields that the SDK relies on at runtime are non-optional here.
 */
export interface TatchiConfigsResolved {
  network: TatchiNetworkConfig;
  signing: TatchiSigningConfig;
  auth: TatchiAuthConfig;
  wallet: TatchiWalletConfig;
  ui: TatchiUiConfig;
}

export type TatchiConfigsReadonly = ReadonlyDeep<TatchiConfigsResolved>;

// === TRANSACTION TYPES ===
export interface TransactionParams {
  receiverId: string;
  methodName: string;
  args: Record<string, unknown>;
  gas?: string;
  deposit?: string;
}
