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
  accountIds: string[],
  lastUsedAccount: {
    nearAccountId: AccountId,
    deviceNumber: number,
  } | null
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

//////////////////////////////////
/// TatchiPasskey Configuration
//////////////////////////////////

export interface TatchiConfigsInput {
  nearRpcUrl?: string;
  nearNetwork?: 'testnet' | 'mainnet';
  contractId?: 'w3a-v1.testnet' | string;
  appearance?: AppearanceConfigInput;
  /**
   * NEAR account ID under which the relay server creates new subaccounts.
   *
   * This must match the relay server config `RELAYER_ACCOUNT_ID` when
   * using atomic registration via `POST /registration/bootstrap`.
   *
   * Defaults to `contractId`.
   */
  relayerAccount?: string;
  nearExplorerUrl?: string; // NEAR Explorer URL for transaction links
  /**
   * Default signing mode used by higher-level convenience helpers and UI wrappers when a per-call
   * `signerMode` is not explicitly provided.
   *
   * Defaults to `{ mode: 'local-signer' }`.
   *
   */
  signerMode?: SignerMode;
  /**
   * Defaults for relay-minted warm signing sessions minted by `loginAndCreateSession()`.
   * These can be overridden per-call via `LoginHooksOptions.signingSession`.
   */
  signingSessionDefaults?: {
    ttlMs?: number;
    remainingUses?: number;
  };
  /**
   * Default registration signer provisioning policy.
   * Per-call overrides are available via `RegistrationHooksOptions.signerOptions`.
   */
  registrationSignerDefaults?: RegistrationSignerOptions;
  // Iframe Wallet configuration (when using a separate wallet origin)
  iframeWallet?: {
    walletOrigin?: string; // e.g., https://wallet.example.com
    walletServicePath?: string; // defaults to '/wallet-service'
    // SDK assets base used by the parent app to tell the wallet
    // where to load embedded bundles from.
    sdkBasePath?: string; // defaults to '/sdk'
    // Force WebAuthn rpId to a base domain so credentials work across subdomains
    // Example: rpIdOverride = 'example.localhost' usable from wallet.example.localhost
    rpIdOverride?: string;
  };
  // Relay Server is used to create new NEAR accounts
  relayer?: {
    // accountId: string;
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
    };
  }
  // authenticator options for registrations
  authenticatorOptions?: AuthenticatorOptions;
  // Email recovery contract identifier
  emailDkimVerifierContract?: string;
}

/**
 * Resolved, internal config shape used by SDK classes after merging defaults and validation.
 * All fields that the SDK relies on at runtime are non-optional here.
 */
export interface TatchiConfigs {
  nearRpcUrl: string;
  nearNetwork: 'testnet' | 'mainnet';
  contractId: 'w3a-v1.testnet' | string;
  appearance: AppearanceConfig;
  relayerAccount: string;
  nearExplorerUrl?: string;
  signerMode: SignerMode;
  signingSessionDefaults: {
    ttlMs: number;
    remainingUses: number;
  };
  registrationSignerDefaults: RegistrationSignerOptions;
  iframeWallet?: {
    walletOrigin?: string;
    walletServicePath: string;
    sdkBasePath: string;
    rpIdOverride?: string;
  };
  relayer: {
    url: string;
    delegateActionRoute: string;
    smartAccountDeployRoute: string;
    smartAccountDeploymentMode: 'observe' | 'enforce';
    smartAccountDeploymentMaxAttempts: number;
    emailRecovery: {
      minBalanceYocto: string;
      pollingIntervalMs: number;
      maxPollingDurationMs: number;
      pendingTtlMs: number;
      mailtoAddress: string;
    };
  };
  authenticatorOptions?: AuthenticatorOptions;
  emailDkimVerifierContract: string;
}

// === TRANSACTION TYPES ===
export interface TransactionParams {
  receiverId: string;
  methodName: string;
  args: Record<string, unknown>;
  gas?: string;
  deposit?: string;
}
