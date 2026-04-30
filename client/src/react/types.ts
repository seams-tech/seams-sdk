import type { ReactNode } from 'react';
import type {
  LoginHooksOptions,
  RegistrationHooksOptions,
  ActionHooksOptions,
  SignNEP413HooksOptions,
  SeamsPasskey,
  SeamsConfigsInput,
  SignNEP413MessageParams,
  SignNEP413MessageResult,
} from '../core/SeamsPasskey';
import type { ThemeName, WalletAuthMethod } from '../core/types/seams';
import { TransactionInput } from '../core/types/actions';
import type { ConfirmationConfig, ConfirmationBehavior } from '../core/types/signer-worker';
import type { ClientUserData } from '../core/accountData/near/types';
import type { ActionArgs } from '../core/types/actions';
import type {
  DelegateActionHooksOptions,
  EventCallback,
  SignAndSendTransactionHooksOptions,
} from '../core/types/sdkSentEvents';
import type { DelegateActionInput } from '../core/types/delegate';
import type { WasmSignedDelegate } from '../core/types/signer-worker';
import type {
  ActionResult,
  WalletSession,
  LoginAndCreateSessionResult,
  LoginResult,
  RegistrationResult,
  SigningSessionStatus,
} from '../core/types/seams';
import type { DeviceLinkingQRData, StartDevice2LinkingFlowArgs } from '../core/types/linkDevice';
import type { AccessKeyList } from '../core/rpcClients/near/NearClient';

// === React states types ===

export interface LoginState {
  // Whether a user is currently authenticated
  isLoggedIn: boolean;
  // The public key of the currently authenticated user (if available)
  nearPublicKey: string | null;
  // The NEAR account ID of the currently authenticated user (e.g., "alice.testnet")
  nearAccountId: string | null;
  // Auth method that unlocked the active wallet session.
  authMethod?: WalletAuthMethod | null;
  // Canonical threshold ECDSA account address used for Tempo/EVM signing
  thresholdEcdsaEthereumAddress?: string | null;
  // Canonical threshold ECDSA public key (base64url)
  thresholdEcdsaPublicKeyB64u?: string | null;
}

export interface StoredAccountOption {
  nearAccountId: string;
  signerSlot?: number;
  authMethod?: WalletAuthMethod | null;
}

// UI input state - tracks user input and form state
export interface AccountInputState {
  // The username portion being typed by the user (e.g., "alice")
  inputUsername: string;
  // The username from the last logged-in account
  lastLoggedInUsername: string;
  // The domain from the last logged-in account (e.g., ".testnet")
  lastLoggedInDomain: string;
  // The complete account ID for input operations (e.g., "alice.testnet")
  targetAccountId: string;
  // The domain postfix to display in the UI (e.g., ".testnet")
  displayPostfix: string;
  // Whether the current input was resolved from a locally saved account match
  isUsingExistingAccount: boolean;
  // Whether the target account currently exists on-chain
  accountExists: boolean;
  // All account IDs stored in IndexDB
  indexDBAccounts: string[];
  // Stored accounts with signer auth method metadata, used by account picker UIs.
  indexDBAccountOptions: StoredAccountOption[];
}

// Account input hook types
export interface UseAccountInputReturn extends AccountInputState {
  setInputUsername: (username: string) => void;
  refreshAccountData: () => Promise<void>;
}

export type SDKFlowKind = 'login' | 'register' | 'sync' | null;
export type SDKFlowStatus = 'idle' | 'in-progress' | 'success' | 'error';

export type SDKFlowState = {
  seq: number;
  kind: SDKFlowKind;
  status: SDKFlowStatus;
  eventsText: string;
  accountId?: string;
  error?: string;
};

export type SDKFlowRuntime = SDKFlowState & {
  /**
   * Resolves when the flow `seq` completes successfully; rejects on error/timeout.
   */
  awaitCompletion: (seq: number, timeoutMs: number) => Promise<SDKFlowState>;
  /**
   * Resolves with the next started flow sequence number (or null if it doesn't start in time).
   */
  awaitNextStart: (
    kind: Exclude<SDKFlowKind, null>,
    seqAfter: number,
    timeoutMs: number,
  ) => Promise<number | null>;
  /**
   * Waits for the next started flow (after `seqAfter`) and then for its completion.
   * If no flow starts in `startTimeoutMs`, it returns without error.
   */
  awaitNextCompletion: (
    kind: Exclude<SDKFlowKind, null>,
    seqAfter: number,
    startTimeoutMs: number,
    completionTimeoutMs: number,
  ) => Promise<void>;
};

export interface SeamsContextType {
  // Core SeamsPasskey instance - provides all user-facing functionality
  seams: SeamsPasskey;

  /**
   * SDK progress state for the most recent flow (login/registration).
   * Used by UI components (e.g., PasskeyAuthMenu) to keep waiting screens visible
   * even when integrators do not return a Promise from their handlers.
   */
  sdkFlow: SDKFlowRuntime;

  ////////////////////////////
  // SeamsPasskey functions
  ////////////////////////////

  // Registration and wallet unlock functions
  registerPasskey: (
    nearAccountId: string,
    options?: RegistrationHooksOptions,
  ) => Promise<RegistrationResult>;
  unlock: (
    nearAccountId: string,
    options?: LoginHooksOptions,
  ) => Promise<LoginAndCreateSessionResult>;
  lock: () => void;

  // Execute actions
  executeAction: (args: {
    nearAccountId: string;
    receiverId: string;
    actionArgs: ActionArgs;
    options?: ActionHooksOptions;
  }) => Promise<ActionResult>;

  // NEP-413 message signing
  signNEP413Message: (args: {
    nearAccountId: string;
    params: SignNEP413MessageParams;
    options?: SignNEP413HooksOptions;
  }) => Promise<SignNEP413MessageResult>;

  // Delegate action signing (NEP-461)
  signDelegateAction: (args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    options?: DelegateActionHooksOptions;
  }) => Promise<{
    signedDelegate: WasmSignedDelegate;
    hash: string;
    nearAccountId: string;
    logs?: string[];
  }>;

  // Device linking functions
  startDevice2LinkingFlow: (args?: StartDevice2LinkingFlowArgs) => Promise<{
    qrData: DeviceLinkingQRData;
    qrCodeDataURL: string;
  }>;

  stopDevice2LinkingFlow: () => Promise<void>;

  // Login State
  loginState: LoginState;
  // Wallet iframe connectivity (true when service client handshake completes)
  walletIframeConnected: boolean;

  getWalletSession: (nearAccountId?: string) => Promise<WalletSession>;
  refreshLoginState: (nearAccountId?: string) => Promise<void>;

  // Account input management
  // UI account name input state (form/input tracking)
  accountInputState: AccountInputState;
  setInputUsername: (username: string) => void;
  refreshAccountData: () => Promise<void>;

  // Confirmation configuration functions
  setConfirmBehavior: (behavior: ConfirmationBehavior) => void;
  setConfirmationConfig: (config: ConfirmationConfig) => void;
  getConfirmationConfig: () => ConfirmationConfig;

  // Account management functions
  viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;

  // Theme capabilities (controlled by host app)
  themeCapabilities: {
    canSetHostTheme: boolean;
  };
}

/** Config options for SeamsContextProvider
 * @param children - ReactNode to render inside the provider
 * @param config - SeamsConfigsInput
 * @example
 * config: {
 *   chains: [
 *     {
 *       network: 'near-testnet',
 *       rpcUrl: 'https://rpc.testnet.near.org',
 *       explorerUrl: 'https://testnet.nearblocks.io',
 *     },
 *   ],
 *   // Parent account used for new subaccount creation via the relay server.
 *   // Must match relay-server `RELAYER_ACCOUNT_ID` when using atomic registration.
 *   relayerAccount: 'w3a-relayer.testnet',
 *   relayer: { url: 'https://relay.example.com' },
 * }
 */
export interface SeamsContextProviderProps {
  children: ReactNode;
  // Config overrides; provider resolves defaults and validates required fields.
  // Includes optional `appearance` defaults (`theme`, `palette`, `tokens`).
  config: SeamsConfigsInput;
  // Controlled theme from host app (optional).
  theme?: {
    theme: ThemeName;
    setTheme?: (theme: ThemeName) => void;
  };
  /**
   * When true, the provider will opportunistically pre-warm iframe + workers
   * on idle after mount to reduce first-action latency.
   * Default: false (lazy by default).
   */
  eager?: boolean;
}

// === CONVENIENCE RE-EXPORTS ===
export type {
  // Core manager types
  RegistrationHooksOptions,
  LoginHooksOptions,
  ActionHooksOptions,
  SignNEP413HooksOptions,
} from '../core/types/sdkSentEvents';

export type {
  // Results
  RegistrationResult,
  LoginResult,
} from '../core/types/seams';
