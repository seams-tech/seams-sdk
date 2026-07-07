import type { ReactNode } from 'react';
import type {
  LoginHooksOptions,
  RegistrationHooksOptions,
  ActionHooksOptions,
  SignNEP413HooksOptions,
  SeamsWeb,
  SeamsConfigsInput,
  SignNEP413MessageParams,
  SignNEP413MessageResult,
  RegistrationCapability,
  DevicesCapability,
  PasskeyRegistrationOptions,
} from '../SeamsWeb';
import type { ThemeName, WalletAuthMethod } from '../core/types/seams';
import type {
  CurrentWalletAuthMethod,
  WalletAuthMethodBinding,
} from '@shared/utils/walletCapabilityBindings';
import { TransactionInput } from '../core/types/actions';
import type { ConfirmationConfig, ConfirmationBehavior } from '../core/types/signer-worker';
import type { ClientUserData } from '../core/accountData/near/nearAccountData.types';
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
import type {
  NearAccountRef,
  WalletSessionRef,
} from '../core/signingEngine/interfaces/ecdsaChainTarget';

export type { PasskeyRegistrationOptions };

// === React states types ===

export type LoginState =
  | {
      isLoggedIn: false;
      walletId: null;
      nearPublicKey: null;
      nearAccountId: null;
      authMethods: readonly [];
      currentAuthMethod: { kind: 'none' };
      thresholdEcdsaEthereumAddress?: null;
      thresholdEcdsaPublicKeyB64u?: null;
    }
  | {
      isLoggedIn: true;
      walletId: string;
      nearPublicKey: string | null;
      nearAccountId: string | null;
      authMethods: readonly WalletAuthMethodBinding[];
      currentAuthMethod: CurrentWalletAuthMethod;
      thresholdEcdsaEthereumAddress?: string | null;
      thresholdEcdsaPublicKeyB64u?: string | null;
    };

export interface StoredAccountOption {
  walletId: string;
  displayName: string;
  nearAccountId?: string | null;
  signerSlot?: number;
  authMethod?: WalletAuthMethod | null;
}

// UI input state - tracks user input and form state
export interface AccountInputState {
  // The wallet/display name being typed by the user.
  inputUsername: string;
  // The display name from the last logged-in wallet.
  lastLoggedInUsername: string;
  // The domain from the last logged-in sponsored named NEAR account, when applicable.
  lastLoggedInDomain: string;
  // Sponsored named NEAR account target used only by named-account registration.
  targetAccountId: string;
  // The wallet identity used for login/session operations.
  targetWalletId: string;
  // The sponsored named NEAR account postfix to display, when applicable.
  displayPostfix: string;
  // Whether the current input was resolved from a locally saved wallet match.
  isUsingExistingAccount: boolean;
  // Whether the sponsored named NEAR account target currently exists on-chain.
  accountExists: boolean;
  // Whether the target wallet has a local passkey credential for passkey login
  passkeyCredentialExists: boolean;
  // NEAR account IDs stored in IndexedDB, used for sponsored named-account checks.
  indexDBAccounts: string[];
  // Stored wallets with signer auth method metadata, used by account picker UIs.
  indexDBAccountOptions: StoredAccountOption[];
}

// Account input hook types
export interface UseAccountInputReturn extends AccountInputState {
  setInputUsername: (username: string) => void;
  refreshAccountData: () => Promise<void>;
}

export type SDKFlowKind = 'login' | 'register' | 'sync' | null;
export type ActiveSDKFlowKind = Exclude<SDKFlowKind, null>;

type SDKFlowStateBase = {
  seq: number;
  eventsText: string;
};

export type SDKFlowState =
  | (SDKFlowStateBase & {
      status: 'idle';
      kind: null;
      accountId?: never;
      error?: never;
    })
  | (SDKFlowStateBase & {
      status: 'in-progress';
      kind: ActiveSDKFlowKind;
      accountId?: string;
      error?: never;
    })
  | (SDKFlowStateBase & {
      status: 'success';
      kind: ActiveSDKFlowKind;
      accountId?: string;
      error?: never;
    })
  | (SDKFlowStateBase & {
      status: 'error';
      kind: ActiveSDKFlowKind;
      error: string;
      accountId?: string;
    });

export type SDKFlowRuntime = SDKFlowState & {
  /**
   * Resolves when the flow `seq` completes successfully; rejects on error/timeout.
   */
  awaitCompletion: (seq: number, timeoutMs: number) => Promise<SDKFlowState>;
  /**
   * Resolves with the next started flow sequence number (or null if it doesn't start in time).
   */
  awaitNextStart: (
    kind: ActiveSDKFlowKind,
    seqAfter: number,
    timeoutMs: number,
  ) => Promise<number | null>;
  /**
   * Waits for the next started flow (after `seqAfter`) and then for its completion.
   * If no flow starts in `startTimeoutMs`, it returns without error.
   */
  awaitNextCompletion: (
    kind: ActiveSDKFlowKind,
    seqAfter: number,
    startTimeoutMs: number,
    completionTimeoutMs: number,
  ) => Promise<void>;
};

export interface SeamsContextType {
  // Core SeamsWeb instance - provides all user-facing functionality
  seams: SeamsWeb;

  /**
   * SDK progress state for the most recent flow (login/registration).
   * Used by UI components (e.g., PasskeyAuthMenu) to keep waiting screens visible
   * even when integrators do not return a Promise from their handlers.
   */
  sdkFlow: SDKFlowRuntime;

  ////////////////////////////
  // SeamsWeb functions
  ////////////////////////////

  // Registration and wallet unlock functions
  addWalletSigner: RegistrationCapability['addWalletSigner'];
  registerWallet: RegistrationCapability['registerWallet'];
  registerPasskey: RegistrationCapability['registerPasskey'];
  unlock: (
    walletId: string,
    options?: LoginHooksOptions,
  ) => Promise<LoginAndCreateSessionResult>;
  lock: () => void;

  // Execute actions
  executeAction: (args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    receiverId: string;
    actionArgs: ActionArgs;
    options?: ActionHooksOptions;
  }) => Promise<ActionResult>;

  // NEP-413 message signing
  signNEP413Message: (args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    params: SignNEP413MessageParams;
    options?: SignNEP413HooksOptions;
  }) => Promise<SignNEP413MessageResult>;

  // Delegate action signing (NEP-461)
  signDelegateAction: (args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
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

  getWalletSession: (walletId?: string) => Promise<WalletSession>;
  refreshLoginState: (walletId?: string) => Promise<void>;

  // Account input management
  // UI account name input state (form/input tracking)
  accountInputState: AccountInputState;
  setInputUsername: (username: string) => void;
  refreshAccountData: () => Promise<void>;

  // Confirmation configuration functions
  setConfirmBehavior: (behavior: ConfirmationBehavior) => void;
  setConfirmationConfig: (config: Partial<ConfirmationConfig>) => void;
  getConfirmationConfig: () => ConfirmationConfig;

  // Account management functions
  viewAccessKeyList: DevicesCapability['viewAccessKeyList'];

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
 *   // Parent account used for new subaccount creation via the Router API server.
 *   // Must match server `RELAYER_ACCOUNT_ID` when using atomic registration.
 *   relayerAccount: 'w3a-relayer.testnet',
 *   relayer: { url: 'https://router-api.example.com' },
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
