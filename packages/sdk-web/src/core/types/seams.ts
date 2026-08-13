import type { FinalExecutionOutcome } from '@near-js/types';
import type { AccountId } from './accountIds';
import type { SignedTransaction } from '../rpcClients/near/NearClient';
import type {
  NonceCoordinatorDiagnostics,
  NonceLeaseRef,
} from '../signingEngine/nonce/NonceCoordinator';
import type { AuthenticatorOptions } from './authenticatorOptions';
import type { WalletHostVariant } from '../browser/walletIframe/hostVariant';
import type { ClientUserData } from '../accountData/near/nearAccountData.types';
import type { WasmSignedDelegate } from './signer-worker';
import type { EcdsaSignerProvisioningDefaults } from './ecdsaSignerProvisioningDefaults';
import type { SigningSessionSealProtocol } from '@shared/utils/signingSessionSeal';
import type {
  SensitiveOperationPolicy,
  SignerAuthMethod,
  SigningSessionPolicy,
  SigningSessionRetention,
  WalletAuthMethod,
} from '@shared/utils';
import type {
  NearEd25519SigningKeyId,
  RegistrationNearAccountProvisioning,
  ResolvedRegistrationNearAccount,
  WalletId,
} from '@shared/utils/registrationIntent';
import type { WalletAuthMethodBinding } from '@shared/utils/walletCapabilityBindings';
import type {
  LinkedDeviceWalletSessionAuthorizationId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { ThresholdEcdsaChainTarget } from '../signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaWalletUnlockSubject,
  NearEd25519WalletUnlockSubject,
  WalletUnlockSubjectSet,
} from '../signingEngine/session/identity/walletUnlockSubject';

export type {
  SensitiveOperationPolicy,
  SignerAuthMethod,
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

export type SigningSessionSealConfig =
  | { mode: 'none'; protocol?: never }
  | { mode: 'sealed_refresh_v1'; protocol: SigningSessionSealProtocol };

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
 *   routerAb?: {
 *     normalSigning?: {
 *       mode: 'disabled' | 'enabled';
 *       signingWorkerId?: string; // required when mode === 'enabled'
 *     };
 *   };
 *   routerAbEcdsaDerivationPresignaturePool?: {
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
 *     mode?: 'managed';
 *     projectEnvironmentId: string;
 *     publishableKey: string;
 *     paymentMode?: 'disabled' | 'quota_then_x402' | 'always_x402';
 *   };
 *   authenticatorOptions?: AuthenticatorOptions;
 * }
 * ```
 *
 * Notes:
 * - `relayer.url` is required after defaults are merged; missing values fail fast.
 * - Managed registration authenticates setup directly with the configured publishable key.
 * - `iframeWallet.walletOrigin` is required when `iframeWallet` is configured.
 *   Browser wallet capabilities run through hosted iframe mode.
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
  routerAbEcdsaDerivationPresignaturePool?: RouterAbEcdsaDerivationPresignaturePoolPolicyInput;
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
 *     registration: {
 *       mode: 'managed';
 *       projectEnvironmentId: string;
 *       publishableKey: string;
 *       paymentMode: 'disabled' | 'quota_then_x402' | 'always_x402';
 *     };
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
 *     routerAbEcdsaDerivation: {
 *       presignaturePool: RouterAbEcdsaDerivationPresignaturePoolPolicy;
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

export type WalletSessionIdentityResolveFailure =
  | 'missing_wallet_profile'
  | 'ambiguous_wallet_profile'
  | 'missing_requested_capability_subject'
  | 'capability_subject_lookup_failed'
  | 'invalid_capability_subject'
  | 'activation_reconciliation_pending'
  | 'activation_reconciliation_failed'
  | 'invalid_wallet_profile';

export type WalletSessionAppIdentity =
  | {
      readonly kind: 'anonymous';
      readonly walletId?: never;
      readonly reason?: never;
      readonly nearAccountId?: never;
      readonly nearOperationalPublicKey?: never;
      readonly userData?: never;
      readonly authMethods?: never;
      readonly thresholdEcdsaEthereumAddress?: never;
      readonly thresholdEcdsaPublicKeyB64u?: never;
    }
  | {
      readonly kind: 'unresolvable';
      readonly walletId: WalletId;
      readonly reason: WalletSessionIdentityResolveFailure;
      readonly nearAccountId?: never;
      readonly nearOperationalPublicKey?: never;
      readonly userData?: never;
      readonly authMethods?: never;
      readonly thresholdEcdsaEthereumAddress?: never;
      readonly thresholdEcdsaPublicKeyB64u?: never;
    }
  | {
      readonly kind: 'resolved';
      readonly walletId: WalletId;
      readonly nearAccountId: AccountId | null;
      readonly nearOperationalPublicKey: string | null;
      readonly userData: ClientUserData | null;
      readonly authMethods: readonly WalletAuthMethodBinding[];
      readonly thresholdEcdsaEthereumAddress: string | null;
      readonly thresholdEcdsaPublicKeyB64u: string | null;
      readonly reason?: never;
    };

export type WalletAuthenticationState =
  | {
      readonly kind: 'signed_out';
      readonly walletId?: never;
      readonly authMethod?: never;
    }
  | {
      readonly kind: 'authenticated';
      readonly walletId: WalletId;
      readonly authMethod: WalletAuthMethod;
    }
  | {
      readonly kind: 'linked_device_session';
      readonly walletId: WalletId;
      readonly authMethod?: never;
    };

export type ReusableWalletSessionState =
  | {
      readonly kind: 'absent';
      readonly walletId?: never;
      readonly authorizationId?: never;
      readonly walletSessionId?: never;
      readonly authMethod?: never;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly detectedAtMs?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'active';
      readonly walletId: WalletId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly authMethod: WalletAuthMethod;
      readonly remainingUses: number;
      readonly expiresAtMs: number;
      readonly detectedAtMs?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'linked_device_active';
      readonly walletId: WalletId;
      readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly authMethod: 'linked_device';
      readonly expiresAtMs: number;
      readonly remainingUses?: never;
      readonly detectedAtMs?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'exhausted';
      readonly walletId: WalletId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly authMethod: WalletAuthMethod;
      readonly remainingUses: 0;
      readonly expiresAtMs: number;
      readonly detectedAtMs?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'expired';
      readonly walletId: WalletId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly authMethod: WalletAuthMethod;
      readonly expiresAtMs: number;
      readonly detectedAtMs: number;
      readonly remainingUses?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'missing';
      readonly walletId: WalletId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly authMethod: WalletAuthMethod;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly detectedAtMs?: never;
      readonly reason?: never;
    }
  // R90-INV-010. The authority or lifecycle behind this session was replaced,
  // so the session is stale rather than broken: discard it and resolve current
  // state again. It carries no expiry or remaining uses because the replaced
  // session's budget is no longer the one that governs.
  | {
      readonly kind: 'superseded';
      readonly walletId: WalletId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly authMethod: WalletAuthMethod;
      readonly detectedAtMs: number;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'unavailable';
      readonly walletId: WalletId;
      readonly authorizationId?: WalletSessionAuthorizationId;
      readonly reason: 'persistence_unavailable';
      readonly walletSessionId?: never;
      readonly authMethod?: never;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly detectedAtMs?: never;
    }
  | {
      readonly kind: 'invalid';
      readonly walletId: WalletId;
      readonly authorizationId?: WalletSessionAuthorizationId;
      // `lifecycle_mismatch` is gone: replacement is `superseded`, which the
      // caller re-resolves. Collapsing it here told adapters a routine
      // replacement was a broken session.
      readonly reason:
        | 'malformed'
        | 'identity_mismatch'
        | 'ambiguous_wallet_session'
        | 'auth_method_mismatch';
      readonly walletSessionId?: never;
      readonly authMethod?: never;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
      readonly detectedAtMs?: never;
    };

export type WalletSessionCapabilityLaneReadiness =
  | {
      readonly kind: 'ready';
      readonly resume?: never;
      readonly requirement?: never;
      readonly replacement?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'pending';
      readonly resume: 'restore_material' | 'resolve_deferred_state';
      readonly requirement?: never;
      readonly replacement?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'authorization_required';
      readonly requirement:
        | 'same_method_step_up'
        | 'wallet_session_expired'
        | 'wallet_session_exhausted';
      readonly resume?: never;
      readonly replacement?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'superseded';
      readonly replacement: 're_resolve_current_capability';
      readonly resume?: never;
      readonly requirement?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'failed';
      readonly reason:
        | 'missing'
        | 'persistence_unavailable'
        | 'malformed'
        | 'identity_mismatch'
        | 'ambiguous_lane';
      readonly resume?: never;
      readonly requirement?: never;
      readonly replacement?: never;
    };

export type WalletSessionCapabilityReadiness =
  | {
      readonly kind: 'near_ed25519';
      readonly subject: NearEd25519WalletUnlockSubject;
      readonly lane: WalletSessionCapabilityLaneReadiness;
      readonly targets?: never;
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly subject: EvmFamilyEcdsaWalletUnlockSubject;
      readonly targets:
        | { readonly kind: 'no_configured_target' }
        | {
            readonly kind: 'configured_targets';
            readonly lanes: readonly [
              {
                readonly chainTarget: ThresholdEcdsaChainTarget;
                readonly readiness: WalletSessionCapabilityLaneReadiness;
              },
              ...{
                readonly chainTarget: ThresholdEcdsaChainTarget;
                readonly readiness: WalletSessionCapabilityLaneReadiness;
              }[],
            ];
          };
      readonly lane?: never;
    };

export type WalletSessionCapabilityProjection =
  | {
      readonly kind: 'not_requested';
      readonly subjectSet?: never;
      readonly capabilities?: never;
      readonly reason?: never;
    }
  | {
      readonly kind: 'unresolvable';
      readonly reason: WalletSessionIdentityResolveFailure;
      readonly subjectSet?: never;
      readonly capabilities?: never;
    }
  | {
      readonly kind: 'resolved';
      readonly subjectSet: WalletUnlockSubjectSet;
      readonly capabilities: readonly [
        WalletSessionCapabilityReadiness,
        ...WalletSessionCapabilityReadiness[],
      ];
      readonly reason?: never;
    };

export interface WalletSession {
  readonly appIdentity: WalletSessionAppIdentity;
  readonly authentication: WalletAuthenticationState;
  readonly reusableWalletSession: ReusableWalletSessionState;
  readonly capabilityProjection: WalletSessionCapabilityProjection;
  readonly nonceDiagnostics: NonceCoordinatorDiagnostics | null;
}

export type ThemeMode = 'light' | 'dark';
export type ThemeId = string;
export type ThemePaletteName = 'default';

export interface AppearanceThemeInput {
  id: ThemeId;
  mode: ThemeMode;
  colors?: Record<string, string>;
  /**
   * Component geometry overrides, emitted as --w3a-shape-<key> CSS vars
   * (e.g. { card: '3rem', control: '2rem' }). Omitted keys fall back to the
   * square preset values baked into the component CSS.
   */
  shape?: Record<string, string>;
}

export interface AppearanceConfigInput {
  theme?: AppearanceThemeInput;
  palette?: ThemePaletteName;
}

export interface AppearanceTheme {
  id: ThemeId;
  mode: ThemeMode;
  colors: Record<string, string>;
  shape?: Record<string, string>;
}

export interface AppearanceConfig {
  theme: AppearanceTheme;
  palette: ThemePaletteName;
}

export type RegisteredNearEd25519Capability = {
  readonly kind: 'near_ed25519';
  readonly accountProvisioning: RegistrationNearAccountProvisioning;
  readonly resolvedAccount: ResolvedRegistrationNearAccount;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly operationalPublicKey: string | null;
  readonly nearAccountId: AccountId;
  readonly transactionId: string | null;
};

export type RegisteredEvmFamilyEcdsaCapability = {
  readonly kind: 'evm_family_ecdsa';
  readonly thresholdEcdsaEthereumAddress: string;
  readonly thresholdEcdsaPublicKeyB64u: string;
};

export type AddedNearEd25519SignerCapability = {
  readonly kind: 'near_ed25519';
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly operationalPublicKey: string | null;
  readonly nearAccountId: AccountId;
};

export type AddedEvmFamilyEcdsaSignerCapability = {
  readonly kind: 'evm_family_ecdsa';
  readonly thresholdEcdsaEthereumAddress: string;
  readonly thresholdEcdsaPublicKeyB64u: string;
};

/**
 * Lifecycle of the deferred Ed25519/NEAR branch for one wallet.
 *
 * `near_pending` is the state registration returns in: the ECDSA wallet is
 * durable and nothing has started provisioning NEAR yet. `near_provisioning`
 * means an attempt is in flight. `near_failed_retryable` means the Yao ceremony
 * or its finalize failed without touching the ECDSA wallet, so the commit can
 * be reissued against the same registration ceremony.
 *
 * These are published to page-owned state and persisted to the local wallet
 * record. `RegistrationResult` carries only a snapshot: it has crossed the
 * postMessage boundary by the time provisioning settles and must not be
 * mutated.
 */
export type NearProvisioningStatus =
  | 'near_pending'
  | 'near_provisioning'
  | 'near_ready'
  | 'near_failed_retryable';

/**
 * Wire input for a durable NEAR provisioning write.
 *
 * Deliberately a closed discriminated union of plain data: it carries the
 * wallet, the target status, and — only where the status defines them — the
 * NEAR account or a stable error code. No promises, factors, credentials,
 * sessions, or raw error objects cross this boundary, and no lifecycle field
 * is optional on a status that does not define it.
 */
export type NearProvisioningWriteV1 =
  | { walletId: string; status: 'near_pending' }
  | { walletId: string; status: 'near_provisioning' }
  | { walletId: string; status: 'near_ready'; nearAccountId: string }
  | { walletId: string; status: 'near_failed_retryable'; errorCode: NearProvisioningErrorCode };

/** Stable, enumerable reasons a deferred NEAR commit can fail. */
export type NearProvisioningErrorCode =
  | 'near_provisioning_interrupted'
  | 'near_finalize_failed'
  | 'near_capability_persist_failed'
  | 'near_seal_failed'
  | 'near_provisioning_failed';

export type NearProvisioningState =
  | { status: 'near_pending'; updatedAtMs: number; error?: never; errorCode?: never }
  | { status: 'near_provisioning'; updatedAtMs: number; error?: never; errorCode?: never }
  | {
      status: 'near_ready';
      updatedAtMs: number;
      nearAccountId: string;
      error?: never;
      errorCode?: never;
    }
  | {
      status: 'near_failed_retryable';
      updatedAtMs: number;
      error: string;
      errorCode: NearProvisioningErrorCode;
    };

/** Snapshot carried on the registration result. */
export type RegistrationNearProvisioningState =
  | { status: 'pending'; error?: never; errorCode?: never }
  | { status: 'retryable'; error: string; errorCode: NearProvisioningErrorCode };

export type RegistrationResult =
  | {
      readonly success: true;
      readonly kind: 'wallet_registered';
      readonly walletId: WalletId;
      readonly capabilities:
        | readonly [RegisteredNearEd25519Capability]
        | readonly [RegisteredEvmFamilyEcdsaCapability]
        | readonly [RegisteredNearEd25519Capability, RegisteredEvmFamilyEcdsaCapability];
      readonly error?: never;
      readonly errorCode?: never;
    }
  | {
      readonly success: true;
      readonly kind: 'ecdsa_wallet_registered_near_pending';
      readonly walletId: WalletId;
      readonly capabilities: readonly [RegisteredEvmFamilyEcdsaCapability];
      readonly nearProvisioning: RegistrationNearProvisioningState;
      readonly error?: never;
      readonly errorCode?: never;
    }
  | {
      readonly success: true;
      readonly kind: 'wallet_signer_added';
      readonly walletId: WalletId;
      readonly capabilities:
        | readonly [AddedNearEd25519SignerCapability]
        | readonly [AddedEvmFamilyEcdsaSignerCapability];
      readonly error?: never;
      readonly errorCode?: never;
    }
  | {
      readonly success: true;
      readonly kind: 'near_wallet_registered_pending';
      readonly walletId: WalletId;
      readonly nearProvisioning: RegistrationNearProvisioningState;
      readonly capabilities?: never;
      readonly error?: never;
      readonly errorCode?: never;
    }
  | {
      readonly success: false;
      readonly error: string;
      readonly errorCode?: RegistrationErrorCode;
      readonly kind?: never;
      readonly walletId?: never;
      readonly capabilities?: never;
    };

export type RouterApiSecretKeyAuthErrorCode =
  | 'secret_key_missing'
  | 'secret_key_invalid'
  | 'secret_key_revoked'
  | 'secret_key_forbidden_scope'
  | 'secret_key_ip_blocked'
  | 'secret_key_environment_mismatch';

export type RegistrationErrorCode = RouterApiSecretKeyAuthErrorCode | string;

export type LoginResult =
  | {
      success: true;
      kind: 'near_wallet_unlocked';
      walletId: WalletId;
      loggedInNearAccountId: string;
      operationalPublicKey: string | null;
      nearAccountId: AccountId;
      jwt?: string;
      error?: never;
    }
  | {
      success: true;
      kind: 'ecdsa_wallet_unlocked';
      walletId: WalletId;
      loggedInNearAccountId?: never;
      operationalPublicKey?: never;
      nearAccountId?: never;
      jwt?: string;
      error?: never;
    }
  | {
      success: false;
      error: string;
      kind?: never;
      walletId?: never;
      loggedInNearAccountId?: never;
      operationalPublicKey?: never;
      nearAccountId?: never;
      jwt?: never;
    };

export interface SigningSessionStatus {
  sessionId: string;
  status:
    | 'active'
    | 'active_restorable'
    | 'exhausted'
    | 'expired'
    | 'not_found'
    | 'unavailable'
    | 'status_unknown';
  statusCode?: string;
  authMethod?: SignerAuthMethod | null;
  retention?: SigningSessionRetention | null;
  availableUses?: number;
  inFlightReservedUses?: number;
  committedRemainingUses?: number;
  remainingUses?: number;
  expiresAtMs?: number;
  createdAtMs?: number;
  projectionVersion?: string;
}

export type LoginAndCreateSessionResult =
  | (Extract<LoginResult, { success: true }> & {
      signingSession?: SigningSessionStatus;
    })
  | (Extract<LoginResult, { success: false }> & {
      signingSession?: never;
    });

export type ThresholdWarmLoginAndCreateSessionResult = Extract<
  LoginAndCreateSessionResult,
  { success: true }
> & {
  signingSession: SigningSessionStatus & { status: 'active' };
};

export type ActionResult =
  | {
      success: true;
      transactionId?: string;
      result?: FinalExecutionOutcome;
      error?: never;
      errorDetails?: never;
    }
  | {
      success: false;
      error: string;
      // Optional structured error details when available (e.g., NEAR RPC error payload)
      errorDetails?: unknown;
      transactionId?: never;
      result?: never;
    };

export interface SignTransactionResult {
  signedTransaction: SignedTransaction;
  nearAccountId: string;
  nonceLease?: NonceLeaseRef;
  logs?: string[];
}

export interface RecentUnlockAccount {
  walletId: string;
  nearAccountId: AccountId;
  displayName: string;
  signerSlot: number;
  lastLogin?: number;
  authMethod?: WalletAuthMethod | null;
}

export interface GetRecentUnlocksResult {
  walletIds: string[];
  accountIds: string[];
  accounts?: RecentUnlockAccount[];
  lastUsedAccount: RecentUnlockAccount | null;
}

export interface SignDelegateActionResult {
  hash: string;
  signedDelegate: WasmSignedDelegate;
  nearAccountId: string;
  logs?: string[];
}

export interface DelegateRouterApiResult {
  ok: boolean;
  relayerTxHash?: string;
  status?: string;
  outcome?: unknown;
  error?: string;
}

export interface SignAndSendDelegateActionResult {
  signResult: SignDelegateActionResult;
  relayResult: DelegateRouterApiResult;
}

export interface RouterAbEcdsaDerivationPresignaturePoolPolicyInput {
  enabled?: boolean;
  targetDepth?: number;
  lowWatermark?: number;
  maxRefillInFlight?: number;
  refillAttemptTimeoutMs?: number;
}

export interface RouterAbEcdsaDerivationPresignaturePoolPolicy {
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

type ReadonlyDeepPrimitive = string | number | boolean | bigint | symbol | null | undefined;

export type ReadonlyDeep<T> = T extends ReadonlyDeepPrimitive
  ? T
  : T extends (...args: never[]) => unknown
    ? T
    : T extends readonly (infer U)[]
      ? readonly ReadonlyDeep<U>[]
      : T extends object
        ? { readonly [K in keyof T]: ReadonlyDeep<T[K]> }
        : T;

export type SeamsWalletMode = 'direct' | 'iframe';

export type SeamsRegistrationPaymentMode = 'disabled' | 'quota_then_x402' | 'always_x402';

export type SeamsRegistrationNearAccountProvisioning =
  | {
      kind: 'implicit_account';
    }
  | {
      kind: 'relayer_named_subaccount';
    };

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

/**
 * Registration is managed-only (Refactor 94C). `/wallets/register/setup`
 * authenticates with a publishable key and nothing else, so the credential has
 * to reach the browser; a backend-proxied mode has no way to supply one.
 */
export type SeamsRegistrationConfigInput = {
  mode?: 'managed';
  projectEnvironmentId: string;
  publishableKey: string;
  paymentMode?: SeamsRegistrationPaymentMode;
  nearAccountProvisioning?: SeamsRegistrationNearAccountProvisioning;
};

export interface SeamsRelayerConfigInput {
  url?: string;
  /**
   * Relative path on the Router API used for delegate action execution.
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

export type SeamsRegistrationConfig = {
  mode: 'managed';
  projectEnvironmentId: string;
  publishableKey: string;
  paymentMode: SeamsRegistrationPaymentMode;
  nearAccountProvisioning: SeamsRegistrationNearAccountProvisioning;
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

export interface SeamsRouterAbEcdsaDerivationConfig {
  presignaturePool: RouterAbEcdsaDerivationPresignaturePoolPolicy;
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
  routerAbEcdsaDerivation: SeamsRouterAbEcdsaDerivationConfig;
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
