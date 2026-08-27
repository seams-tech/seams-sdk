import type { EvmFamilyWalletSignerStorePort } from '../flows/signEvmFamily/accountAuth';
import type { EmailOtpEcdsaChallengeAuthority } from '../flows/signEvmFamily/emailOtpSigningSession';
import type { EvmFamilyPasskeyAuthenticatorStorePort } from './passkeyAuthenticatorStore';
import type { RegistrationAccountStorePort } from '../flows/registration/registrationStorePorts';
import type { AccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { EmailOtpSigningSessionAuthLane } from '../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../session/emailOtp/ecdsaSigningSessionAuthority';
import type { EmailOtpTransactionSigningChallenge } from '../session/emailOtp/publicTypes';
import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type {
  AvailableSigningLanes,
  ReadAvailableSigningLanesForSigningInput,
} from '../session/availability/availableSigningLanes';
import type { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type { ThresholdEcdsaSessionStoreSource } from '../session/identity/laneIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../session/identity/exactSigningLaneIdentity';
import type { RestorePersistedSessionForSigningInput } from '../session/sealedRecovery/sealedRecovery.types';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type {
  UiConfirmContextPort,
  UiConfirmRegistrationPort,
  UiConfirmRequestConfirmationPort,
  UiConfirmSigningPort,
  VolatileWarmMaterialPort,
  WarmSessionStatusResult,
} from '../uiConfirm/uiConfirm.types';
import type { SignerWorkerManagerContext } from '../workerManager/SignerWorkerManager';
import type { NearEd25519YaoPreparedMaterialBoundary } from './near';
import type { SigningLaneAuthBinding } from '../session/identity/signingLaneAuthBinding';
import type { ExactEd25519SigningLaneIdentity } from '../session/identity/exactSigningLaneIdentity';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import type { ThresholdEd25519SessionId } from '../session/operationState/types';
import type {
  ActiveEvmFamilyWalletSessionAuthorization,
  AuthorizedEvmFamilyEcdsaSigningCapability,
  CanonicalEvmFamilyEcdsaSigningCapability,
} from '../session/material/ecdsaSigningCapability';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type { OwnerLaneScope } from '../session/identity/signingLaneAuthBinding';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';

export type EvmFamilyChain = 'tempo' | 'evm';

export type EmailOtpEcdsaSigningBootstrapResult = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ActiveWalletSessionAuthorizationProjection;
};

export type DurableEmailOtpEcdsaSigningSessionAuthorityResolver = {
  resolveDurableEmailOtpEcdsaSigningSessionAuthority: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    chain: EvmFamilyChain;
  }) =>
    | EmailOtpEcdsaSigningSessionAuthority
    | null
    | Promise<EmailOtpEcdsaSigningSessionAuthority | null>;
};

/** Stable Ed25519 material identity used before a reusable Wallet Session exists. */
export type NearEd25519MaterialIdentity = {
  readonly kind: 'near_ed25519_material_identity';
  readonly signer: NearEd25519SignerBinding;
  readonly auth: SigningLaneAuthBinding;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
};

export type NearEd25519MaterialBoundaryInput = {
  readonly walletId: WalletId;
  readonly nearAccountId: AccountId;
} & (
  | {
      readonly laneIdentity: ExactEd25519SigningLaneIdentity;
      readonly auth: SigningLaneAuthBinding;
      readonly materialIdentity?: never;
    }
  | {
      readonly laneIdentity?: never;
      readonly auth?: never;
      readonly materialIdentity: NearEd25519MaterialIdentity;
    }
);

export type NearSigningApiDeps = {
  nearRpcUrl: string;
  resolveOwnerLaneScope: (walletId: WalletId) => Promise<OwnerLaneScope>;
  prepareNearEd25519YaoMaterialBoundary: (
    args: NearEd25519MaterialBoundaryInput,
  ) => Promise<NearEd25519YaoPreparedMaterialBoundary>;
  requestEmailOtpEd25519SigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    operationFingerprintDigest: DigestB64u;
  }) => Promise<EmailOtpTransactionSigningChallenge>;
  signingSessionCoordinator: SigningSessionCoordinator;
  readAvailableSigningLanesForSigning: (
    args: Extract<ReadAvailableSigningLanesForSigningInput, { curve: 'ed25519' }>,
  ) => Promise<AvailableSigningLanes>;
  createSigningSessionId: (prefix: string) => string;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEd25519CommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
};

export type EcdsaSigningLookupArgs = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EcdsaSigningListLookupArgs = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
};

export type PasskeyEcdsaSigningLookupArgs = EcdsaSigningLookupArgs & {
  source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
};

export type EvmFamilySigningDeps = DurableEmailOtpEcdsaSigningSessionAuthorityResolver & {
  resolveOwnerLaneScope: (walletId: WalletId) => Promise<OwnerLaneScope>;
  resolveCanonicalEcdsaSigningCapability: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    materialActivation: MpcMaterialActivationRef;
  }) => Promise<CanonicalEvmFamilyEcdsaSigningCapability>;
  resolveAuthorizedEcdsaSigningCapability: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    materialActivation: MpcMaterialActivationRef;
  }) => Promise<AuthorizedEvmFamilyEcdsaSigningCapability>;
  // Wallet-level view of the reusable Wallet Session authorization. Null
  // means no active authorization; inactive session states never throw.
  resolveActiveEcdsaWalletSessionAuthorization: (
    walletId: WalletId,
  ) => Promise<ActiveEvmFamilyWalletSessionAuthorization | null>;
  walletSignerStore: EvmFamilyWalletSignerStorePort;
  passkeyAuthenticatorStore: EvmFamilyPasskeyAuthenticatorStorePort;
  seamsWebConfigs: SeamsConfigsReadonly;
  nonceCoordinator: NonceCoordinator;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEcdsaSigningQueue: <T>(args: {
    queueKey: string;
    walletId: WalletId;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    chain: EvmFamilyChain;
    authority: EmailOtpEcdsaChallengeAuthority;
    operationFingerprintDigest: DigestB64u;
  }) => Promise<EmailOtpTransactionSigningChallenge>;
  restorePersistedSessionForSigning: (
    args: Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>,
  ) => Promise<unknown>;
  readAvailableSigningLanesForSigning: (
    args: Extract<ReadAvailableSigningLanesForSigningInput, { curve: 'ecdsa' }>,
  ) => Promise<AvailableSigningLanes>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  signingSessionCoordinator: SigningSessionCoordinator;
  provisionThresholdEcdsaSession: (
    args: import('../session/passkey/ecdsaSessionProvision').ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  touchConfirm: UiConfirmContextPort & UiConfirmSigningPort & UiConfirmRequestConfirmationPort;
};

export type RegistrationAccountLifecycleDeps = {
  accountStore: RegistrationAccountStorePort;
  userPreferencesManager: Pick<UserPreferencesManager, 'setCurrentWallet' | 'reloadUserSettings'>;
  nonceCoordinator: Pick<NonceCoordinator, 'initializeNearAccessKey' | 'prefetchNearContext'>;
};

export type RegistrationSessionDeps = {
  touchConfirm: UiConfirmRegistrationPort;
  touchIdPrompt: Pick<TouchIdPrompt, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
};
