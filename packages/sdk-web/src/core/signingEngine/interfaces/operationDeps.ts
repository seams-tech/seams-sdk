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
import type { ThresholdEd25519SessionRecord } from '../session/persistence/records';
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
import type {
  NearEd25519YaoSigningCapability,
  NearPasskeyEd25519OperationStepUpCapabilityPreparation,
} from './near';
import type { NearEd25519YaoSigningPreparation } from '../session/material/nearEd25519YaoSigningPreparation';
import type { SigningLaneAuthBinding } from '../session/identity/signingLaneAuthBinding';
import type { ExactEd25519SigningLaneIdentity } from '../session/identity/exactSigningLaneIdentity';
import type { EmailOtpEd25519YaoSilentRecoveryResultV1 } from '../session/emailOtp/ed25519YaoSealedRecovery';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type {
  ActiveEvmFamilyWalletSessionAuthorization,
  AuthorizedEvmFamilyEcdsaSigningCapability,
  CanonicalEvmFamilyEcdsaSigningCapability,
} from '../flows/signEvmFamily/ecdsaSigningCapability';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type { EcdsaOperationStepUpSessionAuth } from '../threshold/ecdsa/operationStepUp';

export type EvmFamilyChain = 'tempo' | 'evm';

export type NearEd25519SigningSessionStatus = {
  sessionId?: string | null;
  status?: string | null;
  remainingUses?: number | null;
  expiresAtMs?: number | null;
};

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

export type EcdsaOperationStepUpSessionAuthResolver = {
  resolveEcdsaOperationStepUpSessionAuth: (args: {
    walletSession: WalletSessionRef;
    authMethod: SignerAuthMethod;
  }) => Promise<EcdsaOperationStepUpSessionAuth>;
};

export type NearSigningApiDeps = {
  nearRpcUrl: string;
  resolveActiveEd25519YaoSigningCapability: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
  }) => NearEd25519YaoSigningCapability | null;
  readPersistedEd25519SessionRecordForSigning: (args: {
    walletId: WalletId;
    laneIdentity: ExactEd25519SigningLaneIdentity;
  }) => Promise<ThresholdEd25519SessionRecord | null>;
  prepareNearEd25519YaoSigning: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    laneIdentity: ExactEd25519SigningLaneIdentity;
    auth: SigningLaneAuthBinding;
  }) => Promise<NearEd25519YaoSigningPreparation>;
  rehydratePasskeyEd25519YaoCapabilityForSigning: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    laneIdentity: ExactEd25519SigningLaneIdentity;
  }) => Promise<NearEd25519YaoSigningCapability>;
  preparePasskeyEd25519YaoOperationStepUpForSigning: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    laneIdentity: ExactEd25519SigningLaneIdentity;
  }) => Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation>;
  recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    signerSlot: number;
    thresholdSessionId: string;
  }) => Promise<EmailOtpEd25519YaoSilentRecoveryResultV1>;
  requestEmailOtpEd25519SigningChallenge?: (args: {
    walletSession: WalletSessionRef;
  }) => Promise<EmailOtpTransactionSigningChallenge>;
  signingSessionCoordinator: SigningSessionCoordinator;
  readAvailableSigningLanesForSigning: (
    args: Extract<ReadAvailableSigningLanesForSigningInput, { curve: 'ed25519' }>,
  ) => Promise<AvailableSigningLanes>;
  getWarmThresholdEd25519SessionStatusForSession?: (args: {
    nearAccountId: AccountId;
    thresholdSessionId: string;
  }) => Promise<NearEd25519SigningSessionStatus | null>;
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

export type PasskeyEcdsaSessionStoreSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

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
  source: PasskeyEcdsaSessionStoreSource;
};

export type EvmFamilyEcdsaSessionReaderDeps = {
  // Exact persistence-boundary read: selection matches these records on
  // stable material identity; no by-key, source-priority, or keyRef reads
  // survive on the signing path.
};

export type EvmFamilySigningDeps = EvmFamilyEcdsaSessionReaderDeps &
  DurableEmailOtpEcdsaSigningSessionAuthorityResolver &
  EcdsaOperationStepUpSessionAuthResolver & {
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
    touchConfirm: UiConfirmContextPort &
      UiConfirmSigningPort &
      UiConfirmRequestConfirmationPort;
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
