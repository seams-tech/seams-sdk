import type { EvmFamilyWalletSignerStorePort } from '../flows/signEvmFamily/accountAuth';
import type {
  EmailOtpEcdsaChallengeAuthority,
  EmailOtpEcdsaStepUpAuthority,
} from '../flows/signEvmFamily/emailOtpSigningSession';
import type { EvmFamilyPasskeyAuthenticatorStorePort } from './passkeyAuthenticatorStore';
import type { RecoveryNearKeyMaterialStorePort } from '../flows/recovery/recoveryStorePorts';
import type { RegistrationAccountStorePort } from '../flows/registration/registrationStorePorts';
import type { AccountId } from '@/core/types/accountIds';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import type { SeamsConfigsReadonly, ThemeMode, WalletAuthMethod } from '@/core/types/seams';
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
import type {
  SelectedEcdsaLane,
  ThresholdEcdsaSessionStoreSource,
} from '../session/identity/laneIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../session/identity/exactSigningLaneIdentity';
import type {
  ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ConsumeSingleUseEmailOtpEcdsaLaneResult,
  ThresholdEcdsaKeyRefLookupResult,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../session/persistence/records';
import type { RestorePersistedSessionForSigningInput } from '../session/sealedRecovery/sealedRecovery.types';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { WarmSessionEcdsaCapabilityState } from '../session/warmCapabilities/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type { ThresholdEd25519WebAuthnPrfSecretSource } from '../threshold/ed25519/walletSession';
import type {
  UiConfirmContextPort,
  UiConfirmRegistrationPort,
  UiConfirmSecureConfirmationPort,
  UiConfirmSigningPort,
  VolatileWarmMaterialPort,
  WarmSessionStatusResult,
} from '../uiConfirm/uiConfirm.types';
import type { SignerWorkerManagerContext } from '../workerManager/SignerWorkerManager';
import type { NearEd25519YaoSigningCapability } from './near';
import type { Ed25519SigningLane } from '../session/emailOtp/ed25519SigningLane';
import type { ExactEd25519SigningLaneIdentity } from '../session/identity/exactSigningLaneIdentity';
import type { EmailOtpEd25519YaoSilentRecoveryResultV1 } from '../session/emailOtp/ed25519YaoSealedRecovery';

export type EvmFamilyChain = 'tempo' | 'evm';

export type NearEd25519SigningSessionStatus = {
  sessionId?: string | null;
  status?: string | null;
  remainingUses?: number | null;
  expiresAtMs?: number | null;
};

export type EmailOtpEcdsaSigningBootstrapResult = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
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

export type NearSigningApiDeps = {
  nearRpcUrl: string;
  resolveActiveEd25519YaoSigningCapability: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    thresholdSessionId: string;
  }) => NearEd25519YaoSigningCapability | null;
  resolveThresholdEd25519SessionIdForNearAccount: (
    nearAccountId: AccountId | string,
  ) => string | null;
  readPersistedEd25519SessionRecordForSigning: (args: {
    walletId: WalletId;
    laneIdentity: ExactEd25519SigningLaneIdentity;
  }) => Promise<ThresholdEd25519SessionRecord | null>;
  rehydratePasskeyEd25519YaoCapabilityForSigning: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    laneIdentity: ExactEd25519SigningLaneIdentity;
  }) => Promise<NearEd25519YaoSigningCapability>;
  recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    signerSlot: number;
    thresholdSessionId: string;
  }) => Promise<EmailOtpEd25519YaoSilentRecoveryResultV1>;
  refreshPasskeyEd25519CapabilityForSigning?: (args: {
    record: ThresholdEd25519SessionRecord;
    laneIdentity: ExactEd25519SigningLaneIdentity;
    policySecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
    operationUsesNeeded: number;
  }) => Promise<
    { sessionId: string; record: ThresholdEd25519SessionRecord } & NearEd25519YaoSigningCapability
  >;
  requestEmailOtpEd25519SigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    nearAccountId: AccountId;
    authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
  }) => Promise<EmailOtpTransactionSigningChallenge>;
  rehydrateEmailOtpEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId;
    record: ThresholdEd25519SessionRecord;
    committedLane: Ed25519SigningLane;
    challengeId: string;
    otpCode: string;
    remainingUses: number;
  }) => Promise<
    { sessionId: string; record: ThresholdEd25519SessionRecord } & NearEd25519YaoSigningCapability
  >;
  resolveAccountAuthMethodForSigning: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    curve: 'ed25519';
    chain: 'near';
  }) => Promise<WalletAuthMethod | null>;
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
  getPasskeyThresholdEcdsaSessionRecordForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
  listThresholdEcdsaSessionRecordsForSigning: (
    args: EcdsaSigningListLookupArgs,
  ) => ThresholdEcdsaSessionRecord[];
  listThresholdEcdsaKeyRefsForSigning: (
    args: EcdsaSigningListLookupArgs,
  ) => ThresholdEcdsaKeyRefLookupResult[];
  getThresholdEcdsaSessionRecordByKey: (
    identity: SelectedEcdsaLane,
  ) => ThresholdEcdsaSessionRecord | null;
};

export type EvmFamilySigningDeps = EvmFamilyEcdsaSessionReaderDeps &
  DurableEmailOtpEcdsaSigningSessionAuthorityResolver & {
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
    loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
      walletSession: WalletSessionRef;
      subjectId?: never;
      chainTarget: ThresholdEcdsaChainTarget;
      challengeId: string;
      otpCode: string;
      authority: EmailOtpEcdsaStepUpAuthority;
      remainingUses: number;
    }) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
    restorePersistedSessionForSigning: (
      args: Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<unknown>;
    readAvailableSigningLanesForSigning: (
      args: Extract<ReadAvailableSigningLanesForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<AvailableSigningLanes>;
    getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
    consumeSingleUseEmailOtpEcdsaLane?: (
      command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
    ) => ConsumeSingleUseEmailOtpEcdsaLaneResult;
    signingSessionCoordinator: SigningSessionCoordinator;
    provisionThresholdEcdsaSession: (
      args: import('../session/passkey/ecdsaSessionProvision').ThresholdEcdsaActivationRequest,
    ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
    touchConfirm: UiConfirmContextPort &
      UiConfirmSigningPort &
      UiConfirmSecureConfirmationPort &
      Pick<VolatileWarmMaterialPort, 'getWarmSessionStatus'> &
      Partial<Pick<VolatileWarmMaterialPort, 'clearVolatileWarmSessionMaterial'>>;
  };

export type PrivateKeyExportRecoveryDeps = {
  keyMaterialStore: RecoveryNearKeyMaterialStorePort;
  relayerUrl: string;
  getRpId: () => string | null;
  requestExportPrivateKeysWithUi?: (
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ) => Promise<ExportPrivateKeysWithUiWorkerResult>;
  getTheme: () => ThemeMode;
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
