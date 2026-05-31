import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { AccountId } from '@/core/types/accountIds';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import type { SeamsConfigsReadonly, ThemeName } from '@/core/types/seams';
import type { EmailOtpAuthLane } from '../stepUpConfirmation/otpPrompt/authLane';
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
import type {
  ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ConsumeSingleUseEmailOtpEcdsaLaneResult,
  ThresholdEcdsaKeyRefLookupResult,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../session/persistence/records';
import type { RestorePersistedSessionForSigningInput } from '../session/sealedRecovery/types';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { WarmSessionEcdsaCapabilityState } from '../session/warmCapabilities/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type { ThresholdEd25519WebAuthnPrfSecretSource } from '../threshold/ed25519/authSession';
import type {
  UiConfirmContextPort,
  UiConfirmRegistrationPort,
  UiConfirmSecureConfirmationPort,
  UiConfirmSigningPort,
  VolatileWarmMaterialPort,
  WarmSessionStatusResult,
} from '../uiConfirm/types';
import type { SignerWorkerManagerContext } from '../workerManager/SignerWorkerManager';

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

export type NearSigningApiDeps = {
  nearRpcUrl: string;
  resolveThresholdEd25519SessionId?: (nearAccountId: AccountId) => string | null;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    nearAccountId: AccountId;
    chain: 'near';
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    thresholdSessionId: string;
    curve: 'ed25519';
  }) => EmailOtpAuthLane | null;
  isEmailOtpEd25519WarmupPending?: (args: { nearAccountId: AccountId }) => boolean;
  waitForPendingEmailOtpEd25519Warmup?: (args: {
    nearAccountId: AccountId;
  }) => Promise<boolean>;
  loginWithEmailOtpEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    remainingUses?: number;
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
  restorePersistedSessionForSigning?: (
    args: RestorePersistedSessionForSigningInput,
  ) => Promise<unknown>;
  reconnectPasskeyEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId;
    record: ThresholdEd25519SessionRecord;
    policySecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
    usesNeeded?: number;
    remainingUses?: number;
    sessionId: string;
    walletSigningSessionId: string;
  }) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
  resolveAccountAuthMethodForSigning?: (args: {
    nearAccountId: AccountId;
    curve: 'ed25519';
    chain: 'near';
  }) => Promise<'email_otp' | 'passkey' | null>;
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
  getEmailOtpThresholdEcdsaSessionRecordForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
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

export type EvmFamilySigningDeps = EvmFamilyEcdsaSessionReaderDeps & {
  indexedDB: UnifiedIndexedDBManager;
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  nonceCoordinator: NonceCoordinator;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEcdsaCommitQueue: <T>(args: {
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
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    walletId: WalletId;
    thresholdSessionId: string;
    curve: 'ecdsa';
    chain: EvmFamilyChain;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => EmailOtpAuthLane | null | Promise<EmailOtpAuthLane | null>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    walletSession: WalletSessionRef;
    subjectId?: never;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
    remainingUses?: number;
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
  indexedDB: UnifiedIndexedDBManager;
  relayerUrl: string;
  getRpId: () => string | null;
  requestExportPrivateKeysWithUi?: (
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ) => Promise<ExportPrivateKeysWithUiWorkerResult>;
  getTheme: () => ThemeName;
};

export type RegistrationAccountLifecycleDeps = {
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: Pick<UserPreferencesManager, 'setCurrentWallet' | 'reloadUserSettings'>;
  nonceCoordinator: Pick<NonceCoordinator, 'initializeNearAccessKey' | 'prefetchNearContext'>;
  extractCosePublicKey: (attestationObjectBase64url: string) => Promise<Uint8Array>;
};

export type RegistrationSessionDeps = {
  touchConfirm: UiConfirmRegistrationPort;
  touchIdPrompt: Pick<TouchIdPrompt, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
};
