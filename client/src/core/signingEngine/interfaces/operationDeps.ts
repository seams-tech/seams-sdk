import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import type { SeamsConfigsReadonly, ThemeName } from '@/core/types/seams';
import type { EmailOtpAuthLane } from '../stepUpConfirmation/otpPrompt/authLane';
import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { ThresholdEcdsaSecp256k1KeyRef } from './signing';
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
  ThresholdEcdsaKeyRefLookupResult,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../session/persistence/records';
import type { RestorePersistedSessionForSigningInput } from '../session/sealedRecovery/types';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { WarmSessionEcdsaCapabilityState } from '../session/warmCapabilities/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type {
  UiConfirmContextPort,
  UiConfirmRegistrationPort,
  UiConfirmSecureConfirmationPort,
  UiConfirmSigningPort,
  WarmSessionMaterialClearer,
  WarmSessionStatusReader,
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
  clientRootShare32B64u: string;
};

export type NearSigningApiDeps = {
  nearRpcUrl: string;
  resolveThresholdEd25519SessionId?: (nearAccountId: AccountId) => string | null;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    nearAccountId: AccountId | string;
    chain: 'near';
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    thresholdSessionId: string;
    curve: 'ed25519';
  }) => EmailOtpAuthLane | null;
  isEmailOtpEd25519WarmupPending?: (args: { nearAccountId: AccountId | string }) => boolean;
  waitForPendingEmailOtpEd25519Warmup?: (args: {
    nearAccountId: AccountId | string;
  }) => Promise<boolean>;
  loginWithEmailOtpEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
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
    nearAccountId: AccountId | string;
    record: ThresholdEd25519SessionRecord;
    localPrfCredential: WebAuthnAuthenticationCredential;
    usesNeeded?: number;
    remainingUses?: number;
    sessionId: string;
    walletSigningSessionId: string;
  }) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
  resolveAccountAuthMethodForSigning?: (args: {
    nearAccountId: AccountId | string;
    curve: 'ed25519';
    chain: 'near';
  }) => Promise<'email_otp' | 'passkey' | null>;
  signingSessionCoordinator: SigningSessionCoordinator;
  readAvailableSigningLanesForSigning: (
    args: Extract<ReadAvailableSigningLanesForSigningInput, { curve: 'ed25519' }>,
  ) => Promise<AvailableSigningLanes>;
  getWarmThresholdEd25519SessionStatusForSession?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId: string;
  }) => Promise<NearEd25519SigningSessionStatus | null>;
  createSigningSessionId: (prefix: string) => string;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEd25519CommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
};

export type PasskeyEcdsaSessionStoreSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

export type EcdsaSigningLookupArgs = {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  signingRootId?: string;
  signingRootVersion?: string;
};

export type EcdsaSigningListLookupArgs = {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
};

export type PasskeyEcdsaSigningLookupArgs = EcdsaSigningLookupArgs & {
  source: PasskeyEcdsaSessionStoreSource;
};

export type EvmFamilyEcdsaSessionReaderDeps = {
  getEmailOtpThresholdEcdsaKeyRefForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
  getEmailOtpThresholdEcdsaSessionRecordForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
  getPasskeyThresholdEcdsaKeyRefForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
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
  getThresholdEcdsaKeyRefByKey: (
    identity: SelectedEcdsaLane,
  ) => ThresholdEcdsaKeyRefLookupResult | null;
};

export type EvmFamilySigningDeps = EvmFamilyEcdsaSessionReaderDeps & {
  indexedDB: UnifiedIndexedDBManager;
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  nonceCoordinator: NonceCoordinator;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEcdsaCommitQueue: <T>(args: {
    queueKey: string;
    walletId: string;
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
    thresholdSessionId: string;
    curve: 'ecdsa';
    chain: EvmFamilyChain;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => EmailOtpAuthLane | null | Promise<EmailOtpAuthLane | null>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    walletSession: WalletSessionRef;
    subjectId: WalletSubjectId;
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
  markThresholdEcdsaEmailOtpSessionConsumedForSubjectTarget?: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  }) => void;
  signingSessionCoordinator: SigningSessionCoordinator;
  provisionThresholdEcdsaSession: (
    args: import('../session/passkey/ecdsaSessionProvision').ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  touchConfirm: UiConfirmContextPort &
    UiConfirmSigningPort &
    UiConfirmSecureConfirmationPort &
    WarmSessionStatusReader &
    Partial<WarmSessionMaterialClearer>;
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
  nearRpcUrl: string;
  touchConfirm: UiConfirmRegistrationPort;
  touchIdPrompt: Pick<TouchIdPrompt, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
};
