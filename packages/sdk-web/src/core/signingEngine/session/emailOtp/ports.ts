import type { AccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  listStoredThresholdEcdsaSessionRecordsForWallet,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type {
  acquireSigningSessionRestoreLease,
  deleteDurableSealedSessionRecord,
  listExactSealedSessionsForWallet,
  releaseSigningSessionRestoreLease,
  readExactSealedSession,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';

export type EmailOtpCoordinatorRuntimePorts = {
  configs: SeamsConfigsReadonly;
  signerWorkerManager: SignerWorkerManager;
  getRpId: () => string | null;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
};

export type EmailOtpEcdsaSessionPorts = {
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
  listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
};

export type EmailOtpEd25519SessionPorts = {
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
};

export type EmailOtpEd25519PersistencePorts = {
  persistEmailOtpThresholdEd25519LocalMetadata: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  }) => Promise<void>;
  persistWarmSessionEd25519Capability: (
    args: PersistWarmSessionEd25519CapabilityArgs,
  ) => unknown | Promise<unknown>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }) => Promise<void>;
};

export type EmailOtpSealedSessionStorePorts = {
  writeExactSealedSession: typeof writeExactSealedSession;
  readExactSealedSession: typeof readExactSealedSession;
  listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
  acquireSigningSessionRestoreLease: typeof acquireSigningSessionRestoreLease;
  releaseSigningSessionRestoreLease: typeof releaseSigningSessionRestoreLease;
  deleteDurableSealedSessionRecord: typeof deleteDurableSealedSessionRecord;
  updateExactSealedSessionPolicy: typeof updateExactSealedSessionPolicy;
};

export type EmailOtpWalletSessionCoordinatorDeps =
  & EmailOtpCoordinatorRuntimePorts
  & EmailOtpEcdsaSessionPorts
  & EmailOtpEd25519SessionPorts
  & EmailOtpEd25519PersistencePorts
  & EmailOtpSealedSessionStorePorts;
