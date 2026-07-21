import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  listStoredThresholdEcdsaSessionRecordsForWallet,
  ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
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
import type { ThresholdEcdsaActivationRequest } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { ThresholdEcdsaEmailOtpExportActivationRequest } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { EmailOtpEcdsaExplicitExportBootstrapResult } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';

export type EmailOtpCoordinatorRuntimePorts = {
  configs: SeamsConfigsReadonly;
  signerWorkerManager: SignerWorkerManager;
  getRpId: () => string | null;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
};

export type EmailOtpEcdsaSessionPorts = {
  provisionThresholdEcdsaSession: (
    request: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionEmailOtpEcdsaExplicitExportSession: (
    request: ThresholdEcdsaEmailOtpExportActivationRequest,
  ) => Promise<EmailOtpEcdsaExplicitExportBootstrapResult>;
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
  listThresholdEcdsaSessionRecordsForWallet: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
  listActiveEcdsaSignersForWallet: (args: {
    walletId: WalletId;
  }) => Promise<readonly AccountSignerRecord[]>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
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

export type EmailOtpWalletSessionCoordinatorDeps = EmailOtpCoordinatorRuntimePorts &
  EmailOtpEcdsaSessionPorts &
  EmailOtpSealedSessionStorePorts;
