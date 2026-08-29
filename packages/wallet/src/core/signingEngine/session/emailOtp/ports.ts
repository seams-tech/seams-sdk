import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import type { resolveActiveEcdsaCapabilityRuntime } from '@/core/signingEngine/session/material/activeEcdsaCapabilityRuntime';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ActiveWalletSessionAuthorizationProjection,
  WalletSessionAuthorizationExactOperationCredentialReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
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
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { WalletAuthorityId, WalletAuthMethodId } from '@shared/utils/domainIds';
import type { EmailOtpWalletCustodyEd25519MaterialRequest } from '../../workerManager/workerTypes';
import type { ImportWalletCustodyEcdsaContinuityInput } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';

export type EmailOtpCoordinatorRuntimePorts = {
  configs: SeamsConfigsReadonly;
  signerWorkerManager: SignerWorkerManager;
  getRpId: () => string | null;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  readExactWalletSessionAuthorization: (input: {
    walletId: WalletId;
    authorityId: WalletAuthorityId;
    authMethodId: WalletAuthMethodId;
  }) => Promise<WalletSessionAuthorizationExactOperationCredentialReadResult>;
};

export type EmailOtpEcdsaSessionPorts = {
  loadWalletCustodyEd25519Material: (args: {
    nearAccountId: string;
    signerSlot: number;
  }) => Promise<EmailOtpWalletCustodyEd25519MaterialRequest>;
  restoreWalletCustodyEcdsaContinuity: (
    args: Omit<ImportWalletCustodyEcdsaContinuityInput, 'store'>,
  ) => Promise<unknown>;
  withThresholdEcdsaSigningQueue: <T>(args: {
    queueKey: string;
    walletId: WalletId;
    enabled: boolean;
    task: () => Promise<T>;
  }) => Promise<T>;
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
    authority: WalletAuthAuthorityRef;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    authorization: ActiveWalletSessionAuthorizationProjection;
  }>;
  listActiveEcdsaCapabilityManifestsForWallet: (
    walletId: WalletId,
  ) => Promise<readonly ActiveEcdsaCapabilityManifest[]>;
  resolveCurrentEcdsaCapabilityRuntime: typeof resolveActiveEcdsaCapabilityRuntime;
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
