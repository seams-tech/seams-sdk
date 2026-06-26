import type { RuntimePorts } from '@/core/platform';
import type {
  ReadonlyDeep,
  SeamsNetworkConfig,
  SeamsRegistrationConfig,
  SeamsSigningConfig,
} from '@/core/types/seams';
import type { ThresholdEcdsaCanonicalExportArtifact } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { EcdsaRelayerClient } from '@/core/platform';
import type { ProvisionEcdsaUseCase } from '@/core/signingEngine/useCases/provisionEcdsa';
import type { EcdsaRegistrationBootstrapService } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { RegistrationAccountLifecycleDeps } from '@/core/signingEngine/interfaces/operationDeps';
import type { EcdsaWalletRecordsService } from '@/core/signingEngine/flows/registration/services/ecdsaWalletRecords';
import type { ThresholdEcdsaBootstrapStorePort } from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import type { WarmSessionMaterialWriter } from '@/core/signingEngine/session/passkey/warmSessionMaterialWriter';
import type { EcdsaRegistrationSessionsService } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type { WarmSessionHydrationService } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import type { RegistrationAccountsService } from '@/core/signingEngine/flows/registration/services/registrationAccounts';
import type { NearSigningApiDeps } from '@/core/signingEngine/interfaces/operationDeps';
import type {
  NearSignIntentRequest,
  NearSignIntentResult,
} from '@/core/signingEngine/flows/signNear/signNear';
import type {
  ReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs,
  ReconcileTempoNonceLaneArgs,
  TempoNonceLaneStatus,
  TempoSigningDeps,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type SigningRuntimeConfig = ReadonlyDeep<{
  network: SeamsNetworkConfig;
  registration: SeamsRegistrationConfig;
  signing: SeamsSigningConfig;
}>;

export type SigningRuntimeEcdsaStatePorts = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

export type SigningRuntimeStatePorts = {
  ecdsaSessions: SigningRuntimeEcdsaStatePorts;
};

export type SigningRuntimeRelayerClients = {
  ecdsa: Pick<EcdsaRelayerClient, 'bootstrapEcdsaSession'>;
};

export type SigningRuntimeWarmSessionUiPorts = {
  getWarmSessionMaterialWriter: () => WarmSessionMaterialWriter;
};
export type SigningRuntimeUiDeps = {
  warmSessions: SigningRuntimeWarmSessionUiPorts;
};

export type SigningRuntimeWorkerPorts = {
  emailOtp: WorkerOperationContext;
};

export type SigningRuntimeNearSigningDeps = {
  getDeps: () => NearSigningApiDeps;
};

export type SigningRuntimeEvmFamilySigningDeps = {
  getDeps: () => TempoSigningDeps;
};

export type SigningRuntimeSignEvmFamilyArgs = {
  walletSession: WalletSessionRef;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  shouldAbort?: () => boolean;
  onEvent?: (event: SigningFlowEvent) => void;
};

export type SigningRuntimeNearSigningService = {
  signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>>;
};

export type SigningRuntimeEvmFamilySigningService = {
  signEvmFamily(
    args: SigningRuntimeSignEvmFamilyArgs,
  ): Promise<TempoSignedResult | EvmSignedResult>;
  reportTempoBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void>;
  reportTempoBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void>;
  reportTempoFinalized(args: ReportTempoFinalizedArgs): Promise<void>;
  reportTempoDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void>;
  reconcileTempoNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus>;
};

export type SigningRuntimeServices = {
  warmSessions: WarmSessionHydrationService;
  registrationAccounts: RegistrationAccountsService;
  nearSigning: SigningRuntimeNearSigningService;
  evmFamilySigning: SigningRuntimeEvmFamilySigningService;
  ecdsaRegistrationBootstrap: EcdsaRegistrationBootstrapService;
  ecdsaRegistrationSessions: EcdsaRegistrationSessionsService;
  ecdsaWalletRecords: EcdsaWalletRecordsService;
  ecdsaProvisioning: ProvisionEcdsaUseCase;
};

export type SigningRuntimeDeps = {
  runtimePorts: RuntimePorts;
  relayers: SigningRuntimeRelayerClients;
  workers: SigningRuntimeWorkerPorts;
  signing: {
    near: SigningRuntimeNearSigningDeps;
    evmFamily: SigningRuntimeEvmFamilySigningDeps;
  };
  registration: {
    accountLifecycle: RegistrationAccountLifecycleDeps;
    ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  };
  ui: SigningRuntimeUiDeps;
  config: SigningRuntimeConfig;
  state: SigningRuntimeStatePorts;
};

export type SigningRuntime = SigningRuntimeDeps & {
  services: SigningRuntimeServices;
};
