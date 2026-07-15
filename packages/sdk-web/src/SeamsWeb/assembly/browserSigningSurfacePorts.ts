import type { SigningRuntime } from '@/core/runtime/runtime.types';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import type { ManagerAssemblyStores } from '@/core/signingEngine/assembly/createManagers';
import type { EmailOtpSealedSessionStorePorts } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { CreateBrowserSigningRuntimeArgs } from './createBrowserSigningRuntime';
import type { WorkerResourceWarmupPolicy } from '@/core/signingEngine/assembly/warmup';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';

export type InitializeSigningRuntimePort = (args: {
  config: SeamsConfigsReadonly;
  userPreferencesManager: Pick<UserPreferencesManager, 'initFromIndexedDB'>;
  getWorkerBaseOrigin: () => string;
  setWorkerBaseOrigin: (origin: string) => void;
}) => void;

export type BrowserSigningSurfaceConstructorDeps = {
  managerStores: ManagerAssemblyStores;
  signingEngineStores: SigningEngineStorePorts;
  sealedSigningSessionStore: EmailOtpSealedSessionStorePorts;
  ed25519YaoPublicCapabilityReferences: Ed25519YaoPublicCapabilityReferenceStorePort;
  createRuntime: (args: CreateBrowserSigningRuntimeArgs) => SigningRuntime;
  initializeRuntime: InitializeSigningRuntimePort;
  workerWarmupPolicy: WorkerResourceWarmupPolicy;
};
