import {
  createSigningRuntime,
  createSigningRuntimeStatePorts,
} from '@/core/runtime/createSigningRuntime';
import type { SigningRuntime, SigningRuntimeConfig } from '@/core/runtime/runtime.types';
import { createBrowserPlatformRuntime } from '@/core/platform';
import { IndexedDBManager } from '@/core/indexedDB';
import type { SignerWorkerManagerContext } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { toSigningRuntimeConfig } from './runtimeConfig';
import type { RegistrationAccountLifecycleDeps } from '@/core/signingEngine/interfaces/operationDeps';
import type { NearSigningApiDeps } from '@/core/signingEngine/interfaces/operationDeps';
import type { ThresholdEcdsaBootstrapStorePort } from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import type { WarmSessionMaterialWriter } from '@/core/signingEngine/session/passkey/warmSessionMaterialWriter';
import type { TempoSigningDeps } from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';

export type CreateBrowserSigningRuntimeArgs = {
  config: SeamsConfigsReadonly;
  workerCtx: SignerWorkerManagerContext;
  accountLifecycle: RegistrationAccountLifecycleDeps;
  ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  getWarmSessionMaterialWriter: () => WarmSessionMaterialWriter;
  getNearSigningDeps: () => NearSigningApiDeps;
  getEvmFamilySigningDeps: () => TempoSigningDeps;
};

export function createBrowserSigningRuntime(
  args: CreateBrowserSigningRuntimeArgs,
): SigningRuntime {
  const state = createSigningRuntimeStatePorts();
  const config: SigningRuntimeConfig = toSigningRuntimeConfig(args.config);
  const runtimePorts = createBrowserPlatformRuntime({
    indexedDB: IndexedDBManager,
    workerCtx: args.workerCtx,
    ecdsaSessionStore: state.ecdsaSessions,
  });

  return createSigningRuntime({
    runtimePorts,
    workers: {
      emailOtp: args.workerCtx,
    },
    signing: {
      near: {
        getDeps: args.getNearSigningDeps,
      },
      evmFamily: {
        getDeps: args.getEvmFamilySigningDeps,
      },
    },
    registration: {
      accountLifecycle: args.accountLifecycle,
      ecdsaBootstrapStore: args.ecdsaBootstrapStore,
    },
    ui: {
      warmSessions: {
        getWarmSessionMaterialWriter: args.getWarmSessionMaterialWriter,
      },
    },
    config,
    state,
  });
}
