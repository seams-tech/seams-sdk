import type { SigningSessionStatus } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { WarmSessionMaterialWriteDiagnostics } from './types';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildWalletSessionStatusCheckForSession,
  getWalletSessionStatus as getWalletSessionStatusValue,
  mergeWalletSigningSessionStatus,
  type WalletSigningSessionStatusDeps,
} from '../lifecycle/walletSessionStatus';
import { ed25519WalletSessionStatusOwner } from '../lifecycle/walletSessionStatus';
import {
  scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill as scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue,
  type RouterAbEcdsaDerivationLoginPresignaturePrefillResult,
} from './ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaBootstrapSignerAuth } from './ecdsaBootstrapPersistence';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';
import type { ThresholdWarmSessionStatusReader } from './types';
import type { ExactEd25519SealedSessionRuntime } from './ed25519SealedSessionRuntime';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

export type PersistThresholdEcdsaBootstrapForWalletTargetInput = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  signerAuth: ThresholdEcdsaBootstrapSignerAuth;
};

export type HydrateSigningSessionInput = {
  thresholdSessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: WarmSessionSealTransportInput;
  diagnostics?: WarmSessionMaterialWriteDiagnostics;
};

export type WarmCapabilitiesPublicDeps = {
  statusReader: Pick<ThresholdWarmSessionStatusReader, 'getEd25519SigningSessionStatus'>;
  persistThresholdEcdsaBootstrapForWalletTarget: (
    args: PersistThresholdEcdsaBootstrapForWalletTargetInput,
  ) => Promise<void>;
  hydrateSigningSession: (args: HydrateSigningSessionInput) => Promise<void>;
  clearVolatileWarmSigningMaterial: (walletId?: WalletId) => Promise<void>;
  getWalletSessionStatus: WalletSigningSessionStatusDeps['getAvailableStatus'];
  getSignerWorkerContext: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['getSignerWorkerContext'];
  resolveActiveWalletAuthority: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['resolveActiveWalletAuthority'];
  readExactWalletSessionWithOperationCredential: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['readExactWalletSessionWithOperationCredential'];
  resolveClientSigningMaterialSource: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['resolveClientSigningMaterialSource'];
  routerAbEcdsaDerivationPresignaturePoolPolicy?: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['routerAbEcdsaDerivationPresignaturePoolPolicy'];
};

export async function persistThresholdEcdsaBootstrapForWalletTarget(
  deps: WarmCapabilitiesPublicDeps,
  args: PersistThresholdEcdsaBootstrapForWalletTargetInput,
): Promise<void> {
  await deps.persistThresholdEcdsaBootstrapForWalletTarget(args);
}

export async function getWarmThresholdEd25519SessionStatus(
  deps: WarmCapabilitiesPublicDeps,
  args: {
    runtime: ExactEd25519SealedSessionRuntime;
    authorization: ActiveWalletSessionAuthorizationProjection | null;
    nowMs: number;
  },
): Promise<SigningSessionStatus> {
  const status = await deps.statusReader.getEd25519SigningSessionStatus(args);
  const sessionStatusCheck = args.authorization
    ? buildWalletSessionStatusCheckForSession({
        owner: ed25519WalletSessionStatusOwner(args.runtime.walletId),
        authorization: args.authorization,
      })
    : null;
  const walletSessionStatus = sessionStatusCheck
    ? await getWalletSessionStatusValue(
        {
          getAvailableStatus: deps.getWalletSessionStatus,
        },
        sessionStatusCheck,
      )
    : null;
  return mergeWalletSigningSessionStatus(status, walletSessionStatus);
}

export async function scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(
  deps: WarmCapabilitiesPublicDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    manifest: ActiveEcdsaCapabilityManifest;
    runtime: ExactEcdsaSealedRuntime;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult> {
  return await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue(
    {
      getSignerWorkerContext: deps.getSignerWorkerContext,
      resolveActiveWalletAuthority: deps.resolveActiveWalletAuthority,
      readExactWalletSessionWithOperationCredential:
        deps.readExactWalletSessionWithOperationCredential,
      resolveClientSigningMaterialSource: deps.resolveClientSigningMaterialSource,
      routerAbEcdsaDerivationPresignaturePoolPolicy:
        deps.routerAbEcdsaDerivationPresignaturePoolPolicy,
    },
    args,
  );
}

export async function hydrateSigningSession(
  deps: WarmCapabilitiesPublicDeps,
  args: HydrateSigningSessionInput,
): Promise<void> {
  await deps.hydrateSigningSession(args);
}

export async function clearVolatileWarmSigningMaterial(
  deps: WarmCapabilitiesPublicDeps,
  walletId?: WalletId,
): Promise<void> {
  await deps.clearVolatileWarmSigningMaterial(walletId);
}

export type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult };
