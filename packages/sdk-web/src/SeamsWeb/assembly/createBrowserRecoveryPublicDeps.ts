import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { WarmSigningPorts } from '@/core/signingEngine/assembly/ports/warmSigning';
import { createRecoveryPublicDeps } from '@/core/signingEngine/assembly/ports/recovery';
import { provisionPasskeyEcdsaExplicitExportSession as provisionPasskeyEcdsaExplicitExportSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { RuntimePorts } from '@/core/platform';
import type { WalletSessionActivationDeps } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { RecoveryPublicDeps } from '@/core/signingEngine/flows/recovery/public';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/types';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { resolvePasskeyEd25519WalletSessionRouteAuthV1 } from '@/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';

type BrowserWarmSession = Awaited<ReturnType<WarmSessionCapabilityReader['getWarmSession']>>;
type BrowserWarmSessionAuth =
  | BrowserWarmSession['capabilities']['ed25519']['auth']
  | BrowserWarmSession['capabilities']['ecdsa']['evm']['auth'];

function walletSessionRouteAuthFromWarmAuth(
  auth: BrowserWarmSessionAuth,
): AppOrWalletSessionAuth | null {
  if (!auth || !('walletSessionJwt' in auth)) return null;
  const jwt = String(auth.walletSessionJwt || '').trim();
  return jwt ? { kind: 'wallet_session', jwt } : null;
}

async function resolvePasskeyEcdsaExportRouteAuth(
  capabilityReader: WarmSessionCapabilityReader,
  walletId: string,
  chainTarget: ThresholdEcdsaChainTarget,
): Promise<AppOrWalletSessionAuth> {
  const warmSession = await capabilityReader.getWarmSession(toWalletId(walletId));
  const targetEcdsa =
    chainTarget.kind === 'tempo'
      ? warmSession.capabilities.ecdsa.tempo
      : warmSession.capabilities.ecdsa.evm;
  const warmRouteAuth =
    walletSessionRouteAuthFromWarmAuth(targetEcdsa.auth) ||
    walletSessionRouteAuthFromWarmAuth(warmSession.capabilities.ed25519.auth);
  const routeAuth =
    warmRouteAuth || (await resolvePasskeyEd25519WalletSessionRouteAuthV1(walletId));
  if (!routeAuth) {
    throw new Error(
      '[SigningEngine][ecdsa-export] strict ECDSA export requires an active wallet-scoped route authority',
    );
  }
  return routeAuth;
}

export function createBrowserRecoveryPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  runtimePorts: RuntimePorts;
  signerWorkerManager: SignerWorkerManager;
  warmSigning: WarmSigningPorts;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  getWalletSessionActivationDeps: () => WalletSessionActivationDeps;
  resolveActiveEd25519YaoCapability: RecoveryPublicDeps['ed25519Yao']['resolveActiveCapability'];
  recoverPasskeyEd25519YaoCapability: RecoveryPublicDeps['ed25519Yao']['recoverPasskeyCapability'];
  resolvePasskeyEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext'];
  resolveEmailOtpEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['emailOtp']['resolveExportContext'];
  getTheme: () => ThemeMode;
}): RecoveryPublicDeps {
  return createRecoveryPublicDeps({
    seamsWebConfigs: args.seamsWebConfigs,
    signerWorkerManager: args.signerWorkerManager,
    getTheme: args.getTheme,
    ecdsaSessions: args.warmSigning.ecdsaSessions,
    touchConfirm: args.touchConfirm,
    emailOtpSessions: args.emailOtpSessions,
    provisionPasskeyEcdsaExplicitExportSession: (provisionArgs) =>
      provisionPasskeyEcdsaExplicitExportSessionOperation(
        {
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.getWalletSessionActivationDeps(),
          touchConfirm: args.touchConfirm,
          persistEcdsaRoleLocalReadyRecord:
            args.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
          resolveSealTransport: ({ lane }) =>
            args.warmSigning.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
              lane,
            }),
        },
        provisionArgs,
      ),
    resolvePasskeyEcdsaExportRouteAuth: resolvePasskeyEcdsaExportRouteAuth.bind(
      null,
      args.warmSigning.capabilityReader,
    ),
    warmSessionPolicy: {
      getWarmSession: (walletId) => args.warmSigning.capabilityReader.getWarmSession(walletId),
      resolveExactEcdsaRecord: (recordArgs) =>
        args.warmSigning.statusReader.resolveExactEcdsaRecord(recordArgs),
    },
    getWalletSigningBudgetStatus: (statusArgs) =>
      readTrustedWalletSigningBudgetStatusOperation(
        {
          ecdsaSessions: args.warmSigning.ecdsaSessions,
        },
        statusArgs,
      ),
    resolveActiveEd25519YaoCapability: args.resolveActiveEd25519YaoCapability,
    recoverPasskeyEd25519YaoCapability: args.recoverPasskeyEd25519YaoCapability,
    resolvePasskeyEd25519YaoExportContext: args.resolvePasskeyEd25519YaoExportContext,
    resolveEmailOtpEd25519YaoExportContext: args.resolveEmailOtpEd25519YaoExportContext,
  });
}
