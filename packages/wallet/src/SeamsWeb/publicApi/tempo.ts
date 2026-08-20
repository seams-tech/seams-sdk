import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  resolveConfiguredChainTarget,
  resolveTempoChainTarget,
} from '@/SeamsWeb/publicApi/chainTargets';
import type { CurrentWalletResolver, WalletSessionInput } from '@/SeamsWeb/publicApi/currentWallet';
import { toError } from '@shared/utils/errors';
import type { TempoSignerCapability, TempoSigningSurface } from '@/SeamsWeb/signingSurface/types';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import {
  executeEvmFamilyTransactionLifecycle,
  withResolvedChainId,
  type EvmFamilyTransactionSignArgs,
} from '@/SeamsWeb/operations/tempo/executeEvmFamilyTransaction';
import { buildTempoBootstrapArgs, toSerializableTempoError } from '@/SeamsWeb/operations/tempo';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import { requireBrowserCapabilityOperation } from '@/SeamsWeb/publicApi/capabilitySelection';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import {
  getTempoFeeTokenPreference,
  setTempoFeeTokenPreference,
  validateConfiguredTempoFeeToken,
} from '@/SeamsWeb/operations/tempo/feeTokenPreference';

function requireTempoSignedResult(
  result: Awaited<ReturnType<TempoSigningSurface['signEvmFamily']>>,
): TempoSignedResult {
  if (result.chain !== 'tempo' || result.kind !== 'tempoTransaction') {
    throw new Error(`[Tempo capability] expected Tempo result, received ${result.chain}`);
  }
  return result;
}

function toLocalTempoBootstrapRequest(
  args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0],
): EcdsaBootstrapRequest {
  return {
    kind: 'reuse_warm_ecdsa_bootstrap',
    walletId: toWalletId(args.walletSession.walletId),
    chainTarget: args.chainTarget,
    source: args.source,
    relayerUrl: args.relayerUrl,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  };
}

function requireEvmFamilySigningCapability(
  configs: SeamsConfigsReadonly,
  chainTarget: ReturnType<typeof resolveConfiguredChainTarget>,
): void {
  requireBrowserCapabilityOperation(configs, {
    capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
    operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
    chainTarget,
  });
}

export function createTempoSignerCapability(deps: {
  signingEngine: TempoSigningSurface;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  getTheme: () => ThemeMode;
  getWalletIframe: () => WalletIframeCoordinator;
  currentWallet: CurrentWalletResolver;
}): TempoSignerCapability {
  // Capability-level entry: `walletSession` may be omitted here and resolves to
  // the authenticated wallet. The lifecycle below always receives a resolved one.
  type CapabilitySignEvmFamilyArgs = Omit<EvmFamilyTransactionSignArgs, 'walletSession'> & {
    walletSession?: WalletSessionInput;
  };
  const signEvmFamily = async (args: CapabilitySignEvmFamilyArgs) => {
    const chainTarget = resolveConfiguredChainTarget(deps.configs.network.chains, args.chainTarget);
    const walletSession = await deps.currentWallet.walletSession(args.walletSession);
    requireEvmFamilySigningCapability(deps.configs, chainTarget);
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      const result = await deps.signingEngine.signEvmFamily({
        walletSession,
        request: args.request,
        chainTarget,
        confirmationConfigOverride: args.options?.confirmationConfig,
        shouldAbort: args.options?.shouldAbort,
        onEvent: args.options?.onEvent,
      });
      return result;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      const result = await router.signTempo({
        walletSession,
        request: args.request,
        chainTarget,
        options: {
          confirmationConfig: args.options?.confirmationConfig,
          onEvent: args.options?.onEvent,
        },
      });
      return result;
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const signTempo: TempoSignerCapability['signTempo'] = async (args) =>
    requireTempoSignedResult(
      await signEvmFamily({
        ...args,
        chainTarget: resolveTempoChainTarget(deps.configs.network.chains, args.chainTarget),
      }),
    );
  const reportBroadcastAccepted: TempoSignerCapability['reportBroadcastAccepted'] = async (
    args,
  ) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoBroadcastAccepted({
        walletId,
        signedResult: args.signedResult,
        txHash: args.txHash,
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoBroadcastAccepted({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        txHash: args.txHash,
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reportBroadcastRejected: TempoSignerCapability['reportBroadcastRejected'] = async (
    args,
  ) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoBroadcastRejected({
        walletId,
        signedResult: args.signedResult,
        ...(args.error !== undefined ? { error: args.error } : {}),
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoBroadcastRejected({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        ...(args.error != null ? { error: toSerializableTempoError(args.error) } : {}),
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reportFinalized: TempoSignerCapability['reportFinalized'] = async (args) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoFinalized({
        walletId,
        signedResult: args.signedResult,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoFinalized({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reportDroppedOrReplaced: TempoSignerCapability['reportDroppedOrReplaced'] = async (
    args,
  ) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      await deps.signingEngine.reportTempoDroppedOrReplaced({
        walletId,
        signedResult: args.signedResult,
        reason: args.reason,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        onEvent: args.options?.onEvent,
      });
      return;
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      await router.reportTempoDroppedOrReplaced({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        reason: args.reason,
        ...(args.txHash ? { txHash: args.txHash } : {}),
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const reconcileNonceLane: TempoSignerCapability['reconcileNonceLane'] = async (args) => {
    const walletIframe = deps.getWalletIframe();
    const walletId = toWalletId(args.walletSession.walletId);
    if (!walletIframe.shouldUseWalletIframe()) {
      return await deps.signingEngine.reconcileTempoNonceLane({
        walletId,
        signedResult: args.signedResult,
        onEvent: args.options?.onEvent,
      });
    }
    try {
      const router = await walletIframe.requireRouter(walletId);
      return await router.reconcileTempoNonceLane({
        walletSession: args.walletSession,
        signedResult: args.signedResult,
        options: {
          onEvent: args.options?.onEvent,
        },
      });
    } catch (error: unknown) {
      throw toError(error);
    }
  };
  const lifecycle = {
    signEvmFamily,
    reportBroadcastAccepted,
    reportBroadcastRejected,
    reportFinalized,
    reportDroppedOrReplaced,
    reconcileNonceLane,
  };
  const executeEvmFamilyTransaction: TempoSignerCapability['executeEvmFamilyTransaction'] = async (
    args,
  ) => {
    const chainTarget = resolveConfiguredChainTarget(deps.configs.network.chains, args.chainTarget);
    const walletSession = await deps.currentWallet.walletSession(args.walletSession);
    return await executeEvmFamilyTransactionLifecycle({
      lifecycle,
      chains: deps.configs.network.chains,
      input: {
        ...args,
        chainTarget,
        walletSession,
        request: withResolvedChainId(args.request, chainTarget),
      },
    });
  };
  const bootstrapEcdsaSession: TempoSignerCapability['bootstrapEcdsaSession'] = async (args) => {
    const walletIframe = deps.getWalletIframe();
    const bootstrapArgs = buildTempoBootstrapArgs(deps.configs, args);
    if (!walletIframe.shouldUseWalletIframe()) {
      return await deps.signingEngine.bootstrapEcdsaSession(
        toLocalTempoBootstrapRequest(bootstrapArgs),
      );
    }
    const router = await walletIframe.requireRouter(toWalletId(args.walletSession.walletId));
    return await router.bootstrapEcdsaSession(bootstrapArgs);
  };
  const advanced = {
    reportBroadcastAccepted,
    reportBroadcastRejected,
    reportFinalized,
    reportDroppedOrReplaced,
    reconcileNonceLane,
    bootstrapEcdsaSession,
  };
  return {
    // Mirrors `seams.evm`; the deprecated names below stay wired to the same code.
    signTransaction: signTempo,
    executeTransaction: executeEvmFamilyTransaction,
    advanced,
    signTempo,
    getFeeTokenPreference: async (args) =>
      await getTempoFeeTokenPreference(deps.configs.network.chains, args),
    validateFeeToken: async (args) =>
      await validateConfiguredTempoFeeToken(deps.configs.network.chains, args),
    setFeeTokenPreference: async (args) =>
      await setTempoFeeTokenPreference(
        { chains: deps.configs.network.chains, execute: executeEvmFamilyTransaction },
        args,
      ),
    executeEvmFamilyTransaction,
    reportBroadcastAccepted,
    reportBroadcastRejected,
    reportFinalized,
    reportDroppedOrReplaced,
    reconcileNonceLane,
    bootstrapEcdsaSession,
  };
}
