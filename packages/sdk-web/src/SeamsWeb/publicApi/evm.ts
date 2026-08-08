import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toError } from '@shared/utils/errors';
import type {
  EcdsaSessionBootstrapSurface,
  EvmFamilySigningSurface,
  EvmSignerCapability,
  RegistrationSigningSurface,
  RegistrationWebContext,
} from '@/SeamsWeb/signingSurface/types';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { registerWallet as registerWalletWithUnifiedCeremony } from '@/SeamsWeb/operations/registration/registration';
import { buildEvmBootstrapArgs, buildEvmWalletRegistrationArgs } from '@/SeamsWeb/operations/evm';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import { requireBrowserCapabilityOperation } from '@/SeamsWeb/publicApi/capabilitySelection';

function requireEvmSignedResult(
  result: Awaited<ReturnType<EvmFamilySigningSurface['signEvmFamily']>>,
): EvmSignedResult {
  if (result.chain !== 'evm' || result.kind !== 'eip1559') {
    throw new Error(`[EVM capability] expected EVM result, received ${result.chain}`);
  }
  return result;
}

function toLocalEvmBootstrapRequest(
  args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0],
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

export function createEvmSignerCapability(deps: {
  signingEngine: RegistrationSigningSurface &
    EcdsaSessionBootstrapSurface &
    EvmFamilySigningSurface;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  getTheme: () => ThemeMode;
  getWalletIframe: () => WalletIframeCoordinator;
}): EvmSignerCapability {
  return {
    signTransaction: async (args) => {
      const chainTarget = thresholdEcdsaChainTargetFromRequest(args.chainTarget);
      requireBrowserCapabilityOperation(deps.configs, {
        capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
        operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
        chainTarget,
      });
      const walletIframe = deps.getWalletIframe();
      if (!walletIframe.shouldUseWalletIframe()) {
        const result = await deps.signingEngine.signEvmFamily({
          walletSession: args.walletSession,
          request: args.request,
          chainTarget,
          confirmationConfigOverride: args.options?.confirmationConfig,
          shouldAbort: args.options?.shouldAbort,
          onEvent: args.options?.onEvent,
        });
        return requireEvmSignedResult(result);
      }
      try {
        const router = await walletIframe.requireRouter(toWalletId(args.walletSession.walletId));
        const result = await router.signTempo({
          walletSession: args.walletSession,
          request: args.request,
          chainTarget,
          options: {
            confirmationConfig: args.options?.confirmationConfig,
            onEvent: args.options?.onEvent,
          },
        });
        return requireEvmSignedResult(result);
      } catch (error: unknown) {
        throw toError(error);
      }
    },
    registerEvmWallet: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const registerWalletArgs = buildEvmWalletRegistrationArgs(args);
      if (!walletIframe.shouldUseWalletIframe()) {
        const context: RegistrationWebContext = {
          signingEngine: deps.signingEngine,
          nearClient: deps.nearClient,
          configs: deps.configs,
          theme: deps.getTheme(),
        };
        return await registerWalletWithUnifiedCeremony({
          context,
          ...registerWalletArgs,
          authenticatorOptions: cloneAuthenticatorOptions(
            deps.configs.webauthn.authenticatorOptions,
          ),
        });
      }
      try {
        const router = await walletIframe.requireRouter();
        const result = await router.registerWallet(registerWalletArgs);
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    bootstrapEcdsaSession: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const bootstrapArgs = buildEvmBootstrapArgs(deps.configs, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        return await deps.signingEngine.bootstrapEcdsaSession(
          toLocalEvmBootstrapRequest(bootstrapArgs),
        );
      }
      const router = await walletIframe.requireRouter(toWalletId(args.walletSession.walletId));
      return await router.bootstrapEcdsaSession(bootstrapArgs);
    },
  };
}
