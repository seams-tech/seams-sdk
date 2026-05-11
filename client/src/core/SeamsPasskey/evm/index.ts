import { toAccountId } from '../../types/accountIds';
import type { EvmSignerCapability } from '..';
import { routeWalletIframeOrLocal, type WalletIframeRouteDeps } from '../walletIframeRoute';
import { toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';

type ChainSignerDeps = {
  getContext: () => import('../index').PasskeyManagerContext;
  walletIframe: WalletIframeRouteDeps;
};

function toLocalBootstrapRequest(
  args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0],
): EcdsaBootstrapRequest {
  const common = {
    nearAccountId: toAccountId(args.nearAccountId),
    subjectId: toWalletSubjectId(args.nearAccountId),
    chainTarget: args.chainTarget,
    source: args.source,
    relayerUrl: args.relayerUrl,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    participantIds: args.participantIds,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    smartAccount: args.smartAccount ? { ...args.smartAccount } : undefined,
  } as const;
  switch (args.kind) {
    case 'reuse_warm_ecdsa_bootstrap':
      return {
        kind: 'reuse_warm_ecdsa_bootstrap',
        ...common,
      };
    case 'passkey_fresh_ecdsa_bootstrap':
      if (args.sessionKind === 'cookie') {
        return {
          kind: 'passkey_fresh_ecdsa_bootstrap',
          ...common,
          sessionKind: args.sessionKind,
          sessionIdentity: buildEcdsaSessionIdentity(args.sessionIdentity),
          clientRootShare32B64u: args.clientRootShare32B64u,
          ...('webauthnAuthentication' in args && args.webauthnAuthentication
            ? { webauthnAuthentication: args.webauthnAuthentication }
            : {}),
        };
      }
      if ('routeAuth' in args && args.routeAuth) {
        return {
          kind: 'passkey_fresh_ecdsa_bootstrap',
          ...common,
          sessionKind: args.sessionKind,
          sessionIdentity: buildEcdsaSessionIdentity(args.sessionIdentity),
          clientRootShare32B64u: args.clientRootShare32B64u,
          routeAuth: args.routeAuth,
        };
      }
      return {
        kind: 'passkey_fresh_ecdsa_bootstrap',
        ...common,
        sessionKind: args.sessionKind,
        sessionIdentity: buildEcdsaSessionIdentity(args.sessionIdentity),
        clientRootShare32B64u: args.clientRootShare32B64u,
        webauthnAuthentication: args.webauthnAuthentication,
      };
    case 'passkey_cookie_reconnect_ecdsa_bootstrap':
      return {
        kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
        ...common,
        sessionKind: args.sessionKind,
        sessionIdentity: buildEcdsaSessionIdentity(args.sessionIdentity),
      };
    case 'threshold_session_auth_reconnect_ecdsa_bootstrap':
      return {
        kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
        ...common,
        sessionKind: args.sessionKind,
        sessionIdentity: buildEcdsaSessionIdentity(args.sessionIdentity),
        routeAuth: args.routeAuth,
      };
    case 'email_otp_ecdsa_bootstrap':
      return {
        kind: 'email_otp_ecdsa_bootstrap',
        ...common,
        source: 'email_otp',
        sessionKind: args.sessionKind,
        sessionIdentity: buildEcdsaSessionIdentity(args.sessionIdentity),
        clientRootShare32B64u: args.clientRootShare32B64u,
        routeAuth: args.routeAuth,
        emailOtpAuthContext: args.emailOtpAuthContext,
      };
  }
  args satisfies never;
  throw new Error('[SeamsPasskey][evm] unsupported bootstrap request');
}

/**
 * EVM signer currently exposes threshold-ECDSA bootstrap only.
 */
export class EvmSigner implements EvmSignerCapability {
  private readonly getContext: ChainSignerDeps['getContext'];
  private readonly walletIframe: ChainSignerDeps['walletIframe'];

  constructor(deps: ChainSignerDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async bootstrapEcdsaSession(args: Parameters<EvmSignerCapability['bootstrapEcdsaSession']>[0]) {
    const context = this.getContext();
    const managedRegistration =
      context.configs.registration.mode === 'managed' ? context.configs.registration : null;
    const runtimeScopeBootstrap =
      args.runtimeScopeBootstrap ||
      (managedRegistration
        ? {
            environmentId: managedRegistration.environmentId,
            publishableKey: managedRegistration.publishableKey,
          }
        : undefined);
    const chainTarget = args.chainTarget;
    if (chainTarget.kind !== 'evm') {
      throw new Error('[SeamsPasskey][evm] bootstrapEcdsaSession requires an EVM chainTarget');
    }
    const bootstrapArgs = {
      ...args,
      ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
    };

    return await routeWalletIframeOrLocal({
      walletIframe: this.walletIframe,
      nearAccountId: args.nearAccountId,
      remote: async (router) => {
        return await router.bootstrapEcdsaSession(bootstrapArgs);
      },
      local: async () => {
        return await context.signingEngine.bootstrapEcdsaSession(
          toLocalBootstrapRequest(bootstrapArgs),
        );
      },
    });
  }
}
